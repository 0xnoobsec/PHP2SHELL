#!/usr/bin/env bash
# ci_validate.sh -- run validation and enforce acceptance criteria independently.
#
# Fails on: differential not confirmed, trials below minimum, OOM not observed,
# missing evidence, or evidence hash mismatch. Never passes merely because the
# process exited 0.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TRIALS="${TRIALS:-20}"
MIN="${MIN_TRIALS:-10}"
OUT="${OUT:-ci_report.json}"
EVID="${EVIDENCE_DIR:-evidence}"

python3 "$HERE/c_validate.py" --trials "$TRIALS" --min-trials "$MIN" \
  --evidence-dir "$EVID" --out "$OUT" "$@"
tool_rc=$?

python3 - "$OUT" "$MIN" <<'PY'
import json, os, sys, hashlib
path, min_trials = sys.argv[1], int(sys.argv[2])
if not os.path.exists(path):
    print("GATE FAIL: report missing (%s)" % path); sys.exit(1)
rep = json.load(open(path))
fail = []
if rep.get("patch_differential") != "Confirmed":
    fail.append("differential=%s" % rep.get("patch_differential"))
if rep["config"]["trials"] < min_trials:
    fail.append("trials %d < min %d" % (rep["config"]["trials"], min_trials))
for t in rep["targets"]:
    if t["stats"]["oom_yes"] == 0:
        fail.append("%s: OOM not observed" % t["name"])
    ev = t.get("evidence")
    if not ev or not os.path.exists(ev["path"]):
        fail.append("%s: evidence missing" % t["name"])
    else:
        h = hashlib.sha256(open(ev["path"], "rb").read()).hexdigest()
        if h != ev["sha256"]:
            fail.append("%s: evidence hash mismatch" % t["name"])
if fail:
    print("GATE FAIL: " + "; ".join(fail)); sys.exit(1)
print("GATE PASS: %d targets, differential confirmed, evidence hashed"
      % len(rep["targets"]))
PY
gate_rc=$?
[ "$tool_rc" -ne 0 ] && echo "NOTE: validator exit=$tool_rc"
exit "$gate_rc"
