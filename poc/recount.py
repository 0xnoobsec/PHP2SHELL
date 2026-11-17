#!/usr/bin/env python3
"""recount -- recount a validation report from its own raw evidence logs.

c_validate.py records, for every trial, whether the allocator reported
corruption. Up to v2.1.0 it took that from a before/after count over
`docker logs --tail 400`, which under-counts once the window fills with
earlier abort lines (see logcount.py and ERRATA.md).

The raw logs the validator saved next to its report do not have that problem:
every worker abort is in them, with a timestamp and the pid of the worker that
died. This tool reads a report and its evidence logs and counts again:

* every trial is matched to the exit notices logged between the previous
  trial's timestamp and its own;
* where the report recorded the worker's pid for the trial, the notice must
  also name that pid;
* a trial counts as "heap corruption" when a matched notice is directly
  preceded by the allocator's "zend_mm_heap corrupted" line.

It reads files only. It sends nothing and needs neither Docker nor a lab.

Usage:
  python3 poc/recount.py                 # this repository's report and logs
  python3 poc/recount.py --report poc/c_validation.json --root . \
      --out poc/c_validation_recount.json
  python3 poc/recount.py --strict        # exit 1 if the recount disagrees with the report
"""
import argparse
import hashlib
import json
import os
import statistics
import sys
from datetime import datetime, timedelta, timezone

from logcount import access_log_offsets, count_signals, log_time_span, parse_exit_notices

VERSION = "1.0.0"
# Records are stamped after the trial's log count; a notice can trail the dead
# worker by up to Apache's one-second maintenance cycle.
SLACK = timedelta(seconds=2)


def parse_ts(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def trial_windows(times):
    """(start, end] for each trial, from the timestamps written after each one."""
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    typical = statistics.median(gaps) if gaps else 60.0
    first_start = times[0] - timedelta(seconds=1.5 * typical)
    starts = [first_start] + times[:-1]
    return [(start, end + SLACK) for start, end in zip(starts, times)]


def recount_target(target, root):
    records = target.get("records") or []
    evidence = target.get("evidence") or {}
    out = {
        "name": target["name"],
        "kind": target.get("kind"),
        "trials": len(records),
        "report": {
            "oom": sum(1 for r in records if r.get("oom")),
            "corruption": sum(1 for r in records if r.get("corruption")),
            "worker_aborts": sum(1 for r in records if r.get("worker_aborted")),
        },
    }
    path = os.path.join(root, evidence.get("path") or "")
    if not records or not evidence.get("path") or not os.path.isfile(path):
        out["evidence"] = {"path": evidence.get("path"),
                           "found": bool(evidence.get("path")) and os.path.isfile(path)}
        out["recount"] = None
        out["agrees_with_report"] = None
        return out
    unstamped = [r.get("trial", i) for i, r in enumerate(records) if not r.get("ts")]
    if unstamped:
        raise ValueError("%s: trial record(s) %s carry no 'ts', so they cannot be placed "
                         "in the log" % (target["name"], unstamped))

    with open(path, "rb") as handle:
        raw = handle.read()
    text = raw.decode("utf-8", "replace")
    notices = parse_exit_notices(text)
    times = [parse_ts(r["ts"]) for r in records]
    windows = trial_windows(times)
    run_start, run_end = windows[0][0], windows[-1][1]
    in_run = [n for n in notices if run_start < n["time"] <= run_end]
    first, last = log_time_span(text)

    have_pids = all(isinstance(r.get("pid_before"), int) for r in records)
    used = set()
    per_trial = []
    for index, (record, (start, end)) in enumerate(zip(records, windows)):
        # Always inside this trial's own window. With a recorded pid the notice
        # must also name that worker: a worker that survives several trials has
        # the same pid in each of them, so the pid alone does not pick a trial.
        matched = [n for n in in_run if start < n["time"] <= end]
        if have_pids:
            matched = [n for n in matched if n["pid"] == record["pid_before"]]
        used.update(n["line"] for n in matched)
        per_trial.append({
            "trial": record.get("trial", index),
            "pid_before": record.get("pid_before"),
            "pid_after": record.get("pid_after"),
            "report_corruption": bool(record.get("corruption")),
            "exit_notices": len(matched),
            "heap_corruption": any(n["heap_line_before"] for n in matched),
            "notice_time": matched[0]["time"].strftime("%Y-%m-%dT%H:%M:%S.%fZ") if matched else None,
            "signal": matched[0]["signal"] if matched else None,
        })

    recount = {
        "attribution": "worker pid" if have_pids else "time window",
        "trials_with_exit_notice": sum(1 for t in per_trial if t["exit_notices"]),
        "trials_with_heap_corruption": sum(1 for t in per_trial if t["heap_corruption"]),
        "exit_notices_in_run_window": len(in_run),
        "unattributed_notices": len([n for n in in_run if n["line"] not in used]),
    }
    totals = count_signals(text)
    out["evidence"] = {
        "path": evidence["path"],
        "found": True,
        "sha256": sha256_bytes(raw),
        "matches_report_hash": sha256_bytes(raw) == evidence.get("sha256"),
        "lines": totals["lines"],
        "heap_lines_total": totals["heap"],
        "exit_notices_total": totals["exit"],
        # The log must start before the run did and still be going when the
        # last trial began; otherwise "no notice" could just mean "not captured".
        "covers_run": (first is not None and first <= run_start
                       and last >= windows[-1][0]),
        "access_log_utc_offsets": sorted(access_log_offsets(text)),
    }
    out["recount"] = recount
    out["agrees_with_report"] = all(
        t["report_corruption"] == t["heap_corruption"] for t in per_trial)
    out["per_trial"] = per_trial
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root_default = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="Recount a c_validate report from its raw logs.")
    ap.add_argument("--report", default=os.path.join(here, "c_validation.json"))
    ap.add_argument("--root", default=root_default,
                    help="directory the report's evidence paths are relative to")
    ap.add_argument("--out", default=None, help="write the recount as JSON")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when the recount disagrees with the report")
    args = ap.parse_args()

    with open(args.report, "rb") as handle:
        raw = handle.read()
    report = json.loads(raw)
    try:
        targets = [recount_target(t, args.root) for t in report.get("targets") or []]
    except ValueError as error:
        print("recount: %s" % error, file=sys.stderr)
        return 2
    if not targets:
        print("recount: %s has no targets" % args.report, file=sys.stderr)
        return 2

    result = {
        "tool": "recount v%s" % VERSION,
        "source_report": {
            "file": os.path.basename(args.report),
            "sha256": sha256_bytes(raw),
            "tool": report.get("tool"),
            "generated": report.get("generated"),
        },
        "method": ("Each trial is matched to the Apache exit notices logged between the "
                   "previous trial's timestamp and its own; where the report recorded the "
                   "worker's pid for the trial, the notice must also name that pid. A trial "
                   "counts as heap corruption when a matched notice is directly preceded by the "
                   "allocator's 'zend_mm_heap corrupted' line. Counted over the complete "
                   "evidence log, not a tail."),
        "targets": targets,
    }

    print("recount v%s  %s (%s, generated %s)\n"
          % (VERSION, os.path.basename(args.report), report.get("tool"), report.get("generated")))
    print("%-8s %-11s %-7s %-20s %-30s %s"
          % ("target", "kind", "trials", "report: corruption", "raw log: corruption aborts", "agree"))
    disagree = False
    problems = []
    for t in targets:
        if t["recount"] is None:
            why = "no trial records" if not t["trials"] else "evidence log not found"
            print("%-8s %-11s %-7d %-20s %-30s %s"
                  % (t["name"], t["kind"], t["trials"],
                     "%d/%d" % (t["report"]["corruption"], t["trials"]), why, "?"))
            problems.append("%s: %s" % (t["name"], why))
            continue
        raw_cell = "%d/%d (by %s)" % (t["recount"]["trials_with_heap_corruption"], t["trials"],
                                      t["recount"]["attribution"])
        print("%-8s %-11s %-7d %-20s %-30s %s"
              % (t["name"], t["kind"], t["trials"],
                 "%d/%d" % (t["report"]["corruption"], t["trials"]), raw_cell,
                 "yes" if t["agrees_with_report"] else "NO"))
        if not t["agrees_with_report"]:
            disagree = True
        if not t["evidence"]["matches_report_hash"]:
            problems.append("%s: evidence log does not match the hash in the report" % t["name"])
        if not t["evidence"]["covers_run"]:
            problems.append("%s: evidence log does not span the whole run" % t["name"])
        if t["recount"]["unattributed_notices"]:
            problems.append("%s: %d exit notice(s) in the run window match no trial"
                            % (t["name"], t["recount"]["unattributed_notices"]))
        if t["evidence"]["access_log_utc_offsets"] not in ([], ["+0000"]):
            problems.append("%s: log is not in UTC (%s); timestamps were compared as UTC"
                            % (t["name"], ", ".join(t["evidence"]["access_log_utc_offsets"])))

    result["agrees_with_report"] = not disagree
    result["problems"] = problems
    if disagree:
        print("\nThe recount DISAGREES with the report's per-trial corruption flags.")
    else:
        print("\nThe recount agrees with the report.")
    for problem in problems:
        print("note: " + problem)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
        print("recount -> %s" % args.out)
    return 1 if (args.strict and (disagree or problems)) else 0


if __name__ == "__main__":
    sys.exit(main())
