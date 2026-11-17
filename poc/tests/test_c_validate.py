"""Tests for c_validate's run loop, against a simulated container log.

Nothing here sends a request or needs Docker: the request sequence and the
log reader are replaced by fakes, so only the bookkeeping is exercised.

    python3 -m unittest discover -s poc/tests -v
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

try:
    import c_validate
except ImportError as error:  # the validator needs the third-party `requests` module
    c_validate = None
    IMPORT_ERROR = str(error)
else:
    IMPORT_ERROR = ""

from logcount import count_signals  # noqa: E402

ACCESS = '172.17.0.1 - - [22/Oct/2026:21:04:54 +0000] "POST /decode.php HTTP/1.1" 200 421 "-" "x"'
HEAP = "zend_mm_heap corrupted"
NOTICE = ("[Thu Oct 22 21:05:01.549439 2026] [core:notice] [pid 1:tid 1] AH00051: "
          "child pid %d exit signal Abort (6), possible coredump in /etc/apache2")


class FakeLab:
    """A container log that grows as trials run."""

    def __init__(self, earlier_aborts=0, readable=True):
        self.lines = []
        self.readable = readable
        self.pid = 500
        for i in range(earlier_aborts):
            self.lines += [ACCESS, HEAP, NOTICE % (100 + i)]

    def text(self):
        return "\n".join(self.lines) + "\n"

    def container_counts(self, container, timeout=60):
        return count_signals(self.text()) if self.readable else None

    def read_container_log(self, container, timeout=60):
        return self.text() if self.readable else None

    def aborting_trial(self, url, sid, probe_url=None):
        before = self.pid
        self.lines += [ACCESS, HEAP, NOTICE % before]
        self.pid += 1
        return {"oom": True, "a_status": 200, "b_status": None, "a_error": None,
                "b_error": "ConnectionError", "pid_before": before, "pid_after": self.pid}

    def clean_trial(self, url, sid, probe_url=None):
        self.lines += [ACCESS, ACCESS]
        return {"oom": True, "a_status": 200, "b_status": 200, "a_error": None,
                "b_error": None, "pid_before": self.pid, "pid_after": self.pid}


@unittest.skipIf(c_validate is None, "c_validate not importable: %s" % IMPORT_ERROR)
class RunTarget(unittest.TestCase):
    def run_target(self, lab, trial, name="t", kind="vulnerable", trials=20):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with mock.patch.object(c_validate, "container_counts", lab.container_counts), \
                mock.patch.object(c_validate, "read_container_log", lab.read_container_log), \
                mock.patch.object(c_validate, "trigger", trial), \
                mock.patch.object(c_validate, "php_provenance", lambda container: {}), \
                mock.patch.object(c_validate.time, "sleep", lambda seconds: None), \
                mock.patch("builtins.print"):
            return c_validate.run_target(name, "http://127.0.0.1:1/x", kind, "c",
                                         "", trials, self.tmp.name)

    def test_every_aborting_trial_is_counted_on_a_long_lived_container(self):
        # 140 earlier aborts: far more than the old 400-line window could hold.
        lab = FakeLab(earlier_aborts=140)
        result = self.run_target(lab, lab.aborting_trial)
        stats = result["stats"]
        self.assertEqual(stats["corruption_yes"], 20)
        self.assertEqual(stats["corruption_unknown"], 0)
        self.assertEqual(stats["worker_aborts"], 20)
        self.assertEqual(stats["abort_events"], 20)
        self.assertEqual(stats["heap_lines"], 20)
        for record in result["records"]:
            self.assertIs(record["corruption"], True)
            self.assertEqual((record["heap_lines"], record["exit_notices"]), (1, 1))

    def test_clean_trials_are_negative_not_unknown(self):
        lab = FakeLab(earlier_aborts=140)
        result = self.run_target(lab, lab.clean_trial, kind="patched")
        self.assertEqual(result["stats"]["corruption_yes"], 0)
        self.assertEqual(result["stats"]["corruption_unknown"], 0)
        self.assertEqual(result["stats"]["worker_aborts"], 0)
        self.assertEqual(result["stats"]["corruption_upper95_onesided"], 0.1391)
        self.assertIs(result["records"][0]["corruption"], False)

    def test_unreadable_log_is_unknown_not_clean(self):
        lab = FakeLab(readable=False)
        result = self.run_target(lab, lab.clean_trial, kind="patched")
        stats = result["stats"]
        self.assertEqual(stats["corruption_unknown"], 20)
        self.assertEqual(stats["corruption_yes"], 0)
        self.assertIsNone(stats["corruption_rate"])
        self.assertIsNone(stats["abort_events"])
        self.assertIsNone(result["records"][0]["corruption"])
        self.assertIsNone(result["evidence"])
        verdict = c_validate.verdict(result, "Inconclusive", None, None)
        self.assertEqual(verdict["corruption_observed"], "Unknown")

    def test_evidence_file_is_the_whole_log_and_matches_its_hash(self):
        lab = FakeLab(earlier_aborts=140)
        result = self.run_target(lab, lab.aborting_trial, trials=3)
        evidence = result["evidence"]
        with open(evidence["path"], "rb") as handle:
            data = handle.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), evidence["sha256"])
        self.assertEqual(evidence["bytes"], len(data))
        self.assertEqual(evidence["heap_lines"], 143)
        self.assertEqual(evidence["abort_lines"], 143)


@unittest.skipIf(c_validate is None, "c_validate not importable: %s" % IMPORT_ERROR)
class Helpers(unittest.TestCase):
    def test_worker_aborted_is_three_valued(self):
        change = {"lines": 3, "heap": 1, "exit": 1, "segv": 0}
        quiet = {"lines": 2, "heap": 0, "exit": 0, "segv": 0}
        self.assertIs(c_validate.worker_aborted(10, 11, None), True)
        self.assertIs(c_validate.worker_aborted(None, None, change), True)
        self.assertIs(c_validate.worker_aborted(10, 10, None), False)
        self.assertIs(c_validate.worker_aborted(None, None, quiet), False)
        self.assertIsNone(c_validate.worker_aborted(None, None, None))

    def test_counts_after_trial_waits_for_a_late_exit_notice(self):
        before = {"lines": 10, "heap": 0, "exit": 0, "segv": 0}
        late = {"lines": 12, "heap": 1, "exit": 1, "segv": 0}
        reads = [{"lines": 11, "heap": 1, "exit": 0, "segv": 0}, late]
        with mock.patch.object(c_validate, "container_counts", lambda container: reads.pop(0)), \
                mock.patch.object(c_validate.time, "sleep", lambda seconds: None):
            self.assertEqual(c_validate.counts_after_trial("c", before, expect_abort=True), late)

    def test_counts_after_trial_gives_up_when_no_notice_ever_arrives(self):
        before = {"lines": 10, "heap": 0, "exit": 0, "segv": 0}
        same = {"lines": 11, "heap": 0, "exit": 0, "segv": 0}
        reads = []
        clock = iter(range(1000))
        with mock.patch.object(c_validate, "container_counts",
                               lambda container: reads.append(1) or same), \
                mock.patch.object(c_validate.time, "time", lambda: next(clock)), \
                mock.patch.object(c_validate.time, "sleep", lambda seconds: None):
            result = c_validate.counts_after_trial("c", before, expect_abort=True, wait=3.0)
        self.assertEqual(result, same)
        self.assertGreater(len(reads), 1)
        self.assertLess(len(reads), 10)

    def test_counts_after_trial_does_not_wait_when_nothing_died(self):
        before = {"lines": 10, "heap": 0, "exit": 0, "segv": 0}
        after = {"lines": 12, "heap": 0, "exit": 0, "segv": 0}
        calls = []
        with mock.patch.object(c_validate, "container_counts",
                               lambda container: calls.append(1) or after):
            self.assertEqual(c_validate.counts_after_trial("c", before, expect_abort=False), after)
        self.assertEqual(len(calls), 1)


@unittest.skipIf(c_validate is None, "c_validate not importable: %s" % IMPORT_ERROR)
class Gate(unittest.TestCase):
    """main() end to end, with run_target replaced by prepared results."""

    def result(self, name, kind, corruption, unknown=0, trials=20):
        records = [{"corruption": None if i < unknown else i < unknown + corruption,
                    "worker_aborted": None if i < unknown else i < unknown + corruption}
                   for i in range(trials)]
        known = trials - unknown
        return {"name": name, "url": "u", "kind": kind, "container": "c", "probe_url": "",
                "provenance": {"php_version": "PHP x"},
                "stats": {"trials": trials, "oom_yes": trials, "oom_rate": 1.0,
                          "oom_ci95": [0.84, 1.0], "corruption_yes": corruption,
                          "corruption_unknown": unknown,
                          "corruption_rate": (corruption / known) if known else None,
                          "corruption_ci95": c_validate.wilson(corruption, known),
                          "corruption_upper95_onesided": None,
                          "worker_aborts": corruption, "abort_events": corruption,
                          "heap_lines": corruption},
                "records": records,
                "evidence": {"path": "evidence/%s.log" % name, "sha256": "0" * 64, "bytes": 10}}

    def run_main(self, results):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = os.path.join(tmp.name, "report.json")
        argv = ["c_validate.py", "--out", out]
        for r in results:
            argv += ["--target", "%s|u|%s|c|" % (r["name"], r["kind"])]
        queue = list(results)
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(c_validate, "run_target", lambda *a: queue.pop(0)), \
                mock.patch("builtins.print"):
            code = c_validate.main()
        with open(out, encoding="utf-8") as handle:
            return code, json.load(handle)

    def test_all_trials_corrupt_on_vulnerable_and_none_on_patched_is_confirmed(self):
        code, report = self.run_main([self.result("8.4.26", "vulnerable", 20),
                                      self.result("8.4.27", "patched", 0)])
        self.assertEqual(code, 0)
        self.assertEqual(report["patch_differential"], "Confirmed")
        self.assertTrue(report["gate"]["pass"])
        self.assertEqual(report["tool"], "c_validate v2.2.0")
        self.assertIn("no tail window", report["counting"]["method"])

    def test_an_unknown_trial_fails_the_gate_and_is_never_a_clean_result(self):
        code, report = self.run_main([self.result("8.4.26", "vulnerable", 20),
                                      self.result("8.4.27", "patched", 0, unknown=3)])
        self.assertEqual(code, 1)
        self.assertEqual(report["patch_differential"], "Inconclusive")
        self.assertFalse(report["gate"]["pass"])
        self.assertTrue(any("corruption unknown" in reason for reason in report["gate"]["reasons"]))
        patched = report["targets"][1]["verdict"]
        self.assertEqual(patched["corruption_observed"], "Unknown")


if __name__ == "__main__":
    unittest.main()
