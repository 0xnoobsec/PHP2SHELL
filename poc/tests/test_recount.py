"""Recount the published October 2026 report from its published raw logs.

These tests read poc/c_validation.json and evidence/*.log as committed. They
pin the corrected figures in ERRATA.md to the files anyone can download.

    python3 -m unittest discover -s poc/tests -v
"""
import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
POC = os.path.join(HERE, "..")
ROOT = os.path.join(POC, "..")
sys.path.insert(0, POC)

from recount import recount_target, resolve_evidence, trial_windows  # noqa: E402

# The published layout keeps the logs in <repo>/evidence/. A lab that copied only
# poc/ keeps them in poc/evidence/. resolve_evidence() accepts both, so these
# tests run in either layout.
with open(os.path.join(POC, "c_validation.json"), "rb") as _handle:
    _REPORT_8426 = next(t for t in json.loads(_handle.read())["targets"] if t["name"] == "8.4.26")
LOG_8426 = resolve_evidence(ROOT, _REPORT_8426["evidence"]["path"], POC,
                            _REPORT_8426["evidence"]["sha256"])


def load_report():
    with open(os.path.join(POC, "c_validation.json"), "rb") as handle:
        return json.loads(handle.read())


class PublishedRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = load_report()
        cls.targets = {t["name"]: recount_target(t, ROOT, POC) for t in cls.report["targets"]}

    def test_every_evidence_log_matches_the_hash_in_the_report(self):
        for name, target in self.targets.items():
            self.assertTrue(target["evidence"]["found"], name)
            self.assertTrue(target["evidence"]["matches_report_hash"], name)

    def test_every_evidence_log_reaches_back_past_the_start_of_its_run(self):
        for name, target in self.targets.items():
            self.assertTrue(target["evidence"]["covers_run"], name)

    def test_vulnerable_build_aborted_with_heap_corruption_in_all_twenty_trials(self):
        recount = self.targets["8.4.26"]["recount"]
        self.assertEqual(recount["attribution"], "worker pid")
        self.assertEqual(recount["trials_with_heap_corruption"], 20)
        self.assertEqual(recount["trials_with_exit_notice"], 20)
        self.assertEqual(recount["exit_notices_in_run_window"], 20)
        self.assertEqual(recount["unattributed_notices"], 0)

    def test_each_trial_on_the_vulnerable_build_lost_exactly_one_worker(self):
        for trial in self.targets["8.4.26"]["per_trial"]:
            self.assertEqual(trial["exit_notices"], 1, trial)
            self.assertEqual(trial["signal"], "Abort", trial)
            self.assertNotEqual(trial["pid_before"], trial["pid_after"], trial)

    def test_report_under_counted_the_vulnerable_build(self):
        target = self.targets["8.4.26"]
        self.assertEqual(target["report"]["corruption"], 10)
        self.assertFalse(target["agrees_with_report"])
        missed = [t["trial"] for t in target["per_trial"]
                  if t["heap_corruption"] and not t["report_corruption"]]
        self.assertEqual(missed, list(range(9, 19)))

    def test_patched_builds_show_no_abort_at_all(self):
        for name in ("8.4.27", "8.2.35", "8.3.36", "8.5.12"):
            target = self.targets[name]
            self.assertEqual(target["recount"]["trials_with_heap_corruption"], 0, name)
            self.assertEqual(target["recount"]["exit_notices_in_run_window"], 0, name)
            self.assertEqual(target["evidence"]["heap_lines_total"], 0, name)
            self.assertEqual(target["evidence"]["exit_notices_total"], 0, name)
            self.assertTrue(target["agrees_with_report"], name)

    def test_every_build_reached_the_memory_limit_in_every_trial(self):
        for name, target in self.targets.items():
            self.assertEqual(target["report"]["oom"], 20, name)

    def test_committed_recount_file_is_what_the_tool_produces(self):
        with open(os.path.join(POC, "c_validation_recount.json"), "rb") as handle:
            committed = json.loads(handle.read())
        self.assertEqual(committed["targets"], list(self.targets.values()))
        with open(os.path.join(POC, "c_validation.json"), "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(committed["source_report"]["sha256"], digest)


class WholeCapturedLog(unittest.TestCase):
    """The figures ERRATA.md gives for the rest of evidence/8.4.26.log.

    In that log the out-of-memory response to request A is 421 bytes. A request
    is "followed by an abort" when an exit notice appears before the next POST.
    """

    OOM_BYTES = 421

    @classmethod
    def setUpClass(cls):
        import re
        with open(LOG_8426, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        post = re.compile(r'\[\d+/\w+/\d+:(\d\d:\d\d:\d\d) \+0000\] "POST /decode\.php [^"]+" 200 (\d+)')
        found = [(i, m.group(1), int(m.group(2))) for i, line in enumerate(lines)
                 for m in [post.search(line)] if m]
        cls.requests = []
        for k, (index, stamp, size) in enumerate(found):
            end = found[k + 1][0] if k + 1 < len(found) else len(lines)
            aborted = any("exit signal" in line for line in lines[index + 1:end])
            cls.requests.append((stamp, size, aborted))

    def oom(self, start="00:00:00", end="24:00:00"):
        return [(stamp, aborted) for stamp, size, aborted in self.requests
                if size == self.OOM_BYTES and start <= stamp < end]

    def test_ninety_two_out_of_memory_responses_eighty_seven_followed_by_an_abort(self):
        rows = self.oom()
        self.assertEqual(len(rows), 92)
        self.assertEqual(sum(1 for _stamp, aborted in rows if aborted), 87)

    def test_every_one_in_the_minimizer_window_was_followed_by_an_abort(self):
        rows = self.oom("20:04:38", "20:23:15")
        self.assertEqual(len(rows), 42)
        self.assertTrue(all(aborted for _stamp, aborted in rows))

    def test_the_earlier_stretch_of_twenty_all_aborted(self):
        rows = self.oom("20:42:00", "20:46:00")
        self.assertEqual(len(rows), 20)
        self.assertTrue(all(aborted for _stamp, aborted in rows))

    def test_two_rounds_of_five_trials_alternate(self):
        first = [aborted for _stamp, aborted in self.oom("20:23:41", "20:24:30")]
        second = [aborted for _stamp, aborted in self.oom("20:24:30", "20:25:40")]
        self.assertEqual(first, [False, True, False, True, False])   # abort in 2 of 5
        self.assertEqual(second, [True, False, True, False, True])   # abort in 3 of 5
        # these ten are the only out-of-memory responses with a surviving worker
        survivors = [stamp for stamp, aborted in self.oom() if not aborted]
        self.assertEqual(survivors, ["20:23:41", "20:23:56", "20:24:12", "20:25:05", "20:25:21"])


ACCESS = '172.17.0.1 - - [22/Oct/2026:%s +0000] "POST /decode.php HTTP/1.1" 200 421 "-" "x"'
HEAP = "zend_mm_heap corrupted"
NOTICE = ("[Thu Oct 22 %s.500000 2026] [core:notice] [pid 1:tid 1] AH00051: "
          "child pid %d exit signal Abort (6), possible coredump in /etc/apache2")


def record(trial, stamp, pid_before=None, pid_after=None, corruption=False):
    return {"trial": trial, "ts": "2026-10-22T%s.900000Z" % stamp, "oom": True,
            "corruption": corruption, "worker_aborted": corruption,
            "pid_before": pid_before, "pid_after": pid_after}


class SyntheticReports(unittest.TestCase):
    """Cases the published run does not contain."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def target(self, lines, records):
        path = os.path.join(self.tmp.name, "evidence", "t.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = ("\n".join(lines) + "\n").encode("utf-8")
        with open(path, "wb") as handle:
            handle.write(data)
        return {"name": "t", "kind": "vulnerable", "records": records,
                "evidence": {"path": "evidence/t.log", "sha256": hashlib.sha256(data).hexdigest()}}

    def test_a_worker_that_survives_early_trials_is_charged_only_where_it_died(self):
        # One worker (pid 7) serves three trials and dies in the third.
        lines = [ACCESS % "21:05:00", ACCESS % "21:05:09", ACCESS % "21:05:18",
                 HEAP, NOTICE % ("21:05:27", 7), ACCESS % "21:05:28"]
        records = [record(0, "21:05:09", 7, 7), record(1, "21:05:18", 7, 7),
                   record(2, "21:05:27", 7, 8, corruption=True)]
        result = recount_target(self.target(lines, records), self.tmp.name)
        self.assertEqual([t["heap_corruption"] for t in result["per_trial"]], [False, False, True])
        self.assertEqual(result["recount"]["trials_with_heap_corruption"], 1)
        self.assertEqual(result["recount"]["unattributed_notices"], 0)
        self.assertTrue(result["agrees_with_report"])

    def test_without_pids_notices_are_matched_by_time(self):
        lines = [ACCESS % "21:05:00", HEAP, NOTICE % ("21:05:08", 40),
                 ACCESS % "21:05:09", ACCESS % "21:05:18", HEAP, NOTICE % ("21:05:26", 41),
                 ACCESS % "21:05:28"]
        records = [record(0, "21:05:09"), record(1, "21:05:18"), record(2, "21:05:27")]
        result = recount_target(self.target(lines, records), self.tmp.name)
        self.assertEqual(result["recount"]["attribution"], "time window")
        self.assertEqual([t["heap_corruption"] for t in result["per_trial"]], [True, False, True])
        self.assertFalse(result["agrees_with_report"])  # the records all say "no corruption"

    def test_an_abort_without_the_allocator_message_is_an_abort_but_not_corruption(self):
        lines = [ACCESS % "21:05:00", NOTICE % ("21:05:08", 40), ACCESS % "21:05:10"]
        result = recount_target(self.target(lines, [record(0, "21:05:09", 40, 41)]), self.tmp.name)
        trial = result["per_trial"][0]
        self.assertEqual((trial["exit_notices"], trial["heap_corruption"]), (1, False))

    def test_a_log_that_stops_before_the_last_trial_does_not_cover_the_run(self):
        lines = [ACCESS % "21:05:00", ACCESS % "21:05:09"]
        records = [record(0, "21:05:09"), record(1, "21:05:18"), record(2, "21:05:27")]
        result = recount_target(self.target(lines, records), self.tmp.name)
        self.assertFalse(result["evidence"]["covers_run"])

    def test_a_log_that_starts_after_the_run_began_does_not_cover_the_run(self):
        lines = [ACCESS % "21:05:20", ACCESS % "21:05:28"]
        records = [record(0, "21:05:09"), record(1, "21:05:18"), record(2, "21:05:27")]
        result = recount_target(self.target(lines, records), self.tmp.name)
        self.assertFalse(result["evidence"]["covers_run"])

    def test_a_record_without_a_timestamp_is_an_error_not_a_guess(self):
        records = [record(0, "21:05:09"), {"trial": 1, "oom": True}]
        with self.assertRaises(ValueError) as caught:
            recount_target(self.target([ACCESS % "21:05:00"], records), self.tmp.name)
        self.assertIn("no 'ts'", str(caught.exception))

    def test_a_target_without_records_is_reported_not_crashed(self):
        result = recount_target(self.target([ACCESS % "21:05:00"], []), self.tmp.name)
        self.assertIsNone(result["recount"])
        self.assertIsNone(result["agrees_with_report"])

    def test_a_missing_evidence_file_is_reported(self):
        target = {"name": "t", "kind": "patched", "records": [record(0, "21:05:09")],
                  "evidence": {"path": "evidence/absent.log", "sha256": "0" * 64}}
        result = recount_target(target, self.tmp.name)
        self.assertFalse(result["evidence"]["found"])
        self.assertIsNone(result["recount"])



class CommandLine(unittest.TestCase):
    """The tool must fail closed: missing evidence is not agreement."""

    def test_missing_evidence_exits_nonzero_and_says_inconclusive(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            report = {
                "tool": "c_validate v2.2.0",
                "generated": "2026-10-22T21:20:05.180456Z",
                "targets": [{
                    "name": "t",
                    "kind": "patched",
                    "records": [{"trial": 0, "ts": "2026-10-22T21:05:09.000000Z",
                                 "corruption": False, "pid_before": 1}],
                    "evidence": {"path": "evidence/absent.log", "sha256": "0" * 64},
                }],
            }
            path = os.path.join(tmp, "c_validation.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report, handle)
            proc = subprocess.run(
                [sys.executable, os.path.join(POC, "recount.py"),
                 "--report", path, "--root", tmp],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("INCONCLUSIVE", proc.stdout)
            self.assertNotIn("The recount agrees", proc.stdout)


class FailsClosed(unittest.TestCase):
    """Evidence that exists but cannot support a verdict is not agreement either."""

    # Three clean trials, nine seconds apart; the run starts about 21:04:56.
    RECORDS = [record(0, "21:05:09"), record(1, "21:05:18"), record(2, "21:05:27")]
    COMPLETE = [ACCESS % "21:04:50", ACCESS % "21:05:09", ACCESS % "21:05:18",
                ACCESS % "21:05:28"]

    def run_tool(self, targets, logs, *extra):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            for rel, (lines, hash_is_right) in logs.items():
                data = ("\n".join(lines) + "\n").encode("utf-8")
                os.makedirs(os.path.join(tmp, os.path.dirname(rel)), exist_ok=True)
                with open(os.path.join(tmp, rel), "wb") as handle:
                    handle.write(data)
                for target in targets:
                    if target["evidence"]["path"] == rel:
                        target["evidence"]["sha256"] = (
                            hashlib.sha256(data).hexdigest() if hash_is_right else "0" * 64)
            report = os.path.join(tmp, "c_validation.json")
            out = os.path.join(tmp, "recount.json")
            with open(report, "w", encoding="utf-8") as handle:
                json.dump({"tool": "test", "generated": "x", "targets": targets}, handle)
            proc = subprocess.run(
                [sys.executable, os.path.join(POC, "recount.py"), "--report", report,
                 "--root", tmp, "--out", out, *extra],
                capture_output=True, text=True)
            with open(out, encoding="utf-8") as handle:
                return proc, json.load(handle)

    def target(self, name, path, records=None):
        return {"name": name, "kind": "patched",
                "records": [dict(r) for r in (records or self.RECORDS)],
                "evidence": {"path": path, "sha256": ""}}

    def assert_inconclusive(self, proc, result):
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("INCONCLUSIVE", proc.stdout)
        self.assertNotIn("The recount agrees", proc.stdout)
        self.assertIsNone(result["agrees_with_report"])

    def test_complete_log_with_the_right_hash_agrees(self):
        # the positive control for the cases below
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (self.COMPLETE, True)})
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("The recount agrees with the report.", proc.stdout)
        self.assertIs(result["agrees_with_report"], True)

    def test_the_log_whose_hash_matches_wins_over_an_unrelated_one(self):
        # A later run left its own evidence/ at the root, next to an older report
        # kept with its logs (found while staging on the lab, 18 November 2026).
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            right = ("\n".join(self.COMPLETE) + "\n").encode()
            wrong = b"an unrelated, later log\n"
            for folder, data in ((tmp, wrong), (os.path.join(tmp, "poc"), right)):
                os.makedirs(os.path.join(folder, "evidence"), exist_ok=True)
                with open(os.path.join(folder, "evidence", "t.log"), "wb") as handle:
                    handle.write(data)
            chosen = resolve_evidence(tmp, "evidence/t.log", os.path.join(tmp, "poc"),
                                      hashlib.sha256(right).hexdigest())
            self.assertEqual(os.path.normpath(chosen), os.path.join(tmp, "poc", "evidence", "t.log"))
            # without a matching file the root is still the default
            fallback = resolve_evidence(tmp, "evidence/t.log", os.path.join(tmp, "poc"), "0" * 64)
            self.assertEqual(os.path.normpath(fallback), os.path.join(tmp, "evidence", "t.log"))

    def test_a_whole_container_log_covers_its_run(self):
        # Starts with Apache's start-up notice; the first request is the run's own.
        startup = ("[Thu Oct 22 21:04:30.000001 2026] [mpm_prefork:notice] [pid 1:tid 1] "
                   "AH00163: Apache/2.4.69 (Debian) PHP/8.4.26 configured")
        log = [startup, ACCESS % "21:05:00", ACCESS % "21:05:09", ACCESS % "21:05:18",
               ACCESS % "21:05:28"]
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (log, True)})
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("does not span", proc.stdout)
        self.assertIs(result["agrees_with_report"], True)

    def test_a_log_that_is_not_the_hashed_file_is_inconclusive(self):
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (self.COMPLETE, False)})
        self.assert_inconclusive(proc, result)
        self.assertIn("does not match the hash", proc.stdout)

    def test_a_log_that_stops_before_the_last_trial_is_inconclusive(self):
        partial = [ACCESS % "21:04:50", ACCESS % "21:05:09"]
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (partial, True)})
        self.assert_inconclusive(proc, result)

    def test_a_log_that_starts_after_the_run_began_is_inconclusive(self):
        late = [ACCESS % "21:05:20", ACCESS % "21:05:28"]
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (late, True)})
        self.assert_inconclusive(proc, result)

    def test_a_log_without_timestamps_is_inconclusive(self):
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (["hello", "world"], True)})
        self.assert_inconclusive(proc, result)

    def test_a_log_in_another_time_zone_is_inconclusive(self):
        shifted = [line.replace("+0000", "+0600") for line in self.COMPLETE]
        proc, result = self.run_tool([self.target("t", "evidence/t.log")],
                                     {"evidence/t.log": (shifted, True)})
        self.assert_inconclusive(proc, result)
        self.assertIn("not in UTC", proc.stdout)

    def test_a_known_disagreement_is_reported_beside_a_missing_log(self):
        aborting = [ACCESS % "21:04:50", HEAP, NOTICE % ("21:05:08", 40), ACCESS % "21:05:09",
                    ACCESS % "21:05:18", ACCESS % "21:05:28"]
        proc, result = self.run_tool(
            [self.target("vuln", "evidence/v.log"), self.target("other", "evidence/absent.log")],
            {"evidence/v.log": (aborting, True)})
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("DISAGREES", proc.stdout)
        self.assertIn("(vuln)", proc.stdout)
        self.assertIn("INCONCLUSIVE for other", proc.stdout)
        self.assertIs(result["agrees_with_report"], False)


class TrialWindows(unittest.TestCase):
    def test_each_window_runs_from_the_previous_timestamp_to_its_own(self):
        base = datetime(2026, 10, 22, 21, 5, 0, tzinfo=timezone.utc)
        times = [base + timedelta(seconds=9 * i) for i in range(3)]
        windows = trial_windows(times)
        self.assertEqual(len(windows), 3)
        # the first trial started about one trial-length before its timestamp
        self.assertEqual(windows[0][0], base - timedelta(seconds=13.5))
        self.assertEqual(windows[1][0], times[0])
        self.assertEqual(windows[2][0], times[1])
        for (start, end), stamp in zip(windows, times):
            self.assertLess(start, stamp)
            self.assertGreaterEqual(end, stamp)

    def test_single_trial_gets_a_window(self):
        stamp = datetime(2026, 10, 22, 21, 5, 0, tzinfo=timezone.utc)
        (start, end), = trial_windows([stamp])
        self.assertLess(start, stamp)
        self.assertGreaterEqual(end, stamp)


if __name__ == "__main__":
    unittest.main()
