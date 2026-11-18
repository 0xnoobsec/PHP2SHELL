"""What php2shell.py is allowed to claim for Category C, and what it sends.

An out-of-memory error is reached on every patched build, so it must never be
reported as a result, and a corruption line left in the log by an earlier run
must not confirm the current one.

The second half compares the current file with archive/php2shell_v17.py, the
version it was derived from: in every branch the method chain has to stop or
continue exactly where it did before, so the requests sent are the same.

No request leaves the process: the HTTP session and the verify command are
fakes.

    python3 -m unittest discover -s poc/tests -v
"""
import argparse
import importlib.util
import os
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
POC = os.path.join(HERE, "..")
sys.path.insert(0, POC)

try:
    import php2shell
except ImportError as error:  # needs the third-party `requests` module
    php2shell = None
    IMPORT_ERROR = str(error)
else:
    IMPORT_ERROR = ""

OOM_BODY = "Fatal error: Allowed memory size of 16777216 bytes exhausted"
HEAP = "zend_mm_heap corrupted"
URL = "http://127.0.0.1:1/decode.php"


class FakeResponse:
    def __init__(self, text):
        self.text = text
        self.status_code = 200


class FakeSession:
    """Answers every POST; the first of each A/B pair gets the OOM body."""

    def __init__(self, oom=True):
        self.oom = oom
        self.posts = 0
        self.session_ids = []  # the PHPSESSID cookie sent with each POST, or None

    def post(self, url, data=None, headers=None, timeout=None, **kwargs):
        self.posts += 1
        self.session_ids.append((kwargs.get("cookies") or {}).get("PHPSESSID"))
        if data is not None and not isinstance(data, (bytes, str)):
            b"".join(data)  # drain the chunked body like a real client would
        is_request_a = self.posts % 2 == 1
        return FakeResponse(OOM_BODY if (self.oom and is_request_a) else "ok")


class FakeCompleted:
    def __init__(self, text):
        self.stdout = text.encode("utf-8")


def verify_runner(outputs):
    """A subprocess.run stand-in: one output per call, the last one repeating."""
    remaining = list(outputs)

    def run(*args, **kwargs):
        return FakeCompleted(remaining.pop(0) if len(remaining) > 1 else remaining[0])
    return run


def arguments(verify_cmd=None):
    return argparse.Namespace(heap_parts=2, heap_depth=2, heap_rounds=3, verify_cmd=verify_cmd)


def run_chain(module, session, verify_outputs):
    """Run c_heap_corrupt as the first of two methods, the way -m c does.

    Returns (chain outcome, was the next method reached, result object).
    """
    result = module.Result(URL)
    reached = []
    methods = [
        ("heap_corrupt", lambda: module.c_heap_corrupt(
            URL, session, result, arguments("print-log" if verify_outputs else None))),
        ("next_method", lambda: (reached.append(True) and False, "sentinel")),
    ]
    runner = verify_runner(verify_outputs) if verify_outputs else (lambda *a, **k: FakeCompleted(""))
    with mock.patch("subprocess.run", runner), \
            mock.patch.object(module.time, "sleep", lambda seconds: None), \
            mock.patch("builtins.print"):
        outcome = module.try_methods(result, "C", methods, time.time() + 600)
    return outcome, bool(reached), result


def finding(result, tag):
    return next((f for f in result.findings if f["tag"] == tag), None)


STALE = "\n".join(["access", HEAP, "notice"])
GREW = STALE + "\n" + "\n".join(["access", HEAP, "notice"])


@unittest.skipIf(php2shell is None, "php2shell not importable: %s" % IMPORT_ERROR)
class HeapCorruptReporting(unittest.TestCase):
    def test_oom_alone_is_a_precondition_not_a_result(self):
        outcome, _reached, result = run_chain(php2shell, FakeSession(oom=True), None)
        self.assertEqual(outcome, php2shell.PRECONDITION_ONLY)
        self.assertIsNot(outcome, True)
        oom = finding(result, "heap_oom_bucket")
        self.assertEqual(oom["severity"], "info")
        self.assertIn("not evidence of corruption", oom["detail"])
        method = finding(result, "method_C_heap_corrupt")
        self.assertEqual(method["severity"], "info")
        self.assertTrue(method["detail"].startswith("precondition only"))
        self.assertNotIn("LANDED", method["detail"])
        self.assertIsNone(finding(result, "heap_corruption_confirmed"))

    def test_no_oom_is_a_plain_failure(self):
        outcome, reached, result = run_chain(php2shell, FakeSession(oom=False), None)
        self.assertIs(outcome, False)
        self.assertTrue(reached)
        self.assertIn("no OOM", finding(result, "method_C_heap_corrupt")["detail"])

    def test_a_corruption_line_from_an_earlier_run_does_not_confirm_this_one(self):
        outcome, _reached, result = run_chain(php2shell, FakeSession(oom=True), [STALE, STALE])
        self.assertIs(outcome, False)
        self.assertIsNone(finding(result, "heap_corruption_confirmed"))
        self.assertIn("no new corruption line", finding(result, "method_C_heap_corrupt")["detail"])

    def test_a_new_corruption_line_during_the_run_confirms_it(self):
        outcome, reached, result = run_chain(php2shell, FakeSession(oom=True), [STALE, GREW])
        self.assertIs(outcome, True)
        self.assertFalse(reached)
        confirmed = finding(result, "heap_corruption_confirmed")
        self.assertEqual(confirmed["severity"], "critical")
        self.assertIn("1 new", confirmed["detail"])

    def test_an_exit_notice_without_the_allocator_message_is_not_corruption(self):
        notice = "[core:notice] AH00051: child pid 9 exit signal Abort (6)"
        outcome, _reached, result = run_chain(php2shell, FakeSession(oom=True), ["", notice])
        self.assertIs(outcome, False)
        self.assertIsNone(finding(result, "heap_corruption_confirmed"))

    def test_each_round_sends_one_session_id_with_both_requests(self):
        # Without a session id the upload-progress callback never starts the
        # session during parsing, and the trigger only reaches the memory limit.
        session = FakeSession(oom=True)
        run_chain(php2shell, session, None)
        ids = session.session_ids
        self.assertEqual(len(ids), 6)                       # three rounds of A then B
        self.assertTrue(all(ids), ids)                      # every request carries one
        self.assertEqual(ids[0::2], ids[1::2])              # A and B share it
        self.assertEqual(len(set(ids[0::2])), 3)            # a new one each round

    def test_the_phrase_inside_a_request_line_is_not_corruption(self):
        request = '10.0.0.1 - - [x] "GET /?q=1 HTTP/1.1" 200 5 "-" "zend_mm_heap corrupted"'
        outcome, _reached, result = run_chain(php2shell, FakeSession(oom=True), ["", request])
        self.assertIs(outcome, False)
        self.assertIsNone(finding(result, "heap_corruption_confirmed"))

    def test_a_shrinking_verify_output_is_reported_not_trusted(self):
        outcome, _reached, result = run_chain(php2shell, FakeSession(oom=True), [GREW, STALE])
        self.assertIs(outcome, False)
        self.assertIsNotNone(finding(result, "verify_log_shrank"))
        self.assertIsNone(finding(result, "heap_corruption_confirmed"))


@unittest.skipIf(php2shell is None, "php2shell not importable: %s" % IMPORT_ERROR)
class Wording(unittest.TestCase):
    def test_outcome_text(self):
        text = php2shell.outcome_text
        self.assertEqual(text("A", True), "command execution")
        self.assertEqual(text("B", True), "command execution")
        self.assertIn("not code execution", text("C", True))
        self.assertIn("corruption not verified", text("C", php2shell.PRECONDITION_ONLY))
        self.assertEqual(text("C", False), "no result")

    def test_version_in_the_docstring_matches_the_code(self):
        self.assertIn("php2shell v%s" % php2shell.VERSION, php2shell.__doc__)

    def test_source_never_labels_category_c_as_code_execution(self):
        with open(php2shell.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("RCE/PROVEN", source)


def load_v17():
    spec = importlib.util.spec_from_file_location(
        "php2shell_v17", os.path.join(POC, "archive", "php2shell_v17.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(php2shell is None, "php2shell not importable: %s" % IMPORT_ERROR)
class SameRequestsAsV17(unittest.TestCase):
    """The chain must stop or continue exactly where v17 did."""

    @classmethod
    def setUpClass(cls):
        cls.v17 = load_v17()

    def both(self, oom, verify_outputs):
        old = run_chain(self.v17, FakeSession(oom=oom), verify_outputs)
        new = run_chain(php2shell, FakeSession(oom=oom), verify_outputs)
        return old, new

    def assert_same_flow(self, oom, verify_outputs):
        (old_outcome, old_reached, _), (new_outcome, new_reached, _) = self.both(oom, verify_outputs)
        self.assertEqual(new_reached, old_reached)
        self.assertEqual(bool(new_outcome), bool(old_outcome))
        return old_outcome, new_outcome

    def test_oom_without_a_verify_command_stops_the_chain_in_both(self):
        old, new = self.assert_same_flow(True, None)
        self.assertIs(old, True)                        # v17 called it a success
        self.assertEqual(new, php2shell.PRECONDITION_ONLY)

    def test_no_oom_continues_in_both(self):
        self.assert_same_flow(False, None)

    def test_unconfirmed_oom_with_a_verify_command_continues_in_both(self):
        self.assert_same_flow(True, ["", ""])

    def test_confirmed_corruption_stops_in_both(self):
        self.assert_same_flow(True, [STALE, GREW])

    def test_same_number_of_requests_to_the_target(self):
        for verify_outputs in (None, ["", ""], [STALE, GREW]):
            old_session, new_session = FakeSession(), FakeSession()
            run_chain(self.v17, old_session, verify_outputs)
            run_chain(php2shell, new_session, verify_outputs)
            self.assertEqual(new_session.posts, old_session.posts)

    def run_main_mode_c(self, module):
        """The whole `-m c` path with a fake network: (printed lines, GETs, POSTs)."""
        fake = FakeSession(oom=True)
        gets = []

        def get(url, **kwargs):
            gets.append(url)
            response = FakeResponse("")
            response.headers = {}
            response.cookies = []
            return response
        fake.get = get
        printed = []
        with mock.patch.object(module, "session", lambda *a, **k: fake), \
                mock.patch.object(sys, "argv", ["php2shell.py", URL, "-m", "c"]), \
                mock.patch.object(module.time, "sleep", lambda seconds: None), \
                mock.patch("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a)))):
            code = module.main()
        self.assertEqual(code, 0)
        return printed, len(gets), fake.posts

    def test_mode_c_end_to_end_sends_the_same_requests_and_changes_only_the_verdict(self):
        old_printed, old_gets, old_posts = self.run_main_mode_c(self.v17)
        new_printed, new_gets, new_posts = self.run_main_mode_c(php2shell)
        self.assertEqual((new_gets, new_posts), (old_gets, old_posts))
        self.assertEqual(new_posts, 6)  # three A/B rounds, then the chain stops
        self.assertIn("RESULT: SUCCESS", "\n".join(old_printed))
        result_line = [line for line in new_printed if "RESULT:" in line][-1]
        self.assertIn("no result", result_line)
        self.assertIn("corruption not verified", result_line)
        self.assertNotIn("SUCCESS", "\n".join(new_printed))

    def test_the_one_intended_difference_is_a_stale_line(self):
        # v17 confirmed corruption from a line that predates the run and stopped.
        # That was a false result; the current version does not confirm it.
        (old_outcome, old_reached, _), (new_outcome, new_reached, _) = self.both(True, [STALE, STALE])
        self.assertIs(old_outcome, True)
        self.assertFalse(old_reached)
        self.assertIs(new_outcome, False)
        self.assertTrue(new_reached)


if __name__ == "__main__":
    unittest.main()
