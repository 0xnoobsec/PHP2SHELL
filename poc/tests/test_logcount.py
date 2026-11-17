"""Tests for the abort counter.

Run from the repository root:

    python3 -m unittest discover -s poc/tests -v

No Docker, no lab and no network: everything here works on text.
"""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from logcount import (  # noqa: E402
    access_log_offsets,
    count_signals,
    delta,
    earliest_time,
    log_time_span,
    parse_exit_notices,
)

ACCESS = '172.17.0.1 - - [22/Oct/2026:21:04:%02d +0000] "POST /decode.php HTTP/1.1" 200 421 "-" "x"'
HEAP = "zend_mm_heap corrupted"
NOTICE = ("[Thu Oct 22 21:05:%02d.549439 2026] [core:notice] [pid 1:tid 1] AH00051: "
          "child pid %d exit signal Abort (6), possible coredump in /etc/apache2")


def abort_block(second, pid):
    """The three lines one aborting trial leaves in the log."""
    return [ACCESS % second, HEAP, NOTICE % (second, pid)]


def tail_window_count(lines, window=400):
    """What v2.1.0 measured: matching lines among the last `window` lines."""
    return sum(1 for line in lines[-window:]
               if HEAP in line or "exit signal" in line or "Segmentation fault" in line)


class CountSignals(unittest.TestCase):
    def test_counts_each_kind_of_line_separately(self):
        text = "\n".join(abort_block(1, 329) + [ACCESS % 2])
        self.assertEqual(count_signals(text), {"lines": 4, "heap": 1, "exit": 1, "segv": 0})

    def test_one_abort_is_one_heap_line_and_one_exit_notice_not_two_aborts(self):
        counts = count_signals("\n".join(abort_block(1, 329)))
        self.assertEqual((counts["heap"], counts["exit"]), (1, 1))

    def test_segfault_notice_counts_as_exit_and_segv(self):
        line = ("[Thu Oct 22 21:05:01.000001 2026] [core:notice] [pid 1:tid 1] AH00052: "
                "child pid 7 exit signal Segmentation fault (11)")
        self.assertEqual(count_signals(line), {"lines": 1, "heap": 0, "exit": 1, "segv": 1})

    def test_empty_log(self):
        self.assertEqual(count_signals(""), {"lines": 0, "heap": 0, "exit": 0, "segv": 0})


class Delta(unittest.TestCase):
    def test_reports_what_appeared_between_two_counts(self):
        before = count_signals("\n".join(abort_block(1, 329)))
        after = count_signals("\n".join(abort_block(1, 329) + abort_block(10, 403)))
        self.assertEqual(delta(before, after), {"lines": 3, "heap": 1, "exit": 1, "segv": 0})

    def test_unreadable_log_is_unknown_not_zero(self):
        counts = count_signals(ACCESS % 1)
        self.assertIsNone(delta(None, counts))
        self.assertIsNone(delta(counts, None))

    def test_shorter_log_is_unknown(self):
        long_log = count_signals("\n".join(abort_block(1, 329) + abort_block(10, 403)))
        short_log = count_signals(ACCESS % 1)
        self.assertIsNone(delta(long_log, short_log))


class SlidingWindowRegression(unittest.TestCase):
    """The bug behind the published 10/20: a tail count stops rising."""

    def setUp(self):
        # A long-lived container: its log already holds many earlier aborts.
        self.log = []
        for i in range(140):
            self.log += abort_block(i % 60, 100 + i)

    def test_tail_count_misses_an_abort_that_the_whole_log_count_sees(self):
        before_lines = list(self.log)
        after_lines = before_lines + abort_block(30, 999)

        # v2.1.0: old abort lines leave the 400-line window as the new ones enter.
        self.assertEqual(tail_window_count(after_lines) - tail_window_count(before_lines), 0)

        # v2.2.0: the whole log, so the new abort is counted.
        change = delta(count_signals("\n".join(before_lines)), count_signals("\n".join(after_lines)))
        self.assertEqual((change["heap"], change["exit"]), (1, 1))

    def test_twenty_aborting_trials_are_all_counted(self):
        seen = 0
        for trial in range(20):
            before = count_signals("\n".join(self.log))
            self.log += abort_block(trial, 2000 + trial)
            if delta(before, count_signals("\n".join(self.log)))["heap"] > 0:
                seen += 1
        self.assertEqual(seen, 20)


class ParseExitNotices(unittest.TestCase):
    def test_reads_pid_signal_time_and_the_heap_line_above(self):
        notices = parse_exit_notices("\n".join(abort_block(1, 329)))
        self.assertEqual(len(notices), 1)
        notice = notices[0]
        self.assertEqual((notice["pid"], notice["signal"], notice["signo"], notice["line"]),
                         (329, "Abort", 6, 3))
        self.assertTrue(notice["heap_line_before"])
        self.assertEqual(notice["time"],
                         datetime(2026, 10, 22, 21, 5, 1, 549439, tzinfo=timezone.utc))

    def test_notice_without_a_heap_line_above_is_not_heap_corruption(self):
        text = "\n".join([ACCESS % 1, NOTICE % (1, 5)])
        self.assertFalse(parse_exit_notices(text)[0]["heap_line_before"])

    def test_single_digit_day_is_parsed(self):
        line = ("[Mon Nov  2 09:00:00.000001 2026] [core:notice] [pid 1:tid 1] AH00051: "
                "child pid 12 exit signal Abort (6)")
        self.assertEqual(parse_exit_notices(line)[0]["time"].day, 2)

    def test_ordinary_lines_are_ignored(self):
        self.assertEqual(parse_exit_notices("\n".join([ACCESS % 1, HEAP])), [])


class LogTimes(unittest.TestCase):
    def test_offsets_and_earliest_time(self):
        text = "\n".join([ACCESS % 5] + abort_block(9, 329))
        self.assertEqual(access_log_offsets(text), {"+0000"})
        self.assertEqual(earliest_time(text),
                         datetime(2026, 10, 22, 21, 4, 5, tzinfo=timezone.utc))

    def test_log_without_timestamps(self):
        self.assertIsNone(earliest_time(HEAP))
        self.assertEqual(log_time_span(HEAP), (None, None))

    def test_span_runs_from_the_first_to_the_last_timestamp(self):
        text = "\n".join([ACCESS % 5] + abort_block(9, 329))
        first, last = log_time_span(text)
        self.assertEqual(first, datetime(2026, 10, 22, 21, 4, 5, tzinfo=timezone.utc))
        self.assertEqual(last, datetime(2026, 10, 22, 21, 5, 9, 549439, tzinfo=timezone.utc))


class RequestLinesAreNotServerMessages(unittest.TestCase):
    """A client controls the URL and the User-Agent; neither may count as an abort."""

    SPOOF = ('10.0.0.1 - - [22/Oct/2026:21:04:54 +0000] "GET /?child pid 5 exit signal Abort (6) '
             'HTTP/1.1" 200 5 "-" "zend_mm_heap corrupted Segmentation fault"')

    def test_marker_text_in_a_request_line_is_not_counted(self):
        self.assertEqual(count_signals(self.SPOOF), {"lines": 1, "heap": 0, "exit": 0, "segv": 0})

    def test_a_spoofed_line_above_a_real_notice_is_not_a_heap_line(self):
        notices = parse_exit_notices("\n".join([self.SPOOF, NOTICE % (1, 5)]))
        self.assertEqual(len(notices), 1)
        self.assertFalse(notices[0]["heap_line_before"])


if __name__ == "__main__":
    unittest.main()
