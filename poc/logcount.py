#!/usr/bin/env python3
"""logcount -- count worker-abort signals in a container log, without a window.

Why this module exists
----------------------
c_validate.py and c_minimize.py used to decide "did this trial corrupt the
heap?" by running

    docker logs --tail 400 <container> | grep -cE '<patterns>'

before and after the trial and comparing the two numbers.

A tail is a sliding window. Once the log is longer than the window, every new
line pushes an old one out. When the lines leaving the window also match the
pattern, the count stops rising (or falls) while aborts are still happening,
and the trial is recorded as clean. On the 20-trial run against PHP 8.4.26
that marked ten trials "no corruption" although the worker aborted with
"zend_mm_heap corrupted" in all twenty. See ERRATA.md.

Two more problems sat in the same counter:

* the pattern matched two lines per abort (the allocator's message and
  Apache's exit notice), so the number was a line count, not an abort count;
* when the log could not be read at all, the trial was recorded as "no
  corruption" instead of "unknown".

The rules here:

1. count over the whole log, never over a tail;
2. count each kind of line separately;
3. an unreadable log is unknown (None), never zero.

Standard library only, so it can be tested without Docker or a lab.
"""
import re
import subprocess
from datetime import datetime, timezone

HEAP_MARK = "zend_mm_heap corrupted"
SEGV_MARK = "Segmentation fault"

# A request line in Apache's common or combined log format. Whatever a client
# puts in the URL or the User-Agent is copied into such a line, so a request
# line is never read as a message from the server.
_ACCESS_LINE = re.compile(
    r"^\S+ \S+ \S+ \[\d{2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\] \""
)
_EXIT_ANY = re.compile(r"child pid \d+ exit signal ")

# Apache error-log line written by the parent when it reaps a dead child, e.g.
# [Thu Oct 22 21:05:01.549439 2026] [core:notice] [pid 1:tid 1] AH00051: child pid 329 exit signal Abort (6), ...
_EXIT_NOTICE = re.compile(
    r"^\[(?P<ts>[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d\d:\d\d:\d\d\.\d+ \d{4})\]"
    r".*child pid (?P<pid>\d+) exit signal (?P<signal>[A-Za-z][A-Za-z ]*?) \((?P<signo>\d+)\)"
)
# Access-log request time, e.g. [22/Oct/2026:21:04:54 +0000]
_ACCESS_TIME = re.compile(
    r"\[(?P<stamp>\d{2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d (?P<offset>[+-]\d{4}))\]"
)


def count_signals(text):
    """Count abort-related lines in a complete log.

    Returns {"lines", "heap", "exit", "segv"}:
      heap  lines carrying the allocator's "zend_mm_heap corrupted" message;
      exit  Apache "child pid N exit signal ..." notices, one per dead worker;
      segv  lines mentioning a segmentation fault.

    Access-log request lines are skipped for all three: a client can put any
    text into a URL or a User-Agent, and that must not count as an abort.
    """
    lines = text.splitlines()
    server = [line for line in lines if not _ACCESS_LINE.match(line)]
    return {
        "lines": len(lines),
        "heap": sum(1 for line in server if HEAP_MARK in line),
        "exit": sum(1 for line in server if _EXIT_ANY.search(line)),
        "segv": sum(1 for line in server if SEGV_MARK in line),
    }


def delta(before, after):
    """What appeared in the log between two whole-log counts.

    Returns None when either count is missing, or when the log got shorter
    (the container was restarted or its log rotated), because the difference
    then says nothing about the trial.
    """
    if before is None or after is None:
        return None
    if after["lines"] < before["lines"]:
        return None
    return {key: after[key] - before[key] for key in ("lines", "heap", "exit", "segv")}


def read_container_log(container, timeout=60):
    """The complete log of a container (stdout and stderr), or None.

    No --tail on purpose: see the module docstring.
    """
    if not container:
        return None
    try:
        done = subprocess.run(
            ["docker", "logs", container],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.decode("utf-8", "replace")


def container_counts(container, timeout=60):
    """count_signals() over a container's complete log, or None if unreadable."""
    text = read_container_log(container, timeout=timeout)
    return None if text is None else count_signals(text)


def parse_exit_notices(text, tz=timezone.utc):
    """Every worker-exit notice in a log, in order.

    Each item: {"line", "pid", "signal", "signo", "time", "heap_line_before"}.
    "heap_line_before" is True when the line directly above the notice is the
    allocator's "zend_mm_heap corrupted" message, which is how a heap-corruption
    abort appears in the lab logs. That adjacency holds because the lab runs a
    single worker; with several workers dying at once it would not.

    Apache writes these timestamps in the container's local time without an
    offset. The lab containers run in UTC (their access-log lines say +0000;
    see access_log_offsets), so UTC is the default.
    """
    lines = text.splitlines()
    notices = []
    for index, line in enumerate(lines):
        match = _EXIT_NOTICE.match(line)
        if not match:
            continue
        stamp = " ".join(match.group("ts").split())
        when = datetime.strptime(stamp, "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=tz)
        notices.append({
            "line": index + 1,
            "pid": int(match.group("pid")),
            "signal": match.group("signal"),
            "signo": int(match.group("signo")),
            "time": when,
            "heap_line_before": (index > 0 and HEAP_MARK in lines[index - 1]
                                 and not _ACCESS_LINE.match(lines[index - 1])),
        })
    return notices


def access_log_offsets(text):
    """The set of UTC offsets seen in access-log lines, e.g. {"+0000"}."""
    return {m.group("offset") for m in _ACCESS_TIME.finditer(text)}


def log_time_span(text, tz=timezone.utc):
    """(earliest, latest) timestamp in a log, from access lines and exit notices.

    Used to check that a captured log covers a whole run. (None, None) when the
    log carries no timestamp at all.
    """
    times = [
        datetime.strptime(m.group("stamp"), "%d/%b/%Y:%H:%M:%S %z")
        for m in _ACCESS_TIME.finditer(text)
    ]
    times.extend(notice["time"] for notice in parse_exit_notices(text, tz=tz))
    return (min(times), max(times)) if times else (None, None)


def earliest_time(text, tz=timezone.utc):
    """The earliest timestamp in a log, or None."""
    return log_time_span(text, tz=tz)[0]
