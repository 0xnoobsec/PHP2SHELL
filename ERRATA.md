# Errata

Corrections to this repository and to figures published from it. Newest first.

## 18 November 2026

### 1. PHP 8.4.26 aborted in 20 of 20 trials, not 10 of 20

**What was published.** The README, `poc/c_validation.json` and the first
version of Part 1 of the write-up reported allocator corruption on PHP 8.4.26
in 10 of 20 trials. The report also gave a Wilson 95% interval of 0.30 to 0.70
for that rate.

**What the raw log shows.** `evidence/8.4.26.log` is the container log the
validator saved at the end of that run: the last 500 lines, reaching back to
20:04:38 UTC, an hour before the run began. It holds one `zend_mm_heap corrupted`
line and one Apache exit notice (`exit signal Abort (6)`) for every one of the
20 trials, about nine seconds apart, from 21:05:01 to 21:07:52 UTC. Each notice
names the worker pid the report recorded for that trial (`pid_before`). The
report itself also records that the pid changed, and that the follow-up request
failed, in all 20 trials.

The corrected figure is **20 of 20**. For 20 of 20 the two-sided Wilson 95%
interval is 0.84 to 1.00, with the same caveat as before: the trials ran one
after another against one container in a single-worker configuration, so they
are not independent draws.

**Why the validator said 10.** `c_validate.py` v2.1.0 decided whether a trial
corrupted the heap by running `docker logs --tail 400 <container> | grep -c`
before and after the trial and checking whether the number went up. A tail is a
sliding window. The container had been running for hours, and its last 400
lines already held many abort lines from earlier experiments. From the tenth
trial on, the lines each trial added pushed at least as many old abort lines
out of the window as the trial brought in. The count stopped rising, and trials
9 to 18 (counting from 0) were recorded as clean. Trial 19 was counted again
once the lines leaving the window were mostly ordinary request lines.

Two more defects sat in the same counter:

* The pattern matched two lines per abort: the allocator's message and Apache's
  exit notice. `aborts_this_trial` and `abort_events` in the report are
  therefore line counts taken through that window, not numbers of aborts. The
  raw log shows exactly one abort per trial.
* When the log could not be read at all, the trial was recorded as "no
  corruption" instead of as unknown.

**How to check it yourself.** No Docker and no lab are needed:

```bash
python3 poc/recount.py
python3 -m unittest discover -s poc/tests -v
```

`recount.py` matches each trial to the exit notices logged during it, and to
the trial's worker pid where the report recorded one, and prints the report's
count next to the raw log's count. Its output for the
published files is committed as `poc/c_validation_recount.json`. The tests
include the sliding-window case and pin the corrected figures to the committed
files.

**What changed.**

* `poc/logcount.py` (new) counts over a container's whole log, never a tail,
  counts heap-corruption lines and exit notices separately, and treats an
  unreadable log as unknown.
* `poc/c_validate.py` v2.2.0 and `poc/c_minimize.py` v1.1.0 use it. The
  requests they send are unchanged. Two timings did change: after a trial in
  which the worker appears to have died, the validator waits up to three
  seconds for Apache's exit notice to reach the log, and the minimizer waits
  half a second after every trial before counting. The minimizer also refuses
  to start if it cannot read the container's log. The versions that produced
  the October results are kept unmodified in `poc/archive/`.
* `poc/c_validation.json` and `evidence/` are left exactly as they were. In
  that report, the per-trial `corruption` flags for trials 9 to 18 on 8.4.26,
  and `corruption_yes`, `corruption_rate`, `corruption_ci95` and
  `abort_events` for that build, are wrong and are superseded by the recount.

**What did not change.**

* Every build reached the out-of-memory error in 20 of 20 trials. That was read
  from the HTTP response, not from the log.
* None of the four patched builds (8.4.27, 8.3.36, 8.2.35, 8.5.12) shows a
  single abort. Their logs cover each container's whole life and contain no
  `zend_mm_heap corrupted` line and no exit notice. 0 of 20 still means "none
  observed", not "impossible": under an independent binomial model the
  one-sided 95% upper bound for zero events in 20 trials is about 14%.
* The detection site is known from the backtrace. The site where the corruption
  is created is not.
* No memory disclosure and no code execution through the corruption were
  attempted or demonstrated.

**What this withdraws.** The write-up drew a lesson from the two numbers: five
trials suggested 100%, twenty brought it down to 50%, so small samples mislead.
The second number was the counting error. The captured log also holds an
earlier stretch of 20 out-of-memory requests in the same pattern (20:42:33 to
20:45:33 UTC), and all 20 of those were followed by an abort as well.

One limit on the corrected statement. Across the whole captured log (20:04:38
to 21:07:53 UTC), 92 requests returned the out-of-memory response, which is
recognisable in the access log by its 421-byte size, and 87 of them were
followed by an abort before the next request in the log. The five that were
not all fall in the two rounds described in item 2. So "20 of 20" describes the
validator's request sequence, at its fixed size, in this configuration. It is
not a claim that every out-of-memory request kills the worker.

### 2. Minimizer results at intermediate sizes are not reliable

`poc/c_minimize.py` v1.0.0 used the same windowed counter. `poc/c_minimized.json`
(493 x 45: 2 of 5) and the non-canonical entries of `poc/c_cases.json` (560 x 45
and 520 x 45 as "negative controls", 493 x 45 as "intermittent") carry figures
produced with it. Do not rely on those figures.

What the raw log supports instead:

* In the part of the minimizer's run that the captured log covers (20:04:38 to
  20:23:15 UTC), 42 requests returned the out-of-memory response, and every one
  of them was followed by a heap-corruption abort.
* Straight after it, between 20:23:41 and 20:25:36 UTC, there are two rounds of
  five trials in which the outcome alternated. In one trial the follow-up
  request completed and the worker survived; in the next the worker aborted.
  Counted by trial, that is an abort in 2 of 5 and in 3 of 5. The log does not
  record the request size those rounds used.

So behaviour that is not all-or-nothing does exist in this log. The recorded
per-size figures do not describe it, and no size can be called a negative
control on this evidence. The statement that corruption rates are
"non-monotonic" in the record count is withdrawn as unsupported.

What stands, because it does not depend on that counter: at 145 x 45 the patched
build stopped reaching the out-of-memory error, which is read from the HTTP
response. That size was rightly rejected as a comparison.

The two JSON files are kept as they were. `c_cases.json` is one of the files
hashed in `poc/ARTIFACTS.sha256`.

### 3. php2shell.py reported an out-of-memory error as a Category C success

In `-m c`, `-m all` and `-m auto`, `c_heap_corrupt` returned success as soon as
request A ran out of memory, unless `--verify-cmd` was given. Every patched
build reaches that error, so a fully patched server was reported as a hit, and
`-m all` printed `Category C: RCE/PROVEN`. With `--verify-cmd`, any
`zend_mm_heap corrupted` line anywhere in the command's output confirmed
corruption, including lines left by an earlier run.

Fixed in this version:

* an out-of-memory error alone is reported as "precondition only", not as a
  result;
* the verify command's output is read before and after the run, and only a new
  `zend_mm_heap corrupted` line confirms corruption;
* the summaries no longer use "RCE" for Category C. It can show a corruption or
  crash signal. It has never shown code execution;
* the module docstring said v15.0.0 while the code said 17.0.0, and described
  Category C only as an `unserialize()` probe.

The requests sent to the target, and the point at which the chain of methods
stops, are the same as before in every case but one. When the verify command's
output already held a corruption line from an earlier run, the old version
stopped with a false confirmation. This version carries on to the next method,
as it does for any other unconfirmed result. The verify command itself is now
run twice. `poc/tests/test_php2shell_reporting.py` compares the two versions
branch by branch.

### 4. Lab descriptions attributed the categories to the wrong things

`lab/docker-compose.yml`, `lab/cat-c/Dockerfile`, `lab/cat-c/php.ini`, the
comments in `decode.php` and the Category C landing page described Categories A
and B as "flaws" of CVE-2026-109619, and Category C as a use-after-free caused
by more than 1018 back-references in `unserialize()` under CVE-2026-109618.

None of that is supported. Categories A and B are application-level and work on
patched PHP. The advisory describes the two CVEs as out-of-memory handling
interrupting partially initialised request state. The back-reference payload is
a detection probe that decodes without corruption on the builds tested. Those
descriptions were an early hypothesis and have been corrected.

`decode.php` still prints its original text, including the heading "UAF
Trigger". Only its comments changed, so that response sizes stay comparable with
the archived logs. Read that heading as a label, not as a finding.

### 5. Lab ports were published on every network interface

`lab/docker-compose.yml` used `8081:80`, `8082:80` and `8083:80`, and the README
used `-p 8084:80`. Docker publishes such ports on all interfaces, so the
deliberately vulnerable apps, two of which have working command-execution
chains, were reachable from the local network. All ports are now bound to
`127.0.0.1`, and the compose file no longer sets a restart policy, so the lab
does not come back by itself after a reboot.

### 6. The report file and the artifact list

`poc/ARTIFACTS.sha256` lists the files as they were for the October run. Line by
line:

| Entry | Status |
|---|---|
| `/tmp/cv3_report.json` `8344a6d9...` | The report as first written. The published `poc/c_validation.json` has SHA-256 `5641aec1...` in every commit of this repository, so it is not byte-identical to that original. What differs was not recorded. |
| `c_validate.py` `15a4c5b1...` | Now `poc/archive/c_validate_v2.1.0.py`, unmodified. |
| `c_cases.json`, `ci_validate.sh` | Unchanged; they match. |
| `PATCH_MAP.md` `463c1657...` | Removed from this repository on 9 November 2026 with the write-up drafts. It is in the history: [docs/PATCH_MAP.md at b8cc027](https://github.com/Cybersecly-LLC/PHP2SHELL/blob/b8cc027f8470e473d710fc386dfab50fd24ab3bb/docs/PATCH_MAP.md). |
| `evidence/*.log` (five files) | Unchanged; they match. |

The report's attribution block also cites `C_ATTRIBUTION.md`, removed at the
same time:
[docs/C_ATTRIBUTION.md at b8cc027](https://github.com/Cybersecly-LLC/PHP2SHELL/blob/b8cc027f8470e473d710fc386dfab50fd24ab3bb/docs/C_ATTRIBUTION.md).

Both notes carry the superseded 10 of 20 figure. `C_ATTRIBUTION.md` also reports
"9 worker aborts" in five trials, which is the two-lines-per-abort count
described in item 1.

A checkout on Windows used to fail every one of these hash checks, because git
converted line endings. `.gitattributes` now keeps the files byte-for-byte.

### 7. The worker-pid probe was missing from the lab

The validator's usage example and the raw logs refer to `/probe.php` on the
study container. That file was not kept, so the published lab could not
reproduce the pid tracking. `lab/cat-c-vuln/probe.php` is a replacement that
returns the worker's pid, which is the only field the validator reads.

### 8. Categories A and B on patched PHP

The README says the two application-level chains remain possible on patched
PHP. The lab record behind that is command execution on PHP 7.4.33, 8.1.34 and
8.4.27, using images built from `lab/cat-a` and `lab/cat-b` with a
`PHP_VERSION` build argument
([docs/CAPABILITIES.md at b8cc027](https://github.com/Cybersecly-LLC/PHP2SHELL/blob/b8cc027f8470e473d710fc386dfab50fd24ab3bb/docs/CAPABILITIES.md)).
No raw logs of those runs were kept, so this repository holds no evidence for
them beyond that record. The compose file builds both apps on PHP 8.1 by
default, which is end-of-life and never received the October 2026 fixes.

Superseded for PHP 8.4.27 by item 11: both chains were run again on
18 November and their logs are in `evidence/replication-2026-11-18/`.

### 9. Replication run, and a fail-open bug in recount.py

Two things, dated 17-18 November 2026.

**The claim reproduces.** With the fixed validator (`c_validate v2.2.0`), a
fresh 20-trial run against rebuilt PHP 8.4.26 and 8.4.27 images gave the same
corrected result: 20 of 20 trials on 8.4.26 reached the allocator abort, 0 of 20
on 8.4.27. Gate PASS, differential Confirmed. The logs and the report are in
`evidence/replication-2026-11-17/`, and `poc/recount.py` checks them in place:

```bash
python3 poc/recount.py --report evidence/replication-2026-11-17/REPORT.json --root .
```

**recount.py used to fail open.** When an evidence log was missing it printed
"The recount agrees with the report" and exited 0: an unknown was reported as
agreement. That is the same class of mistake as the original counter, pointed
the other way. It now prints INCONCLUSIVE, writes `agrees_with_report: null`,
and exits 2. Evidence paths also resolve beside the report, so a lab that copied
only `poc/` still works. A regression test covers the missing-log case.
Fixed in 7894281.

### 10. A second replication, 18 November 2026

The Category C study was run a third time, on the lab host, with
`c_validate v2.2.0`, from 16:07 to 16:12 UTC. Same result: 20 of 20 trials on
8.4.26 ended in `zend_mm_heap corrupted` and a worker abort, each matched to
that trial's worker, and 0 of 20 on 8.4.27. Gate PASS, differential Confirmed.
The logs and the report are in `evidence/replication-2026-11-18/`:

```bash
python3 poc/recount.py --report evidence/replication-2026-11-18/REPORT.json --root . --strict
```

Only 8.4.26 and 8.4.27 have been run again. The figures for 8.2.35, 8.3.36 and
8.5.12 still rest on the October logs.

A correction to item 9: the 8.4.27 image in both replications is the October
build (image digest `sha256:2947903cb4ff...`, the same as in
`poc/c_validation.json`), not a rebuild. It has no `probe.php`, so its worker
pid was not tracked and its trials are matched by time. The 8.4.26 image was
rebuilt from `lab/cat-c-vuln`.

Both replication reports keep the validator's absolute path on the lab host,
which includes the lab account's home directory.

### 11. Categories A and B on PHP 8.4.27, now with logs

Item 8 said no raw logs were kept for the application-level chains. On
18 November both were run again against PHP 8.4.27, the patched release, from
the `p2s-a84` and `p2s-b84` images:

* Category A (include sink plus upload progress) ended in command execution as
  `www-data` through the session-file race;
* Category B (serialize-handler mismatch) ran the lab gadget's destructor as
  `www-data`, in the same response as the "Failed to decode session" warning.

The harness output and both containers' logs are in
`evidence/replication-2026-11-18/`. The earlier runs on PHP 7.4.33 and 8.1.34
remain a lab record without logs.

### 12. php2shell.py could not trigger the Category C corruption

`c_heap_corrupt` sent request A and request B without a session cookie.
`c_validate.py`, `c_minimize.py` and `debug/trigger_oom.py` all send one. Without
a session id the upload-progress callback never starts the session while PHP is
parsing, so the path the advisory describes is never taken.

On the lab, against PHP 8.4.26, the method reached the out-of-memory error in
every round and no worker aborted. The old version hid this: it counted the
out-of-memory error, or any old corruption line in the log, as a success
(item 3).

The method now sends a fresh `PHPSESSID` with each round, shared by A and B,
as the validator does. Run again on the lab, it confirmed corruption in 3 of 3
rounds on 8.4.26, from new log lines only, and none on 8.4.27
(`evidence/replication-2026-11-18/harness-c-*.log`).

This changes what the harness sends: each Category C request now carries a
cookie. Item 3 said no request was changed; that held until this fix.

### 13. recount.py: three more ways to report "agrees" without the evidence for it

* **Start-up lines were ignored.** The check that a log spans its run used only
  request lines and abort notices. A log captured from a fresh container, whose
  first request is the run's own, looked as if it began after the run started,
  although it begins with Apache's start-up notice minutes earlier. Error-log
  lines now count. Found on the 18 November run.
* **Evidence that exists but cannot support a verdict** (a log that is not the
  file the report hashed, does not span the run, has no timestamps, or is in
  another time zone) used to end in "The recount agrees with the report" and
  exit 0, with only a note. It is now INCONCLUSIVE and exits 2, like a missing
  log (item 9). When one target disagrees and another has no usable evidence,
  both are reported.
* **Two candidate logs.** When the same relative path existed under the root
  and next to the report, the root's copy was read even if it was another run's
  log. The file whose SHA-256 matches the report is now chosen.

The recount of the October report is unchanged, byte for byte. The tests pass
in the published layout and in a lab that keeps the logs in `poc/evidence/`.
