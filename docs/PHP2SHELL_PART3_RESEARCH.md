# Investigating PHP2Shell: Reproducing Memory Corruption and Analyzing the Results

*Part 3 of a three-part laboratory study of PHP's request lifecycle, sessions, out-of-memory handling, and CVE-2026-109618 / CVE-2026-109619.*

> **PHP2Shell series**
> 1. Foundations: PHP Internals, Sessions, and Memory Management
> 2. Source-Code Analysis: Analyzing the PHP Source Code and Security Patches
> 3. **Original Research: Reproducing Memory Corruption and Analyzing the Results** — *you are here*
>
> *Audience for this part: vulnerability researchers, red teamers, and advanced pentesters. Parts 1 and 2 built the concepts and the source analysis this part tests.*

## Recap: the question the source could not answer

Part 1 gave us the mechanisms — a lifecycle conditional that can skip extension cleanup, a hash insertion that counts before it fills, a bailout that can jump out mid-operation. Part 2 compared PHP 8.4.26 and 8.4.27 and found three plausible defenses in the patch: fallible hash operations, a delayed-OOM allocator path, and an rfc1867 session safeguard.

Reading established what the patch *changed*. It did not establish which change, if any, matters under a real trigger — or whether the vulnerable build behaves differently from the patched ones at all when you actually run them.

This part runs that experiment, and spends as much time on what the results do not establish as on what they do.

**A reminder on scope.** The lab exercises target an isolated local environment only. The harness that produced these results is in the repository's `poc/` directory; it is exploitation code and belongs nowhere else.

---

## 7. The research environment and methodology

### 7.1 Environment

Apache with mod_php, prefork, **one worker**. I used a single worker because the investigation involved failures detected during subsequent request processing. Keeping requests on the same worker helped me study whether process state persisted between requests.

The memory limit was set below what the request body could expand to. With a large limit and a small body the OOM simply never happens — which is exactly what my first configuration did, and why nothing happened for some time.

```ini
memory_limit = 16M
post_max_size = 64M
max_file_uploads = 5000
session.upload_progress.enabled = On
```

These are experimental conditions, not deployment advice.

Every run recorded the PHP version, image digest, OS, the ini values above, and the raw container log. That is bookkeeping, but without it two runs that look identical may not be.

### 7.2 Test matrix

| PHP version | Classification |
|---|---|
| 8.4.26 | Vulnerable research build |
| 8.4.27 | Patched comparison |
| 8.2.35 | Patched comparison |
| 8.3.36 | Patched comparison |
| 8.5.12 | Patched comparison |

### 7.3 Three outcomes, kept separate

The validation measured three different things:

1. whether the request produced an OOM condition,
2. whether the allocator reported an integrity failure,
3. whether the worker aborted.

These were kept apart because they are not the same claim.

An OOM error does not imply memory corruption. A worker crash does not imply code execution.

My first version of the test collapsed them into one "vulnerable / not vulnerable" answer. That was a mistake, and untangling it took longer than writing the original test.

### 7.4 Why multiple trials

The first validation used five trials. All five produced the corruption signal on the vulnerable build.

Five successful trials are not a reproduction rate. I expanded to 20 per build, and the number changed.

---

## 8. Experimental results and lessons from failed tests

### 8.1 Twenty trials per build

| PHP build | OOM observed | Corruption observed |
|---|---:|---:|
| 8.4.26 | 20/20 | 10/20 |
| 8.4.27 | 20/20 | 0/20 |
| 8.2.35 | 20/20 | 0/20 |
| 8.3.36 | 20/20 | 0/20 |
| 8.5.12 | 20/20 | 0/20 |

The vulnerable build produced the allocator corruption signal in 10 of 20 trials — an observed proportion of 50%.

The four patched builds did not produce that signal during the recorded trials, despite reaching OOM.

### 8.2 What the proportion does and does not mean

Ten out of twenty is an observed proportion for this run.

It is not a corruption probability. The trials were sequential and shared a worker, so they are not independent draws: the allocator's state at the start of trial *n* depends partly on what trial *n−1* did.

That is why I do not report a confidence interval as if it were a population estimate. It is a summary of this run under an assumption I cannot fully defend.

### 8.3 What 0/20 means

No corruption event was observed in those 20 trials.

It does not mean corruption is impossible on those builds.

Under an independent binomial model, zero events in 20 trials gives a one-sided 95% upper bound of about 13.9%. That is a **conditional statistical bound** — conditional on independence, which this experiment does not strictly satisfy. It is not a "ceiling" for the configuration, and it should not be quoted as one.

### 8.4 What the differential does and does not show

It shows a difference in observed outcomes under one trigger: one build corrupted, four did not, all reached OOM.

It does not show that the patch caused the difference. The builds differ in more than the patch — version, compiler, and whatever else changed between releases.

It does not show that a clean patched run generalises to other configurations.

Keeping those three sentences separate from the table took me an embarrassingly long time, and they are the reason the table is worth anything.

### 8.5 How to count a reproducer

Counting crash lines is not counting reproductions.

In one early run I had five trials and nine abort events. That is not nine reproductions. A single trial can generate multiple abort events across its request sequence. Without attributing each event to a specific request and process, counting log lines can inflate the apparent reproduction count.

The unit of evidence is the **trial**.

Three habits made the numbers usable:

* read the abort counter before and after each trial, and attribute the delta to that trial;
* record the worker pid before and after — if it changed, the state under test did not survive;
* treat a dropped connection as its own observation, separate from an HTTP status code.

Then report `trials_with_corruption / trials`, and `abort_events` separately if you want to describe severity.

### 8.6 Lessons from the failed configurations

Most of my early runs were meaningless, and each failure taught something.

**The session directory was not what I assumed.** I had hard-coded a path. When the code actually reported the configured path, the files were somewhere else entirely. Exercise 3 in Part 1 exists because of this.

**The window was shorter than I thought.** With cleanup enabled, the progress entry disappears when the upload completes. Anything that reads it afterwards sees an empty file.

**Malformed requests can be silently truncated.** Request-variable and upload-count limits can stop parsing partway without an obvious error.

**More than one worker destroys the observation.** If the next request lands on a fresh child, there is nothing to observe regardless of what the previous one did.

**Minimisation can destroy the experiment.** When I shrank the input, the vulnerable build still crashed — but the patched build stopped reaching the precondition altogether. "No corruption on patched" had quietly become "no memory pressure on patched".

The fix was a rule: a smaller input is only an improvement if it still reproduces *and* the control still reaches the same precondition. Later runs also showed that intermediate sizes were not monotonically better or worse, which is a good reason to treat a single successful trial as an anecdote rather than a result.

I have left the exact trigger dimensions out of this article. The lesson — that an acceptance rule matters more than a smaller number — is the part worth keeping.

---

## 9. Analyzing the crash with GDB

GDB lets us inspect a process at the moment it stops. A backtrace shows the active calls.

My recorded trace, shortened:

```text
zend_mm_panic("zend_mm_heap corrupted")
zend_mm_get_next_free_slot
zend_mm_alloc_small
zend_mm_alloc_heap
_emalloc
zend_string_alloc
zend_string_init
lex_scan
zendlex
zendparse
zend_compile
zend_execute_script
php_handler
```

Read from the bottom up:

* `php_handler` — Apache is processing a PHP request.
* `zend_execute_script`, `zend_compile` — PHP is preparing a script to run.
* `zend_string_alloc`, `_emalloc` — PHP asks the allocator for memory.
* `zend_mm_get_next_free_slot` — the allocator looks for a free slot.
* `zend_mm_panic` — the allocator detects an internal inconsistency.

The allocator noticed damage while servicing an allocation.

It did not notice when the damage was done.

### 9.1 Detection site versus creation site

The **detection site** is where the program notices something is wrong.
The **creation site** is where the invalid memory operation happened.

They are frequently different. Here, the corruption was detected while a later request was being compiled, and the experiment did not establish when or where it originated.

| Question | Result |
|---|---|
| Was allocator corruption detected? | Yes |
| Was the detection site identified? | Yes |
| Was the original corruption site identified? | No |
| Was the causal request conclusively established? | No |
| Was code execution demonstrated through this corruption? | No |

The backtrace is evidence of an integrity failure. It is not evidence of a complete causal chain.

### 9.2 Debugging notes

A few things cost me hours:

* **Symbol names differ from function names.** The breakpoint that silently never bound was `zend_bailout`; the symbol in this build is `_zend_bailout`. Check with `nm libphp.so | grep bailout` before trusting a breakpoint to bind.
* **ptrace needs permission.** A container needs `--cap-add=SYS_PTRACE`; without it, attach fails with "Operation not permitted".
* **Attach to a worker, not the master**, and keep a single prefork worker if you want to know which process served the request.
* **Do not dereference the pointer you are investigating.** Printing `ps_globals.id->val` can fault, or return bytes from a reused allocation, and either way proves nothing about lifetime. Print the pointer value, not the pointee. I did this early on and had to discard the "evidence" it gave me.
* **Instrumentation changes behaviour.** A debug allocator, a sanitizer or a watchpoint all perturb timing and layout. `-g -O0` without `ZEND_DEBUG` is a reasonable middle ground: symbols, without changing the allocator.

I am deliberately not describing how to shape the request to make the crash more reliable. That is a different kind of work from reading a backtrace correctly, and it does not belong in a beginner-oriented study.

---

## 10. Three security behaviors investigated: two application-level chains and one engine-level failure

The research describes three categories. I spent most of my time on the third, but the first two deserve proper explanation — they are the ones you are most likely to meet in a real application, and the ones a PHP upgrade will not fix.

### 10.1 Why they are different

Category C concerns PHP engine-level memory handling. In my laboratory, PHP 8.4.26 produced allocator integrity failures under the tested conditions, while the four patched comparison builds did not.

Categories A and B are application-level problems. They use documented PHP behaviour exactly as intended.

In my lab both worked on PHP 8.4.27, the patched release. That is not evidence that 8.4.27 is vulnerable to the two CVEs; it is evidence that application-level bugs outlive engine-level fixes.

### 10.2 Category A: an include sink plus session data

Two ordinary features combine:

1. a page that includes a file named by the request, and
2. `session.upload_progress`, which records upload metadata — including the client-supplied filename — in the session store.

Neither is a vulnerability alone. The include is the sink; the session store is the source of attacker-influenced bytes.

For the progress feature, PHP serialises an array containing the uploaded file's name:

```text
upload_progress_probe|a:5:{ ... s:4:"name";s:N:"<client-supplied filename>"; ... }
```

If that file is later passed to `include`, PHP parses it as source. Any PHP inside the recorded filename executes.

The filename is not treated as data to display. It is bytes in a file, and a file passed to `include` is source.

**Why it is a race.** With cleanup enabled, the progress entry is deleted when the upload finishes. A quick POST leaves an empty session file. The entry exists only while the body is in flight.

```text
uploader:  [=========>                  ]   body still arriving
includer:  GET ?page=...                    lookup during that window
```

**Why patching does not help.** Nothing here is a memory-safety bug. The include is the application's decision, and the filename recording is documented session behaviour. The fixes are architectural: never build an include path from request input; disable upload progress where it is not needed; keep session files outside includeable paths.

**Safe exercise.** Build a page that includes only from an allowlist:

```php
<?php
$allowed = ['about', 'help', 'terms'];

$page = $_GET['page'] ?? 'about';

if (!in_array($page, $allowed, true)) {
    http_response_code(400);
    exit("Unknown page");
}

include __DIR__ . "/pages/{$page}.php";
```

Create `pages/about.php`, `pages/help.php` and `pages/terms.php` first — each
can be a single echo — otherwise even the allowed requests produce include
warnings.

Then try `?page=../../etc/passwd` and observe it is rejected. The lesson is the sink — an include whose argument comes from the request — not a working traversal. Keep the exercise on loopback.

### 10.3 Category B: two serializers, one session directory

Two parts of one application share a session directory but use different serialize handlers:

```apache
<Directory /app/seed>
    php_value session.serialize_handler php_serialize
</Directory>
<Directory /app/api>
    php_value session.serialize_handler php
</Directory>
```

This usually happens by accident — a legacy directory, a copied vhost, a framework default that differs from the application's own setting.

`php_serialize` stores the session as a serialised array; the `php` handler expects `key|serialized_value`. It finds the first pipe — which may be inside the value — and splits there.

A schematic illustration (not a valid payload, and the lengths are
abbreviated):

```text
php_serialize stored:  a:1:{s:4:"data";s:9:"x|PAYLOAD";}
                                             ^ the pipe sits inside the value

php handler splits at the first pipe:
    name  = a:1:{s:4:"data";s:9:"x
    value = PAYLOAD";}          -> unserialize()
```

**The second half.** In my lab, the value passed to `unserialize()` had trailing characters, so decoding failed and PHP printed "Failed to decode session object". The same response also contained output from the destructor, despite the session decoding failure. This confirmed that the destructor executed during the request, but I did not establish its exact timing. The behaviour is version- and input-dependent.

I want to label that clearly: it is what I observed, in one lab, with one PHP build and a specific input. Object creation, destructor timing and decode behaviour are version- and input-dependent. Do not read it as a general guarantee about PHP's session implementation.

**Why patching does not help.** Each handler does what it documents. The fixes are configuration: one handler per session store; no shared session directory between applications; avoid destructive magic methods in request-scoped data.

**Optional advanced exercise (conceptual).** This one needs two directories with
different `php_value session.serialize_handler` settings, which is more setup
than anything else in this series. If you want to try it: add the two
`<Directory>` blocks shown above, send the same session cookie to both, write a
plain string containing a pipe through the `php_serialize` side, and read it
back through the `php` side. Print what comes back.

The interesting part is that the same bytes mean different things to the two
handlers. No object, no gadget — just the confusion. If the setup is more than
you want, the diagram above carries the lesson on its own.

### 10.4 The three behaviors side by side

| | A — include + session data | B — serializer mismatch | C — OOM corruption |
|---|---|---|---|
| Layer | application + PHP feature | application configuration | PHP engine |
| Tested conditions | include sink | two handlers, one store | finite limit, mod_php |
| Fixed by a PHP upgrade? | no | no | no corruption observed in tested patched builds |
| Lab result | command execution (7.4 / 8.1 / 8.4.27) | command execution (same) | corruption on 8.4.26, 10/20 trials |
| Defensive control | allowlist the include | one handler per store | upgrade + upload progress off |

The middle row is the one I would read twice. For C, the honest phrasing is "no corruption was observed in the tested patched builds" — not "patched builds are safe under all conditions".

---

## 11. Defensive recommendations

The primary recommendation is to run a PHP release containing the fixes. At the time of writing the advisory names 8.5.12, 8.4.27, 8.3.36 and 8.2.35; check the current advisory before relying on those numbers, since this article will age faster than the advisory will.

For applications that do not need upload-progress reporting:

```ini
session.upload_progress.enabled = Off
```

Also:

* never build an include path from request input — use an allowlist;
* use one session serialize handler per session store;
* do not share a session directory between unrelated applications;
* apply request-size, upload and worker-resource limits as defence in depth;
* monitor for worker crashes and allocator errors such as `zend_mm_heap corrupted`.

Those messages warrant investigation. They do not, on their own, establish exploitation.

### 11.1 A note on memory_limit

Disabling the memory limit is not a general security fix. It can turn a bounded memory problem into unbounded consumption, and an underlying allocation failure can still reach the vulnerable path.

"Set `memory_limit=-1`" circulates as advice because it removes one trigger condition. It does not make the bug unreachable, and it makes the machine less predictable under load.

Similarly, lowering `post_max_size` may reduce exposure in some deployments, but my own results (section 8.6) show that the relationship between body size and memory pressure is not simple. Treat it as hardening, not as a fix.

### 11.2 Both layers

Patching the engine does not fix a page that includes a file from a query parameter, or two directories disagreeing about a session handler.

Both layers need attention.

---

## 12. Limitations, conclusion, and appendices

### 12.1 Limitations

* **Independence.** Trials ran sequentially on one worker; the 50% figure is an observation for this run, not a probability estimate.
* **Sample size.** Twenty trials separate 10/20 from 0/20, but do not pin the rate tightly.
* **One host environment, one configuration per tested version.** Five PHP versions were compared, but each under a single configuration on a single host. Allocator layout also depends on compiler, libc and build options.
* **Synthetic applications.** Category A's include sink and Category B's handler pair were built for the test.
* **Partial attribution.** Detection site confirmed; creation site unknown; causal request not established.
* **No exploitation of C.** No memory disclosure, no control-flow hijack, no code execution was demonstrated through the corruption.

### 12.2 What I learned

**Reproducing an error is not the same as understanding the vulnerability.** I reproduced OOM long before I had any evidence about corruption.

**Small samples mislead.** Five successful trials suggested a stable result; twenty changed the number to 50%.

**A backtrace is not a root cause.** It tells you where the program noticed, not where the damage began.

**Source analysis and runtime evidence have to support each other.** A plausible explanation from the code is not automatically the explanation for an observed crash.

And one habit I would keep: write down what you did *not* establish. In this project that list was longer than the list of things I could prove, and it is the part I trust most.

### 12.3 Conclusion

PHP2Shell is an interesting case study because it brings together HTTP parsing, sessions, memory allocation, nonlocal error handling and request lifecycle management.

The most useful part of the investigation was not getting PHP to crash. It was learning to say precisely what each observation meant, correcting my own reproduction-rate claim, and separating established findings from plausible mechanisms.

For anyone starting in memory-corruption research: learn how memory is allocated and released, understand pointers and data structures, get comfortable reading small sections of C, and practice reading backtraces. Those skills transfer far beyond PHP.

**A crash is an observation. Understanding why it happened requires evidence.**

---

## References and research materials

- PHP security releases and source: https://www.php.net/
- PHP source repository: https://github.com/php/php-src
- Original PHP2Shell research by Calif: https://calif.io/php2shell/
- PHP sessions: https://www.php.net/manual/en/book.session.php
- Upload progress: https://www.php.net/manual/en/session.upload-progress.php
- GDB documentation: https://sourceware.org/gdb/documentation/

### Identifier verification

Checked 10 November 2026:

* The NEWS file shipped with the 8.4.27 tag contains: `Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via bailout). (CVE-2026-109618, CVE-2026-109619)`. That is the primary basis for the CVE-to-GHSA mapping used here.
* The security advisory was announced on **21 October 2026**; the per-release NEWS entries are dated **22 October 2026** (the 8.4.27 NEWS header reads `22 Oct 2026, PHP 8.4.27`). The one-day gap between the announcement and the tagged releases appears across sources, so cite the date for the specific artifact you are pointing at rather than a single "release date".
* The GitHub advisory pages for both GHSA identifiers returned 404 when checked. That reflects that the advisory pages were not public at those URLs at the time of checking — **not** that the identifiers are wrong: the NEWS file ties both GHSA IDs to the two CVEs directly, and that NEWS mapping is the basis used here. If you cite these identifiers, re-check the advisory before publication.

*Research note: figures and source observations in this series come from my laboratory records. The artifact set should be reviewed independently before the results are treated as a verified reproduction of the published vulnerabilities.*

---

## Appendix A: Glossary

| Term | Meaning |
|---|---|
| SAPI | Interface between PHP and the web server (here mod_php, named `apache2handler`) |
| Worker | Process handling one request at a time |
| Soft limit | `memory_limit` as configured |
| Hard limit | Derived ceiling above the soft limit; crossing it is fatal |
| Fallible mode | Per-allocation flag; failure is reported instead of raised |
| Bailout | PHP's nonlocal jump on fatal errors |
| Bucket | One slot in a hash table |
| Detection site | Where the damage is noticed |
| Creation site | Where the damage was written |
| Differential | Difference in observed outcomes between builds |

## Appendix B: Reading list

| File | What to look for |
|---|---|
| `main/main.c` | `php_request_startup()` ordering, the `modules_activated` conditional |
| `Zend/zend_hash.c` | insertion order, `zend_array_destroy()` |
| `Zend/zend_alloc.c` | limit checks, delayed OOM handling |
| `ext/session/session.c` | upload-progress callback, session shutdown |

## Appendix C: Pitfall checklist

- session files are not where you assume — read `session.save_path`;
- the progress entry exists only while the body is in flight;
- request-variable and upload limits can truncate parsing silently;
- several workers make "the next request" a different process;
- a memory limit above the body expansion means no OOM at all;
- count trials, not log lines;
- a minimised case whose control no longer reaches the precondition is not a smaller experiment — it is a different one.

---

*This is Part 3 of the PHP2Shell series. Part 1 (Foundations) and Part 2 (Source-Code Analysis) precede it.*
