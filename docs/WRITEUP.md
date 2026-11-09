# php2shell

*A laboratory study of two PHP core vulnerabilities, alongside two application-level
session attack patterns and an OOM-associated corruption experiment.*

*Two PHP core vulnerabilities, three exploitation categories, one laboratory, and
a long argument with myself about what the evidence actually supports.*

---

## Abstract

In October 2026 the PHP project shipped 8.5.12, 8.4.27, 8.3.36 and 8.2.35 to
close two memory-safety bugs in the engine. Both were rated 9.2. The advisory's
framing is deceptively simple:

> out-of-memory handling can interrupt PHP while internal request data is only
> partially initialized. Request cleanup may then treat the invalid data as
> valid.

This document is what happened when I tried to reproduce that sentence.

Three categories emerged:

* **A** — session filename injection plus an include sink. A logic flaw.
* **B** — a serialize-handler mismatch across two directories. Also logic.
* **C** — the OOM corruption itself.

**Categories A and B are application-level attack patterns.** They depend on
specific application and session configurations. Their success on patched PHP
versions does **not** establish that those versions remain vulnerable to either
CVE.

A and B produce command execution on every build I tried, including the patched
8.4.27, because they depend on application behaviour rather than PHP version.
C produces a reproducible heap corruption and worker abort on 8.4.26, and
nothing on the four patched builds — but only at a measured rate of 50%, not the
100% that five trials first suggested.

What follows is the full trail: the source, the lab, the payloads that failed,
the measurement that corrected an overclaim, and the line where the work stops.

---

## Contents

1. Prologue — the shape of the bug
2. Background — how a PHP request is born, and where it dies
3. CVE-2026-109619 — the session flaws
4. CVE-2026-109618 — the OOM corruption
5. The laboratory
6. Testing methodology
7. Results
8. Analysis
9. Limitations
10. Defensive guidance
11. Verification and availability
12. Appendix — source, artifacts, chronology

---

## 1. Prologue — the shape of the bug

Every memory-safety bug in a language runtime is, at bottom, a disagreement
about when a thing stops existing. The interesting ones are not the
disagreements over a single free(); they are the ones where two subsystems hold
different opinions for a few microseconds, and a third subsystem walks through
the gap.

Calif's write-up reduces the family to a pattern:

```
publish or destroy state
    -> perform fallible work
        -> nonlocal fatal during that work
            -> commit/rollback skipped
                -> surviving consumer trusts false state
```

Once you have that shape in your head, the two CVEs stop looking like separate
bugs and start looking like two instances of the same mistake in two different
subsystems:

* **CVE-2026-109618**: the source exposes a potentially unsafe ordering — the
  hash-table count is advanced before key allocation completes. This provides a
  plausible explanation for how an OOM bailout could leave partially initialized
  state. The laboratory has **not** attributed the observed allocator corruption
  to that specific insertion or teardown path.
* **CVE-2026-109619**: session globals may survive a fatal that skips module
  shutdown. The evidence for this is a shutdown trace showing the gate closed and
  the globals still populated; whether that surviving state causes the observed
  corruption is not established.

A tempting summary is that both bugs "count the bucket before filling it". It is
a useful hypothesis for reading the code, and it is not a conclusion this
evidence can carry.

---

## 2. Background — how a PHP request is born, and where it dies

To say anything precise about C, you have to know the order of operations in
`main/main.c`. This is the 8.4.26 sequence, abbreviated:

```c
/* main/main.c, php_request_startup() */
zend_activate();
sapi_activate();
...
php_hash_environment();      /* parses POST, multipart, uploads */
zend_activate_modules();     /* RINIT for every extension */
PG(modules_activated) = 1;
```

The important line is the last one. Everything before it happens with
`PG(modules_activated) == 0`, and that flag is the switch that decides whether
extension shutdown runs at the end of the request:

```c
/* main/main.c:1928, php_request_shutdown() */
if (PG(modules_activated)) {
    zend_deactivate_modules();
}
```

So a fatal *during* `php_hash_environment()` produces a request that is half
born: the heap exists, the session may already be initialized, but the module
shutdown path is gated off. What runs instead is `shutdown_memory_manager()`,
which destroys the request heap wholesale.

### 2.1 Where the session wakes up early

The upload-progress feature is implemented as a multipart callback, and it is
allowed to start a session while the body is still being parsed. That is the
"early session" path in `ext/session/session.c`:

```c
case MULTIPART_EVENT_FILE_START: {
    ...
    if (Z_ISUNDEF(progress->data)) {
        ...
        php_rinit_session(0);
        PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0);
        ...
    }
```

Two things are now true at once: `PS(id)` is a pointer into the request heap, and
`modules_activated` is still 0. The cleanup that would release that string —
`php_rshutdown_session_globals()` — is an RSHUTDOWN handler, so it is exactly
the thing the gate suppresses.

### 2.2 Zend MM, and the three limits

Zend's allocator tracks three numbers:

```
real_size     bytes currently mapped
limit         memory_limit (soft)
hard_limit    derived: 200% of limit under 1G, else limit + 1G
```

When an allocation would cross the soft limit, `zend_mm_check_limit()` has three
possible responses, and which one you get depends on the *allocation mode*:

```c
if (!heap->fallible && add_size > heap->hard_limit - heap->real_size) {
    zend_mm_hard_limit_error(...);          /* ZEND_NORETURN */
}
if (!ZEND_HAS_OOM()) { zend_mm_delayed_error(...); }   /* queue + vm_interrupt */
return heap->fallible ? FAILURE : SUCCESS;
```

That `SUCCESS` is the hinge of the entire patch. In 8.4.26 there is no such
branch: crossing the limit is an immediate fatal, `zend_mm_safe_error()` raises
E_ERROR inside a `zend_try` and then calls `zend_bailout()` regardless.

---

## 3. CVE-2026-109619 — the session flaws

This CVE is the one you can understand without a debugger, which is why it is
where the work started. Three separate behaviours combine.

### 3.1 The filename is stored verbatim

`session.upload_progress` records the client's filename in the session file so
the application can display progress. The filename is not sanitised, because it
is not supposed to be executed — it is supposed to be shown.

That assumption fails the moment the session file is reachable through an
include: the recorded value is parsed as PHP when the file is included, and the
filename field is not escaped for that context.

The recorded entry looks like this, with the name field carrying whatever the
client sent:

```
upload_progress_probe|a:5:{s:10:"start_time";i:...;s:5:"files";a:1:{i:0;a:7:{
    s:10:"field_name";s:1:"f";s:4:"name";s:N:"<client-supplied filename>"; ...
```

Two escaping details constrain a working value: the filename is truncated at a
semicolon and broken by a double quote, so it has to avoid both.

*The specific payload strings used in the laboratory are in the harness
(`poc/php2shell.py`); this text describes the mechanism so defenders can
recognise it.*

### 3.2 The window is only open while the body is in flight

`session.upload_progress.cleanup = On` deletes the progress entry the moment the
upload completes. A fast POST leaves a 0-byte session file and looks, to a
casual tester, like "not vulnerable".

The exploit therefore streams the body slowly with an explicit Content-Length
and races the include against it:

```
uploader thread:  [==>                        ]  (chunk, delay, chunk, ...)
include loop:     GET ?page=/var/lib/php/sessions/sess_<sid>
```

The lab needed several corrections before this worked: the session path is not
`/tmp` (it was `/var/lib/php/sessions`), a chunked body without a declared length
produces no progress data at all, and a marker race that checks for `uid=` can
never match a payload that only echoes a number.


### 3.3 Two directories, two serializers

The second session flaw needs a specific deployment mistake: two parts of the
same application that write and read the same session directory with *different*
serialize handlers.

```apache
<Directory /var/www/html/seed>
    php_value session.serialize_handler php_serialize
</Directory>
<Directory /var/www/html/fire>
    php_value session.serialize_handler php
</Directory>
```

`php_serialize` writes a serialised array:

```
a:1:{s:4:"data";s:41:"x|O:9:"LabGadget":1:{s:3:"cmd";s:2:"id";}";}
```

The `php` handler expects `key|serialized_value`. It finds the first pipe —
inside our value — and splits there:

```
key   : a:1:{s:4:"data";s:41:"x
value : O:9:"LabGadget":1:{s:3:"cmd";s:2:"id";}";}
```

The value is handed to `unserialize()`. The trailing `";}` makes the parse fail,
and PHP reports:

```
Warning: session_start(): Failed to decode session object.
         Session has been destroyed
```

and yet the object's destructor still runs. That is the third flaw: the object
is instantiated during the parse, before the trailing-garbage error is noticed,
and destruction happens at request end regardless of the failure.

The lab proves this in two places. On the CLI:

```
--- case 1: trailing junk after object ---
object(LabGadget)#1 (1) { ["cmd"]=> string(2) "id" }
...
DESTRUCT_FIRED
uid=0(root) gid=0(root) groups=0(root)
```

and over HTTP, where the same payload against the fire endpoint prints
`[GADGET] __destruct fired: uid=33(www-data)` *underneath* the decode warning.

### 3.4 What A and B actually require

Neither is a PHP-version bug. Both are application-configuration bugs that the
PHP session machinery converts into code execution:

```
A:  app includes a user-controlled path      +  upload_progress enabled
B:  two dirs, different serialize handlers   +  a class with __destruct loaded
```

That is why both still work on 8.4.27. The patch changes the engine, not the
application's assumptions. Saying "8.4.27 is vulnerable" because A or B succeed
would be a category error, and the capability statement says so explicitly.

---

## 4. CVE-2026-109618 — the OOM corruption

This is the hard one, and the one that took the most work to state honestly.

### 4.1 The insert that counts before it builds

`Zend/zend_hash.c`, 8.4.26, lines 961-976:

```c
add_to_hash:
    idx = ht->nNumUsed++;                            /* 962: published */
    ht->nNumOfElements++;
    p = ht->arData + idx;
    p->key = key = zend_string_init(str, len, ...);  /* 965: can bail out */
    p->h = ZSTR_H(key) = h;                          /* 971: skipped */
    ...
    ZVAL_COPY_VALUE(&p->val, pData);                 /* 976: skipped */
```

The count is visible to teardown at 962. The allocation at 965 can throw the
OOM fatal. Lines 971-976 never execute. The bucket is now a hole in the table
that `nNumUsed` swears is filled.

Teardown does exactly what it was told:

```c
for (p = ht->arData; p != ht->arData + ht->nNumUsed; p++) {
    i_zval_ptr_dtor(&p->val);
    if (p->key) { zend_string_release(p->key); }
}
```

It walks one bucket too far, into uninitialised memory, and calls the zval
destructor on whatever is there.

```
    arData:  [ bucket 0 ][ bucket 1 ][ bucket 2 ][  ???  ]
                                                 ^
                                    nNumUsed points here
    teardown walks 0..nNumUsed, including the ??? bucket
```

### 4.2 Reaching the fatal inside the parse

Two obstacles have to be cleared first.

**Obstacle one: `post_max_size`.** PHP checks the declared Content-Length before
parsing and refuses bodies above the cap. A chunked HTTP/1.1 request declares no
length at all. (This bypass is from the published research and was *not*
independently measured here — the lab's 16M limit was reached inside a 64M cap,
so the bypass was never required.)

**Obstacle two: making a small body expensive.** An RFC1867 part with
`filename=""` carries no file data and is not counted toward `max_file_uploads`,
but PHP still builds all six `$_FILES` entries for it. Give each record a unique
nested prefix and every one of those entries has to construct its own chain of
hash tables:

```
files[0][k0][k1]...[k44]
files[1][k0][k1]...[k44]
...
```

A few hundred such records, nested near the parser's depth limit, build tens of
thousands of keys from a body of a few hundred kilobytes. Under a 16M limit the
allocator reaches its ceiling while inserting a key — the line 965 case.

### 4.3 A hypothesized two-request model

The observations are consistent with a two-request failure model. An OOM bailout
occurs during multipart parsing, while module shutdown is gated off. A later
request on the same worker then encounters allocator corruption. The experiments
have not established where the corruption is created, whether the surviving
session state is the cause, or which request first damages the allocator state.

The sequence below is a hypothesis, not a trace of proven events:

```
Request A
  FILE_START -> session initialized early (PS(id) -> request heap)
  ... more parsing ...
  OOM at hash insert -> zend_bailout()
  modules_activated == 0  ->  session RSHUTDOWN skipped
  request heap freed, worker survives

Request B
  multipart, progress field, no file part
  no FILE_START reset
  END cleanup -> php_session_initialize() -> zval_ptr_dtor(freed session value)
```

Request B never executes application code either; the fatal happens during
parsing, on a value that no longer exists.

This is why the gdb trace at request shutdown of the OOM request shows
`modules_activated=0` with `PS(id)` non-NULL: the cleanup was gated out, and the
pointer survived. It is also why a short `Set-Cookie` on the next request proves
nothing either way — the state can be dangling without being emitted.

### 4.4 What the patch changes

```
git diff php-8.4.26 php-8.4.27
  Zend/zend_alloc.c      659 lines
  Zend/zend_hash.c       302 lines
  ext/session/session.c   73 lines
  main/main.c             50 lines
```

Three mechanisms, and it matters which one applies where.

**Fallible hash operations.** New flag `HASH_FALLIBLE`, sentinel `HASH_NOMEM`,
allocation helper `fpemalloc()`, and a family of `zend_hash_f*()` entry points
that return failure instead of unwinding. Table init, resize and packed-to-hash
conversion can now report "out of memory" and leave the table untouched.

**Delayed OOM.** A non-fallible allocation over the soft limit is allowed to
succeed while the error is queued, then raised at a safe point. The consumption
sites are `zend_execute_script()` after `zend_execute()` returns, and the VM
interrupt path (`zend_fcall_interrupt()`, the opcode-loop check). If there is no
userland frame to unwind, `zend_handle_delayed_oom()` calls `zend_bailout()`
itself.

**Session serialisation gating.** `PS(in_rfc1867_update)` plus
"incomplete classes only" means that during the upload-progress callback the
serializer keeps objects as `__PHP_Incomplete_Class` and writes them back
unchanged. No `__wakeup`, no `unserialize_callback_func`, no userland code before
RINIT.

The bucket ordering from 4.1 is **unchanged** in 8.4.27. The patch does not make
the bucket atomic; it removes the fatal from the middle of the insert. That
distinction is easy to get wrong and is why the source analysis is labelled
separately from the measurements.

---

## 5. The laboratory

### 5.1 Host

| Item | Value |
|---|---|
| Host | adaptix, Ubuntu 25.10 |
| CPU / RAM | 8 vCPU / 11 GB |
| Runtime | Docker 29.1.3 |
| Network | isolated lab subnet |

### 5.2 Images and ports

| Port | Container | PHP | Purpose |
|---|---|---|---|
| 8081 | php2shell-cat-a | 8.1.34 | Category A |
| 8082 | php2shell-cat-b | 8.1.34 | Category B |
| 8083 | php2shell-cat-c | 8.1.34 | Category C baseline |
| 8084 | php2shell-cat-c-vuln | 8.4.26 | vulnerable C |
| 8085 | p2s-c8.2 | 8.2.35 | patched |
| 8086 | p2s-c8.3 | 8.3.36 | patched |
| 8087 | p2s-c8.5 | 8.5.12 | patched |
| 8088 | p2s-c8427 | 8.4.27 | patched |
| 8091 | p2s-a74 | 7.4.33 | A version matrix |
| 8093 | p2s-a84 | 8.4.27 | A version matrix |
| 8094 | p2s-b74 | 7.4.33 | B version matrix |
| 8096 | p2s-b84 | 8.4.27 | B version matrix |
| 8095 | p2s-dbg | 8.4.26 debug | gdb attribution, loopback |

### 5.3 Category A

The image is parameterised so the same Dockerfile builds every version:

```dockerfile
ARG PHP_VERSION=8.1
FROM php:${PHP_VERSION}-apache
RUN a2enmod rewrite
COPY php.ini /usr/local/etc/php/php.ini
COPY index.php /var/www/html/index.php
COPY slow.php /var/www/html/slow.php
RUN mkdir -p /var/lib/php/sessions \
 && chown www-data:www-data /var/lib/php/sessions \
 && chmod 1733 /var/lib/php/sessions
```

`index.php` is deliberately naive — the kind of include that shows up in every
"LFI to RCE" walkthrough:

```php
$page = $_GET['page'] ?? null;
$file = $_GET['file'] ?? null;
...
$target = $page ?? $file ?? $inc ?? $load ?? $path ?? $doc ?? null;
if ($target !== null) { @include($target); }
```

`slow.php` exists to hold a session open in early experiments; the working race
turned out not to need it.

### 5.4 Category B

Two directories, two handlers, and a gadget. The Dockerfile fix list is worth
recording because both failures were silent:

1. the composer binary in the official image lives at `/usr/bin/composer`, not
   `/usr/local/bin/composer` — the original `COPY --from` failed the build
   outright;
2. `gadget.php` existed on disk but was missing from the `COPY` list, so the
   class was never declared in the container. `fire/index.php` guarded its
   require with `file_exists()`, so nothing failed: the mismatch was "confirmed"
   and no destructor ever ran.

The gadget stands in for a phpggc chain because `composer install` leaves
`vendor/` empty in this image, and the fire page reports `Monolog loaded: NO`.

### 5.5 Category C

The configuration is the experiment. A 512M limit with a 100M body cap makes the
OOM arithmetically unreachable — which is exactly what the first Category C lab
did, and why nothing ever happened there.

```ini
memory_limit = 16M
post_max_size = 64M
upload_max_filesize = 64M
max_file_uploads = 5000
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
display_errors = On
```

```apache
StartServers 1
MinSpareServers 1
MaxSpareServers 1
MaxRequestWorkers 1
MaxConnectionsPerChild 0
```

One worker is not a convenience. The corruption is created in one request and
detected in a later one; if the child is recycled between them, there is nothing
to detect.

### 5.6 The debug build

| Field | Value |
|---|---|
| Source | php-8.4.26.tar.gz |
| SHA-256 | c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662 |
| Verified | matches php.net release metadata |
| Configure | CFLAGS='-g -O0' ./configure --with-apxs2=/usr/bin/apxs2 --disable-cgi --without-pear |
| ZEND_DEBUG | off — the allocator must behave like a release build |
| Runtime | apache2handler, prefork, 1 worker, Debian 12, gdb 13.1 |

Two practical notes. The container needs `--cap-add=SYS_PTRACE`; without it every
attach fails with "Operation not permitted". And the symbol is `_zend_bailout`,
not `zend_bailout` — the first breakpoint I set silently never bound.

---

## 6. Testing methodology

### 6.1 The four questions

Every test in this project had to answer one of four questions, and the answers
had to be kept apart:

```
Q1  Does the OOM happen?                 -> yes/no, per trial
Q2  Does corruption follow?              -> abort attribution, per trial
Q3  Is the difference patch-related?     -> vulnerable vs patched
Q4  Is code execution demonstrated?      -> explicit evidence record
```

The first version of the validator answered these with one boolean. That was the
main architectural mistake: "vulnerable" collapsed Q1 and Q2, and
"EXECUTION_NOT_DEMONSTRATED" was hard-coded, which meant the report could never
change its mind even if evidence appeared.

### 6.2 Request shape (described, not supplied)

Category C uses two multipart requests.

**Request A** carries an upload-progress field and many records with empty
filenames under *distinct nested field names*. The nesting is what makes a small
body expensive: each record expands into its own chain of hash tables, so the
heap cost is driven by the shape of the names rather than by bytes on the wire.

**Request B** carries the progress field and no file part, so the parser reaches
its end-of-multipart cleanup without resetting the session first.

The exact field-name scheme, per-record depth and record count are implemented
in the harness rather than spelled out here; the harness is published with the
laboratory artifacts for reproducibility and defensive testing.

### 6.3 Statistics

Rates are reported with a two-sided 95% Wilson interval, and zero-event builds
additionally get an exact one-sided bound:

```
Wilson:          (p + z^2/2n ± z*sqrt(p(1-p)/n + z^2/4n^2)) / (1 + z^2/n)
one-sided upper: 1 - 0.05^(1/n)          (0.1391 at n = 20)
```

The independence assumption is stated rather than assumed. These are nominal
binomial intervals calculated under an independence assumption; because trials
share a worker and allocator history, their inferential interpretation is
limited.

### 6.4 Attribution

A gdb session with `handle SIGABRT stop` attaches to the single worker, runs the
A→B sequence, and prints the globals at the stop. The harness deliberately does
not dereference `PS(id)` — an earlier version printed `ps_globals.id->val`,
which is both unsafe and non-evidentiary.

### 6.5 Minimization

Search over (parts, depth) with an acceptance rule that has two clauses:

```
1. corruption reproduces in >= 2 of 3 trials
2. the patched build still reaches OOM at that size
```

Clause 2 exists because of a mistake: the first minimizer reached 145 × 45, where
the vulnerable build still crashed but the patched build no longer reached the
memory limit at all. "No corruption on patched" there meant "no pressure",
which is not a differential.

### 6.6 CI

The gate re-derives the acceptance criteria from the JSON rather than trusting
the tool's exit code: differential must be Confirmed, trials must meet the
minimum, every target must have OOM, and every evidence file must still hash to
the recorded value.

---

## 7. Results

### 7.1 Categories A and B

| PHP | A | B |
|---|---|---|
| 7.4.33 | uid=33(www-data) | [GADGET] __destruct fired |
| 8.1.34 | uid=33(www-data) | [GADGET] __destruct fired |
| 8.4.27 (patched) | uid=33(www-data) | [GADGET] __destruct fired |

A's fallback chain was exercised by disabling the winning method:

```
--skip session_race
  method_A_session_race    skipped
  method_A_log_poison      failed (access log not readable via the sink)
  method_A_environ_poison  LANDED — /proc/self/environ
```

Two independent primitives on the same host is a useful property: it means the
category is not one fragile trick.

### 7.2 Category C, twenty trials per build

| Build | OOM | Corruption | Wilson 95% | One-sided upper |
|---|---|---|---|---|
| 8.4.26 | 20/20 | 10/20 | [0.30, 0.70] | — |
| 8.4.27 | 20/20 | 0/20 | [0.00, 0.16] | 0.1391 |
| 8.2.35 | 20/20 | 0/20 | [0.00, 0.16] | 0.1391 |
| 8.3.36 | 20/20 | 0/20 | [0.00, 0.16] | 0.1391 |
| 8.5.12 | 20/20 | 0/20 | [0.00, 0.16] | 0.1391 |

The per-trial pattern on the vulnerable build is informative: every A request
returns 200 with the OOM text, and the trials that corrupt show the B request
as a transport drop rather than an HTTP response — the worker died before it
could answer.

The initial 5/5 result was based on a small sample. In the expanded run,
corruption was observed in 10 of 20 trials on the tested 8.4.26 build. The
earlier result should not be treated as an estimate of the underlying
probability; 50% is the number this report uses.

### 7.3 Detection

```
Program received signal SIGABRT, Aborted.
#3  zend_mm_panic ("zend_mm_heap corrupted")     zend_alloc.c:398
#4  zend_mm_get_next_free_slot (bin_num=3)       zend_alloc.c:1326
#5  zend_mm_alloc_small
#6  zend_mm_alloc_heap (size=32)
#7  _emalloc
#8  zend_string_alloc (len=7)
#9  zend_string_init ("_SERVER['REQUEST_METHOD']...")
#10 lex_scan -> zendlex -> zendparse -> zend_compile
#16 zend_execute_script
#19 php_handler                                  sapi_apache2.c:717
```

At the stop: `modules_activated=1`, `ps_id=nil`.

Read carefully, this says the allocator noticed a damaged free list while the
*next* request was being compiled — not while the session was being destroyed,
and not in the request that caused the damage. The corruption is a time bomb
with a variable fuse: whichever allocation touches the damaged bin first
detonates it.

### 7.4 Reproducer sizes

| Size | Role | Corruption (vuln / patched) |
|---|---|---|
| 600 × 45 | canonical gate | 10/20 · 0/20 |
| 493 × 45 | intermittent diagnostic | 2/5 · 0/5 |
| 560 × 45 | negative control | 0/5 · 0/5 |
| 520 × 45 | negative control | 0/5 · 0/5 |
| 145 × 45 | rejected (patched lost OOM) | 5/5 · 0/5 |

The non-monotonicity — 493 works, 520 and 560 do not, 600 works — is the most
interesting negative result in the project. It says the trigger is not simply
"more pressure". It does not say which allocator state is responsible, and the
report does not claim to know.

---

## 8. Analysis

### 8.1 Why the rate is 50%

Several explanations are consistent with the data, and none is established:

* **Bin state varies.** The damaged free list is only fatal when a later
  allocation lands in the affected bin; different trial ordering changes that.
* **Hash growth is batched.** Zend grows tables in powers of two, so the exact
  record count decides whether the fatal lands during a key insert or during a
  table resize — two different aftermaths.
* **Worker history matters.** Trials run sequentially; the allocator's free
  lists at the start of trial n depend on what trial n−1 freed.

A causal account needs a watchpoint or an instrumented allocator, and
instrumentation perturbs the layout it is measuring. That trade-off is not
resolved here.

### 8.2 Why the patch works

Source-supported, not experimentally proven end to end:

1. with delayed OOM, the key allocation at 965 no longer unwinds mid-insert; the
   bucket gets its `h` and `val`, and the count stops lying;
2. with "incomplete classes only" during the rfc1867 callback, the session
   decode cannot instantiate a class before RINIT;
3. fallible hash operations give internal callers a way to fail cleanly instead
   of relying on the fatal path.

Which of these actually prevents *this* corruption is a hypothesis. The
differential proves the patched builds behave differently; it does not prove
which line did it.

### 8.3 What would be needed for code execution

Stated at the level of missing capability, not recipe:

* a **controlled read** of the corrupted state (the published chain uses
  heap pointers in a cookie to derive the Zend MM chunk base and the libphp
  base);
* a **controlled write** into the reclaimed region (a fake table or fake closure
  with a destructor pointed at a system call);
* **calibration** of build-specific offsets and the sweep constant.

The laboratory has none of these. It has the crash, the offsets (via LFI), and a
clear statement of the gap.

### 8.4 What the differential does and does not prove

It proves: under one trigger, one 8.4.26 build corrupts and four patched builds
do not, with OOM present everywhere.

It does not prove: that the patch caused the difference (the builds also differ
in version), that the rate is stable across hosts, or that a clean patched run
generalises to other configurations.

---

## 9. Limitations

1. **Independence.** Sequential trials on one worker; intervals are approximate.
2. **Sample size.** 20 trials separate 10/20 from 0/20 but bound the rate only
   loosely.
3. **Single host, single build.** glibc, compiler and configure options change
   allocator layout.
4. **Synthetic applications.** A's include and B's handler pair were built for
   the test; real targets must already expose them.
5. **Partial attribution.** Detection site confirmed, creation site unknown.
6. **No exploitation of C.** No disclosure, no control transfer, no RCE.
7. **The chunked post_max bypass is literature-derived**, not measured here.

---

## 10. Defensive guidance

1. **Upgrade to a fixed release** — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. This is
   the only complete fix.
2. **Disable `session.upload_progress`** if the application does not need upload
   progress reporting. It is the producer for the early-session path.
3. **Apply resource limits as defence in depth** — request-body and upload caps,
   concurrency limits, worker lifetimes. These are mitigations, not substitutes
   for patching.
4. **Monitor** worker crashes, `zend_mm_heap corrupted`, and multipart requests
   with very large numbers of parts.
5. **Treat a clean patched run as evidence for that configuration**, not as proof
   of immunity.

Two cautions on configuration advice:

* Disabling the memory limit is **not** a safe general mitigation. It converts a
  bounded memory problem into unbounded resource consumption, and an underlying
  allocation failure can still reach the vulnerable path.
* Lowering `post_max_size` may reduce exposure in some deployments, but this
  laboratory's own results show that the relationship between body size and
  memory pressure is not straightforward (see the non-monotonic sizes in 7.4). It
  should not be presented as a guaranteed fix.

---

## 11. Verification and availability

This report is intended to be checkable without being a working exploit kit.

**What is published:** the measurements, the statistical method, the source
analysis, the patch map, and hashes for every artifact. A reader can verify that
the documents are the ones referenced by the report:

```bash
sha256sum -c ARTIFACTS.sha256
```

**What is included:** the request-generation code for Categories A, B and C, the
trigger configuration, and the payload strings used in the A and B chains. They
are published alongside this report so the experiments can be reproduced and the
defenses tested. They are also exploitation code: run them only against the
isolated laboratory in `lab/`, never against a system you do not own or have
written authorization to test.

**What can still be reproduced from this document:** the environmental
conditions (section 5), the observation protocol (section 6.1), the statistical
treatment (section 6.3), and the attribution method (section 6.4). A team with
its own lab can reconstruct a comparable experiment from those alone.

**Availability:** the harness and raw evidence are in the repository, together
with this report. The hashes below let a reader confirm that what they downloaded
is what the report describes.

---

## 12. Appendix

### 12.1 Source excerpts that matter

The gate at shutdown (main.c:1928):

```c
if (PG(modules_activated)) {
    zend_deactivate_modules();
}
```

The early session (session.c:3308):

```c
php_rinit_session(0);
PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0);
```

The limit branch (zend_alloc.c:533):

```c
if (!heap->fallible && add_size > heap->hard_limit - heap->real_size) {
    zend_mm_hard_limit_error(...);
}
if (!ZEND_HAS_OOM()) { zend_mm_delayed_error(...); }
return heap->fallible ? FAILURE : SUCCESS;
```

The delayed handler's terminal case (zend_alloc.c:3642):

```c
if (!execute_data) {
    zend_bailout();
}
```

### 12.2 Artifacts

| File | Contents |
|---|---|
| php2shell.py | exploit framework, modes auto/all/a/b/c |
| c_validate.py | evidence-model validator (v2.1) |
| c_minimize.py | two-parameter minimizer with OOM-on-both rule |
| ci_validate.sh | CI gate |
| c_cases.json | machine-readable case roles |
| PATCH_MAP.md | claim-to-code map with epistemic labels |
| C_ATTRIBUTION.md | detection backtrace and reading |
| C_MINIMIZED.md | reproducer sizes and rejection rationale |
| C_VALIDATION.md | 20-trial results with intervals |
| c_validation.json | full report incl. per-trial records |
| ARTIFACTS.sha256 | end-to-end hash manifest |
| debug/ | gdb command file, runner, trigger |

### 12.3 Chronology

```
2026-10-21  PHP security release; advisory published
2026-10-22  labs built; A and B reproduced; C trigger developed
2026-10-22  corruption confirmed; gdb attribution; minimization
2026-10-23  20-trial validation; CI gate; this document
```

### 12.4 Glossary

* **OOM** — an allocation failing against `memory_limit`.
* **Detection site** — where the process notices the damage.
* **Creation site** — where the damage was written. Unknown here.
* **Differential** — a difference in observed outcomes between builds.
* **Corruption** — in this report, a `zend_mm_heap corrupted` panic and abort.

---

*Written from the laboratory artifacts, not from memory. Where the evidence
stopped, the text says so.*
