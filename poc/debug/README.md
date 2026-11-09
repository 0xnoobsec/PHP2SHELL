# gdb trace — request lifecycle across an OOM

## Supported conclusion

On PHP 8.4.26 (`-g -O0`, `apache2handler`, prefork, 16M/64M), an OOM during
multipart parsing reaches `php_request_shutdown()` with:

* `PG(modules_activated) == 0` → `zend_deactivate_modules()` (main.c:1928) is
  skipped;
* session globals still populated (`PS(id)` non-NULL, `http_session_vars`
  carrying a type_info).

## Not established

* **Allocation lifetime.** A non-NULL pointer, and even a readable string, says
  nothing about whether the allocation is still valid. Address containment in a
  Zend MM region does not identify the owning allocation or its state.
* **Uniqueness of the cleanup path.** Showing that one gated call site is
  skipped does not prove no other path releases or resets the session globals;
  that needs the complete call graph in this exact revision.
* **What the next request observes.** Unproven by these artifacts.

## Why the pointer is never dereferenced

An earlier revision printed `ps_globals.id->val`. If the allocation is invalid,
that read may fault or return stale bytes; either way it is not evidence of
lifetime, and it can break the trace. The script now prints pointer values and
module-global scalars only.


## Provenance

**Source**

| Field | Value |
|---|---|
| Artifact | `php-8.4.26.tar.gz` (release tarball, not a git checkout) |
| SHA-256 | `c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662` |
| Verified against | php.net `releases/index.php?json&version=8.4.26` — **matches** |
| Release date | 24 Sep 2026 (tagged `security`) |
| Local patches | none — no git tree, no edits applied |

**Build**

```
CFLAGS='-g -O0' ./configure \
  --with-apxs2=/usr/bin/apxs2 \
  --disable-cgi \
  --without-pear
```

`PHP 8.4.26 (NTS)`, Zend 4.4.26, API 20240924, built 2026-10-22.
`ZEND_DEBUG` intentionally **off** so the Zend MM behaves like a release build.

**Runtime**

| Field | Value |
|---|---|
| SAPI | `apache2handler` (mod_php) |
| MPM | prefork, `MaxRequestWorkers 1` |
| OS | Debian GNU/Linux 12 (bookworm) |
| Compiler | gcc 12.2.0-14+deb12u1 |
| Debugger | GNU gdb (Debian 13.1-3) 13.1 |
| Container image | `sha256:58311ac213fa4...` (committed from `p2s-dbg`) |
| php.ini | memory_limit=16M, post_max_size=64M, max_file_uploads=5000, upload_progress On |

**What the hash match does and does not mean.** It establishes the identity of
the *source archive* against the stated official reference. It does **not**
establish that the resulting binary is reproducible: compiler version, linker,
dependency versions, configure options and generated build configuration all
affect the produced `libphp.so`, and therefore its symbol offsets. Reproduce the
build with the recorded toolchain before assuming identical addresses.

## Attribution caveat

The breakpoint values are observations at a point in one worker's request
lifecycle. Attributing them to the OOM request depends on that worker having
served it: the harness attaches to a specific pid, and `MaxRequestWorkers 1`
means only that pid can serve the trigger. Confirm the attached pid in the trace
(and that it is unchanged across the run) before treating the values as
belonging to the OOM request.

`run_trace.sh` now does this by construction: it records `worker pid before`
and `worker pid after`, warns if they differ, and **fails loudly** (non-zero
exit) if no worker pid is found or if gdb never reaches the breakpoint — so a
missing pid or a failed attach cannot masquerade as a successful trace.

## Isolation

The lab container is bound to `127.0.0.1:8095` only (verified: `ss -ltnp`
shows `127.0.0.1:8095`, not `0.0.0.0`). `trigger_oom.py` is **not purely
observational** — it deliberately generates a memory-exhaustion request that
aborts the worker. Keep it confined to this isolated lab; never aim it at a
host you do not own or have written authorisation to test.

## Usage

```
./run_trace.sh p2s-dbg 8095 dbgsess01
```

Requirements: `--cap-add=SYS_PTRACE` (default seccomp denies ptrace); attach to a
worker, not the master; one prefork worker so a single pid serves the request.
`ZEND_DEBUG` is off (`-g -O0`) so the allocator behaves like a release build.

## Symbols (8.4.26, this build)

```
_zend_bailout            T    (not zend_bailout)
php_request_shutdown     T
ps_globals               B
zif_system               t
closure_handlers         b
```


---

# Control comparison — 8.4.26 (vulnerable) vs 8.4.27 (patched)

## Official advisory (php.net, 21 Oct 2026)

> **CVE-2026-109618** … out-of-memory handling can interrupt PHP while internal
> request data is only partially initialized. Request cleanup may then treat the
> invalid data as valid.
>
> **CVE-2026-109619** … request-owned internal state can survive after its
> backing memory has been freed. A later request handled by the same worker may
> use that stale state before normal initialization resets it.

Highest risk is stated as mod_php, where the trigger runs before application
code. Mitigations listed: `memory_limit=-1`, low `post_max_size`.

## Fidelity vs the published environment

| Item | Calif / advisory | This lab |
|---|---|---|
| Release | 8.4.x, fixed at 8.4.27 | 8.4.26 (vulnerable) + 8.4.27 (control) |
| SAPI | mod_php (SAPI name `apache2handler`) | same — `apache2handler` |
| MPM | prefork, single worker | prefork, MaxRequestWorkers 1 |
| OOM precondition | memory_limit below body expansion | 16M vs 64M |
| upload_progress | On | On |
| distro | Debian 12 (bookworm) | Debian 12 |
| source build | docker-library release | same tarball, `-g -O0` for tracing |

## Measured behaviour (identical trigger, both builds)

| Step | 8.4.26 | 8.4.27 |
|---|---|---|
| probe before | pid 97, cookie 62 | pid 17, cookie 62 |
| OOM request | HTTP 200, OOM text | HTTP 200, OOM text |
| probe after A | same pid, 62 | same pid, 62 |
| B (progress, no file) | 200 | 200 |
| probe after B | same pid, 62 | same pid, 62 |
| worker aborts | **0** | **0** |

## Interpretation

The vulnerable and patched builds are **indistinguishable** under this sequence.
This is a successful reproduction of the OOM condition and an **inconclusive
test of the state-corruption behaviour** — not a failed reproduction of the
whole vulnerability.

What that does *not* mean: it is not evidence that the sequence fails to reach
the code the patch changes. Two builds can execute different code and still
produce identical external observations, which is exactly what a state-corruption
fix is designed to do — it removes an effect without changing the visible
outcome of ordinary requests.

## Patch scope (verified with git)

```
git diff php-8.4.26 php-8.4.27

Zend/zend_alloc.c      659 lines   delayed-OOM / hard-limit machinery
Zend/zend_hash.c       302 lines   not analysed here
ext/session/session.c   73 lines   see below
main/main.c             50 lines   see below
```

NEWS entry: *"Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state
corruption via bailout)."*

**main/main.c** adds `memory_hard_limit_percent` and `ZEND_MM_MAX_ALLOCS`,
makes `php_verror()` return early under OOM, skips discarding output buffers
while `PHP_OUTPUT_LOCKED`, calls `php_basic_early_rinit()` before
`sapi_activate()`, clears `EG(delayed_oom)` at shutdown, `ZVAL_UNDEF`s each
`PG(http_globals)` entry after dtor, and `clear_last_error()` before
`shutdown_memory_manager()`.

**ext/session/session.c** adds `PS(in_rfc1867_update)` and routes the
serializers through `php_session_unserialize_init()` /
`php_session_serialize_init()`, which set *incomplete classes only* while the
upload-progress callback runs before RINIT. `php_session_initialize()` also
aborts cleanly (and throws) if SID creation fails, instead of falling back.

## Why this sequence cannot show the difference

The session half of the fix only changes behaviour when the session payload
decoded during rfc1867 contains **object instances**: the patched build keeps
them as `__PHP_Incomplete_Class` and writes them back unchanged, while the
vulnerable build may run `__wakeup`/`unserialize_callback_func` at a point
where no user code should run. The payload used here is an upload-progress array
of scalars, so both builds follow the same path — consistent with the identical
measurements, and a concrete reason rather than an assertion.


---

# Code review — Zend/zend_hash.c (8.4.26 → 8.4.27)

## What changed

The patch introduces a *fallible* allocation mode throughout the table
machinery:

```
HASH_FALLIBLE / HASH_NOMEM          new flag + sentinel return
zend_hash_fupdate / fadd_new / flookup / fextend / fconvert_*
fpemalloc(...)                       allocation that may return NULL
zend_hash_do_fresize()               returns zend_result instead of void
zend_mm_delayed_error_or_panic()     replaces zend_error_noreturn()
```

31 references to `HASH_FALLIBLE`/`HASH_NOMEM` in the file.

**Modified invariant:** an allocation failure inside a table operation no longer
has to unwind via `zend_bailout()` mid-operation. The operation can instead
return `HASH_NOMEM` with the table left in its pre-operation state.

**What it protects:** exactly the "count published before the bucket is
initialised" window — if the operation cannot be interrupted halfway, teardown
never sees a bucket whose count was bumped but whose contents were not written.

## The notable finding

The inserted-bucket sequence is **byte-for-byte unchanged** in 8.4.27:

```c
1122: add_to_hash:
1123:     idx = ht->nNumUsed++;          /* still incremented first  */
1124:     ht->nNumOfElements++;
1125:     p = ht->arData + idx;
1126:     p->key = key = zend_string_init(str, len, ...);  /* still may fail */
1132:     p->h = ZSTR_H(key) = h;
1137:     ZVAL_COPY_VALUE(&p->val, pData);
```

So the patch does **not** fix this ordering. The mitigation must therefore come
from preventing `zend_string_init()` from `longjmp`ing at that point — i.e. from
the delayed-OOM machinery in `zend_alloc.c` (plus `EG(delayed_oom)` being reset
in `main/main.c` at shutdown), with the fallible hash paths used for the
internal arrays.

## Unverified link

I have **not** traced the exact path by which a failed `zend_string_init()` at
line 1126 becomes a delayed OOM rather than an immediate `zend_bailout()`. That
requires reading `zend_alloc.c`'s `_emalloc` path and the `ZEND_OOM_STATE`
machinery. Until that is traced, the statement above is the most likely
mechanism, not an established one.


---

# Allocator trace — how the bucket insert survives (8.4.27)

Answers the three questions raised in review.

## 1. Does `_emalloc()` defer, or can it still bail out here?

`Zend/zend_alloc.c:533`, `zend_mm_check_limit()`:

```c
if (heap->limit < heap->real_size || add_size > heap->limit - heap->real_size) {
    if (gc && zend_mm_gc(heap)) { ... }
    if (!heap->fallible && add_size > heap->hard_limit - heap->real_size) {
        zend_mm_hard_limit_error(heap, add_size ...);   /* ZEND_NORETURN */
    }
    if (!ZEND_HAS_OOM()) { zend_mm_delayed_error(...); }  /* queues + vm_interrupt */
    return heap->fallible ? FAILURE : SUCCESS;            /* <-- SUCCESS if not fallible */
}
```

So for the **soft** limit and a non-fallible allocation: the error is queued and the
call returns **SUCCESS**. The allocation proceeds; no longjmp at this point.

For the **hard** limit (`add_size > hard_limit - real_size`, non-fallible):
`zend_mm_hard_limit_error()` is `ZEND_NORETURN` — immediate termination.

`zend_string_init()` at `zend_hash.c:1126` goes through plain `emalloc` (not the
fallible variants), so it takes the **SUCCESS** branch under the soft limit.

## 2. Where is `EG(delayed_oom)` set, consumed, reset?

| Phase | Site |
|---|---|
| set | `zend_alloc.c:445` `state = ZEND_OOM_STATE_PENDING` + `vm_interrupt = true` |
| consume | `zend.c:1944` — after `zend_execute()` returns in `zend_execute_script()` |
| consume | `zend_execute.c:4087` — `zend_fcall_interrupt()` (VM interrupt) |
| consume | `zend_vm_def.h:10431` — opcode-loop interrupt handler |
| reset | `main.c` — `EG(delayed_oom).state = ZEND_OOM_STATE_NONE` at request shutdown entry, and again after `shutdown_memory_manager()` |

`zend_handle_delayed_oom()` raises the fatal error inside `zend_try`, then:

```c
if (!execute_data) {
    zend_bailout();     /* no userland frame: propagate, abort the request */
}
```

## 3. Which hash callers check `HASH_NOMEM`?

The fallible variants introduced by the patch — `zend_hash_fextend`,
`zend_hash_fupdate`, `zend_hash_fadd_new`, `zend_hash_flookup`,
`zend_hash_fconvert_packed_to_hash` — return `HASH_NOMEM` and are checked at
the call sites that use them (table init, resize, packed→hash conversion).

The string-key insert at `zend_hash.c:1126` does **not** use them: it calls the
ordinary non-fallible `zend_string_init`. Its safety therefore does **not** come
from `HASH_NOMEM` handling, but from the delayed-OOM behaviour in (1): the
allocation succeeds, `p->h` and `p->val` are written, and the bucket is complete.

## Corrected causal claim

The bucket insertion order is unchanged in 8.4.27.

The soft-limit path permits the non-fallible allocation to proceed while
recording a delayed OOM (`zend_alloc.c:533-560`). The resulting VM interrupt is
handled at a later interrupt-check point (`zend.c:1944`,
`zend_execute.c:4087`, `zend_vm_def.h:10431`). **The source supports this
mechanism; the exact handling point relative to multipart parsing and the bucket
insertion has not been observed in the lab.**

The hard-limit path is different: it can terminate immediately
(`zend_mm_hard_limit_error()` is `ZEND_NORETURN`), so the soft-limit
explanation cannot be applied without that qualification.

## Remaining verification items

* Break on `zend_handle_delayed_oom()` to observe when the pending error is
  actually handled.
* Establish whether the hard limit is crossed in the measured run.
* Keep the claim about the specific insertion site qualified until that trace
  connects source to runtime.

**Summary:** mechanism plausibly established from source; runtime timing still
unverified.
