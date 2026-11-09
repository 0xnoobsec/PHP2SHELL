# Patch map — claims, code references, and epistemic status

Labels:

* **[OBSERVED]** — measured in this lab, with an artifact.
* **[SOURCE]** — read directly from php-src at the stated tag.
* **[HYPOTHESIS]** — plausible, not established.
* **[UNKNOWN]** — no evidence either way.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | The trigger reaches `memory_limit` on every tested build | [OBSERVED] | `c_validation.json` — OOM 20/20 on all five builds |
| 2 | 8.4.26 corrupts the heap under this trigger (10/20, 95% CI 0.30-0.70); the four patched builds do not (0/20, upper bound 0.16) | [OBSERVED] | `c_validation.json`, `evidence/*.log` |
| 3 | Corruption is detected in `zend_mm_get_next_free_slot` → `zend_mm_panic("zend_mm_heap corrupted")` | [OBSERVED] | `C_ATTRIBUTION.md` backtrace |
| 4 | Detection occurs while lexing the **next** request's script (`modules_activated=1`, `ps_id=nil`) | [OBSERVED] | same backtrace + gdb globals |
| 5 | The **creation site** of the corruption is not identified | [UNKNOWN] | no watchpoint/ASAN data |
| 6 | 8.4.27 adds fallible hash operations (`HASH_FALLIBLE`, `HASH_NOMEM`, `fpemalloc`) | [SOURCE] | `Zend/zend_hash.c` diff, 302 lines |
| 7 | Bucket insertion order is unchanged in 8.4.27 (`nNumUsed++` before key init) | [SOURCE] | `zend_hash.c:1123-1137` (8.4.27) |
| 8 | A non-fallible allocation over the soft limit is allowed to return SUCCESS with a delayed OOM queued | [SOURCE] | `zend_alloc.c:533-560` — `return heap->fallible ? FAILURE : SUCCESS` |
| 9 | The hard-limit path can terminate immediately | [SOURCE] | `zend_mm_hard_limit_error()` is `ZEND_NORETURN` |
| 10 | Delayed OOM is consumed at VM interrupt / after script execution; bailout when no execute_data | [SOURCE] | `zend.c:1944`, `zend_execute.c:4087`, `zend_alloc.c:3642-3685` |
| 11 | The exact consumption instant relative to multipart parsing is unverified | [UNKNOWN] | no `zend_handle_delayed_oom` breakpoint |
| 12 | 8.4.27 prevents object instantiation during the rfc1867 callback (`incomplete_classes_only`) | [SOURCE] | `ext/session/session.c` diff |
| 13 | Session RSHUTDOWN is skipped when `modules_activated=0` after an OOM | [OBSERVED] + [SOURCE] | gdb trace + `main.c:1928` |
| 14 | A and B succeed on 8.4.27 because their prerequisites are application-level, not PHP-version flaws | [SOURCE] + [INTERPRETATION] | A/B results + feature semantics |
| 15 | A/B on 8.4.27 implies PHP 8.4.27 is vulnerable to those chains | **FALSE** — application prerequisites only | see capability statement |

| 16 | Corruption rate on 8.4.26 is 10/20; Wilson two-sided 95% CI [0.30, 0.70] | [OBSERVED] | `c_validation.json` stats block |
| 17 | The trials are sequential on one worker, so the interval is approximate: runs are not strictly independent | [METHOD] | `statistics.independence` in the report |
| 18 | 0/20 on patched builds means **no corruption observed**; one-sided 95% upper bound 0.14 | [OBSERVED] + [METHOD] | `corruption_upper95_onesided` |
| 19 | The differential is a difference in **observed outcomes**, not proof the patch caused it | [INTERPRETATION] | `differential_basis` |
| 20 | Code execution requires an explicit `execution_evidence` record (kind, path, 64-hex sha256); none exists, so the verdict cannot become Demonstrated by accident | [METHOD] | `verdict()` in `c_validate.py` |
| 21 | The backtrace confirms the **detection** site and does not identify the causal request or the creation site | [OBSERVED] + [UNKNOWN] | `C_ATTRIBUTION.md`, `attribution` block |

## Statistical method (explicit)

* Intervals: **Wilson score interval, two-sided 95%, z = 1.96**.
* Zero-event builds: **exact one-sided 95% upper bound** `1 - 0.05^(1/n)`
  (Clopper-Pearson upper limit) — 0.14 for n = 20.
* Independence: trials are run **sequentially against a single worker**. Worker
  state and allocator history can correlate consecutive trials, so the intervals
  are approximate summaries of this run, not a sampling of independent identical
  experiments.

## How the patch is believed to prevent the corruption

Two independent mechanisms, both [SOURCE], neither [OBSERVED] end to end:

1. **Allocator deferral** — a non-fallible allocation that exceeds the soft limit
   returns successfully while a delayed OOM is recorded, so an insert can finish
   instead of unwinding mid-bucket.
2. **Session serialisation gating** — during the rfc1867 callback the serializer
   keeps objects as `__PHP_Incomplete_Class`, so no userland code runs before
   RINIT.

Which of these is responsible for the *specific* corruption observed here is
**[HYPOTHESIS]**. The differential is [OBSERVED]; the causal path is not.
