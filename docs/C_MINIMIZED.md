# Minimized reproducer — CVE-2026-109618 corruption (v2, differential-safe)

Generated: 2026-10-22T20:23:15.851398Z

## Result

| Case | parts × depth | records | OOM | trials with corruption |
|---|---|---|---|---|
| baseline | 600 × 45 | 27000 | 5/5 | 5/5 |
| **minimized** | **493 × 45** | **22185** | 5/5 | 2/5 |
| patched control (8.4.27) | 493 × 45 | 22185 | 5/5 | 0/5 |

Size: **82.2%** of the baseline record count.

Differential preserved: **true**

## Why v2 exists

The first minimization reached 145 × 45 and reproduced corruption 5/5 on the
vulnerable build — but the **patched build stopped OOM-ing altogether** at that
size (0/5). "No corruption" there was just "no memory pressure", so the
differential was confounded and the result was rejected.

v2 adds the missing acceptance rule: a candidate must reach OOM on the
**vulnerable *and* the patched build**, and reproduce corruption only on the
vulnerable one. If the patched build loses the OOM, parts are grown until it
returns.

## Acceptance rules (v2)

1. Corruption reproduces in ≥2 of 3 trials during search.
2. OOM signal still present on the vulnerable build.
3. OOM signal present on the patched build at the final size.
4. Zero corruption on the patched build.
5. Final candidate re-verified with 5 trials on both.

## Scope

Corruption is a denial-of-service observation; no RCE attempted.

## Status of each size

| Size | OOM (vuln / patched) | Corruption (vuln / patched) | Role |
|---|---|---|---|
| **600 × 45** | 5/5 · 5/5 | **5/5 · 0/5** | **canonical reproducer** |
| 493 × 45 | 5/5 · 5/5 | 2/5 · 0/5 | secondary, intermittent evidence |
| 560 × 45 | 5/5 · 5/5 | 0/5 · 0/5 | negative control (this configuration) |
| 520 × 45 | 5/5 · 5/5 | 0/5 · 0/5 | negative control (this configuration) |
| 145 × 45 | 5/5 · **0/5** | 5/5 · 0/5 | **rejected** — patched build loses the OOM |

## Using 493 x 45

This size is kept as a **secondary, intermittent case** - deliberately, and not
as a regression test.

* **Purpose:** measure instability. A 2/5 rate shows that corruption is not a
  deterministic function of record count, which is the evidence a single
  pass/fail case cannot give you.
* **How to run it:** repeat trials and report a *rate* (e.g. 2/5, 6/15), never a
  boolean. Pooling more trials narrows the estimate; one run tells you nothing.
* **How not to use it:** never as a CI gate, never as the comparison case for
  vulnerable-vs-patched, and never as evidence that a target is exploitable.
  A 0/5 at this size would not mean "not vulnerable" either.
* **Machine-readable role:** `c_cases.json`, id `secondary-intermittent`.

The gate stays on 600 x 45. 493 exists to show the variance that 600 hides.

## Qualification on the non-monotonic pattern

The measurements show corruption **rates** that do not increase monotonically with
record count across the sizes tested (600 → 5/5, 560 → 0/5, 520 → 0/5, 493 → 2/5).

That is an observation about rates. It is **not** evidence that a specific
allocator state is responsible. Other variables could produce the same pattern:

* allocation order within the request (which record consumes which bin first);
* request/worker history (what the worker allocated before this request);
* timing and concurrency effects in the prefork worker;
* differences in how the multipart parser batches hash growth at each size.

A causal account would need instrumentation of the allocator at the OOM point, not
a rate table.

## Statistical caveat

Five trials per size give useful preliminary evidence and are enough to separate
5/5 from 0/5 in a lab. They do **not** estimate the underlying failure
probability with any precision — the 95% interval around 5/5 is wide, and 0/5
means "no failure observed in five", not "cannot fail". The separation is
compelling for this configuration; it is not a universal guarantee.

## Scope

Corruption is recorded as a denial-of-service observation. No memory disclosure
and no code execution were attempted, and none is claimed.
