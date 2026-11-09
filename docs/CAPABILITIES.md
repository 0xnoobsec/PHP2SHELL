# php2shell — capability statement

Status as of the current artifacts. Every claim below was measured on the lab;
anything unmeasured is marked as such.

## 1. Summary

**A and B demonstrate conditional command execution through application-level
weaknesses.**

**C detects a reproducible OOM-associated heap-corruption and worker-abort
condition on the tested vulnerable build, with no corruption observed on the
tested patched builds. C does not demonstrate memory disclosure or code
execution.**

| Category | Capability | Status |
|---|---|---|
| A | LFI + session-file race -> command execution | working, application-dependent |
| B | serialize-handler mismatch -> object injection -> command execution | working, application-dependent |
| C | OOM -> heap corruption -> worker abort | working as DoS / patch test |
| C | memory disclosure / code execution | **not achieved** |

C is a **crash reproducer and patch-validation test**, not an RCE chain.

> A or B succeeding on PHP 8.4.27 does **not** mean PHP 8.4.27 is vulnerable to
> those chains. Their prerequisites are application-specific: an include sink in
> the application, or two session directories with different serialize handlers
> plus a loaded gadget class.

## 2. Category A — LFI race

**Mechanism:** `session.upload_progress` stores the client filename verbatim in
the session file; a slow chunked upload keeps the file alive while an include
sink reads it.

**Measured:** command execution (`uid=33(www-data)`) on PHP **7.4.33**, **8.1.34**
and **8.4.27** — including the patched 8.4.27, because A is a logic flaw.

**Methods, in order:** `session_race` -> `log_poison` -> `environ_poison` ->
`data_wrapper`. Fallback proven: with `--skip session_race`, log poisoning failed
and `environ_poison` landed via `/proc/self/environ`.

**Requires:** an include sink and upload-progress. Session path discovery, param
discovery and payload sanitisation (no `;`, no `"`) are automatic.

## 3. Category B — handler mismatch

**Mechanism:** a writer directory using `php_serialize` and a reader using `php`;
the pipe in a value becomes a key delimiter, and a destructor runs even when the
decode then fails.

**Measured:** `[GADGET] __destruct fired: uid=33(www-data)` on **7.4.33**,
**8.1.34**, **8.4.27**.

**Requires:** two endpoints with different serialize handlers and a gadget class
loaded on the reader side. Real phpggc chains only if `phpggc` is on PATH;
otherwise a lab stand-in gadget.

## 4. Category C — OOM / corruption

**Trigger:** chunked multipart, `PHP_SESSION_UPLOAD_PROGRESS` plus unique nested
`filename=""` records; followed by a progress-only request.

**Measured on 5 builds, 20 trials each (16M / 64M, prefork, 1 worker):**

| Build | OOM | Corruption | 95% CI |
|---|---|---|---|
| 8.4.26 | 20/20 | **10/20 (50%)** | [0.30, 0.70] |
| 8.4.27 | 20/20 | 0/20 | [0.00, 0.16] |
| 8.2.35 | 20/20 | 0/20 | [0.00, 0.16] |
| 8.3.36 | 20/20 | 0/20 | [0.00, 0.16] |
| 8.5.12 | 20/20 | 0/20 | [0.00, 0.16] |

Note: an earlier 5-trial run reported 5/5 on 8.4.26; 20 trials put the rate at
50%, so the smaller sample overestimated it.

* Intervals are **Wilson two-sided 95% (z = 1.96)**.
* `0/20` means **no corruption observed**, with an exact **one-sided 95% upper
  bound of 0.14** (`1 - 0.05^(1/20)`). It is not "immune".
* Trials run sequentially on one worker, so the intervals are approximate: the
  runs are not strictly independent.
* The differential is a difference in **observed outcomes**; source analysis and
  any causal claim are kept separate in `PATCH_MAP.md`.

**Attribution:** SIGABRT in `zend_mm_get_next_free_slot` ->
`zend_mm_panic("zend_mm_heap corrupted")`, reached while **lexing the next
request's script** (`lex_scan` -> `zend_compile`), with `modules_activated=1`
and `ps_id=nil`. The corruption is *created* by the OOM request and *detected* by
a later request. Creation site not established.

**Offsets:** `--offsets-via-lfi` reads `/proc/self/maps` and `libphp.so` through
an include sink and parses `.dynsym` (`zval_ptr_dtor=0x457150`,
`zend_call_function=0x44abc0`, delta `0xc590` on the 8.1.34 image).

**Not achieved:** memory disclosure, controlled execution, ASLR bypass.

## 5. Reproducer sizes

| Size | Role | Corruption (vuln / patched) |
|---|---|---|
| 600 x 45 | canonical regression gate | 10/20 · 0/20 (20 trials) |
| 493 x 45 | secondary, intermittent — measures variance | 2/5 · 0/5 (5 trials) |
| 560 x 45 | negative control (this config) | 0/5 · 0/5 |
| 520 x 45 | negative control (this config) | 0/5 · 0/5 |
| 145 x 45 | rejected — patched build loses OOM | 5/5 · 0/5 |

Rates are non-monotonic across these sizes. That is an observation about rates;
causation is not established. Five trials separate 5/5 from 0/5 in a lab but do
not estimate a probability precisely.

## 6. Tooling

| File | Role |
|---|---|
| `php2shell.py` | exploit framework: `-m auto\|all\|a\|b\|c`, per-category fallback chains, crawl, offsets |
| `c_validate.py` | N-trial validator, independent verdicts, patch differential |
| `c_minimize.py` | two-parameter minimizer with OOM-on-both acceptance rule |
| `c_cases.json` | machine-readable case roles (gate / probe / control / rejected) |
| `debug/gdb.cmd`, `run_trace.sh`, `trigger_oom.py` | lifecycle trace; no pointer dereference |
| `ci_validate.sh` | CI gate: fails on missing evidence, hash mismatch, OOM absence, trials below minimum |
| `PATCH_MAP.md` | claim-to-code map with [OBSERVED]/[SOURCE]/[HYPOTHESIS]/[UNKNOWN] labels |
| `c_validation.json` | machine-readable results: per-trial records, CIs, provenance, evidence hashes |
| `remote_cve.py` | published reference exploit; **does not run** in this environment (fails its own stage 1) |

## 7. Verdict model (v2)

Independent fields, each with an explicit unknown state:

| Field | Values |
|---|---|
| OOM observed | Yes / No / Unknown |
| Corruption observed | Yes / No / Unknown |
| Worker aborted | Yes / No / Unknown |
| Patch differential | Confirmed / Not observed / Inconclusive |
| Detection-site attribution | Confirmed / Partial / Unknown |
| Creation-site attribution | Confirmed / Unknown |
| Code execution | Demonstrated / Not demonstrated — requires an explicit `execution_evidence` record (kind, path, 64-hex SHA-256); free-form fields cannot flip it |

Rates carry Wilson 95% confidence intervals. Every verdict links to a hashed raw
log (`evidence/<target>.log`) and a provenance block.

## 8. What is explicitly not claimed

* No RCE via C.
* No memory disclosure or pointer leak from the corruption.
* No "works on any website": A needs an include sink, B needs a handler pair and
  a gadget class, C needs a finite memory limit below the body expansion.
* A clean patched result is evidence for the tested configuration, not a
  universal guarantee.

## 9. Reproduction

Labs: 8081/8082/8083 (8.1.34), 8084 (8.4.26 C), 8085 (8.2.35), 8086 (8.3.36),
8087 (8.5.12), 8088 (8.4.27), 8091/8093 (A on 7.4/8.4.27), 8094/8096 (B on
7.4/8.4.27), 8095 (debug build, loopback only).

```bash
python3 php2shell.py http://127.0.0.1 --self-test
python3 php2shell.py http://host/ -m auto
python3 c_validate.py --trials 5 --target '8.4.26|http://127.0.0.1:8084/decode.php|vulnerable|php2shell-cat-c-vuln' ...
```
