# C validation — publication checklist pass (v2.1)

Generated: 2026-10-22T21:20:05.180456Z
Tool: c_validate v2.1.0

## Results

| Build | Class | OOM | Corruption | Wilson two-sided 95% | One-sided 95% upper |
|---|---|---|---|---|---|
| 8.4.26 | vulnerable | 20/20 | 10/20 | [0.2993, 0.7007] | — |
| 8.4.27 | patched | 20/20 | 0/20 | [0, 0.1611] | 0.1391 |
| 8.2.35 | patched | 20/20 | 0/20 | [0, 0.1611] | 0.1391 |
| 8.3.36 | patched | 20/20 | 0/20 | [0, 0.1611] | 0.1391 |
| 8.5.12 | patched | 20/20 | 0/20 | [0, 0.1611] | 0.1391 |

Patch differential: **Confirmed**
Gate: **PASS**

## 1. Interval method, stated explicitly

> Wilson score interval, two-sided 95% (z=1.96)
>
> corruption_upper95_onesided = 1 - 0.05^(1/n) (Clopper-Pearson upper limit), reported when 0 events
>
> trials run sequentially against the same worker; worker state and allocator history can correlate them, so treat the intervals as approximate, not as a sampling of independent identical runs

The independence caveat is not boilerplate: the 20 trials run sequentially against
a single prefork worker, so heap state from trial *n* can influence trial *n+1*.
The intervals summarise this run; they are not a sample of 20 independent
identical experiments.

## 2. Patched-build conclusion kept narrow

`0/20` = **no corruption observed under the tested conditions**. It is not
immunity. The exact one-sided 95% upper bound is **0.1391** for every patched
build; the two-sided Wilson interval is [0.00, 0.16].

## 3. Differential vs causation

> difference in OBSERVED outcomes under this trigger; it is not by itself evidence that the patch caused the difference. Source analysis is separate and labelled in PATCH_MAP.md.

The experimental result is a difference in observed outcomes under one trigger.
The source-level explanation lives in `PATCH_MAP.md` and is labelled
[SOURCE]/[HYPOTHESIS]; it is not evidence produced by this experiment.

## 4. Attribution, kept separate

> detection site: confirmed by backtrace (C_ATTRIBUTION.md)
> creation site: unknown (no watchpoint / ASAN data)
> causal request: not established (corruption detected in a later request)

## 5. Execution evidence, strict

`Demonstrated` requires a record of the shape
`{"kind": "marker_file"|"command_output", "path": ..., "sha256": <64 hex>}`.
No free-form field can flip the verdict. No such record exists, so every build
reports `Not demonstrated`.

## 6. Evidence integrity, end to end

The report carries SHA-256 for the validator script, the CI gate, and every raw
log. Two entries (`c_cases.json`, `PATCH_MAP.md`) are `null` because those
inputs were added to the test directory **after** this run; they are covered by
the external manifest rather than retro-fitted into the report.

```
8344a6d96e8d8cee123a8653a1f24ca65f1ff5783263062feb534f73375c74b7  /tmp/cv3_report.json
15a4c5b100567eff390b3f4f468bb82f8bb8c07e70fdfe17ec86eab174831b1c  c_validate.py
4bc6463bb6ddec229747db4b01d65780ace45fb8492352febedc6228f8961cd0  c_cases.json
463c16571e300681d66fd898624aca60b58eb84572a732ee81a5c60e8d585677  PATCH_MAP.md
2c3d4b5b782fac9f540f82d7921a4eaba8a0166a2c46bdcd6cfb0a347904cf25  ci_validate.sh
af4401228efa54c3674e0bc25747761278f374322d5f4b99c7878b1fea8db476  evidence/8.2.35.log
3bfd6af2c06873403ae84e30dc1e0222cbb2ce721a22c72b51fa4dc038bca1fc  evidence/8.3.36.log
1a84750a9795729925bb152ade5118ad576ece14da5cd8fc8def0cc72aa73982  evidence/8.4.26.log
b5af008f4b79f7a4dbc65d36d910ae2f53fc8f780010fc77e46db2cd4f0d9385  evidence/8.4.27.log
586bc233ad20dee5ee22595a9b3e67de14d9b9fdf170c36aba5d7852edf57446  evidence/8.5.12.log
```

`ARTIFACTS.sha256` covers the report itself, every script, the case manifest,
the patch map, and all evidence logs. Verification:

```bash
sha256sum -c ARTIFACTS.sha256
```

## 7. What a reader should take away

* The vulnerable/patched **outcome difference is reproducible** at 20 trials.
* The **rate** is 50% on the vulnerable build, not 100% — the 5-trial run
  overestimated it.
* **Why** the patch changes the outcome is source-supported, not experiment-proven.
* The corruption's **origin** is still unknown; only its detection site is
  confirmed.
