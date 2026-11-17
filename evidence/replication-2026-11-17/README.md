# Replication run, 17 November 2026

A second, independent execution of the study, made after the validator fix in
ERRATA item 1. It does not replace `evidence/*.log`; it is a separate
confirmation that the corrected figures reproduce.

| Field | Value |
|---|---|
| Run window | 2026-11-17T22:16:39Z – 2026-11-17T22:24:32Z |
| Validator | c_validate v2.2.0 (counts the whole log, not a tail) |
| Targets | PHP 8.4.26 (vulnerable), PHP 8.4.27 (patched) |
| Trials | 20 per target |
| Images | built from `lab/cat-c-vuln` with `ARG PHP_VERSION=8.4.26` and `8.4.27` |
| Configuration | mod_php, prefork, one worker, `memory_limit=16M` |
| Result | 8.4.26: 20/20 OOM, 20/20 corruption, 20 abort events · 8.4.27: 20/20 OOM, 0/20 corruption |
| Differential | Confirmed |
| Gate | PASS |

Command, from the repository root:

```bash
python3 poc/c_validate.py \
  --target "8.4.26|http://127.0.0.1:8084/decode.php|vulnerable|php2shell-cat-c-vuln|http://127.0.0.1:8084/probe.php" \
  --target "8.4.27|http://127.0.0.1:8088/decode.php|patched|php2shell-c8427|http://127.0.0.1:8088/probe.php" \
  --trials 20 --evidence-dir evidence_run2 --out c_validation_run2.json
```

`REPORT.json` is that report with its evidence paths rewritten from
`evidence_run2/` to this directory, so `poc/recount.py` can check it in place:

```bash
python3 poc/recount.py --report evidence/replication-2026-11-17/REPORT.json --root .
```

## Hashes

| File | SHA-256 |
|---|---|
| 8.4.26.log | `5d1b6f2dd2cbe69a12710c0b5fb28f461c2f982adf557743e141dd5ae14b0a02` |
| 8.4.27.log | `ef17757dd6cf3fa0c94333d01ee900899c9c3775380073401aa40fb1489fc8e1` |

Both are the container logs as captured at the end of the run, complete rather
than tailed.
