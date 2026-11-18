# Replication run, 18 November 2026

A third execution of the Category C study, on the lab host, after the
17 November replication. It also re-runs Categories A and B on patched PHP
8.4.27 with their logs kept, and checks the harness fix in ERRATA item 12. It
does not replace `evidence/*.log` or `evidence/replication-2026-11-17/`.

Every container was started for this run from the existing lab images,
published on 127.0.0.1 only, and removed afterwards.

## Category C: 20 trials per build

| Field | Value |
|---|---|
| Run window | 2026-11-18T16:07:12Z - 2026-11-18T16:12:42Z |
| Validator | c_validate v2.2.0 (counts the whole log, not a tail) |
| 8.4.26 | image `p2s-c8426`, 20/20 OOM, 20/20 corruption, 20 abort events, worker pid tracked |
| 8.4.27 | image `p2s-c8427` (the October build, which has no `probe.php`; trials matched by time), 20/20 OOM, 0/20 corruption |
| Configuration | mod_php, prefork, one worker, `memory_limit=16M`, `post_max_size=64M` |
| Differential | Confirmed |
| Gate | PASS |

Command, run on the lab host:

```bash
python3 poc/c_validate.py --trials 20 \
  --target "8.4.26|http://127.0.0.1:18084/decode.php|vulnerable|p2s-verify-c8426|http://127.0.0.1:18084/probe.php" \
  --target "8.4.27|http://127.0.0.1:18088/decode.php|patched|p2s-verify-c8427|" \
  --evidence-dir runs/verify-20261118/evidence --out runs/verify-20261118/c_validation.json
```

`REPORT.json` is that report with its four evidence paths rewritten from
`runs/verify-20261118/evidence/` to this directory. Nothing else in it was
changed. The report as written on the lab has SHA-256
`8e4e593ae81807ad2873ceac8a5dc52ac080b7a68890fc0d8c29aef3486833cc`.

```bash
python3 poc/recount.py --report evidence/replication-2026-11-18/REPORT.json --root . --strict
```

Both logs begin at Apache's start-up, so each covers its container's whole life.

## Categories A and B on PHP 8.4.27

| File | What it is |
|---|---|
| `category-a-8.4.27.json` | `php2shell.py -m a` against image `p2s-a84` (PHP 8.4.27): the session-file race through the include sink ended in command execution as `www-data` |
| `category-a-8.4.27.log` | that container's log |
| `category-b-8.4.27.json` | `php2shell.py -m b` against image `p2s-b84` (PHP 8.4.27): the serialize-handler mismatch ran the lab gadget's destructor as `www-data` |
| `category-b-8.4.27.log` | that container's log |

These are application-level weaknesses in deliberately vulnerable lab apps.
They are not CVE-2026-109618 or CVE-2026-109619.

## The harness fix (ERRATA item 12)

| File | What it shows |
|---|---|
| `harness-c-8.4.26.log` | `php2shell.py -m c --verify-cmd "docker logs <container>"` with the session-id fix, against a fresh 8.4.26 container: 3 rounds, 3 `zend_mm_heap corrupted` lines, 3 worker aborts |
| `harness-c-8.4.27.log` | the same against 8.4.27: 3 rounds, out-of-memory reached, no corruption |

## Hashes

| File | SHA-256 |
|---|---|
| 8.4.26.log | `0df8c8ad5f9579b734f470876a6bb392ab0537036f36383da138e3acbad9c77f` |
| 8.4.27.log | `e980091ea366d4342fd8521d3c2b5a6ddae9e95d833620c342306934fec0df03` |
| category-a-8.4.27.json | `45996ec49fe89888b741b1151db00f31622deab9959093faae54ef26ed8eb177` |
| category-a-8.4.27.log | `c20a1051311b0dbf1fc5e5c763bb81284553e15e21e3936ca1d5535e5b195d61` |
| category-b-8.4.27.json | `ac7d54da0f786937ae6522c4882ec6362676836ab5f00f4b74857e2d71219295` |
| category-b-8.4.27.log | `4be3f454d0acbec20e2ed76d9efb5f78504718985d82abcb16bb34ddc3f7bf76` |
| harness-c-8.4.26.log | `039cc2dfe07aeafda5067d69b1861301ae38da40b7c9c0cf97c45a64cc49b076` |
| harness-c-8.4.27.log | `e110cddb337aa28a9f2d464dd1667aa4f825cd6eeb3b88de2ec7b1a577b32e84` |
