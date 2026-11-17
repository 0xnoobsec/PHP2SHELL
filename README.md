# php2shell - PHP2Shell Research Lab

This repository contains the lab setup, proof-of-concept code, test harness, and logs from my investigation of PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

I also tested two application-level session attack patterns that remain possible on patched PHP versions.

**This repository contains working exploitation code.** All testing was performed in an isolated lab environment. Read [SECURITY.md](SECURITY.md) before running anything.

> **Correction, 18 November 2026.** Earlier versions of this README, and the validation report, said PHP 8.4.26 showed allocator corruption in 10 of 20 trials. That was a counting error in the validator. The raw log shows the worker aborting with `zend_mm_heap corrupted` in all 20. The details, and seven smaller corrections, are in [ERRATA.md](ERRATA.md).

## Write-up

I've documented the research in a three-part series on **[cybersecly.com](https://cybersecly.com/resources)**:

1. **[Part 1: Internals and sessions](https://cybersecly.com/resources/php2shell-part-1-internals-and-sessions).** PHP request lifecycle, sessions, memory management, and OOM handling.
2. **Part 2: Source analysis and patches.** Comparing PHP 8.4.26 and 8.4.27 to understand the changes.
3. **Part 3: Reproduction and results.** Lab setup, test results, GDB analysis, and lessons from failed attempts.

This repository contains the code and supporting evidence discussed in the articles.

## Results

Five builds, 20 trials each, one configuration: Apache with mod_php, prefork, a single worker, `memory_limit = 16M`, `post_max_size = 64M`, upload progress on.

| Test | Result |
|---|---|
| OOM reproduced | 20/20 trials on each of the five builds |
| Allocator corruption and worker abort on PHP 8.4.26 | 20/20 trials |
| Allocator corruption on PHP 8.4.27 | 0/20 trials |
| Allocator corruption on PHP 8.3.36 | 0/20 trials |
| Allocator corruption on PHP 8.2.35 | 0/20 trials |
| Allocator corruption on PHP 8.5.12 | 0/20 trials |
| Original corruption site identified | No |
| RCE through memory corruption | Not demonstrated |

The results reflect the conditions of my lab. 20/20 is what one sequence of requests, at one size, did in one configuration, with the trials run one after another against the same container. It is not an exploitation probability. Elsewhere in the same log, two rounds of five trials ended with an abort in only 2 and 3 of them (see [ERRATA.md](ERRATA.md), item 2). Similarly, 0/20 does not mean corruption is impossible on patched builds: it means none was observed, and the logs of the four patched containers contain no abort at all.

The two application-level chains (Categories A and B) ended in command execution inside the lab's deliberately vulnerable apps. My lab record has them working on PHP 7.4.33, 8.1.34 and 8.4.27. I did not keep raw logs of those runs, so this repository holds no evidence for them beyond that record.

### Check the numbers yourself

You do not need Docker or the lab for this. It reads the published report and the published raw logs:

```bash
python3 poc/recount.py
python3 -m unittest discover -s poc/tests -v
```

`recount.py` matches every trial to the Apache exit notices logged during it, and to the worker's pid where the report recorded one, and prints the report's count beside the raw log's count.

## Repository structure

```text
lab/          Dockerfiles, PHP configurations, and test applications
  cat-a         include sink + upload progress (application-level)
  cat-b         serialize-handler mismatch (application-level)
  cat-c         unserialize() baseline for the detection probe
  cat-c-vuln    the PHP 8.4.26 study environment; takes PHP_VERSION
  cat-c-bw      PHP 8.4.26 on the Debian bookworm image, same limits
  cat-c-def     PHP 8.4.26 on bookworm with stock limits

poc/
  php2shell.py      the harness (Categories A, B and C)
  c_validate.py     N-trial validator for Category C
  c_minimize.py     reproducer minimizer
  recount.py        recounts a report from its raw logs
  logcount.py       the abort counter those three share
  ci_validate.sh    gate around c_validate.py
  tests/            unit tests; no Docker needed
  debug/            gdb command file, trace runner, and notes
  archive/          superseded versions, kept as they were run

evidence/     Raw container logs from the five-build run
ERRATA.md     Corrections
```

## Running the lab

Every port is published on `127.0.0.1` only. Keep it that way: these apps are deliberately vulnerable.

Start the application-level test environments:

```bash
cd lab
docker compose up -d --build
```

Services:

- Category A: `127.0.0.1:8081`
- Category B: `127.0.0.1:8082`
- Category C baseline: `127.0.0.1:8083`

These three build on PHP 8.1 by default. PHP 8.1 is end-of-life and never received the October 2026 fixes. The weakness in Categories A and B is in the application, not the PHP version, so to run them on a patched release pass the version when you build, for example `docker build --build-arg PHP_VERSION=8.4.27 lab/cat-a`.

Build and start the vulnerable PHP 8.4.26 environment separately:

```bash
cd lab/cat-c-vuln
docker build -t php2shell-cat-c-vuln .
docker run -d --name php2shell-cat-c-vuln -p 127.0.0.1:8084:80 php2shell-cat-c-vuln
```

The vulnerable environment uses PHP 8.4.26, the last 8.4 release without the fix. For a patched comparison in the same configuration, build the same directory with another version:

```bash
docker build --build-arg PHP_VERSION=8.4.27 -t p2s-c8427 .
docker run -d --name p2s-c8427 -p 127.0.0.1:8088:80 p2s-c8427
```

The October run used ports 8084 (8.4.26), 8088 (8.4.27), 8085 (8.2.35), 8086 (8.3.36) and 8087 (8.5.12).

## Running the validator

```bash
python3 poc/c_validate.py --trials 20 \
  --target '8.4.26|http://127.0.0.1:8084/decode.php|vulnerable|php2shell-cat-c-vuln|http://127.0.0.1:8084/probe.php' \
  --target '8.4.27|http://127.0.0.1:8088/decode.php|patched|p2s-c8427|http://127.0.0.1:8088/probe.php' \
  --evidence-dir runs/evidence --out runs/c_validation.json
```

Each target is `name|url|kind|container|probe url`. The validator needs to read the container's log through `docker logs`, so run it on the Docker host. Write to `runs/` as shown, not to `evidence/` or `poc/`, or you will overwrite the archived October files.

This request sequence makes the PHP 8.4.26 worker abort. Run it only against the containers above.

## Integrity

`poc/ARTIFACTS.sha256` and the report record SHA-256 values for the scripts and logs as they were for the October run. [ERRATA.md](ERRATA.md) item 6 goes through that list line by line, including the one entry that does not match a published file. The validator and minimizer that produced the October results are kept unmodified in `poc/archive/`.

`.gitattributes` stops git from converting line endings, so the hashes also verify on a Windows checkout.

## What is not claimed

- No code execution, and no memory disclosure, through the memory corruption.
- No identification of where the corruption is created. Only the place where the allocator notices it is known.
- No claim that a clean result on a patched build holds for other configurations.
- No claim that Categories A and B are the two CVEs. They need an include sink, or two endpoints with different session serialize handlers plus a loaded gadget class.

## Requirements

Docker with Compose, Python 3.8 or later, and the `requests` package for the harness and validator. `recount.py` and its tests need only the standard library.

## License

MIT. See [LICENSE](LICENSE).
