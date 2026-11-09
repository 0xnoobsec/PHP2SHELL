# php2shell — laboratory study of PHP2Shell

A three-part study of PHP's request lifecycle, session handling, and out-of-memory
behavior, covering CVE-2026-109618 and CVE-2026-109619, plus two application-level
session attack patterns that a PHP upgrade does not fix.

**This repository contains working exploitation code.** It was used only against
the isolated laboratory in `lab/`. See [SECURITY.md](SECURITY.md) before running
anything.

## The series

| Part | File | What it covers |
|---|---|---|
| 1 | [docs/PHP2SHELL_PART1_FOUNDATIONS.md](docs/PHP2SHELL_PART1_FOUNDATIONS.md) | lifecycle, sessions, a beginner Docker lab, C fundamentals, OOM handling |
| 2 | [docs/PHP2SHELL_PART2_SOURCE_ANALYSIS.md](docs/PHP2SHELL_PART2_SOURCE_ANALYSIS.md) | the 8.4.26 → 8.4.27 source diff and what it does and does not establish |
| 3 | [docs/PHP2SHELL_PART3_RESEARCH.md](docs/PHP2SHELL_PART3_RESEARCH.md) | the five-build matrix, 20 trials each, GDB analysis, all three categories |

A single-file technical report with the full methodology is in
[docs/WRITEUP.md](docs/WRITEUP.md).

## Headline results

| Research question | Finding |
|---|---|
| Ordinary OOM reproducible | yes, all five tested builds |
| Allocator corruption observed | 10/20 trials on PHP 8.4.26 |
| Corruption on patched comparisons | 0/20 on each of 8.4.27, 8.3.36, 8.2.35, 8.5.12 |
| Original corruption site identified | no |
| RCE through the memory corruption | no |

## Layout

```text
docs/       the series and the technical report
lab/        Dockerfiles, php.ini files, test applications (cat-a, cat-b, cat-c*)
poc/        harness: php2shell.py, validators, minimizer, debug helpers
evidence/   raw container logs and the Category B verification record
```

## Running the lab

```bash
cd lab
docker compose up -d --build          # cat-a (8081), cat-b (8082), cat-c (8083)
cd cat-c-vuln && docker build -t p2s-c8426 . && docker run -d -p 8084:80 p2s-c8426
```

The vulnerable build is PHP 8.4.26 with a 16M limit and a single prefork worker.
Patched comparisons use the same configuration with 8.4.27, 8.3.36, 8.2.35 and
8.5.12.

## Scope and ethics

* Everything here targets a local, disposable environment.
* Do not point the harness at systems you do not own or have written authorization
  to test.
* The application-level chains (A and B) are ordinary web vulnerabilities. They
  are included because defenders need to recognize them, not because publishing a
  PHP upgrade advisory is sufficient — it is not.

## License

Code: MIT (see [LICENSE](LICENSE)). Prose: CC BY 4.0.

## Credits

The original PHP2Shell research is by Calif: https://calif.io/php2shell/
