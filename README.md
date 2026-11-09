# php2shell - PHP2Shell Research Lab

This repository contains the lab setup, proof-of-concept code, test harness, and logs from my investigation of PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

I also tested two application-level session attack patterns that remain possible on patched PHP versions.

**This repository contains working exploitation code.** All testing was performed in an isolated lab environment. Read [SECURITY.md](SECURITY.md) before running anything.

## Write-up

I've documented the research in a three-part series on **[cybersecly.com](https://cybersecly.com)**:

1. **Foundations:** PHP request lifecycle, sessions, memory management, and OOM handling.
2. **Source analysis:** Comparing PHP 8.4.26 and 8.4.27 to understand the changes.
3. **Reproduction and findings:** Lab setup, test results, GDB analysis, and lessons from failed attempts.

This repository contains the code and supporting evidence discussed in the articles.

## Results

| Test | Result |
|---|---|
| OOM reproduced | All five PHP builds |
| Allocator corruption on PHP 8.4.26 | 10/20 trials |
| Allocator corruption on PHP 8.4.27 | 0/20 trials |
| Allocator corruption on PHP 8.3.36 | 0/20 trials |
| Allocator corruption on PHP 8.2.35 | 0/20 trials |
| Allocator corruption on PHP 8.5.12 | 0/20 trials |
| Original corruption site identified | No |
| RCE through memory corruption | Not demonstrated |

The results reflect the conditions of my lab. The 10/20 figure is an observed result, not an estimated exploitation probability. Similarly, 0/20 does not mean corruption is impossible on patched builds.

## Repository structure

```text
lab/        Dockerfiles, PHP configurations, and test applications
            (cat-a, cat-b, cat-c*)

poc/        php2shell.py, validators, minimizer, and debugging helpers

evidence/   Raw container logs and Category B verification records
```

## Running the lab

Start the application-level test environments:

```bash
cd lab
docker compose up -d --build
```

Services:

- Category A: `localhost:8081`
- Category B: `localhost:8082`
- Category C: `localhost:8083`

Build and start the vulnerable PHP 8.4.26 environment separately:

```bash
cd cat-c-vuln
docker build -t p2s-c8426 .
docker run -d -p 8084:80 p2s-c8426
```

The vulnerable environment uses PHP 8.4.26,
