# Security and scope

## What this repository is

A laboratory reproduction and write-up. It contains:

* Docker definitions for a vulnerable PHP 8.4.26 environment and patched comparisons;
* working exploitation code (`poc/php2shell.py`) for the categories described in the series;
* raw evidence logs.

## Authorized use only

Run the harness **only** against:

* the lab defined in this repository, on your own machine, or
* systems for which you hold written authorization.

The application-level chains in `lab/cat-a` and `lab/cat-b` are real vulnerabilities.
Using them against a third party without permission is a criminal offence in most
jurisdictions.

## Keep the lab on your own machine

* Every port in `lab/docker-compose.yml` and in the README is bound to `127.0.0.1`.
  Do not change that to publish the lab on a network. `lab/cat-a` and `lab/cat-b`
  give command execution to anyone who can reach them.
* The lab does not restart by itself. Stop it when you are done: `docker compose down`
  in `lab/`, and `docker rm -f` for the Category C containers you started by hand.
* `poc/c_validate.py`, `poc/c_minimize.py` and `poc/debug/trigger_oom.py` send a
  request sequence that makes an unpatched PHP worker abort. They are not
  observational. Aim them only at the lab containers.
* `poc/recount.py` and the tests in `poc/tests/` read files only. They send nothing.

## Reporting

This repository documents a vulnerability that has already been fixed upstream.
It is not a disclosure channel. Report issues in the code here via GitHub issues;
report PHP issues to the PHP project.

## No warranty

The code is provided as-is for research and education. It may crash, corrupt memory,
or behave differently on your build.
