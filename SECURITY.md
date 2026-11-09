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

## Reporting

This repository documents a vulnerability that has already been fixed upstream.
It is not a disclosure channel. Report issues in the code here via GitHub issues;
report PHP issues to the PHP project.

## No warranty

The code is provided as-is for research and education. It may crash, corrupt memory,
or behave differently on your build.
