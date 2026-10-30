# ZENITH-1-PRO v0.1.0 Release Evidence

## Verified publication

Release: v0.1.0

Tag commit: `fb384877afec4ba0d0d72e992901c2e58863f1d8`

Published: `2026-10-28T05:45:51Z`

The published tag has not been rewritten.

## Exact release-candidate checks

- [smoke-test — PASS](https://github.com/KrAZicK604/ZENITH-1-PRO-main/actions/runs/40638367921)
- [Analyze (actions) — PASS](https://github.com/KrAZicK604/ZENITH-1-PRO-main/actions/runs/40638368251)
- Analyze (python) — PASS, in the same CodeQL run

The recorded smoke-test run passed 19 unit tests, Bandit and strict pip-audit.

## Post-release verification

PR #29 corrected the changelog publication date.

Current protected main: `40f0c6891f64e74a1a49d3a32ed55a5fbf532343`

All three required checks passed on this commit.

PR #28 was closed without merging. Its invalid filelock downgrade was not introduced into main.

## Outstanding independent evidence

Signed-in security-alert inventory: NOT INDEPENDENTLY VERIFIED.

Full repository-history credential screening: NOT VERIFIED.

Comprehensive external-network and persistent-write behavior audit: NOT VERIFIED.

Independent human release review: NOT RECORDED.

These are outstanding review items and must not be described as passed without evidence.

## Authorization

PAPER_ONLY: true

PROMOTION_BLOCKED: true

productionAuthority: NONE
