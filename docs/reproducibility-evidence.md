# Reproducibility evidence gate (v1)

This workflow produces an unsigned source-integrity inventory after the unit, static-security,
and dependency-audit gates succeed. It is not a signature, independent security audit,
scientific proof, or production authorization.

## Fields and limits

The manifest records the checked-out Git commit, SHA-256 for every tracked file
(including source, tests, dependency lockfile and workflow), CI event/run identifiers,
Python version, a UTC host-clock timestamp, and monotonic elapsed duration.
The timestamp is HOST_CLOCK_UNATTESTED. A manifest and its sidecar checksum
can both be replaced by an attacker controlling the runner.
GitHub artifact transport adds a SHA-256 digest but not an independent signature.

Generation fails closed for dirty tracked files, GITHUB_SHA mismatch, unsafe paths,
symlinks, empty or duplicate tracking lists, and existing evidence.
Verification fails closed for changed content, wrong checkout, missing files, altered
sidecar, and promotion/authority changes. The evidence format remains PAPER_ONLY,
PROMOTION_BLOCKED with production authority NONE.

## Independent offline check

Check out the manifest's exact git_head (on PRs this may be a generated merge
commit rather than the branch tip). Download both files from the GitHub
repro-evidence artifact into .evidence/ and run:

    python scripts/repro_evidence.py verify

A passing check reports EVIDENCE_VERIFIED, the exact commit and file count.

For a local trial in a clean Git working tree:

    python scripts/repro_evidence.py create
    python scripts/repro_evidence.py verify

The generator intentionally refuses to overwrite an existing manifest.
Archive evidence separately before repeating the experiment.

## What this does NOT establish

This does not authenticate the origin of results, guarantee a trusted clock,
prove that tests are scientifically adequate, or establish operational
readiness. Independent reviewer identity, signed attestations, calibrated
false-acceptance rates, and external scientific validation are separate gates.
