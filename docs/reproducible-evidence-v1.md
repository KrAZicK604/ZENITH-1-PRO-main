# Reproducible Evidence v1 (experimental)

This module records a bounded logistic-map orbit as exact Python float hex
values and verifies the payload SHA-256 before independently replaying the
existing deterministic implementation.

Run: `uv run --locked --group security python -m unittest discover -s tests -v`

The verifier returns PASS, FAIL or ABSTAIN. PASS means local replay matched
the stored data; it does **not** prove a trustworthy clock, independent
scientific review, tamper-proof origin, cross-platform bitwise reproducibility,
or a novel mathematical result. SHA-256 is unsigned and cannot authenticate
who produced the record. Timestamp provenance is host-unattested. The
implementation does not alter the application or production permissions.

Trust posture: PAPER_ONLY / PROMOTION_BLOCKED / productionAuthority NONE.
