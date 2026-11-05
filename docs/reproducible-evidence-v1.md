# Reproducible Evidence v1 (experimental)

This module records a bounded logistic-map orbit as exact Python float hex
values and verifies both the payload SHA-256 and a second canonical SHA-256
covering the complete record, including safety and timing metadata, before
replaying the existing deterministic implementation. The verifier requires
an explicitly bounded orbit and strictly validates metadata, including UTC
format, a nonnegative monotonic duration, PAPER_ONLY, promotionBlocked=true,
and productionAuthority NONE. Older experimental records without the full
record checksum are rejected rather than silently accepted.

Run: `uv run --locked --group security python -m unittest discover -s tests -v`

The verifier returns PASS, FAIL or ABSTAIN. PASS means local replay matched
the stored data; it does **not** prove a trustworthy clock, independent
scientific review, tamper-proof origin, cross-platform bitwise reproducibility,
or a novel mathematical result. SHA-256 is unsigned and cannot authenticate
who produced the record. A writer who can change evidence can also recompute
both hashes. The experiment and verifier share the same local orbit
implementation, so PASS is not an independent scientific oracle. Timestamp
provenance is host-unattested. The
implementation does not alter the application or production permissions.

## Verification resource contract

Before serialization, key-set construction, hashing or metadata parsing, the
verifier accepts only plain built-in JSON values. Traversal is limited to depth
8, 4,096 visited values (including mapping keys), 4,096 characters per string,
and 256 bits per integer. Repeated references count on every visit. Subclasses
are rejected rather than invoking custom serialization or container methods.
Canonical JSON is then encoded incrementally with a 100,000-byte output cap;
escape expansion counts against that cap. Existing full-budget generated
records retain identical canonical bytes and checksums.

These limits bound verifier work on an already-decoded object. They do not
bound the caller's file read, JSON parser, existing input allocation, concurrent
mutation, or operating-system resource availability. Callers must limit bytes
before parsing and must not mutate a record during verification. MemoryError
inside verification returns FAIL; this is not a process sandbox or a guarantee
of recovery after an operating-system kill.

Trust posture: PAPER_ONLY / PROMOTION_BLOCKED / productionAuthority NONE.
