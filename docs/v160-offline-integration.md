# ZENITH and QOIIN V160: offline verification bridge

**Status: PAPER_ONLY · PROMOTION_BLOCKED · productionAuthority NONE**

This standalone command-line research tool is NOT imported by the Streamlit application. It has no network access, does not sign or transact, and does not modify a V160 register.

## Exact version compatibility

ZENITH's evidence_v1.py creates bounded zenith-evidence-v1 records with unsigned SHA-256 digests and deterministic replay checks. The bridge invokes the existing verify_evidence() method and prepares digest-only, unsigned handoff material. This does NOT authenticate the evidence or create a V160 checkpoint.

The independently distributed research kit is named QOIIN_ZENITH_V160_OFFLINE_REVIEW_KIT_VERIFIED.zip.
Its whole-file SHA-256 must be:

b8870eb26b598e356938ec63265b14aa19cf1a4c67dee82263ea4fa7608ec4df

The release ZIP is NOT included in this repository: historical examples contain a deliberately insecure demonstration HMAC key and local mock certificates. Compare the expected hash against a separately authenticated record before relying on it.

## Local commands

Run from the repository root. Before starting, set ZENITH_EVIDENCE to the exact existing evidence JSON path and ZENITH_HANDOFF to a NEW output filename. The export command writes to standard output and leaves evidence unchanged:

~~~sh
python scripts/zenith_v160_bridge.py export --evidence "$ZENITH_EVIDENCE" > "$ZENITH_HANDOFF"
python scripts/zenith_v160_bridge.py verify --evidence "$ZENITH_EVIDENCE" --handoff "$ZENITH_HANDOFF"
~~~

The handoff binds the exact bytes, original record checksum and payload checksum, but is explicitly UNSIGNED_NOT_A_V160_CHECKPOINT.

The offline V160 register audit requires an existing database, the exact SHA-pinned kit, Python 3.11+ and the optional cryptography package (used only by the isolated research verifier, not the Streamlit app). Obtain V160_DB, V160_KIT, V160_TRUSTED_TIP and V160_TRUSTED_GENESIS from authenticated custody records, not from files supplied by an untrusted proponent:

~~~sh
python scripts/zenith_v160_bridge.py audit \
  --kit "$V160_KIT" \
  --database "$V160_DB" \
  --expected-tip "$V160_TRUSTED_TIP" \
  --genesis-pin "$V160_TRUSTED_GENESIS"
~~~

The bridge checks the complete ZIP digest, member paths and size bounds, extracts source into a disposable directory, then calls only the V160 read-only audit under isolated Python. Incorrect pins fail closed. Authenticated conflicts produce a NONZERO exit status.

## Critical limits

- The ZENITH evidence handoff and the V160 register audit are **separately verified inputs**. No authenticated linkage between this specific ZENITH record and a V160 historical checkpoint exists until an independently signed subject-to-checkpoint commitment explicitly binds both.
- SHA-256 checksums and a successful replay do not prove scientific truth, sender identity, historical time or independent custody.
- Local mock signatures, timestamps, synthetic review keys and the sample HMAC key are unsuitable for production use.
- Caller-supplied hashes are not independently retained unless separately governed monitors actually retained them before later publication.
- This is not an OS-hardened sandbox. Symlink/path prechecks cannot defeat a privileged concurrent attacker.
- The productionAuthority remains NONE; no real telemetry, release authority, financial execution, deployment automation or wallet operations are enabled.

## Review acceptance

The GitHub PR must pass the current smoke-test, Analyze (actions) and Analyze (python) for the exact reviewed head. An independent security reviewer is still needed. No additional runtime dependencies, Streamlit writes, main-only signing permissions or workflow changes are required.

The next V161 research gate is a genuinely signed, externally witnessed subject-to-checkpoint commitment with independent historical timestamp and revocation evidence and multi-monitor conflict gossip. Locally signed test records must not be described as external evidence.
