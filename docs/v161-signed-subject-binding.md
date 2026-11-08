# QOIIN / ZENITH V161 — Subject-to-Checkpoint Signed Binding (LOCAL RESEARCH)

V161 extends V160 with a **read-only, role-separated, authenticated subject-to-tip binding**. It does not supply an independent external signer, trusted chronology, historical CRLs, or semantic certification.

## What the verifier checks

* The exact existing ZENITH `evidence_v1.py` replay and the PR #67 unsigned handoff, through `zenith_v160_bridge.verify_handoff`.
* The original, SHA-pinned V160 offline verifier runs against a consistent snapshot of an existing SQLite register, with an operator-supplied exact genesis and tip pin. Snapshot metadata is independently restricted to one ZENITH stream/session and two unchanged monitor IDs on both PRIOR and NEW checkpoint stages.
* A canonical trust policy for two distinct role keys (`source_reviewer` and `checkpoint_custodian`) from different declared organization IDs, different from V160 monitor public keys. Its SHA-256 must match a separately supplied pinned value.
* Both Ed25519 signatures, verified by OpenSSL, over **the same** domain-separated canonical subject body. That body binds the source file, record and payload digests, unsigned handoff digest, V160 kit SHA-256, register genesis/tip, count, stream/session, policy hash and epoch, and signer-supplied nonce digest. A nonce digest does not prove unpredictability or freshness.
* Optional authenticated conflicting signed claims for the same subject/session/nonce, with a distinct proposed tip, return `ABSTAIN_AUTHENTICATED_CONFLICT` (exit code 3). Invalid competitor signatures are `REJECT`, not conflict.

## Run against the actual GitHub repo

Place `v161_subject_binding.py` in `scripts/` of ZENITH-1-PRO-main, where the V160 bridge is already installed. Run from a trusted local checkout with Python 3.14.10 and an approved OpenSSL 3.x executable. Inputs must be sourced through their intended trust channels.

```
python scripts/v161_subject_binding.py \
  --evidence "$ZENITH_EVIDENCE" --handoff "$ZENITH_V160_HANDOFF" \
  --kit "$V160_KIT" --database "$V160_SQLITE_REGISTER" \
  --trusted-tip "$V160_OUT_OF_BAND_TIP" --trusted-genesis "$V160_OUT_OF_BAND_GENESIS" \
  --trust-file "$V161_TRUST_POLICY" --trust-pin "$V161_OUT_OF_BAND_POLICY_SHA256" \
  --statement-file "$V161_SIGNED_STATEMENT"
```

The program **does not generate private keys or sign statements**, issue timestamp tokens, mutate the database, connect a ZENITH node, interact with MetaMask/Stripe, or change release authority.

## Interpretation and limitations

`CRYPTO_VALID_EXTERNAL_RETENTION_ABSTAIN` means verified signatures under the *supplied* policy and locally consistent evidence/register snapshots. It **cannot** prove the policy hash was externally governed, the signers actually belong to independent organizations, the register existed before the later event, or the underlying science is correct. These require separately retained, authenticated out-of-band evidence and source-disjoint auditors.

V160 synthetic fixtures **must not** be uploaded as production credentials or evidence of external participation. A verification error is `REJECT` (exit 2); signed conflicting claims are an abstention (exit 3). Trust and source paths are preflight-checked, but this is not an OS sandbox against a privileged hostile process concurrently modifying files.

Baseline: PR #67 was merged into protected `main` at `645bd404bde9e771e41efc4a85104e5dd8726ecb` with all post-merge CI checks successful. No independent PR review was recorded; the full approval settings could not be read with available GitHub integration privileges. V161 changes must remain a separate draft research PR pending independent review.

**Status:** `PAPER_ONLY`, `ABSTAIN_EXTERNAL_PROVENANCE`, `ABSTAIN_EXTERNAL_WITNESS`, `PROMOTION_BLOCKED`, `productionAuthority NONE`, `UTC_HOST_UNATTESTED`.
