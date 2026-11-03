# Trusted-main evidence provenance gate (draft)

The unsigned reproducibility manifest in PR #50 is useful for checking bytes and
Git object identity, but a manifest SHA-256 sidecar is not a cryptographic
identity or external provenance signature. This gated follow-up proposes a
separate GitHub Actions job that attests both the verified manifest and its
checksum **only after a successful protected `main` push smoke-test**.

## Separation of privilege

- The original `smoke-test` job retains workflow-level `contents: read` and has
  no OIDC (`id-token`) or attestation write permission. Pull requests and
  `workflow_dispatch` can generate and test **unsigned** evidence only.
- The `attest-main` job is conditional on a push to `refs/heads/main` in
  `KrAZicK604/ZENITH-1-PRO-main`, and depends on a successful `smoke-test`.
- Only `attest-main` has job-scoped `id-token: write`, `attestations: write`,
  and `artifact-metadata: write`. Its policy script additionally requires
  `GITHUB_REF_PROTECTED=true` to fail if branch protection disappears.
- The job downloads `repro-evidence` from the **same workflow run**, verifies
  its transport checksum, checks its Git object hashes against a separate
  checkout, and enforces matching SHA, repository, event, run ID and run
  attempt. A copied artifact from another run is rejected.
- `actions/download-artifact` v8.0.2 and `actions/attest` v4.2.2 are pinned to
  immutable Git commit SHAs; no unpinned third-party action is introduced.

## Independent verification after an approved main merge

Download the original `repro-evidence` artifact from the trusted `main` push.
Extract the manifest and sidecar to `.evidence/` in a byte-exact checkout of
its recorded commit; verify with the repository's locked environment:

    uv run --locked --group security python scripts/repro_evidence.py verify

Then use a supported GitHub CLI to verify the repository-backed Sigstore
attestation of each file (network access and a published attestation required):

    gh attestation verify .evidence/repro-manifest.json -R KrAZicK604/ZENITH-1-PRO-main
    gh attestation verify .evidence/repro-manifest.json.sha256 -R KrAZicK604/ZENITH-1-PRO-main

A reviewer must additionally inspect the verified signed statement's source
repository, workflow identity and commit, and check those against the intended
protected-main run. A valid signature alone does not prove that the GitHub
runner, underlying code, or scientific claims were independently audited.

## Research and authority limitations

**This draft cannot create a genuine signed attestation on a pull request**:
that would undermine the trust boundary. The first live signing attempt must
occur after the workflow is reviewed and merged to protected `main` using the
account's established independent-approval policy. Until that event, the
attestation job is unexecuted and signing behavior is UNVERIFIED, regardless of
how many PR unit tests pass.

Do not merge this or other drafts automatically, publish a release, or
interpret attestation as production, financial or scientific authorization.
`PAPER_ONLY`, `ABSTAIN`, `PROMOTION_BLOCKED`, `productionAuthority: NONE`.
