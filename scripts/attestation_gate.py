"""Fail-closed policy for a trusted-main GitHub evidence attestation job.

Checks source identity and original producer-run context; this is not itself
an attestation, signature verifier, or replacement for GitHub branch protection.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from collections.abc import Mapping

REPOSITORY = "KrAZicK604/ZENITH-1-PRO-main"
MAIN_REF = "refs/heads/main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
CONTEXT_KEYS = (
    "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME",
)


class AttestationGateError(ValueError):
    """A privileged provenance precondition is not satisfied."""


def check_context(
    manifest: Mapping[str, object],
    environment: Mapping[str, str],
    checked_out_commit: str,
    python_version: str,
) -> None:
    """Require a protected-main push and evidence from this exact workflow run."""
    required = {
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": MAIN_REF,
        "GITHUB_REF_PROTECTED": "true",
    }
    for key, expected in required.items():
        if environment.get(key) != expected:
            raise AttestationGateError(f"untrusted GitHub context: {key}")
    sha = environment.get("GITHUB_SHA", "")
    if not SHA.fullmatch(sha) or sha != checked_out_commit:
        raise AttestationGateError("GITHUB_SHA must equal checked-out HEAD")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environment.get(key, "")
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or not value.strip("0"):
            raise AttestationGateError(f"invalid run identity: {key}")
    if not isinstance(manifest, dict):
        raise AttestationGateError("invalid manifest object")
    if manifest.get("git_head") != sha or manifest.get("python_version") != python_version:
        raise AttestationGateError("manifest checkout or Python version mismatch")
    if (manifest.get("status") != "PAPER_ONLY"
        or manifest.get("promotion_blocked") is not True
        or manifest.get("production_authority") != "NONE"
        or manifest.get("integrity") != "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION"
        or manifest.get("clock_provenance") != "HOST_CLOCK_UNATTESTED"):
        raise AttestationGateError("invalid evidence safety/authority markers")
    source = manifest.get("github_context")
    if not isinstance(source, dict):
        raise AttestationGateError("missing manifest run context")
    for key in CONTEXT_KEYS:
        if source.get(key) != environment.get(key):
            raise AttestationGateError(f"manifest not produced by this run: {key}")


def main() -> int:
    try:
        # Do not process an artifact at all if this job is not a trusted-main push.
        minimal = {
            "git_head": os.environ.get("GITHUB_SHA", ""),
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "status": "PAPER_ONLY", "promotion_blocked": True,
            "production_authority": "NONE",
            "integrity": "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION",
            "clock_provenance": "HOST_CLOCK_UNATTESTED",
            "github_context": {key: os.environ.get(key, "") for key in CONTEXT_KEYS},
        }
        check_context(minimal, os.environ, os.environ.get("GITHUB_SHA", ""), minimal["python_version"])
        from repro_evidence import commit_sha, verify
        root = Path(__file__).resolve().parents[1]
        manifest = root / ".evidence" / "repro-manifest.json"
        if (root.is_symlink() or manifest.parent.is_symlink()
            or manifest.is_symlink() or manifest.with_name(manifest.name + ".sha256").is_symlink()):
            raise AttestationGateError("symlink in attestation evidence path")
        record = verify(root, manifest)
        check_context(record, os.environ, commit_sha(root), ".".join(map(str, sys.version_info[:3])))
    except (AttestationGateError, OSError, ValueError, UnicodeError) as error:
        print(f"ATTESTATION_BLOCKED: {error}", file=sys.stderr)
        return 1
    print(f"ATTESTATION_POLICY_PASS commit={record['git_head']} authority=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
