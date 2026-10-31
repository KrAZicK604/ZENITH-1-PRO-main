"""Fail-closed, unsigned, repository-bound reproducibility evidence for CI.

Generate after all CI security checks; verify against a fresh checkout of the
same Git commit. This does NOT attest to host-clock trust or test correctness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess  # nosec B404 - fixed Git commands execute without a shell
import sys
import time
from datetime import datetime, timezone

SCHEMA_VERSION = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    """Evidence precondition or verification failed."""


def git(root: Path, *args: str) -> bytes:
    git_executable = shutil.which("git")
    if not git_executable or not Path(git_executable).is_absolute():
        raise EvidenceError("absolute git executable not available")
    process = subprocess.run(  # nosec B603 - absolute Git path, argument array, shell=False
        [git_executable, "-C", str(root), *args], capture_output=True, check=False
    )
    if process.returncode:
        raise EvidenceError(f"git {' '.join(args)} failed ({process.returncode})")
    return process.stdout


def commit_sha(root: Path) -> str:
    value = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if not COMMIT.fullmatch(value):
        raise EvidenceError("invalid Git HEAD SHA")
    return value


def secure_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise EvidenceError("invalid relative path")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
        raise EvidenceError("unsafe relative path")
    target = root.joinpath(*path.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise EvidenceError("file escapes repository")
    if any(p.is_symlink() for p in [target, *list(target.parents)[:-1]] if p != root):
        raise EvidenceError("symlink not permitted in evidence")
    try:
        mode = target.stat().st_mode
    except OSError as error:
        raise EvidenceError("missing or inaccessible file") from error
    if not stat.S_ISREG(mode):
        raise EvidenceError("evidence path is not a regular file")
    return target


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while data := source.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def tracked_files(root: Path) -> list[str]:
    raw = git(root, "ls-files", "-z")
    names = [os.fsdecode(item) for item in raw.split(b"\0") if item]
    if not names or names != sorted(set(names)):
        raise EvidenceError("tracked file index is empty, duplicated, or not sorted")
    return names


def generate(root: Path, output: Path) -> dict:
    started = time.monotonic_ns()
    sha = commit_sha(root)
    git_sha = os.environ.get("GITHUB_SHA", "")
    if git_sha and git_sha != sha:
        raise EvidenceError("GITHUB_SHA does not match checked-out commit")
    if git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise EvidenceError("tracked working tree is dirty")
    tracked = tracked_files(root)
    entries = [
        {"path": name, "sha256": file_digest(secure_file(root, name))}
        for name in tracked
    ]
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "status": "PAPER_ONLY",
        "promotion_blocked": True,
        "production_authority": "NONE",
        "integrity": "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION",
        "clock_provenance": "HOST_CLOCK_UNATTESTED",
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "elapsed_monotonic_ns": time.monotonic_ns() - started,
        "git_head": sha,
        "github_context": {key: os.environ.get(key, "") for key in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME"
        )},
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "file_count": len(entries),
        "files": entries,
    }
    if output.exists() or output.with_name(output.name + ".sha256").exists():
        raise EvidenceError("refuse to overwrite existing evidence")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(evidence, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    output.write_bytes(payload)
    output.with_name(output.name + ".sha256").write_text(
        hashlib.sha256(payload).hexdigest() + "  " + output.name + "\n", encoding="ascii"
    )
    return evidence


def verify(root: Path, manifest: Path) -> dict:
    raw = manifest.read_bytes()
    sidecar = manifest.with_name(manifest.name + ".sha256").read_text(encoding="ascii")
    expected = sidecar.split("  ")
    if len(expected) != 2 or not SHA256.fullmatch(expected[0]) or expected[1] != manifest.name + "\n":
        raise EvidenceError("invalid sidecar checksum")
    if hashlib.sha256(raw).hexdigest() != expected[0]:
        raise EvidenceError("manifest checksum mismatch")
    data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
        or data.get("status") != "PAPER_ONLY" or data.get("promotion_blocked") is not True
        or data.get("production_authority") != "NONE"
        or data.get("integrity") != "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION"
        or data.get("clock_provenance") != "HOST_CLOCK_UNATTESTED"):
        raise EvidenceError("invalid fail-closed evidence fields")
    if data.get("git_head") != commit_sha(root):
        raise EvidenceError("manifest is not for the checked-out Git commit")
    if not isinstance(data.get("files"), list) or data.get("file_count") != len(data["files"]):
        raise EvidenceError("invalid file count")
    names = [entry.get("path") for entry in data["files"] if isinstance(entry, dict)]
    if len(names) != len(data["files"]) or names != tracked_files(root):
        raise EvidenceError("file listing diverges from Git index")
    for entry in data["files"]:
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise EvidenceError("malformed digest")
        if file_digest(secure_file(root, entry["path"])) != digest:
            raise EvidenceError(f"file content mismatch: {entry['path']}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "verify"])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path, default=Path(".evidence/repro-manifest.json"))
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        result = generate(root, manifest) if args.operation == "create" else verify(root, manifest)
    except (EvidenceError, OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"EVIDENCE_FAIL: {error}", file=sys.stderr)
        return 1
    print(f"EVIDENCE_{'CREATED' if args.operation == 'create' else 'VERIFIED'} commit={result['git_head']} files={result['file_count']} authority=NONE unsigned=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
