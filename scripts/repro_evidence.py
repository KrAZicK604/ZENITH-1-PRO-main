"""Fail-closed, unsigned, repository-bound reproducibility evidence for CI.

Generate after all CI security checks; verify against a fresh checkout of the
same Git commit. This does NOT attest to host-clock trust or test correctness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
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
MAX_MANIFEST_BYTES = 1_000_000
MAX_CHECKSUM_BYTES = 4096
MAX_JSON_DEPTH = 16
MAX_FILES = 4096
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PYTHON_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
GITHUB_CONTEXT_KEYS = (
    "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME",
)


class EvidenceError(ValueError):
    """Evidence precondition or verification failed."""


def file_snapshot(info) -> tuple:
    """Exclude access time, which may legitimately change while reading."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def bounded_regular_bytes(path: Path, limit: int) -> bytes:
    """Read at most limit+1 bytes, refusing special files and leaf symlinks.

    Nonblocking open also prevents a raced-in POSIX FIFO from blocking before
    the descriptor type check. Parent-directory races require external isolation.
    """
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise EvidenceError("evidence input is not a bounded regular file")
        expected = file_snapshot(info)
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise EvidenceError("evidence input is not a bounded regular file")
            if file_snapshot(info) != expected:
                raise EvidenceError("evidence input changed before opening")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(limit + 1)
            if len(raw) > limit:
                raise EvidenceError("evidence input exceeds byte limit")
            if (file_snapshot(os.fstat(descriptor)) != expected
                    or len(raw) != info.st_size):
                raise EvidenceError("evidence input changed while reading")
        finally:
            os.close(descriptor)
        if file_snapshot(path.lstat()) != expected:
            raise EvidenceError("evidence input path changed while reading")
        return raw
    except (OSError, MemoryError) as error:
        raise EvidenceError("missing or inaccessible evidence input") from error


def parse_manifest(raw: bytes) -> dict:
    """Parse bounded UTF-8 JSON without duplicate members or deep nesting."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise EvidenceError("manifest exceeds byte limit")
    depth, in_string, escaped = 0, False, False
    for value in raw:
        if in_string:
            if escaped:
                escaped = False
            elif value == 92:  # Backslash.
                escaped = True
            elif value == 34:  # Quote.
                in_string = False
        elif value == 34:
            in_string = True
        elif value in (91, 123):  # Array/object opening delimiter.
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise EvidenceError("manifest nesting exceeds limit")
        elif value in (93, 125):
            depth -= 1
            if depth < 0:
                raise EvidenceError("invalid manifest nesting")

    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError("duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(value):
        raise EvidenceError("nonfinite JSON constant")

    def bounded_integer(value):
        if len(value) > 128:
            raise EvidenceError("manifest integer exceeds digit limit")
        return int(value)

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise EvidenceError("nonfinite JSON number")
        return result

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_members,
                          parse_constant=reject_constant, parse_int=bounded_integer,
                          parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError, MemoryError) as error:
        raise EvidenceError("malformed manifest JSON") from error
    if not isinstance(data, dict):
        raise EvidenceError("manifest must be a JSON object")
    return data


def validate_metadata(data: dict) -> None:
    """Validate format and internal consistency, not host truth or identity."""
    stamp = data.get("created_at_utc")
    if type(stamp) is not str or not UTC_TIMESTAMP.fullmatch(stamp):
        raise EvidenceError("invalid host UTC timestamp")
    try:
        datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise EvidenceError("invalid host UTC calendar value") from error
    elapsed = data.get("elapsed_monotonic_ns")
    if type(elapsed) is not int or elapsed < 0:
        raise EvidenceError("invalid monotonic duration")
    version = data.get("python_version")
    if type(version) is not str or not PYTHON_VERSION.fullmatch(version):
        raise EvidenceError("invalid Python version metadata")
    context = data.get("github_context")
    if (type(context) is not dict or set(context) != set(GITHUB_CONTEXT_KEYS)
        or any(type(value) is not str for value in context.values())):
        raise EvidenceError("invalid GitHub context shape")
    sha = context["GITHUB_SHA"]
    if sha and (not COMMIT.fullmatch(sha) or sha != data.get("git_head")):
        raise EvidenceError("GitHub context SHA differs from manifest commit")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = context[key]
        if value and (not value.isascii() or not value.isdecimal() or not value.strip("0")):
            raise EvidenceError("invalid GitHub run identity format")


def git(root: Path, *args: str) -> bytes:
    git_executable = shutil.which("git")
    if not git_executable or not Path(git_executable).is_absolute():
        raise EvidenceError("absolute git executable not available")
    process = subprocess.run(  # nosec B603 - absolute Git path, argument array, shell=False
        [git_executable, "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        capture_output=True, check=False
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
    if not names or len(names) > MAX_FILES or names != sorted(set(names)):
        raise EvidenceError("tracked file index is empty, oversized, duplicated, or not sorted")
    return names


def safe_evidence_output(root: Path, output: Path) -> Path:
    """Restrict evidence to a nonsymlink path inside the working tree, outside .git."""
    trusted_root = root.resolve()
    if not output.is_absolute():
        raise EvidenceError("evidence output must be an absolute path")
    try:
        relative = output.relative_to(trusted_root)
    except ValueError as error:
        raise EvidenceError("evidence output escapes repository") from error
    if (not relative.parts or len(relative.parts) < 2 or relative.parts[0] != ".evidence"
        or any(part in (".", "..") for part in relative.parts)):
        raise EvidenceError("unsafe evidence output path: creation requires .evidence/")
    current = trusted_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceError("symlink not permitted in evidence output")
    if not output.resolve().is_relative_to(trusted_root):
        raise EvidenceError("evidence output escapes repository")
    # Reject a dangling sidecar link before creating the manifest. Exclusive
    # creation below still protects against late pre-existing file changes.
    sidecar = output.with_name(output.name + ".sha256")
    if sidecar.is_symlink():
        raise EvidenceError("symlink not permitted in evidence output checksum")
    return output


def assert_committed_files(root: Path, tracked: list[str]) -> None:
    """Require raw checkout bytes to match HEAD, even for assume-unchanged files."""
    for name in tracked:
        target = secure_file(root, name)
        committed_oid = git(root, "rev-parse", "--verify", f"HEAD:{name}").decode("ascii").strip()
        actual_oid = git(root, "hash-object", "--no-filters", str(target)).decode("ascii").strip()
        if committed_oid != actual_oid:
            raise EvidenceError(f"working file differs from committed Git object: {name}")


def generate(root: Path, output: Path) -> dict:
    started = time.monotonic_ns()
    sha = commit_sha(root)
    git_sha = os.environ.get("GITHUB_SHA", "")
    if git_sha and git_sha != sha:
        raise EvidenceError("GITHUB_SHA does not match checked-out commit")
    if git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise EvidenceError("tracked working tree is dirty")
    tracked = tracked_files(root)
    assert_committed_files(root, tracked)
    output = safe_evidence_output(root, output)
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
        "github_context": {key: os.environ.get(key, "") for key in GITHUB_CONTEXT_KEYS},
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "file_count": len(entries),
        "files": entries,
    }
    validate_metadata(evidence)
    checksum_path = output.with_name(output.name + ".sha256")
    if output.exists() or checksum_path.exists():
        raise EvidenceError("refuse to overwrite existing evidence")
    output.parent.mkdir(parents=True, exist_ok=True)
    safe_evidence_output(root, output)  # Recheck after directory creation.
    payload = (json.dumps(evidence, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    checksum = (hashlib.sha256(payload).hexdigest() + "  " + output.name + "\n").encode("ascii")
    if len(payload) > MAX_MANIFEST_BYTES or len(checksum) > MAX_CHECKSUM_BYTES:
        raise EvidenceError("generated evidence exceeds input byte limits")
    created: list[Path] = []
    try:
        for path, content in ((output, payload), (checksum_path, checksum)):
            with path.open("xb") as destination:  # Exclusive: never replace existing evidence.
                created.append(path)
                destination.write(content)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return evidence


def verify(root: Path, manifest: Path) -> dict:
    raw = bounded_regular_bytes(manifest, MAX_MANIFEST_BYTES)
    sidecar = bounded_regular_bytes(
        manifest.with_name(manifest.name + ".sha256"), MAX_CHECKSUM_BYTES
    ).decode("ascii")
    expected = sidecar.split("  ")
    if len(expected) != 2 or not SHA256.fullmatch(expected[0]) or expected[1] != manifest.name + "\n":
        raise EvidenceError("invalid sidecar checksum")
    if hashlib.sha256(raw).hexdigest() != expected[0]:
        raise EvidenceError("manifest checksum mismatch")
    data = parse_manifest(raw)
    if (type(data.get("schema_version")) is not int
        or data.get("schema_version") != SCHEMA_VERSION
        or data.get("status") != "PAPER_ONLY" or data.get("promotion_blocked") is not True
        or data.get("production_authority") != "NONE"
        or data.get("integrity") != "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION"
        or data.get("clock_provenance") != "HOST_CLOCK_UNATTESTED"):
        raise EvidenceError("invalid fail-closed evidence fields")
    validate_metadata(data)
    if data.get("git_head") != commit_sha(root):
        raise EvidenceError("manifest is not for the checked-out Git commit")
    if (not isinstance(data.get("files"), list)
        or type(data.get("file_count")) is not int
        or not 1 <= data["file_count"] <= MAX_FILES
        or data["file_count"] != len(data["files"])):
        raise EvidenceError("invalid file count")
    names = [entry.get("path") for entry in data["files"] if isinstance(entry, dict)]
    if len(names) != len(data["files"]) or names != tracked_files(root):
        raise EvidenceError("file listing diverges from Git index")
    # Compare against the *committed* Git object, not just a mutable manifest.
    # A regenerated unsigned manifest and sidecar cannot authorize altered
    # working-tree bytes while the claimed Git HEAD stays unchanged.
    if git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise EvidenceError("tracked working tree differs from Git HEAD")
    assert_committed_files(root, names)
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
    except (EvidenceError, OSError, ValueError, UnicodeError, MemoryError, subprocess.SubprocessError) as error:
        print(f"EVIDENCE_FAIL: {error}", file=sys.stderr)
        return 1
    print(f"EVIDENCE_{'CREATED' if args.operation == 'create' else 'VERIFIED'} commit={result['git_head']} files={result['file_count']} authority=NONE unsigned=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())




















































































































































































































































































































































































































































