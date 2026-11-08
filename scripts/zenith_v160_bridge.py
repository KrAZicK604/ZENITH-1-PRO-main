"""Offline ZENITH evidence v1 -> V160 research handoff and local register audit.

No network, persistent register writes, key signing, or production authority.
A handoff digest is UNSIGNED. It MUST NOT be interpreted as a V160 checkpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess  # nosec B404 - fixed executable, argument list, no shell
import sys
import tempfile
import zipfile

# Single-source immutable research artifact identity; the pin is not a third-party signature.
V160_KIT_SHA256 = "b8870eb26b598e356938ec63265b14aa19cf1a4c67dee82263ea4fa7608ec4df"
REPOSITORY = "KrAZicK604/ZENITH-1-PRO-main"
HANDOFF_SCHEMA = "zenith-v160-handoff-v1"
PREFIX = b"ZENITH-V160-HANDOFF-v1\x00"
HEXDIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_EVIDENCE_BYTES = 100_000
MAX_HANDOFF_BYTES = 4096
MAX_KIT_BYTES = 500_000
MAX_KIT_MEMBERS = 256
MAX_KIT_UNCOMPRESSED = 8_000_000
MAX_DB_BYTES = 32_000_000
ALLOWED_AUDIT = {
    "LOCAL_HASH_CHAIN_VALID_EXTERNAL_RETENTION_UNVERIFIED",
    "ABSTAIN_AUTHENTICATED_CONFLICT",
}


class BridgeError(ValueError):
    """Fail-closed local research boundary violation."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise BridgeError("DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def _strict_json(data: bytes) -> object:
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(BridgeError("NONFINITE_JSON")),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BridgeError("INVALID_JSON") from exc


def _regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    """Reject symlinked path components and size-bound an untrusted regular file.

    This check is not an OS-hardened defense against malicious concurrent replacement.
    """
    current = path.absolute()
    for parent in (current, *current.parents):
        if parent.is_symlink():
            raise BridgeError(f"{label}_SYMLINK")
    try:
        info = current.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_size < 1:
            raise BridgeError(f"{label}_SIZE_OR_TYPE")
        with current.open("rb") as handle:
            data = handle.read(maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            raise BridgeError(f"{label}_SIZE_CHANGED")
        return data
    except OSError as exc:
        raise BridgeError(f"{label}_UNREADABLE") from exc


def _verify_zenith_record(path: Path) -> tuple[dict, bytes]:
    raw = _regular_file(path, maximum=MAX_EVIDENCE_BYTES, label="EVIDENCE")
    record = _strict_json(raw)
    if type(record) is not dict:
        raise BridgeError("EVIDENCE_RECORD_TYPE")
    # Bind imports to this checkout rather than an untrusted current directory.
    repo_root = str(Path(__file__).resolve().parents[1])
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from evidence_v1 import verify_evidence

    verdict, reason = verify_evidence(record)
    if verdict != "PASS":
        raise BridgeError("ZENITH_REPLAY_NOT_VERIFIED:" + str(verdict) + ":" + str(reason)[:100])
    return record, raw


def build_handoff(path: Path) -> dict:
    record, raw = _verify_zenith_record(path)
    body = {
        "schema": HANDOFF_SCHEMA,
        "repository": REPOSITORY,
        "source_schema": "zenith-evidence-v1",
        "source_file_sha256": _digest(raw),
        "source_record_sha256": record["record_sha256"],
        "source_payload_sha256": record["payload_sha256"],
        "v160_kit_sha256": V160_KIT_SHA256,
        "local_verifier_result": "PASS",
        "handoff_authentication": "UNSIGNED_NOT_A_V160_CHECKPOINT",
        "external_retention": "UNVERIFIED",
        "timestamp_trust": "HOST_CLOCK_UNATTESTED",
        "productionAuthority": "NONE",
        "promotionBlocked": True,
    }
    return {"handoff": body, "handoff_sha256": _digest(PREFIX + _plain(body))}


def verify_handoff(handoff_path: Path, evidence_path: Path) -> dict:
    supplied = _strict_json(_regular_file(handoff_path, maximum=MAX_HANDOFF_BYTES, label="HANDOFF"))
    expected = build_handoff(evidence_path)
    if type(supplied) is not dict or set(supplied) != {"handoff", "handoff_sha256"}:
        raise BridgeError("HANDOFF_SCHEMA")
    if _plain(supplied) != _plain(expected):
        raise BridgeError("HANDOFF_BINDING_MISMATCH")
    return {"result": "LOCAL_EVIDENCE_AND_UNSIGNED_HANDOFF_MATCH", "handoff_sha256": expected["handoff_sha256"],
            "external_retention": "UNVERIFIED", "productionAuthority": "NONE"}


def _kit_members(z: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = z.infolist()
    if not members or len(members) > MAX_KIT_MEMBERS:
        raise BridgeError("KIT_MEMBER_COUNT")
    seen = set()
    total = 0
    for member in members:
        name = member.filename
        if (name in seen or not name or name.startswith("/") or "\\" in name or "\x00" in name
                or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
            raise BridgeError("KIT_UNSAFE_MEMBER")
        seen.add(name)
        mode = member.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise BridgeError("KIT_SPECIAL_MEMBER")
        if member.flag_bits & 1:
            raise BridgeError("KIT_ENCRYPTED_MEMBER")
        if member.file_size > 1_000_000:
            raise BridgeError("KIT_MEMBER_TOO_BIG")
        total += member.file_size
        if total > MAX_KIT_UNCOMPRESSED:
            raise BridgeError("KIT_EXPANSION_LIMIT")
    if "src/verify_v160_cli.py" not in seen or "src/custody_register_v160.py" not in seen:
        raise BridgeError("KIT_VERIFIER_MISSING")
    return members


def audit_v160(kit: Path, database: Path, expected_tip: str, genesis_pin: str) -> dict:
    for name, value in (("TIP", expected_tip), ("GENESIS", genesis_pin)):
        if type(value) is not str or not HEXDIGEST.fullmatch(value):
            raise BridgeError(name + "_PIN_FORMAT")
    data = _regular_file(kit, maximum=MAX_KIT_BYTES, label="KIT")
    if _digest(data) != V160_KIT_SHA256:
        raise BridgeError("KIT_SHA256_MISMATCH")
    # Never let a forged path or oversized DB be opened by the downstream verifier.
    _regular_file(database, maximum=MAX_DB_BYTES, label="REGISTER")
    with tempfile.TemporaryDirectory(prefix="zenith_v160_readonly_") as td:
        root = Path(td)
        try:
            with zipfile.ZipFile(kit) as z:
                _kit_members(z)
                # The complete ZIP bytes are pinned before processing members.
                for item in z.infolist():
                    target = root / item.filename
                    if item.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with z.open(item) as reader, target.open("xb") as writer:
                            data_part = reader.read(item.file_size + 1)
                            if len(data_part) != item.file_size:
                                raise BridgeError("KIT_MEMBER_SIZE_MISMATCH")
                            writer.write(data_part)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise BridgeError("KIT_UNPACK_FAILED") from exc
        main = root / "src" / "verify_v160_cli.py"
        # Isolated Python path: only verified extracted research code is prepended.
        bootstrap = (
            "import pathlib,runpy,sys; "
            "p=pathlib.Path(sys.argv[1]).resolve(strict=True); "
            "sys.path.insert(0,str(p.parent)); "
            "sys.argv=[str(p),*sys.argv[2:]]; "
            "runpy.run_path(str(p),run_name='__main__')"
        )
        cmd = [sys.executable, "-I", "-B", "-c", bootstrap, str(main), "audit", "--database",
               str(database.absolute()), "--expected-tip", expected_tip, "--genesis-pin", genesis_pin]
        try:
            result = subprocess.run(  # nosec B603 - fixed Python executable, fixed arguments, no shell
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=root, env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BridgeError("V160_AUDIT_UNAVAILABLE") from exc
        if result.returncode != 0 or len(result.stdout) > 8192:
            raise BridgeError("V160_AUDIT_REJECTED")
        assessment = _strict_json(result.stdout)
        if type(assessment) is not dict or assessment.get("result") not in ALLOWED_AUDIT:
            raise BridgeError("V160_AUDIT_UNEXPECTED_RESULT")
        return {
            "result": assessment["result"],
            "tip": assessment["tip"], "events": assessment["events"],
            "conflict_codes": assessment.get("reason_codes", []),
            "v160_kit_sha256": V160_KIT_SHA256,
            "independent_pin_custody": "NOT_ESTABLISHED",
            "zenith_handoff_linkage": "NOT_ESTABLISHED",
            "productionAuthority": "NONE",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZENITH V160 offline research handoff (no production authority)")
    p = parser.add_subparsers(dest="operation", required=True)
    export = p.add_parser("export", help="validate ZENITH record and print unsigned handoff")
    export.add_argument("--evidence", type=Path, required=True)
    verify = p.add_parser("verify", help="recheck handoff against unchanged ZENITH record")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--handoff", type=Path, required=True)
    audit = p.add_parser("audit", help="read-only independent V160 register audit from pinned ZIP")
    audit.add_argument("--kit", type=Path, required=True)
    audit.add_argument("--database", type=Path, required=True)
    audit.add_argument("--expected-tip", required=True)
    audit.add_argument("--genesis-pin", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "export":
            response = build_handoff(args.evidence)
        elif args.operation == "verify":
            response = verify_handoff(args.handoff, args.evidence)
        else:
            response = audit_v160(args.kit, args.database, args.expected_tip, args.genesis_pin)
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    except (BridgeError, KeyError, TypeError, ValueError, OSError) as exc:
        print(json.dumps({"result": "REJECT", "reason": str(exc)[:180],
                          "productionAuthority": "NONE"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
