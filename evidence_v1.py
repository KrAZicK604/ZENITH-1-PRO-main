"""Fail-closed, reproducible evidence for bounded logistic-map experiments.

Host timestamps are informative, not an attested time source. SHA-256 hashes
provide integrity against accidental changes, not authenticated provenance.
"""
import hashlib
import json
import math
import platform
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from logistic_map import logistic_orbit
from rational_oracle import verify_recurrence

SCHEMA = "zenith-evidence-v1"
MAX_BYTES = 100_000
MAX_DEPTH = 8
MAX_NODES = 4096
MAX_STRING_CHARS = 4096
MAX_INTEGER_BITS = 256
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
METADATA_KEYS = {
    "utc_started_host_unattested", "elapsed_monotonic_ns", "python_version",
    "python_implementation", "float_info_mant_dig", "trust",
    "promotionBlocked", "productionAuthority",
}


def canonical(obj):
    """Encode bounded plain JSON data without first allocating its full text.

    The preflight also bounds shared-container expansion and rejects subclasses
    before invoking any user-defined iteration or serialization behavior.
    Callers loading bytes must separately bound input before JSON parsing.
    """
    remaining = MAX_NODES

    def visit(value, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            raise ValueError("evidence structure exceeds limits")
        kind = type(value)
        if kind is str:
            if len(value) > MAX_STRING_CHARS:
                raise ValueError("evidence string exceeds limit")
        elif kind is int:
            if value.bit_length() > MAX_INTEGER_BITS:
                raise ValueError("evidence integer exceeds limit")
        elif kind is float:
            if not math.isfinite(value):
                raise ValueError("nonfinite evidence scalar")
        elif value is None or kind is bool:
            pass
        elif kind is list:
            if len(value) > remaining:
                raise ValueError("evidence list exceeds limit")
            for child in value:
                visit(child, depth + 1)
        elif kind is dict:
            if len(value) > remaining // 2:
                raise ValueError("evidence mapping exceeds limit")
            for key, child in value.items():
                if type(key) is not str:
                    raise ValueError("evidence keys must be plain strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise ValueError("evidence must contain plain JSON values")

    visit(obj, 0)
    encoded = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
    for chunk in encoder.iterencode(obj):
        data = chunk.encode("utf-8")
        if len(data) > MAX_BYTES - len(encoded):
            raise ValueError("oversized evidence")
        encoded.extend(data)
    return bytes(encoded)


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def make_evidence(rate, initial_state, iterations):
    start_ns = time.monotonic_ns()
    started = datetime.now(timezone.utc).isoformat()
    orbit = logistic_orbit(rate, initial_state, iterations)
    payload = {
        "schema": SCHEMA,
        "algorithm": "logistic-orbit-v1",
        "parameters": {"rate": float(rate), "initial_state": float(initial_state), "iterations": iterations},
        "orbit_hex": [x.hex() for x in orbit],
    }
    record = {
        "payload": payload,
        "payload_sha256": digest(payload),
        "metadata": {
            "utc_started_host_unattested": started,
            "elapsed_monotonic_ns": time.monotonic_ns() - start_ns,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "float_info_mant_dig": sys.float_info.mant_dig,
            "trust": "PAPER_ONLY",
            "promotionBlocked": True,
            "productionAuthority": "NONE",
        },
    }
    # Bind metadata as well as experiment bytes. This is an unsigned checksum;
    # anyone able to rewrite the file can still recompute it.
    record["record_sha256"] = digest(record)
    return record


def verify_evidence(record):
    """Return (status, reason); check full record and deterministic replay."""
    try:
        # Bound work before key-set construction, hashing, or metadata parsing.
        canonical(record)
        if not isinstance(record, dict) or set(record) != {"payload", "payload_sha256", "metadata", "record_sha256"}:
            return "FAIL", "record shape"
        payload = record["payload"]
        if not isinstance(payload, dict) or set(payload) != {"schema", "algorithm", "parameters", "orbit_hex"}:
            return "FAIL", "payload shape"
        if payload["schema"] != SCHEMA or payload["algorithm"] != "logistic-orbit-v1":
            return "ABSTAIN", "unsupported algorithm or schema"
        params = payload["parameters"]
        if not isinstance(params, dict) or set(params) != {"rate", "initial_state", "iterations"}:
            return "FAIL", "parameter shape"
        orbit = payload["orbit_hex"]
        n = params["iterations"]
        if type(n) is not int or not 1 <= n <= 1000 or not isinstance(orbit, list) or len(orbit) != n + 1:
            return "FAIL", "invalid work bound"
        if (type(record["payload_sha256"]) is not str
            or not SHA256_RE.fullmatch(record["payload_sha256"])
            or digest(payload) != record["payload_sha256"]):
            return "FAIL", "payload digest mismatch"
        meta = record["metadata"]
        if not isinstance(meta, dict) or set(meta) != METADATA_KEYS:
            return "FAIL", "metadata shape"
        if (meta["trust"] != "PAPER_ONLY" or meta["promotionBlocked"] is not True
            or meta["productionAuthority"] != "NONE"):
            return "FAIL", "invalid safety metadata"
        if (type(meta["elapsed_monotonic_ns"]) is not int
            or meta["elapsed_monotonic_ns"] < 0
            or type(meta["float_info_mant_dig"]) is not int
            or meta["float_info_mant_dig"] <= 0
            or type(meta["python_version"]) is not str
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", meta["python_version"])
            or type(meta["python_implementation"]) is not str
            or not meta["python_implementation"]
            or type(meta["utc_started_host_unattested"]) is not str):
            return "FAIL", "invalid runtime metadata"
        recorded_time = datetime.fromisoformat(meta["utc_started_host_unattested"])
        if recorded_time.utcoffset() != timedelta(0):
            return "FAIL", "host timestamp is not UTC"
        unsigned_body = {key: value for key, value in record.items() if key != "record_sha256"}
        if (type(record["record_sha256"]) is not str
            or not SHA256_RE.fullmatch(record["record_sha256"])
            or digest(unsigned_body) != record["record_sha256"]):
            return "FAIL", "record digest mismatch"
        actual = logistic_orbit(params["rate"], params["initial_state"], n)
        if not all(type(s) is str and s == x.hex() for s, x in zip(orbit, actual)):
            return "FAIL", "replay mismatch"
        oracle_status, reason = verify_recurrence(
            params["rate"], params["initial_state"], orbit
        )
        if oracle_status != "PASS":
            return oracle_status, reason
        return "PASS", "deterministic replay and exact-rational residual oracle matched"
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, MemoryError):
        return "FAIL", "malformed evidence"


def write_evidence(path, rate, initial_state, iterations):
    """Create a new file exclusively; never overwrite an existing evidence file."""
    path = Path(path)
    record = make_evidence(rate, initial_state, iterations)
    data = canonical(record) + b"\n"
    if len(data) > MAX_BYTES:
        raise ValueError("evidence exceeds size limit")
    with path.open("xb") as output:
        output.write(data)
    return record
