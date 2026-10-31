"""Fail-closed, reproducible evidence for bounded logistic-map experiments.

Host timestamps are informative, not an attested time source. SHA-256 hashes
provide integrity against accidental changes, not authenticated provenance.
"""
import hashlib
import json
import math
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from logistic_map import logistic_orbit

SCHEMA = "zenith-evidence-v1"
MAX_BYTES = 100_000


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


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
            "productionAuthority": "NONE",
        },
    }
    return record


def verify_evidence(record):
    """Return (status, reason); never accept an unrecognized or modified payload."""
    try:
        if not isinstance(record, dict) or set(record) != {"payload", "payload_sha256", "metadata"}:
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
        if len(canonical(record)) > MAX_BYTES:
            return "FAIL", "oversized evidence"
        if type(record["payload_sha256"]) is not str or digest(payload) != record["payload_sha256"]:
            return "FAIL", "digest mismatch"
        if not isinstance(record["metadata"], dict) or record["metadata"].get("productionAuthority") != "NONE":
            return "FAIL", "invalid safety metadata"
        actual = logistic_orbit(params["rate"], params["initial_state"], n)
        if not all(type(s) is str and s == x.hex() for s, x in zip(orbit, actual)):
            return "FAIL", "replay mismatch"
        return "PASS", "local deterministic replay matched"
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
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
