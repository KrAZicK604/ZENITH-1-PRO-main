"""Regression controls for bounded verification of plain JSON evidence."""
import copy
import json
import unittest
from unittest.mock import patch

from evidence_v1 import canonical, digest, make_evidence, verify_evidence


class EvidenceResourceTest(unittest.TestCase):
    def setUp(self):
        self.record = make_evidence(3.9, 0.2, 25)

    def assert_preflight_rejects(self, record):
        with patch("evidence_v1.json.JSONEncoder", side_effect=AssertionError("encoder reached")):
            self.assertEqual(verify_evidence(record), ("FAIL", "malformed evidence"))

    def test_plain_json_large_field_rejected_before_encoding(self):
        record = copy.deepcopy(self.record)
        record["metadata"]["python_implementation"] = "x" * 4_000_000
        record = json.loads(json.dumps(record))
        self.assert_preflight_rejects(record)

    def test_shared_nested_containers_rejected_before_encoding(self):
        value = "x"
        for _ in range(26):
            value = [value, value]
        record = copy.deepcopy(self.record)
        record["metadata"]["python_implementation"] = value
        self.assert_preflight_rejects(record)

    def test_wide_mapping_rejected_before_key_iteration(self):
        self.assert_preflight_rejects({str(i): None for i in range(5000)})

    def test_large_integer_rejected_before_encoding(self):
        record = copy.deepcopy(self.record)
        record["metadata"]["elapsed_monotonic_ns"] = 1 << 100_000
        self.assert_preflight_rejects(record)

    def test_subclass_behavior_is_not_invoked(self):
        class HostileDict(dict):
            def items(self):
                raise AssertionError("subclass method invoked")

        self.assert_preflight_rejects(HostileDict(self.record))

    def test_total_encoded_bytes_are_bounded(self):
        # Each string and the structure fit preflight, but total JSON does not.
        with self.assertRaisesRegex(ValueError, "oversized evidence"):
            canonical(["x" * 4096 for _ in range(30)])

    def test_escaped_strings_count_against_encoded_byte_limit(self):
        with self.assertRaisesRegex(ValueError, "oversized evidence"):
            canonical(["\u0000" * 4096 for _ in range(5)])

    def test_memory_error_returns_failure_status(self):
        with patch("evidence_v1.canonical", side_effect=MemoryError):
            self.assertEqual(verify_evidence(self.record), ("FAIL", "malformed evidence"))

    def test_full_budget_record_still_passes(self):
        record = make_evidence(3.9, 0.2, 1000)
        self.assertEqual(verify_evidence(record)[0], "PASS")
        self.assertEqual(canonical(record), json.dumps(
            record, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8"))

    def test_rehashed_host_claims_are_not_authenticated(self):
        record = copy.deepcopy(self.record)
        record["metadata"]["python_implementation"] = "ClaimedRuntime"
        record["metadata"]["python_version"] = "0.0.1"
        record["record_sha256"] = digest({k: v for k, v in record.items() if k != "record_sha256"})
        self.assertEqual(verify_evidence(record)[0], "PASS")


if __name__ == "__main__":
    unittest.main()
