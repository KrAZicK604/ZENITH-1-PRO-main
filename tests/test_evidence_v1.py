"""Adversarial regression tests for evidence generation and replay."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from evidence_v1 import make_evidence, verify_evidence, write_evidence


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.record = make_evidence(3.9, 0.2, 25)

    def test_replay(self):
        self.assertEqual(verify_evidence(self.record)[0], "PASS")

    def test_corrupted_hash(self):
        r = copy.deepcopy(self.record)
        r["payload_sha256"] = "0" * 64
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_tampered_orbit_even_with_rehashed_payload(self):
        from evidence_v1 import digest
        r = copy.deepcopy(self.record)
        r["payload"]["orbit_hex"][1] = "0x1.0000000000000p-1"
        r["payload_sha256"] = digest(r["payload"])
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_unsupported_schema_abstains(self):
        r = copy.deepcopy(self.record)
        r["payload"]["schema"] = "unknown"
        self.assertEqual(verify_evidence(r)[0], "ABSTAIN")

    def test_rejects_unbounded_work(self):
        r = copy.deepcopy(self.record)
        r["payload"]["parameters"]["iterations"] = 1001
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_rejects_missing_metadata(self):
        r = copy.deepcopy(self.record)
        del r["metadata"]
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_metadata_timestamp_tampering_fails(self):
        r = copy.deepcopy(self.record)
        r["metadata"]["utc_started_host_unattested"] = "2000-01-01T00:00:00+00:00"
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_metadata_runtime_tampering_fails(self):
        r = copy.deepcopy(self.record)
        r["metadata"]["python_version"] = "0.0.1"
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_metadata_elapsed_tampering_fails(self):
        r = copy.deepcopy(self.record)
        r["metadata"]["elapsed_monotonic_ns"] += 1
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_rehashed_production_authority_rejected(self):
        from evidence_v1 import digest
        r = copy.deepcopy(self.record)
        r["metadata"]["productionAuthority"] = "PRODUCTION"
        r["record_sha256"] = digest({key: value for key, value in r.items() if key != "record_sha256"})
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_rehashed_trust_and_promotion_rejected(self):
        from evidence_v1 import digest
        for name, value in (("trust", "PRODUCTION"), ("promotionBlocked", False)):
            with self.subTest(name=name):
                r = copy.deepcopy(self.record)
                r["metadata"][name] = value
                r["record_sha256"] = digest({key: val for key, val in r.items() if key != "record_sha256"})
                self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_rehashed_non_utc_timestamp_rejected(self):
        from evidence_v1 import digest
        r = copy.deepcopy(self.record)
        r["metadata"]["utc_started_host_unattested"] = "2026-10-31T20:00:00-07:00"
        r["record_sha256"] = digest({key: val for key, val in r.items() if key != "record_sha256"})
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_missing_record_digest_rejected(self):
        r = copy.deepcopy(self.record)
        del r["record_sha256"]
        self.assertEqual(verify_evidence(r)[0], "FAIL")

    def test_serialized_roundtrip(self):
        from evidence_v1 import canonical
        r = json.loads(canonical(self.record))
        self.assertEqual(verify_evidence(r)[0], "PASS")

    def test_write_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_evidence(path, 3.9, 0.2, 25)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_evidence(path, 3.9, 0.2, 25)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
