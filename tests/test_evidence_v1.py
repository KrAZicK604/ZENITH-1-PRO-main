"""Adversarial regression tests for evidence generation and replay."""
import copy
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
