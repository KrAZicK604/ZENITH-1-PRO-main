"""Negative and positive reproducibility-evidence tests (temporary Git repos)."""
from __future__ import annotations
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repro_evidence", ROOT / "scripts" / "repro_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "sample.py").write_text("print('safe')\n")
        subprocess.run(["git", "-C", str(self.root), "add", "sample.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
        self.path = self.root / ".evidence" / "repro-manifest.json"

    def test_roundtrip(self):
        generated = evidence.generate(self.root, self.path)
        self.assertEqual(generated["production_authority"], "NONE")
        self.assertEqual(evidence.verify(self.root, self.path)["file_count"], 1)

    def test_detects_tampered_source(self):
        evidence.generate(self.root, self.path)
        (self.root / "sample.py").write_text("print('changed')\n")
        with self.assertRaises(evidence.EvidenceError): evidence.verify(self.root, self.path)

    def test_detects_tampered_manifest(self):
        evidence.generate(self.root, self.path)
        self.path.write_text(self.path.read_text() + " ")
        with self.assertRaises(evidence.EvidenceError): evidence.verify(self.root, self.path)

    def test_prevents_rewrite(self):
        evidence.generate(self.root, self.path)
        with self.assertRaises(evidence.EvidenceError): evidence.generate(self.root, self.path)

    def test_dirty_tree_blocks_creation(self):
        (self.root / "sample.py").write_text("changed")
        with self.assertRaises(evidence.EvidenceError): evidence.generate(self.root, self.path)

    def test_symlink_escape(self):
        target = self.root / "out.txt"
        target.write_text("outside")
        (self.root / "sample.py").unlink()
        (self.root / "sample.py").symlink_to(target)
        with self.assertRaises(evidence.EvidenceError): evidence.generate(self.root, self.path)

    def test_checksum_sidecar_mismatch(self):
        evidence.generate(self.root, self.path)
        self.path.with_name(self.path.name + ".sha256").write_text("0" * 64 + "  " + self.path.name + "\n")
        with self.assertRaises(evidence.EvidenceError): evidence.verify(self.root, self.path)

    def test_rejects_escape_path(self):
        for name in ("../bad", "/tmp/other", "x/../sample.py", "x\\y"):
            with self.subTest(name=name), self.assertRaises(evidence.EvidenceError):
                evidence.secure_file(self.root, name)

    def test_manifest_abstain_fields_cannot_change(self):
        evidence.generate(self.root, self.path)
        payload = json.loads(self.path.read_text())
        payload["production_authority"] = "PRODUCTION"
        raw = (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
        self.path.write_bytes(raw)
        import hashlib
        self.path.with_name(self.path.name + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "  " + self.path.name + "\n")
        with self.assertRaises(evidence.EvidenceError): evidence.verify(self.root, self.path)


if __name__ == "__main__":
    unittest.main()
