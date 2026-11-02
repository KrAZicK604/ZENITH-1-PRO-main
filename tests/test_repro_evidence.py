"""Negative and positive reproducibility-evidence tests (temporary Git repos)."""
from __future__ import annotations
import importlib.util
import json
import hashlib
import os
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repro_evidence", ROOT / "scripts" / "repro_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        fixture_env = patch.dict(os.environ, {"GITHUB_SHA": ""})
        fixture_env.start()
        self.addCleanup(fixture_env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        evidence.git(self.root, "init", "-q")
        (self.root / "sample.py").write_text("print('safe')\n")
        evidence.git(self.root, "add", "sample.py")
        evidence.git(self.root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
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

    def test_rehashed_manifest_rejects_changed_source(self):
        evidence.generate(self.root, self.path)
        changed = b"print('altered')\n"
        (self.root / "sample.py").write_bytes(changed)
        record = json.loads(self.path.read_text())
        record["files"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
        raw = (json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
        self.path.write_bytes(raw)
        self.path.with_name(self.path.name + ".sha256").write_text(
            hashlib.sha256(raw).hexdigest() + "  " + self.path.name + "\n"
        )
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify(self.root, self.path)

    def test_assume_unchanged_cannot_hide_modified_git_blob(self):
        evidence.generate(self.root, self.path)
        evidence.git(self.root, "update-index", "--assume-unchanged", "sample.py")
        (self.root / "sample.py").write_text("print('altered')\n")
        self.assertFalse(
            evidence.git(self.root, "status", "--porcelain", "--untracked-files=no").strip()
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "committed Git object"):
            evidence.verify(self.root, self.path)

    def test_prevents_rewrite(self):
        evidence.generate(self.root, self.path)
        with self.assertRaises(evidence.EvidenceError): evidence.generate(self.root, self.path)

    def test_ci_sha_mismatch_is_rejected(self):
        with patch.dict(os.environ, {"GITHUB_SHA": "0" * 40}):
            with self.assertRaises(evidence.EvidenceError):
                evidence.generate(self.root, self.path)

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
        for name in ("../bad", str(self.root.parent / "outside-test"), "x/../sample.py", "x\\y"):
            with self.subTest(name=name), self.assertRaises(evidence.EvidenceError):
                evidence.secure_file(self.root, name)

    def test_output_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external)
            (self.root / ".evidence").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(evidence.EvidenceError, "symlink|escapes"):
                evidence.generate(self.root, self.path)
            self.assertFalse((outside / "repro-manifest.json").exists())

    def test_dangling_output_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as external:
            self.path.parent.mkdir()
            outside = Path(external) / "outside-manifest.json"
            self.path.symlink_to(outside)
            with self.assertRaisesRegex(evidence.EvidenceError, "symlink|escapes"):
                evidence.generate(self.root, self.path)
            self.assertFalse(outside.exists())

    def test_output_outside_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external) / "outside-manifest.json"
            with self.assertRaisesRegex(evidence.EvidenceError, "escapes"):
                evidence.generate(self.root, outside)
            self.assertFalse(outside.exists())

    def test_failed_checksum_write_cleans_partial_manifest(self):
        original = Path.open

        def fail_sidecar(path, mode="r", *args, **kwargs):
            if str(path).endswith(".sha256") and mode == "x":
                raise OSError("injected checksum failure")
            return original(path, mode, *args, **kwargs)

        with patch.object(Path, "open", fail_sidecar):
            with self.assertRaisesRegex(OSError, "injected checksum failure"):
                evidence.generate(self.root, self.path)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.path.with_name(self.path.name + ".sha256").exists())
        # The failure must not permanently block a normal retry.
        evidence.generate(self.root, self.path)
        self.assertEqual(evidence.verify(self.root, self.path)["file_count"], 1)

    def test_generation_rejects_dirty_assume_unchanged_file(self):
        evidence.git(self.root, "update-index", "--assume-unchanged", "sample.py")
        (self.root / "sample.py").write_text("print('changed but hidden')\n")
        self.assertFalse(evidence.git(self.root, "status", "--porcelain", "--untracked-files=no").strip())
        with self.assertRaisesRegex(evidence.EvidenceError, "committed Git object"):
            evidence.generate(self.root, self.path)
        self.assertFalse(self.path.exists())

    def test_rejects_evidence_output_inside_git_admin(self):
        git_dir = Path(os.fsdecode(evidence.git(self.root, "rev-parse", "--absolute-git-dir").rstrip(b"\n")))
        out = git_dir / "hooks" / "post-commit"
        self.assertFalse(out.exists())
        with self.assertRaisesRegex(evidence.EvidenceError, "Git administrative"):
            evidence.generate(self.root, out)
        self.assertFalse(out.exists())

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
