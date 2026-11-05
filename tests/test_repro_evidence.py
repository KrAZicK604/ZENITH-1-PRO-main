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

    def test_manifest_abstain_fields_cannot_change(self):
        evidence.generate(self.root, self.path)
        payload = json.loads(self.path.read_text())
        payload["production_authority"] = "PRODUCTION"
        raw = (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
        self.path.write_bytes(raw)
        import hashlib
        self.path.with_name(self.path.name + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "  " + self.path.name + "\n")
        with self.assertRaises(evidence.EvidenceError): evidence.verify(self.root, self.path)

    def write_hashed(self, raw):
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_bytes(raw)
        self.path.with_name(self.path.name + ".sha256").write_text(
            hashlib.sha256(raw).hexdigest() + "  " + self.path.name + "\n"
        )

    def test_oversized_manifest_rejected_before_json_or_git(self):
        self.write_hashed(b" " * (evidence.MAX_MANIFEST_BYTES + 1))
        with patch.object(evidence.json, "loads", side_effect=AssertionError("JSON reached")):
            with patch.object(evidence, "git", side_effect=AssertionError("Git reached")):
                with self.assertRaisesRegex(evidence.EvidenceError, "bounded regular file"):
                    evidence.verify(self.root, self.path)

    def test_oversized_sidecar_rejected_before_json_or_git(self):
        self.write_hashed(b"{}")
        self.path.with_name(self.path.name + ".sha256").write_bytes(
            b"x" * (evidence.MAX_CHECKSUM_BYTES + 1)
        )
        with patch.object(evidence.json, "loads", side_effect=AssertionError("JSON reached")):
            with self.assertRaisesRegex(evidence.EvidenceError, "bounded regular file"):
                evidence.verify(self.root, self.path)

    def test_deep_json_rejected_before_parser(self):
        count = evidence.MAX_JSON_DEPTH + 1
        self.write_hashed(b"[" * count + b"0" + b"]" * count)
        with patch.object(evidence.json, "loads", side_effect=AssertionError("parser reached")):
            with self.assertRaisesRegex(evidence.EvidenceError, "nesting exceeds"):
                evidence.verify(self.root, self.path)

    def test_rehashed_duplicate_safety_member_rejected(self):
        evidence.generate(self.root, self.path)
        raw = self.path.read_bytes().replace(
            b'"production_authority": "NONE"',
            b'"production_authority": "PRODUCTION", "production_authority": "NONE"',
        )
        self.write_hashed(raw)
        with self.assertRaisesRegex(evidence.EvidenceError, "malformed manifest JSON"):
            evidence.verify(self.root, self.path)

    def test_boolean_schema_and_file_count_rejected(self):
        evidence.generate(self.root, self.path)
        original = json.loads(self.path.read_bytes())
        for key in ("schema_version", "file_count"):
            with self.subTest(key=key):
                changed = dict(original)
                changed[key] = True
                self.write_hashed(json.dumps(changed).encode())
                with self.assertRaises(evidence.EvidenceError):
                    evidence.verify(self.root, self.path)

    def test_nonfinite_and_long_numeric_inputs_rejected(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"9" * 129):
            with self.subTest(value=value[:20]):
                self.write_hashed(b'{"extra":' + value + b"}")
                with self.assertRaises(evidence.EvidenceError):
                    evidence.verify(self.root, self.path)

    def test_delimiters_and_escaped_quotes_in_strings_parse_normally(self):
        obj = {"text": '[{\\"\\}]' * 20}
        self.assertEqual(evidence.parse_manifest(json.dumps(obj).encode()), obj)

    def test_truncated_json_and_utf8_errors_are_normalized(self):
        for raw in (b'{"x":', b'{"x":"\xff"}'):
            with self.subTest(raw=raw), self.assertRaises(evidence.EvidenceError):
                evidence.parse_manifest(raw)

    def test_parser_resource_exceptions_are_normalized(self):
        for error in (RecursionError, MemoryError):
            with self.subTest(error=error):
                with patch.object(evidence.json, "loads", side_effect=error):
                    with self.assertRaisesRegex(evidence.EvidenceError, "malformed manifest JSON"):
                        evidence.parse_manifest(b"{}")

    def test_input_leaf_symlink_rejected(self):
        evidence.generate(self.root, self.path)
        saved = self.path.with_name("saved.json")
        self.path.rename(saved)
        try:
            self.path.symlink_to(saved)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(evidence.EvidenceError, "bounded regular file"):
            evidence.verify(self.root, self.path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO support required")
    def test_fifo_rejected_without_opening(self):
        self.path.parent.mkdir()
        os.mkfifo(self.path)
        with patch.object(evidence.os, "open", side_effect=AssertionError("FIFO opened")):
            with self.assertRaisesRegex(evidence.EvidenceError, "bounded regular file"):
                evidence.verify(self.root, self.path)

    def test_file_growth_still_obeys_read_cap(self):
        from types import SimpleNamespace
        import stat
        self.path.parent.mkdir()
        self.path.write_bytes(b"x" * 129)
        stale = SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
        with patch.object(Path, "lstat", return_value=stale):
            with patch.object(evidence.os, "fstat", return_value=stale):
                with self.assertRaisesRegex(evidence.EvidenceError, "exceeds byte limit"):
                    evidence.bounded_regular_bytes(self.path, 128)

    def test_generation_refuses_evidence_above_verifier_cap(self):
        with patch.object(evidence, "MAX_MANIFEST_BYTES", 16):
            with self.assertRaisesRegex(evidence.EvidenceError, "generated evidence exceeds"):
                evidence.generate(self.root, self.path)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.path.with_name(self.path.name + ".sha256").exists())

    def test_manifest_file_count_limit_rejected(self):
        evidence.generate(self.root, self.path)
        obj = json.loads(self.path.read_bytes())
        obj["files"] = obj["files"] * (evidence.MAX_FILES + 1)
        obj["file_count"] = len(obj["files"])
        self.write_hashed(json.dumps(obj).encode())
        with self.assertRaisesRegex(evidence.EvidenceError, "invalid file count"):
            evidence.verify(self.root, self.path)


if __name__ == "__main__":
    unittest.main()
