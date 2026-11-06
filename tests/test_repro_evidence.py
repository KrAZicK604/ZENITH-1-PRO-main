"""Negative and positive reproducibility-evidence tests (temporary Git repos)."""
from __future__ import annotations
import importlib.util
import copy
import json
import hashlib
import os
import subprocess  # nosec B404 - fixed interpreter argv for an isolated CLI regression
import sys
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
        self.path.parent.mkdir()
        self.path.write_bytes(b"x" * 129)
        actual = self.path.stat()
        stale = SimpleNamespace(
            st_mode=actual.st_mode, st_size=0, st_dev=actual.st_dev,
            st_ino=actual.st_ino, st_mtime_ns=actual.st_mtime_ns,
            st_ctime_ns=actual.st_ctime_ns,
        )
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

    def test_same_size_replacement_before_open_is_rejected(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b"old")
        replacement = self.path.with_name("replacement.json")
        replacement.write_bytes(b"new")
        original_open = evidence.os.open

        def replace_before_open(path, flags):
            os.replace(replacement, path)
            return original_open(path, flags)

        with patch.object(evidence.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(evidence.EvidenceError, "changed before opening"):
                evidence.bounded_regular_bytes(self.path, 128)

    def test_same_size_in_place_change_during_read_is_rejected(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b"old")
        original_fdopen = evidence.os.fdopen

        class ChangingReader:
            def __init__(inner, descriptor, *args, **kwargs):
                inner.source = original_fdopen(descriptor, *args, **kwargs)

            def __enter__(inner):
                inner.source.__enter__()
                return inner

            def read(inner, count):
                raw = inner.source.read(count)
                self.path.write_bytes(b"new")
                info = self.path.stat()
                os.utime(self.path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
                return raw

            def __exit__(inner, *args):
                return inner.source.__exit__(*args)

        with patch.object(evidence.os, "fdopen", side_effect=ChangingReader):
            with self.assertRaisesRegex(evidence.EvidenceError, "changed while reading"):
                evidence.bounded_regular_bytes(self.path, 128)

    @unittest.skipUnless(os.name == "posix", "renaming an open file is POSIX-specific")
    def test_path_replacement_after_descriptor_check_is_rejected(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b"old")
        replacement = self.path.with_name("replacement.json")
        replacement.write_bytes(b"new")
        original_fstat = evidence.os.fstat
        calls = 0

        def replace_after_final_fstat(descriptor):
            nonlocal calls
            calls += 1
            result = original_fstat(descriptor)
            if calls == 2:
                os.replace(replacement, self.path)
            return result

        with patch.object(evidence.os, "fstat", side_effect=replace_after_final_fstat):
            with self.assertRaisesRegex(evidence.EvidenceError, "path changed while reading"):
                evidence.bounded_regular_bytes(self.path, 128)

    def test_unchanged_file_reads_repeatably(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b"stable")
        for _ in range(3):
            self.assertEqual(evidence.bounded_regular_bytes(self.path, 128), b"stable")

    def test_invalid_host_timestamp_rejected(self):
        original = evidence.generate(self.root, self.path)
        values = ("not-a-date", "2026-02-30T12:00:00Z",
                  "2026-01-01T00:00:00-07:00", True, None)
        for value in values:
            with self.subTest(value=value):
                record = copy.deepcopy(original)
                record["created_at_utc"] = value
                self.write_hashed(json.dumps(record).encode())
                with self.assertRaisesRegex(evidence.EvidenceError, "host UTC"):
                    evidence.verify(self.root, self.path)

    def test_invalid_duration_rejected_before_git(self):
        original = evidence.generate(self.root, self.path)
        for value in (-1, True, 1.5, "1", None):
            with self.subTest(value=value):
                record = copy.deepcopy(original)
                record["elapsed_monotonic_ns"] = value
                self.write_hashed(json.dumps(record).encode())
                with patch.object(evidence, "git", side_effect=AssertionError("Git reached")):
                    with self.assertRaisesRegex(evidence.EvidenceError, "monotonic duration"):
                        evidence.verify(self.root, self.path)

    def test_invalid_python_version_metadata_rejected(self):
        original = evidence.generate(self.root, self.path)
        for value in ("not-a-version", "3.14", True, None):
            with self.subTest(value=value):
                record = copy.deepcopy(original)
                record["python_version"] = value
                self.write_hashed(json.dumps(record).encode())
                with self.assertRaisesRegex(evidence.EvidenceError, "Python version"):
                    evidence.verify(self.root, self.path)

    def test_invalid_ci_context_shape_rejected(self):
        original = evidence.generate(self.root, self.path)
        missing = dict(original["github_context"])
        del missing["GITHUB_RUN_ID"]
        extra = dict(original["github_context"], unknown="value")
        for value in ([], None, missing, extra):
            with self.subTest(value=value):
                record = copy.deepcopy(original)
                record["github_context"] = value
                self.write_hashed(json.dumps(record).encode())
                with self.assertRaisesRegex(evidence.EvidenceError, "context shape"):
                    evidence.verify(self.root, self.path)

    def test_invalid_ci_context_values_rejected(self):
        original = evidence.generate(self.root, self.path)
        values = (("GITHUB_REPOSITORY", 1), ("GITHUB_SHA", "not-a-sha"),
                  ("GITHUB_SHA", "0" * 40), ("GITHUB_RUN_ID", "0"),
                  ("GITHUB_RUN_ID", "-1"), ("GITHUB_RUN_ID", "１"),
                  ("GITHUB_RUN_ATTEMPT", False))
        for key, value in values:
            with self.subTest(key=key, value=value):
                record = copy.deepcopy(original)
                record["github_context"][key] = value
                self.write_hashed(json.dumps(record).encode())
                with self.assertRaises(evidence.EvidenceError):
                    evidence.verify(self.root, self.path)

    def test_well_formed_host_claims_remain_unauthenticated(self):
        record = evidence.generate(self.root, self.path)
        record["created_at_utc"] = "2000-01-01T00:00:00Z"
        record["elapsed_monotonic_ns"] = 0
        record["python_version"] = "0.0.1"
        record["github_context"].update({
            "GITHUB_REPOSITORY": "Claimed/Repository", "GITHUB_SHA": record["git_head"],
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push",
        })
        self.write_hashed(json.dumps(record).encode())
        self.assertEqual(evidence.verify(self.root, self.path)["production_authority"], "NONE")

    def test_generator_refuses_invalid_run_metadata_before_writing(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "0"}):
            with self.assertRaisesRegex(evidence.EvidenceError, "run identity format"):
                evidence.generate(self.root, self.path)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.path.with_name(self.path.name + ".sha256").exists())

    def test_cli_malformed_metadata_reports_failure_without_traceback(self):
        record = evidence.generate(self.root, self.path)
        record["elapsed_monotonic_ns"] = -1
        self.write_hashed(json.dumps(record).encode())
        result = subprocess.run(  # nosec B603 - fixed absolute interpreter and controlled fixture paths
            [sys.executable, str(ROOT / "scripts" / "repro_evidence.py"), "verify",
             "--root", str(self.root), "--manifest", str(self.path)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("EVIDENCE_FAIL: invalid monotonic duration", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("EVIDENCE_VERIFIED", result.stdout)


if __name__ == "__main__":
    unittest.main()
