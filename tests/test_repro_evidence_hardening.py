"""Adversarial evidence-output and committed-blob checks using isolated Git fixtures."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "repro_evidence_hardening", ROOT / "scripts" / "repro_evidence.py"
)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceHardeningTest(unittest.TestCase):
    def setUp(self):
        fixture_env = patch.dict(os.environ, {"GITHUB_SHA": ""})
        fixture_env.start()
        self.addCleanup(fixture_env.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.root = self.tmp / "repo"
        self.root.mkdir()
        evidence.git(self.root, "init", "-q")
        (self.root / "sample.py").write_text('print("safe")\n')
        evidence.git(self.root, "add", "sample.py")
        evidence.git(
            self.root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "fixture"
        )
        self.output = self.root / ".evidence" / "repro-manifest.json"

    def test_normal_create_verify(self):
        self.assertEqual(evidence.generate(self.root, self.output)["file_count"], 1)
        self.assertEqual(evidence.verify(self.root, self.output)["file_count"], 1)

    def test_absolute_destination_outside_repo_rejected(self):
        output = self.tmp / "external.json"
        with self.assertRaisesRegex(evidence.EvidenceError, "escapes repository"):
            evidence.generate(self.root, output)
        self.assertFalse(output.exists())

    def test_symlinked_evidence_directory_rejected(self):
        external = self.tmp / "other"
        external.mkdir()
        (self.root / ".evidence").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(evidence.EvidenceError, "symlink"):
            evidence.generate(self.root, self.output)
        self.assertEqual(list(external.iterdir()), [])

    def test_internal_symlinked_directory_rejected(self):
        (self.root / "nested").mkdir()
        (self.root / ".evidence").symlink_to(self.root / "nested", target_is_directory=True)
        with self.assertRaisesRegex(evidence.EvidenceError, "symlink"):
            evidence.generate(self.root, self.output)

    def test_git_metadata_destination_rejected(self):
        output = self.root / ".git" / "evidence.json"
        with self.assertRaisesRegex(evidence.EvidenceError, "unsafe evidence"):
            evidence.generate(self.root, output)
        self.assertFalse(output.exists())

    def test_parent_traversal_rejected(self):
        output = self.root / ".." / "outside.json"
        with self.assertRaises(evidence.EvidenceError):
            evidence.generate(self.root, output)
        self.assertFalse((self.tmp / "outside.json").exists())

    def test_rejects_unapproved_output_subtree(self):
        # Even in-repository paths must not become arbitrary write targets.
        output = self.root / ".github" / "workflows" / "new.yml"
        with self.assertRaisesRegex(evidence.EvidenceError, "unsafe evidence"):
            evidence.generate(self.root, output)
        self.assertFalse(output.exists())

    def test_dangling_manifest_symlink_does_not_escape(self):
        external = self.tmp / "uncreated-external.json"
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.symlink_to(external)
        with self.assertRaisesRegex(evidence.EvidenceError, "symlink"):
            evidence.generate(self.root, self.output)
        self.assertFalse(external.exists())
        self.assertTrue(self.output.is_symlink())

    def test_dangling_sidecar_symlink_does_not_escape(self):
        external = self.tmp / "uncreated-external.sha256"
        self.output.parent.mkdir(parents=True, exist_ok=True)
        sidecar = self.output.with_name(self.output.name + ".sha256")
        sidecar.symlink_to(external)
        with self.assertRaisesRegex(evidence.EvidenceError, "symlink"):
            evidence.generate(self.root, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(external.exists())
        self.assertTrue(sidecar.is_symlink())

    def test_custom_manifest_inside_evidence_still_works(self):
        nested = self.root / ".evidence" / "custom" / "manifest.json"
        self.assertEqual(evidence.generate(self.root, nested)["file_count"], 1)
        self.assertEqual(evidence.verify(self.root, nested)["file_count"], 1)

    def test_assume_unchanged_modified_file_blocks_creation(self):
        evidence.git(self.root, "update-index", "--assume-unchanged", "sample.py")
        (self.root / "sample.py").write_text("TAMPERED\n")
        self.assertFalse(
            evidence.git(self.root, "status", "--porcelain", "--untracked-files=no").strip()
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "committed Git object"):
            evidence.generate(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_skip_worktree_modified_file_blocks_creation(self):
        evidence.git(self.root, "update-index", "--skip-worktree", "sample.py")
        (self.root / "sample.py").write_text("TAMPERED\n")
        with self.assertRaisesRegex(evidence.EvidenceError, "committed Git object"):
            evidence.generate(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_checksum_write_failure_cleans_manifest(self):
        original_open = Path.open

        def failed_open(path, mode="r", *args, **kwargs):
            if path.name.endswith(".sha256") and mode == "xb":
                raise OSError("injected checksum write failure")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", failed_open):
            with self.assertRaisesRegex(OSError, "injected checksum"):
                evidence.generate(self.root, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_name(self.output.name + ".sha256").exists())
        self.assertEqual(evidence.generate(self.root, self.output)["file_count"], 1)

    def test_refuse_existing_checksum_preserves_bytes(self):
        self.output.parent.mkdir()
        sidecar = self.output.with_name(self.output.name + ".sha256")
        sidecar.write_bytes(b"ORIGINAL")
        with self.assertRaises(evidence.EvidenceError):
            evidence.generate(self.root, self.output)
        self.assertEqual(sidecar.read_bytes(), b"ORIGINAL")
        self.assertFalse(self.output.exists())

    def test_repository_fsmonitor_hook_is_not_executed(self):
        hook = self.tmp / "fsmonitor.sh"
        marker = self.tmp / "FS_MONITOR_EXECUTED"
        hook.write_text('#!/bin/sh\nprintf invoked > "' + str(marker) + '"\nprintf "\\0"\n')
        hook.chmod(0o700)
        evidence.git(self.root, "config", "core.fsmonitor", str(hook))
        evidence.generate(self.root, self.output)
        self.assertFalse(marker.exists(), "Git executed a repository-controlled hook")
        self.assertEqual(evidence.verify(self.root, self.output)["file_count"], 1)

    def test_modified_tracked_file_reports_dirty(self):
        (self.root / "sample.py").write_text("BAD")
        with self.assertRaises(evidence.EvidenceError):
            evidence.generate(self.root, self.output)


if __name__ == "__main__":
    unittest.main()
