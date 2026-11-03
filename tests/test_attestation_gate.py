"""Deterministic negative/positive tests for privileged signing preconditions."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("attestation_gate", HERE / "scripts" / "attestation_gate.py")
gate = importlib.util.module_from_spec(spec)
if spec is None or spec.loader is None:
    raise RuntimeError("attestation_gate module could not be loaded")
spec.loader.exec_module(gate)
SHA = "a" * 40
VERSION = "3.14.10"


def valid_input():
    env = {
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": gate.REPOSITORY,
        "GITHUB_REF": gate.MAIN_REF,
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": "41566064517",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    manifest = {
        "git_head": SHA, "python_version": VERSION,
        "status": "PAPER_ONLY", "promotion_blocked": True,
        "production_authority": "NONE",
        "integrity": "SHA256_UNSIGNED_NO_EXTERNAL_ATTESTATION",
        "clock_provenance": "HOST_CLOCK_UNATTESTED",
        "github_context": {key: env[key] for key in gate.CONTEXT_KEYS},
    }
    return manifest, env


class TrustedAttestationGateTest(unittest.TestCase):
    def test_trusted_protected_main_push(self):
        m,e=valid_input()
        gate.check_context(m,e,SHA,VERSION)

    def test_untrusted_events_and_refs(self):
        for name,value in (
            ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_REF", "refs/pull/50/merge"), ("GITHUB_REF", "refs/heads/other"),
            ("GITHUB_REF_PROTECTED", "false"), ("GITHUB_REPOSITORY", "other/fork"),
        ):
            with self.subTest(name=name,value=value):
                m,e=valid_input()
                e[name]=value
                with self.assertRaises(gate.AttestationGateError):
                    gate.check_context(m,e,SHA,VERSION)

    def test_bad_sha_and_checkout_identity(self):
        for changed_sha,checked in (("0"*40,SHA),("not-a-sha",SHA),(SHA,"b"*40)):
            with self.subTest(changed_sha=changed_sha):
                m,e=valid_input()
                e["GITHUB_SHA"]=changed_sha
                with self.assertRaises(gate.AttestationGateError):
                    gate.check_context(m,e,checked,VERSION)

    def test_run_id_and_attempt_must_be_valid(self):
        for key in ("GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT"):
            for value in ("","0","-1","abc","1.5"):
                with self.subTest(key=key,value=value):
                    m,e=valid_input()
                    e[key]=value
                    with self.assertRaises(gate.AttestationGateError):
                        gate.check_context(m,e,SHA,VERSION)

    def test_cross_run_replay_is_rejected(self):
        for key in gate.CONTEXT_KEYS:
            with self.subTest(key=key):
                m,e=valid_input()
                m["github_context"][key]="old-run-value"
                with self.assertRaises(gate.AttestationGateError):
                    gate.check_context(m,e,SHA,VERSION)

    def test_invalid_manifest_and_production_authority(self):
        for key,value in (
            ("status","PROMOTED"),("promotion_blocked",False),
            ("production_authority","PRODUCTION"), ("integrity","SIGNED"),
            ("clock_provenance","TRUSTED"),("git_head","b"*40),
            ("python_version","3.14.9"),("github_context",None),
        ):
            with self.subTest(key=key):
                m,e=valid_input()
                m[key]=value
                with self.assertRaises(gate.AttestationGateError):
                    gate.check_context(m,e,SHA,VERSION)

    def test_non_object_manifest(self):
        _,e=valid_input()
        with self.assertRaises(gate.AttestationGateError):
            gate.check_context([],e,SHA,VERSION)


class AttestationWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow_path=HERE / ".github" / "workflows" / "smoke-test.yml"
        cls.workflow=workflow_path.read_text(encoding="utf-8")
        cls.smoke=cls.workflow.split("  smoke-test:",1)[1].split("  attest-main:",1)[0]
        cls.signer=cls.workflow.split("  attest-main:",1)[1]

    def test_unprivileged_smoke_job(self):
        self.assertIn("permissions:\n  contents: read\n", self.workflow)
        for token in ("id-token: write", "attestations: write", "artifact-metadata: write"):
            self.assertNotIn(token,self.smoke)

    def test_privileged_job_after_passing_smoke(self):
        self.assertIn("needs: smoke-test",self.signer)
        self.assertIn("github.event_name == 'push'",self.signer)
        self.assertIn("github.ref == 'refs/heads/main'",self.signer)
        self.assertIn("github.repository == 'KrAZicK604/ZENITH-1-PRO-main'",self.signer)
        for token in ("contents: read", "id-token: write", "attestations: write", "artifact-metadata: write"):
            self.assertIn(token,self.signer)
        self.assertNotIn("pull_request_target",self.workflow)

    def test_source_provenance_verified_before_signing(self):
        self.assertIn("digest-mismatch: error",self.signer)
        self.assertIn("name: repro-evidence",self.signer)
        self.assertIn("path: .evidence",self.signer)
        verify=self.signer.index('"$PYTHON" scripts/attestation_gate.py')
        sign=self.signer.index("uses: actions/attest@")
        self.assertLess(verify,sign)
        self.assertIn(".evidence/repro-manifest.json",self.signer)
        self.assertIn(".evidence/repro-manifest.json.sha256",self.signer)

    def test_privileged_verifier_is_stdlib_only(self):
        self.assertIn('PYTHON="$(uv python find 3.14.10)"', self.signer)
        self.assertIn('test -x "$PYTHON"', self.signer)
        self.assertIn('"$PYTHON" scripts/attestation_gate.py', self.signer)
        self.assertIn('sys.version_info[:3] == (3, 14, 10)', self.signer)
        for unsafe in (
            "uv sync ", "uv run ", "uv lock --check", "enable-cache: true",
            "pip install ", "pipx ", "curl ", "wget ",
        ):
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, self.signer)

    def test_all_new_actions_pinned_exactly(self):
        self.assertIn("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",self.signer)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",self.signer)

    def test_runtime_guard_remains_active_under_python_optimization(self):
        self.assertNotIn("assert sys.version_info",self.smoke)
        self.assertIn('sys.exit(0 if sys.version_info[:3] == (3, 14, 10)',self.smoke)

    def test_attestation_not_in_unsigned_job(self):
        self.assertNotIn("actions/attest@",self.smoke)
        self.assertNotIn("actions/download-artifact@",self.smoke)


if __name__ == "__main__":
    unittest.main()
