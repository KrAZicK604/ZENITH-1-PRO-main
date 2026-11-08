"""Read-only ZENITH/V160 integration tests; no Streamlit or production changes."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
MODULE = HERE / "scripts" / "zenith_v160_bridge.py"
spec = importlib.util.spec_from_file_location("zenith_v160_bridge", MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError("ZENITH_V160_BRIDGE_MISSING")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class ZenithV160BridgeTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        from evidence_v1 import make_evidence, canonical
        self.record = make_evidence(3.9, 0.2, 25)
        self.evidence = self.root / "evidence.json"
        self.evidence.write_bytes(canonical(self.record) + b"\n")

    def test_complete_handoff_and_reverification(self):
        handoff = bridge.build_handoff(self.evidence)
        self.assertEqual(handoff["handoff"]["source_record_sha256"], self.record["record_sha256"])
        self.assertEqual(handoff["handoff"]["productionAuthority"], "NONE")
        self.assertEqual(handoff["handoff"]["handoff_authentication"], "UNSIGNED_NOT_A_V160_CHECKPOINT")
        saved = self.root / "handoff.json"
        saved.write_bytes(bridge._plain(handoff) + b"\n")
        result = bridge.verify_handoff(saved, self.evidence)
        self.assertEqual(result["result"], "LOCAL_EVIDENCE_AND_UNSIGNED_HANDOFF_MATCH")

    def test_any_changed_evidence_bytes_break_binding(self):
        handoff = bridge.build_handoff(self.evidence)
        saved = self.root / "handoff.json"
        saved.write_bytes(bridge._plain(handoff))
        self.evidence.write_bytes(self.evidence.read_bytes() + b" ")
        with self.assertRaisesRegex(bridge.BridgeError, "HANDOFF_BINDING_MISMATCH"):
            bridge.verify_handoff(saved, self.evidence)

    def test_rehashed_wrong_orbit_still_fails_existing_replay(self):
        from evidence_v1 import digest, canonical
        r = json.loads(self.evidence.read_bytes())
        r["payload"]["orbit_hex"][1] = "0x1.0000000000000p-1"
        r["payload_sha256"] = digest(r["payload"])
        r["record_sha256"] = digest({key: value for key, value in r.items() if key != "record_sha256"})
        self.evidence.write_bytes(canonical(r))
        with self.assertRaisesRegex(bridge.BridgeError, "ZENITH_REPLAY_NOT_VERIFIED"):
            bridge.build_handoff(self.evidence)

    def test_duplicate_json_member_fails_closed(self):
        self.evidence.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaises(bridge.BridgeError):
            bridge.build_handoff(self.evidence)

    def test_malformed_handoff_and_forged_hash_rejected(self):
        saved = self.root / "handoff.json"
        signed = bridge.build_handoff(self.evidence)
        signed["handoff"]["productionAuthority"] = "PRODUCTION"
        signed["handoff_sha256"] = bridge._digest(bridge.PREFIX + bridge._plain(signed["handoff"]))
        saved.write_bytes(bridge._plain(signed))
        with self.assertRaisesRegex(bridge.BridgeError, "HANDOFF_BINDING_MISMATCH"):
            bridge.verify_handoff(saved, self.evidence)

    def test_export_does_not_write_to_source(self):
        before = self.evidence.read_bytes()
        r = bridge.build_handoff(self.evidence)
        self.assertEqual(self.evidence.read_bytes(), before)
        self.assertNotIn("private_key", str(r))

    def test_invalid_kit_digest_rejected(self):
        bad = self.root / "kit.zip"
        bad.write_bytes(b"not an authenticated V160 ZIP")
        db = self.root / "sample.db"
        db.write_bytes(b"SQLite mock")
        with self.assertRaisesRegex(bridge.BridgeError, "KIT_SHA256_MISMATCH"):
            bridge.audit_v160(bad, db, "a" * 64, "b" * 64)

    def test_missing_database_still_rejected(self):
        bad = self.root / "kit.zip"
        bad.write_bytes(b"not an authenticated V160 ZIP")
        with self.assertRaises(bridge.BridgeError):
            bridge.audit_v160(bad, self.root / "missing.db", "a" * 64, "b" * 64)

    def test_invalid_pins_fail_closed(self):
        with self.assertRaisesRegex(bridge.BridgeError, "TIP_PIN_FORMAT"):
            bridge.audit_v160(self.root / "kit.zip", self.root / "sample.db", "XYZ", "b" * 64)
        with self.assertRaisesRegex(bridge.BridgeError, "GENESIS_PIN_FORMAT"):
            bridge.audit_v160(self.root / "kit.zip", self.root / "sample.db", "a" * 64, " ")

    def test_symlinked_evidence_rejected(self):
        link = self.root / "link.json"
        link.symlink_to(self.evidence)
        with self.assertRaisesRegex(bridge.BridgeError, "EVIDENCE_SYMLINK"):
            bridge.build_handoff(link)

    def test_zip_traversal_and_duplicate_members_rejected(self):
        for entries in (("../evil",), ("src/verify_v160_cli.py", "src/verify_v160_cli.py")):
            zpath = self.root / "attack.zip"
            with zipfile.ZipFile(zpath, "w") as z:
                for name in entries:
                    z.writestr(name, "x")
            with zipfile.ZipFile(zpath) as z:
                with self.assertRaisesRegex(bridge.BridgeError, "KIT_UNSAFE_MEMBER"):
                    bridge._kit_members(z)

    def test_cli_export_returns_unsigned_handoff(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            code = bridge.main(["export", "--evidence", str(self.evidence)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["handoff"]["external_retention"], "UNVERIFIED")

    def test_cli_denies_missing_research_kit(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            code = bridge.main(["audit", "--kit", str(self.root / "absent.zip"),
                                "--database", str(self.root / "absent.db"),
                                "--expected-tip", "a" * 64, "--genesis-pin", "b" * 64])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["productionAuthority"], "NONE")

    def test_authenticated_conflict_exits_nonzero(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with patch.object(bridge, "audit_v160", return_value={"result": "ABSTAIN_AUTHENTICATED_CONFLICT"}):
            with redirect_stdout(output):
                code = bridge.main(["audit", "--kit", str(self.root / "not_used.zip"),
                                    "--database", str(self.root / "not_used.db"),
                                    "--expected-tip", "a" * 64, "--genesis-pin", "b" * 64])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["result"], "ABSTAIN_AUTHENTICATED_CONFLICT")


if __name__ == "__main__":
    unittest.main()
