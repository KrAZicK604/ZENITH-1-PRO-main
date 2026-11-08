"""Optional repository integration tests: real ZENITH replay, mocked V160 registry input.

The registry responses are intentionally mocked for this unit integration test;
V160's *real* register is independently exercised in the local research kit.
"""
from __future__ import annotations
import importlib.util
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from shutil import which
import subprocess  # nosec B404 - isolated test key generation only
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE/'scripts'))
try:
    from evidence_v1 import make_evidence,canonical as evidence_canonical
    from zenith_v160_bridge import build_handoff
    REPO_AVAILABLE=True
except ImportError:
    REPO_AVAILABLE=False
import v161_subject_binding as v


def openssl(*argv):
    executable=which('openssl')
    if executable is None: raise AssertionError('OpenSSL not installed')
    p=subprocess.run([executable,*map(str,argv)],capture_output=True,timeout=10,check=False)  # nosec B603
    if p.returncode:raise AssertionError(p.stderr.decode(errors='replace'))
    return p.stdout


@unittest.skipUnless(REPO_AVAILABLE, 'requires actual ZENITH GitHub source checkout')
class RepoBridgeUnitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.tmp.name)
        cls.keys={}
        for role in sorted(v.ROLE_SET):
            priv=cls.root/(role+'.pem');pub=cls.root/(role+'.der')
            openssl('genpkey','-algorithm','Ed25519','-out',priv)
            openssl('pkey','-in',priv,'-pubout','-outform','DER','-out',pub)
            der=pub.read_bytes()
            if not der.startswith(v.SPKI_PREFIX): raise AssertionError("Unexpected OpenSSL DER SPKI")
            cls.keys[role]=(priv,der[len(v.SPKI_PREFIX):].hex())
        cls.stream='2'*64;cls.session='3'*64;cls.genesis='4'*64;cls.tip='5'*64
        cls.policy={'schema':v.TRUST_SCHEMA,'repository':v.REPO,'system':'ZENITH',
                    'stream_id':cls.stream,'session_id':cls.session,'policy_epoch':1,
                    'authority':'PAPER_ONLY','signers':{
                        r:{'public_hex':cls.keys[r][1], 'key_epoch':1,
                           'organization_id': ('org-alpha' if r=='source_reviewer' else 'org-beta')}
                        for r in v.ROLE_SET}}
        cls.policy_pin=v.sha(v.canonical(cls.policy))

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def setUp(self):
        self.work=tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        root=Path(self.work.name)
        # Never mutate class-scoped trust across test cases.
        self.policy=copy.deepcopy(type(self).policy)
        self.policy_pin=v.sha(v.canonical(self.policy))
        self.evidence=root/'evidence.json';self.handoff=root/'handoff.json'
        self.trust=root/'trust.json';self.statement=root/'signed.json'
        self.db=root/'current.db';self.kit=root/'unused_kit.zip'
        record=make_evidence(3.9,0.2,25)
        self.evidence.write_bytes(evidence_canonical(record)+b'\n')
        self.unsigned=build_handoff(self.evidence)
        self.handoff.write_bytes(v.canonical(self.unsigned)+b'\n')
        self.trust.write_bytes(v.canonical(self.policy)+b'\n')
        # The fake table is only for scope tests; V160 audit is mocked in this class.
        with closing(sqlite3.connect(self.db)) as c:
            c.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY, record BLOB)')
            seq=0
            for stage in ('PRIOR_CHECKPOINT','NEW_CHECKPOINT'):
                for idx,monitor in enumerate(('monitor_a','monitor_b')):
                    seq+=1
                    c.execute('INSERT INTO events VALUES (?,?)',(seq,v.canonical({
                        'system':'ZENITH', 'stream_id':self.stream,
                        'session_id':self.session,'stage':stage,'monitor_id':monitor,
                        'monitor_public_hex':('6' if idx==0 else '7')*64})))
            c.commit()
        self.audited={'result':'LOCAL_HASH_CHAIN_VALID_EXTERNAL_RETENTION_UNVERIFIED',
                      'events':4,'tip':self.tip,'genesis':self.genesis,
                      'v160_kit_sha256':self.unsigned['handoff']['v160_kit_sha256'],
                      'productionAuthority':'NONE'}
        self.body=v.expected_binding(self.unsigned,self.audited,
                      {'system':'ZENITH','stream_id':self.stream,'session_id':self.session},
                      self.policy,self.policy_pin,'8'*64)
        self.statement.write_bytes(v.canonical(self.sign_record(self.body))+b'\n')

    def sign_record(self,body):
        message=self.root/'tbs';signature=self.root/'sig'
        message.write_bytes(v.DOMAIN+v.canonical(body))
        signatures=[]
        for role in sorted(v.ROLE_SET):
            openssl('pkeyutl','-sign','-inkey',self.keys[role][0],'-rawin',
                    '-in',message,'-out',signature)
            signatures.append({'role':role,'signature_hex':signature.read_bytes().hex()})
        return {'body':body,'signatures':signatures}

    def verify(self,competitor=None):
        # Real ZENITH verify_handoff + consistent SQLite snapshot, mocked V160
        # audit so no packaged historical material enters the GitHub repository.
        with mock.patch('zenith_v160_bridge.audit_v160',return_value=dict(self.audited)):
            return v.verify_files(evidence=self.evidence,handoff=self.handoff,
                     kit=self.kit,database=self.db,trusted_tip=self.tip,
                     trusted_genesis=self.genesis,trust_file=self.trust,
                     trust_pin=self.policy_pin,statement_file=self.statement,
                     competitor_file=competitor)

    def test_source_and_handoff_are_verified_from_stable_copies(self):
        import zenith_v160_bridge as bridge
        real_verify=bridge.verify_handoff
        original_evidence=self.evidence.read_bytes()
        original_handoff=self.handoff.read_bytes()
        def change_original_after_replay(handoff_copy,evidence_copy):
            self.assertNotEqual(evidence_copy,self.evidence)
            self.assertNotEqual(handoff_copy,self.handoff)
            self.assertEqual(evidence_copy.read_bytes(),original_evidence)
            self.assertEqual(handoff_copy.read_bytes(),original_handoff)
            result=real_verify(handoff_copy,evidence_copy)
            self.evidence.write_bytes(b'source overwritten after staging')
            self.handoff.write_bytes(b'handoff overwritten after staging')
            return result
        with mock.patch('zenith_v160_bridge.verify_handoff',side_effect=change_original_after_replay):
            assessment=self.verify()
        self.assertEqual(assessment['result'],'CRYPTO_VALID_EXTERNAL_RETENTION_ABSTAIN')
        self.assertNotEqual(self.evidence.read_bytes(),original_evidence)

    def test_valid_exact_signed_subject_tip_pair(self):
        r=self.verify()
        self.assertEqual(r['result'],'CRYPTO_VALID_EXTERNAL_RETENTION_ABSTAIN')
        self.assertEqual(r['events'],4)
        self.assertEqual(r['external_custody'],'UNVERIFIED')
        self.assertEqual(r['productionAuthority'],'NONE')

    def test_competing_correctly_signed_tip_abstains(self):
        alt=dict(self.body,register_tip_sha256='a'*64)
        c=Path(self.work.name)/'competing.json'
        c.write_bytes(v.canonical(self.sign_record(alt)))
        r=self.verify(competitor=c)
        self.assertEqual(r['result'],'ABSTAIN_AUTHENTICATED_CONFLICT')

    def test_invalid_competitor_not_classified_as_conflict(self):
        alt=dict(self.body,register_tip_sha256='a'*64)
        forged=self.sign_record(alt)
        forged['signatures'][0]['signature_hex']='0'*128
        c=Path(self.work.name)/'forged.json';c.write_bytes(v.canonical(forged))
        with self.assertRaisesRegex(v.Reject,'SIGNATURE_INVALID'):
            self.verify(competitor=c)

    def test_source_tamper_rejected_before_signature_check(self):
        self.evidence.write_bytes(self.evidence.read_bytes()+b' ')
        with self.assertRaises(Exception):
            self.verify()

    def test_wrong_register_tip_even_if_audit_claims_success(self):
        self.tip='f'*64
        with self.assertRaisesRegex(v.Reject,'AUDIT_TIP_MISMATCH'):
            self.verify()

    def test_malformed_body_rejected_not_crash(self):
        self.statement.write_bytes(v.canonical({'body':[], 'signatures':[]}))
        with self.assertRaisesRegex(v.Reject,'STATEMENT_BODY'):
            self.verify()

    def test_wrong_trust_policy_pin_fails(self):
        self.policy_pin='c'*64
        with self.assertRaisesRegex(v.Reject,'TRUST_PIN_MISMATCH'):
            self.verify()

    def test_replayed_claim_different_session_rejected(self):
        self.policy['session_id']='9'*64
        self.trust.write_bytes(v.canonical(self.policy))
        self.policy_pin=v.sha(v.canonical(self.policy))
        with self.assertRaisesRegex(v.Reject,'TRUST_REGISTER_SCOPE_MISMATCH'):
            self.verify()

if __name__=='__main__':unittest.main()
