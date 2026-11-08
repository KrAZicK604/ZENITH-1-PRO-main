"""V161 generated-at-test-time Ed25519 keys and negative binding regression."""
from __future__ import annotations
import copy
import hashlib
from shutil import which
import json
import os
from pathlib import Path
import sqlite3
import subprocess  # nosec B404 - test-only openssl invocations, no shell
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from types import ModuleType

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import v161_subject_binding as v

KIT = Path('/mnt/data/QOIIN_ZENITH_V160_OFFLINE_REVIEW_KIT_VERIFIED.zip')


def cmd(*argv):
    executable=which('openssl')
    if executable is None: raise AssertionError('OpenSSL not installed')
    p = subprocess.run([executable, *map(str, argv)], capture_output=True, timeout=10, check=False)  # nosec B603
    if p.returncode: raise AssertionError(p.stderr.decode('utf-8', errors='replace'))
    return p.stdout


class BindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='v161_test_keys_')
        cls.path=Path(cls.tmp.name)
        cls.keys={}
        for role in sorted(v.ROLE_SET):
            prv=cls.path/(role+'.pem'); pub=cls.path/(role+'.pub')
            cmd('genpkey','-algorithm','Ed25519','-out',prv)
            cmd('pkey','-in',prv,'-pubout','-outform','DER','-out',pub)
            der=pub.read_bytes()
            if not der.startswith(v.SPKI_PREFIX): raise AssertionError("Unexpected OpenSSL DER SPKI")
            cls.keys[role]=(prv,der[len(v.SPKI_PREFIX):].hex())
        cls.policy={
          'schema':v.TRUST_SCHEMA,'repository':v.REPO,'system':'ZENITH',
          'stream_id':'1'*64,'session_id':'2'*64,'policy_epoch':2,
          'authority':'PAPER_ONLY',
          'signers':{
              role:{'public_hex':key[1], 'key_epoch':2,
                    'organization_id':('reviewer-example' if role=='source_reviewer' else 'custodian-example')}
              for role,key in cls.keys.items()}}
        cls.policy_pin=v.sha(v.canonical(cls.policy))
        cls.handoff={'handoff':{
            'repository':v.REPO,'source_schema':'zenith-evidence-v1',
            'source_file_sha256':'a'*64,'source_record_sha256':'b'*64,
            'source_payload_sha256':'c'*64,'local_verifier_result':'PASS',
            'handoff_authentication':'UNSIGNED_NOT_A_V160_CHECKPOINT',
            'v160_kit_sha256':'d'*64,'productionAuthority':'NONE'},
            'handoff_sha256':'e'*64}
        cls.audited={'result':'LOCAL_HASH_CHAIN_VALID_EXTERNAL_RETENTION_UNVERIFIED',
                     'tip':'f'*64,'genesis':'0'*64,'events':4,
                     'v160_kit_sha256':'d'*64,'productionAuthority':'NONE'}
        cls.scope={'stream_id':'1'*64,'session_id':'2'*64,'system':'ZENITH'}
        cls.body=v.expected_binding(cls.handoff,cls.audited,cls.scope,cls.policy,cls.policy_pin,'9'*64)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def sign(self,body,role):
        message=self.path/'message'; signature=self.path/'signature'
        message.write_bytes(v.DOMAIN+v.canonical(body))
        cmd('pkeyutl','-sign','-inkey',self.keys[role][0],'-rawin','-in',message,'-out',signature)
        return {'role':role,'signature_hex':signature.read_bytes().hex()}

    def statement(self,body=None):
        body=copy.deepcopy(self.body if body is None else body)
        return {'body':body,'signatures':[self.sign(body,role) for role in sorted(v.ROLE_SET)]}

    def test_baseline_statement_verifies(self):
        self.assertEqual(v.check_trust(self.policy,self.policy_pin,set()),self.policy_pin)
        self.assertEqual(v.check_statement(self.statement(),self.policy,self.body),
                         v.sha(v.DOMAIN+v.canonical(self.body)))

    def test_256_seeded_signature_mutations_rejected(self):
        original=self.statement()
        for i in range(256):
            changed=copy.deepcopy(original)
            sig=bytearray.fromhex(changed['signatures'][i%2]['signature_hex'])
            entropy=hashlib.sha256(f'v161-mutation-{i}'.encode()).digest()
            sig[entropy[0]%64] ^= 1 << (entropy[1]%8)
            changed['signatures'][i%2]['signature_hex']=sig.hex()
            with self.subTest(i=i),self.assertRaisesRegex(v.Reject,'SIGNATURE_INVALID'):
                v.check_statement(changed,self.policy,self.body)

    def test_wrong_domain_signatures_are_rejected(self):
        s=self.statement()
        s['signatures'][0]['signature_hex']=self.sign(dict(self.body,nonce_sha256='8'*64),s['signatures'][0]['role'])['signature_hex']
        with self.assertRaisesRegex(v.Reject,'SIGNATURE_INVALID'):
            v.check_statement(s,self.policy,self.body)

    def test_replaced_claim_rejected_even_if_re_signed(self):
        for field,value in [('source_file_sha256','0'*64),('register_tip_sha256','2'*64),
                            ('register_genesis_sha256','3'*64),('unsigned_handoff_sha256','4'*64),
                            ('source_record_sha256','5'*64),('nonce_sha256','6'*64),
                            ('policy_epoch',5),('session_id','7'*64),('trust','PRODUCTION'),
                            ('productionAuthority','PRODUCTION'),('register_events',5)]:
            bad=dict(self.body);bad[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(v.Reject,'SUBJECT_BINDING_MISMATCH'):
                v.check_statement(self.statement(bad),self.policy,self.body)

    def test_trust_pin_substitution(self):
        p=copy.deepcopy(self.policy);p['policy_epoch']=3
        with self.assertRaisesRegex(v.Reject,'TRUST_PIN_MISMATCH'):
            v.check_trust(p,self.policy_pin,set())

    def test_signer_key_reuse_rejected(self):
        p=copy.deepcopy(self.policy)
        p['signers']['source_reviewer']['public_hex']=p['signers']['checkpoint_custodian']['public_hex']
        with self.assertRaisesRegex(v.Reject,'SIGNER_NOT_ROLE_SEPARATED'):
            v.check_trust(p,v.sha(v.canonical(p)),set())

    def test_same_organization_rejected(self):
        p=copy.deepcopy(self.policy)
        p['signers']['source_reviewer']['organization_id']=p['signers']['checkpoint_custodian']['organization_id']
        with self.assertRaisesRegex(v.Reject,'SIGNER_NOT_ROLE_SEPARATED'):
            v.check_trust(p,v.sha(v.canonical(p)),set())

    def test_reuse_of_v160_monitor_key_rejected(self):
        with self.assertRaisesRegex(v.Reject,'SIGNER_NOT_ROLE_SEPARATED'):
            v.check_trust(self.policy,self.policy_pin,{self.policy['signers']['source_reviewer']['public_hex']})

    def test_missing_signer_rejected(self):
        s=self.statement();s['signatures'].pop()
        with self.assertRaisesRegex(v.Reject,'SIGNATURE_QUORUM'):
            v.check_statement(s,self.policy,self.body)

    def test_duplicate_role_rejected(self):
        s=self.statement();s['signatures'][1]=copy.deepcopy(s['signatures'][0])
        with self.assertRaisesRegex(v.Reject,'SIGNATURE_ROLE_REUSE'):
            v.check_statement(s,self.policy,self.body)

    def test_swapped_signature_rejected(self):
        s=self.statement();s['signatures'][0]['signature_hex']=s['signatures'][1]['signature_hex']
        with self.assertRaisesRegex(v.Reject,'SIGNATURE_INVALID'):
            v.check_statement(s,self.policy,self.body)

    def test_wrong_system_not_supported(self):
        p=copy.deepcopy(self.policy);p['system']='QOIIN'
        with self.assertRaisesRegex(v.Reject,'TRUST_SCOPE'):
            v.check_trust(p,v.sha(v.canonical(p)),set())

    def test_overly_broad_policy_rejected(self):
        p=copy.deepcopy(self.policy);p['allow_production']=True
        with self.assertRaisesRegex(v.Reject,'TRUST_SCHEMA'):
            v.check_trust(p,v.sha(v.canonical(p)),set())

    def test_bad_record_scope_rejected(self):
        bad=copy.deepcopy(self.scope);bad['stream_id']='5'*64
        with self.assertRaisesRegex(v.Reject,'TRUST_REGISTER_SCOPE_MISMATCH'):
            v.expected_binding(self.handoff,self.audited,bad,self.policy,self.policy_pin,'9'*64)

    def test_conflicted_audit_cannot_produce_binding(self):
        a=dict(self.audited,result='ABSTAIN_AUTHENTICATED_CONFLICT')
        with self.assertRaisesRegex(v.Reject,'REGISTER_AUDIT_NOT_VALID'):
            v.expected_binding(self.handoff,a,self.scope,self.policy,self.policy_pin,'9'*64)

    def test_v160_kit_hash_disagreement_rejected(self):
        h=copy.deepcopy(self.handoff);h['handoff']['v160_kit_sha256']='8'*64
        with self.assertRaisesRegex(v.Reject,'REGISTER_AUDIT_NOT_VALID'):
            v.expected_binding(h,self.audited,self.scope,self.policy,self.policy_pin,'9'*64)

    def test_unsigned_evidence_cannot_claim_production(self):
        h=copy.deepcopy(self.handoff);h['handoff']['productionAuthority']='PRODUCTION'
        with self.assertRaisesRegex(v.Reject,'UNSIGNED_HANDOFF_SCOPE'):
            v.expected_binding(h,self.audited,self.scope,self.policy,self.policy_pin,'9'*64)

    def test_json_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(v.Reject,'DUPLICATE_JSON_KEY'):
            v.strict_json(b'{"a":1,"a":2}')

    def test_json_noncanonical_rejected(self):
        with self.assertRaisesRegex(v.Reject,'NONCANONICAL_JSON'):
            v.strict_json(b'{ "a": 1 }')

    def test_json_float_rejected(self):
        with self.assertRaisesRegex(v.Reject,'NON_INTEGER_JSON_NUMBER'):
            v.strict_json(b'{"a":1.25}')

    def test_statement_other_key_cannot_sign_both_roles(self):
        p=copy.deepcopy(self.policy)
        p['signers']['source_reviewer']['public_hex']=self.keys['checkpoint_custodian'][1]
        # Recompute policy hash cannot remove role-separation gate.
        with self.assertRaisesRegex(v.Reject,'SIGNER_NOT_ROLE_SEPARATED'):
            v.check_trust(p,v.sha(v.canonical(p)),set())

    def test_read_file_symlink_rejected(self):
        path=self.path/'body.json';path.write_bytes(v.canonical(self.body))
        link=self.path/'link.json'
        try:link.symlink_to(path)
        except (OSError,NotImplementedError):self.skipTest('symlinks unavailable')
        with self.assertRaisesRegex(v.Reject,'FILE_SYMLINK'):
            v.read_file(link)
        link.unlink();path.unlink()

    def test_snapshot_scope_and_two_roles_from_actual_v160_database(self):
        if not KIT.exists():self.skipTest('historical V160 kit not locally mounted')
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'orig.db';snap=Path(td)/'snap.db'
            with zipfile.ZipFile(KIT) as z:
                src.write_bytes(z.read('examples/v160_local_demo/zenith/REGISTER_SYNTHETIC_NOT_EXTERNAL.db'))
            v.snapshot_db(src,snap)
            scope=v.inspect_snapshot(snap)
            self.assertEqual(scope['events'],4)
            self.assertEqual(scope['system'],'ZENITH')
            self.assertEqual(scope['stream_id'],'7129c3a9a744e6ba97657c389639e162aab6fc1c0b566f841987600167fd4f56')
            self.assertEqual(len(scope['monitor_keys']),2)
            # Snapshot stays unchanged after the source is modified.
            source_before=v.sha(snap.read_bytes())
            src.write_bytes(b'replaced')
            self.assertEqual(v.sha(snap.read_bytes()),source_before)

    def test_copied_snapshot_with_mixed_stream_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/'mock.db'
            with sqlite3.connect(db) as c:
                c.execute('create table events(seq integer primary key,record blob)')
                for i in range(4):
                    c.execute('insert into events values (?,?)',(i+1,v.canonical({
                        'system':'ZENITH','stream_id':str(i%2)*64,'session_id':'3'*64,
                        'stage':'PRIOR_CHECKPOINT' if i<2 else 'NEW_CHECKPOINT',
                        'monitor_id':'monitor_a' if i%2==0 else 'monitor_b',
                        'monitor_public_hex':'4'*64})))
            with self.assertRaisesRegex(v.Reject,'REGISTER_SCOPE_INCONSISTENT'):
                v.inspect_snapshot(db)

    def test_invalid_claim_scope_is_never_promoted(self):
        self.assertEqual(self.body['trust'],'PAPER_ONLY')
        self.assertTrue(self.body['promotionBlocked'])
        self.assertEqual(self.body['productionAuthority'],'NONE')

if __name__=='__main__':unittest.main()
