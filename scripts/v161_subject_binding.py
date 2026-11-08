"""ZENITH/QOIIN V161 signed subject-to-V160-tip research verifier.

Verifies the actual ZENITH replay and V160 register audit via the existing bridge,
then checks two independently provisioned ED25519 *key slots*. A signature or
organization label does not establish genuinely independent custody or time.

The verifier NEVER signs, writes to a register, or grants production authority.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from shutil import which
import sqlite3
import stat
import subprocess  # nosec B404 - fixed openssl binary, no shell
import sys
import tempfile
from urllib.parse import quote

SCHEMA = 'zenith-v161-subject-tip-v1'
TRUST_SCHEMA = 'zenith-v161-trust-v1'
DOMAIN = b'ZENITH-QOIIN-V161-SUBJECT-TIP-BINDING-v1\0'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX128 = re.compile(r'[0-9a-f]{128}\Z')
ROLE_SET = {'source_reviewer', 'checkpoint_custodian'}
REPO = 'KrAZicK604/ZENITH-1-PRO-main'
MAX_JSON_BYTES = 16384
MAX_DB_BYTES = 32000000
SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')

class Reject(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def hex64(value: object, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise Reject('BAD_' + label)
    return value


def strict_json(data: bytes, max_bytes: int=MAX_JSON_BYTES) -> dict:
    if type(data) is not bytes or len(data) > max_bytes or not data:
        raise Reject('JSON_SIZE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise Reject('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def no_float(_): raise Reject('NON_INTEGER_JSON_NUMBER')
    try:
        obj = json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=unique,
                         parse_float=no_float, parse_constant=no_float)
        if type(obj) is not dict: raise Reject('JSON_OBJECT_REQUIRED')
        # Canonical byte equality prevents alternate encodings, whitespace and order tricks.
        if canonical(obj) != data: raise Reject('NONCANONICAL_JSON')
        return obj
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise Reject('INVALID_JSON') from exc


def read_file(path: Path, *, cap: int=MAX_JSON_BYTES) -> bytes:
    p = path.absolute()
    for component in (p, *p.parents):
        if component.is_symlink(): raise Reject('FILE_SYMLINK')
    try:
        before = p.stat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
            raise Reject('FILE_SIZE_OR_TYPE')
        with p.open('rb') as fh: data = fh.read(cap + 1)
        after = p.stat()
        if (len(data) != before.st_size or after.st_size != before.st_size or
                after.st_ino != before.st_ino or after.st_dev != before.st_dev):
            raise Reject('FILE_CHANGED')
        return data
    except OSError as exc:
        raise Reject('FILE_UNAVAILABLE') from exc


def _ed25519_verify(public_hex: str, signature_hex: str, message: bytes) -> None:
    hex64(public_hex, 'PUBLIC_KEY')
    if type(signature_hex) is not str or HEX128.fullmatch(signature_hex) is None:
        raise Reject('BAD_SIGNATURE_FORMAT')
    der = SPKI_PREFIX + bytes.fromhex(public_hex)
    pem = b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(der) + b'-----END PUBLIC KEY-----\n'
    # The openssl invocation is verification only. No private keys are handled.
    with tempfile.TemporaryDirectory(prefix='zv161_verify_') as td:
        root = Path(td)
        pub = root / 'public.pem'; msg = root / 'message'; sig = root / 'sig'
        pub.write_bytes(pem); msg.write_bytes(message); sig.write_bytes(bytes.fromhex(signature_hex))
        openssl = which('openssl')
        if openssl is None: raise Reject('OPENSSL_UNAVAILABLE')
        try:
            completed = subprocess.run(  # nosec B603 - resolved verifier binary, no shell
                [openssl, 'pkeyutl', '-verify', '-pubin', '-inkey', str(pub), '-rawin',
                 '-in', str(msg), '-sigfile', str(sig)],
                capture_output=True, timeout=5, check=False,
                env={'PATH': os.defpath},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject('OPENSSL_UNAVAILABLE') from exc
        if completed.returncode != 0:
            raise Reject('SIGNATURE_INVALID')


def check_trust(policy: dict, expected_pin: str, forbidden_keys: set[str]) -> str:
    hex64(expected_pin, 'TRUST_PIN')
    if sha(canonical(policy)) != expected_pin: raise Reject('TRUST_PIN_MISMATCH')
    if type(policy) is not dict or set(policy) != {'schema','repository','system', 'stream_id',
                'session_id','policy_epoch','signers','authority'}:
        raise Reject('TRUST_SCHEMA')
    if policy['schema'] != TRUST_SCHEMA or policy['repository'] != REPO or policy['system'] != 'ZENITH':
        raise Reject('TRUST_SCOPE')
    for key in ('stream_id', 'session_id'): hex64(policy[key], key.upper())
    if type(policy['policy_epoch']) is not int or not 1 <= policy['policy_epoch'] <= 2**31-1:
        raise Reject('BAD_POLICY_EPOCH')
    if policy['authority'] != 'PAPER_ONLY': raise Reject('TRUST_AUTHORITY')
    signers = policy['signers']
    if type(signers) is not dict or set(signers) != ROLE_SET: raise Reject('TRUST_ROLES')
    used_keys = set(); used_orgs = set()
    for role in sorted(ROLE_SET):
        s = signers[role]
        if type(s) is not dict or set(s) != {'public_hex', 'organization_id', 'key_epoch'}:
            raise Reject('TRUST_SIGNER_SHAPE')
        key = hex64(s['public_hex'], 'SIGNER_PUBLIC')
        org = s['organization_id']
        if type(org) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{2,63}', org):
            raise Reject('BAD_ORGANIZATION_ID')
        if type(s['key_epoch']) is not int or s['key_epoch'] < 1 or s['key_epoch'] > 2**31-1:
            raise Reject('BAD_KEY_EPOCH')
        if key in forbidden_keys or key in used_keys or org in used_orgs:
            raise Reject('SIGNER_NOT_ROLE_SEPARATED')
        used_keys.add(key); used_orgs.add(org)
    return expected_pin


def check_statement(statement: dict, policy: dict, expected_body: dict) -> str:
    if type(statement) is not dict or set(statement) != {'body', 'signatures'}:
        raise Reject('STATEMENT_SCHEMA')
    body = statement['body']
    if type(body) is not dict or canonical(body) != canonical(expected_body):
        raise Reject('SUBJECT_BINDING_MISMATCH')
    signatures = statement['signatures']
    if type(signatures) is not list or len(signatures) != 2:
        raise Reject('SIGNATURE_QUORUM')
    verified_roles = set()
    for record in signatures:
        if type(record) is not dict or set(record) != {'role', 'signature_hex'}:
            raise Reject('SIGNATURE_SCHEMA')
        role = record['role']
        if type(role) is not str or role not in ROLE_SET or role in verified_roles:
            raise Reject('SIGNATURE_ROLE_REUSE')
        _ed25519_verify(policy['signers'][role]['public_hex'], record['signature_hex'],
                        DOMAIN + canonical(body))
        verified_roles.add(role)
    if verified_roles != ROLE_SET: raise Reject('SIGNATURE_QUORUM')
    return sha(DOMAIN + canonical(body))


def inspect_snapshot(db: Path) -> dict:
    try:
        with closing(sqlite3.connect('file:' + quote(str(db.resolve(strict=True)), safe='/') + '?mode=ro',
                                     uri=True, timeout=2)) as con:
            con.execute('PRAGMA trusted_schema=OFF')
            rows = con.execute('SELECT record FROM events ORDER BY seq').fetchall()
    except (sqlite3.Error, OSError) as exc:
        raise Reject('SNAPSHOT_READ_FAILED') from exc
    if len(rows) < 4 or len(rows) > 8192: raise Reject('REGISTER_SCOPE_CARDINALITY')
    common = set(); monitor_keys = set(); stages = {'PRIOR_CHECKPOINT':set(),'NEW_CHECKPOINT':set()}
    for row in rows:
        rec = strict_json(row[0], max_bytes=10000)
        common.add((rec.get('system'), rec.get('stream_id'), rec.get('session_id')))
        stage = rec.get('stage')
        if stage not in stages: raise Reject('REGISTER_STAGE')
        stages[stage].add(rec.get('monitor_id'))
        monitor_keys.add(hex64(rec.get('monitor_public_hex'), 'MONITOR_PUBLIC'))
    if (len(common) != 1 or len(stages['PRIOR_CHECKPOINT']) != 2
            or len(stages['NEW_CHECKPOINT']) != 2
            or stages['PRIOR_CHECKPOINT'] != stages['NEW_CHECKPOINT']):
        raise Reject('REGISTER_SCOPE_INCONSISTENT')
    system, stream, session = next(iter(common))
    if system != 'ZENITH': raise Reject('REGISTER_NOT_ZENITH')
    hex64(stream, 'REGISTER_STREAM'); hex64(session, 'REGISTER_SESSION')
    return {'stream_id':stream, 'session_id':session, 'system':'ZENITH',
            'monitor_keys':monitor_keys, 'events':len(rows)}


def snapshot_db(source: Path, destination: Path) -> None:
    # SQLite online-backup snapshot is consistent across concurrent committed changes;
    # V160 rechecks that SAME snapshot, never the changing source DB.
    p = source.absolute()
    for component in (p, *p.parents):
        if component.is_symlink(): raise Reject('REGISTER_SYMLINK')
    try:
        st = p.stat()
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_DB_BYTES:
            raise Reject('REGISTER_FILE_BOUNDS')
        with closing(sqlite3.connect('file:' + quote(str(p),safe='/') + '?mode=ro', uri=True, timeout=3)) as c:
            c.execute('PRAGMA trusted_schema=OFF')
            with closing(sqlite3.connect(str(destination), timeout=3)) as dst:
                c.backup(dst, pages=64, sleep=0.01)
        if destination.stat().st_size > MAX_DB_BYTES:
            raise Reject('SNAPSHOT_TOO_LARGE')
    except (OSError, sqlite3.Error) as exc:
        raise Reject('REGISTER_SNAPSHOT_FAILED') from exc


def expected_binding(handoff: dict, audited: dict, scope: dict, policy: dict, trust_sha: str,
                     nonce_sha: str) -> dict:
    hex64(nonce_sha, 'NONCE')
    source = handoff['handoff']
    if (source['repository'] != REPO or source['source_schema'] != 'zenith-evidence-v1'
            or source['local_verifier_result'] != 'PASS'
            or source['handoff_authentication'] != 'UNSIGNED_NOT_A_V160_CHECKPOINT'
            or source['productionAuthority'] != 'NONE'):
        raise Reject('UNSIGNED_HANDOFF_SCOPE')
    if (audited['result'] != 'LOCAL_HASH_CHAIN_VALID_EXTERNAL_RETENTION_UNVERIFIED'
            or audited['productionAuthority'] != 'NONE'
            or audited['v160_kit_sha256'] != source['v160_kit_sha256']):
        raise Reject('REGISTER_AUDIT_NOT_VALID')
    if scope['system'] != 'ZENITH' or any(scope[x] != policy[x] for x in ('stream_id','session_id')):
        raise Reject('TRUST_REGISTER_SCOPE_MISMATCH')
    if policy['repository'] != source['repository']:
        raise Reject('TRUST_REPOSITORY')
    return {
        'schema':SCHEMA, 'repository':REPO, 'system':'ZENITH',
        'stream_id':scope['stream_id'], 'session_id':scope['session_id'],
        'source_file_sha256':hex64(source['source_file_sha256'],'SOURCE_DIGEST'),
        'source_record_sha256':hex64(source['source_record_sha256'],'RECORD_DIGEST'),
        'source_payload_sha256':hex64(source['source_payload_sha256'],'PAYLOAD_DIGEST'),
        'unsigned_handoff_sha256':hex64(handoff['handoff_sha256'],'HANDOFF_DIGEST'),
        'v160_kit_sha256':hex64(source['v160_kit_sha256'],'KIT_DIGEST'),
        'register_tip_sha256':hex64(audited['tip'],'REGISTER_TIP'),
        'register_genesis_sha256':hex64(audited['genesis'],'REGISTER_GENESIS'),
        'register_events':audited['events'],
        'trust_policy_sha256':trust_sha, 'policy_epoch':policy['policy_epoch'],
        'nonce_sha256':nonce_sha,
        'trust':'PAPER_ONLY', 'productionAuthority':'NONE', 'promotionBlocked':True,
    }


def verify_files(*, evidence: Path, handoff: Path, kit: Path, database: Path,
                 trusted_tip: str, trusted_genesis: str, trust_file: Path, trust_pin: str,
                 statement_file: Path, competitor_file: Path | None=None) -> dict:
    hex64(trusted_tip, 'TIP_PIN'); hex64(trusted_genesis, 'GENESIS_PIN')
    # Import only our repository's existing V160 bridge. The installed executable
    # must be trusted; a valid response does not prove a non-hostile Python runtime.
    from zenith_v160_bridge import audit_v160, verify_handoff
    def load(raw: bytes) -> dict:
        return strict_json(raw[:-1] if raw.endswith(b'\n') else raw)
    # Verify one stable private copy of source and unsigned handoff. Reopening
    # original paths between replay and signature checking creates a TOCTOU gap.
    with tempfile.TemporaryDirectory(prefix='zenith_v161_snapshot_') as td:
        root = Path(td)
        evidence_bytes = read_file(evidence, cap=100_000)
        handoff_bytes = read_file(handoff, cap=4096)
        source_copy = root / 'evidence_copy.json'
        handoff_copy = root / 'handoff_copy.json'
        with source_copy.open('xb') as out: out.write(evidence_bytes)
        with handoff_copy.open('xb') as out: out.write(handoff_bytes)
        verified = verify_handoff(handoff_copy, source_copy)
        if verified['result'] != 'LOCAL_EVIDENCE_AND_UNSIGNED_HANDOFF_MATCH':
            raise Reject('ZENITH_RECORD_NOT_VERIFIED')
        h = load(handoff_bytes)
        policy = load(read_file(trust_file))
        statement = load(read_file(statement_file))
        snap = root / 'register_snapshot.db'
        snapshot_db(database, snap)
        audited = audit_v160(kit, snap, trusted_tip, trusted_genesis)
        # PR #67's bridge returns the verified tip but not the genesis. Its
        # pinned V160 auditor checked the supplied genesis; bind that argument.
        if audited.get('tip') != trusted_tip: raise Reject('AUDIT_TIP_MISMATCH')
        audited['genesis'] = trusted_genesis
        if audited['result'] == 'ABSTAIN_AUTHENTICATED_CONFLICT':
            return {'result':'ABSTAIN_AUTHENTICATED_CONFLICT','productionAuthority':'NONE'}
        scope = inspect_snapshot(snap)
        trust_sha = check_trust(policy, trust_pin, scope['monitor_keys'])
        # NONCE is set by the signing party before signing, no generation by verifier.
        body_obj = statement.get('body')
        if type(body_obj) is not dict: raise Reject('STATEMENT_BODY')
        nonce = hex64(body_obj.get('nonce_sha256'), 'STATEMENT_NONCE')
        expected = expected_binding(h, audited, scope, policy, trust_sha, nonce)
        claim_hash = check_statement(statement, policy, expected)
        if competitor_file is not None:
            competitor = load(read_file(competitor_file))
            # Authenticate competitor before deciding whether there is equivocation.
            other_body = competitor.get('body')
            if type(other_body) is not dict: raise Reject('COMPETITOR_BODY')
            differing = set(other_body) != set(expected) or any(other_body[k] != expected[k] for k in expected)
            # Competitor must differ only in checkpoint tip to be an admissible same-scope fork.
            expected_other = dict(expected)
            expected_other['register_tip_sha256'] = hex64(other_body.get('register_tip_sha256'), 'COMPETITOR_TIP')
            if any(other_body.get(k) != v for k,v in expected_other.items()):
                raise Reject('COMPETITOR_DIFFERENT_SCOPE')
            check_statement(competitor, policy, expected_other)
            if expected_other['register_tip_sha256'] != expected['register_tip_sha256']:
                return {'result':'ABSTAIN_AUTHENTICATED_CONFLICT',
                        'claim_sha256':claim_hash, 'productionAuthority':'NONE'}
            if differing: raise Reject('COMPETITOR_UNEXPECTED_DIFFERENCE')
        return {'result':'CRYPTO_VALID_EXTERNAL_RETENTION_ABSTAIN',
                'claim_sha256':claim_hash,
                'v160_register_tip':audited['tip'], 'events':audited['events'],
                'external_custody':'UNVERIFIED','trusted_chronology':'UNVERIFIED',
                'productionAuthority':'NONE'}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='V161 signed, scoped research-only ZENITH/V160 binding check')
    for flag in ('evidence','handoff','kit','database','trust-file','statement-file'):
        p.add_argument('--'+flag, type=Path, required=True)
    for flag in ('trusted-tip','trusted-genesis','trust-pin'):
        p.add_argument('--'+flag, required=True)
    p.add_argument('--competitor-file', type=Path)
    a = p.parse_args(argv)
    try:
        result = verify_files(**{k.replace('-','_'): v for k,v in vars(a).items()})
        print(json.dumps(result, sort_keys=True, separators=(',',':')))
        return 3 if result['result'].startswith('ABSTAIN_AUTHENTICATED_CONFLICT') else 0
    except (Reject, KeyError, TypeError, ValueError, OSError) as exc:
        print(json.dumps({'result':'REJECT','reason':str(exc)[:120],
                          'productionAuthority':'NONE'}, sort_keys=True))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
