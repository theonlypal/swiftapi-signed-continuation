
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from nacl.signing import SigningKey, VerifyKey
from swiftapi import SwiftAPI
from swiftapi.verifier import verify_signature, SWIFTAPI_PUBLIC_KEY_B64

SCOPE = "pccg2.native_decode"
AUTHORITY_URL = "https://swiftapi.ai"
MAX_GRANT_AGE = 60
KEY_PATTERN = re.compile(r"swiftapi_live_[0-9a-f]{64}\Z")
CONDITION_PATTERN = re.compile(r"EQ\(([1-9][0-9]{5}),([1-9][0-9]{5})\)\Z")


class ServiceError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def http_clock_observation(date_header, dispatched_at, received_at):
    pass
    from email.utils import parsedate_to_datetime
    try:
        remote=parsedate_to_datetime(date_header).timestamp()
    except (TypeError,ValueError,AttributeError,OverflowError):
        return {'available':False,'reason':'Missing or invalid HTTP Date'}
    return {'available':True,'http_date':date_header,'server_epoch_seconds':remote,
            'host_dispatch_at':dispatched_at,'host_receive_at':received_at,
            'server_minus_host_midpoint_seconds':remote-(dispatched_at+received_at)/2,
            'uncertainty_seconds':(received_at-dispatched_at)/2+1,
            'basis':'HTTP Date second resolution; network half-roundtrip plus one second; not an NTP measurement'}


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ServiceError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def invalid(_):
        raise ServiceError("NONFINITE_JSON")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ServiceError("INVALID_JSON") from exc


def validate_key(key):
    if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
        raise ServiceError("AUTHENTICATION_REQUIRED", 401)
    return sha(b"swiftapi-native-principal-v2\0" + key.encode("ascii"))


def public_principal_identity(key):
    """Public digests identify a key without storing its secret bytes."""
    principal = validate_key(key)
    return {"principal_sha256": principal,
            "principal_derivation": "SHA256(ASCII(swiftapi-native-principal-v2) || 0x00 || ASCII(key))",
            "operator_key_sha256": sha(key.encode("ascii")),
            "operator_derivation": "SHA256(ASCII(key))",
            "binding_evidence": "RUNTIME_SIGNED_KEY_DIGEST_MAPPING"}


def read_key(path):
    
    key = Path(path).read_text(encoding="ascii").strip()
    validate_key(key)
    return key


def condition_truth(condition):
    if not isinstance(condition, str):
        raise ServiceError("INVALID_CONDITION")
    match = CONDITION_PATTERN.fullmatch(condition)
    if not match:
        raise ServiceError("INVALID_CONDITION")
    return match[1] == match[2]


def validate_request(request, questions):
    if not isinstance(request, dict) or set(request) != {"request_id", "question"}:
        raise ServiceError("INVALID_REQUEST_FIELDS")
    try:
        if str(uuid.UUID(request["request_id"])) != request["request_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ServiceError("INVALID_REQUEST_ID") from None
    if not isinstance(request["question"], str) or request["question"] not in questions:
        raise ServiceError("QUESTION_OUTSIDE_PINNED_BANK")
    return strict_json(canonical(request))


def timestamp(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except (ValueError, AttributeError, TypeError):
        raise ServiceError("INVALID_GRANT_TIME", 403) from None


def check_grant(grant, action, now=None, verifier=verify_signature):
    now = time.time() if now is None else now
    if not isinstance(grant, dict) or grant.get("signing_mode") != "ed25519":
        raise ServiceError("INVALID_AUTHORITY_SIGNATURE", 403)
    try:
        verifier(grant, ignore_expiry=True)
    except Exception:
        raise ServiceError("INVALID_AUTHORITY_SIGNATURE", 403) from None
    if grant.get("action_type") != action["scope"] or grant.get("action_fingerprint") != sha(canonical(action))[:32]:
        raise ServiceError("GRANT_BINDING_MISMATCH", 403)
    if "action_data" in grant and grant["action_data"] != action:
        raise ServiceError("GRANT_ACTION_ECHO_MISMATCH", 403)
    if grant.get("approved") is not True:
        raise ServiceError("AUTHORITY_DENIED", 403)
    issued, expires = timestamp(grant.get("issued_at")), timestamp(grant.get("expires_at"))
    if issued > now + 5:
        raise ServiceError("GRANT_FUTURE", 403)
    age_limit = action.get('profile', {}).get('max_grant_age_seconds', MAX_GRANT_AGE)
    if type(age_limit) not in (int, float) or not 0 < age_limit <= 3600:
        raise ServiceError('INVALID_GRANT_AGE_PROFILE', 500)
    if now - issued > age_limit or expires <= now or expires <= issued:
        raise ServiceError("GRANT_EXPIRED", 403)
    if not isinstance(grant.get("jti"), str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", grant["jti"]):
        raise ServiceError("INVALID_GRANT_ID", 403)


class RemoteAuthority:
    pass
    public_key = SWIFTAPI_PUBLIC_KEY_B64
    evidence_kind = "LIVE_SWIFTAPI_AUTHORITY"

    def __init__(self, event_sink=None, restricted_run=False):
        self.event_sink = event_sink
        self.restricted_run = restricted_run
        from .pacing import AuthorityPacer
        self.pacer = AuthorityPacer(self._emit)

    def _emit(self,event):
        if self.event_sink is not None:self.event_sink(event)

    def begin_slot(self,arm):self.pacer.begin_slot(arm)

    def end_slot(self):self.pacer.end_slot()

    def _client(self, key):
        client = SwiftAPI(key=key, base_url=AUTHORITY_URL, timeout=15)
        client._session.trust_env = False
        original = client._session.request
        def observed(method, url, **kwargs):
            
            
            with self.pacer.lock:
                from urllib.parse import urlsplit
                target=urlsplit(url);anchor=urlsplit(AUTHORITY_URL);path=target.path
                if self.restricted_run and not (target.scheme==anchor.scheme and target.netloc==anchor.netloc
                    and not target.fragment and not target.query and (
                    method.upper()=='POST' and path in ('/attest','/attestation/revoke') or
                    method.upper()=='GET' and (path=='/attestation/revocations' or
                        re.fullmatch(r'/attestation/revoked/[A-Za-z0-9_-]{1,128}',path))
                )):
                    raise ServiceError('RUN_KEY_ROUTE_FORBIDDEN',403)
                if method.upper()=='POST' and urlsplit(url).path=='/attestation/revoke':
                    self.pacer.assert_revoke_capacity()
                tier,standalone=self.pacer.before_dispatch(method,urlsplit(url).path)
                event = {'method':method,'path':urlsplit(url).path,'dispatched_at':time.time()}
                self._emit(dict(event,stage='DISPATCH'))
                try:
                    response = original(method, url, **kwargs)
                except Exception as exc:
                    if standalone:self.pacer.end_slot()
                    self._emit(dict(event,stage='TRANSPORT_ERROR',exception_type=type(exc).__name__))
                    raise
                event.update(status=response.status_code,completed_at=time.time(),stage='RESPONSE')
                event['rate_limit']=self.pacer.observe(tier,response.headers,response.status_code)
                if standalone:self.pacer.end_slot()
                event['clock']=http_clock_observation(response.headers.get('Date'),event['dispatched_at'],event['completed_at'])
                try:
                    body = response.json()
                    if isinstance(body,dict):
                        event['attestation'] = {k:body[k] for k in
                            ('jti','approved','issued_at','expires_at','action_type','action_fingerprint') if k in body}
                except ValueError:
                    pass
                self._emit(event)
                return response
        client._session.request = observed
        return client

    def authenticate(self, key, instance):
        action = {"scope": "swiftapi.native_service.connection_check",
                  "nonce": str(uuid.uuid4()), "principal_sha256": validate_key(key),
                  "instance_id": instance}
        grant = self.authorize(key, action)
        return {"action": action, "grant": grant, "observed_at": time.time(),
                "identity_basis": "Approved signed connection-check grant"}

    def validate(self, grant, action, now=None):
        check_grant(grant, action, now=now)

    def authorize(self, key, action):
        validate_key(key)
        try:
            with self._client(key) as client:
                grant = client.attest(action_type=action["scope"], action_data=action)
                check_grant(grant, action)
                if client.check_revocation(grant["jti"]):
                    raise ServiceError("AUTHORITY_REVOKED", 403)
                return grant
        except ServiceError:
            raise
        except Exception as exc:
            from swiftapi.exceptions import AuthenticationError, PolicyViolation, RateLimitError
            if isinstance(exc, RateLimitError):
                raise ServiceError('AUTHORITY_RATE_LIMITED',429) from None
            if isinstance(exc, AuthenticationError):
                raise ServiceError("AUTHENTICATION_REJECTED", 401) from None
            if isinstance(exc, PolicyViolation):
                denial = getattr(exc, 'response', None)
                if isinstance(denial, dict) and denial.get('approved') is False:
                    
                    
                    try:
                        verify_signature(denial, ignore_expiry=True)
                        if (denial.get('action_type') == action['scope']
                                and denial.get('action_fingerprint') == sha(canonical(action))[:32]
                                and denial.get('action_data', action) == action):
                            return denial
                    except Exception:
                        raise ServiceError('INVALID_AUTHORITY_SIGNATURE', 503) from None
                raise ServiceError("AUTHORITY_DENIED", 403) from None
            
            raise ServiceError("AUTHORITY_UNAVAILABLE", 503) from None

    def recheck(self, key, grant, action):
        check_grant(grant, action)
        try:
            with self._client(key) as client:
                if client.check_revocation(grant["jti"]):
                    evidence = self.revocation_evidence(client, grant['jti'])
                    revoked=ServiceError("AUTHORITY_REVOKED",403)
                    revoked.revocation_evidence=evidence
                    raise revoked
        except ServiceError:
            raise
        except Exception as exc:
            from swiftapi.exceptions import RateLimitError
            if isinstance(exc, RateLimitError):
                raise ServiceError('AUTHORITY_RATE_LIMITED',429) from None
            raise ServiceError("REVOCATION_UNAVAILABLE", 503) from None

    def revocation_evidence(self, client, jti):
        pass
        from swiftapi.native_verify import verify_revocation_entry
        from swiftapi.exceptions import RateLimitError
        cursor=0
        try:
            for _ in range(20):
                page=client._request('GET','/attestation/revocations',params={'since':cursor,'limit':1000})
                for entry in page.get('revocations',[]):
                    if entry.get('jti')==jti:
                        try:
                            verify_revocation_entry(entry,jti,self.public_key)
                        except Exception:
                            return {'authority_signed':False,'reason':'FEED_ENTRY_SIGNATURE_NOT_VERIFIED'}
                        return {'authority_signed':True,'entry':entry,'reason':'VERIFIED_SIGNED_FEED_ENTRY'}
                new_cursor=page.get('next_cursor',cursor)
                if not page.get('has_more') or new_cursor<=cursor:break
                cursor=new_cursor
            return {'authority_signed':False,'reason':'JTI_NOT_IN_AVAILABLE_FEED'}
        except RateLimitError:
            raise ServiceError('AUTHORITY_RATE_LIMITED',429) from None
        except Exception as exc:
            return {'authority_signed':False,'reason':'FEED_UNAVAILABLE','exception_type':type(exc).__name__}


def private_mkdir(path):
    pass
    path = Path(path)
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ServiceError("INVALID_RUNTIME_DIRECTORY", 500)
        return
    private_mkdir(path.parent)
    path.mkdir(mode=0o700, exist_ok=True)


def private_write(path, raw):
    path = Path(path)
    private_mkdir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class RuntimeSigner:
    def __init__(self, directory, seed=None):
        self.directory = Path(directory)
        private_mkdir(self.directory)
        os.chmod(self.directory, 0o700)
        secret = self.directory / "runtime-signing.seed"
        if seed is not None:
            if type(seed) is not bytes or len(seed)!=32 or secret.exists():
                raise ServiceError('RUNTIME_SEED_INPUT',500)
            self.key=SigningKey(seed)
        elif secret.exists():
            if secret.stat().st_mode & 0o077:
                raise ServiceError("RUNTIME_KEY_PERMISSIONS", 500)
            self.key = SigningKey(secret.read_bytes())
        else:
            self.key = SigningKey.generate()
            private_write(secret, bytes(self.key))
        self.public = base64.b64encode(bytes(self.key.verify_key)).decode()
        self.instance = sha(bytes(self.key.verify_key))
        public_path = self.directory / "runtime-public.json"
        public_doc = {"schema": "swiftapi-runtime-trust/1", "public_key": self.public,
                      "issuer": "LOCAL_RUNTIME", "instance_id": self.instance,
                      "hardware_attested": False}
        if public_path.exists():
            if strict_json(public_path.read_bytes()) != public_doc:
                raise ServiceError("RUNTIME_PUBLIC_KEY_MISMATCH", 500)
        else:
            private_write(public_path, canonical(public_doc) + b"\n")

    def sign(self, payload):
        signature = self.key.sign(canonical(payload)).signature
        return {"payload": payload, "signature": base64.b64encode(signature).decode(),
                "signer": "LOCAL_RUNTIME", "algorithm": "ed25519"}


class Ledger:
    def __init__(self, path):
        self.path = Path(path)
        private_mkdir(self.path.parent)
        with self.connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS requests (principal TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, status TEXT NOT NULL, jti TEXT UNIQUE, receipt TEXT, PRIMARY KEY(principal, request_id))")
            conn.execute("CREATE TABLE IF NOT EXISTS used_grants (jti TEXT PRIMARY KEY, request_hash TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS attempts (execution_id TEXT PRIMARY KEY, status TEXT NOT NULL, receipt TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS limits (name TEXT PRIMARY KEY, used INTEGER NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO limits VALUES('anonymous_receipts',0)")
        os.chmod(self.path, 0o600)

    def connection(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def reserve_anonymous(self, limit=64):
        with self.connection() as conn:
            row = conn.execute("UPDATE limits SET used=used+1 WHERE name='anonymous_receipts' AND used<?", (limit,))
            return row.rowcount == 1

    def claim(self, principal, request_id, request_hash, jti):
        try:
            with self.connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO requests VALUES(?,?,?,?,?,NULL)",
                             (principal, request_id, request_hash, "UNKNOWN", jti))
                conn.execute("INSERT INTO used_grants VALUES(?,?)", (jti, request_hash))
        except sqlite3.IntegrityError:
            raise ServiceError("REPLAYED_REQUEST_OR_GRANT", 409) from None

    def claim_boundary_grant(self, jti, request_hash):
        try:
            with self.connection() as conn:
                conn.execute("INSERT INTO used_grants VALUES(?,?)", (jti, request_hash))
        except sqlite3.IntegrityError:
            raise ServiceError("REPLAYED_BOUNDARY_GRANT", 409) from None

    def finish(self, principal, request_id, receipt):
        with self.connection() as conn:
            cursor = conn.execute("UPDATE requests SET status=?,receipt=? WHERE principal=? AND request_id=? AND status='UNKNOWN'",
                                 (receipt["payload"]["status"], canonical(receipt).decode(), principal, request_id))
            if cursor.rowcount != 1:
                raise ServiceError("LEDGER_FINALIZATION_FAILED", 500)

    def begin_attempt(self, execution_id):
        with self.connection() as conn:
            conn.execute("INSERT INTO attempts VALUES(?, 'UNKNOWN', NULL)", (execution_id,))

    def reserve_request(self, principal, request_id, action_hash):
        try:
            with self.connection() as conn:
                conn.execute("INSERT INTO requests VALUES(?,?,?,?,NULL,NULL)",
                             (principal, request_id, action_hash, "UNKNOWN"))
            return True
        except sqlite3.IntegrityError:
            return False

    def finish_attempt(self, execution_id, receipt):
        with self.connection() as conn:
            row = conn.execute("UPDATE attempts SET status=?, receipt=? WHERE execution_id=? AND receipt IS NULL",
                               (receipt["payload"]["status"], canonical(receipt).decode(), execution_id))
            if row.rowcount != 1:
                raise ServiceError("ATTEMPT_FINALIZATION_FAILED", 500)


def verify_envelope(envelope, trusted_public_key):
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature", "signer", "algorithm"}:
        raise ValueError("Invalid receipt envelope")
    if envelope["signer"] != "LOCAL_RUNTIME" or envelope["algorithm"] != "ed25519":
        raise ValueError("Wrong runtime signer")
    VerifyKey(base64.b64decode(trusted_public_key, validate=True)).verify(
        canonical(envelope["payload"]), base64.b64decode(envelope["signature"], validate=True))
    return envelope["payload"]
