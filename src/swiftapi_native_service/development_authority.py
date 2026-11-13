
import base64
from datetime import datetime, timezone
import secrets
import time
import uuid
from nacl.signing import SigningKey
from .core import ServiceError, canonical, sha, check_grant, validate_key
from swiftapi.native_verify import signature, UNSIGNED

class DevelopmentAuthority:
    evidence_kind = 'DEVELOPMENT_TEST_AUTHORITY_NOT_SWIFTAPI_PRODUCTION'

    def __init__(self):
        self._signer = SigningKey.generate()
        self.public_key = base64.b64encode(bytes(self._signer.verify_key)).decode()
        self.client_key = 'swiftapi_live_' + secrets.token_hex(32)
        self.revoked = set()
        self.permission_approved = True

    def _require_key(self, key):
        validate_key(key)
        if key != self.client_key:
            raise ServiceError('AUTHENTICATION_REJECTED',401)

    def _issue(self, action, approved):
        now=time.time()
        grant={'jti':'development_'+uuid.uuid4().hex, 'approved':approved,
               'action_type':action['scope'],'action_fingerprint':sha(canonical(action))[:32],
               'issued_at':datetime.fromtimestamp(now,timezone.utc).isoformat(),
               'expires_at':datetime.fromtimestamp(now+120,timezone.utc).isoformat(),
               'issuer_kind':self.evidence_kind}
        grant['signature']=base64.b64encode(self._signer.sign(canonical(grant)).signature).decode()
        grant.update(signing_mode='ed25519',action_data=action)
        return grant

    def authorize(self,key,action):
        self._require_key(key)
        return self._issue(action, self.permission_approved and not action.get('strict_action_type',False))

    def authenticate(self,key,instance):
        self._require_key(key)
        action={'scope':'swiftapi.native_service.connection_check','instance_id':instance,
                'principal_sha256':validate_key(key),'nonce':uuid.uuid4().hex}
        return {'action':action,'grant':self._issue(action,True),'observed_at':time.time(),
                'identity_basis':self.evidence_kind}

    def validate(self,grant,action,now=None):
        def verify(g,**_):
            signature({k:v for k,v in g.items() if k not in UNSIGNED},g['signature'],self.public_key)
        check_grant(grant,action,now=now,verifier=verify)

    def recheck(self,key,grant,action):
        self._require_key(key)
        self.validate(grant,action)
        if grant['jti'] in self.revoked:
            raise ServiceError('AUTHORITY_REVOKED',403)
