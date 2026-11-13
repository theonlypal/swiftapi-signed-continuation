
import base64
from datetime import datetime,timezone
import time
import uuid
from nacl.signing import SigningKey
from swiftapi_native_service.core import ServiceError,canonical,sha,validate_key
from swiftapi.native_verify import grant_check,UNSIGNED

KEY='swiftapi_live_'+'1'*64
OTHER='swiftapi_live_'+'2'*64
Q='What is 2 + 2?'
def body():
    return {'request_id':str(uuid.uuid4()),'question':Q}
def iso(t):
    return datetime.fromtimestamp(t,timezone.utc).isoformat()
class SigningAuthority:
    evidence_kind='OFFLINE_TEST_AUTHORITY'
    def __init__(self):
        self.key=SigningKey.generate()
        self.public_key=base64.b64encode(bytes(self.key.verify_key)).decode()
        self.revoked=set();self.fail=False;self.recheck_fail=False;self.auth_calls=0
        self.boundary_reject=False
    def issue(self,action,**kwargs):
        now=time.time()
        grant=dict(jti='att_'+uuid.uuid4().hex,action_type=action['scope'],
                   action_fingerprint=sha(canonical(action))[:32],approved=True,
                   issued_at=iso(now-1),expires_at=iso(now+120),actor='OFFLINE_TEST')
        grant.update(kwargs)
        grant['signature']=base64.b64encode(self.key.sign(canonical(grant)).signature).decode()
        grant['signing_mode']='ed25519';grant['action_data']=action
        return grant
    def authenticate(self,key,instance):
        self.auth_calls+=1
        if self.fail:raise ServiceError('AUTHORITY_UNAVAILABLE',503)
        if key not in (KEY,OTHER) or (self.boundary_reject and self.auth_calls%2 == 0):
            raise ServiceError('AUTHENTICATION_REJECTED',401)
        action={'scope':'swiftapi.native_service.connection_check','principal_sha256':validate_key(key),
                'instance_id':instance,'nonce':str(uuid.uuid4())}
        return {'action':action,'grant':self.issue(action),'observed_at':time.time()}
    def authorize(self,key,action):
        return self.issue(action,approved=not action.get('strict_action_type',False))
    def validate(self,grant,action,now=None):
        why=grant_check(grant,action,time.time() if now is None else now,self.public_key)
        if why:raise ServiceError(why,403)
    def recheck(self,key,grant,action):
        if self.recheck_fail:raise ServiceError('REVOCATION_UNAVAILABLE',503)
        if grant['jti'] in self.revoked:raise ServiceError('AUTHORITY_REVOKED',403)

def authorized(service,req=None):
    req=req or body()
    return dict(req,grant=service.authorize(KEY,req)['grant'])
