
import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import threading
import time
import uuid
import pytest
import requests
from swiftapi.native_verify import verify_receipt
from swiftapi_native_service.backend import PCCG2Backend,REPLAY
from swiftapi_native_service.core import ServiceError,canonical
from swiftapi_native_service.service import NativeService
from swiftapi_native_service.httpd import LocalServer
from native_fixtures import KEY,OTHER,Q,SigningAuthority,body,authorized,iso
ROOT=Path(__file__).resolve().parents[1]
HARNESS=ROOT.parent/'swiftapi-native-eos-receipts'
SOURCE=HARNESS/'.cache/pccg2'
@pytest.fixture(scope='module')
def backend():
    return PCCG2Backend(SOURCE,Path('/no-model-load'),HARNESS,REPLAY)
@pytest.fixture
def service(backend,tmp_path):
    return NativeService(backend,tmp_path/'runtime',SigningAuthority())
def check(service,receipt):
    path=service.signer.directory/'evidence'/receipt['payload']['execution_id']/'receipt.json'
    return verify_receipt(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
def test_verified_and_missing_permission(service):
    yes=service.generate(KEY,authorized(service)); no=service.generate(KEY,dict(body(),grant=None))
    assert yes['payload']['taxonomy']['class']=='R'
    assert yes['payload']['result']['answer_scope']=='FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER'
    assert no['payload']['taxonomy']['class']=='V0'
    assert no['payload']['grant'] is None
    assert no['payload']['result']['generated_token_ids']==[151645]
    check(service,yes); check(service,no)
@pytest.mark.parametrize('kind',['forged','expired','future','wrong_scope','wrong_request','revoked','signed_denial'])
def test_known_key_invalid_permission_signed_void(service,kind):
    req=body(); action,_=service.action(__import__('swiftapi_native_service.core',fromlist=['validate_key']).validate_key(KEY),req)
    a=service.authority
    if kind=='expired': grant=a.issue(action,issued_at=iso(time.time()-70))
    elif kind=='future': grant=a.issue(action,issued_at=iso(time.time()+60))
    elif kind=='wrong_scope': grant=a.issue(dict(action,scope='other'))
    elif kind=='wrong_request': grant=a.issue(dict(action,request=body()))
    elif kind=='signed_denial': grant=a.issue(action,approved=False)
    else:
        grant=a.issue(action)
        if kind=='forged':grant['signature']=base64.b64encode(bytes(64)).decode()
        if kind=='revoked':a.revoked.add(grant['jti'])
    row=service.generate(KEY,dict(req,grant=grant))
    assert row['payload']['status']=='COMPLETED',row
    assert row['payload']['taxonomy']['class']=='V0'
    assert row['payload']['authority_decision']['denial_authority_signed'] is (kind=='signed_denial')
    check(service,row)
@pytest.mark.parametrize('key',[None,'','bad','swiftapi_live_'+'3'*64])
def test_unknown_or_malformed_key_operational(service,key):
    row=service.generate(key,dict(body(),grant=None))
    assert row['payload']['taxonomy']['class']=='operational'
    assert row['payload']['decoder_executed'] is False
    check(service,row)
def test_repeat_request_returns_signed_v0(service):
    req=authorized(service);first=service.generate(KEY,req);second=service.generate(KEY,req)
    assert first['payload']['taxonomy']['class']=='R'
    assert second['payload']['authority_decision']['reason']=='REPLAYED_REQUEST'
    assert second['payload']['taxonomy']['class']=='V0'
    check(service,second)
def test_concurrent_single_use(service):
    req=authorized(service)
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows=list(pool.map(lambda _:service.generate(KEY,req),range(4)))
    assert [r['payload']['taxonomy']['class'] for r in rows].count('R')==1
    assert [r['payload']['taxonomy']['class'] for r in rows].count('V0')==3
def test_source_change_refuses_before_decoder(service,monkeypatch):
    import swiftapi_native_service.service as S
    monkeypatch.setattr(S,'source_identity',lambda:{})
    row=service.generate(KEY,dict(body(),grant=None))
    assert row['payload']['error_code']=='SOURCE_CHANGED' and not row['payload']['decoder_executed']
def test_revocation_unavailable_is_operational(service):
    req=authorized(service);service.authority.recheck_fail=True
    row=service.generate(KEY,req)
    assert row['payload']['error_code']=='REVOCATION_UNAVAILABLE'
    assert row['payload']['taxonomy']['class']=='operational'
    check(service,row)
def test_authority_unreachable_is_operational(service):
    service.authority.fail=True
    row=service.generate(KEY,dict(body(),grant=None))
    assert row['payload']['error_code']=='AUTHORITY_UNAVAILABLE'
    check(service,row)
def test_anonymous_persistence_bounded_across_restarts(service):
    for _ in range(64):service.reject('AUTHENTICATION_REQUIRED',401)
    with pytest.raises(ServiceError,match='ANONYMOUS_RECEIPT_LIMIT'):service.reject('AUTHENTICATION_REQUIRED',401)
    restarted=NativeService(service.backend,service.signer.directory,service.authority)
    with pytest.raises(ServiceError,match='ANONYMOUS_RECEIPT_LIMIT'):restarted.reject('AUTHENTICATION_REQUIRED',401)
    assert len(list((service.signer.directory/'evidence').iterdir()))==64
def test_slow_scores_expire_presented_grant_at_boundary(service,monkeypatch):
    req=authorized(service)
    original=service.backend.run
    real=time.time
    offset=[0]
    monkeypatch.setattr(time,'time',lambda:real()+offset[0])
    def slow(question,*,decide):
        offset[0]=65
        return original(question,decide=decide)
    monkeypatch.setattr(service.backend,'run',slow)
    row=service.generate(KEY,req)
    p=row['payload']
    assert p['taxonomy']['class']=='V0' and p['authority_decision']['reason']=='GRANT_EXPIRED'
    assert p['times']['scores_ready_at']-p['times']['request_arrival_at']>=65
    assert p['times']['grant_issued_at']==req['grant']['issued_at']
    check(service,row)
def test_raw_request_prompt_ids_output_bind(service):
    req=authorized(service);raw=b' '+canonical(req)+b'\n'
    row=service.generate(KEY,req,raw_request=raw)
    path=service.signer.directory/'evidence'/row['payload']['execution_id']
    assert (path/'request.json').read_bytes()==raw
    assert (path/'output.bin').read_bytes()==b'4'
    assert KEY.encode() not in (path/'receipt.json').read_bytes()
    check(service,row)

def test_public_principal_identifies_operator_key_without_secret(service):
    import hashlib
    from swiftapi_native_service.core import validate_key
    row=service.generate(KEY,authorized(service))
    identity=row['payload']['principal_identity']
    assert identity['principal_sha256']==validate_key(KEY)==row['payload']['action']['principal_sha256']
    assert identity['operator_key_sha256']==hashlib.sha256(KEY.encode('ascii')).hexdigest()
    assert identity['operator_key_sha256']!=identity['principal_sha256']
    assert identity['binding_evidence']=='RUNTIME_SIGNED_KEY_DIGEST_MAPPING'
    assert KEY not in canonical(row).decode()
    check(service,row)
    path=service.signer.directory/'evidence'/row['payload']['execution_id']/'receipt.json'
    row['payload']['principal_identity']['operator_key_sha256']='0'*64
    path.write_bytes(canonical(row))
    from nacl.exceptions import BadSignatureError
    with pytest.raises(BadSignatureError):check(service,row)

def test_unknown_key_has_no_authenticated_public_identity(service):
    row=service.generate('swiftapi_live_'+'3'*64,dict(body(),grant=None))
    assert row['payload']['principal_identity'] is None
def test_caller_condition_rejected(service):
    req=dict(body(),grant=None,condition='EQ(485487,485487)')
    row=service.generate(KEY,req)
    assert row['payload']['error_code']=='INVALID_REQUEST_FIELDS'
    assert not row['payload']['decoder_executed']
def test_installed_sdk_loopback_client(service,tmp_path):
    from swiftapi.native import NativeEOSClient
    server=LocalServer(('127.0.0.1',0),service)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with NativeEOSClient(key=KEY,base_url=f'http://127.0.0.1:{server.server_port}') as client:
            row=client.generate(Q)
        assert row['payload']['taxonomy']['class']=='R'
        check(service,row)
    finally:
        server.shutdown();server.server_close();thread.join()
