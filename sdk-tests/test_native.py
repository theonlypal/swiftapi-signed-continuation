import json
from unittest.mock import Mock
import pytest
from swiftapi import SwiftAPI,PolicyViolation
from swiftapi.native_taxonomy import classify,classification_record,classifier_hash,near_void,INVISIBLE,ELLIPSIS_FORMS
from swiftapi.native import NativeEOSClient

def test_release_registry_pins_packaged_classifier():
    from swiftapi.native_classifier_releases import RELEASED_CLASSIFIER_HASHES
    release=RELEASED_CLASSIFIER_HASHES[classifier_hash()]
    assert release['first_sdk_version']=='1.4.0'
    assert release['rule']=='void-matrix/2dfe895bdafd35d23d6dab5f307ed560214a3843'

def test_native_verifier_requires_external_expected_age_without_loading_model():
    import inspect
    from swiftapi.native_verify import verify_receipt
    parameter=inspect.signature(verify_receipt).parameters['expected_max_grant_age_seconds']
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty

@pytest.mark.parametrize('raw,successful,present,stop,expected',[
    (b'',True,True,'stop','V0'),(b'',True,False,'stop','V2'),
    (b'',True,True,'length','V1'),(b'',True,False,'length','V1'),
    (b'',True,True,None,'VU'),(b'',False,True,'stop','operational'),
    (b' ',True,True,'stop','NV'),(b'?!',True,True,'stop','R'),
    ('…'.encode(),True,True,'stop','NV'),('\u200b'.encode(),True,True,'stop','NV'),
    (b'4',True,True,None,'R'),(b'hello.',True,True,'stop','R')])
def test_taxonomy(raw,successful,present,stop,expected):
    assert classify(raw,successful=successful,container_present=present,stop=stop)==expected
@pytest.mark.parametrize('event',['RF','SB','TC'])
def test_distinct_fields(event):
    assert classify(b'',successful=True,event=event)==event
def test_replay_not_complete():
    r=classification_record(b'4','COMPLETED',{'finish':'REPLAY_ONE_TOKEN_ONLY',
        'answer_scope':'FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER','generation_complete':False,'generated_token_ids':[19]})
    assert r['class']=='R' and not r['fields']['generation_complete']
    assert r['response_scope']=='FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER'
    assert r['classifier_sha256']==classifier_hash()
def test_policy_violation_retains_exact_body_nonbreaking():
    raw=b'{"approved": false, "denial_reason": "test"}'
    response=Mock(status_code=200,content=raw)
    response.json.return_value=json.loads(raw)
    with SwiftAPI('swiftapi_live_test') as api:
        with pytest.raises(PolicyViolation) as caught:api._handle_response(response)
    assert caught.value.response==json.loads(raw)
    assert caught.value.raw_response==raw
    assert caught.value.status_code==200 and caught.value.denial_reason=='test'
@pytest.mark.parametrize('url',['https://other.example','http://localhost:3','http://127.0.0.1:3/?x=key','http://a:b@127.0.0.1:3','http://127.0.0.1:3/x'])
def test_native_client_rejects_key_exfiltration_urls(url):
    with pytest.raises(ValueError):NativeEOSClient(key='swiftapi_live_'+'a'*64,base_url=url)


def frozen_near_void(text):
    if not text:
        return False
    
    frozen_invisible = {0x200B,0x200C,0x200D,0x200E,0x200F,0xFEFF,
        0x2060,0x2061,0x2062,0x2063,0x2064,0x2066,0x2067,0x2068,0x2069,
        0x202A,0x202B,0x202C,0x202D,0x202E}
    if all(ord(character) in frozen_invisible or character.isspace() for character in text):
        return True
    return text.strip() in {'.', '..', '...', '....', '…', '….'}

@pytest.mark.parametrize('text',['',' ','\t\n','\u200b','\u200d','\ufeff',
    '.','..','...','....','.....','. .','…','….','… …','?','!','-','4',' 4 '])
def test_frozen_matrix_equivalence(text):
    assert near_void(text) == frozen_near_void(text)
    if text:
        assert classify(text.encode(),successful=True,stop='stop') == ('NV' if frozen_near_void(text) else 'R')
    else:
        assert classify(b'',successful=True,stop='stop') == 'V0'

def test_receipt_grant_age_is_signed_profile_value():
    from swiftapi.native_verify import grant_check,encoded,digest
    from nacl.signing import SigningKey
    from datetime import datetime,timezone
    import base64
    key=SigningKey.generate()
    action={'scope':'pccg2.native_decode','profile':{'max_grant_age_seconds':90}}
    grant={'action_type':action['scope'],'action_fingerprint':digest(encoded(action))[:32],
           'approved':True,'jti':'test','issued_at':datetime.fromtimestamp(1000,timezone.utc).isoformat(),
           'expires_at':datetime.fromtimestamp(1200,timezone.utc).isoformat()}
    grant['signature']=base64.b64encode(key.sign(encoded(grant)).signature).decode()
    grant['signing_mode']='ed25519'
    public=base64.b64encode(bytes(key.verify_key)).decode()
    assert grant_check(grant,action,1070,public) is None
    assert grant_check(grant,action,1091,public) == 'GRANT_EXPIRED'
