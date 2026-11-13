
import base64
from pathlib import Path
import socket
import subprocess
import sys
import pytest
from swiftapi.native_verify import verify_receipt as light,read_json
from swiftapi_native_service import verify as full
from swiftapi_native_service.core import canonical
from swiftapi_native_service.service import NativeService
from swiftapi_native_service.backend import PCCG2Backend,REPLAY
from native_fixtures import SigningAuthority,KEY,body,authorized
ROOT=Path(__file__).resolve().parents[1]
HARNESS=ROOT.parent/'swiftapi-native-eos-receipts'
@pytest.fixture(scope='module')
def backend():
    return PCCG2Backend(HARNESS/'.cache/pccg2',Path('/no-weights'),HARNESS,REPLAY)
@pytest.fixture
def captured(tmp_path,backend):
    service=NativeService(backend,tmp_path,SigningAuthority())
    row=service.generate(KEY,dict(body(),grant=None))
    assert row['payload']['status']=='COMPLETED'
    return service,tmp_path/'evidence'/row['payload']['execution_id']/'receipt.json'
def test_full_and_light_no_network(captured,backend,monkeypatch):
    service,path=captured
    def blocked(*a,**k):raise AssertionError('Network forbidden')
    monkeypatch.setattr(socket,'socket',blocked)
    report=full.verify_receipt(path,service.signer.public,REPLAY,backend,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
    assert report['numerical_replay']=='PASS' and report['class']=='V0'
def test_light_import_never_loads_torch():
    code="import sys; import swiftapi.native_verify; assert 'torch' not in sys.modules and 'transformers' not in sys.modules"
    assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0

@pytest.mark.parametrize('center',[-2.7571136951446533,4.069106101989746])
@pytest.mark.parametrize('direction',[-1,1])
def test_gate_scalar_inclusive_absolute_boundary(center,direction):
    import math
    tolerance = full.GATE_STATE_ABSOLUTE_TOLERANCE
    assert tolerance == 4.76837158203125e-7
    edge = center + direction*tolerance
    inward = math.nextafter(edge,center)
    outward = math.nextafter(edge,math.copysign(math.inf,direction))
    assert full.gate_state_comparison(edge,center)['absolute_difference'] == tolerance
    assert full.gate_state_comparison(inward,center)['absolute_difference'] < tolerance
    with pytest.raises(ValueError,match='Gate state absolute tolerance'):
        full.gate_state_comparison(outward,center)

@pytest.mark.parametrize('value',[True,None,'4',float('nan'),float('inf'),-float('inf')])
def test_gate_scalar_requires_finite_numbers(value):
    with pytest.raises(ValueError,match='Finite gate state'):
        full.gate_state_comparison(value,4.0)
    with pytest.raises(ValueError,match='Finite gate state'):
        full.gate_state_comparison(4.0,value)

@pytest.mark.parametrize('value',[-8,-1,0,1,8])
def test_gate_scalar_pinned_magnitude(value):
    with pytest.raises(ValueError,match='Pinned gate state magnitude'):
        full.gate_state_comparison(value,value)

def test_gate_scalar_tolerance_preserves_exact_vector_check(captured,backend):
    service,path=captured
    row=read_json(path)['payload']
    row['result']['steps'][0]['permission_state'] += full.GATE_STATE_ABSOLUTE_TOLERANCE
    path.write_bytes(canonical(service.signer.sign(row)))
    report=full.verify_receipt(path,service.signer.public,REPLAY,backend,
        authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
    assert report['gate_state_comparison']['absolute_difference']==full.GATE_STATE_ABSOLUTE_TOLERANCE
    vector=path.parent/'0-selected.bf16.bin'
    import torch
    from swiftapi.native_verify import digest
    raw=bytearray(vector.read_bytes());values=torch.frombuffer(raw,dtype=torch.bfloat16)
    values[151645]+=1
    vector.write_bytes(raw)
    step=row['result']['steps'][0]
    step['selected_vector_sha256']=digest(raw)
    row['vector_files']['0-selected.bf16.bin']=digest(raw)
    step['intervened_eos_logit']=step['selected_logit']=float(values[151645])
    path.write_bytes(canonical(service.signer.sign(row)))
    assert light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,
                 expected_max_grant_age_seconds=60)['status']=='PASS'
    with pytest.raises(ValueError,match='Numerical boundary replay'):
        full.verify_receipt(path,service.signer.public,REPLAY,backend,
            authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
@pytest.mark.parametrize('change',['mode','class','classifier','token','answer','condition','authority','source','finish','scope','prompt','input_ids','grant','score','non_eos','causal_label'])
def test_resigned_tampering_is_rejected(captured,backend,change):
    service,path=captured;r=read_json(path)['payload'];v=r['result']
    if change=='mode':r['mode']='FRESH_MODEL_EXECUTION'
    elif change=='class':r['taxonomy']['class']='R'
    elif change=='classifier':r['taxonomy']['classifier_sha256']='0'*64
    elif change=='token':v['generated_token_ids']=[19]
    elif change=='answer':v['output_bytes']=1
    elif change=='condition':v['gate_condition']='EQ(485487,485487)'
    elif change=='authority':r['authentication']['grant']['approved']=False
    elif change=='source':r['source']['sha256']='0'*64
    elif change=='finish':v['finish']='TOKEN_CAP'
    elif change=='scope':v['answer_scope']='FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER'
    elif change=='prompt':r['action']['rendered_prompt_sha256']='0'*64
    elif change=='input_ids':v['input_ids']=[1]
    elif change=='grant':r['grant']={}
    elif change=='score':v['steps'][0]['intervened_eos_logit']=1
    elif change=='non_eos':v['steps'][0]['non_eos_sha256']='0'*64
    elif change=='causal_label':v['stop_cause']='VETO';r['stop_cause']='VETO'
    path.write_bytes(canonical(service.signer.sign(r)))
    with pytest.raises(Exception):
        full.verify_receipt(path,service.signer.public,REPLAY,backend,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
@pytest.mark.parametrize('asset',['request.json','prompt.utf8.bin','input-token-ids.json','grant.json','output.bin','0-stock.bf16.bin','0-selected.bf16.bin'])
def test_asset_tampering(captured,asset):
    service,path=captured;p=path.parent/asset;p.write_bytes(p.read_bytes()+b'x')
    with pytest.raises(Exception):light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
def test_wrong_trust_anchor(captured):
    service,path=captured
    with pytest.raises(Exception):light(path,base64.b64encode(bytes(32)).decode(),REPLAY,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
def test_replay_cannot_verify_as_fresh(captured):
    service,path=captured
    with pytest.raises(Exception):light(path,service.signer.public,'FRESH_MODEL_EXECUTION',authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)

def test_receipt_declared_sdk_version_not_a_verification_gate(captured):
    service,path=captured
    row=read_json(path)['payload'];row['sdk']['version']='1.4.1'
    path.write_bytes(canonical(service.signer.sign(row)))
    result=light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,expected_max_grant_age_seconds=60)
    assert result['sdk_version_declared']=='1.4.1' and result['class']=='V0'

def test_released_classifier_survives_nonsemantic_source_edit(captured,monkeypatch):
    from swiftapi import native_taxonomy
    service,path=captured
    declared=read_json(path)['payload']['taxonomy']['classifier_sha256']
    
    monkeypatch.setattr(native_taxonomy,'classifier_hash',lambda:'f'*64)
    result=light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,
                 expected_max_grant_age_seconds=60)
    assert result['classifier_sha256_declared']==declared
    assert result['classifier_first_sdk_version']=='1.4.0'

def test_signed_runtime_cannot_choose_unregistered_age(captured):
    from swiftapi.native_verify import digest,encoded
    service,path=captured
    r=read_json(path)['payload']
    r['action']['profile']['max_grant_age_seconds']=90
    r['action_sha256']=digest(encoded(r['action']))
    
    path.write_bytes(canonical(service.signer.sign(r)))
    with pytest.raises(ValueError,match='Registered grant age mismatch'):
        light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,
              expected_max_grant_age_seconds=60)
    accepted=light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,
                   expected_max_grant_age_seconds=90)
    assert accepted['expected_max_grant_age_seconds']==90

def test_expected_age_is_mandatory(captured):
    service,path=captured
    with pytest.raises(TypeError,match='expected_max_grant_age_seconds'):
        light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key)

@pytest.mark.parametrize('value',[True,False,0,-1,3601,float('inf'),float('nan'),'60',None])
def test_expected_age_must_be_finite_positive_number(captured,value):
    service,path=captured
    with pytest.raises(ValueError,match='Expected registered grant age required'):
        light(path,service.signer.public,REPLAY,authority_key=service.authority.public_key,
              expected_max_grant_age_seconds=value)
