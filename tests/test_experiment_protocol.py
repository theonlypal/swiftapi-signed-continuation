
import json
from pathlib import Path
import uuid
import pytest
from swiftapi_native_service import experiment as X
from swiftapi_native_service import backend as B
from swiftapi_native_service.service import source_identity
from swiftapi_native_service.core import sha, canonical, ServiceError
from swiftapi.native_taxonomy import classifier_hash

ROOT=Path(__file__).resolve().parents[1]
HARNESS=ROOT.parent/'swiftapi-native-eos-receipts'
SOURCE=HARNESS/'.cache/pccg2'
WHEEL=ROOT/'packages/swiftapi_python-1.4.0-py3-none-any.whl'

def config(**updates):
    row={'schema':'swiftapi-native-experiment-config/2','purpose':'DEVELOPMENT_QUALIFICATION',
         'sdk_version':'1.4.0','sdk_wheel_sha256':sha(WHEEL.read_bytes()),
         'service_source_sha256':source_identity()['sha256'],'classifier_sha256':classifier_hash(),
         'population':'WITNESS_ONE','schedule':['VALID','MISSING_GRANT'],'repetitions':1,
         'max_grant_age_seconds':60,'max_new_tokens':4,'authority':'LOCAL_TEST_DOUBLE',
         'mode':B.REPLAY,'device':'cpu'}
    row.update(updates);return row

def test_bank_schedule_and_authority_count():
    c=config(population='BANK_188');X.validate_config(c,WHEEL)
    bank=json.loads((SOURCE/'evidence/bank.json').read_bytes())
    if isinstance(bank,dict):bank=bank['questions']
    assert len(bank)==188
    slots=X.planned_slots(c,[r['question'] for r in bank])
    assert len(slots)==376 and [s['slot'] for s in slots]==list(range(376))
    for i in range(188):
        assert [s['arm'] for s in slots[i*2:i*2+2]]==['VALID','MISSING_GRANT']
        assert slots[i*2]['question']==slots[i*2+1]['question']==bank[i]['question']
    plan=X.authority_load_plan(dict(c,authority='LIVE_SWIFTAPI'),188)
    assert plan['planned_attest_dispatches']==1128
    assert plan['planned_http_dispatches_excluding_ledger_and_revocation_feed']==2444
    assert plan['snapshot_reads_minimum']==6

def test_study_surprise_preserved_and_remaining_arm_runs(tmp_path,monkeypatch):
    c=config(purpose='PREREGISTERED_STUDY',author_freeze_approved=True,
             public_registration_timestamp='TEST_FIXTURE_NOT_A_REAL_REGISTRATION',
             registration_sha256='0'*64,author_predictions_sha256='1'*64,
             predictions={'VALID':{'class':'V0'},'MISSING_GRANT':{'class':'V0'}})
    monkeypatch.setattr(X,'APPROVAL_REGISTRY',tmp_path/'registry')
    approval=tmp_path/'approval.json'
    approval.write_bytes(canonical({'approval_id':str(uuid.uuid4()),'config_sha256':sha(canonical(c)),
        'purpose':c['purpose'],'author_approved':True,'maximum_attempts':1}))
    out=tmp_path/'fixture';report=X.run(c,WHEEL,out,SOURCE,Path('/no-model'),HARNESS,approval_file=approval)
    assert report['sequence_completed'] and report['status']=='FAIL'
    assert report['verified_receipt_count']==2 and report['prediction_matches']==1
    assert [r['class'] for r in report['rows']]==['R','V0']
    assert all(r['receipt_integrity']=='PASS' for r in report['rows'])
    assert all(s['status']=='OBSERVED' for s in report['slots'])

def test_development_surprise_stops_with_unexecuted_denominator(tmp_path,monkeypatch):
    monkeypatch.setattr(X,'prediction_for',lambda c,a:{'class':'V0'})
    out=tmp_path/'fixture'
    with pytest.raises(RuntimeError,match='development acceptance'):
        X.run(config(),WHEEL,out,SOURCE,Path('/no-model'),HARNESS)
    report=json.loads((out/'summary.json').read_bytes())
    assert not report['sequence_completed'] and report['planned_count']==2
    assert report['verified_receipt_count']==1
    assert report['slots'][1]['status']=='NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT'

def test_authority_rate_limit_stops_preserves_receipt_and_remaining_slots(tmp_path,monkeypatch):
    from swiftapi_native_service.development_authority import DevelopmentAuthority
    original=DevelopmentAuthority.recheck
    def limited(self,key,grant,action):raise ServiceError('AUTHORITY_RATE_LIMITED',429)
    monkeypatch.setattr(DevelopmentAuthority,'recheck',limited)
    out=tmp_path/'fixture'
    with pytest.raises(ServiceError,match='AUTHORITY_RATE_LIMITED'):
        X.run(config(),WHEEL,out,SOURCE,Path('/no-model'),HARNESS)
    report=json.loads((out/'summary.json').read_bytes())
    assert report['verified_receipt_count']==1 and report['rows'][0]['class']=='operational'
    assert report['slots'][1]['status']=='NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT'
    assert (out/'error.json').is_file() and (out/'evidence.tar.gz').is_file()

def test_copied_approval_cannot_bypass_registry(tmp_path,monkeypatch):
    monkeypatch.setattr(X,'APPROVAL_REGISTRY',tmp_path/'registry')
    c=config(authority='LIVE_SWIFTAPI')
    a={'approval_id':str(uuid.uuid4()),'config_sha256':sha(canonical(c)),
       'purpose':c['purpose'],'author_approved':True,'maximum_attempts':1}
    first=tmp_path/'one.json';first.write_bytes(canonical(a))
    second=tmp_path/'two.json';second.write_bytes(first.read_bytes())
    X.consume_approval(c,first)
    with pytest.raises(FileExistsError):X.consume_approval(c,second)

@pytest.mark.parametrize('update',[{'schedule':['MISSING_GRANT','VALID']},{'repetitions':2},
                                  {'schedule':['VALID','REVOKED']}])
def test_bank_configuration_is_exact(update):
    with pytest.raises(ValueError):X.validate_config(config(population='BANK_188',**update),WHEEL)

@pytest.mark.parametrize('change',[{'max_new_tokens':1},{'max_new_tokens':True},
    {'attention':'SDPA_MATH'},{'attention':'UNKNOWN'},{'device':'cuda'},
    {'device':'mps'},{'mode':'UNKNOWN'},{'enable_full_model':True},
    {'enable_full_model':1},{'enable_full_model':None},{'pins':{'native_eos':0}},
    {'authority':'LIVE_SWIFTAPI','authority_public_key':'wrong-key'}])
def test_wrong_replay_profile_rejected_before_approval_or_output(tmp_path,monkeypatch,change):
    monkeypatch.setattr(X,'consume_approval',lambda *a:pytest.fail('Approval must not be consumed'))
    out=tmp_path/'never-created'
    with pytest.raises(ValueError):
        X.validate_config(config(**change),WHEEL)
    with pytest.raises(ValueError):
        X.run(config(**change),WHEEL,out,SOURCE,Path('/no-model'),HARNESS)
    assert not out.exists()

@pytest.mark.parametrize('population,count',[('WITNESS_ONE',11),('BANK_188',376)])
def test_initialization_error_keeps_requested_denominator(tmp_path,monkeypatch,population,count):
    def unavailable(*a,**k):raise ValueError('Test-only initialization error')
    monkeypatch.setattr(B,'PCCG2Backend',unavailable)
    c=config(population=population,schedule=list(X.SERVICE_ARMS) if population=='WITNESS_ONE'
             else ['VALID','MISSING_GRANT'],one_disposable_grant_revocation_approved=True)
    out=tmp_path/'initialization-error'
    with pytest.raises(ValueError,match='Test-only'):
        X.run(c,WHEEL,out,SOURCE,Path('/no-model'),HARNESS)
    report=json.loads((out/'summary.json').read_bytes())
    assert report['planned_count']==count and report['verified_receipt_count']==0
    assert report['population_source_verified'] is False and report['authority_dispatches']==0
    assert len(report['slots'])==count
    assert all(s['status']=='NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT' for s in report['slots'])
