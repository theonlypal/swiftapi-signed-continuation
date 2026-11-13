
import json
import socket
from pathlib import Path
import pytest
from swiftapi_native_service import mac_ledger as M,experiment as X,core
from swiftapi_native_service.development_authority import DevelopmentAuthority
from test_experiment_protocol import config,WHEEL,SOURCE,HARNESS

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    connect=socket.socket.connect
    def local(sock,address):
        if address[0]!='127.0.0.1':raise AssertionError('External network prohibited')
        return connect(sock,address)
    monkeypatch.setattr(socket.socket,'connect',local)

def capture_record(c,phase='BEFORE',archive=None):
    return {'schema':M.SCHEMA,'phase':phase,'config_sha256':core.sha(core.canonical(c)),
        'capture_host':'Darwin','evidence_kind':'LIVE_SWIFTAPI_READ_ONLY_ADMIN_CAPTURE',
        'authority_public_key':M.SWIFTAPI_PUBLIC_KEY_B64,'started_at':10,'finished_at':11,
        'execution_archive_sha256':archive,'snapshot':{'source':core.AUTHORITY_URL,
        'governance':[],'revocations':[],'limitations':[],'fallback':[],'read_requests':0}}

def test_mac_policy_mandatory_on_fresh_live():
    c=config(authority='LIVE_SWIFTAPI',mode='FRESH_MODEL_EXECUTION')
    with pytest.raises(ValueError):M.validate_policy(c)
    c['ledger_capture_mode']=M.MODE;M.validate_policy(c)
    with pytest.raises(ValueError):M.validate_policy(dict(c,authority='LOCAL_TEST_DOUBLE'))

@pytest.mark.parametrize('change',[{'phase':'AFTER'},{'config_sha256':'0'*64},
    {'authority_public_key':'wrong'},{'capture_host':'Linux'},{'started_at':float('nan')},
    {'execution_archive_sha256':'0'*64},{'extra':'not permitted'}])
def test_before_capture_binds_config_host_phase_and_anchor(change):
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE)
    obj=capture_record(c);obj.update(change)
    with pytest.raises(ValueError):M.validate_capture(obj,c,'BEFORE')

def test_missing_before_rejected_before_approval_or_key(tmp_path,monkeypatch):
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE)
    monkeypatch.setattr(X,'validate_config',lambda *a:None)
    monkeypatch.setattr(X,'consume_approval',lambda *a:pytest.fail('approval reached'))
    monkeypatch.setattr(X,'read_key',lambda *a:pytest.fail('key reached'))
    with pytest.raises(ValueError,match='before snapshot'):
        X.run(c,WHEEL,tmp_path/'out',SOURCE,Path('/no-model'),HARNESS)
    assert not (tmp_path/'out').exists()

@pytest.mark.parametrize('method,path',[('GET','/governance/events'),('GET','/authority/denials'),
    ('GET','/audit'),('POST','/authority/keys'),('POST','/authority/keys/revoke'),('GET','/unlisted')])
def test_restricted_run_rejects_route_before_transport(monkeypatch,method,path):
    import requests
    monkeypatch.setattr(requests.Session,'request',lambda *a,**k:pytest.fail('transport reached'))
    remote=core.RemoteAuthority(restricted_run=True)
    with remote._client('swiftapi_live_'+'f'*64) as api:
        with pytest.raises(core.ServiceError,match='RUN_KEY_ROUTE_FORBIDDEN'):
            api._session.request(method,core.AUTHORITY_URL+path)

@pytest.mark.parametrize('host,approved',[('Linux',True),('Darwin',False),('Darwin',True)])
def test_capture_gate_precedes_key_and_network(tmp_path,monkeypatch,host,approved):
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE)
    monkeypatch.setattr(M.platform,'system',lambda:host)
    monkeypatch.setattr(core,'read_key',lambda *a:pytest.fail('key reached'))
    with pytest.raises(ValueError):
        M.capture(c,'BEFORE',tmp_path/'no-key',tmp_path/'out',predictions_file=None,author_authorized=approved)
    assert not (tmp_path/'out').exists()

def test_capture_after_requires_exact_archive():
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE)
    obj=capture_record(c,'AFTER','a'*64)
    with pytest.raises(ValueError):M.validate_capture(obj,c,'AFTER',archive_sha256='b'*64)

@pytest.fixture
def pending(tmp_path,monkeypatch):
    pass
    base=DevelopmentAuthority()
    monkeypatch.setattr(M,'SWIFTAPI_PUBLIC_KEY_B64',base.public_key)
    class LocalAuthority(DevelopmentAuthority):
        def __init__(self,event_sink=None,restricted_run=False):
            super().__init__();self.event_sink=event_sink
            self.client_key=base.client_key;self._signer=base._signer;self.public_key=base.public_key
            assert restricted_run is True
        def begin_slot(self,arm):pass
        def end_slot(self):pass
    monkeypatch.setattr(core,'RemoteAuthority',LocalAuthority)
    import swiftapi_native_service.authority_ledger as L
    monkeypatch.setattr(L,'snapshot',lambda *a,**k:pytest.fail('Pod attempted ledger snapshot'))
    monkeypatch.setattr(X,'validate_config',lambda *a:None)
    monkeypatch.setattr(X,'require_sealed_predictions',lambda *a:None)
    monkeypatch.setattr(X,'validate_approval',lambda *a:None)
    monkeypatch.setattr(X,'consume_approval',lambda *a:None)
    fake=LocalAuthority(restricted_run=True)
    key=tmp_path/'synthetic.key';key.write_text(fake.client_key);key.chmod(0o600)
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE,schedule=['VALID'])
    before=tmp_path/'before.json';before.write_bytes(core.canonical(capture_record(c)))
    out=tmp_path/'pending'
    report=X.run(c,WHEEL,out,SOURCE,Path('/no-model'),HARNESS,key_file=key,mac_ledger_before=before)
    return c,out,report

def test_pod_path_has_no_admin_snapshot_and_stays_pending(pending):
    c,out,report=pending
    assert report['status']=='EXECUTION_COMPLETE_LEDGER_PENDING'
    assert report['ledger_status']=='PENDING_MAC_AFTER_CAPTURE'
    assert report['ledger_read_requests']==0
    assert (out/'mac-ledger-before.json').is_file()
    assert not (out/'authority-ledger-reconciliation.json').exists()

def test_offline_join_preserves_original_verifies_receipts_and_retains_findings(pending,tmp_path):
    c,root,summary=pending
    archive=root/'evidence.tar.gz';old=core.sha(archive.read_bytes())
    after=tmp_path/'after.json';after.write_bytes(core.canonical(capture_record(c,'AFTER',old)))
    result=M.finalize(archive,after,tmp_path/'joined')
    assert core.sha(archive.read_bytes())==old
    assert result['receipt_count']==summary['verified_receipt_count']
    assert result['status']=='JOINED_WITH_FINDINGS'
    data,_=M.read_archive(tmp_path/'joined/evidence.tar.gz')
    assert M.verify_join(data,c,summary)['status']=='JOINED_WITH_FINDINGS'
    assert not any('.private-runtime' in name for name in data)
    with pytest.raises(FileExistsError):M.finalize(archive,after,tmp_path/'joined')
    rec=json.loads(data['mac-ledger-finalization.json']);rec['status']='JOINED_WITH_API_LIMITATIONS'
    data['mac-ledger-finalization.json']=core.canonical(rec)
    with pytest.raises(ValueError):M.verify_join(data,c,summary)

def test_authority_clock_bracket_does_not_compare_host_wall_clocks():
    c=config();before=capture_record(c);after=capture_record(c,'AFTER','a'*64)
    before['snapshot']['governance']=[{'clock':{'available':True,'server_epoch_seconds':100}}]
    after['snapshot']['governance']=[{'clock':{'available':True,'server_epoch_seconds':200}}]
    after['started_at']=-999
    data={'authority-dispatches/1.json':core.canonical({'stage':'RESPONSE','clock':{
        'available':True,'server_epoch_seconds':150}})}
    assert M.clock_bracket(before,after,data)['status']=='BRACKETED'
    after['snapshot']['governance'][0]['clock']['server_epoch_seconds']=120
    assert M.clock_bracket(before,after,data)['status']=='FINDING_CLOCK_ORDER'

def test_capture_module_has_no_fixed_prediction_file_dependency():
    source=Path(M.__file__).read_text()
    assert 'AUTHOR_PREDICTIONS.md' not in source

def test_before_snapshot_signature_flag_is_not_trusted():
    c=config();obj=capture_record(c)
    obj['snapshot']['revocations']=[{'signature_verified':True,'payload':{},'signature':'bad'}]
    with pytest.raises(Exception):M.validate_capture(obj,c,'BEFORE')

def test_before_capture_uses_only_explicit_host_time_boundary(tmp_path):
    c=config(authority='LIVE_SWIFTAPI',ledger_capture_mode=M.MODE)
    obj=capture_record(c)
    path=tmp_path/'before.json';path.write_bytes(core.canonical(obj))
    assert M.read_before(path,c)[1]==obj
    assert M.read_before(path,c,now=11)[1]==obj
    with pytest.raises(ValueError,match='supplied time boundary'):
        M.read_before(path,c,now=10)

def test_join_requires_pending_archive_for_recomputed_source_binding(pending,tmp_path):
    c,root,summary=pending
    archive=root/'evidence.tar.gz';digest=core.sha(archive.read_bytes())
    after=tmp_path/'after.json';after.write_bytes(core.canonical(capture_record(c,'AFTER',digest)))
    M.finalize(archive,after,tmp_path/'joined')
    data,_=M.read_archive(tmp_path/'joined/evidence.tar.gz')
    assert M.verify_join(data,c,summary,archive)['source_archive_binding']=='VERIFIED_WITH_PENDING_ARCHIVE'
    assert M.verify_join(data,c,summary)['source_archive_binding']=='HASH_DECLARED_PENDING_ARCHIVE_REQUIRED_FOR_RECOMPUTATION'
    extra=dict(data);extra['unbound.txt']=b'not an authorized join member'
    with pytest.raises(ValueError,match='member set'):
        M.verify_join(extra,c,summary,archive)
    changed=json.loads(data['mac-ledger-finalization.json'])
    changed['source_execution_archive_sha256']='0'*64
    data['mac-ledger-finalization.json']=core.canonical(changed)
    with pytest.raises(ValueError,match='Pending execution archive hash mismatch'):
        M.verify_join(data,c,summary,archive)
