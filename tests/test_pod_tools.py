
import importlib.util
import json
import io
import tarfile
from pathlib import Path
import pytest
from prediction_fixtures import prediction_bytes

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('smoke_tools',ROOT/'tools/runpod_smoke.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

def test_synthetic_linux_descriptor_has_private_mode_and_complete_seals(monkeypatch):
    spec=importlib.util.spec_from_file_location('memory_selftest',ROOT/'tools/runtime_input_selftest.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    events=[]
    monkeypatch.setattr(module.os,'MFD_CLOEXEC',1,raising=False)
    monkeypatch.setattr(module.os,'MFD_ALLOW_SEALING',2,raising=False)
    monkeypatch.setattr(module.os,'memfd_create',lambda name,flags:events.append(('create',name,flags)) or 8,raising=False)
    monkeypatch.setattr(module.os,'fchmod',lambda fd,mode:events.append(('mode',fd,mode)))
    monkeypatch.setattr(module.os,'write',lambda fd,raw:events.append(('write',fd,len(raw))) or len(raw))
    for name,value in {'F_SEAL_WRITE':8,'F_SEAL_GROW':4,'F_SEAL_SHRINK':2,'F_SEAL_SEAL':1,'F_ADD_SEALS':1033}.items():
        monkeypatch.setattr(module.fcntl,name,value,raising=False)
    monkeypatch.setattr(module.fcntl,'fcntl',lambda *args:events.append(('seal',*args)))
    assert module.sealed_descriptor('synthetic',b'x'*32)==8
    assert events==[('create','synthetic',3),('mode',8,0o600),('write',8,32),('seal',8,1033,15)]

class FakeAPI:
    calls=[];price=.59;created=False;deleted=False;ambiguous=False;availability='HIGH'
    def __init__(self,key):self.key=key
    def call(self,method,path,**kwargs):
        type(self).calls.append((method,path,kwargs))
        if path.startswith('/catalog/'):
            row={'id':P.GPU,'price':{'secure':self.price},'availability':self.availability,
                'manufacturer':'NVIDIA',
                'secure':True,'memory':24,'minRam':125,
                'dataCenters':[{'id':P.DATA_CENTERS[0],'availability':self.availability}]}
            return {'gpus':[row]} if path=='/catalog/gpus' else row
        if method=='POST' and path=='/pods':
            type(self).created=True;type(self).name=kwargs['json']['name']
            if self.ambiguous:raise RuntimeError('Simulated transport error after allocation')
            return {'id':'test-only-pod','name':self.name,'status':'RUNNING','cost':.59,'gpu':{'id':P.GPU}}
        if path=='/pods':
            return {'pods':[{'id':'test-only-pod','name':self.name}]} if self.created and not self.deleted else {'pods':[]}
        if path=='/pods/test-only-pod':
            if method=='DELETE':type(self).deleted=True;return None
            if self.deleted:raise P.APIError(404)
            return {'id':'test-only-pod','name':self.name,'status':'RUNNING','cost':.59,'gpu':{'id':P.GPU}}
        if path=='/billing/pods':return {'metadata':{'totals':{'totalAmount':.01}},'records':[]}
        raise AssertionError((method,path))
    def execute(self,pod,argv,timeout=20):raise RuntimeError('Simulated setup error')

@pytest.fixture
def world(tmp_path,monkeypatch):
    monkeypatch.setattr(P,'ROOT',tmp_path);monkeypatch.setattr(P,'RunPod',FakeAPI)
    monkeypatch.setattr(P,'DEFAULT_CLAIM',tmp_path/'private-state/allocation.json')
    monkeypatch.setattr(P,'watchdog',lambda *a:12345);monkeypatch.setattr(P.time,'sleep',lambda seconds:None)
    FakeAPI.calls=[];FakeAPI.price=.59;FakeAPI.created=False;FakeAPI.deleted=False;FakeAPI.ambiguous=False;FakeAPI.availability='HIGH'
    bundle=tmp_path/'bundle';bundle.mkdir()
    predictions=prediction_bytes(optional=False)
    from swiftapi_native_service.predictions import parse_predictions,select_for_run
    from swiftapi_native_service.experiment import MODEL
    selected=select_for_run(parse_predictions(predictions,MODEL),'WITNESS_ONE',['VALID','SIGNED_DENIAL'])[1]
    config={'purpose':'DEVELOPMENT_SMOKE','authority':'LOCAL_TEST_DOUBLE','mode':'FRESH_MODEL_EXECUTION',
        'author_predictions_sha256':P.sha(predictions),'predictions_sealed_at':'2026-01-01T00:00:00+00:00',
        'population':'WITNESS_ONE','schedule':['VALID','SIGNED_DENIAL'],'repetitions':1,'predictions':selected,
        'gpu_type_id':P.GPU,'data_center_ids':P.DATA_CENTERS}
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name,data in [('smoke-config.json',json.dumps(config).encode()),('author-predictions.md',predictions)]:
            member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
    raw=buffer.getvalue()
    (bundle/'smoke-bundle.tar.gz').write_bytes(raw)
    (bundle/'author-predictions.md').write_bytes(predictions)
    (bundle/'bundle.json').write_text(json.dumps({'sha256':P.sha(raw),'image':P.IMAGE,
        'config':config}))
    key=tmp_path/'test-key';key.write_text('rpa_SYNTHETIC_NOT_A_CREDENTIAL')
    return bundle,key,tmp_path

def test_error_destroys_exact_created_pod_once_and_preserves_record(world):
    bundle,key,tmp=world;out=tmp/'attempt'
    assert P.run(bundle,out,key)==2
    result=json.loads((out/'outcome.json').read_bytes())
    assert result['status']=='FAIL' and result['destroy_confirmed'] is True
    assert [(m,p) for m,p,k in FakeAPI.calls if m=='POST']==[('POST','/pods')]
    assert [(m,p) for m,p,k in FakeAPI.calls if m=='DELETE']==[('DELETE','/pods/test-only-pod')]
    calls=len(FakeAPI.calls)
    with pytest.raises(FileExistsError):P.run(bundle,tmp/'different-parent'/'second',key)
    assert not any(m=='POST' for m,p,k in FakeAPI.calls[calls:])

def test_catalog_over_price_never_creates_pod(world):
    bundle,key,tmp=world;FakeAPI.price=4.39
    with pytest.raises(ValueError,match='price bound'):P.run(bundle,tmp/'attempt',key)
    assert not any(m in ('POST','DELETE') for m,p,k in FakeAPI.calls)

@pytest.mark.parametrize('field,value',[('secure',False),('memory',16),('minRam',16),('dataCenters',[])])
def test_catalog_preflight_precedes_allocation_claim(world,monkeypatch,field,value):
    bundle,key,tmp=world
    original=FakeAPI.call
    def altered(self,method,path,**kwargs):
        response=original(self,method,path,**kwargs)
        if path.startswith('/catalog/') and path!='/catalog/gpus':response[field]=value
        return response
    monkeypatch.setattr(FakeAPI,'call',altered)
    with pytest.raises(ValueError,match='memory/location'):P.run(bundle,tmp/'capacity-check',key)
    assert not P.DEFAULT_CLAIM.exists()
    assert not any(m in ('POST','DELETE') for m,p,k in FakeAPI.calls)

@pytest.mark.parametrize('availability',['NONE',None,'UNKNOWN'])
def test_unavailable_gpu_does_not_consume_allocation(world,availability):
    bundle,key,tmp=world;FakeAPI.availability=availability
    out=tmp/'capacity-check'
    assert P.run(bundle,out,key)==2
    row=json.loads((out/'outcome.json').read_bytes())
    assert row['status']=='NOT_EXECUTED' and row['allocation_requests']==0
    assert not P.DEFAULT_CLAIM.exists()
    assert not any(m in ('POST','DELETE') for m,p,k in FakeAPI.calls)

def test_ambiguous_create_resolves_unique_name_and_destroys_without_create_retry(world):
    bundle,key,tmp=world;FakeAPI.ambiguous=True
    assert P.run(bundle,tmp/'attempt',key)==2
    assert FakeAPI.deleted
    assert sum(m=='POST' for m,p,k in FakeAPI.calls)==1

def test_public_pod_metadata_excludes_credentials():
    row=P.safe_pod({'id':'x','env':{'SECRET':'private'},'ssh':'private','registry':'private'})
    assert 'env' not in row and 'private' not in json.dumps(row)

def test_same_selection_inventory_is_recent_and_query_bound(monkeypatch):
    monkeypatch.setattr(P.time,'monotonic',lambda:100.)
    query={'count':1}
    snapshot={'queried_at_monotonic':99.,'query':query,'body':{'gpus':[]}}
    class Forbidden:
        def call(self,*args,**kwargs):pytest.fail('Same catalog selection is reused without a second inventory request')
    assert P.current_inventory(Forbidden(),query,snapshot)=={'gpus':[]}
    for changed in ({'queried_at_monotonic':69.},{'queried_at_monotonic':101.},
                    {'queried_at_monotonic':float('nan')},{'query':{'count':2}}):
        with pytest.raises(ValueError,match='same selection'):
            P.current_inventory(Forbidden(),query,dict(snapshot,**changed))

def test_current_wrapper_binds_cheapest_selection_and_reuses_paced_connection(tmp_path,monkeypatch):
    import sys
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    import run_current_smoke as current
    driver=current.driver
    row={'id':'NVIDIA qualifying fixture','manufacturer':'NVIDIA','secure':True,
         'memory':48,'minRam':50,'availability':'LOW','price':{'secure':.59},
         'dataCenters':[{'id':'fixture-dc','availability':'LOW'}]}
    class SelectionAPI:
        def __init__(self,key,event_sink=None):self.key=key;self.calls=[]
        def call(self,method,path,**kwargs):
            self.calls.append((method,path,kwargs));return {'gpus':[row]}
    monkeypatch.setattr(driver,'ROOT',tmp_path)
    monkeypatch.setattr(driver,'DEFAULT_CLAIM',tmp_path/'private-state/allocation.json')
    monkeypatch.setattr(driver,'key_from_existing',lambda path:'SYNTHETIC_CREDENTIAL')
    monkeypatch.setattr(driver,'RunPod',SelectionAPI)
    monkeypatch.setattr(driver,'GPU','NVIDIA fixture initial')
    monkeypatch.setattr(driver,'DATA_CENTERS',['initial'])
    monkeypatch.setattr(current.bundle,'GPU','NVIDIA fixture initial')
    monkeypatch.setattr(current.bundle,'DATA_CENTERS',['initial'])
    built=[]
    def build(out,*args,**kwargs):
        Path(out).mkdir();built.append((driver.GPU,current.bundle.GPU,kwargs))
    monkeypatch.setattr(current.bundle,'build',build)
    def run(bundle_dir,out,key_file,*,inventory_snapshot,api_connection):
        assert api_connection.calls[0][:2]==('GET','/catalog/gpus')
        assert len(api_connection.calls)==1
        assert driver.GPU==current.bundle.GPU==row['id']
        assert driver.DATA_CENTERS==current.bundle.DATA_CENTERS==['fixture-dc']
        assert inventory_snapshot['body']=={'gpus':[row]}
        assert built[0][2]['author_confirmed_sealed'] is True
        return 0
    monkeypatch.setattr(driver,'run',run)
    monkeypatch.setattr(sys,'argv',['run_current_smoke.py','--out',str(tmp_path/'run'),
        '--bundle-out',str(tmp_path/'bundle'),'--wheel','sdk.whl','--service-wheel','service.whl',
        '--predictions','predictions.md','--predictions-sealed-at','2026-01-01T00:00:00Z',
        '--runpod-key-file','existing-key-file','--execute-one-approved-development-smoke'])
    assert current.main()==0

def test_pod_name_resolution_follows_all_pages():
    class Listing:
        calls=[]
        def call(self,method,path,**kwargs):
            self.calls.append(kwargs['params'])
            if 'cursor' not in kwargs['params']:
                return {'pods':[{'id':'not-target','name':'other'}],
                        'pagination':{'hasNextPage':True,'nextCursor':'opaque-two'}}
            return {'pods':[{'id':'target-id','name':'target-name'}],
                    'pagination':{'hasNextPage':False,'nextCursor':None}}
    api=Listing()
    assert P.pod_ids_named(api,'target-name')==['target-id']
    assert api.calls==[{'limit':1000},{'limit':1000,'cursor':'opaque-two'}]

def test_cheapest_gpu_selection_requires_secure_memory_and_capacity():
    valid={'id':'valid','manufacturer':'NVIDIA','secure':True,'memory':24,'minRam':32,
           'availability':'LOW','price':{'secure':.5},'dataCenters':[{'id':'dc','availability':'LOW'}]}
    rows=[valid,dict(valid,id='cheaper',price={'secure':.4}),
          dict(valid,id='no-capacity',availability='NONE',price={'secure':.1}),
          dict(valid,id='too-small',memory=16,price={'secure':.1}),
          dict(valid,id='community',secure=False,price={'secure':.1})]
    assert [p['id'] for p in P.qualifying_gpus({'gpus':rows})]==['cheaper','valid']

@pytest.mark.parametrize('field',['author_predictions_sha256','predictions_sealed_at'])
def test_unsealed_smoke_never_reads_key_creates_output_or_calls_provider(world,monkeypatch,field):
    bundle,key,tmp=world
    path=bundle/'bundle.json';meta=json.loads(path.read_bytes());meta['config'].pop(field)
    path.write_text(json.dumps(meta))
    monkeypatch.setattr(P,'key_from_existing',lambda *a:pytest.fail('Orchestration key must not be read'))
    with pytest.raises(ValueError,match='Sealed author predictions'):
        P.run(bundle,tmp/'attempt',key)
    assert not (tmp/'attempt').exists() and not FakeAPI.calls

def test_outer_seal_cannot_disguise_unsealed_bundled_configuration(world,monkeypatch):
    bundle,key,tmp=world
    path=bundle/'bundle.json';meta=json.loads(path.read_bytes())
    meta['config']['predictions_sealed_at']='2026-02-01T00:00:00+00:00'
    path.write_text(json.dumps(meta))
    monkeypatch.setattr(P,'key_from_existing',lambda *a:pytest.fail('No key read on a bundle mismatch'))
    with pytest.raises(ValueError,match='configurations differ'):P.run(bundle,tmp/'attempt',key)
    assert not FakeAPI.calls

def test_outer_bundle_equality_preserves_json_number_types(world,monkeypatch):
    bundle,key,tmp=world
    path=bundle/'bundle.json';meta=json.loads(path.read_bytes())
    meta['config']['repetitions']=1.0
    path.write_text(json.dumps(meta))
    monkeypatch.setattr(P,'key_from_existing',lambda *a:pytest.fail('No key read on a bundle mismatch'))
    with pytest.raises(ValueError,match='configurations differ'):P.run(bundle,tmp/'attempt',key)
    assert not FakeAPI.calls

def test_exec_readiness_waits_only_on_explicit_not_started(tmp_path,monkeypatch):
    clock=[100.0];monkeypatch.setattr(P.time,'time',lambda:clock[0])
    monkeypatch.setattr(P.time,'sleep',lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    class Starting:
        calls=0
        def execute(self,*a):
            self.calls+=1
            if self.calls==1:raise P.APIError(409,'2')
            if self.calls==2:raise P.APIError(503,'3')
            return '{"python":"fixture","ensurepip":"fixture"}'
    api=Starting()
    assert P.wait_exec_ready(api,'fixture',120,tmp_path)['python']=='fixture'
    assert api.calls==3 and clock[0]==106
    assert len(json.loads((tmp_path/'exec-readiness.json').read_text())['waits'])==2

@pytest.mark.parametrize('status',[400,401,403,422])
def test_exec_permanent_error_is_not_polled(tmp_path,status):
    class Failed:
        calls=0
        def execute(self,*a):self.calls+=1;raise P.APIError(status,'1')
    api=Failed()
    with pytest.raises(P.APIError):P.wait_exec_ready(api,'fixture',P.time.time()+30,tmp_path)
    assert api.calls==1

@pytest.mark.parametrize('header',[None,'','unparseable','NaN','-1'])
def test_readiness_poll_does_not_require_retry_header(tmp_path,monkeypatch,header):
    clock=[100.];monkeypatch.setattr(P.time,'time',lambda:clock[0])
    monkeypatch.setattr(P.time,'sleep',lambda delay:clock.__setitem__(0,clock[0]+delay))
    class Ready:
        calls=0
        def execute(self,*args):
            self.calls+=1
            if self.calls<=2:raise P.APIError(404 if self.calls==1 else 409,header)
            return '{"python":"3.12"}'
    api=Ready()
    assert P.wait_exec_ready(api,'pod',120,tmp_path)=={'python':'3.12'}
    assert api.calls==3 and clock[0]==106

def test_transient_poll_has_a_finite_deadline(monkeypatch):
    clock=[0.];monkeypatch.setattr(P.time,'time',lambda:clock[0])
    monkeypatch.setattr(P.time,'sleep',lambda delay:clock.__setitem__(0,clock[0]+delay))
    calls=[]
    def unavailable():calls.append(clock[0]);raise P.APIError(503)
    with pytest.raises(TimeoutError):P.poll(unavailable,9)
    assert clock[0]==9 and calls==[0,2,6]

def test_upload_is_idempotent_after_ambiguous_chunk_completion(tmp_path,monkeypatch):
    import subprocess,sys
    monkeypatch.setattr(P.time,'sleep',lambda seconds:None)
    data=b'x'*340000;archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w') as tar:
        info=tarfile.TarInfo('payload.bin');info.size=len(data);tar.addfile(info,io.BytesIO(data))
    class Remote:
        seen=set()
        def execute(self,pod,argv):
            args=[sys.executable,*argv[1:]];args[2]=args[2].replace('/workspace/',str(tmp_path)+'/')
            result=subprocess.check_output(args,text=True)
            identity=tuple(argv)
            if identity not in self.seen:
                self.seen.add(identity);raise P.TransportError('Ambiguous response')
            return result
    assert P.upload(Remote(),'pod',archive.getvalue(),P.time.time()+60).strip()=='BUNDLE_VERIFIED'
    assert (tmp_path/'native-smoke-bundle.tar.gz').read_bytes()==archive.getvalue()
    assert (tmp_path/'native-smoke/payload.bin').read_bytes()==data

def test_bounded_authorization_includes_all_allocations(tmp_path):
    auth=tmp_path/'approval.json'
    auth.write_text(json.dumps({'purpose':'DEVELOPMENT_SMOKE','cap_usd':2,
        'maximum_total_attempts':3,'prior_attempts':1,'prior_spend_reserved_usd':.05}))
    first=tmp_path/'attempt-two';first.mkdir()
    assert P.reserve_attempt(auth,first,.88)['attempt']==2
    with pytest.raises(ValueError,match='destruction'):P.reserve_attempt(auth,tmp_path/'blocked',.88)
    (first/'parent-destroy-confirmed.json').write_text('{"gone":true}')
    second=tmp_path/'attempt-three';second.mkdir()
    assert P.reserve_attempt(auth,second,.88)['combined_reserved_usd']==pytest.approx(1.81)
    (second/'parent-destroy-confirmed.json').write_text('{"gone":true}')
    with pytest.raises(ValueError,match='exhausted'):P.reserve_attempt(auth,tmp_path/'four',.01)

def test_spend_reservation_refuses_over_cap_before_allocation(tmp_path):
    auth=tmp_path/'approval.json'
    auth.write_text(json.dumps({'purpose':'DEVELOPMENT_SMOKE','cap_usd':2,
        'maximum_total_attempts':3,'prior_attempts':1,'prior_spend_reserved_usd':1.5}))
    with pytest.raises(ValueError,match='exhausted'):P.reserve_attempt(auth,tmp_path/'pod',.88)

def test_three_additional_allocations_share_original_cap(tmp_path):
    auth=tmp_path/'approval.json'
    auth.write_text(json.dumps({'purpose':'DEVELOPMENT_SMOKE','cap_usd':2,
        'maximum_total_attempts':6,'prior_attempts':3,'prior_spend_reserved_usd':.25}))
    reserved=(P.MAX_COMPUTE_PER_HOUR+60*.10/720)*(P.DEADLINE_SECONDS+120)/3600+.05
    assert .25+3*reserved<2
    for number in (4,5,6):
        folder=tmp_path/str(number);folder.mkdir()
        row=P.reserve_attempt(auth,folder,reserved)
        assert row['attempt']==number and row['combined_reserved_usd']<2
        (folder/'parent-destroy-confirmed.json').write_text('{"gone":true}')
    with pytest.raises(ValueError,match='exhausted'):
        P.reserve_attempt(auth,tmp_path/'seven',.01)

def test_model_download_transient_waits_preserve_pins(tmp_path,monkeypatch):
    import requests
    spec=importlib.util.spec_from_file_location('fetch_test',ROOT/'tools/fetch_pinned_model.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    clock=[0.];monkeypatch.setattr(module.time,'time',lambda:clock[0])
    monkeypatch.setattr(module.time,'sleep',lambda delay:clock.__setitem__(0,clock[0]+delay))
    calls=[]
    def fetch(**kwargs):
        calls.append(kwargs)
        if len(calls)==1:raise requests.ConnectionError('Transient fixture')
    module.download(tmp_path,[{'file':'model.safetensors'}],10,fetch=fetch)
    assert len(calls)==2 and calls[0]==calls[1]
    assert calls[0]['revision']==module.REV and calls[0]['token'] is False
    def invalid(**kwargs):raise ValueError('Pinned mismatch')
    with pytest.raises(ValueError,match='Pinned mismatch'):module.download(tmp_path,[],10,fetch=invalid)

def test_pod_stage_deadline_records_before_cleanup(tmp_path,monkeypatch):
    import subprocess
    spec=importlib.util.spec_from_file_location('pod_entry_test',ROOT/'tools/pod_entry.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    monkeypatch.setattr(module,'OUT',tmp_path);monkeypatch.setattr(module,'DEADLINE',module.time.time()+30)
    def timeout(args,**kwargs):
        assert 0<kwargs['timeout']<=30
        raise subprocess.TimeoutExpired(args,kwargs['timeout'])
    monkeypatch.setattr(module.subprocess,'run',timeout)
    with pytest.raises(TimeoutError):module.command(['fixture'],'load')
    assert json.loads((tmp_path/'load.command.json').read_text())['status']=='DEADLINE'

def test_ambiguous_launch_observes_pid_without_workload_retry(monkeypatch):
    monkeypatch.setattr(P.time,'sleep',lambda seconds:None)
    class Remote:
        launches=0;observations=0
        def execute(self,pod,args):
            if 'subprocess.Popen' in args[2]:
                self.launches+=1;raise P.TransportError('Lost response')
            self.observations+=1
            return 'PENDING' if self.observations==1 else '1234'
    api=Remote()
    assert P.launch_once(api,'pod',P.time.time()+900)==1234
    assert api.launches==1 and api.observations==2

def test_positive_allocation_refusal_does_not_strand_allowance(tmp_path):
    auth=tmp_path/'approval.json'
    auth.write_text(json.dumps({'purpose':'DEVELOPMENT_SMOKE','cap_usd':2,
        'maximum_total_attempts':3,'prior_attempts':1,'prior_spend_reserved_usd':.05}))
    first=tmp_path/'refused';first.mkdir();P.reserve_attempt(auth,first,.8)
    (first/'creation-no-pod-observed.json').write_text('{"definitive_refusal":false}')
    with pytest.raises(ValueError,match='destruction'):P.reserve_attempt(auth,tmp_path/'uncertain',.8)
    (first/'creation-no-pod-observed.json').write_text('{"definitive_refusal":true}')
    assert P.reserve_attempt(auth,tmp_path/'next',.8)['attempt']==3

def test_pod_environment_uses_pinned_http_download_without_optional_accelerator():
    import os,subprocess,sys
    spec=importlib.util.spec_from_file_location('pod_env_test',ROOT/'tools/pod_entry.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    env=module.locked_environment(dict(os.environ,HF_HUB_ENABLE_HF_TRANSFER='1',HF_HUB_OFFLINE='1',
        HF_TOKEN='SYNTHETIC',RUNPOD_API_KEY='SYNTHETIC',HF_ENDPOINT='https://invalid.example'))
    assert env['HF_HUB_ENABLE_HF_TRANSFER']=='0' and env['HF_HUB_DISABLE_XET']=='1'
    assert env['HF_HUB_OFFLINE']=='0' and env['HF_ENDPOINT']=='https://huggingface.co'
    assert 'HF_TOKEN' not in env and 'RUNPOD_API_KEY' not in env
    result=subprocess.check_output([sys.executable,'-c',
        'from huggingface_hub import constants as c;assert not c.HF_HUB_ENABLE_HF_TRANSFER;assert not c.HF_HUB_OFFLINE;assert c.HF_HUB_DISABLE_XET;print("PASS")'],env=env,text=True)
    assert result.strip()=='PASS'

def test_provider_low_quota_paces_before_next_dispatch(monkeypatch):
    clock=[100.0];monkeypatch.setattr(P.time,'time',lambda:clock[0])
    monkeypatch.setattr(P.time,'sleep',lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    class Response:
        status_code=200;content=b'{}';headers={'RateLimit':'"default";r=4;t=10'}
        def json(self):return {}
    api=P.RunPod('SYNTHETIC_CREDENTIAL');observed=[]
    api.transport.request=lambda *a,**k:(observed.append(clock[0]) or Response())
    api.call('GET','/catalog/gpus');api.call('GET','/catalog/gpus')
    assert observed==[100.0,111.0]
