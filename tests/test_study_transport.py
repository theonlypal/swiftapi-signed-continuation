import base64
import importlib.util
import json
from pathlib import Path
import pytest
from nacl.public import PrivateKey,SealedBox
from nacl.signing import SigningKey

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('study_worker',ROOT/'tools/study_worker.py')
W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)

def message():
    key='swiftapi_live_'+'1'*64;seed=bytes(SigningKey.generate())
    private=PrivateKey.generate()
    config={'runtime_public_key':base64.b64encode(bytes(SigningKey(seed).verify_key)).decode(),
            'operator_key_sha256':W.digest(key.encode())}
    body={'key':key,'seed':base64.b64encode(seed).decode(),'nonce':'n',
          'config_sha256':W.digest(W.canonical(config))}
    return key,seed,private,config,body

def test_private_input_is_bound_and_encrypted():
    key,seed,private,config,body=message()
    cipher=SealedBox(private.public_key).encrypt(W.canonical(body))
    assert key.encode() not in cipher and seed not in cipher
    assert W.decode_frame(cipher,private,'n',config)==(key.encode(),seed)

@pytest.mark.parametrize('field',['nonce','config_sha256','key','seed','extra'])
def test_private_input_rejects_wrong_binding(field):
    key,seed,private,config,body=message();body[field]='wrong'
    cipher=SealedBox(private.public_key).encrypt(W.canonical(body))
    with pytest.raises(Exception):W.decode_frame(cipher,private,'n',config)

def tools_module(name):
    import sys
    sys.path.insert(0,str(ROOT/'tools'))
    return __import__(name)

@pytest.mark.parametrize('changes',[{'sequence_completed':False},{'execution_integrity':'INCOMPLETE_OR_FAILED'},
                                  {'verified_receipt_count':10}])
def test_secondary_requires_all_primary_receipts(changes):
    module=tools_module('run_registered')
    row={'sequence_completed':True,'execution_integrity':'COMPLETE','verified_receipt_count':11,
         'author_prediction':{'status':'MISMATCH'}}
    assert module.eligible_primary(row)
    assert not module.eligible_primary(dict(row,**changes))

def test_timestamp_and_archive_resolution_are_explicit():
    module=tools_module('study_inputs')
    template={'registration_doi':'10.5281/zenodo.1','registration_sha256':module.sha(b'registration'),
        'public_registration_timestamp':'PUBLIC_CONTENT_VERIFIED_AT','run_role':'SECONDARY',
        'primary_archive_sha256':'SEALED_PRIMARY_ARCHIVE','predictions':{'VALID':{'class_counts':{'R':188}}}}
    record={'is_published':True,'doi':'10.5281/zenodo.1','created':'2026-01-01T00:00:00Z'}
    verification={'verified':True,'doi':record['doi'],'verified_public_at':'2026-01-02T00:00:00Z'}
    resolved=module.resolve(template,record,b'registration',publication_verification=verification,primary_sha256='a'*64)
    assert resolved['public_registration_timestamp']==verification['verified_public_at']
    assert resolved['primary_archive_sha256']=='a'*64 and resolved['predictions']==template['predictions']
    assert template['primary_archive_sha256']=='SEALED_PRIMARY_ARCHIVE'
    for changed in ({'is_published':False},{'doi':'different'}):
        with pytest.raises(ValueError):module.resolve(template,dict(record,**changed),b'registration',publication_verification=verification,primary_sha256='a'*64)
    for changed in ({'verified':False},{'doi':'different'},{'verified_public_at':'2099-01-01T00:00:00Z'},
                    {'verified_public_at':None},{'verified_public_at':'2026-01-01T00:00:00'}):
        with pytest.raises(ValueError):module.resolve(template,record,b'registration',publication_verification=dict(verification,**changed),primary_sha256='a'*64)
    with pytest.raises(ValueError):module.resolve(template,record,b'changed',publication_verification=verification,primary_sha256='a'*64)

def test_registered_claim_is_shared_across_output_directories(tmp_path,monkeypatch):
    module=tools_module('run_registered');monkeypatch.setattr(module,'CLAIM_ROOT',tmp_path/'claims')
    templates={'PRIMARY':{'x':1},'SECONDARY':{'x':2}}
    module.claim_execution('doi',templates,tmp_path/'one')
    with pytest.raises(FileExistsError):module.claim_execution('doi',templates,tmp_path/'two')

def test_uncertain_private_ack_uses_public_readback_only(monkeypatch):
    module=tools_module('study_remote');calls=[]
    class API:
        def execute(self,pod,argv):
            calls.append(argv)
            raise tools_module('runpod_smoke').TransportError('transport')
    monkeypatch.setattr(module,'read_json',lambda *a,**k:{'config_sha256':'x'})
    result=module.send_private_frame(API(),'pod','PRIMARY',b'encrypted',module.time.time()+5)
    assert result['config_sha256']=='x' and len(calls)==1

def test_partial_export_excludes_private_runtime(tmp_path):
    module=tools_module('study_export');control=tmp_path/'control/PRIMARY';control.mkdir(parents=True)
    folder=tmp_path/'study-evidence/PRIMARY';folder.mkdir(parents=True)
    (folder/'scheduled-slots.json').write_text('[1,2,3]')
    private=folder/'.private-runtime';private.mkdir();(private/'seed').write_bytes(b'private')
    record=module.export(tmp_path,'PRIMARY')
    assert record['sealed_registered_archive'] is False
    import tarfile
    with tarfile.open(record['path']) as archive:
        assert 'population/scheduled-slots.json' in archive.getnames()
        assert not any('.private-runtime' in n or n.endswith('/seed') for n in archive.getnames())

def test_worker_deadline_is_exception_not_an_extra_dispatch():
    with pytest.raises(TimeoutError,match='REGISTERED_RUNTIME_DEADLINE'):
        W.deadline_signal(None,None)

def test_concurrent_partial_exports_publish_only_complete_archive(tmp_path,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import hashlib
    import threading
    module=tools_module('study_export');control=tmp_path/'control/PRIMARY';control.mkdir(parents=True)
    folder=tmp_path/'study-evidence/PRIMARY';folder.mkdir(parents=True)
    (folder/'receipt.json').write_text('{"public":true}')
    entered=threading.Event();release=threading.Event()
    original=module.tarfile.TarFile.add
    def slow_add(archive,*args,**kwargs):
        entered.set();assert release.wait(5)
        return original(archive,*args,**kwargs)
    monkeypatch.setattr(module.tarfile.TarFile,'add',slow_add)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(module.export,tmp_path,'PRIMARY')
        assert entered.wait(5)
        second=pool.submit(module.export,tmp_path,'PRIMARY')
        assert not (control/'partial-export.json').exists()
        assert not (control/'partial.tar.gz').exists()
        release.set();a=first.result(5);b=second.result(5)
    assert a==b==json.loads((control/'partial-export.json').read_bytes())
    raw=Path(a['path']).read_bytes()
    assert len(raw)==a['bytes'] and hashlib.sha256(raw).hexdigest()==a['sha256']

def test_capacity_wait_uses_fixed_gpu_without_writes(monkeypatch):
    module=tools_module('run_registered');clock=[100.];calls=[];events=[]
    monkeypatch.setattr(module.P.time,'time',lambda:clock[0])
    monkeypatch.setattr(module.P.time,'sleep',lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    class API:
        def call(self,method,path,**kwargs):
            calls.append((method,path))
            return {'id':'NVIDIA RTX A5000','secure':True,'memory':24,'minRam':50,'minVcpuCount':9,
                    'price':{'secure':.27},'dataCenters':[{'id':'CA-MTL-1',
                    'availability':'HIGH' if len(calls)==3 else 'NONE'}]}
    result,selection=module.wait_for_capacity(API(),'NVIDIA RTX A5000',120.,events)
    assert result['id']=='NVIDIA RTX A5000' and len(calls)==3
    assert selection['data_center_id']=='CA-MTL-1'
    assert all(method=='GET' and path.endswith('NVIDIA%20RTX%20A5000') for method,path in calls)

def test_capacity_none_with_omitted_fields_waits_to_deadline(monkeypatch):
    module=tools_module('run_registered');clock=[100.];calls=[]
    monkeypatch.setattr(module.P.time,'time',lambda:clock[0])
    monkeypatch.setattr(module.P.time,'sleep',lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    class API:
        def call(self,method,path,**kwargs):
            calls.append(method)
            return json.loads((ROOT/'tests/fixtures/runpod-a5000-none.json').read_bytes())
    with pytest.raises(TimeoutError):module.wait_for_capacity(API(),'NVIDIA RTX A5000',105.,[])
    assert calls and set(calls)=={'GET'} and clock[0]==105.

def test_capacity_location_order_is_deterministic():
    module=tools_module('run_registered')
    catalog={'id':'NVIDIA RTX A5000','secure':True,'memory':24,'minRam':50,'minVcpuCount':9,
        'price':{'secure':.27},'availability':'LOW','dataCenters':[
            {'id':'EU-SE-1','availability':'HIGH'},{'id':'CA-MTL-1','availability':'LOW'},
            {'id':'A','availability':'NONE'}]}
    assert module.capacity_decision(catalog,'NVIDIA RTX A5000')['data_center_id']=='CA-MTL-1'
    catalog['dataCenters'].reverse()
    assert module.capacity_decision(catalog,'NVIDIA RTX A5000')['data_center_id']=='CA-MTL-1'
    for field,value in [('minRam',49),('minVcpuCount',5),('price',{'secure':.81})]:
        assert module.capacity_decision(dict(catalog,**{field:value}),'NVIDIA RTX A5000')['decision']=='WAIT'
    for field,value in [('id','NVIDIA A40'),('secure',False),('memory',16)]:
        with pytest.raises(ValueError):module.capacity_decision(dict(catalog,**{field:value}),'NVIDIA RTX A5000')

@pytest.mark.parametrize('role,purpose,authority,accepted',[
    ('SMOKE','DEVELOPMENT_SMOKE','LOCAL_TEST_DOUBLE',True),
    ('SMOKE','DEVELOPMENT_SMOKE','LIVE_SWIFTAPI',False),
    ('SMOKE','PREREGISTERED_STUDY','LOCAL_TEST_DOUBLE',False),
    ('PRIMARY','PREREGISTERED_STUDY','LIVE_SWIFTAPI',True),
    ('SECONDARY','PREREGISTERED_STUDY','LIVE_SWIFTAPI',True),
    ('PRIMARY','DEVELOPMENT_SMOKE','LOCAL_TEST_DOUBLE',False),
    ('PRIMARY','PREREGISTERED_STUDY','LOCAL_TEST_DOUBLE',False)])
def test_worker_role_is_authority_bound(role,purpose,authority,accepted):
    config={'run_role':role,'purpose':purpose,'authority':authority}
    if accepted:W.validate_role(config,role)
    else:
        with pytest.raises(ValueError):W.validate_role(config,role)

def test_smoke_inputs_carry_only_dummy_key_and_distinct_seed():
    module=tools_module('run_registered')
    primary=json.loads((ROOT/'RUN_CONFIG_PRIMARY.json').read_bytes())
    templates,key,seeds=module.smoke_inputs(primary);config=templates['SMOKE']
    from swiftapi_native_service.experiment import DEVELOPMENT_TRANSPORT_KEY
    assert key==DEVELOPMENT_TRANSPORT_KEY
    assert config['runtime_public_key']!=primary['runtime_public_key']
    assert config['operator_key_sha256']!=primary['operator_key_sha256']
    assert config['purpose']=='DEVELOPMENT_SMOKE' and config['authority']=='LOCAL_TEST_DOUBLE'
    assert config['schedule']==['VALID','SIGNED_DENIAL'] and 'ledger_capture_mode' not in config
    private=PrivateKey.generate()
    channel={'public_key':base64.b64encode(bytes(private.public_key)).decode(),
        'nonce':'n','config_sha256':W.digest(W.canonical(config))}
    cipher=module.encrypted_runtime(channel,config,key,seeds['SMOKE'])
    assert W.decode_frame(cipher,private,'n',config)==(key.encode(),seeds['SMOKE'])

def test_allocation_body_pins_gpu_ram_image_and_selected_center():
    module=tools_module('run_registered')
    primary=json.loads((ROOT/'RUN_CONFIG_PRIMARY.json').read_bytes())
    body=module.allocation_body('example',primary,{'data_center_id':'EU-SE-1','gpu_type_id':'NVIDIA RTX A5000'})
    assert body['gpu']=={'id':'NVIDIA RTX A5000','count':1,'minRamPerGpu':50,
                        'minVcpuCountPerGpu':6,'minCudaVersion':'12.8'}
    assert body['cloud']=='SECURE' and body['dataCenterIds']==['EU-SE-1']
    assert body['image']==primary['image_digest'] and body['ports']==[]

def test_cost_reservation_includes_existing_cost_and_cleanup():
    module=tools_module('run_registered')
    plan=module.budget_plan(True,.75)
    assert plan['combined_reserved_usd']<2 and plan['deadline_seconds']==3600
    with pytest.raises(ValueError):module.budget_plan(True,1.5)
    with pytest.raises(ValueError):module.budget_plan(True,-1)
    assert module.budget_plan(False,0)['combined_reserved_usd']<10

def test_environment_export_contains_host_and_hash_records(tmp_path):
    module=tools_module('study_prepare')
    folder=tmp_path/'environment';folder.mkdir()
    (folder/'host.json').write_text('{"gpu":"NVIDIA RTX A5000"}')
    (folder/'download-and-hash-verify-model.log').write_text('PASS')
    record=module.export_environment(tmp_path,folder)
    import tarfile,hashlib
    path=Path(record['path'])
    assert record['sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
    with tarfile.open(path) as archive:
        assert sorted(archive.getnames())==['download-and-hash-verify-model.log','host.json']

def test_environment_status_exists_when_export_is_unavailable(tmp_path,monkeypatch):
    module=tools_module('study_prepare')
    def unavailable(*args):raise OSError('storage unavailable')
    monkeypatch.setattr(module,'export_environment',unavailable)
    status=module.finish_status(tmp_path,tmp_path,{'ready':True})
    assert status['ready'] is False and status['export_exception_type']=='OSError'
    assert json.loads((tmp_path/'PREPARED.json').read_bytes())==status

@pytest.mark.parametrize('first_available',[True,False])
def test_qualified_gpu_selection_preserves_order_and_filters(first_available):
    module=tools_module('run_registered');calls=[]
    class API:
        def call(self,method,path,**kwargs):
            calls.append((method,path))
            gpu=module.requests.utils.unquote(path.rsplit('/',1)[1])
            if gpu=='NVIDIA RTX A5000' and not first_available:
                return json.loads((ROOT/'tests/fixtures/runpod-a5000-none.json').read_bytes())
            return {'id':gpu,'secure':True,'memory':24,'minRam':62,'minVcpuCount':6,
                'availability':'LOW','price':{'secure':.69},'dataCenters':[
                    {'id':'US-MO-2','availability':'HIGH'},{'id':'EU-RO-1','availability':'LOW'}]}
    catalog,selection=module.inspect_qualified_capacity(API(),module.QUALIFIED_GPUS)
    assert selection['gpu_type_id']==('NVIDIA RTX A5000' if first_available else 'NVIDIA L4')
    assert selection['data_center_id']=='EU-RO-1'
    assert len(calls)==(1 if first_available else 2) and all(m=='GET' for m,p in calls)
    with pytest.raises(ValueError):module.inspect_qualified_capacity(API(),['NVIDIA A40'])

def test_ordered_capacity_deadline_consumes_only_reads(monkeypatch):
    module=tools_module('run_registered');clock=[100.];calls=[]
    monkeypatch.setattr(module.P.time,'time',lambda:clock[0])
    monkeypatch.setattr(module.P.time,'sleep',lambda s:clock.__setitem__(0,clock[0]+s))
    class API:
        def call(self,method,path,**kwargs):
            calls.append(method)
            return {'id':module.requests.utils.unquote(path.rsplit('/',1)[1]),
                    'secure':True,'memory':24,'availability':'NONE'}
    with pytest.raises(TimeoutError):
        module.wait_for_qualified_capacity(API(),module.QUALIFIED_GPUS,105.,[])
    assert set(calls)=={'GET'} and clock[0]==105.

def test_host_device_name_matches_selected_gpu():
    module=tools_module('run_registered')
    host={'nvidia_smi':{'exit_code':0,'stdout':'NVIDIA L4, GPU-example, 595.91.07, 0000:41:00, 23034\n'}}
    selection={'gpu_type_id':'NVIDIA L4','data_center_id':'EU-RO-1'}
    result=module.verify_host_gpu(host,selection)
    assert result['gpu_type_id']=='NVIDIA L4' and result['hardware_attested'] is False
    with pytest.raises(ValueError):module.verify_host_gpu(host,dict(selection,gpu_type_id='NVIDIA RTX A5000'))
    with pytest.raises(ValueError):module.verify_host_gpu({'nvidia_smi':{'exit_code':1}},selection)

def test_development_allocation_requires_source_bound_unused_approval(tmp_path):
    from types import SimpleNamespace
    module=tools_module('run_registered')
    source=tmp_path/'source.tar.gz';source.write_bytes(b'source')
    args=SimpleNamespace(development_approval=None,source_archive=source,prior_cost_upper_usd=.75)
    with pytest.raises(ValueError):module.development_approval(args)
    args.development_approval=tmp_path/'approval.json'
    row={'purpose':'DEVELOPMENT_SMOKE','maximum_allocations':1,'combined_cap_usd':2,
        'source_archive_sha256':module.P.sha(source.read_bytes()),'prior_cost_upper_usd':.75}
    args.development_approval.write_text(json.dumps(row))
    assert module.development_approval(args)==row
    args.development_approval.with_suffix('.consumed').touch()
    with pytest.raises(ValueError):module.development_approval(args)
