"""Single-pod primary and secondary execution with an external authority."""
import argparse
import base64
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import time
import uuid
import requests
import runpod_smoke as P
import study_remote as R
from study_inputs import resolve,encrypted_runtime

ROOT=Path(__file__).resolve().parents[1]
HARNESS_REVISION='64b7bb90b7f8141448292ecad62494b05f1b5aee'
DEADLINE_SECONDS=7200
CAPACITY_DEADLINE_SECONDS=900
CLAIM_ROOT=Path.home()/'.local/state/swiftapi-native/registered-runs'

def read_private(path):
    path=Path(path);info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:raise ValueError('Private regular file required')
    return path.read_bytes()

def eligible_primary(summary):
    return (summary.get('sequence_completed') is True and summary.get('execution_integrity')=='COMPLETE'
            and summary.get('verified_receipt_count')==11)

def claim_execution(doi,templates,out):
    from swiftapi_native_service.core import canonical
    identity=P.sha(canonical({'doi':doi,'configurations':templates}))
    CLAIM_ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    record={'doi':doi,'configuration_identity':identity,'output':str(out.resolve()),'claimed_at':P.now()}
    P.save(CLAIM_ROOT/(identity+'.json'),record)
    return record

DATA_CENTER_RULE='LEXICOGRAPHIC_SECURE_CAPACITY'
GPU_RULE='ORDERED_QUALIFIED_SECURE_CAPACITY'
QUALIFIED_GPUS=['NVIDIA RTX A5000','NVIDIA L4']

def capacity_decision(catalog,gpu):
    if catalog.get('id')!=gpu or catalog.get('secure') is not True or catalog.get('memory',0)<24:
        raise ValueError('Qualified GPU identity or memory mismatch')
    if catalog.get('availability')=='NONE':
        return {'decision':'WAIT','reason':'NO_CAPACITY','data_center_id':None}
    centers=sorted(d['id'] for d in catalog.get('dataCenters',[])
        if isinstance(d.get('id'),str) and d.get('availability') in ('LOW','MEDIUM','HIGH'))
    if not centers:
        return {'decision':'WAIT','reason':'NO_QUALIFYING_DATA_CENTER','data_center_id':None}
    if catalog.get('minRam',0)<50 or catalog.get('minVcpuCount',0)<6:
        return {'decision':'WAIT','reason':'HOST_MEMORY_OR_CPU_UNAVAILABLE','data_center_id':None}
    if not 0<catalog.get('price',{}).get('secure',0)<=.80:
        return {'decision':'WAIT','reason':'PRICE_BOUND','data_center_id':None}
    return {'decision':'READY','reason':'QUALIFIED_CAPACITY','data_center_id':centers[0],
            'gpu_type_id':gpu,'gpu_selection':GPU_RULE,'data_center_selection':DATA_CENTER_RULE}

def inspect_capacity(api,gpu):
    query={'include':'AVAILABILITY','product':'POD','cloud':'SECURE','count':1,'minCudaVersion':'12.8'}
    catalog=api.call('GET','/catalog/gpus/'+requests.utils.quote(gpu,safe=''),params=query)
    return catalog,capacity_decision(catalog,gpu)

def inspect_qualified_capacity(api,gpus):
    if gpus!=QUALIFIED_GPUS:raise ValueError('Ordered qualified GPU list required')
    inspected=[]
    for gpu in gpus:
        catalog,decision=inspect_capacity(api,gpu)
        inspected.append({'catalog':catalog,'selection':decision})
        if decision['decision']=='READY':return {'inspected':inspected},decision
    return {'inspected':inspected},{'decision':'WAIT','reason':'NO_QUALIFIED_CAPACITY',
        'gpu_type_id':None,'data_center_id':None,'gpu_selection':GPU_RULE}

def wait_for_qualified_capacity(api,gpus,deadline,events):
    def inspect():
        catalog,decision=inspect_qualified_capacity(api,gpus)
        events.append({'at':P.now(),'catalog':catalog,'selection':decision})
        if decision['decision']!='READY':raise P.CommandPending(decision['reason'])
        return catalog,decision
    return P.poll(inspect,deadline,event_sink=events.append,label='QUALIFIED_CAPACITY')

def wait_for_capacity(api,gpu,deadline,events):
    def inspect():
        catalog,decision=inspect_capacity(api,gpu)
        events.append({'at':P.now(),'catalog':catalog,'selection':decision})
        if decision['decision']!='READY':raise P.CommandPending(decision['reason'])
        return catalog,decision
    return P.poll(inspect,deadline,event_sink=events.append,label='QUALIFIED_CAPACITY')

def make_bundle(source_archive,sdk_wheel,service_wheel,harness,purpose='PREREGISTERED_STUDY'):
    files={}
    with tarfile.open(source_archive) as archive:
        entries=[m for m in archive.getmembers() if m.isfile()]
        prefixes={m.name.split('/',1)[0] for m in entries}
        if len(prefixes)!=1:raise ValueError('Tagged archive root')
        for member in entries:
            name=member.name.split('/',1)[1]
            if name.startswith('/') or '..' in Path(name).parts:raise ValueError('Tagged archive path')
            files[name]=archive.extractfile(member).read()
    for path in (sdk_wheel,service_wheel):files['wheels/'+path.name]=path.read_bytes()
    files['author-predictions.md']=files['AUTHOR_PREDICTIONS.md']
    frozen=subprocess.check_output(['git','-C',str(harness),'archive','--format=tar',HARNESS_REVISION])
    with tarfile.open(fileobj=io.BytesIO(frozen)) as archive:
        for member in archive.getmembers():
            if member.isfile():files['frozen-harness/'+member.name]=archive.extractfile(member).read()
            elif not member.isdir():raise ValueError('Harness member type')
    files['bundle-manifest.json']=json.dumps(
        {'purpose':purpose,'files':{n:P.sha(b) for n,b in files.items()}},sort_keys=True).encode()
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as archive:
        for name,raw in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600
            archive.addfile(info,io.BytesIO(raw))
    return stream.getvalue()

def verify_local(folder,harness):
    from swiftapi_native_service.backend import PCCG2Backend,REPLAY,FRESH
    from swiftapi_native_service.verify import verify_receipt
    from swiftapi.native_verify import verify_receipt as light
    backend=PCCG2Backend(harness/'.cache/pccg2',Path('/no-content-model'),harness,REPLAY,full_model=False)
    runtime=json.loads((folder/'runtime-public.json').read_bytes())['public_key']
    authority=json.loads((folder/'authority-public.json').read_bytes())['public_key']
    rows=[]
    for path in sorted((folder/'receipts').glob('*/receipt.json')):
        rows.append({'path':str(path.relative_to(folder)),
            'sdk':light(path,runtime,FRESH,authority_key=authority,expected_max_grant_age_seconds=60),
            'full':verify_receipt(path,runtime,FRESH,backend,authority_key=authority,expected_max_grant_age_seconds=60)})
    return rows

def smoke_inputs(primary):
    from nacl.signing import SigningKey
    from swiftapi_native_service.experiment import DEVELOPMENT_TRANSPORT_KEY
    seed=bytes(SigningKey.generate());key=DEVELOPMENT_TRANSPORT_KEY
    config=json.loads(json.dumps(primary))
    for field in ('registration_doi','registration_sha256','public_registration_timestamp',
                  'ledger_capture_mode','author_freeze_approved','authority_public_key'):
        config.pop(field,None)
    config.update(purpose='DEVELOPMENT_SMOKE',authority='LOCAL_TEST_DOUBLE',run_role='SMOKE',
        schedule=['VALID','SIGNED_DENIAL'],one_disposable_grant_revocation_approved=False,
        runtime_public_key=base64.b64encode(bytes(SigningKey(seed).verify_key)).decode(),
        operator_key_sha256=P.sha(key.encode()),spend_cap_usd=2)
    config['predictions']={arm:primary['predictions'][arm] for arm in config['schedule']}
    if config['operator_key_sha256']==primary['operator_key_sha256'] or config['runtime_public_key']==primary['runtime_public_key']:
        raise ValueError('Development and live identities must differ')
    return {'SMOKE':config},key,{'SMOKE':seed}

def artifact_checks(args,templates):
    from swiftapi_native_service.experiment import require_sealed_predictions,verify_installed_sdk
    from swiftapi_native_service.service import source_identity
    pins=json.loads((ROOT/'WHEEL_HASHES.json').read_bytes())
    for name,path in [('sdk_wheel_sha256',args.sdk_wheel),('service_wheel_sha256',args.service_wheel)]:
        if P.sha(path.read_bytes())!=pins[name]:raise ValueError('Published wheel hash')
    verify_installed_sdk(args.sdk_wheel)
    identity=source_identity()['sha256']
    for config in templates.values():
        if config.get('capacity_wait_seconds')!=CAPACITY_DEADLINE_SECONDS:
            raise ValueError('Registered capacity deadline mismatch')
        if (config.get('qualified_gpu_type_ids')!=QUALIFIED_GPUS or config.get('gpu_selection')!=GPU_RULE
                or 'gpu_type_id' in config
                or config.get('data_center_selection')!=DATA_CENTER_RULE or 'data_center_id' in config):
            raise ValueError('Qualified GPU order and deterministic data-center rule required')
        if config['service_source_sha256']!=identity or pins['service_source_sha256']!=identity:
            raise ValueError('Service source identity mismatch')
        require_sealed_predictions(config,ROOT/'AUTHOR_PREDICTIONS.md')
    with tarfile.open(args.source_archive) as archive:
        for member in archive.getmembers():
            if not member.isfile():continue
            if '/' not in member.name:raise ValueError('Source archive requires a single directory root')
            name=member.name.split('/',1)[1]
            if '..' in Path(name).parts or not (ROOT/name).is_file():raise ValueError('Source archive member')
            if archive.extractfile(member).read()!=(ROOT/name).read_bytes():raise ValueError('Source archive bytes mismatch')
    return {'wheel_hashes':pins,'service_source_sha256':identity,'predictions_verified':True}

def allocation_body(name,template,selection):
    if selection['gpu_type_id'] not in template['qualified_gpu_type_ids']:
        raise ValueError('GPU is outside the qualified list')
    P.GPU=selection['gpu_type_id'];P.DATA_CENTERS=[selection['data_center_id']];P.IMAGE=template['image_digest']
    body=P.create_body(name)
    body['gpu'].update(minRamPerGpu=50,minVcpuCountPerGpu=6)
    P.validate_provider_schema(body)
    return body

def verify_host_gpu(host,selection):
    record=host.get('nvidia_smi',{})
    rows=[line.split(',') for line in record.get('stdout','').splitlines() if line.strip()]
    if (record.get('exit_code')!=0 or len(rows)!=1 or len(rows[0])!=5
            or rows[0][0].strip()!=selection['gpu_type_id']):
        raise ValueError('Host GPU differs from selected catalog type')
    return {'gpu_type_id':rows[0][0].strip(),'uuid':rows[0][1].strip(),
        'driver_version':rows[0][2].strip(),'memory_mib':int(rows[0][4].strip()),
        'data_center_id':selection['data_center_id'],'hardware_attested':False}

def budget_plan(development,prior_cost_upper):
    duration=3600 if development else DEADLINE_SECONDS
    cap=2 if development else 10
    if not 0<=prior_cost_upper<cap:raise ValueError('Invalid existing cost bound')
    reserved=(.80+60*.10/720)*(duration+180)/3600+.10
    if reserved+prior_cost_upper>cap:raise ValueError('Combined cost reservation exceeds cap')
    return {'combined_cap_usd':cap,'prior_cost_upper_usd':prior_cost_upper,'reserved_usd':reserved,
        'combined_reserved_usd':reserved+prior_cost_upper,'deadline_seconds':duration,
        'provider_enforced_cap':False,'mechanism':'Parent cleanup and detached watchdog'}

def development_approval(args):
    if args.development_approval is None:raise ValueError('Development allocation approval required')
    if args.development_approval.with_suffix('.consumed').exists():raise ValueError('Development allocation allowance consumed')
    claim=json.loads(args.development_approval.read_bytes())
    if (claim.get('purpose')!='DEVELOPMENT_SMOKE' or claim.get('maximum_allocations')!=1
            or claim.get('combined_cap_usd')!=2 or claim.get('source_archive_sha256')!=P.sha(args.source_archive.read_bytes())
            or claim.get('prior_cost_upper_usd')!=args.prior_cost_upper_usd):raise ValueError('Development allocation approval')
    return claim

def execute(args):
    from swiftapi_native_service.core import canonical,read_key
    from swiftapi_native_service.mac_ledger import capture,finalize,read_archive,verify_join
    from swiftapi_native_service.experiment import verify_primary_seal
    out=args.out;out.mkdir(parents=True,exist_ok=False)
    development=args.development_smoke
    declared={role:json.loads((ROOT/('RUN_CONFIG_'+role+'.json')).read_bytes()) for role in ('PRIMARY','SECONDARY')}
    if development:
        if any(getattr(args,k,None) is not None for k in ('key_file','admin_key_file','primary_seed','secondary_seed')):
            raise ValueError('Development uses no live private input files')
        templates,key,seeds=smoke_inputs(declared['PRIMARY'])
        if not args.no_allocation:development_approval(args)
        record=receipt=None
    else:
        templates=declared
        record=json.loads(args.public_record.read_bytes()) if args.public_record else None
        receipt=json.loads(args.publication_verification.read_bytes()) if args.publication_verification else None
        if not args.no_allocation:
            if (not record or not receipt or receipt.get('verified') is not True
                    or receipt.get('archive_sha256')!=P.sha(args.source_archive.read_bytes())
                    or receipt.get('doi')!=record.get('doi')):
                raise ValueError('Public source verification required')
            for name,expected in receipt['member_hashes'].items():
                path=ROOT/name
                if not path.is_file() or path.is_symlink() or P.sha(path.read_bytes())!=expected:
                    raise ValueError('Local artifact differs from public tag')
            for role,template in templates.items():
                resolve(template,record,(ROOT/'REGISTRATION.md').read_bytes(),publication_verification=receipt,
                        primary_sha256='0'*64 if role=='SECONDARY' else None)
        read_private(args.key_file);read_private(args.admin_key_file);key=read_key(args.key_file)
        seeds={role:read_private(getattr(args,role.lower()+'_seed')) for role in templates}
    for role,seed in seeds.items():
        from nacl.signing import SigningKey
        if len(seed)!=32 or base64.b64encode(bytes(SigningKey(seed).verify_key)).decode()!=templates[role]['runtime_public_key']:
            raise ValueError('Published signing key mismatch')
        if P.sha(key.encode())!=templates[role]['operator_key_sha256']:raise ValueError('Published run key identifier')
    checks=artifact_checks(args,templates)
    P.save(out/'preallocation-checks.json',dict(checks,public_registration_checked=bool(receipt and receipt.get('verified')),
        authority_dispatches=0,purpose='DEVELOPMENT_SMOKE' if development else 'PREREGISTERED_STUDY'))
    bundle=make_bundle(args.source_archive,args.sdk_wheel,args.service_wheel,args.harness,
                       'DEVELOPMENT_SMOKE' if development else 'PREREGISTERED_STUDY')
    configs={};primary_hash=None
    api=P.RunPod(P.key_from_existing(args.runpod_key_file))
    first=next(iter(templates.values()));gpus=first['qualified_gpu_type_ids']
    budget=budget_plan(development,args.prior_cost_upper_usd)
    P.save(out/'budget.json',budget)
    if args.no_allocation:
        catalog,selection=inspect_qualified_capacity(api,gpus)
        P.save(out/'catalog.json',catalog)
        body=allocation_body('swiftapi-preallocation',first,dict(selection,
            gpu_type_id=selection['gpu_type_id'] or gpus[0],
            data_center_id=selection['data_center_id'] or 'CATALOG_SELECTED_AT_ALLOCATION'))
        report=dict(selection,pod_created=False,execution_claim_consumed=False,registered_slots_executed=0,
                    public_registration_required_for_execution=not development,create_schema_valid=True)
        P.save(out/'preallocation-decision.json',report)
        print(json.dumps(report));return 0
    capacity_events=[]
    try:
        catalog,selection=wait_for_qualified_capacity(api,gpus,time.time()+CAPACITY_DEADLINE_SECONDS,capacity_events)
    except TimeoutError:
        P.save(out/'outcome.json',{'status':'NOT_EXECUTED','reason':'QUALIFIED_CAPACITY_DEADLINE',
            'pod_created':False,'execution_claim_consumed':False,'registered_slots_executed':0})
        return 2
    finally:
        P.save(out/'capacity-waits.json',{'deadline_seconds':CAPACITY_DEADLINE_SECONDS,'waits':capacity_events})
    P.save(out/'catalog.json',catalog)
    P.save(out/'hardware-selection.json',selection)
    gpu=selection['gpu_type_id']
    name='swiftapi-'+('smoke-' if development else 'registered-')+uuid.uuid4().hex[:12]
    body=allocation_body(name,first,selection)
    if development:
        claim=development_approval(args)
        args.development_approval.with_suffix('.consumed').open('x').close()
        P.save(out/'execution-claim.json',claim)
    else:P.save(out/'execution-claim.json',claim_execution(record['doi'],templates,out))
    deadline=time.time()+budget['deadline_seconds']
    watcher=P.watchdog(api.key,out,name,deadline)
    P.save(out/'watchdog.json',{'pid':watcher,'deadline':deadline})
    pod=None;role=None;result={'started_at':P.now(),'registered':not development,'runs':{},
        'purpose':'DEVELOPMENT_SMOKE' if development else 'PREREGISTERED_STUDY'}
    try:
        created=api.call('POST','/pods',json=body);pod=created['id']
        P.save(out/'created.json',P.safe_pod(created));result['pod_id']=pod
        if (created.get('gpu',{}).get('id')!=gpu or not 0<created.get('cost',100)<=.80
                or created.get('gpu',{}).get('memory',0)<50 or created.get('gpu',{}).get('vcpuCount',0)<6
                or created.get('image')!=first['image_digest']
                or created.get('dataCenterId')!=selection['data_center_id'] or created.get('cloud')!='SECURE'):
            raise ValueError('Allocated GPU, location, cloud or rate mismatch')
        P.wait_exec_ready(api,pod,min(deadline-600,time.time()+900),out)
        P.upload(api,pod,bundle,deadline-600)
        R.launch(api,pod,'PREPARE',deadline)
        prepared=P.poll(lambda:R.read_json(api,pod,'PREPARED.json',deadline-600),deadline-600,label='ENVIRONMENT_READINESS')
        P.save(out/'environment-ready.json',prepared)
        if prepared.get('export'):
            R.pull_file(api,pod,prepared['export'],out/'environment.tar.gz',deadline-600)
            R.unpack(out/'environment.tar.gz',out/'environment')
        if prepared.get('ready') is not True:raise ValueError('Pod environment is not ready')
        host=json.loads((out/'environment/host.json').read_bytes())
        P.save(out/'host-selection-verification.json',verify_host_gpu(host,selection))
        for role in templates:
            folder=out/role;folder.mkdir()
            config=(templates[role] if development else resolve(templates[role],record,
                (ROOT/'REGISTRATION.md').read_bytes(),publication_verification=receipt,primary_sha256=primary_hash))
            config=dict(config,gpu_type_id=gpu,data_center_id=selection['data_center_id'])
            if role=='SECONDARY':verify_primary_seal(config,out/'PRIMARY/finalized/evidence.tar.gz')
            configs[role]=config;P.save(folder/'config.json',config)
            if not development:
                capture(config,'BEFORE',args.admin_key_file,folder/'mac-before.json',
                        predictions_file=ROOT/'AUTHOR_PREDICTIONS.md',author_authorized=True)
            else:P.save(folder/'mac-ledger-applicability.json',{'status':'NOT_APPLICABLE','authority':'LOCAL_TEST_DOUBLE'})
            approval={'approval_id':str(uuid.uuid4()),'config_sha256':P.sha(canonical(config)),
                'purpose':config['purpose'],'author_approved':True,'maximum_attempts':1}
            P.save(folder/'approval.json',approval)
            for filename in (('config.json','approval.json') if development else ('config.json','approval.json','mac-before.json')):
                R.upload_file(api,pod,'control/'+role+'/'+filename,(folder/filename).read_bytes(),deadline-600)
            if role=='SECONDARY':R.upload_file(api,pod,'control/SECONDARY/primary.tar.gz',
                (out/'PRIMARY/finalized/evidence.tar.gz').read_bytes(),deadline-600)
            R.launch(api,pod,role,deadline)
            channel=P.poll(lambda:R.read_json(api,pod,'control/'+role+'/channel.json',deadline-600),deadline-600,label='PRIVATE_CHANNEL')
            P.save(folder/'channel-public.json',channel)
            cipher=encrypted_runtime(channel,config,key,seeds[role])
            R.send_private_frame(api,pod,role,cipher,min(deadline-1500,time.time()+90))
            P.save(folder/'private-input-delivery.json',{'at':P.now(),'transport':'SEALED_BOX_TO_ANONYMOUS_SEALED_MEMFD',
                'config_sha256':P.sha(canonical(config)),'plaintext_written':False})
            done=P.poll(lambda:R.read_json(api,pod,'control/'+role+'/done.json',deadline-1200),deadline-1200,label='POPULATION_COMPLETION')
            meta=R.read_json(api,pod,'control/'+role+'/export.json',deadline-180)
            R.pull_file(api,pod,meta,folder/'execution.tar.gz',deadline-120)
            R.unpack(folder/'execution.tar.gz',folder/'execution')
            if not development:
                capture(config,'AFTER',args.admin_key_file,folder/'mac-after.json',
                    predictions_file=ROOT/'AUTHOR_PREDICTIONS.md',author_authorized=True,execution_archive=folder/'execution.tar.gz')
                finalize(folder/'execution.tar.gz',folder/'mac-after.json',folder/'finalized')
            verified_folder=folder/('execution' if development else 'finalized')
            reports=verify_local(verified_folder,args.harness)
            P.save(folder/'independent-verification.json',reports)
            sealed_archive=folder/('execution.tar.gz' if development else 'finalized/evidence.tar.gz')
            data,digest=read_archive(sealed_archive)
            summary=json.loads(data['summary.json'])
            ledger=({'status':'NOT_APPLICABLE','findings':[]} if development else verify_join(data,config,summary,folder/'execution.tar.gz'))
            result['runs'][role]={'archive_sha256':digest,'summary':summary,'ledger':ledger,'verified_receipts':len(reports)}
            if summary.get('execution_integrity')!='COMPLETE' or not summary.get('sequence_completed'):
                raise ValueError('Population execution is operationally incomplete')
            if development and (len(reports)!=2 or summary.get('status')!='PASS'):
                raise ValueError('Development receipt acceptance required')
            if role=='PRIMARY':
                if not eligible_primary(summary):raise ValueError('Primary completion required')
                if ledger.get('findings'):raise ValueError('Primary ledger findings require a stop')
                primary_hash=digest
        result['status']='COMPLETE'
    except BaseException as exc:
        result.update(status='STOPPED',exception_type=type(exc).__name__)
        reason=str(exc)
        if key not in reason and api.key not in reason:result['reason']=reason
        if pod and role in ('PRIMARY','SECONDARY','SMOKE'):
            folder=out/role
            try:
                error=R.read_json(api,pod,'control/'+role+'/error.json',min(deadline-90,time.time()+30),required=False)
                if error is not None:P.save(folder/'pod-error.json',error)
                if not (folder/'execution.tar.gz').exists():
                    meta=R.stop_and_export(api,pod,role,deadline-180)
                    filename='partial.tar.gz' if meta.get('sealed_registered_archive') is False else 'execution.tar.gz'
                    R.pull_file(api,pod,meta,folder/filename,deadline-60)
            except Exception as retrieval:result['evidence_retrieval_exception']=type(retrieval).__name__
    finally:
        if pod is None:
            try:
                matches=P.pod_ids_named(api,name)
                if len(matches)==1:pod=matches[0]
            except Exception as lookup:result['creation_lookup_exception']=type(lookup).__name__
        result['destroy_confirmed']=P.destroy(api,pod,out,'parent') if pod else None
        result['finished_at']=P.now()
        if pod:
            try:P.save(out/'billing.json',api.call('GET','/billing/pods',params={'podId':pod,'lastN':1,'bucketSize':'day'}))
            except Exception:result['billing_pending']=True
        P.save(out/'outcome.json',result)
    return 0 if result['status']=='COMPLETE' and result['destroy_confirmed'] else 2

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('out','source-archive','sdk-wheel','service-wheel','harness','runpod-key-file'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('public-record','publication-verification','key-file','admin-key-file','primary-seed','secondary-seed','development-approval'):
        p.add_argument('--'+name,type=Path)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--execute-authorized-registered-runs',action='store_true')
    mode.add_argument('--development-smoke',action='store_true')
    p.add_argument('--no-allocation',action='store_true')
    p.add_argument('--prior-cost-upper-usd',type=float,default=0)
    raise SystemExit(execute(p.parse_args()))
