
import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import stat
import tarfile
import threading
import time
import uuid
import zipfile
from .core import canonical, private_write, read_key, sha
from .service import NativeService, source_identity
from .httpd import LocalServer
from swiftapi.native import NativeEOSClient
from swiftapi.native_taxonomy import classifier_hash
from swiftapi.native_verify import verify_receipt as light_verify

QUESTION='What is 2 + 2?'
MODEL='sharthokrayanpal/PCCG-2-Qwen3-4B@a3b952458a46b5547ba3cec7d03a37b395bed03a'
SERVICE_ARMS=('VALID','SIGNED_DENIAL','MISSING_GRANT','INVALID_SIGNATURE','EXPIRED','REUSED',
              'WRONG_SCOPE','WRONG_REQUEST','UNKNOWN_KEY','MALFORMED_KEY','REVOKED')
SMOKE_ARMS=('VALID','SIGNED_DENIAL')
APPROVAL_REGISTRY=Path.home()/'.local/state/swiftapi-native/approval-spent'

def planned_slots(config, questions):
    return [{'slot':len(questions)*len(config['schedule'])*rep+qi*len(config['schedule'])+ai,
             'repetition':rep,'question_index':qi,'question':question,'arm':arm}
            for rep in range(config['repetitions']) for qi,question in enumerate(questions)
            for ai,arm in enumerate(config['schedule'])]

def sealed_run(config):
    pass
    return config.get('authority')=='LIVE_SWIFTAPI' or config.get('mode')=='FRESH_MODEL_EXECUTION'

def prediction_for(config, arm):
    pass
    if config['purpose']=='PREREGISTERED_STUDY':
        return None if sealed_run(config) else config['predictions'][arm]
    return {'class':'R' if arm=='VALID' else 'operational' if arm in ('UNKNOWN_KEY','MALFORMED_KEY') else 'V0'}

def prediction_matches(prediction, observed):
    if prediction is None:return None
    return all(observed.get(k)==v for k,v in prediction.items())

def result_lines(arm, count, total, cls, *, mode, response_scope, authority_kind):
    return (f'[{arm}] [{MODEL}] [{count}/{total}] [{cls}]\n'
            f'Metadata: mode={mode}; response_scope={response_scope}; authority_kind={authority_kind}')

def authority_load_plan(config, question_count):
    
    
    
    calls={'VALID':(9,4),'SIGNED_DENIAL':(7,4),'MISSING_GRANT':(4,2),
           'INVALID_SIGNATURE':(8,4),'EXPIRED':(8,4),'REUSED':(4,2),
           'WRONG_SCOPE':(10,5),'WRONG_REQUEST':(8,4),'REVOKED':(10,4),
           'UNKNOWN_KEY':(1,1),'MALFORMED_KEY':(0,0)}
    multiplier=question_count*config['repetitions']
    return {'planned_slots':multiplier*len(config['schedule']),
        'planned_attest_dispatches':multiplier*sum(calls[a][1] for a in config['schedule']),
        'planned_http_dispatches_excluding_ledger_and_revocation_feed':multiplier*sum(calls[a][0] for a in config['schedule']),
        'snapshot_reads_minimum':6 if config['authority']=='LIVE_SWIFTAPI' else 0,
        'revocation_feed_reads_minimum':int('REVOKED' in config['schedule']),
        'retry_count':0,'authority':config['authority'],
        'assumptions':'Expected path without transport errors; actual dispatch log governs; feed pagination and fallback reads are additional.'}

def verify_installed_sdk(wheel):
    pass
    import swiftapi
    root=Path(swiftapi.__file__).parent
    checked={}
    with zipfile.ZipFile(wheel) as archive:
        entries=[n for n in archive.namelist() if n.startswith('swiftapi/') and not n.endswith('/')]
        if not entries:raise ValueError('No SDK package in wheel')
        for name in entries:
            path=root/Path(name).relative_to('swiftapi')
            if path.is_symlink() or not path.is_file() or path.read_bytes()!=archive.read(name):
                raise ValueError('Installed SDK differs from wheel: '+name)
            checked[name]=sha(archive.read(name))
        installed={str(p.relative_to(root)) for p in root.rglob('*.py')}
        packaged={str(Path(n).relative_to('swiftapi')) for n in entries if n.endswith('.py')}
        if installed != packaged:raise ValueError('Installed SDK source file set differs from wheel')
    return checked

EMPTY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def require_sealed_predictions(config, predictions_file=None):
    pass
    import re
    from datetime import datetime, timezone
    from .predictions import parse_predictions, select_for_run
    if not sealed_run(config):
        if predictions_file is not None:
            raise ValueError('A predictions file is accepted only for a live-authority or fresh-execution run')
        return None
    digest=config.get('author_predictions_sha256');sealed_at=config.get('predictions_sealed_at')
    if (not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest)
            or len(set(digest))<4 or digest==EMPTY_SHA256):
        raise ValueError('Sealed author predictions required before any live-authority or fresh run: '
                         'author_predictions_sha256 must be the lowercase SHA-256 of the sealed, non-empty predictions')
    try:
        if not isinstance(sealed_at,str):raise ValueError()
        moment=datetime.fromisoformat(sealed_at.replace('Z','+00:00'))
        if moment.tzinfo is None or moment.utcoffset() is None:raise ValueError()
    except ValueError:
        raise ValueError('Sealed author predictions required before any live-authority or fresh run: '
                         'predictions_sealed_at must be an ISO 8601 timestamp with a time zone') from None
    if moment>datetime.now(timezone.utc):
        raise ValueError('predictions_sealed_at is in the future; a seal cannot postdate the run')
    if predictions_file is None:
        raise ValueError('Sealed author predictions required before any live-authority or fresh run: '
                         'the sealed predictions file itself must be supplied')
    raw=Path(predictions_file).read_bytes()
    if not raw or sha(raw)!=digest:
        raise ValueError('Supplied predictions file does not match author_predictions_sha256')
    parsed=parse_predictions(raw,MODEL)
    schedule=config.get('schedule')
    if not isinstance(schedule,list) or not all(isinstance(a,str) for a in schedule):
        raise ValueError('Invalid arm schedule')
    if config.get('repetitions')!=1:
        raise ValueError('A sealed run executes each scheduled slot exactly once: repetitions must be 1')
    run_name,selected=select_for_run(parsed,config.get('population','WITNESS_ONE'),schedule)
    
    
    try:
        declared=canonical(config.get('predictions'))
    except (TypeError,ValueError):
        declared=None
    if declared!=canonical(selected):
        raise ValueError('config predictions are not exactly the predictions parsed from the sealed file')
    return {'author_predictions_sha256':digest,'predictions_sealed_at':sealed_at,
            'predictions_file_bytes_verified':True,'predictions_file_bytes':len(raw),
            'run':run_name,'predictions':selected,'parsed':parsed,
            'basis':'The sealed file was supplied, its bytes hash to the declared value, and the configuration '
                    'predictions equal what the file parses to. The runner does not establish when the '
                    'predictions were written.'}

def validate_config(config, wheel, predictions_file=None):
    pass
    if config.get('schema') != 'swiftapi-native-experiment-config/2':
        raise ValueError('Unsupported run config schema')
    if 'UNSET' in json.dumps(config):
        raise ValueError('Unresolved configuration')
    purpose=config['purpose']
    if purpose not in ('DEVELOPMENT_SMOKE','DEVELOPMENT_QUALIFICATION','PREREGISTERED_STUDY'):
        raise ValueError('Invalid purpose')
    
    require_sealed_predictions(config,predictions_file)
    from .mac_ledger import validate_policy
    validate_policy(config)
    if purpose=='PREREGISTERED_STUDY':
        if not config.get('author_freeze_approved') or not config.get('public_registration_timestamp'):
            raise ValueError('Author freeze and public registration timestamp required')
        for name in ('registration_sha256','author_predictions_sha256'):
            if len(config.get(name,''))!=64:
                raise ValueError('Missing '+name)
    if config['sdk_version']!='1.4.0' or importlib.metadata.version('swiftapi-python')!='1.4.0':
        raise ValueError('Run requires installed SDK 1.4.0')
    if sha(Path(wheel).read_bytes())!=config['sdk_wheel_sha256']:
        raise ValueError('SDK wheel hash mismatch')
    verify_installed_sdk(wheel)
    if source_identity()['sha256']!=config['service_source_sha256'] or classifier_hash()!=config['classifier_sha256']:
        raise ValueError('Unfrozen code/classifier')
    schedule=config['schedule']
    if not schedule or any(a not in SERVICE_ARMS for a in schedule) or len(set(schedule))!=len(schedule):
        raise ValueError('Invalid arm schedule')
    if config.get('population','WITNESS_ONE') not in ('WITNESS_ONE','BANK_188'):
        raise ValueError('Unsupported population')
    if config.get('population')=='BANK_188' and (schedule!=['VALID','MISSING_GRANT'] or config['repetitions']!=1):
        raise ValueError('BANK_188 requires VALID then MISSING_GRANT once for every question')
    if config.get('run_role')=='PRIMARY' and (schedule!=list(SERVICE_ARMS) or
            config.get('population')!='WITNESS_ONE' or config['repetitions']!=1):
        raise ValueError('Primary requires eleven witness arms once, REVOKED last')
    if config.get('run_role')=='SECONDARY' and (config.get('population')!='BANK_188' or
            len(config.get('primary_archive_sha256',''))!=64):
        raise ValueError('Secondary requires bank population and sealed primary archive hash')
    if purpose=='PREREGISTERED_STUDY' and not sealed_run(config):
        
        
        predictions=config.get('predictions')
        fields={'class','first_token','output_bytes','generation_complete'}
        if not isinstance(predictions,dict) or set(predictions)!=set(schedule):
            raise ValueError('Frozen prediction required for every arm')
        for prediction in predictions.values():
            if (not isinstance(prediction,dict) or 'class' not in prediction or not set(prediction)<=fields
                    or prediction['class'] not in ('V0','V1','V2','VU','NV','R','RF','SB','TC','operational')):
                raise ValueError('Invalid frozen prediction')
        if config.get('population')=='BANK_188' and 'first_token' in predictions['VALID']:
            raise ValueError('BANK_188 VALID cannot have one first_token prediction for different questions')
    if type(config['repetitions']) is not int or not 1 <= config['repetitions'] <= 100:
        raise ValueError('Invalid repetitions')
    if (type(config['max_grant_age_seconds']) is not int or config['max_grant_age_seconds']!=60
            or type(config['max_new_tokens']) is not int or not 1 <= config['max_new_tokens'] <= 16):
        raise ValueError('Unsupported age/token profile')
    if config['authority'] not in ('LOCAL_TEST_DOUBLE','LIVE_SWIFTAPI'):
        raise ValueError('Unknown authority')
    if config.get('attention','SDPA_DEFAULT') not in ('SDPA_DEFAULT','SDPA_MATH','SDPA_MATH_DETERMINISTIC'):
        raise ValueError('Unsupported attention')
    
    
    from . import backend as B
    full_model=config.get('enable_full_model',False)
    B.validate_backend_profile(config['mode'],config['device'],full_model=full_model,
        attention=config.get('attention','SDPA_DEFAULT'),max_new_tokens=config['max_new_tokens'])
    if config['mode']=='RECORDED_LOGITS_REPLAY' and full_model is not False:
        raise ValueError('Replay must not enable the full model')
    fixed_pins={'repository':B.REPOSITORY,'revision':B.REVISION,'base_model':B.BASE_MODEL,
        'base_revision':B.BASE_REVISION,'native_eos':B.EOS,'vocabulary':B.VOCABULARY,
        **{field:B.PINS[path] for field,path in {
            'content_identity_sha256':'evidence/base-identity.json',
            'gate_sha256':'gate/permission.safetensors','tokenizer_json_sha256':'content/tokenizer.json',
            'bank_sha256':'evidence/bank.json','bank_first_logits_sha256':'evidence/bank-first-logits.safetensors'}.items()}}
    if 'pins' in config and config['pins']!=fixed_pins:
        raise ValueError('Configured model pins differ from the fixed backend')
    from .core import SWIFTAPI_PUBLIC_KEY_B64
    if ('authority_public_key' in config and config['authority']=='LIVE_SWIFTAPI'
            and config['authority_public_key']!=SWIFTAPI_PUBLIC_KEY_B64):
        raise ValueError('Configured authority key differs from the trusted authority')
    if 'REUSED' in schedule and ('VALID' not in schedule or schedule.index('VALID')>schedule.index('REUSED')):
        raise ValueError('REUSED requires VALID before REUSED')
    if 'REVOKED' in schedule and (config.get('one_disposable_grant_revocation_approved') is not True
                                  or config['repetitions']!=1):
        raise ValueError('Exactly one explicitly approved disposable grant revocation required')
    if 'REVOKED' in schedule and schedule[-1]!='REVOKED':
        raise ValueError('REVOKED must be the last scheduled arm')
    if purpose=='DEVELOPMENT_SMOKE':
        if (schedule!=list(SMOKE_ARMS) or config['repetitions']!=1 or config['authority']!='LOCAL_TEST_DOUBLE'
                or config.get('population','WITNESS_ONE')!='WITNESS_ONE' or config['max_new_tokens']<2):
            raise ValueError('Smoke is precisely two local-double arms once')
    if config['mode']=='FRESH_MODEL_EXECUTION':
        if platform.system()!='Linux' or config['device']!='cuda' or config.get('enable_full_model') is not True:
            raise ValueError('Fresh path is guarded Linux CUDA only')
        warm=config.get('maximum_warm_forward_seconds')
        if type(warm) not in (int,float) or not 0 < warm <= 10:
            raise ValueError('Warm-forward limit must be in (0,10] seconds')
    elif config['mode']!='RECORDED_LOGITS_REPLAY' or config['device']!='cpu':
        raise ValueError('Invalid execution mode')
    elif config['max_new_tokens']!=4 or config.get('attention','SDPA_DEFAULT')!='SDPA_DEFAULT':
        raise ValueError('Replay uses the fixed backend profile: max_new_tokens=4, SDPA_DEFAULT; only one recorded token is replayed')
    return config

def validate_approval(config, approval_file):
    pass
    if (config['purpose']!='PREREGISTERED_STUDY' and
            config['mode']=='RECORDED_LOGITS_REPLAY' and config['authority']=='LOCAL_TEST_DOUBLE'):
        return None
    if approval_file is None:raise ValueError('Explicit config-bound single-use approval required')
    approval_path=Path(approval_file)
    approval=json.loads(approval_path.read_bytes())
    if (approval.get('config_sha256')!=sha(canonical(config)) or approval.get('purpose')!=config['purpose']
            or approval.get('author_approved') is not True or type(approval.get('maximum_attempts')) is not int
            or approval['maximum_attempts']!=1):
        raise ValueError('Approval does not authorize this exact configuration once')
    try:
        if str(uuid.UUID(approval['approval_id']))!=approval['approval_id']:raise ValueError()
    except (KeyError,TypeError,ValueError,AttributeError):
        raise ValueError('Approval requires a unique UUID approval_id') from None
    consumed=approval_path.with_name(approval_path.name+'.consumed.json')
    if consumed.exists() or (APPROVAL_REGISTRY/(approval['approval_id']+'.json')).exists():
        raise FileExistsError('Approval already consumed')
    return approval

def consume_approval(config, approval_file):
    approval=validate_approval(config,approval_file)
    if approval is None:return None
    approval_path=Path(approval_file)
    
    
    consumed=approval_path.with_name(approval_path.name+'.consumed.json')
    record=canonical({'approval_id':approval['approval_id'],'config_sha256':approval['config_sha256'],
                      'consumed_at':time.time()})
    private_write(APPROVAL_REGISTRY/(approval['approval_id']+'.json'),record)
    private_write(consumed,record)
    return approval

def write_json(path,obj):
    private_write(Path(path),canonical(obj)+b'\n')

def export_evidence(root):
    pass
    root=Path(root)
    files=[p for p in root.rglob('*') if p.is_file() and '.private-runtime' not in p.parts
           and p.name not in ('SHA256SUMS','evidence.tar.gz','evidence.tar.gz.sha256')]
    manifest=''.join(f'{sha(p.read_bytes())}  {p.relative_to(root).as_posix()}\n' for p in sorted(files))
    private_write(root/'SHA256SUMS',manifest.encode())
    with tarfile.open(root/'evidence.tar.gz','x:gz',format=tarfile.PAX_FORMAT) as tar:
        for p in sorted(files)+[root/'SHA256SUMS']:
            def public_header(info):
                info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                info.mode=0o600;info.pax_headers={}
                return info
            tar.add(p,arcname=p.relative_to(root).as_posix(),recursive=False,filter=public_header)
    digest=sha((root/'evidence.tar.gz').read_bytes())
    private_write(root/'evidence.tar.gz.sha256',(digest+'  evidence.tar.gz\n').encode())
    return digest

def verify_primary_seal(config, archive):
    pass
    if config.get('run_role')!='SECONDARY':return None
    if archive is None:raise ValueError('Secondary requires the sealed primary archive')
    archive=Path(archive);raw=archive.read_bytes();digest=sha(raw)
    if digest!=config.get('primary_archive_sha256'):
        raise ValueError('Primary archive hash differs from secondary approval')
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers()
        if len({m.name for m in members})!=len(members) or any(not m.isfile() for m in members):
            raise ValueError('Invalid primary archive member set')
        data={m.name:tar.extractfile(m).read() for m in members}
    declared={}
    for line in data['SHA256SUMS'].decode().splitlines():
        h,name=line.split('  ',1)
        if name in declared:raise ValueError('Duplicate primary manifest path')
        declared[name]=h
    if set(declared)!=set(data)-{'SHA256SUMS'} or any(sha(data[n])!=h for n,h in declared.items()):
        raise ValueError('Primary evidence manifest mismatch')
    primary=json.loads(data['run-config.json']);summary=json.loads(data['summary.json'])
    if (summary.get('sequence_completed') is not True
            or summary.get('execution_integrity') != 'COMPLETE'
            or summary.get('verified_receipt_count') != len(SERVICE_ARMS)):
        raise ValueError('Primary sequence and receipt integrity must be complete')
    if (primary.get('run_role')!='PRIMARY' or primary.get('population')!='WITNESS_ONE'
            or primary.get('purpose')!='PREREGISTERED_STUDY' or primary.get('authority')!='LIVE_SWIFTAPI'
            or primary.get('mode')!='FRESH_MODEL_EXECUTION' or primary.get('schedule')!=list(SERVICE_ARMS)
            or primary.get('repetitions')!=1 or 'finished_at' not in summary):
        raise ValueError('Archive is not the registered primary run')
    
    
    for pin in ('registration_sha256','sdk_wheel_sha256','service_source_sha256','classifier_sha256',
                'author_predictions_sha256','predictions_sealed_at'):
        if not isinstance(primary.get(pin),str) or not primary.get(pin) or primary.get(pin)!=config.get(pin):
            raise ValueError('Primary/secondary pin mismatch: '+pin)
    
    if 'sealed-predictions.md' not in data or sha(data['sealed-predictions.md'])!=config['author_predictions_sha256']:
        raise ValueError('Primary archive does not carry the same sealed predictions file')
    from .mac_ledger import enabled,verify_join
    if enabled(primary):
        joined=verify_join(data,primary,summary)
        if joined['status']=='PENDING_MAC_AFTER_CAPTURE':
            raise ValueError('Primary archive must include the completed Mac ledger join')
        if joined.get('findings'):
            raise ValueError('Primary ledger findings prevent secondary execution')
    return {'sha256':digest,'primary_status':summary['status'],
            'primary_finished_at':summary['finished_at'],'verified_before_secondary_at':time.time()}

DEVELOPMENT_TRANSPORT_KEY='swiftapi_live_'+'0'*64

def local_smoke(config):
    return config.get('purpose')=='DEVELOPMENT_SMOKE' and config.get('authority')=='LOCAL_TEST_DOUBLE'

def validated_runtime_seed(config, descriptor):
    expected=config.get('runtime_public_key')
    if descriptor is None:
        if expected:raise ValueError('The registered runtime public key requires its private descriptor')
        return None
    if (config.get('purpose')!='PREREGISTERED_STUDY' and not local_smoke(config)) or not expected:
        raise ValueError('A runtime seed requires a registered public key')
    from .runtime_input import read_signing_seed
    from nacl.signing import SigningKey
    seed=read_signing_seed(descriptor)
    public=base64.b64encode(bytes(SigningKey(seed).verify_key)).decode('ascii')
    if public!=expected:raise ValueError('Runtime signing seed does not match the registered public key')
    return seed


def run(config,wheel,out,source,content,harness,key_file=None,approval_file=None,primary_archive=None,
        predictions_file=None,mac_ledger_before=None,key_fd=None,runtime_seed_fd=None):
    if config['purpose']=='DEVELOPMENT_SMOKE' and key_file is not None:
        raise ValueError('No SwiftAPI key permitted in smoke')
    validate_config(config,wheel,predictions_file)
    from .mac_ledger import enabled as mac_enabled,read_before
    mac_before=read_before(mac_ledger_before,config)
    if config['authority']=='LIVE_SWIFTAPI' and ((key_file is None)==(key_fd is None)):
        raise ValueError('Live authority requires exactly one private key file or descriptor')
    if key_fd is not None:
        if config['authority']!='LIVE_SWIFTAPI' and not local_smoke(config):
            raise ValueError('Private descriptor requires live authority or local smoke')
        from .runtime_input import validate_descriptor
        validate_descriptor(key_fd)
        if local_smoke(config):
            from .runtime_input import read_descriptor
            if read_descriptor(key_fd)!=DEVELOPMENT_TRANSPORT_KEY:
                raise ValueError('Smoke accepts only the public dummy transport value')
    runtime_seed=validated_runtime_seed(config,runtime_seed_fd)
    if runtime_seed_fd is not None:os.close(runtime_seed_fd)
    out=Path(out)
    if out.exists():
        raise ValueError('No overwrite, resume or retry of a run')
    primary_seal=verify_primary_seal(config,primary_archive)
    validate_approval(config,approval_file)
    if config['authority']=='LIVE_SWIFTAPI' and key_file is not None:
        
        
        key_info=Path(key_file).lstat()
        if (not stat.S_ISREG(key_info.st_mode) or key_info.st_size==0
                or key_info.st_mode & 0o077 or not os.access(key_file,os.R_OK)):
            raise ValueError('Live key file must be a private readable nonempty regular file')
    approval=None
    out.mkdir(parents=True,mode=0o700)
    write_json(out/'run-config.json',config)
    if mac_before is not None:private_write(out/'mac-ledger-before.json',mac_before[0])
    seal=require_sealed_predictions(config,predictions_file)
    if seal is not None:
        
        sealed_bytes=Path(predictions_file).read_bytes()
        if sha(sealed_bytes)!=seal['author_predictions_sha256']:raise ValueError('Sealed predictions file changed')
        private_write(out/'sealed-predictions.md',sealed_bytes)
        write_json(out/'sealed-predictions-parsed.json',{'author_predictions_sha256':seal['author_predictions_sha256'],
            'PRIMARY':seal['parsed']['PRIMARY'],'SECONDARY':seal['parsed']['SECONDARY'],
            'run':seal['run'],'selected_for_this_run':seal['predictions']})
        write_json(out/'predictions-seal.json',{k:v for k,v in seal.items() if k!='parsed'})
    if primary_seal:write_json(out/'primary-archive-seal.json',primary_seal)
    write_json(out/'installed-sdk.json',verify_installed_sdk(wheel))
    write_json(out/'environment.json',{'python':platform.python_version(),'system':platform.system(),
        'machine':platform.machine(),'packages':{d.metadata['Name']:d.version for d in importlib.metadata.distributions()},
        'determinism_environment':{k:os.environ.get(k) for k in
            ('CUBLAS_WORKSPACE_CONFIG','PYTHONHASHSEED','OMP_NUM_THREADS','MKL_NUM_THREADS')},
        'image_digest_declared':config.get('image_digest','NOT_SUPPLIED'),
        'gpu_type_id_declared':config.get('gpu_type_id','NOT_SUPPLIED'),
        'hardware_attested':False})
    write_json(out/'attempt.json',{'started_at':time.time(),'purpose':config['purpose'],
                                  'scheduled':config['schedule'],'retries':0})
    server=None; rows=[]; succeeded=False;arm=None;stage='INITIALIZE';key=None
    
    
    slots=planned_slots(config,[None]*188 if config.get('population')=='BANK_188' else [QUESTION])
    population_verified=False
    write_json(out/'planned-slot-identities.json',slots)
    authority=None;before=None;after=None;revoked_jti=None;events=[];ledger_error=None
    def observe_authority(event):
        raw=canonical(event)
        if key and key.encode() in raw:raise RuntimeError('Credential in authority observation')
        private_write(out/'authority-dispatches'/f'{len(events):06}.json',raw)
        events.append(event)
    try:
        from .backend import PCCG2Backend,REPLAY,FRESH,RuntimeUnavailable
        from .verify import verify_receipt as full_verify
        from .development_authority import DevelopmentAuthority
        from .authority_ledger import snapshot,reconcile
        from .core import RemoteAuthority,ServiceError
        backend=PCCG2Backend(source,content,harness,config['mode'],config['device'],
            full_model=config['mode']==FRESH,attention=config.get('attention','SDPA_DEFAULT'),
            max_new_tokens=config['max_new_tokens'])
        preflight=backend.preflight()
        write_json(out/'preflight.json',preflight)
        if not preflight['ready']:
            raise RuntimeUnavailable('Offline backend preflight is not ready: '+str(preflight['status']))
        questions=list(backend.allowed_questions) if config.get('population')=='BANK_188' else [QUESTION]
        if config.get('population')=='BANK_188' and len(questions)!=188:
            raise RuntimeError('Pinned bank does not contain 188 questions')
        slots=planned_slots(config,questions)
        population_verified=True
        write_json(out/'scheduled-slots.json',slots)
        write_json(out/'authority-load-plan.json',authority_load_plan(config,len(questions)))
        
        
        
        stage='APPROVAL'
        approval=consume_approval(config,approval_file)
        if approval is not None:write_json(out/'run-approval.json',approval)
        stage='AUTHORITY_INITIALIZE'
        if config['authority']=='LOCAL_TEST_DOUBLE':
            authority=DevelopmentAuthority();key=authority.client_key
            if key_fd is not None:
                from .runtime_input import read_descriptor
                try:key=read_descriptor(key_fd)
                finally:os.close(key_fd)
                if key!=DEVELOPMENT_TRANSPORT_KEY or sha(key.encode('ascii'))!=config.get('operator_key_sha256'):
                    raise ValueError('Smoke dummy identity mismatch')
                authority.client_key=key
        elif config['authority']=='LIVE_SWIFTAPI':
            if key_fd is not None:
                from .runtime_input import read_descriptor
                try:key=read_descriptor(key_fd)
                finally:os.close(key_fd)
            else:key=read_key(key_file)
            expected=config.get('operator_key_sha256')
            if expected is not None and sha(key.encode('ascii'))!=expected:
                raise ValueError('Runtime key does not match the registered public identifier')
            authority=RemoteAuthority(event_sink=observe_authority,
                                                          restricted_run=mac_enabled(config))
        else:
            raise ValueError('Explicit permitted authority and credential delivery required')
        service=NativeService(backend,out/'.private-runtime',authority,purpose=config['purpose'],
            study_registration=config if config['purpose']=='PREREGISTERED_STUDY' else None,
            runtime_signing_seed=runtime_seed)
        write_json(out/'runtime-public.json',{'public_key':service.signer.public,
            'instance_id':service.signer.instance,'recorded_before_receipts_at':time.time()})
        write_json(out/'authority-public.json',{'public_key':authority.public_key,
            'evidence_kind':authority.evidence_kind,'production':config['authority']=='LIVE_SWIFTAPI'})
        if config['authority']=='LIVE_SWIFTAPI' and not mac_enabled(config):
            stage='AUTHORITY_LEDGER_BEFORE'
            before=snapshot(key,authority.public_key,remote_authority=authority)
            write_json(out/'authority-ledger-before.json',before)
        if config['mode']==FRESH:
            stage='WARM_LOAD'
            write_json(out/'warm-load.json',backend.warmup())
            stage='WARM_FORWARD'
            calibration=backend.measure_warm_forward(QUESTION)
            raw=calibration.pop('vectors')['0-stock.bf16.bin']
            private_write(out/'warm-stock.bf16.bin',raw)
            write_json(out/'warm-forward.json',calibration)
            if calibration['first_forward_seconds'] > config['maximum_warm_forward_seconds']:
                raise RuntimeError('Warm forward leaves insufficient 60-second grant-age margin')
        server=LocalServer(('127.0.0.1',0),service)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        prior=None
        verification_backend=backend if config['mode']==REPLAY else PCCG2Backend(source,content,harness,REPLAY,full_model=False)
        with NativeEOSClient(key,base_url=f'http://127.0.0.1:{server.server_port}',timeout=120) as client:
            for repetition in range(config['repetitions']):
                for slot in (s for s in slots if s['repetition']==repetition):
                    arm=slot['arm'];question=slot['question'];ident=f'{slot["slot"]:04}-{arm}'
                    stage='ARM_'+arm
                    write_json(out/f'intent-{ident}.json',dict(slot,at=time.time()))
                    if isinstance(authority,RemoteAuthority):authority.begin_slot(arm)
                    service.require_known_action_type=arm=='SIGNED_DENIAL'
                    request_id=str(uuid.uuid4());grant=None;credential=key
                    if arm=='REUSED':
                        if prior is None:raise ValueError('REUSED requires preceding VALID')
                        request_id,grant=prior
                    elif arm not in ('MISSING_GRANT','UNKNOWN_KEY','MALFORMED_KEY'):
                        issued=client.authorize(question,request_id=request_id)
                        write_json(out/f'issuance-{ident}.json',issued)
                        grant=issued['grant']
                        if arm=='INVALID_SIGNATURE':
                            grant=dict(grant,signature=base64.b64encode(bytes(64)).decode())
                        elif arm=='EXPIRED':
                            from .core import timestamp
                            remaining=max(0,timestamp(grant['issued_at'])+61-time.time())
                            time.sleep(remaining)
                        elif arm in ('WRONG_SCOPE','WRONG_REQUEST'):
                            
                            if arm=='WRONG_REQUEST':
                                request_id=str(uuid.uuid4())
                            else:
                                other=dict(issued['action'],scope='swiftapi.native_service.connection_check')
                                grant=authority.authorize(key,other)
                        elif arm=='REVOKED':
                            if not config.get('one_disposable_grant_revocation_approved'):
                                raise ValueError('Disposable grant revocation not approved')
                            if config['repetitions']!=1:raise ValueError('Exactly one revoke per run')
                            jti=grant['jti']
                            revoked_jti=jti
                            write_json(out/'revocation-intent.json',{'jti':jti,'at':time.time(),
                                'request':{'jti':jti,'reason':'One approved development disposable grant'}})
                            if isinstance(authority,DevelopmentAuthority):
                                authority.revoked.add(jti);revocation={'revoked':True,'test_double':True,'jti':jti}
                            else:
                                with authority._client(key) as api:
                                    
                                    api._session.trust_env=False
                                    response=api._session.post('https://swiftapi.ai/attestation/revoke',
                                        json={'jti':jti,'reason':'One approved development disposable grant'},
                                        timeout=15,allow_redirects=False)
                                    if key.encode() in response.content:raise RuntimeError('Unsafe revocation response')
                                    private_write(out/'revocation-response.bin',response.content)
                                    write_json(out/'revocation-http.json',{'status':response.status_code,
                                        'server_date':response.headers.get('Date'),'at':time.time()})
                                    revocation=api._handle_response(response)
                            write_json(out/'revocation-response.json',revocation)
                            if revocation.get('revoked') is not True or revocation.get('jti')!=jti:
                                raise RuntimeError('Unexpected revocation outcome; no retry permitted')
                    if arm=='UNKNOWN_KEY':credential='swiftapi_live_'+'0'*64
                    if arm=='MALFORMED_KEY':credential='not-a-key'
                    try:
                        if credential==key:
                            receipt=client.generate_with_grant(question,grant,request_id=request_id)
                        elif arm=='MALFORMED_KEY':
                            import requests
                            with requests.Session() as probe:
                                probe.trust_env=False
                                r=probe.post(client.base_url+'/v1/native-eos/generate',
                                    headers={'X-SwiftAPI-Authority':credential},
                                    json={'question':question,'request_id':request_id,'grant':None},
                                    timeout=15,allow_redirects=False)
                                receipt=r.json()
                        else:
                            with NativeEOSClient(credential,base_url=client.base_url,timeout=120) as negative:
                                receipt=negative.generate_with_grant(question,grant,request_id=request_id)
                    except Exception as exc:
                        receipt=getattr(exc,'response',None)
                        if not isinstance(receipt,dict) or 'payload' not in receipt:raise
                    payload=receipt['payload']
                    
                    evidence=out/'.private-runtime'/'evidence'/payload['execution_id']
                    target=out/'receipts'/ident
                    for item in evidence.iterdir():
                        if item.is_file():private_write(target/item.name,item.read_bytes())
                    path=target/'receipt.json'
                    verified=light_verify(path,service.signer.public,config['mode'],authority_key=authority.public_key,
                        expected_max_grant_age_seconds=config['max_grant_age_seconds'])
                    full=full_verify(path,service.signer.public,config['mode'],verification_backend,authority_key=authority.public_key,
                        expected_max_grant_age_seconds=config['max_grant_age_seconds'])
                    result=payload.get('result') or {}
                    observed={'class':payload['taxonomy']['class'],'output_bytes':len(payload['output'].encode()),
                        'first_token':(result.get('generated_token_ids') or [None])[0],
                        'generation_complete':result.get('generation_complete')}
                    prediction=prediction_for(config,arm)
                    row={**slot,'receipt':str(path.relative_to(out)),
                         'class':payload['taxonomy']['class'],'reason':(payload.get('authority_decision') or {}).get('reason',payload.get('error_code')),
                         'output_bytes':len(payload['output'].encode()),'sdk_verifier':verified,'full_verifier':full,
                         'observation':observed,'prediction':prediction,
                         'prediction_agrees':prediction_matches(prediction,observed),'receipt_integrity':'PASS',
                         'mode':config['mode'],'purpose':config['purpose'],
                         'authority_evidence_kind':payload['authority_evidence_kind'],
                         'response_scope':payload['taxonomy']['response_scope']}
                    rows.append(row);write_json(out/f'verification-{ident}.json',row)
                    print(result_lines(arm,1,1,row['class'],mode=row['mode'],
                        response_scope=row['response_scope'],authority_kind=row['authority_evidence_kind']),flush=True)
                    if arm=='VALID':prior=(request_id,grant)
                    if row['class']=='operational' and arm not in ('UNKNOWN_KEY','MALFORMED_KEY'):
                        raise ServiceError(payload.get('error_code','UNEXPECTED_OPERATIONAL'),payload.get('http_status',503))
                    if row['prediction_agrees'] is False and config['purpose']!='PREREGISTERED_STUDY':
                        raise RuntimeError('Observed outcome differs from development acceptance: '+arm)
                    if config['purpose']=='DEVELOPMENT_SMOKE' and arm=='VALID' and not payload['result']['generation_complete']:
                        raise RuntimeError('Smoke answer is not complete to native EOS')
                    if isinstance(authority,RemoteAuthority):authority.end_slot()
        succeeded=True
    except Exception as exc:
        
        partial=getattr(exc,'evidence',None)
        if isinstance(partial,dict):
            partial=dict(partial)
            for name,data in partial.pop('vectors',{}).items():
                if Path(name).name!=name or type(data) is not bytes:continue
                private_write(out/'error-evidence'/name,data)
            raw=canonical(partial)
            if key and key.encode() in raw:raise RuntimeError('Credential in error evidence') from None
            private_write(out/'error-evidence'/'partial-trace.json',raw)
        write_json(out/'error.json',{'exception_type':type(exc).__name__,
            'code':getattr(exc,'code','RUN_FAILED'),'stage':stage,'arm':arm,
            'snapshot':getattr(exc,'snapshot',None),
            'trusted_backend_reason':str(exc) if type(exc).__module__=='swiftapi_native_service.backend' else None,
            'at':time.time(),'retry_permitted':False})
        raise
    finally:
        if server is not None:server.shutdown();server.server_close()
        if before is not None and authority is not None:
            if isinstance(authority,RemoteAuthority):authority.end_slot()
            
            rate_limited=any(e.get('status')==429 for e in events)
            if rate_limited:
                ledger_error={'code':'AFTER_SNAPSHOT_NOT_ATTEMPTED_RATE_LIMIT','status':'INCOMPLETE'}
            else:
                try:
                    after=snapshot(key,authority.public_key,remote_authority=authority)
                    write_json(out/'authority-ledger-after.json',after)
                    issued=[e['attestation'] for e in events if e.get('path')=='/attest' and
                            e.get('stage')=='RESPONSE' and 'jti' in e.get('attestation',{})]
                    write_json(out/'authority-ledger-reconciliation.json',reconcile(before,after,issued,revoked_jti))
                except Exception as exc:
                    ledger_error={'code':getattr(exc,'code','LEDGER_FAILURE'),'exception_type':type(exc).__name__,
                                  'snapshot':getattr(exc,'snapshot',None),'status':'INCOMPLETE'}
            if ledger_error is not None:write_json(out/'authority-ledger-error.json',ledger_error)
        observed_slots={r['slot'] for r in rows}
        coverage=[dict(s,status='OBSERVED' if s['slot'] in observed_slots else 'NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT') for s in slots]
        
        
        
        per_slot=[r['prediction_agrees'] for r in rows if r['prediction_agrees'] is not None]
        author=None
        if seal is not None:
            from .predictions import score,comparison_scope
            planned={};observations={}
            for s in slots:planned[s['arm']]=planned.get(s['arm'],0)+1
            for r in rows:observations.setdefault(r['arm'],[]).append(r['observation'])
            author=score(seal['predictions'],{a:planned.get(a,0) for a in seal['predictions']},observations)
            
            author['comparison_scope']=comparison_scope(config)
            write_json(out/'author-prediction-score.json',author)
        study_sealed=config['purpose']=='PREREGISTERED_STUDY' and seal is not None
        agrees=(author['status']=='MATCH') if study_sealed else all(per_slot)
        status='PASS' if succeeded and agrees and ledger_error is None else 'FAIL'
        execution_status=status
        if mac_enabled(config) and status=='PASS':status='EXECUTION_COMPLETE_LEDGER_PENDING'
        summary={'status':status,'sequence_completed':succeeded,'rows':rows,'slots':coverage,
            'execution_integrity':'COMPLETE' if succeeded and ledger_error is None else 'INCOMPLETE_OR_FAILED',
            'per_slot_comparison':{'kind':('NONE_SEALED_STUDY' if study_sealed else
                                         'LEGACY_UNSEALED_STUDY_CLASS' if config['purpose']=='PREREGISTERED_STUDY'
                                         else 'DEVELOPMENT_ACCEPTANCE_IMPLIED_BY_CODE_NOT_AUTHOR_PREDICTION'),
                                   'compared':len(per_slot),'agree':sum(per_slot)},
            'author_prediction':author,
            'author_prediction_comparison':(author['comparison_scope']['kind'] if author is not None
                                            else 'NO_SEALED_PREDICTIONS_IN_THIS_RUN'),
            'planned_count':len(slots),'verified_receipt_count':len(rows),
            'population_source_verified':population_verified,
            'prediction_matches':sum(per_slot),'ledger_error':ledger_error,
            'execution_status_before_mac_join':execution_status,
            'ledger_status':'PENDING_MAC_AFTER_CAPTURE' if mac_enabled(config) else 'IN_PROCESS_OR_NOT_APPLICABLE',
            'admin_capture_location':'MAC_EXTERNAL' if mac_enabled(config) else 'RUN_HOST',
            'authority_dispatches':sum(e['stage']=='DISPATCH' for e in events),
            'attest_dispatches':sum(e['stage']=='DISPATCH' and e['path']=='/attest' for e in events),
            'ledger_read_requests':sum(s.get('read_requests',0) for s in (before,after) if s),
            'pacing_sleeps':sum(e['stage']=='PACING_SLEEP' for e in events),
            'purpose':config['purpose'],'mode':config['mode'],'authority':config['authority'],
            'run_role':config.get('run_role','DEVELOPMENT'),'finished_at':time.time(),
            'registered_result':(config['purpose']=='PREREGISTERED_STUDY' and
                config['authority']=='LIVE_SWIFTAPI' and config['mode']=='FRESH_MODEL_EXECUTION')}
        write_json(out/'summary.json',summary)
        try:export_evidence(out)
        except Exception as archive_error:
            write_json(out/'archive-error.json',{'exception_type':type(archive_error).__name__})
            if succeeded:raise
    return summary

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=('run','check','question'))
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--wheel',type=Path)
    for name in ('source','content','harness','out','key-file','approval','primary-archive','predictions','mac-ledger-before'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--arm',choices=SERVICE_ARMS)
    p.add_argument('--key-fd',type=int)
    p.add_argument('--runtime-seed-fd',type=int)
    a=p.parse_args();config=json.loads(a.config.read_text())
    if a.command=='question':
        if not a.out or not a.arm:p.error('question requires --out and --arm')
        report=json.loads((a.out/'summary.json').read_text());rows=report['rows']
        rows=[r for r in rows if r['arm']==a.arm]
        denominator=sum(s['arm']==a.arm for s in report.get('slots',[])) or len(rows)
        for cls in sorted({r['class'] for r in rows}):
            print(result_lines(a.arm,sum(r['class']==cls for r in rows),denominator,cls,mode=config['mode'],
                response_scope=','.join(sorted({r['response_scope'] for r in rows if r['class']==cls})),
                authority_kind=','.join(sorted({r['authority_evidence_kind'] for r in rows if r['class']==cls}))))
        return
    if not a.wheel:p.error('--wheel required')
    validate_config(config,a.wheel,a.predictions)
    if a.command=='check':print('CONFIG_PASS_NO_MODEL_NO_NETWORK');return
    if any(getattr(a,n) is None for n in ('source','content','harness','out')):p.error('run paths required')
    try:
        report=run(config,a.wheel,a.out,a.source,a.content,a.harness,a.key_file,a.approval,a.primary_archive,
                   a.predictions,a.mac_ledger_before,a.key_fd,a.runtime_seed_fd)
        if report['status'] not in ('PASS','EXECUTION_COMPLETE_LEDGER_PENDING'):raise SystemExit(2)
    except Exception as exc:
        print(json.dumps({'status':'FAIL','exception_type':type(exc).__name__,
                          'code':getattr(exc,'code','RUN_FAILED'),'evidence':str(a.out)}))
        raise SystemExit(2) from None

if __name__=='__main__':main()
