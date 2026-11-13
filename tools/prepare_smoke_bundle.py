
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import uuid
import zipfile
from swiftapi_native_service.service import source_identity
from swiftapi_native_service.core import canonical,sha
from swiftapi.native_taxonomy import classifier_hash
from runpod_smoke import GPU,DATA_CENTERS

ROOT=Path(__file__).resolve().parents[1]
HARNESS=ROOT.parent/'swiftapi-native-eos-receipts'
IMAGE='runpod/pytorch@sha256:4d1721e62b56d345c83b4fd6090664be6daf9312caab5b2e76f23d8231941851'
REV='64b7bb90b7f8141448292ecad62494b05f1b5aee'

def build(out,wheel,service_wheel,*,predictions,predictions_sealed_at,author_confirmed_sealed):
    if author_confirmed_sealed is not True:raise ValueError('Author must confirm predictions are sealed')
    raw_predictions=Path(predictions).read_bytes()
    seal={'author_predictions_sha256':sha(raw_predictions),'predictions_sealed_at':predictions_sealed_at}
    from swiftapi_native_service.experiment import require_sealed_predictions,MODEL
    from swiftapi_native_service.predictions import parse_predictions,select_for_run
    selected=select_for_run(parse_predictions(raw_predictions,MODEL),'WITNESS_ONE',['VALID','SIGNED_DENIAL'])[1]
    require_sealed_predictions(dict(seal,authority='LOCAL_TEST_DOUBLE',mode='FRESH_MODEL_EXECUTION',
        population='WITNESS_ONE',schedule=['VALID','SIGNED_DENIAL'],repetitions=1,predictions=selected),predictions)
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    source=source_identity()
    with zipfile.ZipFile(service_wheel) as z:
        for name,digest in source['files'].items():
            if sha(z.read('swiftapi_native_service/'+name))!=digest:raise ValueError('Service wheel is stale: '+name)
    files={'author-predictions.md':raw_predictions}
    for path,name in [(wheel,'wheels/'+Path(wheel).name),(service_wheel,'wheels/'+Path(service_wheel).name),
        (ROOT/'requirements-runpod-cu128.lock','requirements-runpod-cu128.lock'),
        (ROOT/'tools/pod_entry.py','tools/pod_entry.py'),(ROOT/'tools/verify_run.py','tools/verify_run.py'),
        (ROOT/'tools/runtime_input_selftest.py','tools/runtime_input_selftest.py'),
        (ROOT/'tools/capture_host.py','tools/capture_host.py'),
        (ROOT/'tools/fetch_pinned_model.py','tools/fetch_pinned_model.py'),
        (ROOT/'pins/model-files.json','pins/model-files.json')]:
        files[name]=Path(path).read_bytes()
    archive=subprocess.check_output(['git','-C',str(HARNESS),'archive','--format=tar',REV])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if member.isfile():files['frozen-harness/'+member.name]=tar.extractfile(member).read()
            elif not member.isdir():raise ValueError('Unexpected harness archive member')
    config={'schema':'swiftapi-native-experiment-config/2','purpose':'DEVELOPMENT_SMOKE',
        'sdk_version':'1.4.0','sdk_wheel_sha256':sha(Path(wheel).read_bytes()),
        'service_source_sha256':source['sha256'],'classifier_sha256':classifier_hash(),
        'population':'WITNESS_ONE','schedule':['VALID','SIGNED_DENIAL'],'repetitions':1,
        'max_grant_age_seconds':60,'max_new_tokens':4,'authority':'LOCAL_TEST_DOUBLE',
        'mode':'FRESH_MODEL_EXECUTION','device':'cuda','enable_full_model':True,
        'attention':'SDPA_MATH_DETERMINISTIC','maximum_warm_forward_seconds':10,
        'image_digest':IMAGE.split('@')[1],'gpu_type_id':GPU,'data_center_ids':DATA_CENTERS,'spend_cap_usd':2,
        'production_authority_credentials_permitted':False,'predictions':selected,**seal}
    require_sealed_predictions(config,predictions)
    approval={'approval_id':str(uuid.uuid4()),'config_sha256':sha(canonical(config)),
        'purpose':'DEVELOPMENT_SMOKE','author_approved':True,'maximum_attempts':1,
        'record_kind':'TRANSCRIPTION_OF_EXPLICIT_AUTHOR_AUTHORIZATION_NOT_AUTHOR_SIGNATURE',
        'basis':'One authorized development execution on a secure GPU with at least 24 GB VRAM and 32 GB host RAM, maximum USD 2, local test authority only'}
    files['smoke-config.json']=canonical(config);files['smoke-approval.json']=canonical(approval)
    manifest={'purpose':'DEVELOPMENT_SMOKE','secrets_included':False,'files':{n:sha(b) for n,b in files.items()},
              'harness_commit':REV,'sdk_sha256':config['sdk_wheel_sha256'],'service_source_sha256':source['sha256']}
    files['bundle-manifest.json']=canonical(manifest)
    with tarfile.open(out/'smoke-bundle.tar.gz','x:gz') as tar:
        for name,raw in sorted(files.items()):
            if name.startswith('/') or '..' in Path(name).parts:raise ValueError('Invalid bundle path')
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;tar.addfile(info,io.BytesIO(raw))
    report={'purpose':'DEVELOPMENT_SMOKE','file_count':len(files),'bytes':(out/'smoke-bundle.tar.gz').stat().st_size,
            'sha256':sha((out/'smoke-bundle.tar.gz').read_bytes()),'config':config,'image':IMAGE,
            'swiftapi_key_included':False,'runpod_key_included':False,'pod_created':False}
    (out/'author-predictions.md').write_bytes(raw_predictions)
    (out/'bundle.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    p.add_argument('--wheel',type=Path,required=True);p.add_argument('--service-wheel',type=Path,required=True)
    p.add_argument('--predictions',type=Path,required=True)
    p.add_argument('--predictions-sealed-at',required=True)
    p.add_argument('--author-confirmed-sealed',action='store_true',required=True)
    a=p.parse_args();print(json.dumps(build(a.out,a.wheel,a.service_wheel,predictions=a.predictions,
        predictions_sealed_at=a.predictions_sealed_at,author_confirmed_sealed=a.author_confirmed_sealed)))
