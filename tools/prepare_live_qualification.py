
import argparse
import json
from pathlib import Path
import uuid
from swiftapi_native_service.core import canonical,sha,SWIFTAPI_PUBLIC_KEY_B64
from swiftapi_native_service.experiment import SERVICE_ARMS,MODEL,validate_config
from swiftapi_native_service.predictions import parse_predictions,select_for_run
from swiftapi_native_service.service import source_identity
from swiftapi.native_taxonomy import classifier_hash

p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
p.add_argument('--wheel',type=Path,required=True)
p.add_argument('--predictions',type=Path,required=True)
p.add_argument('--predictions-sealed-at',required=True)
p.add_argument('--author-confirmed-sealed',action='store_true',required=True)
a=p.parse_args()
config={'schema':'swiftapi-native-experiment-config/2','purpose':'DEVELOPMENT_QUALIFICATION',
    'sdk_version':'1.4.0','sdk_wheel_sha256':sha(a.wheel.read_bytes()),
    'service_source_sha256':source_identity()['sha256'],'classifier_sha256':classifier_hash(),
    'population':'WITNESS_ONE','schedule':list(SERVICE_ARMS),'repetitions':1,
    'max_grant_age_seconds':60,'max_new_tokens':4,'authority':'LIVE_SWIFTAPI',
    'ledger_capture_mode':'MAC_ADMIN_SIDECAR',
    'mode':'RECORDED_LOGITS_REPLAY','device':'cpu','enable_full_model':False,
    'attention':'SDPA_DEFAULT','authority_public_key':SWIFTAPI_PUBLIC_KEY_B64,
    'pins':json.loads((Path(__file__).resolve().parents[1]/'RUN_CONFIG_PRIMARY.json').read_bytes())['pins'],
    'one_disposable_grant_revocation_approved':True,
    'production_key_revocation_permitted':False,'bank_execution_permitted':False,
    'author_predictions_sha256':sha(a.predictions.read_bytes()),
    'predictions_sealed_at':a.predictions_sealed_at}
config['predictions']=select_for_run(parse_predictions(a.predictions.read_bytes(),MODEL),
                                    config['population'],config['schedule'])[1]
validate_config(config,a.wheel,predictions_file=a.predictions)
a.out.mkdir(parents=True,exist_ok=False)
(a.out/'author-predictions.md').write_bytes(a.predictions.read_bytes())
approval={'approval_id':str(uuid.uuid4()),'config_sha256':sha(canonical(config)),
    'purpose':'DEVELOPMENT_QUALIFICATION','author_approved':True,'maximum_attempts':1,
    'record_kind':'TRANSCRIPTION_OF_EXPLICIT_AUTHOR_AUTHORIZATION_NOT_AUTHOR_SIGNATURE',
    'basis':'One authorized live replay qualification: eleven WITNESS_ONE arms once, REVOKED last, one disposable grant. An error stops execution. No retry.'}
for name,value in [('config.json',config),('approval.json',approval)]:
    (a.out/name).write_bytes(canonical(value)+b'\n')
print(json.dumps({'prepared_only':True,'config_sha256':sha(canonical(config)),
    'authority_requests':0,'revocations':0,'model_forward_passes':0}))
