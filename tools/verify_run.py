
import argparse
import hashlib
import json
from pathlib import Path
from swiftapi.native_verify import verify_receipt

MODEL='sharthokrayanpal/PCCG-2-Qwen3-4B@a3b952458a46b5547ba3cec7d03a37b395bed03a'

def exact(left,right):
    return json.dumps(left,sort_keys=True,allow_nan=False)==json.dumps(right,sort_keys=True,allow_nan=False)

def verify_predictions(root,config,summary,payloads):
    pass
    if config.get('authority')!='LIVE_SWIFTAPI' and config.get('mode')!='FRESH_MODEL_EXECUTION':
        return {'status':'NOT_APPLICABLE_UNSEALED_LOCAL_REPLAY'}
    from swiftapi_native_service.predictions import parse_predictions,select_for_run,score,comparison_scope
    raw=(root/'sealed-predictions.md').read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=config.get('author_predictions_sha256'):raise ValueError('Sealed prediction bytes mismatch')
    parsed=parse_predictions(raw,MODEL)
    run,selected=select_for_run(parsed,config.get('population','WITNESS_ONE'),config['schedule'])
    if not exact(selected,config.get('predictions')):raise ValueError('Prediction configuration mismatch')
    declared=json.loads((root/'sealed-predictions-parsed.json').read_bytes())
    expected={'author_predictions_sha256':digest,'PRIMARY':parsed['PRIMARY'],'SECONDARY':parsed['SECONDARY'],
              'run':run,'selected_for_this_run':selected}
    if not exact(declared,expected):raise ValueError('Parsed prediction record mismatch')
    seal=json.loads((root/'predictions-seal.json').read_bytes())
    if (seal.get('author_predictions_sha256')!=digest or
            seal.get('predictions_sealed_at')!=config.get('predictions_sealed_at') or
            not exact(seal.get('predictions'),selected)):
        raise ValueError('Prediction seal record mismatch')
    if type(config.get('repetitions')) is not int or config['repetitions']!=1:
        raise ValueError('Sealed prediction denominator mismatch')
    count=188 if config.get('population')=='BANK_188' else 1
    schedule=config['schedule']
    if len(set(schedule))!=len(schedule):raise ValueError('Repeated scheduled arm')
    expected_slots={i:(arm,qi) for i,(qi,arm) in enumerate((qi,arm) for qi in range(count) for arm in schedule)}
    if summary['planned_count']!=len(expected_slots):raise ValueError('Declared schedule denominator mismatch')
    seen_slots=set();seen_paths=set();seen_executions=set();observations={}
    for row in summary['rows']:
        slot=row['slot'];arm=row['arm'];relative=row['receipt']
        if type(slot) is not int or slot in seen_slots or expected_slots.get(slot)!=(arm,row['question_index']):
            raise ValueError('Receipt slot identity mismatch')
        if relative!=f'receipts/{slot:04}-{arm}/receipt.json' or relative in seen_paths or relative not in payloads:
            raise ValueError('Receipt path mapping mismatch')
        payload=payloads[relative]
        if payload['execution_id'] in seen_executions:raise ValueError('Repeated execution identity')
        action=payload.get('action')
        if isinstance(action,dict) and 'request' in action:
            if not exact(row.get('question'),action['request'].get('question')):
                raise ValueError('Summary question differs from signed action')
        seen_slots.add(slot);seen_paths.add(relative);seen_executions.add(payload['execution_id'])
        result=payload.get('result') or {}
        observation={'class':payload['taxonomy']['class'],'output_bytes':len(payload['output'].encode('utf-8')),
            'first_token':(result.get('generated_token_ids') or [None])[0],
            'generation_complete':result.get('generation_complete')}
        if not exact(row.get('observation'),observation):raise ValueError('Summary observation differs from signed receipt')
        observations.setdefault(arm,[]).append(observation)
    if seen_paths!=set(payloads):raise ValueError('Receipt omitted from prediction scoring')
    actual=score(selected,{arm:count for arm in schedule},observations)
    actual['comparison_scope']=comparison_scope(config)
    recorded=json.loads((root/'author-prediction-score.json').read_bytes())
    if not exact(recorded,actual) or not exact(summary.get('author_prediction'),actual):
        raise ValueError('Recorded prediction score differs from reconstruction')
    return {'status':'VERIFIED','author_predictions_sha256':digest,'run':run,'score':actual}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--expected-mode',required=True)
    p.add_argument('--expected-purpose',required=True)
    p.add_argument('--authority-kind',choices=('LOCAL_TEST_DOUBLE','LIVE_SWIFTAPI'),required=True)
    p.add_argument('--expected-max-grant-age-seconds',type=int,required=True);a=p.parse_args()
    runtime=json.loads((a.run/'runtime-public.json').read_bytes())
    authority=json.loads((a.run/'authority-public.json').read_bytes())
    config=json.loads((a.run/'run-config.json').read_bytes())
    if config['purpose']!=a.expected_purpose or config['authority']!=a.authority_kind:raise ValueError('Evidence kind mismatch')
    if a.authority_kind=='LIVE_SWIFTAPI':
        from swiftapi.verifier import SWIFTAPI_PUBLIC_KEY_B64
        if authority['public_key']!=SWIFTAPI_PUBLIC_KEY_B64:raise ValueError('Wrong live authority')
    files=[];payloads={}
    for path in sorted((a.run/'receipts').glob('*/receipt.json')):
        payload=json.loads(path.read_bytes())['payload']
        if payload['purpose']!=a.expected_purpose:raise ValueError('Receipt purpose mismatch')
        result=verify_receipt(path,runtime['public_key'],a.expected_mode,authority_key=authority['public_key'],
                             expected_max_grant_age_seconds=a.expected_max_grant_age_seconds)
        payloads[str(path.relative_to(a.run))]=payload
        files.append({'receipt':str(path.relative_to(a.run)),'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                      'result':result,'class':payload['taxonomy']['class']})
    summary=json.loads((a.run/'summary.json').read_bytes())
    if len(files)!=summary['verified_receipt_count']:raise ValueError('Receipt denominator mismatch')
    prediction_verification=verify_predictions(a.run,config,summary,payloads)
    from swiftapi_native_service.mac_ledger import enabled,verify_join
    ledger={'status':'NOT_APPLICABLE'}
    if enabled(config):
        
        names=('run-config.json','summary.json','attempt.json','mac-ledger-before.json',
               'mac-ledger-after.json','mac-ledger-finalization.json','authority-ledger-reconciliation.json')
        data={n:(a.run/n).read_bytes() for n in names if (a.run/n).is_file()}
        for directory,pattern in [('authority-dispatches','*.json'),('receipts','*/*.json')]:
            data.update({str(p.relative_to(a.run)):p.read_bytes() for p in (a.run/directory).glob(pattern)})
        data.update({str(p.relative_to(a.run)):p.read_bytes() for p in a.run.glob('revocation-*.json')})
        ledger=verify_join(data,config,summary)
    overall='RECEIPTS_VERIFIED_LEDGER_PENDING' if ledger['status']=='PENDING_MAC_AFTER_CAPTURE' else 'PASS'
    report={'verifier':'INSTALLED_SWIFTAPI_SDK_NO_TORCH','trust':'Supplied public anchors; software claims, not host attestation',
            'status':overall,'expected_purpose':a.expected_purpose,'expected_mode':a.expected_mode,
            'verified_receipts':len(files),'planned_count':summary['planned_count'],'receipts':files,
            'prediction_verification':prediction_verification,'mac_ledger':ledger}
    with a.out.open('x') as out:json.dump(report,out,indent=2)
    print(json.dumps({'status':overall,'verified_receipts':len(files),'planned_count':summary['planned_count']}))

if __name__=='__main__':main()
