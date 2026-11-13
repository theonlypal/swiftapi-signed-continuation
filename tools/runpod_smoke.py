
import argparse
import base64
from datetime import datetime,timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import tarfile
import time
import requests

API='https://api.runpod.io/v2'
IMAGE='runpod/pytorch@sha256:4d1721e62b56d345c83b4fd6090664be6daf9312caab5b2e76f23d8231941851'
GPU='NVIDIA A40'
DATA_CENTERS=['EU-SE-1']
DEADLINE_SECONDS=1800
STARTUP_SECONDS=900
CLEANUP_RESERVE_SECONDS=180
MAX_COMPUTE_PER_HOUR=.80
ROOT=Path(__file__).resolve().parents[1]
DEFAULT_CLAIM=Path.home()/'.local/state/swiftapi-native/development-smoke/allocation.json'

def now():return datetime.now(timezone.utc).isoformat()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    with Path(path).open('x') as out:json.dump(value,out,indent=2)

def key_from_existing(path):
    raw=Path(path).read_text().strip();tokens=re.findall(r'rpa_[A-Za-z0-9_-]+',raw)
    if len(tokens)==1:return tokens[0]
    if len(raw.split())==1 and raw:return raw
    raise ValueError('RunPod credential format not recognized; content withheld')

class APIError(Exception):
    def __init__(self,status,retry_after=None):
        self.status=status;self.retry_after=retry_after
        super().__init__('RunPod HTTP '+str(status))

class TransportError(RuntimeError):
    pass

class CommandPending(RuntimeError):
    pass


def poll(operation,deadline,*,event_sink=None,label='READINESS'):
    """Poll a read-only or idempotent operation; workload launch is excluded."""
    attempt=0
    while time.time()<deadline:
        try:return operation()
        except (APIError,TransportError,CommandPending) as exc:
            if isinstance(exc,APIError) and exc.status not in (404,409,429,500,502,503,504):raise
            attempt+=1
            delay=min(30,2**min(attempt,5))
            try:hint=float(getattr(exc,'retry_after',None))
            except (TypeError,ValueError):hint=None
            if hint is not None and math.isfinite(hint) and hint>=0:delay=max(delay,min(60,hint))
            delay=min(delay,deadline-time.time())
            if delay<=0:break
            row={'at':now(),'stage':label,'status':getattr(exc,'status',type(exc).__name__),
                 'sleep_seconds':delay,'workload_retry':False}
            if event_sink:event_sink(row)
            time.sleep(delay)
    raise TimeoutError(label+' deadline')

class RunPod:
    def __init__(self,key,event_sink=None):
        self.key=key;self.transport=requests.Session();self.transport.trust_env=False
        self.next_dispatch=0;self.event_sink=event_sink
    def event(self,row):
        if self.event_sink:self.event_sink(dict(row,at=now()))
    def call(self,method,path,**kwargs):
        
        
        delay=max(0,self.next_dispatch-time.time()) if method!='DELETE' else 0
        if delay:
            self.event({'stage':'PACING_SLEEP','seconds':delay,'path':path});time.sleep(delay)
        try:r=self.transport.request(method,API+path,headers={'Authorization':'Bearer '+self.key},
            timeout=40,allow_redirects=False,**kwargs)
        except requests.RequestException:raise TransportError('RunPod transport error; credential withheld') from None
        headers={name:r.headers[name] for name in ('RateLimit','RateLimit-Policy','Retry-After','Date') if name in r.headers}
        self.event({'stage':'RESPONSE','method':method,'path':path,'status':r.status_code,'headers':headers})
        self.next_dispatch=time.time()+1
        
        for quota in headers.get('RateLimit','').split(','):
            remaining=re.search(r'(?:^|;)\s*r=(\d+)',quota)
            reset=re.search(r'(?:^|;)\s*t=(\d+)',quota)
            if remaining and reset and int(remaining[1])<=5:
                self.next_dispatch=max(self.next_dispatch,time.time()+int(reset[1])+1)
        if not 200<=r.status_code<300:raise APIError(r.status_code,headers.get('Retry-After'))
        body=r.json() if r.content else None
        if self.key in json.dumps(body):raise RuntimeError('Credential echoed; response not retained')
        return body
    def execute(self,pod,argv,timeout=20):
        if any(len(a)>4096 for a in argv) or len(argv)>256:raise ValueError('Exec argument limit')
        result=self.call('POST','/pods/'+pod+'/exec',json={'command':argv,'timeoutSeconds':timeout})
        if result.get('timedOut'):raise CommandPending('Remote command still running')
        if result.get('truncated') or result.get('exitCode')!=0:
            raise RuntimeError('Remote command did not complete successfully')
        return result['stdout']

def wait_exec_ready(api,pod,deadline,out):
    observations=[]
    try:
        result=poll(lambda:api.execute(pod,['python3','-c',
            'import sys,ensurepip,json;print(json.dumps({"python":sys.version,"ensurepip":ensurepip.version()}))']),
            deadline,event_sink=observations.append,label='EXEC_READINESS')
        return json.loads(result)
    finally:
        save(out/'exec-readiness.json',{'status':'READY' if 'result' in locals() else 'DEADLINE_OR_ERROR','waits':observations})


def safe_exec(api,pod,argv,deadline,label):
    return poll(lambda:api.execute(pod,argv),deadline,event_sink=getattr(api,'event',None),label=label)


def launch_once(api,pod,deadline):
    code=("import subprocess,os;from pathlib import Path;p=Path('/workspace/native-smoke');"
          "f=(p/'launcher.log').open('xb');env=dict(os.environ,SWIFTAPI_DEVELOPMENT_DEADLINE='"+str(deadline-300)+"');"
          "x=subprocess.Popen(['python3',str(p/'tools/pod_entry.py')],stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True);"
          "(p/'workload.pid').write_text(str(x.pid));print(x.pid)")
    try:return int(api.execute(pod,['python3','-c',code]).strip())
    except (TransportError,CommandPending,APIError) as exc:
        if isinstance(exc,APIError) and exc.status not in (500,502,503,504):raise
        def observe():
            value=api.execute(pod,['python3','-c',"from pathlib import Path;p=Path('/workspace/native-smoke/workload.pid');print(p.read_text() if p.exists() else 'PENDING')"]).strip()
            if value=='PENDING':raise CommandPending('Awaiting workload acknowledgement')
            return int(value)
        return poll(observe,min(deadline-CLEANUP_RESERVE_SECONDS,time.time()+90),
                    event_sink=getattr(api,'event',None),label='LAUNCH_ACKNOWLEDGEMENT')

def safe_pod(body):
    return {k:body.get(k) for k in ('id','name','status','image','disk','cloud','dataCenterId',
            'cudaVersion','cost','createdAt','startedAt','gpu')}

def destroy(api,pod,out,label):
    pass
    records=[]
    for attempt in range(5):
        row={'at':now(),'attempt':attempt+1,'pod_id':pod}
        try:
            try:api.call('DELETE','/pods/'+pod);row['delete']='204'
            except APIError as exc:
                row['delete_status']=exc.status
                if exc.status!=404:raise
            try:api.call('GET','/pods/'+pod);row['still_exists']=True
            except APIError as exc:
                row['get_status']=exc.status
                if exc.status==404:
                    records.append(row);save(out/(label+'-destroy-confirmed.json'),{'gone':True,'pod_id':pod,'records':records})
                    return True
                raise
        except Exception as exc:row['exception_type']=type(exc).__name__
        records.append(row);time.sleep(10)
    save(out/(label+'-destroy-unconfirmed.json'),{'gone':False,'pod_id':pod,'records':records});return False

def watchdog(key,out,name,deadline):
    pass
    pid=os.fork()
    if pid:return pid
    try:
        os.setsid()
        null=os.open(os.devnull,os.O_RDWR)
        for descriptor in (0,1,2):os.dup2(null,descriptor)
        api=RunPod(key)
        while time.time()<deadline:
            if (out/'parent-destroy-confirmed.json').exists():os._exit(0)
            time.sleep(10)
        pod=None
        if (out/'created.json').exists():pod=json.loads((out/'created.json').read_bytes())['id']
        else:
            
            matches=pod_ids_named(api,name)
            if len(matches)==1:pod=matches[0]
        if pod:destroy(api,pod,out,'watchdog')
        else:save(out/'watchdog-no-pod-found.json',{'at':now(),'name':name})
    except Exception as exc:
        try:save(out/'watchdog-error.json',{'at':now(),'exception_type':type(exc).__name__})
        except Exception:pass
    os._exit(0)

def upload(api,pod,bundle,deadline):
    chunks=[bundle[i:i+150000] for i in range(0,len(bundle),150000)]
    for i,raw in enumerate(chunks):
        encoded=base64.b64encode(raw).decode()
        code=("import sys,base64,fcntl,hashlib;from pathlib import Path;"
              "p=Path('/workspace/native-smoke-bundle.tar.gz');f=p.open('r+b' if p.exists() else 'w+b');"
              "fcntl.flock(f,fcntl.LOCK_EX);offset=int(sys.argv[1]);raw=base64.b64decode(''.join(sys.argv[3:]));"
              "assert hashlib.sha256(raw).hexdigest()==sys.argv[2];assert p.stat().st_size>=offset;"
              "f.seek(offset);f.write(raw);f.flush();f.seek(offset);assert f.read(len(raw))==raw;f.close()")
        safe_exec(api,pod,['python3','-c',code,str(i*150000),sha(raw),
            *[encoded[j:j+3500] for j in range(0,len(encoded),3500)]],deadline,'UPLOAD_CHUNK')
    code=("import hashlib,tarfile,fcntl;from pathlib import Path;"
          "p=Path('/workspace/native-smoke-bundle.tar.gz');assert hashlib.sha256(p.read_bytes()).hexdigest()=='"+sha(bundle)+"';"
          "lock=Path('/workspace/native-smoke-extract.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX);"
          "d=Path('/workspace/native-smoke');d.mkdir(exist_ok=True);marker=d/'.bundle-sha256';"
          "tarfile.open(p).extractall(d,filter='data') if not marker.exists() else None;"
          "marker.write_text('"+sha(bundle)+"') if not marker.exists() else None;"
          "assert marker.read_text()=='"+sha(bundle)+"';print('BUNDLE_VERIFIED')")
    return safe_exec(api,pod,['python3','-c',code],deadline,'EXTRACT_BUNDLE')

def pull(api,pod,out,deadline):
    remote='/workspace/native-smoke/'
    meta=json.loads(safe_exec(api,pod,['python3','-c',"from pathlib import Path;print(Path('"+remote+"development-export.json').read_text())"],deadline,'EVIDENCE_METADATA'))
    if type(meta.get('bytes')) is not int or not 0<meta['bytes']<=512*1024**2:raise ValueError('Invalid evidence size')
    data=bytearray()
    for offset in range(0,meta['bytes'],300000):
        code="from pathlib import Path;import base64;p=Path('"+remote+"development-evidence.tar.gz');f=p.open('rb');f.seek("+str(offset)+");print(base64.b64encode(f.read(300000)).decode())"
        data.extend(base64.b64decode(safe_exec(api,pod,['python3','-c',code],deadline,'EVIDENCE_CHUNK').strip(),validate=True))
    if len(data)!=meta['bytes'] or sha(data)!=meta['sha256']:raise ValueError('Downloaded evidence hash mismatch')
    (out/'development-evidence.tar.gz').write_bytes(data);save(out/'remote-export.json',meta)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:archive.extractall(out/'evidence',filter='data')
    return meta

def current_inventory(api,query,snapshot=None):
    if snapshot is None:return api.call('GET','/catalog/gpus',params=query)
    if (set(snapshot)!={'queried_at_monotonic','query','body'}
            or snapshot['query']!=query
            or type(snapshot['queried_at_monotonic']) not in (int,float)
            or not 0<=time.monotonic()-snapshot['queried_at_monotonic']<=30):
        raise ValueError('Inventory must be from the same selection within thirty seconds')
    return snapshot['body']

def run(bundle_dir,out,key_file,*,inventory_snapshot=None,api_connection=None,authorization=None):
    bundle_dir=Path(bundle_dir);out=Path(out)
    meta=json.loads((bundle_dir/'bundle.json').read_bytes());bundle=(bundle_dir/'smoke-bundle.tar.gz').read_bytes()
    if sha(bundle)!=meta['sha256'] or meta['config']['purpose']!='DEVELOPMENT_SMOKE':raise ValueError('Wrong smoke bundle')
    if (meta['config']['authority']!='LOCAL_TEST_DOUBLE' or meta['image']!=IMAGE
            or meta['config'].get('gpu_type_id')!=GPU
            or meta['config'].get('data_center_ids')!=DATA_CENTERS):
        raise ValueError('Forbidden smoke profile')
    
    
    from swiftapi_native_service.experiment import require_sealed_predictions
    require_sealed_predictions(meta['config'],bundle_dir/'author-predictions.md')
    with tarfile.open(fileobj=io.BytesIO(bundle)) as sealed_bundle:
        inner=json.load(sealed_bundle.extractfile('smoke-config.json'))
        if json.dumps(inner,sort_keys=True,allow_nan=False)!=json.dumps(meta['config'],sort_keys=True,allow_nan=False):
            raise ValueError('Outer and bundled smoke configurations differ')
        predictions=sealed_bundle.extractfile('author-predictions.md').read()
        if not predictions or sha(predictions)!=inner['author_predictions_sha256']:
            raise ValueError('Smoke bundle predictions do not match the author seal')
    body=create_body('swiftapi-development-smoke-'+meta['sha256'][:12])
    schema_check=validate_provider_schema(body)
    out.mkdir(parents=True,exist_ok=False)
    save(out/'provider-schema-validation.json',schema_check)
    api=api_connection if api_connection is not None else RunPod(key_from_existing(key_file))
    key=api.key
    dispatches=[]
    def observe(event):
        folder=out/'provider-dispatches';folder.mkdir(exist_ok=True)
        save(folder/f'{len(dispatches):05}.json',event);dispatches.append(event)
    api.event_sink=observe
    
    query={'include':'AVAILABILITY','product':'POD','cloud':'SECURE','count':1,'minCudaVersion':'12.8'}
    inventory=current_inventory(api,query,inventory_snapshot)
    save(out/'gpu-inventory.json',inventory)
    choices=qualifying_gpus(inventory)
    if not choices or choices[0]['id']!=GPU:
        result={'purpose':'DEVELOPMENT_SMOKE','status':'NOT_EXECUTED',
            'code':'SELECTED_GPU_NOT_CURRENT_CHEAPEST','gpu_type_id':GPU,
            'cheapest_qualifying_id':choices[0]['id'] if choices else None,
            'checked_at':now(),'pod_created':False,'allocation_requests':0,'compute_spend_usd':0}
        save(out/'outcome.json',result);print(json.dumps(result));return 2
    catalog=api.call('GET','/catalog/gpus/'+requests.utils.quote(GPU,safe=''),params=query)
    save(out/'catalog.json',catalog)
    if catalog.get('id')!=GPU or catalog.get('price',{}).get('secure',100)>MAX_COMPUTE_PER_HOUR:
        raise ValueError('Read-only catalog exceeds selected GPU/price bound; no allocation')
    if catalog.get('availability') not in ('LOW','MEDIUM','HIGH'):
        result={'purpose':'DEVELOPMENT_SMOKE','status':'NOT_EXECUTED',
            'code':'GPU_CAPACITY_UNAVAILABLE','gpu_type_id':GPU,'checked_at':now(),
            'pod_created':False,'allocation_requests':0,'compute_spend_usd':0,
            'authority_requests':0,'model_forward_passes':0}
        save(out/'outcome.json',result)
        print(json.dumps(result));return 2
    available_centers={p['id'] for p in catalog.get('dataCenters',[])
                       if p.get('availability') in ('LOW','MEDIUM','HIGH')}
    if (catalog.get('secure') is not True or catalog.get('memory',0)<24
            or catalog.get('minRam',0)<32 or not available_centers.intersection(DATA_CENTERS)):
        raise ValueError('Read-only catalog does not establish selected memory/location; no allocation')
    reserved=(MAX_COMPUTE_PER_HOUR+60*.10/720)*(DEADLINE_SECONDS+120)/3600+.05
    budget=reserve_attempt(authorization,out,reserved) if authorization else None
    save(out/'budget.json',{'cap_usd':2,'max_compute_rate_usd_h':MAX_COMPUTE_PER_HOUR,
        'disk_gb':60,'disk_usd_h':60*.10/720,'deadline_seconds':DEADLINE_SECONDS,
        'estimated_compute_plus_disk_at_deadline':(MAX_COMPUTE_PER_HOUR+60*.10/720)*DEADLINE_SECONDS/3600,
        'combined_budget':budget,'reserved_for_this_attempt_usd':reserved,
        'provider_enforced_cap':False,'mechanism':'Parent finally plus precreated detached deadline watchdog',
        'tax_and_provider_error_caveat':'Recorded actual billing governs; no claim of guaranteed cap during loss of both cleanup paths'})
    claim=out/'allocation-claim.json' if authorization else DEFAULT_CLAIM
    claim.parent.mkdir(parents=True,exist_ok=True)
    with claim.open('x') as f:json.dump({'started_at':now(),'bundle_sha256':meta['sha256'],'output':str(out)},f)
    name='swiftapi-development-smoke-'+meta['sha256'][:12]
    start=time.time();deadline=start+DEADLINE_SECONDS
    watcher=watchdog(key,out,name,deadline)
    save(out/'watchdog.json',{'pid':watcher,'deadline_epoch':start+DEADLINE_SECONDS,'secret_written':False})
    pod=None;pull_attempted=False;creation_refused=False
    result={'purpose':'DEVELOPMENT_SMOKE','started_at':now(),'status':'FAIL','retry_permitted':False}
    try:
        save(out/'create-request.json',body)
        try:created=api.call('POST','/pods',json=body)
        except APIError as exc:
            creation_refused=exc.status in (400,401,403,404,409,422,429)
            raise
        pod=created['id'];save(out/'created.json',safe_pod(created))
        result['pod_id']=pod
        if created.get('cost',100)>MAX_COMPUTE_PER_HOUR:raise RuntimeError('Allocated rate exceeds approved rate ceiling')
        if created.get('gpu',{}).get('id')!=GPU:raise RuntimeError('Unexpected allocated GPU type')
        index=0
        while time.time()<min(deadline-CLEANUP_RESERVE_SECONDS,start+STARTUP_SECONDS):
            state=poll(lambda:api.call('GET','/pods/'+pod),min(deadline-CLEANUP_RESERVE_SECONDS,start+STARTUP_SECONDS),
                       event_sink=api.event if hasattr(api,'event') else None,label='POD_STARTUP')
            save(out/f'pod-state-{index:03}.json',safe_pod(state));index+=1
            if state['status']=='RUNNING':break
            if state['status'] in ('EXITED','ERROR','TERMINATED'):raise RuntimeError('Pod did not start')
            time.sleep(10)
        else:raise TimeoutError('Pod startup deadline')
        
        probe=wait_exec_ready(api,pod,min(deadline-CLEANUP_RESERVE_SECONDS,start+STARTUP_SECONDS),out)
        save(out/'image-python-preflight.json',probe)
        upload(api,pod,bundle,deadline-CLEANUP_RESERVE_SECONDS)
        pid=launch_once(api,pod,deadline);save(out/'remote-process.json',{'pid':pid,'at':now()})
        while time.time()<deadline-CLEANUP_RESERVE_SECONDS:
            code="from pathlib import Path;p=Path('/workspace/native-smoke/DONE.json');print(p.read_text() if p.exists() else 'RUNNING')"
            status=safe_exec(api,pod,['python3','-c',code],deadline-CLEANUP_RESERVE_SECONDS,'WORKLOAD_STATUS').strip()
            if status!='RUNNING':
                save(out/'remote-status.json',json.loads(status));pull_attempted=True
                result.update(pull(api,pod,out,deadline-60));break
            time.sleep(15)
        else:raise TimeoutError('Development run deadline')
    except Exception as exc:
        result.update(exception_type=type(exc).__name__,error=str(exc),failed_at=now())
        
        if pod:
            if not pull_attempted:
                try:
                    status=safe_exec(api,pod,['python3','-c',
                        "from pathlib import Path;p=Path('/workspace/native-smoke/DONE.json');print(p.read_text() if p.exists() else 'INCOMPLETE')"],
                        min(deadline-30,time.time()+30),'ERROR_STATUS').strip()
                    if status!='INCOMPLETE':
                        pull_attempted=True
                        result['error_evidence_export']=pull(api,pod,out,deadline-30)
                except Exception as e:result['error_evidence_error']=type(e).__name__
            try:
                code="from pathlib import Path;import json;p=Path('/workspace/native-smoke');print(json.dumps({str(f.relative_to(p)):f.read_text(errors='replace')[-15000:] for f in [p/'launcher.log',*list((p/'development-evidence').glob('*.log'))] if f.exists()}))"
                save(out/'error-logs.json',json.loads(safe_exec(api,pod,['python3','-c',code],
                    min(deadline-15,time.time()+30),'ERROR_LOGS')))
            except Exception as e:result['error_log_error']=type(e).__name__
    finally:
        if pod is None:
            try:
                matches=pod_ids_named(api,name)
                if len(matches)==1:pod=matches[0];result['pod_id']=pod
                elif len(matches)==0:save(out/'creation-no-pod-observed.json',{'at':now(),'name':name,
                    'definitive_refusal':creation_refused})
            except Exception as exc:result['ambiguous_creation_check']=type(exc).__name__
        if pod:result['destroy_confirmed']=destroy(api,pod,out,'parent')
        else:result['destroy_confirmed']=False
        result['finished_at']=now();result['elapsed_seconds']=time.time()-start
        if pod:
            try:save(out/'provider-billing.json',api.call('GET','/billing/pods',params={'podId':pod,'lastN':1,'bucketSize':'day'}))
            except Exception as exc:result['billing_status']='UNAVAILABLE_'+type(exc).__name__
        save(out/'outcome.json',result)
    print(json.dumps(result));return 0 if result.get('status')=='PASS' and result.get('destroy_confirmed') else 2


def reserve_attempt(authorization,out,reserved):
    """Reserve an allocation against the complete, explicit development allowance."""
    path=Path(authorization).resolve();record=json.loads(path.read_bytes())
    if (record.get('purpose')!='DEVELOPMENT_SMOKE' or record.get('cap_usd')!=2
            or (record.get('maximum_total_attempts'),record.get('prior_attempts')) not in ((3,1),(6,3))
            or not .01<=record.get('prior_spend_reserved_usd',0)<=2):
        raise ValueError('Invalid bounded smoke authorization')
    claims=path.parent/(path.stem+'-claims');claims.mkdir(exist_ok=True)
    rows=[json.loads(p.read_bytes()) for p in claims.glob('*.json')]
    def cleared(row):
        folder=Path(row['output'])
        gone=folder/'parent-destroy-confirmed.json'
        absent=folder/'creation-no-pod-observed.json'
        return ((gone.exists() and json.loads(gone.read_bytes()).get('gone') is True)
                or (absent.exists() and json.loads(absent.read_bytes()).get('definitive_refusal') is True))
    if any(not cleared(r) for r in rows):
        raise ValueError('A smoke pod requires confirmed destruction before another allocation')
    count=record['prior_attempts']+len(rows)
    committed=record['prior_spend_reserved_usd']+sum(r['reserved_usd'] for r in rows)
    if count>=record['maximum_total_attempts'] or committed+reserved>record['cap_usd']:
        raise ValueError('Combined smoke attempt or spending allowance exhausted')
    row={'attempt':count+1,'output':str(out.resolve()),'reserved_usd':reserved,
         'combined_reserved_usd':committed+reserved,'authorization_sha256':sha(path.read_bytes()),'at':now()}
    save(claims/f'{count+1:02}.json',row)
    return row

def qualifying_gpus(inventory):
    rows=inventory.get('gpus',[]) if isinstance(inventory,dict) else inventory
    return sorted((p for p in rows if p.get('manufacturer')=='NVIDIA'
        and p.get('secure') is True and p.get('memory',0)>=24 and p.get('minRam',0)>=32
        and p.get('availability') in ('LOW','MEDIUM','HIGH')
        and 0<p.get('price',{}).get('secure',0)
        and any(d.get('availability') in ('LOW','MEDIUM','HIGH') for d in p.get('dataCenters',[]))),
        key=lambda p:(p['price']['secure'],p['id']))

def pod_ids_named(api,name):
    ids=[];cursor=None;seen=set()
    while True:
        params={'limit':1000}
        if cursor is not None:params['cursor']=cursor
        body=api.call('GET','/pods',params=params)
        items=body.get('pods',[]) if isinstance(body,dict) else body
        ids.extend(p['id'] for p in items if p.get('name')==name)
        page=body.get('pagination',{}) if isinstance(body,dict) else {}
        if not page.get('hasNextPage'):return list(dict.fromkeys(ids))
        cursor=page.get('nextCursor')
        if not isinstance(cursor,str) or not cursor or cursor in seen:
            raise RuntimeError('Invalid pod pagination cursor')
        seen.add(cursor)

def create_body(name):
    return {'name':name,'image':IMAGE,'gpu':{'id':GPU,'count':1,'minRamPerGpu':32,
        'minVcpuCountPerGpu':4,'minCudaVersion':'12.8'},'cloud':'SECURE','dataCenterIds':DATA_CENTERS,
        'disk':60,'ports':[],'startSsh':False,'startJupyter':False,
        'entrypoint':['/bin/bash','-lc'],'cmd':['sleep infinity'],
        'env':{'HF_HUB_DISABLE_IMPLICIT_TOKEN':'1','HF_HUB_DISABLE_TELEMETRY':'1'}}

def validate_provider_schema(body):
    pass
    from jsonschema import Draft202012Validator
    path=Path(__file__).resolve().parents[1]/'pins/runpod-api.json'
    raw=path.read_bytes();document=json.loads(raw)
    for ref,instance in [('CreatePodRequest',body),
            ('PodExecRequest',{'command':['python3','-c','print(1)'],'timeoutSeconds':20})]:
        schema={'$ref':'#/components/schemas/'+ref,'components':document['components']}
        Draft202012Validator(schema).validate(instance)
    if '/v2/pods/{id}/exec' not in document['paths']:raise ValueError('Exec absent from saved provider schema')
    return {'status':'PASS','schema_sha256':sha(raw),'schema_url':'https://api.runpod.io/v2/openapi.json',
        'create_body_valid':True,'exec_body_valid':True,'pod_created':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--runpod-key-file',type=Path,required=True)
    p.add_argument('--execute-one-approved-development-smoke',action='store_true',required=True)
    a=p.parse_args();raise SystemExit(run(a.bundle,a.out,a.runpod_key_file))
