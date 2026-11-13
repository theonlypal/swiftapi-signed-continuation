
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'development-evidence'
DEADLINE=None


def locked_environment(parent):
    env=dict(parent,HF_HUB_DISABLE_IMPLICIT_TOKEN='1',HF_HUB_DISABLE_TELEMETRY='1',
             PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',OMP_NUM_THREADS='4',MKL_NUM_THREADS='4',
             CUBLAS_WORKSPACE_CONFIG=':4096:8',PIP_DISABLE_PIP_VERSION_CHECK='1',
             PIP_NO_INPUT='1',PIP_RETRIES='5',PIP_DEFAULT_TIMEOUT='45',HF_HUB_DOWNLOAD_TIMEOUT='60',
             HF_HUB_DISABLE_XET='1',HF_HUB_ENABLE_HF_TRANSFER='0',
             HF_ENDPOINT='https://huggingface.co',HF_HUB_OFFLINE='0',TRANSFORMERS_OFFLINE='0')
    for key in ('HF_TOKEN','HF_API_TOKEN','HUGGING_FACE_HUB_TOKEN','RUNPOD_API_KEY'):
        env.pop(key,None)
    return env

def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def command(args,name,env=None):
    with (OUT/(name+'.log')).open('xb') as log:
        start=time.time()
        remaining=(DEADLINE-time.time()) if DEADLINE is not None else 3300
        if remaining<=0:raise TimeoutError('Development deadline before '+name)
        try:result=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,env=env,cwd=ROOT,timeout=remaining)
        except subprocess.TimeoutExpired:
            (OUT/(name+'.command.json')).write_text(json.dumps({'argv':args,'start':start,'end':time.time(),'status':'DEADLINE'}))
            raise TimeoutError('Development deadline during '+name) from None
    (OUT/(name+'.command.json')).write_text(json.dumps({'argv':args,'start':start,'end':time.time(),'exit_code':result.returncode}))
    if result.returncode:raise RuntimeError(name+' failed with exit '+str(result.returncode))

def main():
    global DEADLINE
    DEADLINE=float(os.environ.get('SWIFTAPI_DEVELOPMENT_DEADLINE',str(time.time()+3300)))
    OUT.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    status={'purpose':'DEVELOPMENT_SMOKE','registered_result':False,'start':time.time(),
            'authority_adapter':'LOCAL_TEST_DOUBLE','credential_check_scope':'Named environment variables only'}
    try:
        status['swiftapi_environment_present']=any(os.environ.get(k) for k in ('SWIFTAPI_API_KEY','SWIFTAPI_KEY'))
        if status['swiftapi_environment_present']:
            raise RuntimeError('Forbidden credential environment in smoke')
        
        
        status['provider_key_environment_removed']='RUNPOD_API_KEY' in os.environ
        os.environ.pop('RUNPOD_API_KEY',None)
        manifest=json.loads((ROOT/'bundle-manifest.json').read_bytes())
        for name,expected in manifest['files'].items():
            path=ROOT/name
            if path.is_symlink() or digest(path)!=expected:raise RuntimeError('Bundle hash mismatch')
        python=sys.executable
        command([python,'-m','venv',str(ROOT/'venv')],'create-venv')
        python=str(ROOT/'venv/bin/python')
        env=locked_environment(os.environ)
        command([python,'-m','pip','install','--require-hashes','--only-binary=:all:',
                 '-r',str(ROOT/'requirements-runpod-cu128.lock')],'install-dependencies',env)
        wheel=next((ROOT/'wheels').glob('swiftapi_python-*.whl'))
        service=next((ROOT/'wheels').glob('swiftapi_native_service-*.whl'))
        command([python,'-m','pip','install','--no-deps',str(wheel),str(service)],'install-wheels',env)
        command([python,'-m','pip','check'],'pip-check',env)
        command([python,str(ROOT/'tools/runtime_input_selftest.py')],'synthetic-memory-input-check',env)
        command([python,str(ROOT/'tools/capture_host.py'),'--out',str(OUT/'host.json')],'capture-host',env)
        command([python,str(ROOT/'tools/fetch_pinned_model.py'),'--destination',str(ROOT/'model'),
                 '--deadline-epoch',str(DEADLINE-60)],
                'download-and-hash-verify-model',env)
        command([python,'-m','swiftapi_native_service.experiment','run','--config',str(ROOT/'smoke-config.json'),
                 '--predictions',str(ROOT/'author-predictions.md'),
                 '--approval',str(ROOT/'smoke-approval.json'),'--wheel',str(wheel),
                 '--source',str(ROOT/'model'),'--content',str(ROOT/'model/content'),
                 '--harness',str(ROOT/'frozen-harness'),'--out',str(OUT/'run')],'guarded-run',env)
        command([python,str(ROOT/'tools/verify_run.py'),'--run',str(OUT/'run'),
                 '--expected-mode','FRESH_MODEL_EXECUTION','--expected-purpose','DEVELOPMENT_SMOKE',
                 '--authority-kind','LOCAL_TEST_DOUBLE','--expected-max-grant-age-seconds','60',
                 '--out',str(OUT/'installed-sdk-verification.json')],'verify-installed-sdk',env)
        status['status']='PASS'
    except Exception as exc:
        status.update(status='FAIL',exception_type=type(exc).__name__,reason=str(exc))
    finally:
        status['end']=time.time();(OUT/'smoke-status.json').write_text(json.dumps(status,indent=2))
        files=[p for p in OUT.rglob('*') if p.is_file() and '.private-runtime' not in p.parts]
        with tarfile.open(ROOT/'development-evidence.tar.gz','x:gz') as archive:
            def public_header(info):
                info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                info.mode=0o600;info.pax_headers={};return info
            for path in sorted(files):archive.add(path,arcname=str(path.relative_to(OUT)),recursive=False,filter=public_header)
        (ROOT/'development-export.json').write_text(json.dumps({'sha256':digest(ROOT/'development-evidence.tar.gz'),
            'bytes':(ROOT/'development-evidence.tar.gz').stat().st_size,'status':status['status']}))
        (ROOT/'DONE.json').write_text(json.dumps(status))
    return 0 if status['status']=='PASS' else 2

if __name__=='__main__':
    try:code=main()
    except Exception as exc:
        
        with (ROOT/'ENTRY_FAILURE.json').open('x') as out:
            json.dump({'purpose':'DEVELOPMENT_SMOKE','status':'FAIL','exception_type':type(exc).__name__},out)
        if not (ROOT/'DONE.json').exists():
            with (ROOT/'DONE.json').open('x') as out:json.dump({'status':'FAIL','entry_failed':True},out)
        code=2
    raise SystemExit(code)
