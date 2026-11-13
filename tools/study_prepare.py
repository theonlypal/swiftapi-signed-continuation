"""Pinned Linux environment and model inputs for registered populations."""
import json
import os
from pathlib import Path
import resource
import sys
import tarfile
import time
import pod_entry as common

def export_environment(root,folder):
    path=root/'environment-evidence.tar.gz'
    with tarfile.open(path,'x:gz') as archive:
        for item in sorted(folder.rglob('*')):
            if item.is_file() and not item.is_symlink():
                archive.add(item,arcname=str(item.relative_to(folder)),recursive=False)
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':common.digest(path)}

def finish_status(root,folder,status):
    status['finished_at']=time.time()
    try:status['export']=export_environment(root,folder)
    except Exception as exc:status.update(ready=False,export_exception_type=type(exc).__name__)
    with (root/'PREPARED.json').open('x') as stream:json.dump(status,stream)
    return status

def main():
    root=Path(__file__).resolve().parents[1]
    common.ROOT=root;common.OUT=root/'environment-evidence'
    common.OUT.mkdir(exist_ok=False)
    common.DEADLINE=float(os.environ['SWIFTAPI_STUDY_DEADLINE'])
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    status={'started_at':time.time()}
    try:
        manifest=json.loads((root/'bundle-manifest.json').read_bytes())
        for name,expected in manifest['files'].items():
            path=root/name
            if path.is_symlink() or common.digest(path)!=expected:raise ValueError('Bundle hash mismatch')
        env=common.locked_environment(os.environ)
        common.command([sys.executable,'-m','venv',str(root/'venv')],'create-venv',env)
        python=str(root/'venv/bin/python')
        common.command([python,'-m','pip','install','--require-hashes','--only-binary=:all:',
            '-r',str(root/'requirements-runpod-cu128.lock')],'install-dependencies',env)
        wheels=[str(p) for p in sorted((root/'wheels').glob('*.whl'))]
        common.command([python,'-m','pip','install','--no-deps',*wheels],'install-wheels',env)
        common.command([python,'-m','pip','check'],'pip-check',env)
        common.command([python,str(root/'tools/runtime_input_selftest.py')],'memory-input-check',env)
        common.command([python,str(root/'tools/capture_host.py'),'--out',str(common.OUT/'host.json')],'capture-host',env)
        common.command([python,str(root/'tools/fetch_pinned_model.py'),'--destination',str(root/'model'),
            '--deadline-epoch',str(common.DEADLINE-600)],'download-and-hash-verify-model',env)
        status['ready']=True
    except Exception as exc:status.update(ready=False,exception_type=type(exc).__name__)
    finally:
        finish_status(root,common.OUT,status)
    return 0 if status['ready'] else 2

if __name__=='__main__':raise SystemExit(main())
