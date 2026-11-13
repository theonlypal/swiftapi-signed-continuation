
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
p=argparse.ArgumentParser()
p.add_argument('--out',type=Path,required=True)
p.add_argument('args',nargs='+')
a=p.parse_args()
if a.out.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
    raise ValueError('Test output must be outside the source repository')
a.out.mkdir(parents=True,exist_ok=False)
command=[sys.executable,'-m','pytest',*a.args,'-q','-p','no:cacheprovider',
         '--basetemp',str(a.out/'temporary')]
start=time.time()
environment=dict(os.environ,HYPOTHESIS_STORAGE_DIRECTORY=str(a.out.resolve()/'hypothesis'))
r=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=environment)
(a.out/'output.txt').write_text(r.stdout)
import importlib.util
locations={name:importlib.util.find_spec(name).origin for name in ('swiftapi','swiftapi_native_service')}
(a.out/'command.json').write_text(json.dumps({'argv':command,'started_at':start,'finished_at':time.time(),
    'exit_code':r.returncode,'package_locations':locations},indent=2))
print('\n'.join(r.stdout.splitlines()[-35:]));raise SystemExit(r.returncode)
