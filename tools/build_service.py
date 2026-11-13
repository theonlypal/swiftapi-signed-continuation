
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import zipfile
import shutil
from swiftapi_native_service.service import source_identity
from swiftapi_native_service.core import sha

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
if out.is_relative_to(ROOT):raise ValueError('Build output must be outside the source repository')
identity=source_identity()
source=out/'source';source.mkdir()
shutil.copy2(ROOT/'pyproject.toml',source/'pyproject.toml')
shutil.copytree(ROOT/'src',source/'src',ignore=shutil.ignore_patterns('__pycache__','*.egg-info','*.pyc'))
argv=[sys.executable,'-m','build','--wheel','--no-isolation','--outdir',str(out),str(source)]
start=time.time();result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
(out/'build.log').write_text(result.stdout)
if result.returncode:raise SystemExit(result.returncode)
wheel=next(out.glob('*.whl'))
with zipfile.ZipFile(wheel) as archive:
    for name,digest in identity['files'].items():
        if sha(archive.read('swiftapi_native_service/'+name))!=digest:raise ValueError('Stale service wheel: '+name)
record={'argv':argv,'start':start,'end':time.time(),'exit_code':result.returncode,
    'source_identity':identity,'wheel':wheel.name,'wheel_sha256':sha(wheel.read_bytes())}
(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(record['wheel_sha256']+'  '+wheel.name+'\n')
print(json.dumps(record))
