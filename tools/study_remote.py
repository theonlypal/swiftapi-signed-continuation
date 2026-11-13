"""Bounded public-file transfer and private in-memory input for a registered pod."""
import base64
import hashlib
import json
from pathlib import Path,PurePosixPath
import tarfile
import time
from runpod_smoke import safe_exec,CommandPending,poll,sha

REMOTE='/workspace/native-smoke'

def upload_file(api,pod,path,raw,deadline):
    name=PurePosixPath(path)
    if name.is_absolute() or '..' in name.parts:raise ValueError('Relative public path required')
    for offset in range(0,len(raw),150000):
        block=raw[offset:offset+150000];encoded=base64.b64encode(block).decode()
        code=("import sys,base64,fcntl,hashlib;from pathlib import Path;"
              "p=Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);"
              "f=p.open('r+b' if p.exists() else 'w+b');fcntl.flock(f,fcntl.LOCK_EX);"
              "n=int(sys.argv[2]);b=base64.b64decode(''.join(sys.argv[4:]));"
              "assert hashlib.sha256(b).hexdigest()==sys.argv[3];assert p.stat().st_size>=n;"
              "f.seek(n);f.write(b);f.flush();f.seek(n);assert f.read(len(b))==b;f.close()")
        safe_exec(api,pod,['python3','-c',code,REMOTE+'/'+str(name),str(offset),sha(block),
            *[encoded[i:i+3500] for i in range(0,len(encoded),3500)]],deadline,'PUBLIC_FILE_TRANSFER')
    code="import hashlib,sys;from pathlib import Path;p=Path(sys.argv[1]);assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2];print('VERIFIED')"
    safe_exec(api,pod,['python3','-c',code,REMOTE+'/'+str(name),sha(raw)],deadline,'PUBLIC_FILE_HASH')

def read_json(api,pod,path,deadline,*,required=True):
    code="import sys;from pathlib import Path;p=Path(sys.argv[1]);print(p.read_text() if p.exists() else 'PENDING')"
    value=safe_exec(api,pod,['python3','-c',code,REMOTE+'/'+path],deadline,'PUBLIC_READBACK').strip()
    if value=='PENDING':
        if required:raise CommandPending('Awaiting public state')
        return None
    return json.loads(value)

def launch(api,pod,role,deadline):
    if role not in ('PREPARE','PRIMARY','SECONDARY','SMOKE'):raise ValueError('Unknown pod command')
    args=(['python3',REMOTE+'/tools/study_prepare.py'] if role=='PREPARE' else
          [REMOTE+'/venv/bin/python',REMOTE+'/tools/study_worker.py','--root',REMOTE,
           '--role',role,'--deadline',str(deadline-1500)])
    code=("import subprocess,sys,os,json;from pathlib import Path;"
          "p=Path('"+REMOTE+"');sys.path.insert(0,str(p/'tools'));from pod_entry import locked_environment;"
          "role=sys.argv[1];f=(p/(role+'.log')).open('xb');env=locked_environment(os.environ);"
          "env['SWIFTAPI_STUDY_DEADLINE']=sys.argv[2];"
          "x=subprocess.Popen(json.loads(sys.argv[3]),stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True);"
          "(p/(role+'.pid')).write_text(str(x.pid));print(x.pid)")
    # A submission is singular. An uncertain acknowledgement only permits public reads.
    try:return int(api.execute(pod,['python3','-c',code,role,str(deadline-300),json.dumps(args)]))
    except Exception:
        def acknowledgement():
            code="import sys;from pathlib import Path;p=Path(sys.argv[1]);print(p.read_text() if p.exists() else 'PENDING')"
            result=api.execute(pod,['python3','-c',code,REMOTE+'/'+role+'.pid']).strip()
            if result=='PENDING':raise CommandPending('Awaiting process acknowledgement')
            return int(result)
        return poll(acknowledgement,min(deadline-300,time.time()+90),label='PROCESS_ACKNOWLEDGEMENT')

def send_private_frame(api,pod,role,ciphertext,deadline):
    code=("import socket,sys,base64,struct;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
          "s.settimeout(20);s.connect(sys.argv[1]);b=base64.b64decode(sys.argv[2]);"
          "s.sendall(struct.pack('!I',len(b))+b);assert s.recv(8)==b'ACCEPTED';s.close();print('ACCEPTED')")
    try:
        return api.execute(pod,['python3','-c',code,REMOTE+'/control/'+role+'/private-input.sock',
                           base64.b64encode(ciphertext).decode()])
    except Exception:
        return poll(lambda:read_json(api,pod,'control/'+role+'/input-accepted.json',deadline),
                    min(deadline,time.time()+90),label='PRIVATE_INPUT_ACKNOWLEDGEMENT')

def stop_and_export(api,pod,role,deadline):
    code=("import os,signal,sys;from pathlib import Path;p=Path(sys.argv[1]);"
          "pid=int(p.read_text()) if p.exists() else None;"
          "os.kill(pid,signal.SIGTERM) if pid else None")
    try:api.execute(pod,['python3','-c',code,REMOTE+'/'+role+'.pid'])
    except Exception:pass
    try:
        poll(lambda:read_json(api,pod,'control/'+role+'/done.json',min(deadline,time.time()+90)),
             min(deadline,time.time()+90),label='POPULATION_STOP')
    except Exception:
        code=code.replace('signal.SIGTERM','signal.SIGKILL')
        try:api.execute(pod,['python3','-c',code,REMOTE+'/'+role+'.pid'])
        except Exception:pass
    meta=read_json(api,pod,'control/'+role+'/export.json',deadline,required=False)
    if meta:return meta
    safe_exec(api,pod,['python3',REMOTE+'/tools/study_export.py','--root',REMOTE,'--role',role],deadline,'PARTIAL_EXPORT')
    return read_json(api,pod,'control/'+role+'/partial-export.json',deadline)

def pull_file(api,pod,metadata,destination,deadline):
    if (type(metadata.get('bytes')) is not int or not 0<metadata['bytes']<=2*1024**3
            or not metadata.get('path','').startswith(REMOTE+'/')):raise ValueError('Invalid export metadata')
    checksum=hashlib.sha256();length=0
    with Path(destination).open('xb') as stream:
        for offset in range(0,metadata['bytes'],600000):
            code="import sys,base64;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2]));print(base64.b64encode(f.read(600000)).decode())"
            raw=base64.b64decode(safe_exec(api,pod,['python3','-c',code,metadata['path'],str(offset)],
                                        deadline,'EVIDENCE_TRANSFER').strip(),validate=True)
            if not raw:raise ValueError('Incomplete evidence')
            stream.write(raw);checksum.update(raw);length+=len(raw)
    if length!=metadata['bytes'] or checksum.hexdigest()!=metadata['sha256']:
        raise ValueError('Evidence hash or length mismatch')
    return checksum.hexdigest()

def unpack(archive,destination):
    with tarfile.open(archive,'r:gz') as source:
        members=source.getmembers()
        if any(not m.isfile() or PurePosixPath(m.name).is_absolute() or '..' in PurePosixPath(m.name).parts for m in members):
            raise ValueError('Invalid evidence member')
        source.extractall(destination,filter='data')
