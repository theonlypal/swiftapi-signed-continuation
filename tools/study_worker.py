"""One registered population with sealed, anonymous runtime input."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import signal
import socket
import struct
import time

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    with Path(path).open('x') as stream:json.dump(value,stream,indent=2)

def sealed_descriptor(raw):
    fd=os.memfd_create('swiftapi-runtime',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd,0o600)
        if os.write(fd,raw)!=len(raw):raise ValueError('Incomplete runtime input')
        os.lseek(fd,0,os.SEEK_SET)
        flags=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,flags)
        return fd
    except BaseException:os.close(fd);raise

def read_exact(connection,size):
    result=bytearray()
    while len(result)<size:
        part=connection.recv(size-len(result))
        if not part:raise ValueError('Incomplete private runtime frame')
        result.extend(part)
    return bytes(result)

def deadline_signal(signum,frame):
    raise TimeoutError('REGISTERED_RUNTIME_DEADLINE')

def decode_frame(ciphertext,private,nonce,config):
    from nacl.public import SealedBox
    value=json.loads(SealedBox(private).decrypt(ciphertext))
    if (set(value)!={'nonce','config_sha256','key','seed'} or value['nonce']!=nonce
            or value['config_sha256']!=digest(canonical(config))):
        raise ValueError('Private runtime binding mismatch')
    from swiftapi_native_service.core import validate_key
    validate_key(value['key'])
    seed=base64.b64decode(value['seed'],validate=True)
    from nacl.signing import SigningKey
    if len(seed)!=32 or base64.b64encode(bytes(SigningKey(seed).verify_key)).decode()!=config['runtime_public_key']:
        raise ValueError('Registered runtime public key mismatch')
    if digest(value['key'].encode('ascii'))!=config['operator_key_sha256']:
        raise ValueError('Registered Operator identifier mismatch')
    return value['key'].encode('ascii'),seed

def validate_role(config,role):
    if role=='SMOKE':
        if (config.get('run_role')!='SMOKE' or config.get('purpose')!='DEVELOPMENT_SMOKE'
                or config.get('authority')!='LOCAL_TEST_DOUBLE'):
            raise ValueError('Local smoke role required')
    elif (role not in ('PRIMARY','SECONDARY') or config.get('run_role')!=role
            or config.get('purpose')!='PREREGISTERED_STUDY' or config.get('authority')!='LIVE_SWIFTAPI'):
        raise ValueError('Registered role required')

def execute(root,role,deadline):
    from nacl.public import PrivateKey
    from swiftapi_native_service.experiment import run,validate_config
    root=Path(root);control=root/'control'/role;out=root/'study-evidence'/role
    out.parent.mkdir(exist_ok=True)
    config=json.loads((control/'config.json').read_bytes())
    wheel=next((root/'wheels').glob('swiftapi_python-*.whl'))
    predictions=root/'author-predictions.md'
    validate_config(config,wheel,predictions)
    validate_role(config,role)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if len(Path('/proc/swaps').read_text().splitlines())!=1:raise ValueError('Swap must be disabled')
    private=PrivateKey.generate();nonce=secrets.token_hex(32)
    endpoint=control/'private-input.sock'
    fds=[]
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(endpoint));os.chmod(endpoint,0o600);server.listen(1)
            server.settimeout(max(1,deadline-time.time()))
            save(control/'channel.json',{'public_key':base64.b64encode(bytes(private.public_key)).decode(),
                'nonce':nonce,'config_sha256':digest(canonical(config)),'endpoint':str(endpoint)})
            connection,_=server.accept()
            with connection:
                connection.settimeout(20)
                size=struct.unpack('!I',read_exact(connection,4))[0]
                if not 0<size<4096:raise ValueError('Private runtime frame size')
                key,seed=decode_frame(read_exact(connection,size),private,nonce,config)
                fds=[sealed_descriptor(key),sealed_descriptor(seed)]
                del key,seed,private
                save(control/'input-accepted.json',{'config_sha256':digest(canonical(config)),'at':time.time()})
                try:connection.sendall(b'ACCEPTED')
                except OSError:pass
        signal.signal(signal.SIGTERM,deadline_signal)
        signal.signal(signal.SIGALRM,deadline_signal)
        signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.time()))
        summary=run(config,wheel,out,root/'model',root/'model/content',root/'frozen-harness',
            approval_file=control/'approval.json',predictions_file=predictions,
            primary_archive=(control/'primary.tar.gz' if role=='SECONDARY' else None),
            mac_ledger_before=(None if role=='SMOKE' else control/'mac-before.json'),
            key_fd=os.dup(fds[0]),runtime_seed_fd=os.dup(fds[1]))
        save(control/'result.json',{'sequence_completed':summary['sequence_completed'],
            'execution_integrity':summary['execution_integrity'],'prediction_status':summary['author_prediction']['status'],
            'finished_at':time.time()})
    except BaseException as exc:
        save(control/'error.json',{'exception_type':type(exc).__name__,'at':time.time()})
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        for fd in fds:
            try:os.close(fd)
            except OSError:pass
        if (out/'evidence.tar.gz').exists():
            path=out/'evidence.tar.gz'
            with path.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
            save(control/'export.json',{'path':str(path),'bytes':path.stat().st_size,'sha256':sha})
        save(control/'done.json',{'at':time.time(),'result_present':(control/'result.json').exists()})

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--role',choices=('PRIMARY','SECONDARY','SMOKE'),required=True)
    parser.add_argument('--deadline',type=float,required=True);args=parser.parse_args()
    try:execute(args.root,args.role,args.deadline)
    except BaseException as exc:
        control=args.root/'control'/args.role
        if not (control/'error.json').exists():
            save(control/'error.json',{'exception_type':type(exc).__name__,'at':time.time()})
        if not (control/'done.json').exists():
            save(control/'done.json',{'at':time.time(),'result_present':False})
        raise SystemExit(2) from None
