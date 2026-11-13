
import argparse
from collections.abc import MutableMapping
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import tarfile
import time
from .core import AUTHORITY_URL, SWIFTAPI_PUBLIC_KEY_B64, canonical, sha, private_write
from .authority_ledger import reconcile, snapshot
from swiftapi.native_verify import signature, verify_receipt

MODE='MAC_ADMIN_SIDECAR'
SCHEMA='swiftapi-mac-authority-snapshot/1'

def enabled(config):
    return config.get('ledger_capture_mode')==MODE

def validate_policy(config):
    mode=config.get('ledger_capture_mode','IN_PROCESS_MAC_QUALIFICATION')
    if mode not in (MODE,'IN_PROCESS_MAC_QUALIFICATION'):
        raise ValueError('Unknown ledger capture mode')
    if config.get('authority')=='LIVE_SWIFTAPI' and config.get('mode')=='FRESH_MODEL_EXECUTION':
        if not enabled(config):raise ValueError('Registered or fresh live runs require Mac-side admin capture')
    if enabled(config) and config.get('authority')!='LIVE_SWIFTAPI':
        raise ValueError('Mac admin capture is for the live authority only')

def validate_capture(record, config, phase, *, archive_sha256=None, boundary=None):
    required={'schema','phase','config_sha256','capture_host','evidence_kind',
              'authority_public_key','started_at','finished_at','execution_archive_sha256','snapshot'}
    if not isinstance(record,dict) or set(record)!=required:
        raise ValueError('Invalid Mac snapshot fields')
    if (record['schema']!=SCHEMA or record['phase']!=phase or record['capture_host']!='Darwin'
            or record['evidence_kind']!='LIVE_SWIFTAPI_READ_ONLY_ADMIN_CAPTURE'
            or record['config_sha256']!=sha(canonical(config))
            or record['authority_public_key']!=SWIFTAPI_PUBLIC_KEY_B64):
        raise ValueError('Mac snapshot binding mismatch')
    for k in ('started_at','finished_at'):
        if type(record[k]) not in (int,float) or not math.isfinite(record[k]):
            raise ValueError('Invalid capture time')
    if record['started_at']>record['finished_at']:raise ValueError('Invalid capture time order')
    if phase=='BEFORE':
        if record['execution_archive_sha256'] is not None:raise ValueError('Before capture cannot name an execution archive')
        if boundary is not None and record['finished_at']>boundary:
            raise ValueError('Before capture postdates execution start')
    elif phase=='AFTER':
        if record['execution_archive_sha256']!=archive_sha256 or not isinstance(archive_sha256,str) or len(archive_sha256)!=64:
            raise ValueError('After capture must bind the exact execution archive')
        if boundary is not None and record['started_at']<boundary:
            raise ValueError('After capture predates execution finish')
    else:raise ValueError('Invalid capture phase')
    snap=record['snapshot']
    if not isinstance(snap,dict) or snap.get('source')!=AUTHORITY_URL:
        raise ValueError('Wrong snapshot authority')
    for page in snap.get('revocations',[]):
        if page.get('signature_verified'):
            signature(page['payload'],page['signature'],SWIFTAPI_PUBLIC_KEY_B64)
    return record

def read_before(path,config,now=None):
    if not enabled(config):
        if path is not None:raise ValueError('Unexpected Mac snapshot for this configuration')
        return None
    if path is None:raise ValueError('Mac before snapshot required before approval or credential access')
    raw=Path(path).read_bytes()
    obj=validate_capture(json.loads(raw),config,'BEFORE')
    if now is not None and obj['finished_at']>now:
        raise ValueError('Before capture postdates supplied time boundary')
    return raw,obj

def capture(config,phase,key_file,out,*,predictions_file,author_authorized=False,execution_archive=None):
    
    if platform.system()!='Darwin':raise ValueError('Admin capture runs on the Mac, not a pod')
    if not author_authorized:raise ValueError('Explicit author authorization required for admin reads')
    validate_policy(config)
    if not enabled(config):raise ValueError('Configuration does not select Mac-side capture')
    from .experiment import require_sealed_predictions
    require_sealed_predictions(config,predictions_file)
    out=Path(out)
    if out.exists():raise FileExistsError('Capture cannot overwrite an existing record')
    digest=None
    if phase=='AFTER':
        if execution_archive is None:raise ValueError('After capture requires the execution archive')
        data, digest=read_archive(execution_archive)
        if json.loads(data['run-config.json'])!=config:raise ValueError('Archive configuration differs')
    elif phase!='BEFORE':raise ValueError('Invalid capture phase')
    info=Path(key_file).lstat()
    if not stat.S_ISREG(info.st_mode) or not info.st_size or info.st_mode & 0o077:
        raise ValueError('Admin key file must be private, nonempty and regular')
    from .core import read_key,RemoteAuthority
    key=read_key(key_file)
    started=time.time()
    
    remote=RemoteAuthority()
    try:
        body=snapshot(key,SWIFTAPI_PUBLIC_KEY_B64,remote_authority=remote,include_denials=True)
        record={'schema':SCHEMA,'phase':phase,'config_sha256':sha(canonical(config)),
                'capture_host':'Darwin','evidence_kind':'LIVE_SWIFTAPI_READ_ONLY_ADMIN_CAPTURE',
                'authority_public_key':SWIFTAPI_PUBLIC_KEY_B64,'started_at':started,'finished_at':time.time(),
                'execution_archive_sha256':digest,'snapshot':body}
        raw=canonical(record)+b'\n'
        if key.encode() in raw:raise ValueError('Credential detected in capture')
        private_write(out,raw)
        return record
    except Exception as exc:
        
        error={'schema':'swiftapi-mac-capture-error/1','phase':phase,
                 'config_sha256':sha(canonical(config)),'started_at':started,'finished_at':time.time(),
                 'code':getattr(exc,'code','CAPTURE_FAILED'),'exception_type':type(exc).__name__,
                 'retry_permitted':False}
        private_write(out.with_name(out.name+'.error.json'),canonical(error)+b'\n')
        raise

class ArchiveData(MutableMapping):
    def __init__(self,path):
        self.archive=tarfile.open(path,'r:gz');self.members={};self.overrides={}
        for member in self.archive.getmembers():
            p=PurePosixPath(member.name)
            if (not member.isfile() or p.is_absolute() or '..' in p.parts or
                    '.private-runtime' in p.parts or member.name in self.members or str(p)!=member.name):
                self.archive.close();raise ValueError('Unsafe or duplicate archive member')
            self.members[member.name]=member
    def __getitem__(self,name):
        if name in self.overrides:return self.overrides[name]
        with self.archive.extractfile(self.members[name]) as f:return f.read()
    def __setitem__(self,name,value):self.overrides[name]=value
    def __delitem__(self,name):raise TypeError('Archive entries are immutable')
    def __iter__(self):return iter(dict.fromkeys([*self.members,*self.overrides]))
    def __len__(self):return len(set(self.members)|set(self.overrides))
    def __del__(self):
        if hasattr(self,'archive'):self.archive.close()

def read_archive(path):
    path=Path(path)
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    data=ArchiveData(path)
    declared={}
    for line in data['SHA256SUMS'].decode().splitlines():
        digest_line,name=line.split('  ',1)
        if name in declared:raise ValueError('Duplicate manifest path')
        declared[name]=digest_line
    if set(declared)!=set(data)-{'SHA256SUMS'} or any(sha(data[n])!=v for n,v in declared.items()):
        raise ValueError('Execution archive manifest mismatch')
    return data,digest

def records_for_reconciliation(data):
    grants=[];revoked=None;revoke_dispatched=False
    for name in sorted(data):
        if name.startswith('authority-dispatches/') and name.endswith('.json'):
            event=json.loads(data[name])
            if event.get('path')=='/attest' and event.get('stage')=='RESPONSE' and 'jti' in event.get('attestation',{}):
                grants.append(event['attestation'])
            if event.get('path')=='/attestation/revoke' and event.get('stage')=='DISPATCH':revoke_dispatched=True
    intent=json.loads(data.get('revocation-intent.json',b'{}'))
    response=json.loads(data.get('revocation-response.json',b'{}'))
    if revoke_dispatched and response.get('revoked') is True and response.get('jti')==intent.get('jti'):
        revoked=intent.get('jti')
    return grants,revoked

def clock_bracket(before,after,data):
    pass
    def page_times(record):
        snap=record['snapshot']
        pages=snap.get('governance',[])+snap.get('revocations',[])+snap.get('fallback',[])
        if 'authentication_denials' in snap:pages.append(snap['authentication_denials'])
        return [p['clock']['server_epoch_seconds'] for p in pages if p.get('clock',{}).get('available')]
    dispatches=[json.loads(data[name]) for name in data if name.startswith('authority-dispatches/')]
    times=[e['clock']['server_epoch_seconds'] for e in dispatches
           if e.get('stage')=='RESPONSE' and e.get('clock',{}).get('available')]
    b,a=page_times(before),page_times(after)
    if not b or not a or not times:
        return {'status':'UNESTABLISHED','reason':'Missing authority Date observations or no dispatched responses'}
    okay=max(b)<=min(times) and min(a)>=max(times)
    return {'status':'BRACKETED' if okay else 'FINDING_CLOCK_ORDER',
        'before_last_server_epoch':max(b),'run_first_server_epoch':min(times),
        'run_last_server_epoch':max(times),'after_first_server_epoch':min(a),
        'limit':'HTTP Date second resolution; proxy clock not a signed or independently trusted timestamp'}

def join_report(before,after,data):
    grants,revoked=records_for_reconciliation(data)
    result=reconcile(before['snapshot'],after['snapshot'],grants,revoked)
    result['authority_clock_bracket']=clock_bracket(before,after,data)
    if result['authority_clock_bracket']['status']!='BRACKETED':
        result['findings'].append({'finding':'Authority Date bracket not established',
                                   'detail':result['authority_clock_bracket']['status']})
    expected={g['jti'] for g in grants}
    receipt_jtis=set()
    for name in data:
        if name.startswith('receipts/') and name.endswith('/grant.json'):
            grant=json.loads(data[name])
            if isinstance(grant,dict) and isinstance(grant.get('jti'),str):receipt_jtis.add(grant['jti'])
        if name.startswith('receipts/') and name.endswith('/receipt.json'):
            payload=json.loads(data[name])['payload']
            grants_used=[payload.get('grant')]+[(payload.get(k) or {}).get('grant')
                for k in ('authentication','boundary_authentication')]
            receipt_jtis.update(g['jti'] for g in grants_used if isinstance(g,dict) and isinstance(g.get('jti'),str))
    result['receipt_grants_in_dispatch_log']={'checked':len(receipt_jtis),'missing':sorted(receipt_jtis-expected)}
    if receipt_jtis-expected:result['findings'].append({'finding':'Receipt grant missing from dispatch log','jtis':sorted(receipt_jtis-expected)})
    intent=json.loads(data.get('revocation-intent.json',b'{}')).get('jti')
    dispatched=any(json.loads(data[name]).get('path')=='/attestation/revoke' and json.loads(data[name]).get('stage')=='DISPATCH'
                   for name in data if name.startswith('authority-dispatches/'))
    result['revocation_dispatch']={'intended_jti':intent,'dispatched':dispatched,
        'status':'CONFIRMED_BY_RESPONSE' if revoked else 'UNKNOWN_AFTER_DISPATCH' if dispatched else 'NOT_DISPATCHED'}
    if dispatched and not revoked:result['findings'].append({'finding':'Revocation outcome unknown after dispatch','jti':intent})
    if revoked and not result['all_revocation_pages_signature_verified']:
        result['findings'].append({'finding':'Revoked grant lacks a fully verified signed-feed witness','jti':revoked})
    if result['findings']:result['status']='FINDINGS'
    return result

def finalize(execution_archive,after_file,out):
    pass
    data,digest=read_archive(execution_archive)
    config=json.loads(data['run-config.json']);summary=json.loads(data['summary.json'])
    if not enabled(config) or summary.get('ledger_status')!='PENDING_MAC_AFTER_CAPTURE':
        raise ValueError('Archive is not awaiting Mac ledger completion')
    if 'mac-ledger-finalization.json' in data:raise ValueError('Already finalized')
    before=validate_capture(json.loads(data['mac-ledger-before.json']),config,'BEFORE')
    after_raw=Path(after_file).read_bytes()
    after=validate_capture(json.loads(after_raw),config,'AFTER',archive_sha256=digest)
    reconciliation=join_report(before,after,data)
    out=Path(out)
    if out.exists():raise FileExistsError('Finalization never overwrites an existing directory')
    out.mkdir(parents=True,mode=0o700)
    for name,raw in data.items():
        if name!='SHA256SUMS':private_write(out/name,raw)
    
    try:
        runtime=json.loads(data['runtime-public.json']);authority=json.loads(data['authority-public.json'])
        if authority['public_key']!=SWIFTAPI_PUBLIC_KEY_B64:
            raise ValueError('Wrong live authority anchor')
        count=0
        for path in sorted((out/'receipts').glob('*/receipt.json')):
            verify_receipt(path,runtime['public_key'],config['mode'],authority_key=authority['public_key'],
                           expected_max_grant_age_seconds=config['max_grant_age_seconds'])
            count+=1
        if count!=summary['verified_receipt_count']:raise ValueError('Receipt count differs from summary')
        private_write(out/'mac-ledger-after.json',after_raw)
        private_write(out/'authority-ledger-reconciliation.json',canonical(reconciliation)+b'\n')
        record={'schema':'swiftapi-mac-ledger-finalization/1','source_execution_archive_sha256':digest,
                'config_sha256':sha(canonical(config)),
                'before_sha256':sha(data['mac-ledger-before.json']),'after_sha256':sha(after_raw),
                'reconciliation_sha256':sha(canonical(reconciliation)+b'\n'),
                'completed_at':time.time(),'verified_receipts':count,
                'status':'JOINED_WITH_FINDINGS' if reconciliation['findings'] else 'JOINED_WITH_API_LIMITATIONS',
                'trust':'Mac software capture, unsigned governance listing; signed revocation pages checked. Not host attestation.'}
        private_write(out/'mac-ledger-finalization.json',canonical(record)+b'\n')
        from .experiment import export_evidence
        final_digest=export_evidence(out)
        return {'status':record['status'],'archive_sha256':final_digest,'receipt_count':count}
    except Exception as exc:
        private_write(out/'mac-ledger-finalization-error.json',canonical({
            'exception_type':type(exc).__name__,'status':'INCOMPLETE','retry_permitted':False})+b'\n')
        raise

def verify_join(data,config,summary,pending_archive=None):
    pass
    if not enabled(config):return {'status':'NOT_APPLICABLE'}
    if 'mac-ledger-finalization.json' not in data:return {'status':'PENDING_MAC_AFTER_CAPTURE'}
    record=json.loads(data['mac-ledger-finalization.json'])
    source_binding='HASH_DECLARED_PENDING_ARCHIVE_REQUIRED_FOR_RECOMPUTATION'
    if pending_archive is not None:
        original,digest=read_archive(pending_archive)
        if digest!=record['source_execution_archive_sha256']:
            raise ValueError('Pending execution archive hash mismatch')
        additions={'mac-ledger-after.json','mac-ledger-finalization.json',
                   'authority-ledger-reconciliation.json'}
        if set(data)!=set(original)|additions:
            raise ValueError('Unexpected joined archive member set')
        for name in original:
            if name!='SHA256SUMS' and original[name]!=data[name]:
                raise ValueError('Pending execution member differs from joined evidence')
        source_binding='VERIFIED_WITH_PENDING_ARCHIVE'
    before=validate_capture(json.loads(data['mac-ledger-before.json']),config,'BEFORE')
    after=validate_capture(json.loads(data['mac-ledger-after.json']),config,'AFTER',
        archive_sha256=record['source_execution_archive_sha256'])
    for field,name in [('before_sha256','mac-ledger-before.json'),('after_sha256','mac-ledger-after.json'),
                       ('reconciliation_sha256','authority-ledger-reconciliation.json')]:
        if sha(data[name])!=record[field]:raise ValueError('Mac ledger asset hash mismatch')
    if record['config_sha256']!=sha(canonical(config)):raise ValueError('Mac finalization config mismatch')
    actual=join_report(before,after,data)
    if canonical(actual)!=canonical(json.loads(data['authority-ledger-reconciliation.json'])):
        raise ValueError('Mac reconciliation differs from independent reconstruction')
    expected_status='JOINED_WITH_FINDINGS' if actual['findings'] else 'JOINED_WITH_API_LIMITATIONS'
    if record['status']!=expected_status or record['verified_receipts']!=summary['verified_receipt_count']:
        raise ValueError('Mac finalization status/count mismatch')
    return {'status':record['status'],'findings':actual['findings'],'counts':actual['counts'],
            'source_archive_binding':source_binding}

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('capture');c.add_argument('--config',type=Path,required=True)
    c.add_argument('--phase',choices=['BEFORE','AFTER'],required=True)
    c.add_argument('--admin-key-file',type=Path,required=True);c.add_argument('--out',type=Path,required=True)
    c.add_argument('--predictions',type=Path,required=True);c.add_argument('--author-authorized-capture',action='store_true')
    c.add_argument('--execution-archive',type=Path)
    f=sub.add_parser('finalize');f.add_argument('--execution-archive',type=Path,required=True)
    f.add_argument('--after',type=Path,required=True);f.add_argument('--out',type=Path,required=True)
    v=sub.add_parser('verify');v.add_argument('--archive',type=Path,required=True)
    v.add_argument('--pending-archive',type=Path,required=True)
    a=p.parse_args()
    try:
        if a.command=='capture':
            capture(json.loads(a.config.read_bytes()),a.phase,a.admin_key_file,a.out,
                predictions_file=a.predictions,author_authorized=a.author_authorized_capture,execution_archive=a.execution_archive)
            print('MAC_READ_ONLY_CAPTURE_COMPLETE')
        elif a.command=='finalize':print(json.dumps(finalize(a.execution_archive,a.after,a.out)))
        else:
            data,digest=read_archive(a.archive)
            result=verify_join(data,json.loads(data['run-config.json']),json.loads(data['summary.json']),a.pending_archive)
            print(json.dumps({'archive_sha256':digest,**result}))
    except Exception as exc:
        print(json.dumps({'status':'FAILED','exception_type':type(exc).__name__,'code':getattr(exc,'code','MAC_LEDGER_ERROR')}))
        raise SystemExit(2) from None

if __name__=='__main__':main()
