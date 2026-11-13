"""Byte-preserving export of an incomplete population directory."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tarfile
import uuid

def export(root,role):
    root=Path(root);control=root/'control'/role
    with (control/'export.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        return export_locked(root,role,control)

def export_locked(root,role,control):
    destination=control/'partial.tar.gz'
    if not destination.exists():
        temporary=control/('export-'+uuid.uuid4().hex+'.tmp')
        with tarfile.open(temporary,'x:gz') as archive:
            for folder,prefix in ((root/'study-evidence'/role,'population'),(control,'control')):
                for path in sorted(folder.rglob('*')):
                    if ('.private-runtime' in path.parts or not path.is_file() or path.is_symlink()
                            or path.name in ('partial.tar.gz','partial-export.json','export.lock')
                            or path.name.startswith('export-')):continue
                    archive.add(path,arcname=prefix+'/'+str(path.relative_to(folder)),recursive=False)
        with temporary.open('rb') as stream:os.fsync(stream.fileno())
        os.replace(temporary,destination)
    with destination.open('rb') as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
    record={'path':str(destination),'sha256':checksum,'bytes':destination.stat().st_size,
            'sealed_registered_archive':False,'state':'INCOMPLETE_PUBLIC_FILES'}
    path=control/'partial-export.json'
    if not path.exists():
        with path.open('x') as stream:json.dump(record,stream)
    elif json.loads(path.read_bytes())!=record:
        raise ValueError('Export metadata does not match the complete archive')
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--role',choices=('PRIMARY','SECONDARY','SMOKE'),required=True)
    a=p.parse_args();print(json.dumps(export(a.root,a.role)))
