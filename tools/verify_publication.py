"""Verify identical public tagged source bytes on GitHub and Zenodo."""
import argparse
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path
import requests
import tarfile

def sha(raw):return hashlib.sha256(raw).hexdigest()
def files(raw):
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        selected=[m for m in archive.getmembers() if m.isfile()]
        if len({m.name.split('/',1)[0] for m in selected})!=1:raise ValueError('Single archive root required')
        result={}
        for member in selected:
            name=member.name.split('/',1)[1]
            if name in result or '..' in Path(name).parts or name.startswith('/'):raise ValueError('Unsafe tagged path')
            result[name]=archive.extractfile(member).read()
        return result

def verify(record_id,repository,out,source_archive=None):
    out=Path(out);out.mkdir(exist_ok=False,parents=True)
    http=requests.Session();http.trust_env=False
    record_response=http.get('https://zenodo.org/api/records/'+str(record_id),timeout=60)
    record_response.raise_for_status();record=record_response.json()
    if not (record.get('status')=='published' or record.get('is_published') is True):raise ValueError('Record not published')
    if len(record.get('files',[]))!=1:raise ValueError('Exactly one tagged source file required')
    entry=record['files'][0];url=entry['links']['self']
    if not url.startswith('https://zenodo.org/'):raise ValueError('Unexpected public-file host')
    remote=http.get(url,timeout=120);remote.raise_for_status()
    github_url='https://api.github.com/repos/'+repository+'/tarball/v1.0.0'
    tagged=http.get(github_url,timeout=120);tagged.raise_for_status()
    original=Path(source_archive).read_bytes() if source_archive is not None else tagged.content
    if remote.content!=original:raise ValueError('Zenodo and supplied GitHub source archive bytes differ')
    members=files(original)
    if members!=files(tagged.content):raise ValueError('Public GitHub tag member bytes differ')
    (out/'public-record.json').write_bytes(record_response.content)
    (out/'tagged-source.tar.gz').write_bytes(original)
    result={'verified':True,'doi':record['doi'],'record_id':record_id,'repository':repository,
        'tag':'v1.0.0','archive_sha256':sha(original),'bytes':len(original),
        'github_readback_sha256':sha(tagged.content),'tag_member_bytes_identical':True,
        'verified_public_at':datetime.now(timezone.utc).isoformat(),
        'record_created_at':record.get('created'),'member_hashes':{n:sha(b) for n,b in members.items()},
        'github_url':github_url,'zenodo_file_url':url}
    (out/'publication-verification.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--record-id',required=True);p.add_argument('--repository',required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--source-archive',type=Path)
    a=p.parse_args();verify(a.record_id,a.repository,a.out,a.source_archive)
