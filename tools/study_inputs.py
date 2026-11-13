"""Resolve timestamp and primary-archive inputs from verified public and local records."""
import base64
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
from nacl.public import PublicKey,SealedBox

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def resolve(template,record,registration_bytes,*,publication_verification,primary_sha256=None):
    value=json.loads(json.dumps(template))
    if not (record.get('is_published') is True or record.get('status')=='published') or record.get('doi')!=value['registration_doi']:
        raise ValueError('Public registration identity required')
    if (publication_verification.get('verified') is not True
            or publication_verification.get('doi')!=record.get('doi')):
        raise ValueError('Public content verification required')
    timestamp=publication_verification.get('verified_public_at')
    if not isinstance(timestamp,str):raise ValueError('Public registration timestamp required')
    parsed=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
    if parsed.tzinfo is None or parsed>datetime.now(timezone.utc):raise ValueError('Invalid public timestamp')
    if value['public_registration_timestamp']!='PUBLIC_CONTENT_VERIFIED_AT':
        raise ValueError('Timestamp resolution contract')
    if value['registration_sha256']!=sha(registration_bytes):raise ValueError('Registration content hash')
    value['public_registration_timestamp']=timestamp
    if value.get('run_role')=='SECONDARY':
        if value.get('primary_archive_sha256')!='SEALED_PRIMARY_ARCHIVE' or not re.fullmatch('[0-9a-f]{64}',primary_sha256 or ''):
            raise ValueError('Sealed primary archive required')
        value['primary_archive_sha256']=primary_sha256
    elif primary_sha256 is not None:raise ValueError('Unexpected primary archive input')
    return value

def encrypted_runtime(channel,config,key,seed):
    if channel['config_sha256']!=sha(canonical(config)):raise ValueError('Channel config mismatch')
    if sha(key.encode('ascii'))!=config['operator_key_sha256']:raise ValueError('Run key identity mismatch')
    body={'nonce':channel['nonce'],'config_sha256':channel['config_sha256'],
          'key':key,'seed':base64.b64encode(seed).decode('ascii')}
    return SealedBox(PublicKey(base64.b64decode(channel['public_key'],validate=True))).encrypt(canonical(body))
