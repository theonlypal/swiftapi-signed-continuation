
import time
from .core import AUTHORITY_URL, ServiceError, canonical, sha, http_clock_observation
from swiftapi import SwiftAPI
from swiftapi.native_verify import signature, verify_revocation_entry

SCOPES=('pccg2.native_decode','swiftapi.native_service.connection_check')
EVENT_FIELDS=('event_id','jti','action_type','action_fingerprint','decision','policy_hash','timestamp')

def snapshot(key, public_key, *, since=0, limit=5000, remote_authority=None, include_denials=False):
    result={'observed_at':time.time(),'source':AUTHORITY_URL,'governance':[],
        'revocations':[],'limitations':[], 'fallback':[], 'read_requests':0,
        'key_scope':'Not independently filterable by key; scope-filtered events reconciled to observed grant JTIs',
        'raw_bodies_retained':False,'redaction':'Only event and attestation identifiers, decisions, hashes and timestamps retained'}
    def get(api,path,params):
        result['read_requests']+=1
        sent=time.time()
        try:
            response=api._session.get(AUTHORITY_URL+path,params=params,timeout=15,allow_redirects=False)
        except Exception:
            exc=ServiceError('AUTHORITY_LEDGER_UNAVAILABLE',503);exc.snapshot=result
            raise exc from None
        if response.status_code==429:
            exc=ServiceError('AUTHORITY_RATE_LIMITED',429);exc.snapshot=result
            raise exc
        if response.status_code>=500 and response.status_code!=501:
            exc=ServiceError('AUTHORITY_LEDGER_UNAVAILABLE',503);exc.snapshot=result
            raise exc
        meta={'endpoint':path,'params':params,'http_status':response.status_code,
              'date':response.headers.get('Date'),'body_sha256':sha(response.content),
              'clock':http_clock_observation(response.headers.get('Date'),sent,time.time())}
        if response.status_code!=200:
            result['limitations'].append(meta)
            return None,meta
        try:return response.json(),meta
        except ValueError:
            exc=ServiceError('AUTHORITY_LEDGER_INVALID_RESPONSE',503);exc.snapshot=result
            raise exc from None
    with (remote_authority._client(key) if remote_authority is not None else
          SwiftAPI(key=key,base_url=AUTHORITY_URL,timeout=15)) as api:
        api._session.trust_env=False
        for scope in SCOPES:
            body,meta=get(api,'/governance/events',{'action_type':scope,'limit':limit})
            if body is None:continue
            events=body.get('events')
            if not isinstance(events,list):
                result['limitations'].append(dict(meta,reason='Missing events array'));continue
            result['governance'].append(dict(meta,events=[{k:e.get(k) for k in EVENT_FIELDS} for e in events],
                returned=len(events),complete_recent_window=None))
            if len(events)>=limit:result['limitations'].append({'reason':'Governance limit reached; no cursor endpoint provided','scope':scope})
        if len(result['governance'])!=len(SCOPES):
            fallback_routes=() if include_denials else (('/audit','verifications'),('/authority/denials','denials'))
            for endpoint,field in fallback_routes:
                body,meta=get(api,endpoint,{'limit':limit})
                records=body.get(field,[]) if isinstance(body,dict) else []
                result['fallback'].append(dict(meta,returned=len(records),
                    record_field_names=sorted({k for item in records for k in item}),
                    usable_attestation_ledger=False))
            result['limitations'].append({'reason':'Verification records and authentication denials do not replace /attest governance decisions'})
        if include_denials:
            body,meta=get(api,'/authority/denials',{'limit':limit})
            records=body.get('denials',[]) if isinstance(body,dict) else []
            allowed=('event_id','timestamp','action_type','policy_hash')
            result['authentication_denials']=dict(meta,records=[
                {k:e[k] for k in allowed if k in e} for e in records if isinstance(e,dict)],
                returned=len(records),attestation_jti_available=False)
        cursor=since
        for _ in range(20):
            body,meta=get(api,'/attestation/revocations',{'since':cursor,'limit':1000})
            if body is None:break
            signed={'revocations':[r['jti'] for r in body['revocations']],
                'since':body['since'],'next_cursor':body['next_cursor'],'fetched_at':body['fetched_at']}
            verified=False
            if body.get('signing_mode')=='ed25519':
                signature(signed,body['signature'],public_key);verified=True
            entries=[]
            for entry in body['revocations']:
                try:verify_revocation_entry(entry,entry['jti'],public_key);valid=True
                except Exception:valid=False
                entries.append({'jti':entry.get('jti'),'cursor':entry.get('cursor'),'signature_verified':valid})
            result['revocations'].append(dict(meta,payload=signed,signature=body.get('signature'),entries=entries,
                signature_verified=verified,has_more=body.get('has_more'),total_revoked=body.get('total_revoked')))
            cursor=body['next_cursor']
            if not body.get('has_more'):break
        else:result['limitations'].append({'reason':'Revocation page bound reached'})
        result['revocation_cursor']=cursor
    result['limitations'].append({'reason':'Governance listing has no key-hash filter, signed total, or pagination cursor; counts are window/scoped observations, not a cryptographic per-key census'})
    return result

def reconcile(before, after, grants, revoked_jti=None):
    def events(s):
        return {e['jti']:e for page in s.get('governance',[]) for e in page['events']}
    old,new=events(before),events(after)
    delta=set(new)-set(old)
    expected={g['jti']:g for g in grants if isinstance(g,dict) and isinstance(g.get('jti'),str)}
    checks=[];findings=[]
    listed=set(j for page in after.get('revocations',[]) for j in page['payload']['revocations'])
    old_listed=set(j for page in before.get('revocations',[]) for j in page['payload']['revocations'])
    for jti,grant in expected.items():
        event=new.get(jti)
        match=bool(event and event['action_fingerprint']==grant['action_fingerprint'] and
                   ('action_type' not in grant or event['action_type']==grant['action_type']) and
                   event['decision']==('approved' if grant['approved'] else 'denied'))
        checks.append({'jti':jti,'appears':event is not None,'decision_and_binding_match':match,
                       'new_since_before':jti in delta,'signed_denial':grant['approved'] is False})
        if not match:findings.append({'jti':jti,'finding':'Missing or mismatched authority event'})
        if jti in old:findings.append({'jti':jti,'finding':'Run grant was already present in before snapshot'})
    extra=sorted(delta-set(expected))
    if extra:findings.append({'finding':'Other authority scope events arrived during run','jtis':extra})
    if revoked_jti and revoked_jti not in listed:
        findings.append({'finding':'Approved disposable JTI absent from after revocation snapshot','jti':revoked_jti})
    counts={'observed_issued_jtis':len(expected),'observed_approved':sum(g['approved'] is True for g in expected.values()),
            'observed_denied':sum(g['approved'] is False for g in expected.values()),
            'authority_scoped_delta':len(delta),'exact_scope_delta_matches_run':delta==set(expected),
            'new_revocations_in_feed':len(listed-old_listed),'expected_run_revocations':int(revoked_jti is not None),
            'exact_revocation_delta_matches_run':listed-old_listed==({revoked_jti} if revoked_jti else set())}
    if not counts['exact_revocation_delta_matches_run']:
        findings.append({'finding':'Revocation delta differs from observed run revoke','new_jtis':sorted(listed-old_listed)})
    return {'status':'FINDINGS' if findings else 'MATCH_WITH_API_LIMITATIONS','checks':checks,'counts':counts,
        'revoked_jti':revoked_jti,'revoked_jti_listed':revoked_jti in listed if revoked_jti else None,
        'findings':findings,'limitations':before.get('limitations',[])+after.get('limitations',[]),
        'authority_governance_records_signed':False,
        'all_revocation_pages_signature_verified':bool(after.get('revocations')) and all(p['signature_verified'] for p in after['revocations'])}
