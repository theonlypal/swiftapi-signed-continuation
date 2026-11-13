
from email.utils import formatdate
import pytest
from swiftapi_native_service.pacing import AuthorityPacer,LIMITS,SLOT_BUDGETS,route_tier
from swiftapi_native_service.core import ServiceError

class Clock:
    def __init__(self):self.value=1800000000.;self.sleeps=[]
    def now(self):return self.value
    def sleep(self,seconds):self.sleeps.append(seconds);self.value+=seconds

def headers(clock,limit,remaining):
    return {'Date':formatdate(clock.now(),usegmt=True),'X-RateLimit-Limit':str(limit),
        'X-RateLimit-Remaining':str(remaining),'X-RateLimit-Reset':str(int(clock.now())+60)}

def test_low_remaining_sleeps_before_issuance_not_after():
    clock=Clock();events=[];p=AuthorityPacer(events.append,clock=clock.now,sleep=clock.sleep)
    p.observe('public_read',headers(clock,120,6),200)
    p.observe('authenticated',headers(clock,300,250),200)
    p.begin_slot('VALID');issued=clock.now();sleep_count=len(clock.sleeps)
    for method,path in [('POST','/attest')]*4+[('GET','/attestation/revoked/test')]*5:
        tier,_=p.before_dispatch(method,path)
        p.observe(tier,headers(clock,LIMITS[tier],100),200)
    assert issued>=1800000061 and len(clock.sleeps)==sleep_count and clock.now()-issued<60
    assert events and all(e['location']=='BEFORE_SLOT_ISSUANCE' for e in events if e['stage']=='PACING_SLEEP')

def test_bank_188_virtual_authority_zero_429_and_no_midgrant_sleep():
    clock=Clock();events=[];p=AuthorityPacer(events.append,clock=clock.now,sleep=clock.sleep)
    calls={t:[] for t in LIMITS};generations=0;expired=0;rate_limited=0
    for _ in range(188):
        for arm in ('VALID','MISSING_GRANT'):
            p.begin_slot(arm);issued=clock.now();sleeps=len(clock.sleeps)
            for tier,count in SLOT_BUDGETS[arm].items():
                for _ in range(count):
                    method,path=('POST','/attest') if tier=='authenticated' else ('GET','/attestation/revoked/test')
                    p.before_dispatch(method,path)
                    calls[tier]=[t for t in calls[tier] if clock.now()-t<60]
                    status=429 if len(calls[tier])>=LIMITS[tier] else 200
                    rate_limited+=int(status==429);calls[tier].append(clock.now())
                    p.observe(tier,headers(clock,LIMITS[tier],max(0,LIMITS[tier]-len(calls[tier]))),status)
                    clock.value+=.01
            expired+=int(clock.now()-issued>=60);generations+=1
            assert len(clock.sleeps)==sleeps
            p.end_slot()
    assert (generations,rate_limited,expired)==(376,0,0)
    assert events

def test_reserve_lost_mid_slot_is_operational_without_sleep_or_retry():
    clock=Clock();p=AuthorityPacer(clock=clock.now,sleep=clock.sleep)
    p.begin_slot('VALID');n=len(clock.sleeps)
    p.observe('public_read',headers(clock,120,0),200)
    with pytest.raises(ServiceError,match='PACING_RESERVE_LOST_AT_BOUNDARY'):
        p.before_dispatch('GET','/attestation/revoked/test')
    assert len(clock.sleeps)==n
    p.observe('public_read',headers(clock,120,0),429);p.end_slot()
    with pytest.raises(ServiceError,match='AUTHORITY_RATE_LIMITED'):p.begin_slot('VALID')

def test_missing_headers_burst_spacing_is_before_issuance():
    clock=Clock();p=AuthorityPacer(clock=clock.now,sleep=clock.sleep)
    for _ in range(5):
        p.begin_slot('MISSING_GRANT');n=len(clock.sleeps)
        for method,path in [('POST','/attest')]*2+[('GET','/attestation/revoked/test')]*2:
            tier,_=p.before_dispatch(method,path);p.observe(tier,{},200)
        assert len(clock.sleeps)==n;p.end_slot()
    assert clock.sleeps and clock.now()>1800000000

def test_route_mapping_matches_source_dependencies():
    assert route_tier('POST','/attest')=='authenticated'
    assert route_tier('POST','/attestation/revoke')=='authenticated'
    assert route_tier('GET','/attestation/revoked/test')=='public_read'
    assert route_tier('GET','/attestation/revocations')=='public_read'
    assert route_tier('GET','/governance/events')=='admin'
