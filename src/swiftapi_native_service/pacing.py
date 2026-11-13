
import time
import math
import threading
from functools import wraps
from email.utils import parsedate_to_datetime

LIMITS={'authenticated':300,'public_read':120,'public_write':30,'admin':60}
RESERVE=5
WINDOW=61.0
SLOT_BUDGETS={
    'VALID':{'authenticated':4,'public_read':5},
    'SIGNED_DENIAL':{'authenticated':4,'public_read':3},
    'MISSING_GRANT':{'authenticated':2,'public_read':2},
    'INVALID_SIGNATURE':{'authenticated':4,'public_read':4},
    'EXPIRED':{'authenticated':4,'public_read':4},
    'REUSED':{'authenticated':2,'public_read':2},
    'WRONG_SCOPE':{'authenticated':5,'public_read':5},
    'WRONG_REQUEST':{'authenticated':4,'public_read':4},
    'UNKNOWN_KEY':{'authenticated':1},'MALFORMED_KEY':{},
    
    
    'REVOKED':{'authenticated':7,'public_read':30},
}


REVOKE_CONTINUATION_BUDGET={'authenticated':4,'public_read':25}

def synchronized(method):
    @wraps(method)
    def guarded(self,*args,**kwargs):
        with self.lock:return method(self,*args,**kwargs)
    return guarded

def route_tier(method,path):
    if path in ('/attest','/attestation/revoke'):return 'authenticated'
    if path in ('/governance/events','/authority/denials'):return 'admin'
    if path=='/audit':return 'authenticated'
    return 'public_read' if method.upper() in ('GET','HEAD') else 'public_write'

class AuthorityPacer:
    def __init__(self,emit=None,*,clock=None,sleep=None):
        self.lock=threading.RLock()
        self.emit=emit or (lambda event:None)
        self.clock=clock or time.monotonic;self.sleep=sleep or time.sleep
        self.headers={};self.calls={tier:[] for tier in LIMITS}
        self.last_dispatch={};self.active=None;self.remaining={};self.stopped=False

    def _clean(self,tier,now):
        self.calls[tier]=[t for t in self.calls[tier] if now-t<WINDOW]

    def _wait_plan(self,budget,skip_fallback=()):
        now=self.clock();waits=[]
        for tier,count in budget.items():
            if not count:continue
            self._clean(tier,now)
            header=self.headers.get(tier)
            limit=min(LIMITS[tier],header['limit']) if header else LIMITS[tier]
            if count+RESERVE>limit:raise ValueError('Slot exceeds conservative tier capacity: '+tier)
            if len(self.calls[tier])+count+RESERVE>limit:
                waits.append((self.calls[tier][0]+WINDOW-now,tier,
                              limit-len(self.calls[tier]),'LOCAL_SLIDING_WINDOW'))
            if header and now<header['expires'] and header['remaining']-count<RESERVE:
                waits.append((header['expires']-now,tier,header['remaining'],'HEADER_RESET'))
            elif not header and tier not in skip_fallback:
                
                spacing=count*WINDOW/(limit-RESERVE)
                delay=self.last_dispatch.get(tier,now)+spacing-now
                if delay>0:waits.append((delay,tier,None,'NO_HEADERS_CONSERVATIVE_SPACING'))
        return max(waits,key=lambda row:row[0],default=(0,None,None,None))

    @synchronized
    def reserve(self,budget,label):
        from .core import ServiceError
        if self.stopped:raise ServiceError('AUTHORITY_RATE_LIMITED',429)
        if self.active is not None:raise ServiceError('PACING_SLOT_ALREADY_ACTIVE',500)
        
        
        fallback_paid=set()
        while True:
            delay,tier,remaining,reason=self._wait_plan(budget,fallback_paid)
            if delay<=1e-6:break
            self.emit({'stage':'PACING_SLEEP','tier':tier,'remaining':remaining,
                       'seconds':delay,'reason':reason,'location':'BEFORE_SLOT_ISSUANCE',
                       'slot':label,'observed_at':time.time()})
            
            left=delay
            while left>0:
                chunk=min(left,30.0);self.sleep(chunk);left-=chunk
            if reason=='NO_HEADERS_CONSERVATIVE_SPACING':fallback_paid.add(tier)
        self.active=label;self.remaining=dict(budget)
        self.emit({'stage':'PACING_RESERVATION','slot':label,'budget':dict(budget),
                   'reserve_per_tier':RESERVE,'observed_at':time.time()})

    def begin_slot(self,arm):self.reserve(SLOT_BUDGETS[arm],arm)

    @synchronized
    def end_slot(self):
        self.active=None;self.remaining={}

    @synchronized
    def assert_revoke_capacity(self):
        pass
        from .core import ServiceError
        if self.stopped:raise ServiceError('AUTHORITY_RATE_LIMITED',429)
        if self.active!='REVOKED':
            raise ServiceError('PACING_REVOKE_SLOT_REQUIRED',503)
        now=self.clock()
        for tier,count in REVOKE_CONTINUATION_BUDGET.items():
            self._clean(tier,now)
            header=self.headers.get(tier)
            limit=min(LIMITS[tier],header['limit']) if header else LIMITS[tier]
            if (self.remaining.get(tier,0)<count
                    or len(self.calls[tier])+count+RESERVE>limit
                    or (header and now<header['expires']
                        and header['remaining']-count<RESERVE)):
                raise ServiceError('PACING_REVOKE_CONTINUATION_RESERVE_INSUFFICIENT',503)
        self.emit({'stage':'PACING_REVOKE_CAPACITY_CHECK','slot':self.active,
                   'required':dict(REVOKE_CONTINUATION_BUDGET),
                   'remaining':dict(self.remaining),'before_revoke_post':True,
                   'observed_at':time.time()})

    @synchronized
    def before_dispatch(self,method,path):
        from .core import ServiceError
        tier=route_tier(method,path)
        standalone=self.active is None
        if standalone:self.reserve({tier:1},'READ_OR_CALL_WITHOUT_LIVE_SLOT_GRANT')
        if self.stopped:raise ServiceError('AUTHORITY_RATE_LIMITED',429)
        now=self.clock();self._clean(tier,now)
        header=self.headers.get(tier)
        if self.remaining.get(tier,0)<=0:
            raise ServiceError('PACING_RESERVED_CALL_BUDGET_EXCEEDED',503)
        if header and now<header['expires'] and header['remaining']-1<RESERVE:
            
            
            raise ServiceError('PACING_RESERVE_LOST_AT_BOUNDARY',503)
        self.remaining[tier]-=1;self.calls[tier].append(now);self.last_dispatch[tier]=now
        if header and now<header['expires']:header['remaining']-=1
        return tier,standalone

    @synchronized
    def observe(self,tier,headers,status):
        normalized={str(k).lower():v for k,v in headers.items()}
        raw={k:normalized.get(k.lower()) for k in
             ('X-RateLimit-Limit','X-RateLimit-Remaining','X-RateLimit-Reset')}
        try:
            limit=int(raw['X-RateLimit-Limit']);remaining=int(raw['X-RateLimit-Remaining'])
            reset=float(raw['X-RateLimit-Reset'])
            if limit<=0 or remaining<0 or remaining>limit or not math.isfinite(reset):raise ValueError()
            try:server=parsedate_to_datetime(normalized['date']).timestamp()
            except (KeyError,ValueError,TypeError,AttributeError):server=time.time()
            
            expires=self.clock()+max(WINDOW,reset-server+2)
            self.headers[tier]={'limit':limit,'remaining':remaining,'expires':expires}
            valid=True
        except (ValueError,TypeError,OverflowError):
            self.headers.pop(tier,None);valid=False
        if status==429:self.stopped=True
        return {'tier':tier,'headers':raw,'usable':valid,'reserve':RESERVE,
                'retry_after':normalized.get('retry-after')}
