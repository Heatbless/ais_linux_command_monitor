import copy
import json
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from ais.server.app import create_app
from ais.contracts import Assessment
from ais.sender import Outbox, Sender

@pytest.fixture
def env(tmp_path):
    now=[1000.0]
    app=create_app(tmp_path/'server.sqlite',secret='s'*48,operator_token='o'*48,clock=lambda:now[0],allowed_hosts=['testserver'],origin='http://testserver')
    agent,token=app.state.store.provision('VM','vm-01')
    with TestClient(app) as client:
        headers={'Authorization':'Bearer '+token}
        run={'run_id':str(uuid4()),'boot_id':'boot','mode':'demo','agent_version':'test'}
        assert client.post('/api/v1/agent-runs',json=run,headers=headers).status_code==200
        yield client,app,headers,run,now,agent

def item(run,count=1,sequence=1):
    return {'record_id':str(uuid4()),'run_id':run['run_id'],'sequence':sequence,'assessment':{'event_id':str(uuid4()),'host':'vm-01','boot_id':'boot','account':'web','role':'service','program':'python3','source':'exec','status':'warming_up','warnings':[{'rule':'python_attention','source':'rule','severity':'medium','reason':'Review Python','evidence_programs':['python3'],'group_id':'group','count':count}]}}

def post(client,headers,items):
    return client.post('/api/v1/events',json={'items':items},headers=headers)

def login(client):
    r=client.post('/operator/login',content='o'*48,headers={'Origin':'http://testserver'})
    assert r.status_code==200
    return {'Origin':'http://testserver','X-CSRF-Token':r.json()['csrf']}

def hb(run,seq=1):
    return {'run_id':run['run_id'],'boot_id':'boot','heartbeat_seq':seq,'uptime_seconds':1,'collector':{'mode':'replay','state':'healthy'},'detector':{'state':'running'},'delivery':{'state':'healthy'}}

def test_retry_atomic_conflict_grouping(env):
    c,app,h,r,now,agent=env
    a=item(r,count=5,sequence=5)
    assert post(c,h,[a]).status_code==200
    assert post(c,h,[a]).status_code==200
    earlier=item(r,count=2,sequence=2); earlier['assessment']['warnings'][0]['evidence_programs']=['old']
    assert post(c,h,[earlier]).status_code==200
    conflict=copy.deepcopy(a); conflict['sequence']=8
    assert post(c,h,[item(r),conflict]).status_code==409
    login(c)
    assert len(c.get('/api/v1/events').json()['items'])==2
    group=c.get('/api/v1/alerts').json()['items'][0]
    assert group['count']==5 and group['body']['warning']['evidence_programs']==['python3']
    assert c.post(f"/api/v1/alerts/{group['id']}/acknowledge").status_code==403
    csrf=login(c)
    for _ in range(2): assert c.post(f"/api/v1/alerts/{group['id']}/acknowledge",headers=csrf).status_code==200
    assert post(c,h,[item(r,count=10,sequence=10)]).status_code==200
    assert c.get('/api/v1/alerts').json()['items'][0]['acknowledged']==1

def test_heartbeat_receipt_freshness_retired_runs(env):
    c,app,h,r,now,agent=env
    login(c)
    def state(): return c.get('/api/v1/agents').json()['items'][0]['state']
    assert state()=='pending'
    body=hb(r)
    assert c.post('/api/v1/heartbeat',json=body,headers=h).status_code==200
    assert state()=='online'
    now[0]+=90
    assert c.post('/api/v1/heartbeat',json=body,headers=h).status_code==200
    assert state()=='unreachable'
    body['heartbeat_seq']=2; body['collector']['state']='stopped'
    assert c.post('/api/v1/heartbeat',json=body,headers=h).status_code==200
    assert state()=='degraded'
    second={**r,'run_id':str(uuid4())}
    assert c.post('/api/v1/agent-runs',json=second,headers=h).status_code==200
    assert c.post('/api/v1/agent-runs',json=r,headers=h).status_code==409
    assert c.post('/api/v1/heartbeat',json=body,headers=h).status_code==409
    assert post(c,h,[item(r)]).status_code==200
    assert state()=='pending'

@pytest.mark.parametrize('status',['scored','warming_up','no_profile','missing_session_context','missing_features','duplicate','authentication_context','failed_execution'])
def test_statuses(status):
    a=item({'run_id':str(uuid4())})['assessment']; a['status']=status
    assert Assessment.model_validate(a).status==status

def test_privacy_auth_limits(env):
    c,app,h,r,now,agent=env
    assert c.get('/api/v1/agents',headers=h).status_code==401
    for path in ['/api/v1/agent-runs','/api/v1/events','/api/v1/heartbeat']:
        assert c.post(path,json={},headers={'Authorization':'Bearer wrong'}).status_code==401
    a=item(r); a['assessment']['argv']='PRIVATE-CONTENT'
    response=post(c,h,[a]); assert response.status_code==422 and 'PRIVATE-CONTENT' not in response.text and 'argv' not in response.text
    a=item(r); a['assessment']['host']='other'
    assert post(c,h,[a]).status_code==409
    a=item(r); a['assessment']['service_id']='/raw/path'
    assert post(c,h,[a]).status_code==422
    assert c.post('/api/v1/events',content='x'*1048577,headers=h).status_code==413
    a=item(r); a['assessment']['ais']={'score':float('inf')}
    body=json.dumps({'items':[a]})
    assert c.post('/api/v1/events',content=body,headers=h).status_code==422
    with app.state.store.connect() as db: db.execute('UPDATE agents SET enabled=0 WHERE id=?',(agent,))
    assert post(c,h,[item(r)]).status_code==401

def test_outbox_restart_delivery_and_loss(env,tmp_path):
    c,app,h,r,now,agent=env
    box=Outbox(tmp_path/'outbox.sqlite',max_records=2)
    with box.connect() as db: db.execute('INSERT INTO runs(run_id,body) VALUES(?,?)',(r['run_id'],json.dumps(r)))
    a=item(r)['assessment']; a['argv']='discard this'
    first=box.enqueue(a,r['run_id']); assert first
    sender=Sender(box,'http://testserver',h['Authorization'][7:],client=c)
    sender.flush()
    assert box.health()['queue_depth']==0
    box=Outbox(tmp_path/'outbox.sqlite',max_records=2)
    for _ in range(3): box.enqueue(a,r['run_id'])
    assert box.health()['dropped_warnings']==1
    assert box.health()['state']=='degraded'
    a['service_id']='/raw/path'
    assert box.enqueue(a,r['run_id']) is None
    with box.connect() as db:
        assert 'discard this' not in ''.join(row[0] for row in db.execute('SELECT body FROM queue'))
        assert db.execute('SELECT COUNT(*) FROM rejections').fetchone()[0]==1

def test_retention_backup_restart(env,tmp_path):
    c,app,h,r,now,agent=env
    assert post(c,h,[item(r)]).status_code==200
    a=item(r); a['assessment']['warnings']=[]
    assert post(c,h,[a]).status_code==200
    app.state.store.cleanup(now[0]+8*86400)
    with app.state.store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM assessments').fetchone()[0]==1
        assert db.execute('SELECT COUNT(*) FROM ingest_receipts').fetchone()[0]==2
    app.state.store.backup(tmp_path/'backup.sqlite')
    from ais.server.storage import Store
    restored=Store(tmp_path/'backup.sqlite')
    with restored.connect() as db:
        assert db.execute('SELECT count FROM alert_groups').fetchone()[0]==1
        assert db.execute('SELECT token_hash FROM agents').fetchone()[0]

def test_network_retry_preserves_envelope_and_quarantine(env,tmp_path):
    import httpx
    c,app,h,r,now,agent=env
    box=Outbox(tmp_path/'retry.sqlite')
    with box.connect() as db: db.execute('INSERT INTO runs(run_id,body) VALUES(?,?)',(r['run_id'],json.dumps(r)))
    box.enqueue(item(r)['assessment'],r['run_id'])
    attempts=[]
    def failed(request):
        attempts.append(request.content)
        raise httpx.ConnectError('offline',request=request)
    s=Sender(box,'https://agent.invalid',h['Authorization'][7:],client=httpx.Client(transport=httpx.MockTransport(failed)),clock=lambda:now[0])
    s.flush()
    assert box.health()['queue_depth']==1 and box.health()['state']=='degraded'
    def retry(request):
        attempts.append(request.content)
        return httpx.Response(200,json={'accepted_record_ids':[json.loads(request.content)['items'][0]['record_id']]})
    restarted=Sender(Outbox(tmp_path/'retry.sqlite'),'https://agent.invalid',h['Authorization'][7:],client=httpx.Client(transport=httpx.MockTransport(retry)))
    restarted.flush()
    assert attempts[0]==attempts[1] and box.health()['queue_depth']==0
    box.enqueue(item(r)['assessment'],r['run_id'])
    bad=Sender(box,'https://agent.invalid','wrong',client=httpx.Client(transport=httpx.MockTransport(lambda req:httpx.Response(401))))
    bad.flush(); assert bad.paused and box.health()['queue_depth']==1
    bad.credentials('corrected'); assert not bad.paused
    bad.client=httpx.Client(transport=httpx.MockTransport(lambda req:httpx.Response(422)))
    bad.flush(); assert box.health()['queue_depth']==0 and box.health()['last_error_code']=='http_422'

def test_identity_isolation_cursor_severity_and_escape(env):
    c,app,h,r,now,agent=env
    other,token=app.state.store.provision('other','vm-01')
    assert post(c,{'Authorization':'Bearer '+token},[item(r)]).status_code==409
    a=item(r,count=8,sequence=8); a['assessment']['warnings'][0]['severity']='high'
    b=item(r,count=2,sequence=2)
    assert post(c,h,[a,b]).status_code==200
    login(c)
    first=c.get('/api/v1/events?limit=1').json()
    second=c.get('/api/v1/events',params={'limit':1,'cursor':first['next_cursor']}).json()
    assert first['items'][0]['id']!=second['items'][0]['id']
    assert c.get('/api/v1/alerts').json()['items'][0]['severity']=='high'
    assert c.get('/api/v1/events',params={'agent':other}).json()['items']==[]
    assert 'textContent' in c.get('/static/dashboard.js').text
    assert 'innerHTML' not in c.get('/static/dashboard.js').text
