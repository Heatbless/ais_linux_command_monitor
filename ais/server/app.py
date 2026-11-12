import asyncio
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from uuid import uuid4
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from ais.contracts import Batch, Run, Heartbeat, canonical
from ais.server.storage import Store


def fail(status, code):
    raise HTTPException(status, detail={'code': code})


def create_app(db_path=None, secret=None, operator_token=None, clock=time.time, allowed_hosts=None, origin=None, additional_origins=()):
    store = Store(db_path or os.environ.get('AIS_DATABASE', 'var/server.sqlite'))
    secret = secret or os.environ.get('AIS_SERVER_SECRET')
    operator_token = operator_token or os.environ.get('AIS_OPERATOR_TOKEN')
    if not secret or len(secret) < 32 or not operator_token or len(operator_token) < 32:
        raise RuntimeError('Set AIS_SERVER_SECRET and AIS_OPERATOR_TOKEN to independent random secrets (32+ characters)')
    origin = origin or os.environ.get('AIS_OPERATOR_ORIGIN', 'http://127.0.0.1:8000')
    allowed_origins = frozenset((origin, *additional_origins))
    if origin.startswith('https:') and any(not item.startswith('https:') for item in allowed_origins):
        raise ValueError('Cannot add HTTP origins to an HTTPS-only dashboard')

    @asynccontextmanager
    async def lifespan(app):
        async def maintenance():
            last_cleanup = 0
            while True:
                await asyncio.to_thread(store.sweep, clock())
                if clock() - last_cleanup >= 86400:
                    await asyncio.to_thread(store.cleanup, clock())
                    last_cleanup = clock()
                await asyncio.sleep(5)
        task = asyncio.create_task(maintenance())
        yield
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.add_middleware(SessionMiddleware, secret_key=secret, same_site='strict', https_only=origin.startswith('https:'), max_age=8*3600)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or os.environ.get('AIS_ALLOWED_HOSTS','127.0.0.1,localhost').split(','))
    templates = Jinja2Templates(directory=str(Path(__file__).parent / 'templates'))

    @app.middleware('http')
    async def bounds(request, call_next):
        # Consume with a streaming bound before JSON parsing, including chunked bodies.
        if request.method == 'POST':
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 1048576:
                    return JSONResponse({'code':'body_too_large'}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({'code':'schema_error','fields':[{'path':list(e['loc']), 'code':e['type']} for e in exc.errors()]}, status_code=422)

    @app.exception_handler(sqlite3.OperationalError)
    async def database_busy(request, exc):
        return JSONResponse({'code':'storage_unavailable'}, status_code=503)

    async def parse(request, contract):
        try:
            return contract.model_validate_json(await request.body())
        except ValidationError as exc:
            # Unknown key names can themselves contain raw data; return schema paths only.
            fields = [{'path':[x if isinstance(x,int) or x in contract.model_fields else 'field' for x in e['loc']], 'code': e['type']} for e in exc.errors()]
            return_error = HTTPException(422, detail={'code':'schema_error','fields':fields})
            raise return_error from None

    def agent(request: Request):
        token = request.headers.get('authorization','').removeprefix('Bearer ')
        with store.connect() as db:
            row = db.execute('SELECT * FROM agents WHERE id=?', (token.split('.')[0],)).fetchone()
        digest = hashlib.sha256(token.encode()).hexdigest()
        if not row or not row['enabled'] or not hmac.compare_digest(row['token_hash'],digest):
            fail(401, 'bad_token')
        return dict(row)

    def operator(request: Request):
        if not request.session.get('operator'):
            fail(401,'operator_required')

    def csrf(request):
        if request.headers.get('origin') not in allowed_origins or not hmac.compare_digest(request.headers.get('x-csrf-token',''),request.session.get('csrf','!')):
            fail(403,'csrf_failed')

    @app.post('/operator/login')
    async def login(request: Request):
        if request.headers.get('origin') not in allowed_origins:
            fail(403,'origin_failed')
        if not hmac.compare_digest((await request.body()).decode(errors='replace'), operator_token):
            fail(401,'bad_operator_token')
        request.session.clear()
        request.session.update(operator=True, csrf=secrets.token_urlsafe(32))
        return {'csrf':request.session['csrf']}

    @app.get('/operator/session', dependencies=[Depends(operator)])
    def session(request: Request):
        return {'csrf':request.session['csrf']}

    @app.post('/api/v1/agent-runs')
    async def register(request: Request, identity=Depends(agent)):
        run = await parse(request, Run)
        body = canonical(run)
        now = clock()
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM agent_runs WHERE agent_id=? AND run_id=?',(identity['id'],str(run.run_id))).fetchone()
            if old:
                if old['body'] != body:
                    fail(409,'run_content_conflict')
                if old['retired_at'] is not None:
                    fail(409,'retired_run')
            else:
                db.execute('UPDATE agent_runs SET retired_at=? WHERE agent_id=? AND retired_at IS NULL',(now,identity['id']))
                db.execute('INSERT INTO agent_runs(agent_id,run_id,body,registered_at) VALUES(?,?,?,?)',(identity['id'],str(run.run_id),body,now))
                db.execute('UPDATE agents SET current_run=?, heartbeat=NULL, heartbeat_at=NULL WHERE id=?',(str(run.run_id),identity['id']))
        store.sweep(now)
        return {'agent_id':identity['id'],'run_id':str(run.run_id),'learning_enabled':False}

    @app.post('/api/v1/heartbeat')
    async def heartbeat(request: Request, identity=Depends(agent)):
        h = await parse(request, Heartbeat)
        body = canonical(h)
        digest = hashlib.sha256(body.encode()).hexdigest()
        now = clock()
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            r = db.execute('SELECT * FROM agent_runs WHERE agent_id=? AND run_id=?',(identity['id'],str(h.run_id))).fetchone()
            if not r or r['retired_at'] is not None:
                fail(409,'wrong_or_retired_run')
            registration = json.loads(r['body'])
            if h.boot_id != registration['boot_id'] or h.capabilities.model_dump() != registration['capabilities']:
                fail(409,'run_identity_conflict')
            if h.heartbeat_seq < r['heartbeat_seq'] or (h.heartbeat_seq == r['heartbeat_seq'] and digest != r['heartbeat_digest']):
                fail(409,'heartbeat_sequence_conflict')
            if h.heartbeat_seq > r['heartbeat_seq']:
                db.execute('UPDATE agent_runs SET heartbeat_seq=?,heartbeat_digest=? WHERE agent_id=? AND run_id=?',(h.heartbeat_seq,digest,identity['id'],str(h.run_id)))
                db.execute('UPDATE agents SET heartbeat=?,heartbeat_at=? WHERE id=?',(body,now,identity['id']))
            receipt = db.execute('SELECT heartbeat_at FROM agents WHERE id=?',(identity['id'],)).fetchone()[0]
        store.sweep(now)
        return {'received_at':receipt,'learning_enabled':False}

    @app.post('/api/v1/events')
    async def events(request: Request, identity=Depends(agent)):
        batch = await parse(request, Batch)
        now = clock()
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for item in batch.items:
                a = item.assessment
                if a.host != identity['host']:
                    fail(409,'host_mismatch')
                r = db.execute('SELECT body FROM agent_runs WHERE agent_id=? AND run_id=?',(identity['id'],str(item.run_id))).fetchone()
                if not r or json.loads(r['body'])['boot_id'] != a.boot_id:
                    fail(409,'run_identity_conflict')
                body = canonical(item)
                digest = hashlib.sha256(body.encode()).hexdigest()
                old = db.execute('SELECT digest FROM ingest_receipts WHERE agent_id=? AND record_id=?',(identity['id'],str(item.record_id))).fetchone()
                if old:
                    if old['digest'] != digest:
                        fail(409,'record_content_conflict')
                    continue
                db.execute('INSERT INTO ingest_receipts VALUES(?,?,?,?)',(identity['id'],str(item.record_id),digest,now))
                db.execute('INSERT INTO assessments(agent_id,run_id,record_id,sequence,received_at,observed_at,account,role,program,status,source,warning,body) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(identity['id'],str(item.run_id),str(item.record_id),item.sequence,now,a.timestamp,a.account,a.role,a.program,a.status,a.source,bool(a.warnings),canonical(a)))
                for w in a.warnings:
                    key = (identity['id'],str(item.run_id),w.group_id,w.rule)
                    old = db.execute('SELECT * FROM alert_groups WHERE agent_id=? AND run_id=? AND group_id=? AND rule=?',key).fetchone()
                    evidence = canonical({'warning':w.model_dump(mode='json'),'account':a.account,'role':a.role,'stage_hints':a.stage_hints})
                    if not old:
                        db.execute('INSERT INTO alert_groups(agent_id,run_id,group_id,rule,source,severity,count,first_received,last_received,first_observed,last_observed,sequence,body) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(*key,w.source,w.severity,w.count,now,now,a.timestamp,a.timestamp,item.sequence,evidence))
                    else:
                        if old['source'] != w.source:
                            fail(409,'warning_source_conflict')
                        severity = max((old['severity'],w.severity),key=['low','medium','high','critical'].index)
                        observed = [v for v in (old['first_observed'],old['last_observed'],a.timestamp) if v is not None]
                        db.execute('UPDATE alert_groups SET count=?,severity=?,last_received=?,first_observed=?,last_observed=?,sequence=?,body=? WHERE id=?',(max(old['count'],w.count),severity,now,min(observed) if observed else None,max(observed) if observed else None,max(old['sequence'],item.sequence),evidence if item.sequence > old['sequence'] else old['body'],old['id']))
        return {'accepted_record_ids':[str(i.record_id) for i in batch.items]}

    @app.get('/healthz')
    def health():
        with store.connect() as db:
            db.execute('SELECT 1').fetchone()
        return {'status':'ready'}

    @app.get('/api/v1/agents', dependencies=[Depends(operator)])
    def agents():
        store.sweep(clock())
        with store.connect() as db:
            rows = db.execute('SELECT id,name,host,enabled,current_run,heartbeat,heartbeat_at,state FROM agents').fetchall()
            results = []
            for row in rows:
                result = dict(row)
                result['heartbeat'] = json.loads(row['heartbeat']) if row['heartbeat'] else None
                run = db.execute('SELECT body FROM agent_runs WHERE agent_id=? AND run_id=?',(row['id'],row['current_run'])).fetchone()
                result['run'] = json.loads(run[0]) if run else None
                results.append(result)
        return {'items':results,'server_time':clock()}

    @app.get('/api/v1/agents/{agent_id}', dependencies=[Depends(operator)])
    def detail(agent_id: str):
        data = next((a for a in agents()['items'] if a['id']==agent_id),None)
        if not data:
            fail(404,'agent_not_found')
        with store.connect() as db:
            data['transitions'] = [dict(r) for r in db.execute('SELECT * FROM health_transitions WHERE agent_id=? ORDER BY received_at DESC,id DESC LIMIT 200',(agent_id,))]
            data['coverage'] = [dict(r) for r in db.execute('SELECT account,role,status,program,received_at FROM assessments WHERE agent_id=? ORDER BY received_at DESC,id DESC LIMIT 50',(agent_id,))]
        return data

    def page(request, table, filters, time_column):
        clauses, params = [], []
        for query, column in filters.items():
            if query in request.query_params:
                clauses.append(column+'=?'); params.append(request.query_params[query])
        try:
            limit = min(200,max(1,int(request.query_params.get('limit','50'))))
            cursor = request.query_params.get('cursor')
            if cursor:
                stamp, row_id = cursor.split(',')
                clauses.append(f'({time_column},id)<(?,?)'); params.extend((float(stamp),int(row_id)))
            for name, op in [('since','>='),('until','<=')]:
                if name in request.query_params:
                    clauses.append(time_column+op+'?'); params.append(float(request.query_params[name]))
        except ValueError:
            fail(422,'invalid_pagination')
        where = ' WHERE '+' AND '.join(clauses) if clauses else ''
        with store.connect() as db:
            rows = [dict(r) for r in db.execute(f'SELECT * FROM {table}{where} ORDER BY {time_column} DESC,id DESC LIMIT ?',(*params,limit+1))]
        has_more = len(rows)>limit
        rows = rows[:limit]
        for row in rows:
            row['body']=json.loads(row['body'])
        return {'items':rows,'next_cursor':f"{rows[-1][time_column]},{rows[-1]['id']}" if rows and has_more else None}

    @app.get('/api/v1/events', dependencies=[Depends(operator)])
    def activity(request: Request):
        return page(request,'assessments',{'agent':'agent_id','account':'account','source':'source','status':'status'},'received_at')

    @app.get('/api/v1/alerts', dependencies=[Depends(operator)])
    def alerts(request: Request):
        return page(request,'alert_groups',{'agent':'agent_id','rule':'rule','severity':'severity','source':'source','acknowledged':'acknowledged'},'last_received')

    @app.post('/api/v1/alerts/{alert_id}/acknowledge', dependencies=[Depends(operator)])
    def acknowledge(alert_id: int, request: Request):
        csrf(request)
        with store.connect() as db:
            if not db.execute('UPDATE alert_groups SET acknowledged=1 WHERE id=?',(alert_id,)).rowcount:
                fail(404,'alert_not_found')
        return {'acknowledged':True}

    @app.get('/', response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse(request=request,name='dashboard.html',context={'authenticated':bool(request.session.get('operator'))})

    @app.get('/static/{asset}')
    def static(asset: str):
        from fastapi.responses import FileResponse
        if asset not in ('dashboard.js','style.css'):
            fail(404,'not_found')
        return FileResponse(Path(__file__).parent/'static'/asset)

    return app
