"""Self-contained transport demonstration, pending the external detector source."""
import argparse
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
from ais.sender import Outbox, Sender
from ais.server.app import create_app


def demonstrate(directory):
    secret='demo-server-secret-which-is-never-for-deployment'
    operator='demo-operator-secret-which-is-never-for-deployment'
    app=create_app(directory/'server.sqlite',secret=secret,operator_token=operator,allowed_hosts=['testserver'],origin='http://testserver')
    agent,token=app.state.store.provision('Synthetic VM','demo-vm')
    outbox=Outbox(directory/'outbox.sqlite')
    run=outbox.new_run('demo-boot',mode='demo')
    with TestClient(app) as client:
        sender=Sender(outbox,'http://testserver',token,client=client)
        sender.register(run)
        for index,program in enumerate(('nginx','python3','sh')):
            a={'event_id':f'demo-{index}','host':'demo-vm','boot_id':'demo-boot','account':'web','role':'service','source':'exec','program':program,'status':'warming_up','warnings':[]}
            if program=='python3':
                a['warnings']=[{'rule':'python_attention','source':'rule','severity':'medium','reason':'Synthetic Python policy observation','evidence_programs':['nginx','python3'],'group_id':'demo-python','count':1}]
            sender.enqueue(a,run.run_id)
        sender.flush()
        heartbeat={'run_id':str(run.run_id),'boot_id':run.boot_id,'heartbeat_seq':1,'uptime_seconds':1,'collector':{'mode':'replay','state':'healthy','collected':3},'detector':{'state':'running','experimental':True},'delivery':outbox.health()}
        assert client.post('/api/v1/heartbeat',json=heartbeat,headers={'Authorization':'Bearer '+token}).status_code==200
        login=client.post('/operator/login',content=operator,headers={'Origin':'http://testserver'})
        assert login.status_code==200
        activity=client.get('/api/v1/events').json()['items']
        alerts=client.get('/api/v1/alerts').json()['items']
        assert len(activity)==3 and len(alerts)==1
        assert client.get('/api/v1/agents').json()['items'][0]['run']['mode']=='demo'
        assert client.get('/').status_code==200
        print('Demo passed: 3 assessments, 1 warning group, demo run, healthy replay heartbeat, private dashboard. No programs executed.')


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('--directory',type=Path)
    args=p.parse_args()
    if args.directory:
        args.directory.mkdir(parents=True,exist_ok=True); demonstrate(args.directory)
    else:
        with TemporaryDirectory(prefix='ais-demo-') as directory: demonstrate(Path(directory))

if __name__=='__main__': main()
