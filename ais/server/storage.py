import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

SCHEMA = '''
CREATE TABLE agents(id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, token_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, current_run TEXT, heartbeat TEXT, heartbeat_at REAL, state TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE agent_runs(agent_id TEXT NOT NULL REFERENCES agents(id), run_id TEXT NOT NULL, body TEXT NOT NULL, retired_at REAL, registered_at REAL NOT NULL, heartbeat_seq INTEGER NOT NULL DEFAULT 0, heartbeat_digest TEXT, PRIMARY KEY(agent_id,run_id));
CREATE TABLE ingest_receipts(agent_id TEXT NOT NULL REFERENCES agents(id), record_id TEXT NOT NULL, digest TEXT NOT NULL, received_at REAL NOT NULL, PRIMARY KEY(agent_id,record_id));
CREATE TABLE assessments(id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), run_id TEXT NOT NULL, record_id TEXT NOT NULL, sequence INTEGER NOT NULL, received_at REAL NOT NULL, observed_at REAL, account TEXT, role TEXT, program TEXT, status TEXT, source TEXT, warning INTEGER NOT NULL, body TEXT NOT NULL);
CREATE INDEX activity_page ON assessments(agent_id,received_at,id);
CREATE TABLE alert_groups(id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), run_id TEXT NOT NULL, group_id TEXT NOT NULL, rule TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL, count INTEGER NOT NULL, first_received REAL NOT NULL, last_received REAL NOT NULL, first_observed REAL, last_observed REAL, sequence INTEGER NOT NULL, body TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, UNIQUE(agent_id,run_id,group_id,rule));
CREATE INDEX warning_page ON alert_groups(agent_id,acknowledged,severity,last_received);
CREATE TABLE health_transitions(id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), previous TEXT, state TEXT NOT NULL, received_at REAL NOT NULL, reason TEXT NOT NULL);
PRAGMA user_version=1;
'''

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version == 0:
                db.executescript(SCHEMA)
            elif version != 1:
                raise RuntimeError('unsupported database version')
        Path(path).chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=5000')
        try:
            with db:
                yield db
        finally:
            db.close()

    def provision(self, name, host):
        agent_id = str(uuid4())
        token = agent_id + '.' + secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('INSERT INTO agents(id,name,host,token_hash) VALUES(?,?,?,?)', (agent_id,name,host,hashlib.sha256(token.encode()).hexdigest()))
        return agent_id, token

    def rotate(self, agent_id):
        token = agent_id + '.' + secrets.token_urlsafe(32)
        with self.connect() as db:
            if not db.execute('UPDATE agents SET token_hash=? WHERE id=?', (hashlib.sha256(token.encode()).hexdigest(),agent_id)).rowcount:
                raise ValueError('unknown agent')
        return token

    @staticmethod
    def availability(agent, now):
        if agent['heartbeat_at'] is None:
            return 'pending'
        if now - agent['heartbeat_at'] >= 90:
            return 'unreachable'
        h = json.loads(agent['heartbeat'])
        if h['collector']['state'] != 'healthy' or h['detector']['state'] == 'unavailable' or h['delivery']['state'] == 'degraded':
            return 'degraded'
        return 'online'

    def sweep(self, now):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for agent in db.execute('SELECT * FROM agents').fetchall():
                state = self.availability(agent, now)
                if state != agent['state']:
                    db.execute('UPDATE agents SET state=? WHERE id=?', (state,agent['id']))
                    db.execute('INSERT INTO health_transitions(agent_id,previous,state,received_at,reason) VALUES(?,?,?,?,?)', (agent['id'],agent['state'],state,now,state))

    def cleanup(self, now, batch=1000):
        with self.connect() as db:
            for table, predicate, args in [
                ('assessments','received_at < ? AND (warning=0 OR received_at < ?)',(now-7*86400,now-90*86400)),
                ('ingest_receipts','received_at < ?',(now-90*86400,)),
                ('alert_groups','last_received < ?',(now-90*86400,)),
                ('health_transitions','received_at < ?',(now-90*86400,))]:
                db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {predicate} LIMIT ?)', (*args,batch))

    def backup(self, target):
        with self.connect() as db, sqlite3.connect(str(target)) as dest:
            db.backup(dest)
        Path(target).chmod(0o600)
