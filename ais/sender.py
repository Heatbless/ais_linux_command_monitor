"""Durable sanitized outbox. Importing this module never executes telemetry."""

import asyncio
import copy
import email.utils
import ipaddress
import json
import random
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import ValidationError

from ais.contracts import Assessment, Envelope, Run, canonical

FIELDS = (
    "event_id host boot_id account role source program timestamp uid login_uid session service_id lineage_id parent_program stage_hints path_kind used_sudo wrapper_opaque coverage_notes context known_reference model_version first_seen_for_profile unexpected_parent sequence_reset status ais markov warnings"
).split()


def clip(value, size):
    return value.encode("utf-8")[:size].decode("utf-8", errors="ignore")


def map_assessment(output):
    data = {key: copy.deepcopy(output[key]) for key in FIELDS if key in output}
    # Server v1 accepts a quality label and reset flag, whereas Engine retains
    # full calibration diagnostics and the reset reason in its local output.
    reset = data.get("sequence_reset")
    if isinstance(reset, str):
        if reset not in {"idle_gap", "out_of_order"}:
            raise ValueError("Unknown sequence reset")
        data["sequence_reset"] = True
    score = data.get("ais")
    if isinstance(score, dict) and isinstance(score.get("quality"), dict):
        quality = score["quality"]
        if (
            quality.get("experimental") is not True
            or quality.get("deployment_ready") is not False
        ):
            raise ValueError("Unsupported model quality")
        score["quality"] = "experimental"
    truncated = []
    for index, warning in enumerate(data.get("warnings", [])):
        prefix = f"warnings.{index}"
        reason = warning.get("reason", "")
        if len(reason.encode()) > 512:
            warning["reason"] = clip(reason, 512)
            truncated.append(prefix + ".reason")
        evidence = warning.get("evidence_programs", [])
        if len(evidence) > 10:
            truncated.append(prefix + ".evidence_programs")
        warning["evidence_programs"] = []
        for j, program in enumerate(evidence[-10:]):
            if len(program.encode()) > 128:
                truncated.append(prefix + f".evidence_programs.{j}")
            warning["evidence_programs"].append(clip(program, 128))
    return Assessment.model_validate_json(json.dumps(data, allow_nan=False)), truncated


class Outbox:
    def __init__(self, path, max_records=100000, max_bytes=256 * 1024 * 1024):
        self.path = str(path)
        self.max_records = max_records
        self.max_bytes = max_bytes
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        Path(path).touch(mode=0o600, exist_ok=True)
        Path(path).chmod(0o600)
        with self.connect() as db:
            db.executescript("""PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, body TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS queue(id INTEGER PRIMARY KEY, record_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL, warning INTEGER NOT NULL, bytes INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS rejections(id INTEGER PRIMARY KEY, record_id TEXT, code TEXT NOT NULL, at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            """)
        Path(path).chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def new_run(self, boot_id, mode="replay", agent_version="server-adapter-v1"):
        run = Run.model_validate_json(
            json.dumps(
                {
                    "run_id": str(uuid4()),
                    "boot_id": boot_id,
                    "mode": mode,
                    "agent_version": agent_version,
                }
            )
        )
        with self.connect() as db:
            db.execute(
                "INSERT INTO runs(run_id,body) VALUES(?,?)",
                (str(run.run_id), canonical(run)),
            )
        return run

    def rejection(self, db, record_id, code):
        db.execute(
            "INSERT INTO rejections(record_id,code,at) VALUES(?,?,?)",
            (record_id, code, time.time()),
        )
        db.execute(
            "DELETE FROM rejections WHERE id NOT IN (SELECT id FROM rejections ORDER BY id DESC LIMIT 1000)"
        )
        db.execute("INSERT OR REPLACE INTO state VALUES('last_error',?)", (code,))

    def enqueue(self, output, run_id):
        if output.get("status") == "duplicate":
            return None
        record_id = str(uuid4())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                assessment, truncated = map_assessment(output)
                row = db.execute(
                    "SELECT sequence,body FROM runs WHERE run_id=?", (str(run_id),)
                ).fetchone()
                if not row:
                    raise ValueError("unknown run")
                if assessment.boot_id != json.loads(row["body"])["boot_id"]:
                    raise ValueError("Assessment boot differs from run")
                sequence = row[0] + 1
                item = Envelope.model_validate_json(
                    json.dumps(
                        {
                            "record_id": record_id,
                            "run_id": str(run_id),
                            "sequence": sequence,
                            "truncated_fields": truncated,
                            "assessment": assessment.model_dump(mode="json"),
                        }
                    )
                )
            except (ValidationError, ValueError, TypeError, KeyError, AttributeError):
                self.rejection(db, record_id, "invalid_assessment")
                return None
            body = canonical(item)
            db.execute(
                "UPDATE runs SET sequence=? WHERE run_id=?", (sequence, str(run_id))
            )
            db.execute(
                "INSERT INTO queue(record_id,body,warning,bytes) VALUES(?,?,?,?)",
                (record_id, body, bool(assessment.warnings), len(body.encode())),
            )
            while True:
                count, size = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM queue"
                ).fetchone()
                if count <= self.max_records and size <= self.max_bytes:
                    break
                old = db.execute(
                    "SELECT id,warning FROM queue ORDER BY warning,id LIMIT 1"
                ).fetchone()
                db.execute("DELETE FROM queue WHERE id=?", (old["id"],))
                key = "dropped_warnings" if old["warning"] else "dropped_assessments"
                db.execute(
                    "INSERT INTO state(key,value) VALUES(?,1) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1",
                    (key,),
                )
                db.execute(
                    "INSERT OR REPLACE INTO state VALUES('last_error','queue_loss')"
                )
        return record_id

    def checkpoint(self, key, value):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?)", (key, value))

    def health(self):
        with self.connect() as db:
            count, size = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM queue"
            ).fetchone()
            state = dict(db.execute("SELECT key,value FROM state").fetchall())
        return {
            "state": "degraded" if state.get("last_error") else "healthy",
            "queue_depth": count,
            "queue_bytes": size,
            "dropped_assessments": int(state.get("dropped_assessments", 0)),
            "dropped_warnings": int(state.get("dropped_warnings", 0)),
            "last_error_code": state.get("last_error"),
        }


class Sender:
    def __init__(
        self,
        outbox,
        url,
        token,
        client=None,
        clock=time.time,
        allow_tailscale_http=False,
        async_client_factory=None,
    ):
        endpoint = urlsplit(url)
        if (
            endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
            or endpoint.path not in {"", "/"}
        ):
            raise ValueError("Ingestion URL must be an origin without credentials")
        if endpoint.scheme not in {"https", "http"} or not endpoint.hostname:
            raise ValueError("Invalid ingestion origin")
        if endpoint.scheme != "https" and client is None:
            try:
                private_tailnet = ipaddress.ip_address(
                    endpoint.hostname
                ) in ipaddress.ip_network("100.64.0.0/10")
            except ValueError:
                private_tailnet = False
            if not allow_tailscale_http or not private_tailnet:
                raise ValueError(
                    "HTTPS required unless private Tailscale HTTP is explicitly enabled"
                )
        self.outbox = outbox
        self.token = token
        self.url = url.rstrip("/")
        self.client = client or httpx.Client(timeout=15, verify=True, trust_env=False)
        self.async_client_factory = async_client_factory or (
            lambda: httpx.AsyncClient(timeout=15, verify=True, trust_env=False)
        )
        self.clock = clock
        self.next_attempt = 0
        self.failures = 0
        self.paused = False
        self._wake = None

    def credentials(self, token):
        self.token = token
        self.paused = False
        self.next_attempt = 0

    def post(self, path, body):
        return self.client.post(
            self.url + path,
            content=body,
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
            },
        )

    def register(self, run):
        response = self.post("/api/v1/agent-runs", canonical(run))
        response.raise_for_status()

    def enqueue(self, assessment, run_id):
        record = self.outbox.enqueue(assessment, run_id)
        if self._wake:
            health = self.outbox.health()
            if (
                assessment.get("warnings")
                or health["queue_depth"] >= 100
                or health["queue_bytes"] >= 1048500
            ):
                self._wake.set()
        return record

    def flush(self):
        if self.paused or self.clock() < self.next_attempt:
            return
        items = []
        size = 32
        with self.outbox.connect() as db:
            for row in db.execute("SELECT * FROM queue ORDER BY id LIMIT 100"):
                if size + row["bytes"] + 1 > 1048576:
                    break
                items.append(dict(row))
                size += row["bytes"] + 1
        if not items:
            return
        try:
            response = self.post(
                "/api/v1/events",
                '{"schema_version":1,"items":['
                + ",".join(i["body"] for i in items)
                + "]}",
            )
            if response.status_code == 401:
                self.paused = True
            elif response.status_code in (409, 413, 422):
                with self.outbox.connect() as db:
                    for i in items:
                        self.outbox.rejection(
                            db, i["record_id"], "http_" + str(response.status_code)
                        )
                        db.execute(
                            "DELETE FROM queue WHERE record_id=?", (i["record_id"],)
                        )
                return
            elif response.status_code == 429 or response.status_code >= 500:
                self.backoff(response.headers.get("retry-after"))
            elif response.is_success:
                accepted = response.json().get("accepted_record_ids", [])
                with self.outbox.connect() as db:
                    for i in items:
                        if i["record_id"] in accepted:
                            db.execute(
                                "DELETE FROM queue WHERE record_id=?", (i["record_id"],)
                            )
                    # Persistent rejection/loss faults require operator review.
                    if (
                        not db.execute("SELECT 1 FROM rejections LIMIT 1").fetchone()
                        and not db.execute(
                            "SELECT 1 FROM state WHERE key LIKE 'dropped_%'"
                        ).fetchone()
                    ):
                        db.execute("DELETE FROM state WHERE key='last_error'")
                self.failures = 0
                self.next_attempt = 0
                return
            else:
                self.backoff()
            with self.outbox.connect() as db:
                db.execute(
                    "INSERT OR REPLACE INTO state VALUES('last_error',?)",
                    ("http_" + str(response.status_code),),
                )
        except (httpx.TransportError, ValueError):
            self.backoff()
            with self.outbox.connect() as db:
                db.execute(
                    "INSERT OR REPLACE INTO state VALUES('last_error','transport_error')"
                )

    def backoff(self, retry_after=None):
        self.failures += 1
        delay = random.uniform(0, min(60, 2 ** min(self.failures, 6)))
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                try:
                    delay = max(
                        delay,
                        email.utils.parsedate_to_datetime(retry_after).timestamp()
                        - self.clock(),
                    )
                except (ValueError, TypeError):
                    pass
        self.next_attempt = self.clock() + delay

    async def supervise(self, run, health_provider, stop):
        """Provider must report real collector health; replay is explicitly labeled.

        Checkpoint persistence belongs to collection, independent of HTTP acks.
        """
        self._wake = asyncio.Event()
        await asyncio.to_thread(self.register, run)

        async def delivery():
            while not stop.is_set():
                await asyncio.to_thread(self.flush)
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=5)
                except TimeoutError:
                    pass

        async def heartbeat():
            seq = 0
            started = time.monotonic()
            # Independent client prevents outbox requests serializing heartbeats.
            async with self.async_client_factory() as client:
                while not stop.is_set():
                    seq += 1
                    health = health_provider()
                    body = {
                        "schema_version": 1,
                        "run_id": str(run.run_id),
                        "boot_id": run.boot_id,
                        "heartbeat_seq": seq,
                        "sent_at": time.time(),
                        "uptime_seconds": time.monotonic() - started,
                        "capabilities": run.capabilities.model_dump(),
                        "delivery": self.outbox.health(),
                        **health,
                    }
                    from ais.contracts import Heartbeat

                    payload = Heartbeat.model_validate_json(json.dumps(body))
                    try:
                        response = await client.post(
                            self.url + "/api/v1/heartbeat",
                            content=canonical(payload),
                            headers={
                                "Authorization": "Bearer " + self.token,
                                "Content-Type": "application/json",
                            },
                        )
                        response.raise_for_status()
                    except httpx.HTTPError:
                        with self.outbox.connect() as db:
                            db.execute(
                                "INSERT OR REPLACE INTO state VALUES('last_error','heartbeat_error')"
                            )
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=30)
                    except TimeoutError:
                        pass

        async with asyncio.TaskGroup() as group:
            group.create_task(delivery())
            group.create_task(heartbeat())
