import asyncio
import copy
import io
import json
from types import SimpleNamespace

import httpx
import pytest

from ais.contracts import Batch, Heartbeat, Run
from ais.demo import document
from ais.engine import Engine
from ais.events import event_from_record
from ais.sender import Outbox, Sender, map_assessment
from ais.transport import read_token, replay
from ais.workflows import train_workflows


@pytest.fixture
def model_and_body(tmp_path):
    body = document()
    path = tmp_path / "workflows.json"
    path.write_text(json.dumps(body))
    return train_workflows(path, allow_synthetic=True)[0], body


def sample(model_and_body):
    model, body = model_and_body
    row = body["workflows"][0]["events"][0]
    return Engine(model).process(event_from_record(row))


def test_all_actual_demo_outputs_fit_server_contract(model_and_body):
    model, body = model_and_body
    count = 0
    for workflow in body["workflows"]:
        engine = Engine(model)
        for event in workflow["events"]:
            output = engine.process(event_from_record(event))
            before = copy.deepcopy(output)
            mapped, _ = map_assessment(output)
            assert mapped.status == output["status"]
            assert output == before
            if output["ais"]:
                assert mapped.ais.quality == "experimental"
                count += 1
    assert count > 0


def test_reset_and_privacy(model_and_body):
    output = sample(model_and_body)
    output["sequence_reset"] = "idle_gap"
    output["argv"] = ["SECRET"]
    mapped, _ = map_assessment(output)
    assert mapped.sequence_reset is True
    assert "SECRET" not in mapped.model_dump_json()
    output["context"]["raw_path"] = "SECRET"
    with pytest.raises(ValueError):
        map_assessment(output)


def test_durable_retry_preserves_envelope_and_origin(tmp_path, model_and_body):
    assessment = sample(model_and_body)
    path = tmp_path / "outbox.sqlite"
    outbox = Outbox(path)
    run = outbox.new_run(assessment["boot_id"])
    record = outbox.enqueue(assessment, run.run_id)
    calls = []

    def endpoint(request):
        calls.append(json.loads(request.content))
        Batch.model_validate_json(request.content)
        if len(calls) == 1:
            raise httpx.ReadTimeout("lost acknowledgment")
        return httpx.Response(200, json={"accepted_record_ids": [record]})

    with httpx.Client(transport=httpx.MockTransport(endpoint)) as client:
        sender = Sender(outbox, "https://ingest.test", "test-token", client=client)
        sender.flush()
        assert outbox.health()["queue_depth"] == 1
        restarted = Outbox(path)
        Sender(restarted, "https://ingest.test", "test-token", client=client).flush()
    assert calls[0] == calls[1]
    assert calls[1]["items"][0]["run_id"] == str(run.run_id)
    assert restarted.health()["queue_depth"] == 0


def test_rejection_duplicate_boot_and_overflow(tmp_path, model_and_body):
    assessment = sample(model_and_body)
    outbox = Outbox(tmp_path / "outbox.sqlite", max_records=1)
    run = outbox.new_run(assessment["boot_id"])
    assert outbox.enqueue({**assessment, "status": "duplicate"}, run.run_id) is None
    assert outbox.health()["queue_depth"] == 0
    assert outbox.enqueue({**assessment, "boot_id": "wrong"}, run.run_id) is None
    assert outbox.health()["last_error_code"] == "invalid_assessment"
    outbox.enqueue(assessment, run.run_id)
    outbox.enqueue(assessment, run.run_id)
    assert outbox.health()["dropped_assessments"] == 1


def test_replay_sends_actual_engine_output_and_heartbeat(tmp_path, model_and_body):
    assessment = sample(model_and_body)
    token = tmp_path / "token"
    token.write_text("test-token\n")
    token.chmod(0o600)
    requests = []

    def endpoint(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.url.path.endswith("agent-runs"):
            Run.model_validate_json(request.content)
        elif request.url.path.endswith("heartbeat"):
            heartbeat = Heartbeat.model_validate_json(request.content)
            assert heartbeat.collector.mode == "replay"
            assert heartbeat.collector.state == "stopped"
            assert heartbeat.detector.experimental
        else:
            batch = Batch.model_validate_json(request.content)
            return httpx.Response(
                200,
                json={"accepted_record_ids": [str(i.record_id) for i in batch.items]},
            )
        return httpx.Response(200, json={})

    def factory(*args, **kwargs):
        return Sender(
            *args,
            **kwargs,
            client=httpx.Client(transport=httpx.MockTransport(endpoint)),
            async_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(endpoint)
            ),
        )

    args = SimpleNamespace(
        token_file=token,
        outbox=tmp_path / "queue.sqlite",
        transport_boot_id=assessment["boot_id"],
        transport_mode="replay",
        server_url="https://ingest.test",
        expected_host=assessment["host"],
        transport_linger=0.1,
        allow_tailscale_http=False,
    )
    destination = io.StringIO()
    code = asyncio.run(
        replay(iter([assessment]), destination, model_and_body[0], args, factory)
    )
    assert code == 0
    assert {r.url.path for r in requests} == {
        "/api/v1/agent-runs",
        "/api/v1/heartbeat",
        "/api/v1/events",
    }
    assert json.loads(destination.getvalue()) == assessment


def test_token_permissions_and_tailscale_opt_in(tmp_path):
    token = tmp_path / "token"
    token.write_text("test-token")
    token.chmod(0o644)
    with pytest.raises(ValueError):
        read_token(token)
    token.chmod(0o600)
    assert read_token(token) == "test-token"
    outbox = Outbox(tmp_path / "outbox.sqlite")
    for url, allow in [
        ("http://100.64.0.10:8000", False),
        ("http://example.com", True),
        ("https://user:secret@example.com", False),
    ]:
        with pytest.raises(ValueError):
            Sender(outbox, url, "test-token", allow_tailscale_http=allow)
    sender = Sender(
        outbox, "http://100.64.0.10:8000", "test-token", allow_tailscale_http=True
    )
    sender.client.close()
