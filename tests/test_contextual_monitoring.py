import copy
import json

import pytest

from ais.audit import audit_records
from ais.catalogue import catalogue
from ais.cli import main
from ais.demo import document
from ais.engine import Engine
from ais.events import event_from_record, path_kind, unwrap
from ais.model import Model, frames
from ais.rules import RuleConfig
from ais.workflows import train_workflows


@pytest.fixture
def training(tmp_path):
    body = document()
    path = tmp_path / "workflows.json"
    path.write_text(json.dumps(body))
    model, provenance = train_workflows(path, allow_synthetic=True)
    return model, body, path, provenance


def scenario(body, name):
    return copy.deepcopy(
        next(w for w in body["workflows"] if w["id"] == name)["events"]
    )


def assessments(model, rows, **kwargs):
    engine = Engine(model, **kwargs)
    return [engine.process(event_from_record(row)) for row in rows]


def warnings(rows):
    return {w["rule"] for row in rows for w in row["warnings"]}


def test_demo_scenarios_pass_with_normal_and_unusual_contexts(training):
    model, body, _, _ = training
    for workflow in body["workflows"]:
        if workflow["partition"] != "evaluation":
            continue
        results = assessments(model, workflow["events"])
        assert set(workflow["expected_rules"]) <= warnings(results), workflow["id"]
        if workflow["label"] == "normal":
            assert warnings(results) <= set(workflow["expected_rules"]), workflow["id"]
    long_attack = assessments(model, scenario(body, "post_compromise_session"))
    assert any(row["ais"] and row["ais"]["alert"] for row in long_attack)
    control = assessments(model, scenario(body, "same_names_different_intent"))
    assert not any(row["ais"] and row["ais"]["alert"] for row in control)


def test_early_burst_rule_without_pretending_ais_scored(training):
    model, body, _, _ = training
    result = assessments(model, scenario(body, "service_orientation"))
    assert "orientation_burst" in warnings(result)
    assert all(row["ais"] is None for row in result)
    assert result[-1]["status"] == "warming_up"


def test_unknown_time_disables_bursts_not_python_policy(training):
    model, body, _, _ = training
    rows = scenario(body, "service_orientation")
    for row in rows:
        row["timestamp"] = None
    assert "orientation_burst" not in warnings(assessments(model, rows))
    rows = scenario(body, "normal_developer")
    for row in rows:
        row["timestamp"] = None
    result = assessments(model, rows)
    assert "python_attention" in warnings(result)
    assert result[-1]["status"] == "missing_features"
    assert result[-1]["ais"]["score"] is None
    assert "distinct_rate" in result[-1]["ais"]["missing_features"]


def test_host_role_source_and_session_boundaries_are_not_pooled(training):
    model, body, _, _ = training
    rows = scenario(body, "service_orientation")
    rows[2]["session"] = "different-session"
    rows[3]["session"] = "different-session"
    assert "orientation_burst" not in warnings(assessments(model, rows))
    for field, value in [
        ("host", "another-host"),
        ("role", "unknown"),
        ("source", "shell"),
    ]:
        row = scenario(body, "normal_admin")[0]
        row[field] = value
        result = assessments(model, [row])[0]
        assert result["status"] == "no_profile"
    unscoped = scenario(body, "normal_admin")
    for row in unscoped:
        row["session"] = None
    assert all(
        r["status"] == "missing_session_context" for r in assessments(model, unscoped)
    )


def test_service_lpe_keeps_trusted_service_actor_but_not_unknown_context(training):
    model, body, _, _ = training
    rows = scenario(body, "compile_elevation")
    assert rows[0]["uid"] == 33 and rows[-1]["uid"] == 0
    assert (
        event_from_record(rows[0]).profile_key
        == event_from_record(rows[-1]).profile_key
    )
    assert "compile_execute" in warnings(assessments(model, rows))
    for row in rows:
        row["service_id"] = None
        row["session"] = "4294967295"
    assert all(event_from_record(row).stream_key is None for row in rows)


def test_repetition_does_not_update_baseline_and_duplicates_do_not_count(training):
    model, body, _, _ = training
    before = json.dumps([p.artifact() for p in model.profiles.values()], sort_keys=True)
    engine = Engine(model)
    row = scenario(body, "service_shell")[0]
    first = engine.process(event_from_record(row))
    duplicate = engine.process(event_from_record(row))
    assert (
        first["warnings"]
        and duplicate["status"] == "duplicate"
        and not duplicate["warnings"]
    )
    for i in range(20):
        row["event_id"] = f"unusual:{i}"
        row["timestamp"] += 1
        engine.process(event_from_record(row))
    after = json.dumps([p.artifact() for p in model.profiles.values()], sort_keys=True)
    assert before == after


def test_rule_grouping_and_idle_or_out_of_order_resets(training):
    model, body, _, _ = training
    engine = Engine(model)
    row = scenario(body, "service_shell")[0]
    first = engine.process(event_from_record(row))["warnings"][0]
    row["event_id"] = "next"
    row["timestamp"] += 1
    second = engine.process(event_from_record(row))["warnings"][0]
    assert first["group_id"] == second["group_id"] and second["count"] == 2
    row["event_id"] = "after-group"
    row["timestamp"] += 31
    third = engine.process(event_from_record(row))["warnings"][0]
    assert third["group_id"] != first["group_id"] and third["count"] == 1
    row["event_id"] = "after-idle"
    row["timestamp"] += 301
    assert engine.process(event_from_record(row))["sequence_reset"] == "idle_gap"
    row["event_id"] = "reverse-time"
    row["timestamp"] -= 5
    assert engine.process(event_from_record(row))["sequence_reset"] == "out_of_order"


def test_outputs_and_model_do_not_retain_raw_arguments_or_paths(training, tmp_path):
    model, body, _, _ = training
    row = scenario(body, "service_shell")[0]
    row["argv"] = ["python3", "/private/SECRET_SCRIPT.py", "--token", "SECRET_TOKEN"]
    row["src_ip"] = "SECRET_SOURCE_IP"
    row["executable"] = "/private/python3"
    event = event_from_record(row)
    output = Engine(model).process(event)
    path = tmp_path / "model.json"
    model.save(path)
    text = json.dumps(output) + repr(event) + path.read_text()
    for secret in ("SECRET_SCRIPT", "SECRET_TOKEN", "SECRET_SOURCE_IP", "/private/"):
        assert secret not in text
    assert not hasattr(event, "argv")


def test_wrappers_are_static_and_exec_identity_cannot_be_spoofed(training):
    words, wrappers, opaque = unwrap(
        [
            "sudo",
            "-u",
            "root",
            "env",
            "API_KEY=SECRET",
            "nohup",
            "timeout",
            "-s",
            "TERM",
            "5s",
            "python3",
            "task.py",
        ]
    )
    assert (
        words[0] == "python3"
        and wrappers == ("sudo", "env", "nohup", "timeout")
        and not opaque
    )
    assert unwrap(["sudo", "--unknown", "python3"])[2]
    assert unwrap(["xargs", "-n", "1", "python3"])[0][0] == "python3"
    row = scenario(training[1], "service_shell")[0]
    row["executable"] = "/usr/bin/curl"
    row["argv"] = ["python3", "secret.py"]
    event = event_from_record(row)
    assert event.program == "curl"
    assert "python_attention" not in warnings([Engine(training[0]).process(event)])
    row["source"] = "shell"
    row["executable"] = "sudo"
    row["argv"] = ["sudo", "-u", "root", "python3", "script.py"]
    event = event_from_record(row)
    assert event.program == "python3" and event.used_sudo


def test_path_flags_require_more_than_a_relative_name(training):
    assert path_kind("/tmp/../usr/bin/python3") == "system"
    assert path_kind(".") is None
    row = scenario(training[1], "relative_program_alone")[0]
    assert not warnings(assessments(training[0], [row]))
    result = assessments(training[0], scenario(training[1], "delivery_cleanup"))
    assert "delivery_execution" in warnings(result)


def test_sensitive_actions_use_arguments_not_program_name_alone(training):
    model, body, _, _ = training
    row = scenario(body, "normal_admin")[0]
    row.update(
        executable="/usr/bin/systemctl",
        argv=["systemctl", "status", "host-monitor.service"],
    )
    assert "monitor_tamper" not in warnings(assessments(model, [row]))
    row.update(event_id="stop", argv=["systemctl", "stop", "host-monitor.service"])
    assert "monitor_tamper" in warnings(assessments(model, [row]))
    row.update(
        event_id="dd-file",
        executable="/usr/bin/dd",
        argv=["dd", "if=/dev/zero", "of=/tmp/test.img"],
    )
    assert "destructive_device_write" not in warnings(assessments(model, [row]))
    row.update(event_id="dd-device", argv=["dd", "of=/dev/sdb"])
    assert "destructive_device_write" in warnings(assessments(model, [row]))
    row.update(
        event_id="keys-backup",
        executable="/usr/bin/cp",
        argv=["cp", "/home/u/.ssh/authorized_keys", "/tmp/backup"],
    )
    assert "persistence_target_write" not in event_from_record(row).facts


def test_auth_outcomes_are_not_inferred_from_exec_success(training):
    model, body, _, _ = training
    rows = scenario(body, "auth_failures")
    assert "repeated_auth_failure" in warnings(assessments(model, rows))
    for row in rows:
        row.update(source="exec", success=True)
    assert "repeated_auth_failure" not in warnings(assessments(model, rows))


def test_normal_approval_and_calibration_separation_are_enforced(training, tmp_path):
    _, body, path, provenance = training
    assert not provenance["evaluation_used_for_training"]
    with pytest.raises(ValueError, match="allow-synthetic"):
        train_workflows(path)
    invalid = copy.deepcopy(body)
    invalid["workflows"][0]["approved"] = False
    target = tmp_path / "invalid.json"
    target.write_text(json.dumps(invalid))
    with pytest.raises(ValueError, match="approved normal"):
        train_workflows(target, True)
    invalid = copy.deepcopy(body)
    invalid["workflows"][0]["label"] = "unusual"
    target.write_text(json.dumps(invalid))
    with pytest.raises(ValueError, match="approved normal"):
        train_workflows(target, True)
    invalid = copy.deepcopy(body)
    # Reusing an actual event across partitions must fail even in synthetic mode.
    train_event = invalid["workflows"][0]["events"][0]
    cal = next(w for w in invalid["workflows"] if w["partition"] == "calibration")
    cal["events"][0]["event_id"] = train_event["event_id"]
    target.write_text(json.dumps(invalid))
    with pytest.raises(ValueError, match="reused"):
        train_workflows(target, True)


def test_models_exclude_training_self_and_round_trip(training, tmp_path):
    model, body, _, _ = training
    for workflow in body["workflows"]:
        if workflow["partition"] == "train":
            events = [event_from_record(row) for row in workflow["events"]]
            profile = model.profiles[events[0].profile_key]
            assert all(profile.score(window)[0] == 0 for window in frames(events))
    path = tmp_path / "model.json"
    model.save(path)
    loaded = Model.load(path)
    events = [
        event_from_record(row) for row in scenario(body, "post_compromise_session")[:10]
    ]
    assert model.profiles[events[0].profile_key].score(events) == loaded.profiles[
        events[0].profile_key
    ].score(events)
    content = json.loads(path.read_text())
    content["profiles"][0]["threshold"] = 0.8
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="changed"):
        Model.load(path)


def test_reference_catalogue_never_approves_normality(training, tmp_path):
    (tmp_path / "examples.txt").write_text(
        "git status\npython3 task.py --token SECRET\nexport API_KEY=SECRET\n"
    )
    reference = catalogue(tmp_path)
    assert not reference["normality_approved"] and not reference["ordered_sessions"]
    assert "SECRET" not in json.dumps(reference)
    model, body, _, _ = training
    row = scenario(body, "service_orientation")[0]
    result = assessments(model, [row], reference=["whoami"])[0]
    assert (
        result["known_reference"] is True and result["first_seen_for_profile"] is True
    )


def test_audit_assembly_roles_and_argument_visibility():
    text = """type=SYSCALL msg=audit(100.5:1) arch=c000003e syscall=59 success=yes pid=30 ppid=10 uid=33 auid=4294967295 ses=4294967295 exe="/usr/bin/python3"
type=EXECVE msg=audit(100.5:1) argc=2 a0="python3" a1="SECRET.py"
type=EOE msg=audit(100.5:1)
type=USER_AUTH msg=audit(101:2) exe="/bin/su" res=failed
"""
    rows = list(
        audit_records(
            text.splitlines(),
            "vm",
            "boot",
            {
                "uid:33": {
                    "account": "web",
                    "role": "service",
                    "service_id": "web.service",
                }
            },
        )
    )
    assert len(rows) == 1 and rows[0]["argv"] == ["python3", "SECRET.py"]
    event = event_from_record(rows[0])
    assert event.actor == "service:web.service" and event.session is None
    assert event.role == "service" and "SECRET" not in repr(event)
    assert len(list(audit_records(text.splitlines()[:-3], "vm", "boot"))) == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, True])
def test_invalid_rule_thresholds_are_rejected(value):
    with pytest.raises(ValueError):
        RuleConfig(burst_seconds=value)


def test_bounded_state_and_cli_input_protection(training, tmp_path, capsys):
    model, body, path, _ = training
    engine = Engine(model, max_contexts=2, max_seen=3)
    row = scenario(body, "normal_admin")[0]
    for i in range(8):
        row.update(event_id=f"{i}", session=f"{i}")
        engine.process(event_from_record(row))
    assert len(engine.states) <= 2 and len(engine.seen) <= 3
    assert main(["train", str(path), "--output", str(path), "--allow-synthetic"]) == 2
    assert path.exists() and "workflows" in json.loads(path.read_text())
    assert "SECRET" not in capsys.readouterr().err


def test_evaluation_event_reuse_is_rejected(training, tmp_path):
    _, body, _, _ = training
    invalid = copy.deepcopy(body)
    training_event = invalid["workflows"][0]["events"][0]
    evaluation = next(w for w in invalid["workflows"] if w["partition"] == "evaluation")
    evaluation["events"][0]["event_id"] = training_event["event_id"]
    path = tmp_path / "duplicate-evaluation.json"
    path.write_text(json.dumps(invalid))
    with pytest.raises(ValueError, match="reused"):
        train_workflows(path, True)


def test_streaming_cli_outputs_only_sanitized_assessments(training, tmp_path, capsys):
    model, body, _, _ = training
    path = tmp_path / "model.json"
    model.save(path)
    row = scenario(body, "service_shell")[0]
    row["argv"] = ["python3", "/private/SECRET.py", "--token", "SECRET_TOKEN"]
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(row) + "\n")
    assert main(["score", "--model", str(path), "--input", str(source)]) == 0
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out
    assert "python_attention" in {
        w["rule"] for w in json.loads(captured.out)["warnings"]
    }
    assert (
        main(
            [
                "score",
                "--model",
                str(path),
                "--input",
                str(source),
                "--output",
                str(source),
            ]
        )
        == 2
    )
    assert json.loads(source.read_text())["argv"][-1] == "SECRET_TOKEN"
