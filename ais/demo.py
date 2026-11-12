"""Explicitly synthetic correctness scenarios, not independent security validation."""

from __future__ import annotations

import json
from pathlib import Path

from ais.engine import Engine
from ais.events import event_from_record
from ais.model import Model
from ais.workflows import train_workflows

DEVELOPER = [
    "git",
    "git",
    "python3",
    "git",
    "python3",
    "git",
    "git",
    "python3",
    "git",
    "git",
    "ls",
    "cat",
]
ADMIN = [
    "apt-get",
    "dpkg",
    "systemctl",
    "journalctl",
    "systemctl",
    "ps",
    "ss",
    "df",
    "free",
    "systemctl",
    "journalctl",
    "apt-get",
]
BACKUP = [
    "find",
    "tar",
    "split",
    "base64",
    "scp",
    "rsync",
    "find",
    "tar",
    "base64",
    "scp",
    "ls",
    "df",
]
SERVICE = ["nginx", "php-fpm"] * 6
WORKER = ["nginx", "python3"] * 6
AUTOMATION = [
    "apt-get",
    "dpkg",
    "systemctl",
    "journalctl",
    "ps",
    "ss",
    "df",
    "free",
    "ls",
    "cat",
    "ip",
    "find",
]


def document(host="demo-vm"):
    workflows = []
    index = 0

    def add(
        identifier,
        role,
        programs,
        partition="evaluation",
        label="normal",
        expected=(),
        args=None,
        overrides=None,
    ):
        nonlocal index
        index += 1
        service = role == "service"
        actor = 33 if service else (1000 if role == "developer" else 0)
        events = []
        for i, program in enumerate(programs):
            executable = program if "/" in program else "/usr/bin/" + program
            row = {
                "event_id": f"{identifier}:{i}",
                "host": host,
                "boot_id": "demo-boot",
                "account": "web"
                if service
                else ("dev" if role == "developer" else "root"),
                "role": role,
                "uid": actor,
                "login_uid": None if service else actor,
                "session": None if service else identifier,
                "service_id": "web.service" if service else None,
                "timestamp": 1700000000
                + index * 1000
                + i * (1 if label != "normal" else 8),
                "source": "exec",
                "success": True,
                "executable": executable,
                "argv": (args or {}).get(i, [program]),
                "parent_program": "nginx" if service else "bash",
            }
            row.update((overrides or {}).get(i, {}))
            events.append(row)
        workflows.append(
            {
                "id": identifier,
                "partition": partition,
                "label": label,
                "approved": partition != "evaluation",
                "approved_by": "demo_fixture",
                "synthetic": True,
                "expected_rules": list(expected),
                "events": events,
            }
        )

    for partition in ("train", "calibration"):
        for role, programs, name in [
            ("developer", DEVELOPER, "development"),
            ("admin", ADMIN, "maintenance"),
            ("admin", BACKUP, "backup"),
            ("service", SERVICE, "web"),
        ]:
            add(f"{partition}_{name}", role, programs, partition)
        add(
            f"{partition}_worker",
            "service",
            WORKER,
            partition,
            overrides={
                i: {"parent_program": "service-launcher"}
                for i in range(len(WORKER))
                if WORKER[i] == "python3"
            },
        )
        add(f"{partition}_automation", "admin", AUTOMATION, partition)
        for i, row in enumerate(workflows[-1]["events"]):
            row["timestamp"] = 1700000000 + index * 1000 + i
    add("normal_developer", "developer", DEVELOPER, expected=["python_attention"])
    add("normal_admin", "admin", ADMIN)
    add("normal_backup", "admin", BACKUP)
    add("normal_service", "service", SERVICE)
    add(
        "normal_service_worker",
        "service",
        WORKER,
        expected=["python_attention"],
        overrides={
            i: {"parent_program": "service-launcher"}
            for i in range(len(WORKER))
            if WORKER[i] == "python3"
        },
    )
    add("normal_fast_automation", "admin", AUTOMATION)
    for i, row in enumerate(workflows[-1]["events"]):
        row["timestamp"] = 1700000000 + index * 1000 + i
    add(
        "service_orientation",
        "service",
        ["whoami", "id", "uname", "ps"],
        label="unusual",
        expected=["orientation_burst"],
    )
    add(
        "service_shell",
        "service",
        ["python3", "stty", "reset", "bash"],
        label="unusual",
        expected=["python_attention", "service_interpreter"],
    )
    add(
        "host_discovery",
        "service",
        ["find", "getcap", "crontab", "ss", "arp", "ip"],
        label="unusual",
        expected=["discovery_burst"],
    )
    add(
        "delivery_cleanup",
        "service",
        ["curl", "chmod", "/tmp/demo-payload", "rm"],
        label="unusual",
        expected=["delivery_execution", "delivery_cleanup"],
        args={1: ["chmod", "+x", "/tmp/demo-payload"], 3: ["rm", "/tmp/demo-payload"]},
        overrides={2: {"new_executable": True}},
    )
    add(
        "compile_elevation",
        "service",
        ["find", "getcap", "sudo", "gcc", "/tmp/demo-exploit", "id"],
        label="unusual",
        expected=["compile_execute"],
        overrides={4: {"uid": 0, "new_executable": True}, 5: {"uid": 0}},
    )
    add(
        "persistence",
        "service",
        ["ssh-keygen", "chmod", "tee"],
        label="unusual",
        expected=["persistence_chain"],
        args={
            1: ["chmod", "600", "/home/demo/.ssh/authorized_keys"],
            2: ["tee", "-a", "/home/demo/.ssh/authorized_keys"],
        },
    )
    add(
        "credential_read",
        "service",
        ["cat"],
        label="unusual",
        expected=["credential_read"],
        args={0: ["cat", "/etc/shadow"]},
    )
    add(
        "credential_tool",
        "service",
        ["unshadow", "john"],
        label="unusual",
        expected=["credential_tool_context"],
    )
    add(
        "account_persistence",
        "service",
        ["useradd", "usermod", "passwd", "ssh-keygen", "cat"],
        label="unusual",
        expected=["account_change_chain"],
    )
    add(
        "security_tamper",
        "admin",
        ["auditctl", "systemctl", "rm"],
        label="unusual",
        expected=["security_disabled", "monitor_tamper"],
        args={
            0: ["auditctl", "-e", "0"],
            1: ["systemctl", "stop", "host-monitor.service"],
            2: ["rm", "/opt/ais/model.json"],
        },
    )
    add(
        "lateral",
        "service",
        ["ssh", "ssh", "ssh", "scp"],
        label="unusual",
        expected=["outgoing_remote_burst"],
        overrides={2: {"new_destination": True}},
    )
    add(
        "collection",
        "service",
        ["find", "tar", "base64", "curl"],
        label="unusual",
        expected=["collection_transfer"],
    )
    add(
        "impact",
        "service",
        ["find", "xargs", "openssl", "openssl", "openssl", "openssl"],
        label="unusual",
        expected=["bulk_crypto_chain"],
    )
    add(
        "device_overwrite",
        "admin",
        ["dd"],
        label="unusual",
        expected=["destructive_device_write"],
        args={0: ["dd", "if=/dev/zero", "of=/dev/sdb"]},
    )
    add(
        "history_controls",
        "service",
        ["unset", "history"],
        label="unusual",
        expected=["history_setting_changed", "history_cleared"],
        args={0: ["unset", "HISTFILE"], 1: ["history", "-c"]},
        overrides={0: {"source": "shell"}, 1: {"source": "shell"}},
    )
    add(
        "auth_failures",
        "admin",
        ["sudo", "sudo", "su"],
        label="unusual",
        expected=["repeated_auth_failure"],
        overrides={i: {"source": "auth", "success": False} for i in range(3)},
    )
    add(
        "same_names_different_intent",
        "developer",
        DEVELOPER,
        label="intent_control",
        expected=["python_attention"],
    )
    for i, row in enumerate(workflows[-1]["events"]):
        row["timestamp"] = 1700000000 + index * 1000 + i * 8
        if row["argv"][0] == "python3":
            row["argv"] = ["python3", "different-purpose.py"]
    add(
        "post_compromise_session",
        "service",
        [
            "whoami",
            "id",
            "uname",
            "ps",
            "ss",
            "find",
            "curl",
            "chmod",
            "/tmp/demo-payload",
            "crontab",
            "rm",
            "ssh",
            "ssh",
            "scp",
        ],
        label="unusual",
        expected=[
            "orientation_burst",
            "delivery_execution",
            "delivery_cleanup",
            "outgoing_remote_burst",
        ],
        args={7: ["chmod", "+x", "/tmp/demo-payload"], 10: ["rm", "/tmp/demo-payload"]},
        overrides={8: {"new_executable": True, "uid": 0}},
    )
    add("relative_program_alone", "developer", ["./ordinary-program"])
    return {
        "schema_version": 1,
        "description": "Synthetic demonstration only; demo_fixture approval is not operator approval of real activity",
        "workflows": workflows,
    }


def run(directory, host="demo-vm"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "synthetic-workflows.json"
    body = document(host)
    source.write_text(json.dumps(body, indent=2) + "\n")
    (directory / "evaluation-events.jsonl").write_text(
        "".join(
            json.dumps(event) + "\n"
            for workflow in body["workflows"]
            if workflow["partition"] == "evaluation"
            for event in workflow["events"]
        )
    )
    model, provenance = train_workflows(source, allow_synthetic=True)
    model.save(directory / "model.json")
    # Exercise serialization, not just an in-memory prototype.
    model = Model.load(directory / "model.json")
    results = []
    assessments = []
    for workflow in body["workflows"]:
        if workflow["partition"] != "evaluation":
            continue
        engine = Engine(model)
        observed = set()
        ais = False
        markov = False
        scored = 0
        markov_scored = 0
        for row in workflow["events"]:
            event = event_from_record(row, protected_paths=("/opt/ais/model.json",))
            assessment = engine.process(event)
            assessments.append({"scenario": workflow["id"], **assessment})
            observed.update(w["rule"] for w in assessment["warnings"])
            ais = ais or bool(assessment["ais"] and assessment["ais"]["alert"])
            markov = markov or bool(
                assessment["markov"] and assessment["markov"]["alert"]
            )
            scored += int(
                assessment["ais"] is not None and assessment["ais"]["score"] is not None
            )
            markov_scored += int(assessment["markov"] is not None)
        missing = set(workflow["expected_rules"]) - observed
        unexpected = (
            observed - set(workflow["expected_rules"])
            if workflow["label"] == "normal"
            else set()
        )
        results.append(
            {
                "scenario": workflow["id"],
                "synthetic_label": workflow["label"],
                "ais_alert": ais if scored else None,
                "markov_alert": markov if markov_scored else None,
                "ais_scored_windows": scored,
                "rules": sorted(observed),
                "missing_expected_rules": sorted(missing),
                "unexpected_normal_rules": sorted(unexpected),
                "checks_passed": not missing and not unexpected,
            }
        )
    (directory / "assessments.jsonl").write_text(
        "".join(json.dumps(a, allow_nan=False) + "\n" for a in assessments)
    )
    result = {
        "synthetic_only": True,
        "deployment_ready": False,
        "model_version": model.version,
        "provenance": provenance,
        "profiles": len(model.profiles),
        "scenarios": results,
        "checks_passed": all(r["checks_passed"] for r in results),
    }
    (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def render(result):
    lines = [
        "# Contextual monitoring demonstration",
        "",
        "This is a deterministic synthetic correctness demonstration, not a reliability benchmark or evidence of real attack detection. "
        "Normal training/calibration workflows are separate from evaluation scenarios. The reference command catalogue is not normal training data.",
        "",
        f"Profiles: {result['profiles']}. Expected rule checks passed: {result['checks_passed']}.",
        "",
        "| Scenario | Synthetic label | AIS alert | Markov baseline alert | Rules | Checks |",
        "|---|---|---|---|---|---|",
    ]
    for row in result["scenarios"]:
        lines.append(
            f"| {row['scenario']} | {row['synthetic_label']} | {row['ais_alert'] if row['ais_alert'] is not None else 'not scored'} | {row['markov_alert'] if row['markov_alert'] is not None else 'not scored'} | {', '.join(row['rules']) or 'none'} | {row['checks_passed']} |"
        )
    lines += [
        "",
        "The always-warn Python policy is intentional attention during normal developer work; "
        "it is not counted as evidence that AIS detected malicious intent. The same-name/different-intent control "
        "illustrates that command names cannot reveal changed arguments or purpose.",
        "",
        "Burst thresholds and stage correlations are configurable hypotheses. Legitimate administration can trigger them. "
        "Unknown context is never replaced with fabricated timestamps, roles or source IPs. "
        "Shell history-control cases explicitly require shell telemetry; raw exec auditing cannot observe built-ins.",
        "",
        "The local and VPS history experiments remain unvalidated. This new layer has not been trained on raw histories "
        "with invented roles/timing or tuned using Cowrie/AIT outcomes. Live audit recordings from the intended account remain necessary.",
        "",
        "Run `uv run python -m ais demo`. See [usage and schema](../contextual-monitoring.md).",
    ]
    return "\n".join(lines) + "\n"
