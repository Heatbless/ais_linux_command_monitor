"""Explicit normal-workflow approval and partition boundaries."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from ais.events import event_from_record
from ais.model import Model, Profile


def train_workflows(path, allow_synthetic=False):
    body = json.loads(Path(path).read_text())
    if (
        not isinstance(body, dict)
        or body.get("schema_version") != 1
        or not isinstance(body.get("workflows"), list)
    ):
        raise ValueError("Expected versioned workflow document")
    groups = defaultdict(lambda: defaultdict(list))
    workflow_ids = set()
    event_ids = set()
    accepted = []
    for workflow in body["workflows"]:
        if not isinstance(workflow, dict):
            raise ValueError("Expected workflow objects")
        identifier = workflow.get("id")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in workflow_ids
        ):
            raise ValueError("Workflow IDs must be unique nonempty strings")
        workflow_ids.add(identifier)
        partition = workflow.get("partition")
        if partition not in {"train", "calibration", "evaluation"}:
            raise ValueError("Every workflow needs an explicit partition")
        records = workflow.get("events")
        if not isinstance(records, list):
            raise ValueError("Workflow events must be an array")
        for record in records:
            if not isinstance(record, dict) or any(
                not isinstance(record.get(k), str) or not record[k]
                for k in ("host", "boot_id", "event_id")
            ):
                raise ValueError("Each workflow event needs stable source identity")
            identity = (record["host"], record["boot_id"], record["event_id"])
            if identity in event_ids:
                raise ValueError("Event reused across workflow partitions")
            event_ids.add(identity)
        # Evaluation scenarios are never accepted as normal training, even if
        # approved. They are read separately by replay/demo, not by this trainer.
        if partition == "evaluation":
            continue
        if (
            workflow.get("label") != "normal"
            or workflow.get("approved") is not True
            or not isinstance(workflow.get("approved_by"), str)
            or not workflow["approved_by"].strip()
        ):
            raise ValueError(
                "Training and calibration require explicitly approved normal workflows"
            )
        if not isinstance(workflow.get("synthetic", False), bool):
            raise ValueError("Synthetic marker must be boolean")
        if workflow.get("synthetic") and not allow_synthetic:
            raise ValueError("Synthetic workflows require --allow-synthetic")
        if workflow.get("approved_by") == "demo_fixture" and not (
            workflow.get("synthetic") and allow_synthetic
        ):
            raise ValueError("Demo approval cannot approve real recordings")
        events = [event_from_record(row) for row in records]
        if not events or any(e.source == "auth" or e.success is False for e in events):
            raise ValueError(
                "Normal workflows must contain observed successful/typed command events"
            )
        if len({e.stream_key for e in events}) != 1 or events[0].stream_key is None:
            raise ValueError(
                "Each workflow must identify one explicit session or service context"
            )
        times = [e.time for e in events if e.time is not None]
        if times != sorted(times):
            raise ValueError("Workflow timestamps must be ordered")
        groups[events[0].profile_key][partition].append(events)
        accepted.append(
            {
                "id": identifier,
                "partition": partition,
                "synthetic": bool(workflow.get("synthetic")),
                "approved_by": workflow["approved_by"],
                "label": "normal",
            }
        )
    if not groups:
        raise ValueError("No approved normal workflows")
    profiles = {}
    for key, partitions in groups.items():
        if not partitions["train"] or not partitions["calibration"]:
            raise ValueError(
                "Each account/role/source profile requires separate train and calibration workflows"
            )
        profiles[key] = Profile().fit(partitions["train"], partitions["calibration"])
    model = Model(profiles)
    provenance = {
        "workflow_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "accepted_workflows": accepted,
        "evaluation_used_for_training": False,
    }
    return model, provenance
