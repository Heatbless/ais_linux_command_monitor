"""Version-one sanitized transport contracts; no raw telemetry is accepted."""

import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator


def bounded_text(value, limit=255):
    if (
        len(value.encode("utf-8")) > limit
        or "/" in value
        or "\\" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("invalid bounded name")
    return value


def reason_text(value):
    if len(value.encode("utf-8")) > 512:
        raise ValueError("byte limit")
    return value


Name = Annotated[str, Field(max_length=256), AfterValidator(bounded_text)]
Program = Annotated[str, Field(max_length=255), AfterValidator(bounded_text)]
SmallID = Annotated[
    str, Field(max_length=128), AfterValidator(lambda s: bounded_text(s, 128))
]
Count = Annotated[int, Field(ge=0, le=9223372036854775807)]
Number = Annotated[float, Field(allow_inf_nan=False)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, strict=True)


class Context(Contract):
    off_hours: bool | None = None
    new_source: bool | None = None
    new_destination: bool | None = None
    new_executable: bool | None = None


class Score(Contract):
    score: Number | None = None
    threshold: Number | None = None
    alert: bool | None = None
    features: dict[SmallID, Number | bool | None] | None = None
    quality: Name | None = None
    missing_features: list[SmallID] = Field(default_factory=list, max_length=64)


class Warning(Contract):
    rule: SmallID
    source: Literal["rule", "ais"]
    severity: Literal["low", "medium", "high", "critical"]
    reason: Annotated[str, Field(max_length=512), AfterValidator(reason_text)]
    evidence_programs: list[SmallID] = Field(default_factory=list, max_length=10)
    group_id: SmallID
    count: Count = Field(ge=1)


class Assessment(Contract):
    event_id: Name
    host: Name
    boot_id: Name
    account: Name
    role: Name
    source: Literal["exec", "shell", "auth"]
    program: Program
    timestamp: Number | None = None
    uid: Count | None = None
    login_uid: Count | None = None
    session: Name | None = None
    service_id: Name | None = None
    lineage_id: Name | None = None
    parent_program: Program | None = None
    stage_hints: list[SmallID] = Field(default_factory=list, max_length=64)
    path_kind: Name | None = None
    used_sudo: bool | None = None
    wrapper_opaque: bool | None = None
    coverage_notes: list[SmallID] = Field(default_factory=list, max_length=64)
    context: Context = Field(default_factory=Context)
    known_reference: bool | None = None
    model_version: Name | None = None
    first_seen_for_profile: bool | None = None
    unexpected_parent: bool | None = None
    sequence_reset: bool | None = None
    status: Literal[
        "scored",
        "warming_up",
        "no_profile",
        "missing_session_context",
        "missing_features",
        "duplicate",
        "authentication_context",
        "failed_execution",
    ]
    ais: Score | None = None
    markov: Score | None = None
    warnings: list[Warning] = Field(default_factory=list, max_length=100)


class Envelope(Contract):
    record_id: UUID
    run_id: UUID
    sequence: Count = Field(ge=1)
    type: Literal["assessment"] = "assessment"
    truncated_fields: list[SmallID] = Field(default_factory=list, max_length=100)
    assessment: Assessment

    @model_validator(mode="after")
    def size(self):
        if len(self.model_dump_json().encode()) > 65536:
            raise ValueError("item_size")
        if self.assessment.status == "duplicate":
            raise ValueError("duplicate_not_transportable")
        return self


class Batch(Contract):
    schema_version: Literal[1] = 1
    items: list[Envelope] = Field(min_length=1, max_length=100)


class Capabilities(Contract):
    shell_telemetry: bool = False
    authentication_outcomes: bool = False
    source_enrichment: bool = False
    learning: Literal[False] = False
    model_activation: Literal[False] = False


class Run(Contract):
    schema_version: Literal[1] = 1
    run_id: UUID
    boot_id: Name
    mode: Literal["live", "replay", "demo"]
    agent_version: Name
    capabilities: Capabilities = Field(default_factory=Capabilities)


class Collector(Contract):
    mode: Literal["audit", "normalized_stream", "replay"]
    state: Literal["healthy", "degraded", "stopped", "unavailable"]
    last_successful_poll: Number | None = None
    last_observed_event: Number | None = None
    collected: Count = 0
    lost: Count = 0


class Detector(Contract):
    state: Literal["running", "unavailable"]
    model_version: Name | None = None
    profile_count: Count = 0
    experimental: bool = True
    deployment_ready: bool = False


class Delivery(Contract):
    state: Literal["healthy", "degraded"]
    queue_depth: Count = 0
    queue_bytes: Count = 0
    dropped_assessments: Count = 0
    dropped_warnings: Count = 0
    last_error_code: SmallID | None = None


class Heartbeat(Contract):
    schema_version: Literal[1] = 1
    run_id: UUID
    boot_id: Name
    heartbeat_seq: Count = Field(ge=1)
    sent_at: Number | None = None
    uptime_seconds: Number = Field(ge=0)
    collector: Collector
    detector: Detector
    delivery: Delivery
    capabilities: Capabilities = Field(default_factory=Capabilities)


def canonical(value):
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
