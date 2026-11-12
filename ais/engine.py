"""Bounded streaming assessment; detection never updates the normal profile."""

from __future__ import annotations

import hashlib
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from ais.rules import RuleConfig, evaluate, stages


@dataclass
class State:
    events: deque = field(default_factory=lambda: deque(maxlen=128))
    groups: dict = field(default_factory=dict)
    failures: deque = field(default_factory=lambda: deque(maxlen=64))
    last_time: float | None = None


class Engine:
    def __init__(
        self, model, config=None, reference=(), max_contexts=1024, max_seen=100000
    ):
        if max_contexts < 1 or max_seen < 1:
            raise ValueError("State limits must be positive")
        self.model = model
        self.config = config or RuleConfig()
        self.reference = set(reference)
        self.states = OrderedDict()
        self.seen = OrderedDict()
        self.max_contexts = max_contexts
        self.max_seen = max_seen

    def process(self, event):
        base = {
            "event_id": event.event_id,
            "host": event.host,
            "account": event.account,
            "role": event.role,
            "program": event.program,
            "timestamp": event.time,
            "source": event.source,
            "stage_hints": stages(event.program),
            "path_kind": event.executable_kind,
            "used_sudo": event.used_sudo,
            "wrapper_opaque": event.wrapper_opaque,
            "uid": event.effective_uid,
            "login_uid": event.login_uid,
            "coverage_notes": sorted(
                event.facts
                & {"argument_visibility_incomplete", "audit_assembly_evicted"}
            ),
            "boot_id": event.boot_id,
            "session": event.session,
            "service_id": event.service_id,
            "lineage_id": event.lineage_id,
            "parent_program": event.parent,
            "context": {
                "off_hours": event.off_hours,
                "new_source": event.new_source,
                "new_destination": event.new_destination,
                "new_executable": event.new_executable,
            },
            "known_reference": event.program in self.reference
            if self.reference
            else None,
            "model_version": self.model.version,
            "warnings": [],
        }
        for missing, condition in [
            ("timestamp_unknown", event.time is None),
            ("parent_unknown", event.parent is None),
            ("role_unknown", event.role == "unknown"),
            ("path_unknown", event.executable_kind is None),
            ("session_context_unknown", event.stream_key is None),
        ]:
            if condition:
                base["coverage_notes"].append(missing)
        identity = (event.host, event.boot_id, event.event_id)
        if identity in self.seen:
            return {**base, "status": "duplicate", "ais": None, "markov": None}
        self.seen[identity] = None
        if len(self.seen) > self.max_seen:
            self.seen.popitem(last=False)
        profile = self.model.profiles.get(event.profile_key)
        key = event.stream_key
        # No session or service identity means no invented shared sequence.
        state_key = (
            key
            if key is not None
            else ("unscoped", event.profile_key, event.boot_id, event.event_id)
        )
        state = self.states.setdefault(state_key, State())
        self.states.move_to_end(state_key)
        if len(self.states) > self.max_contexts:
            self.states.popitem(last=False)
        reset = None
        if state.last_time is not None and event.time is not None:
            if event.time < state.last_time:
                reset = "out_of_order"
            elif event.time - state.last_time > self.config.idle_seconds:
                reset = "idle_gap"
        if reset:
            state.events.clear()
            state.groups.clear()
            state.failures.clear()
        state.last_time = event.time
        if event.source == "auth":
            warnings = []
            if (
                event.program in {"sudo", "su"}
                and event.success is False
                and event.time is not None
                and key is not None
            ):
                state.failures.append(event.time)
                recent = [
                    t
                    for t in state.failures
                    if event.time - t <= self.config.auth_seconds
                ]
                if len(recent) >= self.config.auth_failure_count:
                    warnings = [
                        {
                            "rule": "repeated_auth_failure",
                            "severity": "medium",
                            "source": "rule",
                            "reason": "Repeated supplied authentication failures; execve status is not used as authentication evidence",
                            "evidence_programs": [event.program],
                        }
                    ]
            return {
                **base,
                "status": "authentication_context",
                "ais": None,
                "markov": None,
                "warnings": self.group(warnings, state, event, state_key),
            }
        if event.source == "exec" and event.success is False:
            # Known failed exec attempts must not contaminate successful-execution sequences.
            return {**base, "status": "failed_execution", "ais": None, "markov": None}
        state.events.append(event)
        warnings = evaluate(list(state.events), profile, self.config)
        status = "no_profile" if profile is None else "warming_up"
        if key is None:
            status = "missing_session_context"
        score_info = None
        markov_info = None
        if profile is not None and key is not None and len(state.events) >= 10:
            window = list(state.events)[-10:]
            score, missing = profile.score(window)
            status = "missing_features" if missing else "scored"
            score_info = {
                "score": score,
                "threshold": profile.threshold,
                "alert": score > profile.threshold if score is not None else None,
                "missing_features": missing,
                "features": profile.features(window),
                "quality": profile.quality,
            }
            markov = profile.markov(window)
            markov_info = {
                "score": markov,
                "threshold": profile.markov_threshold,
                "alert": markov > profile.markov_threshold,
            }
            if score is not None and score > profile.threshold:
                warnings.append(
                    {
                        "rule": "behavioral_anomaly",
                        "severity": "medium",
                        "source": "ais",
                        "reason": "Window differs from the approved account/role normal profile; score is not attack probability",
                        "evidence_programs": [e.program for e in window],
                    }
                )
        return {
            **base,
            "status": status,
            "sequence_reset": reset,
            "ais": score_info,
            "markov": markov_info,
            "first_seen_for_profile": profile.novel(event) if profile else None,
            "unexpected_parent": profile.unexpected_parent(event) if profile else None,
            "warnings": self.group(warnings, state, event, state_key),
        }

    def group(self, warnings, state, event, key):
        result = []
        for warning in warnings:
            name = warning["rule"]
            old = state.groups.get(name)
            if (
                old
                and event.time is not None
                and old["start"] is not None
                and 0 <= event.time - old["start"] <= self.config.grouping_seconds
            ):
                old["count"] += 1
            else:
                old = {
                    "start": event.time,
                    "count": 1,
                    "group_id": hashlib.sha256(
                        repr((key, name, event.event_id)).encode()
                    ).hexdigest()[:24],
                }
                state.groups[name] = old
            result.append(
                {**warning, "group_id": old["group_id"], "count": old["count"]}
            )
        return result
