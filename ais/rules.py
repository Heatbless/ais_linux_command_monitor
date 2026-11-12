"""Configurable attention hypotheses, not malicious-command verdicts."""

from __future__ import annotations

import math
from dataclasses import dataclass

from ais.events import INTERPRETERS, PYTHON

STAGES = {
    name: set(words.split())
    for name, words in {
        "orientation": "whoami id uname hostname pwd ls w who last ifconfig ip cat env printenv ps",
        "shell_tooling": "python python3 script perl bash sh stty reset export tty",
        "discovery": "find ss netstat lsof arp route ip nslookup dig host cat getcap crontab systemctl mount df lsblk dpkg rpm lscpu docker kubectl",
        "tool_delivery": "wget curl scp ftp tftp nc ncat base64 chmod tar unzip gzip mv cp",
        "privilege_escalation": "sudo su pkexec doas find getcap chmod chown passwd gcc make python perl",
        "persistence": "crontab at systemctl service useradd adduser usermod passwd ssh-keygen echo tee cp ln touch chattr",
        "defense_evasion": "history unset export rm shred touch chattr kill pkill systemctl service auditctl setenforce iptables ufw ln truncate echo",
        "credential_access": "cat grep find strings less head tail cp tar unshadow john hashcat",
        "lateral_movement": "ssh scp sshpass rsync nc socat proxychains chisel ngrok nmap ping curl kubectl docker",
        "collection_exfiltration": "tar zip 7z gzip cp find cat base64 split openssl gpg curl wget scp rsync nc ftp mysqldump pg_dump",
        "impact": "openssl gpg rm shred dd mkfs wipefs find xargs xmrig minerd kill systemctl",
    }.items()
}


def stages(program):
    result = {name for name, programs in STAGES.items() if program in programs}
    if PYTHON.fullmatch(program):
        result.update({"shell_tooling", "privilege_escalation"})
    if program.startswith("mkfs."):
        result.add("impact")
    return sorted(result)


@dataclass
class RuleConfig:
    burst_seconds: float = 20
    orientation_distinct: int = 4
    discovery_distinct: int = 4
    rapid_distinct: int = 10
    chain_seconds: float = 120
    auth_failure_count: int = 3
    auth_seconds: float = 60
    idle_seconds: float = 300
    grouping_seconds: float = 30

    def __post_init__(self):
        for value in vars(self).values():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("Rule thresholds must be positive numbers")
        for field in (
            "orientation_distinct",
            "discovery_distinct",
            "rapid_distinct",
            "auth_failure_count",
        ):
            if not isinstance(getattr(self, field), int):
                raise ValueError("Rule count thresholds must be integers")


def evaluate(events, profile, config):
    current = events[-1]
    warnings = []

    def warn(rule, severity, reason, evidence=None):
        warnings.append(
            {
                "rule": rule,
                "severity": severity,
                "reason": reason,
                "evidence_programs": [e.program for e in (evidence or [current])],
                "source": "rule",
            }
        )

    if PYTHON.fullmatch(current.program):
        warn(
            "python_attention",
            "medium",
            "Python observed; review required independently of AIS normality",
        )
    direct = {
        "monitor_tamper": (
            "high",
            "Monitoring service, process or protected artifact targeted",
        ),
        "security_disabled": (
            "high",
            "An explicit security-control disabling request was observed",
        ),
        "credential_read": (
            "medium",
            "Command targets a specifically identified credential file; access success is not inferred",
        ),
        "destructive_device_write": (
            "high",
            "A formatting or overwrite operation targets a block device",
        ),
        "history_setting_changed": (
            "medium",
            "Shell history configuration changed; requires shell telemetry",
        ),
        "history_cleared": (
            "medium",
            "Shell history clear requested; requires shell telemetry",
        ),
    }
    for fact, (severity, reason) in direct.items():
        if fact in current.facts:
            warn(fact, severity, reason)
    novel = profile.novel(current) if profile else None
    rare = bool(profile and (novel or profile.unexpected_parent(current)))
    unprofiled_service = current.role == "service" and profile is None
    if (
        current.role == "service"
        and (current.program in INTERPRETERS or PYTHON.fullmatch(current.program))
        and (rare or unprofiled_service)
    ):
        warn(
            "service_interpreter",
            "high" if profile else "medium",
            "Interpreter in an unfamiliar service-account execution context",
        )
    if current.program in {"unshadow", "john", "hashcat"} and (
        rare or unprofiled_service
    ):
        warn(
            "credential_tool_context",
            "high" if current.role == "service" else "medium",
            "Credential-recovery tool in an unfamiliar account context; intent is not established",
        )
    if current.program in {"xmrig", "minerd"}:
        warn(
            "mining_tool",
            "high"
            if current.cpu_fraction is not None and current.cpu_fraction >= 0.85
            else "medium",
            "Mining-associated program observed; intent is not established",
        )
    elif (
        current.cpu_fraction is not None
        and current.cpu_fraction >= 0.85
        and current.new_executable is True
        and rare
    ):
        warn(
            "new_binary_high_cpu",
            "medium",
            "New unfamiliar executable has a high supplied per-process CPU reading",
        )
    # Time-based evidence cannot be manufactured from an unordered/untimed list.
    if current.time is None:
        return warnings
    timed = []
    for event in reversed(events):
        if (
            event.time is None
            or event.time > current.time
            or current.time - event.time > config.chain_seconds
        ):
            break
        timed.append(event)
    timed.reverse()
    recent = [e for e in timed if current.time - e.time <= config.burst_seconds]

    def unfamiliar(group):
        return bool(
            group
            and (
                (
                    profile
                    and any(
                        profile.novel(e) or profile.unexpected_parent(e) for e in group
                    )
                )
                or unprofiled_service
            )
        )

    for name, minimum in [
        ("orientation", config.orientation_distinct),
        ("discovery", config.discovery_distinct),
    ]:
        tail = []
        for event in reversed(recent):
            if event.program not in STAGES[name]:
                break
            tail.append(event)
        tail.reverse()
        if len({e.program for e in tail}) >= minimum and unfamiliar(tail):
            warn(
                name + "_burst",
                "high" if current.role == "service" else "medium",
                "Rapid consecutive discovery activity in an unfamiliar account context",
                tail,
            )
    if len({e.program for e in recent}) >= config.rapid_distinct and unfamiliar(recent):
        warn(
            "rapid_distinct_commands",
            "medium",
            "Rapid diverse command activity; automation is a possible benign explanation",
            recent,
        )

    def ordered(groups):
        picked = []
        index = 0
        for event in timed:
            if event.program in groups[index]:
                picked.append(event)
                index += 1
                if index == len(groups):
                    return picked
        return []

    if current.program == "reset":
        interpreters = {
            e.program
            for e in timed
            if PYTHON.fullmatch(e.program) or e.program in {"perl", "script"}
        }
        chain = ordered([interpreters, {"stty", "tty"}, {"reset"}])
        if chain and unfamiliar(chain):
            warn(
                "shell_stabilization",
                "high" if current.role == "service" else "medium",
                "Interpreter, terminal adjustment and reset occur in an unfamiliar context",
                chain,
            )
    account_changes = [
        e for e in timed if e.program in {"useradd", "adduser", "usermod", "passwd"}
    ]
    if (
        current.program in {"useradd", "adduser", "usermod", "passwd", "ssh-keygen"}
        and len({e.program for e in account_changes}) >= 2
        and unfamiliar(account_changes)
    ):
        warn(
            "account_change_chain",
            "high" if current.role == "service" else "medium",
            "Rapid account-management changes in an unfamiliar context; authorized provisioning is a possible explanation",
            account_changes,
        )
    if current.executable_kind in {"relative", "temporary"} and (
        current.new_executable is True or rare
    ):
        chain = ordered(
            [{"wget", "curl", "scp", "ftp", "tftp", "nc", "ncat"}, {"chmod"}]
        )
        if chain and chain[-1] is not current:
            warn(
                "delivery_execution",
                "high",
                "Download and permission change precede unfamiliar writable-location execution",
                chain + [current],
            )
        chain = ordered(
            [{"sudo", "find", "getcap"}, {"getcap", "sudo"}, {"gcc", "make"}]
        )
        if chain and chain[-1] is not current and unfamiliar(chain + [current]):
            warn(
                "compile_execute",
                "high",
                "Privilege/discovery activity and compilation precede unfamiliar binary execution",
                chain + [current],
            )
    if current.program in {"curl", "scp", "rsync", "nc", "ftp"}:
        chain = ordered([{"find"}, {"tar", "zip", "7z"}, {"split", "base64"}])
        if chain and unfamiliar(chain + [current]):
            warn(
                "collection_transfer",
                "high",
                "Collection, packaging and encoding precede an unfamiliar transfer context",
                chain + [current],
            )
    if "persistence_target_write" in current.facts:
        chain = ordered([{"ssh-keygen", "mkdir", "chmod"}])
        if chain and unfamiliar(chain + [current]):
            warn(
                "persistence_chain",
                "high",
                "Preparation precedes a request to modify an identified persistence-related target",
                chain + [current],
            )
    remote = [e for e in timed if e.program in {"ssh", "scp", "sshpass"}]
    if (
        current.program in {"ssh", "scp", "sshpass"}
        and len(remote) >= 3
        and (unfamiliar(remote) or current.new_destination is True)
    ):
        warn(
            "outgoing_remote_burst",
            "high" if current.new_destination is True else "medium",
            "Repeated outgoing remote commands in an unfamiliar context; distinct hosts are not inferred",
            remote,
        )
    if current.program in {"rm", "shred", "truncate"}:
        chain = ordered([{"wget", "curl"}, {"chmod"}])
        executed = [e for e in timed if e.executable_kind in {"temporary", "relative"}]
        if (
            chain
            and executed
            and chain[-1].time <= executed[-1].time <= current.time
            and unfamiliar(chain + executed + [current])
        ):
            warn(
                "delivery_cleanup",
                "high",
                "Cleanup follows download, permission change and writable-location execution",
                chain + [executed[-1], current],
            )
    if current.program in {"openssl", "gpg"}:
        crypto = [e for e in timed if e.program in {"openssl", "gpg"}]
        chain = ordered([{"find"}, {"xargs"}])
        if len(crypto) >= 4 and chain and unfamiliar(chain + crypto):
            warn(
                "bulk_crypto_chain",
                "high",
                "Repeated cryptographic operations follow discovery and batch execution",
                chain + crypto,
            )
    if current.off_hours is True and current.new_source is True and rare:
        warn(
            "new_source_off_hours",
            "medium",
            "Supplied session context reports a new source and off-hours unfamiliar activity",
        )
    return warnings
