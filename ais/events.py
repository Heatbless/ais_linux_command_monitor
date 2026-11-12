"""Normalize trusted local collector events without executing command text."""

from __future__ import annotations

import math
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime

ROLES = {"developer", "admin", "service", "unknown"}
SOURCES = {"exec", "shell", "auth"}
INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "perl",
    "bash",
    "sh",
    "dash",
    "zsh",
    "ruby",
    "node",
}
PYTHON = re.compile(r"python(?:[23](?:\.\d+)*)?\Z")
BUILTINS = {"export", "unset", "history", "cd", "exec", ".", "source"}


def basename(value):
    return value.rsplit("/", 1)[-1]


def timestamp(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError("Invalid timestamp")
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("Timestamp needs timezone")
            value = parsed.timestamp()
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Timestamp must be finite")
    return value


def optional_bool(row, key):
    value = row.get(key)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{key} must be boolean or null")
    return value


def uid(value):
    if value in (None, -1, "-1", 4294967295, "4294967295", "unset"):
        return None
    if isinstance(value, bool) or not str(value).isdigit():
        raise ValueError("Invalid user ID")
    return int(value)


def path_kind(path):
    if not path:
        return None
    normalized = posixpath.normpath(path)
    if normalized.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return "temporary"
    if path.startswith("./"):
        return "relative"
    if normalized.startswith(("/usr/", "/bin/", "/sbin/")):
        return "system"
    return "other" if "/" in path else None


def unwrap(argv):
    """Return a statically identifiable target. Unknown options stay opaque.

    Never emits fabricated child events. Runtime exec telemetry still uses its
    observed executable; typed shell records can use the inferred target.
    """
    words = list(argv)
    wrappers = []
    for _ in range(8):
        if not words:
            break
        program = basename(words[0])
        if program not in {"sudo", "env", "nohup", "time", "timeout", "xargs", "exec"}:
            return words, tuple(wrappers), False
        original = words
        i = 1
        flags = {
            "sudo": {
                "-n",
                "-E",
                "-H",
                "-S",
                "-k",
                "-K",
                "-b",
                "--non-interactive",
                "--preserve-env",
            },
            "env": {"-i", "--ignore-environment", "-0", "--null"},
            "nohup": set(),
            "time": {"-p"},
            "timeout": {"--foreground", "--preserve-status", "-v", "--verbose"},
            "xargs": {"-0", "--null", "-r", "--no-run-if-empty", "-t", "-p", "-x"},
            "exec": {"-c", "-l"},
        }[program]
        takes_value = {
            "sudo": {
                "-u",
                "-g",
                "-h",
                "-p",
                "-C",
                "-T",
                "-R",
                "-D",
                "-r",
                "-t",
                "--user",
                "--group",
                "--host",
            },
            "env": {"-u", "--unset", "-C", "--chdir"},
            "nohup": set(),
            "time": {"-f", "--format", "-o", "--output"},
            "timeout": {"-s", "--signal", "-k", "--kill-after"},
            "xargs": {
                "-n",
                "-P",
                "-L",
                "-I",
                "-d",
                "-E",
                "-a",
                "--max-args",
                "--max-procs",
                "--replace",
                "--delimiter",
            },
            "exec": {"-a"},
        }[program]
        opaque = False
        while i < len(words):
            word = words[i]
            if word == "--":
                i += 1
                break
            if program in {"env", "sudo"} and re.match(
                r"^[A-Za-z_][A-Za-z0-9_]*=", word
            ):
                i += 1
            elif word in takes_value:
                if i + 1 >= len(words):
                    opaque = True
                    break
                i += 2
            elif word.split("=", 1)[0] in takes_value and "=" in word:
                i += 1
            elif word in flags:
                i += 1
            elif word.startswith("-"):
                opaque = True
                break
            else:
                break
        if program == "timeout" and not opaque:
            if i >= len(words) or not re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", words[i]):
                opaque = True
            else:
                i += 1
        if opaque or i >= len(words):
            return original, tuple(wrappers), True
        wrappers.append(program)
        words = words[i:]
    return words, tuple(wrappers), True


@dataclass(frozen=True)
class Event:
    event_id: str
    host: str
    boot_id: str
    account: str
    role: str
    source: str
    program: str
    time: float | None
    actor: str
    session: str | None
    service_id: str | None
    lineage_id: str | None
    parent: str | None
    executable_kind: str | None
    used_sudo: bool
    wrapper_opaque: bool
    facts: frozenset[str]
    new_executable: bool | None
    off_hours: bool | None
    new_source: bool | None
    new_destination: bool | None
    cpu_fraction: float | None
    success: bool | None
    effective_uid: int | None
    login_uid: int | None

    @property
    def profile_key(self):
        # No cross-host, role, or observation-unit fallback.
        return self.host, self.actor, self.role, self.source

    @property
    def stream_key(self):
        context = (
            ("session", self.session)
            if self.session
            else (("service", self.service_id) if self.service_id else None)
        )
        if context is None:
            return None
        return self.profile_key, self.boot_id, context, self.lineage_id


def event_from_record(
    row,
    protected_paths=(),
    protected_services=("host-monitor", "host-monitor.service"),
    protected_pids=(),
):
    if not isinstance(row, dict):
        raise ValueError("Expected an event object")
    for name, values in (
        ("protected_paths", protected_paths),
        ("protected_services", protected_services),
    ):
        if not isinstance(values, (list, tuple)) or any(
            not isinstance(v, str) or not v for v in values
        ):
            raise ValueError(f"{name} must be a sequence of nonempty strings")
    if not isinstance(protected_pids, (list, tuple)) or any(
        isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in protected_pids
    ):
        raise ValueError("Protected process IDs must be positive integers")
    if any(not p.startswith("/") for p in protected_paths):
        raise ValueError("Protected paths must be absolute")
    protected_paths = tuple(posixpath.normpath(p) for p in protected_paths)
    for field in ("event_id", "host", "boot_id", "account"):
        if (
            not isinstance(row.get(field), str)
            or not row[field]
            or len(row[field]) > 256
        ):
            raise ValueError(f"Missing or invalid {field}")
    role = row.get("role", "unknown")
    source = row.get("source", "exec")
    if role not in ROLES or source not in SOURCES:
        raise ValueError("Invalid role or observation source")
    argv = row.get("argv", [])
    if (
        not isinstance(argv, list)
        or len(argv) > 256
        or any(not isinstance(a, str) or len(a) > 65536 for a in argv)
    ):
        raise ValueError("argv must be a bounded string array")
    executable = (
        row.get("executable") or row.get("program") or (argv[0] if argv else None)
    )
    if not isinstance(executable, str) or not executable or len(executable) > 4096:
        raise ValueError("Missing or invalid executable")
    if not argv:
        argv = [executable]
    actual = basename(executable)
    # argv[0] is process-controlled. It must not change exec telemetry identity.
    unwrap_input = (
        argv
        if source == "shell" or basename(argv[0]) == actual
        else [executable, *argv[1:]]
    )
    target, wrappers, opaque = unwrap(unwrap_input)
    # An exec record's executable is authoritative, even if argv[0] is spoofed.
    program = basename(target[0]) if source == "shell" and target else actual
    if not program or any(c.isspace() or ord(c) < 32 for c in program):
        raise ValueError("Program must be a basename")
    effective_args = target[1:] if source == "shell" and not opaque else argv[1:]
    effective_executable = target[0] if source == "shell" and target else executable
    parent = row.get("parent_program")
    if parent is not None and (not isinstance(parent, str) or not parent):
        raise ValueError("Invalid parent_program")
    parent = basename(parent) if parent else None
    facts = set()
    if row.get("argv_incomplete") is True:
        facts.add("argument_visibility_incomplete")
    if row.get("audit_assembly_evicted") is True:
        facts.add("audit_assembly_evicted")
    if source == "shell" and (
        program == "trap"
        and effective_args == ["-", "DEBUG"]
        or program == "add-zsh-hook"
        and effective_args == ["-d", "preexec", "_ais_preexec"]
        or program == "unset"
        and effective_args in (["-f", "_ais_preexec"], ["_ais_preexec"])
    ):
        facts.add("monitor_tamper")
    if opaque:
        facts.add("opaque_wrapper")
    if (
        program in {"export", "unset"}
        and source == "shell"
        and any(a == "HISTFILE" or a.startswith("HISTFILE=") for a in effective_args)
    ):
        facts.add("history_setting_changed")
    if program == "history" and source == "shell" and "-c" in effective_args:
        facts.add("history_cleared")
    if (
        program == "setenforce"
        and effective_args == ["0"]
        or program == "ufw"
        and "disable" in effective_args
        or program == "auditctl"
        and any(
            effective_args[i : i + 2] == ["-e", "0"] for i in range(len(effective_args))
        )
    ):
        facts.add("security_disabled")
    if program == "systemctl" and any(
        a in {"stop", "disable", "mask", "kill", "restart"} for a in effective_args
    ):
        if any(a in protected_services for a in effective_args):
            facts.add("monitor_tamper")
        if any(
            a in {"auditd", "auditd.service", "fail2ban", "fail2ban.service"}
            for a in effective_args
        ):
            facts.add("security_disabled")
    if program in {"kill", "pkill", "killall"}:
        if any(a.isdigit() and int(a) in protected_pids for a in effective_args) or any(
            a in protected_services for a in effective_args
        ):
            facts.add("monitor_tamper")

    def protected(path):
        normalized = posixpath.normpath(path)
        return any(
            normalized == p or normalized.startswith(p.rstrip("/") + "/")
            for p in protected_paths
        )

    def sensitive(path):
        return path in {"/etc/shadow", "/etc/gshadow"} or path.endswith(
            ("/.ssh/id_rsa", "/.ssh/id_ed25519")
        )

    def persistence(path):
        return path.endswith(
            ("/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile")
        ) or path.startswith(("/etc/cron.", "/var/spool/cron/"))

    read_paths = row.get("read_paths", [])
    write_paths = row.get("write_paths", [])
    if any(
        not isinstance(paths, list) or any(not isinstance(p, str) for p in paths)
        for paths in (read_paths, write_paths)
    ):
        raise ValueError("File targets must be string arrays")
    if program in {"cat", "grep", "less", "head", "tail", "strings", "cp", "tar"}:
        read_paths = read_paths + [a for a in effective_args if a.startswith("/")]
    if (
        program in {"cp", "mv", "ln"}
        and effective_args
        and not any(
            a in {"-t", "--target-directory"} or a.startswith("--target-directory=")
            for a in effective_args
        )
    ):
        write_paths = write_paths + [effective_args[-1]]
    if program in {"tee", "touch", "rm", "shred", "truncate", "chattr"}:
        write_paths = write_paths + [a for a in effective_args if not a.startswith("-")]
    if any(sensitive(posixpath.normpath(p)) for p in read_paths):
        facts.add("credential_read")
    if any(persistence(posixpath.normpath(p)) for p in write_paths):
        facts.add("persistence_target_write")
    if any(protected(p) for p in write_paths):
        facts.add("monitor_tamper")
    block = re.compile(
        r"/dev/(?:sd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|md\d+|mapper/[^/]+)\Z"
    )
    if program == "dd" and any(
        a.startswith("of=") and block.fullmatch(a[3:]) for a in effective_args
    ):
        facts.add("destructive_device_write")
    if (program.startswith("mkfs") or program == "wipefs") and any(
        block.fullmatch(a) for a in effective_args
    ):
        facts.add("destructive_device_write")
    login = uid(row.get("login_uid"))
    effective_uid = uid(row.get("uid"))
    service_id = row.get("service_id")
    actor = (
        f"login:{login}"
        if login is not None
        else (
            f"service:{service_id}"
            if service_id
            else (
                f"uid:{effective_uid}"
                if effective_uid is not None
                else f"account:{row['account']}"
            )
        )
    )
    if login not in (None, 0) and effective_uid == 0:
        facts.add("elevated_context")
    session = row.get("session")
    if session in ("-1", "4294967295", "unset"):
        session = None
    for field, value in (
        ("session", session),
        ("service_id", service_id),
        ("lineage_id", row.get("lineage_id")),
    ):
        if value is not None and (
            not isinstance(value, str) or not value or len(value) > 256
        ):
            raise ValueError(f"Invalid {field}")
    cpu = row.get("cpu_fraction")
    if cpu is not None and (
        isinstance(cpu, bool)
        or not isinstance(cpu, (int, float))
        or not math.isfinite(cpu)
        or not 0 <= cpu <= 1
    ):
        raise ValueError("CPU fraction must be in [0,1]")
    return Event(
        row["event_id"],
        row["host"],
        row["boot_id"],
        row["account"],
        role,
        source,
        program,
        timestamp(row.get("timestamp")),
        actor,
        session,
        service_id,
        row.get("lineage_id"),
        parent,
        path_kind(effective_executable),
        "sudo" in wrappers or actual == "sudo" or parent == "sudo",
        opaque,
        frozenset(facts),
        optional_bool(row, "new_executable"),
        optional_bool(row, "off_hours"),
        optional_bool(row, "new_source"),
        optional_bool(row, "new_destination"),
        cpu,
        optional_bool(row, "success"),
        effective_uid,
        login,
    )
