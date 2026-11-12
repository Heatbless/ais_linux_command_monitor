"""Bounded audit event assembly. Exec success is not authentication success."""

from __future__ import annotations

import re
from collections import OrderedDict

from ais.events import basename, uid

IDENTIFIER = re.compile(r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)")
FIELD = re.compile(r'\b([A-Za-z0-9_]+)=(?:"([^"]*)"|(\S+))')


def decode(value, quoted=False):
    if quoted:
        return value
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        try:
            return bytes.fromhex(value).decode("utf-8")
        except (ValueError, UnicodeError):
            return None
    return value


def audit_records(lines, host, boot_id, identities=None, max_pending=1024):
    if max_pending < 1:
        raise ValueError("Audit pending bound must be positive")
    pending = OrderedDict()
    parents = OrderedDict()
    identities = identities or {}
    if not isinstance(identities, dict):
        raise ValueError("Identity mapping must be an object")

    def finish(identifier, data):
        syscall = data.get("syscall")
        if (
            not syscall
            or syscall.get("success") != "yes"
            or not (
                syscall.get("arch") == "c000003e"
                and syscall.get("syscall") in {"59", "322"}
            )
        ):
            return None
        executable = syscall.get("exe")
        if not executable or any(
            not syscall.get(k, "").isdigit() for k in ("uid", "auid")
        ):
            return None
        actual_uid, login_uid = uid(syscall["uid"]), uid(syscall["auid"])
        actor = f"login:{login_uid}" if login_uid is not None else f"uid:{actual_uid}"
        identity = identities.get(actor, {})
        if not isinstance(identity, dict):
            raise ValueError("Audit identity entries must be objects")
        pid, ppid = syscall.get("pid"), syscall.get("ppid")
        parent = parents.get(ppid)
        if pid:
            parents[pid] = basename(executable)
            parents.move_to_end(pid)
            if len(parents) > 10000:
                parents.popitem(last=False)
        argc = data.get("argc")
        arguments = data.get("arguments", {})
        complete = (
            argc is not None and 0 < argc <= 256 and set(arguments) == set(range(argc))
        )
        argv = [arguments[i] for i in range(argc)] if complete else [executable]
        session = syscall.get("ses")
        if session in {None, "-1", "4294967295"}:
            session = None
        return {
            "event_id": f"audit:{identifier[0]}:{identifier[1]}",
            "host": host,
            "boot_id": boot_id,
            "account": identity.get(
                "account", str(login_uid if login_uid is not None else actual_uid)
            ),
            "role": identity.get("role", "unknown"),
            "source": "exec",
            "success": True,
            "timestamp": identifier[0],
            "program": basename(executable),
            "executable": executable,
            "argv": argv,
            "uid": actual_uid,
            "login_uid": login_uid,
            "session": session,
            "service_id": identity.get("service_id"),
            "parent_program": parent,
            "argv_incomplete": not complete,
        }

    for line in lines:
        if len(line) > 1024 * 1024:
            raise ValueError("Oversized audit line")
        if line.strip() == "----":
            for identifier, data in list(pending.items()):
                result = finish(identifier, data)
                if result:
                    yield result
            pending.clear()
            continue
        match = IDENTIFIER.search(line)
        kind = re.match(r"type=(\w+)", line)
        if not match or not kind:
            continue
        identifier = match.groups()
        data = pending.setdefault(identifier, {"arguments": {}})
        if kind[1] == "SYSCALL":
            fields = {}
            for key, quoted, plain in FIELD.findall(line):
                if key == "exe":
                    fields[key] = decode(quoted or plain, bool(quoted))
                else:
                    fields[key] = quoted or plain
            data["syscall"] = fields
        elif kind[1] == "EXECVE":
            for key, quoted, plain in FIELD.findall(line):
                if key == "argc" and plain.isdigit():
                    data["argc"] = int(plain)
                elif re.fullmatch(r"a\d+", key):
                    value = decode(quoted or plain, bool(quoted))
                    if value is not None:
                        data["arguments"][int(key[1:])] = value
        if kind[1] == "EOE":
            result = finish(identifier, pending.pop(identifier))
            if result:
                yield result
        while len(pending) > max_pending:
            oldest, data = pending.popitem(last=False)
            result = finish(oldest, data)
            if result:
                result["audit_assembly_evicted"] = True
                yield result
    for identifier, data in pending.items():
        result = finish(identifier, data)
        if result:
            yield result
