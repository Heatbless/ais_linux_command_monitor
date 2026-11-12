"""Opt-in live shell monitoring for Linux/WSL; not a machine-wide exec sensor."""

import asyncio
import json
import os
import pwd
import shlex
import signal
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from uuid import uuid4

import bashlex

from ais.contracts import canonical
from ais.engine import Engine
from ais.events import event_from_record, uid
from ais.model import Model
from ais.rules import RuleConfig
from ais.sender import Outbox, Sender
from ais.transport import read_token


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(
            "State directory must be owned by this user and mode 700 on Linux storage"
        )
    return path


def shell_commands(text):
    """Extract static simple-command intentions, without executing expansions.

    Compounds/functions/conditionals are deliberately not traversed: their
    branches may never execute. Dynamic arguments are omitted and flagged.
    """
    nodes = bashlex.parse(text)
    found = []

    def visit(node):
        if node.kind in {"list", "pipeline"}:
            # Conditional lists cannot claim that both sides were executed.
            if any(getattr(part, "op", None) in {"&&", "||"} for part in node.parts):
                return
            for part in node.parts:
                visit(part)
        elif node.kind == "command":
            words = [part for part in node.parts if part.kind == "word"]
            if not words or words[0].parts:
                return
            incomplete = any(word.parts for word in words) or any(
                part.kind in {"redirect", "assignment"} for part in node.parts
            )
            # Retaining later arguments after omitting expansions would shift
            # option arity (sudo -u "$USER" python3). Keep only the static
            # command name in that case; never invent a wrapper target.
            argv = (
                [words[0].word]
                if any(word.parts for word in words)
                else [word.word for word in words]
            )
            found.append((argv, incomplete))

    for node in nodes:
        visit(node)
    return found


def hook(shell, socket_path):
    emitter = Path(__file__).with_name("shell_emit.py").resolve()
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(emitter))} {shlex.quote(str(socket_path))}"
    function = "_ais_preexec() { printf '%s' \"$1\" | " + command + "; return 0; }\n"
    if shell == "zsh":
        return (
            function + "autoload -Uz add-zsh-hook\nadd-zsh-hook preexec _ais_preexec\n"
        )
    return (
        "if [[ -o functrace ]] || shopt -q extdebug; then\n"
        "  printf '%s\\n' 'AIS: disable functrace/extdebug before installing this hook' >&2\n"
        "  return 1\nfi\n"
        "if [[ -n $(trap -p DEBUG) ]]; then\n"
        "  printf '%s\\n' 'AIS: existing DEBUG trap; refusing to replace it' >&2\n"
        "  return 1\nfi\n" + function + "trap '_ais_preexec \"$BASH_COMMAND\"' DEBUG\n"
    )


class ShellCollector:
    def __init__(self, engine, host, boot, role, emit, normalization=None):
        self.engine, self.host, self.boot, self.role = engine, host, boot, role
        self.emit = emit
        self.normalization = normalization or {}
        self.state = {
            "mode": "normalized_stream",
            "state": "unavailable",
            "last_successful_poll": None,
            "last_observed_event": None,
            "collected": 0,
            "lost": 0,
        }
        self.limit = asyncio.Semaphore(16)
        self.clients = set()

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.clients.add(task)
        try:
            if self.limit.locked():
                self.state["lost"] += 1
                return
            async with self.limit:
                peer = writer.get_extra_info("socket").getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                )
                pid, peer_uid, _ = struct.unpack("3i", peer)
                if peer_uid != os.getuid():
                    raise ValueError("Unexpected peer")
                # Kernel-derived peer/session identity, never supplied UID fields.
                session = str(os.getsid(pid))
                login = uid(Path(f"/proc/{pid}/loginuid").read_text().strip())
                account = pwd.getpwuid(peer_uid).pw_name
                payload = await asyncio.wait_for(reader.readline(), timeout=1)
                if len(payload) > 65536 or not payload.endswith(b"\n"):
                    raise ValueError("Oversized observation")
                body = json.loads(payload)
                if (
                    not isinstance(body, dict)
                    or set(body) != {"command"}
                    or not isinstance(body["command"], str)
                ):
                    raise ValueError("Invalid observation")
                commands = shell_commands(body["command"])
                if not commands:
                    raise ValueError("No static simple command")
                for argv, incomplete in commands:
                    now = time.time()
                    record = {
                        "event_id": "shell-" + str(uuid4()),
                        "host": self.host,
                        "boot_id": self.boot,
                        "account": account,
                        "role": self.role,
                        "uid": peer_uid,
                        "login_uid": login,
                        "session": session,
                        "source": "shell",
                        "timestamp": now,
                        "argv": argv,
                        "program": argv[0],
                        "argv_incomplete": incomplete,
                    }
                    assessment = self.engine.process(
                        event_from_record(record, **self.normalization)
                    )
                    assessment["coverage_notes"].append(
                        "shell_intent_not_exec_confirmation"
                    )
                    self.emit(assessment)
                    self.state["collected"] += 1
                    self.state["last_observed_event"] = now
                writer.write(b"ok\n")
                await writer.drain()
        except (
            ValueError,
            TypeError,
            KeyError,
            OSError,
            TimeoutError,
            NotImplementedError,
            bashlex.errors.ParsingError,
        ):
            self.state["lost"] += 1
            writer.write(b"rejected\n")
        finally:
            writer.close()
            await writer.wait_closed()
            self.clients.discard(task)


async def monitor(args, stop=None, sender_factory=Sender):
    state_dir = private_directory(args.state_dir)
    path = state_dir / "monitor.sock"
    # Never unlink another live monitor or an arbitrary preexisting file.
    if path.exists():
        raise ValueError("Socket exists; stop existing monitor or remove stale socket")
    model = Model.load(args.model)
    config = json.loads(args.config.read_text()) if args.config else {}
    if set(config) - {
        "rules",
        "protected_paths",
        "protected_services",
        "protected_pids",
    }:
        raise ValueError("Unknown configuration fields")
    protected = {k: v for k, v in config.items() if k != "rules"}
    protected["protected_pids"] = list(protected.get("protected_pids", [])) + [
        os.getpid()
    ]
    protected["protected_paths"] = (
        list(protected.get("protected_paths", []))
        + [str(args.model.resolve()), str(state_dir.resolve())]
        + ([str(args.token_file.resolve())] if args.token_file else [])
    )
    engine = Engine(model, RuleConfig(**config.get("rules", {})))
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    stop = stop or asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals = []
    sender = run = None
    if args.server_url:
        if (state_dir / "outbox.sqlite").resolve() in {
            p.resolve()
            for p in (args.model, args.config, args.token_file)
            if p is not None
        }:
            raise ValueError("Outbox overlaps a model/config/credential")
        outbox = Outbox(state_dir / "outbox.sqlite")
        sender = sender_factory(
            outbox,
            args.server_url,
            read_token(args.token_file),
            allow_tailscale_http=args.allow_tailscale_http,
        )
        run = outbox.new_run(boot, mode="live", agent_version="shell-monitor-v1")
        run.capabilities.shell_telemetry = True
        with outbox.connect() as db:
            db.execute(
                "UPDATE runs SET body=? WHERE run_id=?",
                (canonical(run), str(run.run_id)),
            )

    def emit(assessment):
        if sender:
            result = sender.enqueue(assessment, run.run_id)
            if result is None and assessment["status"] != "duplicate":
                raise ValueError("Transport rejected assessment")
        # stdout is sanitized assessment JSONL, never raw shell input.
        print(json.dumps(assessment, allow_nan=False), flush=True)

    collector = ShellCollector(engine, args.host, boot, args.role, emit, protected)

    def health():
        return {
            "collector": dict(collector.state),
            "detector": {
                "state": "running",
                "model_version": model.version,
                "profile_count": len(model.profiles),
                "experimental": True,
                "deployment_ready": False,
            },
        }

    async def check_loop():
        while not stop.is_set():
            collector.state["last_successful_poll"] = time.time()
            collector.state["state"] = (
                "degraded" if collector.state["lost"] else "healthy"
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=1)
            except TimeoutError:
                pass

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
            installed_signals.append(sig)
        async with await asyncio.start_unix_server(
            collector.accept, path=path, limit=65537
        ) as server:
            path.chmod(0o600)
            collector.state["state"] = "healthy"
            print(
                f"AIS shell monitor ready: {path}; enable the hook in each target terminal. Scope: this user's hooked shells only.",
                file=sys.stderr,
                flush=True,
            )
            async with asyncio.TaskGroup() as group:
                group.create_task(check_loop())
                if sender:
                    group.create_task(sender.supervise(run, health, stop))
                await stop.wait()
                collector.state["state"] = "stopped"
                server.close()
                await server.wait_closed()
                for client in list(collector.clients):
                    client.cancel()
                if sender and sender._wake:
                    sender._wake.set()
    finally:
        for sig in installed_signals:
            loop.remove_signal_handler(sig)
        if path.exists():
            path.unlink()
        if sender:
            sender.client.close()
    return 0
