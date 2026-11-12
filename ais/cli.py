"""Local event-stream CLI. Inputs are data, never shell commands to execute."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
from contextlib import nullcontext
from pathlib import Path

import httpx

from ais.audit import audit_records
from ais.catalogue import catalogue
from ais.demo import render as render_demo
from ais.demo import run as run_demo
from ais.engine import Engine
from ais.events import event_from_record
from ais.model import Model
from ais.rules import RuleConfig
from ais.workflows import train_workflows


def output_file(path):
    if path == "-":
        return nullcontext(sys.stdout)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target.open("w")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    live = sub.add_parser(
        "monitor", help="Listen for live commands from opted-in local shells"
    )
    live.add_argument("--model", type=Path, required=True)
    live.add_argument("--config", type=Path)
    live.add_argument("--host", default="vm-01", help="Exact registered host identity")
    live.add_argument(
        "--role", choices=("developer", "admin", "unknown"), default="developer"
    )
    live.add_argument(
        "--state-dir", type=Path, default=Path(f"/tmp/ais-live-{os.getuid()}")
    )
    live.add_argument("--server-url")
    live.add_argument("--token-file", type=Path)
    live.add_argument("--allow-tailscale-http", action="store_true")
    shell_hook = sub.add_parser(
        "hook", help="Print a Bash or Zsh opt-in hook to source"
    )
    shell_hook.add_argument("shell", choices=("bash", "zsh"))
    shell_hook.add_argument(
        "--socket", type=Path, default=Path(f"/tmp/ais-live-{os.getuid()}/monitor.sock")
    )
    train = sub.add_parser(
        "train", help="Train separate profiles from approved normal workflows"
    )
    train.add_argument("workflows", type=Path)
    train.add_argument("--output", type=Path, required=True)
    train.add_argument("--allow-synthetic", action="store_true")
    catalog = sub.add_parser(
        "catalogue", help="Import reference vocabulary without normality approval"
    )
    catalog.add_argument("--directory", type=Path, default=Path("commands"))
    catalog.add_argument(
        "--output", type=Path, default=Path("private-data/contextual/catalogue.json")
    )
    for name in ("score", "audit-score"):
        score = sub.add_parser(
            name,
            help="Assess JSONL events"
            if name == "score"
            else "Assess completed raw audit groups",
        )
        score.add_argument("--model", type=Path, required=True)
        score.add_argument("--input", default="-")
        score.add_argument("--output", default="-")
        score.add_argument("--config", type=Path)
        score.add_argument("--reference-dir", type=Path)
        score.add_argument(
            "--server-url", help="HTTPS ingestion origin; enables file replay delivery"
        )
        score.add_argument(
            "--allow-tailscale-http",
            action="store_true",
            help="Allow HTTP to a literal 100.64.0.0/10 address over your existing Tailscale connection",
        )
        score.add_argument("--token-file", type=Path)
        score.add_argument(
            "--outbox", type=Path, default=Path("private-data/transport/outbox.sqlite")
        )
        score.add_argument(
            "--expected-host", help="Exact host registered on the server"
        )
        score.add_argument(
            "--transport-boot-id", help="Boot identity in every input event"
        )
        score.add_argument(
            "--transport-mode", choices=("replay", "demo"), default="replay"
        )
        score.add_argument(
            "--transport-linger",
            type=float,
            default=35,
            help="Seconds to deliver and report EOF health before exiting",
        )
        if name == "audit-score":
            score.add_argument("--host", required=True)
            score.add_argument("--boot-id", required=True)
            score.add_argument(
                "--identities", type=Path, help="Trusted login/uid role mapping"
            )
    demo = sub.add_parser(
        "demo", help="Run synthetic scenarios; does not execute their commands"
    )
    demo.add_argument(
        "--host",
        default="demo-vm",
        help="Synthetic host identity; match your demo agent registration",
    )
    demo.add_argument(
        "--output", type=Path, default=Path("private-data/contextual-demo")
    )
    demo.add_argument(
        "--report", type=Path, default=Path("docs/research/contextual-demo.md")
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "hook":
            from ais.live import hook

            print(hook(args.shell, args.socket), end="")
            return 0
        if args.command == "monitor":
            from ais.live import monitor

            if args.server_url and not args.token_file:
                raise ValueError("Server delivery requires a private token file")
            if not args.server_url and (args.token_file or args.allow_tailscale_http):
                raise ValueError("Transport options require a server URL")
            return asyncio.run(monitor(args))
        if args.command == "catalogue":
            if args.output.resolve() in {
                p.resolve() for p in args.directory.glob("*.txt")
            }:
                raise ValueError("Output overlaps a reference input")
            result = catalogue(args.directory)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            print(
                json.dumps(
                    {
                        "files": len(result["files"]),
                        "reference_programs": len(result["programs"]),
                        "normality_approved": False,
                    }
                )
            )
            return 0
        if args.command == "train":
            if args.workflows.resolve() in {
                args.output.resolve(),
                args.output.with_suffix(".provenance.json").resolve(),
            }:
                raise ValueError("Output overlaps workflow input")
            model, provenance = train_workflows(args.workflows, args.allow_synthetic)
            model.save(args.output)
            args.output.with_suffix(".provenance.json").write_text(
                json.dumps(provenance, indent=2) + "\n"
            )
            print(
                json.dumps(
                    {
                        "profiles": len(model.profiles),
                        "version": model.version,
                        "deployment_ready": False,
                    }
                )
            )
            return 0
        if args.command == "demo":
            result = run_demo(args.output, host=args.host)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(render_demo(result))
            print(
                json.dumps(
                    {
                        "synthetic_only": True,
                        "profiles": result["profiles"],
                        "scenarios": len(result["scenarios"]),
                        "checks_passed": result["checks_passed"],
                        "report": str(args.report),
                    }
                )
            )
            return 0 if result["checks_passed"] else 1
        model = Model.load(args.model)
        if args.server_url:
            if not all((args.token_file, args.expected_host, args.transport_boot_id)):
                raise ValueError(
                    "Transport requires credential, registered host and boot ID"
                )
            if args.input == "-":
                raise ValueError(
                    "Transport currently supports finite replay files only"
                )
            if (
                not args.server_url.startswith("https://")
                and not args.allow_tailscale_http
            ):
                raise ValueError("HTTPS ingestion URL required")
            if (
                not math.isfinite(args.transport_linger)
                or not 0 <= args.transport_linger <= 3600
            ):
                raise ValueError("Invalid transport linger")
        elif (
            args.token_file
            or args.expected_host
            or args.transport_boot_id
            or args.allow_tailscale_http
        ):
            raise ValueError("Transport settings require server URL")
        inputs_to_preserve = [args.model]
        if args.input != "-":
            inputs_to_preserve.append(Path(args.input))
        if args.config:
            inputs_to_preserve.append(args.config)
        if getattr(args, "identities", None):
            inputs_to_preserve.append(args.identities)
        if args.token_file:
            inputs_to_preserve.append(args.token_file)
        if args.server_url:
            preserved = {p.resolve() for p in inputs_to_preserve}
            if args.outbox.resolve() in preserved or (
                args.output != "-"
                and args.outbox.resolve() == Path(args.output).resolve()
            ):
                raise ValueError("Outbox overlaps an input or output")
            inputs_to_preserve.append(args.outbox)
        if args.output != "-" and Path(args.output).resolve() in {
            p.resolve() for p in inputs_to_preserve
        }:
            raise ValueError("Output overlaps input or model")
        config = json.loads(args.config.read_text()) if args.config else {}
        if set(config) - {
            "rules",
            "protected_paths",
            "protected_services",
            "protected_pids",
        }:
            raise ValueError("Unknown configuration fields")
        reference = (
            catalogue(args.reference_dir)["programs"] if args.reference_dir else ()
        )
        engine = Engine(model, RuleConfig(**config.get("rules", {})), reference)
        normalization = {
            key: config[key]
            for key in ("protected_paths", "protected_services", "protected_pids")
            if key in config
        }
        inputs = (
            nullcontext(sys.stdin) if args.input == "-" else Path(args.input).open()
        )
        with inputs as stream, output_file(args.output) as destination:
            if args.command == "audit-score":
                identities = (
                    json.loads(args.identities.read_text()) if args.identities else {}
                )
                rows = audit_records(stream, args.host, args.boot_id, identities)
                print(
                    "Audit coverage: successful x86-64 exec only; no shell built-ins, auth outcomes, cgroup discovery or source-IP enrichment. Live raw input needs complete EOE/---- groups.",
                    file=sys.stderr,
                )
            else:

                def records():
                    for line in stream:
                        if len(line) > 1024 * 1024:
                            raise ValueError("Oversized event record")
                        if line.strip():
                            yield json.loads(line)

                rows = records()
            assessments = (
                engine.process(event_from_record(row, **normalization)) for row in rows
            )
            if args.server_url:
                from ais.transport import replay

                return asyncio.run(replay(assessments, destination, model, args))
            for assessment in assessments:
                destination.write(json.dumps(assessment, allow_nan=False) + "\n")
                destination.flush()
        return 0
    except (
        ValueError,
        TypeError,
        KeyError,
        OSError,
        httpx.HTTPError,
        ExceptionGroup,
    ) as error:
        # Do not echo malformed argv, paths, secrets or raw log lines in errors.
        print(
            f"Input/model validation failed ({type(error).__name__}). Check the schema, approval, partitions and profile context in docs/contextual-monitoring.md.",
            file=sys.stderr,
        )
        return 2
