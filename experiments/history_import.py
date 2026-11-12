"""Conservative reusable history sanitization; never executes input."""

import bisect
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

import bashlex

BUILTINS = set(
    "alias bg bind break builtin caller cd command compgen complete compopt continue declare dirs disown echo enable eval exec exit export false fc fg getopts hash help history jobs kill let local logout mapfile popd printf pushd pwd read readarray readonly return set shift shopt source suspend test times trap true type typeset ulimit umask unalias unset wait".split()
)
KNOWN = set()
for folder in ("/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/local/bin"):
    path = Path(folder)
    if path.is_dir():
        KNOWN.update(
            p.name for p in path.iterdir() if p.is_file() and os.access(p, os.X_OK)
        )
KNOWN.update(
    "sudo apt apt-get aptitude yum dnf pacman apk systemctl service journalctl docker docker-compose podman kubectl helm nginx apache2 certbot ufw iptables nft fail2ban-client mysql mariadb psql redis-cli redis-server mongosh mongod php composer node npm npx pnpm yarn bun deno python python2 python3 pip pip2 pip3 uv uvx poetry pipenv gunicorn uvicorn celery supervisorctl supervisord git gh rsync scp sftp ssh ssh-keygen tmux screen htop btop nano vim nvim vi wget curl unzip zip tar make gcc g++ cc cargo rustc rustup go java javac dotnet code codex claude ollama tailscale cloudflared pm2 reboot shutdown login su".split()
)
SAFE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+\-]*\Z")
PYTHON = re.compile(r"(?:python|pip)(?:[23](?:\.\d+)*)?\Z")


def walk(node):
    yield node
    for value in vars(node).values():
        if isinstance(value, bashlex.ast.node):
            yield from walk(value)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, bashlex.ast.node):
                    yield from walk(child)


def known(word):
    name = word.rsplit("/", 1)[-1]
    return (
        name
        if SAFE_NAME.fullmatch(name) and (name in KNOWN or PYTHON.fullmatch(name))
        else None
    )


def extract(node):
    # Avoid inferring execution order inside definitions, compound shell logic,
    # substitutions, or dynamically constructed commands.
    kinds = {n.kind for n in walk(node)}
    if kinds & {
        "compound",
        "function",
        "commandsubstitution",
        "processsubstitution",
        "heredoc",
    }:
        return [], "complex_shell_entry"
    found = []
    for command in sorted(
        (n for n in walk(node) if n.kind == "command"), key=lambda n: n.pos
    ):
        words = [p for p in command.parts if p.kind == "word"]
        if not words or getattr(words[0], "parts", []):
            return [], "dynamic_or_assignment_only"
        name = known(words[0].word)
        if words[0].word in BUILTINS or words[0].word in {".", "[", "!", "time"}:
            if words[0].word in {"eval", "exec", "source", ".", "command", "builtin"}:
                return [], "opaque_shell_execution"
            continue
        if not name:
            return [], "unrecognized_executable"
        found.append(name)
        # sudo itself and its statically identifiable target both execute.
        # Never reinterpret arguments to general programs as executable names.
        if name == "sudo":
            index = 1
            unsafe = False
            while index < len(words):
                value = words[index].word
                if getattr(words[index], "parts", []):
                    unsafe = True
                    break
                if value == "--":
                    index += 1
                    break
                if value in {
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
                }:
                    index += 2
                elif value.startswith("-"):
                    # Only unwrap options whose arity is known.
                    if value in {
                        "-n",
                        "-E",
                        "-H",
                        "-S",
                        "-k",
                        "-K",
                        "-b",
                    } or value.startswith(("--user=", "--group=", "--host=")):
                        index += 1
                    else:
                        unsafe = True
                        break
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", value):
                    index += 1
                else:
                    break
            if not unsafe and index < len(words):
                target = known(words[index].word)
                if target and target not in BUILTINS:
                    found.append(target)
    return found, None if found else "builtin_only"


def parse_one(source):
    try:
        nodes = bashlex.parse(source)
    except Exception:
        return [], "unparseable_shell_entry"
    names = []
    for node in nodes:
        current, reason = extract(node)
        if reason:
            if reason != "builtin_only":
                return [], reason
        names.extend(current)
    return names, None if names else "builtin_only"


def run(ROOT, OUT):
    ROOT = ROOT.resolve()
    OUT = (ROOT / OUT).resolve() if not OUT.is_absolute() else OUT.resolve()
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUT.parent, 0o700)
    os.chmod(OUT, 0o700)
    report = {
        "format_version": 2,
        "parser": "bashlex 0.18",
        "executable_catalog_sha256": hashlib.sha256(
            "\n".join(sorted(KNOWN)).encode()
        ).hexdigest(),
        "sources": [],
        "limitations": [
            "Command-name-only baseline candidates, not a determination of benign intent.",
            "History has no reliable execution outcome, session identity, or privilege transition evidence.",
            "Simple lists/pipelines preserve textual order; actual execution and ordering are not established.",
            "Simple non-executing builtins are omitted; opaque builtins (eval/exec/source), compound syntax, substitutions and unknown programs create gaps.",
            "Unknown/ambiguous entries split segments; simple non-executing builtins do not. Never cross segment boundaries.",
            "Arguments, paths, timestamps, environment values, comments and redirection targets are not retained.",
            "Local malformed history uses conservative per-line parsing; multiline entry boundaries cannot be fully recovered.",
        ],
    }
    for filename, profile in [
        ("heat_bash_history", "local"),
        ("vps_bash_history", "vps"),
    ]:
        source = ROOT / filename
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        text = data.decode("utf-8", errors="strict")
        lines = text.splitlines()
        starts = [0]
        for match in re.finditer("\n", text):
            starts.append(match.end())
        # A full valid stream preserves heredoc/quoted-entry boundaries. Fall back
        # only for the malformed local history, retaining explicit segment gaps.
        try:
            nodes = bashlex.parse(text)
            entries = [
                (bisect.bisect_right(starts, n.pos[0]), *extract(n)) for n in nodes
            ]
            mode = "whole_stream"
        except Exception:
            entries = [
                (number, *parse_one(line)) for number, line in enumerate(lines, 1)
            ]
            mode = "conservative_lines"
        records, excluded = [], Counter()
        segment = 0
        for line, names, reason in entries:
            if reason:
                excluded[reason] += 1
                if reason not in {"builtin_only", "blank_or_comment"}:
                    segment += 1
                continue
            for name in names:
                records.append(
                    {"source_line": line, "segment": segment, "command": name}
                )
        json_path = OUT / f"{profile}.commands.jsonl"
        text_path = OUT / f"{profile}.commands"
        json_path.write_text("".join(json.dumps(r) + "\n" for r in records))
        text_path.write_text("".join(r["command"] + "\n" for r in records))
        for path in (json_path, text_path):
            os.chmod(path, 0o600)
        assert all(SAFE_NAME.fullmatch(r["command"]) for r in records)
        assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
        sizes = Counter(r["segment"] for r in records)
        report["sources"].append(
            {
                "source": filename,
                "profile": profile,
                "sha256": digest,
                "source_lines": len(lines),
                "parsing_mode": mode,
                "retained_command_names": len(records),
                "unique_command_names": len({r["command"] for r in records}),
                "retained_segments": len(sizes),
                "longest_segment": max(sizes.values(), default=0),
                "excluded_entries_by_reason": dict(excluded),
                "outputs": [
                    str(path.relative_to(ROOT))
                    if path.is_relative_to(ROOT)
                    else str(path)
                    for path in (json_path, text_path)
                ],
            }
        )
    report_path = OUT / "filter-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    os.chmod(report_path, 0o600)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--output", type=Path, default=Path("private-data/histories-v2")
    )
    args = parser.parse_args()
    print(json.dumps(run(args.root, args.output), indent=2))
