"""Reference recognition is never normal-behavior approval."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import bashlex

from ais.events import basename


def walk(node):
    yield node
    for value in vars(node).values():
        children = value if isinstance(value, list) else [value]
        for child in children:
            if isinstance(child, bashlex.ast.node):
                yield from walk(child)


def catalogue(directory):
    files = []
    programs = set()
    for path in sorted(Path(directory).glob("*.txt")):
        rows = []
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            names = set()
            status = "reference"
            try:
                nodes = bashlex.parse(line)
                for root in nodes:
                    for node in walk(root):
                        if node.kind == "command":
                            words = [part for part in node.parts if part.kind == "word"]
                            if words and not getattr(words[0], "parts", []):
                                name = basename(words[0].word)
                                if (
                                    re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+\-]*", name)
                                    and name != "ctrl+r"
                                ):
                                    names.add(name)
            except Exception:
                status = "unparsed"
            rows.append({"line": number, "programs": sorted(names), "status": status})
            programs.update(names)
        files.append(
            {
                "file": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "entries": rows,
            }
        )
    if not files:
        raise ValueError("No reference catalogue files")
    return {
        "schema_version": 1,
        "normality_approved": False,
        "ordered_sessions": False,
        "programs": sorted(programs),
        "files": files,
    }
