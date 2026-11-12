"""Score external attack groups with a frozen demo model; never fit or execute."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from experiments.fetch_external import COWRIE_FILES
from experiments.history_feasibility import POSITIONS, HistoryNSA, windows
from experiments.history_import import parse_one


def load_demo_model(path):
    artifact = json.loads(path.read_text())
    supplied = artifact.pop("model_version")
    actual = hashlib.sha256(json.dumps(artifact, sort_keys=True).encode()).hexdigest()
    if actual != supplied or artifact["mode"] != "complete_any":
        raise ValueError("Changed or unsupported frozen model")
    vocabulary = artifact["vocabulary"]
    if sorted(vocabulary.values()) != list(range(1, len(vocabulary) + 1)):
        raise ValueError("Invalid vocabulary IDs")
    model = HistoryNSA("complete_any")
    model.vocabulary = vocabulary
    model.detectors = {(tuple(pos), tuple(pair)) for pos, pair in artifact["detectors"]}
    for positions, pair in model.detectors:
        if (
            positions not in POSITIONS
            or len(pair) != 2
            or any(t < 0 or t > len(vocabulary) for t in pair)
        ):
            raise ValueError("Invalid detector pattern")
    model.threshold = float(artifact["threshold"])
    if not 0 <= model.threshold < 1:
        raise ValueError("Model threshold is unusable")
    return model, supplied


def sanitize(commands):
    segments = [[]]
    excluded = Counter()
    for command in commands:
        if not isinstance(command, str) or len(command) > 65536:
            names, reason = [], "oversized_or_invalid"
        else:
            names, reason = parse_one(command)
        if reason:
            excluded[reason] += 1
            if reason not in {"builtin_only", "blank_or_comment"} and segments[-1]:
                segments.append([])
        else:
            segments[-1].extend(names)
    return [s for s in segments if s], excluded


def analyze_period(path, model, seen):
    expected_size, expected_blob = COWRIE_FILES[path.name]
    data = path.read_bytes()
    if (
        len(data) != expected_size
        or hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        != expected_blob
    ):
        raise ValueError("External input does not match pinned source")
    result = Counter()
    exclusions = Counter()
    for line in data.decode().splitlines():
        row = json.loads(line)
        if not isinstance(row.get("commands"), list):
            raise ValueError("Expected ordered command list")
        result["source_groups"] += 1
        segments, excluded = sanitize(row["commands"])
        exclusions.update(excluded)
        result["source_command_entries"] += len(row["commands"])
        result["retained_program_names"] += sum(map(len, segments))
        signature = hashlib.sha256(
            json.dumps(segments, separators=(",", ":")).encode()
        ).hexdigest()
        if not segments:
            result["empty_after_filtering"] += 1
            continue
        if signature in seen:
            result["duplicate_sanitized_groups"] += 1
            continue
        seen.add(signature)
        result["unique_nonempty_groups"] += 1
        if any(
            re.fullmatch(r"python(?:[23](?:\.\d+)*)?", c) for s in segments for c in s
        ):
            result["python_attention_groups"] += 1
        samples = windows(segments)
        if not samples:
            result["below_ten_command_warmup"] += 1
            continue
        result["scorable_unique_groups"] += 1
        scores = [model.score(w) for w in samples]
        result["scored_windows"] += len(scores)
        if max(scores) > model.threshold:
            result["ais_flagged_unique_groups"] += 1
    # Ensure stable zero-valued keys rather than omitted/ambiguous metrics.
    for key in (
        "source_groups",
        "source_command_entries",
        "retained_program_names",
        "empty_after_filtering",
        "duplicate_sanitized_groups",
        "unique_nonempty_groups",
        "below_ten_command_warmup",
        "scorable_unique_groups",
        "scored_windows",
        "ais_flagged_unique_groups",
        "python_attention_groups",
    ):
        result[key] += 0
    return {
        **result,
        "exclusions_by_reason": dict(exclusions),
        "flagged_fraction_of_scorable": result["ais_flagged_unique_groups"]
        / result["scorable_unique_groups"]
        if result["scorable_unique_groups"]
        else None,
        "flagged_fraction_of_unique_nonempty": result["ais_flagged_unique_groups"]
        / result["unique_nonempty_groups"]
        if result["unique_nonempty_groups"]
        else None,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def run(root, model_path, output):
    model, version = load_demo_model(model_path)
    seen = set()
    periods = {}
    for period in ("2021_2022", "2024"):
        periods[period] = analyze_period(root / f"{period}.jsonl", model, seen)
        print(
            f"Cowrie {period}: {periods[period]['source_groups']} source groups processed",
            flush=True,
        )
    evidence = {
        "schema_version": 1,
        "purpose": "external evaluation only; no fitting or threshold changes",
        "source": "Wang et al., Unveiling Evolving Threats, SRDS 2025; dataset CC BY 4.0",
        "model_version": version,
        "profile": "vps",
        "threshold": model.threshold,
        "periods": periods,
        "benign_samples_available": False,
        "accuracy": None,
        "false_positive_rate": None,
        "real_vps_attack_recall": None,
        "deduplication": "sanitized program sequences including gaps, across both periods in chronological order",
        "source_unit": "effective source-IP group, not necessarily a single login session",
        "training_unchanged": hashlib.sha256(model_path.read_bytes()).hexdigest(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def render(evidence):
    lines = [
        "# External Cowrie evaluation",
        "",
        "The frozen VPS history-plus-synthetic-normal wildcard-pair model was evaluated without fitting, "
        "threshold changes, or adding attacker activity to normal training. "
        "No local model is promoted because the local-history experiment did not yield a usable candidate.",
        "",
        f"Model version: `{evidence['model_version']}`. Threshold: {evidence['threshold']:.4f}.",
        "",
        "| Period | Source groups | Unique nonempty groups | Scorable unique groups | AIS-flagged groups | Below warm-up | Empty after filtering | Duplicate groups |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for period, row in evidence["periods"].items():
        lines.append(
            f"| {period} | {row['source_groups']} | {row['unique_nonempty_groups']} | {row['scorable_unique_groups']} | "
            f"{row['ais_flagged_unique_groups']} | {row['below_ten_command_warmup']} | {row['empty_after_filtering']} | {row['duplicate_sanitized_groups']} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "- The source contains post-login honeypot attack activity. Its effective groups combine ordered commands by attacker IP; "
        "they are not guaranteed to be individual login sessions. Individual commands can be legitimate even inside an attack group.",
        "- The parser strips arguments and preserves gaps for unsupported syntax or unrecognized programs. "
        "Simple omitted built-ins do not split sequences. Inputs are never executed, downloaded scripts are never followed, and source IPs/arguments are not published.",
        "- Duplicate sanitized groups are removed across periods, so the 2024 count excludes patterns already seen in 2021–2022. "
        "This is evaluation deduplication only; the model never learns those patterns.",
        "- A scorable group has at least one continuous ten-program window. Short groups and filtering gaps are coverage failures, "
        "not negative detections. Do not report the scorable subset alone as total attack recall.",
        "- Source commands are typed shell input, not verified successful audit executions. That observation mismatch limits transfer to the planned live collector.",
        "- Attack-only data cannot estimate false positives, precision, overall accuracy, or attack recall on a real VPS. "
        "Personal-history false alerts and synthetic scenario results remain separate in the history report.",
        "- Python attention counts in private evidence are independent rule coverage and do not count as AIS detections. "
        "The ten-execution warm-up remains a limitation; these results must not silently tune it.",
        "",
        "## Source and reproduction",
        "",
        "[Dataset and attribution](https://github.com/zyw-286/shell-attack-evolution-dataset), "
        "Wang et al., “Unveiling Evolving Threats: A Data Analysis for Next-Generation Honeypot Development”, IEEE SRDS 2025. "
        "Dataset license: CC BY 4.0. Input Git-blob hashes and SHA-256 digests are saved in private provenance.",
        "",
        "```sh",
        "uv run python -m experiments.fetch_external --source cowrie",
        "uv run python -m experiments.external_evaluation",
        "```",
        "",
        "The raw source and detailed evidence are in ignored `private-data/external/`. "
        "See [personal-history results](history-results.md) for baseline limitations.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path, default=Path("private-data/external/cowrie")
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(
            "private-data/history-experiment/models/vps-history_plus_synthetic_normal-complete_any-42.json"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("private-data/external/cowrie/evaluation.json"),
    )
    parser.add_argument(
        "--report", type=Path, default=Path("docs/research/external-results.md")
    )
    args = parser.parse_args()
    evidence = run(args.input, args.model, args.output)
    args.report.write_text(render(evidence))
