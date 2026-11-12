"""Bounded, label-aligned AIT v1.1 execution sample; never executes log data.

The full host log expands to 12.4 GB. Read a chronological prefix through nested
ZIP ranges and save sanitized successful execution records, not the raw payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from experiments.external_evaluation import load_demo_model
from experiments.fetch_external import AIT_V1_URL, RemoteZip, StoredMember
from experiments.history_feasibility import windows


def execution(line):
    # Auth/service logs can contain exe= but do NOT represent execve events.
    if not line.startswith("type=SYSCALL "):
        return None
    fields = dict(
        re.findall(r"\b(arch|syscall|success|pid|ppid|uid|auid|ses)=([^\s]+)", line)
    )
    call = fields.get("syscall")
    if fields.get("success") != "yes" or not (
        call in {"execve", "execveat"}
        or fields.get("arch") == "c000003e"
        and call in {"59", "322"}
    ):
        return None
    match = re.search(r'\bexe=(?:"([^"]+)"|([0-9A-Fa-f]+))', line)
    event = re.search(r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)", line)
    if not match or not event:
        return None
    try:
        executable = (
            match[1]
            if match[1] is not None
            else bytes.fromhex(match[2]).decode("utf-8")
        )
    except (ValueError, UnicodeError):
        return None
    basename = executable.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+\-]*", basename):
        return None
    if any(not fields.get(key, "").isdigit() for key in ("uid", "auid", "ses")):
        return None
    return {
        "command": basename,
        "timestamp": event[1],
        "event_id": event[2],
        "uid": fields["uid"],
        "auid": fields["auid"],
        "session": fields["ses"],
    }


def score_contexts(records, model):
    segments = defaultdict(list)
    for row in records:
        if row["normal_label"] and row["uid"] == "0":
            key = (row["auid"], row["session"], row.get("normal_block", 0))
            segments[key].append(row["command"])
    broad = windows(list(segments.values()))
    login = windows([s for key, s in segments.items() if key[0] == "0"])
    unset = windows([s for key, s in segments.items() if key[0] == "4294967295"])
    flagged = sum(model.score(w) > model.threshold for w in broad)
    return {
        "normal_root_windows": len(broad),
        "flagged_normal_root_windows": flagged,
        "normal_root_window_flag_fraction": flagged / len(broad) if broad else None,
        "normal_root_login_windows": len(login),
        "flagged_normal_root_login_windows": sum(
            model.score(w) > model.threshold for w in login
        ),
        "normal_unset_login_windows": len(unset),
        "flagged_normal_unset_login_windows": sum(
            model.score(w) > model.threshold for w in unset
        ),
    }


def run(root, model_path, max_lines=1000000, max_bytes=256 * 1024 * 1024):
    if max_lines <= 0 or max_bytes <= 0:
        raise ValueError("Sample bounds must be positive")
    root.mkdir(parents=True, exist_ok=True)
    remote = RemoteZip(AIT_V1_URL)
    counts = Counter()
    audit_hash, label_hash = hashlib.sha256(), hashlib.sha256()
    records = []
    normal_block = 0
    previously_normal = True
    model, version = load_demo_model(model_path)
    with zipfile.ZipFile(remote) as outer:
        data_info = outer.getinfo("data/mail.spiral.com/audit/audit.zip")
        label_info = outer.getinfo("labels/mail.spiral.com/audit/audit.zip")
        with (
            zipfile.ZipFile(StoredMember(remote, data_info)) as data_zip,
            zipfile.ZipFile(StoredMember(remote, label_info)) as label_zip,
        ):
            with (
                data_zip.open("audit.log") as audit,
                label_zip.open("audit.log") as labels,
            ):
                for number in range(1, max_lines + 1):
                    raw = audit.readline(1024 * 1024 + 1)
                    if not raw:
                        break
                    label = labels.readline(1024)
                    if not label or len(raw) > 1024 * 1024:
                        raise ValueError("Audit/label alignment or line-size failure")
                    if counts["uncompressed_audit_bytes"] + len(raw) > max_bytes:
                        break
                    pair = label.decode("ascii").strip().split(",")
                    if len(pair) != 2 or any(
                        not re.fullmatch(r"-?\d+", v) for v in pair
                    ):
                        raise ValueError("Unsupported AIT label encoding")
                    counts["source_lines"] += 1
                    counts["uncompressed_audit_bytes"] += len(raw)
                    audit_hash.update(raw)
                    label_hash.update(label)
                    normal = pair == ["0", "0"]
                    if not normal and previously_normal:
                        normal_block += 1
                    previously_normal = normal
                    counts[
                        "normal_labeled_lines" if normal else "non_normal_labeled_lines"
                    ] += 1
                    row = execution(raw.decode("utf-8", errors="replace"))
                    if row:
                        counts["successful_executions"] += 1
                        row.update(
                            {
                                "source_line": number,
                                "normal_label": normal,
                                "normal_block": normal_block,
                            }
                        )
                        records.append(row)
                    if number % 100000 == 0:
                        print(
                            f"AIT prefix: {number} source lines; {counts['successful_executions']} successful executions",
                            flush=True,
                        )
    evidence = {
        "source": "https://zenodo.org/records/4264796",
        "host": "mail.spiral.com",
        "sample_kind": "bounded chronological prefix, not full benchmark",
        "maximum_source_lines": max_lines,
        "maximum_uncompressed_bytes": max_bytes,
        "counts": dict(counts),
        "range_transfer_bytes": remote.downloaded,
        "audit_prefix_sha256": audit_hash.hexdigest(),
        "label_prefix_sha256": label_hash.hexdigest(),
        "first_execution_timestamp": records[0]["timestamp"] if records else None,
        "last_execution_timestamp": records[-1]["timestamp"] if records else None,
        "vps_model_version": version,
        "model_unchanged": True,
        **score_contexts(records, model),
        "interpretation": "Cross-environment normal-activity stress check; simulated mail server differs from personal VPS; approximate source labels; no combined accuracy or personal FPR claim",
    }
    (root / "execution-sample.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in records)
    )
    (root / "sample-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        f"AIT sample complete: {counts['successful_executions']} executions; {remote.downloaded} bytes transferred",
        flush=True,
    )
    return evidence


def render(evidence):
    counts = evidence["counts"]
    return f"""# AIT execution coverage and cross-environment check

AIT v2.1 was inspected before use. The seven audit logs in the selected russellmitchell testbed contain **zero successful execve/execveat events**: most records are authentication/service activity, and its few SYSCALL records are syscall 1 (write). Those files are not used as command sequences. Authentication records with an exe field must not be mistaken for executions.

## Usable v1.1 sample

The older [AIT v1.1 release](https://zenodo.org/records/4264796) includes fine-grained syscall logs. A bounded prefix from mail.spiral.com was read with its matching per-line labels, through stored nested ZIP members and HTTP ranges. No full archive was downloaded and no dataset commands were executed.

- Source lines examined: **{counts["source_lines"]:,}**.
- Normal-labeled lines (both source labels zero): **{counts["normal_labeled_lines"]:,}**.
- Non-normal-labeled lines: **{counts.get("non_normal_labeled_lines", 0):,}**.
- Successful executable events retained: **{counts["successful_executions"]:,}**.
- Network bytes transferred for this sample: **{evidence["range_transfer_bytes"]:,}**.
- Normal root-login-context windows (uid=0, auid=0): **{evidence["normal_root_login_windows"]:,}**; flagged: **{evidence["flagged_normal_root_login_windows"]:,}**.
- Normal root windows with an unset login UID: **{evidence["normal_unset_login_windows"]:,}**; flagged: **{evidence["flagged_normal_unset_login_windows"]:,}**. These daemon/service contexts are outside the planned per-login-account filter and are reported separately.

The sample's source timestamps run from {evidence["first_execution_timestamp"]} to {evidence["last_execution_timestamp"]}. This is a chronological prefix, not the complete six-day benchmark, and contains no source-labeled attack lines. The full host log expands to 12.4 GB; the sample uses a one-million-line / 256 MiB uncompressed limit and 64 MiB transfer cap.

## Interpretation

The personal VPS model does not transfer reliably to this different simulated mail-server workload, including the root-login-context subset. A high recognition rate on foreign attack data alone is therefore insufficient: unfamiliar normal activity also triggers it. Audit telemetry also includes child executions absent from typed Bash history; normal training recordings must match the live collector's observation unit. Do not pool this server's activity into the personal baseline without explicitly changing the intended profile and independently validating the result.

Records are grouped by user/login/session context and kept out of personal training. Only successful x86-64 execve/execveat records (or explicit named syscalls) are accepted. Arguments, full executable paths and source log contents are excluded from public outputs. Non-normal label spans break normal sequences; source labels remain approximate, as documented by the authors.

The sampled prefix does not support AIT attack recall or full-benchmark claims. It is a normal-workload stress check and an execution-corpus sample. Additional representative **personal** normal recordings are still needed to calibrate your VPS profile.

## Provenance and reproduction

Source: Landauer et al., AIT Log Data Set v1.1, DOI 10.5281/zenodo.4264796. The [dataset documentation](https://zenodo.org/records/4264796) describes label construction and its limitations. The v2.1 audit check uses [record 19483937](https://zenodo.org/records/19483937).

Private normalized events and evidence: private-data/external/ait-v1/. Prefix SHA-256 hashes identify the sampled bytes; partial sampling does not verify the full host log's CRC. The full-member v2 audit extractions were checked by ZIP CRC during reads.

```sh
uv run python -m experiments.fetch_external --source ait --ait-members
uv run python -m experiments.fetch_external --source ait-v1
uv run python -m experiments.ait_sample
```

See [Cowrie results](external-results.md) and [personal-history results](history-results.md). Metrics remain separate; no combined accuracy is reported.
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path("private-data/external/ait-v1")
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(
            "private-data/history-experiment/models/vps-history_plus_synthetic_normal-complete_any-42.json"
        ),
    )
    parser.add_argument("--max-lines", type=int, default=1000000)
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument(
        "--report", type=Path, default=Path("docs/research/ait-coverage.md")
    )
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--rescore-only", action="store_true")
    args = parser.parse_args()
    if args.rescore_only:
        evidence = json.loads((args.output / "sample-evidence.json").read_text())
        records = [
            json.loads(line)
            for line in (args.output / "execution-sample.jsonl")
            .read_text()
            .splitlines()
        ]
        model, version = load_demo_model(args.model)
        if version != evidence["vps_model_version"]:
            raise ValueError("Offline rescore requires the same frozen model")
        evidence.update(score_contexts(records, model))
        (args.output / "sample-evidence.json").write_text(
            json.dumps(evidence, indent=2) + "\n"
        )
    evidence = (
        json.loads((args.output / "sample-evidence.json").read_text())
        if args.report_only or args.rescore_only
        else run(args.output, args.model, args.max_lines, args.max_bytes)
    )
    args.report.write_text(render(evidence))
