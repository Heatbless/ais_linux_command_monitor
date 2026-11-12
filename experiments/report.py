"""Render the saved experiment evidence without rerunning or tuning models."""

import json
from pathlib import Path


def percent(value):
    return "undefined" if value is None else f"{100 * value:.1f}%"


def render(result):
    lines = [
        "# AIS feasibility results",
        "",
        "Historical Schonlau experiment. The active workflow now uses personal histories; see [current results](history-results.md).",
        "",
        "Negative selection is feasible for a command-name demo after replacing the sparse five-command detector. "
        "The selected development candidate is uniform three-command detectors with any two matching positions. "
        "False alarms remain substantial; this is not evidence of deployment readiness.",
        "",
        "## Protocol",
        "",
        "- Development users only: User1, User10, User25, User50. No reserved command streams were read.",
        "- Per user: commands 1–4,000 train; 4,001–4,500 calibrate thresholds; "
        "4,501–5,000 provide a later normal-only check; 5,001–15,000 are labeled development evaluation.",
        "- Threshold: higher-method empirical 99th percentile on calibration scores; alert strictly above it. "
        "The later normal-only check is reported, not used to adjust thresholds.",
        "- Seven AIS configurations, two seeds (42, 123), four users, and two window lengths, "
        "plus two deterministic baselines: 128 runs. Configurations were compared as a development search; "
        "these are not confirmatory final-test results.",
        "- Each seed has 400 labeled blocks: 22 masquerade and 378 normal. "
        "All positive blocks belong to User10 (13) and User25 (9); User1 and User50 contribute only negative blocks.",
        "- 100-command evaluation scores each labeled block once. "
        "10-command evaluation marks a block if any of its 91 internal windows alerts; "
        "it does not assign labels to individual commands/windows or establish detection delay.",
        "- No Python or tamper rules participated in these experiments. Personal histories were not used.",
        "",
        "## Comparison",
        "",
        "Seed 42 is shown below as the pre-existing default, not selected as the best seed. "
        "FPR is false-positive blocks divided by normal blocks; precision is positive blocks divided by all flagged blocks.",
        "",
        "| Configuration | Window | TP / 22 | FP / 378 | Recall | Precision | Block FPR |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for summary in result["summary"]:
        metrics = summary["per_seed"]["42"]
        lines.append(
            f"| {summary['configuration']} | {summary['window']} | {metrics['tp']} | "
            f"{metrics['fp']} | {percent(metrics['recall'])} | {percent(metrics['precision'])} | "
            f"{percent(metrics['false_positive_rate'])} |"
        )
    lines += [
        "",
        "## Selected demo design",
        "",
        "- Uniform categorical negative selection: length 3, any 2 corresponding positions; "
        "2,000 unique detectors, at most 200,000 proposals, seed 42. Fit vocabulary only on training; unknown ID is 0.",
        "- Reject each candidate if it matches any training triple. "
        "The runner asserts no accepted detector matches training data; tests compare signature indexing with brute force.",
        "- Score the fraction of triples matched by at least one detector. A 10-command window contains 8 triples; "
        "a 100-command window contains 98. Fit separate thresholds for the two lengths.",
        "- Use 10-command windows with stride 1 for live monitoring after readiness. "
        "Keep 100-command windows for benchmark reporting; first 10 live executions are warm-up.",
        "- Retain seed 123 as a sensitivity check, not an alternative chosen after observing results.",
        "",
        "### Seed sensitivity",
        "",
    ]
    for summary in result["summary"]:
        if summary["configuration"] != "uniform_n3_r2":
            continue
        for seed, metrics in summary["per_seed"].items():
            lines.append(
                f"- Window {summary['window']}, seed {seed}: TP {metrics['tp']}/22, "
                f"FP {metrics['fp']}/378, recall {percent(metrics['recall'])}, "
                f"precision {percent(metrics['precision'])}, block FPR {percent(metrics['false_positive_rate'])}."
            )
    lines += [
        "",
        "### Later normal-only check",
        "",
        "| User | Window | Threshold | Normal windows | Flagged normal windows |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in result["rows"]:
        if row["configuration"] == "uniform_n3_r2" and row["seed"] == 42:
            check = row["normal_validation"]
            lines.append(
                f"| User{row['user']} | {row['window']} | {row['threshold']:.6f} | "
                f"{check['windows']} | {percent(check['alarm_fraction'])} |"
            )
    selected = [
        r
        for r in result["rows"]
        if r["configuration"] == "uniform_n3_r2" and r["seed"] == 42
    ]
    lines += [
        "",
        "## Interpretation and limits",
        "",
        "- The original five-command/four-position detector scores every inspected evaluation window zero "
        "at both seeds and both lengths. Detector acceptance alone was misleading.",
        "- Shorter categorical detectors improve relevant recognition coverage. "
        "Numerical variable-radius detectors also avoid constant scores, but are more complex and "
        "produce more flagged normal blocks in the short-window experiment. They have no certified V-detector coverage guarantee.",
        "- The selected method improves over unseen-fivegram and unseen-bigram baselines in this small development comparison, "
        "but no significance test or general superiority claim is justified.",
        "- The 99th-percentile calibration threshold is not a future 1% false-alarm guarantee. "
        "In particular, User25 has substantial drift in the later normal-only 100-command check. "
        "Overlapping windows are correlated and a block may trigger on any of many live windows.",
        "- Only two development accounts contain positive examples. High recall here cannot establish coverage "
        "of real attackers, local privilege escalation, malicious Python, or commands with unseen arguments.",
        "- Constant or fully saturated calibration scores must prevent operational model activation "
        "and appear as a model-quality warning. Do not silently adjust thresholds to make a demo alert.",
        "- Final evaluation on the other 46 users is still pending. Freeze this representation, seed, proposal count, "
        "matching rule, split and threshold policy before that evaluation; do not tune against its results.",
        "- For the live scripted demo, measure false alerts per session and command-level delay only "
        "using separately annotated scenarios. Keep explicit Python/tamper warnings distinct in their stated reason.",
        "- Personal history segments are only baseline candidates, have no attack labels, and "
        "must retain source/segment separation. No personal data appears in this report.",
        "",
        "## Runtime and reproduction",
        "",
        f"Environment: Python {result['python']}, NumPy {result['numpy']}. "
        f"Selected fits took {min(r['fit_seconds'] for r in selected):.3f}–"
        f"{max(r['fit_seconds'] for r in selected):.3f} seconds. "
        "Timing is a local microbenchmark, not a live collector or network latency measurement.",
        "",
        "```sh",
        "uv sync --locked",
        "uv run python -m experiments.feasibility",
        "uv run python -m experiments.report",
        "uv run python -m pytest -q",
        "uv run ruff check experiments tests",
        "```",
        "",
        "The runner expects `schonlau/masquerade_summary.labels` from "
        "[the dataset owner](https://schonlau.net/intrusion.html). "
        "Machine-readable results include input digests, thresholds, detector counts, distributions, "
        "confusion counts, environment versions and timings.",
        "",
        "See [primary-source design notes](negative-selection-design.md) for the algorithm background "
        "and [machine-readable evidence](feasibility-results.json) for every run.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    source = Path("docs/research/feasibility-results.json")
    source.with_suffix(".md").write_text(render(json.loads(source.read_text())))
