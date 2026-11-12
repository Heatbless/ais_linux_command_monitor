"""Personal-history negative-selection experiment. Never executes input commands.

Run the importer first. All model artifacts remain in Git-ignored private-data.
Synthetic examples are demonstration assumptions, never real attack labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from itertools import combinations, product
from pathlib import Path

import numpy as np

WINDOW = 10
POSITIONS = tuple(combinations(range(3), 2))


def triples(segment):
    return [tuple(segment[i : i + 3]) for i in range(len(segment) - 2)]


def signatures(triple):
    return {(positions, tuple(triple[i] for i in positions)) for positions in POSITIONS}


def read_segments(path):
    segments, current, previous_line = [], None, 0
    for line in path.read_text().splitlines():
        row = json.loads(line)
        if row["source_line"] < previous_line:
            raise ValueError("History must preserve source order")
        if current is None or row["segment"] != current:
            if current is not None and row["segment"] <= current:
                raise ValueError("Segment identifiers must increase")
            segments.append([])
            current = row["segment"]
        command = row["command"]
        if not command or any(c.isspace() for c in command) or "/" in command:
            raise ValueError("Expected sanitized executable basenames")
        segments[-1].append(command)
        previous_line = row["source_line"]
    if len(segments) < 3:
        raise ValueError("Need at least three ordered segments for distinct partitions")
    return segments


def split_segments(segments):
    cumulative = np.cumsum([len(s) for s in segments])
    n = len(segments)
    train_end = min(
        range(1, n - 1), key=lambda i: abs(cumulative[i - 1] - cumulative[-1] * 0.6)
    )
    cal_end = min(
        range(train_end + 1, n),
        key=lambda i: abs(cumulative[i - 1] - cumulative[-1] * 0.8),
    )
    return segments[:train_end], segments[train_end:cal_end], segments[cal_end:]


def windows(segments, stride=1):
    return [
        segment[i : i + WINDOW]
        for segment in segments
        for i in range(0, len(segment) - WINDOW + 1, stride)
    ]


def describe(segments):
    return {
        "commands": sum(map(len, segments)),
        "segments": len(segments),
        "overlapping_windows": len(windows(segments)),
        "nonoverlapping_windows": len(windows(segments, WINDOW)),
    }


class HistoryNSA:
    """Wildcard negative selection with complete finite pair-pattern coverage.

    A detector fixes two corresponding positions and wildcards the third.
    Censor every pattern occurring in a training triple. Require two detector
    matches per triple and consecutive novel triples for the conservative rule.
    Computationally this is positional-pair novelty, not an advantage claim.
    """

    def __init__(self, mode="complete_sustained", seed=42):
        self.mode, self.seed = mode, seed

    def encode(self, segment):
        return [self.vocabulary.get(c, 0) for c in segment]

    def fit(self, segments):
        self.vocabulary = {
            c: i + 1 for i, c in enumerate(sorted({c for s in segments for c in s}))
        }
        self.normal_triples = {g for s in segments for g in triples(self.encode(s))}
        if not self.normal_triples:
            raise ValueError("Insufficient training triples")
        self.normal_pairs = {p for g in self.normal_triples for p in signatures(g)}
        self.bigrams = {
            tuple(s[i : i + 2]) for s in segments for i in range(len(s) - 1)
        }
        if self.mode == "random_previous":
            rng = np.random.default_rng(self.seed)
            accepted = set()
            for _ in range(200000):
                candidate = tuple(
                    int(x) for x in rng.integers(0, len(self.vocabulary) + 1, 3)
                )
                if not signatures(candidate) & self.normal_pairs:
                    accepted.add(candidate)
                if len(accepted) == 2000:
                    break
            self.detectors = {p for g in accepted for p in signatures(g)}
        else:
            self.detectors = {
                (pos, pair)
                for pos in POSITIONS
                for pair in product(range(len(self.vocabulary) + 1), repeat=2)
            } - self.normal_pairs
        assert not self.detectors & self.normal_pairs
        self.threshold = None
        return self

    def score(self, window):
        if len(window) != WINDOW:
            raise ValueError("A score requires exactly ten commands")
        if self.mode == "unknown_baseline":
            return sum(c not in self.vocabulary for c in window) / WINDOW
        if self.mode == "bigram_baseline":
            return sum(
                tuple(window[i : i + 2]) not in self.bigrams for i in range(WINDOW - 1)
            ) / (WINDOW - 1)
        counts = [
            len(signatures(g) & self.detectors) for g in triples(self.encode(window))
        ]
        if self.mode == "complete_sustained":
            evidence = [count >= 2 for count in counts]
            sustained = [
                evidence[i]
                and (
                    (i > 0 and evidence[i - 1])
                    or (i + 1 < len(evidence) and evidence[i + 1])
                )
                for i in range(len(evidence))
            ]
            return sum(sustained) / len(sustained)
        return sum(count > 0 for count in counts) / len(counts)

    def calibrate(self, segments):
        values = [self.score(w) for w in windows(segments)]
        if not values:
            raise ValueError("No complete real calibration windows")
        # Identical policy for every comparison. No test or synthetic scores used.
        self.threshold = float(np.quantile(values, 0.99, method="higher"))
        return values

    def artifact(self):
        return {
            "schema_version": 1,
            "mode": self.mode,
            "seed": self.seed,
            "window": WINDOW,
            "threshold": self.threshold,
            "vocabulary": self.vocabulary,
            "detectors": [
                [list(pos), list(pair)] for pos, pair in sorted(self.detectors)
            ],
            "normal_pair_count": len(self.normal_pairs),
            "quality": "experimental; sparse personal history; not deployment-validated",
        }


class ContinuousHistoryNSA:
    """Variable-radius negative selection; no statistical coverage guarantee.

    Keep three continuous features to distinguish a burst of diverse unfamiliar
    commands from repetition of a newly installed normal program. All feature
    parameters and self vectors use training only; gaps are never flattened.
    """

    def __init__(self, mode="continuous_nsa", seed=42):
        self.mode, self.seed = mode, seed

    def features(self, window):
        unknown = sum(c not in self.vocabulary for c in window) / WINDOW
        diversity = len(set(window)) / WINDOW
        rarity = sum(
            -math.log((self.counts[c] + 1) / self.denominator) for c in window
        ) / (WINDOW * math.log(self.denominator))
        return np.array([unknown, diversity, rarity])

    def fit(self, segments):
        self.counts = Counter(c for s in segments for c in s)
        self.vocabulary = {c: i + 1 for i, c in enumerate(sorted(self.counts))}
        self.denominator = sum(self.counts.values()) + len(self.vocabulary) + 1
        normal = np.unique([self.features(w) for w in windows(segments)], axis=0)
        if not len(normal):
            raise ValueError("No complete training windows for numerical NSA")
        rng = np.random.default_rng(self.seed)
        centers = rng.uniform(0, 1, (1024, 3))
        distance = np.linalg.norm(centers[:, None] - normal[None, :], axis=2)
        radius = distance.min(axis=1) - 0.02
        eligible = radius > 0
        self.centers = centers[eligible][:256]
        self.radii = radius[eligible][:256]
        self.detectors = self.centers
        self.normal_pairs = set()
        self.threshold = None
        assert np.all(
            np.linalg.norm(self.centers[:, None] - normal[None, :], axis=2)
            > self.radii[:, None]
        )
        return self

    def score(self, window):
        if len(window) != WINDOW:
            raise ValueError("A score requires exactly ten commands")
        distances = np.linalg.norm(self.centers - self.features(window), axis=1)
        return float(np.maximum(0, 1 - distances / self.radii).max())

    def calibrate(self, segments):
        return HistoryNSA.calibrate(self, segments)

    def artifact(self):
        return {
            "schema_version": 1,
            "mode": self.mode,
            "seed": self.seed,
            "window": WINDOW,
            "threshold": self.threshold,
            "counts": dict(self.counts),
            "vocabulary": self.vocabulary,
            "denominator": self.denominator,
            "centers": self.centers.tolist(),
            "radii": self.radii.tolist(),
            "self_margin": 0.02,
            "features": ["unknown_fraction", "diversity", "mean_surprisal"],
            "quality": "experimental; sparse personal history; not deployment-validated",
        }


FAMILIES = {
    "identity_query": "whoami id groups who w last getent",
    "system_query": "uname hostname lsb_release uptime date",
    "observation": "ps top htop btop ss ip netstat lsof journalctl dmesg free df du lsblk",
    "file_read": "ls cat find stat head tail grep rg sed awk wc readlink realpath strings",
    "file_write": "cp mv rm mkdir touch install tee",
    "source_control": "git gh",
    "development": "npm npx pnpm yarn bun node deno uv uvx pip pip2 pip3 python python2 python3 poetry pipenv pytest make gcc g++ cc cargo rustc rustup go java javac code codex claude",
    "packages": "apt apt-get aptitude dpkg yum dnf pacman apk",
    "service": "systemctl service supervisorctl supervisord pm2",
    "archive": "tar gzip gunzip zip unzip",
    "download": "curl wget",
    "remote": "ssh scp sftp rsync",
    "privilege_permissions": "sudo su chmod chown chgrp",
    "container": "docker docker-compose podman kubectl helm",
}
FAMILY_LOOKUP = {
    command: family
    for family, commands in FAMILIES.items()
    for command in commands.split()
}


def command_family(command):
    if re.fullmatch(r"(python|pip)[23](\.\d+)*", command):
        return "development"
    # Unmapped names remain distinct. Do not silently classify every new command
    # as the same supposedly normal "other" family.
    return FAMILY_LOOKUP.get(command, f"program:{command}")


class FamilyHistoryNSA(HistoryNSA):
    def __init__(self, mode="family_complete", seed=42):
        self.family_mode = mode
        super().__init__(
            "unknown_baseline" if mode == "family_unknown_baseline" else "complete_any",
            seed,
        )

    def fit(self, segments):
        return super().fit(
            [[command_family(c) for c in segment] for segment in segments]
        )

    def score(self, window):
        return super().score([command_family(c) for c in window])

    def artifact(self):
        return {
            **super().artifact(),
            "mode": self.family_mode,
            "representation": "command_family",
            "family_mapping": FAMILY_LOOKUP,
        }


# Fixed generic normal workflows, declared before evaluating real holdout scores.
# These are synthetic training assumptions, not commands extracted from private data.
SYNTHETIC_NORMAL_TRAIN = {
    "local": [
        [
            "git",
            "git",
            "python3",
            "git",
            "python3",
            "git",
            "git",
            "python3",
            "git",
            "git",
        ],
        ["npm", "npm", "git", "npm", "node", "npm", "git", "npm", "node", "git"],
        ["ls", "find", "cat", "git", "git", "python3", "ls", "cat", "git", "ls"],
    ],
    "vps": [
        [
            "apt-get",
            "dpkg",
            "apt-get",
            "systemctl",
            "journalctl",
            "systemctl",
            "dpkg",
            "apt-get",
            "journalctl",
            "systemctl",
        ],
        [
            "systemctl",
            "journalctl",
            "ps",
            "ss",
            "df",
            "free",
            "systemctl",
            "journalctl",
            "ps",
            "ss",
        ],
        [
            "git",
            "git",
            "python3",
            "systemctl",
            "journalctl",
            "git",
            "python3",
            "systemctl",
            "journalctl",
            "systemctl",
        ],
    ],
}
SYNTHETIC_EVAL = [
    (
        "benign_file_inspection",
        False,
        ["ls", "find", "stat", "cat", "ls", "du", "df", "find", "stat", "ls"],
    ),
    (
        "benign_python_work",
        False,
        [
            "python3",
            "git",
            "python3",
            "git",
            "git",
            "python3",
            "git",
            "python3",
            "git",
            "git",
        ],
    ),
    (
        "unusual_inventory_burst",
        True,
        ["whoami", "id", "uname", "hostname", "ps", "ss", "ip", "groups", "who", "w"],
    ),
    (
        "unusual_packaging_transfer",
        True,
        ["find", "find", "tar", "gzip", "sha256sum", "scp", "ssh", "tar", "scp", "ssh"],
    ),
    (
        "unusual_runtime_change",
        True,
        ["curl", "chmod", "sh", "curl", "chmod", "sh", "crontab", "sh", "curl", "sh"],
    ),
]


def rate(scores, threshold):
    return sum(s > threshold for s in scores) / len(scores) if scores else None


def run(source, output):
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = output / "models"
    private.mkdir(exist_ok=True, mode=0o700)
    modes = [
        "random_previous",
        "complete_any",
        "complete_sustained",
        "continuous_nsa",
        "family_complete",
        "family_unknown_baseline",
        "unknown_baseline",
        "bigram_baseline",
    ]
    report = {
        "schema_version": 1,
        "schonlau_used": False,
        "selection_policy": "exploratory comparison; continuous features added after categorical saturation; entire histories are development data, not a fresh final validation set",
        "synthetic_policy": "Run history-only first. If fewer than 30 nonoverlapping calibration or test windows, augment training with fixed generic normal workflows and evaluate separate synthetic scenarios. Never train on synthetic unusual scenarios or real test.",
        "profiles": [],
    }
    for profile in ("local", "vps"):
        path = source / f"{profile}.commands.jsonl"
        segments = read_segments(path)
        train, cal, test = split_segments(segments)
        insufficient = len(windows(cal, WINDOW)) < 30 or len(windows(test, WINDOW)) < 30
        entry = {
            "profile": profile,
            "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "split": {
                name: describe(part)
                for name, part in [
                    ("train", train),
                    ("calibration", cal),
                    ("test", test),
                ]
            },
            "real_attack_labels": False,
            "synthetic_fallback_reason": "insufficient separate real calibration/test windows"
            if insufficient
            else None,
            "runs": [],
        }
        if not windows(train) or not windows(cal):
            entry["status"] = "insufficient complete real training/calibration windows"
            report["profiles"].append(entry)
            continue
        # Stage order intentionally evaluates real-only models before augmentation.
        stages = [("history_only", train)]
        if insufficient:
            stages.append(
                (
                    "history_plus_synthetic_normal",
                    train + SYNTHETIC_NORMAL_TRAIN[profile],
                )
            )
        for stage, training in stages:
            for mode in modes:
                seeds = (
                    (42, 123)
                    if mode in {"random_previous", "continuous_nsa"}
                    else (42,)
                )
                for seed in seeds:
                    factory = (
                        ContinuousHistoryNSA
                        if mode == "continuous_nsa"
                        else FamilyHistoryNSA
                        if mode.startswith("family_")
                        else HistoryNSA
                    )
                    model = factory(mode, seed).fit(training)
                    calibration = model.calibrate(cal)
                    overlapping = [model.score(w) for w in windows(test)]
                    disjoint = [model.score(w) for w in windows(test, WINDOW)]
                    result = {
                        "stage": stage,
                        "mode": mode,
                        "seed": seed,
                        "threshold": model.threshold,
                        "detector_patterns": len(model.detectors),
                        "training_vocabulary": len(model.vocabulary),
                        "calibration_windows": len(calibration),
                        "calibration_unique_scores": len(set(calibration)),
                        "calibration_saturated": model.threshold >= 1,
                        "test_windows": len(overlapping),
                        "test_false_alerts": sum(
                            s > model.threshold for s in overlapping
                        ),
                        "test_false_alert_fraction": rate(overlapping, model.threshold),
                        "nonoverlapping_test_windows": len(disjoint),
                        "nonoverlapping_test_false_alert_fraction": rate(
                            disjoint, model.threshold
                        ),
                        "real_detection_recall": None,
                        "deployment_ready": False,
                    }
                    if insufficient:
                        examples = []
                        for name, unusual, commands in SYNTHETIC_EVAL:
                            if tuple(commands) in {tuple(w) for w in windows(training)}:
                                raise ValueError(
                                    "Synthetic evaluation duplicates a training window"
                                )
                            score = model.score(commands)
                            examples.append(
                                {
                                    "scenario": name,
                                    "synthetic_unusual": unusual,
                                    "score": score,
                                    "alert": score > model.threshold,
                                }
                            )
                        # A suspicious use with exactly the same command names is
                        # intentionally undetectable: an important negative control.
                        same_names = next(iter(windows(train)))
                        examples.append(
                            {
                                "scenario": "same_names_different_intent",
                                "synthetic_unusual": True,
                                "score": model.score(same_names),
                                "alert": model.score(same_names) > model.threshold,
                            }
                        )
                        result["synthetic_examples"] = examples
                        result["synthetic_tp"] = sum(
                            e["alert"] and e["synthetic_unusual"] for e in examples
                        )
                        result["synthetic_fn"] = sum(
                            not e["alert"] and e["synthetic_unusual"] for e in examples
                        )
                        result["synthetic_fp"] = sum(
                            e["alert"] and not e["synthetic_unusual"] for e in examples
                        )
                        result["synthetic_tn"] = sum(
                            not e["alert"] and not e["synthetic_unusual"]
                            for e in examples
                        )
                    entry["runs"].append(result)
                    if mode in {
                        "complete_sustained",
                        "continuous_nsa",
                        "complete_any",
                        "family_complete",
                    }:
                        target = private / f"{profile}-{stage}-{mode}-{seed}.json"
                        artifact = {
                            **model.artifact(),
                            "profile": profile,
                            "stage": stage,
                            "input_sha256": entry["input_sha256"],
                            "synthetic_normal_training": stage != "history_only",
                            "calibration_source": "separate real history partition only",
                            "calibration_saturated": model.threshold >= 1,
                            "operational_activation_allowed": False,
                        }
                        artifact["model_version"] = hashlib.sha256(
                            json.dumps(artifact, sort_keys=True).encode()
                        ).hexdigest()
                        target.write_text(json.dumps(artifact, indent=2) + "\n")
                        target.chmod(0o600)
            print(
                f"{profile}: {stage} finished (command contents kept private)",
                flush=True,
            )
        report["profiles"].append(entry)
    report["demo_candidates"] = {}
    for profile in report["profiles"]:
        candidate = demo_candidate(profile)
        report["demo_candidates"][profile["profile"]] = (
            {
                "artifact": f"models/{profile['profile']}-{candidate['stage']}-{candidate['mode']}-{candidate['seed']}.json",
                "experimental_only": True,
                "deployment_ready": False,
            }
            if candidate
            else None
        )
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    target.chmod(0o600)
    return report


def pct(value):
    return "unavailable" if value is None else f"{value:.1%}"


def demo_candidate(profile):
    # Exploratory demo screening only, never an operational activation decision.
    for row in profile["runs"]:
        if (
            row["stage"] == "history_plus_synthetic_normal"
            and row["mode"] == "complete_any"
            and row["threshold"] < 1
            and row["test_false_alerts"] == 0
            and row.get("synthetic_tp", 0) >= 3
            and row.get("synthetic_fp", 1) == 0
        ):
            return row
    return None


def render(report):
    lines = [
        "# Personal-history AIS experiment",
        "",
        "Active experiments use separate local and VPS histories. Schonlau is not used. "
        "The inputs are operator-approved normal candidates, not labeled attacks. "
        "All model artifacts and detailed evidence remain in ignored private-data. "
        "Because designs are being improved iteratively, both histories are development evidence; no untouched final validation is claimed.",
        "",
        "## Outcome",
        "",
    ]
    for profile in report["profiles"]:
        candidate = demo_candidate(profile)
        if candidate:
            lines.append(
                f"- **{profile['profile']}**: history plus synthetic normal workflows provides a usable scripted-demo candidate (complete wildcard-pair NSA). "
                f"It flagged {candidate['test_false_alerts']}/{candidate['test_windows']} chronological real-development windows and "
                f"{candidate['synthetic_fp']}/2 synthetic benign scenarios; it detected {candidate['synthetic_tp']}/4 synthetic unusual scenarios. "
                "This is exploratory screening on very little data, not real attack recall or deployment validation."
            )
        else:
            lines.append(
                f"- **{profile['profile']}**: no candidate passes the exploratory demo screen. "
                "The screen requires an unsaturated complete-pair model, no real-development false alerts, "
                "at least 3/4 synthetic unusual scenarios flagged, and neither synthetic benign scenario flagged. "
                "Do not activate a silent or oversensitive model just to claim improvement."
            )
    lines += [
        "",
        "## Data and separation",
        "",
        "| Profile | Training commands | Calibration commands | Test commands | Calibration nonoverlapping windows | Test nonoverlapping windows |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for profile in report["profiles"]:
        s = profile["split"]
        lines.append(
            f"| {profile['profile']} | {s['train']['commands']} | {s['calibration']['commands']} | {s['test']['commands']} | {s['calibration']['nonoverlapping_windows']} | {s['test']['nonoverlapping_windows']} |"
        )
    lines += [
        "",
        "Splits approximate 60/20/20 by command count at existing gap boundaries. "
        "Windows never cross gaps or partitions. Simple non-executing shell built-ins are omitted without inventing an execution gap; "
        "opaque built-ins, unknown executables and ambiguous syntax remain gaps. These are inferred history segments, not known login sessions.",
        "",
        "## Real history results",
        "",
        "Each threshold uses the 99th percentile of real calibration scores only, strictly greater comparison. "
        "No real test observations or synthetic examples choose thresholds; model-family exploration and demo screening do use development outcomes. "
        "Rates use overlapping ten-command windows; disjoint counts are also disclosed. "
        "Small samples and correlated windows prevent a reliable operational false-alarm estimate.",
        "",
        "| Profile | Training | Model | Seed | Threshold | False alerts / real test windows | Window false-alert fraction |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for p in report["profiles"]:
        for row in p["runs"]:
            lines.append(
                f"| {p['profile']} | {row['stage']} | {row['mode']} | {row['seed']} | {row['threshold']:.4f} | {row['test_false_alerts']}/{row['test_windows']} | {pct(row['test_false_alert_fraction'])} |"
            )
    lines += [
        "",
        "## Synthetic fallback — separate evidence",
        "",
        "Both profiles fail the predeclared data-adequacy check of 30 nonoverlapping calibration and 30 test windows. "
        "After the history-only stage, three generic normal workflow templates per profile augment training. "
        "They do not contain real held-out history or the evaluation scenario templates. Calibration remains real-only.",
        "",
        "Synthetic evaluation includes benign file inspection, benign Python work, unusual inventory, packaging/transfer, "
        "runtime changes, and an intentionally undetectable same-command-names/different-intent control. "
        "These are scripted assumptions about behavior, not evidence of malicious intent. "
        "Their counts are separate from real-history false alerts; no real attack recall is claimed.",
        "",
        "| Profile | Training | Model | Seed | Synthetic TP | FN | FP | TN |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for p in report["profiles"]:
        for row in p["runs"]:
            if row["mode"] in {
                "complete_sustained",
                "complete_any",
                "continuous_nsa",
                "family_complete",
            }:
                lines.append(
                    f"| {p['profile']} | {row['stage']} | {row['mode']} | {row['seed']} | {row.get('synthetic_tp', 'n/a')} | {row.get('synthetic_fn', 'n/a')} | {row.get('synthetic_fp', 'n/a')} | {row.get('synthetic_tn', 'n/a')} |"
                )
    lines += [
        "",
        "## Detector changes and limitations",
        "",
        "- Compare the previous random triple detector to complete wildcard-pair detectors. "
        "Enumerate every pair-pattern over the training vocabulary plus an unknown token, then reject any pattern matching a training triple. "
        "This removes random coverage holes in that finite representation; it does not guarantee attack coverage.",
        "- The conservative candidate requires at least two nonself positional pairs in a triple and at least two consecutive such triples. "
        "Its first results exposed calibration saturation locally and nuisance warnings on the VPS; it is retained as comparison evidence. "
        "It is mathematically a positional-pair novelty detector with negative-selection training.",
        "- Add variable-radius negative selection over unknown-command fraction, command diversity, and smoothed mean command surprisal. "
        "Generate 256 detectors (seeds 42 and 123), with radius equal to the nearest normal training-vector distance minus 0.02. "
        "Normal vectors and frequencies use training only, keeping gap boundaries. This is a simplified numerical NSA, not certified V-detector coverage.",
        "- A final exploratory command-family representation groups generic development, package, file and service tools using a fixed explicit mapping. "
        "This can recognize normal tool changes without learning every executable name, at the cost of losing distinctions within a family. "
        "Unmapped programs remain distinct. Compare to a family-unknown baseline; semantic grouping is prior domain knowledge, not a learned AIS ability.",
        "- Compare unknown-command and unseen-bigram baselines. All models use the same partitions and threshold policy.",
        "- Reduced alarms can also mean missed unusual activity. Saturated calibration thresholds are explicitly flagged in private results; "
        "a model with threshold 1 cannot warn. Do not call a silent model successful.",
        "- Never combine synthetic and real metrics into an accuracy number. Repeating synthetic workflows is not additional independent personal evidence.",
        "- Legitimate new administration can still be flagged. Python and tamper rules are excluded from AIS metrics and remain independent requirements.",
        "- No artifact is marked deployment-ready. Collect separate representative normal sessions and labeled demonstration scenarios before live validation.",
        "",
        "## Reproduce",
        "",
        "```sh",
        "uv sync --locked",
        "uv run python -m experiments.history_import",
        "uv run python -m experiments.history_feasibility",
        "uv run python -m pytest -q",
        "```",
        "",
        "Private models and evidence: `private-data/history-experiment/`. "
        "The old Schonlau experiment is historical evidence only, not the active workflow. "
        "The complete comparison includes failures as well as promising results; the demo screen is exploratory and not a preregistered validation protocol.",
        "",
        "Subsequent [Cowrie evaluation](external-results.md) and [AIT workload checks](ait-coverage.md) expose transfer and coverage limits. The initial scripted-demo screen does not establish reliability on other hosts or real attacks.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("private-data/histories-v2"))
    parser.add_argument(
        "--output", type=Path, default=Path("private-data/history-experiment")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("docs/research/history-results.md")
    )
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    result = (
        json.loads((args.output / "results.json").read_text())
        if args.report_only
        else run(args.input, args.output)
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render(result))
    print(f"Saved aggregate report: {args.report}")
