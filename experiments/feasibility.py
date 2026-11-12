"""Negative-selection feasibility on explicitly designated development users.

Run: .venv/bin/python -m experiments.feasibility
Never imports raw personal histories or reads reserved users' command streams.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import time
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

import numpy as np

DEVELOPMENT_USERS = (1, 10, 25, 50)
SEEDS = (42, 123)


def read_user(directory: Path, user: int) -> list[str]:
    if user not in DEVELOPMENT_USERS:
        raise ValueError("Feasibility must not read reserved users")
    commands = (directory / f"User{user}").read_text().splitlines()
    if len(commands) != 15000 or any(not c or c != c.strip() for c in commands):
        raise ValueError(f"Invalid command records for User{user}")
    return commands


def read_labels(path: Path) -> np.ndarray:
    labels = np.loadtxt(path, dtype=int)
    if labels.shape != (100, 50) or not np.isin(labels, [0, 1]).all():
        raise ValueError("Expected binary 100-block by 50-user label matrix")
    return labels


def grams(commands, size):
    return [tuple(commands[i : i + size]) for i in range(len(commands) - size + 1)]


def signatures(sequence, match):
    # Include positional indices; values at different positions must not match.
    for positions in combinations(range(len(sequence)), match):
        yield positions, tuple(sequence[i] for i in positions)


def signature_index(sequences, match):
    return {signature for s in sequences for signature in signatures(s, match)}


@dataclass
class CategoricalNSA:
    size: int
    match: int
    strategy: str = "uniform"
    target: int = 2000
    limit: int = 200000

    def fit(self, commands, seed):
        rng = np.random.default_rng(seed)
        self.vocabulary = {c: i + 1 for i, c in enumerate(sorted(set(commands)))}
        normal = sorted(set(grams(self.encode(commands), self.size)))
        normal_index = signature_index(normal, self.match)
        accepted = set()
        attempts = 0
        while len(accepted) < self.target and attempts < self.limit:
            attempts += 1
            if self.strategy == "uniform":
                candidate = tuple(
                    int(x) for x in rng.integers(0, len(self.vocabulary) + 1, self.size)
                )
            else:
                candidate = list(normal[int(rng.integers(len(normal)))])
                count = int(rng.integers(1, self.size + 1))
                for position in rng.choice(self.size, count, replace=False):
                    candidate[position] = int(rng.integers(len(self.vocabulary) + 1))
                candidate = tuple(candidate)
            if candidate in accepted:
                continue
            if not any(s in normal_index for s in signatures(candidate, self.match)):
                accepted.add(candidate)
        self.detectors = sorted(accepted)
        self.index = signature_index(self.detectors, self.match)
        self.info = {
            "detectors": len(accepted),
            "attempts": attempts,
            "training_sequences": len(normal),
            "vocabulary": len(self.vocabulary),
        }
        # Prove the core negative-selection invariant for the actual fitted model.
        assert not any(s in self.index for s in normal_index)
        return self

    def encode(self, commands):
        return [self.vocabulary.get(c, 0) for c in commands]

    def scores(self, commands, window, stride):
        sequences = grams(self.encode(commands), self.size)
        hits = np.array(
            [
                any(s in self.index for s in signatures(g, self.match))
                for g in sequences
            ],
            dtype=int,
        )
        return window_means(hits, len(commands), window, stride, self.size)


def window_means(hits, count, window, stride, size):
    if window < size or count < window:
        return np.array([], dtype=float)
    starts = np.arange(0, count - window + 1, stride)
    cumulative = np.r_[0, np.cumsum(hits)]
    return (cumulative[starts + window - size + 1] - cumulative[starts]) / (
        window - size + 1
    )


@dataclass
class NoveltyBaseline:
    size: int

    def fit(self, commands, seed):
        self.normal = set(grams(commands, self.size))
        self.info = {"training_sequences": len(self.normal)}
        return self

    def scores(self, commands, window, stride):
        hits = np.array(
            [g not in self.normal for g in grams(commands, self.size)], dtype=int
        )
        return window_means(hits, len(commands), window, stride, self.size)


@dataclass
class NumericalNSA:
    """Experimental variable-radius NSA; no V-detector coverage guarantee.

    Four bounded features: unknown fraction, mean smoothed command surprisal,
    unique fraction, and unseen-bigram fraction. Feature parameters use fit data only.
    """

    margin: float = 0.02
    target: int = 512

    def features(self, commands, window, stride):
        vectors = []
        for start in range(0, len(commands) - window + 1, stride):
            block = commands[start : start + window]
            unknown = sum(c not in self.counts for c in block) / window
            surprisal = sum(
                -math.log((self.counts[c] + 1) / self.denominator) for c in block
            ) / (window * math.log(self.denominator))
            distinct = len(set(block)) / window
            transitions = sum(g not in self.bigrams for g in grams(block, 2)) / (
                window - 1
            )
            vectors.append((unknown, surprisal, distinct, transitions))
        return np.array(vectors, dtype=float).reshape(-1, 4)

    def fit(self, commands, seed, window):
        self.counts = Counter(commands)
        self.denominator = len(commands) + len(self.counts) + 1
        self.bigrams = set(grams(commands, 2))
        normal = np.unique(self.features(commands, window, 10), axis=0)
        rng = np.random.default_rng(seed)
        centers = rng.uniform(0, 1, (self.target * 4, 4))
        distances = np.sqrt(((centers[:, None] - normal[None, :]) ** 2).sum(axis=2))
        radii = distances.min(axis=1) - self.margin
        eligible = radii > 0
        self.centers = centers[eligible][: self.target]
        self.radii = radii[eligible][: self.target]
        if not len(self.radii):
            raise ValueError("No valid numerical detectors")
        self.info = {
            "detectors": len(self.radii),
            "training_vectors": len(normal),
            "self_margin": self.margin,
            "features": 4,
        }
        assert np.all(self.vector_scores(normal) == 0)
        return self

    def vector_scores(self, vectors):
        scores = []
        for offset in range(0, len(vectors), 256):
            batch = vectors[offset : offset + 256]
            distances = np.sqrt(
                ((batch[:, None] - self.centers[None, :]) ** 2).sum(axis=2)
            )
            scores.extend(np.maximum(0, 1 - distances / self.radii).max(axis=1))
        return np.array(scores)

    def scores(self, commands, window, stride):
        return self.vector_scores(self.features(commands, window, stride))


def threshold(scores):
    if len(scores) == 0:
        raise ValueError("Insufficient calibration data")
    return float(np.quantile(scores, 0.99, method="higher"))


def distribution(scores, cut):
    return {
        "windows": len(scores),
        "unique_scores": len(np.unique(scores)),
        "nonzero_fraction": float(np.mean(scores > 0)),
        "alarm_fraction": float(np.mean(scores > cut)),
        "minimum": float(scores.min()),
        "maximum": float(scores.max()),
    }


def metrics(scores, labels, cut):
    predicted = scores > cut
    truth = np.array(labels, dtype=bool)
    tp, fp = int(sum(predicted & truth)), int(sum(predicted & ~truth))
    fn, tn = int(sum(~predicted & truth)), int(sum(~predicted & ~truth))
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def aggregate(rows):
    totals = {
        key: sum(row["benchmark"][key] for row in rows)
        for key in ("tp", "fp", "fn", "tn")
    }
    tp, fp, fn, tn = (totals[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        **totals,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def run(data_dir: Path, label_path: Path, output: Path):
    labels = read_labels(label_path)
    configurations = {
        "original_n5_r4": lambda: CategoricalNSA(5, 4),
        "uniform_n3_r2": lambda: CategoricalNSA(3, 2),
        "uniform_n2_r2": lambda: CategoricalNSA(2, 2),
        "mutated_n3_r2": lambda: CategoricalNSA(3, 2, "mutated"),
        "mutated_n5_r3": lambda: CategoricalNSA(5, 3, "mutated"),
        "numerical_margin002": lambda: NumericalNSA(0.02),
        "numerical_margin005": lambda: NumericalNSA(0.05),
        "baseline_unseen5": lambda: NoveltyBaseline(5),
        "baseline_unseen2": lambda: NoveltyBaseline(2),
    }
    rows, digests = [], {}
    for user in DEVELOPMENT_USERS:
        commands = read_user(data_dir, user)
        digests[f"User{user}"] = hashlib.sha256(
            (data_dir / f"User{user}").read_bytes()
        ).hexdigest()
        train, calibrate, validate, test = (
            commands[:4000],
            commands[4000:4500],
            commands[4500:5000],
            commands[5000:],
        )
        for name, factory in configurations.items():
            seeds = (42,) if name.startswith("baseline") else SEEDS
            for seed in seeds:
                for window in (100, 10):
                    started = time.perf_counter()
                    model = factory()
                    if isinstance(model, NumericalNSA):
                        model.fit(train, seed, window)
                    else:
                        model.fit(train, seed)
                    fit_seconds = time.perf_counter() - started
                    cal = model.scores(calibrate, window, 1 if window == 10 else 10)
                    cut = threshold(cal)
                    normal_check = model.scores(
                        validate, window, 1 if window == 10 else 10
                    )
                    score_started = time.perf_counter()
                    # Score each labeled block independently; live windows never
                    # cross a block boundary and have no per-command labels.
                    blocks = [
                        model.scores(
                            test[i : i + 100], window, 1 if window == 10 else 100
                        )
                        for i in range(0, len(test), 100)
                    ]
                    block_scores = np.array([scores.max() for scores in blocks])
                    elapsed = time.perf_counter() - score_started
                    all_scores = np.concatenate(blocks)
                    row = {
                        "user": user,
                        "configuration": name,
                        "seed": seed,
                        "window": window,
                        "threshold": cut,
                        "model": model.info,
                        "calibration": distribution(cal, cut),
                        "normal_validation": distribution(normal_check, cut),
                        "development_test": distribution(all_scores, cut),
                        "benchmark": metrics(block_scores, labels[:, user - 1], cut),
                        "fit_seconds": fit_seconds,
                        "scoring_microseconds_per_window": elapsed
                        / len(all_scores)
                        * 1e6,
                    }
                    rows.append(row)
            print(f"User{user}: {name} complete", flush=True)
    summary = []
    for name in configurations:
        for window in (100, 10):
            subset = [
                r for r in rows if r["configuration"] == name and r["window"] == window
            ]
            per_seed = {
                str(seed): aggregate([r for r in subset if r["seed"] == seed])
                for seed in sorted({r["seed"] for r in subset})
            }
            summary.append(
                {
                    "configuration": name,
                    "window": window,
                    "per_seed": per_seed,
                    "constant_test_runs": sum(
                        r["development_test"]["unique_scores"] == 1 for r in subset
                    ),
                    "runs": len(subset),
                    "mean_normal_validation_alarm_fraction": float(
                        np.mean(
                            [r["normal_validation"]["alarm_fraction"] for r in subset]
                        )
                    ),
                }
            )
    result = {
        "schema_version": 1,
        "python": platform.python_version(),
        "numpy": np.__version__,
        "development_users": list(DEVELOPMENT_USERS),
        "reserved_users_evaluated": False,
        "data_sha256": digests,
        "labels_sha256": hashlib.sha256(label_path.read_bytes()).hexdigest(),
        "split": {
            "training": [1, 4000],
            "calibration": [4001, 4500],
            "normal_validation": [4501, 5000],
            "development_test": [5001, 15000],
        },
        "live_metric": "Any alarm among 91 ten-command windows within a labeled 100-command block; not per-command accuracy or detection delay",
        "rows": rows,
        "summary": summary,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(f"Saved {len(rows)} runs to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("schonlau"))
    parser.add_argument(
        "--labels", type=Path, default=Path("schonlau/masquerade_summary.labels")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("docs/research/feasibility-results.json")
    )
    args = parser.parse_args()
    run(args.data_dir, args.labels, args.output)
