"""Role/account-specific negative selection and an independently scored Markov baseline."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np

from ais.events import INTERPRETERS, PYTHON

FEATURES = (
    "first_seen_fraction",
    "transition_novelty",
    "distinct_fraction",
    "interpreter_fraction",
    "writable_execution_fraction",
    "distinct_rate",
    "off_hours_fraction",
    "new_source_fraction",
)


def frames(session, length=10):
    return [session[i : i + length] for i in range(len(session) - length + 1)]


class Profile:
    def fit(self, sessions, calibration, seed=42):
        self.key = sessions[0][0].profile_key
        self.known = {e.program for session in sessions for e in session}
        self.parents = {
            (e.parent, e.program)
            for session in sessions
            for e in session
            if e.parent is not None
        }
        self.transitions = Counter(
            (a.program, b.program)
            for session in sessions
            for a, b in zip(session, session[1:])
        )
        self.outgoing = Counter()
        for (a, _), count in self.transitions.items():
            self.outgoing[a] += count
        training = [window for session in sessions for window in frames(session)]
        calibration_frames = [
            window for session in calibration for window in frames(session)
        ]
        if not training or not calibration_frames:
            raise ValueError(
                "Each profile needs separate training and calibration sessions with ten events"
            )
        all_features = [self.features(window) for window in training]
        self.columns = [
            name
            for name in FEATURES
            if all(row[name] is not None for row in all_features)
        ]
        normal = np.unique(
            [[row[c] for c in self.columns] for row in all_features], axis=0
        )
        rng = np.random.default_rng(seed)
        centers = rng.uniform(0, 1, (1024, len(self.columns)))
        distances = np.linalg.norm(centers[:, None] - normal[None, :], axis=2)
        radii = distances.min(axis=1) - 0.02
        selected = radii > 0
        self.centers, self.radii = centers[selected][:256], radii[selected][:256]
        if not len(self.radii):
            raise ValueError("No usable negative-selection detectors")
        if np.any(
            np.linalg.norm(self.centers[:, None] - normal[None, :], axis=2)
            <= self.radii[:, None]
        ):
            raise ValueError("A detector overlaps normal training vectors")
        values = []
        markov = []
        for window in calibration_frames:
            score, _ = self.score(window)
            if score is not None:
                values.append(score)
                markov.append(self.markov(window))
        if not values:
            raise ValueError("Calibration lacks features observed during training")
        self.threshold = float(np.quantile(values, 0.99, method="higher"))
        self.markov_threshold = float(np.quantile(markov, 0.99, method="higher"))
        self.quality = {
            "experimental": True,
            "deployment_ready": False,
            "training_windows": len(training),
            "calibration_windows": len(values),
            "missing_calibration_windows": len(calibration_frames) - len(values),
            "nonoverlapping_calibration_windows": sum(
                len(s) // 10 for s in calibration
            ),
            "constant_calibration": len(set(values)) == 1,
            "saturated_threshold": self.threshold >= 1,
        }
        return self

    def novel(self, event):
        return event.program not in self.known

    def unexpected_parent(self, event):
        return bool(
            self.parents
            and event.parent is not None
            and (event.parent, event.program) not in self.parents
        )

    def features(self, window):
        if len(window) != 10:
            raise ValueError("Contextual features require exactly ten events")
        n = len(window)
        times = [e.time for e in window]
        rate = None
        if all(t is not None for t in times) and times == sorted(times):
            rate = min(
                1,
                len({e.program for e in window}) * 2 / max(times[-1] - times[0], 0.001),
            )
        return {
            "first_seen_fraction": sum(self.novel(e) for e in window) / n,
            "transition_novelty": sum(
                (a.program, b.program) not in self.transitions
                for a, b in zip(window, window[1:])
            )
            / (n - 1),
            "distinct_fraction": len({e.program for e in window}) / n,
            "interpreter_fraction": sum(
                e.program in INTERPRETERS or bool(PYTHON.fullmatch(e.program))
                for e in window
            )
            / n,
            "writable_execution_fraction": sum(
                e.executable_kind in {"temporary", "relative"} for e in window
            )
            / n
            if all(e.executable_kind is not None for e in window)
            else None,
            "distinct_rate": rate,
            "off_hours_fraction": sum(e.off_hours for e in window) / n
            if all(e.off_hours is not None for e in window)
            else None,
            "new_source_fraction": sum(e.new_source for e in window) / n
            if all(e.new_source is not None for e in window)
            else None,
        }

    def score(self, window):
        values = self.features(window)
        missing = [name for name in self.columns if values[name] is None]
        if missing:
            return None, missing
        vector = np.array([values[name] for name in self.columns])
        distances = np.linalg.norm(self.centers - vector, axis=1)
        return float(np.maximum(0, 1 - distances / self.radii).max()), []

    def markov(self, window):
        scale = math.log(sum(self.transitions.values()) + len(self.known) + 1)
        return sum(
            -math.log(
                (self.transitions[(a.program, b.program)] + 1)
                / (self.outgoing[a.program] + len(self.known) + 1)
            )
            / scale
            for a, b in zip(window, window[1:])
        ) / (len(window) - 1)

    def artifact(self):
        return {
            "key": list(self.key),
            "known": sorted(self.known),
            "parents": [list(p) for p in sorted(self.parents)],
            "transitions": [
                [a, b, n] for (a, b), n in sorted(self.transitions.items())
            ],
            "columns": self.columns,
            "centers": self.centers.tolist(),
            "radii": self.radii.tolist(),
            "threshold": self.threshold,
            "markov_threshold": self.markov_threshold,
            "quality": self.quality,
        }

    @classmethod
    def load(cls, row):
        model = cls()
        model.key = tuple(row["key"])
        model.known = set(row["known"])
        model.parents = {tuple(p) for p in row["parents"]}
        model.transitions = Counter({(a, b): n for a, b, n in row["transitions"]})
        model.outgoing = Counter()
        for (a, _), n in model.transitions.items():
            model.outgoing[a] += n
        model.columns = row["columns"]
        model.centers = np.array(row["centers"], dtype=float)
        model.radii = np.array(row["radii"], dtype=float)
        model.threshold = float(row["threshold"])
        model.markov_threshold = float(row["markov_threshold"])
        model.quality = row["quality"]
        if (
            not model.columns
            or len(set(model.columns)) != len(model.columns)
            or not set(model.columns) <= set(FEATURES)
            or model.centers.shape != (len(model.radii), len(model.columns))
            or not len(model.radii)
            or not np.isfinite(model.centers).all()
            or not np.isfinite(model.radii).all()
            or np.any(model.radii <= 0)
            or not 0 <= model.threshold <= 1
            or not math.isfinite(model.markov_threshold)
        ):
            raise ValueError("Invalid contextual model arrays or thresholds")
        return model


class Model:
    def __init__(self, profiles=None):
        self.profiles = profiles or {}
        self.version = None

    def save(self, path):
        body = {
            "schema_version": 1,
            "kind": "contextual_negative_selection",
            "deployment_ready": False,
            "profiles": [
                self.profiles[key].artifact() for key in sorted(self.profiles)
            ],
        }
        body["version"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, allow_nan=False).encode()
        ).hexdigest()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(body, indent=2, allow_nan=False) + "\n")
        target.chmod(0o600)
        self.version = body["version"]

    @classmethod
    def load(cls, path):
        body = json.loads(Path(path).read_text())
        version = body.pop("version")
        if (
            body.get("schema_version") != 1
            or body.get("kind") != "contextual_negative_selection"
            or hashlib.sha256(
                json.dumps(body, sort_keys=True, allow_nan=False).encode()
            ).hexdigest()
            != version
        ):
            raise ValueError("Unsupported or changed contextual model")
        profiles = [Profile.load(row) for row in body["profiles"]]
        if len({p.key for p in profiles}) != len(profiles):
            raise ValueError("Duplicate model profile keys")
        model = cls({p.key: p for p in profiles})
        model.version = version
        return model
