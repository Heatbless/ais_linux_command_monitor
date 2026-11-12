from itertools import product

import numpy as np
import pytest

from experiments.feasibility import (
    CategoricalNSA,
    NoveltyBaseline,
    NumericalNSA,
    grams,
    metrics,
    read_labels,
    read_user,
    signatures,
    threshold,
)


def test_signature_matching_is_equivalent_to_positional_matching():
    sequences = list(product(range(2), repeat=4))
    for left in sequences:
        for right in sequences:
            for required in (1, 2, 3, 4):
                indexed = bool(
                    set(signatures(left, required)) & set(signatures(right, required))
                )
                assert indexed == (sum(a == b for a, b in zip(left, right)) >= required)


@pytest.mark.parametrize("strategy", ["uniform", "mutated"])
def test_categorical_detector_censoring_reproducibility_and_unknowns(strategy):
    commands = ["a", "b", "a", "b", "c"] * 20
    first = CategoricalNSA(3, 2, strategy, target=10, limit=1000).fit(commands, 42)
    second = CategoricalNSA(3, 2, strategy, target=10, limit=1000).fit(commands, 42)
    assert first.detectors == second.detectors
    assert len(first.detectors) > 0
    for candidate in first.detectors:
        for normal in grams(first.encode(commands), 3):
            assert sum(a == b for a, b in zip(candidate, normal)) < 2
    assert first.encode(["never_seen"]) == [0]
    assert np.all(first.scores(commands, 10, 1) == 0)


def test_windows_do_not_count_transitions_outside_each_window():
    baseline = NoveltyBaseline(2).fit(["a", "a"], 42)
    # Only the pair b,c crosses the boundary; independent two-command windows
    # must score [1,0] and must not include a cross-boundary gram.
    assert baseline.scores(["b", "b", "a", "a"], 2, 2).tolist() == [1, 0]
    assert baseline.scores(["a"], 2, 1).size == 0


def test_numerical_detector_spheres_exclude_all_training_vectors():
    commands = ["a", "b", "a", "c"] * 30
    model = NumericalNSA(target=32).fit(commands, 42, 10)
    normal = model.features(commands, 10, 10)
    distances = np.linalg.norm(normal[:, None] - model.centers[None, :], axis=2)
    assert np.all(distances >= model.radii)
    assert np.all(model.vector_scores(normal) == 0)
    scores = model.scores(["unknown"] * 10, 10, 1)
    assert np.all((0 <= scores) & (scores <= 1))
    assert model.counts["unknown"] == 0


def test_calibration_uses_strict_greater_than_and_handles_ties():
    cut = threshold(np.array([0, 0, 0.5, 1]))
    assert cut == 1
    result = metrics(np.array([1, 1]), [0, 1], cut)
    assert result == {
        "tp": 0,
        "fp": 0,
        "fn": 1,
        "tn": 1,
        "precision": None,
        "recall": 0,
        "false_positive_rate": 0,
    }
    with pytest.raises(ValueError, match="Insufficient"):
        threshold(np.array([]))


def test_reserved_user_access_is_rejected_before_reading(tmp_path):
    with pytest.raises(ValueError, match="reserved"):
        read_user(tmp_path, 2)


def test_labels_validate_shape_and_binary_values(tmp_path):
    path = tmp_path / "labels"
    np.savetxt(path, np.zeros((50, 100)), fmt="%d")
    with pytest.raises(ValueError, match="100-block"):
        read_labels(path)
    labels = np.zeros((100, 50), dtype=int)
    labels[1, 9] = 1
    np.savetxt(path, labels, fmt="%d")
    assert read_labels(path)[1, 9] == 1
    labels[0, 0] = 2
    np.savetxt(path, labels, fmt="%d")
    with pytest.raises(ValueError, match="binary"):
        read_labels(path)
