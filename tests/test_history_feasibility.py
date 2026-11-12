import json

import pytest

from experiments.history_feasibility import (
    ContinuousHistoryNSA,
    FamilyHistoryNSA,
    HistoryNSA,
    read_segments,
    signatures,
    split_segments,
    windows,
)
from experiments.history_import import parse_one
from experiments.history_import import run as import_histories


def test_import_never_exposes_arguments_or_executes_substitutions(tmp_path):
    marker = tmp_path / "not_created"
    assert parse_one("python3 secret.py --password PRIVATE_VALUE")[0] == ["python3"]
    assert parse_one(f'echo "$(touch {marker})"')[0] == []
    assert not marker.exists()
    assert parse_one("sudo -u root apt-get update")[0] == ["sudo", "apt-get"]
    assert parse_one("cd /private && python3 secret.py")[0] == ["python3"]
    assert parse_one('eval "python3 secret.py"')[0] == []
    assert parse_one("UNRECOGNIZED_SECRET_VALUE")[0] == []


def test_builtin_only_entry_does_not_claim_missing_execution():
    assert parse_one("cd /private")[1] == "builtin_only"
    assert parse_one("source /private/script")[1] == "opaque_shell_execution"


def test_no_window_or_training_triple_crosses_a_gap():
    segments = [["a"] * 6, ["b"] * 6]
    assert windows(segments) == []
    model = HistoryNSA().fit(segments)
    a, b = model.vocabulary["a"], model.vocabulary["b"]
    assert (a, a, b) not in model.normal_triples
    assert (a, b, b) not in model.normal_triples


def test_complete_negative_selection_censors_every_self_pattern():
    segments = [["a", "b", "c", "a", "b", "c", "a", "b", "c", "a"]]
    model = HistoryNSA().fit(segments)
    assert model.detectors
    for triple in model.normal_triples:
        assert not signatures(triple) & model.detectors
    assert model.score(segments[0]) == 0
    assert model.score(["new"] * 10) == 1


def test_conservative_rule_rejects_isolated_novelty():
    model = HistoryNSA().fit([["a"] * 12])
    assert model.score(["a"] * 9 + ["new"]) == 0
    assert model.score(["new"] * 10) == 1
    with pytest.raises(ValueError, match="exactly ten"):
        model.score(["a"])


def test_training_does_not_include_calibration_or_test_tokens():
    segments = [["train"] * 10] * 6 + [["calibration"] * 10] * 2 + [["test"] * 10] * 2
    train, calibration, test = split_segments(segments)
    assert len(train) == 6 and len(calibration) == 2 and len(test) == 2
    model = HistoryNSA().fit(train)
    model.calibrate(calibration)
    assert set(model.vocabulary) == {"train"}
    assert model.encode(test[0]) == [0] * 10
    assert model.threshold == 1  # Saturation is visible, not silently tuned away.


def test_reader_rejects_arguments_and_reordered_segments(tmp_path):
    path = tmp_path / "commands.jsonl"
    path.write_text(
        json.dumps({"source_line": 1, "segment": 0, "command": "python secret"}) + "\n"
    )
    with pytest.raises(ValueError, match="basenames"):
        read_segments(path)
    records = [
        {"source_line": i, "segment": segment, "command": "a"}
        for i, segment in [(1, 1), (2, 2), (3, 1)]
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in records))
    with pytest.raises(ValueError, match="increase"):
        read_segments(path)


def test_continuous_spheres_exclude_segmented_training_windows():
    segments = [["git", "python3", "git", "ls", "python3"] * 3, ["ls", "cat"] * 8]
    model = ContinuousHistoryNSA().fit(segments)
    assert all(model.score(window) == 0 for window in windows(segments))
    assert 0 <= model.score(["unfamiliar"] * 10) <= 1
    assert model.vocabulary.get("unfamiliar") is None
    assert len(model.centers) == 256


def test_family_representation_is_explicit_and_does_not_merge_unknown_programs():
    model = FamilyHistoryNSA().fit([["python3"] * 10])
    assert model.score(["python3.12"] * 10) == 0
    assert model.score(["git"] * 10) > 0
    artifact = model.artifact()
    assert artifact["representation"] == "command_family"
    assert artifact["mode"] == "family_complete"


def test_importer_omits_builtins_but_keeps_real_gaps_and_originals(tmp_path):
    text = "git status\ncd /private\ngit log\nUNRECOGNIZED_SECRET\ngit status\n"
    for name in ("heat_bash_history", "vps_bash_history"):
        (tmp_path / name).write_text(text)
    output = tmp_path / "sanitized"
    report = import_histories(tmp_path, output)
    records = [
        json.loads(line)
        for line in (output / "local.commands.jsonl").read_text().splitlines()
    ]
    assert [row["command"] for row in records] == ["git", "git", "git"]
    assert records[0]["segment"] == records[1]["segment"]
    assert records[2]["segment"] > records[1]["segment"]
    assert (tmp_path / "heat_bash_history").read_text() == text
    assert "/private" not in (output / "local.commands.jsonl").read_text()
    assert report["format_version"] == 2
