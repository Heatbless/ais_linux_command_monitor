import hashlib
import io
import json
import zipfile

import pytest

from experiments.ait_sample import execution, score_contexts
from experiments.external_evaluation import analyze_period, load_demo_model, sanitize
from experiments.fetch_external import COWRIE_FILES, RemoteZip, StoredMember
from experiments.history_feasibility import HistoryNSA


def test_auth_exe_is_not_a_program_execution():
    assert execution('type=USER_AUTH msg=audit(1:1) exe="/bin/su" res=success') is None
    assert (
        execution(
            'type=SYSCALL msg=audit(1:2) arch=c000003e syscall=1 success=yes exe="/bin/bash"'
        )
        is None
    )
    sample = 'type=SYSCALL msg=audit(1.123:3) arch=c000003e syscall=59 success=yes uid=0 auid=1000 ses=2 exe="/usr/bin/python3"'
    assert execution(sample)["command"] == "python3"
    assert execution(sample.replace("success=yes", "success=no")) is None
    assert execution(sample.replace("c000003e", "unknown")) is None


def test_external_normalization_preserves_gaps_and_discards_arguments():
    segments, excluded = sanitize(
        [
            "git status",
            "cd /private",
            "git log",
            "UNRECOGNIZED_SECRET",
            "python3 secret.py --token PRIVATE",
        ]
    )
    assert segments == [["git", "git"], ["python3"]]
    assert excluded["unrecognized_executable"] == 1
    assert "PRIVATE" not in json.dumps(segments)


def test_frozen_model_integrity_and_round_trip(tmp_path):
    original = HistoryNSA("complete_any").fit([["git"] * 12])
    original.threshold = 0.5
    artifact = original.artifact()
    artifact["model_version"] = hashlib.sha256(
        json.dumps(artifact, sort_keys=True).encode()
    ).hexdigest()
    path = tmp_path / "model.json"
    path.write_text(json.dumps(artifact))
    loaded, version = load_demo_model(path)
    assert loaded.score(["git"] * 10) == original.score(["git"] * 10)
    assert loaded.score(["python3"] * 10) == original.score(["python3"] * 10)
    assert version == artifact["model_version"]
    artifact["threshold"] = 0.9
    path.write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match="Changed"):
        load_demo_model(path)


def test_attack_groups_are_deduplicated_and_short_or_empty_are_not_successes(
    tmp_path, monkeypatch
):
    path = tmp_path / "fixture.jsonl"
    rows = [
        {"commands": ["python3 task.py"] * 10},
        {"commands": ["python3 other.py"] * 10},
        {"commands": ["git status"] * 2},
        {"commands": ["UNRECOGNIZED_SECRET"]},
    ]
    body = "".join(json.dumps(row) + "\n" for row in rows).encode()
    path.write_bytes(body)
    digest = hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
    monkeypatch.setitem(COWRIE_FILES, path.name, (len(body), digest))
    model = HistoryNSA("complete_any").fit([["git"] * 12])
    model.threshold = 0.5
    result = analyze_period(path, model, set())
    assert result["source_groups"] == 4
    assert result["scorable_unique_groups"] == 1
    assert result["ais_flagged_unique_groups"] == 1
    assert result["duplicate_sanitized_groups"] == 1
    assert result["below_ten_command_warmup"] == 1
    assert result["empty_after_filtering"] == 1


def test_stored_nested_zip_can_be_read_without_extracting_paths():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("audit.log", "fixture data")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("nested.zip", inner.getvalue())
    outer.seek(0)
    with zipfile.ZipFile(outer) as archive:
        with zipfile.ZipFile(
            StoredMember(outer, archive.getinfo("nested.zip"))
        ) as nested:
            assert nested.read("audit.log") == b"fixture data"


def test_http_range_reader_refuses_full_archive_response(monkeypatch):
    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Length": "1000000000"}

        def read(self, *args):
            pytest.fail("Full archive body must not be consumed")

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: Response())
    source = RemoteZip("https://example.invalid/archive.zip")
    with pytest.raises(ValueError, match="exact byte ranges"):
        source.read(1)


def test_http_range_budget_is_enforced_before_body_download(monkeypatch):
    class Response(io.BytesIO):
        headers = {"Content-Length": "1024"}

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: Response())
    source = RemoteZip("https://example.invalid/archive.zip", budget=4)
    with pytest.raises(ValueError, match="budget"):
        source.read(1)


def test_login_scope_is_separate_from_unset_login_daemon_activity():
    model = HistoryNSA("complete_any").fit([["git"] * 12])
    model.threshold = 0.5
    base = {"uid": "0", "session": "1", "normal_label": True, "normal_block": 0}
    records = [{**base, "auid": "0", "command": "git"} for _ in range(10)]
    records += [{**base, "auid": "4294967295", "command": "python3"} for _ in range(10)]
    result = score_contexts(records, model)
    assert result["normal_root_login_windows"] == 1
    assert result["flagged_normal_root_login_windows"] == 0
    assert result["normal_unset_login_windows"] == 1
    assert result["flagged_normal_unset_login_windows"] == 1


def test_normal_windows_do_not_cross_labeled_attack_spans():
    model = HistoryNSA("complete_any").fit([["git"] * 12])
    model.threshold = 0.5
    base = {
        "uid": "0",
        "auid": "0",
        "session": "1",
        "normal_label": True,
        "command": "git",
    }
    records = [{**base, "normal_block": block} for block in (0, 1) for _ in range(6)]
    assert score_contexts(records, model)["normal_root_login_windows"] == 0
