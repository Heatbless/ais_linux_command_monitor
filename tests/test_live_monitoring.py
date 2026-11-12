import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ais.demo import document
from ais.engine import Engine
from ais.events import event_from_record
from ais.live import ShellCollector, hook, monitor, private_directory, shell_commands
from ais.workflows import train_workflows


@pytest.fixture
def model_path(tmp_path):
    source = tmp_path / "workflows.json"
    source.write_text(json.dumps(document()))
    model, _ = train_workflows(source, allow_synthetic=True)
    target = tmp_path / "model.json"
    model.save(target)
    return model, target


def test_parse_never_executes_or_claims_conditional_branches(tmp_path):
    marker = tmp_path / "executed"
    assert shell_commands("python3 -c 'print(1)'") == [
        (["python3", "-c", "print(1)"], False)
    ]
    assert shell_commands(f"python3 $(touch {marker})") == [(["python3"], True)]
    assert not marker.exists()
    assert shell_commands("false && python3 exploit.py") == []
    assert shell_commands("if false; then python3 x; fi") == []
    assert shell_commands("cat /etc/shadow | head") == [
        (["cat", "/etc/shadow"], False),
        (["head"], False),
    ]


def test_state_directory_permissions(tmp_path):
    private_directory(tmp_path / "state")
    path = tmp_path / "unsafe"
    path.mkdir(mode=0o755)
    with pytest.raises(ValueError):
        private_directory(path)


def test_hook_removal_is_attention_when_observed(model_path):
    row = {
        "event_id": "remove-hook",
        "host": "local",
        "boot_id": "boot",
        "account": "user",
        "source": "shell",
        "argv": ["trap", "-", "DEBUG"],
    }
    assessment = Engine(model_path[0]).process(event_from_record(row))
    assert any(w["rule"] == "monitor_tamper" for w in assessment["warnings"])


def test_actual_socket_client_produces_python_warning_without_raw_args(
    tmp_path, model_path
):
    async def scenario():
        outputs = []
        collector = ShellCollector(
            Engine(model_path[0]), "test-host", "test-boot", "developer", outputs.append
        )
        path = tmp_path / "collector.sock"
        async with await asyncio.start_unix_server(collector.accept, path=path):
            client = await asyncio.create_subprocess_exec(
                sys.executable,
                str(Path("ais/shell_emit.py").resolve()),
                str(path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, error = await client.communicate(b"python3 -c 'SECRET_TEST_ARGUMENT'\n")
            assert client.returncode == 0, error
        assert len(outputs) == 1
        assert outputs[0]["source"] == "shell"
        assert outputs[0]["uid"] == os.getuid()
        assert outputs[0]["session"] == str(os.getsid(0))
        assert outputs[0]["status"] == "no_profile"
        assert any(w["rule"] == "python_attention" for w in outputs[0]["warnings"])
        assert "SECRET_TEST_ARGUMENT" not in json.dumps(outputs)
        assert collector.state["collected"] == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_hook_preserves_command_and_exit_behavior(tmp_path, shell):
    if not shutil.which(shell):
        pytest.skip("Shell not installed")
    script = tmp_path / "hook.sh"
    script.write_text(hook(shell, tmp_path / "missing.sock"))
    # Hook source must be valid and collector downtime must not cancel commands.
    result = subprocess.run([shell, "-n", str(script)], capture_output=True)
    assert result.returncode == 0, result.stderr
    command = f"source {script}; _ais_preexec 'python3 -c fake'; printf survived"
    result = subprocess.run([shell, "-c", command], capture_output=True)
    assert result.returncode == 0
    assert b"survived" in result.stdout


def test_monitor_lifecycle_with_real_socket_and_collector_health(
    tmp_path, model_path, capsys
):
    async def scenario():
        state = tmp_path / "state"
        args = SimpleNamespace(
            state_dir=state,
            model=model_path[1],
            config=None,
            server_url=None,
            token_file=None,
            host="test-host",
            role="developer",
        )
        stop = asyncio.Event()
        task = asyncio.create_task(monitor(args, stop=stop))
        path = state / "monitor.sock"
        try:
            for _ in range(100):
                if path.exists():
                    break
                if task.done():
                    await task
                await asyncio.sleep(0.01)
            assert path.exists()

            def send():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    client.connect(str(path))
                    client.sendall(b'{"command":"python3 -V"}\n')
                    return client.recv(32)

            assert await asyncio.to_thread(send) == b"ok\n"
        finally:
            stop.set()
            await asyncio.wait_for(task, timeout=3)
        assert not path.exists()

    asyncio.run(scenario())
    output = json.loads(capsys.readouterr().out)
    assert output["program"] == "python3"
    assert output["warnings"][0]["rule"] == "python_attention"
