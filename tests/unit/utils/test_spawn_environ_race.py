"""Regression tests: a spawn must never hand its child the live ``environ``.

On Linux, CPython 3.10+ spawns with ``vfork``. With ``env=None`` the child runs
``execv`` against the parent's live ``environ`` array, which another thread can
reallocate and free with ``setenv``/``unsetenv`` before ``execve`` reads it. The
result is ``OSError: [Errno 14] Bad address`` from the spawn. In CI this was
cfn-nag failing on a template while ``cdk_nag_wrapper`` toggled its JSII
variables in a neighboring scanner thread.

The stress test reproduces that race with real spawns. The unit tests pin the
mechanism of the fix: the spawn helpers pass an explicit environment copy.
"""

import errno
import os
import shutil
import subprocess  # nosec B404 - the tests exercise real and mocked spawns
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    environ_overrides,
    restore_environ,
    snapshot_environ,
)

# The same three variables cdk_nag_wrapper sets around every evaluation.
_JSII_OVERRIDES = {
    "NODE_NO_WARNINGS": "1",
    "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION": "1",
    "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION": "1",
}

_SPAWNS = 300

# What the churn thread must leave behind once it stops.
_ORIGINAL_ENV = {key: os.environ.get(key) for key in _JSII_OVERRIDES}


def _vfork_race_possible() -> bool:
    # The race needs a vfork-style spawn that shares the parent's memory until
    # execve. CPython uses vfork on Linux from 3.10; elsewhere the child gets its
    # own copy (fork) or the platform builds the environment block itself
    # (Windows), and there is nothing to race.
    return sys.platform.startswith("linux") and sys.version_info >= (3, 10)


def _trivial_command() -> list:
    true_bin = shutil.which("true")
    if true_bin:
        return [true_bin]
    return [sys.executable, "-c", "pass"]


@pytest.mark.skipif(
    not _vfork_race_possible(),
    reason="the vfork/execve environ race exists only on Linux with CPython >= 3.10",
)
@pytest.mark.parametrize(
    "spawn",
    [
        pytest.param(
            lambda cmd: subprocess_utils.run_command(cmd, log_level=5),
            id="run_command",
        ),
        pytest.param(
            lambda cmd: subprocess_utils.run_command_with_output_handling(
                cmd, stdout_preference="return", stderr_preference="return"
            ),
            id="run_command_with_output_handling",
        ),
    ],
)
def test_spawn_survives_concurrent_environ_mutation(spawn):
    """Spawns from the ASH helpers succeed while another thread churns the env.

    Mirrors the production shape: one thread applies and restores the JSII
    overrides through the shared helper in a loop, as cdk_nag_wrapper does per
    template, while this thread spawns through subprocess_utils. Before the fix
    a large fraction of these spawns failed with EFAULT.
    """
    stop = threading.Event()

    def churn() -> None:
        while not stop.is_set():
            with environ_overrides(_JSII_OVERRIDES):
                pass

    command = _trivial_command()
    failures = []
    # A busy churn thread otherwise holds the GIL for the default 5ms switch
    # interval at a time, which makes each spawn wait and the test slow.
    switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(0.0001)
    mutator = threading.Thread(target=churn, daemon=True)
    mutator.start()
    try:
        for _ in range(_SPAWNS):
            # run_command rewrites args[0], so hand it a fresh list each time.
            result = spawn(list(command))
            returncode = (
                result["returncode"] if isinstance(result, dict) else result.returncode
            )
            if returncode != 0:
                detail = (
                    result.get("stderr", "")
                    if isinstance(result, dict)
                    else result.stderr
                )
                failures.append(detail)
    finally:
        stop.set()
        mutator.join(timeout=10)
        sys.setswitchinterval(switch_interval)

    efault = [f for f in failures if "Bad address" in (f or "")]
    assert not failures, (
        f"{len(failures)} of {_SPAWNS} spawns failed "
        f"({len(efault)} with EFAULT / errno {errno.EFAULT}); first: {failures[:1]}"
    )
    for key in _JSII_OVERRIDES:
        assert os.environ.get(key) == _ORIGINAL_ENV.get(key)


class TestSpawnHelpersPassExplicitEnv:
    """With ``env=None`` the helpers pass a copy of the environment, not None."""

    @pytest.fixture(autouse=True)
    def _no_path_resolution(self):
        with patch.object(subprocess_utils, "find_executable", return_value=None):
            yield

    def test_run_command(self):
        with patch.object(subprocess_utils.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(["x"], 0, "", "")
            subprocess_utils.run_command(["x"])
        env = mock_run.call_args.kwargs["env"]
        assert env is not None
        assert env is not os.environ
        assert env == dict(os.environ)

    def test_run_command_with_output_handling(self):
        with patch.object(subprocess_utils.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(["x"], 0, "", "")
            subprocess_utils.run_command_with_output_handling(["x"])
        env = mock_run.call_args.kwargs["env"]
        assert env is not None
        assert env is not os.environ
        assert env == dict(os.environ)

    def test_run_command_stream_output(self):
        process = MagicMock()
        process.stdout = iter([])
        process.returncode = 0
        process.poll.return_value = 0
        with patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as mock_popen:
            subprocess_utils.run_command_stream_output(["x"])
        env = mock_popen.call_args.kwargs["env"]
        assert env is not None
        assert env is not os.environ
        assert env == dict(os.environ)

    def test_create_process_with_pipes(self):
        with patch.object(subprocess_utils.subprocess, "Popen") as mock_popen:
            subprocess_utils.create_process_with_pipes(["x"])
        env = mock_popen.call_args.kwargs["env"]
        assert env is not None
        assert env is not os.environ
        assert env == dict(os.environ)

    def test_explicit_env_is_passed_through_unchanged(self):
        explicit = {"ONLY": "this"}
        with patch.object(subprocess_utils.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(["x"], 0, "", "")
            subprocess_utils.run_command(["x"], env=explicit)
        assert mock_run.call_args.kwargs["env"] is explicit


class TestProcessEnvHelpers:
    _KEY = "ASH_TEST_PROCESS_ENV_HELPER"

    def test_overrides_are_restored_when_previously_unset(self, monkeypatch):
        monkeypatch.delenv(self._KEY, raising=False)
        with environ_overrides({self._KEY: "1"}):
            assert os.environ[self._KEY] == "1"
        assert self._KEY not in os.environ

    def test_overrides_restore_a_previous_value(self, monkeypatch):
        monkeypatch.setenv(self._KEY, "before")
        with environ_overrides({self._KEY: "during"}):
            assert os.environ[self._KEY] == "during"
        assert os.environ[self._KEY] == "before"

    def test_overrides_are_restored_on_exception(self, monkeypatch):
        monkeypatch.delenv(self._KEY, raising=False)
        with pytest.raises(RuntimeError):
            with environ_overrides({self._KEY: "1"}):
                raise RuntimeError("boom")
        assert self._KEY not in os.environ

    def test_none_value_removes_and_restores(self, monkeypatch):
        monkeypatch.setenv(self._KEY, "kept")
        previous = apply_environ_overrides({self._KEY: None})
        assert self._KEY not in os.environ
        restore_environ(previous)
        assert os.environ[self._KEY] == "kept"

    def test_snapshot_is_an_independent_dict(self, monkeypatch):
        monkeypatch.setenv(self._KEY, "x")
        snap = snapshot_environ()
        assert type(snap) is dict
        assert snap == dict(os.environ)
        snap[self._KEY] = "changed"
        assert os.environ[self._KEY] == "x"
