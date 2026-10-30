# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container a run left behind is found by name and removed at the next start.

A second shutdown signal used to SIGKILL the recorded launcher children. For a
container run that ends the runtime client alone: the container keeps running
and writing into the host-mounted output directories, and nothing recorded its
name. The signal now interrupts those children, and every container-mode run
names its container and records the name with its creating process, so the next
container-mode start removes what a dead process left, before it builds or runs
anything.

Nothing here starts a real container runtime or signals a real process. The
runtime is a shell stub that appends its arguments to a call log and exits 0
only for ``rm``; the die-now cells replace ``os.kill`` and ``os.killpg``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from pathlib import Path
from typing import List, Tuple

from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.interactions import container_leftovers
from automated_security_helper.interactions import run_ash_container as module

# Above the kernel's pid space (pid_max is at most 2**22): an entry that leaked
# past a test could never aim a signal at a real process.
_STAND_IN = 2**30 + 91

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the runtime stub is a POSIX shell script"
)


@pytest.fixture
def state(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "ash-state"
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(directory))
    return directory


@pytest.fixture
def runtime(tmp_path) -> Tuple[Path, Path]:
    """A stub runtime and its call log; it exits 0 for ``rm`` and 1 otherwise."""
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(
        f'#!/bin/sh\necho "$@" >> "{log}"\n[ "$1" = rm ] && exit 0\nexit 1\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def _calls(log: Path) -> List[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _write_record(
    state: Path, name: str, pid: int, start=None, host=None, **extra
) -> Path:
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state / f"{name}.json"
    record = {
        "name": name,
        "creator_pid": pid,
        "creator_start": start,
        "host": container_leftovers.host_key() if host is None else host,
    }
    record.update(extra)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


@pytest.fixture
def dead_pid() -> int:
    """The pid of a child this test started and reaped."""
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid


@pytest.fixture
def live_child():
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
    )
    try:
        yield child
    finally:
        child.kill()
        child.wait(timeout=30)


# --- the die-now signals -----------------------------------------------------


@pytest.mark.unit
def test_the_die_now_interrupts_a_recorded_child_and_does_not_kill_it(monkeypatch):
    sent: list = []
    monkeypatch.setattr("os.kill", lambda pid, sig: sent.append((pid, sig)))
    monkeypatch.setattr("os.killpg", lambda pgid, sig: sent.append((pgid, sig)))
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (), raising=False)
    cancellation.record_tool_pid(_STAND_IN)
    try:
        cancellation._kill_recorded_groups()
    finally:
        cancellation.discard_tool_pid(_STAND_IN)

    assert (_STAND_IN, signal.SIGINT) in sent, sent
    assert (_STAND_IN, signal.SIGKILL) not in sent, sent


@pytest.mark.unit
def test_the_die_now_still_kills_a_recorded_tool_group(monkeypatch):
    sent: list = []
    monkeypatch.setattr("os.kill", lambda pid, sig: sent.append(("kill", pid, sig)))
    monkeypatch.setattr(
        "os.killpg", lambda pgid, sig: sent.append(("killpg", pgid, sig))
    )
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (_STAND_IN,))
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", (), raising=False)

    cancellation._kill_recorded_groups()

    assert sent == [("killpg", _STAND_IN, signal.SIGKILL)], sent


# --- the record --------------------------------------------------------------


@pytest.mark.unit
def test_a_run_command_names_its_container(state):
    name = container_leftovers.new_container_name()
    assert name.startswith(f"ash-scan-{os.getpid()}-")
    cmd = module._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="docker",
        image_name="img",
        source_dir=state.parent,
        output_dir=state.parent,
        offline=False,
        debug=False,
        color=False,
        quiet=False,
        progress=False,
        verbose=False,
        simple=False,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=None,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=None,
        ctx=None,
        container_name=name,
    )
    assert cmd[cmd.index("--name") + 1] == name
    assert cmd.index("--name") < cmd.index("img")


@pytest.mark.unit
def test_the_record_holds_the_name_and_the_creating_process(state):
    name = container_leftovers.new_container_name()
    path = container_leftovers.record_container(name)

    assert path == state / f"{name}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["name"] == name
    assert record["creator_pid"] == os.getpid()


# --- the sweep ---------------------------------------------------------------


@pytest.mark.integration
def test_a_container_whose_creator_is_gone_is_removed(state, runtime, dead_pid):
    stub, log = runtime
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    record = _write_record(state, name, dead_pid)

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == [name]
    assert _calls(log) == [f"rm -f {name}"]
    assert not record.exists(), "a removed container's record was kept"


@pytest.mark.integration
def test_a_container_whose_creator_is_alive_is_not_touched(state, runtime, live_child):
    stub, log = runtime
    name = f"ash-scan-{live_child.pid}-0a1b2c3d"
    record = _write_record(state, name, live_child.pid)

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == []
    assert _calls(log) == [], "the runtime was asked about a live run's container"
    assert record.exists()


@pytest.mark.integration
def test_a_record_the_runtime_would_not_remove_is_kept(state, tmp_path, dead_pid):
    refusing = tmp_path / "refusing-runtime"
    refusing.write_text("#!/bin/sh\necho daemon unreachable >&2\nexit 1\n")
    refusing.chmod(0o755)
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    record = _write_record(state, name, dead_pid)

    assert container_leftovers.sweep_leftover_containers([str(refusing)]) == []
    assert record.exists()


@pytest.mark.integration
def test_a_record_naming_something_else_never_reaches_the_runtime(
    state, runtime, dead_pid
):
    stub, log = runtime
    _write_record(state, "ash-scan-1-0a1b2c3d", dead_pid)
    hostile = state / "ash-scan-2-0a1b2c3d.json"
    hostile.write_text(
        json.dumps({"name": "--privileged", "creator_pid": dead_pid}),
        encoding="utf-8",
    )
    (state / "ash-scan-3-0a1b2c3d.json").write_text("{not json", encoding="utf-8")

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == ["ash-scan-1-0a1b2c3d"]
    assert _calls(log) == ["rm -f ash-scan-1-0a1b2c3d"]


# --- the order, through the real entry point -------------------------------


def _run(stub: Path, tmp_path: Path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    return module.run_ash_container(
        source_dir=source,
        output_dir=tmp_path / "out",
        build=False,
        run=True,
        oci_runner=str(stub),
        color=False,
        progress=False,
    )


class _Stop(Exception):
    """Ends the container-mode path once the cells have what they measure."""


@pytest.mark.integration
def test_a_leftover_is_removed_before_the_host_clears_declared_outputs(
    state, tmp_path, dead_pid, monkeypatch
):
    """The sweep comes before the host's clear of the previous results.

    A surviving container can rewrite a declared output after that clear and
    before the next read, and the run would then vouch for the old container's
    bytes. So ``rm -f`` must be called while a declared output planted before
    the run still exists, and the clear must come after it.
    """
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    source = tmp_path / "src"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    planted = output / "planted-output.json"
    planted.write_text("{}", encoding="utf-8")
    log = tmp_path / "order.log"
    stub = tmp_path / "order-runtime"
    stub.write_text(
        f'#!/bin/sh\necho "$@ planted=$([ -e "{planted}" ] && echo present '
        f'|| echo absent)" >> "{log}"\nexit 0\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    leftover = f"ash-scan-{dead_pid}-0a1b2c3d"
    _write_record(state, leftover, dead_pid)

    def clear(opts, logger):
        with log.open("a", encoding="utf-8") as stream:
            stream.write("CLEAR\n")
        planted.unlink()

    def first_run(**kwargs):
        raise _Stop

    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", clear)
    monkeypatch.setattr(run_ash_scan, "run_ash_container", first_run)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    opts = run_ash_scan.ScanOptions(
        source_dir=source,
        output_dir=output,
        mode=RunMode.container,
        oci_runner=str(stub),
        build=False,
        run=True,
    )

    with pytest.raises(_Stop):
        run_ash_scan._run_container_mode(opts, MagicMock())

    calls = _calls(log)
    assert calls == [f"rm -f {leftover} planted=present", "CLEAR"], calls


@pytest.mark.integration
def test_the_run_the_entry_point_starts_names_its_container(
    state, runtime, tmp_path, monkeypatch
):
    """run_ash_container names its container in the command it runs."""
    stub, log = runtime

    _run(stub, tmp_path, monkeypatch)

    runs = [line for line in _calls(log) if line.startswith("run ")]
    assert len(runs) == 1 and "--name ash-scan-" in runs[0], runs


@pytest.mark.integration
def test_the_record_exists_when_the_runtime_starts_and_goes_when_it_ends(
    state, runtime, tmp_path, monkeypatch
):
    stub, _ = runtime
    seen: dict = {}
    real_execute = module._execute_container

    def spy(cmd, debug, env=None):
        seen["name"] = cmd[cmd.index("--name") + 1]
        seen["records"] = sorted(p.name for p in state.glob("ash-scan-*.json"))
        return real_execute(cmd, debug, env=env)

    monkeypatch.setattr(module, "_execute_container", spy)

    _run(stub, tmp_path, monkeypatch)

    assert seen["records"] == [f"{seen['name']}.json"], seen
    assert list(state.glob("ash-scan-*.json")) == [], "a finished run's record stayed"


@pytest.mark.integration
def test_a_run_ended_by_an_exception_leaves_its_record_for_the_sweep(
    state, runtime, tmp_path, monkeypatch
):
    stub, _ = runtime

    def interrupted(cmd, debug, env=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(module, "_execute_container", interrupted)

    with pytest.raises(KeyboardInterrupt):
        _run(stub, tmp_path, monkeypatch)

    assert len(list(state.glob("ash-scan-*.json"))) == 1


def _nix_mode_run(tmp_path, runtime_path, monkeypatch):
    """Run the nix wrapper up to its first step, with a planted declared output.

    Returns the order log: the stub runtime's lines and CLEAR, in call order.
    """
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    source = tmp_path / "src"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    planted = output / "planted-output.json"
    planted.write_text("{}", encoding="utf-8")
    log = tmp_path / "order.log"

    def clear(opts, logger):
        with log.open("a", encoding="utf-8") as stream:
            stream.write("CLEAR\n")
        planted.unlink()

    def nix_shell(**kwargs):
        raise _Stop

    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", clear)
    monkeypatch.setattr(run_ash_scan, "run_ash_nix", nix_shell)
    monkeypatch.setattr(run_ash_scan, "nix_preflight", lambda: None)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    opts = run_ash_scan.ScanOptions(
        source_dir=source,
        output_dir=output,
        mode=RunMode.nix,
        oci_runner=str(runtime_path),
    )
    with pytest.raises(_Stop):
        run_ash_scan._run_nix_mode(opts, MagicMock())
    return log


@pytest.mark.integration
def test_nix_mode_removes_a_leftover_container_before_its_clear(
    state, tmp_path, dead_pid, monkeypatch
):
    """A container from an earlier container-mode run can write into the same
    output directory, so nix mode sweeps before it clears too."""
    stub = tmp_path / "order-runtime"
    log = tmp_path / "order.log"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    leftover = f"ash-scan-{dead_pid}-0a1b2c3d"
    record = _write_record(state, leftover, dead_pid)

    order = _nix_mode_run(tmp_path, stub, monkeypatch)

    assert _calls(order) == [f"rm -f {leftover}", "CLEAR"], _calls(order)
    assert not record.exists()


@pytest.mark.integration
def test_nix_mode_with_no_container_runtime_keeps_the_record(
    state, tmp_path, dead_pid, monkeypatch
):
    record = _write_record(state, f"ash-scan-{dead_pid}-0a1b2c3d", dead_pid)

    order = _nix_mode_run(tmp_path, tmp_path / "no-such-runtime", monkeypatch)

    assert _calls(order) == ["CLEAR"], "a runtime that does not exist was called"
    assert record.exists()


# --- another host's records --------------------------------------------------


@pytest.mark.integration
def test_a_record_from_another_host_is_left_alone_even_with_a_dead_pid(
    state, runtime, dead_pid
):
    """A shared home and a shared runtime: this host cannot tell whether the
    other host's creator is alive, so its container is not this sweep's."""
    stub, log = runtime
    foreign = _write_record(
        state, f"ash-scan-{dead_pid}-0a1b2c3d", dead_pid, host="some-other-boot-id"
    )

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == []
    assert _calls(log) == [], "the runtime was asked about another host's container"
    assert foreign.exists(), "another host's record was deleted"


@pytest.mark.integration
def test_a_record_from_this_host_with_a_dead_pid_is_still_removed(
    state, runtime, dead_pid
):
    stub, log = runtime
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    _write_record(state, name, dead_pid)

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == [name]


@pytest.mark.unit
def test_a_new_record_carries_this_hosts_key_and_its_kind(state):
    path = container_leftovers.record_container(
        container_leftovers.new_container_name()
    )

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["host"] == container_leftovers.host_key()
    assert record["kind"] == "container"


# --- the record's kind -------------------------------------------------------


@pytest.mark.integration
def test_a_record_of_an_unknown_kind_is_skipped(state, runtime, dead_pid):
    stub, log = runtime
    other = _write_record(
        state, f"ash-scan-{dead_pid}-0a1b2c3d", dead_pid, kind="env-directory"
    )

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert _calls(log) == []
    assert other.exists()


@pytest.mark.integration
def test_a_record_with_no_kind_counts_as_a_container(state, runtime, dead_pid):
    stub, _ = runtime
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    path = _write_record(state, name, dead_pid)
    record = json.loads(path.read_text(encoding="utf-8"))
    record.pop("kind", None)
    path.write_text(json.dumps(record), encoding="utf-8")

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == [name]


# --- the state directory -----------------------------------------------------


@pytest.mark.integration
def test_a_state_directory_laxer_than_0700_is_tightened_when_it_is_ours(
    state, runtime, dead_pid
):
    stub, _ = runtime
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    _write_record(state, name, dead_pid)
    state.chmod(0o777)

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == [name]
    assert state.stat().st_mode & 0o777 == 0o700


@pytest.mark.integration
def test_a_state_directory_that_is_not_ours_is_not_swept(
    state, runtime, dead_pid, monkeypatch
):
    stub, log = runtime
    record = _write_record(state, f"ash-scan-{dead_pid}-0a1b2c3d", dead_pid)
    state.chmod(0o777)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(state).st_uid + 1)

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert _calls(log) == []
    assert record.exists()
    assert state.stat().st_mode & 0o777 == 0o777, (
        "a directory of someone else's was changed"
    )


@pytest.mark.integration
def test_a_symlinked_state_directory_is_never_followed(
    tmp_path, runtime, dead_pid, monkeypatch
):
    stub, log = runtime
    real = tmp_path / "real-state"
    link = tmp_path / "linked-state"
    record = _write_record(real, f"ash-scan-{dead_pid}-0a1b2c3d", dead_pid)
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(link))

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert _calls(log) == []
    assert record.exists()
    assert container_leftovers.record_container("ash-scan-1-0a1b2c3d") is None
    assert [p.name for p in real.iterdir()] == [record.name]
