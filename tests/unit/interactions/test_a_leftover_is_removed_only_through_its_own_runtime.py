# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded container is removed only through the runtime it was started under.

``rm -f`` against another runtime or another daemon answers "no such container",
which is not the same as the container being gone: it may be running there. A
record therefore keeps the runtime it was started with and the environment that
picks the daemon, and a later start whose runtime differs leaves the record alone.
A record with none of that (an older one) can be tried, but only success drops
it, never "no such container". Any record past the age bound is forgotten without
asking a runtime anything.

The runtimes are shell stubs under ``tmp_path`` that log their arguments; the
age cells replace the removal step with a counter.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.interactions import container_leftovers
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the runtime stub is a POSIX shell script"
)

_SECRET_A = "tcp://operator:hunter2-alpha@daemon-a.invalid:2376"
_SECRET_B = "tcp://operator:hunter2-bravo@daemon-b.invalid:2376"


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def logged():
    handler = _Lines()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


@pytest.fixture
def state(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "ash-state"
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(directory))
    for key in container_leftovers._daemon_environment():
        monkeypatch.delenv(key, raising=False)
    return directory


@pytest.fixture
def dead_pid() -> int:
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid


def _runtime(tmp_path: Path, *, says: str = "", code: int = 0) -> Path:
    """A stub that logs its arguments, prints ``says`` and exits ``code``."""
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(
        f'#!/bin/sh\necho "$@" >> "{log}"\necho "{says}" >&2\nexit {code}\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub


def _calls(tmp_path: Path) -> List[str]:
    log = tmp_path / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _plant(state: Path, pid: int, **fields: Any) -> Path:
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"ash-scan-{pid}-0a1b2c3d"
    record: Dict[str, Any] = {
        "kind": "container",
        "host": container_leftovers.host_key(),
        "name": name,
        "creator_pid": pid,
        "creator_start": None,
    }
    record.update(fields)
    path = state / f"{name}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _known(stub: Path, **overrides: Any) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        "created": container_leftovers._now(),
        "runtime": str(stub),
        "runner_argv": [],
        "daemon_env": dict.fromkeys(container_leftovers._daemon_environment()),
    }
    fields.update(overrides)
    return fields


@pytest.mark.unit
def test_a_record_keeps_its_runtime_and_the_daemon_environment(state, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", _SECRET_A)

    path = container_leftovers.record_container(
        "ash-scan-1-0a1b2c3d", ["sudo", "-n", "/opt/bin/docker"]
    )

    assert path is not None
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["runtime"] == "/opt/bin/docker"
    assert record["runner_argv"] == ["sudo", "-n"]
    # Every setting a runtime client picks its daemon from, with the one that
    # is set carried as set. The key set is spelled out here rather than read
    # from _daemon_environment, which this record was written from: compared
    # with itself, a key dropped from the product would drop from the
    # expectation too and the test would still pass.
    assert set(record["daemon_env"]) == {
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "docker_config_current_context",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "podman_default_connection",
        "CONTAINERD_ADDRESS",
        "CONTAINERD_NAMESPACE",
    }
    assert record["daemon_env"]["DOCKER_HOST"] == _SECRET_A
    assert record["daemon_env"]["DOCKER_CONTEXT"] is None
    assert record["daemon_env"]["CONTAINER_HOST"] is None
    assert isinstance(record["created"], float)


@pytest.mark.parametrize("different", ["runtime", "runner_argv", "DOCKER_HOST"])
@pytest.mark.integration
def test_a_record_started_under_another_runtime_is_left_with_its_container(
    state, tmp_path, dead_pid, monkeypatch, different
):
    stub = _runtime(tmp_path)
    fields = _known(stub)
    if different == "runtime":
        fields["runtime"] = "/somewhere/else/podman"
    elif different == "runner_argv":
        fields["runner_argv"] = ["sudo"]
    else:
        fields["daemon_env"] = dict(fields["daemon_env"], DOCKER_HOST=_SECRET_A)
    record = _plant(state, dead_pid, **fields)

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == []
    assert _calls(tmp_path) == [], (
        "the container was asked about through the wrong runtime"
    )
    assert record.exists(), "a record for another runtime's container was dropped"


@pytest.mark.integration
def test_a_record_started_under_this_runtime_is_removed(state, tmp_path, dead_pid):
    """The control: the same record with nothing different is swept."""
    stub = _runtime(tmp_path)
    record = _plant(state, dead_pid, **_known(stub))

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == [f"ash-scan-{dead_pid}-0a1b2c3d"]
    assert not record.exists()


@pytest.mark.integration
def test_a_runtime_that_has_no_such_container_still_drops_a_matching_record(
    state, tmp_path, dead_pid
):
    stub = _runtime(tmp_path, says="Error: No such container: x", code=1)
    record = _plant(state, dead_pid, **_known(stub))

    # The record is dropped on its own runtime's word, and nothing was removed
    # to report: a container the runtime never had is not in the names returned.
    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert not record.exists()


@pytest.mark.integration
def test_the_reason_names_the_key_and_never_a_value(
    state, tmp_path, dead_pid, monkeypatch, logged
):
    stub = _runtime(tmp_path)
    monkeypatch.setenv("DOCKER_HOST", _SECRET_B)
    fields = _known(stub)
    fields["daemon_env"] = dict(fields["daemon_env"], DOCKER_HOST=_SECRET_A)
    _plant(state, dead_pid, **fields)

    container_leftovers.sweep_leftover_containers([str(stub)])

    text = "\n".join(logged.messages)
    assert "DOCKER_HOST" in text, logged.messages
    assert "hunter2" not in text and "daemon-" not in text, logged.messages


@pytest.mark.integration
def test_an_older_record_is_tried_and_kept_when_the_runtime_has_no_such_container(
    state, tmp_path, dead_pid
):
    """No runtime fields: it may be another runtime's container, so 'no such
    container' proves nothing and the record stays."""
    stub = _runtime(tmp_path, says="Error: No such container: x", code=1)
    record = _plant(state, dead_pid, created=container_leftovers._now())

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == []
    assert len(_calls(tmp_path)) == 1, "an older record is tried"
    assert record.exists()


@pytest.mark.integration
def test_an_older_record_is_dropped_when_the_runtime_removed_the_container(
    state, tmp_path, dead_pid
):
    stub = _runtime(tmp_path)
    record = _plant(state, dead_pid, created=container_leftovers._now())

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == [f"ash-scan-{dead_pid}-0a1b2c3d"]
    assert not record.exists()


@pytest.mark.integration
def test_a_record_past_the_age_bound_is_forgotten_without_asking_a_runtime(
    state, tmp_path, dead_pid, monkeypatch
):
    asked: List[str] = []

    def counted(runner_command, name):
        asked.append(name)
        return True

    monkeypatch.setattr(container_leftovers, "_removed", counted)
    stub = _runtime(tmp_path)
    old = container_leftovers._now() - container_leftovers.RECORD_MAX_AGE_SECONDS - 60
    aged = _plant(state, dead_pid, **_known(stub, created=old))

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == []
    assert asked == [], "an aged-out record reached the runtime"
    assert not aged.exists(), "the aged-out record was not forgotten"
    assert _calls(tmp_path) == []


@pytest.mark.integration
def test_a_foreign_hosts_record_past_the_age_bound_is_forgotten_too(
    state, tmp_path, dead_pid
):
    stub = _runtime(tmp_path)
    old = container_leftovers._now() - container_leftovers.RECORD_MAX_AGE_SECONDS - 60
    aged = _plant(state, dead_pid, **_known(stub, created=old, host="another-boot"))

    assert container_leftovers.leftover_records() == []
    assert not aged.exists()
    assert _calls(tmp_path) == []


@pytest.mark.integration
def test_a_record_with_no_creation_time_is_aged_by_its_file(
    state, tmp_path, dead_pid, monkeypatch
):
    stub = _runtime(tmp_path)
    record = _plant(state, dead_pid)
    long_ago = (
        container_leftovers._now() - container_leftovers.RECORD_MAX_AGE_SECONDS - 60
    )
    os.utime(record, (long_ago, long_ago))

    container_leftovers.sweep_leftover_containers([str(stub)])

    assert not record.exists()
    assert _calls(tmp_path) == []
