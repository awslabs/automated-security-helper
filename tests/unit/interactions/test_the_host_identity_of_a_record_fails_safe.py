# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A record is swept only on the host and in the pid space that wrote it.

A creator pid and its start time mean something only inside one boot and one
PID namespace. Linux names both, macOS names the boot session, and where neither
can be read there is no key at all: a record written then carries none, and
matches no host. The key never falls back to a value every record shares, such as
the host name, because that would sweep any record on any host that could not name
itself.

The runtime is a shell stub that logs its arguments; no sysctl is called.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.interactions import container_leftovers


@pytest.fixture
def state(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "ash-state"
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(directory))
    return directory


@pytest.fixture
def dead_pid() -> int:
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid


def _stub(tmp_path: Path) -> Path:
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    return stub


def _calls(tmp_path: Path) -> List[str]:
    log = tmp_path / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _plant(state: Path, pid: int, host: Any) -> Path:
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"ash-scan-{pid}-0a1b2c3d"
    path = state / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "kind": "container",
                "host": host,
                "name": name,
                "creator_pid": pid,
                "creator_start": None,
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
@pytest.mark.unit
def test_linux_names_the_boot_and_the_pid_namespace():
    key = container_leftovers.host_key()

    assert key is not None and key.startswith("linux:")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert boot_id in key
    assert "pid:[" in key, key


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
@pytest.mark.integration
def test_a_record_from_another_pid_namespace_is_left_alone(state, tmp_path, dead_pid):
    stub = _stub(tmp_path)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    record = _plant(state, dead_pid, f"linux:{boot_id}:pid:[1]")

    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert _calls(tmp_path) == []
    assert record.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
@pytest.mark.integration
def test_an_unreadable_boot_id_gives_no_key_and_the_sweep_skips(
    state, tmp_path, dead_pid, monkeypatch
):
    stub = _stub(tmp_path)
    record = _plant(state, dead_pid, container_leftovers.host_key())
    monkeypatch.setattr(container_leftovers, "_BOOT_ID_PATH", tmp_path / "no-boot-id")

    assert container_leftovers.host_key() is None
    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert _calls(tmp_path) == []
    assert record.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
@pytest.mark.integration
def test_a_record_written_with_no_key_matches_no_host_even_one_with_no_key(
    state, tmp_path, dead_pid, monkeypatch
):
    """Two hosts that both cannot name themselves are not the same host."""
    stub = _stub(tmp_path)
    monkeypatch.setattr(container_leftovers, "_BOOT_ID_PATH", tmp_path / "no-boot-id")

    path = container_leftovers.record_container(f"ash-scan-{dead_pid}-0a1b2c3d")

    assert path is not None
    assert json.loads(path.read_text(encoding="utf-8"))["host"] is None
    assert container_leftovers.sweep_leftover_containers([str(stub)]) == []
    assert path.exists()


@pytest.mark.unit
def test_a_platform_with_no_identity_has_no_key(monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")

    assert container_leftovers.host_key() is None


@pytest.mark.unit
def test_macos_names_its_boot_session(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(container_leftovers, "_macos_scope", lambda: "darwin:SESSION")

    assert container_leftovers.host_key() == "darwin:SESSION"


@pytest.mark.unit
def test_a_macos_boot_session_that_cannot_be_read_gives_no_key(monkeypatch):
    import ctypes

    def refuse(*args, **kwargs):
        raise OSError("no libc here")

    monkeypatch.setattr(ctypes, "CDLL", refuse)

    assert container_leftovers._macos_scope() is None
