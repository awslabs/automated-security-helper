# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SIGKILL strands the private directories a run made; the next start sweeps them.

Two kinds of directory, found by name prefix under every place one can be: the
env-file directory (empty once its file is unlinked, holding the env file for a
runtime that reads it by path) and the docker config copy (a 0600 config.json and
symlinks into the real config directory). A directory is deleted when it is this
user's, mode 0700, and either older than the age bound or recorded by a creator
that is gone. It is left when it is unrecorded and younger than the bound, when
its creator is alive, when it is not 0700, or when its name has another prefix.
What is in it is never read or logged.

Nothing here starts a process: the directories are planted under ``tmp_path``.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.interactions import container_leftovers
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = [
    pytest.mark.skipif(
        sys.platform == "win32", reason="records and directory descriptors are POSIX"
    ),
    pytest.mark.usefixtures("tempfile_reads_this_tests_tmpdir"),
]


_CANARY = "operator-value-canary-7731"
_PREFIXES = ("ash-container-env-", "ash-container-docker-")


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
def parents(tmp_path, monkeypatch):
    """Two different places a private directory can be: ``$TMPDIR`` and a listed one."""
    first = tmp_path / "tmpdir"
    second = tmp_path / "listed"
    first.mkdir()
    second.mkdir()
    monkeypatch.setenv("TMPDIR", str(first))
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", (str(second),))
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "ash-state"))
    return first, second


@pytest.fixture
def dead_pid() -> int:
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid


def _private_dir(parent: Path, name: str, *, mode: int = 0o700, outside=None) -> Path:
    """A directory holding a file with a canary, and a symlink to ``outside``."""
    directory = parent / name
    directory.mkdir(mode=mode)
    directory.chmod(mode)
    (directory / "env").write_text(f"NAME={_CANARY}\n", encoding="utf-8")
    nested = directory / "nested"
    nested.mkdir()
    (nested / "config.json").write_text(_CANARY, encoding="utf-8")
    if outside is not None:
        (directory / "linked").symlink_to(outside)
    return directory


def _age(path: Path, seconds: float) -> None:
    then = container_leftovers._now() - seconds
    os.utime(path, (then, then))


def _past_the_bound() -> float:
    return container_leftovers.RECORD_MAX_AGE_SECONDS + 3600


def _record(tmp_path: Path, directory: Path, pid: int) -> Path:
    state = tmp_path / "ash-state"
    state.mkdir(exist_ok=True, mode=0o700)
    path = state / f"ash-envdir-{directory.name}.json"
    path.write_text(
        json.dumps(
            {
                "kind": "env-dir",
                "host": container_leftovers.host_key(),
                "dir": str(directory),
                "creator_pid": pid,
                "creator_start": None,
                "created": container_leftovers._now(),
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.integration
def test_a_recorded_directory_of_each_prefix_under_two_parents_is_swept(
    parents, tmp_path, dead_pid
):
    outside = tmp_path / "real-docker-config.json"
    outside.write_text(_CANARY, encoding="utf-8")
    planted = []
    for place, parent in enumerate(parents):
        for index, prefix in enumerate(_PREFIXES):
            directory = _private_dir(
                parent, f"{prefix}ab{place}{index}cd", outside=outside
            )
            planted.append((directory, _record(tmp_path, directory, dead_pid)))

    removed = container_leftovers.sweep_env_dirs()

    assert sorted(removed) == sorted(d.name for d, _ in planted), removed
    for directory, record in planted:
        assert not directory.exists(), directory
        assert not record.exists(), record
    assert outside.read_text(encoding="utf-8") == _CANARY, "a symlink was followed"


@pytest.mark.unit
def test_an_unrecorded_directory_past_the_age_bound_is_swept(parents):
    old = [
        _private_dir(parent, f"{prefix}old00001")
        for parent in parents
        for prefix in _PREFIXES
    ]
    for directory in old:
        _age(directory, _past_the_bound())

    removed = container_leftovers.sweep_env_dirs()

    assert sorted(removed) == sorted(d.name for d in old)
    assert not any(d.exists() for d in old)


@pytest.mark.unit
def test_an_unrecorded_directory_younger_than_the_bound_is_left(parents):
    young = [
        _private_dir(parent, f"{prefix}young001")
        for parent in parents
        for prefix in _PREFIXES
    ]

    assert container_leftovers.sweep_env_dirs() == []
    assert all(d.exists() for d in young)


@pytest.mark.unit
def test_a_directory_with_another_prefix_is_left_however_old(parents):
    other = _private_dir(parents[0], "other-prefix-old00001")
    lookalike = _private_dir(parents[1], "xash-container-env-old00001")
    for directory in (other, lookalike):
        _age(directory, _past_the_bound())

    assert container_leftovers.sweep_env_dirs() == []
    assert other.exists() and lookalike.exists()


@pytest.mark.unit
def test_a_recorded_directory_whose_creator_is_alive_is_left(parents, tmp_path):
    directory = _private_dir(parents[0], f"{_PREFIXES[0]}live0001")
    record = _record(tmp_path, directory, os.getpid())

    assert container_leftovers.sweep_env_dirs() == []
    assert directory.exists() and record.exists()


@pytest.mark.unit
def test_a_directory_that_is_not_mode_0700_is_left(parents):
    loose = _private_dir(parents[0], f"{_PREFIXES[0]}loose001", mode=0o755)
    _age(loose, _past_the_bound())

    assert container_leftovers.sweep_env_dirs() == []
    assert loose.exists()


@pytest.mark.unit
def test_a_symlink_with_a_prefix_name_is_not_followed(parents, tmp_path):
    target = _private_dir(tmp_path, "somewhere-else-0001")
    _age(target, _past_the_bound())
    (parents[0] / f"{_PREFIXES[0]}link0001").symlink_to(
        target, target_is_directory=True
    )

    assert container_leftovers.sweep_env_dirs() == []
    assert target.exists() and (target / "env").exists()


@pytest.mark.integration
def test_a_record_naming_a_place_that_is_not_searched_is_ignored(
    parents, tmp_path, dead_pid
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    directory = _private_dir(elsewhere, f"{_PREFIXES[0]}else0001")
    _record(tmp_path, directory, dead_pid)

    assert container_leftovers.sweep_env_dirs() == []
    assert directory.exists()


@pytest.mark.integration
def test_a_record_whose_directory_is_gone_is_dropped(parents, tmp_path, dead_pid):
    gone = parents[0] / f"{_PREFIXES[0]}gone0001"
    record = _record(tmp_path, gone, dead_pid)

    assert container_leftovers.sweep_env_dirs() == []
    assert not record.exists()


@pytest.mark.integration
def test_what_is_in_a_directory_is_never_logged(parents, tmp_path, dead_pid, logged):
    directory = _private_dir(parents[0], f"{_PREFIXES[0]}logged001")
    _record(tmp_path, directory, dead_pid)
    unreadable = _private_dir(parents[1], f"{_PREFIXES[1]}logged002", mode=0o755)
    _age(unreadable, _past_the_bound())

    container_leftovers.sweep_env_dirs()

    text = "\n".join(logged.messages)
    assert _CANARY not in text, logged.messages
    assert "nested" not in text and "config.json" not in text, logged.messages


@pytest.mark.unit
def test_the_directories_are_swept_before_the_clear_in_nix_mode(
    parents, tmp_path, monkeypatch
):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    stranded = _private_dir(parents[0], f"{_PREFIXES[0]}order001")
    _age(stranded, _past_the_bound())
    seen: List[bool] = []
    source = tmp_path / "src"
    source.mkdir()

    class Stop(Exception):
        pass

    def clear(opts, logger):
        seen.append(stranded.exists())

    def shell(**kwargs):
        raise Stop

    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", clear)
    monkeypatch.setattr(run_ash_scan, "run_ash_nix", shell)
    monkeypatch.setattr(run_ash_scan, "nix_preflight", lambda: None)
    monkeypatch.setattr(run_ash_scan, "sweep_leftovers_before_run", lambda runner: [])
    opts = run_ash_scan.ScanOptions(
        source_dir=source, output_dir=tmp_path / "out", mode=RunMode.nix
    )

    with pytest.raises(Stop):
        run_ash_scan._run_nix_mode(opts, MagicMock())

    assert seen == [False], "the clear ran while the stranded directory still existed"


@pytest.mark.unit
def test_the_directories_are_swept_before_the_clear_in_container_mode(
    parents, tmp_path, monkeypatch
):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    stranded = _private_dir(parents[1], f"{_PREFIXES[1]}order002")
    _age(stranded, _past_the_bound())
    seen: List[bool] = []
    source = tmp_path / "src"
    source.mkdir()

    class Stop(Exception):
        pass

    def clear(opts, logger):
        seen.append(stranded.exists())

    def first_run(**kwargs):
        raise Stop

    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", clear)
    monkeypatch.setattr(run_ash_scan, "run_ash_container", first_run)
    monkeypatch.setattr(run_ash_scan, "sweep_leftovers_before_run", lambda runner: [])
    opts = run_ash_scan.ScanOptions(
        source_dir=source,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        build=False,
        run=True,
    )

    with pytest.raises(Stop):
        run_ash_scan._run_container_mode(opts, MagicMock())

    assert seen == [False], "the clear ran while the stranded directory still existed"
