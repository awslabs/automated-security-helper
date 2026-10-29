# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container runner that a test starts finds the images its leg built.

tests/conftest.py moves HOME and the XDG directories into a private home for the
session. The CI legs that run the container snapshots build the ``ci`` image outside
pytest, and a rootless podman keeps its image store under XDG_DATA_HOME, so a podman
started with the session's value looks in an empty store. The runtime snapshot modules
start the runner with the developer's values of that variable and of XDG_CONFIG_HOME
instead (tests/utils/runner_state.py). These tests need no runtime: they give the
helper a recorded pre-session environment and read what each runner would be given.
"""

import json
from pathlib import Path

import pytest

from tests.utils.runner_state import RECORD_ENV, developer_runner_env

pytestmark = pytest.mark.unit


def _record(monkeypatch: pytest.MonkeyPatch, record: dict) -> None:
    monkeypatch.setenv(RECORD_ENV, json.dumps(record))


@pytest.mark.parametrize("runner", ["podman", "/usr/bin/podman", "podman.exe"])
def test_podman_gets_the_developers_directories(monkeypatch, runner):
    _record(
        monkeypatch,
        {
            "HOME": "/developer/home",
            "XDG_DATA_HOME": "/developer/data",
            "XDG_CONFIG_HOME": "/developer/config",
        },
    )

    assert developer_runner_env(runner) == {
        "XDG_DATA_HOME": "/developer/data",
        "XDG_CONFIG_HOME": "/developer/config",
    }


def test_podman_gets_the_default_directories_of_a_developer_who_set_none(monkeypatch):
    _record(monkeypatch, {"HOME": "/developer/home"})

    assert developer_runner_env("podman") == {
        "XDG_DATA_HOME": str(Path("/developer/home", ".local", "share")),
        "XDG_CONFIG_HOME": str(Path("/developer/home", ".config")),
    }


@pytest.mark.parametrize("runner", ["docker", "finch", "/usr/local/bin/docker"])
def test_a_runner_that_keeps_its_images_in_a_daemon_gets_nothing(monkeypatch, runner):
    _record(
        monkeypatch,
        {"HOME": "/developer/home", "XDG_DATA_HOME": "/developer/data"},
    )

    assert developer_runner_env(runner) == {}


def test_a_session_that_recorded_nothing_gives_podman_nothing(monkeypatch):
    monkeypatch.delenv(RECORD_ENV, raising=False)

    assert developer_runner_env("podman") == {}
