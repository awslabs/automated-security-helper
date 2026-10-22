# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash dependencies install`` prints, and exits with, for an unknown ``--tool``.

The refusal comes after the command has announced the host platform, so the platform
is pinned. Each platform the installer names is rendered on every OS, so a change to
any one of those lines shows up wherever the suite runs.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.cli import dependencies
from tests.snapshot.support.cli import DISPLAYED_CWD, displayed_cwd


@pytest.mark.parametrize(
    "platform_name, arch",
    [
        pytest.param("linux", "amd64", id="linux-amd64"),
        pytest.param("darwin", "arm64", id="darwin-arm64"),
        pytest.param("windows", "amd64", id="windows-amd64"),
    ],
)
def test_unknown_tool(
    run_cli, snapshot, snapshot_normalizer, monkeypatch, platform_name, arch
):
    # The two lookups the message is built from, and not platform.system itself:
    # patching that would make every other part of the process act as if it ran on
    # that OS too.
    monkeypatch.setattr(dependencies, "get_platform", lambda: platform_name)
    monkeypatch.setattr(dependencies, "get_architecture", lambda: arch)
    # The command exports ASH_BIN_PATH into os.environ. Setting it through
    # monkeypatch first means the export is undone after the test.
    monkeypatch.setenv("ASH_BIN_PATH", "bin")
    # The panel prints the bin path absolute; displayed_cwd keeps its length, and so
    # the panel's width, the same on every machine.
    for spelling in (PurePosixPath(DISPLAYED_CWD), PureWindowsPath(DISPLAYED_CWD)):
        snapshot_normalizer.add_root(spelling, "WORKSPACE")
    with displayed_cwd(monkeypatch):
        result = run_cli(
            ["dependencies", "install", "--bin-path", "bin", "--tool", "gryp"]
        )
    assert result == snapshot
