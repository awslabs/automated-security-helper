# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash dependencies install`` prints, and exits with, for an unknown ``--tool``.

The refusal comes after the command has announced the host platform, so the platform
is pinned. Each platform the installer names is rendered on every OS, so a change to
any one of those lines shows up wherever the suite runs.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli import dependencies


@pytest.mark.parametrize(
    "platform_name, arch",
    [
        pytest.param("linux", "amd64", id="linux-amd64"),
        pytest.param("darwin", "arm64", id="darwin-arm64"),
        pytest.param("windows", "amd64", id="windows-amd64"),
    ],
)
def test_unknown_tool(run_cli, snapshot, monkeypatch, tmp_path, platform_name, arch):
    # The two lookups the message is built from, and not platform.system itself:
    # patching that would make every other part of the process act as if it ran on
    # that OS too.
    monkeypatch.setattr(dependencies, "get_platform", lambda: platform_name)
    monkeypatch.setattr(dependencies, "get_architecture", lambda: arch)
    # The command exports ASH_BIN_PATH into os.environ. Setting it through
    # monkeypatch first means the export is undone after the test. Absolute, as
    # the export is: a lookup ignores a relative ASH_BIN_PATH, with a warning.
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    # The panel shows --bin-path as given ("bin"), so its width does not depend on the
    # working directory. No display-only cwd: the command creates the bin directory at
    # os.path.abspath(--bin-path), which reads os.getcwd(), so a patched cwd would
    # send that mkdir outside the test's tmp_path.
    result = run_cli(["dependencies", "install", "--bin-path", "bin", "--tool", "gryp"])
    assert result == snapshot
