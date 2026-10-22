# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --mode container`` takes the ASH_BASE_IMAGE_OVERRIDE values the wrappers take.

./ash and Invoke-ASH hold ASH_BASE_IMAGE_OVERRIDE to the image-name characters, A-Z,
a-z, 0-9 and . _ : / @ -, not starting with '-', and refuse anything else with 3
before anything is built. Container mode applies the same check to the value
before it goes into the build's BASE_IMAGE build argument, with the wrappers'
message and code. An empty or unset override still redirects nothing.

Only the build command the runner would be given is recorded: run_cmd_direct is
replaced, so no runner is called.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.unit.interactions.test_container_image_name_is_held_to_the_wrappers_pattern import (
    _read_back,
    _shown_in_refusal,
)
from tests.unit.test_powershell_wrapper_matches_ash import (
    REFUSAL_EXIT,
    _BASE_IMAGE_OVERRIDES,
    _IMAGE_NAMES,
)

SCAN = [
    "scan",
    "--mode",
    "container",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

#: The refusal both wrappers give, up to the value.
REFUSAL_TEXT = "ASH_BASE_IMAGE_OVERRIDE '"

#: The wrappers' own cells: their image-name list, which the override is held to as
#: well, and their override list.
_CELLS = {
    **{f"image-name-{name}": cell for name, cell in _IMAGE_NAMES.items()},
    **{f"override-{name}": cell for name, cell in _BASE_IMAGE_OVERRIDES.items()},
}


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Every call that would reach an OCI runtime, replaced by a recorder."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    seen: Dict[str, Any] = {"builds": [], "runs": []}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda _rev: dockerfile)

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        seen["builds"].append(list(cmd_list))
        return create_completed_process(args=list(cmd_list), returncode=0)

    def fake_execute(cmd, debug=False, env=None):
        seen["runs"].append(list(cmd))
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in (
        "CI",
        "IsCI",
        "ISCI",
        "CODEBUILD_BUILD_ID",
        "ASH_IMAGE_NAME",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_BASE_OCI_LAYOUT",
        "ACTIONS_RUNTIME_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_DISABLE_GHA_BUILD_CACHE", "1")
    return seen


def _base_image_args(command: list[str]) -> list[str]:
    return [
        value
        for option, value in zip(command, command[1:])
        if option == "--build-arg" and value.startswith("BASE_IMAGE=")
    ]


@pytest.mark.parametrize("cell", sorted(_CELLS))
def test_container_mode_splits_the_overrides_as_the_wrappers_do(
    runtime, monkeypatch, cell
):
    override, code = _CELLS[cell]
    monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", override)

    result = CliRunner().invoke(app, SCAN)

    if code == REFUSAL_EXIT:
        assert result.exit_code == REFUSAL_EXIT, result.output
        assert REFUSAL_TEXT in result.output, result.output
        assert runtime["builds"] == [] and runtime["runs"] == [], runtime
    else:
        assert REFUSAL_TEXT not in result.output, result.output
        assert len(runtime["builds"]) == 1, runtime
        assert _base_image_args(runtime["builds"][0]) == [f"BASE_IMAGE={override}"], (
            runtime["builds"][0]
        )


@pytest.mark.parametrize(
    "override",
    [" ", "\t", "\n", "  \n"],
    ids=["space", "tab", "newline", "spaces-and-newline"],
)
def test_a_blank_override_is_refused_as_the_wrappers_refuse_it(
    runtime, monkeypatch, override
):
    """Only whitespace is not an image reference, so it is refused, not read as unset.

    Both wrappers refuse it. Only an empty value means no override.
    """
    monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", override)

    result = CliRunner().invoke(app, SCAN)

    assert result.exit_code == REFUSAL_EXIT, result.output
    assert REFUSAL_TEXT in result.output, result.output
    assert runtime["builds"] == [] and runtime["runs"] == [], runtime


@pytest.mark.parametrize(
    "override",
    [" ", "\t", "\n", "  \n", "a\tb"],
    ids=["space", "tab", "newline", "spaces-and-newline", "tab-inside"],
)
def test_a_refused_override_is_shown_on_one_line(runtime, monkeypatch, override):
    """A space and a tab are shown apart, and a newline does not break the line.

    secho writes a tab and a newline as they are; the refusal shows the whole
    message with shown_on_one_line, which writes them as \\x09 and \\x0a, so it
    stays one line and reads back to the value.
    """
    monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", override)

    result = CliRunner().invoke(app, SCAN)

    assert result.exit_code == REFUSAL_EXIT, result.output
    shown = _shown_in_refusal(result.output, REFUSAL_TEXT, "' starts with '-'")
    assert _read_back(shown) == override, shown


@pytest.mark.parametrize("override", [None, ""], ids=["unset", "empty"])
def test_no_override_redirects_nothing(runtime, monkeypatch, override):
    if override is not None:
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", override)

    result = CliRunner().invoke(app, SCAN)

    assert REFUSAL_TEXT not in result.output, result.output
    assert len(runtime["builds"]) == 1, runtime
    assert _base_image_args(runtime["builds"][0]) == [], runtime["builds"][0]
