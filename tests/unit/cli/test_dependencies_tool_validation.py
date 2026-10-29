# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--tool`` names are checked before any plugin is built.

The installer built every plugin first and checked the names afterwards. Building
bandit, checkov, semgrep and the jupyter converter probes their version with
``uv tool run --from <requirement> <tool> --version``, which resolves and
downloads each tool's environment: ``ash dependencies install --tool <typo>``
downloaded about 312 MB into uv's cache and then refused the name.

Every test here records each uv command the runner would start instead of
starting it, with uv reported available so the probes are reachable.
"""

from __future__ import annotations

import io
import subprocess

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies
from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    EXIT_INSTALL_FAILED,
    dependencies_app,
)
from automated_security_helper.utils import uv_tool_runner

pytestmark = pytest.mark.unit

runner = CliRunner()


class _Calls(list):
    """The uv and install commands seen, plus the installer's panel output."""

    panels: io.StringIO


@pytest.fixture
def uv_calls(tmp_path, monkeypatch):
    calls = _Calls()

    def _spawn(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "stand-in uv")

    uv_tool_runner._reset_uv_tool_runner_caches()
    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn)
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: True
    )
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: calls.append(cmd) or 0
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(tmp_path)
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=300, no_color=True)
    )
    calls.panels = panels
    yield calls
    uv_tool_runner._reset_uv_tool_runner_caches()


def _invoke(tmp_path, *tools):
    args = ["--bin-path", str(tmp_path / "bin")]
    for tool in tools:
        args += ["--tool", tool]
    return runner.invoke(dependencies_app, args)


def test_an_unknown_tool_is_refused_before_any_plugin_probes_uv(uv_calls, tmp_path):
    result = _invoke(tmp_path, "definitely-not-a-tool")
    assert result.exit_code == EXIT_BAD_SELECTION, result.output
    assert uv_calls == [], (
        "uv ran before the unknown --tool name was refused; each of these resolves "
        f"and downloads a tool environment: {uv_calls}"
    )
    printed = uv_calls.panels.getvalue()
    assert "Unknown tool(s): definitely-not-a-tool" in printed
    # The list of valid names is still complete without building anything.
    for name in ("bandit", "cdk-nag", "grype", "jupyter", "sarif", "archive"):
        assert name in printed


def test_one_unknown_name_among_known_ones_is_refused_the_same_way(uv_calls, tmp_path):
    result = _invoke(tmp_path, "grype", "gryp")
    assert result.exit_code == EXIT_BAD_SELECTION, result.output
    assert uv_calls == []


@pytest.mark.parametrize(
    "selection",
    [
        pytest.param(["--tool", "definitely-not-a-tool"], id="a-tool-no-plugin-has"),
        pytest.param(
            ["--tool", "grype", "--tool", "definitely-not-a-tool"],
            id="a-known-tool-beside-an-unknown-one",
        ),
        pytest.param(
            ["--plugin-type", "reporter", "--tool", "grype"], id="a-type-left-out"
        ),
    ],
)
def test_a_tool_it_cannot_select_exits_2(uv_calls, tmp_path, selection):
    """The number itself, not EXIT_BAD_SELECTION: 2 is the code the CLI reference
    documents for a ``--tool`` this command cannot select, and the other usage
    errors' 5 is not."""
    result = runner.invoke(
        dependencies_app, ["--bin-path", str(tmp_path / "bin"), *selection]
    )
    assert result.exit_code == 2, result.output
    assert uv_calls == [], uv_calls
    assert "Nothing installed" in uv_calls.panels.getvalue()


def test_a_known_tool_builds_its_plugin(uv_calls, tmp_path):
    """Positive control: the recorder does see uv when bandit is built and installed.

    Building the plugin does not probe the tool's version (that waits for the
    dependency check), so the call it sees is bandit's install.
    """
    _invoke(tmp_path, "bandit")
    assert any(
        call[1:3] == ["tool", "install"] and any("bandit" in part for part in call)
        for call in uv_calls
        if isinstance(call, list)
    ), uv_calls


def test_a_requested_plugin_that_will_not_build_fails_the_run_by_name(
    uv_calls, tmp_path, monkeypatch
):
    """A name that exists but whose plugin raises is an install failure, not a typo."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    def _boom(self, context):
        raise RuntimeError("grype stand-in will not build")

    monkeypatch.setattr(GrypeScanner, "model_post_init", _boom)
    result = _invoke(tmp_path, "grype")
    assert result.exit_code == EXIT_INSTALL_FAILED, result.output
    printed = uv_calls.panels.getvalue()
    assert "Unknown tool" not in printed
    assert "GrypeScanner" in printed


def test_only_the_requested_plugin_is_built(uv_calls, tmp_path):
    """``--tool grype`` builds, and so probes, none of bandit, checkov and semgrep."""
    _invoke(tmp_path, "grype")
    probes = [c for c in uv_calls if isinstance(c, list) and c[1:3] == ["tool", "run"]]
    assert probes == [], probes


class _ResolvedConfig:
    """A resolved config whose plugin sections are given, or raise."""

    def __init__(self, section=None, error=None):
        self.section = section
        self.error = error
        self.asked = []

    def get_plugin_config(self, plugin_type, plugin_name):
        self.asked.append((plugin_type, plugin_name))
        if self.error is not None:
            raise self.error
        return self.section


class _Section:
    def __init__(self, name):
        self.name = name


@pytest.mark.parametrize(
    "section, expected",
    [
        pytest.param({"name": "renamed"}, "renamed", id="dict-section"),
        pytest.param(_Section("renamed"), "renamed", id="model-section"),
        pytest.param({"name": ""}, "grype", id="empty-name"),
        pytest.param({"name": None}, "grype", id="null-name"),
        pytest.param({}, "grype", id="no-name"),
        pytest.param(None, "grype", id="no-section"),
    ],
)
def test_the_configured_name_is_what_tool_selects(section, expected):
    """A plugin's section may rename it; --tool then selects it by that name.

    Not reachable through a bundled plugin, whose config declares its name as a
    Literal, so the section is a stand-in here; a third-party plugin's config can
    carry a free-form name.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    config = _ResolvedConfig(section=section)
    name = dependencies._declared_install_name(GrypeScanner, "scanner", config)
    assert name == expected
    assert config.asked == [("scanner", "grype")]


def test_an_unreadable_section_falls_back_to_the_declared_name():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    config = _ResolvedConfig(error=ValueError("bad section"))
    assert dependencies._declared_install_name(GrypeScanner, "scanner", config) == (
        "grype"
    )
