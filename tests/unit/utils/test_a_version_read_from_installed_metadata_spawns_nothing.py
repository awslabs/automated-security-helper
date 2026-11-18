# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool that opts in has its version read from its environment's metadata.

``checkov --version`` imports checkov's framework before printing, about 1.9 s
warm, and the probe is paid on every hook run where checkov scans. The
``.dist-info`` of the environment uv installed it into answers without starting
the tool. These tests pin the two halves of that: the metadata answer is used
and nothing is spawned, and every case that cannot be answered from metadata
(the health check, no installed environment, a version the spec would not
resolve to, extras, a plugin that did not opt in) runs the real probe as before.

The fake uv tools directory is built in ``tmp_path`` and ``spawn_run`` is
replaced by a recorder, so a spawn is seen as an entry in ``spawned``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

_SPEC = "zz-tool>=9.0.0,<10.0.0"


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def _install(tools_dir: Path, tool: str, version: str, dist: str | None = None):
    """Lay out ``<tools>/<tool>/lib/python3.12/site-packages/<dist>-<version>.dist-info``."""
    dist = dist or tool
    info = (
        tools_dir
        / tool
        / "lib"
        / "python3.12"
        / "site-packages"
        / f"{dist.replace('-', '_')}-{version}.dist-info"
    )
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n",
        encoding="utf-8",
    )


@pytest.fixture
def tools_dir(tmp_path, monkeypatch):
    path = tmp_path / "uv-tools"
    path.mkdir()
    monkeypatch.setenv("UV_TOOL_DIR", str(path))
    return path


@pytest.fixture
def spawned(monkeypatch):
    """The commands the probe spawned; the stub answers like ``<tool> --version``."""
    commands: list = []

    def recording_spawn(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="9.1.1\n", stderr="")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", recording_spawn)
    return commands


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    built = UVToolRunner()
    built.uv_executable = "/zz-fake/uv"
    return built


def test_the_metadata_answer_is_used_and_no_probe_is_spawned(
    runner, tools_dir, spawned
):
    _install(tools_dir, "zz-tool", "9.4.2")
    outcome: dict = {}

    version = runner.get_tool_version(
        "zz-tool", _SPEC, from_metadata=True, probe_outcome=outcome
    )

    assert version == "9.4.2"
    assert spawned == [], f"the tool was started: {spawned}"
    assert outcome["from_metadata"] is True
    assert outcome["ran"] is False


def test_the_health_check_still_runs_the_tool(runner, tools_dir, spawned):
    """``refresh=True`` is ``validate_cached_tool``'s call: it decides a reinstall."""
    _install(tools_dir, "zz-tool", "9.4.2")
    outcome: dict = {}

    version = runner.get_tool_version(
        "zz-tool", _SPEC, refresh=True, from_metadata=True, probe_outcome=outcome
    )

    assert len(spawned) == 1
    assert spawned[0][-2:] == ["zz-tool", "--version"]
    assert version == "9.1.1"
    assert outcome["ran"] is True
    assert "from_metadata" not in outcome


def test_validate_cached_tool_runs_the_tool_for_a_tool_that_opted_in(
    runner, tools_dir, spawned
):
    _install(tools_dir, "zz-tool", "9.4.2")

    result = runner.validate_cached_tool("zz-tool", _SPEC)

    assert len(spawned) == 1
    assert result["probed"] is True
    assert result["is_functional"] is True


def test_a_caller_that_did_not_opt_in_still_probes(runner, tools_dir, spawned):
    _install(tools_dir, "zz-tool", "9.4.2")

    assert runner.get_tool_version("zz-tool", _SPEC) == "9.1.1"
    assert len(spawned) == 1


@pytest.mark.parametrize(
    "installed_version",
    ["10.0.0", "8.9.9"],
)
def test_a_version_the_spec_would_not_resolve_to_is_probed(
    runner, tools_dir, spawned, installed_version
):
    """``uv tool run --from <spec>`` would build another environment, so the
    installed one's metadata is not the probe's answer."""
    _install(tools_dir, "zz-tool", installed_version)

    assert runner.get_tool_version("zz-tool", _SPEC, from_metadata=True) == "9.1.1"
    assert len(spawned) == 1


def test_no_installed_environment_falls_back_to_the_probe(runner, tools_dir, spawned):
    assert runner.get_tool_version("zz-tool", _SPEC, from_metadata=True) == "9.1.1"
    assert len(spawned) == 1


def test_a_spec_with_extras_falls_back_to_the_probe(runner, tools_dir, spawned):
    _install(tools_dir, "zz-tool", "9.4.2")

    version = runner.get_tool_version(
        "zz-tool", "zz-tool[sarif]>=9.0.0,<10.0.0", from_metadata=True
    )

    assert version == "9.1.1"
    assert len(spawned) == 1


def test_a_python_request_falls_back_to_the_probe(runner, tools_dir, spawned):
    """``--python`` selects another environment than the installed one."""
    _install(tools_dir, "zz-tool", "9.4.2")

    version = runner.get_tool_version(
        "zz-tool", _SPEC, from_metadata=True, python_request=">=3.10,<3.14"
    )

    assert version == "9.1.1"
    assert len(spawned) == 1


def test_an_unreadable_distribution_falls_back_to_the_probe(runner, tools_dir, spawned):
    """A distribution under another name is no answer for this tool."""
    _install(tools_dir, "zz-tool", "9.4.2", dist="zz-other")

    assert runner.get_tool_version("zz-tool", _SPEC, from_metadata=True) == "9.1.1"
    assert len(spawned) == 1


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def test_checkov_opts_in_and_the_mixin_passes_it_to_the_runner(context):
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as get_runner:
        fake = MagicMock()
        fake.is_uv_available.return_value = True
        fake.get_tool_version.return_value = "3.4.5"
        get_runner.return_value = fake

        version = scanner._get_uv_tool_version("checkov")

    assert version == "3.4.5"
    assert fake.get_tool_version.call_args.kwargs["from_metadata"] is True


def test_bandit_keeps_its_probe(context):
    """Bandit loads stevedore plugins: its probe is what warms their cache."""
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as get_runner:
        fake = MagicMock()
        fake.is_uv_available.return_value = True
        fake.get_tool_version.return_value = "1.7.9"
        get_runner.return_value = fake

        scanner._get_uv_tool_version("bandit")

    assert "from_metadata" not in fake.get_tool_version.call_args.kwargs
