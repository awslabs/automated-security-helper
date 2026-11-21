# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The dependency check's version read honors a plugin's metadata opt-in (#955).

A scanner that opts in through ``UVToolMixin._tool_version_from_metadata`` has its
version read from the installed environment's ``.dist-info`` instead of by starting
the tool. The scan's own version read (``resolve_deferred_tool_version``) did that
since #956, but the dependency check (``_get_tool_installation_info`` ->
``UVToolRunner.get_tool_installation_info``) asked ``get_tool_version`` without the
flag, so checkov (about 1.9 s to print its version) was started once more on every
run where it scans.

``spawn_run`` is replaced by a recorder, so a spawn is an entry in ``spawned``. The
fake uv tools directory lives in ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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


def _install(tools_dir: Path, tool: str, version: str):
    info = (
        tools_dir
        / tool
        / "lib"
        / "python3.12"
        / "site-packages"
        / f"{tool.replace('-', '_')}-{version}.dist-info"
    )
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {tool}\nVersion: {version}\n",
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
    commands: list = []

    def recording_spawn(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="9.1.1\n", stderr="")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", recording_spawn)
    return commands


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    # The tool is listed as installed; the listing itself is not under test.
    monkeypatch.setattr(UVToolRunner, "is_tool_installed", lambda self, tool: True)
    built = UVToolRunner()
    built.uv_executable = "/zz-fake/uv"
    return built


def test_installation_info_reads_the_version_from_metadata_when_asked(
    runner, tools_dir, spawned
):
    _install(tools_dir, "zz-tool", "9.4.2")

    info = runner.get_tool_installation_info("zz-tool", _SPEC, from_metadata=True)

    assert info["uv_version"] == "9.4.2"
    assert spawned == [], f"the tool was started: {spawned}"


def test_installation_info_probes_when_not_asked(runner, tools_dir, spawned):
    """The default is the probe, so a plugin that did not opt in is unchanged."""
    _install(tools_dir, "zz-tool", "9.4.2")

    info = runner.get_tool_installation_info("zz-tool", _SPEC)

    assert info["uv_version"] == "9.1.1"
    assert len(spawned) == 1


def test_installation_info_probes_when_metadata_cannot_answer(
    runner, tools_dir, spawned
):
    """No installed environment: the answer comes from the real probe, as before."""
    info = runner.get_tool_installation_info("zz-tool", _SPEC, from_metadata=True)

    assert info["uv_version"] == "9.1.1"
    assert len(spawned) == 1


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def _installation_info_kwargs(scanner):
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as get_runner:
        fake = get_runner.return_value
        fake.get_tool_installation_info.return_value = {
            "is_uv_installed": True,
            "is_pre_installed": False,
            "preferred_source": "uv",
            "available": True,
        }
        scanner._get_tool_installation_info()
        return fake.get_tool_installation_info.call_args.kwargs


def test_checkov_passes_its_opt_in_to_the_dependency_check(context):
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())

    assert _installation_info_kwargs(scanner).get("from_metadata") is True


def test_bandit_keeps_its_probe_in_the_dependency_check(context):
    """Bandit loads stevedore plugins: its probe is what warms their cache."""
    scanner = BanditScanner(context=context, config=BanditScannerConfig())

    assert "from_metadata" not in _installation_info_kwargs(scanner)
