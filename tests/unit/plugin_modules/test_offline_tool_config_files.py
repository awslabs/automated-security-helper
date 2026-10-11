# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline, trivy and syft read no config file from the scanned tree; online, as before.

``test_offline_scanner_network_checks.py`` shows the in-tree ``trivy.yaml`` and
``.syft.yaml`` are not read offline. These cover the rest of the rule: an operator's
file outside the tree is still used offline (``TRIVY_CONFIG``, syft's
``config_file``), one inside the tree is not whoever names it, and online the
command line is what it was. No tool runs: the spawn helper is replaced by a
recorder, as in that file.
"""

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils


class _Spawn:
    def __init__(self, command, cwd):
        self.command: List[str] = [str(part) for part in command]
        self.cwd = Path(cwd) if cwd is not None else None

    def values(self, flag: str) -> List[str]:
        found = []
        for index, arg in enumerate(self.command):
            if arg.startswith(f"{flag}="):
                found.append(arg.split("=", 1)[1])
            elif arg == flag and index + 1 < len(self.command):
                found.append(self.command[index + 1])
        return found


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def context(tmp_path) -> PluginContext:
    ctx = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    (ctx.source_dir / "trivy.yaml").write_text("server:\n  addr: http://x.invalid\n")
    (ctx.source_dir / ".syft.yaml").write_text("enrich: [all]\n")
    return ctx


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    return monkeypatch


def _scan(scanner, ctx, monkeypatch) -> _Spawn:
    spawns: List[_Spawn] = []

    def record(command, *args, **kwargs):
        spawns.append(_Spawn(command, kwargs.get("cwd")))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    try:
        scanner.scan(target=ctx.source_dir, target_type="source")
    except Exception:
        pass  # no tool ran, so there is no result file to read
    calls = [s for s in spawns if ctx.source_dir.as_posix() in " ".join(s.command)]
    assert calls, spawns
    return calls[-1]


def _trivy(ctx, **options) -> TrivyRepoScanner:
    return TrivyRepoScanner(
        context=ctx,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


def _syft(ctx, **options) -> SyftScanner:
    return SyftScanner(
        context=ctx,
        config=SyftScannerConfig(options=SyftScannerConfigOptions(**options)),
    )


class TestTrivy:
    def test_offline_without_trivy_config_gets_an_empty_config(self, offline, context):
        spawn = _scan(_trivy(context), context, offline)

        assert spawn.values("--config") == [os.devnull]

    def test_offline_uses_trivy_config_outside_the_tree(
        self, offline, context, tmp_path
    ):
        operator = tmp_path / "operator" / "trivy.yaml"
        operator.parent.mkdir()
        operator.write_text("severity: [HIGH]\n")
        offline.setenv("TRIVY_CONFIG", str(operator))

        spawn = _scan(_trivy(context), context, offline)

        assert spawn.values("--config") == [os.path.realpath(operator)]

    def test_offline_refuses_trivy_config_inside_the_tree(self, offline, context):
        offline.setenv("TRIVY_CONFIG", str(context.source_dir / "trivy.yaml"))

        spawn = _scan(_trivy(context), context, offline)

        assert spawn.values("--config") == [os.devnull]

    def test_offline_passes_telemetry_and_version_flags_once(self, offline, context):
        spawn = _scan(_trivy(context, disable_telemetry=True), context, offline)

        assert spawn.command.count("--disable-telemetry") == 1
        assert spawn.command.count("--skip-version-check") == 1

    def test_online_command_line_is_unchanged(self, online, context):
        spawn = _scan(_trivy(context, disable_telemetry=False), context, online)

        assert spawn.values("--config") == []
        assert "--skip-version-check" not in spawn.command
        assert "--disable-telemetry" not in spawn.command


class TestSyft:
    def test_offline_runs_outside_the_tree_with_no_tree_config(self, offline, context):
        spawn = _scan(_syft(context), context, offline)

        assert spawn.values("--config") == []
        assert spawn.cwd is not None
        assert not Path(os.path.realpath(spawn.cwd)).is_relative_to(
            os.path.realpath(context.source_dir)
        )

    def test_offline_config_file_inside_the_tree_is_not_passed(self, offline, context):
        spawn = _scan(_syft(context, config_file=".syft.yaml"), context, offline)

        assert spawn.values("--config") == []

    def test_offline_config_file_outside_the_tree_is_passed(
        self, offline, context, tmp_path
    ):
        operator = tmp_path / "operator" / "syft.yaml"
        operator.parent.mkdir()
        operator.write_text("exclude: []\n")

        spawn = _scan(_syft(context, config_file=str(operator)), context, offline)

        assert spawn.values("--config") == [os.path.realpath(operator)]

    def test_online_still_passes_the_tree_config(self, online, context):
        """Online behavior is unchanged here: syft gets the tree's .syft.yaml and
        runs in the source directory."""
        spawn = _scan(_syft(context), context, online)

        assert spawn.values("--config") == [
            (context.source_dir / ".syft.yaml").resolve().as_posix()
        ]
        assert Path(os.path.realpath(spawn.cwd)) == Path(
            os.path.realpath(context.source_dir)
        )
