# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo and syft never read a config file from the scanned tree, online or offline.

A ``trivy.yaml`` in the scanned repository can turn on a VEX repository download or
client/server mode, and a ``.syft.yaml`` remote license and package lookups. trivy
reads ``trivy.yaml`` from its working directory unless ``--config`` names another
file, and syft reads ``.syft.yaml`` from its working directory or from ``--config``.
So trivy always gets ``--config`` (``TRIVY_CONFIG`` when that names a file outside
the tree, otherwise ASH's own empty config), and syft runs from outside the tree and
is given only a config file outside it. An operator's file outside the tree is still
used. No tool runs: the spawn helper is replaced by a recorder.
"""

import os
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
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
from automated_security_helper.utils.content_db_refresh import EMPTY_TOOL_CONFIG


class _Spawn:
    def __init__(self, command, cwd, env):
        self.command: List[str] = [str(part) for part in command]
        self.cwd = Path(cwd) if cwd is not None else None
        self.env: Dict[str, str] = dict(env) if env is not None else dict(os.environ)

    def values(self, flag: str) -> List[str]:
        found = []
        for index, arg in enumerate(self.command):
            if arg.startswith(f"{flag}="):
                found.append(arg.split("=", 1)[1])
            elif arg == flag and index + 1 < len(self.command):
                found.append(self.command[index + 1])
        return found


def _inside(path: Path, root: Path) -> bool:
    return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(root)))


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
    (ctx.work_dir / "converted.py").write_text("print('hi')\n")
    return ctx


def _no_database_update(monkeypatch) -> None:
    """Online, trivy and trivy-repo update trivy's database before the scan
    (TrivyScannerBase._shared_update_flags), which needs trivy itself and the
    network. These tests read the scan's argv, so the update is replaced."""
    monkeypatch.setattr(trivy_base, "prepare_content_db", lambda *a, **k: None)


@pytest.fixture(params=["online", "offline"])
def mode(request, monkeypatch):
    if request.param == "offline":
        monkeypatch.setenv("ASH_OFFLINE", "YES")
    else:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        _no_database_update(monkeypatch)
    for name in ("TRIVY_CONFIG", "TRIVY_SKIP_VERSION_CHECK", "TRIVY_DISABLE_TELEMETRY"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    for name in ("TRIVY_CONFIG", "TRIVY_SKIP_VERSION_CHECK", "TRIVY_DISABLE_TELEMETRY"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _no_database_update(monkeypatch)
    for name in ("TRIVY_CONFIG", "TRIVY_SKIP_VERSION_CHECK", "TRIVY_DISABLE_TELEMETRY"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _scan(scanner, ctx, monkeypatch, target_type: str = "source") -> _Spawn:
    target = ctx.source_dir if target_type == "source" else ctx.work_dir
    spawns: List[_Spawn] = []

    def record(command, *args, **kwargs):
        spawns.append(_Spawn(command, kwargs.get("cwd"), kwargs.get("env")))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    try:
        scanner.scan(target=target, target_type=target_type)
    except Exception:
        pass  # no tool ran, so there is no result file to read
    calls = [s for s in spawns if target.as_posix() in " ".join(s.command)]
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


TARGET_TYPES = pytest.mark.parametrize("target_type", ["source", "converted"])


class TestTrivy:
    @TARGET_TYPES
    def test_never_reads_a_config_from_the_scanned_tree(
        self, mode, context, target_type
    ):
        spawn = _scan(_trivy(context), context, mode, target_type)

        named = spawn.values("--config") or spawn.values("-c")
        assert named, (
            "trivy runs without --config, so it reads trivy.yaml from its working "
            f"directory ({spawn.cwd}): {spawn.command}"
        )
        for value in named:
            path = Path(value) if Path(value).is_absolute() else spawn.cwd / value
            assert not _inside(path, context.source_dir), value
            assert not _inside(path, context.output_dir), value

    def test_without_trivy_config_gets_ashs_empty_config(self, mode, context):
        spawn = _scan(_trivy(context), context, mode)

        assert spawn.values("--config") == [EMPTY_TOOL_CONFIG.as_posix()]

    def test_uses_trivy_config_outside_the_tree(self, mode, context, tmp_path):
        operator = tmp_path / "operator" / "trivy.yaml"
        operator.parent.mkdir()
        operator.write_text("severity: [HIGH]\n")
        mode.setenv("TRIVY_CONFIG", str(operator))

        spawn = _scan(_trivy(context), context, mode)

        assert spawn.values("--config") == [os.path.realpath(operator)]

    def test_refuses_trivy_config_inside_the_tree(self, mode, context):
        mode.setenv("TRIVY_CONFIG", str(context.source_dir / "trivy.yaml"))

        spawn = _scan(_trivy(context), context, mode)

        assert spawn.values("--config") == [EMPTY_TOOL_CONFIG.as_posix()]

    def test_offline_turns_the_version_check_and_telemetry_off_by_environment(
        self, offline, context
    ):
        """Through TRIVY_* variables, which a trivy too old to know them ignores; an
        unknown flag would make that trivy refuse the whole command."""
        spawn = _scan(_trivy(context, disable_telemetry=False), context, offline)

        assert spawn.env.get("TRIVY_SKIP_VERSION_CHECK") == "true"
        assert spawn.env.get("TRIVY_DISABLE_TELEMETRY") == "true"
        assert "--skip-version-check" not in spawn.command
        assert spawn.command.count("--disable-telemetry") == 0

    def test_disable_telemetry_still_passes_its_flag_once(self, mode, context):
        spawn = _scan(_trivy(context, disable_telemetry=True), context, mode)

        assert spawn.command.count("--disable-telemetry") == 1

    def test_online_version_check_and_telemetry_are_the_operators(
        self, online, context
    ):
        spawn = _scan(_trivy(context, disable_telemetry=False), context, online)

        assert "--disable-telemetry" not in spawn.command
        assert "TRIVY_SKIP_VERSION_CHECK" not in spawn.env
        assert "TRIVY_DISABLE_TELEMETRY" not in spawn.env


class TestSyft:
    @TARGET_TYPES
    def test_never_reads_a_config_from_the_scanned_tree(
        self, mode, context, target_type
    ):
        spawn = _scan(_syft(context), context, mode, target_type)

        named = spawn.values("--config") + spawn.values("-c")
        assert not any(_inside(Path(value), context.source_dir) for value in named), (
            spawn.command
        )
        assert spawn.cwd is not None
        assert not _inside(spawn.cwd, context.source_dir), (
            f"syft runs in {spawn.cwd}, where it reads .syft.yaml"
        )

    def test_config_file_inside_the_tree_is_not_passed(self, mode, context):
        spawn = _scan(_syft(context, config_file=".syft.yaml"), context, mode)

        # syft is always given a config, so it reads none from the tree: here the
        # empty one ASH writes outside it, in place of the file in the tree.
        (named,) = spawn.values("--config")
        assert not _inside(Path(named), context.source_dir), spawn.command
        assert Path(named).name != ".syft.yaml"

    def test_config_file_outside_the_tree_is_passed(self, mode, context, tmp_path):
        operator = tmp_path / "operator" / "syft.yaml"
        operator.parent.mkdir()
        operator.write_text("exclude: []\n")

        spawn = _scan(_syft(context, config_file=str(operator)), context, mode)

        assert spawn.values("--config") == [os.path.realpath(operator)]
