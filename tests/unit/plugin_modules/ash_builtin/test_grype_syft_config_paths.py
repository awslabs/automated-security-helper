# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where grype and syft look for the operator's config file, and where grype writes.

Three readings that went wrong before:

- A ``config_file`` spelled ``~/...`` was joined as written under the scanned
  source directory, so the operator's home config was judged missing (an empty
  config passed in its place), and a same-named file the repository planted at
  ``<source>/~/...`` was the one handed to the tool. Both scanners now resolve the
  value as the tool reads it (``path_trust.resolved_path``: ``~`` expanded, a
  relative path from the source directory, symlinks resolved).
- grype's results path was ``<output_dir>/scanners/grype/<target>/...`` as the
  output directory was spelled, while grype runs with the scanned source as its
  working directory, so a relative ``--output-dir`` put the SARIF under the
  scanned tree and ASH then opened a file that did not exist. The results path is
  absolute now, as the syft scanner's already was.
- syft's warning for a refused configured config called every refusal "a work
  product derived from the scanned repository", which is one of three reasons
  ``honored_path`` refuses (a config inside the scanned tree is the common one).
  The warning now points at the refusal's own line for the reason.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


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
def _offline_and_fresh(monkeypatch):
    """Offline, so neither scanner refreshes a database before the argv is read."""
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def root(tmp_path) -> Path:
    """tmp_path with symlinks resolved, so realpath comparisons hold on hosts
    whose temporary directory is itself a link."""
    return Path(os.path.realpath(tmp_path))


@pytest.fixture
def context(root) -> PluginContext:
    ctx = PluginContext(
        source_dir=root / "repo",
        output_dir=root / "out",
        work_dir=root / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return ctx


@pytest.fixture
def home(root, monkeypatch) -> Path:
    """A home directory of this test's own, read by ``os.path.expanduser``."""
    home = root / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


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


def _grype(ctx, **options) -> GrypeScanner:
    return GrypeScanner(
        context=ctx,
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions(**options)),
    )


def _syft(ctx, **options) -> SyftScanner:
    return SyftScanner(
        context=ctx,
        config=SyftScannerConfig(options=SyftScannerConfigOptions(**options)),
    )


def _plant_tilde_decoy(ctx: PluginContext, relative: str, body: str) -> Path:
    """A file at ``<source>/~/<relative>``: what joining a ``~/...`` value as
    written under the source directory used to find."""
    decoy = ctx.source_dir / "~" / relative
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_text(body)
    return decoy


# --- a config spelled ~/... is the operator's home file -----------------------------


def test_grype_home_relative_config_is_the_operators_file(context, home, monkeypatch):
    operator = home / ".grype" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("output: sarif\n")
    _plant_tilde_decoy(context, ".grype/config.yaml", "only-fixed: true\n")

    spawn = _scan(
        _grype(context, config_file="~/.grype/config.yaml"), context, monkeypatch
    )

    assert spawn.values("--config") == [operator.as_posix()], spawn.command


def test_grype_control_a_planted_tilde_directory_in_the_tree_is_never_handed_over(
    context, home, monkeypatch
):
    """With no home file, the configured value is missing: grype gets the empty
    config ASH writes, never the repository's ``~/.grype/config.yaml``."""
    decoy = _plant_tilde_decoy(context, ".grype/config.yaml", "only-fixed: true\n")

    spawn = _scan(
        _grype(context, config_file="~/.grype/config.yaml"), context, monkeypatch
    )

    (named,) = spawn.values("--config")
    # An absolute path to the empty file ASH writes: the raw "~/..." value handed
    # through unchanged would also differ from the decoy's spelling, and grype,
    # run from the scanned source, would resolve it to the decoy.
    assert Path(named).is_absolute(), spawn.command
    assert Path(named).name == "grype-config-empty.yaml", spawn.command
    assert Path(named).read_text(encoding="utf-8") == "{}\n"
    assert Path(named) != decoy
    assert not _inside(Path(named), context.source_dir), spawn.command


def test_syft_home_relative_config_is_the_operators_file(context, home, monkeypatch):
    operator = home / ".syft.yaml"
    operator.write_text("exclude: []\n")
    _plant_tilde_decoy(context, ".syft.yaml", "enrich: [all]\n")

    spawn = _scan(_syft(context, config_file="~/.syft.yaml"), context, monkeypatch)

    assert spawn.values("--config") == [operator.as_posix()], spawn.command


def test_syft_control_a_planted_tilde_file_in_the_tree_is_never_handed_over(
    context, home, monkeypatch
):
    decoy = _plant_tilde_decoy(context, ".syft.yaml", "enrich: [all]\n")

    spawn = _scan(_syft(context, config_file="~/.syft.yaml"), context, monkeypatch)

    (named,) = spawn.values("--config")
    assert Path(named).is_absolute(), spawn.command
    assert Path(named).name == "syft-config-empty.yaml", spawn.command
    assert Path(named).read_text(encoding="utf-8") == "{}\n"
    assert Path(named) != decoy
    assert not _inside(Path(named), context.source_dir), spawn.command


# --- grype's results path under a relative output directory -----------------------


def test_grype_results_path_is_absolute_under_a_relative_output_dir(root, monkeypatch):
    """``ash --output-dir out`` from the repository's parent: grype runs in the
    scanned source, so a relative results path would land under it."""
    monkeypatch.chdir(root)
    ctx = PluginContext(
        source_dir=root / "repo",
        output_dir=Path("out"),
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "requirements.txt").write_text("requests==2.19.0\n")

    spawn = _scan(_grype(ctx), ctx, monkeypatch)

    (results,) = spawn.values("--file")
    assert Path(results).is_absolute(), spawn.command
    assert Path(results) == root / "out" / "scanners" / "grype" / "source" / (
        "results_sarif.sarif"
    )
    assert not _inside(Path(results), ctx.source_dir)


# --- syft's refusal warning names the reason it has -------------------------------


def test_syft_refusal_warning_does_not_call_an_in_tree_config_a_work_product(
    context, monkeypatch, caplog
):
    (context.source_dir / ".syft.yaml").write_text("enrich: [all]\n")

    with caplog.at_level(logging.WARNING):
        _scan(_syft(context, config_file=".syft.yaml"), context, monkeypatch)

    not_used = [
        record.getMessage()
        for record in caplog.records
        if "Configured syft config file was not used" in record.getMessage()
    ]
    assert not_used, [record.getMessage() for record in caplog.records]
    assert all("work product" not in message for message in not_used), not_used
    assert all("empty config file" in message for message in not_used), not_used
    # The line the warning points at: the refusal's own, naming the key and the
    # reason (path_trust), so the operator is pointed at something that was logged.
    refusals = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring scanners.syft.options.config_file")
    ]
    assert refusals, [record.getMessage() for record in caplog.records]


# --- grype's declared database bound reads the operator's file as grype does ------


def _online(monkeypatch) -> None:
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", raising=False)
    monkeypatch.delenv("GRYPE_DB_VALIDATE_AGE", raising=False)


def test_grype_db_bound_is_not_declared_over_a_home_config_that_sets_it(
    context, home, monkeypatch
):
    """Online, ASH exports grype's database-age bound unless the operator's config
    sets ``db.max-allowed-built-age`` itself (grype puts the environment above the
    file, so the export would override it). The file is read as grype reads it:
    ``~/.grype/config.yaml`` is the home file, not ``<cwd>/~/...``, which the path
    as configured named and could not read."""
    _online(monkeypatch)
    operator = home / ".grype" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("db:\n  max-allowed-built-age: 1h\n")

    scanner = _grype(context, config_file="~/.grype/config.yaml")

    assert "GRYPE_DB_MAX_ALLOWED_BUILT_AGE" not in scanner.extra_env, scanner.extra_env
    assert "GRYPE_DB_VALIDATE_AGE" in scanner.extra_env, scanner.extra_env


def test_grype_control_a_home_config_without_db_settings_gets_the_declared_bound(
    context, home, monkeypatch
):
    _online(monkeypatch)
    operator = home / ".grype" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("output: sarif\n")

    scanner = _grype(context, config_file="~/.grype/config.yaml")

    assert "GRYPE_DB_MAX_ALLOWED_BUILT_AGE" in scanner.extra_env, scanner.extra_env
