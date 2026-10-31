# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The grype database update reads the operator's config as the scan does.

Before a sandboxed online scan ASH updates grype's database outside the
sandbox (``utils/content_db_refresh.py``). The refresh accepts the operator's
config file, so a database mirror or CA it names applies to the update, but the
grype scanner never passed it: the scan ran with the operator's config and the
update with the empty one ASH writes.

Now the scanner hands the refresh the config it resolved for its own run, when
that config lies outside the scanned tree. A config inside the tree (the
checkout's own, accepted for the scan) stays out of the update, which runs
unsandboxed and reads what the config says.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    grype_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _online_and_fresh(monkeypatch):
    """Online, so the scanner asks for the refresh before its argv is read."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def root(tmp_path) -> Path:
    """tmp_path with symlinks resolved, so path comparisons hold on hosts whose
    temporary directory is itself a link."""
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


@pytest.fixture
def refresh(monkeypatch) -> List[Tuple[str, Dict[str, Any]]]:
    """Records each database refresh the scanner asks for, in place of running
    one; the scan is read as sandboxed and online."""
    calls: List[Tuple[str, Dict[str, Any]]] = []

    def record(tool, cache_dir, offline, **kwargs):
        calls.append((tool, dict(kwargs)))

    monkeypatch.setattr(grype_scanner, "prepare_content_db", record)
    monkeypatch.setattr(grype_scanner, "sandboxed_online", lambda offline: True)
    return calls


def _scan(scanner: GrypeScanner, ctx: PluginContext, monkeypatch) -> List[str]:
    """Run one source scan with the tool stood in for; the argv grype was given."""
    commands: List[List[str]] = []

    def record(command, *args, **kwargs):
        commands.append([str(part) for part in command])
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    try:
        scanner.scan(target=ctx.source_dir, target_type="source")
    except Exception:
        pass  # no tool ran, so there is no result file to read
    scans = [c for c in commands if ctx.source_dir.as_posix() in " ".join(c)]
    assert scans, commands
    return scans[-1]


def _config_values(command: List[str]) -> List[str]:
    return [command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "--config"]


def _grype(ctx, **options) -> GrypeScanner:
    return GrypeScanner(
        context=ctx,
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions(**options)),
    )


def test_the_operators_home_config_reaches_the_database_update(
    context, home, refresh, monkeypatch
):
    operator = home / ".grype" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("db:\n  update-url: https://mirror.example.invalid/db\n")

    _scan(_grype(context, config_file="~/.grype/config.yaml"), context, monkeypatch)

    ((tool, kwargs),) = refresh
    assert tool == "grype"
    assert kwargs.get("config_file") is not None, kwargs
    assert Path(kwargs["config_file"]) == operator, kwargs


def test_without_an_operator_config_the_update_keeps_the_empty_config(
    context, refresh, monkeypatch
):
    """The control: nothing configured, nothing handed to the update."""
    _scan(_grype(context), context, monkeypatch)

    ((tool, kwargs),) = refresh
    assert tool == "grype"
    assert kwargs.get("config_file") is None, kwargs


def test_a_config_inside_the_scanned_tree_reaches_the_scan_but_not_the_update(
    context, refresh, monkeypatch
):
    """The checkout's own config is accepted for the sandboxed scan, as before;
    the unsandboxed update never reads a file the repository could have written."""
    in_tree = context.source_dir / ".grype.yaml"
    in_tree.write_text("db:\n  update-url: https://mirror.example.invalid/db\n")

    command = _scan(_grype(context, config_file=".grype.yaml"), context, monkeypatch)

    assert _config_values(command) == [in_tree.as_posix()], command
    ((_tool, kwargs),) = refresh
    assert kwargs.get("config_file") is None, kwargs
