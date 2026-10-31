# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.semgrepignore`` in a delivered tree is named in the results as the client's.

ASH runs semgrep and opengrep with ``--x-ignore-semgrepignore-files`` and their
default exclusions in every tree, so a ``.semgrepignore`` there leaves no files
out, and a config warning says so. When the file is one an MCP client delivered
(``cli/mcp/sandbox.config_is_client_supplied``, judged by its path and by the
file it resolves to), the warning says the file is client-supplied. The warning
becomes a ``config_warning`` validation checkpoint in the results.

Every scanner here is built with ``enabled=True``: semgrep and opengrep publish
no Windows build, so their configs are disabled by default there, and a disabled
scanner records no note. The note's path judgment is what these tests measure,
on every platform alike.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

CLIENT_WORDING = "client-supplied"


@pytest.fixture
def mcp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "mcp-workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return root


def _scanner_warnings(scanner_name: str, source: Path, out: Path) -> List[str]:
    config = AshConfig(project_name="test")
    context = PluginContext(source_dir=source, output_dir=out, config=config)
    if scanner_name == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as Scanner,
            SemgrepScannerConfig as ScannerConfig,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as Scanner,
            OpengrepScannerConfig as ScannerConfig,
        )
    scanner = Scanner(context=context, config=ScannerConfig(enabled=True))
    scanner._resolve_arguments(target=source, results_file=out / "r.sarif")
    return [w for w in config._resolution_warnings if ".semgrepignore" in w]


def _tree(parent: Path) -> Path:
    source = parent / "source"
    source.mkdir(parents=True)
    (source / ".semgrepignore").write_text("hidden/\n", encoding="utf-8")
    return source


@pytest.mark.parametrize("scanner_name", ["semgrep", "opengrep"])
def test_a_delivered_semgrepignore_is_named_as_client_supplied(
    mcp_root: Path, tmp_path: Path, scanner_name: str
) -> None:
    source = _tree(mcp_root / "session-1")
    out = tmp_path / "out"
    out.mkdir()

    (note,) = _scanner_warnings(scanner_name, source, out)

    assert CLIENT_WORDING in note
    assert (source / ".semgrepignore").as_posix() in note
    assert "was not honored" in note


def test_a_semgrepignore_elsewhere_keeps_the_existing_note(
    mcp_root: Path, tmp_path: Path
) -> None:
    source = _tree(tmp_path / "repo")
    out = tmp_path / "out"
    out.mkdir()

    (note,) = _scanner_warnings("semgrep", source, out)

    assert CLIENT_WORDING not in note
    assert note == (
        f"{(source / '.semgrepignore').as_posix()} was not honored: ASH runs semgrep "
        "and opengrep with --x-ignore-semgrepignore-files and their default "
        "exclusions, so a .semgrepignore in the scanned tree does not leave files "
        "out. List them in global_settings.ignore_paths instead."
    )


def test_a_link_to_a_delivered_semgrepignore_is_the_clients(
    mcp_root: Path, tmp_path: Path
) -> None:
    """Judged by the file the link reaches as well as where the link sits."""
    delivered = _tree(mcp_root / "session-1")
    source = tmp_path / "repo" / "source"
    source.mkdir(parents=True)
    try:
        os.symlink(delivered / ".semgrepignore", source / ".semgrepignore")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")
    out = tmp_path / "out"
    out.mkdir()

    (note,) = _scanner_warnings("semgrep", source, out)

    assert CLIENT_WORDING in note


def test_a_delivered_link_to_a_semgrepignore_elsewhere_is_the_clients(
    mcp_root: Path, tmp_path: Path
) -> None:
    """Judged by where the link sits, and named by it, not by the file it reaches."""
    host_file = tmp_path / "host" / ".semgrepignore"
    host_file.parent.mkdir()
    host_file.write_text("hidden/\n", encoding="utf-8")
    source = mcp_root / "session-1" / "source"
    source.mkdir(parents=True)
    try:
        os.symlink(host_file, source / ".semgrepignore")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")
    out = tmp_path / "out"
    out.mkdir()

    (note,) = _scanner_warnings("semgrep", source, out)

    assert CLIENT_WORDING in note
    assert (source / ".semgrepignore").as_posix() in note
    assert host_file.parent.as_posix() not in note


def test_the_checkpoint_in_the_results_carries_the_wording(
    mcp_root: Path, tmp_path: Path
) -> None:
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )

    source = _tree(mcp_root / "session-1")
    out = tmp_path / "out"
    out.mkdir()
    config = AshConfig(project_name="test")
    context = PluginContext(source_dir=source, output_dir=out, config=config)
    SemgrepScanner(
        context=context, config=SemgrepScannerConfig(enabled=True)
    )._resolve_arguments(target=source, results_file=out / "r.sarif")

    class _Engine:
        def execute_phases(self, phases=None):
            return AshAggregatedResults()

    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=out,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=config,
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=_Engine(),
        ),
    ):
        orchestrator.initialize()
    with patch("automated_security_helper.core.orchestrator.scan_set", return_value=[]):
        results = orchestrator.execute_scan(phases=["scan"])

    (checkpoint,) = [
        c
        for c in results.validation_checkpoints
        if c.get("type") == "config_warning" and ".semgrepignore" in c["message"]
    ]
    assert CLIENT_WORDING in checkpoint["message"]


def test_a_note_the_scanner_adds_while_scanning_reaches_the_results(
    mcp_root: Path, tmp_path: Path
) -> None:
    """The scanner adds its note while the phases run; the checkpoints are taken after."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )

    source = _tree(mcp_root / "session-1")
    out = tmp_path / "out"
    out.mkdir()
    config = AshConfig(project_name="test")

    class _Engine:
        def execute_phases(self, phases=None):
            context = PluginContext(source_dir=source, output_dir=out, config=config)
            SemgrepScanner(
                context=context, config=SemgrepScannerConfig(enabled=True)
            )._resolve_arguments(target=source, results_file=out / "r.sarif")
            return AshAggregatedResults()

    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=out,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=config,
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=_Engine(),
        ),
    ):
        orchestrator.initialize()
    assert not [w for w in config._resolution_warnings if ".semgrepignore" in w]
    with patch("automated_security_helper.core.orchestrator.scan_set", return_value=[]):
        results = orchestrator.execute_scan(phases=["scan"])

    (checkpoint,) = [
        c
        for c in results.validation_checkpoints
        if c.get("type") == "config_warning" and ".semgrepignore" in c["message"]
    ]
    assert CLIENT_WORDING in checkpoint["message"]
