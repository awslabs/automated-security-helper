# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run ASH refuses tells an MCP client why, with the code the CLI exits with.

Why this exists
---------------
run_ash_scan ends a run it refuses with an exit after printing or logging why:
a config that does not validate (3), files git tracks where the scan writes, or
files there git cannot account for (3), a scanner selection that names nothing
(5), an exception during the scan (1), and, in container and Nix mode, previous
results it cannot remove or restored results it will not read back (1). An MCP
runner that catches the SystemExit and records "ASH exited with code N" and
nothing else would tell a client polling get_scan_progress that the scan failed,
not why, with no exit code to branch on.

The exit carries the text the CLI shows. The runner records it in
``error_message``, shown on one line, with the code in ``exit_code`` and its
``exit_code_meaning``. Each cell runs the refusal as the CLI runs it and checks
that the client is told the same code and the same text. The config and
exception cells run the MCP scan for real; the others hand the runner the exit
the CLI's run raised, since the MCP tools refuse those trees before a scan
starts, or never run in container or Nix mode.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions import run_ash_scan as run_module
from automated_security_helper.utils.terminal_text import shown_on_one_line
from tests.unit.test_committed_output_refused_at_entry_points import _repo
from tests.unit.test_committed_output_when_git_cannot_answer import (
    _broken_repo,
    _no_orchestrator,
)

# Marked per test. A test is unit only if it never calls _cli AND hands _mcp an
# `ended` exit: that pair replaces run_ash_scan with a raise and stays in-process.
# Any other test is integration, whichever of the two paths it also takes: a call
# of _cli, or of _mcp with no `ended`, hands run_ash_scan a scan, and the scan path
# starts scanners on any outcome the refusal or the patched orchestrator leaves
# open; _repo and _broken_repo also run git in a child process. A test that calls
# _cli and also hands _mcp an `ended` exit is therefore integration.

#: Rich markup, a terminal control and a CI command, in text the scan quotes.
#: The control is a lone ESC plus "c" (reset), not a complete CSI or OSC
#: sequence: error text has those removed whether or not values exist, so
#: only a control outside that set reaches the sink to be shown.
QUOTED = "the orchestrator broke: [red]not markup[/red] \x1bc ::warning::x"


@pytest.fixture
def registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def tree(tmp_path) -> Dict[str, Path]:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return {"source": source, "output": source / ".ash" / "ash_output"}


def _flat(text: str) -> str:
    return " ".join(text.split())


def _cli(capsys, **kwargs: Any) -> tuple[SystemExit, str]:
    """run_ash_scan as the CLI runs it: the exit it raised and what it printed."""
    capsys.readouterr()
    with pytest.raises(SystemExit) as exited:
        run_module.run_ash_scan(
            mode=RunMode.local, progress=False, show_summary=False, **kwargs
        )
    return exited.value, _flat(capsys.readouterr().out)


def _mcp(
    registry,
    source: Path,
    output: Path,
    monkeypatch,
    ended: Optional[BaseException] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """The MCP runner over one scan of *source*, and the progress a client reads.

    With *ended*, run_ash_scan raises it instead of running.
    """
    from automated_security_helper.cli import mcp_tools

    if ended is not None:

        def _raises(**_kwargs: Any) -> None:
            raise ended

        monkeypatch.setattr(run_module, "run_ash_scan", _raises)
    output.mkdir(parents=True, exist_ok=True)
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    async def _run() -> Dict[str, Any]:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(source),
            output_dir=str(output),
            severity_threshold=None,
            config_path=config_path,
        )
        return await mcp_tools.mcp_get_scan_progress(scan_id)

    return asyncio.run(_run())


def _reason(progress: Dict[str, Any], code: int) -> str:
    """The text after the code in a failed scan's error_message."""
    assert progress["status"] == "failed", progress
    assert progress["exit_code"] == code, progress
    assert progress["exit_code_meaning"] == ASH_EXIT_CODES[code], progress
    prefix = f"ASH exited with code {code}: "
    message = progress["error_message"]
    assert message.startswith(prefix), message
    assert "\n" not in message and "\x1b" not in message, message
    return message[len(prefix) :]


# ---------------------------------------------------------------------------
# Run by the MCP scan itself
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_config_that_does_not_validate(tree, registry, monkeypatch, capsys) -> None:
    config = tree["source"] / "bad.ash.yaml"
    config.write_text("global_settings:\n  severity_threshold: LOUD\n", "utf-8")

    cli_exit, printed = _cli(
        capsys,
        source_dir=tree["source"],
        output_dir=tree["output"],
        config=str(config),
    )
    shutil.rmtree(tree["output"])
    progress = _mcp(
        registry, tree["source"], tree["output"], monkeypatch, config_path=str(config)
    )

    assert cli_exit.code == 3
    reason = _reason(progress, 3)
    assert reason.startswith("Invalid configuration: "), reason
    assert f"ERROR (3) {_flat(reason)}" in printed, (reason, printed)


@pytest.mark.integration
def test_an_exception_during_the_scan(tree, registry, monkeypatch, capsys) -> None:
    def _broken(cls, **_kwargs: Any) -> None:
        raise RuntimeError(QUOTED)

    monkeypatch.setattr(ASHScanOrchestrator, "create", classmethod(_broken))

    cli_exit, printed = _cli(
        capsys, source_dir=tree["source"], output_dir=tree["output"]
    )
    shutil.rmtree(tree["output"])
    progress = _mcp(registry, tree["source"], tree["output"], monkeypatch)

    assert cli_exit.code == 1
    reason = _reason(progress, 1)
    assert reason == (
        "Exiting due to exception during ASH scan: " + shown_on_one_line(QUOTED)
    ), reason
    # Shown, not obeyed, the way the CLI shows it.
    assert "\\x1bc" in reason and "[red]not markup[/red]" in reason, reason
    assert f"ERROR (1) {_flat(reason)}" in printed, (reason, printed)


# ---------------------------------------------------------------------------
# Refused before an MCP scan starts, so the runner is handed the CLI's exit
# ---------------------------------------------------------------------------


# integration: _repo and _broken_repo build the repository with git init and git add
# in a child process.
@pytest.mark.integration
@pytest.mark.parametrize("make", [_repo, _broken_repo], ids=["committed", "unknown"])
def test_files_in_the_way_of_the_output(
    make, tmp_path, registry, monkeypatch, capsys
) -> None:
    source, output = make(tmp_path, monkeypatch)
    _no_orchestrator(monkeypatch)

    cli_exit, printed = _cli(capsys, source_dir=source, output_dir=output)
    progress = _mcp(registry, source, output, monkeypatch, ended=cli_exit)

    assert cli_exit.code == 3
    reason = _reason(progress, 3)
    assert reason.startswith("Scan refused: "), reason
    assert f"ERROR (3) {_flat(reason)}" in printed, (reason, printed)


@pytest.mark.integration
def test_a_scanner_selection_that_names_nothing(
    tree, registry, monkeypatch, capsys
) -> None:
    cli_exit, printed = _cli(
        capsys,
        source_dir=tree["source"],
        output_dir=tree["output"],
        scanners=["no-such-scanner"],
    )
    progress = _mcp(registry, tree["source"], tree["output"], monkeypatch, cli_exit)

    assert cli_exit.code == 5
    reason = _reason(progress, 5)
    assert "no-such-scanner" in reason, reason
    assert f"ERROR (5) {_flat(reason)}" in printed, (reason, printed)


def _logged_refusal(call, *args: Any) -> tuple[SystemExit, str]:
    """*call* run with a logger: the exit it raised and the one error it logged."""
    logger = MagicMock()
    with pytest.raises(SystemExit) as exited:
        call(*args, logger)
    logger.error.assert_called_once()
    return exited.value, logger.error.call_args.args[0]


def _held_previous_results_that_will_not_go(output: Path, monkeypatch) -> None:
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        PreviousResults,
    )

    (output / HELD_DIR_NAME).mkdir(parents=True)

    def _refuses(self) -> None:
        raise PermissionError(f"cannot remove [b]{HELD_DIR_NAME}[/b]")

    monkeypatch.setattr(PreviousResults, "discard", _refuses)


def _a_report_that_will_not_go(output: Path, monkeypatch) -> None:
    (output / "reports").mkdir(parents=True)

    def _refuses(path, *args: Any, **kwargs: Any) -> None:
        raise PermissionError(f"cannot remove {path}")

    monkeypatch.setattr(run_module.shutil, "rmtree", _refuses)


@pytest.mark.unit
@pytest.mark.parametrize(
    "arrange",
    [_held_previous_results_that_will_not_go, _a_report_that_will_not_go],
    ids=["held-previous-results", "previous-run-output"],
)
def test_previous_output_a_container_or_nix_scan_cannot_remove(
    arrange, tree, registry, monkeypatch
) -> None:
    from automated_security_helper.core.enums import RunMode

    # What _discard_prior_run_artifacts reads of a ScanOptions: the link check it
    # runs first (_refuse_symlinked_output_dir) reads mode, source_dir and
    # workspace_plan too.
    opts = SimpleNamespace(
        existing_results=None,
        output_dir=tree["output"],
        source_dir=tree["source"],
        mode=RunMode.local,
        workspace_plan=None,
    )
    with pytest.MonkeyPatch.context() as refusing:
        arrange(tree["output"], refusing)
        cli_exit, logged = _logged_refusal(
            run_module._discard_prior_run_artifacts, opts
        )
    progress = _mcp(registry, tree["source"], tree["output"], monkeypatch, cli_exit)

    assert cli_exit.code == 1
    assert _reason(progress, 1) == shown_on_one_line(logged)


@pytest.mark.unit
def test_restored_results_a_container_scan_will_not_read_back(
    tree, registry, monkeypatch
) -> None:
    from automated_security_helper.core.previous_results import RESTORED_MARKER_NAME

    tree["output"].mkdir(parents=True)
    (tree["output"] / RESTORED_MARKER_NAME).write_text("", "utf-8")

    cli_exit, logged = _logged_refusal(
        run_module._refuse_restored_results, tree["output"], "the container"
    )
    progress = _mcp(registry, tree["source"], tree["output"], monkeypatch, cli_exit)

    assert cli_exit.code == 1
    assert _reason(progress, 1) == shown_on_one_line(logged)


# ---------------------------------------------------------------------------
# The runner's other endings
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_bare_exit_keeps_its_code_with_no_reason(tree, registry, monkeypatch):
    progress = _mcp(
        registry, tree["source"], tree["output"], monkeypatch, SystemExit(4)
    )

    assert progress["status"] == "failed", progress
    assert progress["error_message"] == "ASH exited with code 4", progress
    assert progress["exit_code"] == 4, progress
    assert progress["exit_code_meaning"] == ASH_EXIT_CODES[4], progress


@pytest.mark.integration
def test_a_reason_over_several_lines_reaches_the_client_on_one(
    tree, registry, monkeypatch, capsys
) -> None:
    def _broken(cls, **_kwargs: Any) -> None:
        raise RuntimeError("first line\nsecond line\tand a tab")

    monkeypatch.setattr(ASHScanOrchestrator, "create", classmethod(_broken))
    cli_exit, _printed = _cli(
        capsys, source_dir=tree["source"], output_dir=tree["output"]
    )
    progress = _mcp(registry, tree["source"], tree["output"], monkeypatch, cli_exit)

    assert _reason(progress, 1).endswith("first line\\x0asecond line\\x09and a tab")


@pytest.mark.unit
@pytest.mark.parametrize(
    "ended",
    [run_module.ScanRefusedExit(1, QUOTED), RuntimeError(QUOTED)],
    ids=["a refused run", "an error raised out of the scan"],
)
def test_the_runner_logs_the_reason_shown_once(
    tree, registry, monkeypatch, caplog, ended
) -> None:
    """The log line's escapes are single: a sink shows the text it is given, so
    text shown before it was put in a line would be shown twice."""
    import logging

    from automated_security_helper.utils.log import console_text

    caplog.set_level(logging.ERROR)
    _mcp(registry, tree["source"], tree["output"], monkeypatch, ended)

    (record,) = [r for r in caplog.records if " failed: " in r.getMessage()]
    shown = console_text(record, record.getMessage())
    assert "\\x1bc" in shown and "\\\\x1b" not in shown, shown


@pytest.mark.unit
def test_an_error_raised_out_of_the_scan_carries_exit_code_1(
    tree, registry, monkeypatch
) -> None:
    progress = _mcp(
        registry,
        tree["source"],
        tree["output"],
        monkeypatch,
        RuntimeError("the runner broke \x1bc"),
    )

    assert progress["status"] == "failed", progress
    assert progress["exit_code"] == 1, progress
    assert progress["exit_code_meaning"] == ASH_EXIT_CODES[1], progress
    assert progress["error_message"] == (
        "Error executing scan: the runner broke \\x1bc"
    ), progress


@pytest.mark.unit
def test_control_a_scan_that_exits_0_has_no_exit_code(tree, registry, monkeypatch):
    progress = _mcp(
        registry, tree["source"], tree["output"], monkeypatch, SystemExit(0)
    )

    assert progress["status"] == "completed", progress
    assert progress["exit_code"] is None, progress
    assert progress["exit_code_meaning"] is None, progress
