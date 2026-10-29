# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal of a committed results path prints what git tracks, as it is.

A refused scan exits 3 with a message naming the committed entries. The message
was printed inside a Rich markup string, so a committed name holding markup was
read as markup: ``reports/[bold]x[/bold].sarif`` printed as a styled
``reports/x.sarif``, and ``reports/[/x].sarif`` raised ``MarkupError`` out of the
exception handler, so the scan ended with a traceback and not with exit 3. The
line was also labeled "Invalid configuration", which a committed file is not.

The message names at most ten entries and counts the rest; nothing pinned that.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    CommittedOutputFilesError,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_local_mode,
    _run_workspace_mode,
    run_ash_scan,
)
from tests.unit.test_committed_output_refused_at_entry_points import (
    _repo,
    _workspace_plan,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _initialize,
    _orchestrator,
    _snapshot,
)

#: Committed names that Rich reads as markup: a style, and a closing tag with no
#: opening one, which Rich refuses with MarkupError.
MARKUP_NAMES = ("reports/[bold]x[/bold].sarif", "reports/[/x].sarif")


def _printed(capsys) -> str:
    """What was printed, with Rich's line wrapping undone."""
    return capsys.readouterr().out.replace("\n", "")


def _no_scan(monkeypatch) -> None:
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "execute_scan",
        lambda self, *a, **k: (_ for _ in ()).throw(AssertionError("scanned")),
    )


@pytest.mark.integration
@pytest.mark.parametrize("name", MARKUP_NAMES)
def test_the_cli_prints_a_committed_name_verbatim_and_exits_3(
    tmp_path, monkeypatch, capsys, name
):
    source, output = _repo(tmp_path, monkeypatch, committed={name: "committed\n"})
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    _no_scan(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert exited.value.code == 3
    printed = _printed(capsys)
    assert name in printed, printed
    assert "ERROR (3) Scan refused:" in printed, printed
    assert "Invalid configuration" not in printed, printed
    assert _snapshot(output) == before


@pytest.mark.integration
@pytest.mark.parametrize("name", MARKUP_NAMES)
def test_the_local_run_prints_the_orchestrators_refusal_verbatim(
    tmp_path, monkeypatch, capsys, name
):
    """Through _run_local_mode, past the CLI's own check: the orchestrator's
    refusal is printed by the local run's handler."""
    source, output = _repo(tmp_path, monkeypatch, committed={name: "committed\n"})
    _confined(tmp_path, source, output)
    _no_scan(monkeypatch)
    opts = ScanOptions(source_dir=source, output_dir=output)

    with pytest.raises(SystemExit) as exited:
        _run_local_mode(opts, logging.getLogger("test-refusal-message"))

    assert exited.value.code == 3
    printed = _printed(capsys)
    assert name in printed, printed
    assert "ERROR (3) Scan refused:" in printed, printed


def _workspace_options(tmp_path: Path) -> ScanOptions:
    root = tmp_path / "ws"
    root.mkdir()
    return ScanOptions(
        source_dir=root,
        output_dir=tmp_path / "out",
        workspace_plan=_workspace_plan(root),
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("error", "label"),
    [
        (
            ASHConfigValidationError("the value [/x] does not parse"),
            "Invalid configuration",
        ),
        (CommittedOutputFilesError("committed reports/[/x].sarif"), "Scan refused"),
    ],
)
def test_the_workspace_run_prints_a_refusal_verbatim_under_its_label(
    tmp_path, monkeypatch, capsys, error, label
):
    from automated_security_helper.workspace import execution

    def _refuse(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(execution, "execute_workspace", _refuse)
    opts = _workspace_options(tmp_path)

    with pytest.raises(SystemExit) as exited:
        _run_workspace_mode(opts, logging.getLogger("test-refusal-message"))

    assert exited.value.code == 3
    printed = _printed(capsys)
    assert f"ERROR (3) {label}: {error}" in printed, printed


def _commit_reports(tmp_path, monkeypatch, count: int):
    names = [f"reports/r{index:02d}.sarif" for index in range(count)]
    source, output = _repo(
        tmp_path, monkeypatch, committed={name: f"{name}\n" for name in names}
    )
    _confined(tmp_path, source, output)
    return source, output, names


@pytest.mark.integration
def test_the_message_names_ten_committed_files_and_counts_the_rest(
    tmp_path, monkeypatch
):
    source, output, names = _commit_reports(tmp_path, monkeypatch, 12)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _initialize(_orchestrator(source, output))

    message = str(refused.value)
    assert "holds 12 files committed to git" in message, message
    named = re.findall(r"reports/r\d\d\.sarif", message)
    assert named == sorted(names)[:10], message
    assert ", ".join(sorted(names)[:10]) + " and 2 more." in message, message


@pytest.mark.integration
def test_the_message_names_every_file_up_to_ten(tmp_path, monkeypatch):
    source, output, names = _commit_reports(tmp_path, monkeypatch, 10)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _initialize(_orchestrator(source, output))

    message = str(refused.value)
    assert "holds 10 files committed to git" in message, message
    assert re.findall(r"reports/r\d\d\.sarif", message) == names
    assert "more" not in message, message


@pytest.mark.integration
def test_one_committed_file_is_counted_as_one_file(tmp_path, monkeypatch):
    source, output, names = _commit_reports(tmp_path, monkeypatch, 1)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _initialize(_orchestrator(source, output))

    assert "holds 1 file committed to git" in str(refused.value), refused.value
