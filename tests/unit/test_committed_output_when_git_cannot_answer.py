# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refuses to clear its output directory when git cannot say what is committed.

ASH never deletes or overwrites a file git tracks in its output directory: it asks
git which entries are committed where a scan deletes and writes its own, and
refuses with exit 3 when there are any. When the output directory is in a
repository and git could not answer (git is not installed, it timed out, or it
exited with an error: a corrupt index, a ``.git`` file naming a directory that is
not there, a repository format it does not read), a check that answered "nothing
is committed", logged that only at debug level, would let the scan delete the
previous results, committed or not.

So when git cannot answer for a repository, whatever is at those paths on disk
stops the scan with exit 3, and the message names git's error and the two ways
out: let git read the repository, or remove the old results. Outside a repository
nothing changes.

The ownership check git applies to a repository it discovers
(``safe.directory``, "dubious ownership") does not apply here: ASH names the
repository on git's command line, and git checks ownership only for a repository
it finds by itself. Measured with git 2.50.1 and ``GIT_TEST_ASSUME_DIFFERENT_OWNER``,
which makes git treat every repository as another user's: ``git ls-files`` run
inside the repository refused it, and ASH's call listed the index. The last tests
here pin that, so a checkout owned by another user keeps the behavior it has.

Each fixture repository is made unreadable to git by raising
``core.repositoryformatversion`` past what git supports, after its files are
staged. The red run of these tests executed the deletion they guard against, so
each checks first that every directory it hands over lies inside ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

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
    run_ash_scan,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scan_output_dirs import tracked_files_in
from tests.unit.test_committed_output_refused_at_entry_points import (
    _execute_with_a_fake_orchestrator,
    _repo,
    _workspace_plan,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _initialize,
    _orchestrator,
    _results_json,
    _snapshot,
)
from tests.unit.workspace.test_execution import _git

#: What git 2.50.1 writes for a repository whose format it does not read.
GIT_ERROR = "Expected git repo version <= 1, found 99"

#: At the results paths, committed before git stopped answering.
AT_RESULTS_PATHS = {
    "ash_aggregated_results.json": _results_json("committed-results"),
    "reports/ash.sarif": '{"committed": "sarif"}\n',
}


def _unreadable_to_git(repository: Path) -> None:
    """Leave *repository* as it is on disk, in a format git refuses to read."""
    assert (
        _git(repository, "config", "core.repositoryformatversion", "99").returncode == 0
    )
    listed = _git(repository, "ls-files")
    # A control: git itself has to refuse the repository now.
    assert listed.returncode != 0 and GIT_ERROR in listed.stderr, listed


def _broken_repo(
    tmp_path: Path, monkeypatch, files: Dict[str, str] = AT_RESULTS_PATHS
) -> tuple[Path, Path]:
    """A repository whose output directory holds *files*, staged, that git cannot read."""
    source, output = _repo(tmp_path, monkeypatch, committed=files)
    _unreadable_to_git(source)
    # A control: ASH's own question gets no answer either.
    assert tracked_files_in(output) is None
    return source, output


def _words(text: str) -> str:
    """*text* with every run of whitespace one space: Rich wraps what it prints."""
    return " ".join(text.split())


def _assert_names_git_and_both_ways_out(message: str, root: Path) -> None:
    # Rich also folds a path longer than the line inside it, so the path is
    # looked for with every space and line break taken out.
    assert "".join(root.as_posix().split()) in "".join(message.split()), message
    message = _words(message)
    assert GIT_ERROR in message, message
    assert "did not delete or overwrite anything" in message, message
    assert "remove the old results" in message, message


@pytest.fixture
def mcp_ctx():
    ctx = MagicMock()
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


@pytest.fixture
def isolated_registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


def _no_orchestrator(monkeypatch) -> None:
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "create",
        classmethod(
            lambda cls, **kw: (_ for _ in ()).throw(AssertionError("scan started"))
        ),
    )


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------


def test_the_cli_exits_3_and_deletes_nothing_when_git_cannot_answer(
    tmp_path, monkeypatch, capsys
):
    source, output = _broken_repo(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    _no_orchestrator(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert exited.value.code == 3
    printed = _words(capsys.readouterr().out)
    assert "ERROR (3) Scan refused:" in printed, printed
    for name in AT_RESULTS_PATHS:
        assert name in printed, printed
    _assert_names_git_and_both_ways_out(printed, source)
    assert _snapshot(output) == before


def test_the_cli_counts_a_previous_log_before_its_logger_truncates_it(
    tmp_path, monkeypatch, capsys
):
    """The log files are results paths too: the CLI's logger truncates them."""
    source, output = _broken_repo(
        tmp_path, monkeypatch, files={"ash.log": "previous log\n"}
    )
    _confined(tmp_path, source, output)
    _no_orchestrator(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert exited.value.code == 3
    assert "ash.log" in capsys.readouterr().out
    assert (output / "ash.log").read_text(encoding="utf-8") == "previous log\n"


def test_inside_nix_mode_the_hosts_log_files_do_not_stop_the_inner_scan(
    tmp_path, monkeypatch, capsys
):
    """Nix mode runs the CLI again in the same output directory, after the host
    CLI checked it in full and its logger opened the log files there."""
    source, output = _broken_repo(
        tmp_path, monkeypatch, files={"ash.log": "the host's log\n"}
    )
    _confined(tmp_path, source, output)
    monkeypatch.setenv("ASH_IN_NIX", "1")
    started: List[bool] = []

    def _create(cls, **kwargs):
        started.append(True)
        raise AssertionError("scan started")

    monkeypatch.setattr(ASHScanOrchestrator, "create", classmethod(_create))

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    printed = _words(capsys.readouterr().out)
    assert started == [True], printed
    assert exited.value.code != 3, printed


def test_the_local_run_exits_3_from_the_orchestrator_and_keeps_the_results(
    tmp_path, monkeypatch, capsys
):
    """Through _run_local_mode, past the CLI's own check, as the existing
    committed-results test runs it: the scan is stubbed to fail."""
    source, output = _broken_repo(tmp_path, monkeypatch)
    results = output / "ash_aggregated_results.json"
    kept = results.read_bytes()
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "execute_scan",
        lambda self, *a, **k: (_ for _ in ()).throw(AssertionError("scanned")),
    )
    opts = ScanOptions(source_dir=source, output_dir=output)
    _confined(tmp_path, opts.source_dir, opts.output_dir)

    with pytest.raises(SystemExit) as exited:
        _run_local_mode(opts, logging.getLogger("test-git-cannot-answer"))

    assert exited.value.code == 3
    _assert_names_git_and_both_ways_out(capsys.readouterr().out, source)
    assert results.read_bytes() == kept


def test_the_orchestrator_refuses_and_clears_nothing(tmp_path, monkeypatch):
    source, output = _broken_repo(tmp_path, monkeypatch)
    (output / "scanners" / "grype").mkdir(parents=True)
    (output / "scanners" / "grype" / "old.sarif").write_text("old\n", encoding="utf-8")
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)
    before = _snapshot(output)

    with pytest.raises(ASHConfigValidationError) as refused:
        _initialize(orchestrator)

    assert isinstance(refused.value, CommittedOutputFilesError)
    assert type(refused.value).__name__ == "UnverifiedOutputFilesError"
    message = str(refused.value)
    assert "scanners/grype/old.sarif" in message, message
    _assert_names_git_and_both_ways_out(message, source)
    assert _snapshot(output) == before


def test_a_scan_into_an_empty_output_dir_starts_when_git_cannot_answer(
    tmp_path, monkeypatch, capsys
):
    """Nothing is at the results paths, so nothing could be lost. The CLI's logger
    opens ash.log before the orchestrator checks, and that file, this run's own,
    does not stop the scan."""
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    _confined(tmp_path, source, output)
    reached: List[bool] = []

    class _Reached(Exception):
        pass

    def _ensure_directories(self):
        reached.append(True)
        raise _Reached

    monkeypatch.setattr(ASHScanOrchestrator, "ensure_directories", _ensure_directories)

    with pytest.raises(SystemExit):
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    printed = _words(capsys.readouterr().out)
    assert "Scan refused" not in printed, printed
    assert reached == [True], printed
    assert (output / "ash.log").exists(), "the logger did not open its file"


def test_a_report_over_results_read_from_elsewhere_is_not_stopped_by_this_runs_log(
    tmp_path, monkeypatch
):
    """``--use-existing`` may read results from outside the output directory. By the
    time the orchestrator checks, the CLI's logger has opened ash.log there, and
    that file does not stop the report."""
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    (output / "ash.log").write_text("this run's log\n", encoding="utf-8")
    existing = tmp_path / "previous" / "ash_aggregated_results.json"
    existing.parent.mkdir()
    existing.write_text(_results_json("previous-run"), encoding="utf-8")
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config_path=None,
        config_overrides=None,
        no_cleanup=True,
        metadata=None,
        ash_plugin_modules=[],
        existing_results_path=existing,
    )
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir, existing)

    _initialize(orchestrator)

    assert (output / "ash.log").read_text(encoding="utf-8") == "this run's log\n"


def _report_over_existing_results(tmp_path, source, output) -> int:
    existing = tmp_path / "previous" / "ash_aggregated_results.json"
    existing.parent.mkdir()
    existing.write_text(_results_json("previous-run"), encoding="utf-8")
    _confined(tmp_path, source, output, existing)
    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
            existing_results=str(existing),
        )
    return exited.value.code


@pytest.mark.parametrize(
    "git_answers", [False, True], ids=["git-cannot-answer", "committed"]
)
def test_a_refused_report_over_existing_results_is_not_called_a_scan(
    tmp_path, monkeypatch, capsys, git_answers
):
    """``--use-existing`` reports over results a scan wrote earlier and starts no
    scan, so its refusal says the run did not start, not the scan."""
    from tests.unit.test_committed_output_refused_at_entry_points import (
        _repo as _committed_repo,
    )

    files = {"reports/old.html": "old\n"}
    if git_answers:
        source, output = _committed_repo(tmp_path, monkeypatch, committed=files)
    else:
        source, output = _broken_repo(tmp_path, monkeypatch, files=files)
    _no_orchestrator(monkeypatch)

    assert _report_over_existing_results(tmp_path, source, output) == 3

    printed = _words(capsys.readouterr().out)
    assert "reports/old.html" in printed, printed
    assert "scan did not start" not in printed, printed
    assert "this run did not start" in printed, printed


def test_a_refused_scan_says_this_run_did_not_start(tmp_path, monkeypatch, capsys):
    source, output = _broken_repo(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    _no_orchestrator(monkeypatch)

    with pytest.raises(SystemExit):
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    printed = _words(capsys.readouterr().out)
    assert "this run did not start" in printed, printed
    assert "To run it," in printed, printed


# ---------------------------------------------------------------------------
# Outside a repository, and a repository git can read
# ---------------------------------------------------------------------------


def test_outside_a_repository_the_previous_runs_files_are_removed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    source = tmp_path / "plain"
    output = source / ".ash" / "ash_output"
    for relative, text in AT_RESULTS_PATHS.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert not (source / ".git").exists()
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)

    _initialize(orchestrator)

    assert not (output / "ash_aggregated_results.json").exists()
    assert not (output / "reports" / "ash.sarif").exists()


def _owned_by_another_user(monkeypatch, source: Path) -> None:
    """git, from here on, treats every repository as another user's."""
    monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
    discovered = _git(source, "ls-files")
    # A control: git honors the variable, and refuses the repository it finds.
    assert discovered.returncode != 0, discovered
    assert "dubious ownership" in discovered.stderr, discovered


def _mark_safe(monkeypatch, tmp_path: Path, source: Path) -> None:
    """A global git config, read by ASH's git and nothing else, listing *source*."""
    config = tmp_path / "global.gitconfig"
    config.write_text(f"[safe]\n\tdirectory = {source.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    # Controls: git reads the entry from the file, and such an entry lets git read
    # the repository it discovers again.
    entries = _git(
        tmp_path, "config", "--file", str(config), "--get-all", "safe.directory"
    )
    assert entries.stdout.split() == [source.as_posix()], entries
    listed = _git(source, "-c", f"safe.directory={source.as_posix()}", "ls-files")
    assert listed.returncode == 0, listed


@pytest.mark.parametrize("safe_directory", [False, True], ids=["unlisted", "listed"])
def test_a_checkout_owned_by_another_user_has_its_previous_results_removed(
    tmp_path, monkeypatch, safe_directory
):
    """git answers ASH's question about such a checkout, listed in
    safe.directory or not, so an untracked previous run's results are removed
    and nothing is refused."""
    source, output = _repo(tmp_path, monkeypatch, committed={"keep.txt": "kept\n"})
    stale = output / "ash_aggregated_results.json"
    stale.write_text(_results_json("previous-run"), encoding="utf-8")
    _owned_by_another_user(monkeypatch, source)
    if safe_directory:
        _mark_safe(monkeypatch, tmp_path, source)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)

    _initialize(orchestrator)

    assert not stale.exists()
    assert (output / "keep.txt").read_text(encoding="utf-8") == "kept\n"


def test_a_checkout_owned_by_another_user_still_has_its_committed_results_refused(
    tmp_path, monkeypatch
):
    """The refusal is the committed-files one: git said what is committed."""
    source, output = _repo(tmp_path, monkeypatch)
    _owned_by_another_user(monkeypatch, source)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)
    before = _snapshot(output)

    with pytest.raises(ASHConfigValidationError) as refused:
        _initialize(orchestrator)

    assert type(refused.value) is CommittedOutputFilesError
    assert "reports/ash.sarif" in str(refused.value)
    assert _snapshot(output) == before


# ---------------------------------------------------------------------------
# Workspace mode
# ---------------------------------------------------------------------------

#: On disk where a workspace scan deletes or writes: the unified results, the
#: spool, and a project's own results paths.
WORKSPACE_LEFTOVERS = (
    "ash_aggregated_results.json",
    ".workspace-spool/api/ash_aggregated_results.json",
    "projects/api/reports/ash.sarif",
)


def _broken_workspace(tmp_path: Path, monkeypatch):
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    for relative in WORKSPACE_LEFTOVERS:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"previous {relative}\n", encoding="utf-8")
    return source, output, _workspace_plan(source)


def test_a_workspace_scan_exits_3_naming_every_leftover_when_git_cannot_answer(
    tmp_path, monkeypatch, capsys
):
    source, output, plan = _broken_workspace(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            workspace_plan=plan,
            progress=False,
            show_summary=False,
        )

    assert exited.value.code == 3
    assert executed == [], "the workspace was scanned"
    printed = capsys.readouterr().out.replace("\n", "")
    for relative in WORKSPACE_LEFTOVERS:
        assert relative in printed, printed
    assert _snapshot(output) == before


@pytest.mark.asyncio
async def test_the_mcp_workspace_tool_returns_exit_3_when_git_cannot_answer(
    tmp_path, monkeypatch, isolated_registry
):
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    source, output, plan = _broken_workspace(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    result = await mcp_scan_workspace(
        workspace_file=plan.workspace_file, clean_output=True
    )

    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    _assert_names_git_and_both_ways_out(result["error"], source)
    assert executed == []
    assert isolated_registry.get_scan_count() == 0
    assert _snapshot(output) == before


# ---------------------------------------------------------------------------
# The MCP scan tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_mcp_scan_directory_tool_returns_the_refusal(
    tmp_path, monkeypatch, isolated_registry
):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )

    source, output = _broken_repo(tmp_path, monkeypatch)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    runner = AsyncMock()
    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)

    result = await mcp_tools.mcp_scan_directory(directory_path=str(source))
    await asyncio.sleep(0)

    assert result["success"] is False, result
    assert "ash_aggregated_results.json" in result["error"], result
    _assert_names_git_and_both_ways_out(result["error"], source)
    assert isolated_registry.get_scan_count() == 0
    runner.assert_not_called()
    assert _snapshot(output) == before


@pytest.mark.asyncio
async def test_the_mcp_scan_tool_returns_the_refusal_before_clean_output(
    tmp_path, monkeypatch, mcp_ctx, isolated_registry
):
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )
    from automated_security_helper.cli.mcp_server import run_ash_scan as scan_tool

    source, output = _broken_repo(tmp_path, monkeypatch)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    before = _snapshot(output)

    with (
        patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
            return_value={"success": True, "scan_id": "should-not-start"},
        ) as started,
        patch("automated_security_helper.cli.mcp_server.asyncio.create_task"),
    ):
        result = await scan_tool(ctx=mcp_ctx, source_dir=str(source), clean_output=True)

    assert _snapshot(output) == before, "clean_output removed the results"
    assert result["success"] is False, result
    assert result["error_type"] == "committed_output_files", result
    _assert_names_git_and_both_ways_out(result["error"], source)
    started.assert_not_called()


# ---------------------------------------------------------------------------
# What git said, and what is counted on disk
# ---------------------------------------------------------------------------


def _committed_entries_in_the_way(output: Path, **kwargs):
    from automated_security_helper.core.committed_output import (
        committed_entries_in_the_way,
    )

    return committed_entries_in_the_way(output, **kwargs)


def test_a_git_file_naming_a_missing_directory_is_named_in_the_refusal(
    tmp_path, monkeypatch
):
    """A worktree or submodule checkout whose repository is not there, as in a
    container that mounts the checkout alone."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    source = tmp_path / "checkout"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text("{}\n", encoding="utf-8")
    missing = tmp_path / "gone" / "worktrees" / "checkout"
    (source / ".git").write_text(f"gitdir: {missing.as_posix()}\n", encoding="utf-8")

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = _words(str(refused.value))
    assert "not a git repository" in message, message
    assert missing.as_posix() in message, message
    assert "ash_aggregated_results.json" in message, message


def test_git_missing_from_path_is_named_in_the_refusal(tmp_path, monkeypatch):
    source, output = _repo(tmp_path, monkeypatch)
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = _words(str(refused.value))
    assert "git could not be run" in message, message
    assert "make git available" in message, message
    assert "remove the old results" in message, message


def test_git_timing_out_is_named_in_the_refusal(tmp_path, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    source, output = _repo(tmp_path, monkeypatch)

    def _times_out(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout") or 30)

    monkeypatch.setattr(subprocess_utils, "spawn_run", _times_out)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = _words(str(refused.value))
    assert "git did not answer within 30 seconds" in message, message
    assert "reports/ash.sarif" in message, message


def test_an_ownership_refusal_names_the_safe_directory_fix(tmp_path, monkeypatch):
    """git does not check ownership for the repository ASH names on its command
    line (see the module docstring); were it to refuse one, the message gives
    the command git itself suggests."""
    from automated_security_helper.utils import subprocess_utils

    source, output = _repo(tmp_path, monkeypatch)
    stderr = (
        f"fatal: detected dubious ownership in repository at '{source.as_posix()}'\n"
        "To add an exception for this directory, call:\n\n"
        f"\tgit config --global --add safe.directory {source.as_posix()}\n"
    ).encode()

    def _refuses(args, **kwargs):
        return subprocess.CompletedProcess(args, 128, stdout=b"", stderr=stderr)

    monkeypatch.setattr(subprocess_utils, "spawn_run", _refuses)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = _words(str(refused.value))
    assert "dubious ownership" in message, message
    # The path is shell-quoted where a shell would split it, so the expected
    # command is built the same way; a temp path of plain characters is unchanged.
    command = (
        f"git config --global --add safe.directory {shlex.quote(source.as_posix())}"
    )
    assert command in message, message


def test_only_the_paths_a_run_writes_are_counted_on_disk(tmp_path, monkeypatch):
    """The same scoping as for committed entries: a report over existing results
    writes reports/, the results file and the log files, and not scanners/."""
    source, output = _broken_repo(
        tmp_path, monkeypatch, files={"scanners/bandit/old.sarif": "old\n"}
    )
    in_scope = {
        "files": ("ash_aggregated_results.json", "ash.log", "ash.log.jsonl"),
        "directories": ("reports",),
    }

    assert _committed_entries_in_the_way(output, **in_scope) == []

    (output / "reports").mkdir()
    (output / "reports" / "old.html").write_text("old\n", encoding="utf-8")
    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output, **in_scope)
    message = str(refused.value)
    assert "reports/old.html" in message, message
    assert "scanners/bandit/old.sarif" not in message, message


def test_empty_working_directories_and_files_elsewhere_are_not_counted(
    tmp_path, monkeypatch
):
    source, output = _broken_repo(
        tmp_path, monkeypatch, files={"hidden/app.py": "x = 1\n"}
    )
    for name in ("analysis", "reports/nested/deeper", "scanners", "converted"):
        (output / name).mkdir(parents=True)

    assert _committed_entries_in_the_way(output) == []


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_link_at_a_results_path_counts_and_is_not_followed(tmp_path, monkeypatch):
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "theirs.txt").write_text("theirs\n", encoding="utf-8")
    (output / "reports").symlink_to(outside, target_is_directory=True)
    (output / "scanners").mkdir()
    (output / "scanners" / "linked").symlink_to(outside, target_is_directory=True)
    (output / "ash-scan-set-run.json").symlink_to(tmp_path / "nowhere")
    _confined(tmp_path, output, outside)

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = str(refused.value)
    for name in ("reports", "scanners/linked", "ash-scan-set-run.json"):
        assert name in message, message
    assert "theirs.txt" not in message, message
    assert (outside / "theirs.txt").read_text(encoding="utf-8") == "theirs\n"


@pytest.mark.parametrize(
    "held",
    [
        ".ash_previous_results/reports/ash.html",
        ".ash_previous_results.partial/ash_aggregated_results.json",
        ".ash_previous_results_restored",
    ],
)
def test_previous_results_set_aside_are_counted_on_disk(tmp_path, monkeypatch, held):
    """A scan removes a held set of previous results, and the marker a restore
    left, when it starts (core/previous_results.py)."""
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        RESTORED_MARKER_NAME,
    )

    # A control: the parameters are the names the scan uses.
    assert held.split("/")[0] in {
        HELD_DIR_NAME,
        f"{HELD_DIR_NAME}.partial",
        RESTORED_MARKER_NAME,
    }
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    path = output / held
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("previous\n", encoding="utf-8")

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    assert held in str(refused.value), refused.value


def test_the_refusal_names_ten_entries_and_counts_the_rest(tmp_path, monkeypatch):
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    (output / "reports").mkdir()
    for index in range(13):
        (output / "reports" / f"r{index:02d}.html").write_text("x\n", encoding="utf-8")

    with pytest.raises(CommittedOutputFilesError) as refused:
        _committed_entries_in_the_way(output)

    message = str(refused.value)
    assert "reports/r09.html" in message, message
    assert "reports/r10.html" not in message, message
    assert "and 3 more" in message, message


def test_git_not_answering_in_the_scan_set_walk_is_a_warning(tmp_path, monkeypatch):
    """The walk leaves a named output directory out whole when git cannot say
    which of its files are committed; debug level alone would hide that."""
    source, output = _broken_repo(tmp_path, monkeypatch, files={"keep.txt": "kept\n"})
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        assert tracked_files_in(output) is None
    finally:
        ASH_LOGGER.removeHandler(handler)

    warnings = [r.getMessage() for r in records if r.levelno == logging.WARNING]
    assert any(GIT_ERROR in text for text in warnings), warnings
