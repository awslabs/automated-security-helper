# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file that does not load refuses the run; only no file at all means
the defaults.

Why this exists
---------------
A config file carries a project's suppressions, ignore paths and settings. When
one is there and the run cannot use it, scanning with the built-in defaults
instead reports a result for a run the operator did not ask for: every finding
the file suppressed comes back, every path it ignored is scanned, and the exit
code says success. So a config file that does not parse, or parses and does not
validate, refuses the run with exit 3 before anything is scanned, whichever way
it was chosen:

- discovered in the scanned directory (``.ash/.ash.yaml``), in a single-directory
  scan and for a workspace project;
- named with ``--config``, in a single-directory scan, and in a workspace as the
  config of a project that declares none.

The refusal names the file and what the parser or the validator said.
``--dry-run`` refuses the same way, so a plan is never reported for a run that
would be refused. The defaults apply only when no config file exists.

Nothing is scanned in any cell: the orchestrator's execute_scan is a stand-in
that records its calls, git lookups answer "no repository", and no results file
may be written.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: Text no YAML parser reads: an unclosed flow sequence.
UNPARSABLE = "project_name: [unclosed\n"
#: How every refusal says it: where the parser stopped, and nothing the parser
#: itself said, which can quote the file (unparsed_config_reason).
PARSER_SAYS = (
    "could not be parsed "
    "(ParserError at line 2, column 1; started at line 1, column 15)"
)
#: Parses, and does not validate: global_settings must be a mapping.
INVALID = "project_name: probe\nglobal_settings: 7\n"

SCAN = "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan"


def _squeezed(text: str) -> str:
    """``text`` with all whitespace removed, so a line Rich wrapped compares."""
    return "".join(text.split())


class _Run:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "p1"
        self.project.mkdir()
        (self.project / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.output = root / "out"
        self.scans: list = []

    @property
    def discovered(self) -> Path:
        return self.project / ".ash" / ".ash.yaml"

    @property
    def named(self) -> Path:
        return self.root / "defaults.yaml"

    def write_discovered(self, text: str) -> None:
        self.discovered.parent.mkdir()
        self.discovered.write_text(text, encoding="utf-8")

    def write_named(self, text: str) -> None:
        self.named.write_text(text, encoding="utf-8")

    def invoke(self, *, workspace: bool, dry_run: bool, named: bool):
        args = ["scan", "--no-progress", "--output-dir", str(self.output)]
        if workspace:
            (self.root / "dev.code-workspace").write_text(
                json.dumps({"folders": [{"path": "p1"}]}), encoding="utf-8"
            )
            args += ["--workspace", "dev.code-workspace"]
        else:
            args += ["--source-dir", str(self.project)]
        if named:
            args += ["--config", str(self.named)]
        if dry_run:
            args.append("--dry-run")

        def scan(*_args, **_kwargs):
            self.scans.append(1)
            raise RuntimeError("the stand-in scan started")

        with (
            patch(SCAN, scan),
            patch(
                "automated_security_helper.workspace.execution.git_repository_root",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
                return_value=(None, "not a git repository"),
            ),
        ):
            return CliRunner().invoke(app, args)

    def results_written(self) -> list:
        if not self.output.exists():
            return []
        return sorted(
            p.relative_to(self.output).as_posix() for p in self.output.rglob("*.json")
        )


@pytest.fixture
def run(tmp_path, monkeypatch) -> _Run:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return _Run(tmp_path)


def _refused(run: _Run, result, expected: str) -> None:
    assert result.exit_code == 3, result.output[-3000:]
    assert _squeezed(expected) in _squeezed(result.output), result.output[-3000:]
    assert run.scans == [], "a scan started"
    assert run.results_written() == []


MODES = [
    pytest.param(False, False, id="single"),
    pytest.param(True, False, id="workspace"),
    pytest.param(True, True, id="workspace --dry-run"),
]


@pytest.mark.parametrize(("workspace", "dry_run"), MODES)
def test_a_discovered_config_that_does_not_parse_is_refused(run, workspace, dry_run):
    run.write_discovered(UNPARSABLE)

    result = run.invoke(workspace=workspace, dry_run=dry_run, named=False)

    problem = f"{run.discovered.as_posix()} {PARSER_SAYS}"
    if workspace:
        _refused(
            run,
            result,
            f"Project 'p1' at '{run.project.as_posix()}' has an invalid "
            f"configuration: {problem}",
        )
    else:
        _refused(run, result, f"Invalid configuration: {problem}")


@pytest.mark.parametrize(("workspace", "dry_run"), MODES)
def test_a_discovered_config_that_does_not_validate_is_refused(run, workspace, dry_run):
    run.write_discovered(INVALID)

    result = run.invoke(workspace=workspace, dry_run=dry_run, named=False)

    problem = f"Configuration validation failed for '{run.discovered.as_posix()}'"
    if workspace:
        _refused(
            run,
            result,
            f"Project 'p1' at '{run.project.as_posix()}' has an invalid "
            f"configuration: {problem}",
        )
    else:
        _refused(run, result, f"Invalid configuration: {problem}")


@pytest.mark.parametrize(("workspace", "dry_run"), MODES)
def test_a_named_config_that_does_not_parse_is_refused(run, workspace, dry_run):
    run.write_named(UNPARSABLE)

    result = run.invoke(workspace=workspace, dry_run=dry_run, named=True)

    if workspace:
        _refused(
            run,
            result,
            f"{run.named.as_posix()} {PARSER_SAYS}",
        )
    else:
        _refused(
            run,
            result,
            f"Invalid configuration: {run.named.as_posix()} {PARSER_SAYS}",
        )


@pytest.mark.parametrize("named", [False, True], ids=["discovered", "named"])
def test_a_single_directory_dry_run_is_refused_before_any_config_is_read(run, named):
    """--dry-run is a workspace option: a single-directory scan refuses it with
    exit 4 and scans nothing, whatever its config."""
    if named:
        run.write_named(UNPARSABLE)
    else:
        run.write_discovered(UNPARSABLE)

    result = run.invoke(workspace=False, dry_run=True, named=named)

    assert result.exit_code == 4, result.output[-3000:]
    assert run.scans == []
    assert run.results_written() == []


@pytest.mark.parametrize("dry_run", [False, True], ids=["run", "--dry-run"])
def test_a_workspace_root_config_that_does_not_parse_is_refused(run, dry_run):
    """The workspace root's config sets how the run is scheduled. Each project
    here has a config of its own that loads, and the root's still refuses the
    run: it was meant to configure this run."""
    (run.project / ".ash").mkdir()
    (run.project / ".ash" / ".ash.yaml").write_text(
        "project_name: p1\n", encoding="utf-8"
    )
    root_config = run.root / ".ash" / ".ash.yaml"
    root_config.parent.mkdir()
    root_config.write_text(UNPARSABLE, encoding="utf-8")

    result = run.invoke(workspace=True, dry_run=dry_run, named=False)

    _refused(run, result, f"{root_config.as_posix()} {PARSER_SAYS}")


def _invoke_in(directory: Path, args: list):
    with patch(SCAN, side_effect=AssertionError("a scan started")):
        return CliRunner().invoke(app, args)


def test_dependencies_install_refuses_a_config_that_does_not_parse(run, monkeypatch):
    """Installing for the defaults' plugins instead installs for a plugin set the
    config did not choose."""
    run.write_discovered(UNPARSABLE)
    monkeypatch.chdir(run.project)

    result = _invoke_in(run.project, ["dependencies", "install"])

    assert result.exit_code == 3, result.output[-3000:]
    expected = f"Invalid configuration: {run.discovered.as_posix()} {PARSER_SAYS}"
    assert _squeezed(expected) in _squeezed(result.output), result.output[-3000:]


def test_plugin_list_refuses_a_config_that_does_not_parse(run, monkeypatch):
    run.write_discovered(UNPARSABLE)
    monkeypatch.chdir(run.project)

    result = _invoke_in(run.project, ["plugin", "list"])

    assert result.exit_code == 3, result.output[-3000:]
    expected = f"Invalid configuration: {run.discovered.as_posix()} {PARSER_SAYS}"
    assert _squeezed(expected) in _squeezed(result.output), result.output[-3000:]


def test_a_scan_with_use_existing_refuses_a_config_that_does_not_parse(run):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    run.write_discovered(UNPARSABLE)
    run.output.mkdir()
    existing = run.output / "ash_aggregated_results.json"
    existing.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    before = existing.read_bytes()

    result = _invoke_in(
        run.root,
        [
            "scan",
            "--no-progress",
            "--use-existing",
            "--source-dir",
            str(run.project),
            "--output-dir",
            str(run.output),
        ],
    )

    assert result.exit_code == 3, result.output[-3000:]
    expected = f"Invalid configuration: {run.discovered.as_posix()} {PARSER_SAYS}"
    assert _squeezed(expected) in _squeezed(result.output), result.output[-3000:]
    assert existing.read_bytes() == before
    assert not (run.output / "reports").exists()


def test_merge_refuses_a_named_config_that_does_not_parse(run):
    """merge loads a named config with no fallback and refuses it in its own
    words, as the other loaders do."""
    from tests.unit.cli.test_merge import build_shards, write_shards

    run.write_named(UNPARSABLE)
    args = ["merge", "--config", str(run.named), "--output-dir", str(run.output)]
    for path in write_shards(run.root / "shards", build_shards(2)):
        args += ["--results", str(path)]

    result = _invoke_in(run.root, args)

    assert result.exit_code == 3, result.output[-3000:]
    squeezed = _squeezed(result.output)
    assert _squeezed("Invalid configuration:") in squeezed, result.output[-3000:]
    assert _squeezed(run.named.as_posix()) in squeezed, result.output[-3000:]
    assert _squeezed(PARSER_SAYS) in squeezed, result.output[-3000:]
    assert run.results_written() == []


@pytest.mark.asyncio
async def test_the_mcp_workspace_plan_refuses_a_root_config_that_does_not_parse(
    run, monkeypatch
):
    """resolve_workspace, the MCP dry run, refuses the workspace root's config as
    the scan does, so a plan is never reported for a scan that would be refused."""
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(run.root))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    (run.project / ".ash").mkdir()
    (run.project / ".ash" / ".ash.yaml").write_text(
        "project_name: p1\n", encoding="utf-8"
    )
    root_config = run.root / ".ash" / ".ash.yaml"
    root_config.parent.mkdir()
    root_config.write_text(UNPARSABLE, encoding="utf-8")
    workspace_file = run.root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "p1"}]}), encoding="utf-8"
    )

    response = await mcp_resolve_workspace(workspace_file=str(workspace_file))

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    expected = f"{root_config.as_posix()} {PARSER_SAYS}"
    assert _squeezed(expected) in _squeezed(str(response.get("error"))), response


def test_run_ash_scan_refuses_a_config_that_does_not_parse(run, monkeypatch):
    """The function the MCP scan tools run in the background, and a program's
    own entry point."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    run.write_discovered(UNPARSABLE)

    with (
        patch(SCAN, side_effect=AssertionError("a scan started")) as scan,
        pytest.raises(SystemExit) as exited,
    ):
        run_ash_scan(
            source_dir=str(run.project),
            output_dir=str(run.output),
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    message = getattr(exited.value, "message", "")
    assert exited.value.code == 3, message
    expected = f"{run.discovered.as_posix()} {PARSER_SAYS}"
    assert _squeezed(expected) in _squeezed(message), message
    scan.assert_not_called()
    assert run.results_written() == []


@pytest.mark.asyncio
async def test_the_mcp_scan_tool_refuses_a_config_that_does_not_parse(run, monkeypatch):
    """Refused before the scan starts, as a named config the tool cannot load is."""
    from unittest.mock import AsyncMock

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )

    run.write_discovered(UNPARSABLE)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(run.root))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    runner = AsyncMock()
    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)

    response = await mcp_tools.mcp_scan_directory(directory_path=str(run.project))

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    expected = (
        f"Configuration file cannot be loaded: "
        f"{run.discovered.as_posix()} {PARSER_SAYS}"
    )
    assert _squeezed(expected) in _squeezed(str(response.get("error"))), response
    runner.assert_not_called()


def test_the_mcp_get_config_tool_refuses_a_config_that_does_not_parse(run):
    """It never falls back to the defaults, like every other tool here."""
    from automated_security_helper.cli import mcp_tools

    run.write_discovered(UNPARSABLE)

    response = mcp_tools.mcp_get_config(search_dir=str(run.project))

    assert response["success"] is False, response
    assert response["exit_code"] == 3, response
    expected = f"Configuration file cannot be loaded: {run.discovered.as_posix()}"
    assert _squeezed(expected) in _squeezed(str(response.get("error"))), response


def test_with_no_config_file_a_scan_runs_on_the_defaults(run):
    """The control: with no config file anywhere, the scan starts."""
    result = run.invoke(workspace=False, dry_run=False, named=False)

    assert run.scans == [1], result.output[-3000:]


def test_with_no_config_file_a_workspace_plan_is_reported(run):
    """The control: with no config file anywhere, --dry-run reports the plan."""
    result = run.invoke(workspace=True, dry_run=True, named=False)

    assert result.exit_code == 0, result.output[-3000:]
    assert run.scans == []
