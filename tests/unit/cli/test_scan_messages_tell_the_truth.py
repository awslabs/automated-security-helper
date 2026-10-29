# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash scan`` tells the operator matches what the code does.

Each case here was a message or a help text that described ASH as it once was, or as
nobody wrote it:

* the incomplete-scan message told the operator to "drop
  --fail-on-incomplete-scanners", a flag that is on by default, so dropping it changes
  nothing; the opt-out is ``--no-fail-on-incomplete-scanners``. The flag's own help
  said both "without this, a run where nothing ran exits 0" and "defaults to on";
* the exit-code legend printed after a failing scan listed 0, 1 and 2 of the six codes
  a scan can return;
* ``--mode`` said precommit enables Python-based plugins only. It does not touch the
  Python filter: it runs a fixed scanner list, which includes npm-audit;
* the "Next steps" report paths were relative to the source directory, while the
  metrics table printed just above them is relative to the working directory, so the
  two named the same directory differently whenever they differ;
* the metrics legend offered a "(s)canner" threshold source that nothing produces;
* help text and runtime hints pointed at documentation files that do not exist;
* ``run_ash_scan(...)``, the documented Python entry point, refuses a keyword
  argument it does not take, as ``ash scan`` refuses an unknown option.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest.mock import patch

import pytest
import typer.main

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def _option_help(command: str, name: str) -> str:
    root = typer.main.get_command(app)
    cmd = root.commands[command]
    return next(param.help for param in cmd.params if param.name == name)


class TestTheIncompleteScanOptOut:
    @pytest.mark.parametrize(
        "scanner_rows, converter_rows",
        [
            pytest.param([("grype", "MISSING")], [], id="scanner-arm"),
            pytest.param(
                [], [("jupyter", "nbconvert not installed")], id="converter-arm"
            ),
        ],
    )
    def test_the_message_names_the_flag_that_turns_the_gate_off(
        self, capsys, scanner_rows, converter_rows
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            print_incompleteness_message,
        )

        print_incompleteness_message(scanner_rows, converter_rows)

        out = _plain(capsys.readouterr().out)
        assert "drop --fail-on-incomplete-scanners" not in out
        assert "--no-fail-on-incomplete-scanners" in out

    @pytest.mark.parametrize("command", ["scan", "merge"])
    def test_the_help_says_the_gate_is_on_by_default_and_nothing_else(self, command):
        text = _plain(_option_help(command, "fail_on_incomplete_scanners"))

        assert "on by default" in text.lower()
        assert "--no-fail-on-incomplete-scanners" in text
        for contradiction in ("Without this,", "Without it,"):
            assert contradiction not in text, text


class TestTheExitCodeLegend:
    def test_lists_every_code_a_scan_can_return(self, capsys):
        from automated_security_helper.core.constants import ASH_EXIT_CODES
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            print_exit_code_legend,
        )

        opts = ScanOptions(source_dir=Path.cwd(), output_dir=Path.cwd() / "out")
        print_exit_code_legend(opts, actionable_count=3)

        out = _ANSI.sub("", capsys.readouterr().out)
        for code, meaning in ASH_EXIT_CODES.items():
            assert f"  {code}: {meaning}" in out, out
        assert "ERROR (2) Exiting due to 3 actionable findings" in out


class TestTheModeHelp:
    def test_says_what_precommit_runs(self):
        from automated_security_helper.interactions.run_ash_scan import (
            PRECOMMIT_MODE_SCANNERS,
        )

        text = _plain(_option_help("scan", "mode"))

        assert "python-based plugins only" not in text.lower()
        for scanner in PRECOMMIT_MODE_SCANNERS:
            assert scanner in text
        for mode in ("local", "precommit", "container", "nix"):
            assert f"'{mode}'" in text

    def test_precommit_mode_selects_exactly_those_scanners(self, tmp_path, monkeypatch):
        """The help is built from the list the scan uses, and the scan uses it."""
        from unittest.mock import MagicMock, patch

        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.interactions import run_ash_scan as mod

        (tmp_path / "src").mkdir()
        opts = mod.ScanOptions(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            mode=RunMode.precommit,
        )
        with (
            patch(
                "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
                side_effect=RuntimeError("stop"),
            ) as create,
            pytest.raises(SystemExit),
        ):
            mod._run_local_mode(opts, MagicMock())

        assert sorted(create.call_args.kwargs["enabled_scanners"]) == sorted(
            mod.PRECOMMIT_MODE_SCANNERS
        )


class TestReportPathsAreRelativeToTheWorkingDirectory:
    def _next_steps(self, capsys, source_dir: Path, output_dir: Path) -> str:
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_summary,
        )

        opts = ScanOptions(source_dir=source_dir, output_dir=output_dir)
        _print_summary(None, opts, scan_start_time=0.0, actionable_findings=0)
        # rich folds a long path across lines, mid-word; the path is what is tested.
        return _ANSI.sub("", capsys.readouterr().out).replace("\n", "")

    def test_inside_the_working_directory(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        (tmp_path / "src").mkdir()

        out = self._next_steps(
            capsys, tmp_path / "src", tmp_path / "src" / ".ash" / "ash_output"
        )

        assert "'src/.ash/ash_output/reports/ash.sarif'" in out, out

    def test_outside_the_working_directory_is_absolute(
        self, tmp_path, monkeypatch, capsys
    ):
        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        output_dir = tmp_path / "elsewhere" / "out"

        out = self._next_steps(capsys, tmp_path / "elsewhere", output_dir)

        assert f"'{output_dir.as_posix()}/reports/ash.sarif'" in out, out

    @pytest.mark.parametrize("inside", [True, False], ids=["inside", "outside"])
    def test_the_workspace_summary_uses_the_same_rule(
        self, tmp_path, monkeypatch, capsys, inside
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_workspace_summary,
            display_path,
        )
        from automated_security_helper.models.workspace import WorkspaceResults
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        root = (tmp_path / "cwd" if inside else tmp_path / "elsewhere") / "repo"
        output = root / ".ash" / "ash_output"
        payload = WorkspaceResults(
            workspace_file=(root / "dev.code-workspace").as_posix(),
            workspace_root=root.as_posix(),
            exit_code=0,
            projects=[],
        )
        result = WorkspaceRunResult(
            results_path=output / "ash_aggregated_results.json",
            exit_code=0,
            payload=payload,
        )

        _print_workspace_summary(
            result, ScanOptions(source_dir=root, output_dir=output), 0.0
        )

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        for path in (
            root / "dev.code-workspace",
            output,
            output / "ash_aggregated_results.json",
            output / "projects",
        ):
            assert display_path(path) in out, (display_path(path), out)
        if inside:
            assert tmp_path.as_posix() not in out, out

    def test_the_metrics_table_uses_the_same_rule(self, tmp_path, monkeypatch):
        from automated_security_helper.core.metrics_table import (
            generate_metrics_table_from_unified_data,
        )
        from automated_security_helper.interactions.run_ash_scan import (
            display_path,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        monkeypatch.chdir(tmp_path)
        for output_dir in (tmp_path / "src" / "out", tmp_path.parent / "out"):
            table = generate_metrics_table_from_unified_data(
                AshAggregatedResults(),
                source_dir=tmp_path / "src",
                output_dir=output_dir,
            )
            assert f"output-dir: '{display_path(output_dir)}'" in table.caption


#: Text Rich would read as markup: a closing tag raises MarkupError, an opening tag
#: is silently removed. Both are legal in a path.
_MARKUP_LIKE = ["out[/such]", "out[bold]x"]


class TestPathsArePrintedAsGiven:
    """A path in a message is printed as the operator gave it, whatever it contains."""

    @pytest.mark.parametrize("name", _MARKUP_LIKE)
    def test_next_steps(self, tmp_path, monkeypatch, capsys, name):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_summary,
        )

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / name)

        _print_summary(None, opts, scan_start_time=0.0, actionable_findings=1)

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        # Every line that prints the output directory, so a markup-like name that
        # vanished from one of them cannot pass.
        for printed in (
            "reports/ash.sarif",
            "reports/ash.junit.xml",
            "ash_aggregated_results.json",
            "reports/ash.html",
            "reports/ash.summary.md",
            "reports/ash.summary.txt",
            "scanners",
        ):
            assert f"'{name}/{printed}'" in out, (printed, out)

    @pytest.mark.parametrize("name", _MARKUP_LIKE)
    def test_workspace_summary(self, tmp_path, monkeypatch, capsys, name):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_workspace_summary,
        )
        from automated_security_helper.models.workspace import WorkspaceResults
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        output = tmp_path / name
        payload = WorkspaceResults(
            workspace_file=(tmp_path / f"{name}.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            exit_code=0,
            projects=[],
        )
        result = WorkspaceRunResult(
            results_path=output / "ash_aggregated_results.json",
            exit_code=0,
            payload=payload,
        )

        _print_workspace_summary(
            result, ScanOptions(source_dir=tmp_path, output_dir=output), 0.0
        )

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        for printed in (
            f"workspace: {name}.code-workspace",
            f"output:    {name}",
            f"Aggregated results: {name}/ash_aggregated_results.json",
            f"Per-project output: {name}/projects",
        ):
            assert printed in out, out

    @pytest.mark.parametrize("name", _MARKUP_LIKE)
    def test_merge_refusal(self, tmp_path, monkeypatch, name):
        from typer.testing import CliRunner

        from automated_security_helper.core.exceptions import ShardCoverageError

        monkeypatch.chdir(tmp_path)
        with patch(
            "automated_security_helper.cli.merge.load_shard_results",
            side_effect=ShardCoverageError(f"shard {name} completed none"),
        ):
            result = CliRunner().invoke(
                app, ["merge", "--output-dir", "merged", "--results", "."]
            )

        assert result.exit_code == 1, result.output
        assert f"Refusing to merge: shard {name} completed none" in _plain(
            result.output
        )

    @pytest.mark.parametrize("name", _MARKUP_LIKE)
    def test_merge_relocated_output_dir(self, tmp_path, monkeypatch, capsys, name):
        from automated_security_helper.cli.merge import _relocate_colliding_output_dir

        given = tmp_path / name
        (given / "repo").mkdir(parents=True)
        monkeypatch.chdir(given / "repo")

        relocated = _relocate_colliding_output_dir(given)

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        assert relocated == given / ".ash" / "ash_output"
        assert relocated.as_posix() in out, out

    @pytest.mark.parametrize("name", _MARKUP_LIKE)
    def test_merge_summary(self, tmp_path, capsys, name):
        from automated_security_helper.cli.merge import _print_merge_summary
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        merged_file = tmp_path / name / "ash_aggregated_results.json"

        _print_merge_summary(AshAggregatedResults(), merged_file, exit_code=0)

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        assert f"Merged results: {merged_file.as_posix()}" in out, out

    def test_merge_summary_incomplete_scanners(self, tmp_path, capsys):
        from automated_security_helper.cli.merge import _print_merge_summary
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        with patch(
            "automated_security_helper.interactions.run_ash_scan.incomplete_scanners",
            return_value=[("a[/red]b", "MISSING [/x] here"), ("c[bold]d", "ERROR")],
        ):
            _print_merge_summary(
                AshAggregatedResults(), tmp_path / "merged.json", exit_code=1
            )

        out = _ANSI.sub("", capsys.readouterr().out)
        assert "a[/red]b: MISSING [/x] here" in out, out
        assert "c[bold]d: ERROR" in out, out

    def test_config_warnings(self, tmp_path, monkeypatch, capsys):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_summary,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        results = AshAggregatedResults()
        results.validation_checkpoints = [
            {"type": "config_warning", "message": "reporters.a[/b].options is unknown"},
            {"type": "config_warning", "message": "scanners.c[bold]d is unknown"},
        ]
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_summary(results, opts, scan_start_time=0.0, actionable_findings=0)

        out = _ANSI.sub("", capsys.readouterr().out)
        assert "reporters.a[/b].options is unknown" in out, out
        assert "scanners.c[bold]d is unknown" in out, out

    @pytest.mark.parametrize("label", ["a[/red]b", "c[bold]d"])
    def test_workspace_project_lines(self, tmp_path, monkeypatch, capsys, label):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_workspace_summary,
        )
        from automated_security_helper.models.workspace import (
            ProjectRunStatus,
            SkippedProjectReason,
            WorkspaceProjectResult,
            WorkspaceResults,
        )
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        def _project(key, status, **fields):
            return WorkspaceProjectResult(
                project=key,
                relative_path=key,
                display_label=f"{key}-{label}",
                status=status,
                output_path="projects/" + key,
                **fields,
            )

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
        payload = WorkspaceResults(
            workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            exit_code=0,
            projects=[
                _project(
                    "skipped",
                    ProjectRunStatus.SKIPPED,
                    skip_reason=SkippedProjectReason.NO_CHANGES,
                ),
                _project(
                    "failed", ProjectRunStatus.FAILED, error=f"boom in {label} here"
                ),
                _project(
                    "completed",
                    ProjectRunStatus.COMPLETED,
                    finding_count=1,
                    actionable_finding_count=0,
                    exceeds_threshold=False,
                    duration_seconds=1.0,
                ),
            ],
        )
        result = WorkspaceRunResult(
            results_path=tmp_path / "out" / "ash_aggregated_results.json",
            exit_code=0,
            payload=payload,
        )

        _print_workspace_summary(
            result, ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out"), 0.0
        )

        out = _ANSI.sub("", capsys.readouterr().out)
        assert f"skipped-{label} (no-changes)" in out, out
        assert f"failed-{label}: boom in {label} here" in out, out
        assert f"completed-{label} -- 0 actionable of 1" in out, out


class TestABackslashIsPrintedOnce:
    """Rich's escape doubles a trailing backslash wherever no tag follows it.

    ASH_ACTUAL_OUTPUT_DIR is the host's path, which on Windows can end in one.
    Escaped on its own and then joined to "/reports/...", it printed as
    ``C:\\out\\\\/reports/ash.sarif``.
    """

    ALIAS = "C:\\out\\"

    def test_next_steps(self, tmp_path, monkeypatch, capsys):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_summary,
        )

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", self.ALIAS)
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_summary(None, opts, scan_start_time=0.0, actionable_findings=1)

        out = _ANSI.sub("", capsys.readouterr().out).replace("\n", "")
        assert f"'{self.ALIAS}/reports/ash.sarif'" in out, out
        assert f"'{self.ALIAS}/scanners'" in out, out
        assert "\\\\" not in out, out

    def test_workspace_summary(self, tmp_path, monkeypatch, capsys):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _print_workspace_summary,
        )
        from automated_security_helper.models.workspace import WorkspaceResults
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", self.ALIAS)
        payload = WorkspaceResults(
            workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            exit_code=0,
            projects=[],
        )
        result = WorkspaceRunResult(
            results_path=tmp_path / "out" / "ash_aggregated_results.json",
            exit_code=0,
            payload=payload,
        )

        _print_workspace_summary(
            result, ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out"), 0.0
        )

        out = _ANSI.sub("", capsys.readouterr().out)
        assert f"output:    {self.ALIAS}\n" in out, out
        assert "\\\\" not in out, out


class TestStyledTextIsHighlighted:
    """_print_text's styled parts are highlighted as its plain ones are.

    A printed string goes through the console's highlighter, which colors quoted
    strings and numbers. A (text, style) part was passed to Text.assemble as it
    was, so a configuration warning, printed in yellow, lost that on a styled
    console.
    """

    def _styles(self, monkeypatch, *parts):
        import rich
        from rich.console import Console

        from automated_security_helper.interactions.run_ash_scan import _print_text

        console = Console(force_terminal=True, color_system="truecolor", width=200)
        printed = []
        monkeypatch.setattr(console, "print", lambda text, **_: printed.append(text))
        monkeypatch.setattr(rich, "_console", console)

        _print_text(*parts)

        (text,) = printed
        return {str(span.style) for span in text.spans}, text.plain

    def test_a_styled_part(self, monkeypatch):
        message = "  reporters.html.options 'unknown_key' is not an option, line 3"
        styles, plain = self._styles(monkeypatch, (message, "yellow"))

        assert plain == message
        assert {"yellow", "repr.str", "repr.number"} <= styles, styles

    def test_a_plain_part(self, monkeypatch):
        styles, _ = self._styles(monkeypatch, "  output: 'out[/x]' at 3")

        assert {"repr.str", "repr.number"} <= styles, styles

    def test_a_styled_part_renders_as_the_markup_it_replaced_did(self, monkeypatch):
        """Yellow throughout, the highlighting adding only its bold.

        The yellow is not the base style: there it would sit under the
        highlighter's colors, and the warning's quoted words would come out green
        and its numbers bold cyan.
        """
        import rich
        from rich.console import Console

        from automated_security_helper.interactions.run_ash_scan import _print_text

        message = "  reporters.html.options 'unknown_key' is not an option, line 3"

        def _rendered(show):
            console = Console(
                force_terminal=True, color_system="standard", width=200, record=True
            )
            show(console)
            return console.export_text(styles=True)

        def _through_print_text(console):
            monkeypatch.setattr(rich, "_console", console)
            _print_text((message, "yellow"))

        assert _rendered(_through_print_text) == _rendered(
            lambda console: console.print(f"[yellow]{message}[/yellow]")
        )


class TestThresholdSources:
    def test_the_legend_offers_only_sources_that_are_produced(self):
        from automated_security_helper.config.default_config import (
            get_default_config,
        )
        from automated_security_helper.core.metrics_table import METRICS_HELP_TEXT
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        produced = set()
        for overrides in ({}, {"options": {"severity_threshold": "HIGH"}}):
            model = AshAggregatedResults()
            config = get_default_config()
            if overrides:
                config.scanners.bandit.options.severity_threshold = "HIGH"
            model.ash_config = config
            _threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
                model, "bandit"
            )
            produced.add(source)

        line = next(
            line for line in METRICS_HELP_TEXT.splitlines() if "Source:" in line
        )
        offered = set(re.findall(r"\((\w)\)(\w+)", line))
        assert {first + rest for first, rest in offered} == produced, (line, produced)


#: Strings that name a documentation file: help text, hints and messages. Docstrings
#: and comments are excluded; they are read in the checkout, where the path is exact.
_DOCS_PATH = re.compile(r"(?<![\w/.-])(docs/[A-Za-z0-9_./-]+\.md)")


def _docs_paths_in_strings():
    found = []
    for source in sorted((REPO_ROOT / "automated_security_helper").rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        docstrings = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if (
                isinstance(
                    node,
                    (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                )
                and body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                for path in _DOCS_PATH.findall(node.value):
                    found.append((source.relative_to(REPO_ROOT), node.lineno, path))
    return found


class TestDocumentationReferences:
    def test_every_documentation_path_in_a_message_exists(self):
        found = _docs_paths_in_strings()
        assert found, "the scan found no references at all, so it checks nothing"
        missing = [
            f"{source}:{line}: {path}"
            for source, line, path in found
            if not (REPO_ROOT / path).is_file()
        ]
        assert not missing, missing

    def test_config_overrides_points_at_the_configuration_guide(self):
        text = _option_help("scan", "config_overrides")

        assert (
            "https://awslabs.github.io/automated-security-helper/latest/how-to/configure/"
            in text
        )


class TestTheLibraryEntryPointRefusesUnknownKeywords:
    @pytest.mark.parametrize("keyword", ["not_a_parameter", "fail_on_finding"])
    def test_an_unknown_keyword_is_a_type_error_naming_it(self, tmp_path, keyword):
        from unittest.mock import patch

        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.ScanOptions"
            ) as options,
            pytest.raises(TypeError, match=keyword),
        ):
            run_ash_scan(source_dir=tmp_path, **{keyword: False})

        options.assert_not_called()

    def test_an_extra_positional_argument_is_a_type_error(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        signature = __import__("inspect").signature(run_ash_scan)
        too_many = [None] * (len(signature.parameters) + 1)
        with pytest.raises(TypeError):
            run_ash_scan(*too_many)

    @pytest.mark.parametrize(
        "module, name",
        [
            ("automated_security_helper.interactions.run_ash_scan", "run_ash_scan"),
            ("automated_security_helper.cli.merge", "merge_command"),
            ("automated_security_helper.cli.report", "report_command"),
            ("automated_security_helper.cli.scan", "run_ash_scan_cli_command"),
            ("automated_security_helper.cli.image", "build_ash_image_cli_command"),
        ],
    )
    def test_no_public_entry_point_takes_arbitrary_arguments(self, module, name):
        import importlib
        import inspect

        function = getattr(importlib.import_module(module), name)
        kinds = {
            param.kind for param in inspect.signature(function).parameters.values()
        }
        assert inspect.Parameter.VAR_KEYWORD not in kinds, name
        assert inspect.Parameter.VAR_POSITIONAL not in kinds, name


def _programmatic_usage_example(page: Path, heading: str) -> str:
    """The one Python block in the section *heading* opens on *page*."""
    section = page.read_text(encoding="utf-8").split(f"{heading}", 1)[1]
    section = re.split(r"\n#{2,3} ", section, maxsplit=1)[0]
    blocks = re.findall(r"```python\n(.*?)```", section, flags=re.DOTALL)
    assert len(blocks) == 1, blocks
    return blocks[0]


_FOUND = "Found {stats.total} findings, {stats.actionable} actionable"
_ACTIONABLE = "{stats.actionable} actionable findings"


class TestTheDocumentedPythonExampleRuns:
    """The advanced-usage example is the entry point's contract, so it has to run.

    It imports only names that exist, reads ``summary_stats`` off the results'
    metadata, and keeps a scan with findings from ending the call with
    ``SystemExit(2)`` before the print, as the FAQ's shorter copy does too. Only the
    scan itself is stubbed: the import, the keyword binding, the exit-code verdict
    and the attribute access are real. The migration guide, which carried a copy of
    the example, is no longer in the docs.
    """

    @pytest.mark.parametrize(
        "page, heading, printed",
        [
            (page, "## Programmatic Usage", _FOUND)
            for page in (
                "docs/content/docs/advanced-usage.md",
                "docs/content/docs/advanced-usage.md.template",
            )
        ]
        + [("docs/content/faq.md", "## Can I use ASH programmatically?", _ACTIONABLE)],
    )
    def test_the_example_runs_against_a_scan_with_findings(
        self, page, heading, printed, tmp_path, monkeypatch, capsys
    ):
        import logging

        from automated_security_helper.interactions import run_ash_scan as ras
        from tests.snapshot.console.console_inputs import scan_results_model

        model = scan_results_model(with_incomplete_scanners=False)
        monkeypatch.setattr(
            ras, "_setup_logger", lambda opts: logging.getLogger("docs.example")
        )
        monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (model, None))
        (tmp_path / "code").mkdir()
        example = (
            _programmatic_usage_example(REPO_ROOT / page, heading)
            .replace("/path/to/code", (tmp_path / "code").as_posix())
            .replace("/path/to/output", (tmp_path / "output").as_posix())
        )

        exec(compile(example, page, "exec"), {"__name__": "docs_example"})

        out = capsys.readouterr().out
        stats = model.metadata.summary_stats
        assert printed.format(stats=stats) in out
