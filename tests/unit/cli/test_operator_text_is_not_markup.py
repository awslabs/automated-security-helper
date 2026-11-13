# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command whose input holds text Rich reads as markup does its job.

Paths, scanner names and exception text reach the console through log records and
rich.print. Read as markup, a closing tag such as ``[/x]`` raises MarkupError out of
whichever call prints it: ``ash merge`` with an --output-dir holding one would exit
1 and write no reports, and the scan's own handler would re-raise it from
``logger.exception``. These run each command in this process with every process
start refused, so no scanner or tool runs.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.process_guard import refuse_process_starts

pytestmark = pytest.mark.unit

USAGE_ERROR_EXIT = 5


@pytest.fixture(autouse=True)
def no_processes(monkeypatch):
    """Refuse every process start, by every route tests/utils/process_guard.py
    covers, so a test can reach no real tool."""
    return refuse_process_starts(monkeypatch)


@pytest.fixture(autouse=True)
def isolated_plugin_registry(monkeypatch):
    """Give each test its own copy of the plugin registry and its lookup cache.

    The commands here load plugins, and plugin_modules() memoizes what it finds
    per process. Left in place, a later test in the same worker that loads a
    plugin module from its config (tests/unit/cli/
    test_report_refuses_invalid_plugin_options.py loads the AWS reporters) got
    the memoized list without it and could not find its reporter.
    """
    from automated_security_helper.plugins import ash_plugin_manager

    library = ash_plugin_manager.plugin_library
    for kind in ("converters", "scanners", "reporters"):
        monkeypatch.setattr(library, kind, dict(getattr(library, kind)))
    monkeypatch.setattr(
        library,
        "event_handlers",
        {event: list(handlers) for event, handlers in library.event_handlers.items()},
    )
    monkeypatch.setattr(ash_plugin_manager, "_resolved_plugins", {})


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_MODE", "ASH_SCANNERS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("UV_OFFLINE", "1")
    (tmp_path / "src").mkdir()
    return tmp_path


def _plain(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.skipif(os.name == "nt", reason="the POSIX process primitives")
def test_the_process_guard_refuses_a_start_through_posix():
    """os copies its process functions from posix, so a guard that patches only the
    os names leaves posix.system and the rest reachable."""
    import posix

    with pytest.raises(AssertionError, match="the test started a process"):
        posix.system("true")


def test_merge_writes_its_reports_to_a_bracketed_output_dir(in_tmp):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        CsvReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )
    from tests.unit.cli.test_merge import build_shards, write_shards

    shard_paths = write_shards(in_tmp / "artifacts", build_shards(3))
    output_dir = in_tmp / "merged[/x]"
    args = ["merge", "--output-dir", str(output_dir), "--output-formats", "sarif,csv"]
    for path in shard_paths:
        args += ["--results", path]
    manager = MagicMock()
    manager.plugin_modules.return_value = [SarifReporter, CsvReporter]

    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        result = CliRunner().invoke(app, args)

    assert result.exit_code == 2, result.output
    assert (output_dir / "reports" / "ash.sarif").is_file()
    assert (output_dir / "reports" / "ash.csv").is_file()


def test_scan_refuses_a_bracketed_scanner_name_as_a_usage_error(in_tmp):
    with patch(
        "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
        return_value=(None, "not a git repository"),
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--no-progress",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
                "--scanners",
                "x[/y]",
                "--phases",
                "scan",
                "--no-show-summary",
            ],
        )

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert "None of the requested scanners exist: x[/y]" in _plain(result.output)


def test_an_adjusted_output_dir_is_printed_as_given(in_tmp):
    """With the source and output directories the same, the scan moves its output
    under .ash/ash_output and says so; the notice was markup, so a "[/x]" in the
    path ended the scan in a MarkupError traceback."""
    (in_tmp / "src-[").mkdir()
    (in_tmp / "src-[" / "x]").mkdir()
    with (
        patch(
            "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
            return_value=(None, "not a git repository"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            side_effect=RuntimeError("stop after the notice"),
        ),
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--no-progress",
                "--source-dir",
                "src-[/x]",
                "--output-dir",
                "src-[/x]",
            ],
        )

    assert "MarkupError" not in result.output, result.output
    assert not isinstance(result.exception, AttributeError), result.exception
    assert "output-dir has been adjusted" in _plain(result.output), result.output
    assert "src-[/x]/.ash/ash_output" in _plain(result.output), result.output


def test_a_bracketed_config_path_gets_the_config_checks_exit(in_tmp):
    """With --debug, the scan logs the config path as it resolves it. As markup, a
    "[/b]" in that path raised MarkupError, and the scan exited 1 instead of the
    invalid configuration's 3."""
    (in_tmp / "x[" / "b]").mkdir(parents=True)
    (in_tmp / "x[" / "b]" / "c.yaml").write_text(
        "project_name: bracketed\nglobal_settings:\n  severity_threshold: NOPE\n",
        encoding="utf-8",
    )
    with patch(
        "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
        return_value=(None, "not a git repository"),
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--no-progress",
                "--debug",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
                "--config",
                "x[/b]/c.yaml",
                "--phases",
                "scan",
                "--no-show-summary",
            ],
        )

    assert "MarkupError" not in result.output, result.output
    assert result.exit_code == 3, result.output
    # The scan names the file once it loads it, so a file that does not load is
    # named where it is read (the "specified at" line a second discovery logged
    # is gone, tests/unit/interactions/test_config_log_names_the_loaded_file.py).
    assert "Loading configuration from x[/b]/c.yaml" in _plain(result.output)


@pytest.mark.parametrize(
    "error, code, printed",
    [
        pytest.param(
            "RuntimeError",
            1,
            "Exiting due to exception during ASH scan: boom in a[/x] b",
            id="unexpected",
        ),
        # The local "ERROR (3) Invalid configuration" refusal: without this case,
        # its value could go unescaped with every test green.
        pytest.param(
            "ASHConfigValidationError",
            3,
            "Invalid configuration: boom in a[/x] b",
            id="invalid-configuration",
        ),
    ],
)
def test_an_exception_holding_markup_is_logged_and_printed_as_given(
    in_tmp, error, code, printed
):
    """The scan's generic handler logs the exception, then prints it."""
    import builtins

    from automated_security_helper.core import exceptions

    raised = getattr(exceptions, error, None) or getattr(builtins, error)
    with patch(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        side_effect=raised("boom in a[/x] b"),
    ):
        result = CliRunner().invoke(
            app,
            ["scan", "--no-progress", "--source-dir", "src", "--output-dir", "out"],
        )

    assert result.exit_code == code, result.output
    assert printed in _plain(result.output), result.output


#: A color or style sequence, which a console writing as to a terminal adds.
_ANSI_STYLE = re.compile(r"\x1b\[[0-9;]*m")

#: A workspace folder whose name is a Rich link tag, and a project key holding a
#: closing tag. The link target carries no scheme: a colon is not allowed in a
#: Windows file name, so the folder named `[link=http://e.example]L[/link]` could
#: not be made there and the test failed in its own setup. Rich renders the tag
#: as a hyperlink whatever the target spells, so the OSC 8 check keeps its point.
_LINK_FOLDER = "[link=e.example]L[/link]"
_TAG_FOLDER = "api[/x]"


@pytest.mark.parametrize("stream", ["pipe", "terminal"])
def test_a_workspace_project_whose_name_and_error_read_as_markup_is_reported(
    in_tmp, monkeypatch, stream
):
    """Each project's failure is logged with its key and its error, and the scan's
    converters name its folder. Printed as text, the link folder is shown as
    written, with no hyperlink, and project "api[/x]" fails with its own error.
    Here every project's scan raises an error that quotes
    both, so each failure line is the project's own: on the console, also with
    its stream reporting a terminal, where Rich writes a link as an OSC 8
    sequence, and in ash.log."""
    import json

    if stream == "terminal":
        from automated_security_helper.utils.console import CommandSafeStream

        monkeypatch.setattr(CommandSafeStream, "isatty", lambda self: True)
    for folder in (_LINK_FOLDER, _TAG_FOLDER):
        (in_tmp / folder).mkdir(parents=True)
    (in_tmp / "dev.code-workspace").write_text(
        json.dumps({"folders": [{"path": _LINK_FOLDER}, {"path": _TAG_FOLDER}]}),
        encoding="utf-8",
    )
    error = f"boom in {_LINK_FOLDER} and {_TAG_FOLDER}"
    with (
        # The two git lookups a project makes before its scan: no repository.
        patch(
            "automated_security_helper.workspace.execution.git_repository_root",
            return_value=None,
        ),
        patch(
            "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
            return_value=(None, "not a git repository"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
            side_effect=RuntimeError(error),
        ),
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--no-progress",
                "--workspace",
                "dev.code-workspace",
                "--output-dir",
                "out",
            ],
        )

    from automated_security_helper.models.workspace import WorkspaceExitCode

    output = _plain(_ANSI_STYLE.sub("", result.output))
    assert "MarkupError" not in output, result.output
    assert "\x1b]8;" not in result.output, result.output
    assert output.count(f"failed: {error}") == 2, result.output
    # The code for a project that failed with its own error.
    assert result.exit_code == WorkspaceExitCode.INTERNAL_ERROR, result.output
    logs = sorted((in_tmp / "out").rglob("ash.log"))
    assert logs, sorted(p.as_posix() for p in (in_tmp / "out").rglob("*"))
    written = " ".join(log.read_text(encoding="utf-8") for log in logs)
    assert "MarkupError" not in written and "\x1b]8;" not in written, written
    assert _plain(written).count(f"failed: {error}") == 2, written


def test_an_exempted_orphan_under_a_bracketed_directory_is_named_as_given(in_tmp):
    """merge's warning for a scanner no shard was assigned names the shard file it
    was seen in: marked as markup, a "[/x]" in that path raised. Rich folds a long
    path at the console width, wherever tmp_path puts it, so the path is compared
    with whitespace removed."""
    from tests.unit.cli.test_merge import (
        TestCoverageIsRefused,
        build_shards,
        write_shards,
    )

    shards = TestCoverageIsRefused._orphan_grype_with_status(
        None, build_shards(3), "ERROR"
    )
    shard_paths = write_shards(in_tmp / "art[" / "x]", shards)
    args = ["merge", "--output-dir", "merged", "--no-fail-on-incomplete-scanners"]
    for path in shard_paths:
        args += ["--results", path]
    manager = MagicMock()
    manager.plugin_modules.return_value = []

    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        result = CliRunner().invoke(app, args)

    shown = _plain(result.output)
    assert result.exit_code == 2, result.output
    assert "no shard was assigned" in shown, shown
    assert "grype (ERROR, seen in " in shown, shown
    assert "art[/x]/shard-0" in "".join(result.output.split()), shown


@pytest.mark.parametrize(
    "error, code, printed",
    [
        pytest.param(
            "ScannerSelectionError",
            USAGE_ERROR_EXIT,
            "None of the requested scanners exist: x[/y]",
            id="selection",
        ),
        pytest.param(
            "ASHConfigValidationError",
            3,
            "Invalid configuration: None of the requested scanners exist: x[/y]",
            id="config",
        ),
        pytest.param(
            "RuntimeError",
            1,
            "Exiting due to exception during ASH workspace scan: None of the "
            "requested scanners exist: x[/y]",
            id="unexpected",
        ),
    ],
)
def test_a_workspace_refusal_holding_markup_is_printed_as_given(
    in_tmp, capsys, error, code, printed
):
    import builtins

    from automated_security_helper.core import exceptions
    from automated_security_helper.interactions import run_ash_scan as ras

    raised = getattr(exceptions, error, None) or getattr(builtins, error)
    opts = SimpleNamespace(workspace_plan=object(), offline=False)
    with (
        patch.object(ras, "build_project_scan_settings", return_value=MagicMock()),
        patch(
            "automated_security_helper.workspace.execution.execute_workspace",
            side_effect=raised("None of the requested scanners exist: x[/y]"),
        ),
        pytest.raises(SystemExit) as exit_info,
    ):
        ras._run_workspace_mode(opts, MagicMock())

    assert exit_info.value.code == code
    assert printed in _plain(capsys.readouterr().out)


@pytest.mark.parametrize(
    "scanners, converters",
    [
        pytest.param([("a[/b]", "MISSING")], [], id="scanner-row"),
        pytest.param([], [("jupyter", "failed on nb[/x].ipynb")], id="converter-row"),
    ],
)
def test_the_incompleteness_message_prints_its_rows_as_given(
    capsys, scanners, converters
):
    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
    )

    print_incompleteness_message(scanners, converters)

    out = _plain(capsys.readouterr().out)
    for name, status in scanners or converters:
        assert f"{name}: {status}" in out, out


class TestAshReportPrintsWhatItWasGiven:
    """ash report's refusals and log lines, with operator or repository text in them."""

    @pytest.fixture
    def results(self, in_tmp):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        out = in_tmp / "out"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
        return out

    def _report(self, *args):
        return CliRunner().invoke(app, ["report", *args], env={"FORCE_COLOR": "1"})

    def test_an_invalid_config_whose_path_reads_as_markup_exits_3(
        self, in_tmp, results
    ):
        """The refusal names the config file; a bracket in its path raised."""
        (in_tmp / "bad[").mkdir()
        config = in_tmp / "bad[" / "x].yaml"
        config.write_text("global_settings:\n  severity_threshold: NOPE\n")

        result = self._report(
            "--config", "bad[/x].yaml", "--output-dir", "out", "--format", "flat-json"
        )

        assert result.exit_code == 3, result.output
        assert "bad[/x].yaml" in _plain(result.stderr)

    def test_a_plugin_module_name_is_printed_not_obeyed(
        self, in_tmp, results, monkeypatch
    ):
        """A [link=...] in a module name the config gives is shown as text, not
        made a hyperlink.

        The name is printed by a logger warning, through get_logger's console. That
        console is not a terminal under CliRunner, where Rich writes no OSC 8 at
        all, so it is built as a terminal here: the OSC 8 check can only fail on one.
        """
        from automated_security_helper.utils import log

        real_console = log.ash_console
        monkeypatch.setattr(
            log,
            "ash_console",
            lambda **kwargs: real_console(**{**kwargs, "force_terminal": True}),
        )
        (in_tmp / "mods.yaml").write_text(
            'ash_plugin_modules:\n  - "[link=https://example.com]evil[/link]"\n'
        )

        result = self._report(
            "--config", "mods.yaml", "--output-dir", "out", "--format", "flat-json"
        )

        written = result.stdout + result.stderr
        # A terminal console colors the repr of the name, one SGR run per token;
        # only those runs are dropped, so an OSC 8 hyperlink would still show.
        shown = _plain(re.sub(r"\x1b\[[0-9;]*m", "", written))
        assert "[link=https://example.com]evil[/link]" in shown, shown
        assert "\x1b]8;" not in written

    @pytest.mark.parametrize(
        "args, typed",
        [
            pytest.param(["--format", "x\x7fy\x9b31m"], "x\\x7fy\\x9b31m", id="format"),
            pytest.param(
                ["--output-dir", "no\x7fwhere\x9b2K", "--format", "flat-json"],
                "no\\x7fwhere\\x9b2K",
                id="output-dir",
            ),
        ],
    )
    def test_a_control_character_in_an_argument_is_shown_not_obeyed(
        self, in_tmp, results, args, typed
    ):
        """DEL and C1 controls in the operator's own argument reached stderr raw."""
        if "--output-dir" not in args:
            args = [*args, "--output-dir", "out"]

        result = self._report(*args)

        assert result.exit_code != 0, result.output
        assert typed in result.stderr, repr(result.stderr)
        assert "\x7f" not in result.stderr and "\x9b" not in result.stderr

    @pytest.mark.parametrize(
        "content, reason",
        [
            pytest.param(
                b'{"scanner_results": "snippet-from-a-finding"}',
                "Invalid value at 'scanner_results': Input should be an object",
                id="value",
            ),
            pytest.param(
                b'{"scanner_results": {"snippet-from-a-finding\\u001b[5m\\n::error'
                b' title=report::x": 5}}',
                "Invalid value at 'scanner_results.<key>': Input should be an object",
                id="key",
            ),
            pytest.param(
                b'{"name": "ok\xff"}', "not UTF-8 at byte offset 12", id="byte"
            ),
        ],
    )
    def test_a_results_file_that_does_not_validate_is_named_not_quoted(
        self, in_tmp, content, reason
    ):
        """pydantic's text quotes the input, and a results file holds finding snippets.

        Printed as text, the refusal names what failed and never quotes the value
        pydantic refused. An error's location names the file's keys, and a decode
        error prints the byte.
        """
        out = in_tmp / "out"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_bytes(content)

        result = self._report("--output-dir", "out", "--format", "flat-json")

        shown = _plain(result.stdout + result.stderr)
        assert result.exit_code == 1, shown
        assert reason in shown, shown
        assert "snippet-from-a-finding" not in shown, shown
        # The refusal's own red is \x1b[31m; the file's sequence is \x1b[5m.
        assert "\x1b[5m" not in result.stderr, repr(result.stderr)
        assert "\n::" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "source, output",
    [
        pytest.param("src-[/x]", "out", id="closing-tag"),
        pytest.param("src", "out-[bold]x", id="style-tag"),
        # No "//": the caption prints the path as Path normalizes it.
        pytest.param("src", "out-[link=mailto:a@example.com]x[/link]", id="link"),
    ],
)
def test_the_results_table_shows_the_directories_as_given(
    in_tmp, capsys, source, output
):
    """The table's caption quotes --source-dir and --output-dir as text.

    With "[/x]", "[bold]" or "[link=...]" in either, the caption shows the text as
    written and the results table is still printed.
    """
    from automated_security_helper.core.metrics_table import display_metrics_table
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    display_metrics_table(
        AshAggregatedResults(), source_dir=source, output_dir=output, use_color=False
    )

    out = capsys.readouterr().out
    assert "Error displaying metrics table" not in out, out
    assert "ASH Scan Results Summary" in out, out
    assert f"source-dir: '{source}'" in out, out
    assert f"output-dir: '{output}'" in out, out
    assert "\x1b]8;" not in out


def test_the_results_table_shows_the_controls_of_the_directories(in_tmp, capsys):
    """The caption shows a directory's controls as escapes, as every console does,
    so an OSC 52 or a C1 CSI there does not act on the terminal."""
    from automated_security_helper.core.metrics_table import display_metrics_table
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    display_metrics_table(
        AshAggregatedResults(),
        source_dir="src\x1b]52;c;ZXZpbA==\x07x",
        output_dir="out\x9b2Kx",
        use_color=False,
    )

    out = capsys.readouterr().out
    assert "source-dir: 'src\\x1b]52;c;ZXZpbA==\\x07x'" in out, out
    assert "output-dir: 'out\\x9b2Kx'" in out, out
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", out), repr(out)


def test_the_results_table_caption_keeps_the_table_caption_style(in_tmp):
    """Rich applies a table's caption_style to a str caption only, and the caption
    is a Text, so the Text carries table.caption (dim italic) itself."""
    import io

    from rich.console import Console

    from automated_security_helper.core.metrics_table import (
        generate_metrics_table_from_unified_data,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    table = generate_metrics_table_from_unified_data(
        AshAggregatedResults(), source_dir="src", output_dir="out"
    )
    console = Console(
        file=io.StringIO(), force_terminal=True, color_system="truecolor", width=100
    )
    caption_style = console.get_style("table.caption")
    styled = [
        segment
        for segment in console.render(table)
        if "source-dir" in segment.text or "output-dir" in segment.text
    ]

    assert styled, "no caption segment"
    for segment in styled:
        assert segment.style is not None, segment
        assert segment.style.dim == caption_style.dim, segment
        assert segment.style.italic == caption_style.italic, segment
    assert caption_style.dim or caption_style.italic


#: Repository text with what a terminal and a CI runner obey: an OSC 52 clipboard
#: write, a C1 CSI erase and a line that GitHub Actions reads as a command.
OBEYED = "nope\x1b]52;c;ZXZpbA==\x07\x9b2K\n::add-mask::hidden"

#: What the runner would read as a command, or a terminal would act on.
_RAW = re.compile(r"^\s*::|##[A-Za-z]*\[|[\x00-\x08\x0b-\x1f\x7f-\x9f]", re.MULTILINE)


class TestRepositoryTextIsShownNotObeyed:
    """The rich.print sinks show repository text's markup and its controls as
    escapes, on the terminal and in the CI log."""

    def test_a_config_whose_extends_holds_controls_exits_3_and_shows_them(self, in_tmp):
        """The refusal shows an OSC 52 and a C1 CSI as escapes and breaks the
        "::add-mask::hidden.yaml" command form, so stdout holds no workflow
        command."""
        (in_tmp / "src" / ".ash").mkdir()
        (in_tmp / "src" / ".ash" / ".ash.yaml").write_text(
            'extends: "nope\\e]52;c;ZXZpbA==\\a\\x9b2K\\n::add-mask::hidden.yaml"\n',
            encoding="utf-8",
        )
        with patch(
            "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
            return_value=(None, "not a git repository"),
        ):
            result = CliRunner().invoke(
                app,
                ["scan", "--no-progress", "--source-dir", "src", "--output-dir", "out"],
            )

        shown = result.stdout + result.stderr
        assert result.exit_code == 3, shown
        assert "hidden.yaml" in shown, shown
        assert not _RAW.search(shown), (_RAW.search(shown), shown)

    def test_ash_report_refuses_such_a_config_and_shows_its_text(self, in_tmp):
        """ash report's refusal uses the console's control set, which breaks a CI
        command and shows a bidirectional override."""
        out = in_tmp / "out"
        out.mkdir()
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        (out / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
        (in_tmp / "cfg.yaml").write_text(
            'extends: "nope\\u202e\\e]52;c;ZXZpbA==\\a\\n::add-mask::hidden.yaml"\n',
            encoding="utf-8",
        )

        result = CliRunner().invoke(
            app,
            [
                "report",
                "--config",
                "cfg.yaml",
                "--output-dir",
                "out",
                "--format",
                "text",
            ],
        )

        shown = result.stdout + result.stderr
        assert result.exit_code == 3, shown
        assert "hidden.yaml" in shown, shown
        assert "\N{RIGHT-TO-LEFT OVERRIDE}" not in shown, repr(shown)
        assert not _RAW.search(shown), (_RAW.search(shown), shown)

    def test_an_incompleteness_row_shows_its_controls(self, capsys):
        from automated_security_helper.interactions.run_ash_scan import (
            print_incompleteness_message,
        )

        print_incompleteness_message(
            [("npm-audit", "MISSING " + OBEYED)], [("jupyter", OBEYED + ".ipynb")]
        )

        out = capsys.readouterr().out
        assert "add-mask" in out, out
        assert not _RAW.search(out), (_RAW.search(out), out)

    def test_a_workspace_definition_error_shows_its_controls(self, in_tmp, capsys):
        """The error names the workspace's projects, and it is printed through the
        console with its controls shown."""
        from automated_security_helper.core.exceptions import WorkspaceDefinitionError
        from automated_security_helper.interactions import run_ash_scan as ras

        opts = SimpleNamespace(workspace_plan=object(), offline=False)
        with (
            patch.object(ras, "build_project_scan_settings", return_value=MagicMock()),
            patch(
                "automated_security_helper.workspace.execution.execute_workspace",
                side_effect=WorkspaceDefinitionError(f"project '{OBEYED}' is unknown"),
            ),
            pytest.raises(SystemExit),
        ):
            ras._run_workspace_mode(opts, MagicMock())

        err = capsys.readouterr().err
        assert "add-mask" in err, err
        assert not _RAW.search(err), (_RAW.search(err), err)

    def test_a_progress_description_shows_its_controls(self):
        """A description quotes an exception's text; escape_markup shows it."""
        from rich.text import Text

        from automated_security_helper.utils.log import escape_markup

        shown = Text.from_markup(f"[red](npm-audit) Failed: {escape_markup(OBEYED)}")
        assert "add-mask" in shown.plain, repr(shown.plain)
        assert not _RAW.search(shown.plain), repr(shown.plain)


def test_plugin_list_shows_a_plugins_config_and_error_as_text(in_tmp, monkeypatch):
    """``ash plugin list``'s table cells are Rich markup, and they hold a plugin's
    config, its values the operator's, and the error that building one raised. A
    "[/x]" in either raised MarkupError out of the listing, and a
    "[bold]x[/bold]" was taken as a style and lost."""
    from automated_security_helper.config.ash_config import AshConfig

    text = "x[/x] [bold]y[/bold]"
    real = AshConfig.get_plugin_config

    def get_plugin_config(self, plugin_type, plugin_name):
        if plugin_name == "bandit":
            # A declared option that takes free text: the declared config model
            # validates as a config file does, so an undeclared key would be
            # refused as unknown and the column would show that refusal instead.
            return {
                "name": "bandit",
                "enabled": True,
                "options": {"additional_formats": [text]},
            }
        if plugin_name == "semgrep":
            raise ValueError(f"cannot build: {text}")
        return real(self, plugin_type=plugin_type, plugin_name=plugin_name)

    monkeypatch.setattr(AshConfig, "get_plugin_config", get_plugin_config)
    # Wide enough that no cell wraps the text apart.
    monkeypatch.setenv("COLUMNS", "1000")

    result = CliRunner().invoke(app, ["plugin", "list", "--include-plugin-config"])

    assert result.exit_code == 0, result.output
    # Each place the text is shown holds it whole: bandit's config column (the
    # JSON-quoted value), semgrep's error column, and the warning bandit's config
    # validation logs about the additional_formats value. A count would move with
    # every new line that shows the value.
    assert f'"{text}"' in result.output, result.output
    assert f"cannot build: {text}" in result.output, result.output
    assert "\\[" not in result.output, result.output
