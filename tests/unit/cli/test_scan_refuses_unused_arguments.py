# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash`` uses every argument it is given, or refuses it.

What each guard here covers:

* ``ash scan`` declares neither ``ignore_unknown_options`` nor ``allow_extra_args``, so
  a misspelled option (``--fail-on-finding``, ``--scaners``) or a stray positional is a
  usage error and never sits unread in ``ctx.args``: a CI job with a typo in a gate
  flag fails, and does not run without that gate.
* The root callback returns as soon as it sees a subcommand, so an option given to the
  root ``ash`` before a subcommand is handed on to it: ``ash --source-dir /elsewhere
  scan`` scans /elsewhere.
* ``ash build-image`` takes no extra arguments to forward to the scan inside the
  container.

The first and third are usage errors. ``build-image`` refuses rather than forwards
because container mode recomputes the exit code on the host from the host's own
options, so a forwarded ``--min-severity`` or ``--no-fail-on-findings`` would change
what the inner scan reported and not the exit code; ``ash scan --mode container``
takes every scan option and applies them on both sides. Options before a subcommand
are passed to it when it takes them, and refused when it does not. Refusing them all
would have broken the reusable GitHub workflow's report step, which runs
``ash --output-dir <dir> report``: it found its directory through ASH_OUTPUT_DIR, which
the workflow also sets, and an option refused before ``report`` would fail it.
"""

from __future__ import annotations

import re
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: ASH_EXIT_USAGE_ERROR's published value; see tests/unit/cli/test_usage_error_exit_code.py.
USAGE_ERROR_EXIT = 5


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """The output without color codes, panel borders or rich's line wrapping."""
    text = _ANSI.sub("", text)
    return " ".join(text.replace("│", " ").replace("╭", " ").replace("╰", " ").split())


ORCHESTRATOR_CREATE = (
    "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create"
)


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_MODE", "ASH_SCANNERS"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    return tmp_path


def _invoke(args, **kwargs):
    return CliRunner().invoke(app, list(args), **kwargs)


def _write_results(directory: Path) -> None:
    """A results file ``ash report`` can render, in *directory*."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )


class _OrchestratorProbe:
    """Stands in for the orchestrator and records which directory a scan would use."""

    def __init__(self):
        self.source_dirs: list[str] = []

    def __call__(self, *_args, source_dir, **_kwargs):
        self.source_dirs.append(
            Path(os.path.relpath(source_dir, Path.cwd())).as_posix()
        )
        raise RuntimeError("probe: the scan reached the orchestrator")


class TestScanRefusesWhatItDoesNotDeclare:
    @pytest.mark.parametrize(
        "args, fragment",
        [
            pytest.param(["--scaners", "bandit"], "--scaners", id="misspelled-option"),
            pytest.param(
                ["--fail-on-finding"], "--fail-on-finding", id="misspelled-gate-flag"
            ),
            pytest.param(["--sourc-dir", "src"], "--sourc-dir", id="misspelled-path"),
            pytest.param(["extra1", "extra2"], "extra1", id="positional-arguments"),
        ],
    )
    def test_is_a_usage_error(self, in_tmp, args, fragment):
        # --version ends the command before any scan, so on a tree that ignores the
        # argument this exits 0 and prints the version.
        result = _invoke(["scan", *args, "--version"])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert fragment in _plain(result.output)
        assert "automated-security-helper v" not in result.stdout

    def test_is_refused_before_anything_is_scanned(self, in_tmp):
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--sourc-dir",
                    "src",
                    "--output-dir",
                    "out",
                ]
            )

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert probe.source_dirs == [], f"a scan ran over {probe.source_dirs}"

    def test_cli_json_input_supplies_parameters(self, in_tmp):
        """The structured-input options are declared, so strict parsing keeps them."""
        document = in_tmp / "params.json"
        document.write_text(json.dumps({"version": True}), encoding="utf-8")

        result = _invoke(["scan", "--cli-json-input", str(document)])

        assert result.exit_code == 0, result.output
        assert "automated-security-helper v" in result.stdout

    def test_cli_json_input_from_stdin(self, in_tmp):
        result = _invoke(
            ["scan", "--cli-json-input", "-"], input=json.dumps({"version": True})
        )

        assert result.exit_code == 0, result.output


class TestOptionsBeforeASubcommand:
    def test_reach_the_subcommand(self, in_tmp):
        (in_tmp / "elsewhere").mkdir()
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            _invoke(
                [
                    "--source-dir",
                    "elsewhere",
                    "scan",
                    "--no-progress",
                    "--output-dir",
                    "out",
                ]
            )

        assert probe.source_dirs == ["elsewhere"], (
            f"--source-dir elsewhere was dropped and {probe.source_dirs} was scanned"
        )

    def test_a_refusal_of_the_passed_value_is_the_subcommands_own(self, in_tmp):
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            result = _invoke(
                ["--source-dir", "does-not-exist", "scan", "--no-progress"]
            )

        assert probe.source_dirs == []
        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "Source directory does not exist: does-not-exist" in _plain(
            result.output
        )

    def test_the_subcommands_own_value_wins(self, in_tmp):
        (in_tmp / "elsewhere").mkdir()
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            _invoke(
                [
                    "--source-dir",
                    "elsewhere",
                    "scan",
                    "--no-progress",
                    "--source-dir",
                    "src",
                ]
            )

        assert probe.source_dirs == ["src"]

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["--version", "scan"], id="flag"),
            pytest.param(["--mode", "local", "scan", "--version"], id="choice"),
            pytest.param(
                ["--min-severity", "HIGH", "--no-progress", "scan", "--version"],
                id="several",
            ),
        ],
    )
    def test_scan_takes_each_kind_of_option(self, in_tmp, args):
        # The [flag] case has --version only before `scan`: were it dropped, a scan
        # of the working directory would run, so the orchestrator is a probe here.
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            result = _invoke(args)

        assert probe.source_dirs == [], f"a scan ran over {probe.source_dirs}"
        assert result.exit_code == 0, result.output
        assert "automated-security-helper v" in result.stdout

    @pytest.mark.parametrize(
        "before, expected",
        [
            pytest.param(
                ["--no-fail-on-findings"],
                {"fail_on_findings": False},
                id="negative-flag",
            ),
            pytest.param(
                ["--fail-on-findings"], {"fail_on_findings": True}, id="positive-flag"
            ),
            pytest.param(
                ["--scanners", "bandit", "--scanners", "semgrep"],
                {"scanners": ["bandit", "semgrep"]},
                id="repeated-option",
            ),
            pytest.param(
                ["--min-severity", "HIGH"], {"min_severity": "high"}, id="choice"
            ),
            pytest.param(
                ["--output-dir", "elsewhere-out"],
                {"output_dir": "elsewhere-out"},
                id="single-value",
            ),
        ],
    )
    def test_the_value_given_before_is_the_value_the_scan_gets(
        self, in_tmp, before, expected
    ):
        """What reaches the scan, not only that something did: a negative flag stays
        negative, and a repeated option stays one value per use."""
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _invoke([*before, "scan", "--no-progress", "--source-dir", "src"])

        assert result.exit_code == 0, result.output
        given = run.call_args.kwargs
        got = {name: getattr(given[name], "value", given[name]) for name in expected}
        assert got == expected

    def test_report_reads_the_output_dir_given_before_it(self, in_tmp):
        """``ash --output-dir <dir> report`` reads <dir>, with no ASH_OUTPUT_DIR set.

        It read the default output directory, which under in_tmp holds no results,
        so the command exited 1.
        """
        _write_results(in_tmp / "elsewhere-out")

        result = _invoke(
            ["--output-dir", "elsewhere-out", "report", "--format", "flat-json"]
        )

        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize(
        "args, flag",
        [
            pytest.param(["--source-dir", "src", "report"], "--source-dir"),
            pytest.param(["--no-progress", "report"], "--no-progress"),
            pytest.param(["--scanners", "bandit", "config", "get"], "--scanners"),
            pytest.param(["--version", "merge"], "--version"),
            pytest.param(
                ["-f", "sarif", "build-image", "--no-run"],
                "takes -f as --force",
            ),
        ],
        ids=[
            "path-before-report",
            "flag-before-report",
            "list-before-a-group",
            "flag-before-merge",
            "short-alias-meaning-something-else",
        ],
    )
    def test_are_refused_when_the_subcommand_does_not_take_them(
        self, in_tmp, args, flag
    ):
        """A short alias the subcommand spells differently (`-f` is --force on
        build-image, a flag, where the root's -f takes a value) is refused as
        taken differently, not as not taken: the subcommand does take `-f`."""
        with patch("automated_security_helper.cli.image.run_ash_scan") as run:
            result = _invoke(args)

        run.assert_not_called()
        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert flag in _plain(result.output)

    @pytest.mark.parametrize(
        "args, typed",
        [
            pytest.param(["--scanners", "bandit", "report"], "--scanners", id="long"),
            pytest.param(["--scanners=bandit", "report"], "--scanners", id="equals"),
            pytest.param(
                ["--scanners", "--offline", "report"], "--scanners", id="value-token"
            ),
        ],
    )
    def test_the_refusal_names_the_spelling_that_was_typed(self, in_tmp, args, typed):
        """A token that is the option's VALUE ("--offline" after --scanners) is
        not a spelling, so it is not the one named."""
        result = _invoke(args)

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert f"'ash report' does not take {typed}," in _plain(result.output)

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["--format", "text", "report"], id="long-alias"),
            pytest.param(["-f", "text", "report"], id="short-alias"),
            pytest.param(["--formats=text", "report"], id="equals-form"),
        ],
    )
    def test_a_root_option_reaches_the_subcommand_option_spelled_the_same(
        self, in_tmp, args
    ):
        """The root's `--format` is output_formats and report's is report_format:
        matched by name alone, `ash --format text report` was refused as an
        option report does not take, although `ash report --help` lists it."""
        _write_results(in_tmp / ".ash" / "ash_output")

        result = _invoke(args)

        assert result.exit_code == 0, result.output
        assert "does not take" not in _plain(result.output)
        # The text reporter's output, not the default markdown report.
        assert "ASH SECURITY SCAN REPORT" in result.stdout, result.stdout[:400]

    def test_the_subcommands_help_is_shown(self, in_tmp):
        result = _invoke(["--source-dir", "src", "report", "--help"])

        assert result.exit_code == 0, result.output
        assert "Usage: ash report" in _plain(result.output)

    def test_names_every_option_the_subcommand_does_not_take(self, in_tmp):
        result = _invoke(["--offline", "--scanners", "bandit", "report"])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        text = _plain(result.output)
        assert "--offline" in text and "--scanners" in text

    def test_an_environment_variable_is_not_an_option_given_before(
        self, in_tmp, monkeypatch
    ):
        """ASH_SOURCE_DIR sets the root's option too; it was not typed before 'report'.

        report does not take --source-dir, so passing the root's environment-sourced
        values on as though they had been typed would refuse this command.
        """
        _write_results(in_tmp / "elsewhere-out")
        monkeypatch.setenv("ASH_SOURCE_DIR", str(in_tmp / "src"))

        result = _invoke(
            ["report", "--output-dir", "elsewhere-out", "--format", "flat-json"]
        )

        assert "does not take" not in _plain(result.output)
        assert result.exit_code == 0, result.output

    def test_bare_ash_takes_them(self, in_tmp):
        """Without a subcommand the root's options are the scan's."""
        probe = _OrchestratorProbe()
        with patch(ORCHESTRATOR_CREATE, side_effect=probe):
            _invoke(["--no-progress", "--source-dir", "src", "--output-dir", "out"])

        assert probe.source_dirs == ["src"]


class TestBuildImageRefusesWhatItDoesNotDeclare:
    @pytest.mark.parametrize(
        "args",
        [["--scanners", "bandit"], ["--fail-on-finding"], ["extra"]],
        ids=["scan-option", "misspelled-option", "positional-argument"],
    )
    def test_is_a_usage_error(self, in_tmp, args):
        with patch("automated_security_helper.cli.image.run_ash_scan") as run:
            result = _invoke(["build-image", "--no-build", "--no-run", *args])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        run.assert_not_called()

    def test_its_own_options_work(self, in_tmp):
        with patch("automated_security_helper.cli.image.run_ash_scan") as run:
            result = _invoke(["build-image", "--no-build", "--no-run", "--offline"])

        assert result.exit_code == 0, result.output
        assert run.call_args.kwargs["offline"] is True
        assert run.call_args.kwargs["run"] is False
