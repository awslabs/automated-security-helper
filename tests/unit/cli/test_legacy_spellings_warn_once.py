"""The 3.9 contract for every command spelling that moved, and the hints that name one.

ASH 3.9 moves the directory scan under ``ash scan fs``, the scan of a workspace file
under ``ash scan workspace``, the commands that read saved results under ``ash
results`` and the image build under ``ash container build``. Each old spelling keeps
working through 3.x:

* it prints exactly one deprecation line, on stderr and never on stdout, that names
  the spelling replacing it and the 4.0 removal;
* its stdout and its exit code are those of the new spelling;
* the new spelling prints no deprecation line.

ASH 4.0 removes the old spellings. The first half of this file is the record that
removal starts from: each row there becomes a refusal row in 4.0. The rows were green
when written, since they pin behavior the scan group, results group and container
group already deliver, except the two that name the directory in a --cli-json-input
document: ``ash scan fs`` printed no line for a document's ``source_dir`` key until
those two rows were added.

The second half pins the hints ASH prints, its help text and the markdown it ships in
the package: each one names the spelling that does not warn, so following a hint never
leads to a deprecation line. Each of those rows failed before the hint moved. The
markdown check also refuses a top-level ``ash diff`` or ``ash trend``: both live under
``ash results`` and never had a top-level spelling, so the CLI answers those words with
a usage error.

Every scan row passes ``--shard-index 3`` without ``--shard-count``, which the engine
refuses with the usage-error code right after the deprecation line would print, so no
row scans anything; the image build's scan is replaced by a stand-in that records its
arguments, so no image is built.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, List
from unittest.mock import MagicMock, patch

import pytest
import typer.main
from pydantic import BaseModel
from typer.testing import CliRunner

import automated_security_helper
from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: Fails at once in the engine: a shard index needs a shard count.
FAILS_FAST = ["--shard-index", "3"]

#: The two prefixes a deprecation line starts with: the scan spellings print
#: ``Deprecated: ...``, the moved top-level commands ``DeprecationWarning: ...``.
DEPRECATION_PREFIXES = ("Deprecated:", "DeprecationWarning:")


def _invoke(args: List[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _deprecation_lines(text: str) -> List[str]:
    return [line for line in text.splitlines() if line.startswith(DEPRECATION_PREFIXES)]


def _one_line(text: str) -> str:
    return " ".join(text.split())


@dataclass(frozen=True)
class Spelling:
    """An old spelling, the spelling that replaces it, and what the line must name."""

    legacy: Callable[[Path], List[str]]
    noun: Callable[[Path], List[str]]
    names: str
    #: What the stdout of a row that prints must hold, so that row compares text.
    prints: str = ""


def _results_argv(verb: str) -> Callable[[Path], List[str]]:
    """A cheap invocation of *verb* that needs no saved results.

    Each one fails the same way under either spelling (a missing input, or a bare
    group), so the exit code and the command's own output can be compared.
    """

    def build(tmp_path: Path) -> List[str]:
        return {
            "report": [verb, "--output-dir", str(tmp_path / "no-such-output")],
            "merge": [verb, "--results", str(tmp_path / "no-such-shard")],
            "inspect": [verb],
        }[verb]

    return build


def _missing_workspace_file(tmp_path: Path) -> str:
    """A workspace file that is not there, which every spelling refuses at once with the
    workspace error code, so no row plans or scans anything."""
    return str(tmp_path / "gone.code-workspace")


def _document_naming_the_directory(key: str) -> Callable[[Path], List[str]]:
    """``ash scan fs`` handed the directory by the *key* of a --cli-json-input document.

    A document key is a parameter's name or one of its long flags, so ``source_dir``
    and ``--source-dir`` both set the deprecated option.
    """

    def build(tmp_path: Path) -> List[str]:
        document = tmp_path / "scan.json"
        document.write_text(json.dumps({key: "src"}), encoding="utf-8")
        return ["scan", "fs", "--cli-json-input", str(document), *FAILS_FAST]

    return build


SPELLINGS = {
    "bare-ash": Spelling(
        legacy=lambda _: [*FAILS_FAST],
        noun=lambda _: ["scan", "fs", *FAILS_FAST],
        names="ash scan fs",
    ),
    "scan-without-subject": Spelling(
        legacy=lambda _: ["scan", *FAILS_FAST],
        noun=lambda _: ["scan", "fs", *FAILS_FAST],
        names="ash scan fs",
    ),
    "source-dir-on-fs": Spelling(
        legacy=lambda _: ["scan", "fs", "--source-dir", "src", *FAILS_FAST],
        noun=lambda _: ["scan", "fs", "src", *FAILS_FAST],
        names="ash scan fs",
    ),
    "source_dir-key-of-a-json-document": Spelling(
        legacy=_document_naming_the_directory("source_dir"),
        noun=lambda _: ["scan", "fs", "src", *FAILS_FAST],
        names="ash scan fs",
    ),
    "source-dir-flag-key-of-a-json-document": Spelling(
        legacy=_document_naming_the_directory("--source-dir"),
        noun=lambda _: ["scan", "fs", "src", *FAILS_FAST],
        names="ash scan fs",
    ),
    "workspace-option-on-bare-ash": Spelling(
        legacy=lambda tmp_path: ["--workspace", _missing_workspace_file(tmp_path)],
        noun=lambda tmp_path: [
            "scan",
            "workspace",
            _missing_workspace_file(tmp_path),
        ],
        names="ash scan workspace",
    ),
    "workspace-option-on-scan-without-subject": Spelling(
        legacy=lambda tmp_path: [
            "scan",
            "--workspace",
            _missing_workspace_file(tmp_path),
        ],
        noun=lambda tmp_path: [
            "scan",
            "workspace",
            _missing_workspace_file(tmp_path),
        ],
        names="ash scan workspace",
    ),
    **{
        verb: Spelling(
            legacy=_results_argv(verb),
            noun=lambda tmp_path, verb=verb: [
                "results",
                *_results_argv(verb)(tmp_path),
            ],
            names=f"ash results {verb}",
        )
        for verb in ("report", "merge", "inspect")
    },
    "build-image": Spelling(
        legacy=lambda _: ["build-image", "--no-run"],
        noun=lambda _: ["container", "build", "--no-run"],
        names="ash container build",
    ),
}


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """A working directory with no config of its own, and an image build that builds
    nothing: the build command's scan is recorded, not run."""
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    builds: List[dict] = []
    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan",
        lambda **kwargs: builds.append(kwargs),
    )
    return builds


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_a_legacy_spelling_prints_one_line_on_stderr(name, tmp_path, isolated):
    spelling = SPELLINGS[name]

    result = _invoke(spelling.legacy(tmp_path))

    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 1, result.stderr
    assert spelling.names in lines[0], lines[0]
    assert "4.0" in lines[0], lines[0]
    assert _deprecation_lines(result.stdout) == [], (
        "a script's stdout is never handed the line"
    )


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_a_legacy_spelling_keeps_the_nouns_stdout_and_exit_code(
    name, tmp_path, isolated
):
    """The rows stop before the command prints, or print on stderr, so this mostly
    compares exit codes; STDOUT_SPELLINGS below holds the rows that print."""
    spelling = SPELLINGS[name]

    legacy = _invoke(spelling.legacy(tmp_path))
    noun = _invoke(spelling.noun(tmp_path))

    assert legacy.exit_code == noun.exit_code, (legacy.output, noun.output)
    assert legacy.stdout == noun.stdout


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_the_noun_spelling_prints_no_deprecation_line(name, tmp_path, isolated):
    result = _invoke(SPELLINGS[name].noun(tmp_path))

    assert _deprecation_lines(result.stderr) == [], result.stderr
    assert _deprecation_lines(result.stdout) == [], result.stdout
    assert "deprecat" not in result.output.lower(), result.output


def test_both_build_spellings_start_the_same_build(tmp_path, isolated):
    """The rows above compare what the two spellings print; this one, that the
    recorded build is the same, so the stand-in is not hiding a difference."""
    _invoke(SPELLINGS["build-image"].legacy(tmp_path))
    _invoke(SPELLINGS["build-image"].noun(tmp_path))

    assert len(isolated) == 2
    assert isolated[0] == isolated[1]


def test_a_document_without_the_deprecated_key_prints_no_deprecation_line(
    tmp_path, isolated
):
    """The control for the two document rows: the fs skeleton as it is generated
    (it does not list ``source_dir``) and a document that uses the ``path`` key run as
    ``ash scan fs src`` runs, and say nothing."""
    skeleton = _invoke(["scan", "fs", "--generate-cli-skeleton"])
    assert skeleton.exit_code == 0, skeleton.output
    noun = _invoke(["scan", "fs", "src", *FAILS_FAST])

    for name, document in (
        ("skeleton.json", skeleton.stdout),
        ("path.json", json.dumps({"path": "src"})),
    ):
        (tmp_path / name).write_text(document, encoding="utf-8")

        result = _invoke(
            ["scan", "fs", "--cli-json-input", str(tmp_path / name), *FAILS_FAST]
        )

        assert result.exit_code == noun.exit_code, (name, result.output)
        assert _deprecation_lines(result.stderr) == [], (name, result.stderr)
        assert _deprecation_lines(result.stdout) == [], (name, result.stdout)


def _saved_results(tmp_path: Path) -> List[str]:
    """The options that make ``report`` print, as text, the results file saved in a
    scratch output directory. The file is written once, so both spellings read the
    same one."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    output = tmp_path / "saved-output"
    output.mkdir(exist_ok=True)
    saved = output / "ash_aggregated_results.json"
    if not saved.exists():
        saved.write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
    return ["--output-dir", str(output), "--format", "text"]


#: One row for each group that moved whose command prints something on stdout, so
#: the comparison below is of text and not of two empty strings.
STDOUT_SPELLINGS = {
    "report-as-text": Spelling(
        legacy=lambda tmp_path: ["report", *_saved_results(tmp_path)],
        noun=lambda tmp_path: ["results", "report", *_saved_results(tmp_path)],
        names="ash results report",
        prints="ASH SECURITY SCAN REPORT",
    ),
    "build-image-skeleton": Spelling(
        legacy=lambda _: ["build-image", "--generate-cli-skeleton"],
        noun=lambda _: ["container", "build", "--generate-cli-skeleton"],
        names="ash container build",
        prints='"no_run"',
    ),
}

#: The rows whose old spelling prints its line. A skeleton only lists what a command
#: takes, which is not a use of it, so no spelling warns for one.
WARNS = {"report-as-text"}


def _stable(stdout: str) -> str:
    """*stdout* without the one line a text report stamps with the second it was
    made, which two runs a second apart do not share."""
    return "\n".join(
        line
        for line in stdout.splitlines()
        if not line.startswith("Report generated by ")
    )


@pytest.mark.parametrize("name", list(STDOUT_SPELLINGS))
def test_a_legacy_spelling_that_prints_keeps_the_nouns_stdout(name, tmp_path, isolated):
    spelling = STDOUT_SPELLINGS[name]

    legacy = _invoke(spelling.legacy(tmp_path))
    noun = _invoke(spelling.noun(tmp_path))

    assert legacy.exit_code == noun.exit_code == 0, (legacy.output, noun.output)
    assert spelling.prints in noun.stdout, noun.stdout
    assert _stable(legacy.stdout) == _stable(noun.stdout)
    lines = _deprecation_lines(legacy.stderr)
    if name in WARNS:
        assert len(lines) == 1, legacy.stderr
        assert spelling.names in lines[0], lines[0]
    else:
        assert lines == [], legacy.stderr
    assert _deprecation_lines(noun.stderr) == [], noun.stderr


def test_the_skeleton_without_a_subject_adds_the_workspace_and_deprecated_keys():
    """The one stdout an old spelling does not share with its noun. ``ash scan`` with
    no subject still takes the workspace options, as it always did, and ``fs`` does
    not, so its skeleton lists the four keys of those options as well. It lists the two
    deprecated keys too, ``source_dir`` and ``scanners``, which the skeleton of ``fs``
    leaves out so that filling it in never names one: the form with no subject is
    deprecated as a whole and keeps its template as it was. ``fs`` alone takes
    ``--archive``, so only its skeleton lists that key. Everything else is the same,
    and neither prints a line: a skeleton only lists what a command takes."""
    legacy = _invoke(["scan", "--generate-cli-skeleton"])
    noun = _invoke(["scan", "fs", "--generate-cli-skeleton"])

    assert legacy.exit_code == noun.exit_code == 0, (legacy.output, noun.output)
    legacy_keys, noun_keys = json.loads(legacy.stdout), json.loads(noun.stdout)
    assert set(legacy_keys) - set(noun_keys) == {
        "workspace",
        "workspace_config",
        "allow_missing_projects",
        "dry_run",
        "source_dir",
        "scanners",
    }
    assert set(noun_keys) - set(legacy_keys) == {"archive"}
    shared = set(noun_keys) & set(legacy_keys)
    assert {key: legacy_keys[key] for key in shared} == {
        key: noun_keys[key] for key in shared
    }
    assert '"path"' in noun.stdout
    assert _deprecation_lines(legacy.stderr) == [], legacy.stderr
    assert _deprecation_lines(noun.stderr) == [], noun.stderr


# --------------------------------------------------------------------------- #
# Hints, help text and shipped markdown name the spellings that do not warn
# --------------------------------------------------------------------------- #


def test_the_config_commands_source_dir_help_names_the_scan_fs_argument():
    from automated_security_helper.cli.config import _SOURCE_DIR_HELP

    assert "`ash scan fs <path>`" in _SOURCE_DIR_HELP, _SOURCE_DIR_HELP
    assert "--source-dir`" not in _SOURCE_DIR_HELP, _SOURCE_DIR_HELP


def test_an_old_unused_suppressions_report_suggests_scan_fs(tmp_path):
    from automated_security_helper.cli.config import config_app
    from tests.utils.unused_report_layout import ENTRY, lay_out

    config, _path = lay_out(
        tmp_path, {"unused_suppressions": [ENTRY]}, age_seconds=7200
    )

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input="n\n"
    )

    assert "   Consider running a fresh scan: ash scan fs" in (
        result.output.splitlines()
    ), result.output


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(("container", "build"), id="container-build"),
        pytest.param(("build-image",), id="build-image"),
    ],
)
def test_the_container_build_help_names_scan_fs_for_a_scan_with_scan_options(path):
    """Both spellings show the one help text. The deprecated one carried a copy of
    its own that still sent a reader to a scan that warns."""
    from automated_security_helper.cli.main import BUILD_HELP

    command = typer.main.get_command(app)
    for name in path:
        command = command.commands[name]

    assert command.help.strip().endswith(BUILD_HELP.strip()), command.help
    assert "run `ash scan fs --mode container`" in command.help, command.help
    assert "`ash scan --mode container`" not in command.help, command.help


def test_the_merge_ignore_suppressions_help_names_scan_fs():
    merge = typer.main.get_command(app).commands["results"].commands["merge"]
    (option,) = [p for p in merge.params if "--ignore-suppressions" in p.opts]

    assert "'ash scan fs --ignore-suppressions'" in option.help, option.help


def test_a_report_with_no_results_suggests_scan_fs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = _invoke(
        ["results", "report", "--output-dir", str(tmp_path / "no-such-output")]
    )

    text = _one_line(result.stderr)
    assert "No scan results found" in text, text
    assert "Run 'ash scan fs' first" in text, text


@pytest.mark.parametrize("field", ["annotate", "fold"])
def test_the_deduplication_settings_name_the_cli_flag_on_scan_fs_and_results_report(
    field,
):
    from automated_security_helper.config.ash_config import AshDeduplicationConfig

    description = AshDeduplicationConfig.model_fields[field].description

    assert "on `ash scan fs` and `ash results report`." in description, description


class _Workspace(BaseModel):
    """Stands in for the results' ``workspace`` record: any model, not None."""


def _workspace_model():
    model = MagicMock()
    model.to_simple_dict.return_value = {"a": 1}
    model.sarif = None
    model.metadata.generated_at = "2026-01-15T12:00:00+00:00"
    model.metadata.workspace_project = None
    model.workspace = _Workspace()
    return model


def _context(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext

    return PluginContext(
        source_dir=Path(tmp_path / "src"),
        output_dir=Path(tmp_path / "output"),
        work_dir=Path(tmp_path / "work"),
    )


def test_s3_on_workspace_results_suggests_results_report(tmp_path):
    from automated_security_helper.plugin_modules.ash_aws_plugins import s3_reporter

    reporter = s3_reporter.S3Reporter(
        context=_context(tmp_path),
        config=s3_reporter.S3ReporterConfig(
            options=s3_reporter.S3ReporterConfigOptions(
                aws_region="us-west-2", bucket_name="a-bucket"
            )
        ),
    )
    reporter._plugin_log = MagicMock()

    with patch.object(s3_reporter, "boto3") as boto3:
        assert reporter.report(_workspace_model()) is None
    boto3.Session.assert_not_called()

    message = reporter._plugin_log.call_args[0][0]
    assert "Run ash results report with --output-dir" in message, message


def test_cloudwatch_logs_on_workspace_results_suggests_results_report(tmp_path):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        cloudwatch_logs_reporter as cloudwatch,
    )

    reporter = cloudwatch.CloudWatchLogsReporter(
        context=_context(tmp_path),
        config=cloudwatch.CloudWatchLogsReporterConfig(
            options=cloudwatch.CloudWatchLogsReporterConfigOptions(
                aws_region="us-west-2",
                log_group_name="a-log-group",
                log_stream_name="a-stream",
            )
        ),
    )
    reporter._plugin_log = MagicMock()

    with patch.object(cloudwatch, "boto3") as boto3:
        assert reporter.report(_workspace_model()) is None
    boto3.client.assert_not_called()

    message = reporter._plugin_log.call_args[0][0]
    assert "Run ash results report with --output-dir" in message, message


def test_security_hub_on_workspace_results_suggests_results_report():
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        _workspace_results_message,
    )

    message = _workspace_results_message(
        SimpleNamespace(workspace=SimpleNamespace(projects=[]))
    )

    assert "Run ash results report with --output-dir" in message, message


def test_security_hub_with_no_scanned_directory_suggests_scan_fs(tmp_path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        security_hub_reporter as securityhub,
    )

    printed: List[str] = []
    monkeypatch.setattr(
        securityhub, "echo", lambda message, err=False, **_: printed.append(message)
    )
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.why_no_scan_source",
        lambda source_dir, environ: "The scan recorded no directory.",
    )
    securityhub.reset_no_scan_source_notice()
    try:
        securityhub.SecurityHubReporter._notify_no_scan_source(
            SimpleNamespace(context=SimpleNamespace(source_dir=tmp_path))
        )
    finally:
        securityhub.reset_no_scan_source_notice()

    (notice,) = printed
    assert "To archive, scan with `ash scan fs --mode container`" in notice, notice


def test_the_markdown_reports_cut_note_names_results_inspect(test_plugin_context):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
        MarkdownReporterConfig,
        MarkdownReporterConfigOptions,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from tests.utils.scanner_thresholds import without_scanner_thresholds

    model = AshAggregatedResults(ash_config=get_default_config())
    without_scanner_thresholds(model)
    model.ash_config.global_settings.severity_threshold = "MEDIUM"
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": f"ERR-{index}",
                            "level": "error",
                            "message": {"text": f"actionable {index}"},
                            "properties": {"scanner_name": "bandit"},
                        }
                        for index in range(3)
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    reporter = MarkdownReporter(
        context=test_plugin_context,
        config=MarkdownReporterConfig(
            options=MarkdownReporterConfigOptions(max_detailed_findings=2)
        ),
    )

    text = _one_line(reporter.report(model))

    assert "Showing 2 of 3 total actionable findings" in text, text
    assert "use `ash results inspect findings` to review the full set" in text, text


def test_ferret_scans_show_suppressed_refusal_names_scan_fs():
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        UNSUPPORTED_FERRET_OPTIONS,
    )

    reason = UNSUPPORTED_FERRET_OPTIONS["show_suppressed"]

    assert "ash scan fs --ignore-suppressions reports them" in reason, reason


def test_comparing_sharded_results_is_refused_naming_results_merge():
    from automated_security_helper.utils.finding_diff import (
        ComparabilityRefusal,
        check_comparable,
    )

    sharded = SimpleNamespace(
        workspace=None,
        metadata=SimpleNamespace(shard=object()),
        baseline_filtered=False,
    )

    with pytest.raises(ComparabilityRefusal) as refused:
        check_comparable(sharded)

    assert str(refused.value) == (
        "use ash results merge before comparing sharded results"
    )


#: A terminal color sequence, which the console may write around a hint's markup.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_the_next_steps_after_a_scan_with_findings_name_results_report_and_inspect(
    tmp_path, monkeypatch, capsys
):
    """The block every scan with actionable findings ends with: each command it
    tells the reader to run is one that prints no deprecation line."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _print_summary,
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_ACTUAL_OUTPUT_DIR", raising=False)
    opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

    _print_summary(None, opts, scan_start_time=0.0, actionable_findings=1)

    lines = [
        _one_line(line) for line in _ANSI.sub("", capsys.readouterr().out).splitlines()
    ]
    assert (
        "2. Use ash results report to view a short text summary of the scan in your "
        "terminal"
    ) in lines, lines
    assert (
        "3. Use ash results inspect findings to explore the findings interactively"
    ) in lines, lines
    assert [line for line in lines if _is_legacy(line)] == []


def test_the_scan_help_says_to_review_the_result_with_results_inspect():
    from automated_security_helper.cli.scan import run_ash_scan_cli_command
    from automated_security_helper.cli.scan_group import (
        run_ash_scan_fs_cli_command,
        run_ash_scan_workspace_cli_command,
    )

    for args in (
        ["scan", "fs", "--help"],
        ["scan", "workspace", "--help"],
        ["scan", "--help"],
    ):
        result = _invoke(args)
        assert result.exit_code == 0, result.output
        assert "Review the result with: ash results inspect findings" in (
            _one_line(result.stdout)
        ), args
    # The root's scan callback carries the same docstring as `fs`, which is built
    # from it; `ash --help` shows the app's own help instead.
    for function in (
        run_ash_scan_fs_cli_command,
        run_ash_scan_workspace_cli_command,
        run_ash_scan_cli_command,
    ):
        assert "Review the result with: ash results inspect findings" in (
            _one_line(function.__doc__)
        ), function.__name__


def test_the_shard_index_help_says_to_recombine_the_shards_with_results_merge():
    root = typer.main.get_command(app)
    for command in (root, root.commands["scan"].commands["fs"]):
        (option,) = [p for p in command.params if "--shard-index" in p.opts]

        assert "recombine them with 'ash results merge'" in option.help, option.help


def test_an_option_a_command_does_not_take_is_refused_pointing_at_scan_fs():
    """A scan option given before a command that has no such option is refused. The
    refusal used to advise leaving the command out, which is the bare root, a form
    that warns."""
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke(["--scanners", "bandit", "results", "report"])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'ash results report' does not take --scanners" in text, text
    assert "or run 'ash scan fs' with it." in text, text
    assert "leave out" not in text, text


def test_the_merge_warning_about_ignore_paths_names_scan_fs(monkeypatch):
    from automated_security_helper.cli import merge

    logger = MagicMock()
    monkeypatch.setattr(merge, "ASH_LOGGER", logger)
    config = SimpleNamespace(
        global_settings=SimpleNamespace(
            ignore_paths=[SimpleNamespace(path="vendor/", client_supplied=False)]
        )
    )

    merge._warn_ignore_paths_the_flag_cannot_lift(config)

    (message,) = [call.args[0] for call in logger.warning.call_args_list]
    assert "where ash scan fs --ignore-suppressions keeps them" in message, message


#: The subjects of ``ash scan``, read from the CLI's own scan group: a subject a later
#: change adds is accepted as soon as the group has it, and a subject a page names
#: before then is a command that does not exist.
_SCAN_SUBJECTS = tuple(typer.main.get_command(app).commands["scan"].commands)


def _no_subject_command(subjects) -> re.Pattern[str]:
    """The forms that run the scan with no subject, and so warn: ``ash scan`` with
    no word after it or a word that is not one of *subjects*, and a bare root with
    an option, long or short (``ash --mode container``, ``ash -c x.yaml``)."""
    named = "|".join(re.escape(subject) for subject in subjects)
    return re.compile(
        rf"\b(?:ash|ashv3) scan\b(?! (?:{named})\b)"
        r"|(?<![\w./-])(?:\./)?(?:ash|ashv3|automated-security-helper) "
        r"-(?!-(?:version|install-completion|show-completion)\b)"
    )


_NO_SUBJECT = _no_subject_command(_SCAN_SUBJECTS)
#: A fenced line that is only the program, which runs the scan with no subject. In
#: prose ``ash`` is the program's name, not a command to type.
_BARE_PROGRAM = re.compile(
    r"^\s*(?:\$\s+)?(?:uv run\s+)?(?:\./)?(?:ash|ashv3|automated-security-helper)\s*$"
)
#: The top-level commands that moved.
_MOVED_COMMAND = re.compile(
    r"(?<![\w./-])(?:\./)?(?:ash|ashv3) (?:report|merge|inspect|build-image)\b"
)
#: Top-level names that are no command. ``ash diff`` and ``ash trend`` live under ``ash
#: results`` and never had a top-level spelling, so the CLI answers each with its usage
#: error ("No such command"): a page that gives one names a command that does not
#: exist, which is worse than a spelling that only warns.
_NOT_A_COMMAND = re.compile(r"(?<![\w./-])(?:\./)?(?:ash|ashv3) (?:diff|trend)\b")
_SCAN_FS = re.compile(r"\b(?:ash|ashv3) scan fs\b")
#: A scan of any subject, or of none: ``--scanners`` is an option of the scan alone.
_ASH_SCAN = re.compile(r"\b(?:ash|ashv3) scan\b")
#: The option ``ash scan`` and each of its subjects deprecate for ``--only-scanners``
#: and ``--add-scanners`` (cli/scan.py prints "DeprecationWarning: --scanners (and
#: ASH_SCANNERS) is deprecated"), as ``--scanners X`` or ``--scanners=X``. Neither
#: replacement matches it. No other ASH command takes the option, so it is a
#: deprecated spelling only where its command is a scan: Trivy has an option of the
#: same name.
_SCANNERS_OPTION = re.compile(r"(?<![\w-])--scanners(?![\w-])")
#: What ends one command on a shell line and starts the next.
_COMMAND_SEPARATOR = re.compile(r"&&|\|\||[;|]")
#: A help request never warns.
_HELP = re.compile(r"(?<!\S)--help(?=\s|$)")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")

#: The markdown under the package that is a dated record, not documentation a reader
#: is sent to, and the gitignored copy of a docs page the wheel build writes; the
#: docs checks leave out the same two (scripts/verify_docs_freshness.py).
_NOT_DOCUMENTATION = (
    "plugin_modules/ash_ferret_plugins/spec/",
    "assets/genai-steering-guide.md",
)


def _scans_with_the_deprecated_scanners_option(command: str) -> bool:
    """Whether a command on the line *command* is an ``ash scan`` given ``--scanners``.

    A line can run several commands, and an option belongs to the one it follows: the
    ``--scanners`` of ``ash scan fs . && trivy fs --scanners vuln .`` is Trivy's.
    """
    return any(
        _ASH_SCAN.search(part) and _SCANNERS_OPTION.search(part)
        for part in _COMMAND_SEPARATOR.split(command)
    )


def _is_legacy(command: str, fenced: bool = False) -> bool:
    """Whether *command*, as a reader is shown it, runs a spelling that warns, or names
    a top-level command that does not exist.

    A help request never warns, whatever it follows. ``ash diff`` and ``ash trend`` are
    flagged even beside ``--help``: the CLI refuses the word whatever follows it. A scan
    with ``--workspace`` and no subject warns too, naming ``ash scan workspace``, and so
    does ``--scanners`` on any scan, which ``--only-scanners`` and ``--add-scanners``
    replace. The program alone is the bare scan only as a line of a fenced block.
    """
    if _NOT_A_COMMAND.search(command):
        return True
    if _HELP.search(command):
        return False
    no_subject = _NO_SUBJECT.search(command) or (
        fenced and _BARE_PROGRAM.search(command)
    )
    if no_subject:
        return True
    if _MOVED_COMMAND.search(command):
        return True
    if _SCAN_FS.search(command) and "--source-dir" in command:
        return True
    return _scans_with_the_deprecated_scanners_option(command)


def _commands(markdown: str):
    """(line number, text, fenced) of each command a reader of *markdown* is shown:
    every line of a fenced block that is not a comment, and every inline code span. A
    span with no option counts too: ``to run a scan, use `ash scan``` is a command
    to type even though it passes nothing. A fenced line that ends in a backslash
    goes on in the next one, and the lines are one command, numbered from its first."""
    fenced = False
    held: list[str] = []  # the lines of a command that goes on, without their backslash
    first = 0
    for number, line in enumerate(markdown.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            if held:  # the block ends in the middle of a command
                yield first, " ".join(held), True
                held = []
            continue
        if fenced:
            if not held:
                if line.lstrip().startswith("#"):
                    continue
                first = number
            if line.rstrip().endswith("\\"):
                held.append(line.rstrip()[:-1].strip())
                continue
            yield first, " ".join([*held, line.strip()]), True
            held = []
            continue
        for span in _INLINE_CODE.findall(line):
            yield number, span, False
    if held:
        yield first, " ".join(held), True


def _legacy_commands(markdown: str) -> list[tuple[int, str]]:
    """(line number, text) of each command in *markdown* that runs a spelling
    that warns."""
    return [
        (number, command)
        for number, command, fenced in _commands(markdown)
        if _is_legacy(command, fenced)
    ]


def test_the_markdown_the_package_ships_shows_no_legacy_spelling_in_a_command():
    package = Path(automated_security_helper.__file__).parent
    pages = [
        page
        for page in sorted(package.rglob("*.md"))
        if not page.relative_to(package).as_posix().startswith(_NOT_DOCUMENTATION)
    ]
    assert pages, "no markdown found under the package"

    found = [
        f"{page.relative_to(package).as_posix()}:{number}: {command}"
        for page in pages
        for number, command in _legacy_commands(page.read_text(encoding="utf-8"))
    ]

    assert found == [], "\n".join(found)


@pytest.mark.parametrize(
    ("command", "legacy"),
    [
        ("uv run ash --scanners trivy-repo", True),
        ("ash scan --ash-plugin-modules x", True),
        ("uv run ash scan fs src --source-dir src", True),
        ("ash report --format text", True),
        # ``ash diff`` and ``ash trend`` were never top-level commands: each is a usage
        # error, with or without a program path, ``ashv3`` or a help request.
        ("ash diff before.json after.json", True),
        ("ash trend", True),
        ("uv run ashv3 diff before.json after.json", True),
        ("./ash trend runs/a.json runs/b.json", True),
        ("ash diff --help", True),
        # No subject, a short option on the bare root, and a word that is no subject.
        ("ash scan", True),
        ("ash -c x.yaml", True),
        ("uv run ash -c x.yaml --mode container", True),
        ("ash scan nosuchsubject src", True),
        # A deprecated option on a subject still warns.
        ("ash scan fs --mode container --source-dir src", True),
        # --scanners is deprecated on every scan, as ``--scanners X`` and
        # ``--scanners=X``: --only-scanners and --add-scanners replace it.
        ("uv run ash scan fs /path/to/project --scanners trivy-repo", True),
        ("ash scan fs . --scanners=trivy-repo", True),
        ("ash scan workspace ws.code-workspace --scanners detect-secrets", True),
        ("./ash scan fs . --mode container --scanners bandit,semgrep", True),
        # A workspace scan with no subject warns, and names the subject it moved to.
        ("ash scan --workspace ws.yaml", True),
        ("ash --workspace ws.yaml", True),
        ("ash --workspace=ws.yaml --mode container", True),
        ("uv run ash scan --workspace ws.code-workspace --dry-run", True),
        ("ash scan fs --ash-plugin-modules x", False),
        # The options that replace --scanners, a help request, and another program's
        # option of the same name (Trivy's), alone or on a line that runs a scan first.
        ("uv run ash scan fs /path/to/project --only-scanners trivy-repo", False),
        ("ash scan fs . --add-scanners=trivy-repo", False),
        ("ash scan fs . --exclude-scanners trivy-repo", False),
        ("ash scan fs --scanners trivy-repo --help", False),
        ("trivy fs --scanners vuln,secret .", False),
        ("ash scan fs . && trivy fs --scanners vuln .", False),
        ("ash config get --source-dir src", False),
        ("ash --version", False),
        ("ash --install-completion", False),
        ("ash --show-completion", False),
        ("uv run ash plugin list --ash-plugin-modules x", False),
        # The workspace subject, with its own options, and a help request, which never
        # warns, on any spelling.
        ("ash scan workspace ws.code-workspace --dry-run", False),
        ("uv run ash scan workspace ws.code-workspace --allow-missing-projects", False),
        ("ash scan --help", False),
        ("ash scan --workspace --help", False),
        ("ash --help", False),
        ("ash report --help", False),
        # The two commands where they live, and words that only look like the program or
        # the command.
        ("ash results diff before.json after.json", False),
        ("ash results trend runs/a.json runs/b.json", False),
        ("ash results diff --help", False),
        ("bash diff before after", False),
        ("ash difference", False),
        # Every subject the scan group has is one a page may name.
        *[(f"ash scan {subject} src", False) for subject in _SCAN_SUBJECTS],
    ],
)
def test_the_markdown_check_tells_a_legacy_command_from_a_noun_one(command, legacy):
    """The check's own controls: it flags each kind of old spelling, and passes the
    noun forms and the commands whose ``--source-dir`` or ``--scanners`` is their own
    option."""
    assert _is_legacy(command) is legacy


_FENCE = "`" * 3


def _fenced(*lines: str) -> str:
    """A markdown snippet that holds *lines* as one fenced block."""
    return "\n".join([f"{_FENCE}console", *lines, _FENCE])


@pytest.mark.parametrize(
    ("markdown", "flagged"),
    [
        pytest.param(
            _fenced("uv run ash \\", "    --mode container"),
            [(2, "uv run ash --mode container")],
            id="a-bare-root-continued-onto-its-option",
        ),
        pytest.param(
            _fenced("uv run ash scan fs . \\", "    --source-dir src"),
            [(2, "uv run ash scan fs . --source-dir src")],
            id="a-deprecated-option-on-the-continuation-line",
        ),
        pytest.param(
            _fenced("uv run ash scan fs . \\", "    --only-scanners bandit"),
            [],
            id="a-continued-scan-fs-with-its-own-options",
        ),
        pytest.param(
            _fenced("uv run ash scan fs . \\", "    --scanners bandit"),
            [(2, "uv run ash scan fs . --scanners bandit")],
            id="the-scanners-option-on-the-continuation-line",
        ),
        pytest.param(
            _fenced("uv run ash scan fs . --scanners bandit"),
            [(2, "uv run ash scan fs . --scanners bandit")],
            id="the-scanners-option-in-a-fenced-line",
        ),
        pytest.param(
            _fenced("uv run ash scan fs . --scanners=bandit"),
            [(2, "uv run ash scan fs . --scanners=bandit")],
            id="the-scanners-option-with-an-equals-sign-in-a-fenced-line",
        ),
        pytest.param(
            "Narrow it with `ash scan fs . --scanners bandit`.",
            [(1, "ash scan fs . --scanners bandit")],
            id="the-scanners-option-inline",
        ),
        pytest.param(
            "Narrow it with `ash scan fs . --scanners=bandit`.",
            [(1, "ash scan fs . --scanners=bandit")],
            id="the-scanners-option-with-an-equals-sign-inline",
        ),
        pytest.param(
            _fenced("trivy fs --scanners vuln,secret ."),
            [],
            id="another-programs-scanners-option",
        ),
        pytest.param(
            "Use `--only-scanners` where you wrote `--scanners`.",
            [],
            id="the-option-named-in-prose",
        ),
        pytest.param(
            _fenced("ash diff before.json after.json"),
            [(2, "ash diff before.json after.json")],
            id="a-top-level-diff-in-a-fenced-line",
        ),
        pytest.param(
            _fenced("$ ./ash trend runs/a.json runs/b.json"),
            [(2, "$ ./ash trend runs/a.json runs/b.json")],
            id="a-top-level-trend-with-the-wrapper-path",
        ),
        pytest.param(
            "Compare two scans with `ashv3 diff before.json after.json`.",
            [(1, "ashv3 diff before.json after.json")],
            id="a-top-level-diff-inline",
        ),
        pytest.param(
            _fenced("ash results diff before.json after.json"),
            [],
            id="diff-under-results",
        ),
        pytest.param(
            _fenced("ash scan \\", "    --workspace ws.yaml"),
            [(2, "ash scan --workspace ws.yaml")],
            id="a-workspace-scan-with-no-subject-continued",
        ),
        pytest.param(
            _fenced("ash scan workspace ws.yaml \\", "    --dry-run"),
            [],
            id="a-workspace-subject-continued",
        ),
        pytest.param(
            _fenced("uv run ash scan \\"),
            [(2, "uv run ash scan")],
            id="a-continuation-at-the-end-of-the-block",
        ),
        pytest.param(
            _fenced("uv run ash"), [(2, "uv run ash")], id="the-program-alone"
        ),
        pytest.param(
            _fenced("$ ash"), [(2, "$ ash")], id="the-program-alone-after-a-prompt"
        ),
        pytest.param(_fenced("which ash"), [], id="the-program-as-an-argument"),
        pytest.param("Run `ash` to scan.", [], id="the-program-named-in-prose"),
        pytest.param(_fenced("# ash scan"), [], id="a-comment"),
    ],
)
def test_the_markdown_check_reads_a_command_as_its_reader_does(markdown, flagged):
    """A command that goes on after a backslash is one command, and the program on
    a line by itself is the bare scan in a fenced block only."""
    assert _legacy_commands(markdown) == flagged


@pytest.mark.parametrize("name", ["diff", "trend"])
def test_a_top_level_diff_or_trend_is_a_usage_error(name):
    """The premise of ``_NOT_A_COMMAND``: ``ash diff`` and ``ash trend`` are no
    commands, they live under ``ash results``, and ASH answers each top-level word with
    its usage-error code, so a page that gives one sends its reader to a failure, which
    is worse than a spelling that only warns."""
    from automated_security_helper.core.enums import AshExitCode

    root = typer.main.get_command(app)
    assert name not in root.commands
    assert name in root.commands["results"].commands

    result = _invoke([name, "before.json", "after.json"])

    assert result.exit_code == AshExitCode.USAGE_ERROR, result.output
    assert f"No such command '{name}'" in _one_line(result.output), result.output


def test_the_subjects_the_markdown_check_admits_are_the_scan_groups():
    """They are read from the CLI, not listed in this file."""
    group = typer.main.get_command(app).commands["scan"]

    assert _SCAN_SUBJECTS == tuple(group.commands)
    assert "fs" in _SCAN_SUBJECTS


def test_a_subject_the_scan_group_gains_is_admitted_once_it_has_it():
    command = "ash scan workspace ."

    assert _no_subject_command(("fs",)).search(command)
    assert not _no_subject_command(("fs", "workspace")).search(command)
