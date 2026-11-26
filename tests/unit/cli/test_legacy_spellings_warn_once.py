# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The 3.9 contract for every command spelling that moved, and the hints that name one.

ASH 3.9 moves the directory scan under ``ash scan fs``, the commands that read saved
results under ``ash results`` and the image build under ``ash container build``. Each
old spelling keeps working through 3.x:

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
leads to a deprecation line. Each of those rows failed before the hint moved.

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


def _results_argv(verb: str) -> Callable[[Path], List[str]]:
    """A cheap invocation of *verb* that needs no saved results.

    Each one fails the same way under either spelling (a missing input, or a bare
    group), so the exit code and the command's own output can be compared.
    """

    def build(tmp_path: Path) -> List[str]:
        missing = str(tmp_path / "absent.json")
        return {
            "report": [verb, "--output-dir", str(tmp_path / "no-such-output")],
            "diff": [verb, missing, missing],
            "trend": [verb, missing, missing],
            "merge": [verb, "--results", str(tmp_path / "no-such-shard")],
            "inspect": [verb],
        }[verb]

    return build


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
    **{
        verb: Spelling(
            legacy=_results_argv(verb),
            noun=lambda tmp_path, verb=verb: [
                "results",
                *_results_argv(verb)(tmp_path),
            ],
            names=f"ash results {verb}",
        )
        for verb in ("report", "diff", "trend", "merge", "inspect")
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
    (its ``source_dir`` is null, which a document reads as not given) and a document
    that uses the ``path`` key run as ``ash scan fs src`` runs, and say nothing."""
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


def test_the_container_build_help_names_scan_fs_for_a_scan_with_scan_options():
    from automated_security_helper.cli.container import BUILD_HELP

    assert "run `ash scan fs --mode container`" in BUILD_HELP, BUILD_HELP


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
    from automated_security_helper.cli.scan_group import run_ash_scan_fs_cli_command

    for args in (["scan", "fs", "--help"], ["scan", "--help"]):
        result = _invoke(args)
        assert result.exit_code == 0, result.output
        assert "Review the result with: ash results inspect findings" in (
            _one_line(result.stdout)
        ), args
    # The root's scan callback carries the same docstring as `fs`, which is built
    # from it; `ash --help` shows the app's own help instead.
    for function in (run_ash_scan_fs_cli_command, run_ash_scan_cli_command):
        assert "Review the result with: ash results inspect findings" in (
            _one_line(function.__doc__)
        ), function.__name__


def test_the_shard_index_help_says_to_recombine_the_shards_with_results_merge():
    root = typer.main.get_command(app)
    for command in (root, root.commands["scan"].commands["fs"]):
        (option,) = [p for p in command.params if "--shard-index" in p.opts]

        assert "recombine them with 'ash results merge'" in option.help, option.help


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


#: The legacy spellings: a scan with no subject, a bare root with an option, and the
#: top-level commands that moved.
_LEGACY_COMMAND = re.compile(
    r"\b(?:ash|ashv3) scan\b(?! (?:fs|workspace|image|git)\b)"
    r"|(?<![\w./-])(?:\./)?(?:ash|ashv3|automated-security-helper) "
    r"--(?!version\b|help\b|install-completion\b|show-completion\b)"
    r"|(?<![\w./-])(?:\./)?(?:ash|ashv3) (?:report|diff|trend|merge|inspect|build-image)\b"
)
_SCAN_FS = re.compile(r"\b(?:ash|ashv3) scan fs\b")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")

#: The markdown under the package that is a dated record, not documentation a reader
#: is sent to, and the gitignored copy of a docs page the wheel build writes; the
#: docs checks leave out the same two (scripts/verify_docs_freshness.py).
_NOT_DOCUMENTATION = (
    "plugin_modules/ash_ferret_plugins/spec/",
    "assets/genai-steering-guide.md",
)


def _is_legacy(command: str) -> bool:
    return bool(_LEGACY_COMMAND.search(command)) or bool(
        _SCAN_FS.search(command) and "--source-dir" in command
    )


def _commands(markdown: str):
    """(line number, text) of each command a reader of *markdown* is shown: every
    line of a fenced block that is not a comment, and every inline code span. A
    span with no option counts too: ``to run a scan, use `ash scan``` is a command
    to type even though it passes nothing."""
    fenced = False
    for number, line in enumerate(markdown.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            if not line.lstrip().startswith("#"):
                yield number, line
            continue
        for span in _INLINE_CODE.findall(line):
            yield number, span


def test_the_markdown_the_package_ships_shows_no_legacy_spelling_in_a_command():
    package = Path(automated_security_helper.__file__).parent
    pages = [
        page
        for page in sorted(package.rglob("*.md"))
        if not page.relative_to(package).as_posix().startswith(_NOT_DOCUMENTATION)
    ]
    assert pages, "no markdown found under the package"

    found = [
        f"{page.relative_to(package).as_posix()}:{number}: {command.strip()}"
        for page in pages
        for number, command in _commands(page.read_text(encoding="utf-8"))
        if _is_legacy(command)
    ]

    assert found == [], "\n".join(found)


@pytest.mark.parametrize(
    ("command", "legacy"),
    [
        ("uv run ash --scanners trivy-repo", True),
        ("ash scan --ash-plugin-modules x", True),
        ("uv run ash scan fs src --source-dir src", True),
        ("ash report --format text", True),
        ("ash scan fs --ash-plugin-modules x", False),
        ("uv run ash scan fs /path/to/project --scanners trivy-repo", False),
        ("ash config get --source-dir src", False),
        ("ash --version", False),
        ("uv run ash plugin list --ash-plugin-modules x", False),
    ],
)
def test_the_markdown_check_tells_a_legacy_command_from_a_noun_one(command, legacy):
    """The check's own controls: it flags each kind of old spelling, and passes the
    noun forms and the commands whose ``--source-dir`` is their own option."""
    assert _is_legacy(command) is legacy
