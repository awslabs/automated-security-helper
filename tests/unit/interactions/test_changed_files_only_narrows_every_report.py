# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--changed-files-only`` drops the same findings from every report and the verdict.

Why this exists
---------------
Every scanner scans the whole tree under ``--changed-files-only``; findings outside
the changed files are then left out. The scan engine filters the one model all the
reports read, before the summary counts and the reporters, so the HTML, Markdown,
text, CSV, flat-json, JUnit, GitLab SAST, OCSF, GHAS and YAML reports,
``ash.sarif``, ``ash_aggregated_results.json``, the counts and the exit code all
leave out the same findings. A filter run after the report phase would narrow only
the in-memory results and what was rewritten from them; the reports already written
would keep every finding.

The run here is a report over saved results with the real orchestrator and the
real built-in reporters; only git is stubbed. ``changed.py`` has a LOW finding and
``untouched.py`` a HIGH one, under the default MEDIUM threshold, so the verdict
also shows which set it was taken from.
"""

import json
import sys
from pathlib import Path

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    _run_local_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

#: Every built-in report that lists findings.
FINDING_REPORTS = [
    ExportFormat.SARIF,
    ExportFormat.FLAT_JSON,
    ExportFormat.CSV,
    ExportFormat.HTML,
    ExportFormat.MARKDOWN,
    ExportFormat.TEXT,
    ExportFormat.JUNITXML,
    ExportFormat.GITLAB_SAST,
    ExportFormat.OCSF,
    ExportFormat.GITHUB_GHAS,
    ExportFormat.YAML,
]


def _finding(uri: str, level: str, severity: str) -> dict:
    return {
        "ruleId": f"B-{uri}",
        "level": level,
        "message": {"text": f"finding in {uri}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "scanner_name": "bandit",
            "issue_severity": severity,
            "tags": ["bandit"],
        },
    }


@pytest.fixture
def no_aws(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))

    def refuse(*args, **kwargs):
        raise AssertionError("a botocore request was attempted")

    monkeypatch.setattr("botocore.endpoint.Endpoint._send", refuse)


@pytest.fixture
def scanned(tmp_path, monkeypatch, no_aws):
    from automated_security_helper.utils import get_scan_set

    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    (source / "changed.py").write_text("x = 1\n", encoding="utf-8")
    (source / "untouched.py").write_text("y = 2\n", encoding="utf-8")
    monkeypatch.setattr(
        get_scan_set, "get_changed_files", lambda base_ref, cwd: ["src/changed.py"]
    )
    monkeypatch.setattr(
        get_scan_set, "git_repository_root", lambda path, **kwargs: repo
    )

    saved = AshAggregatedResults()
    saved.ash_config = get_default_config()
    saved.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"},
                        "extensions": [{"name": "bandit", "version": "1.8.6"}],
                    },
                    "results": [
                        _finding("changed.py", "note", "LOW"),
                        _finding("untouched.py", "error", "HIGH"),
                    ],
                }
            ],
        }
    )
    saved_path = tmp_path / "saved.json"
    saved_path.write_text(saved.model_dump_json(by_alias=True), encoding="utf-8")

    output = tmp_path / "out"
    output.mkdir()
    opts = ScanOptions(
        source_dir=source,
        output_dir=output,
        changed_files_only=True,
        existing_results=str(saved_path),
        phases=[ExecutionPhase.REPORT],
        output_formats=FINDING_REPORTS,
        # yaml is disabled by default; every report that lists findings is checked.
        config_overrides=["reporters.yaml.enabled=true"],
        show_summary=False,
        progress=False,
        # The saved results carry findings but no scanner status rows; the
        # completeness gate would read that as an incomplete scan. Off, so the
        # verdict below is the findings gate alone.
        fail_on_incomplete_scanners=False,
    )
    results, config_fail_on_findings = _run_local_mode(opts, _Logger())
    return opts, output, results, config_fail_on_findings


class _Logger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def _reports(output: Path):
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((output / "reports").iterdir())
        if path.is_file()
    }


def test_every_report_was_written(scanned):
    _, output, _, _ = scanned

    assert len(_reports(output)) == len(FINDING_REPORTS)


def test_no_report_lists_a_finding_outside_the_changed_files(scanned):
    _, output, _, _ = scanned

    offenders = [
        name for name, content in _reports(output).items() if "untouched.py" in content
    ]
    assert offenders == []


#: These two list only actionable findings, and changed.py's is LOW, below the
#: default MEDIUM threshold. They are still checked for untouched.py above.
ACTIONABLE_ONLY_REPORTS = {"ash.summary.md", "ash.summary.txt"}


def test_each_report_keeps_the_finding_in_the_changed_file(scanned):
    _, output, _, _ = scanned

    missing = [
        name
        for name, content in _reports(output).items()
        if name not in ACTIONABLE_ONLY_REPORTS and "changed.py" not in content
    ]
    assert missing == []


def test_the_summary_counts_only_the_changed_file(scanned):
    _, output, _, _ = scanned
    saved = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    stats = saved["metadata"]["summary_stats"]

    assert stats["total"] == 1
    assert stats["severity_counts"]["high"] == 0
    assert stats["severity_counts"]["low"] == 1


def test_the_verdict_is_taken_from_the_changed_file(scanned):
    opts, _, results, config_fail_on_findings = scanned

    # The LOW finding is below the default MEDIUM threshold; the HIGH one that
    # would fail the scan is in untouched.py.
    assert _compute_exit_code(results, opts, config_fail_on_findings) == 0


def test_the_results_say_they_were_filtered(scanned):
    _, output, _, _ = scanned
    saved = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )

    assert saved["metadata"]["changed_files_only"] is True


def _stale_ash_sarif(output: Path, *findings: dict) -> None:
    """A reports/ash.sarif left by an earlier run, unfiltered."""
    reports = output / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "ash.sarif").write_text(
        SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {"name": "AWS Labs - Automated Security Helper"}
                        },
                        "results": list(findings),
                    }
                ],
            }
        ).model_dump_json(by_alias=True, exclude_none=True),
        encoding="utf-8",
    )


def _spy_on_the_gate(monkeypatch) -> list:
    """What run_ash_scan tells the exit-code gate about reports/ash.sarif.

    One entry per _compute_exit_code call: its report_sarif_written_this_run.
    """
    from automated_security_helper.interactions import run_ash_scan as module

    told = []
    real = module._compute_exit_code

    def spy(*args, **kwargs):
        told.append(kwargs.get("report_sarif_written_this_run"))
        return real(*args, **kwargs)

    monkeypatch.setattr(module, "_compute_exit_code", spy)
    return told


def _saved_results(tmp_path: Path, *findings: dict) -> Path:
    """Saved results for a report-phase run, as --use-existing reads them."""
    saved = AshAggregatedResults()
    saved.ash_config = get_default_config()
    saved.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"}
                    },
                    "results": list(findings),
                }
            ],
        }
    )
    saved_path = tmp_path / "saved.json"
    saved_path.write_text(saved.model_dump_json(by_alias=True), encoding="utf-8")
    return saved_path


def _report_over_saved_results(source, output, saved_path, **kwargs) -> int:
    """run_ash_scan's report phase over saved results; its exit code."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(output),
            existing_results=str(saved_path),
            phases=[ExecutionPhase.REPORT],
            show_summary=False,
            progress=False,
            quiet=True,
            fail_on_incomplete_scanners=False,
            **kwargs,
        )
    except SystemExit as exc:
        return exc.code
    return 0


@pytest.mark.parametrize(
    "formats",
    [[ExportFormat.MARKDOWN], [ExportFormat.MARKDOWN, ExportFormat.SARIF]],
    ids=["sarif-not-written", "sarif-written"],
)
@pytest.mark.parametrize("changed_files_only", [True, False])
def test_a_stale_ash_sarif_never_decides_the_verdict(
    tmp_path, monkeypatch, no_aws, formats, changed_files_only
):
    """The gate reads reports/ash.sarif only when this run wrote it.

    A report over saved results does not clear reports/, so an ash.sarif from an
    earlier, unfiltered run stayed there when this run did not write one, and the
    gate let it decide: here its HIGH finding in untouched.py failed the scan
    (exit 2) although the results this run reports hold only a LOW finding.

    When this run does write the file, over the earlier one, the gate is told
    so: the exit code alone cannot show it, because this run's file and its
    in-memory results agree.
    """
    from automated_security_helper.utils import get_scan_set

    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    monkeypatch.setattr(
        get_scan_set, "get_changed_files", lambda base_ref, cwd: ["src/changed.py"]
    )
    monkeypatch.setattr(
        get_scan_set, "git_repository_root", lambda path, **kwargs: repo
    )
    saved_path = _saved_results(tmp_path, _finding("changed.py", "note", "LOW"))
    output = tmp_path / "out"
    _stale_ash_sarif(
        output,
        _finding("changed.py", "note", "LOW"),
        _finding("untouched.py", "error", "HIGH"),
    )
    told = _spy_on_the_gate(monkeypatch)

    exit_code = _report_over_saved_results(
        source,
        output,
        saved_path,
        changed_files_only=changed_files_only,
        output_formats=formats,
    )

    assert exit_code == 0
    assert told == [ExportFormat.SARIF in formats]
    on_disk = (output / "reports" / "ash.sarif").read_text(encoding="utf-8")
    if ExportFormat.SARIF in formats:
        # Written this run, from the results it reports, and then read.
        assert "untouched.py" not in on_disk
    else:
        # Still the earlier run's file, left alone and not read.
        assert "untouched.py" in on_disk


@pytest.mark.parametrize(
    ("notebook", "kept"),
    [("changed.ipynb", True), ("untouched.ipynb", False)],
    ids=["notebook-in-the-diff", "notebook-not-in-the-diff"],
)
def test_a_converted_finding_is_placed_by_the_source_the_converter_recorded(
    tmp_path, monkeypatch, no_aws, notebook, kept
):
    """The engine reads the converters' converted-sources.json back and hands it
    to the filter, so a finding in a converted notebook follows the notebook: kept
    when the notebook is in the diff, dropped when it is not. Before this the
    engine passed no mapping, and every such finding was kept whatever changed.
    """
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.utils import get_scan_set
    from automated_security_helper.utils.scan_output_dirs import (
        CONVERTED_SOURCES_FILE_NAME,
    )

    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    monkeypatch.setattr(
        get_scan_set, "get_changed_files", lambda base_ref, cwd: ["src/changed.ipynb"]
    )
    monkeypatch.setattr(
        get_scan_set, "git_repository_root", lambda path, **kwargs: repo
    )
    output = tmp_path / "out"
    converter_dir = output / ASH_WORK_DIR_NAME / "jupyter"
    converter_dir.mkdir(parents=True)
    converted = converter_dir / "nb__ipynb-converted.py"
    converted.write_text("import os\n", encoding="utf-8")
    (converter_dir / CONVERTED_SOURCES_FILE_NAME).write_text(
        json.dumps({"jupyter/nb__ipynb-converted.py": notebook}), encoding="utf-8"
    )
    finding = _finding(str(converted), "error", "HIGH")
    finding["properties"]["converted_path"] = "jupyter/nb__ipynb-converted.py"
    saved_path = _saved_results(tmp_path, finding)

    exit_code = _report_over_saved_results(
        source,
        output,
        saved_path,
        changed_files_only=True,
        output_formats=[ExportFormat.SARIF],
    )

    on_disk = (output / "reports" / "ash.sarif").read_text(encoding="utf-8")
    assert ("nb__ipynb-converted.py" in on_disk) is kept
    # A HIGH finding fails the scan when it is reported.
    assert exit_code == (2 if kept else 0)


@needs_symlinks
def test_a_link_at_ash_sarif_is_never_read_as_this_runs(tmp_path, monkeypatch, no_aws):
    """reports/ash.sarif is this run's only as a regular file the run wrote.

    The identity follows no symlink, so a link there to another report this run
    rewrites (ash.flat.json here) is not read as written this run, and the HIGH
    finding this run reports fails the scan. A link survives into the run only
    under --use-existing, as here, or in ``ash merge`` into a reused output
    directory.
    """
    source = tmp_path / "repo" / "src"
    source.mkdir(parents=True)
    saved_path = _saved_results(tmp_path, _finding("untouched.py", "error", "HIGH"))
    output = tmp_path / "out"
    reports = output / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").symlink_to("ash.flat.json")
    told = _spy_on_the_gate(monkeypatch)

    exit_code = _report_over_saved_results(
        source,
        output,
        saved_path,
        output_formats=[ExportFormat.MARKDOWN, ExportFormat.FLAT_JSON],
    )

    # The link is still there, and its target was written this run.
    assert (reports / "ash.sarif").is_symlink()
    assert "untouched.py" in (reports / "ash.flat.json").read_text(encoding="utf-8")
    assert exit_code == 2
    assert told == [False]


@pytest.mark.parametrize(
    "earlier_file", [True, False], ids=["over-an-earlier-file", "no-earlier-file"]
)
def test_the_gate_reads_the_ash_sarif_this_run_wrote(
    tmp_path, monkeypatch, no_aws, earlier_file
):
    """The ash.sarif this run writes decides the exit code.

    In container and nix mode the host's results come from the inner scan, and
    the gate reads the inner scan's ash.sarif; that is why a run reads the file
    at all. Here this run's ash.sarif holds a HIGH finding its in-memory results
    do not, so the exit code shows which one decided: 2 from the file, 0 from
    memory. The identity tells this run's rewrite of an earlier ash.sarif apart
    from that earlier file, so the run reads its own file and exits 2.
    """
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    source = tmp_path / "repo" / "src"
    source.mkdir(parents=True)
    saved_path = _saved_results(tmp_path, _finding("changed.py", "note", "LOW"))
    output = tmp_path / "out"
    if earlier_file:
        _stale_ash_sarif(output, _finding("changed.py", "note", "LOW"))
    this_runs_sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"}
                    },
                    "results": [_finding("untouched.py", "error", "HIGH")],
                }
            ],
        }
    ).model_dump_json(by_alias=True, exclude_none=True)
    monkeypatch.setattr(SarifReporter, "report", lambda self, model: this_runs_sarif)
    told = _spy_on_the_gate(monkeypatch)

    exit_code = _report_over_saved_results(
        source, output, saved_path, output_formats=[ExportFormat.SARIF]
    )

    assert (output / "reports" / "ash.sarif").read_text(
        encoding="utf-8"
    ) == this_runs_sarif
    assert exit_code == 2
    assert told == [True]


class TestReportSarifIdentity:
    """report_sarif_identity has an answer only for a regular file."""

    @staticmethod
    def _identity(output):
        from automated_security_helper.interactions.run_ash_scan import (
            report_sarif_identity,
        )

        return report_sarif_identity(output)

    def test_no_file_has_none(self, tmp_path):
        assert self._identity(tmp_path) is None

    def test_a_regular_file_has_its_device_inode_mtime_and_size(self, tmp_path):
        import os

        sarif = tmp_path / "reports" / "ash.sarif"
        sarif.parent.mkdir()
        sarif.write_text("{}", encoding="utf-8")
        status = os.lstat(sarif)

        assert self._identity(tmp_path) == (
            status.st_dev,
            status.st_ino,
            status.st_mtime_ns,
            status.st_size,
        )

    @needs_symlinks
    def test_a_link_to_a_regular_file_has_none(self, tmp_path):
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "ash.flat.json").write_text("{}", encoding="utf-8")
        (reports / "ash.sarif").symlink_to("ash.flat.json")

        assert self._identity(tmp_path) is None

    def test_a_directory_has_none(self, tmp_path):
        (tmp_path / "reports" / "ash.sarif").mkdir(parents=True)

        assert self._identity(tmp_path) is None
