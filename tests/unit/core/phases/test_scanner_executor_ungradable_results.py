"""A scanner result ASH cannot read is ERROR, not a clean scan.

The executor grades a SARIF report by its findings and a dict by its ``status``,
``severity_counts`` or ``findings``. A dict with none of those carries nothing to
grade, and graded on its zero findings it would read as PASSED. Two routes produce
one: the template ``scan()`` handed JSON that is not SARIF (a tool that wrote
``{"errors": [...]}`` and exited 0), and a scanner that overrides ``scan()`` and
returns its tool's JSON when it does not parse (ferret-scan does). Either way the
scanner's findings are not read, so the row is ERROR and says so.

The controls are the dict shapes the executor does grade: ``severity_counts``, a
``findings`` list, and ``status: failed``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class TemplateScanner(ScannerPluginBase):
    """Runs the template: its tool writes ``self.results_text`` and exits 0."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_dir = self.results_dir / target_type
        results_dir.mkdir(parents=True, exist_ok=True)
        results_file = results_dir / "results.sarif"
        results_file.write_text(self.results_text, encoding="utf-8")
        return ["shape-tool", "--scan"], results_file, None


class OverrideScanner(TemplateScanner):
    """Overrides ``scan()`` and returns ``self.returned`` as it is."""

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        return self.returned


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="shapes"),
    )


def _row(plugin_context, scanner):
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _template_row(plugin_context, results_text: str):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = TemplateScanner(config=config, context=plugin_context)
    scanner.results_text = results_text
    with patch.object(
        scanner, "_run_subprocess", return_value={"returncode": 0, "stderr": ""}
    ):
        return _row(plugin_context, scanner)


def _override_row(plugin_context, returned):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = OverrideScanner(config=config, context=plugin_context)
    scanner.returned = returned
    return _row(plugin_context, scanner)


def _says_why(row) -> bool:
    return any("could not be graded" in str(error) for error in row.errors)


class TestAResultWithNothingToGradeIsAnError:
    @pytest.mark.parametrize(
        "content",
        [
            json.dumps({"errors": ["the tool could not read its rules"]}),
            json.dumps({"version": "2.1.0", "runs": "not a list"}),
            json.dumps([]),
        ],
        ids=["error-object", "malformed-sarif", "json-list"],
    )
    def test_the_template_with_json_that_is_not_sarif(self, plugin_context, content):
        row = _template_row(plugin_context, content)

        assert row.status == ScannerStatus.ERROR, (
            f"the tool exited 0 and wrote {content!r}, which ASH could not read as "
            f"SARIF; the row was graded {row.status.value}"
        )
        assert _says_why(row), f"errors: {row.errors!r}"

    def test_an_override_returning_its_tools_json(self, plugin_context):
        row = _override_row(plugin_context, {"runs": "not sarif", "note": "raw"})

        assert row.status == ScannerStatus.ERROR, row.status.value
        assert _says_why(row), f"errors: {row.errors!r}"


class TestTheDictShapesTheExecutorGrades:
    """Controls: a dict that carries a verdict or counts is graded as before."""

    def test_severity_counts_are_graded(self, plugin_context):
        row = _override_row(
            plugin_context,
            {"severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}},
        )

        assert row.status == ScannerStatus.FAILED
        assert row.finding_count == 1

    def test_a_findings_list_is_graded(self, plugin_context):
        row = _override_row(plugin_context, {"findings": []})

        assert row.status == ScannerStatus.PASSED

    def test_a_failed_status_is_an_error(self, plugin_context):
        row = _override_row(plugin_context, {"status": "failed", "errors": ["boom"]})

        assert row.status == ScannerStatus.ERROR

    def test_valid_sarif_with_no_results_is_passed(self, plugin_context):
        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "shape-tool"}}, "results": []}],
        }
        row = _template_row(plugin_context, json.dumps(sarif))

        assert row.status == ScannerStatus.PASSED


class TestAResultWithNoRunIsAnError:
    """An empty results file, or SARIF with no run, records no scan at all.

    bandit, checkov and semgrep write SARIF with exactly one run even when there is
    nothing for them to scan (measured, clean tree and a tree of a text file), and
    grype's and opengrep's SARIF writers always add one. A file with no run is
    therefore not a clean scan, even with an accepted exit code.
    """

    @pytest.mark.parametrize(
        "content",
        [
            "",
            "null",
            "{}",
            json.dumps({"version": "2.1.0", "runs": []}),
            json.dumps({"$schema": "x"}),
        ],
        ids=["zero-byte", "json-null", "empty-object", "sarif-no-runs", "schema-only"],
    )
    def test_the_row_is_error(self, plugin_context, content):
        row = _template_row(plugin_context, content)

        assert row.status == ScannerStatus.ERROR, (
            f"the tool exited 0 and wrote {content!r}; the row was graded "
            f"{row.status.value} with {row.finding_count} findings"
        )
        assert any("nothing to grade" in str(e) for e in row.errors), row.errors


class PostProcessingFails(TemplateScanner):
    """Valid SARIF, and a defect in the scanner's own post-processing."""

    def _post_process_sarif(self, sarif_report, final_args, target):
        raise RuntimeError("post-processing defect")


def test_a_post_processing_failure_is_not_reported_as_unreadable_sarif(
    plugin_context,
):
    """The message names what failed: the scanner's own code, not the tool's file."""
    config = _Config()
    scanner = PostProcessingFails(config=config, context=plugin_context)
    scanner.results_text = json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "shape-tool"}}, "results": []}],
        }
    )
    with patch.object(
        scanner, "_run_subprocess", return_value={"returncode": 0, "stderr": ""}
    ):
        row = _row(plugin_context, scanner)

    assert row.status == ScannerStatus.ERROR
    errors = " ".join(str(e) for e in row.errors)
    assert "post-processing defect" in errors
    assert "not SARIF" not in errors, errors


class TestAResultOfAnotherTypeIsAnError:
    """A ``scan()`` override can return anything; only some of it can be graded.

    The executor grades a SARIF report, a dict, a CycloneDX report (an SBOM, which
    has no findings) and ``True``. Anything else (a list of findings, a string, a
    number) carries nothing it reads, so graded on its zero findings it would read as
    PASSED. The controls are the two non-dict types it does accept.
    """

    @pytest.mark.parametrize(
        "returned",
        [[{"severity": "high", "message": "a finding"}], "a report", 7, ("x",)],
        ids=["list", "string", "number", "tuple"],
    )
    def test_the_row_is_error(self, plugin_context, returned):
        row = _override_row(plugin_context, returned)

        assert row.status == ScannerStatus.ERROR, (
            f"{type(returned).__name__} was graded {row.status.value} with "
            f"{row.finding_count} findings"
        )
        assert _says_why(row), row.errors

    def test_a_cyclonedx_report_is_graded_as_before(self, plugin_context):
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
            CycloneDXReport,
        )

        row = _override_row(plugin_context, CycloneDXReport())

        assert row.status == ScannerStatus.PASSED, row.errors

    def test_true_is_graded_as_before(self, plugin_context):
        row = _override_row(plugin_context, True)

        assert row.status == ScannerStatus.PASSED, row.errors


#: Answers ``grype db status -o json`` for a database built an hour ago, so the
#: content-database check passes and only the results file decides the row.
GRYPE_STATUS_TOOL = """\
import json, sys
from datetime import datetime, timedelta, timezone
built = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({{"schemaVersion": "v6.0.2", "built": built, "path": {path!r}, "valid": True}}))
sys.exit(0)
"""


class TestGrypeWithNoRunIsAnError:
    """The run check reads what grype wrote, before the scanner adjusts the report.

    grype's SARIF writer always adds a run, so a file with none is not grype's own
    output for a clean scan. The real GrypeScanner runs with its tool replaced: the
    replacement writes the given results file and exits 0, and ``grype`` on PATH
    reports a current database. The control is the same setup with one run.
    """

    @pytest.fixture
    def grype_context(self, tmp_path, monkeypatch):
        from automated_security_helper.utils import subprocess_utils

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        cache = tmp_path / "grype-cache"
        cache.mkdir()
        script = bin_dir / "grype"
        script.write_text(
            f"#!{sys.executable}\n"
            + GRYPE_STATUS_TOOL.format(path=str(cache / "6" / "vulnerability.db")),
            encoding="utf-8",
        )
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        subprocess_utils.clear_find_executable_cache()
        source = tmp_path / "source"
        source.mkdir()
        (source / "package.json").write_text("{}\n")
        output = tmp_path / "output"
        (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
        yield PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="grype-runs"),
        )
        subprocess_utils.clear_find_executable_cache()

    @staticmethod
    def _grype_row(context, monkeypatch, results_text: str):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
        )

        scanner = GrypeScanner(context=context)
        written = {}
        original = scanner._execute_scan

        def capture(*args, **kwargs):
            outcome = original(*args, **kwargs)
            written["results_file"] = Path(outcome[1])
            return outcome

        def tool(*args, **kwargs):
            written["results_file"].parent.mkdir(parents=True, exist_ok=True)
            written["results_file"].write_text(results_text, encoding="utf-8")
            response = {"returncode": 0, "stdout": "", "stderr": ""}
            scanner._process_command_response(response)
            return response

        monkeypatch.setattr(scanner, "_execute_scan", capture)
        monkeypatch.setattr(scanner, "_run_subprocess", tool)
        monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
        return _row(context, scanner)

    @pytest.mark.parametrize(
        "content",
        ["{}", json.dumps({"version": "2.1.0", "runs": []})],
        ids=["empty-object", "sarif-no-runs"],
    )
    def test_the_row_is_error(self, grype_context, monkeypatch, content):
        row = self._grype_row(grype_context, monkeypatch, content)

        assert row.status == ScannerStatus.ERROR, (
            f"grype exited 0 and wrote {content!r}; the row was graded "
            f"{row.status.value} with {row.finding_count} findings"
        )
        assert any("no SARIF run" in str(e) for e in row.errors), row.errors

    def test_one_run_with_no_results_is_passed(self, grype_context, monkeypatch):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "grype", "rules": []}}, "results": []}
            ],
        }

        row = self._grype_row(grype_context, monkeypatch, json.dumps(sarif))

        assert row.status == ScannerStatus.PASSED, row.errors


class TestOnlyACompletedStatusIsGraded:
    """A returned dict's ``status`` says whether its tool completed.

    ``failed`` in any case, ``error``, and any status the executor does not know
    mean the tool did not complete, so the row is ERROR; a dict graded on its zero
    findings would read as clean. ``passed``, ``completed``, ``success`` and ``ok``
    are graded on the findings the dict carries.
    """

    @pytest.mark.parametrize(
        "status", ["error", "FAILED", "Failed", "timeout", "", None, 1]
    )
    def test_any_other_status_is_an_error(self, plugin_context, status):
        row = _override_row(plugin_context, {"status": status, "findings": []})

        assert row.status == ScannerStatus.ERROR, (
            f"status {status!r} was graded {row.status.value} with "
            f"{row.finding_count} findings"
        )
        assert any(f"status {status!r}" in str(e) for e in row.errors), row.errors

    @pytest.mark.parametrize(
        "status", ["passed", "completed", "success", "ok", "PASSED"]
    )
    def test_a_completed_status_is_graded_on_its_findings(self, plugin_context, status):
        clean = _override_row(plugin_context, {"status": status, "findings": []})
        assert clean.status == ScannerStatus.PASSED, clean.errors

    def test_a_completed_status_with_a_finding_is_failed(self, plugin_context):
        row = _override_row(
            plugin_context,
            {"status": "completed", "findings": [{"severity": "high", "id": "x"}]},
        )

        assert (row.status, row.finding_count) == (ScannerStatus.FAILED, 1)


class TestNoResultIsAnErrorThatSaysSo:
    """A ``scan()`` that returns None: the row is ERROR, and its errors say why."""

    def test_the_row_names_the_scanner_and_the_target(self, plugin_context):
        row = _override_row(plugin_context, None)

        assert row.status == ScannerStatus.ERROR
        assert "shape-tool returned no result on source" in row.errors, row.errors
