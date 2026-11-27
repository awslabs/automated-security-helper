# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The base image template's tail is the filesystem template's, measured.

``scan_image`` and ``scan()`` share one grading tail (``_graded_results``).
The hand copy the tail replaced had drifted twice -- a rejected exit code's
failure was described two ways, with the stderr log read against the rejected
contract (scanner_plugin.py's module header), and the empty-results warning
was written on one path only -- and nothing drove ``ScannerPluginBase.
scan_image`` (grype's and trivy's path) through a rejected code, a timeout or
an empty results file. These rows do, with the filesystem rows as controls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar, Literal

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerError,
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

REF = "registry.example.com/team/app:1.2.3"
STDERR_SENTINEL = "the-tools-own-stderr-must-not-be-quoted-for-a-rejected-run"

_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "image-tail-tool", "version": "1"}},
            "results": [],
        }
    ],
}


class _Config(ScannerPluginConfigBase):
    name: Literal["image-tail-tool"] = "image-tail-tool"


class TailScanner(ScannerPluginBase):
    """The base template with a canned subprocess: no tool runs."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: What the next _run_subprocess call answers, set per row.
    canned_response: ClassVar[dict] = {}
    #: What the run leaves in the results file; None leaves it unwritten.
    canned_results: ClassVar[dict | None] = None
    #: The results file's exact text, for the empty-file rows: an EMPTY file
    #: is a different case from an UNWRITTEN one (_read_results_file answers
    #: None for empty, which scan() hands to _handle_empty_results, and MUST
    #: raise for missing -- a tool that died must not read clean). Beats
    #: canned_results when set.
    canned_results_text: ClassVar[str | None] = None

    def model_post_init(self, context):
        self.command = "image-tail-tool"
        self.tool_type = ScannerToolType.SCA
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_image_scan(self, image):
        results_file = Path(self.results_dir) / "image" / "results_sarif.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        return ["image-tail-tool", "scan"], results_file, None

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_file = Path(self.results_dir) / "source" / "results_sarif.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        return ["image-tail-tool", "scan"], results_file, None

    def _handle_empty_results(self) -> SarifReport:
        # A tool whose empty file IS a clean scan: the rows below pin that the
        # shared tail warns first and then finishes the hook's report, on both
        # templates alike (the default hook raises instead; its path is the
        # rejected rows' shape).
        return SarifReport.model_validate(_SARIF)

    def _run_subprocess(self, command, results_dir, cwd=None, env=None, timeout=None):
        results_file = Path(results_dir) / "results_sarif.sarif"
        if type(self).canned_results_text is not None:
            results_file.write_text(type(self).canned_results_text)
        elif type(self).canned_results is not None:
            results_file.write_text(json.dumps(type(self).canned_results))
        # The stderr log a real run leaves beside the results: the rejected
        # contract says it is never read for the message.
        (Path(results_dir) / f"{type(self).__name__}.stderr.log").write_text(
            STDERR_SENTINEL
        )
        return dict(type(self).canned_response)


def _scanner(tmp_path) -> TailScanner:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    (output / "work").mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "work",
        config=AshConfig(project_name="image-tail"),
    )
    scanner = TailScanner(config=_Config(), context=context)
    scanner.results_dir = output / "scanners" / "image-tail-tool"
    # What the setup phase records for a scanner whose dependencies are
    # present; both templates return False before the tool otherwise.
    scanner.dependencies_satisfied = True
    return scanner


def _row(
    tmp_path, *, response: dict, results: dict | None, results_text: str | None = None
):
    TailScanner.canned_response = response
    TailScanner.canned_results = results
    TailScanner.canned_results_text = results_text
    return _scanner(tmp_path)


class TestARejectedExitCode:
    def test_the_image_failure_is_described_once_with_the_stderr_unread(self, tmp_path):
        scanner = _row(tmp_path, response={"returncode": 7}, results=_SARIF)
        with pytest.raises(ScannerError) as raised:
            scanner.scan_image(ImageLocator(ref=REF))
        text = str(raised.value)
        # Once, not twice: the old hand copy passed results_file into
        # _refuse_rejected_exit_code, which described the failure in full,
        # and the handler then described that description again.
        assert text.count("does not accept as a completed run") == 1
        assert text.count("scan failed") == 1
        # The rejected contract: the tool's outputs, its stderr log among
        # them, are not read for the message.
        assert STDERR_SENTINEL not in text

    def test_the_filesystem_control_reads_the_same(self, tmp_path):
        scanner = _row(tmp_path, response={"returncode": 7}, results=_SARIF)
        with pytest.raises(ScannerError) as raised:
            scanner.scan(Path(scanner.context.source_dir), "source", [])
        text = str(raised.value)
        assert text.count("does not accept as a completed run") == 1
        assert STDERR_SENTINEL not in text


class TestATimedOutRun:
    def test_the_image_run_says_timed_out(self, tmp_path):
        scanner = _row(
            tmp_path,
            response={"timed_out": True, "returncode": None},
            results=None,
        )
        with pytest.raises(ScannerError) as raised:
            scanner.scan_image(ImageLocator(ref=REF))
        assert "timed out" in str(raised.value)

    def test_the_filesystem_control_says_the_same(self, tmp_path):
        scanner = _row(
            tmp_path,
            response={"timed_out": True, "returncode": None},
            results=None,
        )
        with pytest.raises(ScannerError) as raised:
            scanner.scan(Path(scanner.context.source_dir), "source", [])
        assert "timed out" in str(raised.value)


class TestAnEmptyResultsFile:
    def test_the_image_run_warns_and_defers_to_the_empty_hook(self, tmp_path, caplog):
        scanner = _row(
            tmp_path, response={"returncode": 0}, results=None, results_text=""
        )
        with caplog.at_level("WARNING", logger="ash"):
            result = scanner.scan_image(ImageLocator(ref=REF))
        # The default empty-results hook answers a clean empty report, which
        # the shared tail finishes exactly as scan() finishes one.
        assert isinstance(result, SarifReport)
        assert result.runs
        assert any(
            "results file is empty" in record.getMessage() for record in caplog.records
        ), "the empty-results warning scan() writes was not written here"

    def test_the_filesystem_control_warns_the_same(self, tmp_path, caplog):
        scanner = _row(
            tmp_path, response={"returncode": 0}, results=None, results_text=""
        )
        with caplog.at_level("WARNING", logger="ash"):
            result = scanner.scan(Path(scanner.context.source_dir), "source", [])
        assert isinstance(result, SarifReport)
        assert any(
            "results file is empty" in record.getMessage() for record in caplog.records
        )
