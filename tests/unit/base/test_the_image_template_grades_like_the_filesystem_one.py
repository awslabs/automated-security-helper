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

The template's head has rows here too: the config a caller hands in is applied
once, ahead of the offline decision; a config that cannot be applied still ends
the target's timing; and the skip of a reference in offline mode is a warning.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import patch

import pydantic
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


@pytest.fixture
def online(monkeypatch):
    """Offline mode off, whatever environment the suite runs in carries."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _config_applications(scanner, run):
    """How many times ``run()`` calls ``_apply_scan_config``.

    The dependency check answers False, so a scan that goes past its skip
    decision stops after its pre-scan, with no tool to run and no results to read.
    """
    real = ScannerPluginBase._apply_scan_config
    with (
        patch.object(type(scanner), "validate_plugin_dependencies", return_value=False),
        patch.object(
            ScannerPluginBase, "_apply_scan_config", autospec=True, side_effect=real
        ) as applied,
    ):
        run()
    return applied.call_count


@pytest.mark.usefixtures("online")
class TestAConfigThatDoesNotValidate:
    """A config the scan cannot apply still ends the target's timing.

    ``scan()`` applies the caller's config inside ``_pre_scan``, so a config that
    fails to validate raises inside the ``try`` whose handler sets the end time.
    ``scan_image`` applied it ahead of its own skip decision, outside that
    ``try``, so the same config left the target with no end time.
    """

    def test_the_image_run_ends_the_target_s_timing(self, tmp_path):
        scanner = _scanner(tmp_path)

        with pytest.raises(pydantic.ValidationError):
            scanner.scan_image(ImageLocator(ref=REF), config={"name": "not-the-tool"})

        assert scanner.end_time is not None

    def test_the_filesystem_control_ends_it_too(self, tmp_path):
        scanner = _scanner(tmp_path)

        with pytest.raises(pydantic.ValidationError):
            scanner.scan(
                Path(scanner.context.source_dir),
                "source",
                [],
                config={"name": "not-the-tool"},
            )

        assert scanner.end_time is not None


@pytest.mark.usefixtures("online")
class TestTheConfigIsAppliedOnce:
    """One image scan swaps its config in once, ahead of the offline decision.

    ``scan_image`` applied the caller's config before deciding whether to skip,
    and ``_pre_scan`` applied the same config again when the scan went on, so a
    scan that reached its tool ran the swap twice, the second time matching only
    because the two dumps compared equal. The swap now runs once for each image
    scan, and ``_pre_scan`` is told the config is already in place.
    """

    @pytest.mark.parametrize(
        "which",
        ["no-config", "the-plugins-own-config", "a-config-that-differs"],
    )
    def test_a_scan_that_goes_on_applies_it_once(self, tmp_path, which):
        scanner = _scanner(tmp_path)
        held = scanner.config
        config = {
            "no-config": None,
            "the-plugins-own-config": held,
            "a-config-that-differs": {
                **held.model_dump(by_alias=True),
                "enabled": not held.enabled,
            },
        }[which]

        applications = _config_applications(
            scanner, lambda: scanner.scan_image(ImageLocator(ref=REF), config=config)
        )

        assert applications == 1

    def test_a_config_that_differs_is_the_one_the_scan_runs_under(self, tmp_path):
        scanner = _scanner(tmp_path)
        held = scanner.config
        changed = {**held.model_dump(by_alias=True), "enabled": not held.enabled}

        with patch.object(
            type(scanner), "validate_plugin_dependencies", return_value=False
        ):
            assert scanner.scan_image(ImageLocator(ref=REF), config=changed) is False

        assert scanner.config is not held
        assert scanner.config.enabled is changed["enabled"]

    def test_a_skipped_reference_applies_it_once_too(self, tmp_path, monkeypatch):
        scanner = _scanner(tmp_path)
        monkeypatch.setenv("ASH_OFFLINE", "true")

        applications = _config_applications(
            scanner,
            lambda: scanner.scan_image(ImageLocator(ref=REF), config=scanner.config),
        )

        assert applications == 1
        assert scanner._nothing_scanned_reason is not None

    def test_the_filesystem_control_applies_it_once(self, tmp_path):
        scanner = _scanner(tmp_path)

        applications = _config_applications(
            scanner,
            lambda: scanner.scan(
                Path(scanner.context.source_dir), "source", [], config=scanner.config
            ),
        )

        assert applications == 1


@pytest.mark.usefixtures("online")
class TestTheSkipReadsTheConfigBeingApplied:
    """The offline decision reads the config being applied.

    ``options.offline`` is read from the plugin's own config, so the swap has to
    land before the decision: deciding against the config being replaced could
    run the tool, and its registry fetches, for a caller whose config said
    offline.
    """

    def test_a_config_that_says_offline_skips_a_plugin_built_online(self, tmp_path):
        scanner = _scanner(tmp_path)
        said_offline = scanner.config.model_dump(by_alias=True)
        said_offline["options"]["offline"] = True

        assert scanner.scan_image(ImageLocator(ref=REF), config=said_offline) is True

        assert scanner._nothing_scanned_reason is not None
        assert "offline" in scanner._nothing_scanned_reason


@pytest.mark.usefixtures("online")
class TestAnOfflineReferenceSkipIsAWarning:
    """The skip of a reference in offline mode is logged as a warning.

    The skip is the only record that an image was never looked at, so its log
    line is a warning, where it was logged at INFO. The reason and the line
    saying the tool was not run are the text it always had.
    """

    @staticmethod
    def _skip_records(caplog):
        return [
            record
            for record in caplog.records
            if "Not running the tool" in record.getMessage()
        ]

    def test_a_reference_is_skipped_with_one_warning(
        self, tmp_path, monkeypatch, caplog
    ):
        scanner = _scanner(tmp_path)
        monkeypatch.setenv("ASH_OFFLINE", "true")

        with caplog.at_level(logging.INFO, logger="ash"):
            assert scanner.scan_image(ImageLocator(ref=REF)) is True

        records = self._skip_records(caplog)
        assert [record.levelno for record in records] == [logging.WARNING]
        assert "was not scanned: offline mode" in records[0].getMessage()

    def test_a_scan_that_goes_on_logs_no_skip(self, tmp_path, caplog):
        scanner = _scanner(tmp_path)

        with (
            patch.object(
                type(scanner), "validate_plugin_dependencies", return_value=False
            ),
            caplog.at_level(logging.INFO, logger="ash"),
        ):
            assert scanner.scan_image(ImageLocator(ref=REF)) is False

        assert self._skip_records(caplog) == []
