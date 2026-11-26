# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An image asset routes scanners by the register and reports what did not look.

The C3 rows of the container-targets design, driven through the real
``_execute_phase`` filter loop:

- a CONTAINER_IMAGE asset offered to a scanner that does not declare
  ``TargetKind.CONTAINER_IMAGE`` produces a SKIPPED status row naming the
  declaration, before the scanner's platform, dependency or tool checks run,
  and queues nothing for it;
- a scan on which nothing scanned the image gets ONE informational SARIF
  result (kind=informational, level=none) on the model's own ASH run, so the
  report is green by contract and visibly incomplete rather than silently
  clean;
- the control: a scan with no asset (every caller that predates assets)
  produces no such row and no such result, byte for byte today's behavior.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


IMAGE_REF = "registry.example.com/team/app:1.2.3"


@pytest.fixture
def plugin_context(tmp_path):
    """Minimal context stub, as the scan-phase suites build one."""
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    # The subject under test: None is the control, an Asset the image rows.
    ctx.asset = None
    return ctx


def _scanner(name="bandit"):
    """A filesystem-shaped scanner double: no operational-facets row at all."""
    plugin_cls = MagicMock()
    plugin_cls.__name__ = name
    plugin_instance = MagicMock()
    plugin_instance.__class__ = plugin_cls
    config = MagicMock()
    config.name = name
    config.enabled = True
    config.options.severity_threshold = "HIGH"
    plugin_instance.config = config
    plugin_instance.validate_plugin_dependencies.return_value = True
    plugin_instance.dependencies_satisfied = True
    plugin_instance.is_python_only.return_value = True
    plugin_instance.errors = []
    plugin_instance.output = []
    plugin_instance.exit_code = 0
    plugin_instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    plugin_instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    plugin_instance.context = None
    plugin_cls.return_value = plugin_instance
    return plugin_cls, plugin_instance


@pytest.fixture
def scan_phase(plugin_context):
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        mock_val_mgr = MagicMock(spec=ScannerValidationManager)
        mock_val_mgr.validate_registered_scanners.return_value = None
        mock_val_mgr.validate_scanner_enablement.return_value = None
        checkpoint = MagicMock()
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.has_issues.return_value = False
        checkpoint.checkpoint_name = "test"
        checkpoint.timestamp = datetime(2024, 1, 1)
        checkpoint.expected_scanners = []
        checkpoint.actual_scanners = []
        checkpoint.discrepancies = []
        checkpoint.errors = []
        checkpoint.metadata = {}
        mock_val_mgr.validate_task_queue.return_value = checkpoint
        mock_val_mgr.validate_execution_completion.return_value = checkpoint
        mock_val_mgr.ensure_complete_results.return_value = checkpoint
        mock_val_mgr.report_execution_discrepancies.return_value = {}
        mock_val_mgr.report_result_completeness.return_value = {}
        MockValMgr.return_value = mock_val_mgr

        progress = MagicMock()
        progress.add_task.return_value = 1
        phase = ScanPhase(
            plugin_context=plugin_context,
            plugins=[],
            progress_display=progress,
        )
        phase.validation_manager = mock_val_mgr
        yield phase


def _informational_results(model: AshAggregatedResults):
    results = []
    for run in (model.sarif.runs if model.sarif else []) or []:
        for result in run.results or []:
            if (
                result.ruleId == ScanPhase.IMAGE_NOT_SCANNED_RULE_ID
                or getattr(result.kind, "value", result.kind) == "informational"
            ):
                results.append(result)
    return results


class TestAnImageAssetSkipsUnservingScanners:
    def test_the_row_is_skipped_with_the_declaration_named(self, scan_phase):
        scanner_cls, scanner = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        row = result.scanner_results["bandit"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is False
        assert row.dependencies_satisfied is True
        assert "container_image" in (row.skipped_reason or "")
        assert "operational facets" in (row.skipped_reason or "")

    def test_the_skip_is_decided_before_any_diagnosis(self, scan_phase):
        scanner_cls, scanner = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        # Selection-before-diagnosis: the tool was never needed, so neither
        # dependency probe ran and nothing was queued.
        scanner.validate_plugin_dependencies.assert_not_called()
        scanner.validate_plugin_dependencies_once.assert_not_called()
        assert scan_phase._scanner_tasks == []

    def test_one_informational_result_lands_on_the_ash_run(self, scan_phase):
        scanner_cls, _ = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        notes = _informational_results(result)
        assert len(notes) == 1
        note = notes[0]
        assert note.ruleId == ScanPhase.IMAGE_NOT_SCANNED_RULE_ID
        assert getattr(note.kind, "value", note.kind) == "informational"
        # SARIF 3.27.10: with any kind but "fail", a present level SHALL be
        # "none"; a note-level result shows as an alert in level-graded viewers.
        assert getattr(note.level, "value", note.level) == "none"
        text = note.message.root.text
        assert IMAGE_REF in text
        assert "was not scanned" in text

    def test_two_unserving_scanners_still_yield_one_note(self, scan_phase):
        scanner_a, _ = _scanner("bandit")
        scanner_b, _ = _scanner("semgrep")
        scan_phase.plugins = [scanner_a, scanner_b]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        assert result.scanner_results["bandit"].status == ScannerStatus.SKIPPED
        assert result.scanner_results["semgrep"].status == ScannerStatus.SKIPPED
        assert len(_informational_results(result)) == 1


def _reached(scanner) -> bool:
    """Whether the scan phase asked the scanner anything: it got past routing."""
    return bool(
        scanner.validate_plugin_dependencies.called
        or scanner.validate_plugin_dependencies_once.called
    )


class TestTheFilesystemControl:
    def test_no_asset_adds_no_row_and_no_note(self, scan_phase):
        scanner_cls, scanner = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = None

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        assert _reached(scanner)
        row = result.scanner_results.get("bandit")
        # Whatever the mock executor recorded, it is not the asset-kind skip.
        if row is not None and row.skipped_reason:
            assert "container_image" not in row.skipped_reason
        assert _informational_results(result) == []

    def test_a_filesystem_asset_adds_no_row_and_no_note(self, scan_phase):
        scanner_cls, scanner = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_filesystem(
            scan_phase.plugin_context.source_dir
        )

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
        )

        assert _reached(scanner)
        row = result.scanner_results.get("bandit")
        if row is not None and row.skipped_reason:
            assert "container_image" not in row.skipped_reason
        assert _informational_results(result) == []

    def test_the_source_tree_is_still_walked(self, scan_phase):
        scanner_cls, _ = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        walked = scan_phase.plugin_context.cached_source_files
        assert any(str(path).endswith("app.py") for path in walked)


def _serving(monkeypatch):
    """Make the scan phase read every scanner as one that serves images."""
    monkeypatch.setattr(
        "automated_security_helper.core.phases.scan_phase.serves_asset_kind",
        lambda *_args, **_kwargs: True,
    )


class TestAnImageScanReadsOnlyTheImage:
    def test_the_anchoring_directory_is_not_walked(self, scan_phase):
        scanner_cls, _ = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert scan_phase.plugin_context.cached_source_files == []


class TestAConstructorFailureIsRoutedLikeAnyOtherRow:
    def _failing(self, name="bandit"):
        scanner_cls, scanner = _scanner(name)
        scanner_cls.side_effect = RuntimeError("constructor broke")
        return scanner_cls

    def test_a_filesystem_only_scanner_that_cannot_be_built_is_an_error_with_the_reason(
        self, scan_phase
    ):
        # The same row, and the same gate visibility, as on a filesystem scan
        # and as a module that fails to import (below): a scanner ASH could not
        # bring up is a loss on any scan kind. The text says it would not have
        # read the image, so nobody goes looking for lost image coverage.
        from automated_security_helper.utils.scan_completeness import (
            incomplete_scanners,
        )

        scan_phase.plugins = [self._failing()]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        row = result.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert ("bandit", "ERROR") in incomplete_scanners(result)

    def test_the_reason_names_the_constructor_error_and_that_no_image_coverage_was_lost(
        self, scan_phase
    ):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        class _Lines(logging.Handler):
            def __init__(self):
                super().__init__(level=1)
                self.lines = []

            def emit(self, record):
                self.lines.append(record.getMessage())

        handler = _Lines()
        ASH_LOGGER.addHandler(handler)
        try:
            scan_phase.plugins = [self._failing()]
            scan_phase.plugin_context.asset = Asset.for_image(
                ImageLocator(ref=IMAGE_REF)
            )
            scan_phase._execute_phase(
                aggregated_results=AshAggregatedResults(), parallel=False
            )
        finally:
            ASH_LOGGER.removeHandler(handler)
        text = "\n".join(handler.lines)
        assert "could not be constructed" in text
        assert "constructor broke" in text
        assert "does not scan container images" in text

    def test_a_scanner_the_operator_excluded_is_still_skipped_when_it_cannot_be_built(
        self, scan_phase
    ):
        # Selection comes before diagnosis, on an image scan as on any other.
        scan_phase.plugins = [self._failing()]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
            excluded_scanners=["bandit"],
        )

        assert result.scanner_results["bandit"].status == ScannerStatus.SKIPPED

    def test_a_module_that_fails_to_import_is_an_error_row_on_an_image_scan_too(
        self, scan_phase
    ):
        from automated_security_helper.plugins.loader import PluginLoadFailure
        from automated_security_helper.utils.scan_completeness import (
            incomplete_scanners,
        )

        failed = "automated_security_helper.plugin_modules.ash_x_plugins.scanners"
        scan_phase.plugin_context.plugin_load_record = {
            failed: PluginLoadFailure(recorded="ImportError: no module named 'x'")
        }
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert result.scanner_results[failed].status == ScannerStatus.ERROR
        assert (failed, "ERROR") in incomplete_scanners(result)

    def test_an_image_capable_scanner_that_cannot_be_built_is_an_error(
        self, scan_phase, monkeypatch
    ):
        _serving(monkeypatch)
        scan_phase.plugins = [self._failing()]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert result.scanner_results["bandit"].status == ScannerStatus.ERROR

    def test_the_control_a_filesystem_scan_still_records_the_error(self, scan_phase):
        scan_phase.plugins = [self._failing()]
        scan_phase.plugin_context.asset = None

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert result.scanner_results["bandit"].status == ScannerStatus.ERROR


class TestTheNotScannedNoteStaysTrue:
    def test_the_note_never_points_at_rows_of_a_report(self, scan_phase):
        scanner_cls, _ = _scanner("bandit")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        (note,) = _informational_results(result)
        text = note.message.root.text
        assert "rows above" not in text
        assert "SKIPPED for the same reason" not in text
        assert "no scanner that was selected and able to run" in text

    def test_no_note_when_an_image_capable_scanner_is_queued(
        self, scan_phase, monkeypatch
    ):
        _serving(monkeypatch)
        scanner_cls, scanner = _scanner("trivy")
        scan_phase.plugins = [scanner_cls]
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        result = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert _reached(scanner)
        row = result.scanner_results.get("trivy")
        assert row is None or row.status != ScannerStatus.SKIPPED
        assert _informational_results(result) == []


class TestTheNoRunWarningIsWrittenOnce:
    def test_a_model_with_no_sarif_run_logs_one_warning(self, scan_phase, caplog):
        # With no run to carry the note, the log line is the whole record and
        # the per-scan ruleId dedup cannot run: the method is called before
        # the executor AND after it, and without its own dedup the second call
        # logged the warning again.
        import logging

        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))
        scan_phase._scanner_tasks = []
        model = AshAggregatedResults()
        model.sarif = None
        with caplog.at_level(logging.WARNING, logger="ash"):
            scan_phase._record_unscanned_image_asset(model)
            scan_phase._record_unscanned_image_asset(model)
        lines = [
            record.getMessage()
            for record in caplog.records
            if "was not scanned" in record.getMessage()
        ]
        assert len(lines) == 1


class TestATagIsResolvedOnceBeforeAnyScannerRuns:
    """The scan phase asks the resolver once, and the scan carries its answer."""

    DIGEST = "sha256:" + "ab" * 32

    def _patched(self, monkeypatch, answer, consumers_selected=True):
        calls = []

        def resolver(image, *, offline, **_):
            calls.append((image, offline))
            return answer(image)

        monkeypatch.setattr(
            "automated_security_helper.utils.image_digest_resolver.resolve_image_locator",
            resolver,
        )
        if consumers_selected:
            # These rows measure the resolution, not the consumer gate: the
            # gate reads LOADED scanner classes, which depend on what the
            # test process imported before this file. The gate's own rows
            # (below) pin the class source instead and leave this unforced.
            monkeypatch.setattr(
                "automated_security_helper.utils.scanner_tool_types."
                "an_image_digest_consumer_is_selected",
                lambda *args, **kwargs: True,
            )
        return calls

    def _gate_reads_exactly(self, monkeypatch, *classes):
        # The real gate over an EXPLICIT class set: the walk otherwise reads
        # every loaded ScannerPluginBase subclass, so another declarer
        # imported by an earlier test in this worker would open the gate and
        # flip the never-asks rows on test order alone.
        monkeypatch.setattr(
            "automated_security_helper.utils.scanner_tool_types."
            "_loaded_scanner_classes",
            lambda: iter(classes),
        )

    def test_the_resolved_digest_is_on_the_asset_the_scanners_are_given(
        self, scan_phase, monkeypatch
    ):
        calls = self._patched(
            monkeypatch,
            lambda image: image.model_copy(update={"resolved_digest": self.DIGEST}),
        )
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert len(calls) == 1
        assert calls[0][0].ref == IMAGE_REF
        image = scan_phase.plugin_context.asset.image
        assert (image.ref, image.resolved_digest) == (IMAGE_REF, self.DIGEST)

    def test_the_recorded_scan_source_then_names_the_digest_not_the_tag(
        self, scan_phase, monkeypatch
    ):
        self._patched(
            monkeypatch,
            lambda image: image.model_copy(update={"resolved_digest": self.DIGEST}),
        )
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))
        results = AshAggregatedResults()
        results.metadata.scan_source = f"image:{IMAGE_REF}"

        scan_phase._execute_phase(aggregated_results=results, parallel=False)

        assert results.metadata.scan_source == f"image:{self.DIGEST}"

    def test_a_scan_source_that_is_not_an_image_is_left_alone(
        self, scan_phase, monkeypatch
    ):
        self._patched(
            monkeypatch,
            lambda image: image.model_copy(update={"resolved_digest": self.DIGEST}),
        )
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))
        results = AshAggregatedResults()
        results.metadata.scan_source = "some/dir"

        scan_phase._execute_phase(aggregated_results=results, parallel=False)

        assert results.metadata.scan_source == "some/dir"

    def test_an_unresolved_locator_leaves_the_asset_as_submitted(
        self, scan_phase, monkeypatch
    ):
        self._patched(monkeypatch, lambda image: image)
        asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))
        scan_phase.plugin_context.asset = asset

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert scan_phase.plugin_context.asset is asset

    @pytest.mark.parametrize("subject", ["none", "filesystem"])
    def test_a_filesystem_scan_never_asks(self, scan_phase, monkeypatch, subject):
        calls = self._patched(monkeypatch, lambda image: image)
        scan_phase.plugin_context.asset = (
            None
            if subject == "none"
            else Asset.for_filesystem(scan_phase.plugin_context.source_dir)
        )

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert calls == []

    def test_a_scan_with_every_digest_consumer_excluded_never_asks(
        self, scan_phase, monkeypatch
    ):
        # The ladder keys FINDING ids, and only a scanner declaring
        # Fetched.IMAGE_DIGEST produces ids the digest keys: with all of them
        # excluded, no engine is asked and no registry request is made, as
        # their operational-facets declarations promise the operator. The
        # real consumer classes are imported, so the exclusion, not an
        # unloaded class, is what the gate reads.
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (  # noqa: F401
            GrypeScanner,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (  # noqa: F401
            TrivyScanner,
        )

        self._gate_reads_exactly(monkeypatch, GrypeScanner, TrivyScanner)
        calls = self._patched(monkeypatch, lambda image: image, consumers_selected=None)
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
            excluded_scanners=["grype", "trivy"],
        )

        assert calls == []

    def test_python_based_plugins_only_never_asks(self, scan_phase, monkeypatch):
        # The declaring scanners are pinned binaries, which this run excludes.
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (  # noqa: F401
            GrypeScanner,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (  # noqa: F401
            TrivyScanner,
        )

        self._gate_reads_exactly(monkeypatch, GrypeScanner, TrivyScanner)
        calls = self._patched(monkeypatch, lambda image: image, consumers_selected=None)
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
            python_based_plugins_only=True,
        )

        assert calls == []

    def test_a_selected_consumer_opens_the_gate_for_real(self, scan_phase, monkeypatch):
        # The positive control for the two rows above, through the REAL gate:
        # with the consumers loaded and nothing deselecting them, the
        # resolution runs.
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (  # noqa: F401
            GrypeScanner,
        )

        self._gate_reads_exactly(monkeypatch, GrypeScanner)
        calls = self._patched(monkeypatch, lambda image: image, consumers_selected=None)
        scan_phase.plugin_context.asset = Asset.for_image(ImageLocator(ref=IMAGE_REF))

        scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        assert len(calls) == 1
