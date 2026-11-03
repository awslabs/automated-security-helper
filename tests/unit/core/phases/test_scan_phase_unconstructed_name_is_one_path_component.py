# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unconstructed scanner is never recorded under a name that is a path.

A scanner whose constructor raised is recorded under its section's ``name``,
read raw from the configuration: that section was never validated by the
scanner's config model, because the scanner never constructed. The row's name
becomes a directory under ``scanners/`` when its results container is written,
so a name holding a separator or ``..`` put ``ASH.ScanResults.json`` outside the
output directory. Such a name now falls back to the class's key.

The fixtures mirror ``tests/unit/core/phases/test_phases_scan_phase.py``.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import (
    ScanPhase,
    _unconstructed_scanner_name,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
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
    ctx.plugin_load_record = {}
    return ctx


@pytest.fixture
def mock_progress_display():
    display = MagicMock()
    display.add_task.return_value = 1
    return display


@pytest.fixture
def scan_phase(mock_plugin_context, mock_progress_display):
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

        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=mock_progress_display,
        )
        phase.validation_manager = mock_val_mgr
        return phase


class _Boom:
    """A scanner class whose constructor raises; the class key is derived from it."""

    def __init__(self, *args, **kwargs):
        raise RuntimeError("constructor failed")


class TestTheNameOfAnUnconstructedScanner:
    @pytest.mark.parametrize(
        "name",
        ["../escaped", "sub/dir", "back\\slash", "..", ".", "nul\x00name", "C:x"],
    )
    def test_a_name_that_is_a_path_falls_back_to_the_class_key(self, name):
        # Red at the base: any non-empty string was returned as it was.
        assert _unconstructed_scanner_name({"name": name}, _Boom) == plugin_config_key(
            _Boom
        )

    @pytest.mark.parametrize("name", ["bandit", "snyk-code", "my.scanner", "x_y"])
    def test_a_plain_name_is_used_as_before(self, name):
        """The control: a name that is one entry of one directory is the record's."""
        assert _unconstructed_scanner_name({"name": name}, _Boom) == name

    def test_a_path_shaped_declared_key_falls_back_to_the_class_name(self, monkeypatch):
        """Even the class's own declared key is held to one path component."""
        import automated_security_helper.core.phases.scan_phase as scan_phase_module

        monkeypatch.setattr(
            scan_phase_module, "plugin_config_key", lambda cls: "../declared"
        )

        # Red at the previous tip: the declared key was returned unchecked.
        assert _unconstructed_scanner_name({"name": "../escaped"}, _Boom) == "_boom"


class TestTheRowOfAnUnconstructedScannerIsUnderAPlainKey:
    def test_the_row_is_keyed_by_the_class_not_the_path(
        self, scan_phase, mock_plugin_context, tmp_path
    ):
        mock_plugin_context.config.get_plugin_config.return_value = {
            "name": "../escaped",
            "enabled": True,
        }
        scan_phase.plugins = [_Boom]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        # Red at the base: the row sat under "../escaped".
        assert "../escaped" not in results.scanner_results
        assert all("/" not in key for key in results.scanner_results)
        row = results.scanner_results[plugin_config_key(_Boom)]
        assert row.status == ScannerStatus.ERROR
        # Nothing was created through the name, wherever "scanners/../escaped"
        # would have landed: the output directory is under tmp_path, so the one
        # place the name could resolve to is inside it, and the walk covers both.
        assert [path for path in tmp_path.rglob("*") if path.name == "escaped"] == []
        assert not (mock_plugin_context.output_dir / "escaped").exists()
