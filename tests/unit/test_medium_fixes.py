"""Tests for medium-priority bug fixes M1, M3, M6, M7."""

import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# M1: scan_registry.py cancel_scan — warn when process_id is None
# ---------------------------------------------------------------------------

class TestCancelScanWarnsOnNoneProcessId:
    """cancel_scan should log a warning when process_id is None (thread scans)."""

    def _make_registry_with_running_scan(self):
        from automated_security_helper.core.resource_management.scan_registry import (
            ScanRegistry,
            ScanStatus,
        )

        registry = ScanRegistry()
        # Bypass validation by inserting directly
        from automated_security_helper.core.resource_management.scan_registry import (
            ScanRegistryEntry,
        )

        entry = ScanRegistryEntry(
            scan_id="test-scan-1",
            directory_path="/tmp/fakedir",
            output_directory="/tmp/fakeout",
        )
        entry.status = ScanStatus.RUNNING
        entry.process_id = None  # thread-based scan, no pid
        registry._registry["test-scan-1"] = entry
        return registry

    def test_cancel_scan_logs_warning_when_process_id_is_none(self):
        registry = self._make_registry_with_running_scan()

        with patch.object(registry._logger, "warning") as mock_warn:
            result = registry.cancel_scan("test-scan-1")

        assert result is True
        # Must have logged a warning about the missing process_id
        mock_warn.assert_called_once()
        msg = mock_warn.call_args[0][0]
        assert "process" in msg.lower() or "thread" in msg.lower()

    def test_cancel_scan_still_marks_cancelled_when_no_pid(self):
        from automated_security_helper.core.resource_management.scan_registry import (
            ScanStatus,
        )

        registry = self._make_registry_with_running_scan()
        registry.cancel_scan("test-scan-1")
        entry = registry.get_scan("test-scan-1")
        assert entry.status == ScanStatus.CANCELLED


# ---------------------------------------------------------------------------
# M3: engine_phase.py — use AshEventType enum instead of string construction
# ---------------------------------------------------------------------------

class TestEnginePhaseUsesAshEventType:
    """notify_event calls in execute() should pass AshEventType enum members."""

    def test_execute_notifies_with_enum_not_string(self):
        from automated_security_helper.plugins.events import AshEventType
        from automated_security_helper.base.engine_phase import EnginePhase
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.base.plugin_context import PluginContext

        # Create a concrete subclass
        class FakePhase(EnginePhase):
            @property
            def phase_name(self) -> str:
                return "scan"

            def _execute_phase(self, aggregated_results, **kwargs):
                return aggregated_results

        ctx = MagicMock(spec=PluginContext)
        phase = FakePhase(plugin_context=ctx)

        captured_events = []
        original_notify = phase.notify_event

        def spy_notify(event_type, **kwargs):
            captured_events.append(event_type)
            # Don't actually dispatch to plugins
            return []

        phase.notify_event = spy_notify

        agg = AshAggregatedResults()
        phase.execute(aggregated_results=agg)

        # The start and complete events should be AshEventType members, not strings
        assert len(captured_events) >= 2
        for evt in captured_events:
            assert isinstance(evt, AshEventType), (
                f"Expected AshEventType enum, got {type(evt).__name__}: {evt!r}"
            )


# ---------------------------------------------------------------------------
# M6: subprocess_utils.py — return None must be outside the for loop
# ---------------------------------------------------------------------------

class TestFindExecutableChecksAllVariants:
    """find_executable should try all command variants before returning None."""

    def test_returns_none_only_after_exhausting_all_variants(self):
        from automated_security_helper.utils.subprocess_utils import find_executable

        # Use a command that doesn't exist anywhere
        result = find_executable("__nonexistent_binary_xyz__")
        assert result is None

    @patch("automated_security_helper.utils.subprocess_utils.shutil.which")
    def test_finds_second_variant(self, mock_which):
        """On non-Windows, both variants resolve to the same command, so we
        just verify the function actually exhausts the loop rather than
        returning None after the first iteration."""
        from automated_security_helper.utils.subprocess_utils import find_executable

        # which returns None on first call, path on second
        mock_which.side_effect = [None, "/usr/bin/somecmd"]

        with patch(
            "automated_security_helper.utils.subprocess_utils.platform.system",
            return_value="Windows",
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.ASH_BIN_PATH",
                Path("/fake"),
            ):
                result = find_executable("somecmd")

        # Before the fix, return None was inside the loop so the second
        # variant would never be tried. After the fix, we should get a result
        # or at least not bail after the first cmd.
        # The key assertion: which was called at least twice (both variants)
        assert mock_which.call_count >= 2


# ---------------------------------------------------------------------------
# M7: get_scan_set.py — glob calls need recursive=True
# ---------------------------------------------------------------------------

class TestGetScanSetGlobRecursive:
    """glob calls with ** patterns must pass recursive=True."""

    def test_nested_gitignore_found_recursively(self):
        from automated_security_helper.utils.get_scan_set import (
            get_ash_ignorespec_lines,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a nested .gitignore two levels deep
            nested = Path(tmpdir) / "sub" / "deep"
            nested.mkdir(parents=True)
            gitignore = nested / ".gitignore"
            gitignore.write_text("*.log\n")

            lines = get_ash_ignorespec_lines(tmpdir)

            # The path is replaced with ${SOURCE_DIR} in the header lines
            relative_suffix = "sub/deep/.gitignore"
            found = any(relative_suffix in line for line in lines)
            assert found, (
                f"Nested .gitignore at {gitignore} not found in lines; "
                f"glob likely missing recursive=True. Lines: {lines}"
            )

    def test_nested_dotignore_found_recursively(self):
        from automated_security_helper.utils.get_scan_set import (
            get_ash_ignorespec_lines,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "a" / "b"
            nested.mkdir(parents=True)
            dotignore = nested / ".ignore"
            dotignore.write_text("*.tmp\n")

            lines = get_ash_ignorespec_lines(tmpdir)

            relative_suffix = "a/b/.ignore"
            found = any(relative_suffix in line for line in lines)
            assert found, (
                f"Nested .ignore at {dotignore} not found in lines; "
                f"glob likely missing recursive=True. Lines: {lines}"
            )
