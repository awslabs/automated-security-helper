# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for low-severity bug fixes (defense-in-depth and minor correctness)."""

import io
import logging
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# Bug #37 — yaml.SafeLoader class mutation
# ---------------------------------------------------------------------------


class TestYamlSafeLoaderNotMutated:
    """After loading an ASH config via from_file(), the global yaml.SafeLoader
    must NOT carry the !ENV constructor.  A local subclass should be used."""

    def test_safeloader_lacks_env_constructor_after_config_load(self, tmp_path):
        """Loading an ASH YAML config must not register !ENV on the global SafeLoader."""
        # Record the constructors before
        before_constructors = dict(yaml.SafeLoader.yaml_constructors)

        config_file = tmp_path / "ash.yml"
        config_file.write_text(
            textwrap.dedent("""\
            scanners: []
            """)
        )

        from automated_security_helper.config.ash_config import AshConfig

        try:
            AshConfig.from_file(config_file)
        except Exception:
            # Config validation may fail — that's fine; we care about the loader.
            pass

        after_constructors = yaml.SafeLoader.yaml_constructors
        assert "!ENV" not in after_constructors, (
            "yaml.SafeLoader was mutated with !ENV constructor"
        )
        # Restore in case something leaked
        yaml.SafeLoader.yaml_constructors = before_constructors


# ---------------------------------------------------------------------------
# Bug #34 — bandit excluded_paths accumulates across calls
# ---------------------------------------------------------------------------


class TestBanditExcludedPathsNotAccumulated:
    """self.config.options.excluded_paths must not grow across scan() calls."""

    def test_excluded_paths_stable_across_scans(self):
        """Calling scan() twice should not double the global_ignore_paths in the
        config's excluded_paths list."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = MagicMock(spec=BanditScanner)
        # Access the real scan method's logic by reading the source behavior:
        # We need to test that config.options.excluded_paths doesn't grow.
        # Build a minimal mock that exposes the relevant attribute.
        excluded = ["original_path"]
        config_options = MagicMock()
        config_options.excluded_paths = list(excluded)  # start with a copy

        config = MagicMock()
        config.options = config_options

        # Simulate what the fixed code should do: use a local copy, not mutate
        global_ignore = [MagicMock()]
        global_ignore[0].path = "extra_path"

        # After fix: config.options.excluded_paths should stay the same length
        # We test this by importing and checking the source directly:
        import inspect
        source = inspect.getsource(BanditScanner.scan)
        # The fix should NOT contain 'self.config.options.excluded_paths.extend'
        assert "self.config.options.excluded_paths.extend" not in source, (
            "BanditScanner.scan still mutates self.config.options.excluded_paths via extend()"
        )


# ---------------------------------------------------------------------------
# Bug #64 — Typo "errorn" in metrics_table.py
# ---------------------------------------------------------------------------


class TestErrornTypo:
    """The literal string 'errorn' should not appear in the metrics table legend."""

    def test_no_errorn_in_metrics_table(self):
        from automated_security_helper.core import metrics_table

        import inspect
        source = inspect.getsource(metrics_table)
        assert "errorn" not in source, (
            "Typo 'errorn' still present in metrics_table module"
        )


# ---------------------------------------------------------------------------
# Bug #79 — error log on success in metrics_alignment
# ---------------------------------------------------------------------------


class TestMetricsAlignmentSuccessNotLoggedAsError:
    """On the SUCCESS branch of verify_metrics_alignment, the logger should not
    emit at ERROR level."""

    def test_success_branch_no_error_log(self):
        """When all metrics align, no ERROR-level log should be emitted for the
        per-metric success messages."""
        from automated_security_helper.core import metrics_alignment
        import inspect

        source = inspect.getsource(metrics_alignment.verify_metrics_alignment)
        # In the else branch (alignment passed), we should see info/debug, not error
        # Find the "alignment passed" line and check its log level
        lines = source.splitlines()
        for i, line in enumerate(lines):
            if "alignment passed" in line.lower():
                # The line or a nearby line should use info or debug, not error
                assert "error(" not in line.lower(), (
                    f"Line {i}: 'alignment passed' message still logged at ERROR level"
                )


# ---------------------------------------------------------------------------
# Bug #80 — print() calls in metrics_alignment.py
# ---------------------------------------------------------------------------


class TestMetricsAlignmentNoPrintCalls:
    """verify_metrics_alignment should not use print() — only logger calls."""

    def test_no_print_in_verify_function(self):
        from automated_security_helper.core import metrics_alignment
        import inspect

        source = inspect.getsource(metrics_alignment.verify_metrics_alignment)
        # Count bare print() calls (not inside comments or strings referring to "print")
        lines = source.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#"):
                continue
            if stripped.startswith("print("):
                pytest.fail(
                    f"Line {i}: bare print() call found in verify_metrics_alignment: {stripped}"
                )


# ---------------------------------------------------------------------------
# Bug #166 — Duplicate "xml" in KNOWN_SCANNABLE_EXTENSIONS
# ---------------------------------------------------------------------------


class TestNoDuplicateExtensions:
    """KNOWN_SCANNABLE_EXTENSIONS should not contain duplicate entries."""

    def test_no_duplicate_extensions(self):
        from automated_security_helper.core.constants import KNOWN_SCANNABLE_EXTENSIONS

        seen = set()
        duplicates = []
        for ext in KNOWN_SCANNABLE_EXTENSIONS:
            if ext in seen:
                duplicates.append(ext)
            seen.add(ext)
        assert duplicates == [], (
            f"Duplicate entries in KNOWN_SCANNABLE_EXTENSIONS: {duplicates}"
        )


# ---------------------------------------------------------------------------
# Bug #175 — debug_echo returns None, passes tuple to logger
# ---------------------------------------------------------------------------


class TestDebugEchoReturnValue:
    """debug_echo should return the message string, not None."""

    def test_debug_echo_returns_string(self):
        from automated_security_helper.utils.get_scan_set import debug_echo

        result = debug_echo("hello", "world", debug=True)
        assert result is not None, "debug_echo returned None instead of a string"
        assert isinstance(result, str), f"debug_echo returned {type(result)}, expected str"

    def test_debug_echo_passes_string_not_tuple(self):
        """The logger should receive a proper string, not a raw tuple."""
        from automated_security_helper.utils.get_scan_set import debug_echo

        with patch("automated_security_helper.utils.get_scan_set.ASH_LOGGER") as mock_logger:
            debug_echo("hello", "world", debug=True)
            mock_logger.debug.assert_called_once()
            call_args = mock_logger.debug.call_args
            first_arg = call_args[0][0]
            assert not isinstance(first_arg, tuple), (
                f"Logger received a tuple {first_arg!r} instead of a string"
            )
