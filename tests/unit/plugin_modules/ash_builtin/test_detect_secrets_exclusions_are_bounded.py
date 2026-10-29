# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A baseline's ``should_exclude_file`` patterns run in ASH's process under ``scan_timeout``.

The scanner applies the baseline's file filter to the scan set itself, before
the worker starts (``_apply_file_exclusions``), so a regular expression the
scanned repository wrote in its ``.secrets.baseline`` is searched in every file
path by the host process. It ran with no bound: a pattern that backtracks
heavily held the scan for as long as it liked, while the worker's own time
limit never started. The filter now runs in a thread bounded by the scanner's
``scan_timeout``, and a filter still running at the deadline fails the scan
with a ScannerError that names the filter; the thread itself cannot be stopped
and is left running until the process exits.

The slow pattern is polynomial, not exponential: ``a*a*a*b`` searched in a run
of 300 ``a`` characters backtracks for a few tenths of a second (measured 0.4 s)
and then finishes, so the thread a test leaves behind ends on its own.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

SLOW_PATTERN = "a*a*a*b"
#: A file name that is a run of 300 ``a``: the pattern's three stars backtrack
#: over it for a few tenths of a second before the search fails.
SLOW_NAME = "a" * 300
TINY_TIMEOUT = 0.02


def test_a_slow_pattern_fails_the_filter_at_the_bound(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / SLOW_NAME), str(root / "src" / "app.py")]
    started = time.monotonic()

    with pytest.raises(ScannerError) as raised:
        DetectSecretsScanner._apply_file_exclusions(
            files, [re.compile(SLOW_PATTERN)], root, timeout=TINY_TIMEOUT
        )

    assert time.monotonic() - started < 2.0
    assert "should_exclude_file" in str(raised.value)
    assert "scan_timeout" in str(raised.value)
    assert SLOW_PATTERN not in str(raised.value)


def test_a_fast_pattern_filters_under_the_bound(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / "src" / "app.py"), str(root / "tests" / "test_app.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"^tests/")], root, timeout=TINY_TIMEOUT
    )

    assert kept == [str(root / "src" / "app.py")]


def test_without_a_bound_the_filter_runs_as_before(tmp_path):
    """``timeout=None`` is the scanner left unbounded (``scan_timeout: null``)."""
    root = tmp_path / "repo"
    files = [str(root / "src" / "app.py"), str(root / "tests" / "test_app.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"^tests/")], root, timeout=None
    )

    assert kept == [str(root / "src" / "app.py")]


def test_the_error_names_the_baseline_the_filter_came_from(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / SLOW_NAME)]

    with pytest.raises(ScannerError) as raised:
        DetectSecretsScanner._apply_file_exclusions(
            files,
            [re.compile(SLOW_PATTERN)],
            root,
            timeout=TINY_TIMEOUT,
            source="the baseline repo/.secrets.baseline",
        )

    assert "repo/.secrets.baseline" in str(raised.value)


# ---------------------------------------------------------------------------
# The scan hands the filter its own time limit
# ---------------------------------------------------------------------------


def _context(tmp_path: Path) -> PluginContext:
    source = tmp_path / "src"
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    source.mkdir(parents=True, exist_ok=True)
    context.output_dir.mkdir(parents=True, exist_ok=True)
    return context


def _write(root: Path, name: str, text: str = "value = 1\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_the_scan_bounds_the_filter_by_its_scan_timeout(tmp_path, monkeypatch):
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    _write(source, "tests/fixture.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^tests/"]
        )
    ]
    scanner.config.options.scan_timeout = 7
    seen: dict = {}
    unbounded = DetectSecretsScanner._apply_file_exclusions

    def recording(files, exclude_patterns, root=None, **kwargs):
        seen.update(kwargs)
        return unbounded(files, exclude_patterns, root)

    monkeypatch.setattr(
        DetectSecretsScanner, "_apply_file_exclusions", staticmethod(recording)
    )
    monkeypatch.setattr(type(scanner), "_scan_in_worker", lambda self, **kwargs: None)

    scanner.scan(target=source, target_type="source")

    assert seen.get("timeout") == 7
    assert "should_exclude_file" in seen.get("source", "")
