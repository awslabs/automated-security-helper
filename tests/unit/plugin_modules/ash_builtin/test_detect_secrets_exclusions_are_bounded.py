# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A baseline's ``should_exclude_file`` patterns run under ``scan_timeout``, in a child process.

The scanner applies the baseline's file filter to the scan set itself, before
the worker starts (``_apply_file_exclusions``), so a regular expression the
scanned repository wrote in its ``.secrets.baseline`` is searched in every file
path by the host process. It ran with no bound: a pattern that backtracks
heavily held the scan for as long as it liked, while the worker's own time
limit never started. The filter now runs in a child process bounded by the
scanner's ``scan_timeout``; a filter still running at the deadline is killed
and fails the scan with a ScannerError that names the filter.

Why a process and not a thread: Python's matcher holds the interpreter lock for
the whole of a search, so a thread joined with a timeout learned of the overrun
only when the search finished on its own. The overrunning filter here is a real
pattern, ``(a+)+$`` over a file named by 64 ``a`` characters and a ``b``, which
finishes on no machine. Under the thread the call never returned, so each test
that runs it runs it inside a child of its own (``_outcome_of``) and reads back
what the call did, within a limit of its own.
"""

from __future__ import annotations

import json
import multiprocessing
import re
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

NEVER_ENDING_PATTERN = r"(a+)+$"
NEVER_ENDING_NAME = "a" * 64 + "b"
TINY_TIMEOUT = 0.5
FAST_TIMEOUT = 5.0
GUARD_LIMIT = 20.0


def _reported(connection: Any, function: Callable[..., Any], args: tuple) -> None:
    """In the guard's child: run the call and send back one line saying what it did."""
    try:
        function(*args)
        connection.send("returned")
    except ScannerError as error:
        connection.send(f"ScannerError: {error}")
    except Exception as error:  # the test reads the type
        connection.send(type(error).__name__)
    finally:
        connection.close()


def _outcome_of(
    function: Callable[..., Any], *args: Any, limit: float = GUARD_LIMIT
) -> str:
    """What ``function(*args)`` did, read from a child of the test's own.

    A bound that does not hold (the thread of the first cut) leaves a hanging
    child the test kills after ``limit`` seconds, not a hanging test. Where
    there is no ``fork`` the call is made inline.
    """
    if "fork" not in multiprocessing.get_all_start_methods():
        try:
            function(*args)
            return "returned"
        except ScannerError as error:
            return f"ScannerError: {error}"
    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    child = context.Process(target=_reported, args=(sending, function, args))
    child.start()
    sending.close()
    try:
        if receiving.poll(limit):
            return receiving.recv()
        return f"no answer within {limit} s"
    finally:
        receiving.close()
        if child.is_alive():
            child.kill()
        child.join()


def test_a_slow_pattern_fails_the_filter_at_the_bound(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / NEVER_ENDING_NAME), str(root / "src" / "app.py")]
    started = time.monotonic()

    outcome = _outcome_of(
        DetectSecretsScanner._apply_file_exclusions,
        files,
        [re.compile(NEVER_ENDING_PATTERN)],
        root,
        TINY_TIMEOUT,
    )

    assert outcome.startswith("ScannerError: ")
    assert "should_exclude_file" in outcome
    assert "scan_timeout" in outcome
    assert time.monotonic() - started < GUARD_LIMIT / 2


def test_a_fast_pattern_filters_under_the_bound(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / "src" / "app.py"), str(root / "tests" / "test_app.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"^tests/")], root, timeout=FAST_TIMEOUT
    )

    assert kept == [str(root / "src" / "app.py")]


def test_a_pattern_keeps_its_flags_across_the_bound(tmp_path):
    root = tmp_path / "repo"
    files = [str(root / "src" / "app.py"), str(root / "TESTS" / "test_app.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"^tests/", re.IGNORECASE)], root, timeout=FAST_TIMEOUT
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
    files = [str(root / NEVER_ENDING_NAME)]

    outcome = _outcome_of(
        DetectSecretsScanner._apply_file_exclusions,
        files,
        [re.compile(NEVER_ENDING_PATTERN)],
        root,
        TINY_TIMEOUT,
        "the baseline repo/.secrets.baseline",
    )

    assert outcome.startswith("ScannerError: ")
    assert "repo/.secrets.baseline" in outcome


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


# ---------------------------------------------------------------------------
# The name the filter gives its baseline is redacted like the scan's other lines
# ---------------------------------------------------------------------------


def _sources_the_scan_gives_the_filter(
    tmp_path: Path, monkeypatch, values: tuple[str, ...]
) -> tuple[list[str], str]:
    """Every ``source`` text a scan hands the baseline's file filter, and the
    baseline's path.

    The baseline is the operator's own file outside the scanned tree, named
    through ``baseline_file``, and its ``should_exclude_file`` filter is the one
    the scan applies. ``values`` stands for what the config read from the
    environment (``_environment_values``): the scan redacts its lines with them.
    """
    from detect_secrets.core.potential_secret import PotentialSecret

    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    _write(source, "tests/fixture.py")
    baseline = tmp_path / "operator-baseline-from-environment.json"
    baseline.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": [
                    {"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": ["^tests/"]}
                ],
                "results": {
                    "settings.py": [
                        {
                            "type": "AWS Access Key",
                            "hashed_secret": PotentialSecret.hash_secret("placeholder"),
                            "line_number": 1,
                            "is_secret": False,
                        }
                    ]
                },
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(baseline))
        ),
    )
    assert scanner._baseline_in_use()
    sources: list[str] = []
    unbounded = DetectSecretsScanner._apply_file_exclusions

    def recording(files, exclude_patterns, root=None, **kwargs):
        sources.append(kwargs.get("source", ""))
        return unbounded(files, exclude_patterns, root)

    monkeypatch.setattr(
        DetectSecretsScanner, "_apply_file_exclusions", staticmethod(recording)
    )
    monkeypatch.setattr(
        DetectSecretsScanner, "_environment_values", lambda self: tuple(values)
    )
    monkeypatch.setattr(type(scanner), "_scan_in_worker", lambda self, **kwargs: None)

    scanner.scan(target=source, target_type="source")

    return sources, baseline.as_posix()


def test_the_filters_source_hides_a_baseline_path_read_from_the_environment(
    tmp_path, monkeypatch
):
    """A ``baseline_file`` read from an environment reference is a value the
    scan hides everywhere it prints. The text the filter's error quotes named
    the baseline whole, as the path."""
    baseline_value = str(tmp_path / "operator-baseline-from-environment.json")

    sources, _ = _sources_the_scan_gives_the_filter(
        tmp_path, monkeypatch, (baseline_value,)
    )

    assert sources
    for source in sources:
        assert "should_exclude_file" in source
        assert baseline_value not in source
        assert Path(baseline_value).as_posix() not in source
        assert "operator-baseline-from-environment" not in source


def test_the_filters_source_hides_a_baseline_path_written_with_backslashes(
    tmp_path, monkeypatch
):
    """The filter's text prints the baseline with forward slashes, while a
    Windows value for ``baseline_file`` is written with backslashes: the
    backslash spelling of the same path must hide it too. Built here from the
    baseline's own path so the check holds on every platform."""
    named = tmp_path / "operator-baseline-from-environment.json"
    backslashed = named.as_posix().replace("/", "\\")

    sources, _ = _sources_the_scan_gives_the_filter(
        tmp_path, monkeypatch, (backslashed,)
    )

    assert sources
    for source in sources:
        assert "should_exclude_file" in source
        assert "operator-baseline-from-environment" not in source


def test_the_filters_source_names_a_baseline_that_is_not_an_environment_value(
    tmp_path, monkeypatch
):
    """Control: with no environment value to hide, the error still tells the
    operator which baseline the filter came from."""
    sources, path = _sources_the_scan_gives_the_filter(tmp_path, monkeypatch, ())

    assert sources
    for source in sources:
        assert "should_exclude_file" in source
        assert path in source
