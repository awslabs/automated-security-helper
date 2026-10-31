# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The operator's detect-secrets filters_used survive a baseline's.

The scan_settings option says it takes precedence over baseline_file. The
scanner loaded a baseline's settings when the operator set no version and no
plugins_used, and then REPLACED the operator's filters_used with the baseline's,
keeping only a verification filter. An operator who configured a heuristic
filter, or an exclude pattern, beside a baseline that also had filters lost it
without a word.

Now every operator filter stays; the baseline's entries are added beside them,
and a baseline entry whose path the operator also configured is the operator's.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

HEURISTIC = "detect_secrets.filters.heuristic.is_likely_id_string"
SEQUENTIAL = "detect_secrets.filters.heuristic.is_sequential_string"


def _context_with_baseline(tmp_path: Path, filters: list) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    (context.source_dir / ".secrets.baseline").write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": filters,
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return context


def _scanner(context: PluginContext, filters: list) -> DetectSecretsScanner:
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(filters_used=filters)
            )
        ),
    )


def test_an_operator_filter_survives_the_baselines_filters(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = _context_with_baseline(
        tmp_path, [{"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": ["^tests/"]}]
    )
    operator = DetectSecretsScanSettingsFiltersUsed(path=HEURISTIC)

    scanner = _scanner(context, [operator])

    filters = scanner.config.options.scan_settings.filters_used
    assert sorted(item.path for item in filters) == sorted(
        [SHOULD_EXCLUDE_FILE_FILTER, HEURISTIC]
    )
    # The operator's own object is kept, so the trust pass still knows it as
    # the operator's (it compares by identity).
    assert any(item is operator for item in filters)
    # The baseline's plugins still load: the baseline is in use.
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "AWSKeyDetector"
    ]


def test_the_operators_entry_wins_over_the_baselines_for_one_path(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    context = _context_with_baseline(
        tmp_path, [{"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": ["^baseline/"]}]
    )
    operator = DetectSecretsScanSettingsFiltersUsed(
        path=SHOULD_EXCLUDE_FILE_FILTER, pattern=["^operator/"]
    )

    scanner = _scanner(context, [operator])

    filters = scanner.config.options.scan_settings.filters_used
    assert len(filters) == 1
    assert filters[0] is operator
    assert filters[0].model_dump(exclude_none=True)["pattern"] == ["^operator/"]


def test_an_operator_filter_file_under_a_derived_directory_stays_the_operators(
    tmp_path, monkeypatch
):
    """Authorship is judged per entry, not per option. The operator's
    ``file://`` filter under the scan's own output directory, a path the
    operator's configuration may name (a derived directory is refused only
    when the writer was not the operator), is kept beside the baseline's
    filters. Judged per option, the baseline having any filter made every
    retained operator ``file://`` entry read as the baseline's, and this one
    was refused with a warning."""
    monkeypatch.chdir(tmp_path)
    context = _context_with_baseline(tmp_path, [{"path": SEQUENTIAL}])
    filter_file = context.output_dir / "filters" / "mine.py"
    filter_file.parent.mkdir(parents=True)
    filter_file.write_text("def allow(secret):\n    return False\n", encoding="utf-8")
    operator = DetectSecretsScanSettingsFiltersUsed(
        path=f"file://{filter_file.as_posix()}::allow"
    )

    scanner = _scanner(context, [operator])

    paths = [item.path for item in scanner.config.options.scan_settings.filters_used]
    assert SEQUENTIAL in paths
    kept = [p for p in paths if p.startswith("file://") and p.endswith("::allow")]
    assert len(kept) == 1, paths
    assert kept[0].endswith("/filters/mine.py::allow"), kept


def test_without_operator_filters_the_baselines_are_the_scans(tmp_path, monkeypatch):
    """Control: the baseline's filters still load when the operator set none."""
    monkeypatch.chdir(tmp_path)
    context = _context_with_baseline(tmp_path, [{"path": SEQUENTIAL}])

    scanner = _scanner(context, [])

    assert [
        item.path for item in scanner.config.options.scan_settings.filters_used
    ] == [SEQUENTIAL]


def test_the_operators_patterns_stay_the_operators_after_the_executors_config_swap(
    tmp_path, monkeypatch
):
    """The executor hands ``_pre_scan`` the config the scanner was built from.
    The base class rebuilds ``self.config`` from a dump of it, which makes new
    filter objects, and the dumps match so no settings pass runs again. The
    record of which entries are the operator's was kept by object identity and
    pointed at the discarded objects: every entry then read as the baseline's,
    and the operator's ``^tests/`` was matched at the baseline's anchor."""
    monkeypatch.chdir(tmp_path)
    context = _context_with_baseline(tmp_path, [{"path": SEQUENTIAL}])
    operator = DetectSecretsScanSettingsFiltersUsed(
        path=SHOULD_EXCLUDE_FILE_FILTER, pattern=["^tests/"]
    )
    scanner = _scanner(context, [operator])
    own_before, others_before = scanner._exclude_patterns_by_author()
    assert [p.pattern for p in own_before] == ["^tests/"]
    assert others_before == []

    validated = scanner._pre_scan(context.source_dir, "source", config=scanner.config)

    assert validated is True
    # The swap really made new objects, so identity alone cannot tell them.
    assert all(
        item is not operator
        for item in scanner.config.options.scan_settings.filters_used
    )
    own, others = scanner._exclude_patterns_by_author()
    assert [p.pattern for p in own] == ["^tests/"]
    assert others == []
