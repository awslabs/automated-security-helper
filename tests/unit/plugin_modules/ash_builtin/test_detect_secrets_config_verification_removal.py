# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner removes a config's verification filter that the operator did not name.

``_apply_settings_trust`` has a last step for scans that took their settings from a
baseline: a verification filter that came from the config, rather than from the
baseline, is removed unless the operator's own settings name that filter
(``operator_verifies``). ``resolve_config`` normally removes such a filter before the
scanner is built, so the end-to-end tests never reach this step. These cells reach it
directly: they record an untrusted-settings record by hand, put a verification
filter among the config's own entries, and call the method.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.secret_verification_trust import (
    UntrustedDetectSecretsSettings,
    is_verification_filter,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScanSettingsFiltersUsed,
)

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
BASELINE_FILTER = "detect_secrets.filters.heuristic.is_sequential_string"


def _scanner(tmp_path: Path) -> DetectSecretsScanner:
    source = tmp_path / "src"
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    return DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())


@pytest.mark.parametrize(
    ("operator_verifies", "verification_kept"),
    [(False, False), (True, True)],
    ids=["operator-does-not-verify", "operator-verifies"],
)
def test_a_config_verification_filter_stays_only_when_the_operator_names_it(
    tmp_path, monkeypatch, operator_verifies, verification_kept
):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _scanner(tmp_path)
    baseline = tmp_path / "shared" / "team.baseline"
    scanner.context.config._untrusted_detect_secrets_settings = (
        UntrustedDetectSecretsSettings(
            reason="the repository's config",
            operator_verifies=operator_verifies,
            operator_baseline=str(baseline),
        )
    )
    scanner.config.options.baseline_file = baseline
    settings = scanner.config.options.scan_settings
    settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(path=BASELINE_FILTER),
        DetectSecretsScanSettingsFiltersUsed(path=VERIFICATION_FILTER, min_level=2),
    ]
    # Read the entries back: identity is how the method tells the config's from the
    # baseline's, so it has to be taken from the list the method will see.
    config_entry = next(
        item for item in settings.filters_used if is_verification_filter(item.path)
    )

    scanner._apply_settings_trust(
        settings_from_baseline=True, config_entries={id(config_entry)}
    )

    paths = [item.path for item in settings.filters_used]
    assert (VERIFICATION_FILTER in paths) is verification_kept, paths
    assert BASELINE_FILTER in paths, paths
    assert scanner._verification_permitted is verification_kept


@pytest.mark.parametrize(
    ("operator_verifies", "verification_kept"),
    [(False, False), (True, True)],
    ids=["operator-does-not-verify", "operator-verifies"],
)
def test_the_scanner_entry_applies_the_same_rule_to_a_baseline_scan(
    tmp_path, monkeypatch, operator_verifies, verification_kept
):
    """The same rule, reached through ``_process_config_options``, which is the
    method the scanner runs when it is built from a config. The scan takes its
    plugins and filters from a baseline the operator named, and the config's own
    ``filters_used`` holds a verification filter."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _scanner(tmp_path)
    baseline = tmp_path / "shared" / "team.baseline"
    baseline.parent.mkdir()
    baseline.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": [{"path": BASELINE_FILTER}],
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    scanner.context.config._untrusted_detect_secrets_settings = (
        UntrustedDetectSecretsSettings(
            reason="the repository's config",
            operator_verifies=operator_verifies,
            operator_baseline=str(baseline),
        )
    )
    scanner.config.options.baseline_file = baseline
    settings = scanner.config.options.scan_settings
    # Building the scanner may already have filled the default plugins in; the
    # baseline's settings replace only an unconfigured plugin list.
    settings.version = None
    settings.plugins_used = []
    settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(path=VERIFICATION_FILTER, min_level=2)
    ]

    scanner._process_config_options()

    assert [item.name for item in settings.plugins_used] == ["AWSKeyDetector"], (
        "the baseline's settings were not the ones used"
    )
    paths = [item.path for item in settings.filters_used]
    assert (VERIFICATION_FILTER in paths) is verification_kept, paths
    assert BASELINE_FILTER in paths, paths
    assert scanner._verification_permitted is verification_kept
    assert scanner.sandbox_requirements.network is verification_kept
