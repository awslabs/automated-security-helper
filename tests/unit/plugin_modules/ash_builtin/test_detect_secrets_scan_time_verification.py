# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verification is decided again on the settings the detect-secrets worker gets.

``_apply_settings_trust`` decides at configuration time whether verification is
permitted (``_verification_permitted``), and ``_execute_scan`` decides it again on
the settings it hands the worker: offline mode is read when it is used, and the
settings can change after the scanner was configured. Each half was hidden by the
other in the end-to-end tests, because the configuration-time drop had always
removed the filter already, so dropping either half of the scan-time check went
unnoticed. These tests reach the scan-time check alone, with the worker stubbed
and its arguments recorded.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_operator_settings import (
    KEY_ID,
    KEY_SECRET,
    VERIFICATION_FILTER,
)
from tests.utils.refusing_proxy import scrub_cloud_credentials

pytestmark = pytest.mark.unit


def _scanner(tmp_path: Path, **options):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
    )

    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "creds.py").write_text(
        f'aws_access_key_id = "{KEY_ID}"\naws_secret_access_key = "{KEY_SECRET}"\n',
        encoding="utf-8",
    )
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(**options)
        ),
    )


def _record_worker(scanner, monkeypatch) -> dict:
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(type(scanner), "_scan_in_worker", recorded)
    return seen


def _names_the_filter(settings: dict) -> bool:
    return any(
        item.get("path") == VERIFICATION_FILTER
        for item in settings.get("filters_used", [])
    )


def test_a_filter_added_after_configuration_does_not_verify(tmp_path, monkeypatch):
    """Online, but the filter was not there when verification was decided."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanSettingsFiltersUsed,
    )

    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _scanner(tmp_path)
    assert scanner._verification_permitted is False
    scanner.config.options.scan_settings.filters_used.append(
        DetectSecretsScanSettingsFiltersUsed(path=VERIFICATION_FILTER, min_level=2)
    )
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert seen, "the worker was not reached"
    assert seen["verify"] is False
    assert not _names_the_filter(seen["scan_settings_dict"]), seen["scan_settings_dict"]


def test_offline_after_configuration_does_not_verify(tmp_path, monkeypatch):
    """Permitted when configured online, then ASH went offline before the scan."""
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _scanner(
        tmp_path,
        scan_settings={
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
        },
    )
    assert scanner._verification_permitted is True
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert seen, "the worker was not reached"
    assert seen["verify"] is False
    assert not _names_the_filter(seen["scan_settings_dict"]), seen["scan_settings_dict"]


def test_control_permitted_and_online_verifies(tmp_path, monkeypatch):
    """The stub sees a verifying run when nothing changed, so the two above can fail."""
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _scanner(
        tmp_path,
        scan_settings={
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
        },
    )
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert seen["verify"] is True
    assert _names_the_filter(seen["scan_settings_dict"])
