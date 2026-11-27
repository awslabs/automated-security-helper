"""A baseline found in the scanned tree sets neither the plugins nor the filters.

The scanner looks for ``.ash/.secrets.baseline`` and ``.secrets.baseline`` in
the scanned tree. Its ``results`` mark known candidates (they stay in the
report as suppressed findings), and that is all a baseline the repository
carries may do. Its ``plugins_used`` and ``filters_used`` decide what the scan
detects and what it leaves out, so they are applied only when the operator
named the baseline file from outside the tree and every checkout.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

SECRET_TYPE = "AWS Access Key"  # pragma: allowlist secret
EXCLUDE_SECRET_FILTER = "detect_secrets.filters.regex.should_exclude_secret"
EXCLUDE_LINE_FILTER = "detect_secrets.filters.regex.should_exclude_line"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholder.
KEPT_SECRET = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


@pytest.fixture(autouse=True)
def _checkouts_below_the_temporary_directory(monkeypatch, tmp_path):
    """Let the trust rules see only the git checkouts at or below ``tmp_path``."""
    from automated_security_helper.config import path_trust
    from automated_security_helper.config.sandbox_grants import is_within

    real = path_trust._checkouts_holding
    monkeypatch.setattr(
        path_trust,
        "_checkouts_holding",
        lambda scan_root: [c for c in real(scan_root) if is_within(c, tmp_path)],
    )


def _baseline_document(results: dict | None = None) -> dict:
    return {
        "version": "1.5.0",
        "plugins_used": [
            {"name": "KeywordDetector"},
            {"name": "Base64HighEntropyString", "limit": 8.0},
        ],
        "filters_used": [
            {"path": EXCLUDE_SECRET_FILTER, "pattern": [".*"]},
            {"path": EXCLUDE_LINE_FILTER, "pattern": [".*"]},
        ],
        "results": results or {},
        "generated_at": "2026-01-01T00:00:00Z",
    }


def _scanner(tmp_path, monkeypatch, *, baseline_file: str | None = None):
    monkeypatch.chdir(tmp_path)
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    options = (
        DetectSecretsScannerConfigOptions(baseline_file=baseline_file)
        if baseline_file
        else DetectSecretsScannerConfigOptions()
    )
    return DetectSecretsScanner(
        context=context, config=DetectSecretsScannerConfig(options=options)
    )


def _plugin_names(scanner) -> set[str]:
    return {item.name for item in scanner.config.options.scan_settings.plugins_used}


def _filter_paths(scanner) -> set[str]:
    return {item.path for item in scanner.config.options.scan_settings.filters_used}


def _default_plugin_names(tmp_path_factory, monkeypatch) -> set[str]:
    empty = tmp_path_factory.mktemp("empty-tree")
    return _plugin_names(_scanner(empty, monkeypatch))


def test_a_baseline_in_the_tree_leaves_the_default_plugins_and_filters(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(_baseline_document()), encoding="utf-8"
    )
    defaults = _default_plugin_names(tmp_path_factory, monkeypatch)
    assert "AWSKeyDetector" in defaults

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch)

    assert scanner._baseline_in_use()
    assert _plugin_names(scanner) == defaults
    assert "AWSKeyDetector" in _plugin_names(scanner)
    assert not any(
        getattr(item, "limit", None) == 8.0
        for item in scanner.config.options.scan_settings.plugins_used
    )
    assert EXCLUDE_SECRET_FILTER not in _filter_paths(scanner)
    assert EXCLUDE_LINE_FILTER not in _filter_paths(scanner)
    assert ".secrets.baseline" in caplog.text
    assert "Base64HighEntropyString" in caplog.text
    assert EXCLUDE_SECRET_FILTER in caplog.text


def test_a_baseline_the_operator_names_outside_the_tree_still_sets_them(
    tmp_path, tmp_path_factory, monkeypatch
):
    operator_dir = tmp_path_factory.mktemp("operator")
    named = operator_dir / "shared.baseline"
    named.write_text(json.dumps(_baseline_document()), encoding="utf-8")

    scanner = _scanner(tmp_path, monkeypatch, baseline_file=str(named))

    assert scanner._baseline_entries_trusted()
    assert _plugin_names(scanner) == {"KeywordDetector", "Base64HighEntropyString"}
    assert EXCLUDE_SECRET_FILTER in _filter_paths(scanner)
    assert EXCLUDE_LINE_FILTER in _filter_paths(scanner)


def test_a_baseline_in_the_tree_still_marks_its_known_candidates(tmp_path, monkeypatch):
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    (tmp_path / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    entries = {
        "settings.py": [
            {
                "type": SECRET_TYPE,
                "hashed_secret": PotentialSecret.hash_secret(KEPT_SECRET),
                "line_number": 1,
                "is_secret": False,
            }
        ]
    }
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(_baseline_document(entries)), encoding="utf-8"
    )
    scanner = _scanner(tmp_path, monkeypatch)

    def scanned(self, **kwargs):
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        collection["settings.py"].add(
            PotentialSecret(
                SECRET_TYPE, "settings.py", secret=KEPT_SECRET, line_number=1
            )
        )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)
    report = scanner.scan(target=Path(tmp_path), target_type="source")

    (result,) = report.runs[0].results
    assert result.suppressions
