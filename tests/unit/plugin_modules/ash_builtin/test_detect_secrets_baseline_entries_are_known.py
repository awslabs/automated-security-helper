# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A detect-secrets baseline marks its entries known; what happens to them depends on whose baseline it is.

A baseline is the record of the findings its author has seen: audited real and
kept, audited false positive, or since removed from the file. detect-secrets
reports against one only what it does not hold, by filename, hash and type.
The scanner loaded the baseline into the collection the worker scans with, and
then reported every entry of that collection as an error-level finding: each
baseline entry once as itself, and a secret still in its file a second time,
under the scan's spelling of the path. An entry without a line number (a
``--slim`` baseline's) became a SARIF region starting at line 0, which the model
refuses, and the whole scan failed.

A baseline's entries are a suppression surface, so whose file it is decides
what "known" does. A baseline the operator names (``baseline_file`` in the
operator's own settings) removes its known candidates from the report, as
``detect-secrets scan --baseline`` would. A baseline the scanned repository
controls, its own in-tree ``.secrets.baseline``, cannot remove anything: a
repository could otherwise hide a secret still in its files by listing the hash
in a file it commits. Its known candidates stay in the report, each marked
suppressed with the baseline named as the reason, so the count stays visible.

The scan is driven in-process: ``_scan_in_worker`` is replaced by a stand-in
that returns what the worker returns, the baseline's entries plus the scan's.
"""

from __future__ import annotations

import json
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

SECRET_TYPE = "AWS Access Key"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholders.
KEPT_SECRET = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
GONE_SECRET = "".join(["AKIA", "I44QH8DHB", "EXAMPLE"])  # noqa: FLY002
NEW_SECRET = "".join(["AKIA", "ZZZZZZZZZ", "EXAMPLE"])  # noqa: FLY002


def _hash(secret: str) -> str:
    from detect_secrets.core.potential_secret import PotentialSecret

    return PotentialSecret.hash_secret(secret)


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    return context


def _baseline(entries: dict) -> dict:
    return {
        "version": "1.5.0",
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [],
        "results": entries,
        "generated_at": "2026-01-01T00:00:00Z",
    }


def _scanner_with_baseline(
    tmp_path, monkeypatch, entries: dict, *, operator_named: bool = False
):
    """A scanner over a tree of two files, with a baseline holding ``entries``.

    ``operator_named`` puts the baseline outside the tree and names it through
    the ``baseline_file`` option (the operator's own settings here: the default
    config carries no repository files), which is the trusted shape. Otherwise
    the baseline is the tree's own ``.secrets.baseline``, the repository's.
    """
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (source / "other.py").write_text(f"KEY = '{NEW_SECRET}'\n", encoding="utf-8")
    if operator_named:
        baseline = tmp_path / "operator.baseline"
        config = DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(baseline))
        )
    else:
        baseline = source / ".secrets.baseline"
        config = DetectSecretsScannerConfig()
    baseline.write_text(json.dumps(_baseline(entries)), encoding="utf-8")
    scanner = DetectSecretsScanner(context=context, config=config)
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is operator_named
    return scanner, source


def _worker_returning(scanner, monkeypatch, found: dict):
    """A worker that returns the baseline's entries plus ``found``.

    ``found`` maps a path relative to the source to the secrets the scan found
    in it, keyed as a multi-file scan keys them: relative to the root.
    """
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        collection_cls, _, _ = _detect_secrets_api()
        collection = (
            collection_cls.load_from_baseline(baseline=baseline)
            if baseline is not None
            else collection_cls()
        )
        collection.root = self._secrets_collection.root
        for relative, secrets in found.items():
            for line, secret in secrets:
                collection[relative].add(
                    PotentialSecret(
                        SECRET_TYPE, relative, secret=secret, line_number=line
                    )
                )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)


def _findings(report) -> list[tuple[str, int | None]]:
    return sorted(
        (
            result.locations[0].physicalLocation.root.artifactLocation.uri,
            result.locations[0].physicalLocation.root.region.startLine,
        )
        for result in report.runs[0].results
    )


def _suppressed(report) -> dict[str, list[str]]:
    """URI -> the justifications of its suppressions ([] for an unsuppressed finding)."""
    return {
        result.locations[0].physicalLocation.root.artifactLocation.uri: [
            item.justification for item in (result.suppressions or [])
        ]
        for result in report.runs[0].results
    }


KNOWN_ENTRIES = {
    "settings.py": [
        # Audited as a false positive, still in the file.
        {
            "type": SECRET_TYPE,
            "hashed_secret": _hash(KEPT_SECRET),
            "line_number": 1,
            "is_secret": False,
        },
        # Audited as real, since removed from the file.
        {
            "type": SECRET_TYPE,
            "hashed_secret": _hash(GONE_SECRET),
            "line_number": 7,
            "is_secret": True,
        },
    ]
}


def test_the_repositorys_baseline_entries_stay_in_the_report_as_suppressed(
    tmp_path, monkeypatch
):
    """The tree's own baseline lists the secret still in settings.py. It is
    reported, at the scan's line, marked suppressed with the baseline as the
    reason; the entry whose secret left the file is not reported at all; the
    new secret is an ordinary finding."""
    scanner, source = _scanner_with_baseline(tmp_path, monkeypatch, KNOWN_ENTRIES)
    _worker_returning(
        scanner,
        monkeypatch,
        {"settings.py": [(1, KEPT_SECRET)], "other.py": [(1, NEW_SECRET)]},
    )

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("other.py", 1), ("settings.py", 1)]
    suppressed = _suppressed(report)
    assert suppressed["other.py"] == []
    (reason,) = suppressed["settings.py"]
    assert ".secrets.baseline" in reason
    assert "repository controls" in reason
    assert "baseline_file" in reason


def test_the_repositorys_baseline_does_not_seed_the_worker(tmp_path, monkeypatch):
    """Control for the test above: the worker gets no baseline to load, so a
    listed secret that left its file cannot come back as a finding at the
    baseline's stale line; the operator's baseline is still handed over."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    seen = {}

    def record(self, *, baseline, **kwargs):
        seen["baseline"] = baseline
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        return collection

    scanner, source = _scanner_with_baseline(tmp_path, monkeypatch, KNOWN_ENTRIES)
    monkeypatch.setattr(type(scanner), "_scan_in_worker", record)
    scanner.scan(target=source, target_type="source")
    assert seen["baseline"] is None

    scanner, source = _scanner_with_baseline(
        tmp_path, monkeypatch, KNOWN_ENTRIES, operator_named=True
    )
    monkeypatch.setattr(type(scanner), "_scan_in_worker", record)
    scanner.scan(target=source, target_type="source")
    assert seen["baseline"] is not None
    assert seen["baseline"]["results"] == KNOWN_ENTRIES


def test_baseline_entries_leave_the_report_and_a_new_secret_stays(
    tmp_path, monkeypatch
):
    """The operator's baseline: a listed candidate still in its file leaves the
    report, the entry whose secret left the file is not reported, and a new
    secret is reported as before."""
    scanner, source = _scanner_with_baseline(
        tmp_path,
        monkeypatch,
        {
            "settings.py": [
                # Audited as a false positive, still in the file.
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(KEPT_SECRET),
                    "line_number": 1,
                    "is_secret": False,
                },
                # Audited as real, since removed from the file.
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(GONE_SECRET),
                    "line_number": 7,
                    "is_secret": True,
                },
            ]
        },
        operator_named=True,
    )
    _worker_returning(
        scanner,
        monkeypatch,
        {"settings.py": [(1, KEPT_SECRET)], "other.py": [(1, NEW_SECRET)]},
    )

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("other.py", 1)]


@pytest.mark.parametrize("operator_named", [True, False], ids=["operator", "repo"])
def test_a_baseline_entry_without_a_line_number_fails_nothing(
    tmp_path, monkeypatch, operator_named
):
    """A ``--slim`` baseline records no line numbers. Its entry is known: the
    operator's removes the finding, the repository's keeps it at the scan's own
    line, suppressed. Before, the entry became a region at line 0 and failed the
    scan, whichever baseline it came from."""
    scanner, source = _scanner_with_baseline(
        tmp_path,
        monkeypatch,
        {
            "settings.py": [
                {"type": SECRET_TYPE, "hashed_secret": _hash(KEPT_SECRET)},
            ]
        },
        operator_named=operator_named,
    )
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    if operator_named:
        assert _findings(report) == []
    else:
        assert _findings(report) == [("settings.py", 1)]
        assert len(_suppressed(report)["settings.py"]) == 1


def test_without_a_baseline_every_secret_is_reported(tmp_path, monkeypatch):
    """Control: the known set is empty when no baseline is in use."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert not scanner._baseline_in_use()
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("settings.py", 1)]
