# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The baseline a repository commits is scanned like any file; only the echoes of its own entries are dropped.

A baseline the scanned repository controls is handed to the worker as an
ordinary file, because leaving it out of the scan set let a repository hide
anything it put in a file of that name (``{"results": {}, "notes": "<key>"}``).
detect-secrets reads such a file as it reads any other, and it reads every
``hashed_secret`` the baseline lists twice: the hex detectors take the value
as a high-entropy string, and the keyword detector takes it as the value of a
key whose name contains ``secret``. The scan has to drop what those detectors
make of the entries and nothing else on the file, whichever detector made it.

The first group replaces the worker with a stand-in that returns findings of
several types on a hash the baseline lists. The second group runs the real
worker over a baseline with two entries, which is the only way to see what the
detectors really make of the file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    HEX_HIGH_ENTROPY_TYPE,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    _detect_secrets_api,
)

pytestmark = pytest.mark.usefixtures("no_tool_probes")

BASELINE_NAME = ".secrets.baseline"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholders.
LISTED_ONE = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
LISTED_TWO = "".join(["AKIA", "I44QH8DHB", "EXAMPLE"])  # noqa: FLY002
PLANTED = "".join(["AKIA", "ZZZZZZZZZ", "EXAMPLE"])  # noqa: FLY002
AWS_RULE = "SECRET-AWS-ACCESS-KEY"


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


def _write_baseline(source: Path, *, notes: str | None = None) -> str:
    """A baseline of the shape ``detect-secrets scan`` writes: two listed
    entries, one per line, and the detectors a repository ordinarily has on.
    Returns the text, so a test can find the line a key sits on."""
    document: dict = {
        "version": "1.5.0",
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "HexHighEntropyString", "limit": 3.0},
            {"name": "KeywordDetector", "keyword_exclude": ""},
        ],
        "filters_used": [],
        "results": {
            "settings.py": [
                {
                    "type": "AWS Access Key",
                    "filename": "settings.py",
                    "hashed_secret": _hash(LISTED_ONE),
                    "is_verified": False,
                    "line_number": 1,
                },
                {
                    "type": "AWS Access Key",
                    "filename": "settings.py",
                    "hashed_secret": _hash(LISTED_TWO),
                    "is_verified": False,
                    "line_number": 2,
                },
            ]
        },
        "generated_at": "2026-01-01T00:00:00Z",
    }
    if notes is not None:
        document["notes"] = notes
    text = json.dumps(document, indent=2) + "\n"
    (source / BASELINE_NAME).write_text(text, encoding="utf-8")
    return text


def _on_the_baseline(report) -> list[tuple[str, int | None]]:
    """(rule id, line) of every finding located in the baseline file."""
    found = []
    for result in report.runs[0].results:
        location = result.locations[0].physicalLocation.root
        if location.artifactLocation.uri == BASELINE_NAME:
            found.append((result.ruleId, location.region.startLine))
    return sorted(found)


@pytest.mark.parametrize(
    "echo_type",
    [HEX_HIGH_ENTROPY_TYPE, "Secret Keyword", "Base64 High Entropy String"],
)
def test_a_finding_on_a_listed_hash_is_dropped_whichever_detector_made_it(
    tmp_path, monkeypatch, echo_type
):
    """The finding the keyword detector makes on ``"hashed_secret": "<hex>"``
    is keyed by the hash of the hex, as the hex detectors' is. Both are the
    baseline's own entries read back, and neither is a finding. A value the
    baseline does not list, found by the same detector, stays: the drop is by
    the value, not by the type. Before, only the hex type was dropped, and every
    entry of a committed baseline came back as a keyword finding on the file."""
    from detect_secrets.core.potential_secret import PotentialSecret

    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source)
    listed = _hash(LISTED_ONE)
    unlisted = _hash(LISTED_TWO + "-not-listed")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        for secret, line in ((listed, 9), (unlisted, 3)):
            collection[BASELINE_NAME].add(
                PotentialSecret(
                    echo_type, BASELINE_NAME, secret=secret, line_number=line
                )
            )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)

    report = scanner.scan(target=source, target_type="source")

    rule = "SECRET-" + "-".join(echo_type.upper().split())
    assert _on_the_baseline(report) == [(rule, 3)]


@pytest.mark.integration
def test_the_real_worker_reports_only_what_the_baseline_hides_in_a_key_of_its_own(
    tmp_path, monkeypatch
):
    """A baseline of two listed entries and a ``notes`` key holding a live key:
    the finding set on the file is exactly the key under ``notes``. The
    entries' echoes, from the hex detector and from the keyword detector, are
    not in it. Run by the real worker, because the detectors' reading of the
    file is the thing under test."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    text = _write_baseline(source, notes=PLANTED)
    line = next(
        number
        for number, content in enumerate(text.splitlines(), 1)
        if PLANTED in content
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    report = scanner.scan(target=source, target_type="source")

    assert report is not False
    assert _on_the_baseline(report) == [(AWS_RULE, line)]


@pytest.mark.integration
def test_the_real_worker_reports_nothing_on_a_baseline_that_only_lists(
    tmp_path, monkeypatch
):
    """The common case: a committed baseline of two entries and nothing else.
    Scanned by the real worker with the default detectors it reports nothing on
    the file, as it did before the baseline was scanned at all."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    report = scanner.scan(target=source, target_type="source")

    assert report is not False
    assert _on_the_baseline(report) == []
