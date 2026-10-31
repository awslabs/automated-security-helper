# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malformed detect-secrets baseline takes the documented fallback.

The scanner's warning says "Falling back to default settings", but only a JSON
syntax error or an OSError reached it. A baseline that was not UTF-8
(UnicodeDecodeError), whose plugin or filter entries were not mappings
(TypeError) or had the wrong field types (pydantic's ValidationError) raised out
of the constructor, so the scanner failed construction. A baseline that parsed
but had no ``results`` mapping (a JSON array, an object without ``results``)
was kept as the scan's baseline and failed every source scan in
``load_from_baseline``.

Every such baseline now takes the fallback: a warning, the default settings,
and a scan with no baseline, as for a missing file. A ``results`` entry whose
items are not objects with a string ``type`` and ``hashed_secret`` is malformed
too: ``load_from_baseline`` reads both by key. And a malformed file is scanned
like any other file, as is a well-formed baseline the repository controls: the
scan set leaves out only a baseline the operator named outside the checkout.
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
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    (context.source_dir / "settings.py").write_text("value = 1\n", encoding="utf-8")
    return context


def _record_worker(scanner, monkeypatch) -> dict:
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(type(scanner), "_scan_in_worker", recorded)
    return seen


MALFORMED = {
    # Valid JSON apart from one byte that is not UTF-8. A UTF-16 byte order mark
    # (``\xff\xfe`` before ``{}``) is a different failure: a reader that
    # detects the encoding from the bytes would decode it.
    "not utf-8": b'{"results": {}, "x": "\xff"}',
    "a json array": json.dumps([]).encode(),
    "no results": json.dumps({"version": "1.5.0", "plugins_used": []}).encode(),
    "results not a mapping": json.dumps({"version": "1.5.0", "results": []}).encode(),
    "a results entry not a list": json.dumps(
        {"version": "1.5.0", "results": {"a.py": {"type": "x"}}}
    ).encode(),
    "a plugin entry not a mapping": json.dumps(
        {"version": "1.5.0", "plugins_used": ["AWSKeyDetector"], "results": {}}
    ).encode(),
    "a plugin name of the wrong type": json.dumps(
        {"version": "1.5.0", "plugins_used": [{"name": 5}], "results": {}}
    ).encode(),
    "a filter entry not a mapping": json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": ["detect_secrets.filters.heuristic.is_likely_id_string"],
            "results": {},
        }
    ).encode(),
    "a results item not a mapping": json.dumps(
        {"version": "1.5.0", "results": {"a.py": [1]}}
    ).encode(),
    "a results item without a type": json.dumps(
        {"version": "1.5.0", "results": {"a.py": [{}]}}
    ).encode(),
    "a results item with a hashed secret of the wrong type": json.dumps(
        {"version": "1.5.0", "results": {"a.py": [{"type": "x", "hashed_secret": 5}]}}
    ).encode(),
    "a results item without a type but with a hashed secret": json.dumps(
        {"version": "1.5.0", "results": {"a.py": [{"hashed_secret": "abc"}]}}
    ).encode(),
    "a results item with a type of the wrong type": json.dumps(
        {
            "version": "1.5.0",
            "results": {"a.py": [{"type": 5, "hashed_secret": "abc"}]},
        }
    ).encode(),
}


def _scanned(seen: dict) -> set[str]:
    """The names, relative to the source, of the files the worker was asked to scan."""
    return {Path(item).name for item in seen["scan_paths"]}


@pytest.mark.parametrize("content", list(MALFORMED.values()), ids=list(MALFORMED))
def test_a_malformed_baseline_warns_and_the_scan_runs_without_it(
    tmp_path, monkeypatch, caplog, content
):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    (context.source_dir / ".secrets.baseline").write_bytes(content)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert any(
        "Failed to read baseline file settings" in record.message
        and "Falling back to default settings" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]
    assert scanner._baseline_document is None
    assert len(scanner.config.options.scan_settings.plugins_used) > 10
    seen = _record_worker(scanner, monkeypatch)

    report = scanner.scan(target=context.source_dir, target_type="source")

    assert seen, "the worker was not reached"
    assert seen["baseline"] is None
    assert report.runs[0].results == []
    # Not in use, so scanned like any other file.
    assert ".secrets.baseline" in _scanned(seen)
    assert "settings.py" in _scanned(seen)


def test_a_well_formed_baseline_is_the_scans(tmp_path, monkeypatch):
    """Control: the shape check admits what detect-secrets writes."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    document = {
        "version": "1.5.0",
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [
            {"path": "detect_secrets.filters.heuristic.is_likely_id_string"}
        ],
        "results": {},
        "generated_at": "2026-01-01T00:00:00Z",
    }
    (context.source_dir / ".secrets.baseline").write_text(
        json.dumps(document), encoding="utf-8"
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_document == document
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "AWSKeyDetector"
    ]
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=context.source_dir, target_type="source")

    # The worker is never seeded with the baseline (the scanner applies the
    # entries to the scan's own findings); the tree's own baseline is the
    # repository's file, so it is scanned like any other.
    assert seen["baseline"] is None
    assert ".secrets.baseline" in _scanned(seen)
    assert "settings.py" in _scanned(seen)
