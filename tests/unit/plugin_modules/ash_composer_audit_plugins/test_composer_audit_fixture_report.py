# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Severity mapping and conversion over a committed audit document.

The document at tests/test_data/scanners/composer_audit/modeled/audit.json is MODELED
on the ``Auditor::audit`` key list; it is not output captured from a Composer run
(Composer and PHP were not available where it was written), and every name in it is
fictional. Replacing it with a capture is a drop-in change: the expectations below
are written by hand from the documented severity table, not derived from the file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    convert_audit_document,
    parse_audit_document,
)

pytestmark = pytest.mark.unit

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "composer_audit"
    / "modeled"
    / "audit.json"
)

LOCK_TEXT = json.dumps(
    {
        "packages": [
            {"name": "acme/alpha", "version": "1.1.0"},
            {"name": "acme/gamma", "version": "3.4.5"},
        ],
        "packages-dev": [
            {"name": "acme/old", "version": "0.9.0"},
            {"name": "acme/dead", "version": "0.1.0"},
        ],
    },
    indent=4,
)


def _results():
    document = parse_audit_document(FIXTURE.read_text(encoding="utf-8"))
    return convert_audit_document(document, uri="composer.lock", lock_text=LOCK_TEXT)


def test_the_fixture_is_present_and_parses():
    assert FIXTURE.is_file()
    document = parse_audit_document(FIXTURE.read_text(encoding="utf-8"))
    assert set(document["advisories"]) == {"acme/alpha", "acme/gamma"}


def test_severity_and_level_per_row():
    results, _ = _results()
    seen = {
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in results
    }
    assert seen == {
        ("PKSA-aaaa-bbbb-cccc", "error", "HIGH"),
        # severity null: rated MEDIUM, never lower
        ("PKSA-dddd-eeee-ffff", "warning", "MEDIUM"),
        ("COMPOSER-ABANDONED", "note", "LOW"),
    }
    assert len(results) == 4


def test_abandoned_rows_name_the_replacement_or_say_there_is_none():
    results, rules = _results()
    texts = sorted(
        r.message.root.text for r in results if r.ruleId == "COMPOSER-ABANDONED"
    )
    assert any("suggest acme/alive" in t for t in texts)
    assert any("no replacement is suggested" in t for t in texts)
    assert set(rules) == {
        "PKSA-aaaa-bbbb-cccc",
        "PKSA-dddd-eeee-ffff",
        "COMPOSER-ABANDONED",
    }


def test_a_null_cve_adds_no_cve_text():
    results, _ = _results()
    gamma = next(r for r in results if r.ruleId == "PKSA-dddd-eeee-ffff")
    assert "CVE" not in gamma.message.root.text
    alpha = next(r for r in results if r.ruleId == "PKSA-aaaa-bbbb-cccc")
    assert "(CVE-2099-0001)" in alpha.message.root.text
