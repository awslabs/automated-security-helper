# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Severity mapping and conversion over a captured audit document.

The document at tests/test_data/scanners/composer_audit/captured/ is real
``composer audit --locked --format=json --abandoned=report`` output (Composer 2.11.3,
PHP 8.5.13; that directory's README records the run), taken over the committed
``composer.lock`` beside it. The expectations below are written by hand from the
documented severity table and the advisory ids Packagist published for
guzzlehttp/psr7 1.8.3; they are not derived from the file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    convert_audit_document,
    parse_audit_document,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "composer_audit"
    / "captured"
)
FIXTURE = CAPTURED / "composer-2.11.3-vulnerable-abandoned.json"
LOCK = CAPTURED / "composer.lock"

#: The six advisories Packagist served for guzzlehttp/psr7 1.8.3 at capture time,
#: every one rated medium there. The two oldest are the long-published pair this
#: fixture was built around: PKSA-gvzg-s447-b5b5 is CVE-2022-24775 (GHSA-q7rv-6hp3-vh96,
#: fixed in 1.8.4) and PKSA-hn62-zkx4-1y5q is CVE-2023-29197 (GHSA-wxmh-65f7-jcvw,
#: fixed in 1.9.1).
PSR7_ADVISORY_IDS = {
    "PKSA-vznr-tgp9-fd7d",
    "PKSA-7qs6-zvnz-h66r",
    "PKSA-gm5x-j3mz-71n9",
    "PKSA-jj5t-2zs1-dcfm",
    "PKSA-hn62-zkx4-1y5q",
    "PKSA-gvzg-s447-b5b5",
}


def _results():
    document = parse_audit_document(FIXTURE.read_text(encoding="utf-8"))
    return convert_audit_document(
        document, uri="composer.lock", lock_text=LOCK.read_text(encoding="utf-8")
    )


def test_the_fixture_is_present_and_parses():
    assert FIXTURE.is_file()
    document = parse_audit_document(FIXTURE.read_text(encoding="utf-8"))
    assert set(document["advisories"]) == {"guzzlehttp/psr7"}
    assert document["abandoned"] == {
        "fzaninotto/faker": None,
        "zendframework/zend-stdlib": "laminas/laminas-stdlib",
    }


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
    # Packagist rates all six psr7 advisories medium; abandoned packages are LOW.
    assert seen == {(rule, "warning", "MEDIUM") for rule in PSR7_ADVISORY_IDS} | {
        ("COMPOSER-ABANDONED", "note", "LOW")
    }
    assert len(results) == 8


def test_every_row_is_located_on_its_package_line_in_the_lock():
    # Every advisory and abandoned package is present in the captured lock, so no
    # row falls back to line 1.
    results, _ = _results()
    lines = {
        (r.ruleId, getattr(r.properties, "composer_package", None)): (
            r.locations[0].physicalLocation.root.region.startLine
        )
        for r in results
    }
    assert all(line > 1 for line in lines.values()), lines


def test_abandoned_rows_name_the_replacement_or_say_there_is_none():
    results, rules = _results()
    texts = sorted(
        r.message.root.text for r in results if r.ruleId == "COMPOSER-ABANDONED"
    )
    assert texts == [
        "fzaninotto/faker v1.9.2 is abandoned and no replacement is suggested",
        (
            "zendframework/zend-stdlib 3.2.1 is abandoned; its maintainers suggest "
            "laminas/laminas-stdlib instead"
        ),
    ]
    assert set(rules) == PSR7_ADVISORY_IDS | {"COMPOSER-ABANDONED"}


def test_the_long_published_cves_are_named_in_their_rows():
    results, _ = _results()
    by_rule = {r.ruleId: r for r in results}
    improper_parsing = by_rule["PKSA-gvzg-s447-b5b5"]
    assert improper_parsing.message.root.text.startswith("guzzlehttp/psr7 1.8.3: ")
    assert "(CVE-2022-24775)" in improper_parsing.message.root.text
    assert getattr(improper_parsing.properties, "cve", None) == "CVE-2022-24775"
    header_validation = by_rule["PKSA-hn62-zkx4-1y5q"]
    assert "(CVE-2023-29197)" in header_validation.message.root.text
    assert getattr(header_validation.properties, "cve", None) == "CVE-2023-29197"
