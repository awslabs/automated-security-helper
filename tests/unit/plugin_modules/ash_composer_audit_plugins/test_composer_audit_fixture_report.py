# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Severity mapping and conversion over a captured audit document.

The document at tests/test_data/scanners/composer_audit/captured/ is real
``composer audit --locked --format=json --abandoned=report`` output (Composer 2.11.3,
PHP 8.5.13; that directory's README records the run), taken over the committed lock
beside it (``composer.lock.capture``). The expectations below are a pinned snapshot of
that capture: the advisory ids, the locked versions and the message texts were read
from the captured document, and the first draft's guesses were re-pinned to them.
Only the severity-to-level mapping is written by hand, from Composer's documented
severity scale. ``captured/audit.sarif`` is held to the adapter by the golden test at
the end, which rebuilds it.
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

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "composer_audit"
    / "captured"
)
FIXTURE = CAPTURED / "composer-2.11.3-vulnerable-abandoned.json"
LOCK = CAPTURED / "composer.lock.capture"
SARIF = CAPTURED / "audit.sarif"

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


def _dumped(model) -> dict:
    """A model as the scanner writes its report: by alias, no unset or null field."""
    return model.model_dump(
        mode="json", by_alias=True, exclude_none=True, exclude_unset=True
    )


def rebuild_audit_sarif() -> str:
    """The text ``captured/audit.sarif`` holds: the adapter's output for the capture.

    To regenerate the file after an adapter change, write this function's return
    value to it, from a host that runs the tests.
    """
    results, rules = _results()
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Composer Audit",
                        "rules": [_dumped(rules[rule]) for rule in sorted(rules)],
                    }
                },
                "results": [_dumped(result) for result in results],
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def test_the_fixture_is_present_and_parses():
    assert FIXTURE.is_file()
    document = parse_audit_document(FIXTURE.read_text(encoding="utf-8"))
    assert set(document["advisories"]) == {"guzzlehttp/psr7"}
    assert document["abandoned"] == {
        "fzaninotto/faker": None,
        "zendframework/zend-stdlib": "laminas/laminas-stdlib",
    }
    # Composer 2.11's two newer keys, empty in this capture.
    assert document["filter"] == [] and document["cooldown"] == []


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


def test_every_row_is_located_on_its_package_name_line_in_the_lock():
    lock_lines = LOCK.read_text(encoding="utf-8").splitlines()
    results, _ = _results()
    located = {}
    for r in results:
        package = getattr(r.properties, "package_name", None)
        line = r.locations[0].physicalLocation.root.region.startLine
        located[(r.ruleId, package)] = line
        assert lock_lines[line - 1].strip().rstrip(",") == f'"name": "{package}"', (
            r.ruleId,
            package,
            line,
        )
    # One line per package: the six psr7 advisories share one, each abandoned
    # package has its own.
    assert len(set(located.values())) == 3, located


def test_every_row_carries_the_package_and_the_locked_version():
    results, _ = _results()
    identities = {
        (
            getattr(r.properties, "package_name", None),
            getattr(r.properties, "package_version", None),
        )
        for r in results
    }
    assert identities == {
        ("guzzlehttp/psr7", "1.8.3"),
        ("fzaninotto/faker", "v1.9.2"),
        ("zendframework/zend-stdlib", "3.2.1"),
    }


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


def test_each_advisory_rule_links_its_advisory():
    _, rules = _results()
    assert str(rules["PKSA-gvzg-s447-b5b5"].helpUri) == (
        "https://github.com/guzzle/psr7/security/advisories/GHSA-q7rv-6hp3-vh96"
    )
    assert all(rules[rule].helpUri is not None for rule in PSR7_ADVISORY_IDS)
    assert rules["COMPOSER-ABANDONED"].helpUri is None


def test_the_committed_sarif_is_what_the_adapter_writes_for_the_capture():
    """The golden check: a message, property or rule change in the adapter moves
    the corpus SARIF, and the register gate reads that file, so it must move with
    the adapter. Regenerate it from ``rebuild_audit_sarif()``."""
    rebuilt = rebuild_audit_sarif()
    committed = SARIF.read_text(encoding="utf-8")
    assert json.loads(committed) == json.loads(rebuilt)
    assert committed == rebuilt, "same content, different serialization"
