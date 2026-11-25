# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converter against a report captured from a real ``cargo audit`` run.

``fixtures/cargo-audit-0.23.0-report.json`` is the stdout of
``cargo-audit audit --json --file=<Cargo.lock>`` (cargo-audit 0.23.0, built with
``cargo install cargo-audit --locked``), run against a lockfile pinning
``time 0.1.43`` and ``atty 0.2.14`` and the RustSec advisory database at commit
10db6998b5d7 (1567 advisories). The tool exited 1, which is its "vulnerabilities
found" code. The file is the tool's JSON re-indented; no value was edited. The
document carries one vulnerability and one warning of each of two kinds, so the
report shape the hand-written documents in the behavior tests assume is checked
against the real one here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_scanner import (
    convert_cargo_audit_report,
)

pytestmark = pytest.mark.unit

CAPTURE = Path(__file__).parent / "fixtures" / "cargo-audit-0.23.0-report.json"


@pytest.fixture(scope="module")
def captured() -> dict:
    return json.loads(CAPTURE.read_text(encoding="utf-8"))


def test_the_capture_is_a_positive_report(captured):
    assert captured["vulnerabilities"]["found"] is True
    assert captured["vulnerabilities"]["count"] == 1
    assert sorted(captured["warnings"]) == ["unmaintained", "unsound"]


def test_each_captured_row_converts_with_its_severity_and_level(captured):
    results = convert_cargo_audit_report(captured, uri="Cargo.lock")
    rows = [
        (
            r["ruleId"],
            r["level"],
            r["properties"]["issue_severity"],
            r["partialFingerprints"]["cargo-audit/advisory-fingerprint"],
        )
        for r in results
    ]
    assert rows == [
        # CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H scores 5.5.
        ("RUSTSEC-2020-0071", "warning", "MEDIUM", "RUSTSEC-2020-0071:time:0.1.43"),
        ("RUSTSEC-2024-0375", "note", "LOW", "RUSTSEC-2024-0375:atty:0.2.14"),
        ("RUSTSEC-2021-0145", "warning", "MEDIUM", "RUSTSEC-2021-0145:atty:0.2.14"),
    ]


def test_a_captured_report_with_nothing_found_converts_to_no_results(captured):
    clean = {**captured, "vulnerabilities": {"found": False, "count": 0, "list": []}}
    clean["warnings"] = {}
    assert convert_cargo_audit_report(clean, uri="Cargo.lock") == []


def test_the_real_vulnerability_shape_is_read_through_its_package_and_advisory(
    captured,
):
    (entry,) = captured["vulnerabilities"]["list"]
    assert entry["package"]["name"] == "time"
    assert entry["advisory"]["id"] == "RUSTSEC-2020-0071"
    assert entry["advisory"]["cvss"].startswith("CVSS:3.1/")
    assert entry["versions"]["patched"] == [">=0.2.23"]
