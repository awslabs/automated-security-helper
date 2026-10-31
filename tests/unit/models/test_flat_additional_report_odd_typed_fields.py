# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's additional-report entry with an odd-typed field is read, not refused.

``from_additional_report`` read a null or non-string title, description and type
as absent, but passed ``rule_id``, ``cve_id``, ``cwe_id``, ``detected_at``,
``fix_available`` and the line numbers to the model as they came. A plugin that
wrote ``"cwe_id": 79`` raised a ValidationError there, which aborted
``to_flat_vulnerabilities`` and with it every flat reporter, for every other
finding too. Each field is now read as the type the model declares for it, and
one entry that still cannot be read is skipped with a warning that names its
scanner and position, not its content.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


def _flat(**fields):
    return FlatVulnerability.from_additional_report({"title": "t", **fields}, "plug")


@pytest.mark.parametrize(
    ("field", "given", "kept"),
    [
        ("cwe_id", 79, "79"),
        ("cve_id", 2026, "2026"),
        ("rule_id", 1234, "1234"),
        ("detected_at", 17000, "17000"),
        ("file_path", 12, "12"),
    ],
)
def test_a_number_where_text_is_declared_is_read_as_its_text(field, given, kept):
    assert getattr(_flat(**{field: given}), field) == kept


@pytest.mark.parametrize(
    ("given", "kept"),
    [(12, 12), ("12", 12), (12.0, 12), (12.5, None), ("twelve", None), (True, None)],
)
def test_a_line_number_is_read_as_a_number_or_not_stated(given, kept):
    vuln = _flat(line_start=given, line_end=given)

    assert vuln.line_start == kept
    assert vuln.line_end == kept


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("yes", True),
        ("No", False),
        (2, None),
        ("maybe", None),
        (None, None),
    ],
)
def test_fix_available_is_read_as_yes_or_no_or_not_stated(given, kept):
    assert _flat(fix_available=given).fix_available is kept


def test_a_well_formed_entry_is_read_as_before():
    """The control: nothing a plugin wrote correctly changes."""
    vuln = _flat(
        rule_id="R1",
        cve_id="CVE-2026-0001",
        cwe_id="CWE-79",
        detected_at="2026-10-31T00:00:00Z",
        file_path="src/app.py",
        line_start=3,
        line_end=5,
        fix_available=True,
    )

    assert (vuln.rule_id, vuln.cve_id, vuln.cwe_id) == ("R1", "CVE-2026-0001", "CWE-79")
    assert vuln.detected_at == "2026-10-31T00:00:00Z"
    assert (vuln.file_path, vuln.line_start, vuln.line_end) == ("src/app.py", 3, 5)
    assert vuln.fix_available is True


def test_an_odd_typed_entry_does_not_fail_the_flattening_of_the_others():
    model = AshAggregatedResults(
        additional_reports={
            "plug": [
                {"title": "first", "rule_id": "R1"},
                {"title": "odd", "cwe_id": 79, "rule_id": 1234, "line_start": "9"},
                {"title": "last", "rule_id": "R3"},
            ]
        }
    )

    flat = model.to_flat_vulnerabilities()

    assert sorted(vuln.title for vuln in flat) == ["first", "last", "odd"]


def test_an_entry_that_still_cannot_be_read_is_left_out_by_position(monkeypatch):
    real = FlatVulnerability.from_additional_report.__func__

    def _refuses_the_poisoned_entry(cls, entry, scanner_name):
        if "poison" in entry:
            raise ValueError("not readable")
        return real(cls, entry, scanner_name)

    monkeypatch.setattr(
        FlatVulnerability,
        "from_additional_report",
        classmethod(_refuses_the_poisoned_entry),
    )
    lines: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        model = AshAggregatedResults(
            additional_reports={
                "plug": [
                    {"title": "first"},
                    {"title": "poisoned", "poison": "SECRET-CANARY-7q"},
                    {"title": "last"},
                ]
            }
        )
        flat = model.to_flat_vulnerabilities()
    finally:
        ASH_LOGGER.removeHandler(handler)

    assert sorted(vuln.title for vuln in flat) == ["first", "last"]
    said = " ".join(lines)
    assert "Entry 1" in said and "plug" in said, said
    assert "SECRET-CANARY-7q" not in said, said
