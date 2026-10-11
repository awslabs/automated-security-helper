# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Observation timestamps must come from the finding's saved evidence."""

import json
import re
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models import flat_vulnerability
from automated_security_helper.schemas.sarif_schema_model import Result


@pytest.mark.parametrize(
    "provenance, invocation, expected",
    [
        (
            {"lastDetectionTimeUtc": "2025-01-02T10:00:00.123456+07:00"},
            {"end_time": "2025-01-03T00:00:00Z"},
            "2025-01-02T03:00:00.123456+00:00",
        ),
        (
            {"firstDetectionTimeUtc": "2025-01-01T00:00:00Z"},
            {"end_time": "2025-01-03T00:00:00Z", "start_time": "2025-01-02T00:00:00Z"},
            "2025-01-03T00:00:00+00:00",
        ),
        (
            {"lastDetectionTimeUtc": "2025-01-02T00:00:00"},
            {"end_time": "bad", "start_time": "2025-01-03T00:00:00-04:00"},
            "2025-01-03T04:00:00+00:00",
        ),
        (
            {"firstDetectionTimeUtc": "2025-01-01T00:00:00Z"},
            {"end_time": "2025-01-03T00:00:00", "start_time": 42},
            "2025-01-01T00:00:00+00:00",
        ),
        ({"lastDetectionTimeUtc": None}, {"end_time": None}, None),
        ({}, {}, None),
        ({"firstDetectionTimeUtc": "2025-01-01T00:00:00"}, {}, None),
        ({}, {"end_time": "bad", "start_time": []}, None),
        (
            {},
            {"end_time": datetime(2025, 1, 3, tzinfo=timezone.utc)},
            "2025-01-03T00:00:00+00:00",
        ),
    ],
)
def test_sarif_observation_evidence_precedence(provenance, invocation, expected):
    result = Result.model_validate(
        {
            "message": {"text": "finding"},
            "provenance": provenance,
            "properties": {"scanner_details": {"tool_invocation": invocation}},
        }
    )
    before = result.model_dump(mode="json")
    flat = FlatVulnerability.from_sarif_result(result, "scanner", "SAST")
    assert flat.detected_at == expected
    assert result.model_dump(mode="json") == before
    assert json.loads(flat.raw_data) == result.model_dump(
        mode="json", exclude_none=True
    )


@pytest.mark.parametrize("details", [None, "bad", [], {"tool_invocation": "bad"}])
def test_malformed_scanner_details_remain_unknown(details):
    result = Result.model_validate(
        {
            "message": {"text": "finding"},
            "properties": {"scanner_details": details},
        }
    )
    assert (
        FlatVulnerability.from_sarif_result(result, "scanner", "SAST").detected_at
        is None
    )


def test_direct_factory_without_evidence_has_no_observation_time():
    result = Result.model_validate({"message": {"text": "finding"}})
    assert (
        FlatVulnerability.from_sarif_result(result, "scanner", "SAST").detected_at
        is None
    )


def test_invalid_provenance_still_fails_sarif_validation():
    with pytest.raises(ValidationError):
        Result.model_validate(
            {
                "message": {"text": "finding"},
                "provenance": {"lastDetectionTimeUtc": "invalid"},
            }
        )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2025-01-02T10:00:00.123456789+07:00", "2025-01-02T03:00:00.123456+00:00"),
        (datetime(2025, 1, 2, tzinfo=timezone.utc), "2025-01-02T00:00:00+00:00"),
        (datetime(2025, 1, 2), None),
        ("2025-01-02T00:00:00", None),
        ("bad", None),
        (None, None),
        (42, None),
        ({}, None),
    ],
)
def test_additional_report_uses_only_explicit_aware_time(value, expected):
    entry = {"id": "one", "detected_at": value}
    flat = FlatVulnerability.from_additional_report(entry, "scanner")
    assert flat.detected_at == expected
    assert json.loads(flat.raw_data)["detected_at"] == json.loads(
        json.dumps(value, default=str)
    )


def test_missing_additional_report_time_remains_unknown():
    assert (
        FlatVulnerability.from_additional_report({"id": "one"}, "scanner").detected_at
        is None
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2025-01-02T00:00:00Z", "2025-01-02T00:00:00+00:00"),
        ("2025-01-02T00:00:00.1Z", "2025-01-02T00:00:00.100000+00:00"),
        ("2025-01-02T00:00:00.1234Z", "2025-01-02T00:00:00.123400+00:00"),
        ("2025-01-02T10:00:00.123456789+07:00", "2025-01-02T03:00:00.123456+00:00"),
        ("2025-01-02T00:00:00.1234", None),
        ("invalidZ", None),
    ],
)
def test_observation_parser_supports_python310_iso_forms(monkeypatch, value, expected):
    class Python310Datetime(datetime):
        @classmethod
        def fromisoformat(cls, text):
            # Python 3.10 accepts offsets and only three/six fractional digits.
            fractions = re.findall(r"\.(\d+)", text)
            if text.endswith("Z") or any(len(part) not in (3, 6) for part in fractions):
                raise ValueError("Unsupported Python 3.10 ISO form")
            return super().fromisoformat(text)

    monkeypatch.setattr(flat_vulnerability, "datetime", Python310Datetime)
    assert flat_vulnerability._normalize_observation_time(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2025-01-02T10:00:00+0700", "2025-01-02T03:00:00+00:00"),
        ("2025-01-02T00:00:00,123+00:00", "2025-01-02T00:00:00.123000+00:00"),
        ("2025-01-02t00:00:00,123456789z", "2025-01-02T00:00:00.123456+00:00"),
        ("2025-01-02 10:00:00.1-0430", "2025-01-02T14:30:00.100000+00:00"),
        ("20250102T100000+07:00", None),
        ("2025-W01-4T10:00:00+07:00", None),
        ("2025-01-02X10:00:00+07:00", None),
        ("2025-01-02T10:00:00+07", None),
        ("2025-01-02T10:00:00+07:00:01", None),
        ("2025-01-02T10:00:00+07:60", None),
        ("2025-01-02T10:00:00+24:00", None),
        ("2025-13-02T10:00:00Z", None),
        ("2025-01-02T10:00:00", None),
    ],
)
def test_portable_extended_timestamp_boundary_preserves_raw_value(value, expected):
    flat = FlatVulnerability.from_additional_report(
        {"id": "one", "detected_at": value}, "scanner"
    )
    assert flat.detected_at == expected
    assert json.loads(flat.raw_data)["detected_at"] == value
