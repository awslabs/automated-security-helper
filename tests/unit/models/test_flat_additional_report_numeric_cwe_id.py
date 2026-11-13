# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An additional-report entry with a numeric ``cwe_id`` still flattens.

``FlatVulnerability.cwe_id`` is ``Optional[str]``, and pydantic does not turn a
number into text for a ``str`` field. ``from_additional_report`` passed the
entry's value through as it stood, so a plugin that wrote ``79`` for CWE-79 raised
a ValidationError, and since ``to_flat_vulnerabilities`` does not catch it, one
such entry aborted the flat view for every report. A number is now read as its
text; null and absent stay absent, and text is kept as written.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit


def test_a_numeric_cwe_id_is_read_as_its_text():
    flat = FlatVulnerability.from_additional_report(
        {"id": "X", "cwe_id": 79}, "planted-plugin"
    )

    assert flat.cwe_id == "79"


def test_a_numeric_cwe_id_does_not_abort_the_flat_view_of_the_other_entries():
    model = AshAggregatedResults(
        additional_reports={
            "planted-plugin": [
                {"id": "A", "title": "first", "cwe_id": 79},
                {"id": "B", "title": "second", "cwe_id": "CWE-89"},
            ]
        }
    )

    flat = model.to_flat_vulnerabilities()

    assert sorted(v.cwe_id for v in flat) == ["79", "CWE-89"]


def test_a_text_cwe_id_is_kept_as_written():
    flat = FlatVulnerability.from_additional_report(
        {"id": "X", "cwe_id": "CWE-79"}, "planted-plugin"
    )

    assert flat.cwe_id == "CWE-79"


def test_a_null_or_missing_cwe_id_stays_absent():
    null = FlatVulnerability.from_additional_report(
        {"id": "X", "cwe_id": None}, "planted-plugin"
    )
    missing = FlatVulnerability.from_additional_report({"id": "Y"}, "planted-plugin")

    assert null.cwe_id is None
    assert missing.cwe_id is None
