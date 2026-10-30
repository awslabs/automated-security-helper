# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An additional-report entry with null text fields still flattens.

``from_additional_report`` read ``title``, ``description`` and ``type`` with
``dict.get`` defaults, which cover only a missing key. An entry whose field was
present with null failed the model's ``str`` fields with a ValidationError, and
one such entry aborted ``to_flat_vulnerabilities`` for every flat report. A null
is read as absent; any other value is read as text.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit


def test_null_text_fields_take_the_defaults():
    flat = FlatVulnerability.from_additional_report(
        {"title": None, "description": None, "type": None, "severity": "LOW"},
        "planted-plugin",
    )

    assert flat.title == "Unknown Issue"
    assert flat.description == "No description available"
    assert flat.scanner_type == "UNKNOWN"
    assert flat.scanner == "planted-plugin"


def test_a_numeric_title_is_read_as_text():
    flat = FlatVulnerability.from_additional_report({"title": 42}, "planted-plugin")

    assert flat.title == "42"


def test_given_text_fields_are_kept():
    flat = FlatVulnerability.from_additional_report(
        {"title": "t", "description": "d", "type": "SCA"}, "planted-plugin"
    )

    assert (flat.title, flat.description, flat.scanner_type) == ("t", "d", "SCA")
