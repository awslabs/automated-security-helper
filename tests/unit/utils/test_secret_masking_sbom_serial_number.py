# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A masked SBOM still validates: its serial number keeps matching its pattern.

The CycloneDX model declares ``urn:uuid:`` plus a lowercase GUID as the pattern of
a BOM's ``serialNumber``. When the random serial's last group happened to be a
value a finding exposed, the mask starred that group, no fixed replacement matched
the pattern, and the file was refused when it was read again. The mask removes the
exposed value; the serial takes a fixed synthetic one that matches the pattern.

Every value here is derived at import time; none is a credential.
"""

import hashlib
import json
import re

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _SYNTHETIC_GUID,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _hex(label, length):
    return hashlib.sha256(label.encode()).hexdigest()[:length]


#: The twelve hex digits a finding exposes; they are also the serial's last group.
VALUE = _hex("sbom-serial-exposed", 12)
SERIAL = "urn:uuid:" + "-".join(
    (
        _hex("sbom-serial-a", 8),
        _hex("sbom-serial-b", 4),
        _hex("sbom-serial-c", 4),
        _hex("sbom-serial-d", 4),
        VALUE,
    )
)
OTHER_SERIAL = "urn:uuid:" + "-".join(
    (
        _hex("sbom-serial-e", 8),
        _hex("sbom-serial-f", 4),
        _hex("sbom-serial-g", 4),
        _hex("sbom-serial-h", 4),
        _hex("sbom-serial-i", 12),
    )
)


def _serial_pattern():
    """The pattern the CycloneDX model declares, read off the declaration."""
    for item in CycloneDXReport.model_fields["serialNumber"].metadata:
        pattern = getattr(item, "pattern", None)
        if isinstance(pattern, str):
            return pattern
    raise AssertionError("serialNumber declares no pattern")


def _results(serial):
    result = {
        "ruleId": "B105",
        "level": "warning",
        "message": {"text": HARDCODED + f"'{VALUE}'"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 5, "endLine": 5},
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }
    run = {"tool": {"driver": {"name": "test"}}, "results": [result]}
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    model.cyclonedx = CycloneDXReport.model_validate(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial}
    )
    return model


class TestAMaskedSerialNumber:
    def test_the_serial_still_matches_its_pattern(self):
        assert re.search(_serial_pattern(), SERIAL)
        model = _results(SERIAL)

        mask_secrets_in_results(model)

        assert re.search(_serial_pattern(), model.cyclonedx.serialNumber)
        assert model.cyclonedx.serialNumber == "urn:uuid:" + _SYNTHETIC_GUID

    def test_the_masked_sbom_passes_model_validate(self):
        model = _results(SERIAL)

        mask_secrets_in_results(model)

        dumped = model.cyclonedx.model_dump_json(by_alias=True, exclude_none=True)
        CycloneDXReport.model_validate(json.loads(dumped))
        AshAggregatedResults.model_validate_json(model.model_dump_json())

    def test_the_exposed_value_is_still_masked(self):
        model = _results(SERIAL)

        mask_secrets_in_results(model)

        assert VALUE not in model.cyclonedx.model_dump_json(by_alias=True)
        assert VALUE not in model.model_dump_json()

    def test_a_serial_that_holds_nothing_exposed_is_kept(self):
        """Control: only a masked serial is replaced."""
        model = _results(OTHER_SERIAL)

        mask_secrets_in_results(model)

        assert model.cyclonedx.serialNumber == OTHER_SERIAL
