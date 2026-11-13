# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A CycloneDX requirement's ``openCre`` list validates entry by entry.

The CycloneDX 1.6 schema puts the OpenCRE identifier pattern on each entry of
``Requirement.openCre``. The generated model put the pattern on the list field,
which pydantic cannot apply to a list: any BOM that carried ``openCre``, a valid
list and an empty list included, raised ``TypeError`` from inside validation
instead of validating, and the TypeError's text quoted the values. The pattern
now sits on the entries, so a valid list validates and a bad entry is an
ordinary ``ValidationError`` at that entry.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import Requirement

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "identifiers",
    [[], ["CRE:123-456"], ["CRE:1-2", "CRE:764-507"]],
)
def test_a_valid_opencre_list_validates(identifiers):
    requirement = Requirement(identifier="ASVS-1.1", openCre=identifiers)
    assert requirement.openCre == identifiers


def test_a_bad_entry_is_a_validation_error_at_that_entry():
    with pytest.raises(ValidationError) as caught:
        Requirement(identifier="ASVS-1.1", openCre=["CRE:1-2", "not-a-cre"])
    (error,) = caught.value.errors()
    assert error["loc"] == ("openCre", 1)
    assert error["type"] == "string_pattern_mismatch"


def test_the_results_schema_puts_the_pattern_on_each_entry():
    open_cre = Requirement.model_json_schema()["properties"]["openCre"]
    (array,) = [branch for branch in open_cre["anyOf"] if branch.get("type") == "array"]
    assert array["items"]["pattern"] == "^CRE:[0-9]+-[0-9]+$"
    assert "pattern" not in array
