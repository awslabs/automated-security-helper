# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file whose metadata records ``project_name`` as null loads.

``ReportMetadata.project_name`` is optional, so a null in the file reaches the
field's validator as None, and the validator called ``.strip()`` on it: a raw
AttributeError out of ``load_model`` instead of the model's own outcome.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import ReportMetadata

pytestmark = pytest.mark.unit


def test_a_null_project_name_loads_as_none():
    # The contract is "loads": a results file with a null project_name must
    # stay readable, so a refusal here would be a regression, not an outcome.
    metadata = ReportMetadata.model_validate({"project_name": None})

    assert metadata.project_name is None


def test_a_blank_project_name_is_still_refused():
    with pytest.raises(ValidationError):
        ReportMetadata.model_validate({"project_name": "   "})


def test_a_named_project_is_still_stripped():
    assert (
        ReportMetadata.model_validate({"project_name": " app "}).project_name == "app"
    )
