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


def test_a_null_project_name_is_not_an_attribute_error():
    try:
        metadata = ReportMetadata.model_validate({"project_name": None})
    except ValidationError:
        # The model's own refusal, if it ever chooses one, is an outcome a
        # caller can read; an AttributeError is not.
        return
    assert metadata.project_name is None


def test_a_blank_project_name_is_still_refused():
    with pytest.raises(ValidationError):
        ReportMetadata.model_validate({"project_name": "   "})


def test_a_named_project_is_still_stripped():
    assert (
        ReportMetadata.model_validate({"project_name": " app "}).project_name == "app"
    )
