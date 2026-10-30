# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``metadata.suppressions_ignored`` is a declared field, not an extra key.

Why this exists
---------------
The engine records a run under ``--ignore-suppressions`` by assigning
``metadata.suppressions_ignored = True``, and the unused-suppressions reporter
reads it back off a saved results file. Nothing declared the field: it rode on
``ReportMetadata``'s ``extra="allow"``, so the committed schema did not document
it, a results file carrying a non-boolean there loaded without complaint, and a
reader had no field to look up. Declared, it is documented, typed and refused
when malformed, while the engine's contract is kept: True when written, absent
from what a normal run writes (never False), so a saved record survives a
report-only run and an older results file reads as before.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ReportMetadata,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def test_the_flag_is_a_declared_field_with_no_value_by_default():
    assert "suppressions_ignored" in ReportMetadata.model_fields
    assert ReportMetadata().suppressions_ignored is None


def test_a_normal_record_writes_nothing_for_it():
    """The engine's control: a run that did not ignore suppressions records
    nothing, so the key is absent from what is written, not written False."""
    dumped = ReportMetadata().model_dump(mode="json")
    assert "suppressions_ignored" not in dumped, sorted(dumped)


def test_a_recorded_true_is_written_and_read_back():
    metadata = ReportMetadata()
    metadata.suppressions_ignored = True

    dumped = metadata.model_dump(mode="json")
    assert dumped["suppressions_ignored"] is True
    assert ReportMetadata.model_validate(dumped).suppressions_ignored is True


def test_a_results_file_with_a_malformed_value_is_refused():
    """A list is no answer to a yes-or-no question; an extra key took it."""
    with pytest.raises(ValidationError):
        ReportMetadata.model_validate({"suppressions_ignored": [True]})


def test_the_field_is_declared_in_the_committed_schema():
    repo_root = Path(__file__).resolve().parents[3]
    schema = (
        repo_root / "automated_security_helper/schemas/AshAggregatedResults.json"
    ).read_text(encoding="utf-8")
    assert '"suppressions_ignored"' in schema
