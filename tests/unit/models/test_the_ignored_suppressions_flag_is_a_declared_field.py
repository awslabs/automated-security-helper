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

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import automated_security_helper
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


def _saved_metadata(directory: Path) -> dict:
    return json.loads(
        (directory / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )["metadata"]


def test_a_normal_run_saves_no_key_for_it(tmp_path):
    """Through the writer the engine uses, not the model dump alone."""
    AshAggregatedResults().save_model(tmp_path)

    assert "suppressions_ignored" not in _saved_metadata(tmp_path)


def test_a_saved_true_survives_a_report_only_run(tmp_path):
    """A file saved under --ignore-suppressions, loaded and saved again by a run
    that does not set the flag, still says True."""
    model = AshAggregatedResults()
    model.metadata.suppressions_ignored = True
    model.save_model(tmp_path)
    assert _saved_metadata(tmp_path)["suppressions_ignored"] is True

    loaded = AshAggregatedResults.load_model(tmp_path / "ash_aggregated_results.json")
    assert loaded is not None
    assert loaded.metadata.suppressions_ignored is True
    again = tmp_path / "again"
    again.mkdir()
    loaded.save_model(again)

    assert _saved_metadata(again)["suppressions_ignored"] is True


def test_the_field_is_declared_in_the_committed_schema():
    """Read from the package the code is imported from, and parsed: the name in
    a description would not count, only the property of the metadata model."""
    schema_file = Path(automated_security_helper.__file__).parent.joinpath(
        "schemas", "AshAggregatedResults.json"
    )
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    properties = schema["$defs"]["ReportMetadata"]["properties"]
    assert "suppressions_ignored" in properties, sorted(properties)
