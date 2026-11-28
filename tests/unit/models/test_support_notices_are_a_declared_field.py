"""``metadata.support_notices`` is a declared field, left out of what a supported run writes.

Why this exists
---------------
A run on a configuration ASH supports only through a polyfill, with a loss, or not at
all records what it met in ``metadata.support_notices``, each notice with the upgrade
paths on offer. The field is declared, so the committed schema documents it and a
results file holding a malformed value is refused, and it is absent while empty:
never written as an empty list or as null. That keeps the results of a run on a
fully supported configuration byte for byte what they were before the field existed.

This file pins that contract in the three places the tests of ``suppressions_ignored``
pin the same shape: the model dump, the writer the engine uses, and the committed
schema. It also pins what a notice looks like when it is written, because the
reporters and every reader of a results file depend on those keys.
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
from tests.unit.models._support_notice_helpers import (
    CPU_ID,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

NOTICE_KEYS = [
    "id",
    "scope",
    "dimension",
    "level",
    "behavior",
    "message",
    "polyfill",
    "found",
    "facts",
    "raised",
    "docs",
    "paths",
]
PATH_KEYS = ["id", "group", "kind", "summary", "docs"]


def test_the_field_is_declared_with_no_value_by_default():
    assert "support_notices" in ReportMetadata.model_fields
    assert ReportMetadata().support_notices is None


def test_a_supported_run_writes_nothing_for_it():
    """The control of the contract: no notice, no key, and not a null either."""
    dumped = ReportMetadata().model_dump(mode="json")

    assert "support_notices" not in dumped, sorted(dumped)


def test_an_empty_list_writes_nothing_either():
    """A writer that sets the field to nothing must not change what is written."""
    metadata = ReportMetadata()
    metadata.support_notices = []

    assert "support_notices" not in metadata.model_dump(mode="json")


def test_recorded_notices_are_written_with_the_keys_readers_depend_on():
    metadata = ReportMetadata()
    metadata.support_notices = [cpu_notice(), sandbox_notice(), polyfill_notice()]

    dumped = metadata.model_dump(mode="json")["support_notices"]

    assert [notice["id"] for notice in dumped] == [CPU_ID, SANDBOX_ID, POLYFILL_ID]
    assert all(list(notice) == NOTICE_KEYS for notice in dumped)
    assert all(list(path) == PATH_KEYS for path in dumped[0]["paths"])
    # The built command stays on the terminal: no key of a notice or a path holds one.
    assert "command" not in json.dumps(dumped)


def test_recorded_notices_are_read_back_equal():
    metadata = ReportMetadata()
    metadata.support_notices = [cpu_notice(), sandbox_notice(), polyfill_notice()]

    dumped = metadata.model_dump(mode="json")

    assert (
        ReportMetadata.model_validate(dumped).support_notices
        == metadata.support_notices
    )


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("unsupported", id="a string"),
        pytest.param({"id": CPU_ID}, id="a record"),
        pytest.param([1], id="a number"),
        pytest.param([{"id": CPU_ID}], id="a record missing keys"),
        pytest.param(
            [{**cpu_notice().model_dump(mode="json"), "level": "supported"}],
            id="a level that is no notice",
        ),
    ],
)
def test_a_results_file_with_a_malformed_value_is_refused(value):
    """A list of whole notices is the only answer the field takes; an extra key took
    any of these."""
    with pytest.raises(ValidationError):
        ReportMetadata.model_validate({"support_notices": value})


def _saved_metadata(directory: Path) -> dict:
    return json.loads(
        (directory / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )["metadata"]


def test_a_normal_run_saves_no_key_for_it(tmp_path):
    """Through the writer the engine uses, not the model dump alone."""
    AshAggregatedResults().save_model(tmp_path)

    assert "support_notices" not in _saved_metadata(tmp_path)


def test_saved_notices_survive_a_report_only_run(tmp_path):
    """A file saved by a run that met notices, loaded and saved again by one that
    does not evaluate anything, still says what the first run met."""
    model = AshAggregatedResults()
    model.metadata.support_notices = [cpu_notice(), polyfill_notice()]
    model.save_model(tmp_path)
    saved = _saved_metadata(tmp_path)["support_notices"]
    assert [notice["id"] for notice in saved] == [CPU_ID, POLYFILL_ID]

    loaded = AshAggregatedResults.load_model(tmp_path / "ash_aggregated_results.json")
    assert loaded is not None
    assert loaded.metadata.support_notices == model.metadata.support_notices
    again = tmp_path / "again"
    again.mkdir()
    loaded.save_model(again)

    assert _saved_metadata(again)["support_notices"] == saved


def test_a_set_field_travels_in_the_off_host_send_and_an_unset_one_does_not():
    """The CloudWatch Logs and S3 reporters send ``metadata_only()``, which dumps the
    fields that were set."""
    results = AshAggregatedResults()
    assert "support_notices" not in results.metadata_only()

    results.metadata.support_notices = [cpu_notice()]
    sent = results.metadata_only()["support_notices"]

    assert [notice["id"] for notice in sent] == [CPU_ID]


def _committed_schema() -> dict:
    """Read from the package the code is imported from, and parsed: a name in a
    description would not count, only a property of the model."""
    schema_file = Path(automated_security_helper.__file__).parent.joinpath(
        "schemas", "AshAggregatedResults.json"
    )
    return json.loads(schema_file.read_text(encoding="utf-8"))


def test_the_field_and_both_records_are_declared_in_the_committed_schema():
    schema = _committed_schema()

    properties = schema["$defs"]["ReportMetadata"]["properties"]
    assert "support_notices" in properties, sorted(properties)
    assert set(schema["$defs"]["SupportNotice"]["properties"]) == set(NOTICE_KEYS)
    assert set(schema["$defs"]["UpgradePathNotice"]["properties"]) == set(PATH_KEYS)
