"""The support-notices model shape, and which shapes record support notices.

``support-notices`` is the single-directory fixture scan of a host ASH supports only in
part: the ``single`` model with the support notices such a run records in its metadata
(``support_notices_fixture``). Every reporter is snapshotted against it in
test_snapshot_reporters.py and test_snapshot_reporters_aws.py, so what a reporter does
with the notices is a diff of the document a user opens.

Two facts those snapshots rest on are pinned here.

A run on a fully supported configuration records no notice and writes no key for them.
The other three shapes stand for such runs, so their snapshots are the ones ASH's
results had before the field existed. The first test holds each of them to that, and
holds the notices to the one shape that sets them.

The second fact is the results file. ``ash report``, ``ash merge`` and the MCP server
read ``ash_aggregated_results.json`` back, so the place the notices take in its
metadata is part of its contract. The second test snapshots that block as
``save_model`` writes it for a run that recorded notices.
"""

from __future__ import annotations

import json

import pytest

from tests.snapshot.support.fixture_model import finalize_fixture_model
from tests.snapshot.support.reporter_catalog import MODEL_VARIANTS

pytestmark = pytest.mark.unit

NOTICES_VARIANT = "support-notices"


@pytest.mark.parametrize("variant", MODEL_VARIANTS)
def test_only_the_support_notices_shape_records_notices(variant, fixture_variant):
    model, _ = fixture_variant(variant)

    metadata = model.model_dump(mode="json")["metadata"]

    if variant != NOTICES_VARIANT:
        assert "support_notices" not in metadata, sorted(metadata)
        return
    assert [notice["level"] for notice in metadata["support_notices"]] == [
        "unsupported",
        "degraded",
        "polyfilled",
    ]


def test_the_results_file_records_the_notices_in_its_metadata(
    fixture_variant, tmp_path, text_snapshot
):
    model, _ = fixture_variant(NOTICES_VARIANT)
    model = finalize_fixture_model(model)
    model.save_model(tmp_path / "final")

    written = json.loads(
        (tmp_path / "final" / "ash_aggregated_results.json").read_text("utf-8")
    )

    assert json.dumps(written["metadata"], indent=2) == text_snapshot("json")
