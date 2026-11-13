# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash.cdx.json`` is a valid CycloneDX document when no SBOM scanner ran.

Why this exists
---------------
The cyclonedx reporter dumps ``model.cyclonedx`` with ``exclude_unset=True``. When
no SBOM scanner contributed, that model is the default ``CycloneDXReport()``, none
of whose fields was ever set, so the dump was ``{}``: two bytes, without the
``bomFormat`` and ``specVersion`` the CycloneDX 1.6 JSON schema requires. A CI step
that uploads ``ash.cdx.json`` to an SBOM consumer then fails on a scan that simply
had no dependencies. ``ash report --format cyclonedx`` over the saved results gave a
third answer, because the results file stores the defaults explicitly: the envelope
fields, but no ``components``.

The expected document is the reporter's own model with the schema's required
fields and an empty ``components`` list. Validity is checked against the generated
``CycloneDXReport`` model (built from the 1.6 schema, ``extra="forbid"``) plus the
schema's two required properties, which that model alone does not enforce because
it gives both a default.

Known limitations
-----------------
* The official CycloneDX JSON schema is not in this repository, so it is not
  validated against here. The same document was validated against
  ``bom-1.6.schema.json`` with ``jsonschema`` when this test was written.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    CycloneDXReporter,
    CycloneDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

#: ``"required"`` at the top level of the CycloneDX 1.6 JSON schema.
SCHEMA_REQUIRED = ("bomFormat", "specVersion")

#: With no SBOM, the empty component list is not a claim that there are no
#: components: ``compositions`` says the inventory's completeness is unknown, so a
#: consumer does not read a scan whose SBOM scanner never ran (missing, skipped,
#: or failed) as a project with no dependencies.
EMPTY_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [],
    "compositions": [{"aggregate": "unknown"}],
}

FIXTURE_RESULTS = Path("tests/test_data/outputs/ash_aggregated_results.json")


@pytest.fixture
def reporter(tmp_path):
    context = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")
    return CycloneDXReporter(context=context, config=CycloneDXReporterConfig())


def _assert_valid_cyclonedx(document: dict) -> None:
    for key in SCHEMA_REQUIRED:
        assert key in document, f"{key} is required by the CycloneDX schema"
    assert document["bomFormat"] == "CycloneDX"
    # Every key must be one the 1.6 model knows, with a value of its type.
    CycloneDXReport.model_validate(document)


def test_no_sbom_scanner_gives_a_valid_empty_document(reporter):
    document = json.loads(reporter.report(AshAggregatedResults()))

    _assert_valid_cyclonedx(document)
    assert document == EMPTY_BOM


def test_reloaded_results_give_the_same_document(reporter):
    """``ash report`` re-renders from the results file; it must agree with the scan."""
    model = AshAggregatedResults()
    reloaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

    assert reporter.report(reloaded) == reporter.report(model)


def test_a_model_without_cyclonedx_gives_a_valid_empty_document(reporter):
    model = AshAggregatedResults()
    model.cyclonedx = None

    document = json.loads(reporter.report(model))

    _assert_valid_cyclonedx(document)
    assert document == EMPTY_BOM


def test_reporting_does_not_change_the_model(reporter):
    model = AshAggregatedResults()
    before = set(model.cyclonedx.model_fields_set)

    reporter.report(model)

    assert set(model.cyclonedx.model_fields_set) == before


def test_an_sbom_with_components_is_the_plain_dump(reporter):
    """The fallback must not touch a real SBOM: same bytes as the plain dump."""
    model = AshAggregatedResults.model_validate_json(
        FIXTURE_RESULTS.read_text(encoding="utf-8")
    )
    assert model.cyclonedx.components, "fixture must carry an SBOM"

    written = reporter.report(model)

    assert written == model.cyclonedx.model_dump_json(
        by_alias=True, exclude_unset=True, exclude_none=True
    )
    _assert_valid_cyclonedx(json.loads(written))


def test_an_sbom_that_lists_no_components_is_not_marked_unknown(reporter):
    """A scanner's own SBOM with nothing in it is written as the scanner said.

    Only the fallback says "unknown": an SBOM scanner that ran and produced a
    document (it carries metadata) made its own statement about completeness.
    """
    model = AshAggregatedResults()
    model.cyclonedx = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "metadata": {"timestamp": "2026-01-15T12:00:00Z"},
        }
    )

    document = json.loads(reporter.report(model))

    _assert_valid_cyclonedx(document)
    assert "compositions" not in document
    assert document["components"] == []


def test_gitlab_cyclonedx_fallback_is_valid_too(tmp_path):
    """The other CycloneDX reporter already had a fallback; pinned so both stay valid."""
    context = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")
    gitlab = GitLabCycloneDXReporter(
        context=context, config=GitLabCycloneDXReporterConfig()
    )

    for model in (
        AshAggregatedResults(),
        AshAggregatedResults.model_validate_json(
            AshAggregatedResults().model_dump_json()
        ),
    ):
        document = json.loads(gitlab.report(model))
        for key in SCHEMA_REQUIRED:
            assert key in document
        assert document["components"] == []
