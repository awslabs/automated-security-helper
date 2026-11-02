# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SARIF reporter writes a document for a model with no SARIF and for a log
with no runs.

* ``model.sarif`` is Optional. The reporter called ``model_dump_json`` on it, so
  a results model whose SARIF was None raised AttributeError and ``ash.sarif``
  was not written; the other reporters treat the same model as empty.
* A converter's refusals are added to the first run. A log with no runs had
  nowhere to put them, so they were left out and nothing said so; such a log
  now carries one run of ASH's own with the invocations.
* That run carried ``results: []``, which SARIF 2.1.0 3.14.23 reads as "the
  tool ran and found nothing"; a consumer that closes open alerts on a
  zero-result analysis would act on it. The run exists because no scan produced
  a run, so it carries no ``results`` array at all.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return SarifReporter(context=test_plugin_context)


def _model_with_a_refusal() -> AshAggregatedResults:
    # The refusal names the extraction limit it exceeded. The invocation is marked
    # unsuccessful only for a refusal that leaves its input unscanned, which is a
    # refusal with a limit (or an unaccepted failed input); a refusal without one
    # is reported as a record and leaves executionSuccessful true.
    model = AshAggregatedResults()
    model.converter_results = {
        "archive": ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(
                    path="lib/bundle.zip",
                    member="bundle.zip",
                    reason="too large",
                    limit="max_total_bytes",
                )
            ]
        )
    }
    return model


def test_a_model_without_sarif_is_written_as_a_log_with_no_runs(reporter):
    model = AshAggregatedResults()
    model.sarif = None

    doc = json.loads(reporter.report(model))

    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["runs"] == []


def test_refusals_get_a_run_of_ashs_own_when_the_log_has_none(reporter):
    model = _model_with_a_refusal()
    model.sarif = SarifReport(version="2.1.0", runs=[])

    doc = json.loads(reporter.report(model))

    (run,) = doc["runs"]
    # No results array: an empty one would say the scan ran and found nothing.
    assert "results" not in run
    assert "Automated Security Helper" in run["tool"]["driver"]["name"]
    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is False
    texts = [
        notification["message"]["text"]
        for notification in invocation["toolExecutionNotifications"]
    ]
    assert any("bundle.zip" in text for text in texts), texts


def test_refusals_without_sarif_at_all_are_carried_the_same_way(reporter):
    model = _model_with_a_refusal()
    model.sarif = None

    doc = json.loads(reporter.report(model))

    (run,) = doc["runs"]
    assert run["invocations"][0]["executionSuccessful"] is False
