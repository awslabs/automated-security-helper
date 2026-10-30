# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed input a suppression accepted is reported as reviewed, not as an
incomplete scan.

The completeness gate (``incomplete_converters``) leaves out a failed-input
record that an ``ash-unconverted-input`` suppression accepted (``waives_gate``:
accepted, and of kind "input"). The reports read the same records through
``converter_refusals`` and used to mark every failed input scan-incomplete: a red
"Not scanned (scan incomplete)" console line, a SARIF notification at level
error and an invocation marked unsuccessful, for a loss the operator had
reviewed and the gate had passed. The reports now agree with the gate, and the
record says which suppression accepted it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
)
from automated_security_helper.utils.converter_refusals import (
    ConverterRefusal,
    converter_refusals,
    markdown_summary_lines,
    summary_lines,
)

pytestmark = pytest.mark.unit

ACCEPTED = FailedInputInfo(
    path="fixtures/not-a-notebook.ipynb",
    reason="not a Jupyter notebook: it is not JSON",
    kind="input",
    accepted=True,
    accepted_reason="a fixture kept on purpose",
)
NOT_ACCEPTED = FailedInputInfo(
    path="notebooks/real.ipynb", reason="nbconvert exited with code 1"
)
#: A record a shard from another producer could carry: accepted, of a kind the
#: writer never accepts. The gate counts it, so the reports count it too.
ACCEPTED_TOOL = FailedInputInfo(
    path="odd.ipynb", reason="nbconvert exited with code 1", accepted=True
)


def _model(*failed: FailedInputInfo) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results["jupyter"] = ConverterStatusInfo(
        converted_paths=[], failed_inputs=list(failed)
    )
    return model


def _context() -> PluginContext:
    return PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )


def test_an_accepted_failed_input_is_not_scan_incomplete():
    refusals = converter_refusals(_model(ACCEPTED, NOT_ACCEPTED, ACCEPTED_TOOL))

    by_path = {r.path: r for r in refusals}
    assert by_path[ACCEPTED.path].scan_incomplete is False
    assert by_path[ACCEPTED.path].accepted is True
    assert by_path[NOT_ACCEPTED.path].scan_incomplete is True
    assert by_path[ACCEPTED_TOOL.path].scan_incomplete is True
    # The incomplete ones are listed first, as before.
    assert [r.path for r in refusals][-1] == ACCEPTED.path


def test_the_message_names_the_accepting_suppression():
    (refusal,) = converter_refusals(_model(ACCEPTED))

    assert refusal.message() == (
        "jupyter: 'fixtures/not-a-notebook.ipynb' was not scanned: not a Jupyter "
        "notebook: it is not JSON (accepted by a suppression: a fixture kept on "
        "purpose)"
    )
    assert not summary_lines([refusal])[0].startswith("[scan incomplete]")
    assert "scan incomplete" not in markdown_summary_lines([refusal])[0]


def test_an_acceptance_with_no_stored_reason_names_no_reason():
    """The message names the acceptance alone, never the word "None", and the
    flat row carries the reason field as null."""
    refusal = ConverterRefusal(
        converter="archive",
        path="lib/b.zip",
        member=None,
        reason="it is named as a zip but could not be read as one",
        failed=True,
        accepted=True,
    )

    assert refusal.message().endswith(
        "could not be read as one (accepted by a suppression)"
    )
    assert "None" not in refusal.message()
    assert refusal.to_dict()["accepted_reason"] is None


def test_the_flat_json_carries_the_reason_of_an_acceptance():
    data = json.loads(FlatJSONReporter(context=_context()).report(_model(ACCEPTED)))

    (row,) = data["converter_refusals"]
    assert row["accepted_reason"] == "a fixture kept on purpose"


def test_the_flat_json_carries_the_acceptance():
    data = json.loads(FlatJSONReporter(context=_context()).report(_model(ACCEPTED)))

    (row,) = data["converter_refusals"]
    assert row["scan_incomplete"] is False
    assert row["accepted"] is True


def test_the_sarif_notification_is_a_warning_and_the_invocation_succeeded():
    doc = json.loads(SarifReporter(context=_context()).report(_model(ACCEPTED)))

    invocations = [
        invocation
        for run in doc["runs"]
        for invocation in run.get("invocations") or []
        if (invocation.get("properties") or {}).get("ash_converter") == "jupyter"
    ]
    (invocation,) = invocations
    assert invocation["executionSuccessful"] is True
    (note,) = invocation["toolExecutionNotifications"]
    assert note["level"] == "warning"


def test_a_failed_input_no_suppression_accepted_still_fails_the_invocation():
    """The control: the SARIF shape of an unaccepted failure is unchanged."""
    doc = json.loads(SarifReporter(context=_context()).report(_model(NOT_ACCEPTED)))

    invocations = [
        invocation
        for run in doc["runs"]
        for invocation in run.get("invocations") or []
        if (invocation.get("properties") or {}).get("ash_converter") == "jupyter"
    ]
    (invocation,) = invocations
    assert invocation["executionSuccessful"] is False
    (note,) = invocation["toolExecutionNotifications"]
    assert note["level"] == "error"
