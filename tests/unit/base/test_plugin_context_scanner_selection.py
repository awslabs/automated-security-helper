# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner selection a run's engine records on its plugin context.

A converter runs before the scan phase and is handed only the context, so it
cannot see the selection the scan phase is given as arguments. The engine records
the selection on the context (``record_scanner_selection``), and a converter that
needs to know which scanners will read its output reads it there
(``scanner_selection``). It is per-run state like the context's other private
records: in no dump and no schema.
"""

import pytest

from automated_security_helper.base.plugin_context import (
    PluginContext,
    ScannerSelection,
)

pytestmark = pytest.mark.unit


def test_a_context_no_engine_ran_has_no_scanner_selection(
    plugin_context: PluginContext,
) -> None:
    """None, not an empty selection: no selection is known, so none narrows."""
    assert plugin_context.scanner_selection is None


def test_a_recorded_selection_is_read_back_as_given(
    plugin_context: PluginContext,
) -> None:
    enabled = ["bandit"]
    excluded = ["grype"]

    plugin_context.record_scanner_selection(
        enabled=enabled, excluded=excluded, python_only=True
    )
    # The record holds its own copies: the caller's lists can change after it.
    enabled.append("trivy")
    excluded.clear()

    assert plugin_context.scanner_selection == ScannerSelection(
        enabled=("bandit",), excluded=("grype",), python_only=True
    )


def test_the_selection_is_in_no_dump_and_no_schema(
    plugin_context: PluginContext,
) -> None:
    """A private attribute, not a model field: the schema is built from the
    fields, and a dump writes only those."""
    plugin_context.record_scanner_selection(enabled=["bandit"], excluded=["grype"])

    dumped = plugin_context.model_dump()
    assert "scanner_selection" not in dumped
    assert "_scanner_selection" not in dumped
    assert "scanner_selection" not in PluginContext.model_fields
    assert "_scanner_selection" in PluginContext.__private_attributes__
