# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression with a blank rule_id recorded in a results file loads, and never applies.

A blank ``rule_id`` is refused in a configuration since ``validate_rule_id_not_blank``,
but an earlier version accepted one, and a results file records the config its scan ran
with. The refusal applied whatever the context, and ``validate_ash_config`` re-raises any
refusal that is not an unreadable environment reference, so ``ash report``, ``ash merge``,
``--existing-results`` and the MCP readers refused the WHOLE file for one such entry.
Under TOLERATE_STORED_CONFIG the entry is kept with a note, like an unreadable
expiration, and ``matches`` never applies it: a blank rule id once covered every rule in
its path, and it is not "any rule" now either. A config file is still refused.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import BLANK_RULE_ID_NOTE, AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

REPO_RESULTS = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "outputs"
    / "ash_aggregated_results.json"
)


def _stored(blank):
    return {"path": "app.py", "reason": "r", "rule_id": blank}


def _finding(rule_id="B101"):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path="app.py",
        line_start=3,
    )


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_recorded_blank_rule_id_is_kept_with_a_note(blank):
    notes: list[str] = []

    kept = AshSuppression.model_validate(
        _stored(blank), context={TOLERATE_STORED_CONFIG: notes}
    )

    assert kept.rule_id == blank
    assert notes == [BLANK_RULE_ID_NOTE], notes


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("finding_rule", ["B101", None])
def test_a_kept_blank_rule_id_never_applies(blank, finding_rule):
    kept = AshSuppression.model_validate(
        _stored(blank), context={TOLERATE_STORED_CONFIG: []}
    )

    assert kept.matches(_finding(finding_rule), symbol_resolver=None) is False


def test_a_kept_entry_with_a_rule_id_still_applies():
    """The control: the tolerance leaves an entry that names a rule alone."""
    kept = AshSuppression.model_validate(
        _stored("B101"), context={TOLERATE_STORED_CONFIG: []}
    )

    assert kept.matches(_finding(), symbol_resolver=None) is True


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_config_file_still_refuses_a_blank_rule_id(blank):
    with pytest.raises(ValidationError, match="rule_id must be omitted"):
        AshSuppression.model_validate(_stored(blank))


def test_a_results_file_with_a_blank_rule_id_loads_and_warns():
    data = json.loads(REPO_RESULTS.read_text(encoding="utf-8"))
    data["ash_config"]["global_settings"]["suppressions"] = [_stored("")]

    with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
        results = AshAggregatedResults.model_validate_json(json.dumps(data))

    kept = results.ash_config.global_settings.suppressions
    assert [entry.rule_id for entry in kept] == [""], kept
    warnings = [str(call.args[0]) for call in log.warning.call_args_list]
    assert len(warnings) == 1, warnings
    assert BLANK_RULE_ID_NOTE in warnings[0], warnings
