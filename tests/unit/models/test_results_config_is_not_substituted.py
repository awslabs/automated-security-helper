# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file's ``ash_config`` is what the scan recorded, never a substitute.

``AshAggregatedResults.validate_ash_config`` answered a results file that records no
configuration (``"ash_config": null``) with ``get_default_config()``: the built-in
defaults, or the file ``ASH_CONFIG`` names in the process that re-renders the
results. So ``ash report`` and the MCP results tools presented a configuration the
scan never ran with as the scan's own. No configuration recorded now stays None,
and a value that is not a valid configuration is refused, as before.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def test_no_recorded_config_stays_none(tmp_path, monkeypatch):
    operator = tmp_path / "operator.yaml"
    operator.write_text("project_name: from-ash-config\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    model = AshAggregatedResults.model_validate_json('{"ash_config": null}')

    assert model.ash_config is None


def test_a_recorded_config_is_kept(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    model = AshAggregatedResults.model_validate_json(
        '{"ash_config": {"project_name": "recorded"}}'
    )

    assert model.ash_config.project_name == "recorded"


def test_control_a_recorded_config_that_does_not_validate_is_refused(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    with pytest.raises(ValidationError):
        AshAggregatedResults.model_validate_json(
            '{"ash_config": {"global_settings": 7}}'
        )
