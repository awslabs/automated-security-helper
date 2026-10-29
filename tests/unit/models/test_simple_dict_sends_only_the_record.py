# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``to_simple_dict`` holds the configuration the results record, and only that.

The S3 and CloudWatch Logs reporters send this dict off the host. Were results
that record no configuration, or an empty one, given ASH's default
configuration in its place, that would be an AshConfig object rather than data,
which the reporters' ``json.dumps(default=str)`` prints as its repr, and one
loaded from the ASH_CONFIG file of the process sending it, values read from the
environment included: not the configuration the scan ran with.
"""

from __future__ import annotations

import json
import re

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"


def _shows_the_value(text: str) -> bool:
    squeezed = re.sub(r"[\s─-╿]", "", text)
    return CANARY in squeezed or CANARY[:12] in squeezed


@pytest.mark.parametrize(
    ("config", "sent"),
    [(None, None), (AshConfig(), {})],
    ids=["no-configuration", "nothing-set"],
)
def test_results_recording_no_settings_send_what_they_record(
    tmp_path, monkeypatch, config, sent
):
    operator = tmp_path / "operator.yaml"
    operator.write_text("project_name: ${ASH_PROBE_VALUE}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)

    simple = AshAggregatedResults(ash_config=config).to_simple_dict()

    recorded = simple["ash_config"] == sent
    assert recorded, (
        f"not what the results record: {type(simple['ash_config']).__name__}"
    )
    # Plain data: it serializes without a default= fallback.
    shown = _shows_the_value(json.dumps(simple))
    assert not shown, "the sent dict holds a value read from the environment"


def test_results_recording_a_configuration_send_its_record():
    """The control: a configuration that sets a field is sent as its record."""
    simple = AshAggregatedResults(
        ash_config=AshConfig(project_name="demo")
    ).to_simple_dict()
    assert simple["ash_config"] == {"project_name": "demo"}
