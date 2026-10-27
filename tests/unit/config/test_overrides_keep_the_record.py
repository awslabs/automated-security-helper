# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configuration with ``--config-overrides`` applied still records each value
its files read from the environment as the reference they wrote.

apply_config_overrides rebuilds the configuration from a dump with the
overrides in it, and a rebuilt model starts without the private state its load
recorded (which values were read from the environment, and how each was
written). The rebuild carries that state over. This is the case that needs it:
the ASH_CONFIG file read with overrides, as ``ash scan --config-overrides``
reads it when the scanned tree has no configuration of its own.
"""

from __future__ import annotations

import re

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

CANARY = "ash-canary-7f3e-0123456789"
REFERENCE = "${ASH_PROBE_VALUE}"


def _shows_the_value(text: str) -> bool:
    squeezed = re.sub(r"[\s─-╿]", "", text)
    return CANARY in squeezed or CANARY[:12] in squeezed


def test_the_ash_config_file_with_overrides_records_each_reference(
    tmp_path, monkeypatch
):
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"project_name: {REFERENCE}\n"
        "reporters:\n"
        "  gitlab-cyclonedx:\n"
        "    options:\n"
        f"      language_override: {REFERENCE}\n",
        encoding="utf-8",
    )
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)

    config = resolve_config(
        None, source_dir=source, config_overrides=["fail_on_findings=false"]
    )

    # The controls: the overrides were applied, and the run has the value.
    assert config.fail_on_findings is False
    read = config.project_name == CANARY
    assert read, "the configuration did not read the variable"
    recorded = AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    shown = _shows_the_value(recorded)
    assert not shown, "the record holds the value"
    assert recorded.count(REFERENCE) >= 2, "the record lost a reference"
