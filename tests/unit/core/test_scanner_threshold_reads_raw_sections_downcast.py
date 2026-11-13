# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The statistics threshold read of a raw section presents a plain str.

An external plugin's section is kept by the segment models as an extra and
never validated, so its ``options.severity_threshold`` is still the
resolver's marker (``EnvResolvedScalar``, a str subclass) when
``get_scanner_threshold_info`` reads the raw dict. The calculator is a
non-validating consumer, so it takes the downcast view at the read: the
threshold it returns into the summary statistics is the type the file gave
-- a str -- and never this module's marker class, whatever a later consumer
does with it (today ``ScannerMetrics``'s str field would downcast; this pin
does not lean on that boundary staying where it is).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

VARIABLE = "ASH_F35_SEV"


def _config_with_external_scanner(threshold_value):
    return AshConfig.model_validate(
        {
            "project_name": "zz-threshold",
            "scanners": {
                "zz-ext-scanner": {
                    "enabled": True,
                    "options": {"severity_threshold": threshold_value},
                }
            },
        }
    )


def _threshold_for(config):
    model = SimpleNamespace(ash_config=config)
    return ScannerStatisticsCalculator.get_scanner_threshold_info(
        model, "zz-ext-scanner"
    )


def test_an_env_read_threshold_returns_as_a_plain_str():
    config = _config_with_external_scanner(env_resolved_scalar("MEDIUM", VARIABLE))
    # The premise: the raw section still holds the marker when the
    # calculator reads it.
    entry = config.get_plugin_config(
        plugin_type="scanner", plugin_name="zz-ext-scanner"
    )
    assert type(entry["options"]["severity_threshold"]).__name__ == "EnvResolvedScalar"

    threshold, source = _threshold_for(config)

    assert (threshold, source) == ("MEDIUM", "config")
    assert type(threshold) is str, type(threshold).__name__


def test_a_file_written_threshold_flows_unchanged():
    threshold, source = _threshold_for(_config_with_external_scanner("HIGH"))
    assert (threshold, source) == ("HIGH", "config")
    assert type(threshold) is str


def test_an_unset_threshold_still_falls_to_the_global_rule():
    threshold, source = _threshold_for(_config_with_external_scanner(None))
    assert source == "global"
    assert type(threshold) is str
