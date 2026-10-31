# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scanner details ASH writes on a run's tool component are masked by value.

A run's tool components are rule metadata and are skipped by the value masking,
but ASH writes the scanner's invocation (command line, arguments) into their
``properties.scanner_details``, so a value that appeared on the command line
stayed in the results.

The value here is derived at import time; it is not a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("u27-plain-value", 12)
NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _results_with_tool_details(details):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bandit",
                            "properties": {"scanner_details": details},
                        }
                    },
                    "results": [
                        {
                            "ruleId": "B105",
                            "level": "warning",
                            "message": {"text": HARDCODED + f"'{VALUE}'"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 2, "endLine": 2},
                                    }
                                }
                            ],
                            "properties": {
                                "scanner_name": "bandit",
                                "tags": ["bandit"],
                            },
                        }
                    ],
                }
            ],
        }
    )
    return model


class TestScannerDetailsUnderTheTool:
    def test_a_value_on_the_tools_command_line_is_masked(self):
        model = _results_with_tool_details(
            {
                "tool_name": "bandit",
                "tool_invocation": {
                    "command_line": f"bandit --config {VALUE} -r .",
                    "arguments": ["--config", VALUE, "-r", "."],
                },
            }
        )

        mask_secrets_in_results(model)

        details = getattr(model.sarif.runs[0].tool.driver.properties, "scanner_details")
        masked = _mask_secret_value(VALUE)
        assert (
            details["tool_invocation"]["command_line"]
            == f"bandit --config {masked} -r ."
        )
        assert details["tool_invocation"]["arguments"] == [
            "--config",
            masked,
            "-r",
            ".",
        ]
        assert details["tool_name"] == "bandit"
