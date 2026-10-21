# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal for a ferret-scan suppression option names where ASH reads suppressions.

The messages pointed users at ``.ash/suppressions.yaml`` and at
``ash inspect suppressions``. ASH reads no such file and has no such command:
suppressions are the ``suppressions`` list under ``global_settings`` in the ASH
config file.
"""

import pytest

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    UNSUPPORTED_FERRET_OPTIONS,
    FerretScannerConfigOptions,
)

SUPPRESSION_OPTIONS = ["generate_suppressions", "suppressions_file", "show_suppressed"]


@pytest.mark.parametrize("option", SUPPRESSION_OPTIONS)
def test_the_message_names_no_file_or_command_ash_lacks(option):
    message = UNSUPPORTED_FERRET_OPTIONS[option]
    assert "suppressions.yaml" not in message, message
    assert "ash inspect suppressions" not in message, message


@pytest.mark.parametrize("option", ["generate_suppressions", "suppressions_file"])
def test_the_message_points_at_the_config_suppressions(option):
    assert "global_settings.suppressions" in UNSUPPORTED_FERRET_OPTIONS[option]


@pytest.mark.parametrize("option", SUPPRESSION_OPTIONS)
def test_the_config_refusal_carries_the_message(option):
    with pytest.raises(ValueError) as caught:
        FerretScannerConfigOptions.model_validate({option: True})
    assert UNSUPPORTED_FERRET_OPTIONS[option] in str(caught.value)
