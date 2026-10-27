# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``config validate --help`` names every scan input that lifts the no-file case.

With no config file, validate exits 1 only when none of the scan's other
inputs is given; --config-overrides and ASH_PLUGIN_MODULES each lift that
(measured: with the variable set and no file, a findable module exits 0 and an
absent one exits 3). The help's exit-code paragraph has to name both, or an
operator reads "no --config-overrides given" and cannot explain the 0 or the 3
the variable produced.
"""

from __future__ import annotations

from typer.testing import CliRunner

from automated_security_helper.cli.main import app


def test_the_help_names_the_environment_module_input():
    result = CliRunner().invoke(
        app, ["config", "validate", "--help"], env={"NO_COLOR": "1"}
    )

    assert result.exit_code == 0, result.output
    # The control: the clause it belongs to is there.
    assert "--config-overrides" in result.output, result.output
    assert "ASH_PLUGIN_MODULES" in result.output, result.output
    # The refusal clause itself, not a bare digit a usage line satisfies.
    squeezed = "".join(result.output.split())
    assert "exiting3when" in squeezed, result.output
