# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` and an off-host plugin reporter that declares no destination options.

A reporter that sets ``sends_off_host`` sends findings to a remote service with the
host's credentials. When it declares no ``destination_options`` there is no list of
which of its options say where, so ``ash report`` cannot confine them one by one:
its whole section is the operator's, taken from the defaults and
``--config-overrides`` (``config/reporter_trust``). A ``--config`` file outside
every tree may still be the scanned tree's own, so it neither enables such a
reporter nor supplies its options.

The stand-in reporter lives in a package written outside every scanned tree and is
registered the way a third-party plugin is, by ``@ash_reporter_plugin`` when the
command imports the package (``off_host_plugin_support``). The command runs in a
subprocess, because importing a plugin package registers its plugins for the rest
of the process. The reporter's ``report`` returns the options it was built with and
sends nothing.
"""

from __future__ import annotations

import pytest

from tests.unit.cli.off_host_plugin_support import (
    DEFAULT_ENDPOINT,
    FILE_ENDPOINT,
    OVERRIDE_ENDPOINT,
    REPORTER,
    run_report,
)

pytestmark = pytest.mark.integration


def test_a_config_file_cannot_enable_it_or_supply_its_options(tmp_path, plugin_site):
    result = run_report(tmp_path, plugin_site, [])

    assert result["exit"] == 1, result["output"]
    # Exit 1 alone would also be any other failure of the command: the refusal is
    # the one that says the reporter sends findings off the host and is not enabled.
    printed = " ".join(result["output"].split())
    assert "sends findings off the host and is not enabled" in printed, printed
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]


def test_an_override_that_enables_it_gives_it_the_overrides_options_alone(
    tmp_path, plugin_site
):
    result = run_report(tmp_path, plugin_site, [f"reporters.{REPORTER}.enabled=true"])

    assert result["exit"] == 0, result["output"]
    assert DEFAULT_ENDPOINT in result["output"], result["output"]
    assert "default title" in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]


def test_an_override_that_aims_it_is_used(tmp_path, plugin_site):
    result = run_report(
        tmp_path,
        plugin_site,
        [
            f"reporters.{REPORTER}.enabled=true",
            f"reporters.{REPORTER}.options.endpoint={OVERRIDE_ENDPOINT}",
        ],
    )

    assert result["exit"] == 0, result["output"]
    assert OVERRIDE_ENDPOINT in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]
