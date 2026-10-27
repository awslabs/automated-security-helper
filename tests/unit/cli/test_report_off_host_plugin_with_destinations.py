# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` and an off-host plugin reporter that declares its destination options.

A reporter that sets ``sends_off_host`` sends findings to a remote service with the
host's credentials. When it declares ``destination_options``, the options that say
where it sends are the operator's alone, and so is whether it runs: ``enabled``
comes from the defaults and ``--config-overrides`` (``config/reporter_trust``). A
``--config`` file outside every tree may still be the scanned tree's own, so it
neither enables such a reporter nor aims it. Its other options, here the title the
reporter prints, still apply from the file.

Two stand-ins (``off_host_plugin_support``) differ only in their own default for
``enabled``. The one that is off by default shows the file cannot turn it on. The
one that is on by default shows the same for a file that says ``enabled: true``,
which matches the reporter's own default and so must not be read as the operator's
word. The command runs in a subprocess, because importing a plugin package
registers its plugins for the rest of the process.
"""

from __future__ import annotations

from tests.unit.cli.off_host_plugin_support import (
    DECLARED_ON_PLUGIN,
    DECLARED_ON_REPORTER,
    DECLARED_PLUGIN,
    DECLARED_REPORTER,
    DEFAULT_ENDPOINT,
    FILE_ENDPOINT,
    OVERRIDE_ENDPOINT,
    run_report,
)

REFUSAL = "sends findings off the host and is not enabled"


def test_a_config_file_cannot_enable_or_aim_one_that_is_off_by_default(
    tmp_path, declared_site
):
    result = run_report(
        tmp_path,
        declared_site,
        [],
        plugin=DECLARED_PLUGIN,
        reporter=DECLARED_REPORTER,
    )

    assert result["exit"] == 1, result["output"]
    printed = " ".join(result["output"].split())
    assert REFUSAL in printed, printed
    assert FILE_ENDPOINT not in result["output"], result["output"]


def test_a_config_file_cannot_enable_or_aim_one_that_is_on_by_default(
    tmp_path, declared_on_site
):
    result = run_report(
        tmp_path,
        declared_on_site,
        [],
        plugin=DECLARED_ON_PLUGIN,
        reporter=DECLARED_ON_REPORTER,
    )

    assert result["exit"] == 1, result["output"]
    # Exit 1 alone would also be any other failure of the command: the refusal is
    # the one that says the reporter sends findings off the host and is not enabled.
    printed = " ".join(result["output"].split())
    assert REFUSAL in printed, printed
    assert DEFAULT_ENDPOINT not in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]


def test_an_override_that_enables_one_that_is_on_by_default_runs_it_at_the_default(
    tmp_path, declared_on_site
):
    result = run_report(
        tmp_path,
        declared_on_site,
        [f"reporters.{DECLARED_ON_REPORTER}.enabled=true"],
        plugin=DECLARED_ON_PLUGIN,
        reporter=DECLARED_ON_REPORTER,
    )

    assert result["exit"] == 0, result["output"]
    assert DEFAULT_ENDPOINT in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]
    # Not a destination option: the file's value applies, as it does for a scan.
    assert "file title" in result["output"], result["output"]


def test_an_override_that_aims_one_that_is_on_by_default_is_used(
    tmp_path, declared_on_site
):
    result = run_report(
        tmp_path,
        declared_on_site,
        [
            f"reporters.{DECLARED_ON_REPORTER}.enabled=true",
            f"reporters.{DECLARED_ON_REPORTER}.options.endpoint={OVERRIDE_ENDPOINT}",
        ],
        plugin=DECLARED_ON_PLUGIN,
        reporter=DECLARED_ON_REPORTER,
    )

    assert result["exit"] == 0, result["output"]
    assert OVERRIDE_ENDPOINT in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]


def test_an_override_that_turns_one_that_is_on_by_default_off_wins_over_the_file(
    tmp_path, declared_on_site
):
    result = run_report(
        tmp_path,
        declared_on_site,
        [f"reporters.{DECLARED_ON_REPORTER}.enabled=false"],
        plugin=DECLARED_ON_PLUGIN,
        reporter=DECLARED_ON_REPORTER,
    )

    assert result["exit"] == 1, result["output"]
    printed = " ".join(result["output"].split())
    assert REFUSAL in printed, printed
