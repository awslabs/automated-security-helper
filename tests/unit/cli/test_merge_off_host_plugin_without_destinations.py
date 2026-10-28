# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge`` and an off-host plugin reporter that declares no destination options.

A reporter that sets ``sends_off_host`` sends the merged findings to a remote
service with the host's credentials. When it declares no ``destination_options``
there is no list of which of its options say where, so the whole of its section is
the operator's: the defaults and ``--config-overrides``, nothing from a file
(``config/reporter_trust``). The shards do not record which tree was scanned, so a
``--config`` file outside every tree may still be the scanned tree's own, and
``ash merge`` holds it to the same rule as ``ash report`` does: it neither enables
such a reporter nor supplies its options.

The stand-in reporter is the one the ``ash report`` tests use
(``off_host_plugin_support``): a package written outside every scanned tree and
registered by ``@ash_reporter_plugin`` when the command imports it. The command runs
in a subprocess, because importing a plugin package registers its plugins for the
rest of the process. The reporter's ``report`` returns the options it was built with
and sends nothing; ``ash merge`` writes that text to a file in ``reports/``, so the
files there show whether the reporter ran and with which options.
"""

from __future__ import annotations

import json

from automated_security_helper.config.untrusted_source import MERGE_CONFIG_FILE
from tests.unit.cli.off_host_plugin_support import (
    DEFAULT_ENDPOINT,
    FILE_ENDPOINT,
    OVERRIDE_ENDPOINT,
    REPORTER,
    reporter_texts,
    run_merge,
)


def test_a_config_file_cannot_enable_it_or_supply_its_options(tmp_path, plugin_site):
    result = run_merge(tmp_path, plugin_site, [])

    assert "Traceback" not in result["output"], result["output"]
    assert reporter_texts(result) == [], result["reports"]
    assert FILE_ENDPOINT not in json.dumps(result["reports"]), result["reports"]
    # The merge ran to the end (exit 2 is a merge that found something) and wrote
    # its local reports: a merge that stopped early would also leave the stand-in's
    # text out. And it held the file to the rule, saying why.
    assert result["exit"] in (0, 2), result["output"]
    assert result["reports"], result["output"]
    reason = " ".join(MERGE_CONFIG_FILE.reason.split())
    assert any(
        f"reporters.{REPORTER}" in warning and reason in " ".join(warning.split())
        for warning in result["warnings"]
    ), result["warnings"]


def test_an_override_that_enables_it_gives_it_the_overrides_options_alone(
    tmp_path, plugin_site
):
    result = run_merge(tmp_path, plugin_site, [f"reporters.{REPORTER}.enabled=true"])

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert DEFAULT_ENDPOINT in written[0], written
    assert "default title" in written[0], written
    assert FILE_ENDPOINT not in written[0], written
    assert "file title" not in written[0], written


def test_an_override_that_aims_it_is_used(tmp_path, plugin_site):
    result = run_merge(
        tmp_path,
        plugin_site,
        [
            f"reporters.{REPORTER}.enabled=true",
            f"reporters.{REPORTER}.options.endpoint={OVERRIDE_ENDPOINT}",
        ],
    )

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert OVERRIDE_ENDPOINT in written[0], written
    assert FILE_ENDPOINT not in written[0], written
    assert "file title" not in written[0], written
