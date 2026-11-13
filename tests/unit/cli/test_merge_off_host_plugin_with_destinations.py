# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge`` and an off-host plugin reporter that declares its destination options.

A reporter that sets ``sends_off_host`` sends the merged findings to a remote
service with the host's credentials. When it declares ``destination_options``, the
options that say where it sends are the operator's alone, and so is whether it runs:
``enabled`` comes from the defaults and ``--config-overrides`` too, or from the
reporter's own default (``config/reporter_trust``). The shards do not record which
tree was scanned, so the operator's ``--config`` file may be that tree's own, and
``ash merge`` holds it to the same rule as ``ash report`` does. Its other options,
here the title the reporter prints, still apply from the file.

The stand-in is the one in ``off_host_plugin_support`` with
``destination_options = ("endpoint",)`` and ``enabled`` off by default, so its
``enabled`` is the one thing a file inside the tree could otherwise turn on. It is
written outside every scanned tree and registered by ``@ash_reporter_plugin`` when
the command imports it, and the command runs in a subprocess for the same reason as
there.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.config.untrusted_source import MERGE_CONFIG_FILE
from tests.unit.cli.off_host_plugin_support import (
    DECLARED_ON_PLUGIN,
    DECLARED_ON_REPORTER,
    DECLARED_PLUGIN,
    DECLARED_REPORTER,
    DEFAULT_ENDPOINT,
    FILE_ENDPOINT,
    OVERRIDE_ENDPOINT,
    reporter_texts,
    run_merge,
)

pytestmark = pytest.mark.integration


def _declared_merge(tmp_path: Path, site: Path, overrides: List[str]) -> Dict:
    return run_merge(
        tmp_path,
        site,
        overrides,
        plugin=DECLARED_PLUGIN,
        reporter=DECLARED_REPORTER,
    )


def test_a_config_file_cannot_enable_it_or_aim_it(tmp_path, declared_site):
    result = _declared_merge(tmp_path, declared_site, [])

    assert reporter_texts(result) == [], result["reports"]
    assert FILE_ENDPOINT not in json.dumps(result["reports"]), result["reports"]
    # The merge ran to the end and held the file to the rule, saying why.
    assert result["exit"] in (0, 2), result["output"]
    assert result["reports"], result["output"]
    reason = " ".join(MERGE_CONFIG_FILE.reason.split())
    assert any(
        f"reporters.{DECLARED_REPORTER}" in warning
        and reason in " ".join(warning.split())
        for warning in result["warnings"]
    ), result["warnings"]


def test_an_override_that_enables_it_aims_it_at_the_default_and_keeps_the_files_title(
    tmp_path, declared_site
):
    result = _declared_merge(
        tmp_path, declared_site, [f"reporters.{DECLARED_REPORTER}.enabled=true"]
    )

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert DEFAULT_ENDPOINT in written[0], written
    assert FILE_ENDPOINT not in written[0], written
    # Not a destination option: the file's value applies, as it does for a scan.
    assert "file title" in written[0], written


def test_an_override_that_aims_it_is_used(tmp_path, declared_site):
    result = _declared_merge(
        tmp_path,
        declared_site,
        [
            f"reporters.{DECLARED_REPORTER}.enabled=true",
            f"reporters.{DECLARED_REPORTER}.options.endpoint={OVERRIDE_ENDPOINT}",
        ],
    )

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert OVERRIDE_ENDPOINT in written[0], written
    assert FILE_ENDPOINT not in written[0], written
    assert "file title" in written[0], written


# A reporter whose own default for ``enabled`` is true. The operator's ``--config``
# file says ``enabled: true`` for it, which matches that default, so it has to be
# read as the file's word and not as the operator's.


def _declared_on_merge(tmp_path: Path, site: Path, overrides: List[str]) -> Dict:
    return run_merge(
        tmp_path,
        site,
        overrides,
        plugin=DECLARED_ON_PLUGIN,
        reporter=DECLARED_ON_REPORTER,
    )


def test_a_config_file_cannot_enable_one_that_is_on_by_default(
    tmp_path, declared_on_site
):
    result = _declared_on_merge(tmp_path, declared_on_site, [])

    assert reporter_texts(result) == [], result["reports"]
    assert FILE_ENDPOINT not in json.dumps(result["reports"]), result["reports"]
    assert result["exit"] in (0, 2), result["output"]
    assert result["reports"], result["output"]
    reason = " ".join(MERGE_CONFIG_FILE.reason.split())
    assert any(
        f"reporters.{DECLARED_ON_REPORTER}.enabled" in warning
        and reason in " ".join(warning.split())
        for warning in result["warnings"]
    ), result["warnings"]


def test_an_override_that_enables_one_that_is_on_by_default_runs_it_at_the_default(
    tmp_path, declared_on_site
):
    result = _declared_on_merge(
        tmp_path, declared_on_site, [f"reporters.{DECLARED_ON_REPORTER}.enabled=true"]
    )

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert DEFAULT_ENDPOINT in written[0], written
    assert FILE_ENDPOINT not in written[0], written
    assert "file title" in written[0], written


def test_an_override_that_turns_off_one_that_is_on_by_default_wins_over_the_file(
    tmp_path, declared_on_site
):
    result = _declared_on_merge(
        tmp_path, declared_on_site, [f"reporters.{DECLARED_ON_REPORTER}.enabled=false"]
    )

    assert reporter_texts(result) == [], result["reports"]
    assert result["exit"] in (0, 2), result["output"]
    assert result["reports"], result["output"]
