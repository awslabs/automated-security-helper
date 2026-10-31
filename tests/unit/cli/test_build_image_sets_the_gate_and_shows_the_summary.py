# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash build-image` sets the last-resort log gate and shows the scan's summary.

The gate: a record logged before run_ash_scan attaches its handlers is shown
at the verbosity the flags ask for, as `ash scan` arranges, so --quiet hides
it and --debug shows it. The summary: the container is run with
--no-show-summary so the host prints the one summary, and the host passed
False, so a scan that found actionable findings exited 2 with no summary.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.utils import log as ash_log

pytestmark = pytest.mark.unit

_PARKED = logging.CRITICAL


def _build(**overrides):
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None
    arguments = {
        "no_build": False,
        "no_run": False,
        "force": False,
        "oci_runner": None,
        "container_network": "bridge",
        "build_target": None,
        "offline_semgrep_rulesets": "p/ci",
        "container_uid": None,
        "container_gid": None,
        "ash_revision_to_install": None,
        "custom_containerfile": None,
        "custom_build_arg": None,
        "config_overrides": None,
        "offline": False,
        "quiet": False,
        "log_level": AshLogLevel.INFO,
        "config": None,
        "verbose": False,
        "debug": False,
        "color": True,
    }
    arguments.update(overrides)
    with patch("automated_security_helper.cli.image.run_ash_scan") as run:
        build_ash_image_cli_command(ctx, **arguments)
    return run


@pytest.mark.parametrize(
    "flags, expected_gate",
    [
        pytest.param({}, logging.INFO, id="default-is-INFO"),
        pytest.param({"quiet": True}, logging.ERROR, id="quiet-collapses-to-ERROR"),
        pytest.param({"debug": True}, logging.DEBUG, id="debug-opens-to-DEBUG"),
        pytest.param({"verbose": True}, 15, id="verbose-opens-to-VERBOSE"),
    ],
)
def test_build_image_sets_the_last_resort_gate_at_the_resolved_level(
    flags, expected_gate, monkeypatch
):
    monkeypatch.delenv("ASH_DEBUG", raising=False)
    monkeypatch.delenv("ASH_VERBOSE", raising=False)
    gate_before = ash_log._LAST_RESORT.level
    try:
        ash_log._LAST_RESORT.setLevel(_PARKED)
        _build(**flags)
        assert ash_log._LAST_RESORT.level == expected_gate, (
            "build-image left the last resort's gate where it was parked"
            if ash_log._LAST_RESORT.level == _PARKED
            else "build-image set the gate, but not at the resolved level"
        )
    finally:
        ash_log._LAST_RESORT.setLevel(gate_before)


def test_a_build_that_scans_shows_the_summary():
    run = _build(no_run=False)

    assert run.call_args.kwargs["show_summary"] is True


def test_a_build_without_a_scan_has_no_summary_to_show():
    run = _build(no_run=True)

    assert run.call_args.kwargs["show_summary"] is False
