# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The confinement does not turn on an off-host reporter the run gate refuses.

A reporter that sends findings off the host runs only for an ``enabled`` that is
the boolean true (``off_host_reporter_refused``). The trusted base can hold a value
the reporter's model reads as on without being true, such as ``1`` or ``"yes"``
from ``--config-overrides``. Under the base alone that reporter is refused. The
confinement used to write a boolean true in its place, which ran it, on ``ash
report`` and ``ash merge`` and in a scan with a file inside the tree. It gives the
sections the base's own value instead, so the reporter is refused as it is without
the confinement, and a boolean true from the base still runs it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.reporter_plugin import off_host_reporter_refused
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
    confine_off_host_reporters_to_overrides,
    confine_reporter_destinations,
)
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.untrusted_source import REPORT_CONFIG_FILE
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")

#: Overrides whose value the reporter's model reads as on and the gate refuses.
NOT_THE_BOOLEAN_TRUE = ["yes", "1", "on"]


def _after_ash_report(file_enabled: object, override: str):
    """The S3 section ``ash report`` builds the reporter from.

    The resolved config holds the override's value, as the scan's own apply left
    it, and both confinement steps of the command run against it.
    """
    overrides = [f"reporters.s3.enabled={override}"]
    config = AshConfig.model_validate({"reporters": {"s3": {"enabled": file_enabled}}})
    config = apply_config_overrides(config, overrides)
    confine_off_host_reporters_to_overrides(
        config, [CONFIG_FILE], overrides, REPORT_CONFIG_FILE
    )
    confine_declared_reporter_destinations(
        config, [S3Reporter], source=REPORT_CONFIG_FILE
    )
    return reporter_section(config, S3Reporter)


@pytest.mark.parametrize("override", NOT_THE_BOOLEAN_TRUE)
def test_ash_report_does_not_run_s3_on_an_enabled_the_gate_refuses(override):
    built = _after_ash_report(file_enabled=False, override=override)

    assert off_host_reporter_refused(S3Reporter, built), built


@pytest.mark.parametrize("override", NOT_THE_BOOLEAN_TRUE)
def test_a_scan_does_not_run_s3_on_a_file_true_over_an_enabled_the_gate_refuses(
    override,
):
    trusted = apply_config_overrides(AshConfig(), [f"reporters.s3.enabled={override}"])
    config = AshConfig.model_validate({"reporters": {"s3": {"enabled": True}}})

    confine_reporter_destinations(config, trusted, [], [CONFIG_FILE])

    section = config.get_plugin_config("reporter", "s3")
    assert off_host_reporter_refused(S3Reporter, section), section


def test_ash_report_still_runs_s3_on_a_boolean_true():
    """Control: the boolean true from the overrides is what turns it on."""
    built = _after_ash_report(file_enabled=False, override="true")

    assert not off_host_reporter_refused(S3Reporter, built), built
