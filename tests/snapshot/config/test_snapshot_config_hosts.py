# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The host simulation the config snapshots rely on actually simulates the host.

Each snapshot that depends on the OS is rendered for every host on every OS. That is
only true if ``simulated_host`` reaches every place the Windows-dependent defaults
are read, and puts them back afterwards. If it stops doing either, these fail with a
message naming the path that leaked, instead of a snapshot diff that only shows up on
one CI runner.
"""

from __future__ import annotations

import platform

import pytest

from automated_security_helper.config.ash_config import AshConfig, ScannerConfigSegment
from automated_security_helper.config.default_config import get_default_config
from tests.snapshot.support.cli import CONFIG_HOSTS, simulated_host
from tests.snapshot.support.cli import _windows_dependent_defaults


def _every_reading(segment_field: str, config_cls) -> dict[str, bool]:
    return {
        "config class": config_cls().enabled,
        "segment default": getattr(ScannerConfigSegment(), segment_field).enabled,
        "segment validated": getattr(
            ScannerConfigSegment.model_validate({segment_field: {}}), segment_field
        ).enabled,
        "AshConfig default": getattr(AshConfig().scanners, segment_field).enabled,
        "AshConfig validated": getattr(
            AshConfig.model_validate({"project_name": "x"}).scanners, segment_field
        ).enabled,
        "get_default_config": getattr(
            get_default_config().scanners, segment_field
        ).enabled,
    }


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
@pytest.mark.parametrize(
    "config_cls, segment_field",
    [pytest.param(*pair, id=pair[1]) for pair in _windows_dependent_defaults()],
)
def test_simulated_host_reaches_every_default(
    host, config_cls, segment_field, monkeypatch
):
    real_system, real_machine = platform.system(), platform.machine()
    real_expected = real_system.lower() != "windows"

    with simulated_host(monkeypatch, host):
        assert platform.system() == host.system
        assert platform.machine() == host.machine
        inside = _every_reading(segment_field, config_cls)

    expected = not host.is_windows
    assert inside == dict.fromkeys(inside, expected), inside
    assert (platform.system(), platform.machine()) == (real_system, real_machine)
    after = _every_reading(segment_field, config_cls)
    assert after == dict.fromkeys(after, real_expected), after
