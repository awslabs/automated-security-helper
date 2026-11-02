# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin section's ``disable_telemetry: 1`` is not the tightening ``true``.

``confine_scanner_config_files`` lets a file keep a confined option's value only
when it is a listed tightening value (``is_tightening_value``), and the call
site passes the value the section holds. A built-in scanner's options model
types ``disable_telemetry`` as a bool, so the model has turned ``1`` into
``True`` before the call site sees it. A plugin scanner's section (trivy-repo
is one) is a plain dict that keeps the number as written, so the call site sees
the number itself. These tests run the whole confinement on such a section, so
a call site that went back to Python equality (``1 in (True,)``) is caught
where the value actually arrives, not only in ``is_tightening_value``'s own
tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.tool_config_trust import (
    confine_scanner_config_files,
)

pytestmark = pytest.mark.unit

TRIVY_REPO = "trivy-repo"


def _plugin_config(options: dict) -> AshConfig:
    return AshConfig.model_validate({"scanners": {TRIVY_REPO: {"options": options}}})


def _written(config: AshConfig) -> Any:
    return (config.scanners.model_extra or {})[TRIVY_REPO]["options"][
        "disable_telemetry"
    ]


@pytest.mark.parametrize("number", [1, 1.0])
def test_a_plugin_section_keeps_the_number_it_wrote_until_the_confinement(
    number: Any,
) -> None:
    """The precondition: no model sits between the file and the call site."""
    config = _plugin_config({"disable_telemetry": number})

    assert type(_written(config)) is type(number)
    assert _written(config) is not True


@pytest.mark.parametrize("number", [1, 1.0])
def test_a_number_is_not_kept_as_the_tightening_value_of_a_plugin_section(
    tmp_path: Path, number: Any
) -> None:
    config = _plugin_config({"disable_telemetry": number})
    trusted = _plugin_config({"disable_telemetry": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _written(config) is False


def test_control_the_listed_tightening_value_is_kept_by_a_plugin_section(
    tmp_path: Path,
) -> None:
    config = _plugin_config({"disable_telemetry": True})
    trusted = _plugin_config({"disable_telemetry": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _written(config) is True


def test_control_a_plugin_section_that_writes_false_gets_the_operators_value(
    tmp_path: Path,
) -> None:
    config = _plugin_config({"disable_telemetry": False})
    trusted = _plugin_config({"disable_telemetry": True})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _written(config) is True
