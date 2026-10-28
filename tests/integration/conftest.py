# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the integration suite. See tests/utils/preinstalled_tools.py."""

from __future__ import annotations

import pytest

from automated_security_helper.utils.uv_tool_runner import get_uv_tool_runner
from tests.utils.preinstalled_tools import (
    REQUIRE_PREINSTALLED,
    guard_installs,
    missing_tools,
    required_tools,
)


@pytest.fixture(scope="session", autouse=True)
def _required_tools_are_installed_before_the_run():
    tools = required_tools()
    missing = missing_tools(tools, get_uv_tool_runner()) if tools else []
    if missing:
        pytest.fail(
            f"{REQUIRE_PREINSTALLED} names {', '.join(missing)}, but the run does not "
            "find them installed, so the suite would install them itself"
        )


@pytest.fixture(autouse=True)
def _no_test_installs_a_required_tool(monkeypatch):
    guard_installs(monkeypatch, required_tools())
