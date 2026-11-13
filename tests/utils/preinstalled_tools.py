# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Make a test run fail when it would install a tool that CI installed before it.

Why this exists
---------------
ash-unified-ci.yml's integration-test job installs bandit, actionlint, cfn-lint,
cfn-guard and gitleaks with ``ash dependencies install --tool ...`` before the
integration suite starts, so the suite runs the scanners against the install users
make. If that install stops reaching the suite (a changed tool directory, a HOME the
tests move, a PATH the step drops), bandit's scanner ``uv tool install``s bandit again
from inside the suite and every test still passes, so nothing shows that the
pre-install no longer does anything.

``ASH_REQUIRE_PREINSTALLED_TOOLS`` (comma separated) names the tools a run must find
already installed. tests/integration/conftest.py reads it, the way
``ASH_REQUIRE_CDK_EXTRA`` and ``ASH_REQUIRE_SANDBOX_BACKENDS`` turn a skip into a
failure there:

* at session start, each named tool must already be available the way the scanner
  looks for it (``UVToolRunner.get_tool_installation_info``: ``uv tool list``, then
  PATH). That finds the pinned binaries too (actionlint, cfn-guard, gitleaks), which
  are on PATH and never in ``uv tool list``;
* during the run, a ``UVToolRunner.install_tool_with_version`` call for a named tool
  fails the test that made it. Only the uv tools are installed that way; a scanner
  whose pinned binary is missing names ``ash dependencies install`` instead, so for
  those the session check is what fails a run the pre-install did not reach.

Unset, nothing changes, so a developer machine without the tools still installs them.
"""

from __future__ import annotations

import os
from typing import Callable, Iterable, Mapping

import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _requirement_base_name,
)

REQUIRE_PREINSTALLED = "ASH_REQUIRE_PREINSTALLED_TOOLS"


def required_tools(environ: Mapping[str, str] = os.environ) -> frozenset[str]:
    """The tool names ``ASH_REQUIRE_PREINSTALLED_TOOLS`` lists."""
    raw = environ.get(REQUIRE_PREINSTALLED, "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def missing_tools(tools: Iterable[str], runner: UVToolRunner) -> list[str]:
    """The named tools the scanner's own lookup does not find installed."""
    return [
        tool
        for tool in sorted(tools)
        if not runner.get_tool_installation_info(tool).get("available")
    ]


def guard_installs(monkeypatch: pytest.MonkeyPatch, tools: frozenset[str]) -> None:
    """Fail the current test if it installs one of ``tools``."""
    if not tools:
        return
    real: Callable[..., bool] = UVToolRunner.install_tool_with_version

    def guarded(self: UVToolRunner, tool_name: str, *args, **kwargs) -> bool:
        if _requirement_base_name(tool_name) in tools:
            pytest.fail(
                f"the run tried to `uv tool install` {tool_name!r}, which "
                f"{REQUIRE_PREINSTALLED} says was installed before it started; the "
                "pre-install no longer reaches the scanner"
            )
        return real(self, tool_name, *args, **kwargs)

    monkeypatch.setattr(UVToolRunner, "install_tool_with_version", guarded)
