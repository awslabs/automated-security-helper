# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures a plugin-module unit test takes by name.

Nothing here is autouse: each fixture replaces something a tested function would
otherwise see, so a module opts in with
``pytestmark = pytest.mark.usefixtures(...)``.
"""

from __future__ import annotations

import pytest

#: What a uv-managed tool's version probe reports under ``no_tool_probes``.
PINNED_TOOL_VERSION = "9.0.0"


@pytest.fixture
def no_tool_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scanner plugins' tool probes answer without starting a tool.

    Building a semgrep scanner asks uv for the tool's version
    (``UVToolRunner.is_uv_available``, then ``get_tool_version``, which runs ``uv
    tool run <tool> --version``). Where uv and the tool are installed, that starts
    the tool, and the tool writes its own state (``~/.semgrep/settings.yml``).
    Those writes come from the process itself; with no process started, nothing
    else in these tests makes them.

    Under this fixture uv is reported available, and every tool's version as
    :data:`PINNED_TOOL_VERSION`. A test of a probe itself does not take this
    fixture, or replaces ``get_tool_version`` with its own recorder.
    """
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.setattr(
        UVToolRunner,
        "get_tool_version",
        lambda self, tool_name, package_name=None, *args, **kwargs: PINNED_TOOL_VERSION,
    )
