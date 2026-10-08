# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandboxed scan's refusal to install a tool names the command to run instead.

#757 refuses to install a missing tool under --sandbox and tells the operator to run
the dependency install first. The message is the operator's next step, so it has to
name the command v4 ships: `ashx`. The deprecated `ash` alias still works on most
hosts, but on Windows under Git for Windows or MSYS2 `ash` is the Almquist shell.
"""

from __future__ import annotations

import logging

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.sandbox import scope


def test_the_refusal_names_the_canonical_dependencies_install(monkeypatch, caplog):
    runner = uv_tool_runner.UVToolRunner()
    monkeypatch.setattr(runner, "is_uv_available", lambda: True)
    monkeypatch.setattr(runner, "is_tool_installed", lambda *a, **k: False)
    monkeypatch.setattr(scope, "active_scope", lambda: object())
    with caplog.at_level(logging.ERROR):
        assert runner.install_tool_with_version("bandit") is False
    messages = [r.getMessage() for r in caplog.records]
    assert any(
        f"Run `{CANONICAL_CLI_NAME} dependencies install` first." in m for m in messages
    ), messages
    assert not any("`ash dependencies install`" in m for m in messages), messages
