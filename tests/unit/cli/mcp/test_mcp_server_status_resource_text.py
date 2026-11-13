# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ash://status resource: no raw controls in its error, no readiness it did not check.

Its error arm put an exception's text into the client-visible resource as it
was, where every other client-facing error text in the module writes controls
as escapes on one line. Its ready arm said ASH was "ready to perform security
scans" from the version and the built-in scanner list alone, without checking
any scanner's tool; it now says so.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.utils import get_ash_version as version_module

pytestmark = pytest.mark.unit


def test_an_error_in_the_status_resource_shows_controls_as_escapes(monkeypatch) -> None:
    monkeypatch.setattr(version_module, "get_ash_version", lambda: "1.2.3")

    def broken() -> str:
        raise RuntimeError("tool \x1b[31mred\x1b[0m missing")

    monkeypatch.setattr(mcp_server, "_builtin_scanner_lines", broken)

    text = mcp_server.get_ash_status()

    assert "ERROR" in text
    assert "missing" in text
    # Red before the fix: the raw ESC reached the client.
    assert "\x1b" not in text, repr(text)


def test_the_ready_status_does_not_claim_the_scanners_are_ready_to_run(
    monkeypatch,
) -> None:
    monkeypatch.setattr(version_module, "get_ash_version", lambda: "1.2.3")
    monkeypatch.setattr(mcp_server, "_builtin_scanner_lines", lambda: "• bandit")

    text = mcp_server.get_ash_status()

    assert "READY" in text
    assert "1.2.3" in text
    # Red before the fix: "ready to perform security scans" with no check behind it.
    assert "ready to perform" not in text, text
    assert "not checked here" in text, text
    assert "list_scanners" in text, text
