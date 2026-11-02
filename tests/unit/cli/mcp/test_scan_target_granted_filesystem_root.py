#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A filesystem root the operator granted is judged by the grant.

The scan-target gate refuses a filesystem root before any other rule, with a
remedy written for the caller who omitted the directory and fell back to a
working directory of ``/``. That early refusal did not look at the operator's
grant, so a root named in ``ASH_MCP_ALLOWED_ROOTS`` (a second volume's drive on
Windows; ``/`` on POSIX where no shared workspace root sits under it) was
refused too, with a remedy that told the operator to set the variable they had
already set. A granted root now passes to the gates below like any granted
directory; an ungranted root keeps its remedy.
"""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.sandbox import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp.scan_target import validate_scan_target

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(platform.system() == "Windows", reason="POSIX filesystem root"),
]


@pytest.fixture(autouse=True)
def _no_shared_workspace_root(monkeypatch):
    """The sibling rule is not under test: with no shared workspace root, nothing
    sits under the filesystem root for it to protect, which is the operator's
    situation the finding describes."""
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(sandbox, "shared_workspace_root", lambda: None)


class TestAGrantedFilesystemRoot:
    def test_a_granted_root_is_permitted(self, monkeypatch):
        """Red at the base: the root was refused before the grant was read."""
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, "/")

        assert validate_scan_target(Path("/")) is None

    def test_an_ungranted_root_keeps_the_working_directory_remedy(self, monkeypatch):
        """Control: with no grant for it, the root is refused as before, and the
        remedy still names the omitted directory, not only the variable."""
        monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)

        error = validate_scan_target(Path("/"))

        assert error is not None
        assert "filesystem root" in str(error)
        assert "Pass the directory to scan explicitly" in str(error)

    def test_a_grant_elsewhere_does_not_admit_the_root(self, tmp_path, monkeypatch):
        """Control: a grant for another directory leaves the root refused."""
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        assert validate_scan_target(Path("/")) is not None
