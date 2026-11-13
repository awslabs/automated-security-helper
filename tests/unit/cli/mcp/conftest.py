# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the MCP cells that name or sweep a scan's profile copy."""

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config import config_sources

#: A well formed identity token (16 lowercase hex digits) standing for "the place
#: these cells run in". It is not the token of any real host.
PINNED_HOST_TOKEN = "fedcba9876543210"


@pytest.fixture(autouse=True)
def _this_host_has_a_fixed_identity(monkeypatch):
    """The cells that plant or read a copy's name get one identity, whatever host
    runs them.

    A copy's name embeds ``mcp_tools._this_host_token()``, which reads the boot
    and the pid namespace of the machine. Left alone, a cell that plants a copy
    "from this host" passes only where that read succeeds (a host without
    ``/proc``, a sandbox, or Windows reads None) and then fails with a message
    about a leftover, not about the identity. A cell that needs another answer
    patches the attribute itself; the one cell that asks the real host is
    test_the_sweep_under_this_hosts_real_identity.
    """
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: PINNED_HOST_TOKEN)


@pytest.fixture(autouse=True)
def _no_copy_outlives_the_cell_that_wrote_it(monkeypatch):
    """Each cell starts with an empty record of the copies a scan has registered.

    The record is module-global state. Cells that call the writer directly never
    discard what they write, so without a fresh record the paths pile up across
    the session and a cell's answer would depend on which cells ran before it.
    """
    monkeypatch.setattr(config_sources, "_LIVE_SCAN_COPIES", set())
