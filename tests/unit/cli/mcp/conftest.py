# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the MCP cells.

Two of them serve the cells that name or sweep a scan's profile copy: the host
identity a copy's name carries, and the record of the copies a scan registered. The
third gives each cell a working directory of its own and fails a cell that writes
into it.
"""

from pathlib import Path
from typing import Iterator

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


@pytest.fixture(autouse=True)
def _each_cell_starts_in_an_empty_working_directory_of_its_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Path]:
    """Start each cell in an empty working directory, and fail the cell that fills it.

    A path built from a relative name is relative to the working directory, which is
    the root of the checkout in a normal run, so what writes there leaves its files in
    the checkout and nothing fails. A ``_run_git`` double did: it took the last argument
    of every git command as the clone target and wrote ``cloned.txt`` into it, and the
    last argument of the ``rev-parse`` that follows a clone with no ref is
    ``HEAD^{commit}``, so each run left ``HEAD^{commit}/cloned.txt`` in the checkout.

    The directory is made beside the cell's ``tmp_path``, not in it: some cells list
    ``tmp_path`` and would count it. A cell that needs another working directory
    changes it itself, as the cells that read a tree from the working directory do.
    The check at the end reads this directory by its path, so a cell that changed the
    working directory and has not changed it back is still judged on this one.

    The change is made with the shared ``monkeypatch``, as in the fixtures above, and
    not with a patch of this fixture's own. The shared one remembers the directory the
    process started in and puts it back after the cell, however the cell moved. A patch
    of this fixture's own would be undone first, and the shared one, if the cell changed
    directory, would then leave the process in the directory made here.
    """
    here = tmp_path_factory.mktemp("cwd")
    monkeypatch.chdir(here)
    yield here
    try:
        left = sorted(entry.name for entry in here.iterdir())
    except FileNotFoundError:
        # A cell that removed the directory it started in left nothing in it.
        return
    if left:
        pytest.fail(
            f"the test left {left} in its working directory, {here}. A path built "
            "from a relative name lands there, which is the root of the checkout in a "
            "normal run. A git double that takes the last argument of every command "
            "as the clone target does it for the rev-parse that follows a clone with "
            "no ref, whose last argument is HEAD^{commit}: have the double act for "
            "the command it stands in for, or build the path from tmp_path."
        )
