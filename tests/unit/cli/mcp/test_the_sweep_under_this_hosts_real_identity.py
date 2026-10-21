# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one cell that runs the sweep under the machine's real identity.

Every other cell in this directory runs with the identity token pinned (see
conftest.py), so none of them depends on what the machine can read. This one asks
the machine itself: a copy named with the token this host reads is, once its
writer is gone, swept. On a host that cannot read its identity the cell is
skipped, and the skip is its declared outcome there: no token exists to name the
copy with, which the other cells cover with a patched token of None.
"""

import subprocess
import sys
import uuid

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

#: Bound at import, before the directory's autouse pin replaces the attribute.
_REAL_THIS_HOST_TOKEN = mcp_tools._this_host_token


def test_a_dead_writers_copy_named_by_the_real_identity_is_swept(tmp_path, monkeypatch):
    token = _REAL_THIS_HOST_TOKEN()
    if token is None:
        pytest.skip("this host cannot read its own identity")
    monkeypatch.setattr(mcp_tools, "_this_host_token", _REAL_THIS_HOST_TOKEN)
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child.wait()
    dead = profile.with_name(f".ash-scan-{uuid.uuid4()}-p{child.pid}-h{token}.ash.yaml")
    dead.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    # Control: the writer's own naming gives the same token the cell planted.
    assert (
        f"-h{token}." in mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4())).name
    )

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not dead.exists(), "a dead writer's copy on this host survived the sweep"
