# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fixed ``id`` on PATH, so a test that runs ``./ash`` names the host IDs it sees.

``./ash`` reads the caller's UID and GID with ``id -u`` and ``id -g`` and builds the
default ``non-root`` image stage with them; with UID 0 or GID 0 it refuses that
build. A test that runs the script with the host's own ``id`` therefore asserts
something else when the suite runs as root (a developer container, CodeBuild, a
root CI job) than when it runs as a user. Tests run it with :func:`with_fixed_ids`
instead: an unprivileged UID and GID unless the test names others.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Mapping

#: The IDs a test runs ./ash as unless it names others.
UNPRIVILEGED_UID = "1000"
UNPRIVILEGED_GID = "1000"


def fixed_id_dir(
    directory: Path, uid: str = UNPRIVILEGED_UID, gid: str = UNPRIVILEGED_GID
) -> Path:
    """Write an ``id`` into *directory* that answers ``-u`` with *uid* and ``-g`` with *gid*."""
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "id"
    stub.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f"  -u) echo {uid} ;;\n"
        f"  -g) echo {gid} ;;\n"
        f"  *) echo 'uid={uid} gid={gid}' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return directory


def with_fixed_ids(
    env: Mapping[str, str],
    directory: Path,
    uid: str = UNPRIVILEGED_UID,
    gid: str = UNPRIVILEGED_GID,
) -> Dict[str, str]:
    """A copy of *env* with an ``id`` reporting *uid* and *gid* first on PATH."""
    fixed_id_dir(directory, uid, gid)
    result = dict(env)
    result["PATH"] = os.pathsep.join([str(directory), env.get("PATH") or os.defpath])
    return result
