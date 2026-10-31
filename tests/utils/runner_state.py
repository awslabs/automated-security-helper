# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where a container runner keeps its images, for the tests that start one.

tests/conftest.py moves HOME, USERPROFILE and the XDG directories into a private home
for the session. A rootless podman keeps its image store under
``$XDG_DATA_HOME/containers/storage`` and reads its configuration from
``$XDG_CONFIG_HOME/containers``; with either unset it uses ``.local/share`` or
``.config`` under HOME. The CI legs that run the container snapshots build the ``ci``
image outside pytest, into the store under the developer's directories, so a podman
that a test starts with the session's values looks in an empty store, finds no image
by that name, and tries to pull it from the unqualified-search registries. docker and
finch keep their images in a daemon, which is not reached through those directories.

:func:`developer_runner_env` is what to add to the environment of a runner that a test
starts: the developer's two directories for podman, and nothing for any other runner.
HOME, USERPROFILE and the other XDG directories stay the session's own, so the
isolation that tests/conftest.py gives the rest of the test is not changed by it.

The developer's values are the ones tests/conftest.py recorded before it moved them,
as JSON in ``ASH_TEST_DEVELOPER_HOME`` (``{"env": {name: value}, "home": path}``, with
only the variables the developer had set in ``env``); xdist workers inherit that
variable. :func:`developer_environment_record` reads its ``env`` part.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tests.utils import real_home_guard

#: The variable tests/conftest.py records the developer's HOME, XDG and uv values in
#: (its ``_DEVELOPER_HOME_ENV``), as JSON: ``{"env": {name: value}, "home": path}``.
RECORD_ENV = "ASH_TEST_DEVELOPER_HOME"

#: The variables a rootless podman finds its image store (data) and its configuration
#: under, each with where it is under the developer's home when the developer has not
#: set it.
_PODMAN_DIRECTORIES = {
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_CONFIG_HOME": (".config",),
}


def developer_environment_record() -> dict[str, str]:
    """The developer's values of the variables tests/conftest.py moved.

    The ``env`` part of the JSON in :data:`RECORD_ENV`: a variable the developer had
    not set is absent. Empty when the variable is unset, is not JSON, is not an object,
    or has no ``env`` object, which is also what a process outside that conftest sees.
    """
    recorded = os.environ.get(RECORD_ENV)
    if not recorded:
        return {}
    try:
        record = json.loads(recorded)
    except ValueError:
        return {}
    env = record.get("env") if isinstance(record, dict) else None
    if not isinstance(env, dict):
        return {}
    return {str(name): str(value) for name, value in env.items()}


def developer_runner_env(runner: str) -> dict[str, str]:
    """What to add to ``runner``'s environment so it finds the developer's images.

    ``runner`` is the program's name or path, as ``OCI_RUNNER`` gives it. For podman
    that is the developer's XDG_DATA_HOME and XDG_CONFIG_HOME, or the directories
    they default to under the developer's home when the developer set neither; for
    any other runner, or when the session recorded nothing, it is empty.
    """
    if Path(runner).stem != "podman":
        return {}
    record = developer_environment_record()
    if not record:
        return {}
    home = record.get("HOME") or real_home_guard.passwd_home()
    if not home:
        return {}
    return {
        name: record.get(name) or str(Path(home, *default))
        for name, default in _PODMAN_DIRECTORIES.items()
    }
