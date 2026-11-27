# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The framework names ASH passes as ``--skip-framework`` do not follow its mirror.

checkov ends the run with ``parser.error`` on a ``--skip-framework`` value it
does not know, and ASH's ``>=3.2.0,<4.0.0`` constraint admits checkov releases
older than the newest. The mirror of checkov's registry (``CheckFrameworks``)
follows the newest checkov, so a ``*_configuration`` name that reaches the
command line through the mirror would fail every default scan on an older one.
The skip set is therefore the measured floor, and a new VCS framework is added
to it only as an explicit decision that also raises the constraint's floor.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - fixed argv, runs this interpreter
import sys

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_vcs_frameworks import (
    KNOWN_VCS_CONFIGURATION_FRAMEWORKS,
)
from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

# Run in a child interpreter: the scanner module computes its constants when it
# is imported, so the mirror is extended before that import and nothing in this
# process is reloaded. get_args is wrapped to add a fictional VCS framework to
# the CheckFrameworks mirror (the one tuple that holds "terraform" and "all").
#
# The child runs through importing_this_checkout, so it imports this checkout's
# ASH and no other copy. That helper imports the package before the probe runs,
# so the probe first checks that the package import loaded neither checkov
# module: in a module loaded before get_args is wrapped, a skip set that
# followed the mirror would hold only today's names, and the tests below could
# not tell it from the floor.
_PROBE = """
import json, sys, typing
_SCANNERS = "automated_security_helper.plugin_modules.ash_builtin.scanners."
_EARLY = [
    name
    for name in ("checkov_scanner", "checkov_vcs_frameworks")
    if _SCANNERS + name in sys.modules
]
assert not _EARLY, "loaded before the mirror was extended: " + ", ".join(_EARLY)
_get_args = typing.get_args
def get_args(tp):
    args = _get_args(tp)
    if "terraform" in args and "all" in args:
        return args + ("gitea_configuration",)
    return args
typing.get_args = get_args
from automated_security_helper.plugin_modules.ash_builtin.scanners import checkov_scanner
print(json.dumps({
    "mirror": list(typing.get_args(checkov_scanner.CheckFrameworks)),
    "skip": list(checkov_scanner._VCS_CONFIGURATION_FRAMEWORKS),
    "conf_dirs": list(checkov_scanner._CHECKOV_VCS_CONF_DIR_ENV),
    "fetch": list(checkov_scanner._VCS_CONFIG_FETCH_ENV_VARS),
}))
"""


@pytest.fixture(scope="module")
def probed():
    done = subprocess.run(  # nosec B603 - fixed argv, this interpreter
        [sys.executable, "-c", importing_this_checkout(_PROBE)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_probe_really_extended_the_mirror(probed):
    # Without this the tests below would pass for a mirror that never grew.
    assert "gitea_configuration" in probed["mirror"]


def test_a_new_mirror_name_does_not_enter_the_skip_set(probed):
    assert probed["skip"] == sorted(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)
    assert "gitea_configuration" not in probed["skip"]


def test_a_new_mirror_name_does_not_enter_the_environment_variables(probed):
    assert "CKV_GITEA_CONF_DIR_NAME" not in probed["conf_dirs"]
    assert "CKV_GITEA_CONFIG_FETCH_DATA" not in probed["fetch"]
