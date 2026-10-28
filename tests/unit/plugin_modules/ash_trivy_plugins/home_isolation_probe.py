# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test that tests/unit/test_home_isolation.py runs in a child pytest, and nothing else.

It lives here because this directory's conftest.py imports ASH at module level, so
``core.constants.ASH_BIN_PATH`` is computed from HOME while pytest loads that conftest,
before any hook of tests/conftest.py has run. The run's own home has to be in place by
then, or the constant points into the home the run started with; under xdist that went
unnoticed, because workers inherit the controller's already-redirected environment.

The file name does not match ``python_files``, so pytest collects it only when it is
named on the command line, and the test skips unless the child's environment sets
ASH_HOME_ISOLATION_PROBE and ASH_HOME_ISOLATION_SENTINEL, the home the child started
with.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core import constants

pytestmark = pytest.mark.skipif(
    os.environ.get("ASH_HOME_ISOLATION_PROBE") != "1"
    or not os.environ.get("ASH_HOME_ISOLATION_SENTINEL"),
    reason="run by tests/unit/test_home_isolation.py in a child with a sentinel home",
)


def test_the_bin_path_ash_computed_at_import_is_outside_the_starting_home():
    sentinel = Path(os.environ["ASH_HOME_ISOLATION_SENTINEL"])
    bin_path = Path(constants.ASH_BIN_PATH)
    assert sentinel != bin_path and sentinel not in bin_path.parents, (
        f"ASH_BIN_PATH={bin_path} is under the home the run started with ({sentinel})"
    )
