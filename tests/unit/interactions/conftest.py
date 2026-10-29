# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the interaction tests.

The host's user and group IDs
-----------------------------
Container mode reads the host's UID and GID (``subprocess_utils.get_host_uid`` and
``get_host_gid``, which run ``id -u`` and ``id -g``) and refuses a ``non-root`` image
build as UID or GID 0 before it starts anything: exit 3, "ASH is running as root".
That refusal is intended, and ``test_container_non_root_stage_uid.py`` and
``test_container_refused_inputs_keep_prior_output.py`` pin the IDs to 0 to test it.

Every other test that reaches container mode asserts something else, such as the
command that would run, how a refusal in the inner run is carried out, or how stale
results are cleared. Left to read the real IDs, each of them passes for a non-root
user and exits 3 for root, so a suite run as root (a container with no ``USER``, a
CI job that does not drop privileges) reports dozens of failures that are about the
account running the tests and not about the code. The sibling test files pin the IDs
one by one; this does it once for the directory.

An individual test or fixture that sets the IDs itself, or patches
``subprocess_utils.get_host_uid``, runs after this fixture and wins.
"""

import pytest

from automated_security_helper.utils import subprocess_utils


@pytest.fixture(autouse=True)
def _host_is_not_root(monkeypatch):
    """Report an ordinary user and group, whoever is running the tests."""
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
