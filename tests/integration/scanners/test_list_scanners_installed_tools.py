# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mcp_list_scanners() against the tools this host has installed.

The unit tests in tests/unit/cli/mcp/test_list_scanners.py take their snapshot
against stand-in tools, so they give the same answer on every machine and cannot
see how a real tool answers. These run the real dependency checks and version
probes instead: on one machine that started 18 processes (uv, cfn_nag_scan,
grype, npm, opengrep, syft, trivy) and took several seconds.
"""

import pytest

from automated_security_helper.cli.mcp_tools import mcp_list_scanners

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def scanners():
    return mcp_list_scanners()


def _bandit(scanners) -> dict:
    return next(e for e in scanners if e["name"] == "bandit")


def test_bandit_reports_its_dependencies_as_satisfied(scanners):
    """bandit is part of ASH's default tool set: uv runs it, or it is on PATH.

    The hardcoded value this field once had was False, so a host that can run
    bandit reporting True is the plainest evidence the check is measured.
    """
    assert _bandit(scanners)["dependencies_satisfied"] is True


def test_bandit_reports_a_version(scanners):
    entry = _bandit(scanners)
    assert isinstance(entry["version"], str) and entry["version"].strip()
