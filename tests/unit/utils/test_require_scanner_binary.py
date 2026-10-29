# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""require_scanner_binary skips without the tool, and fails when CI requires it.

The real-scanner offline tests (syft, trivy) run only in the CI job that installs
every scanner, with ASH_REQUIRE_REAL_SCANNER_TESTS set. If that flag did not turn a
missing tool into a failure, a change to the job's install would let them skip
there too, and nothing would run them anywhere.
"""

from __future__ import annotations

import pytest

from tests.utils import helpers


def test_a_missing_tool_fails_when_the_tests_are_required(monkeypatch):
    monkeypatch.setattr(helpers.shutil, "which", lambda name: None)
    monkeypatch.setenv(helpers.REQUIRE_REAL_SCANNERS, "1")

    with pytest.raises(pytest.fail.Exception, match="syft is not on PATH"):
        helpers.require_scanner_binary("syft")


def test_a_missing_tool_skips_otherwise(monkeypatch):
    monkeypatch.setattr(helpers.shutil, "which", lambda name: None)
    monkeypatch.delenv(helpers.REQUIRE_REAL_SCANNERS, raising=False)

    with pytest.raises(pytest.skip.Exception):
        helpers.require_scanner_binary("syft")


def test_a_present_tool_is_returned(monkeypatch):
    monkeypatch.setattr(helpers.shutil, "which", lambda name: f"/opt/bin/{name}")
    monkeypatch.setenv(helpers.REQUIRE_REAL_SCANNERS, "1")

    assert helpers.require_scanner_binary("trivy") == "/opt/bin/trivy"
