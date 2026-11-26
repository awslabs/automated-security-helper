# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Severity rating and URI relocation over the committed template-shaped report.

The report under tests/test_data/scanners/dependency-check/captured is shaped like
the tool's own template output, not captured from a run (see its README).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_dependency_check_plugins.dependency_check_scanner import (
    DependencyCheckScanner,
    rate_rule,
)

pytestmark = pytest.mark.unit

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "dependency-check"
    / "captured"
    / "template-shaped.sarif"
)


def _run():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["runs"][0]


def test_every_native_result_level_is_warning():
    levels = {r["level"] for r in _run()["results"]}
    assert levels == {"warning"}


def test_rules_rate_from_their_cvss_properties():
    rated = {
        rule["id"]: rate_rule(rule["properties"])
        for rule in _run()["tool"]["driver"]["rules"]
    }
    assert rated == {
        "CVE-2021-44228": ("CRITICAL", "error"),
        "CVE-2019-12345": ("MEDIUM", "warning"),
        "CVE-2010-00001": ("HIGH", "error"),
    }


def test_absolute_uris_become_source_relative():
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in _run()["results"]
    ]
    assert [DependencyCheckScanner._relative_uri(u, "/src") for u in uris] == [
        "lib/log4j-core-2.14.1.jar",
        "web/package-lock.json",
        "requirements.txt",
    ]
