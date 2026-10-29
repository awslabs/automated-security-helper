# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed read of trivy's misconfig scanner list is tried again; a read list is kept.

``trivy_default_misconfig_scanners`` stored None when ``trivy repository --help`` failed
(a 60 s timeout, a transient spawn error), and every later offline scan in that process
(a long-running MCP server, the projects of a workspace) then left out every
misconfiguration check with the "could not read" warning until the process restarted.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.utils import subprocess_utils

pytestmark = [pytest.mark.unit, pytest.mark.live_tool_probes]

HELP = (
    "      --misconfig-scanners strings   comma-separated list of misconfig scanners to "
    "use for misconfiguration scanning (default [azure-arm,cloudformation,terraform])\n"
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    trivy_repo_scanner.reset_trivy_default_misconfig_scanners()
    yield
    trivy_repo_scanner.reset_trivy_default_misconfig_scanners()


def _answers(monkeypatch, *outcomes):
    calls = []
    queue = list(outcomes)

    def run_command(command, **kwargs):
        calls.append(command)
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return SimpleNamespace(stdout=outcome, stderr="")

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)
    return calls


def test_a_failed_read_is_tried_again(monkeypatch):
    calls = _answers(monkeypatch, TimeoutError("trivy --help timed out"), HELP)

    first = trivy_repo_scanner.trivy_default_misconfig_scanners("trivy", ["repository"])
    second = trivy_repo_scanner.trivy_default_misconfig_scanners(
        "trivy", ["repository"]
    )

    assert first is None
    assert second == ["azure-arm", "cloudformation", "terraform"]
    assert len(calls) == 2


def test_output_without_the_list_is_tried_again(monkeypatch):
    calls = _answers(monkeypatch, "Usage: trivy repository [flags]\n", HELP)

    trivy_repo_scanner.trivy_default_misconfig_scanners("trivy", ["repository"])
    second = trivy_repo_scanner.trivy_default_misconfig_scanners(
        "trivy", ["repository"]
    )

    assert second == ["azure-arm", "cloudformation", "terraform"]
    assert len(calls) == 2


def test_a_read_list_is_read_once(monkeypatch):
    calls = _answers(monkeypatch, HELP)

    for _ in range(3):
        listed = trivy_repo_scanner.trivy_default_misconfig_scanners(
            "trivy", ["repository"]
        )

    assert listed == ["azure-arm", "cloudformation", "terraform"]
    assert len(calls) == 1
