# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The integration job installs the scanners its tests run, and requires them.

Why this file exists
--------------------
tests/integration/scanners/test_repo_tool_configs_are_not_read.py runs actionlint,
gitleaks and zizmor for real, and skips when actionlint or gitleaks is missing. The
integration job in ash-unified-ci.yml installed actionlint, cfn-lint and cfn-guard
but not gitleaks, so both tests in that file skipped in CI, and a skip there reads
as a pass. The job now installs gitleaks through the same verified installer, and
sets ``ASH_REQUIRE_GITLEAKS`` beside ``ASH_REQUIRE_ACTIONLINT`` so a missing tool
fails those tests instead.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
CONFIGS_TEST = (
    REPO_ROOT
    / "tests"
    / "integration"
    / "scanners"
    / "test_repo_tool_configs_are_not_read.py"
)


def _integration_steps() -> list[dict[str, Any]]:
    workflow = yaml.safe_load(CI.read_text(encoding="utf-8"))
    return workflow["jobs"]["integration-test"]["steps"]


def _installed_tools() -> set[str]:
    tools: set[str] = set()
    for step in _integration_steps():
        run = step.get("run") or ""
        if "ash dependencies install" not in run:
            continue
        words = run.split()
        tools |= {words[i + 1] for i, word in enumerate(words) if word == "--tool"}
    return tools


def _suite_env() -> dict[str, str]:
    (step,) = [
        s for s in _integration_steps() if "tests/integration" in (s.get("run") or "")
    ]
    return {key: str(value) for key, value in (step.get("env") or {}).items()}


def test_the_job_installs_every_scanner_the_integration_tests_run_for_real() -> None:
    assert {"actionlint", "cfn-lint", "cfn-guard", "gitleaks"} <= _installed_tools()


def test_the_suite_step_requires_actionlint_and_gitleaks() -> None:
    env = _suite_env()
    assert env.get("ASH_REQUIRE_ACTIONLINT") == "1"
    assert env.get("ASH_REQUIRE_GITLEAKS") == "1"


@pytest.fixture(scope="module")
def configs_test() -> ModuleType:
    name = "_integration_repo_tool_configs"
    spec = importlib.util.spec_from_file_location(name, CONFIGS_TEST)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("tool", ["actionlint", "gitleaks"])
def test_a_missing_required_tool_fails_rather_than_skips(
    configs_test: ModuleType, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    monkeypatch.setattr(configs_test, "find_executable", lambda name: None)
    monkeypatch.setenv(f"ASH_REQUIRE_{tool.upper()}", "1")
    # Both outcomes are caught so a skip fails this test rather than skipping it.
    with pytest.raises((pytest.fail.Exception, pytest.skip.Exception)) as raised:
        configs_test._require(tool)
    assert raised.type is pytest.fail.Exception, (
        f"{tool} is missing and ASH_REQUIRE_{tool.upper()} is set, and the test "
        f"skipped: {raised.value}"
    )
    assert tool in str(raised.value)


@pytest.mark.parametrize("tool", ["actionlint", "gitleaks"])
def test_without_the_flag_a_missing_tool_still_skips(
    configs_test: ModuleType, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    monkeypatch.setattr(configs_test, "find_executable", lambda name: None)
    monkeypatch.delenv(f"ASH_REQUIRE_{tool.upper()}", raising=False)
    with pytest.raises(pytest.skip.Exception):
        configs_test._require(tool)
