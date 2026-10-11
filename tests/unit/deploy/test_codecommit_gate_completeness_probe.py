#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform gate refuses to scan with an ASH that cannot fail an incomplete scan.

Why this file exists
--------------------
``run_scan`` passes ``--fail-on-incomplete-scanners`` so that a run in which a selected
scanner was MISSING or ERROR exits 1, outcome "error", rather than 0, outcome "pass",
which is the one outcome that APPROVEs. ASH releases up to v3.7.1 have no such option,
and their ``ash scan`` collects unknown options instead of refusing them, so the flag
was accepted and dropped: measured on v3.7.0, bandit and grype both MISSING still
exited 0 with the flag passed. The handler therefore asks ``ash scan --help`` once
whether the option exists, and refuses to scan when it does not, which the handler
reports as outcome "error" with a REVOKE.

The gate is loaded by path, as test_codecommit_gate_fails_closed.py explains.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_PATH = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)

FLAG = "--fail-on-incomplete-scanners"
HELP_WITH_FLAG = (
    f"Usage: ash scan [OPTIONS]\n  --source-dir PATH\n  {FLAG} / --no-{FLAG[2:]}\n"
)
HELP_WITHOUT_FLAG = "Usage: ash scan [OPTIONS]\n  --source-dir PATH\n  --config PATH\n"
#: What rich prints when colour is forced: each dash of an option name styled apart.
HELP_COLOURED = (
    "\x1b[1;36m-\x1b[0m\x1b[1;36m-fail\x1b[0m\x1b[1;36m-on-incomplete-scanners\x1b[0m\n"
)


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ash_pr_gate_probe", GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gate(monkeypatch, tmp_path) -> ModuleType:
    module = _load_gate()
    monkeypatch.setattr(module, "WORK_ROOT", tmp_path / "ash-gate")
    for name in (
        "ASH_CONFIG",
        "ASH_SCAN_EXTRA_ARGS",
        "ASH_OFFLINE",
        "ASH_BASE_CONFIG_SSM_PARAMETER",
    ):
        monkeypatch.delenv(name, raising=False)
    return module


class _Ash:
    """Stands in for every subprocess the gate starts; answers the help probe."""

    def __init__(self, help_text: str, help_exit: int = 0) -> None:
        self.help_text = help_text
        self.help_exit = help_exit
        self.probes: List[Dict[str, Any]] = []
        self.scans: List[List[str]] = []

    def __call__(self, argv, cwd=None, env=None):
        argv = list(argv)
        if argv == ["ash", "scan", "--help"]:
            self.probes.append(dict(env or {}))
            return SimpleNamespace(
                returncode=self.help_exit, stdout=self.help_text, stderr=""
            )
        self.scans.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_an_ash_without_the_option_is_refused_before_anything_is_scanned(
    gate, monkeypatch, tmp_path
):
    ash = _Ash(HELP_WITHOUT_FLAG)
    monkeypatch.setattr(gate, "_run", ash)

    with pytest.raises(RuntimeError, match=FLAG):
        gate.run_scan(tmp_path / "src", "low", True)
    assert ash.scans == []


def test_a_failed_probe_refuses_rather_than_assuming(gate, monkeypatch, tmp_path):
    ash = _Ash(HELP_WITH_FLAG, help_exit=1)
    monkeypatch.setattr(gate, "_run", ash)

    with pytest.raises(RuntimeError, match="could not be checked"):
        gate.run_scan(tmp_path / "src", "low", True)
    assert ash.scans == []


def test_control_an_ash_with_the_option_scans_with_it(gate, monkeypatch, tmp_path):
    ash = _Ash(HELP_WITH_FLAG)
    monkeypatch.setattr(gate, "_run", ash)

    gate.run_scan(tmp_path / "src", "low", True)

    assert len(ash.scans) == 1 and FLAG in ash.scans[0]


def test_coloured_help_still_counts(gate, monkeypatch, tmp_path):
    ash = _Ash(HELP_COLOURED)
    monkeypatch.setattr(gate, "_run", ash)

    gate.run_scan(tmp_path / "src", "low", True)

    assert len(ash.scans) == 1
    assert ash.probes[0].get("NO_COLOR") == "1" and "FORCE_COLOR" not in ash.probes[0]


def test_the_probe_runs_once_per_execution_environment(gate, monkeypatch, tmp_path):
    ash = _Ash(HELP_WITH_FLAG)
    monkeypatch.setattr(gate, "_run", ash)

    gate.run_scan(tmp_path / "src", "low", True)
    gate.run_scan(tmp_path / "src", "low", True)

    assert (len(ash.probes), len(ash.scans)) == (1, 2)


class _FakeCodeCommit:
    class exceptions:  # noqa: N801 - mirrors the boto3 client attribute
        class PullRequestCannotBeApprovedByAuthorException(Exception):
            pass

    def __init__(self) -> None:
        self.comments: List[Dict[str, Any]] = []
        self.approvals: List[Dict[str, Any]] = []

    def post_comment_for_pull_request(self, **kwargs):
        self.comments.append(kwargs)
        return {}

    def update_pull_request_approval_state(self, **kwargs):
        self.approvals.append(kwargs)
        return {}


def test_the_refusal_reaches_the_pull_request_as_error_and_revokes(
    gate, monkeypatch, tmp_path
):
    client = _FakeCodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: (
            client
            if service == "codecommit"
            else pytest.fail(f"unexpected boto3 client requested: {service}")
        ),
    )
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    ash = _Ash(HELP_WITHOUT_FLAG)
    monkeypatch.setattr(gate, "_run", ash)
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    gate.handler(
        {
            "detail": {
                "pullRequestId": "7",
                "repositoryNames": ["repo"],
                "sourceCommit": "a" * 40,
                "destinationCommit": "b" * 40,
                "sourceReference": "refs/heads/feature",
                "revisionId": "rev-1",
            }
        },
        object(),
    )

    assert ash.scans == []
    assert [a["approvalState"] for a in client.approvals] == ["REVOKE"]
    assert any(FLAG in c["content"] for c in client.comments), client.comments
