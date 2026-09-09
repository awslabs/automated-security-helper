#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform CodeCommit gate must not approve code it did not scan.

Why this file exists
--------------------
Review finding, and until now nothing tested this file at all -- no Python test targeted
``ash_pr_gate.py``, which is why both defects below could sit in a control that can APPROVE a pull
request.

**Exit 0 did not mean "scanned and clean".** ASH exits 0 when no scanner completed, because no
scanner produced a finding to fail on. The gate mapped exit 0 to outcome "pass", and "pass" is the
only outcome that calls ``update_pull_request_approval_state`` with APPROVE. So arming
``ASH_MANAGE_APPROVAL_STATE`` on a Lambda where the scanners cannot run produced auto-approval of
unscanned code. Not hypothetical: Lambda's root filesystem is read-only, ASH's scanners write caches
at scan time, and a measured run on that image reported three scanners MISSING, one ERROR, and grype
PASSED with zero findings. ``--fail-on-incomplete-scanners`` is what makes exit 0 mean what the gate
reads it as meaning.

**A stale approval outlived the code it was granted for.** The gate approved on a clean commit and
then, when a later commit introduced findings, left that approval in place -- declining to withdraw
the very approval it had granted, on code it had just judged unclean. The CDK gate revokes. These
two have to agree, because choosing an infrastructure flavour is not choosing a security posture.

The gate is loaded by path rather than imported: it lives under ``deploy/terraform/modules/`` and is
packaged into a Lambda, so it is not on any import path. Loading it by path is also what lets this
test exist at all, which is the point the review made.
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
CDK_SCRIPTS = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-container-scripts.ts"


def _load_gate() -> ModuleType:
    """Load the gate by path, since it is packaged into a Lambda rather than importable."""
    assert GATE_PATH.is_file(), f"gate not found at {GATE_PATH}"
    spec = importlib.util.spec_from_file_location("_ash_pr_gate_under_test", GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gate() -> ModuleType:
    return _load_gate()


# ---------------------------------------------------------------------------
# 1. Exit 0 has to mean "every requested scanner ran"
# ---------------------------------------------------------------------------


def test_the_scan_argv_forces_incomplete_scanners_to_fail(gate, monkeypatch, tmp_path):
    """Without this flag, a run where nothing ran exits 0 and the gate calls that a pass."""
    captured: List[List[str]] = []

    def _fake_run(argv, cwd=None):
        captured.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run", _fake_run)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")

    gate.run_scan(tmp_path / "src", "low", True)

    assert captured, "run_scan did not invoke the scanner"
    argv = captured[0]
    assert "--fail-on-incomplete-scanners" in argv, (
        "a gate that can APPROVE must treat ERROR/MISSING scanners as a failure; without "
        f"this flag exit 0 is indistinguishable from a clean scan. argv={argv}"
    )


def test_the_flag_is_not_switchable_by_configuration(gate, monkeypatch, tmp_path):
    """The fail-closed behaviour must not depend on how the gate was deployed.

    An environment variable that can disable it is a control whose safety varies by deployment,
    and the failure is silent when it is set wrong. ASH_SCAN_EXTRA_ARGS is the one knob that could
    plausibly be used to smuggle in the negation, so the flag surviving alongside it is checked.
    """
    captured: List[List[str]] = []
    monkeypatch.setattr(
        gate, "_run",
        lambda argv, cwd=None: (captured.append(list(argv))
                                or SimpleNamespace(returncode=0, stdout="", stderr="")),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--offline")

    gate.run_scan(tmp_path / "src", "low", True)

    assert "--fail-on-incomplete-scanners" in captured[0]


# ---------------------------------------------------------------------------
# 2. Approval state: APPROVE only on pass, REVOKE otherwise, matching CDK
# ---------------------------------------------------------------------------


class _FakeCodeCommit:
    """Records approval-state calls. Nothing else about the client is exercised."""

    def __init__(self) -> None:
        self.approval_calls: List[Dict[str, Any]] = []
        self.comments: List[Dict[str, Any]] = []

    def post_comment_for_pull_request(self, **kwargs):
        self.comments.append(kwargs)
        return {}

    def update_pull_request_approval_state(self, **kwargs):
        self.approval_calls.append(kwargs)
        return {}


def _drive_handler(gate, monkeypatch, tmp_path, scan_exit: int) -> _FakeCodeCommit:
    """Run the handler end to end with the scan's exit code forced.

    ``boto3.client`` is patched rather than a module attribute, because the handler builds its own
    client inline. Patching an attribute that does not exist with ``raising=False`` looked like it
    worked and let the real factory run -- botocore then found the developer's own
    ``~/.aws/credentials`` and failed on a missing region, which is a unit test one environment
    variable away from calling a live AWS API.
    """
    client = _FakeCodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: client
        if service == "codecommit"
        else pytest.fail(f"unexpected boto3 client requested: {service}"),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    monkeypatch.setattr(
        gate, "run_scan", lambda *a, **k: (scan_exit, tmp_path / "out", "log tail")
    )
    monkeypatch.setattr(gate, "read_severity_counts", lambda *a, **k: None)
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
    # The handler reads os.environ["AWS_REGION"] directly (ash_pr_gate.py:330) -- a KeyError, not
    # a .get with a default -- because Lambda always sets it. Set explicitly rather than inherited:
    # the first version of this file passed locally only because this developer's shell had
    # AWS_REGION exported, and failed on all 18 CI legs where it is absent. A test whose verdict
    # depends on what happens to be in the environment is not testing the code, and local green
    # was not evidence of anything.
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    event = {
        "detail": {
            "pullRequestId": "7",
            "repositoryNames": ["repo"],
            "sourceCommit": "a" * 40,
            "destinationCommit": "b" * 40,
            "sourceReference": "refs/heads/feature",
            "revisionId": "rev-1",
        }
    }
    gate.handler(event, object())
    return client


@pytest.mark.parametrize(
    "scan_exit, expected_state, why",
    [
        (0, "APPROVE", "a clean scan is the one outcome that may approve"),
        (2, "REVOKE", "findings must withdraw an approval granted on earlier, cleaner code"),
        (
            1,
            "REVOKE",
            "exit 1 is the incomplete-scanner failure: nothing was scanned, so nothing "
            "supports an approval",
        ),
        (70, "REVOKE", "an unrecognised failure is not evidence of cleanliness"),
    ],
)
def test_approval_state_follows_the_outcome(
    gate, monkeypatch, tmp_path, scan_exit, expected_state, why
):
    client = _drive_handler(gate, monkeypatch, tmp_path, scan_exit)

    assert len(client.approval_calls) == 1, (
        f"exit {scan_exit}: expected exactly one approval-state call, got "
        f"{client.approval_calls}"
    )
    assert client.approval_calls[0]["approvalState"] == expected_state, why


def test_a_non_pass_outcome_never_leaves_the_state_untouched(gate, monkeypatch, tmp_path):
    """The specific regression: silence on a non-pass leaves a stale APPROVE standing.

    Asserted separately from the parametrized table because "no call was made" and "the wrong
    call was made" are different failures, and only this one describes the defect that was found.
    """
    client = _drive_handler(gate, monkeypatch, tmp_path, 2)

    assert client.approval_calls, (
        "findings left the approval state untouched; an approval granted on an earlier clean "
        "commit therefore survives on code the gate has just judged unclean"
    )


# ---------------------------------------------------------------------------
# 3. CDK and Terraform must not disagree about what revokes
# ---------------------------------------------------------------------------


def test_cdk_and_terraform_gates_both_revoke_on_a_non_pass():
    """Parity between the two infrastructure flavours.

    A behavioural parity test would need both runtimes -- the CDK gate's handler is a Python
    string inside a TypeScript template literal, executed only inside a Lambda image. What is
    checkable here is that neither file carries the shape this review flagged: an approval path
    that revokes in one flavour and declines to act in the other. Stated as the structural check
    it is, because a text assertion cannot prove behaviour, only that the branch exists.
    """
    assert CDK_SCRIPTS.is_file(), f"CDK scripts not found at {CDK_SCRIPTS}"
    cdk = CDK_SCRIPTS.read_text(encoding="utf-8")
    terraform = GATE_PATH.read_text(encoding="utf-8")

    assert "REVOKE" in cdk, "the CDK gate no longer revokes; parity has moved"
    assert "REVOKE" in terraform, (
        "the Terraform gate has no REVOKE path, so a stale approval survives a failing scan "
        "while the CDK gate withdraws it"
    )
    assert "leaving approval state unchanged" not in terraform, (
        "the leave-untouched branch is back; that is the defect this test exists for"
    )
