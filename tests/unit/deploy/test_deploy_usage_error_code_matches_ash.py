# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every deployment target's copy of ASH's usage-error code is ASH_EXIT_USAGE_ERROR.

Why this exists
---------------
The deployment targets run ASH in places that cannot import it -- a Lambda
handler, a CodeBuild buildspec, a CloudFormation template that embeds the
handler -- so each keeps its own copy of the exit code ASH gives for a refused
command line, and turns it into its own message ("ASH refused this gate's command
line"). Those copies are literals. If ASH_EXIT_USAGE_ERROR in
``core/constants.py`` changed, each target would read the new code as an unknown
failure, or worse as findings, and nothing would say so.

What the test checks
--------------------
That the literal is ASH_EXIT_USAGE_ERROR in each copy: the CDK container scripts'
``EXIT_USAGE_ERROR``, the same constant in every synthesized template that embeds
them, the Terraform CodeCommit gate handler's ``EXIT_USAGE_ERROR``, and the
``N)`` arm (and the exit-code table comment) of the CodePipeline executor's merge
buildspec. Each lookup must find its copy, so a renamed constant fails here too
rather than leaving nothing to compare.

The templates are found by content, so a template whose copy stopped parsing
would drop out of the comparison silently. Two checks close that: the set of
templates that embed the constant is pinned, and a template that mentions
``EXIT_USAGE_ERROR`` without a value this test reads fails.

A definition is not a use. The Terraform handler is run with ASH's usage-error
code as the scan's exit, and its pull request comment has to carry the
usage-error hint; with another error code it must not. (The CDK side's use is
checked by deploy/cdk/test/ash-container-scripts.test.ts.)
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
CONTAINER_SCRIPTS = REPO / "deploy" / "cdk" / "lib" / "ash-container-scripts.ts"
TEMPLATES = REPO / "deploy" / "cdk" / "templates"
GATE_HANDLER = (
    REPO
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)
MERGE_BUILDSPEC = (
    REPO
    / "deploy"
    / "terraform"
    / "modules"
    / "codepipeline-executor"
    / "buildspec-merge.yml.tftpl"
)

#: The synthesized templates that embed the CDK container scripts' usage-error
#: handling. A template added to or dropped from this set is a change to review.
EMBEDDING_TEMPLATES = {
    "AshCodeCommitGate.template.json",
    "AshImagePipeline.template.json",
}

CONSTANT = re.compile(r"^\s*EXIT_USAGE_ERROR\s*=\s*(\d+)\s*$", re.MULTILINE)


def _constants(text: str) -> list[int]:
    return [int(value) for value in CONSTANT.findall(text)]


def _template_strings(node):
    """Every string in a CloudFormation template, joined by Fn::Join pieces too."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _template_strings(value)
    elif isinstance(node, list):
        if len(node) == 2 and isinstance(node[0], str) and isinstance(node[1], list):
            yield "".join(piece for piece in node[1] if isinstance(piece, str))
        for value in node:
            yield from _template_strings(value)


def test_the_cdk_container_scripts():
    found = _constants(CONTAINER_SCRIPTS.read_text(encoding="utf-8"))
    assert found, f"{CONTAINER_SCRIPTS} defines no EXIT_USAGE_ERROR"
    assert set(found) == {ASH_EXIT_USAGE_ERROR}, found


def _templates_embedding_the_constant():
    embedding = []
    for template in sorted(TEMPLATES.glob("*.template.json")):
        document = json.loads(template.read_text(encoding="utf-8"))
        values = [
            value
            for text in _template_strings(document)
            for value in _constants(text.replace("\\n", "\n"))
        ]
        if values:
            embedding.append((template.name, values))
    return embedding


def test_the_templates_that_embed_the_constant_are_the_expected_ones():
    names = {name for name, _ in _templates_embedding_the_constant()}
    assert names == EMBEDDING_TEMPLATES, names


def test_no_template_mentions_the_constant_without_a_value_this_test_reads():
    mentioning = {
        template.name
        for template in TEMPLATES.glob("*.template.json")
        if "EXIT_USAGE_ERROR" in template.read_text(encoding="utf-8")
    }
    parsed = {name for name, _ in _templates_embedding_the_constant()}
    assert mentioning, f"no template under {TEMPLATES} mentions EXIT_USAGE_ERROR"
    assert mentioning <= parsed, sorted(mentioning - parsed)


@pytest.mark.parametrize(
    "name, values",
    _templates_embedding_the_constant(),
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_every_synthesized_template(name, values):
    assert set(values) == {ASH_EXIT_USAGE_ERROR}, (name, values)


def test_the_terraform_codecommit_gate_handler():
    found = _constants(GATE_HANDLER.read_text(encoding="utf-8"))
    assert found, f"{GATE_HANDLER} defines no EXIT_USAGE_ERROR"
    assert set(found) == {ASH_EXIT_USAGE_ERROR}, found


def test_the_terraform_merge_buildspec():
    text = MERGE_BUILDSPEC.read_text(encoding="utf-8")
    arms = [
        int(n)
        for n in re.findall(
            r"^\s*(\d+)\)\s*echo \"ash merge: usage error", text, re.MULTILINE
        )
    ]
    table = [
        int(n) for n in re.findall(r"^#\s+(\d+)\s+usage error", text, re.MULTILINE)
    ]
    assert arms, f"{MERGE_BUILDSPEC} has no usage-error case arm"
    assert table, f"{MERGE_BUILDSPEC} has no usage-error row in its exit-code table"
    assert set(arms) == set(table) == {ASH_EXIT_USAGE_ERROR}, (arms, table)


class _CodeCommit:
    """Records what the handler posts; nothing else about the client is used."""

    def __init__(self) -> None:
        self.comments: list[str] = []
        self.approvals: list[str] = []

    def post_comment_for_pull_request(self, **kwargs):
        self.comments.append(kwargs["content"])
        return {}

    def update_pull_request_approval_state(self, **kwargs):
        self.approvals.append(kwargs["approvalState"])
        return {}


def _load_gate() -> ModuleType:
    """The handler, loaded by path: it is packaged into a Lambda, not importable."""
    spec = importlib.util.spec_from_file_location(
        "_ash_pr_gate_usage_error_use", GATE_HANDLER
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_handler(
    scan_exit: int, monkeypatch, tmp_path
) -> tuple[ModuleType, _CodeCommit]:
    """The handler end to end, with the scan's exit code forced and no AWS call."""
    gate = _load_gate()
    client = _CodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: (
            client
            if service == "codecommit"
            else pytest.fail(f"unexpected boto3 client requested: {service}")
        ),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    monkeypatch.setattr(
        gate, "run_scan", lambda *a, **k: (scan_exit, tmp_path / "out", "log tail")
    )
    monkeypatch.setattr(gate, "read_severity_counts", lambda *a, **k: None)
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
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
    return gate, client


def test_the_terraform_handler_names_ashs_usage_error_on_the_pull_request(
    monkeypatch, tmp_path
):
    gate, client = _run_handler(ASH_EXIT_USAGE_ERROR, monkeypatch, tmp_path)

    assert len(client.comments) == 1, client.comments
    assert gate.USAGE_ERROR_HINT in client.comments[0], client.comments[0]
    assert client.approvals == ["REVOKE"]


def test_control_another_error_code_gets_no_usage_error_hint(monkeypatch, tmp_path):
    gate, client = _run_handler(1, monkeypatch, tmp_path)

    assert len(client.comments) == 1, client.comments
    assert gate.USAGE_ERROR_HINT not in client.comments[0], client.comments[0]
    assert client.approvals == ["REVOKE"]
