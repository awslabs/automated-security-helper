"""The image-build bootstrap starter reads its project from the custom resource.

The starter is the inline Lambda behind ``Custom::AshImageBootstrap`` in the
committed CDK templates. It used to take the CodeBuild project name from a
``PROJECT_NAME`` environment variable. checkov's CKV_AWS_45 ("no hard-coded
secrets in Lambda environment") fired on that variable in CI on some runs and not
others, although its value was a ``Ref``. The name now travels as the custom
resource's ``ProjectName`` property, so the function has no environment at all.

These tests execute the handler code exactly as each committed template ships it,
with a recording stand-in for boto3, so they prove the shipped handler takes the
name from ``ResourceProperties`` and never touches the environment.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "deploy" / "cdk" / "templates"
BOOTSTRAP_TYPE = "Custom::AshImageBootstrap"


def _templates_with_bootstrap() -> list[Path]:
    found = []
    for path in sorted(TEMPLATE_DIR.glob("*.template.json")):
        resources = json.loads(path.read_text())["Resources"]
        if any(r.get("Type") == BOOTSTRAP_TYPE for r in resources.values()):
            found.append(path)
    return found


TEMPLATES = _templates_with_bootstrap()


def test_the_templates_with_a_bootstrap_are_found():
    # Non-vacuity: a rename that stopped the glob or the type match finding them
    # would leave every parametrized test below with nothing to run.
    assert [p.name for p in TEMPLATES] == [
        "AshAgentCore.template.json",
        "AshCodeCommitGate.template.json",
        "AshFargate.template.json",
    ]


def _starter(path: Path) -> tuple[dict, dict]:
    """The bootstrap custom resource and the Lambda its ServiceToken names."""
    resources = json.loads(path.read_text())["Resources"]
    (bootstrap,) = [r for r in resources.values() if r["Type"] == BOOTSTRAP_TYPE]
    starter_id = bootstrap["Properties"]["ServiceToken"]["Fn::GetAtt"][0]
    return bootstrap, resources[starter_id]


class _RecordingCodeBuild:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def start_build(self, **kwargs):
        self.calls.append(kwargs)
        return {"build": {"id": "recorded"}}


def _load_handler(
    code: str, codebuild: _RecordingCodeBuild, monkeypatch, tmp_path: Path
) -> dict:
    """Import the shipped handler as Lambda would, with boto3 replaced."""
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service: codebuild  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    source = tmp_path / "index.py"
    source.write_text(code)
    spec = importlib.util.spec_from_file_location("bootstrap_starter_index", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The module's own globals, so replacing `send` here is what `handler` calls.
    return vars(module)


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_the_starter_has_no_environment(path: Path):
    _, starter = _starter(path)
    assert "Environment" not in starter["Properties"]
    assert "KmsKeyArn" not in starter["Properties"]


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_the_shipped_handler_starts_the_project_named_in_resource_properties(
    path: Path, monkeypatch, tmp_path: Path
):
    bootstrap, starter = _starter(path)
    assert "ProjectName" in bootstrap["Properties"]
    # Nothing in the environment may stand in for the property.
    monkeypatch.delenv("PROJECT_NAME", raising=False)

    codebuild = _RecordingCodeBuild()
    namespace = _load_handler(
        starter["Properties"]["Code"]["ZipFile"], codebuild, monkeypatch, tmp_path
    )
    sent: list[tuple] = []
    namespace["send"] = lambda event, status, reason: sent.append((status, reason))

    event = {
        "RequestType": "Create",
        "ResponseURL": "https://example.invalid/response",
        "StackId": "stack-id",
        "RequestId": "request-id",
        "LogicalResourceId": "ImageBootstrapBuild",
        "ResourceProperties": {"ServiceToken": "arn", "ProjectName": "the-project"},
    }
    namespace["handler"](event, None)

    assert [c["projectName"] for c in codebuild.calls] == ["the-project"]
    # The success path stays silent: the build answers CloudFormation itself.
    assert sent == []


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_a_missing_project_name_fails_the_resource_instead_of_hanging(
    path: Path, monkeypatch, tmp_path: Path
):
    # If the property were ever dropped, the handler must still answer: a
    # KeyError escaping before `send` would leave CloudFormation waiting for an
    # hour on a response nobody sends.
    _, starter = _starter(path)
    codebuild = _RecordingCodeBuild()
    namespace = _load_handler(
        starter["Properties"]["Code"]["ZipFile"], codebuild, monkeypatch, tmp_path
    )
    sent: list[tuple] = []
    namespace["send"] = lambda event, status, reason: sent.append((status, reason))

    event = {
        "RequestType": "Create",
        "ResponseURL": "https://example.invalid/response",
        "StackId": "stack-id",
        "RequestId": "request-id",
        "LogicalResourceId": "ImageBootstrapBuild",
        "ResourceProperties": {"ServiceToken": "arn"},
    }
    namespace["handler"](event, None)

    assert codebuild.calls == []
    assert [status for status, _ in sent] == ["FAILED"]
