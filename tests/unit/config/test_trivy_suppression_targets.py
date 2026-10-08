# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Hold the trivy suppressions in .ash/.ash_community_plugins.yaml to the code.

The self-scan reads these entries, and an entry that matches nothing produces
no error, so a source change can leave one behind silently. Two shapes have
gone stale that way:

- an entry for a finding whose resource is gone or now carries the key. trivy
  reports AWS-0017 (log group) and AWS-0098 (secret) on a CloudFormation
  resource whose key is absent or conditional, and on a terraform resource with
  no ``kms_key_id`` argument. Binding ``kms_key_id`` to an input clears the
  finding even at the input's null default (measured with trivy 0.69.3 on the
  fargate task log group).
- a reason that cites an inline checkov skip which has since been deleted.

Neither check runs trivy. Each reads the files the entry names, so it can only
say an entry has no target left; it cannot prove one that passes is needed.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = ".ash/.ash_community_plugins.yaml"

# rule id -> (CloudFormation resource type, terraform resource type)
KMS_RULES = {
    "AWS-0017": ("AWS::Logs::LogGroup", "aws_cloudwatch_log_group"),
    "AWS-0098": ("AWS::SecretsManager::Secret", "aws_secretsmanager_secret"),
}

CHECKOV_ID = re.compile(r"\bCKV2?_[A-Z0-9]+_\d+\b")


def _entries() -> list[dict[str, Any]]:
    document = yaml.safe_load((REPO_ROOT / CONFIG).read_text())
    return document["global_settings"]["suppressions"]


def _cfn_has_unkeyed(template: dict[str, Any], resource_type: str) -> bool:
    for resource in (template.get("Resources") or {}).values():
        if resource.get("Type") != resource_type:
            continue
        key = (resource.get("Properties") or {}).get("KmsKeyId")
        if key is None or (isinstance(key, dict) and "Fn::If" in key):
            return True
    return False


def _strip_hcl_comments(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")):
            continue
        out.append(line)
    return "\n".join(out)


def _tf_blocks(text: str, resource_type: str) -> list[str]:
    """Bodies of every ``resource "<type>" "<name>" { ... }`` block."""
    text = _strip_hcl_comments(text)
    bodies = []
    for match in re.finditer(rf'resource\s+"{resource_type}"\s+"[^"]+"\s*\{{', text):
        depth, start = 1, match.end()
        i = start
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[start : i - 1])
    return bodies


def _tf_top_level_args(body: str) -> set[str]:
    depth, names = 0, set()
    for line in body.splitlines():
        if depth == 0:
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
            if match:
                names.add(match.group(1))
        depth += line.count("{") - line.count("}")
    return names


def _tf_has_unkeyed(text: str, resource_type: str) -> bool:
    return any(
        "kms_key_id" not in _tf_top_level_args(body)
        for body in _tf_blocks(text, resource_type)
    )


def has_target(rule_id: str, path: str, text: str) -> bool:
    cfn_type, tf_type = KMS_RULES[rule_id]
    if path.endswith(".json"):
        return _cfn_has_unkeyed(json.loads(text), cfn_type)
    return _tf_has_unkeyed(text, tf_type)


def _tracked_files() -> list[str]:
    """Tracked paths, or a test failure that says why they could not be listed.

    The skip index must be built from tracked files only: a walk of the tree
    would also read node_modules and build output, whose checkov comments are
    not this repository's decisions. Outside a git checkout (a ``git archive``
    extract, say) there is no such list, so the check fails rather than pass
    on an empty index.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        pytest.fail("git is not installed; this check reads the tracked file list.")
    if result.returncode != 0:
        pytest.fail(
            f"`git ls-files` failed in {REPO_ROOT} (exit {result.returncode}): "
            f"{result.stderr.strip()}. This check needs a git checkout to know "
            "which files are tracked."
        )
    return [name for name in result.stdout.split("\0") if name]


@lru_cache(maxsize=1)
def _inline_skips() -> dict[str, frozenset[str]]:
    files = _tracked_files()
    found: dict[str, set[str]] = {}
    for name in files:
        try:
            text = (REPO_ROOT / name).read_text(errors="ignore")
        except (IsADirectoryError, FileNotFoundError):
            continue
        for match in re.finditer(r"checkov:skip=([A-Z0-9_]+)", text):
            found.setdefault(match.group(1), set()).add(name)
    return {k: frozenset(v) for k, v in found.items()}


def stale_skip_citations(
    entry: dict[str, Any], skips: dict[str, frozenset[str]]
) -> list[str]:
    """Checkov ids an entry's reason cites as inline skips that do not exist.

    A reason saying "this module" or "this file" must find the skip in the
    entry's own path; any other mention needs it somewhere in the repository.
    """
    reason = entry.get("reason") or ""
    if "inline" not in reason:
        return []
    own = "this module" in reason or "this file" in reason
    stale = []
    for checkov_id in sorted(set(CHECKOV_ID.findall(reason))):
        holders = skips.get(checkov_id, frozenset())
        if not holders or (own and entry.get("path") not in holders):
            stale.append(checkov_id)
    return stale


def _kms_entries() -> list[dict[str, Any]]:
    return [
        e
        for e in _entries()
        if e.get("rule_id") in KMS_RULES and (e.get("path") or "").startswith("deploy/")
    ]


def test_there_are_kms_entries_to_check():
    # Guards against the selector going vacuous after a config restructure.
    assert len(_kms_entries()) >= 5


def test_every_kms_suppression_has_an_unkeyed_resource():
    stale = []
    for entry in _kms_entries():
        path = entry["path"]
        target = REPO_ROOT / path
        if not target.is_file() or not has_target(
            entry["rule_id"], path, target.read_text()
        ):
            stale.append((entry["rule_id"], path))
    assert not stale, (
        f"These entries in {CONFIG} name a file with no resource left that trivy "
        f"would report. Delete them and their suppression_scope_baseline.py keys: "
        f"{stale}"
    )


def test_reasons_cite_inline_skips_that_exist():
    skips = _inline_skips()
    stale = [
        (e.get("rule_id"), e.get("path"), ids)
        for e in _entries()
        if (ids := stale_skip_citations(e, skips))
    ]
    assert not stale, (
        f"These reasons in {CONFIG} cite inline skips that are gone: {stale}"
    )


TF_KEYED = """
resource "aws_cloudwatch_log_group" "task" {
  # kms_key_id would go here
  name       = "x"
  kms_key_id = var.kms_key_arn
}
"""
TF_UNKEYED = """
resource "aws_cloudwatch_log_group" "task" {
  #checkov:skip=CKV_AWS_158:reason mentioning kms_key_id = nothing
  name = "x"
  dynamic "x" {
    content {
      kms_key_id = "nested, not the log group's own argument"
    }
  }
}
"""


@pytest.mark.parametrize(
    "rule_id, path, text, expected",
    [
        ("AWS-0017", "m/main.tf", TF_KEYED, False),
        ("AWS-0017", "m/main.tf", TF_UNKEYED, True),
        ("AWS-0098", "m/main.tf", TF_UNKEYED, False),
        (
            "AWS-0098",
            "t.template.json",
            json.dumps({"Resources": {}}),
            False,
        ),
        (
            "AWS-0098",
            "t.template.json",
            json.dumps(
                {
                    "Resources": {
                        "S": {
                            "Type": "AWS::SecretsManager::Secret",
                            "Properties": {
                                "KmsKeyId": {"Fn::If": ["HasKmsKey", "k", "v"]}
                            },
                        }
                    }
                }
            ),
            True,
        ),
        (
            "AWS-0017",
            "t.template.json",
            json.dumps(
                {
                    "Resources": {
                        "L": {
                            "Type": "AWS::Logs::LogGroup",
                            "Properties": {"KmsKeyId": "arn:literal"},
                        }
                    }
                }
            ),
            False,
        ),
    ],
)
def test_has_target_classifier(rule_id, path, text, expected):
    assert has_target(rule_id, path, text) is expected


def test_stale_skip_citation_classifier():
    skips = {"CKV_AWS_158": frozenset({"a/main.tf"})}
    assert stale_skip_citations(
        {"path": "b/main.tf", "reason": "this module's inline CKV_AWS_158 skip"},
        skips,
    ) == ["CKV_AWS_158"]
    assert (
        stale_skip_citations(
            {"path": "x.json", "reason": "the CKV_AWS_158 inline skips"}, skips
        )
        == []
    )
    assert stale_skip_citations(
        {"path": "x.json", "reason": "the CKV_AWS_149 inline skips"}, skips
    ) == ["CKV_AWS_149"]


def test_outside_a_checkout_the_skip_index_fails_with_a_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    _inline_skips.cache_clear()
    try:
        with pytest.raises(pytest.fail.Exception, match="needs a git checkout"):
            _inline_skips()
    finally:
        _inline_skips.cache_clear()
