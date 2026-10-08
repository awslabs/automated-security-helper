# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lines the repository's own ASH scan reported as actionable stay marked or fixed.

The python-local and SAST self-scans failed the v4 train on four findings in files the
train added: bandit B108 on two container log paths in a test, and detect-secrets on two
hex strings, the pinned Flatpak runtime commit and a release SHA fixture. Each is fixed
at the line, following the convention in .ash/.ash.yaml: the fixture no longer looks
like a digest, and the two that must stay carry the per-line marker with its reason.

This runs detect-secrets itself on those files, and bandit's B108 rule (a string that
starts with a temp directory) as an AST check, so a marker dropped in an edit fails here
rather than in the self-scan.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

REPO_ROOT = Path(__file__).resolve().parents[2]

SECRET_SCANNED = (
    "packaging/flatpak/verify-in-container.sh",
    "tests/unit/test_release_notes_workflow.py",
    "tests/unit/test_native_packages_workflow.py",
)

# bandit's hardcoded_tmp_directory default list.
TMP_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm")  # nosec B108 - the rule's own list


@pytest.mark.parametrize("relative", SECRET_SCANNED)
def test_detect_secrets_finds_nothing_unmarked(relative):
    secrets = SecretsCollection()
    with default_settings():
        secrets.scan_file(str(REPO_ROOT / relative))
    found = [f"{relative}:{secret.line_number} {secret.type}" for _, secret in secrets]
    assert found == []


def test_every_temp_path_literal_in_the_native_workflow_test_carries_nosec():
    path = REPO_ROOT / "tests/unit/test_native_packages_workflow.py"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    bare = [
        f"{node.lineno}: {node.value}"
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(TMP_PREFIXES)
        and "nosec B108" not in lines[node.lineno - 1]
    ]
    assert bare == []
