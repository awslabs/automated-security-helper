#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform merge action must name each `ash merge` exit code, and keep it.

The merge action's last command reads the exit code the merge recorded, prints what it
means and exits with it unchanged. ASH releases after 3.7.1 exit 5 for a usage error,
and the command had no arm for it, so a refused command line printed only "exited 5".
That is a wording defect, not a verdict one: the code is still propagated. These run
the committed command against each code.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
MERGE_BUILDSPEC = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codepipeline-executor"
    / "buildspec-merge.yml.tftpl"
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="executes a POSIX buildspec command destined for a Linux build container",
    ),
]


def _verdict_command() -> str:
    spec = yaml.safe_load(MERGE_BUILDSPEC.read_text(encoding="utf-8"))
    matches = [
        command
        for command in spec["phases"]["post_build"]["commands"]
        if 'case "$MERGE_EXIT"' in command
    ]
    assert len(matches) == 1, f"expected one verdict command, found {len(matches)}"
    return matches[0]


@pytest.mark.parametrize(
    "code, says",
    [
        (0, "no actionable findings"),
        (1, "shard coverage incomplete"),
        (2, "actionable findings at or above"),
        (5, "usage error"),
        (70, "exited 70"),
    ],
)
def test_each_exit_code_is_named_and_propagated(tmp_path, code, says):
    (tmp_path / "merge_exit_code").write_text(str(code), encoding="utf-8")
    shell = shutil.which("sh")
    assert shell, "no sh on PATH"

    result = subprocess.run(
        [shell, "-c", _verdict_command()],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "MIN_SEVERITY": "low"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == code, (result.returncode, result.stderr)
    assert says in result.stdout + result.stderr, result.stdout + result.stderr
