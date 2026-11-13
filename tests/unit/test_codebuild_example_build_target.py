# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AWS CodeBuild example builds the image stage a root job can build.

CodeBuild runs the build as root. The default ``non-root`` image stage would give its
user UID 0, so container mode refuses it before building and names ``--build-target
ci``, the stage that runs as root. Every container command in the example asks for
that stage, so the example runs as written.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = REPO_ROOT / "examples" / "AWSCodeBuild"

#: An `ash` command that builds the image: a container-mode scan or build-image.
_CONTAINER_COMMAND = re.compile(r"\bash\b.*(--mode[ =]container|\bbuild-image\b)")


def _container_commands(path: Path) -> List[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if _CONTAINER_COMMAND.search(line)
    ]


@pytest.mark.parametrize("name", ["buildspec.yml", "README.md"])
def test_every_container_command_asks_for_the_ci_stage(name):
    commands = _container_commands(EXAMPLE / name)

    assert commands, f"no container command found in {name}"
    assert [c for c in commands if "--build-target ci" not in c] == []


def test_the_matcher_sees_a_command_without_the_stage():
    """Control for the check above."""
    assert _CONTAINER_COMMAND.search("      - ash --mode container --no-progress")
    assert not _CONTAINER_COMMAND.search(
        "      - pip install automated-security-helper"
    )
