# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every image the validate-container action builds or scans with is the ``ci`` stage.

The action used to rely on CI variables forcing ``ash build-image`` and
``ash --mode container`` onto the root ``ci`` stage: its nerdctl leg hardcodes
``IMAGE: automated-security-helper:ci`` as the tag of the image it removes before a
retry, and the license check that follows reads ``automated-security-helper:ci`` by
default. CI variables no longer choose the stage, so each invocation has to ask for
``ci`` itself, or the action builds ``non-root`` and then looks for a ``ci`` image
nothing built.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "validate-container" / "action.yml"


def _steps() -> List[dict]:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]


def _commands(script: str) -> Iterator[str]:
    """Each shell command in *script* with its backslash continuations joined."""
    pending = ""
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        yield pending + stripped
        pending = ""
    if pending:
        yield pending


def _ash_invocations() -> List[str]:
    found = []
    for step in _steps():
        for command in _commands(step.get("run") or ""):
            if command.startswith(("ash build-image", "ash scan", "ash --mode")):
                found.append(command)
    return found


def test_the_action_builds_and_scans_with_ash():
    """Guards the guard: an empty list would pass the test below vacuously."""
    invocations = _ash_invocations()

    assert sum(cmd.startswith("ash build-image") for cmd in invocations) == 3
    assert any("--mode container" in cmd for cmd in invocations)


def test_every_build_and_container_scan_asks_for_the_ci_stage():
    missing = [
        cmd
        for cmd in _ash_invocations()
        if "--build-target ci" not in cmd.split("#")[0]
    ]

    assert missing == []


def test_the_image_the_nerdctl_leg_removes_is_the_ci_stage():
    images = [
        step["env"]["IMAGE"] for step in _steps() if "IMAGE" in (step.get("env") or {})
    ]

    assert images == ["automated-security-helper:ci"]
