# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace fixture's output is the same whether or not the host has npm.

The api project's npm-audit is MISSING by the fixture's own design -- its
manifest records ``outcome: missing``, and ``for_missing_deps`` builds that
container without looking any tool up -- so a golden regenerated on a host
with npm and one without must be byte-identical. This control pins that: a
snapshot that appears or disappears with the host's npm would be a
hermeticity defect in the fixture, and this cell fails before any golden
can flap.

Both arms run in one test, each under its own ``MonkeyPatch`` with its own
``pin_clock``: a fresh uuid counter per arm, so the two builds draw the
same pinned ids and instants. One arm puts a stub npm first on PATH (so the
"present" arm is real on a host that has no npm of its own, such as the
burner pool's); the other strips every npm-holding directory from PATH. The
flat-json workspace document is compared after the shared normalizer masks
each arm's temp root to the same token.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Optional, Tuple

import pytest

from tests.snapshot.support.fixture_model import (
    build_fixture_workspace_model,
    pin_clock,
    workspace_reporter_context,
)
from tests.snapshot.support.normalize import default_normalizer
from tests.snapshot.support.reporter_catalog import build_reporter, reporter_classes


def _flat_json_document(arm_dir: Path, path_value: str) -> Tuple[str, Optional[str]]:
    """One arm's rendered document, and what which() finds npm to be there."""
    arm_dir.mkdir(parents=True, exist_ok=True)
    patcher = pytest.MonkeyPatch()
    try:
        patcher.setenv("PATH", path_value)
        found = shutil.which("npm")
        pin_clock(patcher)
        model = build_fixture_workspace_model(arm_dir, patcher)
        context = workspace_reporter_context(model, arm_dir)
        reporter = build_reporter(reporter_classes()["flat-json"], context)
        return reporter.report(model), found
    finally:
        patcher.undo()


def test_the_workspace_output_is_identical_with_and_without_npm(tmp_path: Path):
    without_npm = os.pathsep.join(
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and not (Path(entry) / "npm").exists()
    )
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir()
    stub = stub_dir / "npm"
    # Never run -- nothing in the fixture build looks npm up, which is the
    # point. It exists so the "present" arm is real on any host.
    stub.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    with_npm = os.pathsep.join([str(stub_dir), without_npm])

    present_dir = tmp_path / "with-npm"
    absent_dir = tmp_path / "without-npm"
    present, found_present = _flat_json_document(present_dir, with_npm)
    absent, found_absent = _flat_json_document(absent_dir, without_npm)
    if found_present != str(stub) or found_absent is not None:
        raise RuntimeError(
            (
                "premise: the arms must differ in npm visibility",
                found_present,
                found_absent,
            )
        )

    normalizer = default_normalizer(tmp_paths=[present_dir, absent_dir])
    assert normalizer.text(present) == normalizer.text(absent)
