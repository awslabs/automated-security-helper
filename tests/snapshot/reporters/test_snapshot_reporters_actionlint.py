# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the reporters write for a scan with the opt-in actionlint scanner enabled.

The canonical fixture scan does not include actionlint, because a default scan does
not run it, so these snapshots carry its findings through the same aggregation over
their own manifest, ``tests/test_data/scanners/actionlint/snapshot_outputs``. The
SARIF that manifest names is built at test time by ``build_sarif`` -- the scanner's
own conversion -- from the pinned binary's real output over
``tests/test_data/scanners/actionlint/repo``, so a change to the conversion or the
severity mapping shows up here. The documents pin the severity mapping
(HIGH script injection and credentials, MEDIUM set-env and always-true ``if:``, LOW
lint) as a user reads it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_actionlint_plugins.actionlint_scanner import (
    build_sarif,
)

from tests.snapshot.support.fixture_model import (
    REPO_ROOT,
    _build_model,
    finalize_fixture_model,
    fixture_plugin_context,
)
from tests.snapshot.support.reporter_catalog import (
    build_reporter,
    reporter_classes,
    snapshot_extension,
)

ACTIONLINT_FIXTURES = REPO_ROOT / "tests" / "test_data" / "scanners" / "actionlint"
MANIFEST_DIR = ACTIONLINT_FIXTURES / "snapshot_outputs"
SOURCE_DIR = ACTIONLINT_FIXTURES / "repo"


@pytest.fixture
def actionlint_model(pinned_clock, tmp_path: Path):
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    shutil.copy(MANIFEST_DIR / "scanners.yaml", manifest_dir / "scanners.yaml")
    captured = json.loads(
        (ACTIONLINT_FIXTURES / "actionlint-1.7.12-default.json").read_text("utf-8")
    )
    (manifest_dir / "actionlint.sarif").write_text(
        json.dumps(build_sarif(captured, exit_code=1)), encoding="utf-8"
    )
    context = fixture_plugin_context(tmp_path, source_dir=SOURCE_DIR)
    return finalize_fixture_model(_build_model(manifest_dir, context)), context


@pytest.mark.parametrize("reporter_name", ["markdown", "sarif", "text"])
def test_reporter_output_with_actionlint_enabled(
    reporter_name, actionlint_model, text_snapshot
):
    model, context = actionlint_model
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    assert reporter.report(model) == text_snapshot(snapshot_extension(reporter))


def test_actionlint_status_and_counts(actionlint_model, snapshot):
    model, _ = actionlint_model
    status = model.scanner_results["actionlint"]
    assert status.model_dump(mode="json", exclude_unset=True) == snapshot
