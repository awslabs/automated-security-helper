# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the reporters write for a scan with the opt-in hadolint scanner enabled.

The canonical fixture (test_snapshot_reporters.py) is a default scan, so hadolint
is absent from it by design: an opt-in scanner nobody enabled leaves no trace. This
is the other half: hadolint enabled, run over tests/test_data/scanners/hadolint/
positive, which has a finding at each of hadolint's four levels. The snapshots pin
the severity mapping (error/warning/info/style -> HIGH/MEDIUM/LOW/INFO) as each
report a user opens renders it.

The model is built by the same pipeline as the canonical one
(tests/snapshot/support/fixture_model.py), from the manifest in
tests/test_data/snapshot_fixture/scanner_outputs_hadolint.
"""

from __future__ import annotations

import pytest

from tests.snapshot.support.fixture_model import (
    FIXTURE_ROOT,
    _build_model,
    fixture_plugin_context,
)
from tests.snapshot.support.normalize import REPO_ROOT
from tests.snapshot.support.reporter_catalog import (
    build_reporter,
    reporter_classes,
    snapshot_extension,
)

MANIFEST = FIXTURE_ROOT / "scanner_outputs_hadolint"
SOURCE = REPO_ROOT / "tests" / "test_data" / "scanners" / "hadolint" / "positive"
REPORTERS = ("csv", "flat-json", "markdown", "sarif", "text")


@pytest.fixture
def hadolint_model(pinned_clock, tmp_path):
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig.model_validate(
        {
            "project_name": "hadolint-snapshot",
            "scanners": {"hadolint": {"enabled": True}},
        }
    )
    context = fixture_plugin_context(tmp_path, config=config, source_dir=SOURCE)
    return _build_model(MANIFEST, context), context


@pytest.mark.parametrize("reporter_name", REPORTERS)
def test_reporter_output_with_hadolint_enabled(
    reporter_name, hadolint_model, text_snapshot
):
    model, context = hadolint_model
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    assert reporter.report(model) == text_snapshot(snapshot_extension(reporter))


def test_hadolint_row(hadolint_model, snapshot):
    model, _ = hadolint_model
    row = model.scanner_results["hadolint"].model_dump(mode="json")
    assert row == snapshot
