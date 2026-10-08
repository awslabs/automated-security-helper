# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the reports say when the opt-in cfn-lint and cfn-guard scanners are enabled.

The default fixture scan in tests/snapshot/support/fixture_model.py does not enable
them, which is the point of opt-in: its snapshots must not change when they are added.
This module enables both on the CloudFormation fixture repository under
tests/test_data/scanners/cfn_lint_guard and renders the reports a user opens.

The scanner results are the real tool output captured in that directory (cfn-lint
1.57.1, cfn-guard 3.2.1 with wa-Security-Pillar), passed through each scanner's own
normalization, so the severity mapping and the URI rewrite are part of what is pinned.
Everything after that is ASH's own aggregation, via ``_build_model``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from tests.snapshot.support.normalize import REPO_ROOT
from tests.snapshot.support.reporter_catalog import (
    build_reporter,
    reporter_classes,
    snapshot_extension,
)

CFN_FIXTURES = REPO_ROOT / "tests" / "test_data" / "scanners" / "cfn_lint_guard"
REPORTERS = ("markdown", "sarif", "text")


def _normalized_outputs(manifest_dir: Path, source_dir: Path) -> None:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_guard_scanner import (
        CfnGuardScanner,
    )
    from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_lint_scanner import (
        CfnLintScanner,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    context = PluginContext(
        source_dir=source_dir,
        output_dir=manifest_dir / "out",
        config=get_default_config(),
    )
    captured = CFN_FIXTURES / "captured"

    lint = SarifReport.model_validate(
        json.loads((captured / "cfn-lint-1.57.1-insecure.sarif").read_text())
    )
    lint = CfnLintScanner(context=context).normalize_report(lint)
    (manifest_dir / "cfn-lint.sarif").write_text(
        lint.model_dump_json(by_alias=True, exclude_none=True), encoding="utf-8"
    )

    guard_raw = SarifReport.model_validate(
        json.loads(
            (captured / "cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif").read_text()
        )
    )
    guard = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cfn-guard", "version": "3.2.1"}}}],
        }
    )
    guard.runs[0].results = CfnGuardScanner.normalize_results(
        guard_raw, "templates/insecure.yaml"
    )
    (manifest_dir / "cfn-guard.sarif").write_text(
        guard.model_dump_json(by_alias=True, exclude_none=True), encoding="utf-8"
    )

    (manifest_dir / "scanners.yaml").write_text(
        yaml.safe_dump(
            {
                "scanners": [
                    {
                        "name": "cfn-guard",
                        "outcome": "ran",
                        "output": "cfn-guard.sarif",
                        "version": "3.2.1",
                        "duration_seconds": 0.5,
                    },
                    {
                        "name": "cfn-lint",
                        "outcome": "ran",
                        "output": "cfn-lint.sarif",
                        "version": "1.57.1",
                        "duration_seconds": 1.0,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def cfn_model(pinned_clock, tmp_path: Path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from tests.snapshot.support.fixture_model import (
        _build_model,
        finalize_fixture_model,
    )

    source = tmp_path / "repo"
    shutil.copytree(CFN_FIXTURES / "repo", source)
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    _normalized_outputs(manifest_dir, source)
    config = AshConfig.model_validate(
        {
            "project_name": "cfn-scanners",
            "scanners": {"cfn-lint": {"enabled": True}, "cfn-guard": {"enabled": True}},
        }
    )
    context = PluginContext(
        source_dir=source, output_dir=tmp_path / "ash_output", config=config
    )
    model = finalize_fixture_model(_build_model(manifest_dir, context))
    return model, context


@pytest.mark.parametrize("reporter_name", REPORTERS)
def test_report_with_cfn_lint_and_cfn_guard_enabled(
    reporter_name, cfn_model, text_snapshot
):
    model, context = cfn_model
    reporter = build_reporter(reporter_classes()[reporter_name], context)
    assert reporter.report(model) == text_snapshot(snapshot_extension(reporter))


def test_scanner_rows_and_severities(cfn_model, snapshot):
    """The per-scanner status and severity counts, independent of any one format."""
    model, _ = cfn_model
    assert {
        name: {
            "status": str(getattr(row.status, "value", row.status)),
            "severity_counts": row.severity_counts.model_dump(),
        }
        for name, row in sorted(model.scanner_results.items())
    } == snapshot
