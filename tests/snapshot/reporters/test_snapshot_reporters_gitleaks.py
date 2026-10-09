# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the built-in reporters write for a scan with the gitleaks scanner on.

The default fixture scan never enables gitleaks, so nothing else in this suite shows
a gitleaks finding in a report. The input here is the real report gitleaks 8.30.1
wrote for ``tests/test_data/scanners/gitleaks/repo`` (committed beside it as
``gitleaks-8.30.1.sarif``, written from the tree ``tests/utils/gitleaks_fixture.py``
materializes, which is the source directory here too), put through ``GitleaksScanner._post_process_sarif`` --
the rating, tags and redaction a real scan applies -- and then through ASH's own
aggregation, as the canonical fixture is.

Each report is also checked for the fixture's credential values, so a reporter that
started rendering source lines next to a finding would fail here and not only show
up as a diff.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.snapshot.support.fixture_model import _build_model, fixture_plugin_context
from tests.utils.gitleaks_fixture import fabricated_tokens, materialize
from tests.snapshot.support.reporter_catalog import (
    BUILTIN_REPORTER_NAMES,
    build_reporter,
    reporter_classes,
    snapshot_extension,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
GITLEAKS_DATA = REPO_ROOT / "tests" / "test_data" / "scanners" / "gitleaks"


def _fixture_secrets() -> set[str]:
    found = set(fabricated_tokens().values())
    assert len(found) == 6, found
    return found


@pytest.fixture
def gitleaks_scan(pinned_clock, tmp_path: Path):
    """(model, context) for a scan whose only scanner is gitleaks, enabled."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        GitleaksScanner,
        GitleaksScannerConfig,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    config = AshConfig.model_validate(
        {
            "project_name": "gitleaks-snapshot",
            "scanners": {"gitleaks": {"enabled": True}},
        }
    )
    # The real tree, so a reporter that read source files would render the
    # fabricated values and fail the leak check below.
    source = materialize(tmp_path / "src")
    context = fixture_plugin_context(tmp_path, config=config, source_dir=source)
    scanner = GitleaksScanner(
        context=context, config=GitleaksScannerConfig(enabled=True)
    )
    raw = SarifReport.model_validate_json(
        (GITLEAKS_DATA / "gitleaks-8.30.1.sarif").read_text(encoding="utf-8")
    )
    processed = scanner._post_process_sarif(raw, [], source)

    manifest = tmp_path / "manifest"
    manifest.mkdir()
    (manifest / "gitleaks.sarif").write_text(
        processed.model_dump_json(by_alias=True, exclude_unset=True), encoding="utf-8"
    )
    (manifest / "scanners.yaml").write_text(
        yaml.safe_dump(
            {
                "scanners": [
                    {
                        "name": "gitleaks",
                        "outcome": "ran",
                        "output": "gitleaks.sarif",
                        "version": "8.30.1",
                        "duration_seconds": 0.5,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return _build_model(manifest, context), context


def test_the_model_carries_the_four_findings_as_critical(gitleaks_scan):
    model, _ = gitleaks_scan
    row = model.scanner_results["gitleaks"]
    assert (
        str(row.status.value if hasattr(row.status, "value") else row.status)
        == "FAILED"
    )
    results = model.sarif.runs[0].results
    assert sorted(r.ruleId for r in results) == [
        "aws-access-token",
        "github-pat",
        "github-pat",
        "slack-bot-token",
    ]


@pytest.mark.parametrize("reporter_name", BUILTIN_REPORTER_NAMES)
def test_reporter_output_with_gitleaks_enabled(
    reporter_name, gitleaks_scan, text_snapshot
):
    model, context = gitleaks_scan
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    document = reporter.report(model)

    text = document if isinstance(document, str) else json.dumps(document)
    leaked = [s for s in _fixture_secrets() if s in text]
    assert leaked == [], f"{reporter_name} rendered a fixture secret"
    assert document == text_snapshot(snapshot_extension(reporter))
