# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the built-in reporters write for a scan with the opt-in trivy scanner on.

The default fixture scan never enables trivy, so nothing else in this suite shows a
trivy finding in a report. The input here is the real report trivy v0.69.3 wrote for
the fixture repository ``tests/utils/trivy_fixture.py`` materializes (committed as
``trivy-0.69.3.vuln.sarif``), put through ``TrivyScanner._post_process_sarif`` -- the
package identity and severity a real scan applies -- and then through ASH's own
aggregation, as the canonical fixture is.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.utils.trivy_fixture import materialize
import yaml

from tests.snapshot.support.fixture_model import _build_model, fixture_plugin_context
from tests.snapshot.support.reporter_catalog import (
    BUILTIN_REPORTER_NAMES,
    build_reporter,
    reporter_classes,
    snapshot_extension,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
TRIVY_DATA = REPO_ROOT / "tests" / "test_data" / "scanners" / "trivy"


@pytest.fixture
def trivy_scan(pinned_clock, tmp_path: Path):
    """(model, context) for a scan whose only scanner is trivy, enabled."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
        TrivyScannerConfigOptions,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    config = AshConfig.model_validate(
        {"project_name": "trivy-snapshot", "scanners": {"trivy": {"enabled": True}}}
    )
    # The lockfile is read to tie each npm result to its package copy.
    source = tmp_path / "src"
    materialize(source)
    context = fixture_plugin_context(tmp_path, config=config, source_dir=source)
    scanner = TrivyScanner(
        context=context,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(offline=False)
        ),
    )
    raw = SarifReport.model_validate_json(
        (TRIVY_DATA / "trivy-0.69.3.vuln.sarif").read_text(encoding="utf-8")
    )
    processed = scanner._post_process_sarif(raw, [], source)

    manifest = tmp_path / "manifest"
    manifest.mkdir()
    (manifest / "trivy.sarif").write_text(
        processed.model_dump_json(by_alias=True, exclude_unset=True), encoding="utf-8"
    )
    (manifest / "scanners.yaml").write_text(
        yaml.safe_dump(
            {
                "scanners": [
                    {
                        "name": "trivy",
                        "outcome": "ran",
                        "output": "trivy.sarif",
                        "version": "0.69.3",
                        "duration_seconds": 0.5,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return _build_model(manifest, context), context


def test_the_model_carries_trivys_findings_at_trivys_severity(trivy_scan):
    model, _ = trivy_scan
    row = model.scanner_results["trivy"]
    status = row.status.value if hasattr(row.status, "value") else row.status
    assert str(status) == "FAILED"
    results = model.sarif.runs[0].results
    assert len(results) == 10
    by_rule = {r.ruleId: r.properties.issue_severity for r in results}
    assert by_rule["CVE-2018-18074"] == "HIGH"
    assert by_rule["CVE-2023-32681"] == "MEDIUM"


@pytest.mark.parametrize("reporter_name", BUILTIN_REPORTER_NAMES)
def test_reporter_output_with_trivy_enabled(reporter_name, trivy_scan, text_snapshot):
    model, context = trivy_scan
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    document = reporter.report(model)

    assert document == text_snapshot(snapshot_extension(reporter))
