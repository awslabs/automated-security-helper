# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the reporters write when the opt-in zizmor scanner is enabled.

The canonical fixture scan (tests/snapshot/support/fixture_model.py) is the default
scanner set, which never includes an opt-in scanner, so it cannot show how a zizmor
finding renders. This builds a second model through the same aggregation, from one
scanner: ``ZizmorScanner.scan`` itself, over tests/test_data/scanners/zizmor/repo,
with only the subprocess replaced by the real zizmor 1.30.1 SARIF committed beside
that fixture. The severity mapping, the URI rebasing and the invocation record are
therefore the scanner's own, and a change to any of them shows up here.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from tests.snapshot.support.normalize import REPO_ROOT
from tests.snapshot.support.reporter_catalog import build_reporter, reporter_classes
from tests.snapshot.support.reporter_catalog import snapshot_extension

ZIZMOR_FIXTURE = REPO_ROOT / "tests" / "test_data" / "scanners" / "zizmor"

#: The reporters a person reads a finding in, plus the machine-readable SARIF.
REPORTERS = ("flat-json", "markdown", "sarif", "text")


def _zizmor_report(source: Path, output: Path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_zizmor_plugins.zizmor_scanner import (
        ZizmorScanner,
        ZizmorScannerConfig,
    )

    config = AshConfig.model_validate(
        {"project_name": "zizmor-snapshot", "scanners": {"zizmor": {"enabled": True}}}
    )
    context = PluginContext(source_dir=source, output_dir=output, config=config)
    scanner = ZizmorScanner(context=context, config=ZizmorScannerConfig(enabled=True))
    sarif_text = (ZIZMOR_FIXTURE / "zizmor-1.30.1.sarif").read_text("utf-8")

    def run(command, results_dir=None, env=None, timeout=None, **_):
        Path(results_dir, "ZizmorScanner.stdout.log").write_text(sarif_text, "utf-8")
        response = {"returncode": 0}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    report = scanner.scan(source, "source", [])
    return report, context


@pytest.fixture
def zizmor_model(tmp_path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_zizmor_plugins.zizmor_scanner import (
        ZizmorScanner,
    )
    from tests.snapshot.support.fixture_model import _build_model, pin_clock

    # The scanner stamps its own start and end times (ScannerPluginBase._pre_scan
    # and _post_scan), which the shared list of pinned modules does not cover
    # because no other snapshot runs a scanner.
    pin_clock(
        monkeypatch, extra_modules=("automated_security_helper.base.scanner_plugin",)
    )

    monkeypatch.setattr(
        ZizmorScanner, "_get_uv_tool_version", lambda self, *_: "1.30.1"
    )
    source = tmp_path / "repo"
    shutil.copytree(ZIZMOR_FIXTURE / "repo", source)
    report, context = _zizmor_report(source, tmp_path / "ash_output")

    manifest = tmp_path / "manifest"
    manifest.mkdir()
    (manifest / "zizmor.sarif").write_text(
        report.model_dump_json(by_alias=True, exclude_none=True), "utf-8"
    )
    (manifest / "scanners.yaml").write_text(
        yaml.safe_dump(
            {
                "scanners": [
                    {
                        "name": "zizmor",
                        "outcome": "ran",
                        "output": "zizmor.sarif",
                        "version": "1.30.1",
                        "duration_seconds": 0.25,
                    }
                ]
            }
        ),
        "utf-8",
    )
    return _build_model(manifest, context), context


@pytest.mark.parametrize("reporter_name", REPORTERS)
def test_reporter_output_with_zizmor_enabled(
    reporter_name, zizmor_model, text_snapshot
):
    model, context = zizmor_model
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    document = reporter.report(model)

    assert document == text_snapshot(snapshot_extension(reporter))


def test_zizmor_scanner_row(zizmor_model, snapshot):
    """Status and counts: 7 findings, 6 actionable at the default MEDIUM threshold."""
    model, _ = zizmor_model
    row = model.scanner_results["zizmor"]
    assert json.loads(row.model_dump_json(exclude_none=True)) == snapshot
