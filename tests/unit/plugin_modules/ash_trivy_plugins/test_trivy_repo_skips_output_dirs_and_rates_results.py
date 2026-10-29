# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo skips ASH's output directories and reports trivy's own severity.

Two things the builtin ``trivy`` scanner did that ``trivy-repo`` did not:

- ASH's output directories inside the source target were not skipped, so trivy
  read the converted copies of archives and notebooks (reported again by the
  converted target) and an earlier run's ``.ash/ash_output`` as source. They are
  passed as ``--skip-dirs`` now, each directory on its own.
- Each vulnerability was reported at the CVE rule's last CVSS score, bucketed by
  ASH, instead of trivy's own per-result severity. One CVE is rated differently
  for two packages in one scan, and the rule carries the last result's rating.
  Each result now carries trivy's severity as its ASH severity
  (``TrivyScannerBase._attach_trivy_severity``).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    skip_dirs_value,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)

pytestmark = pytest.mark.unit


def _sarif(message: str, level: str, tags: list[str]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "CVE-2020-0001",
                                "properties": {
                                    "tags": ["vulnerability", "security", *tags],
                                    "security-severity": "5.0",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2020-0001",
                        "ruleIndex": 0,
                        "level": level,
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "requirements.txt"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    """The default layout: the output directory inside the scanned source."""
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for path in (source, output, output / "converted"):
        path.mkdir(parents=True, exist_ok=True)
    (source / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    (output / "reports").mkdir()
    (output / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    return context


@pytest.fixture(autouse=True)
def trivy_on_path(monkeypatch):
    monkeypatch.setattr(
        trivy_repo_scanner, "find_executable", lambda name: "/opt/trivy/bin/trivy"
    )
    for name in ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG"):
        monkeypatch.delenv(name, raising=False)


def _scan(context: PluginContext, document: dict):
    """Run trivy-repo's scan() with a trivy double that writes ``document``.

    Returns the argv the double received and what scan() returned.
    """
    scanner = TrivyRepoScanner(context=context, config=TrivyRepoScannerConfig())
    scanner.dependencies_satisfied = True
    argv: list[str] = []

    def _run(command, **kwargs):
        argv[:] = [str(a) for a in command]
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_run),
        patch.object(scanner, "_plugin_log"),
    ):
        report = scanner.scan(target=Path(context.source_dir), target_type="source")
    return argv, report


def test_ash_output_directories_inside_the_target_are_skipped(context):
    argv, _ = _scan(context, _sarif("Severity: LOW", "note", ["LOW"]))

    expected = f"--skip-dirs={skip_dirs_value('.ash/ash_output')}"
    assert expected in argv, argv


def test_each_result_carries_trivys_own_severity(context):
    """trivy rates the result HIGH; its rule's tag and CVSS score (5.0, MEDIUM
    under ASH's bucketing) belong to another package's rating of the same CVE."""
    message = (
        "Package: requests\nInstalled Version: 2.0.0\nVulnerability CVE-2020-0001\n"
        "Severity: HIGH\nFixed Version: 2.1.0\n"
        "Link: [CVE-2020-0001](https://example.invalid/CVE-2020-0001)"
    )

    _, report = _scan(context, _sarif(message, "error", ["MEDIUM"]))

    assert hasattr(report, "runs"), type(report)
    (result,) = report.runs[0].results
    assert result.properties is not None
    assert getattr(result.properties, "issue_severity", None) == "HIGH"
