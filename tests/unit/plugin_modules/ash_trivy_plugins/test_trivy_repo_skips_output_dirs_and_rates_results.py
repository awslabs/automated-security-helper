# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo skips ASH's output directories, passes ASH's timeout and rates results as trivy does.

Three things the builtin ``trivy`` scanner did that ``trivy-repo`` did not:

- ASH's output directories inside the source target were not skipped, so trivy
  read the converted copies of archives and notebooks (reported again by the
  converted target) and an earlier run's ``.ash/ash_output`` as source. They are
  passed as ``--skip-dirs`` now, each directory on its own.
- trivy's own deadline (five minutes) applied, and a longer scan exited 1. ASH's
  ``scan_timeout`` is passed as ``--timeout`` now, trivy's largest duration for an
  unbounded one.
- Each vulnerability was reported at the CVE rule's last CVSS score, bucketed by
  ASH, instead of trivy's own per-result severity. One CVE is rated differently
  for two packages in one scan, and the rule carries the last result's rating.
  Each result now carries trivy's severity as its ASH severity
  (``TrivyScannerBase._attach_trivy_severity``), counted as the scan phase counts.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
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


def _scan(context: PluginContext, document: dict, *, options: dict | None = None):
    """Run trivy-repo's scan() with a trivy double that writes ``document``.

    The double is spec'd on the real ``_run_subprocess`` (``autospec=True``), so a
    change to its signature fails here instead of passing silently. Returns the
    argv the double received and what scan() returned.
    """
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(**(options or {}))
        ),
    )
    scanner.dependencies_satisfied = True
    argv: list[str] = []

    def _run(self, command, **kwargs):
        argv[:] = [str(a) for a in command]
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(TrivyRepoScanner, "_run_subprocess", autospec=True) as double,
        patch.object(scanner, "_plugin_log"),
    ):
        double.side_effect = _run
        report = scanner.scan(target=Path(context.source_dir), target_type="source")
    return argv, report


def test_ash_output_directories_inside_the_target_are_skipped(context):
    argv, _ = _scan(context, _sarif("Severity: LOW", "note", ["LOW"]))

    # The literal token, not one derived from the production helper: a quoting or
    # escaping change in skip_dirs_value would otherwise pass by construction.
    assert "--skip-dirs=.ash/ash_output" in argv, argv


def test_an_output_directory_outside_the_target_needs_no_skip(tmp_path):
    """With ASH's output outside the scanned source and no earlier run's
    ``.ash/ash_output`` in it, there is nothing of ASH's for trivy to skip, and no
    ``--skip-dirs`` names a path outside the target (``../out``)."""
    source = tmp_path / "src"
    output = tmp_path / "out"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for path in (source, output, output / "converted"):
        path.mkdir(parents=True, exist_ok=True)
    (source / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")

    argv, _ = _scan(context, _sarif("Severity: LOW", "note", ["LOW"]))

    assert [a for a in argv if a.startswith("--skip-dirs=")] == [], argv


@pytest.mark.parametrize(
    "scan_timeout,deadline",
    [(60, "60s"), (1800, "1800s"), (None, "2562047h")],
    ids=["one-minute", "the-default-value", "unbounded"],
)
def test_ashs_scan_timeout_is_passed_as_trivys_deadline(
    context, scan_timeout, deadline
):
    """trivy's own deadline is five minutes; a scan past it exits 1. The bound the
    operator set is the one trivy gets, as the builtin trivy scanner already
    passed it; an unbounded ASH timeout is trivy's largest duration, since trivy
    reads ``0s`` as a deadline already passed. The value is set here rather than
    relied on as the default, so a changed default fails this test by name."""
    argv, _ = _scan(
        context,
        _sarif("Severity: LOW", "note", ["LOW"]),
        options={"scan_timeout": scan_timeout},
    )

    assert [a for a in argv if a.startswith("--timeout=")] == [f"--timeout={deadline}"]


def _sarif_one_rule(ratings: list[tuple[str, str]], tag: str) -> dict:
    """One CVE rule tagged *tag*, with one result per ``(severity line, level)``."""
    results = [
        {
            "ruleId": "CVE-2020-0001",
            "ruleIndex": 0,
            "level": level,
            "message": {
                "text": (
                    f"Package: package-{index}\nInstalled Version: 1.0.0\n"
                    f"Vulnerability CVE-2020-0001\nSeverity: {severity}\n"
                    "Fixed Version: 1.0.1\n"
                    "Link: [CVE-2020-0001](https://example.invalid/CVE-2020-0001)"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "requirements.txt"},
                        "region": {"startLine": index + 1},
                    }
                }
            ],
        }
        for index, (severity, level) in enumerate(ratings)
    ]
    document = _sarif("unused", "note", [tag])
    document["runs"][0]["results"] = results
    return document


def test_two_results_of_one_rule_each_keep_their_own_severity(context):
    """One CVE rated HIGH for one package and LOW for another: the rule's tag and
    score carry the last result's rating (LOW). Counted as the scan phase counts
    them (``get_severity_metrics_from_sarif``), not read from an internal field: a
    counter that read the level (error, CRITICAL) or the rule's score (5.0,
    MEDIUM) would miss here."""
    from automated_security_helper.utils.sarif_utils import (
        get_severity_metrics_from_sarif,
    )

    _, report = _scan(
        context, _sarif_one_rule([("HIGH", "error"), ("LOW", "note")], tag="LOW")
    )

    counts = get_severity_metrics_from_sarif(report, context)
    assert (counts.critical, counts.high, counts.medium, counts.low) == (0, 1, 0, 1)


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
