# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's version in the results is the tool's own, never ASH's.

Why this exists
---------------
``ScanResultProcessor`` attaches scanner details with the version the scanner's
run declares, not ASH's: nothing writes ``metadata["scanner_version"]``, so a
fallback to ``get_ash_version()`` would overwrite the version the scanner already
put on its SARIF driver (from its own ``tool_version``, or from the tool's native
SARIF), and in ``ash.sarif`` each scanner's ``tool.extensions[]`` entry, and on
every result ``properties.scanner_version`` and
``properties.scanner_details.tool_version``, would read ASH's version (bandit 1.8.6
reported as ASH 3.x).

The processor leaves the field out when the scanner did not say, so "unknown" is
never written as ASH's version. ASH's own driver keeps ASH's version.
"""

from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.sarif_utils import attach_scanner_details

ASH_VERSION = get_ash_version()


def _scanner_report(name: str, driver_version=None) -> SarifReport:
    driver = {"name": name, "rules": [{"id": f"{name}-R1"}]}
    if driver_version is not None:
        driver["version"] = driver_version
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": driver},
                    "results": [
                        {
                            "ruleId": f"{name}-R1",
                            "level": "warning",
                            "message": {"text": "finding"},
                        }
                    ],
                }
            ],
        }
    )


def _process(tmp_path, report: SarifReport, name: str, metadata=None):
    context = MagicMock()
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.ignore_suppressions = True
    context.source_dir.mkdir(exist_ok=True)
    container = ScanResultsContainer(
        scanner_name=name,
        report_type="sarif",
        target=context.source_dir,
        target_type="source",
        raw_results=report,
        metadata=metadata or {},
    )
    aggregated = AshAggregatedResults()
    processor = ScanResultProcessor(
        plugin_context=context, validation_manager=MagicMock()
    )
    return processor.process_container(container, aggregated).sarif


def _extension(sarif: SarifReport, name: str):
    return next(e for e in sarif.runs[0].tool.extensions if e.name == name)


def _result_versions(sarif: SarifReport):
    props = sarif.runs[0].results[0].properties
    return (
        getattr(props, "scanner_version", None),
        (getattr(props, "scanner_details", None) or {}).get("tool_version"),
    )


def test_the_version_the_scanner_attached_survives(tmp_path):
    # What ScannerPluginBase does with self.tool_version before handing over.
    report = attach_scanner_details(
        _scanner_report("bandit"), scanner_name="bandit", scanner_version="1.8.6"
    )

    sarif = _process(tmp_path, report, "bandit")

    assert _extension(sarif, "bandit").version == "1.8.6"
    assert _result_versions(sarif) == ("1.8.6", "1.8.6")


def test_a_version_from_the_tools_native_sarif_survives(tmp_path):
    sarif = _process(tmp_path, _scanner_report("semgrep", "1.140.0"), "semgrep")

    assert _extension(sarif, "semgrep").version == "1.140.0"
    assert _result_versions(sarif) == ("1.140.0", "1.140.0")


def test_an_unknown_version_is_left_out_rather_than_written_as_ashs(tmp_path):
    sarif = _process(tmp_path, _scanner_report("custom-tool"), "custom-tool")

    assert _extension(sarif, "custom-tool").version is None
    assert _result_versions(sarif) == (None, None)


@pytest.mark.parametrize("driver_version", [None, "0.0.1"])
def test_a_version_in_the_container_metadata_wins(tmp_path, driver_version):
    sarif = _process(
        tmp_path,
        _scanner_report("grype", driver_version),
        "grype",
        metadata={"scanner_version": "0.100.0"},
    )

    assert _extension(sarif, "grype").version == "0.100.0"
    assert _result_versions(sarif) == ("0.100.0", "0.100.0")


def test_ashs_own_driver_keeps_ashs_version(tmp_path):
    sarif = _process(tmp_path, _scanner_report("semgrep", "1.140.0"), "semgrep")

    assert sarif.runs[0].tool.driver.version == ASH_VERSION
    assert all(e.version != ASH_VERSION for e in sarif.runs[0].tool.extensions)


def test_a_driver_with_only_a_semantic_version_reports_that_version(tmp_path):
    """SARIF has two version fields; a tool that fills only semanticVersion counts."""
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "trivy", "semanticVersion": "0.56.2"}},
                    "results": [
                        {
                            "ruleId": "CVE-1",
                            "level": "warning",
                            "message": {"text": "finding"},
                        }
                    ],
                }
            ],
        }
    )

    sarif = _process(tmp_path, report, "trivy")

    assert _extension(sarif, "trivy").version == "0.56.2"
    assert _result_versions(sarif) == ("0.56.2", "0.56.2")
