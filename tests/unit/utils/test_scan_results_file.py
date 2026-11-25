import json

import pytest

from automated_security_helper.utils.scan_results_file import (
    ScanResultsRefused,
    parse_full_scan_results,
    read_regular_file,
)

pytestmark = pytest.mark.unit


def payload(**metadata):
    return json.dumps(
        {
            "metadata": {"project_name": "project", **metadata},
            "sarif": {"version": "2.1.0", "runs": []},
        }
    ).encode()


def test_results_filtered_by_a_baseline_are_refused():
    with pytest.raises(
        ScanResultsRefused, match="cannot use results filtered by --baseline"
    ):
        parse_full_scan_results(payload(baseline={}))


def test_non_regular_file_is_refused(tmp_path):
    with pytest.raises(ScanResultsRefused, match="regular"):
        read_regular_file(tmp_path)


def test_incomplete_baseline_warns_and_keeps_finding_in_gate(tmp_path):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _gating_actionable_count,
    )
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.scan_baseline import (
        ScanBaseline,
        apply_baseline,
    )

    def model(status):
        result = AshAggregatedResults()
        result.ash_config = get_default_config()
        result.metadata.expected_scanners = ["bandit"]
        result.scanner_results["bandit"] = ScannerTargetStatusInfo(status=status)
        result.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "bandit"}},
                        "results": [
                            {
                                "ruleId": "R",
                                "message": {"text": "finding"},
                                "level": "error",
                                "properties": {
                                    "scanner_name": "bandit",
                                    "issue_severity": "HIGH",
                                },
                            }
                        ],
                    }
                ],
            }
        )
        return result

    old, current = model("MISSING"), model("PASSED")
    outcome = apply_baseline(
        current, ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))
    )
    assert "Baseline scan has incomplete scanner coverage." in outcome.warnings
    assert (
        _gating_actionable_count(
            current,
            ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out"),
            False,
        )
        == 1
    )
