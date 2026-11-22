import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.scan_baseline import ScanBaseline, apply_baseline

pytestmark = pytest.mark.unit


class _Logger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def report_exit_code(**options):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
        _run_local_mode,
    )

    opts = ScanOptions(**options)
    result, config_fail = _run_local_mode(opts, _Logger())
    return _compute_exit_code(result, opts, config_fail)


def finding(line, message="old", severity="LOW", fingerprint=None):
    row = {
        "ruleId": "R1",
        "message": {"text": message},
        "level": "error" if severity in ("HIGH", "CRITICAL") else "note",
        "properties": {
            "issue_severity": severity,
            "scanner_name": "bandit",
            "tags": ["bandit"],
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src.py"},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if fingerprint:
        row["fingerprints"] = {"key": fingerprint}
    return row


def results(*findings):
    result = AshAggregatedResults()
    result.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "scanner"}}, "results": findings}],
        }
    )
    result.scanner_results = {
        row["properties"]["scanner_name"]: ScannerTargetStatusInfo(status="PASSED")
        for row in findings
    }
    return result


def baseline(*findings):
    old = results(*findings)
    return ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))


def test_old_finding_is_left_out():
    current = results(finding(10))
    outcome = apply_baseline(current, baseline(finding(10)))
    assert current.sarif.runs[0].results == []
    assert outcome.matched == 1 and outcome.matched_without_lines == 0


def test_line_shifted_old_finding_does_not_fail():
    current = results(finding(20))
    outcome = apply_baseline(current, baseline(finding(10)))
    assert current.sarif.runs[0].results == []
    assert outcome.matched_without_lines == 1


def test_new_finding_on_old_line_with_other_message_fails():
    current = results(finding(20), finding(10, "new", "HIGH"))
    apply_baseline(current, baseline(finding(10)))
    assert [row.message.root.text for row in current.sarif.runs[0].results] == ["new"]


def test_severity_rise_on_an_exact_pair_is_kept():
    current = results(finding(10, severity="HIGH", fingerprint="f"))
    outcome = apply_baseline(
        current, baseline(finding(10, severity="LOW", fingerprint="f"))
    )
    assert len(current.sarif.runs[0].results) == 1
    assert outcome.matched == 0


def test_results_record_the_baseline_marker_without_a_path():
    current = results(finding(10))
    apply_baseline(current, baseline(finding(10)))
    assert current.metadata.baseline == {
        "sha256": "abc",
        "matched": 1,
        "matched_without_lines": 0,
    }


@pytest.mark.parametrize("current_line", [10, 20])
def test_old_finding_is_left_out_of_every_report_and_the_verdict(
    tmp_path, monkeypatch, current_line
):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
        _run_local_mode,
    )

    class Logger:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out"
    old = results(finding(10, severity="HIGH"))
    old.ash_config = get_default_config()
    current = results(finding(current_line, severity="HIGH"))
    current.ash_config = old.ash_config
    saved = tmp_path / "saved.json"
    saved.write_text(current.model_dump_json(by_alias=True))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    opts = ScanOptions(
        source_dir=source,
        output_dir=output,
        existing_results=str(saved),
        baseline=str(baseline_path),
        phases=[ExecutionPhase.REPORT],
        output_formats=[
            ExportFormat.SARIF,
            ExportFormat.FLAT_JSON,
            ExportFormat.MARKDOWN,
            ExportFormat.TEXT,
            ExportFormat.CSV,
            ExportFormat.HTML,
            ExportFormat.JUNITXML,
            ExportFormat.GITLAB_SAST,
            ExportFormat.OCSF,
            ExportFormat.GITHUB_GHAS,
            ExportFormat.YAML,
        ],
        config_overrides=["reporters.yaml.enabled=true"],
        show_summary=False,
        progress=False,
        fail_on_incomplete_scanners=False,
    )
    result, config_fail = _run_local_mode(opts, Logger())
    assert _compute_exit_code(result, opts, config_fail) == 0
    assert not result.sarif.runs[0].results
    assert result.metadata.baseline["matched"] == 1
    assert result.metadata.baseline["matched_without_lines"] == int(current_line != 10)
    assert all(
        "src.py" not in path.read_text()
        for path in (output / "reports").iterdir()
        if path.is_file()
    )


def test_baseline_does_not_remove_additional_reports():
    current = results(finding(10))
    current.additional_reports = {"other": [{"id": "other", "title": "kept"}]}
    apply_baseline(current, baseline(finding(10)))
    assert current.additional_reports["other"][0]["title"] == "kept"


@pytest.mark.parametrize("with_sarif", [False, True])
def test_new_finding_fails_the_scan(tmp_path, monkeypatch, with_sarif):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    old = results(finding(10, "old", "HIGH"))
    old.ash_config = get_default_config()
    current = results(finding(20, "old", "HIGH"), finding(10, "new", "HIGH"))
    current.ash_config = old.ash_config
    saved = tmp_path / "saved.json"
    saved.write_text(current.model_dump_json(by_alias=True))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    formats = [
        ExportFormat.FLAT_JSON,
        ExportFormat.MARKDOWN,
        ExportFormat.TEXT,
        ExportFormat.CSV,
        ExportFormat.HTML,
        ExportFormat.JUNITXML,
        ExportFormat.GITLAB_SAST,
        ExportFormat.OCSF,
        ExportFormat.GITHUB_GHAS,
        ExportFormat.YAML,
    ]
    if with_sarif:
        formats.append(ExportFormat.SARIF)
    code = report_exit_code(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results=str(saved),
        baseline=str(baseline_path),
        phases=[ExecutionPhase.REPORT],
        output_formats=formats,
        config_overrides=["reporters.yaml.enabled=true"],
        show_summary=False,
        progress=False,
        quiet=True,
        fail_on_incomplete_scanners=False,
    )
    assert code == 2
    final = AshAggregatedResults.model_validate_json(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text()
    )
    assert [row.message.root.text for row in final.sarif.runs[0].results] == ["new"]
    assert final.metadata.summary_stats.total == 1
    assert final.metadata.summary_stats.actionable == 1
    reports = [
        path for path in (tmp_path / "out" / "reports").iterdir() if path.is_file()
    ]
    assert len(reports) == len(formats)
    missing = [
        path.name
        for path in reports
        if ("new [R1]" if path.name == "ash.junit.xml" else "src.py")
        not in path.read_text()
    ]
    assert missing == []


def test_changed_files_only_and_baseline_together(tmp_path, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )
    from automated_security_helper.utils import get_scan_set

    class Logger:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        get_scan_set, "git_repository_root", lambda *args, **kwargs: source
    )
    monkeypatch.setattr(get_scan_set, "get_changed_files", lambda **kwargs: ["src.py"])
    old = results(finding(10, "old", "HIGH"))
    old.ash_config = get_default_config()
    current = results(finding(20, "old", "HIGH"), finding(10, "new", "HIGH"))
    current.ash_config = old.ash_config
    saved = tmp_path / "saved.json"
    saved.write_text(current.model_dump_json(by_alias=True))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    opts = ScanOptions(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results=str(saved),
        baseline=str(baseline_path),
        changed_files_only=True,
        phases=[ExecutionPhase.REPORT],
        output_formats=[ExportFormat.SARIF],
        show_summary=False,
        progress=False,
        fail_on_incomplete_scanners=False,
    )
    result, _ = _run_local_mode(opts, Logger())
    assert [row.message.root.text for row in result.sarif.runs[0].results] == ["new"]
    assert result.metadata.baseline["matched_without_lines"] == 1
    assert result.metadata.changed_files_only is True


@pytest.mark.parametrize("line", [10, 20])
def test_expired_suppression_is_not_removed_from_baseline(line):
    old = finding(10, severity="HIGH")
    old["suppressions"] = [{"kind": "external", "state": "accepted"}]
    current = results(finding(line, severity="HIGH"))
    outcome = apply_baseline(current, baseline(old))
    assert len(current.sarif.runs[0].results) == 1
    assert outcome.matched == 0


def test_finding_suppressed_in_both_scans_is_left_out():
    old = finding(10, severity="HIGH")
    old["suppressions"] = [{"kind": "external", "state": "accepted"}]
    current = results(old)
    outcome = apply_baseline(current, baseline(old))
    assert not current.sarif.runs[0].results
    assert outcome.matched == 1


def test_previously_suppressed_finding_fails_scan(tmp_path, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    old_finding = finding(10, severity="HIGH")
    old_finding["suppressions"] = [{"kind": "external", "state": "accepted"}]
    old = results(old_finding)
    old.ash_config = get_default_config()
    current = results(finding(10, severity="HIGH"))
    current.ash_config = old.ash_config
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    saved = tmp_path / "saved.json"
    saved.write_text(current.model_dump_json(by_alias=True))
    code = report_exit_code(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results=str(saved),
        baseline=str(baseline_path),
        phases=[ExecutionPhase.REPORT],
        output_formats=[ExportFormat.SARIF],
        show_summary=False,
        progress=False,
        quiet=True,
        fail_on_incomplete_scanners=False,
    )
    assert code == 2


def test_fresh_results_match_the_masked_saved_baseline():
    from automated_security_helper.utils.secret_masking import mask_secrets_in_results

    secret = "Zx9Qw7" + "Lm2Pk4Rt8v"
    exposed = finding(3, f"Possible hardcoded password: '{secret}'", "HIGH")
    exposed["ruleId"] = "custom-secret"
    exposed["properties"]["tags"] = ["secrets"]
    referenced = finding(5, f"connect() called with token '{secret}'", "HIGH")
    referenced["ruleId"] = "R2"
    referenced["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        "other.py"
    )
    old = results(exposed, referenced)
    mask_secrets_in_results(old)
    expected = ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))
    current = results(exposed, referenced)
    current.to_flat_vulnerabilities()
    outcome = apply_baseline(current, expected)
    assert outcome.matched == 1
    assert [row.ruleId for row in current.sarif.runs[0].results] == ["custom-secret"]


def test_already_baseline_filtered_results_are_refused_again():
    from automated_security_helper.utils.scan_baseline import BaselineRefused

    current = results(finding(10))
    current.metadata.baseline = {
        "sha256": "old",
        "matched": 1,
        "matched_without_lines": 0,
    }
    with pytest.raises(BaselineRefused, match="baseline"):
        apply_baseline(current, baseline(finding(10)))
    assert len(current.sarif.runs[0].results) == 1


def test_results_without_sarif_keep_additional_reports():
    current = AshAggregatedResults(
        sarif=None, additional_reports={"other": [{"id": "one", "title": "keep"}]}
    )
    outcome = apply_baseline(current, baseline(finding(10)))
    assert outcome.matched == 0
    assert current.additional_reports["other"][0]["title"] == "keep"
    assert current.metadata.baseline["matched"] == 0


@pytest.mark.parametrize("with_sarif", [False, True])
def test_baseline_keeps_dict_result_in_gate(tmp_path, with_sarif):
    import json

    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _gating_actionable_count,
    )
    from automated_security_helper.utils.inner_run_outcome import record_reports_written

    current = results(finding(10, severity="HIGH"))
    current.ash_config = get_default_config()
    current.additional_reports = {
        "plugin": {
            "source": {
                "scanner_name": "plugin",
                "status": "PASSED",
                "raw_results": {"findings": [{"rule": "P"}]},
                "severity_counts": {"high": 1},
            }
        }
    }
    opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
    assert _gating_actionable_count(current, opts, False) == 2
    apply_baseline(current, baseline(finding(10, severity="HIGH")))
    if with_sarif:
        report = tmp_path / "out" / "reports" / "ash.sarif"
        report.parent.mkdir(parents=True)
        report.write_text(
            json.dumps(current.sarif.model_dump(by_alias=True, exclude_none=True))
        )
        record_reports_written(current, [("ash.sarif", "sarif")])
    assert _gating_actionable_count(current, opts, with_sarif) == 1


def test_unfingerprinted_secret_scanner_finding_is_not_left_out():
    old = finding(10, "same", "HIGH")
    old["properties"]["scanner_name"] = "detect-secrets"
    old["properties"]["tags"] = ["detect-secrets"]
    current = results(old)
    apply_baseline(current, baseline(old))
    assert len(current.sarif.runs[0].results) == 1


@pytest.mark.parametrize(
    "status", ["MISSING", "ERROR", "SKIPPED", "excluded", "absent"]
)
def test_scanner_without_complete_baseline_keeps_its_findings(status):
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    old = results(finding(10, severity="HIGH"))
    old.scanner_results.clear()
    if status != "absent":
        old.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status="PASSED" if status == "excluded" else status,
            excluded=status == "excluded",
        )
    current = results(finding(10, severity="HIGH"))
    outcome = apply_baseline(
        current, ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))
    )
    assert outcome.matched == 0
    assert len(current.sarif.runs[0].results) == 1


@pytest.mark.parametrize("with_sarif", [False, True])
def test_baseline_gate_counts_a_native_info_result_under_all(tmp_path, with_sarif):
    import json

    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _gating_actionable_count,
    )
    from automated_security_helper.utils.inner_run_outcome import record_reports_written

    current = results(finding(10, severity="HIGH"))
    current.ash_config = get_default_config()
    current.ash_config.global_settings.severity_threshold = "ALL"
    current.additional_reports = {
        "plugin": {
            "source": {
                "scanner_name": "plugin",
                "status": "PASSED",
                "raw_results": {"findings": [{"rule": "P"}]},
                "severity_counts": {"info": 1},
            }
        }
    }
    opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
    apply_baseline(current, baseline(finding(10, severity="HIGH")))
    if with_sarif:
        report = tmp_path / "out" / "reports" / "ash.sarif"
        report.parent.mkdir(parents=True)
        report.write_text(
            json.dumps(current.sarif.model_dump(by_alias=True, exclude_none=True))
        )
        record_reports_written(current, [("ash.sarif", "sarif")])
    assert _gating_actionable_count(current, opts, with_sarif) == 1
