import json
from pathlib import Path
from stat import S_ISREG

from automated_security_helper.config.config_validator import describe_results_error
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults


class ScanResultsRefused(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def read_regular_file(path: Path) -> bytes:
    try:
        if not S_ISREG(path.stat().st_mode):
            raise ScanResultsRefused("expected a regular scan results file")
        return path.read_bytes()
    except OSError as exc:
        raise ScanResultsRefused(exc.strerror or type(exc).__name__) from exc
    except ValueError as exc:
        raise ScanResultsRefused("invalid path or JSON data") from exc


def parse_full_scan_results(data: bytes) -> AshAggregatedResults:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ScanResultsRefused(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise ScanResultsRefused(describe_results_error(exc)) from exc
    except (ValueError, RecursionError) as exc:
        raise ScanResultsRefused("invalid path or JSON data") from exc
    if not isinstance(parsed, dict):
        raise ScanResultsRefused("expected scan results with metadata and SARIF runs")
    metadata, sarif = parsed.get("metadata"), parsed.get("sarif")
    if (
        not isinstance(metadata, dict)
        or not isinstance(sarif, dict)
        or not isinstance(sarif.get("runs"), list)
    ):
        raise ScanResultsRefused("expected scan results with metadata and SARIF runs")
    try:
        result = AshAggregatedResults.model_validate(parsed)
    except ValueError as exc:
        raise ScanResultsRefused(describe_results_error(exc)) from exc
    if result.workspace is not None:
        raise ScanResultsRefused(
            "use the per-project results instead of a workspace aggregate"
        )
    if result.metadata.shard is not None:
        raise ScanResultsRefused("use ash merge before comparing sharded results")
    changed = metadata.get("changed_files_only")
    if changed is True:
        raise ScanResultsRefused(
            "cannot compare results filtered by --changed-files-only"
        )
    if changed is not None and changed is not False:
        raise ScanResultsRefused("invalid changed-files-only marker")
    if "baseline" in metadata:
        raise ScanResultsRefused("cannot use results filtered by --baseline")
    project = metadata.get("workspace_project")
    if project is not None and (not isinstance(project, str) or not project.strip()):
        raise ScanResultsRefused("invalid workspace project marker")
    return result


def unique_findings(results):
    findings = results.to_flat_vulnerabilities()
    if len({finding.id for finding in findings}) != len(findings):
        raise ScanResultsRefused("scan contains duplicate finding IDs")
    return findings


def _evaluated_scanners(results):
    return {
        name
        for name, row in results.scanner_results.items()
        if not row.excluded
        and row.status in {ScannerStatus.PASSED, ScannerStatus.FAILED}
    }


def coverage_warnings(baseline, current):
    from automated_security_helper.interactions.run_ash_scan import scan_incompleteness

    warnings = []
    if set(baseline.metadata.expected_scanners) != set(
        current.metadata.expected_scanners
    ) or _evaluated_scanners(baseline) != _evaluated_scanners(current):
        warnings.append("Scanner coverage differs between scans.")
    if (
        baseline.metadata.ignore_file_exclusions
        != current.metadata.ignore_file_exclusions
    ):
        warnings.append("Recorded ignore-file exclusions differ between scans.")
    for label, result in (("Baseline", baseline), ("Current", current)):
        missing = set(result.metadata.expected_scanners) - _evaluated_scanners(result)
        if missing or scan_incompleteness(result, gate=True):
            warnings.append(f"{label} scan has incomplete scanner coverage.")
        elif not result.metadata.expected_scanners or not result.scanner_results:
            warnings.append(
                f"{label} scan does not record enough scanner coverage to establish comparability."
            )
        if result.metadata.inputs_not_scanned:
            warnings.append(f"{label} scan records inputs that were not scanned.")
    return warnings
