import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from automated_security_helper.config.config_sources import open_config_for_judgment
from automated_security_helper.config.sandbox_grants import in_tree_reason, is_within
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_diff import unique_findings
from automated_security_helper.utils.scan_results_file import (
    ScanResultsRefused,
    parse_full_scan_results,
)
from automated_security_helper.utils.scan_source import is_relative_scan_source


class BaselineRefused(ASHValidationError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ScanBaseline:
    sha256: str
    results: AshAggregatedResults
    findings: tuple[FlatVulnerability, ...]


def read_baseline(path: Path, *, source_dir: Path, output_dir: Path) -> ScanBaseline:
    try:
        reason = in_tree_reason(path, source_dir)
        if reason:
            raise BaselineRefused(reason)
        if path.resolve().is_relative_to(output_dir.resolve()) or is_within(
            path, output_dir
        ):
            raise BaselineRefused("it is inside the output directory")
        opened = open_config_for_judgment(path)
        if opened is None:
            raise BaselineRefused("expected a readable regular scan results file")
        try:
            if opened.real is None:
                raise BaselineRefused("the baseline file changed while opening")
            reason = in_tree_reason(opened.real, source_dir)
            if reason:
                raise BaselineRefused(reason)
            if opened.real.resolve().is_relative_to(output_dir.resolve()) or is_within(
                opened.real, output_dir
            ):
                raise BaselineRefused("it is inside the output directory")
            info = os.fstat(opened.fd)
            if not stat.S_ISREG(info.st_mode):
                raise BaselineRefused("expected a regular scan results file")
            if info.st_nlink != 1:
                raise BaselineRefused(
                    "it has more than one hard link, so the scanned tree could change it"
                )
            with os.fdopen(os.dup(opened.fd), "rb") as stream:
                data = stream.read()
        finally:
            opened.close()
        results = parse_full_scan_results(data)
        findings = tuple(unique_findings(results, "Baseline"))
    except (ScanResultsRefused, OSError, ValueError) as exc:
        raise BaselineRefused(getattr(exc, "reason", str(exc))) from exc
    return ScanBaseline(sha256(data).hexdigest(), results, findings)


def check_baseline_scope(
    baseline: ScanBaseline, *, project_name: str, scan_source: str | None
) -> list[str]:
    if baseline.results.metadata.project_name != project_name:
        raise BaselineRefused("the baseline belongs to a different project")
    old_source = getattr(baseline.results.metadata, "scan_source", None)
    if is_relative_scan_source(old_source) and is_relative_scan_source(scan_source):
        if old_source != scan_source:
            raise BaselineRefused("the baseline scanned a different directory")
        return []
    return ["The scan directories cannot be compared reliably."]


@dataclass(frozen=True)
class BaselineOutcome:
    matched: int
    matched_without_lines: int
    warnings: tuple[str, ...]


def apply_baseline(
    results: AshAggregatedResults, baseline: ScanBaseline
) -> BaselineOutcome:
    from automated_security_helper.interactions.run_ash_scan import incomplete_scanners
    from automated_security_helper.utils.finding_diff import (
        _evaluated_scanners,
        coverage_warnings,
        match_findings,
    )
    from automated_security_helper.utils.secret_masking import mask_secrets_in_results
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.utils.severity_ladder import (
        _SEVERITY_RANK,
        severity_fails_threshold,
    )

    def actionable(finding: FlatVulnerability, model: AshAggregatedResults) -> bool:
        threshold = ScannerStatisticsCalculator.get_scanner_threshold_info(
            model, finding.scanner
        )[0]
        return severity_fails_threshold(finding.severity or "", threshold)

    if results.baseline_filtered:
        raise BaselineRefused("existing results were filtered by --baseline")
    mask_secrets_in_results(results)
    results._invalidate_flat_cache()
    warnings = tuple(coverage_warnings(baseline.results, results))
    runs = (results.sarif.runs or []) if results.sarif else []
    coordinates = [
        (run_index, result_index)
        for run_index, run in enumerate(runs)
        for result_index, _ in enumerate(run.results or [])
    ]
    flat = results.to_flat_vulnerabilities()
    current = flat[: len(coordinates)]
    completed = _evaluated_scanners(baseline.results) - {
        name for name, _ in incomplete_scanners(baseline.results)
    }
    # A result that states no finding is never matched, so a baseline never
    # removes one: the baseline's own list leaves such rows out already
    # (unique_findings), and the pairing below stays over every current result.
    match = match_findings(
        (
            finding
            for finding in baseline.findings
            if finding.source_report is None and finding.scanner in completed
        ),
        [finding for finding in current if finding.is_finding],
    )
    # Row-wise on purpose: each pair is decided by a chain of early exits, and the
    # threshold lookup in ``actionable`` goes through a scanner-statistics
    # callback that must run only for pairs that reach it. Evaluating the
    # predicates as frame columns would call it for every pair.
    removed = set()
    moved = set()
    for pairs, without_lines in ((match.exact, False), (match.moved, True)):
        for old, new in pairs:
            if old.requires_exact_identity_match or new.requires_exact_identity_match:
                if without_lines or not (
                    old.has_fingerprint_identity and new.has_fingerprint_identity
                ):
                    continue
            old_rank = _SEVERITY_RANK.get((old.severity or "").upper())
            new_rank = _SEVERITY_RANK.get((new.severity or "").upper())
            if old.is_suppressed and not new.is_suppressed:
                continue
            if actionable(new, results) and not actionable(old, baseline.results):
                continue
            if old_rank is None or new_rank is None or new_rank > old_rank:
                continue
            removed.add(id(new))
            if without_lines:
                moved.add(id(new))
    selected = {
        coordinate
        for coordinate, finding in zip(coordinates, current)
        if id(finding) in removed
    }
    for run_index, run in enumerate(runs):
        run.results = [
            result
            for result_index, result in enumerate(run.results or [])
            if (run_index, result_index) not in selected
        ]
    setattr(
        results.metadata,
        "baseline",
        {
            "sha256": baseline.sha256,
            "matched": len(selected),
            "matched_without_lines": len(moved),
        },
    )
    results._invalidate_flat_cache()
    return BaselineOutcome(len(selected), len(moved), warnings)
