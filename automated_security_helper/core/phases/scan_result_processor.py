"""ScanResultProcessor — owns result merging and post-scan validation for ScanPhase."""

import json
import traceback
from typing import Any

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    sanitize_sarif_paths,
)


class ScanResultProcessor:
    """Processes raw scanner containers into AshAggregatedResults.

    Owns: process_container, validate_completion, validate_metrics, and
    the four _validate_* methods that previously lived on ScanPhase.
    """

    def __init__(self, plugin_context: Any, validation_manager: ScannerValidationManager | None = None) -> None:
        self.plugin_context = plugin_context
        self.validation_manager = validation_manager or ScannerValidationManager(plugin_context)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process_container(
        self,
        results: ScanResultsContainer,
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """Merge a single ScanResultsContainer into aggregated_results."""
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

        scanner_name = results.scanner_name
        if scanner_name not in aggregated_results.additional_reports:
            aggregated_results.additional_reports[scanner_name] = {}

        if results.target_type not in aggregated_results.additional_reports[scanner_name]:
            aggregated_results.additional_reports[scanner_name][results.target_type] = {}

        aggregated_results.additional_reports[scanner_name][results.target_type] = results.model_dump(
            exclude_none=True,
            exclude_unset=True,
            by_alias=True,
            mode="json",
        )

        ash_target_result_path = self.plugin_context.output_dir.joinpath(
            "scanners",
            scanner_name,
            (results.target_type or "source"),
            "ASH.ScanResults.json",
        )
        ash_target_result_path.parent.mkdir(parents=True, exist_ok=True)

        ASH_LOGGER.debug(
            f"Processing results for {scanner_name}: type={type(results.raw_results)}"
        )

        if isinstance(results.raw_results, SarifReport):
            ASH_LOGGER.verbose(
                f"{scanner_name}: Processing as SARIF report with "
                f"{len(results.raw_results.runs[0].results) if results.raw_results.runs and results.raw_results.runs[0].results else 0} results"
            )
            sanitized_sarif = sanitize_sarif_paths(results.raw_results, self.plugin_context.source_dir)

            if not self.plugin_context.ignore_suppressions:
                sanitized_sarif = apply_suppressions_to_sarif(
                    sarif_report=sanitized_sarif,
                    plugin_context=self.plugin_context,
                    used_suppressions=aggregated_results.used_suppressions,
                )
            else:
                ASH_LOGGER.debug("Skipping suppression application due to --ignore-suppressions flag")

            scanner_version = None
            if hasattr(results, "metadata") and results.metadata and "scanner_version" in results.metadata:
                scanner_version = results.metadata["scanner_version"]
            # tool_version is not a field on SarifReport; skip that path

            invocation_details: dict = {}
            if hasattr(results, "metadata") and results.metadata:
                for key in ("command_line", "working_directory", "arguments"):
                    if key in results.metadata:
                        invocation_details[key] = results.metadata[key]
                if "exit_code" in results.metadata or hasattr(results, "exit_code"):
                    invocation_details["exit_code"] = results.metadata.get("exit_code", results.exit_code)
                if "duration" in results.metadata or hasattr(results, "duration"):
                    invocation_details["duration"] = results.metadata.get("duration", results.duration)

            if hasattr(results, "start_time") and results.start_time:
                invocation_details["start_time"] = (
                    results.start_time.isoformat()
                    if hasattr(results.start_time, "isoformat")
                    else str(results.start_time)
                )
            if hasattr(results, "end_time") and results.end_time:
                invocation_details["end_time"] = (
                    results.end_time.isoformat()
                    if hasattr(results.end_time, "isoformat")
                    else str(results.end_time)
                )

            sanitized_sarif.attach_scanner_details(
                scanner_name=results.scanner_name,
                scanner_version=scanner_version or get_ash_version(),
                invocation_details=invocation_details if invocation_details else {},
            )

            if aggregated_results.sarif is not None:
                aggregated_results.sarif.merge_sarif_report(sanitized_sarif)
            target_report = aggregated_results.additional_reports[scanner_name][results.target_type]
            target_report.pop("raw_results", None)

        elif isinstance(results.raw_results, CycloneDXReport):
            ASH_LOGGER.verbose(f"{scanner_name}: Processing as CycloneDX report")
            aggregated_results.cyclonedx = results.raw_results
            target_report = aggregated_results.additional_reports[scanner_name][results.target_type]
            target_report.pop("severity_counts", None)
            target_report.pop("raw_results", None)

        else:
            ASH_LOGGER.verbose(
                f"{scanner_name}: Processing as additional report (type: {type(results.raw_results)})"
            )
            aggregated_results.additional_reports[scanner_name][results.target_type]["raw_results"] = (
                results.raw_results
            )
            aggregated_results.additional_reports[scanner_name][results.target_type].pop("severity_counts", None)

        ash_target_result_path.write_text(
            json.dumps(
                aggregated_results.additional_reports[scanner_name][results.target_type],
                default=str,
            )
        )

        return aggregated_results

    def validate_completion(
        self,
        aggregated_results: AshAggregatedResults,
        completed_scanner_names: list[str] | None = None,
    ) -> None:
        """Run the validate_execution_completion check, logging warnings on discrepancy."""
        try:
            names = completed_scanner_names or []
            checkpoint = self.validation_manager.validate_execution_completion(names)
            if checkpoint and checkpoint.has_issues():
                for scanner_name in checkpoint.get_missing_scanners():
                    ASH_LOGGER.warning(
                        f"Execution completion discrepancy: scanner {scanner_name} missing"
                    )
        except Exception as e:
            ASH_LOGGER.warning(f"validate_completion encountered an error: {e}")
            ASH_LOGGER.debug(traceback.format_exc())

    def validate_result_completeness(self, aggregated_results: AshAggregatedResults) -> None:
        """Ensure all originally registered scanners appear in final results."""
        try:
            checkpoint = self.validation_manager.ensure_complete_results(aggregated_results)
            if checkpoint and checkpoint.has_issues():
                for scanner_name in checkpoint.get_missing_scanners():
                    ASH_LOGGER.warning(
                        f"Scanner {scanner_name} missing from final results"
                    )
        except Exception as e:
            ASH_LOGGER.warning(f"validate_result_completeness encountered an error: {e}")
            ASH_LOGGER.debug(traceback.format_exc())

    def validate_metrics(self, aggregated_results: AshAggregatedResults) -> None:
        """Log warnings if scanner_results totals don't match summary_stats."""
        try:
            scanner_results = aggregated_results.scanner_results or {}
            summary = getattr(aggregated_results, "summary_stats", None)
            if not summary or not scanner_results:
                return

            total_from_scanners = sum(
                getattr(info, "finding_count", 0) or 0
                for info in scanner_results.values()
            )
            summary_total = getattr(summary, "total", None)
            if summary_total is not None and total_from_scanners != summary_total:
                ASH_LOGGER.warning(
                    f"Metrics inconsistency: scanner_results total={total_from_scanners}, "
                    f"summary_stats total={summary_total}"
                )
        except Exception as e:
            ASH_LOGGER.warning(f"validate_metrics encountered an error: {e}")
            ASH_LOGGER.debug(traceback.format_exc())
