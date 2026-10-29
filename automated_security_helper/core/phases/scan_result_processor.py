"""ScanResultProcessor — owns result merging and post-scan validation for ScanPhase."""

import json
from typing import Any

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    text_without_values,
    traceback_text,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import resolve_missing_levels
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.undecodable_text import recorded
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    exclude_output_dir_results,
    normalize_sarif_result_severities,
    sanitize_sarif_paths,
)
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports


def _declared_tool_version(sarif_report: Any) -> str | None:
    """The version a scanner's own SARIF run gives its driver, if any."""
    for run in getattr(sarif_report, "runs", None) or []:
        driver = getattr(getattr(run, "tool", None), "driver", None)
        version = getattr(driver, "version", None) or getattr(
            driver, "semanticVersion", None
        )
        if isinstance(version, str) and version.strip():
            return version.strip()
    return None


class ScanResultProcessor:
    """Processes raw scanner containers into AshAggregatedResults.

    Owns: process_container, validate_completion, validate_metrics, and
    the four _validate_* methods that previously lived on ScanPhase.
    """

    def __init__(
        self,
        plugin_context: Any,
        validation_manager: ScannerValidationManager | None = None,
    ) -> None:
        self.plugin_context = plugin_context
        self.validation_manager = validation_manager or ScannerValidationManager(
            plugin_context
        )

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
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
            CycloneDXReport,
        )

        # A container is a plain model the scan fills in after it is built, and a
        # scanner's own report can key a dict by a file name that is not UTF-8
        # (detect-secrets' output is keyed so). The dump below UTF-8-encodes dict
        # keys, so the merge reads the container with every name in the record form
        # (utils/undecodable_text.py); the scanner's object is left as it is.
        results = recorded(results)
        scanner_name = results.scanner_name
        if scanner_name not in aggregated_results.additional_reports:
            aggregated_results.additional_reports[scanner_name] = {}

        if (
            results.target_type
            not in aggregated_results.additional_reports[scanner_name]
        ):
            aggregated_results.additional_reports[scanner_name][
                results.target_type
            ] = {}

        aggregated_results.additional_reports[scanner_name][results.target_type] = (
            results.model_dump(
                exclude_none=True,
                exclude_unset=True,
                by_alias=True,
                mode="json",
            )
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
            # First, before anything round-trips the report: once dumped and
            # re-validated, a level the scanner never stated looks stated.
            resolve_missing_levels(results.raw_results)
            ASH_LOGGER.verbose(
                f"{scanner_name}: Processing as SARIF report with "
                f"{len(results.raw_results.runs[0].results) if results.raw_results.runs and results.raw_results.runs[0].results else 0} results"
            )
            sanitized_sarif = sanitize_sarif_paths(
                results.raw_results, self.plugin_context.source_dir
            )
            sanitized_sarif = normalize_sarif_result_severities(sanitized_sarif)

            if not self.plugin_context.ignore_suppressions:
                sanitized_sarif = apply_suppressions_to_sarif(
                    sarif_report=sanitized_sarif,
                    plugin_context=self.plugin_context,
                    used_suppressions=aggregated_results.used_suppressions,
                )
            else:
                ASH_LOGGER.debug(
                    "Skipping suppression application due to --ignore-suppressions flag"
                )
                # The flag lifts suppressions and ignore paths, not the exclusion
                # of ASH's own output directory.
                sanitized_sarif = exclude_output_dir_results(
                    sarif_report=sanitized_sarif,
                    plugin_context=self.plugin_context,
                )

            scanner_version = None
            if (
                hasattr(results, "metadata")
                and results.metadata
                and "scanner_version" in results.metadata
            ):
                scanner_version = results.metadata["scanner_version"]
            # Otherwise the version the scanner's run declares: the scanner put
            # its own tool_version there, or the tool's native SARIF did. Nothing
            # writes metadata["scanner_version"], so this is where a scanner's
            # version comes from, and ASH's own version never stands in for it. A
            # scanner that did not say gets no version at all.
            if not scanner_version:
                scanner_version = _declared_tool_version(sanitized_sarif)

            invocation_details: dict = {}
            if hasattr(results, "metadata") and results.metadata:
                environment_values = config_environment_values(
                    getattr(self.plugin_context, "config", None)
                )
                for key in ("command_line", "working_directory", "arguments"):
                    if key in results.metadata:
                        value = results.metadata[key]
                        if key == "command_line" and isinstance(value, str):
                            value = text_without_values(value, environment_values)
                        elif key == "arguments" and isinstance(value, (list, tuple)):
                            value = [
                                text_without_values(item, environment_values)
                                if isinstance(item, str)
                                else item
                                for item in value
                            ]
                        invocation_details[key] = value
                if "exit_code" in results.metadata or hasattr(results, "exit_code"):
                    invocation_details["exit_code"] = results.metadata.get(
                        "exit_code", results.exit_code
                    )
                if "duration" in results.metadata or hasattr(results, "duration"):
                    invocation_details["duration"] = results.metadata.get(
                        "duration", results.duration
                    )

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
                scanner_version=scanner_version,
                invocation_details=invocation_details or {},
            )

            if aggregated_results.sarif is not None:
                aggregated_results.sarif.merge_sarif_report(sanitized_sarif)
            target_report = aggregated_results.additional_reports[scanner_name][
                results.target_type
            ]
            target_report.pop("raw_results", None)

        elif isinstance(results.raw_results, CycloneDXReport):
            ASH_LOGGER.verbose(f"{scanner_name}: Processing as CycloneDX report")
            # A delivered config's syft exclusions were moved out of syft's options,
            # so the SBOM lists every component; those they would have dropped are
            # marked instead (config/client_scanner_exclusions.py).
            exclusions = getattr(
                self.plugin_context.config, "_client_scanner_exclusions", None
            )
            if exclusions:
                from automated_security_helper.config.client_scanner_exclusions import (
                    mark_sbom_components,
                )

                mark_sbom_components(results.raw_results, exclusions)
            # A scan can hand over more than one SBOM: syft runs on the source tree
            # and on the converted tree. They are combined, not replaced, so the
            # SBOM keeps every component of both (utils/sbom_merge.py). A second
            # report's lists other than components and dependencies are not
            # carried, and one package under two bom-refs is listed twice.
            aggregated_results.cyclonedx = merge_cyclonedx_reports(
                aggregated_results.cyclonedx, results.raw_results
            )
            target_report = aggregated_results.additional_reports[scanner_name][
                results.target_type
            ]
            target_report.pop("severity_counts", None)
            target_report.pop("raw_results", None)

        else:
            ASH_LOGGER.verbose(
                f"{scanner_name}: Processing as additional report (type: {type(results.raw_results)})"
            )
            # The counts stay on the report, beside the dict they were read from.
            # A dict result (``severity_counts`` or a ``findings`` list) has no
            # result in the merged SARIF, so these counts are the only record of
            # what the executor graded; the statistics calculator reads them
            # when the SARIF holds nothing for the scanner
            # (``extract_sarif_counts_for_scanner``). Dropped, the row the
            # executor graded FAILED rolled up PASSED with 0 actionable.
            aggregated_results.additional_reports[scanner_name][results.target_type][
                "raw_results"
            ] = results.raw_results

        # Without following a symlink: this is the scanner's own results directory,
        # which a sandboxed scanner could write. See utils/sandbox/fs_guard.py.
        with open_for_write(ash_target_result_path) as handle:
            handle.write(
                json.dumps(
                    aggregated_results.additional_reports[scanner_name][
                        results.target_type
                    ],
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
            ASH_LOGGER.warning(
                f"validate_completion encountered an error: {error_text(e)}"
            )
            ASH_LOGGER.debug(traceback_text())

    def validate_result_completeness(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Ensure all originally registered scanners appear in final results."""
        try:
            checkpoint = self.validation_manager.ensure_complete_results(
                aggregated_results
            )
            if checkpoint and checkpoint.has_issues():
                for scanner_name in checkpoint.get_missing_scanners():
                    ASH_LOGGER.warning(
                        f"Scanner {scanner_name} missing from final results"
                    )
        except Exception as e:
            ASH_LOGGER.warning(
                f"validate_result_completeness encountered an error: {error_text(e)}"
            )
            ASH_LOGGER.debug(traceback_text())

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
            ASH_LOGGER.warning(
                f"validate_metrics encountered an error: {error_text(e)}"
            )
            ASH_LOGGER.debug(traceback_text())
