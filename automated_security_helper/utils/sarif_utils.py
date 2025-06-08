"""Utility functions for working with SARIF reports."""

import os
import random
import uuid
from pathlib import Path
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    ToolComponent,
    PropertyBag,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.schemas.sarif_schema_model import (
    Suppression,
    Kind1,
)
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
    check_for_expiring_suppressions,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


def get_finding_id(
    rule_id: str,
    file: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    seed = "::".join(
        [
            item
            for item in [
                rule_id,
                file,
                str(start_line),
                str(end_line),
            ]
            if item
        ]
    )
    rd = random.Random()
    rd.seed(seed)
    return str(uuid.UUID(int=rd.getrandbits(128), version=4))


def _sanitize_uri(uri: str, source_dir_path: Path, source_dir_str: str) -> str:
    """
    Sanitize a URI in a SARIF report.

    Args:
        uri: The URI to sanitize
        source_dir_path: The source directory path object
        source_dir_str: The source directory string with trailing separator

    Returns:
        The sanitized URI
    """
    if not uri:
        return uri

    # Remove file:// prefix if present
    if uri.startswith("file://"):
        uri = uri[7:]

    # Make path relative to source directory
    try:
        # Try to resolve the path and make it relative
        path_obj = Path(uri)
        if path_obj.is_absolute():
            try:
                uri = str(path_obj.relative_to(source_dir_path))
            except ValueError:
                # If the path is not relative to source_dir, keep it as is
                pass
        elif uri.startswith(source_dir_str):
            uri = uri[len(source_dir_str) :]
    except Exception as e:
        ASH_LOGGER.debug(f"Error processing path {uri}: {e}")

    # Replace backslashes with forward slashes for consistency
    uri = uri.replace("\\", "/")
    return uri


def sanitize_sarif_paths(
    sarif_report: SarifReport, source_dir: str | Path
) -> SarifReport:
    """
    Sanitize paths in SARIF report to be relative to the source directory.

    Args:
        sarif_report: The SARIF report to sanitize
        source_dir: The source directory to make paths relative to

    Returns:
        The sanitized SARIF report
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    source_dir_path = Path(source_dir).resolve()
    source_dir_str = str(source_dir_path) + os.sep

    ASH_LOGGER.debug(f"Sanitizing SARIF paths relative to: {source_dir_str}")

    clean_runs = []
    for run in sarif_report.runs:
        if not run.results:
            clean_runs.append(run)
            continue
        clean_results = []
        for result in run.results:
            # Process locations
            if result.locations:
                for location in result.locations:
                    if (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        uri = location.physicalLocation.root.artifactLocation.uri
                        if uri:
                            uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                            location.physicalLocation.root.artifactLocation.uri = uri

            # Process related locations if present
            if hasattr(result, "relatedLocations") and result.relatedLocations:
                for related in result.relatedLocations:
                    if (
                        related.physicalLocation
                        and related.physicalLocation.root.artifactLocation
                    ):
                        uri = related.physicalLocation.root.artifactLocation.uri
                        if uri:
                            uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                            related.physicalLocation.root.artifactLocation.uri = uri

            # Process analysis target if present
            if result.analysisTarget and result.analysisTarget.uri:
                uri = result.analysisTarget.uri
                uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                result.analysisTarget.uri = uri
            clean_results.append(result)

        run.results = clean_results
        clean_runs.append(run)
    sarif_report.runs = clean_runs

    return sarif_report


def attach_scanner_details(
    sarif_report: SarifReport,
    scanner_name: str,
    scanner_version: str = None,
    invocation_details: dict = None,
) -> SarifReport:
    """
    Attach scanner details to a SARIF report.

    Args:
        sarif_report: The SARIF report to update
        scanner_name: Name of the scanner
        scanner_version: Version of the scanner (optional)
        invocation_details: Dictionary with invocation details (optional)
            Can include keys like 'command_line', 'arguments', 'working_directory', etc.

    Returns:
        The updated SARIF report
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    ASH_LOGGER.debug(f"Attaching scanner details for {scanner_name} v{scanner_version}")

    for run in sarif_report.runs:
        # Create or update tool.driver information
        if not run.tool:
            from automated_security_helper.schemas.sarif_schema_model import Tool

            run.tool = Tool()

        if not run.tool.driver:
            run.tool.driver = ToolComponent(name=scanner_name)

        # Update basic properties
        run.tool.driver.name = scanner_name
        if scanner_version:
            run.tool.driver.version = scanner_version

        # Add scanner details to properties
        if not run.tool.driver.properties:
            run.tool.driver.properties = PropertyBag()

        # Add scanner name and version to properties
        run.tool.driver.properties.tags = run.tool.driver.properties.tags or []
        if scanner_name not in run.tool.driver.properties.tags:
            run.tool.driver.properties.tags.append(scanner_name)

        # Add scanner details to properties
        scanner_details = {
            "tool_name": scanner_name,
        }
        if scanner_version:
            scanner_details["tool_version"] = scanner_version

        # Add invocation details if provided
        if invocation_details:
            scanner_details["tool_invocation"] = invocation_details

        # Add scanner details to properties
        run.tool.driver.properties.scanner_details = scanner_details

        # Also attach scanner information to each result
        if run.results:
            for result in run.results:
                # Ensure result has properties
                if not result.properties:
                    result.properties = PropertyBag()

                # Add scanner name to result tags
                result.properties.tags = result.properties.tags or []
                if scanner_name not in result.properties.tags:
                    result.properties.tags.append(scanner_name)

                # Add scanner details to result properties
                setattr(result.properties, "scanner_name", scanner_name)
                if scanner_version:
                    setattr(result.properties, "scanner_version", scanner_version)

                # Add scanner details object to result properties
                setattr(result.properties, "scanner_details", scanner_details)

    return sarif_report


def path_matches_pattern(path: str, pattern: str) -> bool:
    """
    Check if a path matches a pattern.

    Args:
        path: The path to check
        pattern: The pattern to match against

    Returns:
        True if the path matches the pattern, False otherwise
    """
    import fnmatch

    # Normalize paths for comparison
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    patterns = [
        pattern + "/**/*.*",
        pattern + "/*.*",
        pattern,
    ]

    for pat in patterns:
        # Check for exact match
        if path == pat:
            return True
        elif path in pat:
            return True
        elif fnmatch.fnmatch(path, pat):
            return True

        # Check for directory match (e.g., "dir/" should match "dir/file.txt")
        if pat.endswith("/") and path.startswith(pat):
            return True

    return False


def apply_suppressions_to_sarif(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
) -> SarifReport:
    """
    Apply suppressions to a SARIF report based on global ignore paths and suppression rules.

    Args:
        sarif_report: The SARIF report to modify
        plugin_context: Plugin context containing configuration

    Returns:
        The modified SARIF report with suppressions applied
    """
    ignore_paths = plugin_context.config.global_settings.ignore_paths or []
    suppressions = plugin_context.config.global_settings.suppressions or []

    # If ignore_suppressions flag is set, skip applying suppressions
    if (
        hasattr(plugin_context, "ignore_suppressions")
        and plugin_context.ignore_suppressions
    ):
        ASH_LOGGER.info(
            "Ignoring all suppression rules as requested by --ignore-suppressions flag"
        )
        return sarif_report

    # Check for expiring suppressions and warn the user
    expiring_suppressions = check_for_expiring_suppressions(suppressions)
    if expiring_suppressions:
        ASH_LOGGER.warning("The following suppressions will expire within 30 days:")
        for suppression in expiring_suppressions:
            expiration_date = suppression.expiration
            rule_id = suppression.rule_id
            file_path = suppression.path
            reason = suppression.reason or "No reason provided"
            ASH_LOGGER.warning(
                f"  - Rule '{rule_id}' for '{file_path}' expires on {expiration_date}. Reason: {reason}"
            )

    # Check for expiring suppressions and warn the user
    expiring_suppressions = check_for_expiring_suppressions(suppressions)
    if expiring_suppressions:
        ASH_LOGGER.warning("The following suppressions will expire within 30 days:")
        for suppression in expiring_suppressions:
            expiration_date = suppression.expiration
            rule_id = suppression.rule_id
            file_path = suppression.path
            reason = suppression.reason or "No reason provided"
            ASH_LOGGER.warning(
                f"  - Rule '{rule_id}' for '{file_path}' expires on {expiration_date}. Reason: {reason}"
            )

    if not sarif_report or not sarif_report.runs:
        return sarif_report
    for run in sarif_report.runs:
        if not run.results:
            continue

        updated_results = []
        for result in run.results:
            is_in_ignorable_path = False
            # Check if result location matches any ignore path
            if result.locations:
                for location in result.locations:
                    if is_in_ignorable_path:
                        continue
                    if (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        uri = location.physicalLocation.root.artifactLocation.uri
                        if uri:
                            if Path(uri).resolve().is_relative_to(
                                plugin_context.output_dir.resolve()
                            ) and not Path(uri).resolve().is_relative_to(
                                plugin_context.output_dir.joinpath(
                                    ASH_WORK_DIR_NAME
                                ).resolve()
                            ):
                                # if path_matches_pattern(
                                #     uri, "**/scanners/*/source"
                                # ) or path_matches_pattern(uri, "**/scanners/*/converted"):
                                # if re.match(
                                #     pattern=r"scanners[\/\\]+[\w-]+[\/\\]+(source|converted)[\/\\]+",
                                #     string=uri,
                                #     flags=re.IGNORECASE,
                                # ):
                                ASH_LOGGER.verbose(
                                    f"Excluding result -- location is in output path and NOT in the work directory and should not have been included: '{uri}'"
                                )
                                is_in_ignorable_path = True
                                continue
                            for ignore_path in ignore_paths:
                                # Check if the URI matches the ignore path pattern
                                if path_matches_pattern(uri, ignore_path.path):
                                    # Initialize suppressions list if it doesn't exist
                                    if not result.suppressions:
                                        result.suppressions = []

                                    # Add suppression
                                    ASH_LOGGER.verbose(
                                        f"Suppressing rule '{result.ruleId}' on location '{uri}' based on ignore_path match against '{ignore_path.path}' with global reason: [yellow]{ignore_path.reason}[/yellow]"
                                    )
                                    suppression = Suppression(
                                        kind=Kind1.external,
                                        justification=f"(ASH) Suppressing finding on uri '{uri}' based on path match against pattern '{ignore_path.path}' with global reason: {ignore_path.reason}",
                                    )
                                    if len(result.suppressions) == 0:
                                        result.suppressions.append(suppression)
                                    else:
                                        ASH_LOGGER.trace(
                                            f"Multiple suppressions found for rule '{result.ruleId}' on location '{uri}'. Only the first suppression will be applied."
                                        )
                                    # result.level = Level.none
                                    # result.kind = Kind.informational
                                    break  # No need to check other ignore paths
                                # else:
                                #     ASH_LOGGER.verbose(
                                #         f"Rule '{result.ruleId}' on location '{uri}' does not match global ignore path '{ignore_path.path}'"
                                #     )

            # Check if result matches any suppression rule
            if not is_in_ignorable_path and suppressions:
                # Convert SARIF result to FlatVulnerability for suppression matching
                flat_finding = None
                if result.ruleId and result.locations and len(result.locations) > 0:
                    location = result.locations[0]
                    if (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        uri = location.physicalLocation.root.artifactLocation.uri
                        line_start = None
                        line_end = None
                        if (
                            hasattr(location.physicalLocation, "root")
                            and location.physicalLocation.root
                            and hasattr(location.physicalLocation.root, "region")
                            and location.physicalLocation.root.region
                        ):
                            line_start = location.physicalLocation.root.region.startLine
                            line_end = location.physicalLocation.root.region.endLine

                        flat_finding = FlatVulnerability(
                            id=get_finding_id(result.ruleId, uri, line_start, line_end),
                            title=result.message.root.text
                            if result.message
                            else "Unknown Issue",
                            description=result.message.root.text
                            if result.message
                            else "No description available",
                            severity="MEDIUM",  # Default severity, not used for matching
                            scanner=run.tool.driver.name
                            if run.tool and run.tool.driver
                            else "unknown",
                            scanner_type="SAST",  # Default type, not used for matching
                            rule_id=result.ruleId,
                            file_path=uri,
                            line_start=line_start,
                            line_end=line_end,
                        )

                if flat_finding:
                    should_suppress, matching_suppression = should_suppress_finding(
                        flat_finding, suppressions
                    )
                    if should_suppress:
                        # Initialize suppressions list if it doesn't exist
                        if not result.suppressions:
                            result.suppressions = []

                        # Add suppression
                        reason = matching_suppression.reason or "No reason provided"
                        ASH_LOGGER.verbose(
                            f"Suppressing rule '{result.ruleId}' on location '{flat_finding.file_path}' based on suppression rule. Reason: [yellow]{reason}[/yellow]"
                        )
                        suppression = Suppression(
                            kind=Kind1.external,
                            justification=f"(ASH) Suppressing finding for rule '{result.ruleId}' in '{flat_finding.file_path}' with reason: {reason}",
                        )
                        result.suppressions.append(suppression)

            # Add the result to the updated results list
            if not is_in_ignorable_path:
                updated_results.append(result)
        sarif_report.runs[0].results = updated_results
    return sarif_report
