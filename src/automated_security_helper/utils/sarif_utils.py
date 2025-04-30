"""Utility functions for working with SARIF reports."""

import os
from pathlib import Path
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    ToolComponent,
    PropertyBag,
)
from automated_security_helper.utils.log import ASH_LOGGER


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

    # Remove ../../../src prefix if present
    if uri.startswith("../../../src/"):
        uri = uri[12:]  # Remove "../../../src/"
    elif uri.startswith("../../../src"):
        uri = uri[11:]  # Remove "../../../src"

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
    if uri.startswith("/"):
        uri = uri[1:]  # Remove leading slash if present

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

    for run in sarif_report.runs:
        if not run.results:
            continue

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
