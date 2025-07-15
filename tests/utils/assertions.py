"""Custom assertion helpers for ASH tests."""

from typing import Optional, Any, Union
from pathlib import Path

from automated_security_helper.schemas.sarif_schema_model import SarifReport


def assert_finding_suppressed(
    result: SarifReport, rule_id: str, file_path: Optional[str] = None
) -> None:
    """Assert that a finding with the given rule_id is suppressed.

    Args:
        result: The SARIF report to check
        rule_id: The rule ID to look for
        file_path: Optional file path to filter findings

    Raises:
        AssertionError: If the finding is not found or not suppressed
    """
    for run in result.runs:
        for finding in run.results:
            if finding.ruleId == rule_id:
                if file_path is None or any(
                    loc.physicalLocation.artifactLocation.uri == file_path
                    for loc in finding.locations
                    if hasattr(loc, "physicalLocation")
                ):
                    assert finding.suppressions is not None, (
                        f"Finding with rule_id {rule_id} is not suppressed"
                    )
                    assert len(finding.suppressions) > 0, (
                        f"Finding with rule_id {rule_id} has empty suppressions list"
                    )
                    return
    raise AssertionError(f"Finding with rule_id {rule_id} not found")


def assert_finding_not_suppressed(
    result: SarifReport, rule_id: str, file_path: Optional[str] = None
) -> None:
    """Assert that a finding with the given rule_id is not suppressed.

    Args:
        result: The SARIF report to check
        rule_id: The rule ID to look for
        file_path: Optional file path to filter findings

    Raises:
        AssertionError: If the finding is not found or is suppressed
    """
    for run in result.runs:
        for finding in run.results:
            if finding.ruleId == rule_id:
                if file_path is None or any(
                    loc.physicalLocation.artifactLocation.uri == file_path
                    for loc in finding.locations
                    if hasattr(loc, "physicalLocation")
                ):
                    assert (
                        finding.suppressions is None or len(finding.suppressions) == 0
                    ), f"Finding with rule_id {rule_id} is suppressed"
                    return
    raise AssertionError(f"Finding with rule_id {rule_id} not found")


def assert_sarif_has_finding(
    result: SarifReport, rule_id: str, file_path: Optional[str] = None
) -> None:
    """Assert that a SARIF report contains a finding with the given rule_id.

    Args:
        result: The SARIF report to check
        rule_id: The rule ID to look for
        file_path: Optional file path to filter findings

    Raises:
        AssertionError: If the finding is not found
    """
    for run in result.runs:
        for finding in run.results:
            if finding.ruleId == rule_id:
                if file_path is None or any(
                    loc.physicalLocation.artifactLocation.uri == file_path
                    for loc in finding.locations
                    if hasattr(loc, "physicalLocation")
                ):
                    return
    raise AssertionError(f"Finding with rule_id {rule_id} not found in SARIF report")


def assert_sarif_has_no_finding(
    result: SarifReport, rule_id: str, file_path: Optional[str] = None
) -> None:
    """Assert that a SARIF report does not contain a finding with the given rule_id.

    Args:
        result: The SARIF report to check
        rule_id: The rule ID to look for
        file_path: Optional file path to filter findings

    Raises:
        AssertionError: If the finding is found
    """
    for run in result.runs:
        for finding in run.results:
            if finding.ruleId == rule_id:
                if file_path is None or any(
                    loc.physicalLocation.artifactLocation.uri == file_path
                    for loc in finding.locations
                    if hasattr(loc, "physicalLocation")
                ):
                    raise AssertionError(
                        f"Finding with rule_id {rule_id} found in SARIF report"
                    )
    return


def assert_finding_has_severity(
    result: SarifReport,
    rule_id: str,
    expected_severity: str,
    file_path: Optional[str] = None,
) -> None:
    """Assert that a finding with the given rule_id has the expected severity.

    Args:
        result: The SARIF report to check
        rule_id: The rule ID to look for
        expected_severity: The expected severity level
        file_path: Optional file path to filter findings

    Raises:
        AssertionError: If the finding is not found or has incorrect severity
    """
    for run in result.runs:
        for finding in run.results:
            if finding.ruleId == rule_id:
                if file_path is None or any(
                    loc.physicalLocation.artifactLocation.uri == file_path
                    for loc in finding.locations
                    if hasattr(loc, "physicalLocation")
                ):
                    # Check if the finding has a properties bag with severity
                    if (
                        hasattr(finding, "properties")
                        and finding.properties
                        and "severity" in finding.properties
                    ):
                        assert (
                            finding.properties["severity"].upper()
                            == expected_severity.upper()
                        ), (
                            f"Finding with rule_id {rule_id} has severity {finding.properties['severity']} instead of {expected_severity}"
                        )
                        return
                    # Check if the finding has a level attribute
                    elif hasattr(finding, "level"):
                        # Map SARIF levels to severity levels
                        level_to_severity = {
                            "error": "HIGH",
                            "warning": "MEDIUM",
                            "note": "LOW",
                            "none": "INFO",
                        }
                        actual_severity = level_to_severity.get(
                            finding.level, "UNKNOWN"
                        )
                        assert actual_severity.upper() == expected_severity.upper(), (
                            f"Finding with rule_id {rule_id} has severity {actual_severity} instead of {expected_severity}"
                        )
                        return
                    else:
                        raise AssertionError(
                            f"Finding with rule_id {rule_id} does not have severity information"
                        )
    raise AssertionError(f"Finding with rule_id {rule_id} not found in SARIF report")


def assert_config_has_setting(
    config: Any, setting_path: str, expected_value: Any
) -> None:
    """Assert that a configuration object has the expected setting value.

    Args:
        config: The configuration object to check
        setting_path: The path to the setting (dot-separated)
        expected_value: The expected value

    Raises:
        AssertionError: If the setting is not found or has incorrect value
    """
    current = config
    path_parts = setting_path.split(".")

    for i, part in enumerate(path_parts):
        if hasattr(current, part):
            current = getattr(current, part)
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise AssertionError(
                f"Setting {setting_path} not found in config (failed at {'.'.join(path_parts[: i + 1])})"
            )

    assert current == expected_value, (
        f"Setting {setting_path} has value {current} instead of {expected_value}"
    )


def assert_file_exists(path: Union[str, Path]) -> None:
    """Assert that a file exists.

    Args:
        path: The path to check

    Raises:
        AssertionError: If the file does not exist
    """
    path = Path(path)
    assert path.exists(), f"File {path} does not exist"
    assert path.is_file(), f"{path} is not a file"


def assert_directory_exists(path: Union[str, Path]) -> None:
    """Assert that a directory exists.

    Args:
        path: The path to check

    Raises:
        AssertionError: If the directory does not exist
    """
    path = Path(path)
    assert path.exists(), f"Directory {path} does not exist"
    assert path.is_dir(), f"{path} is not a directory"


def assert_file_contains(path: Union[str, Path], expected_content: str) -> None:
    """Assert that a file contains the expected content.

    Args:
        path: The path to check
        expected_content: The content to look for

    Raises:
        AssertionError: If the file does not contain the expected content
    """
    path = Path(path)
    assert_file_exists(path)
    content = path.read_text()
    assert expected_content in content, f"File {path} does not contain expected content"


def assert_json_file_has_key(path: Union[str, Path], key_path: str) -> Any:
    """Assert that a JSON file has the specified key and return its value.

    Args:
        path: The path to the JSON file
        key_path: The path to the key (dot-separated)

    Returns:
        The value at the specified key path

    Raises:
        AssertionError: If the key is not found
    """
    import json

    path = Path(path)
    assert_file_exists(path)

    with open(path, "r") as f:
        data = json.load(f)

    current = data
    path_parts = key_path.split(".")

    for i, part in enumerate(path_parts):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise AssertionError(
                f"Key {key_path} not found in JSON file {path} (failed at {'.'.join(path_parts[: i + 1])})"
            )

    return current
