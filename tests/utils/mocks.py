"""Mock objects and utilities for ASH tests."""

from typing import Optional, List

from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    Message1,
    Location,
    PhysicalLocation,
    PhysicalLocation2,
    ArtifactLocation,
    Region,
)
from tests.utils.helpers import get_ash_temp_path


def create_mock_finding(
    rule_id: str = "MOCK-001",
    message: str = "Mock finding",
    file_path: str = "src/example.py",
    start_line: int = 10,
    end_line: int = 15,
) -> Result:
    """Create a mock SARIF finding for testing.

    Args:
        rule_id: The rule ID for the finding
        message: The message for the finding
        file_path: The file path for the finding
        start_line: The starting line number
        end_line: The ending line number

    Returns:
        A mock SARIF Result object
    """
    return Result.model_construct(
        ruleId=rule_id,
        message=Message.model_construct(root=Message1.model_construct(text=message)),
        locations=[
            Location.model_construct(
                physicalLocation=PhysicalLocation.model_construct(
                    root=PhysicalLocation2.model_construct(
                        artifactLocation=ArtifactLocation.model_construct(uri=file_path),
                        region=Region.model_construct(
                            startLine=start_line,
                            endLine=end_line,
                        ),
                    )
                )
            )
        ],
    )


def create_mock_sarif_report(findings: Optional[List[Result]] = None) -> SarifReport:
    """Create a mock SARIF report for testing.

    Args:
        findings: Optional list of findings to include

    Returns:
        A mock SARIF report
    """
    if findings is None:
        findings = []

    return SarifReport.model_construct(
        field_schema="https://json.schemastore.org/sarif-2.1.0.json",
        version="2.1.0",
        runs=[
            Run.model_construct(
                tool=Tool.model_construct(
                    driver=ToolComponent.model_construct(
                        name="Mock Scanner",
                        version="1.0.0",
                    )
                ),
                results=findings,
            )
        ],
    )
