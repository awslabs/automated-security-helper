"""Mock objects and utilities for ASH tests."""

from typing import Optional, List, Dict, Any, Union
from unittest.mock import MagicMock
from pathlib import Path

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    Location,
    PhysicalLocation,
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
    return Result(
        ruleId=rule_id,
        message=Message(text=message),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri=file_path),
                        region=Region(
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

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="Mock Scanner",
                        version="1.0.0",
                    )
                ),
                results=findings,
            )
        ],
    )


def create_mock_scanner_plugin(
    scan_result: Optional[SarifReport] = None,
) -> ScannerPluginBase:
    """Create a mock scanner plugin for testing.

    Args:
        scan_result: Optional scan result to return

    Returns:
        A mock scanner plugin
    """
    if scan_result is None:
        scan_result = create_mock_sarif_report()

    class MockScannerPlugin(ScannerPluginBase[ScannerPluginConfigBase]):
        config: ScannerPluginConfigBase = ScannerPluginConfigBase(
            name="mock_scanner",
            enabled=True,
        )

        def model_post_init(self, context):
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def scan(self, target, config=None, *args, **kwargs):
            return scan_result

    return MockScannerPlugin()


def create_mock_plugin_context(
    source_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    config: Optional[Any] = None,
) -> MagicMock:
    """Create a mock plugin context for testing.

    Args:
        source_dir: Optional source directory
        output_dir: Optional output directory
        config: Optional configuration

    Returns:
        A mock plugin context
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

    if source_dir is None:
        source_dir = get_ash_temp_path().joinpath("source")

    if output_dir is None:
        output_dir = get_ash_temp_path().joinpath("output")

    if config is None:
        config = AshConfig(project_name="test-project")

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=output_dir / ASH_WORK_DIR_NAME,
        config=config,
    )


def create_mock_vulnerability(
    id: str = "VULN-001",
    title: str = "Mock Vulnerability",
    description: str = "This is a mock vulnerability for testing",
    severity: str = "HIGH",
    scanner: str = "mock-scanner",
    scanner_type: str = "SAST",
    rule_id: Optional[str] = "MOCK-001",
    file_path: Optional[str] = "src/example.py",
    line_start: Optional[int] = 10,
    line_end: Optional[int] = 15,
    cve_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    cvss_vector: Optional[str] = None,
    references: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> "FlatVulnerability":
    """Create a mock vulnerability for testing.

    Args:
        id: The ID for the vulnerability
        title: The title for the vulnerability
        description: The description for the vulnerability
        severity: The severity level (HIGH, MEDIUM, LOW, INFO)
        scanner: The scanner that found the vulnerability
        scanner_type: The type of scanner (SAST, DAST, SCA, etc.)
        rule_id: The rule ID for the vulnerability
        file_path: The file path where the vulnerability was found
        line_start: The starting line number
        line_end: The ending line number
        cve_id: Optional CVE ID
        cvss_score: Optional CVSS score
        cvss_vector: Optional CVSS vector
        references: Optional list of references
        tags: Optional list of tags

    Returns:
        A mock FlatVulnerability object
    """
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

    if references is None:
        references = []

    if tags is None:
        tags = []

    return FlatVulnerability(
        id=id,
        title=title,
        description=description,
        severity=severity,
        scanner=scanner,
        scanner_type=scanner_type,
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        references=references,
        tags=tags,
    )


def create_mock_orchestrator(
    source_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    enabled_scanners: Optional[List[str]] = None,
    ignore_suppressions: bool = False,
    verbose: bool = False,
) -> MagicMock:
    """Create a mock ASHScanOrchestrator for testing.

    Args:
        source_dir: Optional source directory
        output_dir: Optional output directory
        config_path: Optional path to config file
        enabled_scanners: Optional list of enabled scanners
        ignore_suppressions: Whether to ignore suppressions
        verbose: Whether to enable verbose output

    Returns:
        A mock ASHScanOrchestrator
    """
    from unittest.mock import MagicMock
    import tempfile

    if source_dir is None:
        source_dir = Path(tempfile.mkdtemp())

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp())

    if enabled_scanners is None:
        enabled_scanners = ["mock_scanner"]

    # Create a mock orchestrator
    mock_orchestrator = MagicMock()
    mock_orchestrator.source_dir = source_dir
    mock_orchestrator.output_dir = output_dir
    mock_orchestrator.config_path = config_path
    mock_orchestrator.enabled_scanners = enabled_scanners
    mock_orchestrator.ignore_suppressions = ignore_suppressions
    mock_orchestrator.verbose = verbose

    # Mock the execute_scan method to return a mock result
    mock_result = MagicMock()
    mock_orchestrator.execute_scan.return_value = mock_result

    return mock_orchestrator


def create_mock_reporter(name: str = "mock_reporter") -> MagicMock:
    """Create a mock reporter for testing.

    Args:
        name: The name of the reporter

    Returns:
        A mock reporter
    """
    from unittest.mock import MagicMock

    mock_reporter = MagicMock()
    mock_reporter.name = name
    mock_reporter.enabled = True

    # Mock the report method to return a mock result
    mock_result = MagicMock()
    mock_reporter.report.return_value = mock_result

    return mock_reporter


def create_mock_converter(name: str = "mock_converter") -> MagicMock:
    """Create a mock converter for testing.

    Args:
        name: The name of the converter

    Returns:
        A mock converter
    """
    from unittest.mock import MagicMock

    mock_converter = MagicMock()
    mock_converter.name = name
    mock_converter.enabled = True

    # Mock the convert method to return a mock result
    mock_result = MagicMock()
    mock_converter.convert.return_value = mock_result

    return mock_converter


class MockResponse:
    """Mock response object for testing HTTP requests."""

    def __init__(
        self,
        status_code: int = 200,
        content: Union[str, bytes] = "",
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = False,
    ):
        """Initialize the mock response.

        Args:
            status_code: HTTP status code
            content: Response content
            json_data: JSON data to return from json() method
            headers: Response headers
            raise_for_status: Whether to raise an exception from raise_for_status()
        """
        self.status_code = status_code
        self.content = content.encode() if isinstance(content, str) else content
        self._json_data = json_data
        self.headers = headers or {}
        self._raise_for_status = raise_for_status

    def json(self) -> Dict[str, Any]:
        """Return JSON data."""
        if self._json_data is None:
            import json

            return json.loads(self.content)
        return self._json_data

    def raise_for_status(self) -> None:
        """Raise an exception if status code indicates an error."""
        if self._raise_for_status:
            from requests.exceptions import HTTPError

            raise HTTPError(f"Mock HTTP error: {self.status_code}")

    def __enter__(self):
        """Support context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager protocol."""
        pass
