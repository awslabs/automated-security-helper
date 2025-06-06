"""Factory functions for creating mock objects for testing."""

from typing import List, Dict, Any, Optional
from pathlib import Path
import datetime
import uuid
import random
from unittest.mock import MagicMock

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
    PropertyBag,
    Suppression,
    Kind1,
)
from automated_security_helper.models.core import Suppression as CoreSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME


class SarifReportFactory:
    """Factory for creating SARIF reports with customizable properties."""

    @staticmethod
    def create_finding(
        rule_id: str = "MOCK-001",
        message: str = "Mock finding",
        file_path: str = "src/example.py",
        start_line: int = 10,
        end_line: int = 15,
        severity: str = "warning",
        tags: List[str] = None,
        suppressed: bool = False,
        suppression_reason: str = None,
    ) -> Result:
        """Create a mock SARIF finding with customizable properties.

        Args:
            rule_id: The rule ID for the finding
            message: The message for the finding
            file_path: The file path for the finding
            start_line: The starting line number
            end_line: The ending line number
            severity: The severity level (error, warning, note, none)
            tags: Optional list of tags to add to the finding
            suppressed: Whether the finding is suppressed
            suppression_reason: The reason for suppression (if suppressed)

        Returns:
            A mock SARIF Result object
        """
        result = Result(
            ruleId=rule_id,
            message=Message(text=message),
            level=severity,
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

        # Add properties with tags if provided
        if tags:
            result.properties = PropertyBag()
            result.properties.tags = tags

        # Add suppression if requested
        if suppressed:
            result.suppressions = [
                Suppression(
                    kind=Kind1.external,
                    justification=suppression_reason or "Suppressed for testing",
                )
            ]

        return result

    @staticmethod
    def create_report(
        findings: Optional[List[Result]] = None,
        scanner_name: str = "Mock Scanner",
        scanner_version: str = "1.0.0",
        scanner_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> SarifReport:
        """Create a mock SARIF report with customizable properties.

        Args:
            findings: Optional list of findings to include
            scanner_name: The name of the scanner
            scanner_version: The version of the scanner
            scanner_rules: Optional list of rules to include in the report

        Returns:
            A mock SARIF report
        """
        if findings is None:
            findings = []

        # Create tool component with rules if provided
        tool_component = ToolComponent(
            name=scanner_name,
            version=scanner_version,
        )

        if scanner_rules:
            tool_component.rules = scanner_rules

        # Add properties to tool component
        tool_component.properties = PropertyBag()
        tool_component.properties.tags = [scanner_name]
        tool_component.properties.scanner_details = {
            "tool_name": scanner_name,
            "tool_version": scanner_version,
        }

        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=findings,
                )
            ],
        )


class SuppressionFactory:
    """Factory for creating suppression objects for testing."""

    @staticmethod
    def create(
        rule_id: str = "MOCK-001",
        file_path: str = "src/example.py",
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        reason: Optional[str] = "Test suppression",
        expiration: Optional[str] = None,
    ) -> CoreSuppression:
        """Create a Suppression object with customizable properties.

        Args:
            rule_id: The rule ID to suppress
            file_path: The file path pattern to match
            line_start: Optional starting line number
            line_end: Optional ending line number
            reason: Optional reason for suppression
            expiration: Optional expiration date (YYYY-MM-DD)

        Returns:
            A Suppression object
        """
        # Set expiration date to 30 days in the future if not provided
        if expiration is None and random.random() < 0.2:  # 20% chance to add expiration
            future_date = datetime.datetime.now() + datetime.timedelta(days=30)
            expiration = future_date.strftime("%Y-%m-%d")

        return CoreSuppression(
            rule_id=rule_id,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            reason=reason,
            expiration=expiration,
        )

    @staticmethod
    def create_batch(
        count: int = 5,
        rule_prefix: str = "MOCK-",
        file_paths: Optional[List[str]] = None,
    ) -> List[CoreSuppression]:
        """Create a batch of suppression objects with different properties.

        Args:
            count: Number of suppressions to create
            rule_prefix: Prefix for rule IDs
            file_paths: Optional list of file paths to use

        Returns:
            List of Suppression objects
        """
        if file_paths is None:
            file_paths = [
                "src/example.py",
                "src/main.py",
                "tests/test_example.py",
                "*.md",
                "config/*.json",
            ]

        suppressions = []
        for i in range(count):
            rule_id = f"{rule_prefix}{i + 1:03d}"
            file_path = random.choice(file_paths)

            # Randomly decide whether to include line numbers
            if random.random() < 0.7:  # 70% chance to include line numbers
                line_start = random.randint(1, 100)
                line_end = line_start + random.randint(0, 10)
            else:
                line_start = None
                line_end = None

            suppressions.append(
                SuppressionFactory.create(
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    reason=f"Test suppression for {rule_id}",
                )
            )

        return suppressions


class VulnerabilityFactory:
    """Factory for creating vulnerability objects for testing."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        title: str = "Mock Vulnerability",
        description: str = "This is a mock vulnerability for testing",
        severity: str = "HIGH",
        scanner: str = "mock-scanner",
        scanner_type: str = "SAST",
        rule_id: str = "MOCK-001",
        file_path: str = "src/example.py",
        line_start: int = 10,
        line_end: int = 15,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        references: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> FlatVulnerability:
        """Create a mock vulnerability with customizable properties.

        Args:
            id: Optional ID for the vulnerability (generated if not provided)
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
            A FlatVulnerability object
        """
        if id is None:
            # Generate a deterministic ID based on the inputs
            seed = f"{rule_id}::{file_path}::{line_start}::{line_end}"
            random.seed(seed)
            id = str(uuid.UUID(int=random.getrandbits(128), version=4))

        if references is None:
            references = []

        if tags is None:
            tags = []

        # Randomly add CVE information if not provided
        if cve_id is None and random.random() < 0.3:  # 30% chance to add CVE
            year = random.randint(2018, 2025)
            number = random.randint(1000, 9999)
            cve_id = f"CVE-{year}-{number}"
            cvss_score = round(random.uniform(1.0, 10.0), 1)
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

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

    @staticmethod
    def create_batch(
        count: int = 5,
        scanner: str = "mock-scanner",
        severity_distribution: Optional[Dict[str, float]] = None,
    ) -> List[FlatVulnerability]:
        """Create a batch of vulnerability objects with different properties.

        Args:
            count: Number of vulnerabilities to create
            scanner: Scanner name to use
            severity_distribution: Optional distribution of severities (e.g., {"HIGH": 0.2, "MEDIUM": 0.5, "LOW": 0.3})

        Returns:
            List of FlatVulnerability objects
        """
        if severity_distribution is None:
            severity_distribution = {
                "CRITICAL": 0.1,
                "HIGH": 0.2,
                "MEDIUM": 0.4,
                "LOW": 0.2,
                "INFO": 0.1,
            }

        # Create a list of severities based on the distribution
        severities = []
        for severity, probability in severity_distribution.items():
            severities.extend([severity] * int(count * probability))

        # Add any missing items to reach the desired count
        while len(severities) < count:
            severities.append("MEDIUM")

        # Shuffle the severities
        random.shuffle(severities)

        # Sample file paths
        file_paths = [
            "src/main.py",
            "src/utils.py",
            "src/models/user.py",
            "src/api/endpoints.py",
            "src/config/settings.py",
            "tests/test_main.py",
        ]

        vulnerabilities = []
        for i in range(count):
            rule_id = f"MOCK-{i + 1:03d}"
            file_path = random.choice(file_paths)
            line_start = random.randint(1, 200)
            line_end = line_start + random.randint(0, 10)

            vulnerabilities.append(
                VulnerabilityFactory.create(
                    title=f"Mock Vulnerability {i + 1}",
                    description=f"This is mock vulnerability #{i + 1} for testing",
                    severity=severities[i % len(severities)],
                    scanner=scanner,
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                )
            )

        return vulnerabilities


class ContextFactory:
    """Factory for creating plugin context objects for testing."""

    @staticmethod
    def create(
        source_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        config: Optional[AshConfig] = None,
        ignore_suppressions: bool = False,
    ) -> PluginContext:
        """Create a plugin context with customizable properties.

        Args:
            source_dir: Optional source directory (defaults to a temporary directory)
            output_dir: Optional output directory (defaults to a temporary directory)
            config: Optional configuration (defaults to a minimal configuration)
            ignore_suppressions: Whether to ignore suppressions

        Returns:
            A PluginContext object
        """
        import tempfile

        if source_dir is None:
            source_dir = Path(tempfile.mkdtemp(prefix="ash_test_source_"))

        if output_dir is None:
            output_dir = Path(tempfile.mkdtemp(prefix="ash_test_output_"))

        if config is None:
            config = AshConfig(project_name="test-project")

        return PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / ASH_WORK_DIR_NAME,
            config=config,
            ignore_suppressions=ignore_suppressions,
        )


class OrchestratorFactory:
    """Factory for creating orchestrator objects for testing."""

    @staticmethod
    def create(
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
        import tempfile

        if source_dir is None:
            source_dir = Path(tempfile.mkdtemp(prefix="ash_test_source_"))

        if output_dir is None:
            output_dir = Path(tempfile.mkdtemp(prefix="ash_test_output_"))

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
