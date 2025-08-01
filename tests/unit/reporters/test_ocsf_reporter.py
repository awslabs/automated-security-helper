"""Tests for OCSF reporter helper methods."""

import pytest
import uuid
from datetime import datetime, timezone

from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OcsfReporter,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    VulnerabilityFinding,
    Vulnerability,
    Metadata,
    Product,
    StatusId,
    SeverityId,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Message,
    Message1,
    Location,
    PhysicalLocation,
    PhysicalLocation2,
    ArtifactLocation,
    Region,
    Suppression,
    Level,
    Kind1,
    State,
)


class TestOcsfReporterHelperMethods:
    """Test cases for OCSF reporter helper methods."""

    @pytest.fixture
    def reporter(self, test_plugin_context):
        """Create an OCSF reporter instance for testing."""
        return OcsfReporter(context=test_plugin_context)

    @pytest.fixture
    def sample_metadata(self):
        """Create sample OCSF metadata for testing."""
        product = Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version="1.0.0",
        )
        return Metadata(
            product=product,
            version="1.1.0",
            logged_time=int(datetime.now(timezone.utc).timestamp() * 1000),
        )

    def test_create_vulnerability_from_result_basic(self, reporter):
        """Test creating vulnerability from basic SARIF result."""
        result = Result(
            ruleId="TEST001",
            level=Level.error,
            message=Message(root=Message1(text="Test error message")),
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert isinstance(vulnerability, Vulnerability)
        assert vulnerability.title == "TEST001"
        assert vulnerability.desc == "Test error message"
        assert vulnerability.severity == "ERROR"
        assert vulnerability.cve.uid == "TEST001"
        assert vulnerability.cve.desc == "Test error message"

    def test_create_vulnerability_from_result_with_location(self, reporter):
        """Test creating vulnerability from SARIF result with location info."""
        result = Result(
            ruleId="TEST002",
            level=Level.warning,
            message=Message(root=Message1(text="Test warning message")),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/test/file.py"),
                        region=Region(startLine=10, endLine=15),
                    ))
                )
            ],
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "TEST002"
        assert vulnerability.desc == "Test warning message"
        assert vulnerability.severity == "WARNING"
        assert len(vulnerability.affected_code) == 1
        
        affected_code = vulnerability.affected_code[0]
        assert affected_code.file.name == "file.py"
        assert affected_code.file.path == "src/test/file.py"
        assert affected_code.file.type_id == 1
        assert affected_code.start_line == 10
        assert affected_code.end_line == 15

    def test_create_vulnerability_from_result_multiple_locations(self, reporter):
        """Test creating vulnerability from SARIF result with multiple locations."""
        result = Result(
            ruleId="TEST003",
            level=Level.note,
            message=Message(root=Message1(text="Test note message")),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/file1.py"),
                        region=Region(startLine=5),
                    ))
                ),
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/file2.py"),
                        region=Region(startLine=20, endLine=25),
                    ))
                ),
            ],
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "TEST003"
        assert len(vulnerability.affected_code) == 2
        
        # Check first location
        assert vulnerability.affected_code[0].file.name == "file1.py"
        assert vulnerability.affected_code[0].file.path == "src/file1.py"
        assert vulnerability.affected_code[0].start_line == 5
        assert not hasattr(vulnerability.affected_code[0], 'end_line') or vulnerability.affected_code[0].end_line is None
        
        # Check second location
        assert vulnerability.affected_code[1].file.name == "file2.py"
        assert vulnerability.affected_code[1].file.path == "src/file2.py"
        assert vulnerability.affected_code[1].start_line == 20
        assert vulnerability.affected_code[1].end_line == 25

    def test_create_vulnerability_from_result_no_rule_id(self, reporter):
        """Test creating vulnerability from SARIF result without rule ID."""
        result = Result(
            level=Level.error,
            message=Message(root=Message1(text="Test message without rule ID")),
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "Unknown Rule"
        assert vulnerability.desc == "Test message without rule ID"
        assert vulnerability.severity == "ERROR"
        # Should not have CVE when no rule ID
        assert not hasattr(vulnerability, 'cve') or vulnerability.cve is None

    def test_create_vulnerability_from_result_no_level(self, reporter):
        """Test creating vulnerability from SARIF result with explicit None level."""
        result = Result(
            ruleId="TEST004",
            message=Message(root=Message1(text="Test message without level")),
            level=None,  # Explicitly set to None
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "TEST004"
        assert vulnerability.desc == "Test message without level"
        assert vulnerability.severity == "MEDIUM"  # Default when level is None

    def test_create_vulnerability_from_result_empty_locations(self, reporter):
        """Test creating vulnerability from SARIF result with empty locations."""
        result = Result(
            ruleId="TEST005",
            level=Level.warning,
            message=Message(root=Message1(text="Test message with empty locations")),
            locations=[],
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "TEST005"
        assert vulnerability.desc == "Test message with empty locations"
        # Should not have affected_code when no locations
        assert not hasattr(vulnerability, 'affected_code') or not vulnerability.affected_code

    def test_determine_status_from_suppressions_no_suppressions(self, reporter):
        """Test status determination when no suppressions are present."""
        status_id, status_detail = reporter._determine_status_from_suppressions(None)
        
        assert status_id == StatusId.integer_1  # Active/Open
        assert status_detail is None

        # Test with empty list
        status_id, status_detail = reporter._determine_status_from_suppressions([])
        
        assert status_id == StatusId.integer_1  # Active/Open
        assert status_detail is None

    def test_determine_status_from_suppressions_with_suppressions(self, reporter):
        """Test status determination when suppressions are present."""
        suppressions = [
            Suppression(
                kind=Kind1.inSource,
                state=State.accepted,
                justification="False positive - reviewed by security team",
            )
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail is not None
        assert "kind: inSource" in status_detail
        assert "state: accepted" in status_detail
        assert "justification: False positive - reviewed by security team" in status_detail

    def test_determine_status_from_suppressions_multiple_suppressions(self, reporter):
        """Test status determination with multiple suppressions."""
        suppressions = [
            Suppression(
                kind=Kind1.inSource,
                state=State.accepted,
                justification="First suppression",
            ),
            Suppression(
                kind=Kind1.external,
                state=State.underReview,
                justification="Second suppression",
            ),
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail is not None
        assert "First suppression" in status_detail
        assert "Second suppression" in status_detail
        assert " | " in status_detail  # Multiple suppressions separated by |

    def test_determine_status_from_suppressions_minimal_suppression(self, reporter):
        """Test status determination with minimal suppression data."""
        suppressions = [
            Suppression(kind=Kind1.inSource)  # Only kind, no state or justification
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail is not None
        assert "kind: inSource" in status_detail

    def test_determine_status_from_suppressions_empty_suppression(self, reporter):
        """Test status determination with minimal suppression object."""
        suppressions = [
            Suppression(kind=Kind1.inSource)  # Minimal suppression with required field
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail is not None
        assert "kind: inSource" in status_detail

    def test_determine_status_from_suppressions_all_states(self, reporter):
        """Test status determination with all possible suppression states."""
        # Test accepted state
        suppressions_accepted = [
            Suppression(kind=Kind1.inSource, state=State.accepted)
        ]
        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions_accepted)
        assert status_id == StatusId.integer_4
        assert "state: accepted" in status_detail

        # Test underReview state
        suppressions_review = [
            Suppression(kind=Kind1.inSource, state=State.underReview)
        ]
        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions_review)
        assert status_id == StatusId.integer_4
        assert "state: underReview" in status_detail

        # Test rejected state
        suppressions_rejected = [
            Suppression(kind=Kind1.inSource, state=State.rejected)
        ]
        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions_rejected)
        assert status_id == StatusId.integer_4
        assert "state: rejected" in status_detail

    def test_determine_status_from_suppressions_all_kinds(self, reporter):
        """Test status determination with all possible suppression kinds."""
        # Test inSource kind
        suppressions_in_source = [
            Suppression(kind=Kind1.inSource)
        ]
        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions_in_source)
        assert status_id == StatusId.integer_4
        assert "kind: inSource" in status_detail

        # Test external kind
        suppressions_external = [
            Suppression(kind=Kind1.external)
        ]
        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions_external)
        assert status_id == StatusId.integer_4
        assert "kind: external" in status_detail

    def test_determine_status_from_suppressions_no_details(self, reporter):
        """Test status determination when suppression has no optional fields."""
        suppressions = [
            Suppression(kind=Kind1.inSource)  # Only required field
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail == "kind: inSource"  # Only kind should be present

    def test_determine_status_from_suppressions_empty_justification(self, reporter):
        """Test status determination with empty justification."""
        suppressions = [
            Suppression(
                kind=Kind1.inSource,
                state=State.accepted,
                justification="",  # Empty justification
            )
        ]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        assert status_id == StatusId.integer_4  # Suppressed/Closed
        assert status_detail is not None
        assert "kind: inSource" in status_detail
        assert "state: accepted" in status_detail
        # Empty justification should NOT be included
        assert "justification:" not in status_detail

    def test_determine_status_from_suppressions_error_handling(self, reporter, monkeypatch):
        """Test error handling in suppression processing."""
        # Create a mock suppression that will cause an error when accessing attributes
        class MockSuppression:
            @property
            def kind(self):
                raise Exception("Test exception")
            
            @property
            def state(self):
                return State.accepted
            
            @property
            def justification(self):
                return "Test justification"

        suppressions = [MockSuppression()]

        status_id, status_detail = reporter._determine_status_from_suppressions(suppressions)
        
        # Should still return suppressed status despite individual field errors
        assert status_id == StatusId.integer_4  # Suppressed
        assert status_detail is not None
        # Should contain the successfully extracted fields
        assert "state: accepted" in status_detail
        assert "justification: Test justification" in status_detail

    def test_create_vulnerability_finding_basic(self, reporter, sample_metadata):
        """Test creating vulnerability finding from basic SARIF result."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST001",
            level=Level.error,
            message=Message(root=Message1(text="Test error message")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert isinstance(finding, VulnerabilityFinding)
        assert finding.activity_name == "Scan"
        assert finding.severity_id == SeverityId.integer_4  # HIGH for error
        assert finding.status_id == StatusId.integer_1  # Active (no suppressions)
        assert finding.status_detail is None
        assert finding.type_uid == 200201
        assert finding.class_uid == 2002
        assert finding.category_uid == 2
        assert finding.category_name == "Findings"
        assert finding.time == current_time_ms
        assert finding.metadata == sample_metadata
        assert len(finding.vulnerabilities) == 1
        assert finding.vulnerabilities[0].title == "TEST001"

    def test_create_vulnerability_finding_with_suppressions(self, reporter, sample_metadata):
        """Test creating vulnerability finding with suppressions."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST002",
            level=Level.warning,
            message=Message(root=Message1(text="Test warning message")),
            suppressions=[
                Suppression(
                    kind=Kind1.inSource,
                    state=State.accepted,
                    justification="False positive",
                )
            ],
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_3  # MEDIUM for warning
        assert finding.status_id == StatusId.integer_4  # Suppressed
        assert finding.status_detail is not None
        assert "False positive" in finding.status_detail

    def test_create_vulnerability_finding_severity_mapping(self, reporter, sample_metadata):
        """Test severity mapping for different SARIF levels."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Test error -> HIGH
        result_error = Result(
            ruleId="TEST_ERROR",
            level=Level.error,
            message=Message(root=Message1(text="Error level test")),
        )
        finding_error = reporter._create_vulnerability_finding(result_error, sample_metadata, current_time_ms)
        assert finding_error.severity_id == SeverityId.integer_4  # HIGH

        # Test warning -> MEDIUM
        result_warning = Result(
            ruleId="TEST_WARNING",
            level=Level.warning,
            message=Message(root=Message1(text="Warning level test")),
        )
        finding_warning = reporter._create_vulnerability_finding(result_warning, sample_metadata, current_time_ms)
        assert finding_warning.severity_id == SeverityId.integer_3  # MEDIUM

        # Test note -> LOW
        result_note = Result(
            ruleId="TEST_NOTE",
            level=Level.note,
            message=Message(root=Message1(text="Note level test")),
        )
        finding_note = reporter._create_vulnerability_finding(result_note, sample_metadata, current_time_ms)
        assert finding_note.severity_id == SeverityId.integer_2  # LOW

        # Test none -> INFORMATIONAL
        result_none = Result(
            ruleId="TEST_NONE",
            level=Level.none,
            message=Message(root=Message1(text="None level test")),
        )
        finding_none = reporter._create_vulnerability_finding(result_none, sample_metadata, current_time_ms)
        assert finding_none.severity_id == SeverityId.integer_1  # INFORMATIONAL

    def test_create_vulnerability_finding_no_level(self, reporter, sample_metadata):
        """Test creating vulnerability finding without level (uses SARIF schema default)."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST_NO_LEVEL",
            message=Message(root=Message1(text="No level test")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # SARIF schema defaults to Level.error when no level is provided
        assert finding.severity_id == SeverityId.integer_4  # HIGH (error default)

    def test_create_vulnerability_finding_unique_ids(self, reporter, sample_metadata):
        """Test that each vulnerability finding gets a unique ID."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST_UNIQUE",
            level=Level.error,
            message=Message(root=Message1(text="Unique ID test")),
        )

        finding1 = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
        finding2 = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Each finding should have a unique UID
        assert finding1.finding_info.uid != finding2.finding_info.uid
        
        # Verify UIDs are valid UUIDs
        uuid.UUID(finding1.finding_info.uid)  # Should not raise exception
        uuid.UUID(finding2.finding_info.uid)  # Should not raise exception

    def test_create_vulnerability_finding_long_message_truncation(self, reporter, sample_metadata):
        """Test that long messages are truncated in finding title."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        long_message = "This is a very long message that should be truncated in the title " * 5
        result = Result(
            ruleId="TEST_LONG",
            level=Level.error,
            message=Message(root=Message1(text=long_message)),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Title should be truncated but description should be full
        assert len(finding.finding_info.title) <= 123  # 120 chars + "..."
        assert finding.finding_info.title.endswith("...")
        assert finding.finding_info.desc == long_message  # Full message in description

    def test_create_vulnerability_finding_no_message(self, reporter, sample_metadata):
        """Test creating vulnerability finding with empty message."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST_NO_MSG",
            level=Level.error,
            message=Message(root=Message1(text="")),  # Empty message
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.finding_info.desc == "No description"  # Default when empty
        assert "TEST_NO_MSG" in finding.finding_info.title

    def test_create_vulnerability_finding_descriptive_title_with_location(self, reporter, sample_metadata):
        """Test that finding titles include location information when available."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST_LOCATION_TITLE",
            level=Level.error,
            message=Message(root=Message1(text="Security issue found")),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/security/auth.py"),
                        region=Region(startLine=42),
                    ))
                )
            ],
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Title should include rule ID, file name, and message
        assert "TEST_LOCATION_TITLE" in finding.finding_info.title
        assert "auth.py" in finding.finding_info.title
        assert "Security issue found" in finding.finding_info.title
        assert finding.finding_info.desc == "Security issue found"

    def test_create_vulnerability_finding_descriptive_title_without_location(self, reporter, sample_metadata):
        """Test that finding titles are descriptive even without location information."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="TEST_NO_LOCATION_TITLE",
            level=Level.warning,
            message=Message(root=Message1(text="Potential security vulnerability detected")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Title should include rule ID and message
        assert "TEST_NO_LOCATION_TITLE" in finding.finding_info.title
        assert "Potential security vulnerability detected" in finding.finding_info.title
        assert finding.finding_info.desc == "Potential security vulnerability detected"

    def test_create_vulnerability_finding_title_truncation_with_location(self, reporter, sample_metadata):
        """Test that long titles with location info are properly truncated."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        very_long_message = "This is an extremely long security message that should be truncated properly " * 3
        result = Result(
            ruleId="VERY_LONG_RULE_NAME_FOR_TESTING",
            level=Level.error,
            message=Message(root=Message1(text=very_long_message)),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/very/long/path/to/file.py"),
                    ))
                )
            ],
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Title should be truncated but include key components
        assert len(finding.finding_info.title) <= 123  # 120 chars + "..."
        assert "VERY_LONG_RULE_NAME_FOR_TESTING" in finding.finding_info.title
        assert "file.py" in finding.finding_info.title
        assert finding.finding_info.title.endswith("...")
        # Full message should be in description
        assert finding.finding_info.desc == very_long_message

    def test_create_vulnerability_finding_unique_identifiers_stress_test(self, reporter, sample_metadata):
        """Test that unique identifiers are generated consistently under stress."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="STRESS_TEST",
            level=Level.error,
            message=Message(root=Message1(text="Stress test message")),
        )

        # Generate many findings to test uniqueness
        findings = []
        for i in range(100):
            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
            findings.append(finding)

        # Extract all UIDs
        uids = [finding.finding_info.uid for finding in findings]

        # All UIDs should be unique
        assert len(uids) == len(set(uids)), "All UIDs should be unique"

        # All UIDs should be valid UUIDs
        for uid in uids:
            uuid.UUID(uid)  # Should not raise exception

        # All findings should have the same content except UID
        for i in range(1, len(findings)):
            assert findings[i].finding_info.title == findings[0].finding_info.title
            assert findings[i].finding_info.desc == findings[0].finding_info.desc
            assert findings[i].finding_info.uid != findings[0].finding_info.uid

    def test_create_vulnerability_finding_complete_metadata_validation(self, reporter, sample_metadata):
        """Test that each finding contains complete metadata as required."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="METADATA_TEST",
            level=Level.warning,
            message=Message(root=Message1(text="Metadata validation test")),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/test.py"),
                        region=Region(startLine=10, endLine=20),
                    ))
                )
            ],
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Validate complete metadata presence (Requirement 3.1)
        assert finding.metadata is not None
        assert finding.metadata.product is not None
        assert finding.metadata.product.name == "Automated Security Helper"
        assert finding.metadata.product.vendor_name == "Amazon Web Services"
        assert finding.metadata.product.version is not None
        assert finding.metadata.version == "1.1.0"
        # Allow for small timing differences (within 10ms)
        assert abs(finding.metadata.logged_time - current_time_ms) <= 10

        # Validate complete finding information (Requirement 3.2)
        assert finding.finding_info is not None
        assert finding.finding_info.uid is not None
        assert finding.finding_info.title is not None
        assert finding.finding_info.desc is not None

        # Validate unique identifier (Requirement 3.3)
        uuid.UUID(finding.finding_info.uid)  # Should be valid UUID

        # Validate all relevant SARIF information is preserved
        assert len(finding.vulnerabilities) == 1
        vulnerability = finding.vulnerabilities[0]
        assert vulnerability.title == "METADATA_TEST"
        assert vulnerability.desc == "Metadata validation test"
        assert len(vulnerability.affected_code) == 1
        assert vulnerability.affected_code[0].file.path == "src/test.py"
        assert vulnerability.affected_code[0].start_line == 10
        assert vulnerability.affected_code[0].end_line == 20

    def test_create_vulnerability_finding_error_recovery_maintains_uniqueness(self, reporter, sample_metadata, monkeypatch):
        """Test that error recovery still maintains unique identifiers."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a result that will cause errors in title creation
        class MockResult:
            @property
            def ruleId(self):
                raise Exception("Error accessing ruleId")
            
            @property
            def message(self):
                raise Exception("Error accessing message")
            
            @property
            def level(self):
                return Level.error
            
            @property
            def locations(self):
                return None

        result = MockResult()

        # Create multiple findings with error conditions
        findings = []
        for i in range(5):
            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
            findings.append(finding)

        # All findings should have unique UIDs even with errors
        uids = [finding.finding_info.uid for finding in findings]
        assert len(uids) == len(set(uids)), "All UIDs should be unique even with errors"

        # All UIDs should be valid UUIDs
        for uid in uids:
            uuid.UUID(uid)  # Should not raise exception


class TestOcsfReporterSeverityMapping:
    """Test cases specifically for severity mapping functionality."""

    @pytest.fixture
    def reporter(self, test_plugin_context):
        """Create an OCSF reporter instance for testing."""
        return OcsfReporter(context=test_plugin_context)

    @pytest.fixture
    def sample_metadata(self):
        """Create sample OCSF metadata for testing."""
        product = Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version="1.0.0",
        )
        return Metadata(
            product=product,
            version="1.1.0",
            logged_time=int(datetime.now(timezone.utc).timestamp() * 1000),
        )

    @pytest.fixture
    def sample_ash_model(self):
        """Create a sample AshAggregatedResults model for testing."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            SarifReport,
            Run,
            Tool,
            ToolComponent,
        )
        
        # Create SARIF results
        results = [
            Result(
                ruleId="TEST001",
                level=Level.error,
                message=Message(root=Message1(text="Test error message")),
            ),
            Result(
                ruleId="TEST002",
                level=Level.warning,
                message=Message(root=Message1(text="Test warning message")),
                suppressions=[
                    Suppression(
                        kind=Kind1.inSource,
                        state=State.accepted,
                        justification="False positive",
                    )
                ],
            ),
        ]
        
        # Create SARIF schema
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(
            runs=[Run(tool=tool, results=results)]
        )
        
        return AshAggregatedResults(sarif=sarif)

    def test_severity_mapping_error_to_high(self, reporter, sample_metadata):
        """Test that SARIF 'error' level maps to OCSF HIGH severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="SEVERITY_ERROR",
            level=Level.error,
            message=Message(root=Message1(text="Error level severity test")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_4  # HIGH
        assert finding.vulnerabilities[0].severity == "ERROR"

    def test_severity_mapping_warning_to_medium(self, reporter, sample_metadata):
        """Test that SARIF 'warning' level maps to OCSF MEDIUM severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="SEVERITY_WARNING",
            level=Level.warning,
            message=Message(root=Message1(text="Warning level severity test")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_3  # MEDIUM
        assert finding.vulnerabilities[0].severity == "WARNING"

    def test_severity_mapping_note_to_low(self, reporter, sample_metadata):
        """Test that SARIF 'note' level maps to OCSF LOW severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="SEVERITY_NOTE",
            level=Level.note,
            message=Message(root=Message1(text="Note level severity test")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_2  # LOW
        assert finding.vulnerabilities[0].severity == "NOTE"

    def test_severity_mapping_none_to_informational(self, reporter, sample_metadata):
        """Test that SARIF 'none' level maps to OCSF INFORMATIONAL severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="SEVERITY_NONE",
            level=Level.none,
            message=Message(root=Message1(text="None level severity test")),
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_1  # INFORMATIONAL
        assert finding.vulnerabilities[0].severity == "NONE"

    def test_severity_mapping_missing_level_defaults_to_schema_default(self, reporter, sample_metadata):
        """Test that missing SARIF level uses SARIF schema default (error -> HIGH)."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        result = Result(
            ruleId="SEVERITY_MISSING",
            message=Message(root=Message1(text="Missing level severity test")),
            # level is not set (None), but SARIF schema defaults to Level.error
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # SARIF schema defaults to Level.error when no level is provided
        assert finding.severity_id == SeverityId.integer_4  # HIGH (error default)
        assert finding.vulnerabilities[0].severity == "ERROR"  # Schema default

    def test_severity_mapping_explicit_none_level(self, reporter, sample_metadata):
        """Test that explicitly set None level defaults to OCSF LOW severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a mock result that truly has None level
        class MockResult:
            def __init__(self):
                self.ruleId = "SEVERITY_EXPLICIT_NONE"
                self.message = Message(root=Message1(text="Explicit None level severity test"))
                self.level = None  # Explicitly None
                self.suppressions = None

        result = MockResult()
        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        assert finding.severity_id == SeverityId.integer_2  # LOW (default)
        assert finding.vulnerabilities[0].severity == "MEDIUM"  # Default in vulnerability creation

    def test_severity_mapping_case_insensitive(self, reporter, sample_metadata):
        """Test that severity mapping handles case variations correctly."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a mock result with string level instead of enum
        class MockResult:
            def __init__(self, level_str):
                self.ruleId = "CASE_TEST"
                self.message = Message(root=Message1(text="Case sensitivity test"))
                self._level = level_str
            
            @property
            def level(self):
                return self._level
            
            @property
            def suppressions(self):
                return None

        # Test uppercase "ERROR"
        result_upper = MockResult("ERROR")
        finding_upper = reporter._create_vulnerability_finding(result_upper, sample_metadata, current_time_ms)
        assert finding_upper.severity_id == SeverityId.integer_4  # HIGH

        # Test mixed case "Warning"
        result_mixed = MockResult("Warning")
        finding_mixed = reporter._create_vulnerability_finding(result_mixed, sample_metadata, current_time_ms)
        assert finding_mixed.severity_id == SeverityId.integer_3  # MEDIUM

        # Test lowercase "note"
        result_lower = MockResult("note")
        finding_lower = reporter._create_vulnerability_finding(result_lower, sample_metadata, current_time_ms)
        assert finding_lower.severity_id == SeverityId.integer_2  # LOW

    def test_severity_mapping_invalid_level_defaults_to_low(self, reporter, sample_metadata):
        """Test that invalid SARIF level values default to OCSF LOW severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a mock result with invalid level
        class MockResult:
            def __init__(self, level_value):
                self.ruleId = "INVALID_LEVEL_TEST"
                self.message = Message(root=Message1(text="Invalid level test"))
                self._level = level_value
            
            @property
            def level(self):
                return self._level
            
            @property
            def suppressions(self):
                return None

        # Test with invalid string
        result_invalid_str = MockResult("invalid_level")
        finding_invalid_str = reporter._create_vulnerability_finding(result_invalid_str, sample_metadata, current_time_ms)
        assert finding_invalid_str.severity_id == SeverityId.integer_2  # LOW (default)

        # Test with numeric value
        result_numeric = MockResult(42)
        finding_numeric = reporter._create_vulnerability_finding(result_numeric, sample_metadata, current_time_ms)
        assert finding_numeric.severity_id == SeverityId.integer_2  # LOW (default)

        # Test with empty string
        result_empty = MockResult("")
        finding_empty = reporter._create_vulnerability_finding(result_empty, sample_metadata, current_time_ms)
        assert finding_empty.severity_id == SeverityId.integer_2  # LOW (default)

    def test_severity_mapping_error_handling_during_level_access(self, reporter, sample_metadata):
        """Test that errors during level access default to OCSF LOW severity."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a mock result that raises exception when accessing level
        class MockResult:
            def __init__(self):
                self.ruleId = "ERROR_ACCESS_TEST"
                self.message = Message(root=Message1(text="Error access test"))
            
            @property
            def level(self):
                raise Exception("Error accessing level property")
            
            @property
            def suppressions(self):
                return None

        result = MockResult()
        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Should default to LOW severity when level access fails
        assert finding.severity_id == SeverityId.integer_2  # LOW (default)

    def test_severity_mapping_consistency_across_multiple_findings(self, reporter, sample_metadata):
        """Test that severity mapping is consistent across multiple findings with same level."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create multiple results with same level
        results = []
        for i in range(5):
            result = Result(
                ruleId=f"CONSISTENCY_TEST_{i}",
                level=Level.error,
                message=Message(root=Message1(text=f"Consistency test {i}")),
            )
            results.append(result)

        # Create findings for all results
        findings = []
        for result in results:
            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
            findings.append(finding)

        # All findings should have the same severity
        for finding in findings:
            assert finding.severity_id == SeverityId.integer_4  # HIGH
            assert finding.vulnerabilities[0].severity == "ERROR"

    def test_severity_mapping_all_levels_comprehensive(self, reporter, sample_metadata):
        """Comprehensive test of all SARIF levels to OCSF severity mapping."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Test data: (sarif_level, expected_ocsf_severity_id, expected_vuln_severity)
        test_cases = [
            (Level.error, SeverityId.integer_4, "ERROR"),      # HIGH
            (Level.warning, SeverityId.integer_3, "WARNING"),  # MEDIUM
            (Level.note, SeverityId.integer_2, "NOTE"),        # LOW
            (Level.none, SeverityId.integer_1, "NONE"),        # INFORMATIONAL
        ]

        for sarif_level, expected_severity_id, expected_vuln_severity in test_cases:
            result = Result(
                ruleId=f"COMPREHENSIVE_{sarif_level.value.upper()}",
                level=sarif_level,
                message=Message(root=Message1(text=f"Comprehensive test for {sarif_level.value}")),
            )

            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

            assert finding.severity_id == expected_severity_id, f"Failed for level {sarif_level.value}"
            assert finding.vulnerabilities[0].severity == expected_vuln_severity, f"Failed vulnerability severity for level {sarif_level.value}"

    def test_severity_mapping_with_suppressions_preserves_severity(self, reporter, sample_metadata):
        """Test that severity mapping works correctly even when findings are suppressed."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create suppressed finding with high severity
        result = Result(
            ruleId="SUPPRESSED_HIGH_SEVERITY",
            level=Level.error,
            message=Message(root=Message1(text="Suppressed high severity test")),
            suppressions=[
                Suppression(
                    kind=Kind1.inSource,
                    state=State.accepted,
                    justification="False positive",
                )
            ],
        )

        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Severity should still be HIGH even though finding is suppressed
        assert finding.severity_id == SeverityId.integer_4  # HIGH
        assert finding.status_id == StatusId.integer_4  # Suppressed
        assert finding.vulnerabilities[0].severity == "ERROR"

    def test_severity_mapping_individual_finding_independence(self, reporter, sample_metadata):
        """Test that each individual finding gets its own severity based on its SARIF level."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create results with different severity levels
        results = [
            Result(
                ruleId="INDEPENDENCE_ERROR",
                level=Level.error,
                message=Message(root=Message1(text="Error level finding")),
            ),
            Result(
                ruleId="INDEPENDENCE_WARNING",
                level=Level.warning,
                message=Message(root=Message1(text="Warning level finding")),
            ),
            Result(
                ruleId="INDEPENDENCE_NOTE",
                level=Level.note,
                message=Message(root=Message1(text="Note level finding")),
            ),
        ]

        # Create findings
        findings = []
        for result in results:
            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
            findings.append(finding)

        # Each finding should have its own severity
        assert findings[0].severity_id == SeverityId.integer_4  # HIGH (error)
        assert findings[1].severity_id == SeverityId.integer_3  # MEDIUM (warning)
        assert findings[2].severity_id == SeverityId.integer_2  # LOW (note)

        # Verify vulnerability severities match
        assert findings[0].vulnerabilities[0].severity == "ERROR"
        assert findings[1].vulnerabilities[0].severity == "WARNING"
        assert findings[2].vulnerabilities[0].severity == "NOTE"

    def test_severity_mapping_edge_case_level_attribute_missing(self, reporter, sample_metadata):
        """Test severity mapping when level attribute is completely missing from result."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create a mock result without level attribute
        class MockResultNoLevel:
            def __init__(self):
                self.ruleId = "NO_LEVEL_ATTR"
                self.message = Message(root=Message1(text="No level attribute test"))
                self.suppressions = None
            
            # No level property defined at all

        result = MockResultNoLevel()
        finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)

        # Should default to LOW severity when level attribute doesn't exist
        assert finding.severity_id == SeverityId.integer_2  # LOW (default)

    def test_severity_mapping_performance_with_many_findings(self, reporter, sample_metadata):
        """Test that severity mapping performs well with many findings."""
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Create many results with different severity levels
        results = []
        levels = [Level.error, Level.warning, Level.note, Level.none]
        
        for i in range(100):
            level = levels[i % len(levels)]
            result = Result(
                ruleId=f"PERF_TEST_{i}",
                level=level,
                message=Message(root=Message1(text=f"Performance test {i}")),
            )
            results.append(result)

        # Process all results
        findings = []
        for result in results:
            finding = reporter._create_vulnerability_finding(result, sample_metadata, current_time_ms)
            findings.append(finding)

        # Verify all findings have correct severity mapping
        expected_severities = [
            SeverityId.integer_4,  # HIGH (error)
            SeverityId.integer_3,  # MEDIUM (warning)
            SeverityId.integer_2,  # LOW (note)
            SeverityId.integer_1,  # INFORMATIONAL (none)
        ]

        for i, finding in enumerate(findings):
            expected_severity = expected_severities[i % len(expected_severities)]
            assert finding.severity_id == expected_severity, f"Failed for finding {i}"

        # Verify we processed all findings
        assert len(findings) == 100
        """Create a sample AshAggregatedResults model for testing."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            SarifReport,
            Run,
            Tool,
            ToolComponent,
        )
        
        # Create SARIF results
        results = [
            Result(
                ruleId="TEST001",
                level=Level.error,
                message=Message(root=Message1(text="Test error message")),
            ),
            Result(
                ruleId="TEST002",
                level=Level.warning,
                message=Message(root=Message1(text="Test warning message")),
                suppressions=[
                    Suppression(
                        kind=Kind1.inSource,
                        state=State.accepted,
                        justification="False positive",
                    )
                ],
            ),
        ]
        
        # Create SARIF schema
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(
            runs=[Run(tool=tool, results=results)]
        )
        
        return AshAggregatedResults(sarif=sarif)

    def test_report_creates_array_of_findings(self, reporter, sample_ash_model):
        """Test that report method creates array of individual findings."""
        result_json = reporter.report(sample_ash_model)
        
        # Parse JSON result
        import json
        findings = json.loads(result_json)
        
        # Should be an array
        assert isinstance(findings, list)
        assert len(findings) == 2  # Two SARIF results should create two findings
        
        # Each finding should be a VulnerabilityFinding object
        for finding in findings:
            assert "activity_name" in finding
            assert finding["activity_name"] == "Scan"
            assert "vulnerabilities" in finding
            assert len(finding["vulnerabilities"]) == 1  # One vulnerability per finding
            assert "finding_info" in finding
            assert "uid" in finding["finding_info"]

    def test_report_individual_severity_mapping(self, reporter, sample_ash_model):
        """Test that each finding gets its own severity based on SARIF level."""
        result_json = reporter.report(sample_ash_model)
        
        import json
        findings = json.loads(result_json)
        
        # First finding should be HIGH severity (error level)
        assert findings[0]["severity_id"] == 4  # SeverityId.integer_4 (HIGH)
        
        # Second finding should be MEDIUM severity (warning level)
        assert findings[1]["severity_id"] == 3  # SeverityId.integer_3 (MEDIUM)

    def test_report_individual_status_mapping(self, reporter, sample_ash_model):
        """Test that each finding gets its own status based on suppressions."""
        result_json = reporter.report(sample_ash_model)
        
        import json
        findings = json.loads(result_json)
        
        # First finding should be active (no suppressions)
        assert findings[0]["status_id"] == 1  # StatusId.integer_1 (Active)
        assert "status_detail" not in findings[0] or findings[0]["status_detail"] is None
        
        # Second finding should be suppressed
        assert findings[1]["status_id"] == 4  # StatusId.integer_4 (Suppressed)
        assert "status_detail" in findings[1]
        assert "False positive" in findings[1]["status_detail"]

    def test_report_unique_finding_identifiers(self, reporter, sample_ash_model):
        """Test that each finding gets a unique identifier."""
        result_json = reporter.report(sample_ash_model)
        
        import json
        findings = json.loads(result_json)
        
        # Extract UIDs
        uids = [finding["finding_info"]["uid"] for finding in findings]
        
        # All UIDs should be unique
        assert len(uids) == len(set(uids))
        
        # All UIDs should be valid UUIDs
        for uid in uids:
            uuid.UUID(uid)  # Should not raise exception

    def test_report_empty_sarif_results(self, reporter):
        """Test report method with empty SARIF results."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent
        
        # Create empty SARIF
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(runs=[Run(tool=tool, results=[])])
        model = AshAggregatedResults(sarif=sarif)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        # Should return empty array
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_report_no_sarif_data(self, reporter):
        """Test report method with no SARIF data."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        
        model = AshAggregatedResults(sarif=None)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        # Should return empty array
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_report_error_handling_continues_processing(self, reporter, monkeypatch):
        """Test that errors in individual finding creation don't stop processing."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent
        
        # Create SARIF with multiple results
        results = [
            Result(
                ruleId="TEST001",
                level=Level.error,
                message=Message(root=Message1(text="Good result")),
            ),
            Result(
                ruleId="TEST002",
                level=Level.warning,
                message=Message(root=Message1(text="Another good result")),
            ),
        ]
        
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(runs=[Run(tool=tool, results=results)])
        model = AshAggregatedResults(sarif=sarif)
        
        # Mock _create_vulnerability_finding to fail on first call but succeed on second
        original_method = reporter._create_vulnerability_finding
        call_count = 0
        
        def mock_create_finding(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Test error for first finding")
            return original_method(*args, **kwargs)
        
        monkeypatch.setattr(reporter, "_create_vulnerability_finding", mock_create_finding)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        # Should have one finding (second one succeeded)
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0]["vulnerabilities"][0]["title"] == "TEST002"

    def test_report_unique_identifiers_across_findings(self, reporter):
        """Test that all findings in a report have unique identifiers."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent
        
        # Create multiple SARIF results
        results = []
        for i in range(10):
            results.append(Result(
                ruleId=f"TEST{i:03d}",
                level=Level.error,
                message=Message(root=Message1(text=f"Test message {i}")),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri=f"src/file{i}.py"),
                            region=Region(startLine=(i*10)+1),
                        ))
                    )
                ] if i % 2 == 0 else None,  # Some with locations, some without
            ))
        
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(runs=[Run(tool=tool, results=results)])
        model = AshAggregatedResults(sarif=sarif)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        # Extract all UIDs
        uids = [finding["finding_info"]["uid"] for finding in findings]
        
        # All UIDs should be unique
        assert len(uids) == len(set(uids)), "All finding UIDs should be unique"
        assert len(uids) == 10, "Should have 10 unique findings"
        
        # All UIDs should be valid UUIDs
        for uid in uids:
            uuid.UUID(uid)  # Should not raise exception
        
        # Verify titles are descriptive and unique
        titles = [finding["finding_info"]["title"] for finding in findings]
        for i, title in enumerate(titles):
            assert f"TEST{i:03d}" in title, f"Title should contain rule ID: {title}"
            if i % 2 == 0:  # Findings with locations
                assert f"file{i}.py" in title, f"Title should contain filename: {title}"

    def test_report_descriptive_titles_with_mixed_content(self, reporter):
        """Test that descriptive titles are created for various types of findings."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent
        
        # Create diverse SARIF results
        results = [
            # Finding with location and detailed message
            Result(
                ruleId="SQL_INJECTION",
                level=Level.error,
                message=Message(root=Message1(text="Potential SQL injection vulnerability detected in user input handling")),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri="src/database/queries.py"),
                            region=Region(startLine=45, endLine=50),
                        ))
                    )
                ],
            ),
            # Finding without location but with detailed message
            Result(
                ruleId="HARDCODED_SECRET",
                level=Level.warning,
                message=Message(root=Message1(text="Hardcoded API key detected in configuration")),
            ),
            # Finding with minimal information
            Result(
                ruleId="UNKNOWN_ISSUE",
                level=Level.note,
                message=Message(root=Message1(text="")),  # Empty message
            ),
            # Finding with very long message
            Result(
                ruleId="VERBOSE_RULE",
                level=Level.error,
                message=Message(root=Message1(text="This is a very long security message that describes in great detail the nature of the security vulnerability and provides extensive context about why this is problematic and what should be done to fix it" * 2)),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri="src/very/long/path/to/security/module.py"),
                        ))
                    )
                ],
            ),
        ]
        
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(runs=[Run(tool=tool, results=results)])
        model = AshAggregatedResults(sarif=sarif)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        assert len(findings) == 4
        
        # Validate first finding (with location)
        finding1 = findings[0]
        assert "SQL_INJECTION" in finding1["finding_info"]["title"]
        assert "queries.py" in finding1["finding_info"]["title"]
        assert "Potential SQL injection" in finding1["finding_info"]["title"]
        assert finding1["finding_info"]["desc"] == "Potential SQL injection vulnerability detected in user input handling"
        
        # Validate second finding (without location)
        finding2 = findings[1]
        assert "HARDCODED_SECRET" in finding2["finding_info"]["title"]
        assert "Hardcoded API key" in finding2["finding_info"]["title"]
        assert finding2["finding_info"]["desc"] == "Hardcoded API key detected in configuration"
        
        # Validate third finding (minimal info)
        finding3 = findings[2]
        assert "UNKNOWN_ISSUE" in finding3["finding_info"]["title"]
        assert finding3["finding_info"]["desc"] == "No description"
        
        # Validate fourth finding (long message, should be truncated in title)
        finding4 = findings[3]
        assert "VERBOSE_RULE" in finding4["finding_info"]["title"]
        assert "module.py" in finding4["finding_info"]["title"]
        assert len(finding4["finding_info"]["title"]) <= 123  # Should be truncated
        assert finding4["finding_info"]["title"].endswith("...")
        # Full message should be in description
        assert len(finding4["finding_info"]["desc"]) > 200  # Full long message

    def test_report_metadata_consistency_across_findings(self, reporter):
        """Test that metadata is consistent across all findings in a report."""
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent
        
        # Create multiple SARIF results
        results = [
            Result(
                ruleId=f"CONSISTENCY_TEST_{i}",
                level=Level.warning,
                message=Message(root=Message1(text=f"Consistency test message {i}")),
            )
            for i in range(5)
        ]
        
        tool = Tool(driver=ToolComponent(name="test-tool"))
        sarif = SarifReport(runs=[Run(tool=tool, results=results)])
        model = AshAggregatedResults(sarif=sarif)
        
        result_json = reporter.report(model)
        
        import json
        findings = json.loads(result_json)
        
        assert len(findings) == 5
        
        # Extract metadata from all findings
        metadatas = [finding["metadata"] for finding in findings]
        
        # All metadata should be identical except for logged_time (which should be the same)
        first_metadata = metadatas[0]
        for metadata in metadatas[1:]:
            assert metadata["product"]["name"] == first_metadata["product"]["name"]
            assert metadata["product"]["vendor_name"] == first_metadata["product"]["vendor_name"]
            assert metadata["product"]["version"] == first_metadata["product"]["version"]
            assert metadata["version"] == first_metadata["version"]
            assert metadata["logged_time"] == first_metadata["logged_time"]  # Should be same timestamp
        
        # Validate expected metadata values
        assert first_metadata["product"]["name"] == "Automated Security Helper"
        assert first_metadata["product"]["vendor_name"] == "Amazon Web Services"
        assert first_metadata["version"] == "1.1.0"
        assert isinstance(first_metadata["logged_time"], int)

    def test_report_json_serialization_error(self, reporter, sample_ash_model, monkeypatch):
        """Test error handling when JSON serialization fails."""
        # Mock json.dumps to raise an exception only for the main findings array
        import json
        original_dumps = json.dumps
        
        call_count = 0
        def mock_dumps(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Fail on first call (main findings array), succeed on second call (error response)
            if call_count == 1 and isinstance(args[0], list) and len(args[0]) > 0:
                raise Exception("JSON serialization error")
            return original_dumps(*args, **kwargs)
        
        monkeypatch.setattr("json.dumps", mock_dumps)
        
        result_json = reporter.report(sample_ash_model)
        
        import json
        findings = json.loads(result_json)
        
        # Should return error response array
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert "error" in findings[0]
        assert "processing_statistics" in findings[0]
        assert findings[0]["processing_statistics"]["processed_results_count"] == 2
        assert findings[0]["processing_statistics"]["failed_results_count"] == 0
