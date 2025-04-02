"""Unit tests for Infrastructure as Code scanning functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.data_interchange import ReportMetadata
from automated_security_helper.models.iac_scan import IaCVulnerability, IaCScanReport


@pytest.fixture
def sample_vulnerability():
    """Create a sample IaC vulnerability for testing."""
    return IaCVulnerability(
        id="vuln-1",
        file_path="test.template.json",
        line_number=20,
        rule_id="XXXXXX",
        title="Insecure Security Group",
        description="Security group allows unrestricted access",
        severity="HIGH",
        scanner=Scanner(
            name="base_scanner", version="1.0.0", rule_id="TEST-001", type="SAST"
        ),
        location=Location(file_path="/path/to/file", start_line=10, end_line=5),
        timestamp=datetime.now(),
        resource_type="AWS::EC2::SecurityGroup",
        resource_name="WebServerSecurityGroup",
        violation_details={
            "rule": "no-public-ingress-sgr",
            "resource_id": "sg-12345",
            "impact": "Allows unrestricted inbound access",
            "remediation": "Restrict inbound traffic to specific IP ranges",
        },
    )


def test_iac_vulnerability_creation(base_scanner, base_location):
    """Test creation of IaCVulnerability objects."""
    vuln = IaCVulnerability(
        id="vuln-1",
        file_path="test.template.json",
        line_number=20,
        rule_id="RULE-1",
        title="Insecure Security Group",
        description="Security group allows unrestricted access",
        severity="HIGH",
        scanner=base_scanner,
        location=base_location,
        timestamp=datetime.now(),
        resource_type="AWS::EC2::SecurityGroup",
        resource_name="WebServerSecurityGroup",
        violation_details={
            "rule": "no-public-ingress-sgr",
            "resource_id": "sg-12345",
            "impact": "Allows unrestricted inbound access",
            "remediation": "Restrict inbound traffic to specific IP ranges",
        },
    )
    assert vuln.title == "Insecure Security Group"
    assert vuln.severity == "HIGH"
    assert vuln.resource_type == "AWS::EC2::SecurityGroup"
    assert vuln.resource_name == "WebServerSecurityGroup"
    assert "rule" in vuln.violation_details
    assert "remediation" in vuln.violation_details


def test_iac_vulnerability_inheritance(sample_vulnerability):
    """Test that IaCVulnerability inherits correctly from BaseFinding."""
    assert hasattr(sample_vulnerability, "title")
    assert hasattr(sample_vulnerability, "description")
    assert hasattr(sample_vulnerability, "severity")
    assert hasattr(sample_vulnerability, "scanner")
    assert hasattr(sample_vulnerability, "location")
    assert hasattr(sample_vulnerability, "timestamp")


def test_iac_scan_report_creation(sample_vulnerability):
    """Test creation of IaCScanReport objects."""
    report = IaCScanReport(
        name="CloudFormation IaC Scan Report",
        metadata=ReportMetadata(report_id="XXXXX", tool_name="cfn-nag"),
        template_path="templates/main.yaml",
        template_type="CloudFormation",
        timestamp=datetime.now(),
        findings=[sample_vulnerability],
        resources_checked={
            "AWS::EC2::SecurityGroup": 2,
            "AWS::S3::Bucket": 3,
            "AWS::IAM::Role": 1,
        },
    )
    assert report.template_path == "templates/main.yaml"
    assert report.template_type == "cloudformation"
    assert len(report.findings) == 1
    assert report.findings[0] == sample_vulnerability
    assert report.resources_checked["AWS::EC2::SecurityGroup"] == 2


def test_iac_scan_report_empty():
    """Test creation of empty IaCScanReport."""
    report = IaCScanReport(
        name="CloudFormation IaC Scan Report",
        template_path="templates/main.yaml",
        template_type="cloudformation",
        timestamp=datetime.now(timezone.utc),
        findings=[],
        resources_checked={},
        metadata=ReportMetadata(
            report_id="XXXXX",
            tool_name="cfn-nag",
        ),
    )
    assert report.template_path == "templates/main.yaml"
    assert report.template_type == "cloudformation"
    assert len(report.findings) == 0


def test_iac_scan_report_multiple_findings(base_scanner, sample_vulnerability):
    """Test IaCScanReport with multiple findings."""
    vuln2 = IaCVulnerability(
        id="vuln-2",
        file_path="test.template.json",
        line_number=25,
        rule_id="XXXXXX",
        title="Unencrypted S3 Bucket",
        description="S3 bucket does not have encryption enabled",
        severity="MEDIUM",
        scanner=base_scanner,
        location=Location(file_path="templates/main.yaml", start_line=20, end_line=25),
        timestamp=datetime.now(),
        resource_type="AWS::S3::Bucket",
        resource_name="DataBucket",
        violation_details={
            "rule": "encrypt-s3-bucket",
            "resource_id": "my-bucket",
            "impact": "Data stored in plaintext",
            "remediation": "Enable S3 bucket encryption",
        },
    )

    report = IaCScanReport(
        name="CloudFormation IaC Scan Report",
        metadata=ReportMetadata(report_id="XXXXX", tool_name="cdk-nag"),
        template_path="templates/main.yaml",
        template_type="CloudFormation",
        timestamp=datetime.now(),
        findings=[sample_vulnerability, vuln2],
        resources_checked={
            "AWS::EC2::SecurityGroup": 2,
            "AWS::S3::Bucket": 3,
            "AWS::IAM::Role": 1,
        },
    )
    assert len(report.findings) == 2
    assert any(f.severity == "HIGH" for f in report.findings)
    assert any(f.severity == "MEDIUM" for f in report.findings)
    assert any(f.resource_type == "AWS::EC2::SecurityGroup" for f in report.findings)
    assert any(f.resource_type == "AWS::S3::Bucket" for f in report.findings)


def test_iac_scan_report_invalid_template_type():
    """Test that invalid template type raises ValidationError."""
    with pytest.raises(ValueError):
        IaCScanReport(
            template_path="templates/main.yaml",
            template_type="InvalidType",  # Invalid template type
            scan_timestamp=datetime.now(),
            findings=[],
            resources_checked={},
        )


def test_iac_vulnerability_with_policy_violation(base_scanner, base_location):
    """Test IaCVulnerability with policy violation details."""
    vuln = IaCVulnerability(
        id="vuln-1",
        file_path="test.template.json",
        line_number=20,
        rule_id="XXXXXX",
        title="Non-Compliant IAM Policy",
        description="IAM policy grants excessive permissions",
        severity="HIGH",
        scanner=base_scanner,
        location=base_location,
        timestamp=datetime.now(),
        resource_type="AWS::IAM::Policy",
        resource_name="AdminPolicy",
        violation_details={
            "rule": "restrict-iam-policy",
            "resource_id": "policy-12345",
            "impact": "Overly permissive IAM policy",
            "remediation": "Limit IAM permissions to required actions only",
            "policy_violation": "Actions include wildcard permissions",
        },
    )
    assert vuln.title == "Non-Compliant IAM Policy"
    assert vuln.resource_type == "AWS::IAM::Policy"
    assert "policy_violation" in vuln.violation_details
    assert (
        "Actions include wildcard permissions"
        in vuln.violation_details["policy_violation"]
    )
