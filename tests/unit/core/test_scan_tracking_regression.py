"""Regression tests for scan_tracking bug fixes.

PR#274 Bug #15: severity key case mismatch in extract_findings_summary.
"""

import pytest


class TestSeverityKeyCaseMismatch:
    """extract_findings_summary must handle uppercase severity values."""

    def test_uppercase_severity_counted(self):
        """Findings with uppercase 'CRITICAL' must be counted."""
        from automated_security_helper.core.resource_management.scan_tracking import (
            extract_findings_summary,
        )

        findings = [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
            {"severity": "INFO"},
        ]
        summary = extract_findings_summary(findings)
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["info"] == 1

    def test_lowercase_severity_counted(self):
        """Findings with lowercase severity must also work."""
        from automated_security_helper.core.resource_management.scan_tracking import (
            extract_findings_summary,
        )

        findings = [
            {"severity": "critical"},
            {"severity": "high"},
        ]
        summary = extract_findings_summary(findings)
        assert summary["critical"] == 1
        assert summary["high"] == 1

    def test_mixed_case_severity(self):
        """Mixed case like 'Critical' must be counted."""
        from automated_security_helper.core.resource_management.scan_tracking import (
            extract_findings_summary,
        )

        findings = [
            {"severity": "Critical"},
            {"severity": "HIGH"},
            {"severity": "medium"},
        ]
        summary = extract_findings_summary(findings)
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
