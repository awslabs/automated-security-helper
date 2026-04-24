"""Tests for H3, H4, and M9 bug fixes in AWS plugin modules.

H3: bedrock_summary_reporter.py lines 669 and 797 use finding.get("severity")
    but the findings dict uses "level" as the key everywhere else.
H4: security_hub_reporter.py line 74 defines model_post_init__ (double underscore)
    instead of model_post_init (single underscore), so pydantic never calls it.
M9: ocsf_reporter.py line 665 checks StatusId.integer_4 for suppressed findings,
    but _determine_status_from_suppressions returns StatusId.integer_3.
"""

import inspect

import pytest


# ---------------------------------------------------------------------------
# H3: bedrock_summary_reporter uses "level" not "severity"
# ---------------------------------------------------------------------------


class TestBedrockSeverityKeyFix:
    """finding.get('level') must be used, not finding.get('severity')."""

    def test_generate_report_with_headers_uses_level_key(self):
        """Lines 669, 797: must read the 'level' key, not 'severity'."""
        from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
            BedrockSummaryReporter,
        )

        src = inspect.getsource(BedrockSummaryReporter._generate_report_with_headers)
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if '.get("severity"' in line:
                pytest.fail(
                    f"_generate_report_with_headers still uses "
                    f'.get("severity") instead of .get("level"): {line.strip()}'
                )


# ---------------------------------------------------------------------------
# H4: security_hub_reporter model_post_init (not double underscore)
# ---------------------------------------------------------------------------


class TestSecurityHubModelPostInit:
    """model_post_init must have a single trailing underscore (pydantic convention)."""

    def test_method_name_is_model_post_init(self):
        """The class must define model_post_init, not model_post_init__."""
        from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
            SecurityHubReporter,
        )

        assert "model_post_init" in SecurityHubReporter.__dict__, (
            "SecurityHubReporter does not define model_post_init in its own __dict__"
        )

    def test_double_underscore_variant_absent(self):
        """model_post_init__ (double underscore) must not exist."""
        from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
            SecurityHubReporter,
        )

        assert "model_post_init__" not in SecurityHubReporter.__dict__, (
            "SecurityHubReporter still defines model_post_init__ (double underscore)"
        )

    def test_super_call_uses_single_underscore(self):
        """The super() call inside must also be model_post_init, not model_post_init__."""
        from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
            SecurityHubReporter,
        )

        src = inspect.getsource(SecurityHubReporter.model_post_init)
        assert "model_post_init__" not in src, (
            "super().model_post_init__() still uses double underscore"
        )


# ---------------------------------------------------------------------------
# M9: ocsf_reporter suppressed-finding check uses StatusId.integer_3
# ---------------------------------------------------------------------------


class TestOcsfSuppressedStatusId:
    """Suppressed findings have StatusId.integer_3, not integer_4."""

    def test_suppressed_check_uses_integer_3(self):
        """Line 665: the suppressed-finding counter must compare against integer_3."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            OcsfReporter,
        )

        src = inspect.getsource(OcsfReporter.report)
        assert "StatusId.integer_4" not in src, (
            "ocsf_reporter.report still checks StatusId.integer_4 "
            "instead of StatusId.integer_3 for suppressed findings"
        )
        assert "StatusId.integer_3" in src, (
            "ocsf_reporter.report does not check StatusId.integer_3 "
            "for suppressed findings"
        )
