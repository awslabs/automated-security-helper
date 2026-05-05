"""Regression tests for #181: cdk-nag must default to excluding compliant checks.

Before the fix, ``include_compliant_checks`` defaulted to True, flooding
reports with INFO-level "compliant" findings.  Now the default is False,
keeping reports focused on actual violations.
"""

from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScannerConfigOptions,
)


class TestCdkNagCompliantDefault:
    """include_compliant_checks must default to False."""

    def test_default_is_false(self):
        opts = CdkNagScannerConfigOptions()
        assert opts.include_compliant_checks is False

    def test_can_be_set_to_true(self):
        opts = CdkNagScannerConfigOptions(include_compliant_checks=True)
        assert opts.include_compliant_checks is True
