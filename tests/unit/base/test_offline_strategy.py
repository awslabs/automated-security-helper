"""Tests for OfflineStrategy enum and per-scanner declarations."""

import pytest
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import BanditScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import CdkNagScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import CfnNagScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import DetectSecretsScanner
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import FerretScanScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import CheckovScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import GrypeScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import NpmAuditScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import OpengrepScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import SemgrepScanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import SyftScanner
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import TrivyRepoScanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import SnykCodeScanner


def test_enum_values():
    assert OfflineStrategy.BUNDLED == "bundled"
    assert OfflineStrategy.CACHE_FLAGS == "cache_flags"
    assert OfflineStrategy.SKIP_OFFLINE == "skip_offline"
    assert OfflineStrategy.UNKNOWN == "unknown"


def test_default_is_unknown():
    assert ScannerPluginBase.offline_strategy is OfflineStrategy.UNKNOWN


def test_no_scanner_is_unknown():
    scanners = [
        BanditScanner,
        CdkNagScanner,
        CfnNagScanner,
        DetectSecretsScanner,
        FerretScanScanner,
        CheckovScanner,
        GrypeScanner,
        NpmAuditScanner,
        OpengrepScanner,
        SemgrepScanner,
        SyftScanner,
        TrivyRepoScanner,
        SnykCodeScanner,
    ]
    for scanner_cls in scanners:
        assert scanner_cls.offline_strategy is not OfflineStrategy.UNKNOWN, (
            f"{scanner_cls.__name__} still has offline_strategy=UNKNOWN"
        )


_EXPECTED_STRATEGIES = {
    BanditScanner: OfflineStrategy.BUNDLED,
    CdkNagScanner: OfflineStrategy.BUNDLED,
    CfnNagScanner: OfflineStrategy.BUNDLED,
    DetectSecretsScanner: OfflineStrategy.BUNDLED,
    FerretScanScanner: OfflineStrategy.BUNDLED,
    CheckovScanner: OfflineStrategy.CACHE_FLAGS,
    GrypeScanner: OfflineStrategy.CACHE_FLAGS,
    NpmAuditScanner: OfflineStrategy.CACHE_FLAGS,
    OpengrepScanner: OfflineStrategy.CACHE_FLAGS,
    SemgrepScanner: OfflineStrategy.CACHE_FLAGS,
    SyftScanner: OfflineStrategy.CACHE_FLAGS,
    TrivyRepoScanner: OfflineStrategy.CACHE_FLAGS,
    SnykCodeScanner: OfflineStrategy.SKIP_OFFLINE,
}


def test_strategy_classifications_match_investigation():
    for scanner_cls, expected in _EXPECTED_STRATEGIES.items():
        assert scanner_cls.offline_strategy is expected, (
            f"{scanner_cls.__name__}: expected {expected}, got {scanner_cls.offline_strategy}"
        )
