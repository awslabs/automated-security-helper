"""cfn-guard: a filesystem error while checking the rules reports MISSING, not a crash.

``validate_plugin_dependencies`` caught only ``RulesBundleUnavailable``. A
``PermissionError`` from ``Path.exists()`` or ``Path.is_dir()`` on a rules path
under a directory this user cannot search (Python 3.10-3.12 raise it) escaped,
so the scanner was dropped with a traceback instead of being reported MISSING
with the reason.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
    CfnGuardScannerConfig,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def scanner(ash_temp_path) -> CfnGuardScanner:
    repo = ash_temp_path / "repo"
    repo.mkdir()
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )
    return CfnGuardScanner(context=context, config=CfnGuardScannerConfig())


def test_a_permission_error_while_checking_rules_is_reported_missing(scanner):
    denied = PermissionError(13, "Permission denied", str(Path("/locked/rules")))
    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.find_executable",
            return_value="/usr/local/bin/cfn-guard",
        ),
        patch.object(CfnGuardScanner, "rule_files", side_effect=denied),
    ):
        assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependency_unavailable_reason is not None
    assert "PermissionError" in scanner.dependency_unavailable_reason
    assert any("PermissionError" in line for line in scanner.errors)
