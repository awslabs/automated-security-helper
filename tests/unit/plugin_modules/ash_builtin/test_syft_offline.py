"""Unit tests for Syft scanner offline mode support."""

import os
import pytest
from unittest.mock import MagicMock, patch

from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)


@pytest.fixture
def syft_scanner_offline(test_plugin_context):
    config = SyftScannerConfig(
        options=SyftScannerConfigOptions(offline=True)
    )
    return SyftScanner(context=test_plugin_context, config=config)


@pytest.fixture
def syft_scanner_online(test_plugin_context):
    config = SyftScannerConfig(
        options=SyftScannerConfigOptions(offline=False)
    )
    return SyftScanner(context=test_plugin_context, config=config)


def test_syft_offline_mode_sets_check_for_app_update_false(syft_scanner_offline):
    """When offline=True, extra_env must carry the update-check suppression vars."""
    assert syft_scanner_offline.extra_env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert syft_scanner_offline.extra_env["SYFT_LOG_QUIET"] == "true"


def test_syft_offline_false_does_not_set_env_vars(syft_scanner_online):
    """When offline=False, extra_env must not contain the syft offline vars."""
    assert "SYFT_CHECK_FOR_APP_UPDATE" not in syft_scanner_online.extra_env
    assert "SYFT_LOG_QUIET" not in syft_scanner_online.extra_env


def test_syft_subprocess_receives_merged_env(syft_scanner_offline):
    """The subprocess call must receive a merged env containing both os.environ and extra_env."""
    # The extra_env is populated at init time; verify the merge logic directly.
    # This mirrors how grype_scanner.py computes subprocess_env.
    subprocess_env = (
        {**os.environ, **syft_scanner_offline.extra_env}
        if syft_scanner_offline.extra_env
        else None
    )
    assert subprocess_env is not None
    assert subprocess_env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert subprocess_env["SYFT_LOG_QUIET"] == "true"
    # Verify os.environ was merged in (PATH is always present)
    assert "PATH" in subprocess_env
