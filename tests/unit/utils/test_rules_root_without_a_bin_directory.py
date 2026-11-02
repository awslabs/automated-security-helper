# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With no rules directory and no bin directory, ASH says so instead of crashing.

``utils.rules_bundles.rules_root`` is ``$ASH_CFN_GUARD_RULES_DIR``, or the ``share``
directory beside the bin directory. ``download_utils.current_bin_path`` is documented
to return None when ``ASH_BIN_PATH`` is unset and HOME gives no ``~/.ash/bin``, and
``rules_root`` read ``.parent`` off that None. Its callers then saw three different
things:

* the cfn-guard scanner's ``sandbox_requirements`` raised AttributeError, which the
  sandbox scope's ``getattr(scanner, "sandbox_requirements", None)`` swallowed, so the
  scanner silently got a policy with no read access to its rules;
* the scanner's ``validate_plugin_dependencies`` let the AttributeError escape, where
  it handles only ``RulesBundleUnavailable``;
* ``verify_installed_bundle`` and ``install_rules_bundle`` raised AttributeError where
  their docstrings promise ``RulesBundleUnavailable``.

``rules_root`` now raises ``RulesBundleUnavailable`` with the reason, which the callers
that already handle that error report as they report any missing bundle. These tests
replace ``current_bin_path`` with a function that returns None (the sibling test for
the install commands patches the constants it reads instead), and one test goes
through the real ``current_bin_path``. Nothing here downloads or writes anything.
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
from automated_security_helper.utils import download_utils
from automated_security_helper.utils.rules_bundles import (
    RULES_DIR_ENV,
    RulesBundleUnavailable,
    install_rules_bundle,
    rules_root,
    verify_installed_bundle,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.tool_downloads import get_rules_bundle

pytestmark = pytest.mark.unit

BUNDLE = "aws-guard-rules-registry"


@pytest.fixture
def no_rules_directory(monkeypatch, tmp_path) -> Path:
    """No rules directory variable, and no bin directory to put the rules beside.

    ``rules_root`` reads ``current_bin_path`` from ``download_utils`` each time it
    runs, so replacing it there is what the function sees.
    """
    monkeypatch.delenv(RULES_DIR_ENV, raising=False)
    monkeypatch.setattr(download_utils, "current_bin_path", lambda: None)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _scanner(root: Path) -> CfnGuardScanner:
    output = root / "src" / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=root / "src",
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    return CfnGuardScanner(context=context, config=CfnGuardScannerConfig())


def _cfn_guard_on_path():
    """cfn-guard found, whether or not this host has one."""
    return patch(
        "automated_security_helper.plugin_modules.ash_builtin.scanners."
        "cfn_guard_scanner.find_executable",
        return_value="/usr/local/bin/cfn-guard",
    )


def _made_under(directory: Path) -> list[str]:
    return sorted(
        path.relative_to(directory).as_posix() for path in directory.rglob("*")
    )


class TestRulesRoot:
    def test_it_refuses_with_the_reason_and_both_ways_out(self, no_rules_directory):
        with pytest.raises(RulesBundleUnavailable) as refused:
            rules_root()

        message = str(refused.value)
        assert RULES_DIR_ENV in message
        assert "ASH_BIN_PATH" in message
        assert "--bin-path" in message

    def test_the_documented_none_is_how_it_gets_there(self, monkeypatch, tmp_path):
        """Through ``current_bin_path`` itself, with the constant it falls back to
        None, as it is with no ASH_BIN_PATH and no usable home."""
        monkeypatch.delenv(RULES_DIR_ENV, raising=False)
        monkeypatch.delenv("ASH_BIN_PATH", raising=False)
        monkeypatch.setattr(download_utils, "ASH_BIN_PATH", None)
        monkeypatch.chdir(tmp_path)

        assert download_utils.current_bin_path() is None
        with pytest.raises(RulesBundleUnavailable, match="--bin-path"):
            rules_root()

    def test_the_rules_directory_variable_still_decides(
        self, no_rules_directory, monkeypatch
    ):
        chosen = no_rules_directory / "rules"
        monkeypatch.setenv(RULES_DIR_ENV, str(chosen))

        assert rules_root() == chosen

    def test_a_bin_directory_still_puts_the_rules_beside_it(
        self, no_rules_directory, monkeypatch
    ):
        bin_dir = no_rules_directory / "tools" / "bin"
        monkeypatch.setattr(download_utils, "current_bin_path", lambda: bin_dir)

        assert rules_root() == bin_dir.parent / "share" / "cfn-guard-rules"


class TestCallers:
    def test_verify_installed_bundle_raises_the_error_it_documents(
        self, no_rules_directory
    ):
        with pytest.raises(RulesBundleUnavailable, match="ASH_BIN_PATH"):
            verify_installed_bundle(get_rules_bundle(BUNDLE))

    def test_install_rules_bundle_refuses_before_it_downloads_or_creates_anything(
        self, no_rules_directory, monkeypatch
    ):
        attempts = []

        def no_download(*args, **kwargs):
            attempts.append(args)
            raise AssertionError("a download was started")

        monkeypatch.setattr(download_utils, "download_file", no_download)

        with pytest.raises(RulesBundleUnavailable, match="--bin-path"):
            install_rules_bundle(BUNDLE)

        assert attempts == []
        assert _made_under(no_rules_directory) == []


class TestCfnGuardScanner:
    def test_the_sandbox_grant_is_empty_not_lost(self, no_rules_directory):
        """The sandbox scope reads the grant with ``getattr(..., None)``, which
        turned the AttributeError into None and then into the default policy,
        without a word."""
        scanner = _scanner(no_rules_directory)

        requirements = getattr(scanner, "sandbox_requirements", None)

        assert isinstance(requirements, SandboxRequirements)
        assert requirements.read_paths == ()

    def test_reading_the_sandbox_grant_directly_does_not_raise(
        self, no_rules_directory
    ):
        scanner = _scanner(no_rules_directory)

        assert scanner.sandbox_requirements == SandboxRequirements()

    def test_the_empty_grant_is_explained_once(self, no_rules_directory, caplog):
        scanner = _scanner(no_rules_directory)

        with caplog.at_level("WARNING"):
            first = scanner.sandbox_requirements
            second = scanner.sandbox_requirements

        assert first == second == SandboxRequirements()
        assert caplog.text.count("no read access to a cfn-guard rules directory") == 1
        assert "ASH_BIN_PATH" in caplog.text

    def test_the_dependency_check_says_there_is_no_rules_directory(
        self, no_rules_directory
    ):
        scanner = _scanner(no_rules_directory)

        with _cfn_guard_on_path():
            assert scanner.validate_plugin_dependencies() is False

        reason = scanner.dependency_unavailable_reason
        assert RULES_DIR_ENV in reason
        assert "ASH_BIN_PATH" in reason
        # Recorded once, by the ERROR log line the base class appends to
        # self.errors with its "(cfn-guard) " prefix; the bare element this test
        # looked for was the second record an earlier tip appended beside it.
        recorded = [e for e in scanner.errors if reason in e]
        assert len(recorded) == 1, scanner.errors

    def test_selecting_the_rules_raises_the_bundle_error(self, no_rules_directory):
        scanner = _scanner(no_rules_directory)

        with pytest.raises(RulesBundleUnavailable, match="ASH_BIN_PATH"):
            scanner.rule_files()
