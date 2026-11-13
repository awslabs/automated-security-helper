# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A verified-PATH decision survives checkov's dependency re-validation.

Setup verified the copy on PATH and chose to run it directly
(``_select_tool_execution``: ``use_uv_tool`` False), yet a later validation of
the same instance skipped its ``if self.use_uv_tool`` branch -- the decision
had set the flag False -- and fell to the consolidated resolver, which spawned
a cold ``uv tool run ... --version`` probe and flipped ``use_uv_tool`` back to
True. The scan then ran through uv and the verified copy never ran: ash.log
showed "Using pre-installed checkov at ... directly" followed by "Executing
checkov via UV tool run". The decision is now honored while the copy still
exists; a copy that is gone re-resolves, so a genuinely unusable tool still
fails loudly.
"""

from __future__ import annotations

import os

import pytest
from unittest.mock import patch

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


@pytest.fixture
def checkov(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    return CheckovScanner(context=context)


def _verified_copy(tmp_path):
    copy = tmp_path / "pathbin" / "checkov"
    copy.parent.mkdir()
    copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(copy, 0o755)
    return copy


def test_the_verified_path_decision_is_honored(checkov, tmp_path):
    copy = _verified_copy(tmp_path)
    # What _select_tool_execution's satisfied branch records at setup.
    checkov.use_uv_tool = False
    checkov._verified_pre_installed_executable = str(copy)

    with (
        patch.object(CheckovScanner, "resolve_deferred_tool_version"),
        patch.object(
            CheckovScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(checkov_scanner, "get_uv_tool_command") as resolver,
    ):
        assert checkov.validate_plugin_dependencies() is True

    resolver.assert_not_called()
    assert checkov.use_uv_tool is False
    assert checkov.dependencies_satisfied is True


def test_without_the_record_the_resolver_still_flips_to_uv(checkov):
    """The control: the honored record is what prevents the discard."""
    checkov.use_uv_tool = False
    assert checkov._verified_pre_installed_executable is None

    with (
        patch.object(CheckovScanner, "resolve_deferred_tool_version"),
        patch.object(
            CheckovScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            checkov_scanner,
            "get_uv_tool_command",
            return_value=["uv", "tool", "run", "checkov"],
        ) as resolver,
    ):
        assert checkov.validate_plugin_dependencies() is True

    resolver.assert_called_once()
    assert checkov.use_uv_tool is True


def test_a_gone_verified_copy_is_re_resolved_and_can_fail(checkov, tmp_path):
    checkov.use_uv_tool = False
    checkov._verified_pre_installed_executable = str(tmp_path / "gone" / "checkov")

    with (
        patch.object(CheckovScanner, "resolve_deferred_tool_version"),
        patch.object(
            CheckovScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            CheckovScanner,
            "_get_tool_installation_info",
            return_value={"available": False},
        ) as info,
        patch.object(CheckovScanner, "_install_uv_tool", return_value=False),
        patch.object(
            checkov_scanner, "get_uv_tool_command", return_value=None
        ) as resolver,
    ):
        assert checkov.validate_plugin_dependencies() is False

    # The stale record was cleared, the route put back on uv so selection ran
    # afresh (the installation-info read), and the resolver was consulted: an
    # unusable tool still fails loudly instead of being answered from the
    # record.
    assert checkov._verified_pre_installed_executable is None
    assert checkov.use_uv_tool is True
    info.assert_called_once()
    resolver.assert_called_once()


def test_a_config_swap_in_pre_scan_revalidates_without_the_flip(checkov, tmp_path):
    """The DA-named regression: swap the config per target, then re-validate.

    The swap runs BEFORE the dependency check now, so the target is checked
    under the config it scans with, and the swap resets the memoized verdict
    AND restores the uv route, so the re-validation runs selection afresh
    instead of skipping into the consolidated resolver's cold probe and flip.
    """
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')

    copy = _verified_copy(tmp_path)
    # What setup left behind: a satisfied, memoized validation that chose the
    # verified PATH copy.
    checkov.use_uv_tool = False
    checkov._verified_pre_installed_executable = str(copy)
    checkov._dependencies_validated = True
    checkov.dependencies_satisfied = True

    observed = []

    def recording_validate(self):
        observed.append(
            (
                self.use_uv_tool,
                self._verified_pre_installed_executable,
                self.config.options.scan_timeout,
            )
        )
        self.dependencies_satisfied = True
        return True

    changed = checkov.config.model_dump(by_alias=True)
    changed["options"]["scan_timeout"] = 123

    with patch.object(
        CheckovScanner, "validate_plugin_dependencies", recording_validate
    ):
        unchanged = checkov.config.model_dump(by_alias=True)
        assert checkov._pre_scan(target, target_type="source", config=unchanged)
        # Same config: the memoized verdict answers, nothing re-validates.
        assert observed == []

        assert checkov._pre_scan(target, target_type="source", config=changed)

    # The swap re-validated, under the NEW config (the check sees what the
    # target scans with), with the route restored and the record cleared.
    assert observed == [(True, None, 123)]
    assert checkov.config.options.scan_timeout == 123


def test_a_bandit_config_swap_resets_the_validation_too(tmp_path):
    """Bandit swaps the config ITSELF in its _pre_scan override and hands the
    base None, so the base swap's reset never runs for it: the reset is
    bandit's own duty right after _apply_config. Without it, a per-target
    config with another tool_version reused the setup verdict, and the early
    honored-record check accepted a PATH copy verified against the OLD
    requirement.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    bandit = BanditScanner(context=context)

    copy = _verified_copy(tmp_path)
    bandit.use_uv_tool = False
    bandit._verified_pre_installed_executable = str(copy)
    bandit._dependencies_validated = True
    bandit.dependencies_satisfied = True

    observed = []

    def recording_validate(self):
        observed.append(
            (
                self.use_uv_tool,
                self._verified_pre_installed_executable,
                self.config.options.scan_timeout,
            )
        )
        self.dependencies_satisfied = True
        return True

    changed = bandit.config.model_dump(by_alias=True)
    changed["options"]["scan_timeout"] = 321

    with patch.object(
        BanditScanner, "validate_plugin_dependencies", recording_validate
    ):
        unchanged = bandit.config.model_dump(by_alias=True)
        assert bandit._pre_scan(source, target_type="source", config=unchanged)
        assert observed == []

        assert bandit._pre_scan(source, target_type="source", config=changed)

    assert observed == [(True, None, 321)]
    assert bandit.config.options.scan_timeout == 321


def test_a_decision_repointed_at_uv_is_not_honored(checkov, tmp_path):
    """use_uv_tool True again means something newer chose uv; honor nothing."""
    copy = _verified_copy(tmp_path)
    checkov.use_uv_tool = True
    checkov._verified_pre_installed_executable = str(copy)

    with (
        patch.object(CheckovScanner, "resolve_deferred_tool_version"),
        patch.object(
            CheckovScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            CheckovScanner, "_get_tool_installation_info", return_value={}
        ) as info,
        patch.object(CheckovScanner, "_install_uv_tool", return_value=True),
    ):
        assert checkov.validate_plugin_dependencies() is True

    info.assert_called_once()
    assert checkov.use_uv_tool is True
