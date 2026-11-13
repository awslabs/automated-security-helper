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
            checkov_scanner, "get_uv_tool_command", return_value=None
        ) as resolver,
    ):
        assert checkov.validate_plugin_dependencies() is False

    # The stale record was cleared and the resolver consulted: an unusable
    # tool still fails loudly instead of being answered from the record.
    resolver.assert_called_once()
    assert checkov._verified_pre_installed_executable is None


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
