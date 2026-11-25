# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The recorded checkov ``tool_version`` is the executable the scan runs (#955).

Acceptance item 2 of #955: when no checkov is installed in uv's tools directory,
``uv tool run --from <spec> checkov --version`` resolves a fresh environment
(3.4.5 in the report) while the scan runs the copy on PATH (3.3.15). The version
recorded from the probe is then not the version that ran.

``_select_tool_execution`` chooses the PATH copy and records its own ``--version``
answer over the probe's. When the copy verified but its answer carried no version
line, the probe's value used to stay, naming an environment the scan never ran.
The record now names the executed copy or nothing.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

UV_PROBE_VERSION = "3.4.5"
PATH_COPY_VERSION = "3.3.15"


@pytest.fixture
def checkov(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    scanner = CheckovScanner(context=context)
    # What the uv probe recorded before the PATH copy was chosen.
    scanner.tool_version = UV_PROBE_VERSION
    return scanner


def _select(checkov, tmp_path, version):
    copy = tmp_path / "pathbin" / "checkov"
    copy.parent.mkdir()
    copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    copy.chmod(0o755)
    verdict = SimpleNamespace(
        status="satisfied",
        executable=str(copy),
        detail="ok",
        summary="",
        from_nix=False,
        version=version,
    )
    info = {"preferred_source": "pre_installed", "pre_installed_path": str(copy)}
    with (
        patch(
            "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool",
            return_value=verdict,
        ),
        patch.object(CheckovScanner, "_is_offline_mode", return_value=False),
    ):
        assert checkov._select_tool_execution(info) is True
    assert checkov.use_uv_tool is False
    assert checkov._verified_pre_installed_executable == str(copy)


def test_the_executed_copys_version_replaces_the_probes(checkov, tmp_path):
    _select(checkov, tmp_path, PATH_COPY_VERSION)
    assert checkov.tool_version == PATH_COPY_VERSION


def test_a_copy_that_answered_no_version_does_not_keep_the_probes(checkov, tmp_path):
    """Red before: the uv probe's 3.4.5 stayed as the version of a 3.3.15 run."""
    _select(checkov, tmp_path, None)
    assert checkov.tool_version != UV_PROBE_VERSION
    assert checkov.tool_version is None


def test_a_later_deferred_probe_does_not_rewrite_the_copys_record(checkov, tmp_path):
    _select(checkov, tmp_path, PATH_COPY_VERSION)
    checkov._deferred_tool_version_probe = ("checkov", None)
    with patch.object(
        CheckovScanner, "_get_uv_tool_version", return_value=UV_PROBE_VERSION
    ) as probe:
        checkov.resolve_deferred_tool_version()
    probe.assert_not_called()
    assert checkov.tool_version == PATH_COPY_VERSION
