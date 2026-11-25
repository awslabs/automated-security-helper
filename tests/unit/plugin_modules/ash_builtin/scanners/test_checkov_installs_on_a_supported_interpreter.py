# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov is installed with an interpreter request that leaves out CPython 3.15.

Its JSON decoder does not pass the ``array_hook`` argument that 3.15's
``json.decoder.JSONArray`` requires, so on 3.15 every JSON document with an array
fails to parse (see ``CHECKOV_PYTHON_REQUEST``). Without a request, uv picks the
newest interpreter it can find or download.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CHECKOV_PYTHON_REQUEST,
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
    return CheckovScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    )


def test_install_command_requests_a_supported_interpreter(checkov):
    assert checkov.uv_tool_install_commands == [
        f"uv tool install --python {CHECKOV_PYTHON_REQUEST} checkov>=3.2.0,<4.0.0"
    ]


def test_the_request_excludes_python_3_15():
    from packaging.specifiers import SpecifierSet

    request = SpecifierSet(CHECKOV_PYTHON_REQUEST)
    assert "3.12" in request
    assert "3.14" in request
    assert "3.15" not in request
