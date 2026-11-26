# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov is installed with an interpreter request that leaves out CPython 3.15.

Its JSON decoder does not pass the ``array_hook`` argument that 3.15's
``json.decoder.JSONArray`` requires, so on 3.15 every JSON document with an array
fails to parse (bridgecrewio/checkov#7777). Without a request, uv picks the
newest interpreter it can find or download.

The request is not a constant on the scanner: it is derived from the
``runtime_compat`` row of ``CheckovScanner.operational_facets``, the one place
a tool-version-by-runtime-version incompatibility is declared.
"""

from __future__ import annotations

import pytest
from packaging.specifiers import SpecifierSet

from automated_security_helper.base import scanner_operational_facets as opsf
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
    return CheckovScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    )


def test_install_command_requests_a_supported_interpreter(checkov):
    assert checkov.uv_tool_install_commands == [
        "uv tool install --python >=3.10,<3.15 checkov>=3.2.0,<4.0.0"
    ]


def test_the_request_excludes_python_3_15(checkov):
    request = SpecifierSet(checkov._get_tool_python_request())
    assert "3.10" in request
    assert "3.12" in request
    assert "3.14" in request
    assert "3.15" not in request


def test_checkov_derives_its_interpreter_request_from_its_compat_row(checkov):
    (row,) = CheckovScanner.operational_facets.runtime_compat.rows
    assert checkov._get_tool_python_request() == row.runtime_request == ">=3.10,<3.15"


def test_the_checkov_row_is_the_open_ended_one_for_issue_7777():
    (row,) = CheckovScanner.operational_facets.runtime_compat.rows
    assert row.open_ended
    assert row.upstream_issue == "https://github.com/bridgecrewio/checkov/issues/7777"
    assert row.resolution is opsf.CompatResolution.PIN, (
        "checkov's shipped default is the interpreter pin; the array_hook "
        "polyfill is the tested alternative behind the same facet family"
    )


def test_no_per_scanner_constant_or_override_is_left():
    assert not hasattr(checkov_scanner, "CHECKOV_PYTHON_REQUEST")
    assert "_get_tool_python_request" not in vars(CheckovScanner)
