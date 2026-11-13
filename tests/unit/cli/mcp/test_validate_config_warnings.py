# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""validate_config keeps what makes a config invalid apart from what is only a warning.

Why this file exists
--------------------
validate_config's ``valid`` follows the scan: true when a scan accepts the
config. An ``errors`` list that carried the warnings as well (an unknown or
internal-only key, a missing project_name, a directory path without ``**``)
would let a valid config come back with entries in ``errors``, one of them
worded "Missing required top-level field", and a client reading ``errors`` to
decide whether to fix the file would get a list that does not mean what its
name says.

``errors`` holds only what a scan refuses, and ``warnings`` the rest. For an
invalid config, ``errors`` holds what makes it invalid, each entry with its
type (``invalid_field`` for a bad value), and nothing that is only a warning.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp_tools import mcp_validate_config

pytestmark = pytest.mark.unit


def test_a_valid_config_with_warnings_has_no_errors():
    result = mcp_validate_config(
        config_content="global_settings:\n  severity_threshold: HIGH\n"
    )

    assert result["valid"] is True, result
    assert result["errors"] == []
    (warning,) = [w for w in result["warnings"] if w["field"] == "project_name"]
    assert warning["type"] == "missing_required_field"
    assert "is not set" in warning["message"]


def test_an_invalid_config_keeps_its_errors_and_lists_warnings_apart():
    result = mcp_validate_config(
        config_content="global_settings:\n  severity_threshold: SEVERE\n"
    )

    assert result["valid"] is False, result
    assert result["errors"], result
    assert all(e["type"] == "invalid_field" for e in result["errors"]), result
    assert [w["field"] for w in result["warnings"]] == ["project_name"], result


def test_every_answer_has_both_lists():
    result = mcp_validate_config()
    assert result["valid"] is False
    assert result["warnings"] == []
    assert result["errors"][0]["type"] == "missing_input"
