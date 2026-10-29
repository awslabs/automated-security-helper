# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The settle-trace cells publish their rows to the junit file through the
node's ``user_properties``, never through the ``record_property`` fixture.

pytest's default ``junit_family`` is xunit2, and no config of this repository
(pytest.ini, pyproject.toml, tests/conftest.py) sets another, so the fixture
warns at the setup of every test that requests it: a CI run with ``--junit-xml``
carried one warning per settle-trace test. The junit plugin writes a testcase's
``<properties>`` from ``request.node.user_properties`` either way, so the rows
still reach the junit file. This test reads the module's source, so it is a
unit test whatever tier those tests are.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MODULE = Path(__file__).with_name("test_settle_trace_recordings.py")


def test_no_settle_trace_function_requests_the_record_property_fixture():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))

    requesting = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            argument.arg == "record_property"
            for argument in [*node.args.args, *node.args.kwonlyargs]
        )
    ]

    assert requesting == [], requesting


def test_the_rows_are_appended_to_the_nodes_user_properties():
    source = MODULE.read_text(encoding="utf-8")

    assert "request.node.user_properties.append(" in source
    assert "record_property(" not in source
