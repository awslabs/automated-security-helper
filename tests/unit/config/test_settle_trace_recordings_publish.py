# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The settle-trace cells publish their rows to the junit file as testsuite
properties, never as a testcase's ``<properties>``.

pytest's default ``junit_family`` is xunit2, and no config of this repository
(pytest.ini, pyproject.toml, tests/conftest.py) sets another. Under it a
testcase's ``<properties>`` is outside the schema: the ``record_property``
fixture warns at the setup of every test that requests it (a CI run with
``--junit-xml`` carried one warning per settle-trace test), and appending to
``request.node.user_properties`` wrote the same element without the warning. The
``record_testsuite_property`` fixture writes the testsuite's ``<properties>``,
which xunit2 admits, so the rows still reach the junit file. These tests read
the module's source, so they are unit tests whatever tier those cells are.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MODULE = Path(__file__).with_name("test_settle_trace_recordings.py")


def _tree() -> ast.Module:
    return ast.parse(MODULE.read_text(encoding="utf-8"))


def test_no_settle_trace_function_requests_the_record_property_fixture():
    requesting = [
        node.name
        for node in ast.walk(_tree())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            argument.arg == "record_property"
            for argument in [*node.args.args, *node.args.kwonlyargs]
        )
    ]

    assert requesting == [], requesting


def test_no_row_is_written_to_a_testcases_properties():
    """``user_properties`` is the list the junit plugin writes a testcase's
    ``<properties>`` from; nothing in the module names it."""
    named = [
        node.lineno
        for node in ast.walk(_tree())
        if isinstance(node, ast.Attribute) and node.attr == "user_properties"
    ]

    assert named == [], named


def test_the_rows_are_published_as_testsuite_properties():
    requested = [
        node.lineno
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "getfixturevalue"
        and any(
            isinstance(argument, ast.Constant)
            and argument.value == "record_testsuite_property"
            for argument in node.args
        )
    ]

    assert requested, "no call requests record_testsuite_property"
