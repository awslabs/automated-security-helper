# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The name rules in ``tests/integration/cli/conftest.py`` reach only that directory.

pytest hands ``pytest_collection_modifyitems`` every item of the session, and it
loads this conftest only when it collects ``tests/integration/cli``. A rule scoped
wider than the directory therefore marks a test in a sibling directory ``slow`` (and
so skips it without ``--run-slow``) in a run that happens to collect the CLI tests,
and leaves it alone in a run of the sibling on its own. The same test would run or
not depending on which paths were on the command line.

The hook is called here with stand-in items, so nothing is collected or started.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

INTEGRATION = Path(__file__).resolve().parents[1] / "integration"
CONFTEST = INTEGRATION / "cli" / "conftest.py"


class _Item:
    """The parts of a collected item the hook reads, recording the marks it adds."""

    def __init__(self, path: Path, name: str) -> None:
        self.fspath = str(path)
        self.name = name
        self.added: list[str] = []

    def add_marker(self, marker) -> None:
        self.added.append(marker.name)


def _hook():
    spec = importlib.util.spec_from_file_location(
        "_cli_integration_conftest_under_test", CONFTEST
    )
    assert spec is not None and spec.loader is not None, CONFTEST
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pytest_collection_modifyitems


def _marks_added(directory: str, name: str) -> list[str]:
    item = _Item(INTEGRATION / directory / "test_stand_in.py", name)
    _hook()(SimpleNamespace(), [item])
    return item.added


def test_a_workflow_named_test_beside_the_cli_tests_is_marked_slow():
    assert _marks_added("cli", "test_scan_workflow_is_reported") == ["slow"]


def test_an_mcp_named_test_beside_the_cli_tests_is_marked_mcp():
    assert _marks_added("cli", "test_mcp_tools_are_listed") == ["mcp"]


@pytest.mark.parametrize("directory", ["scanners", "converters", "core", "docs"])
def test_a_workflow_named_test_in_a_sibling_directory_is_left_unmarked(directory):
    """The directory's own conftest does not load with the CLI tests' conftest, so
    the name rule must not decide whether this test runs."""
    assert _marks_added(directory, "test_scan_workflow_is_reported") == []


def test_an_mcp_named_test_in_a_sibling_directory_is_left_unmarked():
    assert _marks_added("scanners", "test_mcp_tools_are_listed") == []
