# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The name rules in ``tests/integration/cli/conftest.py`` reach only that directory.

pytest hands ``pytest_collection_modifyitems`` every item of the session, and it
loads this conftest only when it collects ``tests/integration/cli``. A rule scoped
wider than the directory therefore puts a ``slow`` or ``mcp`` mark on a test in a
sibling directory in a run that happens to collect the CLI tests, and leaves it
alone in a run of the sibling on its own. Marker expressions (``-m``) and marker
reports then see the same test differently depending on which paths were on the
command line.

The mark does not change whether the test runs. ``tests/conftest.py`` applies its
``--run-slow`` skip in a hook that runs first, before this conftest's hook adds
``slow``, so the skip never sees the mark this hook adds.

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


@pytest.fixture
def marks_added(pytestconfig):
    """Call the CLI conftest's hook on one stand-in item and return the marks it added.

    The conftest registers its ``mcp`` marker in its own ``pytest_configure``, which
    pytest runs only in a session that collected ``tests/integration/cli``, and
    ``--strict-markers`` (pytest.ini) refuses ``pytest.mark.mcp`` until it is
    registered. Running that hook here, once per call, makes the result the same
    whether this file is run alone or with the rest of the suite; registering a
    marker line again is harmless.
    """
    spec = importlib.util.spec_from_file_location(
        "_cli_integration_conftest_under_test", CONFTEST
    )
    assert spec is not None and spec.loader is not None, CONFTEST
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.pytest_configure(pytestconfig)

    def marks(directory: str, name: str) -> list[str]:
        item = _Item(INTEGRATION / directory / "test_stand_in.py", name)
        module.pytest_collection_modifyitems(SimpleNamespace(), [item])
        return item.added

    return marks


def test_a_workflow_named_test_beside_the_cli_tests_is_marked_slow(marks_added):
    assert marks_added("cli", "test_scan_workflow_is_reported") == ["slow"]


def test_an_mcp_named_test_beside_the_cli_tests_is_marked_mcp(marks_added):
    assert marks_added("cli", "test_mcp_tools_are_listed") == ["mcp"]


@pytest.mark.parametrize("directory", ["scanners", "converters", "core", "docs"])
def test_a_workflow_named_test_in_a_sibling_directory_is_left_unmarked(
    marks_added, directory
):
    """The directory's own conftest does not load with the CLI tests' conftest, so
    the name rule must not decide whether this test runs."""
    assert marks_added(directory, "test_scan_workflow_is_reported") == []


def test_an_mcp_named_test_in_a_sibling_directory_is_left_unmarked(marks_added):
    assert marks_added("scanners", "test_mcp_tools_are_listed") == []
