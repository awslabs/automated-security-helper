# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A conftest hook must not mark tests outside its own tree.

The failure this prevents
-------------------------
``pytest_collection_modifyitems`` receives *every* item in the session, not only
the ones beneath the conftest that defines the hook.
``tests/integration/cli/conftest.py`` used that hook to add ``pytest.mark.slow``
to any test whose name contained "workflow", "lifecycle" or "end_to_end" -- with
no path scoping. ``tests/conftest.py`` then skips slow tests unless ``--run-slow``
is passed.

The result was six unit tests that silently did not run in a full-suite run,
including two CI gates whose entire job is to fail when a GitHub workflow drifts
from its documented timeout budget. All six passed when executed, so nothing was
hiding a real failure -- they were simply providing no coverage while appearing to.

It is worth guarding rather than just fixing, because the failure is invisible
from both ends. A test file gives no hint that a conftest three directories away
will skip it, and the author of that conftest had no reason to think about tests
they did not write. The only signal was a skip count in a summary line, against a
suite that stays green either way.

Asserted against the hook rather than against a real collection
--------------------------------------------------------------
The hook is called directly with stand-in items. Driving a real nested pytest
session would be slower, would need the marker state inspected across process
boundaries, and would test pytest's collection machinery rather than the one
decision this file cares about: does the rule look at the path.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Names that trigger the heuristic in ``tests/integration/cli/conftest.py``.
#: Taken from that file; if it grows a keyword and this list does not, the
#: parametrised cases below simply cover less rather than failing wrongly.
TRIGGERING_NAMES = (
    "test_complete_scan_workflow",
    "test_server_lifecycle",
    "test_report_end_to_end",
)


class _FakeItem:
    """The minimum surface ``pytest_collection_modifyitems`` touches."""

    def __init__(self, path: Path, name: str) -> None:
        self.fspath = path
        self.name = name
        self.applied: list[str] = []

    def add_marker(self, marker) -> None:
        self.applied.append(getattr(marker, "name", str(marker)))


@pytest.fixture
def modify_items():
    """The hook under test, imported from the integration conftest by path."""
    import importlib.util

    conftest = REPO_ROOT / "tests" / "integration" / "cli" / "conftest.py"
    spec = importlib.util.spec_from_file_location(
        "_integration_cli_conftest_under_test", conftest
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pytest_collection_modifyitems


@pytest.fixture
def config():
    class _Config:
        rootpath = REPO_ROOT

        def addinivalue_line(self, *args, **kwargs):  # pragma: no cover
            pass

    return _Config()


@pytest.mark.parametrize("name", TRIGGERING_NAMES)
def test_a_unit_test_is_never_marked_slow_by_the_integration_conftest(
    modify_items, config, name
):
    item = _FakeItem(REPO_ROOT / "tests" / "unit" / "workspace" / "test_x.py", name)
    modify_items(config, [item])
    assert "slow" not in item.applied
    assert "mcp" not in item.applied
    assert "integration" not in item.applied


@pytest.mark.parametrize("name", TRIGGERING_NAMES)
def test_an_integration_test_is_still_marked_slow(modify_items, config, name):
    """The companion assertion, and the reason the fix is a scope and not a delete.

    Without this, removing the heuristic entirely would satisfy the test above --
    and the integration suite would lose the ``--run-slow`` gate that keeps a
    default run fast.
    """
    item = _FakeItem(REPO_ROOT / "tests" / "integration" / "cli" / "test_x.py", name)
    modify_items(config, [item])
    assert "slow" in item.applied
    assert "integration" in item.applied


def test_a_unit_test_named_after_mcp_is_not_marked_mcp(modify_items, config):
    item = _FakeItem(
        REPO_ROOT / "tests" / "unit" / "cli" / "test_x.py", "test_mcp_something"
    )
    modify_items(config, [item])
    assert "mcp" not in item.applied
