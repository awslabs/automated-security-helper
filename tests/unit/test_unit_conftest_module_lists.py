# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module allowlists of tests/unit/conftest.py name files that exist, on purpose.

``REAL_TOOL_MODULES``, ``REAL_HOME_MODULES`` and ``PROBE_SUBJECT_MODULES`` are hand-kept
lists of paths under tests/unit. A renamed or deleted module would leave its entry
behind with nothing to say so, and the guard would then silently cover a test the
list meant to exempt (or exempt none). These tests read the lists from the loaded
conftest plugin, so a stale entry fails here instead of going unnoticed.

Three modules sit in both tool lists. That is not duplication: ``REAL_TOOL_MODULES``
only permits the ``runs_real_tools`` marker, and the tests of such a module that do
not carry it are guarded and keep their real probes through ``PROBE_SUBJECT_MODULES``
alone. The last test pins that each of them marks some tests and not the whole module,
which is what makes the second entry load-bearing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

UNIT_TESTS = Path(__file__).resolve().parent
UNIT_CONFTEST = UNIT_TESTS / "conftest.py"

LISTS = ("REAL_TOOL_MODULES", "REAL_HOME_MODULES", "PROBE_SUBJECT_MODULES")


def _unit_conftest(pytestconfig):
    """The tests/unit/conftest.py plugin as pytest loaded it, not a second import."""
    found = [
        plugin
        for plugin in pytestconfig.pluginmanager.get_plugins()
        if getattr(plugin, "__file__", None)
        and Path(plugin.__file__).resolve() == UNIT_CONFTEST
    ]
    assert len(found) == 1, found
    return found[0]


@pytest.mark.parametrize("name", LISTS)
def test_every_listed_module_exists(pytestconfig, name):
    listed = getattr(_unit_conftest(pytestconfig), name)
    assert listed, name
    missing = sorted(path for path in listed if not (UNIT_TESTS / path).is_file())
    assert missing == [], f"{name} names modules that are not there: {missing}"


@pytest.mark.parametrize("name", LISTS)
def test_every_listed_module_is_a_test_module_path(pytestconfig, name):
    """Paths are POSIX, relative to tests/unit, and name test modules or the one probe."""
    listed = getattr(_unit_conftest(pytestconfig), name)
    odd = sorted(
        path
        for path in listed
        if "\\" in path
        or path.startswith(("/", "tests/"))
        or not (
            Path(path).name.startswith("test_") or Path(path).name.endswith("_probe.py")
        )
    )
    assert odd == [], f"{name} holds paths outside the list's shape: {odd}"


def test_the_runner_memo_seam_modules_keep_their_probes(pytestconfig):
    """A module that sets the runner's availability memo itself
    (``runner._uv_available_cache = True``) and reads the uv command from it is a
    probe subject: under the guard, ``uv_availability`` is replaced class-wide and
    the memo seam answers nothing, so five tests of the python-request module read
    "no uv" and failed on main for that reason alone."""
    conftest = _unit_conftest(pytestconfig)
    assert "utils/test_uv_tool_python_request.py" in conftest.PROBE_SUBJECT_MODULES
    source = (UNIT_TESTS / "utils/test_uv_tool_python_request.py").read_text(
        encoding="utf-8"
    )
    assert "_uv_available_cache = True" in source, "the seam the entry exists for"


def test_a_module_in_both_tool_lists_marks_only_some_of_its_tests(pytestconfig):
    conftest = _unit_conftest(pytestconfig)
    both = sorted(conftest.REAL_TOOL_MODULES & conftest.PROBE_SUBJECT_MODULES)
    assert both, "no module is in both lists; drop this test with the dual listing"
    for module in both:
        source = (UNIT_TESTS / module).read_text(encoding="utf-8")
        # The marker is used, so the REAL_TOOL entry is live...
        assert "runs_real_tools" in source, module
        # ...and not on the whole module, so unmarked tests are guarded and need the
        # PROBE_SUBJECT entry to keep their real probes.
        assert "pytestmark = pytest.mark.runs_real_tools" not in source, module
        assert "pytestmark = [pytest.mark.runs_real_tools" not in source, module
