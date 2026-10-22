# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Runs the list-scanners import-order probe in a pytest process of its own.

The probe's cells (list_scanners_import_order_probe.py) each load plugin
packages, and a load registers classes in the process-global plugin registry
for the rest of the worker: nothing a test may touch takes a registration
back (the project-isolation sweep forbids registry surgery, sys.modules
restore does not unregister, and a re-import mints second-generation
classes). Run in the main process, the cells left the vendored scanner
classes resolved for every later test on their xdist worker. So the probe
runs in its own interpreter, through the real conftests, and this file
asserts its outcomes; the registrations die with the child.
"""

from __future__ import annotations

import configparser
import fnmatch
import os
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pyproject.toml declares tomli for Python below 3.11
    import tomli as tomllib

pytest_plugins = ["pytester"]

REPO_ROOT = Path(__file__).resolve().parents[4]

#: pytest's own default for ``python_files``, used when nothing configures it.
_DEFAULT_PYTHON_FILES = ("test_*.py", "*_test.py")
PROBE = Path(__file__).resolve().parent / "list_scanners_import_order_probe.py"

#: The probe's cell count: a child that collected fewer ran a different file.
PROBE_CELLS = 10


def test_the_probe_passes_in_its_own_interpreter(pytester, monkeypatch):
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join(p for p in (str(REPO_ROOT), os.environ.get("PYTHONPATH")) if p),
    )
    # A child that inherited these would act as an xdist worker of this run.
    for name in [n for n in os.environ if n.startswith("PYTEST_XDIST_")]:
        monkeypatch.delenv(name)

    result = pytester.runpytest_subprocess(
        str(PROBE),
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:randomly",
        "-n",
        "0",
        "-rA",
    )

    outcomes = result.parseoutcomes()
    output = result.stdout.str()
    assert outcomes.get("failed", 0) == 0, output[-6000:]
    assert outcomes.get("errors", 0) == 0, output[-6000:]
    passed = outcomes.get("passed", 0)
    skipped = outcomes.get("skipped", 0)
    # The memo-shortness cell may skip when an earlier cell in the same child
    # already loaded the vendored packages; everything else must pass.
    assert passed + skipped == PROBE_CELLS, (passed, skipped, output[-6000:])
    assert passed >= PROBE_CELLS - 1, (passed, skipped, output[-6000:])

    # The child-process guard lists this launch on the reason that this test
    # puts the checkout first on the child's path. The child checks the
    # substance of that reason itself (captured output masks environment
    # values, the checkout path among them, so the path cannot be read back
    # here) and this run reads back its verdict line.
    marker = "probe-package-in-checkout="
    named = [line for line in output.splitlines() if marker in line]
    assert named, output[-6000:]
    assert named[-1].split(marker, 1)[1].strip() == "True", named[-1]


def _configured_python_files() -> list[str]:
    """The collection patterns the repository configures for pytest.

    pytest reads the first of pytest.ini, pyproject.toml's
    [tool.pytest.ini_options], tox.ini and setup.cfg that has a pytest
    section; the first two are read here. ``python_files`` is a
    whitespace-separated string in an ini file and a list or string in
    TOML. Pytest's own default applies when neither names it.
    """
    ini = REPO_ROOT / "pytest.ini"
    if ini.is_file():
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(ini, encoding="utf-8")
        if parser.has_section("pytest"):
            return parser.get("pytest", "python_files", fallback="").split() or list(
                _DEFAULT_PYTHON_FILES
            )
    pyproject = REPO_ROOT / "pyproject.toml"
    if pyproject.is_file():
        options = (
            tomllib.loads(pyproject.read_text(encoding="utf-8"))
            .get("tool", {})
            .get("pytest", {})
            .get("ini_options")
        )
        if options is not None:
            configured = options.get("python_files", list(_DEFAULT_PYTHON_FILES))
            return configured.split() if isinstance(configured, str) else configured
    return list(_DEFAULT_PYTHON_FILES)


def test_the_probe_is_not_collected_by_the_main_run():
    """The isolation holds only while the probe stays out of normal collection:
    a rename back to a test module's name would re-poison the worker, and so
    would a configured collection pattern (``*_probe.py``) that matches it."""
    assert PROBE.is_file()
    assert not PROBE.name.startswith("test_")
    assert not PROBE.name.endswith("_test.py")
    patterns = _configured_python_files()
    assert patterns, "no collection pattern read"
    matching = [p for p in patterns if fnmatch.fnmatch(PROBE.name, p)]
    assert not matching, (PROBE.name, matching, patterns)


def test_a_pattern_of_the_configured_shape_would_catch_the_probe():
    """The control: the matcher flags a pattern that does match the probe."""
    assert fnmatch.fnmatch(PROBE.name, "*_probe.py")
    assert fnmatch.fnmatch(PROBE.name, "list_scanners_*.py")


def test_the_vendored_list_is_every_in_tree_community_module():
    """A new community module that is not listed here is missing from list_scanners."""
    from automated_security_helper.cli.mcp_tools import (
        _VENDORED_SCANNER_PLUGIN_PACKAGES,
    )
    from automated_security_helper.core.community_scanners import (
        community_scanner_modules,
    )

    assert set(_VENDORED_SCANNER_PLUGIN_PACKAGES) == set(
        community_scanner_modules().values()
    )
