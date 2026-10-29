# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A CI e2e leg has the tools its tests drive, and says so by name when it does not.

The e2e tests run the product the way an operator does: the ``ash`` CLI as a child
process, the MCP server as a child process, a docs page's commands in a shell. A
runner that lacks one of the programs they start does not fail those tests; most of
them skip, and a leg that skips everything exits 0 and reads green. This module is the
leg-level assertion for the tools a leg is provisioned with today, so the loss of one
fails the leg by name instead of thinning it out.

What an e2e leg is provisioned with, from .github/workflows/ash-unified-ci.yml
(``e2e-test-linux``, ``-macos``, ``-windows``) and the ``setup-ash`` and
``run-unit-tests`` actions: uv and a Python from ``setup-ash`` with ``install-ash`` off,
then ``uv sync --extra cdk --extra symbols``, the action's "Install the scanners the e2e
tier runs for real" step (``ash dependencies install`` for eight scanners, two on
Windows), and ``uv run pytest -m e2e``. The sync puts three console scripts in the
environment's own scripts directory: ``ash``, ``cfn-lint`` and ``detect-secrets``. The
runner image supplies ``git``, ``bash`` and ``node``, and ``setup-ash`` supplies ``uv``.

The console scripts are looked up in the running interpreter's scripts directory and
not on PATH, so the check does not depend on how the leg's PATH was built. The system
tools are looked up on PATH. The test runs from an empty directory, and a console
script counts only if it was found in the scripts directory itself, because on Windows
``shutil.which`` also reads the current directory, where the checkout's own ``ash`` file
would answer for a missing ``ash.exe``.

The installed scanners are looked up where ``ash dependencies install`` puts them, in
ASH's bin directory (pinned binaries) and uv's tool bin directory (uv tools), as
``ash_tool_dirs`` in tests/integration/docs/docs_runner.py resolves them for the user
who ran the install: the test session has moved HOME, so the product's own constants
would name an empty directory here. The lists below are the action's, and the two are
kept in step by hand.

Not asserted here: the scanner binaries the step does not install (grype, trivy, syft,
opengrep, ferret-scan and the rest) and the container runtimes. The e2e tests that need
one skip when it is absent (``_why_it_cannot_run`` in
tests/integration/scanners/test_links_leaving_the_tree_reach_no_output.py is the
nearest thing to a shared skip; there is no fixture shared by all e2e modules). The
executed-test floor in tests/utils/sharding.py
(``fail_a_tier_run_that_executed_no_test``) is what catches an e2e leg that ran
nothing. The run-unit-tests action sets it to ``warn`` on the e2e legs for now, so such
a leg is reported with a warning line and not failed, until a hosted run shows every e2e
leg executing a real test; this test still fails a leg that lacks a tool. This test
carries the ``leg_assertion`` marker for that reason: it passes on every leg that has
its tools, so counted as an executed test it would keep the floor from ever firing on an
e2e leg whose real tests all skipped.

The check applies to a CI tier run only, as ``sharding.is_ci_tier_run`` in
tests/utils/sharding.py defines it, the same test the executed-test floor uses. On a
developer's machine it skips and names the tools.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import sysconfig
from pathlib import Path
from typing import Optional, Sequence

import pytest

from tests.utils import sharding

#: A leg assertion: marked with the tier of the leg it asserts, not by what it does (it
#: starts nothing), and left out of the executed-test count, so that passing it does
#: not hide an e2e leg whose product tests all skipped. See tests/NAMING_CONVENTIONS.md.
pytestmark = [pytest.mark.e2e, pytest.mark.leg_assertion]

#: Console scripts of this checkout's environment, found beside the interpreter.
ENVIRONMENT_SCRIPTS = ("ash", "cfn-lint", "detect-secrets")
#: Programs the runner image or ``setup-ash`` puts on PATH.
SYSTEM_TOOLS = ("git", "bash", "node", "uv")
#: The scanners the run-unit-tests action's "Install the scanners the e2e tier runs for
#: real" step installs, by executable name. Keep this and ``INSTALLED_SCANNERS_WINDOWS``
#: equal to that step's two ``--tool`` lists.
INSTALLED_SCANNERS = (
    "bandit",
    "actionlint",
    "cfn-lint",
    "cfn-guard",
    "gitleaks",
    "checkov",
    "semgrep",
    "zizmor",
)
#: What the same step installs on Windows: semgrep publishes no Windows build.
INSTALLED_SCANNERS_WINDOWS = ("bandit", "checkov")

#: The docs runner, which resolves the directories ``ash dependencies install`` writes to
#: for the user who ran it. It is loaded by path, as test_docs_examples.py does, because
#: tests/integration/docs is not a package.
_DOCS_RUNNER = Path(__file__).resolve().parent / "docs" / "docs_runner.py"


def _install_directories() -> list[str]:
    """Where ``ash dependencies install`` put the scanners: ASH's bin directory and uv's
    tool bin directory, for the invoking user. Only those that exist."""
    name = "_ash_docs_runner"
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, _DOCS_RUNNER)
        assert spec and spec.loader, f"cannot load {_DOCS_RUNNER}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return [str(directory) for directory in module.ash_tool_dirs()]


def _not_installed(names: Sequence[str], directories: Sequence[str]) -> list[str]:
    """The names found in none of ``directories`` (each by ``_not_in_directory``)."""
    absent = list(names)
    for directory in directories:
        absent = _not_in_directory(absent, directory)
    return absent


def _missing(names: Sequence[str], search_path: Optional[str]) -> list[str]:
    """The names ``shutil.which`` does not find; ``search_path=None`` means PATH."""
    return [name for name in names if shutil.which(name, path=search_path) is None]


def _not_in_directory(names: Sequence[str], directory: str) -> list[str]:
    """The names not found in ``directory`` itself.

    On Windows with Python 3.12, ``shutil.which`` looks in the current directory before an
    explicit ``path`` and takes names with no extension, and the repository root holds a
    file named ``ash``, so ``ash.exe`` could be missing from the scripts directory while
    the lookup still found ``.\\ash``. The test changes into an empty directory first, and
    this also requires that what was found sits in ``directory``.
    """
    wanted = os.path.normcase(os.path.abspath(directory))
    absent = []
    for name in names:
        found = shutil.which(name, path=directory)
        if found is None:
            absent.append(name)
            continue
        found_in = os.path.normcase(os.path.dirname(os.path.abspath(found)))
        if found_in != wanted:
            absent.append(name)
    return absent


def test_the_e2e_runner_has_the_tools_its_tests_drive(request, monkeypatch, tmp_path):
    # Nothing in the current directory may answer a lookup, whatever the platform's rule.
    monkeypatch.chdir(tmp_path)
    # The control comes first and runs everywhere: the lookup must be able to find a
    # program that is there and to miss one that is not, or the assertion below proves
    # nothing in either direction.
    interpreter = Path(sys.executable)
    assert _not_in_directory([interpreter.name], str(interpreter.parent)) == []
    assert _not_in_directory(["no-such-tool-7c41e2"], str(interpreter.parent)) == [
        "no-such-tool-7c41e2"
    ]
    assert _missing(["no-such-tool-7c41e2"], None) == ["no-such-tool-7c41e2"]
    # The same two controls for the install-directory lookup, which is a different
    # function over a list of directories.
    assert _not_installed([interpreter.name], [str(interpreter.parent)]) == []
    assert _not_installed(["no-such-tool-7c41e2"], [str(interpreter.parent)]) == [
        "no-such-tool-7c41e2"
    ]
    assert _not_installed([interpreter.name], []) == [interpreter.name]

    scanners = (
        INSTALLED_SCANNERS_WINDOWS if sys.platform == "win32" else INSTALLED_SCANNERS
    )
    wanted = ", ".join((*ENVIRONMENT_SCRIPTS, *SYSTEM_TOOLS, *scanners))
    if not sharding.is_ci_tier_run(request.config):
        pytest.skip(
            "not a CI tier run (sharding.is_ci_tier_run is false); "
            f"on a CI e2e leg this asserts that {wanted} are found"
        )

    scripts_directory = sysconfig.get_path("scripts")
    install_directories = _install_directories()
    missing_scripts = _not_in_directory(ENVIRONMENT_SCRIPTS, scripts_directory)
    missing_system = _missing(SYSTEM_TOOLS, None)
    missing_scanners = _not_installed(scanners, install_directories)
    assert not (missing_scripts or missing_system or missing_scanners), (
        "this e2e leg lacks tools its tests drive. "
        f"Missing from the environment's scripts directory ({scripts_directory}): "
        f"{', '.join(missing_scripts) or 'none'}. "
        f"Missing from PATH: {', '.join(missing_system) or 'none'}. "
        "Missing from the directories `ash dependencies install` writes to "
        f"({', '.join(install_directories) or 'none exist'}): "
        f"{', '.join(missing_scanners) or 'none'}. "
        f"All required: {wanted}"
    )
