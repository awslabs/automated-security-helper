# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under Landlock, a tool that is not installed is not found.

The Landlock wrapper starts its command with ``os.execve``, which does not search
PATH: a name with no leading slash is read against the working directory, and a
scanner's working directory is usually the tree it scans. The plan used to pass a name
on as it was when its own lookup found nothing, so a file of that name in the working
directory was what the wrapper started. An unsandboxed spawn, bwrap and firejail
search PATH for the name, and a tool that is not installed is not found in any of
them.

These tests plan a spawn and read the command the wrapper would be given. No process
is started, and the files they create are never run.
"""

import errno
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox import SandboxRequirements
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.backends import LandlockBackend
from automated_security_helper.utils.sandbox.policy import build_scanner_policy

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows"),
]

#: A name no real PATH holds, so only the files these tests create answer to it.
TOOL = "ash-landlock-sample-tool"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A scanned tree, an empty tool directory as the only PATH entry, a private temp."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", Path.home, raising=False)
    source = tmp_path / "src"
    (source / "bin").mkdir(parents=True)
    output = source / ".ash" / "ash_output"
    results = output / "scanners" / "grype"
    results.mkdir(parents=True)
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.setenv("PATH", str(tools))
    # The plan's private root is made with tempfile.mkdtemp. Pointing the temp
    # directory at an empty one shows what a plan leaves behind.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return SimpleNamespace(
        source=source, output=output, results=results, tools=tools, scratch=scratch
    )


def _make_tool(directory: Path) -> Path:
    """An executable file named TOOL. The tests look at where it is; it is never run."""
    program = directory / TOOL
    program.write_text("#!/bin/sh\nexit 0\n")
    program.chmod(0o755)
    return program


def _plan(layout, name):
    """``(plan, error)`` for a Landlock spawn of ``name`` from the scanned tree.

    Exactly one of the two is None. The caller runs a returned plan's cleanup.
    """
    policy = build_scanner_policy(
        "grype",
        SandboxRequirements(),
        argv0=name,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.results,
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )
    try:
        plan = LandlockBackend().plan(
            [name, "scan"], {"PATH": str(layout.tools)}, policy
        )
    except FileNotFoundError as error:
        return None, error
    return plan, None


def _wrapped_command(plan):
    """What the wrapper starts: the words after the ``--`` that ends its options."""
    return plan.argv[plan.argv.index("--") + 1 :]


@pytest.mark.parametrize("name", [TOOL, f"./{TOOL}", f"bin/{TOOL}"])
def test_a_tool_found_only_through_the_working_directory_is_not_found(layout, name):
    _make_tool(layout.source)
    _make_tool(layout.source / "bin")

    plan, error = _plan(layout, name)
    try:
        assert error is not None, f"the wrapper would start {_wrapped_command(plan)}"
    finally:
        if plan is not None:
            plan.run_cleanup()

    assert error.errno == errno.ENOENT
    assert error.filename == name
    assert name in str(error)


def test_a_refused_spawn_leaves_nothing_in_the_temp_directory(layout):
    _make_tool(layout.source)

    plan, error = _plan(layout, TOOL)
    try:
        assert error is not None, f"the wrapper would start {_wrapped_command(plan)}"
        assert list(layout.scratch.iterdir()) == []
    finally:
        if plan is not None:
            plan.run_cleanup()


def test_a_tool_on_path_is_started_by_its_path_not_by_its_name(layout):
    """The control: a copy in the working directory does not take its place."""
    _make_tool(layout.source)
    installed = _make_tool(layout.tools)

    plan, error = _plan(layout, TOOL)
    assert error is None, error
    try:
        assert _wrapped_command(plan) == [str(installed), "scan"]
    finally:
        plan.run_cleanup()


def test_an_absolute_path_is_started_as_it_is(layout):
    _make_tool(layout.source)
    installed = _make_tool(layout.tools)

    plan, error = _plan(layout, str(installed))
    assert error is None, error
    try:
        assert _wrapped_command(plan) == [str(installed), "scan"]
    finally:
        plan.run_cleanup()
