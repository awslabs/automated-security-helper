# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Describing the scanners installs nothing, and says which ones a scan would install.

Why this file exists
--------------------
list_scanners, check_installation and ``ash plugin list --show-versions`` all
describe the scanners through ``core.scanner_inventory.list_scanner_inventory``,
which runs each scanner's dependency check. For bandit, checkov and semgrep that
check installs the tool when it is missing: ``uv tool install``, with a
300-second timeout and retries. Its last fallback, and the version probe, run
``uv tool run <tool> --version``, which downloads the tool into uv's cache when
it is not there. Run that way, asking which scanners are available could start
minutes of package downloads, for list_scanners as much as for
check_installation.

The inventory always describes in check-only mode: the install step is
skipped and every ``uv tool run`` probe runs ``--offline``, so a tool that is not
already present is reported as such. A probe result reached in check-only mode is
not cached, so a later scan probes online. A scan installs as a scan always does.

A scanner whose tool a scan would install on first use (uv is present, the scan
is not offline, the tool is not installed) is reported with
``installs_on_first_scan``: check_installation lists it apart from the missing
dependencies, so on a fresh install it does not report bandit, checkov and
semgrep as missing when the first scan installs them.

Containment
-----------
Every test here runs the real dependency checks, whose install paths a
regression would reach, so nothing real can be reached. The containment is
``tests.utils.install_containment`` (its docstring lists every path it
closes); the ``sandbox`` fixture here wraps it.
"""

from __future__ import annotations

import sys
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from tests.utils.env_assertions import environ_names
from tests.utils.install_containment import (
    GUARDED,
    InstallSandbox,
    reset_tool_caches as _reset_tool_caches,
    sandbox_env,
    write_executable as _write_executable,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX stand-ins")

UV_TOOLS = [BanditScanner, CheckovScanner, SemgrepScanner]
UV_TOOL_NAMES = ["bandit", "checkov", "semgrep"]


@pytest.fixture
def sandbox(tmp_path) -> InstallSandbox:
    """The containment, with its own MonkeyPatch rather than the shared fixture.

    The shared ``monkeypatch`` is already live before this fixture runs: the unit
    conftest's autouse tool guard requests it, so its undo is the last teardown
    of every test here, after ``_the_sandbox_reaches_nothing_real`` has read the
    environment. A context of this fixture's own is undone when this fixture is,
    which is before that check, so the check reads the environment the test
    leaves behind.
    """
    with pytest.MonkeyPatch.context() as sandbox_patch:
        yield from sandbox_env(tmp_path, sandbox_patch)


@pytest.fixture(autouse=True)
def _the_sandbox_reaches_nothing_real():
    """The stand-ins' environment never leaked out of the test that just ran.

    Function-scoped and autouse, so it is set up before ``sandbox`` and torn
    down after it: ``sandbox`` has undone its own MonkeyPatch by then, and a
    variable still present was set past the sandbox, by the test itself. The
    leak is reported against the test that caused it, with every test of the
    module on whatever worker or shard collected it and in whatever order the
    tests ran; a module-scoped teardown would name only whichever test happened
    to run last.
    """
    yield
    assert "ASH_TEST_STAND_IN_LOG" not in environ_names(), (
        "a sandbox user left ASH_TEST_STAND_IN_LOG in the environment"
    )


def _by_name(entries: List[Dict]) -> Dict[str, Dict]:
    return {entry["name"]: entry for entry in entries}


# ---------------------------------------------------------------------------
# The control: the scan's own dependency check does reach the install paths
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_scans_dependency_check_reaches_the_installer(sandbox, tmp_path):
    """Without this, the tests below could pass by never reaching an install path."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    (tmp_path / "src").mkdir()
    (tmp_path / "out").mkdir()
    context = PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=AshConfig()
    )

    satisfied = BanditScanner(context=context).validate_plugin_dependencies()

    assert satisfied is False
    assert sandbox.installs(), sandbox.calls()


@pytest.mark.parametrize("name", GUARDED)
@pytest.mark.integration
def test_a_refusing_stand_in_is_seen_when_started(sandbox, name):
    """The planted positive for the refusing stand-ins (pip, docker, npm and the
    rest): each one, started inside the sandbox the way an install would start
    it, refuses, leaves its line in the log, and ``installs()`` counts that
    line. The control above reaches the installer recorder, not these, so
    without this a stand-in whose log line broke would let every "installs
    nothing" below pass by seeing nothing."""
    import subprocess

    completed = subprocess.run(
        [str(sandbox.guards / name), "install", "planted-package"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 99, completed
    assert f"stand-in {name} refuses: install planted-package" in completed.stderr, (
        completed
    )
    assert sandbox.calls() == [f"{name} install planted-package"], sandbox.calls()
    assert sandbox.installs() == [f"{name} install planted-package"], sandbox.calls()


# ---------------------------------------------------------------------------
# #8: describing the scanners installs nothing
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_scanners_installs_nothing(sandbox, monkeypatch):
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(UV_TOOLS))

    entries = mcp_tools.mcp_list_scanners()

    assert sandbox.installs() == [], sandbox.calls()
    assert sorted(_by_name(entries)) == UV_TOOL_NAMES


@pytest.mark.asyncio
@pytest.mark.integration
async def test_the_list_scanners_tool_installs_nothing(sandbox, monkeypatch):
    """The server's tool runs the same inventory off the event loop, so the
    call is awaited: a coroutine left unawaited would read as entries that
    could not be iterated, never as the sandbox's record."""
    from automated_security_helper.cli import mcp_server, mcp_tools

    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(UV_TOOLS))

    entries = await mcp_server.list_scanners()

    assert sandbox.installs() == [], sandbox.calls()
    assert sorted(e["name"] for e in entries) == UV_TOOL_NAMES


@pytest.mark.asyncio
@pytest.mark.integration
async def test_check_installation_installs_nothing(sandbox, monkeypatch):
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setattr(mcp_tools, "_builtin_scanner_classes", lambda: list(UV_TOOLS))

    report = await mcp_tools.mcp_check_installation()

    assert report["success"] is True, report
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.integration
def test_a_check_only_probe_is_not_remembered_for_the_scan(sandbox, monkeypatch):
    """The offline probe's miss must not stand in for the scan's online probe."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: [BanditScanner])
    mcp_tools.mcp_list_scanners()
    before = len(sandbox.calls())

    get_uv_tool_command("bandit")

    probes = [
        line
        for line in sandbox.calls()[before:]
        if line.startswith("uv tool run") and "--offline" not in line.split()
    ]
    assert probes, (
        "the scan's lookup reused the check-only probe's answer instead of "
        f"probing: {sandbox.calls()[before:]}"
    )


@pytest.mark.integration
def test_a_check_only_version_probe_is_not_remembered_either(sandbox, monkeypatch):
    """The other half of the test above: the version cache, not the command cache.

    A check-only version probe runs offline, a scan's does not, so its answer,
    a version or the None of a tool not installed yet, must not be the one the
    scan reads back (uv_tool_runner.get_uv_tool_version). The test above only
    reaches the command lookup.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.utils import uv_tool_runner

    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(UV_TOOLS))

    mcp_tools.mcp_list_scanners()

    version_probes = [
        line
        for line in sandbox.calls()
        if line.startswith("uv tool run") and line.split()[-1] == "--version"
    ]
    assert version_probes, f"no version was probed: {sandbox.calls()}"
    assert uv_tool_runner._uv_tool_version_cache == {}, (
        uv_tool_runner._uv_tool_version_cache
    )


# ---------------------------------------------------------------------------
# #4: a scanner the first scan installs is reported as such
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_a_fresh_install_reports_what_the_first_scan_installs(
    sandbox, monkeypatch
):
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setattr(mcp_tools, "_builtin_scanner_classes", lambda: list(UV_TOOLS))

    report = await mcp_tools.mcp_check_installation()

    assert report["installs_on_first_scan"] == UV_TOOL_NAMES, report
    assert report["missing_dependencies"] == [], report
    assert report["installed"] is True, report
    assert report["ready"] is True, report
    for entry in report["scanners"]:
        assert entry["dependencies_satisfied"] is False, entry
        assert entry["installs_on_first_scan"] is True, entry
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.integration
def test_list_scanners_says_which_tools_the_first_scan_installs(sandbox, monkeypatch):
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(UV_TOOLS))

    entries = _by_name(mcp_tools.mcp_list_scanners())

    assert {
        n: e["installs_on_first_scan"] for n, e in entries.items()
    } == dict.fromkeys(UV_TOOL_NAMES, True)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_offline_the_first_scan_installs_nothing_so_they_are_missing(
    sandbox, monkeypatch
):
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setenv("ASH_OFFLINE", "YES")
    monkeypatch.setattr(mcp_tools, "_builtin_scanner_classes", lambda: list(UV_TOOLS))

    report = await mcp_tools.mcp_check_installation()

    assert report["installs_on_first_scan"] == [], report
    assert report["missing_dependencies"] == UV_TOOL_NAMES, report
    assert report["ready"] is False, report
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_without_uv_the_first_scan_installs_nothing_so_they_are_missing(
    sandbox, monkeypatch
):
    from automated_security_helper.cli import mcp_tools

    sandbox.remove_uv()
    monkeypatch.setattr(mcp_tools, "_builtin_scanner_classes", lambda: list(UV_TOOLS))

    report = await mcp_tools.mcp_check_installation()

    assert report["installs_on_first_scan"] == [], report
    assert report["missing_dependencies"] == UV_TOOL_NAMES, report
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_a_machines_fixed_dir_uv_does_not_defeat_without_uv(
    sandbox, monkeypatch, tmp_path_factory
):
    """A machine whose /usr/local/bin carries a real uv answers like one
    without. ``find_executable`` searches that directory whatever PATH says,
    so hiding PATH and the bundled uv alone left such a machine finding its
    real uv, every scanner reported as installing on first scan, and real
    probes running during the unit suite."""
    from automated_security_helper.cli import mcp_tools
    from tests.utils.install_containment import UV_STAND_IN

    machine_dir = tmp_path_factory.mktemp("machine-fixed-bin")
    _write_executable(machine_dir / "uv", UV_STAND_IN)
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", lambda: [machine_dir])
    sandbox.remove_uv()
    monkeypatch.setattr(mcp_tools, "_builtin_scanner_classes", lambda: list(UV_TOOLS))

    report = await mcp_tools.mcp_check_installation()

    assert report["installs_on_first_scan"] == [], report
    assert report["missing_dependencies"] == UV_TOOL_NAMES, report
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.unit
def test_a_planted_fixed_dir_uv_is_findable_and_then_hidden(
    sandbox, monkeypatch, tmp_path_factory
):
    """The planted positive for the fixed-dir hiding, in two halves.

    First, with the sandbox's search dropping bypassed, the planted uv is
    exactly what the fixed-dir search returns -- proving the plant is a
    findable executable and the search really consults those directories.
    Then, through the sandbox's search, the same machine state finds nothing.
    Without the first half, a plant that was never findable (wrong name, no
    execute bit, a search that never reaches fixed dirs) would make the
    second half pass while measuring nothing."""
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    machine_dir = tmp_path_factory.mktemp("machine-fixed-bin")
    _write_executable(
        machine_dir / "uv",
        '#!/bin/sh\necho "the planted uv must never run" >&2\nexit 97\n',
    )
    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", lambda: [machine_dir])
    sandbox.remove_uv()

    with monkeypatch.context() as bypass:
        bypass.setattr(
            subprocess_utils,
            "path_independent_dirs",
            sandbox.real_path_independent_dirs,
        )
        _reset_tool_caches()
        assert (
            subprocess_utils.find_executable("uv") == (machine_dir / "uv").as_posix()
        ), "the plant was not findable, so the hidden half below measures nothing"
    _reset_tool_caches()

    assert subprocess_utils.find_executable("uv") is None
    assert uv_tool_runner.find_uv_or_none() is None
    assert sandbox.installs() == [], sandbox.calls()


@pytest.mark.integration
def test_an_installed_tool_is_satisfied_and_installs_nothing(sandbox, monkeypatch):
    """A tool on PATH is reported as present, not as one the first scan installs."""
    from automated_security_helper.cli import mcp_tools

    _write_executable(
        sandbox.guards / "bandit",
        '#!/bin/sh\nprintf "%s\\n" "bandit $*" >> "$ASH_TEST_STAND_IN_LOG"\n'
        'echo "bandit 1.9.4"\nexit 0\n',
    )
    _reset_tool_caches()
    monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: [BanditScanner])

    (entry,) = mcp_tools.mcp_list_scanners()

    assert entry["dependencies_satisfied"] is True, (entry, sandbox.calls())
    assert entry["installs_on_first_scan"] is False, entry
    assert sandbox.installs() == [], sandbox.calls()
