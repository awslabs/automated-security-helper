# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run by tests/unit/test_unit_tool_guard.py in a pytest of its own; never collected.

Each test does one thing the unit tests' tool guard and HOME check
(tests/unit/conftest.py) has to let pass or fail, as its name says. The file
PROBE_OUTSIDE_UV_FILE names holds the path of a program called uv outside this
run's own directories, standing for the host's; it does nothing. The path is read
from a file, not the environment, since the root conftest redacts each
environment value from a report and the check's message names this path.

What is under test can be broken, so no test here starts anything until
``_guarded_and_at_home`` has seen the guard in and the home this run's own: a test
without them errors at setup. test_unit_tool_guard.py also starts this run with a
refusing stand-in for each tool first on PATH and nothing but scratch for a home.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

#: What the tool guard points into each test's home.
_HOME_LOCATIONS = (
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "UV_TOOL_DIR",
    "UV_CACHE_DIR",
)


@pytest.fixture(autouse=True)
def _guarded_and_at_home(tmp_path_factory):
    """Each test runs under the tool guard, in a home under this run's base directory.

    Set up after the conftests' autouse fixtures (pytest orders those from the
    outermost directory in), so it sees what they did. Not requested by name from
    them: that would put the guard in for a probe whose conftest no longer does.
    It stands only between a test's setup and its body: this module's top level and
    the conftests' own fixtures run before it, and none of them starts anything.
    """
    from tests.utils import tool_guard

    guard = tool_guard._ACTIVE
    assert guard is not None, "no tool guard is in, so nothing here may run"
    for name in tool_guard.GUARDED_TOOLS:
        found = shutil.which(name)
        assert found is not None and Path(found).parent == guard.directory, (
            f"{name} resolves to {found}, not to the guard's stand-in"
        )
    home = Path.home()
    assert home.is_relative_to(tmp_path_factory.getbasetemp()), home
    outside = {
        name: os.environ.get(name)
        for name in _HOME_LOCATIONS
        if not Path(os.environ.get(name) or "/").is_relative_to(home)
    }
    assert outside == {}, (home, outside)


def _outside_uv() -> str:
    return Path(os.environ["PROBE_OUTSIDE_UV_FILE"]).read_text(encoding="utf-8")


def test_passes_running_git_a_shell_and_its_own_fake(tmp_path):
    subprocess.run(["git", "--version"], check=True, capture_output=True)
    subprocess.run(["sh", "-c", "true"], check=True)
    fake = tmp_path / "uv"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    subprocess.run([str(fake), "tool", "list"], check=True)


def test_passes_a_version_probe_the_stand_in_answers():
    semgrep = shutil.which("semgrep")
    assert semgrep is not None
    answer = subprocess.run(
        [semgrep, "--version"], capture_output=True, text=True, check=True
    )
    assert answer.stdout.startswith("semgrep "), answer.stdout


def test_passes_leaving_only_ashs_own_state():
    receipts = Path.home() / ".ash" / "install-receipts"
    receipts.mkdir(parents=True)
    (receipts / "tool.json").write_text("{}", encoding="utf-8")
    session = Path.home() / ".cache" / "ash-mcp" / "session" / "config"
    session.mkdir(parents=True)
    (session / "ash.yaml").write_text("", encoding="utf-8")


def test_fails_asking_a_stand_in_to_run():
    subprocess.run(["semgrep", "scan"], capture_output=True)


def test_fails_starting_a_tool_by_its_path():
    subprocess.run([_outside_uv(), "tool", "list"], check=True)


def test_fails_starting_a_tool_found_past_the_stand_ins():
    env = {**os.environ, "PATH": os.path.dirname(_outside_uv())}
    subprocess.run(["uv", "tool", "list"], env=env, check=True)


def test_fails_running_a_tools_module():
    # No such module, so nothing runs; the start is what counts.
    subprocess.run(
        [sys.executable, "-I", "-m", "uv.no_such_module"], capture_output=True
    )


def test_fails_leaving_a_tools_file_in_home():
    settings = Path.home() / ".semgrep" / "settings.yml"
    settings.parent.mkdir()
    settings.write_text("has_shown_metrics_notification: true\n", encoding="utf-8")


def test_fails_leaving_a_uv_cache_in_home():
    # Where the guard points UV_CACHE_DIR, taken from the home the fixture checked
    # rather than from the variable: read from there, a broken redirect aimed this
    # at the developer's cache.
    cache = Path.home() / ".cache" / "uv"
    cache.mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text("Signature: 0\n", encoding="utf-8")


def test_fails_leaving_a_file_in_ashs_bin_directory():
    # Under the test's own directories, so a tool copied there ran as its own.
    copied = Path.home() / ".ash" / "bin" / "semgrep"
    copied.parent.mkdir(parents=True)
    copied.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")


@pytest.mark.runs_real_tools(reason="not a module the list names")
def test_fails_opting_out_unlisted():
    pass


@pytest.mark.real_home
def test_fails_marked_real_home_unlisted():
    pass


def test_fails_swallowing_a_home_rule_refusal(developer_home):
    # A start that skips Popen, given the developer's HOME, is refused, and code
    # that swallows the refusal does not hide it from the check. No child starts:
    # only the audit event is raised.
    home = str(developer_home)
    env = {**os.environ, "HOME": home, "USERPROFILE": home}
    try:
        sys.audit("os.posix_spawn", sys.executable, [sys.executable, "-c", "pass"], env)
    except BaseException:
        pass


def test_fails_leaving_a_pid_in_the_die_now_mirror():
    # A plain-pid mirror entry with no registered child behind it: the hazard the
    # check's pid half exists for. Above the kernel's pid space (pid_max is at
    # most 2**22), so even a broken check aims any kill at no process.
    from automated_security_helper.core.cancellation import record_tool_pid

    record_tool_pid(2**30 + 11)


def test_passes_with_the_die_now_mirrors_empty_after_the_leak_was_cleared():
    # Runs after the planted leak above (this file runs in order, on one worker):
    # the check failed that test AND cleared both mirrors, so one leak does not
    # error every later test in the worker.
    from automated_security_helper.core import cancellation

    assert cancellation._TOOL_GROUPS == ()
    assert cancellation._TOOL_PIDS == ()
