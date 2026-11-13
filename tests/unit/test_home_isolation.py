# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No test writes into the home directory of whoever runs the suite.

ASH keeps per-user state under ``Path.home()``: install receipts in
``~/.ash/install-receipts``, the default bin directory ``~/.ash/bin``, the MCP
server's session configs in ``~/.cache/ash-mcp``, and the scanners it runs keep theirs
(semgrep's ``~/.semgrep``, checkov's ``~/.cache/checkov``, uv's tool directory). Tests
write none of that into the real home of whoever runs them, fixture installs in
``tests/unit/utils`` included.

``tests/conftest.py`` points HOME, USERPROFILE and the XDG base directories at a
temporary directory for the whole run, so state captured when a module is imported
lands there too, and at a fresh one for each test. ``@pytest.mark.real_home`` gives a
test the values the run started with.

The decisive check runs a test module in a child pytest whose HOME is a sentinel
directory, and asserts the sentinel is still empty afterwards. The child's writes go to
the sentinel, never to the real home, so the check is safe to run red.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

from tests.utils.env_assertions import environ_value
from tests.utils.helpers import checkout_env

REPO_ROOT = Path(__file__).resolve().parents[2]
HOME_VARIABLES = (
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
)
#: uv's own directory variables, and the XDG one it puts tool executables in. Each takes
#: precedence over the home, so a value from the developer's environment would point
#: past the test's.
UV_DIRECTORY_VARIABLES = (
    "UV_TOOL_DIR",
    "UV_TOOL_BIN_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "UV_PYTHON_BIN_DIR",
    "XDG_BIN_HOME",
)

PROBE = "tests/unit/home_isolation_probe.py"

#: The home as it was when pytest imported this module: after the run's own home was in
#: place, before any test's.
HOME_AT_IMPORT = os.environ.get("USERPROFILE" if os.name == "nt" else "HOME")
#: uv's cache as the run set it, read at the same time: each unit test has its own.
UV_CACHE_AT_IMPORT = os.environ.get("UV_CACHE_DIR")


def _inherited_environment() -> dict:
    """This environment, minus what ties a child pytest to this run.

    pytest-xdist, pytest-cov and pytest itself keep per-run state in PYTEST_*,
    COV_CORE_* and COVERAGE_* variables, and tests/conftest.py keeps its session
    directory and the developer's home in ASH_TEST_* ones. A child that inherited
    those would act as a part of this run rather than as a run of its own.
    ASH_BIN_PATH goes too: the children here measure where ASH's defaults put things,
    and it replaces the default bin directory.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTEST_", "COV_CORE_", "COVERAGE_", "ASH_TEST_"))
        and key != "ASH_BIN_PATH"
    }


def _run_with_sentinel_home(
    tmp_path: Path,
    *pytest_args: str,
    basetemp: Optional[Path] = None,
    inherited: bool = True,
    **extra_env: str,
):
    """Run pytest in a child whose home, and every XDG directory, is a fresh sentinel.

    ``basetemp`` replaces the child's default ``tmp_path / "basetemp"``. A test may make
    directories under the sentinel home before calling this, to put temp roots there.

    With ``inherited`` False the child starts from PATH alone (plus what Windows
    needs to start Python) instead of this run's environment. The report backstop
    (tests/utils/env_assertions.py) redacts every environment value from the
    child's failure reports, so a cell that asserts a report's exact words runs
    the child with no inherited value an ordinary word could be: on one host the
    value "user" turned the guard's "wrote under the real user's ~/.ash" into
    text the assertion missed. The values this function itself sets are paths of
    this run's own, which the asserted words never hold.
    """
    sentinel = tmp_path / "sentinel"
    home = sentinel / "home"
    home.mkdir(parents=True, exist_ok=True)
    if inherited:
        env = _inherited_environment()
    else:
        env = {
            name: os.environ[name]
            for name in ("PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT")
            if name in os.environ
        }
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(sentinel / "xdg-config"),
        XDG_DATA_HOME=str(sentinel / "xdg-data"),
        XDG_STATE_HOME=str(sentinel / "xdg-state"),
        XDG_CACHE_HOME=str(sentinel / "xdg-cache"),
        UV_OFFLINE="1",
        **extra_env,
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *pytest_args,
            # The repository's addopts run every CPU and write the JUnit report CI
            # publishes; neither belongs to a child run.
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-q",
            f"--basetemp={basetemp or tmp_path / 'basetemp'}",
        ],
        cwd=REPO_ROOT,
        env=checkout_env(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
    )
    # Every path but the empty home this function made: a directory created and left
    # empty is a write too.
    created = sorted(p.relative_to(sentinel).as_posix() for p in sentinel.rglob("*"))
    created.remove("home")
    return result, created


@pytest.mark.integration
def test_the_installer_tests_leave_the_developer_home_untouched(tmp_path):
    """test_pinned_tool_downloads.py wrote 9 install receipts into the home per run."""
    result, created = _run_with_sentinel_home(
        tmp_path, "tests/unit/utils/test_pinned_tool_downloads.py"
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert " passed" in output, output[-4000:]
    assert not created, (
        f"the run created {len(created)} paths under the home it started with: "
        f"{created[:10]}"
    )


@pytest.mark.integration
def test_a_write_to_the_starting_home_shows_in_the_sentinel(tmp_path):
    """Positive control for the check above, and the ``real_home`` contract.

    tests/unit/home_isolation_probe.py has two tests that write through Path.home(): one
    marked ``real_home``, whose write must land in the sentinel (the child's starting
    home), so the check above can fail; and one that is not, whose write must land in
    its own temporary home instead. The probe lives in the repository so that pytest
    loads tests/conftest.py for it, and ``--strict-markers`` fails the run if the
    conftest did not register the marker.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_a_real_home_test_writes_into_the_starting_home",
        f"{PROBE}::test_any_other_test_writes_into_its_own_home",
        "--strict-markers",
        ASH_HOME_ISOLATION_PROBE="1",
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "2 passed" in output, output[-4000:]
    assert "home/ash-home-isolation-probe/real-home" in created, created
    assert not [path for path in created if path.endswith("isolated")], created
    # And the isolated test left its own home empty, as the unit tests' tool guard
    # requires of every test.
    homes = tmp_path / "basetemp" / "homes"
    left = sorted(
        p.relative_to(homes).as_posix() for p in homes.rglob("*") if p.is_file()
    )
    assert left == [], left


@pytest.mark.integration
def test_a_test_that_writes_into_the_developers_ash_is_refused_and_fails(tmp_path):
    """A write the moved HOME cannot redirect is refused, and fails the test that made it.

    Code that finds the home without $HOME (the passwd database, a literal, a path
    computed before the run moved HOME) writes into the developer's ~/.ash itself.
    The probe writes there on purpose, through the developer_home fixture. The
    audit-hook guard in tests/utils/real_home_guard.py must refuse the write, so
    nothing lands (a fixture binary and receipt there are what a later real run would
    trust), and fail the test. In the child that home is the sentinel, so nothing
    real is touched. The child's environment is this cell's own, not this run's:
    the words asserted below come from a failure report the backstop redacts
    every environment value from, and an inherited host value can be any word
    (``inherited`` in _run_with_sentinel_home).
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_a_write_into_the_developers_ash_directory",
        inherited=False,
        ASH_HOME_ISOLATION_PROBE="1",
    )
    output = result.stdout + result.stderr
    assert not [path for path in created if path.startswith("home/.ash")], created
    assert result.returncode == 1, output[-4000:]
    assert "wrote under the real user's ~/.ash" in output, output[-4000:]
    assert "refused by the test guard" in output, output[-4000:]


@pytest.mark.integration
@pytest.mark.parametrize("workers", ["2", "0"], ids=["xdist worker", "one process"])
def test_a_write_after_the_last_teardown_fails_the_run(tmp_path, workers):
    """Nothing charges it to a test, so the session's end does, in a worker too.

    Under xdist the write is in a worker, whose own session end is not the run's: it
    sends what it drained to the controller, which reports it with its own. Without
    xdist the one process drains and reports it.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_a_write_after_the_last_teardown",
        "-n",
        workers,
        ASH_HOME_ISOLATION_PROBE="1",
    )
    output = result.stdout + result.stderr
    assert not [path for path in created if path.startswith("home/.ash")], created
    assert "1 passed" in output, output[-4000:]
    assert result.returncode == 1, output[-4000:]
    assert "outside any test" in output, output[-4000:]
    # The first write refused is the mkdir of the sentinel's ~/.ash itself.
    # The reporter redacts the paths it prints, and the sentinel home is an
    # environment-read value: the line names the write's .ash target through
    # the redaction marker while the raw sentinel path stays hidden, so this
    # pins the reporter's redaction from both directions.
    assert os.path.join("<value>", ".ash") in output, output[-4000:]
    assert os.path.join("sentinel", "home", ".ash") not in output, output[-4000:]
    if workers != "0":
        assert re.search(r"gw\d+: ", output), output[-4000:]


@pytest.mark.integration
def test_the_guard_lets_the_run_use_temp_dirs_inside_the_home(tmp_path):
    """On Windows %TEMP% is under %USERPROFILE%, so every tmp_path is in the home.

    The installer guard refused any destination under the developer's home, the run's
    own temp directories included, and failed the guard's tests on every Windows unit
    leg. Here the child's TMPDIR and --basetemp are inside its starting home, the
    sentinel, as they are on Windows or with TMPDIR under $HOME; the guard's tests and
    the receipt tests that assume a home outside the temp directory must still pass.
    """
    home = tmp_path / "sentinel" / "home"
    temp = home / "AppData" / "Local" / "Temp"
    temp.mkdir(parents=True)
    helpers = "tests/unit/test_conftest_helpers.py"
    result, _ = _run_with_sentinel_home(
        tmp_path,
        f"{helpers}::TestInstallersAreRefusedADestinationInTheDeveloperHome",
        f"{helpers}::TestToolInstallingChildrenGetTheirOwnHome",
        f"{helpers}::TestInstallReceiptsStayOutOfTheDeveloperHome",
        "tests/unit/test_home_isolation.py::TestEachTestHasItsOwnHome",
        basetemp=temp / "pytest-basetemp",
        TMPDIR=str(temp),
        TEMP=str(temp),
        TMP=str(temp),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert " passed" in output and "failed" not in output, output[-4000:]


@pytest.mark.integration
def test_a_temp_dir_that_holds_the_home_does_not_excuse_it(tmp_path):
    """HOME under the temp directory, as in CI images whose HOME is in /tmp.

    The guard lets installers use the run's temp directories, but one that holds the
    developer's home would let them into all of it, so it does not count. Here the
    child's TMPDIR is the directory its home is in; the guard's refusals must still
    hold.
    """
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    helpers = "tests/unit/test_conftest_helpers.py"
    result, _ = _run_with_sentinel_home(
        tmp_path,
        f"{helpers}::TestInstallersAreRefusedADestinationInTheDeveloperHome",
        f"{helpers}::TestToolInstallingChildrenGetTheirOwnHome",
        TMPDIR=str(sentinel),
        TEMP=str(sentinel),
        TMP=str(sentinel),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert " passed" in output and "failed" not in output, output[-4000:]


@pytest.mark.integration
def test_the_guards_tests_pass_with_ash_bin_path_exported_in_the_home(tmp_path):
    """Many developers export ASH_BIN_PATH=~/.ash/bin, and so did this branch's docs.

    The guard's tests must still pass in that environment: they test the guard, not the
    developer's shell. Their stand-in installer took its destination from the inherited
    ASH_BIN_PATH, and two of them failed there.
    """
    home = tmp_path / "sentinel" / "home"
    helpers = "tests/unit/test_conftest_helpers.py"
    result, _ = _run_with_sentinel_home(
        tmp_path,
        f"{helpers}::TestToolInstallingChildrenGetTheirOwnHome",
        f"{helpers}::TestInstallersAreRefusedADestinationInTheDeveloperHome",
        f"{helpers}::TestTheRunHeaderNamesToolsItWillNotUse",
        ASH_BIN_PATH=str(home / ".ash" / "bin"),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert " passed" in output and "failed" not in output, output[-4000:]


#: What a developer behind a package mirror exports, since the user-level uv.toml,
#: pip.conf and .npmrc in their real home are not read once each test has its own.
MIRROR_VARIABLES = (
    "UV_DEFAULT_INDEX",
    "UV_INDEX",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "npm_config_registry",
)


@pytest.mark.integration
def test_the_package_mirror_variables_reach_every_test(tmp_path):
    """The run's home and each test's leave the mirror variables as they were."""
    expected = {
        name: f"https://mirror.invalid/{name.lower()}" for name in MIRROR_VARIABLES
    }
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_the_mirror_variables_reach_the_test",
        ASH_HOME_ISOLATION_PROBE="1",
        ASH_HOME_ISOLATION_EXPECT=json.dumps(expected),
        **expected,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "1 passed" in output, output[-4000:]
    assert not created, created


@pytest.mark.integration
def test_a_refusal_the_test_swallows_still_fails_it(tmp_path):
    """The HOME guard fails a test at teardown even when the test ate the refusal.

    The guard's own tests clear its record before teardown, so they cannot see that
    step; this runs a probe test that swallows the refusal in a child pytest and reads
    the child's verdict.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_a_refusal_the_test_swallows",
        ASH_HOME_ISOLATION_PROBE="1",
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1, output[-4000:]
    assert (
        "this test started a tool-installing child aimed at the developer's home"
        in (output)
    ), output[-4000:]
    assert "1 passed, 1 error" in output, output[-4000:]
    assert not created, created


TRIVY_PROBE = "tests/unit/plugin_modules/ash_trivy_plugins/home_isolation_probe.py"


@pytest.mark.integration
@pytest.mark.parametrize(
    "inherited",
    [
        pytest.param({}, id="a-run-of-its-own"),
        # A pytest started by a test whose env was copied from os.environ inherits the
        # outer run's record. It is still a run of its own, not an xdist worker, and
        # needs a home of its own before its conftests import ASH.
        pytest.param(
            {"ASH_TEST_DEVELOPER_HOME": '{"env": {}, "home": "/nonexistent"}'},
            id="an-inherited-record",
        ),
        # Started from an xdist worker's test, it inherits the worker's
        # PYTEST_XDIST_WORKER, the pid of the process that owns the outer run's home,
        # and the worker's mark of itself, which names the worker's pid, not its own.
        pytest.param(
            {
                "PYTEST_XDIST_WORKER": "gw0",
                "ASH_TEST_HOME_OWNER_PID": "1",
                "ASH_TEST_XDIST_WORKER_PID": "1",
            },
            id="an-inherited-xdist-worker-name",
        ),
    ],
)
def test_ash_computes_its_import_time_paths_inside_the_runs_own_home(
    tmp_path, inherited
):
    """Without xdist, the run's home has to be in place before any conftest imports ASH.

    The probe's directory has a conftest that imports ASH at module level, which pytest
    loads before any hook of tests/conftest.py runs; ``-o addopts=`` in the child drops
    pytest.ini's ``-n auto``, so the run is a single process, as under ``-n 0``,
    ``-p no:xdist`` or ``--pdb``.
    """
    extra = {"ASH_HOME_ISOLATION_PROBE": "1"}
    extra["ASH_HOME_ISOLATION_SENTINEL"] = str(tmp_path / "sentinel")
    extra.update(inherited)
    result, created = _run_with_sentinel_home(tmp_path, TRIVY_PROBE, **extra)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "1 passed" in output, output[-4000:]
    assert not created, created


@pytest.mark.integration
def test_a_jsii_cache_named_from_the_home_is_the_developers(tmp_path):
    """``ASH_JSII_CACHE_DIR=~/...`` is configured when the run starts, after HOME moved.

    The child's live root must be under its starting home, the sentinel, not under the
    run's own home, which the run deletes at the end.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        "tests/unit/test_jsii_package_cache_location.py::"
        "test_live_cache_root_is_repo_local_and_not_in_a_temp_dir",
        ASH_JSII_CACHE_DIR="~/jsii-cache",
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "1 passed" in output, output[-4000:]
    assert not created, created


@pytest.mark.integration
def test_a_jsii_cache_inside_the_developers_ash_is_refused_at_the_start(tmp_path):
    """``ASH_JSII_CACHE_DIR=~/.ash/...`` would put the cache's lock where the guard refuses.

    Every test that boots a jsii kernel takes that lock, so each would fail at
    teardown. The run refuses the setting before any test, with what to change.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        "tests/unit/test_jsii_package_cache_location.py::"
        "test_live_cache_root_is_repo_local_and_not_in_a_temp_dir",
        ASH_JSII_CACHE_DIR="~/.ash/jsii",
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output[-4000:]
    assert "ASH_JSII_CACHE_DIR" in output and "~/.ash" in output, output[-4000:]
    assert not [path for path in created if path.startswith("home/.ash")], created


@pytest.mark.integration
def test_uvs_own_directory_variables_do_not_reach_past_the_tests_home(tmp_path):
    """With UV_TOOL_DIR set, two CLI test modules wrote uv's .gitignore and .lock into it."""
    sentinel = tmp_path / "sentinel"
    extra = {name: str(sentinel / name.lower()) for name in UV_DIRECTORY_VARIABLES}
    result, created = _run_with_sentinel_home(
        tmp_path,
        "tests/unit/cli/test_dependencies_verdict.py",
        "tests/unit/cli/test_dependencies_tool_aliases.py",
        **extra,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert " passed" in output, output[-4000:]
    assert not created, (
        f"the run created {len(created)} paths through uv's directory variables: "
        f"{created[:10]}"
    )


@pytest.mark.integration
def test_none_of_uvs_directory_variables_reaches_a_test(tmp_path):
    """All five are set in the child's env, and a probe test sees none of those values.

    A test may still have one of them with a value inside the run's own directories:
    the unit tests' tool guard points UV_TOOL_DIR into each test's home. The probe's
    control shows the check fails for the value the run started with.

    The in-process check, TestEachTestHasItsOwnHome::test_uvs_directory_variables_are_unset,
    can only fail for a variable the developer happens to set, and CI sets none.
    """
    sentinel = tmp_path / "sentinel"
    extra = {name: str(sentinel / name.lower()) for name in UV_DIRECTORY_VARIABLES}
    result, created = _run_with_sentinel_home(
        tmp_path,
        f"{PROBE}::test_no_variable_named_in_ash_home_isolation_unset_reaches_the_test",
        f"{PROBE}::test_a_uv_directory_in_the_tests_own_home_is_its_own",
        f"{PROBE}::test_the_value_the_run_started_with_is_counted",
        ASH_HOME_ISOLATION_PROBE="1",
        ASH_HOME_ISOLATION_UNSET=json.dumps(extra),
        **extra,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "3 passed" in output, output[-4000:]
    assert not created, created


@pytest.mark.unit
def test_a_module_imported_by_pytest_sees_the_runs_own_home(developer_home):
    """The run's own home, set before collection, is what import-time code reads.

    Each test's home replaces it while the test runs, so only something read at import
    shows whether it was there at all.
    """
    session_tmpdir = Path(os.environ["ASH_TEST_SESSION_TMPDIR"])
    assert HOME_AT_IMPORT, "HOME was unset when pytest imported this module"
    home = Path(HOME_AT_IMPORT)
    # Exactly the run's own: a run nested in another, which takes a home-* directory
    # beside its parent's, never runs this module, and neither does an xdist worker
    # mistaken for one.
    assert home == session_tmpdir / "home", (
        f"HOME at import was {home}, not the home of the session directory "
        f"{session_tmpdir}"
    )
    assert os.path.realpath(home) != os.path.realpath(developer_home)


def _launcher(directory: Path) -> str:
    """An interpreter that runs the real one as its child, as a Windows venv's does.

    In a Windows venv, ``python.exe`` is CPython's launcher, which starts the base
    interpreter as a child process, so sys.executable there is already one. Elsewhere a
    shell script that does not ``exec`` stands in for it.
    """
    if os.name == "nt":
        return sys.executable
    launcher = directory / "python-launcher"
    launcher.write_text(
        f'#!/bin/sh\n{shlex.quote(sys.executable)} "$@"\n', encoding="utf-8"
    )
    launcher.chmod(0o755)
    return str(launcher)


@pytest.mark.integration
def test_an_xdist_worker_whose_parent_is_a_launcher_uses_the_runs_home(tmp_path):
    """Each worker of a pytest run from a Windows venv is a grandchild of its controller.

    execnet starts a worker as ``[python, "-u", "-c", ...]`` with the controller's
    sys.executable, which in a Windows venv is the launcher, and the launcher starts
    the real interpreter. A worker told apart from a nested run by its parent's pid
    took that branch and a home of its own, and the check above failed on every
    Windows leg.
    """
    result, created = _run_with_sentinel_home(
        tmp_path,
        "tests/unit/test_home_isolation.py::"
        "test_a_module_imported_by_pytest_sees_the_runs_own_home",
        "--dist",
        "worksteal",
        "--tx",
        f"2*popen//python={_launcher(tmp_path)}",
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-4000:]
    assert "1 passed" in output, output[-4000:]
    assert not created, created


@pytest.mark.unit
def test_importing_the_conftest_again_changes_nothing():
    """``from tests.conftest import X`` executes tests/conftest.py a second time.

    pytest imports it as ``conftest``, so that import makes a second module, and its
    import-time setup does not run again: run twice, it would move HOME to a new home
    mid-collection in a single-process run, and in any process add a second jsii import
    hook and two more atexit handlers. Executing a fresh copy here must leave all three
    as they were.
    """
    import atexit
    import importlib.util

    def jsii_hooks() -> int:
        return sum(type(h).__name__ == "_JsiiKernelLoadLockHook" for h in sys.meta_path)

    watched = (*HOME_VARIABLES, *UV_DIRECTORY_VARIABLES, "UV_CACHE_DIR")
    env_before = {name: os.environ.get(name) for name in watched}
    hooks_before = jsii_hooks()
    atexit_before = atexit._ncallbacks()

    spec = importlib.util.spec_from_file_location(
        "_conftest_imported_again", REPO_ROOT / "tests" / "conftest.py"
    )
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)

    assert {name: os.environ.get(name) for name in watched} == env_before
    assert jsii_hooks() == hooks_before
    assert atexit._ncallbacks() == atexit_before


@pytest.mark.unit
class TestEachTestHasItsOwnHome:
    def test_the_home_is_a_temporary_directory(self, developer_home, tmp_path_factory):
        home = Path.home()
        assert home.is_dir()
        assert os.path.realpath(home) != os.path.realpath(developer_home)
        assert tmp_path_factory.getbasetemp() in home.parents, home

    def test_every_variable_points_into_it(self):
        home = Path.home()
        for variable in HOME_VARIABLES:
            value = os.environ.get(variable)
            assert value, f"{variable} is unset"
            assert Path(value) == home or home in Path(value).parents, (
                f"{variable}={value} is outside the test's home {home}"
            )

    def test_install_receipts_resolve_inside_it(self, developer_home):
        from automated_security_helper.utils import download_utils

        root = download_utils.receipt_root()
        assert Path.home() in root.parents, root
        # Not "outside the developer's home": on Windows the temp directory, and so the
        # test's home, is inside it.
        assert developer_home / ".ash" not in [root, *root.parents], root

    def test_uvs_directory_variables_are_unset_or_in_the_home(self):
        """So uv takes its tool and Python directories from the test's home.

        tests/conftest.py unsets them all, and tests/unit/conftest.py sets UV_TOOL_DIR
        where XDG_DATA_HOME puts it, which also holds on Windows.
        """
        assert environ_value("UV_TOOL_DIR") == str(
            Path.home() / ".local" / "share" / "uv" / "tools"
        )
        assert not {
            name
            for name in UV_DIRECTORY_VARIABLES
            if name in os.environ and name != "UV_TOOL_DIR"
        }

    @pytest.mark.real_home
    def test_real_home_restores_the_starting_values(self, developer_environment):
        for variable in (*HOME_VARIABLES, *UV_DIRECTORY_VARIABLES):
            # Not developer_environment.get(...) in the assertion: a failure would
            # print the whole mapping.
            starting = developer_environment.get(variable)
            assert environ_value(variable) == starting, variable


@pytest.mark.unit
def test_uv_keeps_the_developers_cache(developer_environment):
    """A child uv under a fresh home would start with an empty cache and go online.

    The run's value, read when pytest imported this module. A unit test has a cache
    inside its own home instead (tests/unit/conftest.py), since none may start a real
    uv but the few its list names.
    """
    if os.name == "nt":
        pytest.skip("uv's Windows cache is under LOCALAPPDATA, which is not moved")
    if "UV_CACHE_DIR" in developer_environment:
        expected = developer_environment["UV_CACHE_DIR"]
    else:
        base = developer_environment.get("XDG_CACHE_HOME") or os.path.join(
            developer_environment["HOME"], ".cache"
        )
        expected = os.path.join(base, "uv")
    assert UV_CACHE_AT_IMPORT == expected
