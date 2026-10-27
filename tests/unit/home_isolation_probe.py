# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that tests/unit/test_home_isolation.py runs in a child pytest, and nothing else.

The file name does not match ``python_files``, so pytest collects it only when it is
named on the command line, and the tests skip unless the child's environment sets
ASH_HOME_ISOLATION_PROBE: the first one writes into the home the run started with,
which in the child is a sentinel directory and anywhere else is a developer's, and the
last one fails by design. The parent names the tests it runs.

A test file planted outside the repository would not do: pytest would not load
tests/conftest.py for it, so neither the per-test home nor the ``real_home`` marker
would apply, and the control would pass without testing either.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("ASH_HOME_ISOLATION_PROBE") != "1",
    reason="run by tests/unit/test_home_isolation.py in a child with a sentinel home",
)


def _write_under_home(name: str) -> Path:
    # Not under ~/.ash: the guard on the real ~/.ash fails a test that writes there,
    # and these two are about which home Path.home() gives.
    target = Path.home() / "ash-home-isolation-probe" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(name, encoding="utf-8")
    return target


@pytest.mark.real_home
def test_a_real_home_test_writes_into_the_starting_home():
    _write_under_home("real-home")


def test_any_other_test_writes_into_its_own_home(tmp_path_factory):
    """The write lands in the test's own home, and is taken away again.

    Taken away by the test itself, as any test should leave its home: the unit tests'
    tool guard fails a test that leaves a file there. The parent checks the run's homes
    are empty afterwards, and that nothing landed in the sentinel.
    """
    target = _write_under_home("isolated")
    try:
        assert tmp_path_factory.getbasetemp() in target.parents, target
    finally:
        target.unlink()
        target.parent.rmdir()


def test_a_write_into_the_developers_ash_directory(developer_home):
    """Writes where the receipts are in the home the run started with, without $HOME.

    The way code that finds the home some other way would. In the child that home is
    the sentinel; the guard on the real ~/.ash must fail this test.
    """
    target = developer_home / ".ash" / "written-by-a-test"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x", encoding="utf-8")


def test_a_write_after_the_last_teardown(developer_home, request):
    """Writes into the developer's ~/.ash from pytest_sessionfinish, after every teardown.

    In whichever process ran this test: under xdist, a worker, whose record only its
    controller can report. The write is refused; the record must still fail the run.
    In the child that home is the sentinel.
    """
    target = developer_home / ".ash" / "written-after-the-last-teardown"

    class LateWriter:
        @pytest.hookimpl(tryfirst=True)
        def pytest_sessionfinish(self, session):
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("x", encoding="utf-8")
            except PermissionError:
                pass  # refused, as it must be; the record is what fails the run

    request.config.pluginmanager.register(LateWriter(), "ash-home-isolation-late")


def test_the_mirror_variables_reach_the_test():
    """Each variable named in ASH_HOME_ISOLATION_EXPECT has the value the run started with."""
    import json

    expected = json.loads(os.environ["ASH_HOME_ISOLATION_EXPECT"])
    assert expected, "the parent named no variables"
    seen = {name: os.environ.get(name) for name in expected}
    assert seen == expected


def _uv_directories_that_reach_the_test(started_with: dict, basetemp: Path) -> dict:
    """The variables of ``started_with`` that a test sees with a value not its run's own.

    The value the run started with (a developer's uv directory) must not reach a test.
    A value inside the run's own directories may: the unit tests' tool guard points
    UV_TOOL_DIR into each test's home.
    """
    from tests.utils.home_rule import inside_the_runs_own_directories

    return {
        name: os.environ[name]
        for name in started_with
        if name in os.environ
        and (
            os.environ[name] == started_with[name]
            or not inside_the_runs_own_directories(os.environ[name], basetemp)
        )
    }


def _started_with() -> dict:
    import json

    started_with = json.loads(os.environ["ASH_HOME_ISOLATION_UNSET"])
    assert started_with, "the parent named no variables"
    return started_with


def test_no_variable_named_in_ash_home_isolation_unset_reaches_the_test(
    tmp_path_factory,
):
    """No variable in ASH_HOME_ISOLATION_UNSET reaches a test with a value not its own."""
    basetemp = tmp_path_factory.getbasetemp()
    assert _uv_directories_that_reach_the_test(_started_with(), basetemp) == {}


def test_a_uv_directory_in_the_tests_own_home_is_its_own(tmp_path_factory, monkeypatch):
    """As the unit tests' tool guard sets UV_TOOL_DIR: not the developer's, not counted."""
    monkeypatch.setenv("UV_TOOL_DIR", str(Path.home() / ".local" / "share" / "uv"))
    basetemp = tmp_path_factory.getbasetemp()
    assert _uv_directories_that_reach_the_test(_started_with(), basetemp) == {}


def test_the_value_the_run_started_with_is_counted(tmp_path_factory, monkeypatch):
    """Control: the check above can fail, for the developer's own uv directory."""
    started_with = _started_with()
    monkeypatch.setenv("UV_TOOL_DIR", started_with["UV_TOOL_DIR"])
    basetemp = tmp_path_factory.getbasetemp()
    reached = _uv_directories_that_reach_the_test(started_with, basetemp)
    assert reached == {"UV_TOOL_DIR": started_with["UV_TOOL_DIR"]}


def test_a_refusal_the_test_swallows(developer_home):
    """Starts an installer with the developer's HOME, and ignores that it was refused.

    The guard in tests/conftest.py refuses the child before it runs and records the
    refusal, so this test must still fail, at teardown. The child never starts, so it
    writes nothing, wherever HOME points.
    """
    import subprocess
    import sys
    import tempfile

    env = {
        **os.environ,
        "HOME": str(developer_home),
        "USERPROFILE": str(developer_home),
    }
    # The pinned installer's argv shape (see test_conftest_helpers._pinned_installer),
    # aimed at a temporary directory: the home is what is wrong here.
    destination = os.path.join(tempfile.gettempdir(), "stand-in-bin")
    script = "pass  # stands in for install_pinned_tool(...)"
    try:
        subprocess.run(
            [sys.executable, "-c", script, "tool", "linux", "amd64", destination],
            env=env,
            check=False,
        )
    except pytest.fail.Exception:
        pass  # as a broad `except BaseException` in the code under test would
