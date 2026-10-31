# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The helpers ``tests/conftest.py`` offers test authors do what they say.

``temp_env_vars`` puts back, on teardown, every environment variable it set, and sets
nothing it was not asked to, so the next test in the same xdist worker keeps its
environment. These tests check that after the fixture's teardown. That teardown is the
shared ``monkeypatch``'s undo, and the autouse unit tool guard (tests/unit/conftest.py)
takes ``monkeypatch`` before any test fixture is set up and patches PATH and the uv
directories on it, so pytest's reverse-order teardown would undo it only AFTER
``environment_check`` has compared, and an undo run by the check itself unwinds the
guard's patches as well as the test's. ``environment_check`` therefore reads the test's
FOOTPRINT (the variables whose value differs between its snapshot and the end of the
test), undoes the shared instance, and asserts that each variable in the footprint is
back to its snapshot value; the guard's variables are outside the footprint unless a
test changes them, and the environment is left as the undo leaves it (re-applying the
snapshot would plant the guard's values in every later test of the worker).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import botocore.endpoint
import pytest

from tests.utils.env_assertions import (
    NamesOnlyEnvironment,
    environ_names,
    environ_value,
)
from tests.utils.helpers import checkout_env

KEPT = "ASH_TEST_TEMP_ENV_VARS_KEPT"
OVERWRITTEN = "ASH_TEST_TEMP_ENV_VARS_OVERWRITTEN"
ADDED = "ASH_TEST_TEMP_ENV_VARS_ADDED"
#: pytest rewrites this one itself at every phase of every test.
PYTEST_OWNED = {"PYTEST_CURRENT_TEST"}


def _environment() -> dict:
    return {k: v for k, v in os.environ.items() if k not in PYTEST_OWNED}


@pytest.fixture
def environment_check(monkeypatch):
    """Fail the test unless every variable it changed is back after the teardown.

    The sentinels are set through ``os.environ`` rather than ``monkeypatch``, so they
    are part of the snapshot and not of what the undo reverts. The shared
    ``monkeypatch`` is created by the autouse unit tool guard before this fixture, with
    the guard's own patches (PATH, UV_CACHE_DIR, UV_TOOL_DIR) already on it when the
    snapshot is taken, so the fixture cannot compare the whole environment after an
    undo: pytest's own undo would come after this check, and an undo run here reverts
    the guard's patches too, which the snapshot holds. It reads the test's footprint
    instead: the variables whose value differs between the snapshot and the end of the
    test, which is what ``temp_env_vars`` set (and nothing the test did not ask for),
    then undoes the shared instance and asserts each of them is back to its snapshot
    value. A ``temp_env_vars`` that set variables outside ``monkeypatch`` would leave
    them in the footprint unrestored. The environment is left as the undo leaves it:
    the guard's later undo finds nothing to do, and re-applying the snapshot would plant
    the guard's values in every later test of the worker.
    """
    os.environ.update({KEPT: "kept", OVERWRITTEN: "before"})
    before = _environment()
    yield
    during = _environment()
    footprint = sorted(
        key
        for key in before.keys() | during.keys()
        if before.get(key) != during.get(key)
    )
    monkeypatch.undo()
    after = _environment()
    os.environ.pop(KEPT, None)
    os.environ.pop(OVERWRITTEN, None)

    assert footprint, "the test changed no variable, so there was nothing to check"
    assert KEPT not in footprint, "a variable the test did not set was changed under it"
    unrestored = sorted(key for key in footprint if after.get(key) != before.get(key))
    assert unrestored == [], (
        f"temp_env_vars did not restore the environment: of the variables the test "
        f"changed ({footprint}), these are not back to their value before the test: "
        f"{unrestored}"
    )


@pytest.mark.unit
def test_temp_env_vars_restores_the_environment_it_found(
    environment_check, temp_env_vars
):
    temp_env_vars(**{ADDED: "added", OVERWRITTEN: "during"})
    assert os.environ[ADDED] == "added"
    assert os.environ[OVERWRITTEN] == "during"
    assert os.environ[KEPT] == "kept"
    assert "PATH" in environ_names()


@pytest.mark.unit
def test_a_variable_set_twice_returns_to_its_first_value(
    environment_check, temp_env_vars
):
    temp_env_vars(**{OVERWRITTEN: "first"})
    temp_env_vars(**{OVERWRITTEN: "second"})
    assert os.environ[OVERWRITTEN] == "second"


@pytest.mark.unit
def test_values_are_set_as_strings(environment_check, temp_env_vars):
    temp_env_vars(**{ADDED: 3})
    assert os.environ[ADDED] == "3"


def _root_conftest(config) -> object:
    """tests/conftest.py as pytest loaded it, rather than a second import of it."""
    path = (Path(__file__).resolve().parents[1] / "conftest.py").resolve()
    for plugin in config.pluginmanager.get_plugins():
        if Path(getattr(plugin, "__file__", "") or "").resolve() == path:
            return plugin
    raise AssertionError(f"pytest has not loaded {path} as a plugin")


class _RecordingParser:
    def __init__(self) -> None:
        self.flags: list[str] = []

    def addoption(self, *names: str, **_kwargs) -> None:
        self.flags.append(names[0])


class _RecordingConfig:
    def __init__(self) -> None:
        self.read: set[str] = set()
        self.hook = types.SimpleNamespace(pytest_deselected=lambda items: None)

    def getoption(self, name: str, default=None):
        self.read.add(name)
        return False


class _ItemWithMarker:
    """An item carrying one marker. One per marker, because the hook stops reading
    options for an item at the first marker that deselects it."""

    def __init__(self, marker: str) -> None:
        self.marker = marker
        self.keywords = {marker: True}

    def get_closest_marker(self, name):
        return object() if name == self.marker else None

    def add_marker(self, marker) -> None:
        pass


def _options_read_by_name_in_tests() -> set[str]:
    """``getoption("--flag")`` literals in tracked test files, for options read outside
    the collection hook (a fixture, say). Listed with git, not by walking the tree."""
    root = Path(__file__).resolve().parents[2]
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "tests/*.py"],
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    pattern = re.compile(r"""getoption\(\s*["'](--[\w-]+)["']""")
    found: set[str] = set()
    for name in filter(None, listed.split("\0")):
        path = root / name
        if path.is_file():
            found.update(pattern.findall(path.read_text(encoding="utf-8")))
    return found


@pytest.mark.integration
def test_every_option_the_conftest_adds_is_read(request):
    """An option that nothing reads accepts the flag and silently does nothing.

    ``--run-changed-only`` and ``--base-branch`` were that: registered since the v3
    release, documented, and read by nothing, so ``pytest --run-changed-only`` ran the
    whole suite.
    """
    conftest = _root_conftest(request.config)
    parser = _RecordingParser()
    conftest.pytest_addoption(parser)
    assert "--run-integration" in parser.flags, (
        f"recorded nothing useful: {parser.flags}"
    )

    markers = {
        line.split(":", 1)[0].strip() for line in request.config.getini("markers")
    }
    config = _RecordingConfig()
    conftest.pytest_collection_modifyitems(
        config=config, items=[_ItemWithMarker(m) for m in sorted(markers)]
    )
    read = config.read | _options_read_by_name_in_tests()
    assert "--run-slow" in read, f"recorded no reads: {read}"

    unread = sorted(set(parser.flags) - read)
    assert not unread, (
        f"tests/conftest.py adds {unread}, which nothing reads. Implement them or remove "
        "them and their documentation."
    )


@pytest.mark.unit
def test_no_marker_promises_scheduling_that_nothing_implements(request):
    """No marker such as ``serial`` ("Tests that should not run in parallel") is registered.

    pytest-xdist schedules a marked test like any other, so a test marked serial would
    run beside the others under ``-n auto``.
    """
    names = {line.split(":", 1)[0].strip() for line in request.config.getini("markers")}
    assert "integration" in names, f"read the wrong marker list: {sorted(names)}"
    assert "serial" not in names, (
        "the 'serial' marker is registered again, and xdist ignores it. Make the test "
        "safe to run in parallel instead, or implement the marker and test that it works."
    )


@pytest.mark.unit
class TestInstallReceiptsStayOutOfTheDeveloperHome:
    """``write_receipt`` keys a directory by the install destination's path.

    Every test that installs into its own ``tmp_path`` adds a new directory, so receipts
    follow the test's temporary home, not the developer's ``~/.ash/install-receipts``
    (tests/unit/test_home_isolation.py covers the home itself). These tests assert
    before they write, so if the home were the developer's
    they would fail without touching it.
    """

    def test_receipts_resolve_inside_the_tests_home(self, developer_home):
        """The test's home, not the developer's ~/.ash.

        Not "outside the developer's home": on Windows the temp directory, and so the
        test's home, is inside it.
        """
        from automated_security_helper.utils import download_utils

        root = download_utils.receipt_root()
        assert developer_home / ".ash" not in [root, *root.parents], (
            f"receipt_root() is under the developer's {developer_home / '.ash'}; a test "
            "writing a receipt would leave it there"
        )
        assert os.path.realpath(Path.home()) != os.path.realpath(developer_home)
        assert root == Path.home() / ".ash" / download_utils.RECEIPT_DIR_NAME

    def test_a_receipt_written_by_a_test_lands_there(self, tmp_path, developer_home):
        from automated_security_helper.utils import download_utils

        root = download_utils.receipt_root()
        assert developer_home / ".ash" not in [root, *root.parents], root
        destination = tmp_path / "bin"
        written = download_utils.write_receipt(destination, "tool", {"tool": "tool"})
        assert written is not None and written.is_file()
        assert root in written.parents
        assert download_utils.read_receipt(destination, "tool") == {"tool": "tool"}

    def test_a_test_that_points_home_elsewhere_keeps_that_location(
        self, tmp_path, monkeypatch
    ):
        """The tests of receipt_root itself set HOME and must see the real derivation."""
        from automated_security_helper.utils import download_utils

        home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        assert download_utils.receipt_root() == home.joinpath(
            ".ash", download_utils.RECEIPT_DIR_NAME
        )


def _pinned_installer(destination) -> list:
    """The argv shape of download_utils.create_pinned_tool_install_command.

    The guard reads the destination from it; the script only stands in for the call.
    """
    script = "pass  # stands in for install_pinned_tool(...)"
    return [sys.executable, "-c", script, "tool", "linux", "amd64", str(destination)]


class TestToolInstallingChildrenGetTheirOwnHome:
    """A child inherits the test's temporary home, unless it is given an env of its own.

    ``ash dependencies install`` installs each pinned tool in a ``python -c`` child that
    calls ``install_pinned_tool``, and that child writes its receipt under its own
    HOME. So the conftest refuses to start such a child, or an ``ash dependencies
    install`` process, whose env carries the developer's HOME or none, before it runs.
    """

    @staticmethod
    def installer() -> list:
        """A pinned installer aimed at a temporary directory: only its HOME can be wrong."""
        return _pinned_installer(os.path.join(tempfile.gettempdir(), "stand-in-bin"))

    @pytest.fixture
    def developer_env(self, developer_home):
        return NamesOnlyEnvironment(
            {
                **os.environ,
                "HOME": str(developer_home),
                "USERPROFILE": str(developer_home),
            }
        )

    @staticmethod
    def _start(argv, **kwargs) -> str:
        try:
            subprocess.run(argv, capture_output=True, check=False, **kwargs)
        except pytest.fail.Exception as exc:
            return f"refused: {exc}"
        return "started"

    @pytest.mark.unit
    def test_an_installer_child_with_the_developer_home_is_refused(
        self, home_guard_violations, developer_env
    ):
        outcome = self._start(self.installer(), env=developer_env)
        assert outcome.startswith("refused"), outcome
        assert "HOME" in outcome
        assert len(home_guard_violations) == 1, home_guard_violations
        home_guard_violations.clear()

    @pytest.mark.unit
    def test_ash_dependencies_install_with_the_developer_home_is_refused(
        self, home_guard_violations, developer_env
    ):
        outcome = self._start(
            ["ash", "dependencies", "install", "--help"], env=developer_env
        )
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_an_installer_child_inheriting_the_tests_home_starts(self):
        assert self._start(self.installer()) == "started"

    @pytest.mark.integration
    def test_a_child_given_no_home_gets_the_tests(self):
        """With HOME unset, Path.home() falls back to the password database, the developer's.

        So an env without one is given the test's home, the one an inheriting child has.
        A command line that removes HOME itself is refused (TestTheGuardReadsThroughWrappers).
        """
        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "USERPROFILE")}
        outcome = self._start(self.installer(), env=env)
        assert outcome == "started"

    @pytest.mark.unit
    def test_a_test_whose_home_is_the_developers_has_none_to_give(
        self, home_guard_violations, developer_home, monkeypatch
    ):
        """As in a real_home test: its home is the developer's, so a child given no
        HOME is refused rather than given that one.

        The test's HOME is pointed there directly, not by the real_home marker, which
        the unit tests' tool guard allows only in the home isolation modules.
        """
        monkeypatch.setenv("HOME", str(developer_home))
        monkeypatch.setenv("USERPROFILE", str(developer_home))
        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "USERPROFILE")}
        outcome = self._start([sys.executable, "-c", "pass"], env=env)
        assert outcome.startswith("refused"), outcome
        assert "HOME unset" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    def test_a_refusal_the_code_swallows_is_still_recorded(
        self, home_guard_violations, developer_env
    ):
        """The fixture fails the test at teardown from this record."""
        try:
            subprocess.run(
                self.installer(), capture_output=True, check=False, env=developer_env
            )
        except pytest.fail.Exception:
            pass  # as a broad `except BaseException` in the code under test would
        assert len(home_guard_violations) == 1
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_the_same_child_with_its_own_home_starts(self, tmp_path):
        env = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
        outcome = self._start(self.installer(), env=env)
        assert outcome == "started"

    @pytest.mark.integration
    def test_a_child_that_installs_nothing_is_not_checked(self):
        assert self._start([sys.executable, "-c", "print('ok')"]) == "started"

    @staticmethod
    def _without_a_home() -> "dict[str, str]":
        return {k: v for k, v in os.environ.items() if k not in ("HOME", "USERPROFILE")}

    @pytest.mark.unit
    @pytest.mark.parametrize("program", ["python", "ash"])
    def test_a_python_or_ash_child_given_the_developer_home_is_refused(
        self, home_guard_violations, developer_home, program
    ):
        """Any Python child can write receipts (write_receipt, Path.home()), not only installers."""
        if program == "ash":
            argv = [TestInstallersAreRefusedADestinationInTheDeveloperHome._ash()]
            argv.append("--version")
        else:
            argv = [sys.executable, "-c", "pass"]
        env = {
            **os.environ,
            "HOME": str(developer_home),
            "USERPROFILE": str(developer_home),
        }
        outcome = self._start(argv, env=checkout_env(env))
        assert outcome.startswith("refused"), outcome
        assert "HOME" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_a_python_child_given_no_home_gets_the_tests(self, tmp_path):
        """ASH's own Landlock probe starts ``python -I`` with ``env={"PATH": ...}``.

        With no HOME a child falls back to the password database, the developer's real
        home. It is given the test's home instead, the one it would have inherited.
        """
        seen = tmp_path / "home.txt"
        script = "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(str(pathlib.Path.home()))"
        argv = [sys.executable, "-c", script, str(seen)]
        outcome = self._start(argv, env=self._without_a_home())
        assert outcome == "started"
        home = os.environ["USERPROFILE" if os.name == "nt" else "HOME"]
        assert seen.read_text() == home

    @pytest.mark.integration
    @pytest.mark.parametrize("given", ["as a keyword", "by position", "as bytes"])
    def test_the_tests_home_reaches_the_child_however_env_is_given(
        self, tmp_path, given
    ):
        """Popen takes env by keyword or as its eleventh argument, and on POSIX as bytes."""
        if given == "as bytes" and os.name == "nt":
            pytest.skip("Windows takes no env of bytes")
        seen = tmp_path / "home.txt"
        script = "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(str(pathlib.Path.home()))"
        argv = [sys.executable, "-c", script, str(seen)]
        env: dict = self._without_a_home()
        if given == "as bytes":
            env = {os.fsencode(k): os.fsencode(v) for k, v in env.items()}
        if given == "by position":
            # bufsize, executable, stdin, stdout, stderr, preexec_fn, close_fds,
            # shell, cwd, env
            process = subprocess.Popen(
                argv, -1, None, None, None, None, None, True, False, None, env
            )
        else:
            process = subprocess.Popen(argv, env=env)
        assert process.wait(timeout=60) == 0
        assert (
            seen.read_text() == os.environ["USERPROFILE" if os.name == "nt" else "HOME"]
        )

    @pytest.mark.integration
    def test_an_ash_child_given_no_home_starts(self):
        ash = TestInstallersAreRefusedADestinationInTheDeveloperHome._ash()
        env = checkout_env(self._without_a_home())
        outcome = self._start([ash, "--version"], env=env)
        assert outcome == "started"

    @pytest.mark.integration
    def test_a_home_less_child_writing_a_receipt_writes_it_in_the_tests_home(
        self, tmp_path, developer_home
    ):
        """``python -c`` calling write_receipt, with no HOME.

        The receipt lands in the test's home, and nothing under the guarded roots. The
        child checks its own home before it writes, so a guard that let it start with
        no home would fail this test without writing to the developer's.
        """
        from tests.utils import real_home_guard

        guarded = sorted(
            {os.path.realpath(root) for root in real_home_guard.watched_roots()}
        )
        written = tmp_path / "written.txt"
        script = (
            "import json, os, pathlib, sys\n"
            "from automated_security_helper.utils.download_utils import write_receipt\n"
            "dot_ash = os.path.realpath(pathlib.Path.home() / '.ash')\n"
            "if dot_ash in json.loads(sys.argv[1]):\n"
            "    sys.exit(3)\n"
            "path = write_receipt(pathlib.Path(sys.argv[2]), 'fixture-tool', {})\n"
            "pathlib.Path(sys.argv[3]).write_text(str(path))\n"
        )
        argv = [sys.executable, "-c", script, json.dumps(guarded)]
        argv += [str(tmp_path / "bin"), str(written)]
        outcome = self._start(argv, env=checkout_env(self._without_a_home()))
        assert outcome == "started"
        receipt = Path(written.read_text())
        assert Path.home() in receipt.parents, receipt
        assert developer_home / ".ash" not in receipt.parents, receipt
        assert not any(
            os.path.commonpath([os.path.realpath(receipt), root]) == root
            for root in guarded
        ), receipt

    @pytest.mark.unit
    def test_ash_run_as_a_module_with_the_developer_home_is_refused(
        self, home_guard_violations, developer_env
    ):
        """The ``python -m automated_security_helper...`` form of the same command."""
        argv = [sys.executable, "-m", "automated_security_helper.cli"]
        argv += ["dependencies", "install", "--help"]
        outcome = self._start(argv, env=checkout_env(developer_env))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()


class TestInstallersAreRefusedADestinationInTheDeveloperHome:
    """Even with the test's own HOME, an installer can be pointed at the developer's.

    The ``python -c`` installer installs into the destination it is given, which ``ash
    dependencies install`` takes from ``--bin-path``, then ASH_BIN_PATH. So an
    ASH_BIN_PATH naming the developer's ~/.ash/bin makes that directory the install
    target of every test that installs to the default directory, and the HOME check
    above lets it through.
    """

    @staticmethod
    def _start(argv, **kwargs) -> str:
        return TestToolInstallingChildrenGetTheirOwnHome._start(argv, **kwargs)

    _pinned_installer = staticmethod(_pinned_installer)

    @staticmethod
    def _ash() -> str:
        name = "ash.exe" if os.name == "nt" else "ash"
        path = Path(sys.executable).with_name(name)
        if not path.exists():
            pytest.skip(f"no {name} beside {sys.executable}")
        return str(path)

    @pytest.mark.unit
    def test_a_pinned_installer_aimed_at_the_developer_home_is_refused(
        self, home_guard_violations, developer_home
    ):
        destination = developer_home / ".ash" / "bin"
        outcome = self._start(self._pinned_installer(destination))
        assert outcome.startswith("refused"), outcome
        assert str(destination) in outcome, outcome
        assert len(home_guard_violations) == 1, home_guard_violations
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_a_pinned_installer_aimed_at_a_temporary_directory_starts(self, tmp_path):
        assert self._start(self._pinned_installer(tmp_path / "bin")) == "started"

    @staticmethod
    def _console_script(name: str) -> str:
        path = Path(sys.executable).with_name(
            f"{name}.exe" if os.name == "nt" else name
        )
        if not path.exists():
            pytest.skip(f"no {path.name} beside {sys.executable}")
        return str(path)

    @pytest.mark.unit
    @pytest.mark.parametrize("name", ["ashv3", "automated-security-helper"])
    def test_each_of_ashs_console_scripts_is_an_installer(
        self, home_guard_violations, developer_home, name
    ):
        """pyproject.toml gives the CLI three names; ``ash`` is only one of them."""
        destination = str(developer_home / ".ash" / "bin")
        argv = [self._console_script(name), "dependencies", "install"]
        argv += ["--bin-path", destination, "--help"]
        outcome = self._start(argv, env=checkout_env())
        assert outcome.startswith("refused"), outcome
        assert "--bin-path" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    @pytest.mark.parametrize("name", ["ashv3", "automated-security-helper"])
    def test_each_of_ashs_console_scripts_needs_a_home_of_its_own(
        self, home_guard_violations, developer_home, name
    ):
        env = {**os.environ, "HOME": str(developer_home)}
        env["USERPROFILE"] = str(developer_home)
        argv = [self._console_script(name), "--version"]
        outcome = self._start(argv, env=checkout_env(env))
        assert outcome.startswith("refused"), outcome
        assert "HOME in the developer home" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    def test_ash_bin_path_in_the_developer_home_is_refused(
        self, home_guard_violations, developer_home
    ):
        env = {**os.environ, "ASH_BIN_PATH": str(developer_home / ".ash" / "bin")}
        outcome = self._start(["ash", "dependencies", "install", "--help"], env=env)
        assert outcome.startswith("refused"), outcome
        assert "ASH_BIN_PATH" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "spelling",
        [
            pytest.param(lambda d, t: ["--bin-path", d], id="--bin-path X"),
            pytest.param(lambda d, t: [f"--bin-path={d}"], id="--bin-path=X"),
            pytest.param(lambda d, t: ["-b", d], id="-b X"),
            pytest.param(lambda d, t: [f"-b{d}"], id="-bX"),
            pytest.param(lambda d, t: ["-vb", d], id="-vb X"),
            # click takes the last of a repeated option
            pytest.param(
                lambda d, t: ["--bin-path", t, "--bin-path", d], id="repeated"
            ),
        ],
    )
    def test_every_spelling_of_bin_path_in_the_developer_home_is_refused(
        self, home_guard_violations, developer_home, tmp_path, spelling
    ):
        """The guard reads --bin-path with the CLI's own parser, so it reads what ash would."""
        destination = str(developer_home / ".ash" / "bin")
        argv = ["ash", "dependencies", "install"]
        argv += [*spelling(destination, str(tmp_path / "bin")), "--help"]
        outcome = self._start(argv)
        assert outcome.startswith("refused"), outcome
        assert destination in outcome and "--bin-path" in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_the_last_bin_path_is_the_one_that_counts(self, tmp_path, developer_home):
        argv = [self._ash(), "dependencies", "install"]
        argv += ["--bin-path", str(developer_home / ".ash" / "bin")]
        argv += ["--bin-path", str(tmp_path / "bin"), "--help"]
        outcome = self._start(argv, env=checkout_env())
        assert outcome == "started"

    @pytest.mark.unit
    def test_a_pinned_installer_with_interpreter_options_is_refused(
        self, home_guard_violations, developer_home
    ):
        """``python -u -c ...``: the destination is found after ``-c``, wherever that is."""
        argv = self._pinned_installer(developer_home / ".ash" / "bin")
        argv.insert(1, "-u")
        outcome = self._start(argv)
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    def test_a_home_inside_the_developer_home_is_refused(
        self, home_guard_violations, developer_home
    ):
        """HOME=<home>/work is not the developer's HOME, but its receipts land in it."""
        inside = str(developer_home / "work")
        env = {**os.environ, "HOME": inside, "USERPROFILE": inside}
        outcome = self._start(
            TestToolInstallingChildrenGetTheirOwnHome.installer(), env=env
        )
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "variable",
        [
            "XDG_DATA_HOME",
            "UV_TOOL_DIR",
            "UV_TOOL_BIN_DIR",
            "UV_PYTHON_INSTALL_DIR",
            "UV_PYTHON_BIN_DIR",
            "XDG_BIN_HOME",
        ],
    )
    def test_uvs_directories_in_the_developer_home_are_refused(
        self, home_guard_violations, developer_home, variable
    ):
        """The ash child runs ``uv tool install``, which installs where these say."""
        env = {**os.environ, variable: str(developer_home / ".local" / variable)}
        outcome = self._start(
            TestToolInstallingChildrenGetTheirOwnHome.installer(), env=env
        )
        assert outcome.startswith("refused"), outcome
        assert variable in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_a_relative_destination_is_resolved_against_the_childs_cwd(
        self, home_guard_violations, developer_home, tmp_path
    ):
        outcome = self._start(self._pinned_installer("bin"), cwd=str(developer_home))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()
        assert self._start(self._pinned_installer("bin"), cwd=str(tmp_path)) == (
            "started"
        )

    @pytest.mark.unit
    def test_a_case_variant_of_the_developer_home_is_refused(
        self, home_guard_violations, developer_home
    ):
        """On a case-insensitive file system (macOS, Windows) it is the same directory."""
        variant = str(developer_home).swapcase()
        if variant == str(developer_home) or not os.path.exists(variant):
            pytest.skip("the file system tells this home's case variants apart")
        if not os.path.samefile(variant, developer_home):
            pytest.skip("the case variant is a different directory here")
        destination = os.path.join(variant, ".ash", "bin")
        outcome = self._start(self._pinned_installer(destination))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @staticmethod
    def _link(link: Path, target: Path) -> Path:
        """``link`` pointing at ``target``, which need not exist (nothing is made in it)."""
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"cannot make a symbolic link here: {exc}")
        return link

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "route",
        [
            "a destination through a link",
            ".. after a link",
            "ASH_BIN_PATH through a link",
            "--bin-path through a link",
            "HOME as a link",
            "UV_TOOL_DIR through a link",
        ],
    )
    def test_a_link_into_the_developer_home_is_followed(
        self, home_guard_violations, developer_home, tmp_path, route
    ):
        """A path in the run's temp directory, as text, can lead into the home.

        Each of these is under tmp_path until its symbolic link is resolved. The links
        point at directories that do not exist, so nothing in the home is touched.
        """
        dot_ash = self._link(tmp_path / "dot-ash", developer_home / ".ash")
        env = None
        if route == "a destination through a link":
            argv = self._pinned_installer(dot_ash / "bin")
        elif route == ".. after a link":
            if os.name == "nt":
                pytest.skip("Windows takes .. off a path before it follows a link")
            up = self._link(tmp_path / "up", developer_home / "sub")
            argv = self._pinned_installer(os.path.join(up, os.pardir, ".ash", "bin"))
        elif route == "ASH_BIN_PATH through a link":
            argv = [self._ash(), "dependencies", "install", "--help"]
            env = {**os.environ, "ASH_BIN_PATH": str(dot_ash / "bin")}
        elif route == "--bin-path through a link":
            argv = [self._ash(), "dependencies", "install"]
            argv += ["--bin-path", str(dot_ash / "bin"), "--help"]
        elif route == "HOME as a link":
            home = self._link(tmp_path / "home-link", developer_home)
            argv = TestToolInstallingChildrenGetTheirOwnHome.installer()
            env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
        else:
            local = self._link(tmp_path / "local", developer_home / ".local")
            argv = TestToolInstallingChildrenGetTheirOwnHome.installer()
            env = {**os.environ, "UV_TOOL_DIR": str(local / "uv-tools")}
        outcome = self._start(argv, env=checkout_env(env))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.fixture
    def home_with_links_out(self, tmp_path, monkeypatch):
        """A developer home whose ~/.ash and ~/.local are links out of it.

        As dotfile managers and small home volumes make them. The developer record
        names this home; a temp root that holds it does not count, so nothing here is
        excused as one of the run's own temp directories.
        """
        home = tmp_path / "home"
        home.mkdir()
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "ash").mkdir(parents=True)
        (elsewhere / "local").mkdir()
        self._link(home / ".ash", elsewhere / "ash")
        self._link(home / ".local", elsewhere / "local")
        record = json.dumps({"env": {}, "home": str(home)})
        monkeypatch.setenv("ASH_TEST_DEVELOPER_HOME", record)
        return home

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "route", ["a destination", "ASH_BIN_PATH", "--bin-path", "XDG_DATA_HOME"]
    )
    def test_a_path_in_the_home_that_leaves_it_through_a_link_is_refused(
        self, home_guard_violations, home_with_links_out, route
    ):
        """~/.ash/bin is the developer's install directory wherever ~/.ash points."""
        bin_dir = home_with_links_out / ".ash" / "bin"
        env = None
        if route == "a destination":
            argv = self._pinned_installer(bin_dir)
        elif route == "ASH_BIN_PATH":
            argv = [self._ash(), "dependencies", "install", "--help"]
            env = {**os.environ, "ASH_BIN_PATH": str(bin_dir)}
        elif route == "--bin-path":
            argv = [self._ash(), "dependencies", "install"]
            argv += ["--bin-path", str(bin_dir), "--help"]
        else:
            argv = TestToolInstallingChildrenGetTheirOwnHome.installer()
            data = home_with_links_out / ".local" / "share"
            env = {**os.environ, "XDG_DATA_HOME": str(data)}
        outcome = self._start(argv, env=checkout_env(env))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "temp_root",
        ["PYTEST_DEBUG_TEMPROOT", "ASH_TEST_SESSION_TMPDIR", "TMPDIR before the run"],
    )
    def test_a_temp_root_in_the_developers_ash_directory_excuses_nothing(
        self, home_guard_violations, developer_home, monkeypatch, temp_root
    ):
        """~/.ash holds the receipts and the default bin directory, temp root or not."""
        dot_ash = str(developer_home / ".ash")
        if temp_root == "TMPDIR before the run":
            monkeypatch.setenv(
                "ASH_TEST_PRE_SESSION_TEMP_ENV", json.dumps({"TMPDIR": dot_ash})
            )
        else:
            monkeypatch.setenv(temp_root, dot_ash)
        outcome = self._start(self._pinned_installer(developer_home / ".ash" / "bin"))
        assert outcome.startswith("refused"), outcome
        home_guard_violations.clear()

    @pytest.mark.integration
    def test_an_explicit_bin_path_elsewhere_comes_first(self, tmp_path, developer_home):
        """``--bin-path`` wins over ASH_BIN_PATH in ``ash dependencies install``."""
        env = {**os.environ, "ASH_BIN_PATH": str(developer_home / ".ash" / "bin")}
        argv = [self._ash(), "dependencies", "install"]
        argv += ["--bin-path", str(tmp_path / "bin"), "--help"]
        outcome = self._start(argv, env=checkout_env(env))
        assert outcome == "started"


#: Endpoint._send as botocore defines it, read when this module is imported, before
#: any test's fixtures have run.
_ORIGINAL_SEND = botocore.endpoint.Endpoint._send


def _sts_client(endpoint_url: str | None = None):
    """A real STS client with placeholder credentials and no retries."""
    import boto3
    from botocore.config import Config

    return boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret
        region_name="us-east-1",
    ).client(
        "sts",
        endpoint_url=endpoint_url,
        config=Config(
            retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=2
        ),
    )


class TestBotocoreRequestsStayOnThisMachine:
    """No test sends a botocore request to AWS, or anywhere off this machine.

    A test that builds a real client without a Stubber, with credentials the
    environment happens to hold, reaches AWS: an import into a developer's
    Security Hub, an object in their bucket. The conftest refuses such a request
    where botocore sends it, ``Endpoint._send``, after any Stubber or
    ``before-send`` handler has had its chance, so a stubbed client never gets
    there. A loopback endpoint is allowed. A test that has to reach AWS carries
    ``@pytest.mark.allow_aws_network``.
    """

    @pytest.mark.unit
    def test_a_request_to_aws_is_refused_before_it_is_sent(
        self, aws_network_violations
    ):
        client = _sts_client()
        with pytest.raises(pytest.fail.Exception, match="sts.us-east-1.amazonaws.com"):
            client.get_caller_identity()
        assert len(aws_network_violations) == 1, aws_network_violations
        aws_network_violations.clear()

    @pytest.mark.unit
    def test_a_refusal_the_code_swallows_is_still_recorded(
        self, aws_network_violations
    ):
        """The fixture fails the test at teardown from this record."""
        client = _sts_client(endpoint_url="https://example.invalid")
        try:
            client.get_caller_identity()
        except BaseException:  # as a broad handler in the code under test would
            pass
        assert len(aws_network_violations) == 1, aws_network_violations
        aws_network_violations.clear()

    @pytest.mark.unit
    def test_a_stubbed_client_is_not_refused(self, aws_network_violations):
        from botocore.stub import Stubber

        client = _sts_client()
        with Stubber(client) as stub:
            stub.add_response(
                "get_caller_identity",
                {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"},
            )
            assert client.get_caller_identity()["Account"] == "123456789012"
        assert aws_network_violations == []

    @pytest.mark.integration
    def test_a_loopback_endpoint_is_not_refused(self, aws_network_violations):
        """Nothing listens on port 9 here, so botocore's own send fails to connect
        (to the endpoint, or to a proxy the environment names)."""
        from botocore.exceptions import ConnectionError as BotocoreConnectionError

        client = _sts_client(endpoint_url="http://127.0.0.1:9")
        with pytest.raises(BotocoreConnectionError):
            client.get_caller_identity()
        assert aws_network_violations == []

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "url, loopback",
        [
            ("http://127.0.0.1:4566/", True),
            ("http://127.8.9.10/", True),
            ("http://[::1]:4566/", True),
            ("http://localhost:4566/", True),
            ("http://s3.localhost/", True),
            ("https://sts.us-east-1.amazonaws.com/", False),
            ("http://10.0.0.1/", False),
            ("http://169.254.169.254/", False),
            ("http://localhost.example.com/", False),
            ("not a url", False),
        ],
    )
    def test_what_counts_as_this_machine(self, request, url, loopback):
        conftest = _root_conftest(request.config)
        assert conftest._is_loopback_url(url) is loopback

    @pytest.mark.unit
    def test_the_send_stage_is_guarded_in_an_ordinary_test(self):
        """Control for the opt-in below: the patch is there without the marker."""
        assert botocore.endpoint.Endpoint._send is not _ORIGINAL_SEND

    @pytest.mark.unit
    @pytest.mark.allow_aws_network
    def test_a_test_that_opts_in_sends_as_botocore_does(self):
        assert botocore.endpoint.Endpoint._send is _ORIGINAL_SEND


class TestTheGuardReadsThroughWrappers:
    """What a wrapper changes, the guard reads the way the child will see it.

    ``env NAME=VALUE cmd`` sets the child's environment on its command line, a shell's
    ``-c STRING`` holds the whole command in one argument, ``python -uc`` hides ``-c`` in
    a cluster, and a shell expands ``$VAR`` and runs ``A=B cmd`` and ``cd x && cmd``.
    Nothing in ASH or its tests starts an installer this way today; read literally,
    each of these got past the guard.
    """

    _start = staticmethod(TestToolInstallingChildrenGetTheirOwnHome._start)
    _ash = staticmethod(TestInstallersAreRefusedADestinationInTheDeveloperHome._ash)

    @pytest.fixture
    def into_home(self, developer_home) -> str:
        return str(developer_home / ".ash" / "bin")

    def _refused(self, home_guard_violations, outcome: str, *words: str) -> None:
        assert outcome.startswith("refused"), outcome
        for word in words:
            assert word in outcome, outcome
        home_guard_violations.clear()

    @pytest.mark.unit
    def test_env_setting_ash_bin_path(self, home_guard_violations, into_home):
        argv = ["env", f"ASH_BIN_PATH={into_home}", "ash", "dependencies", "install"]
        outcome = self._start([*argv, "--help"])
        self._refused(home_guard_violations, outcome, "ASH_BIN_PATH", into_home)

    @pytest.mark.unit
    def test_env_setting_home(self, home_guard_violations, developer_home):
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["env", f"HOME={developer_home}", f"USERPROFILE={developer_home}"]
        outcome = self._start([*argv, *installer])
        self._refused(home_guard_violations, outcome, "HOME")

    @pytest.mark.unit
    def test_env_unsetting_home(self, home_guard_violations):
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["env", "-u", "HOME", "--unset=USERPROFILE", *installer]
        self._refused(home_guard_violations, self._start(argv), "HOME unset")

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="no env command on Windows")
    def test_env_with_an_empty_environment_and_its_own_home_starts(self, tmp_path):
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["env", "-i", f"HOME={tmp_path}", f"USERPROFILE={tmp_path}", *installer]
        assert self._start(argv) == "started"

    @pytest.mark.unit
    @pytest.mark.parametrize("flags", ["-c", "-ec"])
    def test_a_shell_command_string(self, home_guard_violations, into_home, flags):
        """Read through: the refusal names the destination it found inside the string."""
        script = shlex.join(_pinned_installer(into_home))
        outcome = self._start(["sh", flags, script])
        self._refused(
            home_guard_violations, outcome, into_home, "its destination argument"
        )

    @pytest.mark.unit
    def test_a_shell_command_string_running_ash(self, home_guard_violations, into_home):
        command = ["ash", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(["sh", "-c", shlex.join(command)])
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    @pytest.mark.parametrize("option", ["--rcfile", "--init-file"])
    def test_a_bash_option_that_takes_a_value(
        self, home_guard_violations, into_home, option
    ):
        """The option's value is not where the options end: -c still comes after it."""
        command = ["ash", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(["bash", option, os.devnull, "-c", shlex.join(command)])
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "options",
        [
            pytest.param(["-euo", "pipefail", "-c"], id="o-inside-a-cluster-before-c"),
            pytest.param(["-co", "pipefail"], id="c-and-o-in-one-cluster"),
        ],
    )
    def test_an_option_letter_that_takes_a_value_inside_a_cluster(
        self, home_guard_violations, into_home, options
    ):
        """The o inside ``-euo`` takes pipefail as its value, as the whole word ``-o``
        does, so the command string is still the operand after it. Read without that,
        pipefail was the command string, and the destination inside the real one was
        never seen: the installer started."""
        command = ["ash", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(["bash", *options, shlex.join(command)])
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "argv, reads_stdin",
        [
            pytest.param(
                ["sh", "-euo", "pipefail"], True, id="the-value-leaves-no-script"
            ),
            pytest.param(
                ["sh", "-euo", "pipefail", "run.sh"], False, id="a-script-after-it"
            ),
            pytest.param(["sh", "-eu", "pipefail"], False, id="no-valued-letter"),
        ],
    )
    def test_a_shell_whose_cluster_takes_a_value_reads_stdin_or_a_script(
        self, request, argv, reads_stdin
    ):
        """``sh -euo pipefail`` reads its commands from standard input: pipefail is
        the value of o, not a script file. Without the o, pipefail is the script."""
        conftest = _root_conftest(request.config)
        assert conftest._shell_reads_stdin(argv) is reads_stdin

    @pytest.mark.unit
    def test_env_with_an_empty_environment(self, home_guard_violations):
        """``env -i`` drops HOME with the rest: the child falls back to the passwd home."""
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["env", "-i", f"PATH={os.environ.get('PATH', '')}", *installer]
        self._refused(home_guard_violations, self._start(argv), "HOME unset")

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "unset", [["--unset", "HOME"], ["--unset=HOME"], ["-uHOME"]], ids=" ".join
    )
    def test_env_unsetting_home_in_each_spelling(self, home_guard_violations, unset):
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["env", *unset, "--unset=USERPROFILE", *installer]
        self._refused(home_guard_violations, self._start(argv), "HOME unset")

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "spelling",
        [
            lambda d: ["-C", d],
            lambda d: [f"-C{d}"],
            lambda d: ["--chdir", d],
            lambda d: [f"--chdir={d}"],
        ],
        ids=["-C DIR", "-CDIR", "--chdir DIR", "--chdir=DIR"],
    )
    def test_env_changing_directory_for_a_relative_destination(
        self, home_guard_violations, developer_home, tmp_path, spelling
    ):
        """``env -C <home> <installer into .ash/bin>``: the destination is the home's."""
        relative = _pinned_installer(os.path.join(".ash", "bin"))
        argv = ["env", *spelling(str(developer_home)), *relative]
        outcome = self._start(argv, cwd=str(tmp_path))
        self._refused(home_guard_violations, outcome, "its destination argument")

    @pytest.mark.unit
    @pytest.mark.parametrize("form", ["-S", "--split-string"])
    def test_env_splitting_a_string(self, home_guard_violations, into_home, form):
        line = f"ASH_BIN_PATH={into_home} ash dependencies install --help"
        argv = ["env", "-S", line] if form == "-S" else ["env", f"{form}={line}"]
        self._refused(home_guard_violations, self._start(argv), "ASH_BIN_PATH")

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "prefix",
        [
            ["nice"],
            ["nice", "-n", "5"],
            ["nice", "-5"],
            ["timeout", "60"],
            ["timeout", "-s", "KILL", "--preserve-status", "60"],
            ["stdbuf", "-oL"],
            ["stdbuf", "-o", "L"],
            ["setsid"],
            ["nohup"],
            ["command"],
            ["time", "-p"],
        ],
        ids=" ".join,
    )
    def test_a_command_that_runs_the_rest_of_its_argv(
        self, home_guard_violations, into_home, prefix
    ):
        """nice, timeout, stdbuf, setsid, nohup, command and time run what follows."""
        argv = [*prefix, "env", f"ASH_BIN_PATH={into_home}", "ash"]
        outcome = self._start([*argv, "dependencies", "install", "--help"])
        self._refused(home_guard_violations, outcome, "ASH_BIN_PATH", into_home)

    @pytest.mark.unit
    def test_a_prefix_before_env_unsetting_home(self, home_guard_violations):
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        argv = ["stdbuf", "-oL", "env", "-u", "HOME", "--unset=USERPROFILE"]
        self._refused(
            home_guard_violations, self._start([*argv, *installer]), "HOME unset"
        )

    @pytest.mark.unit
    def test_exec_in_a_shell_command_line(self, home_guard_violations, into_home):
        line = (
            f"exec env ASH_BIN_PATH={shlex.quote(into_home)} ash dependencies install"
        )
        outcome = self._start(["sh", "-c", f"{line} --help"])
        self._refused(home_guard_violations, outcome, "ASH_BIN_PATH", into_home)

    @pytest.mark.unit
    def test_a_shell_behind_a_prefix(self, home_guard_violations, into_home):
        command = ["ash", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(["nice", "sh", "-c", shlex.join(command)])
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    def test_the_program_given_as_executable(self, home_guard_violations, into_home):
        """``Popen(["x", ...], executable=ash)`` runs ash whatever argv[0] says."""
        ash = TestInstallersAreRefusedADestinationInTheDeveloperHome._ash()
        argv = ["x", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(argv, executable=ash)
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_a_command_after_pushd_in_a_shell(
        self, home_guard_violations, developer_home, tmp_path
    ):
        command = f"pushd {shlex.quote(str(developer_home))} && "
        command += shlex.join(_pinned_installer(os.path.join(".ash", "bin")))
        outcome = self._start(["bash", "-c", command], cwd=str(tmp_path))
        self._refused(home_guard_violations, outcome, "its destination argument")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "bin_path",
        [
            '"$1"',
            '"${NOPE:-HOME}/.ash/bin"',
            '"$(echo HOME)/.ash/bin"',
            "`echo HOME`/.ash/bin",
            "~nosuchuser/.ash/bin",
            "$'HOME/.ash/bin'",
        ],
        ids=["positional", "default", "substitution", "backticks", "~user", "ansi-c"],
    )
    def test_a_word_the_shell_expands_and_the_guard_cannot_read(
        self, home_guard_violations, developer_home, bin_path
    ):
        """Where such a word points is the shell's to decide; the guard refuses it."""
        word = bin_path.replace("HOME", str(developer_home))
        line = f"ash dependencies install --bin-path {word} --help"
        outcome = self._start(["bash", "-c", line])
        self._refused(home_guard_violations, outcome, "cannot read")

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_a_tilde_is_the_childs_own_home(self, tmp_path):
        """``~/...`` is readable: it is the child's HOME, here a temporary one."""
        env = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
        line = "ash dependencies install --bin-path ~/.ash/bin --help"
        outcome = self._start(["sh", "-c", line], env=env)
        assert outcome == "started"

    @pytest.mark.unit
    def test_a_shell_option_the_guard_does_not_know(
        self, home_guard_violations, into_home
    ):
        command = ["ash", "dependencies", "install", "--bin-path", into_home, "--help"]
        outcome = self._start(["bash", "--new-option", "-c", shlex.join(command)])
        self._refused(home_guard_violations, outcome, "cannot read")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_an_export_before_the_command_in_a_shell(
        self, home_guard_violations, into_home
    ):
        command = f"export ASH_BIN_PATH={shlex.quote(into_home)}; "
        command += "ash dependencies install --help"
        outcome = self._start(command, shell=True)
        self._refused(home_guard_violations, outcome, "ASH_BIN_PATH", into_home)

    @pytest.mark.unit
    def test_a_shell_running_its_operands_with_the_developers_home(
        self, home_guard_violations, developer_home
    ):
        """``sh -c 'exec "$@"' sh CMD...`` runs CMD: the operands after the command line."""
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        env = {**os.environ, "HOME": str(developer_home)}
        env["USERPROFILE"] = str(developer_home)
        outcome = self._start(["sh", "-c", 'exec "$@"', "sh", *installer], env=env)
        self._refused(home_guard_violations, outcome, "HOME")

    @pytest.mark.unit
    @pytest.mark.skipif(
        os.name == "nt", reason="Windows joins a shell=True list into one command line"
    )
    def test_a_shell_true_list_running_its_operands_with_the_developers_home(
        self, home_guard_violations, developer_home
    ):
        """``Popen(['exec "$@"', 'sh', *CMD], shell=True)``: the items after the first are
        the line's $0, $1, ..., so it runs CMD."""
        installer = TestToolInstallingChildrenGetTheirOwnHome.installer()
        env = {**os.environ, "HOME": str(developer_home)}
        env["USERPROFILE"] = str(developer_home)
        outcome = self._start(['exec "$@"', "sh", *installer], shell=True, env=env)
        self._refused(home_guard_violations, outcome, "HOME")

    @pytest.mark.unit
    def test_a_shell_running_ash_from_its_operands(
        self, home_guard_violations, into_home
    ):
        argv = ["sh", "-c", 'exec "$@"', "sh", "ash", "dependencies", "install"]
        outcome = self._start([*argv, "--bin-path", into_home, "--help"])
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    def test_python_with_c_in_a_cluster(self, home_guard_violations, into_home):
        argv = _pinned_installer(into_home)
        argv[1] = "-uc"
        self._refused(home_guard_violations, self._start(argv), into_home)

    @pytest.mark.unit
    def test_an_installer_call_of_another_shape_is_refused(
        self, home_guard_violations, tmp_path
    ):
        """A fifth argument moves the destination; the guard cannot tell where it is."""
        argv = [*_pinned_installer(tmp_path / "bin"), "extra"]
        self._refused(home_guard_violations, self._start(argv), "5 arguments")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="cmd expands %VAR%, not $VAR")
    def test_a_shell_variable_for_the_bin_path(self, home_guard_violations, into_home):
        command = 'ash dependencies install --bin-path "$DEST" --help'
        env = {**os.environ, "DEST": into_home}
        outcome = self._start(command, shell=True, env=env)
        self._refused(home_guard_violations, outcome, "--bin-path", into_home)

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="cmd has no NAME=VALUE prefix")
    def test_a_shell_assignment_before_the_command(
        self, home_guard_violations, into_home
    ):
        command = (
            f"ASH_BIN_PATH={shlex.quote(into_home)} ash dependencies install --help"
        )
        outcome = self._start(command, shell=True)
        self._refused(home_guard_violations, outcome, "ASH_BIN_PATH", into_home)

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_a_command_after_cd_in_a_shell(
        self, home_guard_violations, developer_home, tmp_path
    ):
        """``cd <home> && <installer into bin>``: the relative destination is the home's."""
        command = f"cd {shlex.quote(str(developer_home))} && "
        command += shlex.join(_pinned_installer(os.path.join(".ash", "bin")))
        outcome = self._start(command, shell=True, cwd=str(tmp_path))
        self._refused(home_guard_violations, outcome, "bin")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line, words",
        [
            ("unset HOME; ash dependencies install --help", ["HOME unset"]),
            ("unset HOME; python -c pass", ["HOME unset"]),
            ("unset -v HOME; python -c pass", ["HOME unset"]),
            ("HOME=DEV; python -c pass", ["HOME in the developer home"]),
            ("HOME=DEV X=1; python -c pass", ["HOME in the developer home"]),
            ("D=DEV; HOME=$D python -c pass", ["HOME in the developer home"]),
            ("D=DEV; export D; env HOME=$D python -c pass", ["HOME in the dev"]),
        ],
        ids=[
            "unset before ash",
            "unset before python",
            "unset -v",
            "an assignment",
            "two assignments",
            "a shell variable",
            "export NAME",
        ],
    )
    def test_a_shell_line_that_changes_home_before_the_command(
        self, home_guard_violations, developer_home, line, words
    ):
        """``unset NAME`` and a command of NAME=VALUE words change what follows.

        HOME is exported, so ``HOME=x;`` changes the HOME every later command gets,
        and ``unset HOME`` leaves them with none: a real install would then write its
        receipts under the passwd home. A name the line sets that is not exported is
        seen by $NAME but given to no child.
        """
        line = line.replace("DEV", shlex.quote(str(developer_home)))
        self._refused(home_guard_violations, self._start(line, shell=True), *words)

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line",
        [
            "HOME=TMP; python -c pass",
            "UNEXPORTED_HOME_LIKE=DEV; python -c pass",
            "unset ASH_TEST_NOT_SET; python -c pass",
            "unset -f HOME; python -c pass",
            "command -v python; python -c pass",
            "true\npython -c pass",
            "command -p true; python -c pass",
            "echo 'un\\\nset HOME'; python -c pass",
            "sh SCRIPT; python -c pass",
            "sh - SCRIPT; python -c pass",
            "true 2> /dev/null; python -c pass",
            "true # unset HOME\npython -c pass",
            "echo 'a # b'; python -c pass",
            'echo "# unset HOME"; python -c pass',
            "cat <<EOF\nunset HOME\nEOF\npython -c pass",
            "cat <<EOF\nfoo\\\nEOF\nunset HOME\nEOF\npython -c pass",
            "cat <<< unset HOME; python -c pass",
        ],
        ids=[
            "home set to a temp dir",
            "not exported",
            "unset another",
            "a function",
            "command -v runs nothing",
            "a newline between two commands",
            "command -p of a harmless command",
            "a backslash-newline inside single quotes",
            "a shell given a script file",
            "a shell given - and a script file",
            "a redirect on fd 2 of a harmless command",
            "unset HOME in a comment",
            "a # in single quotes",
            "a # in double quotes",
            "unset HOME in a here-document",
            "a backslash-newline joins a body line to the delimiter",
            "a here-string's word",
        ],
    )
    def test_a_shell_line_that_leaves_the_home_temporary_starts(
        self, developer_home, tmp_path, line
    ):
        script = tmp_path / "script.sh"
        script.write_text("true\n", encoding="utf-8")
        line = line.replace("DEV", shlex.quote(str(developer_home)))
        line = line.replace("TMP", shlex.quote(str(tmp_path)))
        line = line.replace("SCRIPT", shlex.quote(str(script)))
        assert self._start(line, shell=True) == "started"

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line",
        [
            "HOME=$(echo DEV) python -c pass",
            "HOME=`echo DEV` python -c pass",
            'HOME="${NOPE:-DEV}" python -c pass',
            "export HOME=$(echo DEV); python -c pass",
            "HOME=$(echo DEV); ash --version",
        ],
        ids=["substitution", "backticks", "default", "exported", "ash"],
    )
    def test_a_python_child_whose_home_the_guard_cannot_read(
        self, home_guard_violations, developer_home, line
    ):
        """Where such a HOME points is the shell's to decide; the guard refuses it.

        As it does for an installer: ``HOME=$(echo <home>) python ...`` runs Python in
        the developer's home.
        """
        line = line.replace("DEV", str(developer_home))
        outcome = self._start(line, shell=True)
        self._refused(home_guard_violations, outcome, "cannot read")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line, words",
        [
            ("{ unset HOME; }; python -c pass", ["HOME unset"]),
            ("if :; then unset HOME; fi; python -c pass", ["HOME unset"]),
            ("if false; then :; else unset HOME; fi; python -c pass", ["HOME unset"]),
            ("while :; do unset HOME; break; done; python -c pass", ["HOME unset"]),
            ("! unset HOME; python -c pass", ["HOME unset"]),
            ("export -n HOME; python -c pass", ["HOME unset"]),
            ("eval 'unset HOME'; python -c pass", ["HOME unset"]),
            ("eval unset HOME; python -c pass", ["HOME unset"]),
            (". /dev/null; python -c pass", ["cannot read"]),
            ("source /dev/null; python -c pass", ["cannot read"]),
            ("readonly HOME=DEV; python -c pass", ["cannot read"]),
            ("declare -x HOME=DEV; python -c pass", ["cannot read"]),
            ("typeset -x HOME=DEV; python -c pass", ["cannot read"]),
            ("f() { local HOME=DEV; python -c pass; }; f", ["cannot read"]),
            ("{ unset HOME; ash dependencies install --help; }", ["HOME unset"]),
            # A newline ends a command as ";" does.
            ("unset HOME\npython -c pass", ["HOME unset"]),
            ("export -n HOME\npython -c pass", ["HOME unset"]),
            ("unset HOME\nash dependencies install --help", ["HOME unset"]),
            # command and builtin run the builtin after them; bash's `function NAME`
            # starts a function, as NAME() does.
            ("command unset HOME; python -c pass", ["HOME unset"]),
            ("builtin unset HOME; python -c pass", ["HOME unset"]),
            ("function f { unset HOME; }; f; python -c pass", ["HOME unset"]),
            # A backslash before a newline joins the two lines.
            ("unset \\\nHOME; python -c pass", ["HOME unset"]),
            ("un\\\nset HOME; python -c pass", ["HOME unset"]),
            # command -p runs the builtin after it with the default PATH.
            ("command -p unset HOME; python -c pass", ["HOME unset"]),
            # A shell given no -c and no script file reads its commands from stdin,
            # which the guard cannot read.
            ("sh <<< 'unset HOME; python -c pass'", ["cannot read"]),
            ("echo 'unset HOME; python -c pass' | sh", ["cannot read"]),
            # A lone - ends the options, as -- does, so the shell still reads stdin.
            ("echo 'unset HOME; python -c pass' | sh -", ["cannot read"]),
            ("sh -c - 'unset HOME; python -c pass'", ["HOME unset"]),
            # Digits right before a redirect are its file descriptor, not an operand.
            ("bash 0<<< 'unset HOME; python -c pass'", ["cannot read"]),
            ("sh 0< /dev/null", ["cannot read"]),
            ("sh 2> /dev/null", ["cannot read"]),
            # A comment ends at the end of its line, and only a # that starts a word
            # outside quotes starts one.
            ("true # a note\nunset HOME; python -c pass", ["HOME unset"]),
            ("echo a#b; unset HOME; python -c pass", ["HOME unset"]),
            ("echo $#; unset HOME; python -c pass", ["HOME unset"]),
            ("echo a\\ #b; unset HOME; python -c pass", ["HOME unset"]),
            ("sh -c 'true # a note\nunset HOME; python -c pass'", ["HOME unset"]),
            # A backslash-newline inside a comment is part of the comment: the
            # newline still ends it, so the next line runs.
            ("true # c \\\nunset HOME\npython -c pass", ["HOME unset"]),
            # A line shlex cannot split (bash's $'...' escapes) is still read a
            # command per line.
            ("echo $'it\\'s'\nunset HOME\npython -c pass", ["HOME unset"]),
            # A here-document's body is data up to its delimiter, so a quote in it
            # does not hide the commands after it.
            ("cat <<EOF\ndon't\nEOF\nunset HOME; python -c pass", ["HOME unset"]),
            ("cat <<'EOF'\ndon't\nEOF\nunset HOME; python -c pass", ["HOME unset"]),
            ("cat <<-EOF\n\tdon't\n\tEOF\nunset HOME; python -c pass", ["HOME unset"]),
            (
                "cat <<A <<B\ndon't\nA\nwon't\nB\nunset HOME; python -c pass",
                ["HOME unset"],
            ),
            # The rest of the line a here-document starts on is still commands.
            (
                "cat <<EOF > /dev/null; unset HOME\ndon't\nEOF\npython -c pass",
                ["HOME unset"],
            ),
            # A quoted delimiter is matched against the lines as written, so a
            # backslash before a newline joins nothing.
            (
                "cat <<'EOF'\nfoo\\\nEOF\nunset HOME\npython -c pass\nEOF",
                ["HOME unset"],
            ),
            # A body whose delimiter never comes is read as commands: stricter than
            # sh, which reads it as data to the end.
            ("cat <<EOF\nunset HOME\npython -c pass", ["HOME unset"]),
            # << in arithmetic starts no here-document.
            ("echo $((1<<2))\nunset HOME\npython -c pass\n2", ["HOME unset"]),
            # A here-string is one word of data, quoted newlines and all.
            ("cat <<< 'a\nb'\nunset HOME\npython -c pass", ["HOME unset"]),
        ],
        ids=[
            "a group",
            "if then",
            "else",
            "while do",
            "negated",
            "export -n",
            "eval of a string",
            "eval of words",
            "dot",
            "source",
            "readonly",
            "declare -x",
            "typeset -x",
            "local in a function",
            "an installer in a group",
            "unset and a newline",
            "export -n and a newline",
            "a newline before an installer",
            "command unset",
            "builtin unset",
            "a bash function",
            "unset, a backslash-newline, HOME",
            "a backslash-newline inside unset",
            "command -p unset",
            "a here-string into sh",
            "a pipe into sh",
            "a pipe into sh -",
            "a - before the -c command line",
            "a here-string on fd 0",
            "stdin redirected on fd 0",
            "stderr redirected on fd 2",
            "a comment, then the next line",
            "a # inside a word",
            "$#",
            "a # after an escaped blank",
            "a comment in a nested -c",
            "a backslash-newline at the end of a comment",
            "an ANSI-C quote shlex cannot split",
            "an apostrophe in a here-document",
            "an apostrophe, a quoted delimiter",
            "an apostrophe, <<-",
            "two here-documents on one line",
            "the rest of the line after <<",
            "a quoted delimiter and a backslash-newline",
            "a here-document never closed",
            "<< in arithmetic",
            "a here-string with a quoted newline",
        ],
    )
    def test_shell_syntax_and_builtins_before_the_command(
        self, home_guard_violations, developer_home, line, words
    ):
        """Reserved words start no command, and some builtins can set any variable.

        ``{``, ``if``, ``then``, ``else``, ``do``, ``while`` and ``!`` lead into the
        command after them. eval, ``.``, source, readonly, declare, typeset and local
        can set or export HOME in ways this reader does not follow, so a Python or ASH
        command after one has a HOME the guard cannot read. ``export -n`` unexports.
        """
        line = line.replace("DEV", shlex.quote(str(developer_home)))
        self._refused(home_guard_violations, self._start(line, shell=True), *words)

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell")
    @pytest.mark.parametrize(
        "argv",
        [["sh", "-"], ["bash", "-"], ["sh", "-e", "-"]],
        ids=["sh -", "bash -", "an option, then -"],
    )
    def test_a_shell_argv_ending_in_a_dash_reads_stdin(
        self, home_guard_violations, argv
    ):
        """A lone ``-`` ends the options as ``--`` does, and with no script file after
        it the shell reads its commands from standard input, which the guard cannot
        read. stdin is /dev/null here, so a start the guard allows reads nothing."""
        outcome = self._start(argv, stdin=subprocess.DEVNULL)
        self._refused(home_guard_violations, outcome, "cannot read")

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "sourced, line, words",
        [
            ("unset HOME\n", ". FILE; python -c pass", ["HOME unset"]),
            ("unset HOME\n", "source FILE; python -c pass", ["HOME unset"]),
            ('eval "$X"\n', ". FILE; python -c pass", ["cannot read"]),
            ("export HOME=DEV\n", ". FILE; ash --version", ["HOME in the developer"]),
            (". FILE\n", ". FILE; python -c pass", ["cannot read"]),
            ("true\n", ". NAME; python -c pass", ["cannot read"]),
            ("true\n", ". MISSING; python -c pass", ["cannot read"]),
        ],
        ids=[
            "a sourced unset",
            "source, a sourced unset",
            "a sourced eval",
            "a sourced export",
            "a file that sources itself",
            "a name looked up on PATH",
            "a file that is not there",
        ],
    )
    def test_a_sourced_file_is_read_where_it_is_sourced(
        self, home_guard_violations, developer_home, tmp_path, sourced, line, words
    ):
        """``. FILE`` and ``source FILE`` run FILE's commands in this shell, so the
        guard reads FILE there. A file it cannot read (a name looked up on PATH, one
        that is not there, or sources nested too deep) is opaque, as eval is."""
        script = tmp_path / "sourced.sh"
        script.write_text(
            sourced.replace("FILE", shlex.quote(str(script))).replace(
                "DEV", shlex.quote(str(developer_home))
            ),
            encoding="utf-8",
        )
        line = line.replace("FILE", shlex.quote(str(script)))
        line = line.replace("NAME", "sourced.sh")
        line = line.replace("MISSING", shlex.quote(str(tmp_path / "missing.sh")))
        # From tmp_path, so that NAME is a file there too: only the PATH lookup a
        # bare name gets makes it unreadable.
        outcome = self._start(line, shell=True, cwd=tmp_path)
        self._refused(home_guard_violations, outcome, *words)

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "sourced",
        [
            'f() {\n  local LC_ALL=C\n  local text="${1//x/ }"\n  printf \'%s\' "$text"\n}\n',
            "declare -r A=1\ntypeset B=2\nreadonly C\n",
        ],
        ids=["functions with locals", "declarations of other names"],
    )
    def test_a_sourced_file_that_leaves_home_alone_starts(self, tmp_path, sourced):
        script = tmp_path / "sourced.sh"
        script.write_text(sourced, encoding="utf-8")
        line = f". {shlex.quote(str(script))}; python -c pass"
        assert self._start(line, shell=True) == "started"

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_a_file_sourced_nine_deep_is_not_read(
        self, home_guard_violations, tmp_path
    ):
        """Each file sources the next; the ninth, which unsets HOME, is past the depth
        the guard reads, so the source of it is opaque."""
        files = [tmp_path / f"level{n}.sh" for n in range(1, 10)]
        for here, after in zip(files, files[1:]):
            here.write_text(f". {shlex.quote(str(after))}\n", encoding="utf-8")
        files[-1].write_text("unset HOME\n", encoding="utf-8")
        line = f". {shlex.quote(str(files[0]))}; python -c pass"
        self._refused(
            home_guard_violations, self._start(line, shell=True), "cannot read"
        )

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_how_deep_bounds_what_is_read_not_how_much(self, tmp_path):
        """A file holding six evals, sourced twice, is read all through: each read is
        one source deep, or two for the evals in it."""
        script = tmp_path / "sourced.sh"
        script.write_text("eval 'a=1'\n" * 6, encoding="utf-8")
        quoted = shlex.quote(str(script))
        assert self._start(f". {quoted}; . {quoted}; python -c pass", shell=True) == (
            "started"
        )

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line, words",
        [
            ("declare -n ref=HOME; ref=DEV; python -c pass", ["cannot read"]),
            ('declare "${NOPE:-HOME}"=DEV; python -c pass', ["cannot read"]),
        ],
        ids=["a nameref", "a name the guard cannot read"],
    )
    def test_a_declaration_the_guard_cannot_follow(
        self, home_guard_violations, developer_home, line, words
    ):
        line = line.replace("DEV", shlex.quote(str(developer_home)))
        self._refused(home_guard_violations, self._start(line, shell=True), *words)

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line",
        [
            (
                "f() { local x=1; declare -x y=2; typeset z=3; readonly w=4; }; f; "
                "python -c pass"
            ),
            "local -; python -c pass",
        ],
        ids=["declarations of other names", "local -"],
    )
    def test_a_declaration_of_another_name_starts(self, line):
        assert self._start(line, shell=True) == "started"

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line, words",
        [
            ("eval \"eval 'unset HOME'\"; python -c pass", ["HOME unset"]),
            ('eval "$X"; python -c pass', ["cannot read"]),
            ('eval "a$X"; python -c pass', ["cannot read"]),
            ('eval "x=$X"; python -c pass', ["cannot read"]),
            ('eval "$(echo unset HOME)"; python -c pass', ["cannot read"]),
            ("eval 'x=$(id)'; python -c pass", ["cannot read"]),
            ("eval 'x=`id`'; python -c pass", ["cannot read"]),
            ("eval 'a[$(id)]=1'; python -c pass", ["cannot read"]),
            ("eval '$c HOME'; python -c pass", ["cannot read"]),
            ("eval $'unset HOME'; python -c pass", ["cannot read"]),
            ("[[ $UNSET -eq 1 ]]; python -c pass", ["cannot read"]),
            ('n="$(cat f)"; [[ $n -ge 1 ]]; python -c pass', ["cannot read"]),
            ("ksh -c '[ \"$UNSET\" -gt 0 ]; python -c pass'", ["cannot read"]),
            ("bash -c '[[ $UNSET -eq 1 ]]; python -c pass'", ["cannot read"]),
            ("sh -c 'eval \"$X\"; python -c pass'", ["cannot read"]),
            ("test -v 'a[$(id)]'; python -c pass", ["cannot read"]),
            ("[[ -v a[$(id)] ]]; python -c pass", ["cannot read"]),
        ],
        ids=[
            "an eval inside an eval",
            "an eval of a variable",
            "an eval of a word built from a variable",
            "an eval of an assignment built from a variable",
            "an eval of a substitution",
            "a substitution in the eval's text",
            "backticks in the eval's text",
            "a substitution in a subscript",
            "an unreadable command word in the eval's text",
            "an eval of an ANSI-C quote",
            "an arithmetic operand the guard cannot read",
            "an arithmetic operand whose value the guard cannot read",
            "[ of an unknown arithmetic operand in ksh",
            "[[ of an unknown operand in a nested bash -c",
            "an eval of a variable in a nested sh -c",
            "test -v of a subscript that runs a substitution",
            "[[ -v of a subscript that runs a substitution",
        ],
    )
    def test_an_eval_or_test_the_guard_cannot_read(
        self, home_guard_violations, line, words
    ):
        """An eval is read as its text, with the reader the line gets, unless the text
        is built from a variable or a substitution, or runs one, or has a command word
        the guard cannot read. [, [[ and test run nothing, unless an operand they
        evaluate (of -v, -R or an arithmetic comparison) could run a substitution."""
        self._refused(home_guard_violations, self._start(line, shell=True), *words)

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line",
        [
            "eval 'x=1'; python -c pass",
            "eval '[ -n \"${.sh.version}\" ]'; python -c pass",
            "eval 'f() { g \"$@\"; }'; python -c pass",
            'eval "$X"; [ -f /no/such/ash ]',
            'eval "$X"; test -f /no/such/ash -a 1 -eq 1',
            "n=0; [[ $n -ge 40 ]]; python -c pass",
            "bash -c '[ \"$UNSET\" -gt 0 ]; python -c pass'",
            "dash -c '[ \"$UNSET\" -gt 0 ]; python -c pass'",
            "[[ ${#UNSET} -eq 0 && $? -eq 0 ]]; python -c pass",
        ],
        ids=[
            "an eval that sets another name",
            "an eval of a test",
            "an eval that defines a function",
            "[ after an eval the guard cannot read",
            "test of a literal arithmetic operand",
            "an arithmetic operand the guard knows",
            "[ of an unknown arithmetic operand in bash",
            "[ of an unknown arithmetic operand in dash",
            "a length and $?, which are numbers",
        ],
    )
    def test_an_eval_or_test_that_leaves_home_alone_starts(self, line):
        assert self._start(line, shell=True) == "started"

    #: How the reusable workflow's install preflight starts uvx: a shell function, then
    #: a bash -c whose $0 and "$@" are its operands.
    _PREFLIGHT = (
        "with_commands_stopped --capture help bash -c "
        '\': > "$0" && exec "$@" 2>&1\' MARKER '
        "uvx --from SOURCE ash dependencies install --help"
    )

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_a_nested_sh_c_is_read_with_its_operands(self, tmp_path):
        """The script's $0 and "$@" are the operands after it, so the command it runs
        is `uvx --from SOURCE ash dependencies install --help`, under this HOME."""
        line = self._PREFLIGHT.replace("MARKER", shlex.quote(str(tmp_path / "ran")))
        assert self._start(line, shell=True) == "started"

    @pytest.mark.unit
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line, words",
        [
            (
                "f bash -c 'HOME=DEV exec \"$@\"' x ash dependencies install --help",
                ["install receipts"],
            ),
            ('f bash -c "$S" x ash dependencies install --help', ["cannot read"]),
            (
                "f bash -c 'shift; exec \"$@\"' a ash dependencies install --help",
                ["cannot read"],
            ),
            (
                "f bash -c 'set -- y; exec \"$@\"' a ash dependencies install --help",
                ["cannot read"],
            ),
            (
                "f bash -c 'exec \"${10}\"' a ash dependencies install --help",
                ["cannot read"],
            ),
            (
                "f bash -c 'exec \"${@:1}\"' a ash dependencies install --help",
                ["cannot read"],
            ),
            (
                'f bash -c \'exec "$@"\' a ash dependencies install "$(pwd)"',
                ["cannot read"],
            ),
            (
                "f sh -c 'exec $@' a ash dependencies install 'a b'",
                ["cannot read"],
            ),
            (
                "f sh -c 'exec \"x $@\"' a ash dependencies install --help",
                ["cannot read"],
            ),
            (
                'f bash -c \'exec "$@" "$9"\' a ash dependencies install --help',
                ["cannot read"],
            ),
            (
                "bash -c 'HOME=DEV exec \"$@\"' x ash dependencies install --help",
                ["install receipts"],
            ),
            (
                'f bash -c \'exec "$@" dependencies install\' x ash "$(pwd)"',
                ["cannot read"],
            ),
        ],
        ids=[
            "the script sets HOME to the developer's",
            "a script from a variable",
            "shift",
            "set --",
            "${10}",
            "a ${@:...} slice",
            "an operand it uses that the guard cannot read",
            "an unquoted $@ that would split an operand",
            "$@ inside a longer quoted word",
            "a parameter no operand gives",
            "a shell at the start, its operands filled in",
            "an installer the script makes of an operand the guard cannot read",
        ],
    )
    def test_a_nested_sh_c_the_guard_cannot_follow(
        self, home_guard_violations, developer_home, line, words
    ):
        """A script it cannot fill in is a word it cannot read, so an installer is
        refused; one it can is read, so what the script itself does is checked."""
        line = line.replace("DEV", shlex.quote(str(developer_home)))
        self._refused(home_guard_violations, self._start(line, shell=True), *words)

    @pytest.mark.integration
    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    @pytest.mark.parametrize(
        "line",
        [
            "{ python -c pass; }",
            "if :; then python -c pass; fi",
            "eval true; HOME=TMP python -c pass",
        ],
        ids=["a group", "if then", "a readable HOME after eval"],
    )
    def test_shell_syntax_around_a_command_with_its_own_home_starts(
        self, tmp_path, line
    ):
        line = line.replace("TMP", shlex.quote(str(tmp_path)))
        assert self._start(line, shell=True) == "started"

    _RUNNERS = pytest.mark.parametrize(
        "runner", [["taskset", "-c", "0"], ["ionice", "-c", "3"]], ids=lambda r: r[0]
    )

    @staticmethod
    def _runner(runner: list) -> list:
        program = shutil.which(runner[0])
        if program is None:
            pytest.skip(f"no {runner[0]} on PATH")
        return [program, *runner[1:]]

    @pytest.mark.unit
    @_RUNNERS
    def test_python_behind_a_runner_the_guard_does_not_unwrap(
        self, home_guard_violations, developer_home, runner
    ):
        """A Python or ASH name anywhere in argv counts, whatever runs it."""
        env = {**os.environ, "HOME": str(developer_home)}
        env["USERPROFILE"] = str(developer_home)
        argv = [*self._runner(runner), sys.executable, "-c", "pass"]
        outcome = self._start(argv, env=env)
        self._refused(home_guard_violations, outcome, "HOME in the developer home")

    @pytest.mark.integration
    @_RUNNERS
    def test_python_behind_a_runner_given_no_home_gets_the_tests(
        self, tmp_path, runner
    ):
        seen = tmp_path / "home.txt"
        script = "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(str(pathlib.Path.home()))"
        argv = [*self._runner(runner), sys.executable, "-c", script, str(seen)]
        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "USERPROFILE")}
        outcome = self._start(argv, env=env)
        assert outcome == "started"
        assert seen.read_text() == os.environ["HOME"]


@pytest.mark.unit
class TestTheHomeRuleCanBeAskedFromOutsideTheConftest:
    """tests/utils/home_rule.py: the rule, for a start that never reaches Popen.

    os.posix_spawn, os.system and multiprocessing's spawn start skip the Popen guard.
    tests/utils/tool_guard.py's recorder sees them and asks this, so the rule has one
    definition.
    """

    @pytest.fixture
    def basetemp(self, tmp_path_factory) -> Path:
        return tmp_path_factory.getbasetemp()

    @pytest.fixture
    def developer_env(self, developer_home) -> dict:
        home = str(developer_home)
        return NamesOnlyEnvironment({**os.environ, "HOME": home, "USERPROFILE": home})

    def test_it_asks_the_conftest_pytest_loaded(self, request):
        """Not a second import of it, which would have its own state."""
        from tests.utils import home_rule

        assert home_rule.loaded_conftest() is _root_conftest(request.config)

    @pytest.mark.parametrize("held", ["by another conftest", "by none"])
    def test_it_finds_the_conftest_when_the_name_is_not_its_own(
        self, request, monkeypatch, held
    ):
        """pytest imports every conftest.py outside a package as module ``conftest``.

        Before it imports one in a sub-directory (tests/unit/conftest.py, say) it
        drops ``sys.modules["conftest"]``, so the root conftest is no longer under
        that name, nor under any other in sys.modules.
        """
        from tests.utils import home_rule

        if held == "by none":
            monkeypatch.delitem(sys.modules, "conftest", raising=False)
        else:
            monkeypatch.setitem(sys.modules, "conftest", types.ModuleType("conftest"))
        home_rule.loaded_conftest.cache_clear()
        request.addfinalizer(home_rule.loaded_conftest.cache_clear)
        assert home_rule.loaded_conftest() is _root_conftest(request.config)

    def test_a_python_start_with_the_developer_home_breaks_it(
        self, developer_env, basetemp
    ):
        from tests.utils.home_rule import home_rule_refusal

        argv = [sys.executable, "-c", "pass"]
        refusal = home_rule_refusal(argv, developer_env, basetemp=basetemp)
        assert refusal is not None and "HOME in the developer home" in refusal

    def test_a_start_with_the_tests_home_keeps_it(self, basetemp):
        from tests.utils.home_rule import home_rule_refusal

        argv = [sys.executable, "-c", "pass"]
        assert home_rule_refusal(argv, None, basetemp=basetemp) is None

    def test_an_installer_aimed_at_the_developer_home_breaks_it(
        self, developer_home, basetemp
    ):
        from tests.utils.home_rule import home_rule_refusal

        argv = _pinned_installer(developer_home / ".ash" / "bin")
        refusal = home_rule_refusal(argv, basetemp=basetemp)
        assert refusal is not None and "its destination argument" in refusal

    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell command line")
    def test_os_system_is_a_shell_line(self, basetemp):
        from tests.utils.home_rule import home_rule_refusal

        refusal = home_rule_refusal(
            "unset HOME; python -c pass", shell=True, basetemp=basetemp
        )
        assert refusal is not None and "HOME unset" in refusal

    def test_posix_spawn_names_its_program_apart(self, developer_env, basetemp):
        """``os.posix_spawn(path, argv, env)``: path runs, whatever argv[0] says."""
        from tests.utils.home_rule import home_rule_refusal

        refusal = home_rule_refusal(
            ["x", "-c", "pass"],
            developer_env,
            executable=sys.executable,
            basetemp=basetemp,
        )
        assert refusal is not None and "HOME in the developer home" in refusal

    def test_an_env_with_no_home_breaks_it_when_asked_directly(self, basetemp):
        """Only Popen's guard can add the test's home to the env it is given."""
        from tests.utils.home_rule import home_rule_refusal

        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "USERPROFILE")}
        refusal = home_rule_refusal(
            [sys.executable, "-c", "pass"], env, basetemp=basetemp
        )
        assert refusal is not None and "HOME unset" in refusal

    def test_the_run_temp_roots_are_the_guards(self, request, basetemp):
        from tests.utils.home_rule import run_temp_roots

        conftest = _root_conftest(request.config)
        assert run_temp_roots(basetemp) == conftest._run_temp_roots(basetemp)
        assert any(Path(root) == basetemp for root in run_temp_roots(basetemp))

    def test_the_tests_own_home_is_inside_the_runs_own_directories(self, basetemp):
        from tests.utils.home_rule import inside_the_runs_own_directories

        uv_tools = Path.home() / ".local" / "share" / "uv" / "tools"
        assert inside_the_runs_own_directories(uv_tools, basetemp)

    def test_the_developers_uv_directory_is_not(self, developer_home, basetemp):
        """What tests/utils/tool_guard.py asks before it takes a tool for a test's own."""
        from tests.utils.home_rule import inside_the_runs_own_directories

        uv_tools = developer_home / ".local" / "share" / "uv" / "tools"
        assert not inside_the_runs_own_directories(uv_tools, basetemp)

    @pytest.mark.skipif(os.name == "nt", reason="a POSIX symbolic link")
    def test_a_link_from_the_runs_directories_out_of_them_is_not(
        self, developer_home, tmp_path, basetemp
    ):
        """Judged by where it leads, as the HOME rule judges a path."""
        from tests.utils.home_rule import inside_the_runs_own_directories

        link = tmp_path / "leads-out"
        link.symlink_to(developer_home, target_is_directory=True)
        assert not inside_the_runs_own_directories(link / ".ash", basetemp)


class TestTheRunHeaderNamesToolsItWillNotUse:
    """Tools in the developer's ~/.ash/bin are out of reach once each test has a home."""

    @pytest.fixture
    def header(self, request, monkeypatch, tmp_path):
        conftest = _root_conftest(request.config)
        monkeypatch.setenv(
            "ASH_TEST_DEVELOPER_HOME", json.dumps({"env": {}, "home": str(tmp_path)})
        )
        monkeypatch.delenv("ASH_BIN_PATH", raising=False)
        return lambda: conftest.pytest_report_header(request.config)

    @pytest.mark.unit
    def test_installed_tools_are_named_with_the_way_to_use_them(self, header, tmp_path):
        """PATH, not ASH_BIN_PATH: tests install to ASH_BIN_PATH by default.

        find_executable tries PATH first, so a tool on PATH is found, and nothing is
        installed there.
        """
        bin_dir = tmp_path / ".ash" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "trivy").write_text("", encoding="utf-8")
        text = header()
        assert text is not None
        assert f"does not find the tools in {bin_dir};" in text, text
        if os.name == "nt":
            assert f'$env:PATH = "{bin_dir};$env:PATH"' in text, text
        else:
            assert f'PATH="{bin_dir}:$PATH"' in text, text
        assert "ASH_BIN_PATH=" not in text, text

    @pytest.mark.unit
    def test_nothing_is_said_without_installed_tools(self, header, tmp_path):
        assert header() is None
        (tmp_path / ".ash" / "bin").mkdir(parents=True)
        assert header() is None

    @pytest.mark.unit
    def test_nothing_is_said_when_the_directory_is_on_path(
        self, header, tmp_path, monkeypatch
    ):
        bin_dir = tmp_path / ".ash" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "trivy").write_text("", encoding="utf-8")
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        assert header() is None

    @pytest.mark.unit
    def test_an_ash_bin_path_in_the_home_is_named_with_what_it_does(
        self, header, tmp_path, monkeypatch
    ):
        """It is every test's default install target, so the guard refuses installers."""
        bin_dir = tmp_path / ".ash" / "bin"
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        text = header()
        assert text is not None
        assert f"ASH_BIN_PATH={bin_dir} is in your home" in text, text
        assert "refused" in text, text
        assert str(bin_dir) in text.split("refused", 1)[1], text

    @pytest.mark.integration
    def test_an_ash_bin_path_in_a_temp_dir_inside_the_home_is_not_called_refused(
        self, header, tmp_path, monkeypatch
    ):
        """On Windows %TEMP% is inside the home, and the guard lets installers use it.

        The header and the guard ask the same question, so the header does not say
        such an ASH_BIN_PATH "will be refused" where the guard starts its installers.
        """
        temp = tmp_path / "AppData" / "Local" / "Temp"
        monkeypatch.setenv("PYTEST_DEBUG_TEMPROOT", str(temp))
        monkeypatch.setenv("ASH_BIN_PATH", str(temp / "ash-bin"))
        assert header() is None
        installer = TestInstallersAreRefusedADestinationInTheDeveloperHome
        argv = installer._pinned_installer(temp / "ash-bin")
        assert installer._start(argv) == "started"

    @pytest.mark.unit
    def test_an_ash_bin_path_through_a_link_out_of_the_home_is_still_named(
        self, header, tmp_path, monkeypatch
    ):
        """~/.ash linked out of the home: ~/.ash/bin is still the developer's."""
        elsewhere = tmp_path.parent / f"{tmp_path.name}-elsewhere"
        elsewhere.mkdir()
        TestInstallersAreRefusedADestinationInTheDeveloperHome._link(
            tmp_path / ".ash", elsewhere
        )
        bin_dir = tmp_path / ".ash" / "bin"
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        text = header()
        assert text is not None
        assert f"ASH_BIN_PATH={bin_dir} is in your home" in text, text

    @pytest.mark.unit
    def test_nothing_is_said_when_ash_bin_path_is_set_elsewhere(
        self, header, tmp_path, tmp_path_factory, monkeypatch
    ):
        """Tools are found there, and installing there touches no home."""
        bin_dir = tmp_path / ".ash" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "trivy").write_text("", encoding="utf-8")
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path_factory.mktemp("elsewhere")))
        assert header() is None


@pytest.mark.unit
@pytest.mark.parametrize(
    "windows, advice",
    [
        pytest.param(False, ['PATH="$HOME/.ash/bin:$PATH"'], id="posix"),
        pytest.param(
            True,
            [
                '$env:PATH = "$HOME\\.ash\\bin;$env:PATH" (PowerShell)',
                'set "PATH=%USERPROFILE%\\.ash\\bin;%PATH%" (cmd)',
            ],
            id="windows",
        ),
    ],
)
def test_the_tool_skip_reason_points_at_path(windows, advice):
    """The same advice as the run header, in the tests that skip without the tool.

    In the platform's own shells: ':' and $HOME/... are not what PowerShell or cmd
    takes, and cmd takes neither $HOME nor $env:PATH.
    """
    from tests.utils.helpers import ash_tool_not_found_reason

    reason = ash_tool_not_found_reason("trivy", windows=windows)
    assert reason.startswith("trivy is not on PATH"), reason
    for form in advice:
        assert form in reason, reason
    assert "set ASH_BIN_PATH" not in reason, reason
    default = ash_tool_not_found_reason("trivy")
    assert default == ash_tool_not_found_reason("trivy", windows=os.name == "nt")


@pytest.mark.unit
@pytest.mark.parametrize(
    "windows, advice",
    [
        pytest.param(False, ['PATH="/t/bin:$PATH"'], id="posix"),
        pytest.param(
            True,
            [
                '$env:PATH = "/t/bin;$env:PATH" (PowerShell)',
                'set "PATH=/t/bin;%PATH%" (cmd)',
            ],
            id="windows",
        ),
    ],
)
def test_the_header_gives_path_in_each_of_the_platforms_shells(
    request, windows, advice
):
    """The run header's advice, for either platform, wherever the test runs."""
    text = _root_conftest(request.config)._path_prefixed_with("/t/bin", windows=windows)
    for form in advice:
        assert form in text, text


@pytest.mark.unit
@pytest.mark.parametrize(
    "started_by",
    [
        pytest.param({}, id="a-test-of-a-single-process-run"),
        # A worker's test: the copy of os.environ carries the worker's
        # PYTEST_XDIST_WORKER and its mark of itself, which names another pid.
        pytest.param(
            {"PYTEST_XDIST_WORKER": "gw9", "ASH_TEST_XDIST_WORKER_PID": "1"},
            id="a-test-of-an-xdist-worker",
        ),
    ],
)
def test_a_nested_run_takes_a_home_beside_its_parents_and_puts_everything_back(
    request, monkeypatch, tmp_path, started_by
):
    """The branch of _enter_session_home a pytest started by a test takes.

    It inherits the outer run's session directory and developer record. It must not
    reuse the outer run's ``home`` or record its parent's temporary home as the
    developer's, and _leave_session_home must restore the environment it found. The
    worker name it may inherit goes while it runs, so a pytest that one of its own
    tests starts is not taken for an xdist worker either. The child runs in
    test_home_isolation.py cannot reach this branch: they strip ASH_TEST_SESSION_TMPDIR,
    so their child makes a session directory of its own.
    """
    conftest = _root_conftest(request.config)
    parent = tmp_path / "parent-session"
    (parent / "home").mkdir(parents=True)
    record = json.dumps({"env": {"HOME": "/developer"}, "home": "/developer"})
    monkeypatch.setattr(conftest, "_saved_session_env", None)
    monkeypatch.setattr(conftest, "_created_session_tmpdir", None)
    monkeypatch.setenv("ASH_TEST_SESSION_TMPDIR", str(parent))
    monkeypatch.setenv("ASH_TEST_DEVELOPER_HOME", record)
    # The outer run's owner, which is not this process.
    monkeypatch.setenv("ASH_TEST_HOME_OWNER_PID", "1")
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.delenv("ASH_TEST_XDIST_WORKER_PID", raising=False)
    for name, value in started_by.items():
        monkeypatch.setenv(name, value)
    watched = (
        *conftest._RECORDED_VARS,
        "ASH_TEST_DEVELOPER_HOME",
        "ASH_TEST_HOME_OWNER_PID",
        "ASH_TEST_XDIST_WORKER_PID",
        "PYTEST_XDIST_WORKER",
    )
    before = {name: os.environ.get(name) for name in watched}

    conftest._enter_session_home(parent)
    try:
        home = Path(os.environ["HOME" if os.name != "nt" else "USERPROFILE"])
        assert home.parent == parent, home
        assert home.name.startswith("home-"), home
        assert os.environ["ASH_TEST_DEVELOPER_HOME"] == record
        assert os.environ["ASH_TEST_HOME_OWNER_PID"] == str(os.getpid())
        # environ_value, so a failure names the value rather than printing the
        # environment, which `os.environ.get(...) is None` prints.
        assert environ_value("PYTEST_XDIST_WORKER") is None
        assert environ_value("ASH_TEST_XDIST_WORKER_PID") is None
    finally:
        conftest._leave_session_home()

    assert {name: os.environ.get(name) for name in watched} == before


@pytest.mark.unit
def test_an_xdist_worker_marks_itself_and_keeps_the_runs_home(
    request, monkeypatch, tmp_path
):
    """The branch of _enter_session_home a worker takes: mark itself, nothing else.

    A pytest that one of its tests starts inherits the mark, which names the worker
    rather than itself, and so takes a home of its own. Without the mark it was taken
    for a worker, and imported with the outer test's home.
    """
    conftest = _root_conftest(request.config)
    monkeypatch.setattr(conftest, "_saved_session_env", None)
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw7")
    monkeypatch.setenv("ASH_TEST_HOME_OWNER_PID", "1")
    monkeypatch.delenv("ASH_TEST_XDIST_WORKER_PID", raising=False)
    home_before = os.environ.get("HOME"), os.environ.get("USERPROFILE")

    conftest._enter_session_home(tmp_path)

    assert environ_value("ASH_TEST_XDIST_WORKER_PID") == str(os.getpid())
    # The saved environment is not the operand: a failure would print it.
    saved = conftest._saved_session_env is not None
    assert not saved, "a worker entered a home of its own"
    assert (environ_value("HOME"), environ_value("USERPROFILE")) == home_before


@pytest.mark.unit
class TestTheDevelopersUvCache:
    """``_developer_uv_cache`` names the cache uv would use for the developer.

    The run pins UV_CACHE_DIR to it, so a uv under a test's empty home starts warm. These
    check the derivation on fixed inputs; the test in test_home_isolation.py that compares
    the pin with the developer's environment cannot fail when UV_CACHE_DIR was set, since
    it then compares the value with itself.
    """

    @pytest.fixture
    def uv_cache(self, request):
        if os.name == "nt":
            pytest.skip("uv's Windows cache is under LOCALAPPDATA, which is not moved")
        return _root_conftest(request.config)._developer_uv_cache

    def test_it_is_under_home(self, uv_cache):
        assert uv_cache({"HOME": "/h"}) == os.path.join("/h", ".cache", "uv")

    def test_xdg_cache_home_comes_first(self, uv_cache):
        assert uv_cache({"HOME": "/h", "XDG_CACHE_HOME": "/x"}) == os.path.join(
            "/x", "uv"
        )

    def test_uv_cache_dir_comes_before_both(self, uv_cache):
        """A nested pytest, whose env may lack it, still pins the developer's choice."""
        env = {"HOME": "/h", "XDG_CACHE_HOME": "/x", "UV_CACHE_DIR": "/c"}
        assert uv_cache(env) == "/c"
