"""The tool guard (tests/utils/tool_guard.py) has to fail closed.

A guard that lets a start through, or records nothing, reads exactly like a test
that started no tool. Each case here is one way the guard was measured to fail
open.
"""

from __future__ import annotations

import inspect
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.tool_guard import (
    GUARDED_TOOLS,
    _on_windows,
    install_tool_guard,
    reset_tool_lookup_caches,
)


@pytest.fixture(autouse=True)
def _fresh_lookup_caches():
    reset_tool_lookup_caches()
    yield
    reset_tool_lookup_caches()


def _host_tool(directory: Path, name: str) -> Path:
    """An executable named *name* in *directory*, standing for the host's own copy."""
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / name
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def test_a_lookup_cached_before_the_guard_resolves_to_the_guard(
    monkeypatch, tmp_path_factory
):
    """find_executable caches per process; a path cached before the guard bypassed it."""
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    host = tmp_path_factory.mktemp("host-bin")
    _host_tool(host, "semgrep")
    _host_tool(host, "grype")
    monkeypatch.setenv("PATH", f"{host}{os.pathsep}{os.environ.get('PATH', '')}")
    assert subprocess_utils.find_executable("semgrep") == (host / "semgrep").as_posix()
    assert uv_tool_runner.find_executable("grype") == (host / "grype").as_posix()

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    assert Path(subprocess_utils.find_executable("semgrep")).parent == guard.directory
    assert Path(uv_tool_runner.find_executable("grype")).parent == guard.directory


def test_the_uv_installed_with_ash_does_not_bypass_the_guard(
    monkeypatch, tmp_path_factory
):
    """find_uv_or_none asks for the uv installed with ASH before PATH.

    So with that copy present the uv stand-in first on PATH was never reached, and a
    ``uv tool run`` started the real uv by its absolute path. Simulated here with a
    host uv standing for the one installed with ASH.
    """
    from automated_security_helper.utils import uv_tool_runner

    installed_with_ash = _host_tool(tmp_path_factory.mktemp("ash-scripts"), "uv")
    monkeypatch.setattr(
        uv_tool_runner, "bundled_uv_executable", lambda: str(installed_with_ash)
    )
    assert uv_tool_runner.find_uv_or_none() == str(installed_with_ash)

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    found = uv_tool_runner.find_uv_or_none()
    assert found is not None and Path(found).parent == guard.directory, found


def test_on_windows_a_guarded_name_beats_a_later_exe(monkeypatch, tmp_path_factory):
    """Windows tries <name>.exe over the whole PATH before <name>.bat.

    So the host's semgrep.exe, later on PATH, won over the guard's semgrep.bat,
    and uv and pip console scripts are .exe files on windows-latest. Simulated
    here by reporting Windows to the lookup.
    """
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    later = tmp_path_factory.mktemp("later-on-path")
    _host_tool(later, "semgrep.exe")
    monkeypatch.setenv("PATH", f"{later}{os.pathsep}{os.environ.get('PATH', '')}")

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    found = subprocess_utils.find_executable("semgrep")
    assert found is not None and Path(found).parent == guard.directory, found


def test_the_windows_stand_in_passes_no_arguments_through_cmd(
    monkeypatch, tmp_path_factory
):
    """``%*`` in a .bat line is parsed by cmd, so an argument with & or > ran code."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    text = (guard.directory / "semgrep.bat").read_text(encoding="utf-8")
    assert "%*" not in text, text
    assert "semgrep" in text


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
def test_a_log_path_with_an_apostrophe_still_records(monkeypatch, tmp_path_factory):
    """The log path was single-quoted into sh: an apostrophe gave rc 2 and no record.
    Both logs are written: the starts' and the version probes'."""
    directory = tmp_path_factory.mktemp("guard") / "it's here"

    guard = install_tool_guard(monkeypatch, directory)
    subprocess.run([str(directory / "semgrep"), "scan"], check=False)
    subprocess.run([str(directory / "semgrep"), "--version"], check=False)

    assert guard.started == ["semgrep scan"], guard.started
    assert guard.probes == ["semgrep --version"], guard.probes


def test_the_package_managers_and_converters_are_guarded():
    """npm-audit runs yarn and pnpm audits, cfn-nag installs with gem, and the
    Jupyter converter asks ``jupyter nbconvert --version``."""
    for name in ("yarn", "pnpm", "gem", "jupyter", "jupyter-nbconvert"):
        assert name in GUARDED_TOOLS, name


@pytest.mark.skipif(sys.platform == "win32", reason="runs a POSIX script")
def test_a_start_by_absolute_path_is_recorded(monkeypatch, tmp_path_factory):
    """A tool started by its full path, or under a name not on the list, never meets
    a stand-in; the guard records every process start while it is installed."""
    tool = _host_tool(tmp_path_factory.mktemp("host-bin"), "not-a-listed-tool")

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    subprocess.run([str(tool), "--version"], check=False)

    assert any("not-a-listed-tool" in start for start in guard.started), guard.started


def _popen_event(argv, env=None, cwd=None):
    """What ``subprocess.Popen`` reports to the audit hook for *argv*."""
    from tests.utils import tool_guard

    tool_guard._audit("subprocess.Popen", (None, list(argv), cwd, env))


def test_a_python_child_of_the_test_is_recorded(monkeypatch, tmp_path_factory):
    """This interpreter started by a test can run anything: ``-m uv`` runs the real
    uv, and a ``-c`` child starts a tool by its own path, unaudited. Only ASH's two
    worker invocations are let through."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event([sys.executable, "-m", "uv", "--version"])
    subprocess.run([sys.executable, "-c", "pass"], check=False)

    started = guard.started
    assert any("-m uv --version" in start for start in started), started
    assert any(
        start.endswith("-c pass (not through a stand-in)") for start in started
    ), started


def test_the_detect_secrets_and_cdk_nag_workers_may_start(
    monkeypatch, tmp_path_factory
):
    from automated_security_helper.utils.cdk_nag_worker import _CHILD_BOOTSTRAP

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            "request.json",
            "output.json",
        ]
    )
    _popen_event([sys.executable, "-c", _CHILD_BOOTSTRAP, "request.json", "out.jsonl"])

    assert guard.started == [], guard.started


def test_a_tool_inside_the_landlock_wrapper_is_judged_by_itself(
    monkeypatch, tmp_path_factory
):
    """ASH's sandbox starts this interpreter with the tool after ``--``."""
    from automated_security_helper.utils.sandbox.backends import LANDLOCK_EXEC

    host = tmp_path_factory.mktemp("host-bin")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    wrapper = [
        sys.executable,
        "-I",
        str(LANDLOCK_EXEC),
        "--socket-filter",
        "unix",
        "--",
    ]

    _popen_event([*wrapper, str(host / "some-tool"), "--version"])
    _popen_event([*wrapper, str(guard.directory / "semgrep"), "scan"])
    # The line the stand-in writes when the wrapper runs it.
    with guard.log.open("a", encoding="utf-8") as log:
        log.write("semgrep scan\n")

    assert guard.started == [
        "semgrep scan",
        f"{host / 'some-tool'} --version (not through a stand-in)",
    ], guard.started


# ---------------------------------------------------------------------------
# Version probes
# ---------------------------------------------------------------------------

#: The version token the tool locator reads from a probe's output (its
#: ``_VERSION_TOKEN``), vendored so these tests check what it will read.
VERSION_TOKEN = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+(?:(?:a|b|rc)\d+)?)(?![\w])")


def _probe(stand_in: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(stand_in), *args], capture_output=True, text=True, check=False
    )


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
@pytest.mark.parametrize("name", ["grype", "opengrep", "syft", "trivy", "uv"])
def test_a_version_probe_reads_the_pinned_version(monkeypatch, tmp_path_factory, name):
    """The locator probes ``[<path>, "--version"]`` before it runs a tool, and a
    stand-in that printed nothing read as a tool that is not there."""
    from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    answer = _probe(guard.directory / name, "--version")

    assert answer.returncode == 0, answer
    found = VERSION_TOKEN.search(answer.stdout)
    assert found is not None, answer.stdout
    assert found.group(1) == TOOL_VERSIONS[name].removeprefix("v")
    assert guard.probes == [f"{name} --version"], guard.probes
    assert guard.started == [], guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
@pytest.mark.parametrize(
    "name,constraint",
    # The locator's default ranges for these tools (TOOL_VERSION_CONSTRAINTS);
    # snyk has none.
    [("ferret-scan", ">=2.4.5,<2.6.0"), ("node", ">=18.0.0"), ("snyk", None)],
)
def test_a_version_probe_of_an_unpinned_tool_is_in_its_range(
    monkeypatch, tmp_path_factory, name, constraint
):
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    answer = _probe(guard.directory / name, "--version")

    found = VERSION_TOKEN.search(answer.stdout)
    assert answer.returncode == 0 and found is not None, answer
    if constraint is not None:
        assert Version(found.group(1)) in SpecifierSet(constraint), found.group(1)
    assert guard.probes == [f"{name} --version"], guard.probes


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
def test_a_second_probe_of_the_same_path_is_a_start(monkeypatch, tmp_path_factory):
    """The locator probes each binary once per process, so a second probe is a bug."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    grype = guard.directory / "grype"

    _probe(grype, "--version")
    _probe(grype, "--version")

    assert guard.probes == ["grype --version"], guard.probes
    assert guard.started == [f"{grype} --version (a second --version probe)"], (
        guard.started
    )


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
def test_a_version_call_with_more_arguments_is_a_start(monkeypatch, tmp_path_factory):
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    answer = _probe(guard.directory / "grype", "--version", "--json")

    assert answer.returncode == 1, answer
    assert guard.probes == [], guard.probes
    assert guard.started == ["grype --version --json"], guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup")
def test_a_version_call_by_bare_name_is_a_start(monkeypatch, tmp_path_factory):
    """The locator probes the absolute path it resolved; a bare name is a start."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    subprocess.run(["grype", "--version"], capture_output=True, check=False)

    assert guard.probes == [], guard.probes
    assert guard.started == [
        "grype --version (a --version call not by the stand-in's own path)"
    ], guard.started


def test_a_probe_through_the_landlock_wrapper_is_a_probe(monkeypatch, tmp_path_factory):
    """The locator's probe runs sandboxed, so it can arrive inside the wrapper."""
    from automated_security_helper.utils.sandbox.backends import LANDLOCK_EXEC

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    stand_in = guard.directory / ("grype.bat" if _on_windows() else "grype")
    wrapper = [
        sys.executable,
        "-I",
        str(LANDLOCK_EXEC),
        "--socket-filter",
        "unix",
        "--",
    ]
    more = [str(stand_in), "--version", "--json"]

    _popen_event([*wrapper, str(stand_in), "--version"])
    _popen_event([*wrapper, *more])
    # The lines the stand-in writes when the wrapper runs it: for the probe it
    # answers, and with more arguments.
    with guard.probe_log.open("a", encoding="utf-8") as log:
        log.write(f"{stand_in}\n")
    with guard.log.open("a", encoding="utf-8") as log:
        log.write(guard._as_logged("grype", more) + "\n")

    # Only exactly [<path>, "--version"] after the -- is a probe.
    assert guard.probes == ["grype --version"], guard.probes
    assert guard.started == [guard._as_logged("grype", more)], guard.started


def test_the_windows_stand_in_answers_a_probe_without_reading_arguments(
    monkeypatch, tmp_path_factory
):
    """cmd parses an argument it expands, so the .bat prints the version for every
    call; which call was the probe is decided from the audited argv."""
    from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

    monkeypatch.setattr(platform, "system", lambda: "Windows")

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    text = (guard.directory / "grype.bat").read_text(encoding="utf-8")
    assert "%1" not in text and "%~" not in text and "%*" not in text, text
    assert f"grype {TOOL_VERSIONS['grype'].removeprefix('v')}" in text, text


def test_a_fork_is_recorded(monkeypatch, tmp_path_factory):
    """What a forked child starts is audited in the child, so the test never sees it."""
    from tests.utils import tool_guard

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    tool_guard._audit("os.fork", ())

    assert guard.started == [
        "os.fork() (a forked child, whose starts are not recorded)"
    ], guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
def test_a_start_through_a_stand_in_that_records_nothing_is_recorded(
    monkeypatch, tmp_path_factory
):
    """A stand-in that could not write its line read as no start at all."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    silent = guard.directory / "semgrep"
    silent.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")

    subprocess.run([str(silent), "scan"], check=False)
    subprocess.run([str(guard.directory / "checkov"), "scan"], check=False)

    assert guard.started == [
        "checkov scan",
        f"{silent} scan (through a stand-in that recorded nothing)",
    ], guard.started
    # Both asked a stand-in to run its tool.
    assert guard.tool_starts == guard.started, guard.tool_starts


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup")
def test_a_bare_name_is_looked_up_on_the_childs_path(monkeypatch, tmp_path_factory):
    """A child given a PATH without the stand-ins runs the host's tool by name."""
    host = tmp_path_factory.mktemp("host-bin")
    _host_tool(host, "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(["semgrep", "--version"], env={"PATH": str(host)})

    assert guard.started == ["semgrep --version (not through a stand-in)"], (
        guard.started
    )


# ---------------------------------------------------------------------------
# Starts no audit event reports
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="looks up the C library's system")
def test_a_process_function_looked_up_through_ctypes_is_recorded(
    monkeypatch, tmp_path_factory
):
    """libc's system() and exec*() start a process with no audit event of their own;
    looking one up through ctypes is the event there is."""
    import ctypes

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    ctypes.CDLL(None).system  # looked up, never called

    assert any(start.startswith("ctypes system()") for start in guard.started), (
        guard.started
    )


def test_a_multiprocessing_spawn_is_recorded(monkeypatch, tmp_path_factory):
    """multiprocessing's spawn and forkserver start methods start this interpreter
    through _posixsubprocess, which raises no audit event."""
    from multiprocessing import util

    spawned: list[list[str]] = []

    def no_process(path, args, passfds):
        spawned.append(list(args))
        return 4242

    monkeypatch.setattr(util, "spawnv_passfds", no_process)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    assert (
        util.spawnv_passfds(sys.executable, [sys.executable, "-c", "pass"], ()) == 4242
    )

    assert spawned == [[sys.executable, "-c", "pass"]]
    assert any(
        start.endswith("-c pass (not through a stand-in)") for start in guard.started
    ), guard.started


def test_popens_own_fork_exec_is_not_recorded_a_second_time(
    monkeypatch, tmp_path_factory
):
    """On an interpreter whose Popen calls ``_posixsubprocess.fork_exec`` by
    attribute (Python 3.10), the guard's fork_exec wrapper sees Popen's own
    call right after Popen's audit event recorded the start. Re-recording it
    would misname the start as the first PATH candidate - mostly a file that
    does not exist - and double-count every start a stand-in answered. The
    audit-then-fork_exec sequence is played directly, so the pin holds on
    interpreters whose Popen bound fork_exec at import too. Anything short of
    the proof stays a recorded start, the guard's fail direction."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    search_path = os.environ.get("PATH", "")
    candidates = [
        os.path.join(entry, "git") for entry in search_path.split(os.pathsep) if entry
    ]

    # Popen's audit event arms the skip with its (program, argv); its
    # fork_exec then carries the same argv and that start's PATH candidates.
    record = ("git", ["git", "--version"])

    assert guard._popens_own_fork_exec(["git", "--version"], candidates, record)
    # Not that start: another argv, a candidate running another program, an
    # absolute armed program with a differing candidate, or no program.
    assert not guard._popens_own_fork_exec(["git", "status"], candidates, record)
    assert not guard._popens_own_fork_exec(
        ["git", "--version"], [*candidates, "/usr/bin/not-git"], record
    )
    absolute = ("/usr/bin/git", ["git", "--version"])
    assert guard._popens_own_fork_exec(["git", "--version"], ["/usr/bin/git"], absolute)
    assert not guard._popens_own_fork_exec(
        ["git", "--version"], candidates, (None, ["git", "--version"])
    )


def _fake_fork_exec(monkeypatch):
    """A fake installed before the guard, so no start here runs anything."""
    import _posixsubprocess

    started = []
    monkeypatch.setattr(
        _posixsubprocess, "fork_exec", lambda *args: started.append(args) or 0
    )
    return started


def _direct_fork_exec(argv, env):
    import _posixsubprocess

    return _posixsubprocess.fork_exec(
        [os.fsencode(a) for a in argv],
        [os.fsencode(sys.executable)],
        True,
        (),
        None,
        [os.fsencode(f"{k}={v}") for k, v in env.items()],
    )


def _developer_environment(developer_home):
    home = str(developer_home)
    return {**os.environ, "HOME": home, "USERPROFILE": home}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_a_direct_fork_exec_repeating_a_recorded_start_is_held(
    monkeypatch, tmp_path_factory, developer_home
):
    """A direct fork_exec that repeats the last recorded start's argv is a
    start of its own, held to the HOME rule and recorded. Where Popen bound
    fork_exec at import, no call the wrapper sees is ever Popen's, so the
    first repeat is held; where Popen calls by attribute, the audit record
    arms exactly one skip - standing for Popen's own imminent fork_exec -
    and the repeat after that is held. Unbounded, the skip let a direct
    repeat run with the developer's HOME, unrecorded."""
    started = _fake_fork_exec(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    # The audit event, as Popen raises it before its own fork_exec: the only
    # thing that arms a skip. Raised directly: sys.audit itself starts
    # nothing, so the child-process gate reads no launch here, where a
    # same-file helper taking the argv would be read as a launcher.
    sys.audit("subprocess.Popen", sys.executable, _QUIET_PYTHON, None, None)
    if not hasattr(subprocess, "_fork_exec"):
        # The one armed skip, spent on the call standing for Popen's own.
        _direct_fork_exec(_QUIET_PYTHON, dict(os.environ))
        assert len(started) == 1, started
    before = len(started)

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert len(started) == before, started
    assert len(guard.home_refusals) == 1, guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
@pytest.mark.skipif(
    not hasattr(subprocess, "_fork_exec"),
    reason="Popen itself runs through the wrapped attribute here; the "
    "by-attribute branch is pinned by the cell above",
)
def test_a_direct_fork_exec_after_a_real_popen_of_the_same_argv_is_held(
    monkeypatch, tmp_path_factory, tmp_path, developer_home
):
    """The product-side sequence: a real Popen records the start (bound at
    import, it never reaches the wrapper), and the direct fork_exec that
    follows is the only call the wrapper sees - held, never skipped."""
    started = _fake_fork_exec(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    home = tmp_path / "home"
    home.mkdir()
    child_env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    # The call sits outside the assert: a failing assert prints each call in
    # it with its arguments, and env= would print the whole environment.
    child = subprocess.Popen(_QUIET_PYTHON, env=child_env)
    assert child.wait() == 0
    assert started == [], "Popen reached the wrapped fork_exec on this interpreter"

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert started == [], started
    assert len(guard.home_refusals) == 1, guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_a_direct_fork_exec_with_no_record_before_it_is_held(
    monkeypatch, tmp_path_factory, developer_home
):
    """Must-fire control: with no record, nothing is armed and nothing is
    Popen's, on any interpreter."""
    started = _fake_fork_exec(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert started == [], started
    assert len(guard.home_refusals) == 1, guard.home_refusals


# The by-attribute branch, run on any interpreter: dropping
# subprocess._fork_exec BEFORE the guard is installed makes the wrapper read
# this interpreter as one whose Popen calls fork_exec by attribute. No cell
# below starts a real Popen (which would need the attribute); each Popen is
# played as a 3.10 Popen plays it - its audit event, then its own fork_exec
# through the wrapped attribute, with one candidate per PATH directory.
_CANDIDATE_DIRS = ["/nonexistent/under-a", "/nonexistent/under-b"]


def _by_attribute(monkeypatch):
    if hasattr(subprocess, "_fork_exec"):
        monkeypatch.delattr(subprocess, "_fork_exec")


def _popen_audit_event(name, argv):
    sys.audit("subprocess.Popen", name, list(argv), None, None)


def _popens_own_call(name, argv):
    import _posixsubprocess

    return _posixsubprocess.fork_exec(
        [os.fsencode(a) for a in argv],
        [os.fsencode(os.path.join(d, name)) for d in _CANDIDATE_DIRS],
        True,
        (),
        None,
        [os.fsencode(f"{k}={v}") for k, v in os.environ.items()],
    )


def _in_a_thread(target):
    """*target* run to completion in its own thread; its error, if it raised."""
    outcome: dict = {}

    def _runner():
        try:
            target()
        except BaseException as error:  # pytest.fail raises BaseException
            outcome["error"] = error

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join(30)
    assert not thread.is_alive(), "the thread did not finish"
    return outcome.get("error")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_a_held_direct_calls_own_record_arms_no_skip(
    monkeypatch, tmp_path_factory, developer_home
):
    """Two direct fork_execs of one argv, no Popen anywhere: the first is held
    (it passes, with this process's HOME) and recorded; its record must not
    arm a skip that lets the second, with the developer's HOME, pass unheld.
    Arming on every appended record did exactly that."""
    started = _fake_fork_exec(monkeypatch)
    _by_attribute(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _direct_fork_exec(_QUIET_PYTHON, dict(os.environ))
    assert len(started) == 1, started
    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert len(started) == 1, started
    assert len(guard.home_refusals) == 1, guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_a_deduplicated_popen_repeat_still_skips_its_own_fork_exec(
    monkeypatch, tmp_path_factory
):
    """Two identical Popens in a row (the same tool query twice). The second's
    audit record is deduplicated, so arming on appended records armed nothing
    for it, and its own fork_exec was recorded again under the first PATH
    candidate's path - a file that mostly does not exist. The arm rides the
    audit EVENT, deduplicated or not, so both own-calls are skipped and the
    start is recorded once, under its name."""
    started = _fake_fork_exec(monkeypatch)
    _by_attribute(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    before = len(guard._spawned)
    argv = ["a-repeated-tool", "--version"]

    for _ in range(2):
        _popen_audit_event("a-repeated-tool", argv)
        _popens_own_call("a-repeated-tool", argv)

    assert len(started) == 2, started
    programs = [entry[0] for entry in guard._spawned[before:]]
    assert programs == ["a-repeated-tool"], programs


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_two_threads_interleaved_popens_each_record_once(monkeypatch, tmp_path_factory):
    """A records, B records, A's own fork_exec, B's own fork_exec - the order
    a thread pool produces (the scanner executor runs scanners on one). With a
    single process-wide arm, B's record spent A's, and each own-call was
    recorded again; keyed by thread, each Popen keeps its own."""
    started = _fake_fork_exec(monkeypatch)
    _by_attribute(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    before = len(guard._spawned)
    argv_a, argv_b = ["tool-a", "--version"], ["tool-b", "--version"]
    a_recorded, b_recorded, a_called = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )

    def _popen_a():
        _popen_audit_event("tool-a", argv_a)
        a_recorded.set()
        assert b_recorded.wait(30)
        _popens_own_call("tool-a", argv_a)
        a_called.set()

    def _popen_b():
        assert a_recorded.wait(30)
        _popen_audit_event("tool-b", argv_b)
        b_recorded.set()
        assert a_called.wait(30)
        _popens_own_call("tool-b", argv_b)

    errors: list = []

    def _run(target):
        try:
            target()
        except BaseException as error:  # pytest.fail raises BaseException
            errors.append(error)

    thread_a = threading.Thread(target=_run, args=(_popen_a,))
    thread_b = threading.Thread(target=_run, args=(_popen_b,))
    thread_a.start()
    thread_b.start()
    thread_a.join(30)
    thread_b.join(30)

    assert not thread_a.is_alive() and not thread_b.is_alive()
    assert errors == [], errors
    assert len(started) == 2, started
    programs = [entry[0] for entry in guard._spawned[before:]]
    assert programs == ["tool-a", "tool-b"], programs


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_another_threads_direct_call_does_not_spend_a_popens_arm(
    monkeypatch, tmp_path_factory, developer_home
):
    """Another thread's direct fork_exec of the same argv lands between A's
    audit record and A's own fork_exec. It is not Popen's and runs on another
    thread, so it is held - and A's own call, following on A's thread, is
    still skipped."""
    started = _fake_fork_exec(monkeypatch)
    _by_attribute(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    holds = _count_holds(monkeypatch)
    # Raised directly: sys.audit itself starts nothing, so the child-process
    # gate reads no launch here, where a same-file helper taking the argv
    # would be read as a launcher.
    sys.audit("subprocess.Popen", sys.executable, _QUIET_PYTHON, None, None)

    error = _in_a_thread(
        lambda: _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))
    )

    assert isinstance(error, pytest.fail.Exception), error
    assert "HOME in the developer home" in str(error), error
    assert started == [], started
    # A's own fork_exec, on A's thread, still has its arm: it runs, and it is
    # SKIPPED, pinned by the HOME-rule calls - a skipped call asks the rule
    # nothing, while a recorded one would ask and pass with this HOME.
    _popens_own_call(os.path.basename(sys.executable), _QUIET_PYTHON)
    assert len(started) == 1, started
    assert len(holds) == 1, holds
    assert len(guard.home_refusals) == 1, guard.home_refusals


def _count_holds(monkeypatch):
    """Every time the wrapper asks the HOME rule about a start: a skipped
    call asks nothing, so the count tells a skip from a record-and-pass."""
    from tests.utils import tool_guard

    holds: list = []
    original = tool_guard._hold_to_the_home_rule

    def counting(guard, what, *args, **kwargs):
        holds.append(what)
        return original(guard, what, *args, **kwargs)

    monkeypatch.setattr(tool_guard, "_hold_to_the_home_rule", counting)
    return holds


def _played_execute_child(route, between=None):
    """What a 3.10 Popen._execute_child does for *route*: its audit event,
    then its own fork_exec ('fork_exec'), an os.posix_spawn event and no
    fork_exec ('posix_spawn'), or an env error before any start ('raises').
    *between* runs after the audit event, before the route's next step.
    The command line is _QUIET_PYTHON by name at each site, so the
    child-process gate reads the -c "pass", which imports nothing."""
    import _posixsubprocess

    sys.audit("subprocess.Popen", sys.executable, _QUIET_PYTHON, None, None)
    if between is not None:
        between()
    if route == "fork_exec":
        return _posixsubprocess.fork_exec(
            [os.fsencode(a) for a in _QUIET_PYTHON],
            [os.fsencode(sys.executable)],
            True,
            (),
            None,
            [os.fsencode(f"{k}={v}") for k, v in os.environ.items()],
        )
    if route == "posix_spawn":
        sys.audit("os.posix_spawn", sys.executable, _QUIET_PYTHON, dict(os.environ))
        return 0
    raise ValueError("illegal environment variable name")


def _played_popen(route, between=None):
    """One played Popen, through the class attribute as Popen calls it, so
    the guard's bounding of the arm to _execute_child applies."""
    execute_child = subprocess.Popen._execute_child
    try:
        return execute_child(route, between)
    except ValueError:
        if route != "raises":
            raise
        return None


def _popen_route_set_up(monkeypatch, tmp_path_factory):
    """The by-attribute branch with Popen played through _execute_child: the
    fake fork_exec and the played _execute_child go in BEFORE the guard, so
    the guard wraps both as it would wrap 3.10's own."""
    started = _fake_fork_exec(monkeypatch)
    monkeypatch.setattr(subprocess.Popen, "_execute_child", _played_execute_child)
    _by_attribute(monkeypatch)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    return guard, started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
@pytest.mark.parametrize("route", ["raises", "posix_spawn"])
def test_a_popen_with_no_own_fork_exec_leaves_no_arm_for_the_next_call(
    monkeypatch, tmp_path_factory, developer_home, route
):
    """A 3.10 Popen whose own fork_exec never comes - it took the posix_spawn
    route, or raised on its environment before any start - must not leave its
    thread's arm set: the next direct fork_exec on that thread is a start of
    its own and is held."""
    guard, started = _popen_route_set_up(monkeypatch, tmp_path_factory)
    _played_popen(route)

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert started == [], started
    assert len(guard.home_refusals) == 1, guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_a_popen_whose_own_fork_exec_ran_then_a_direct_call_is_held(
    monkeypatch, tmp_path_factory, developer_home
):
    """Must-not-fire control: on the default route the arm was spent by
    Popen's own call, and the following direct call is held as before."""
    guard, started = _popen_route_set_up(monkeypatch, tmp_path_factory)
    _played_popen("fork_exec")

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert len(started) == 1, started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
@pytest.mark.parametrize("route", ["raises", "posix_spawn"])
def test_a_later_thread_with_a_reused_ident_finds_no_arm(
    monkeypatch, tmp_path_factory, developer_home, route
):
    """Thread idents are reused after a join, so a stale arm left by an
    exited thread would be spent by its ident's successor. The arm is bounded
    to the Popen call that set it, so the successor finds none."""
    guard, started = _popen_route_set_up(monkeypatch, tmp_path_factory)
    first = _in_a_thread_with_ident(lambda: _played_popen(route))
    assert first["error"] is None, first
    # Ident reuse is opportunistic (measured: first-try reuse 3000/3000 on
    # 3.14, 82.3% on 3.12 under -n 0 and 94.6% under -n 4, so 50 tries go
    # unreused in 0.13-0.73% of 3.12 runs). Spin new threads until one lands
    # on the exited thread's ident; a non-reused try exercises nothing stale
    # and must be held all the same.
    for _ in range(50):
        second = _in_a_thread_with_ident(
            lambda: _direct_fork_exec(
                _QUIET_PYTHON, _developer_environment(developer_home)
            )
        )
        assert isinstance(second["error"], pytest.fail.Exception), second["error"]
        assert "HOME in the developer home" in str(second["error"]), second["error"]
        if second["ident"] == first["ident"]:
            break
    else:
        pytest.skip("the ident was not reused in 50 tries")
    assert started == [], started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX fork_exec")
def test_another_live_thread_finds_no_arm_either(
    monkeypatch, tmp_path_factory, developer_home
):
    """Must-not-fire control for the reuse cell: the same would-be-stale arm,
    with the direct call made on the main thread instead."""
    guard, started = _popen_route_set_up(monkeypatch, tmp_path_factory)
    first = _in_a_thread_with_ident(lambda: _played_popen("raises"))
    assert first["error"] is None, first
    assert first["ident"] != threading.get_ident()

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        _direct_fork_exec(_QUIET_PYTHON, _developer_environment(developer_home))

    assert started == [], started


def _in_a_thread_with_ident(target):
    """*target* run to completion in its own thread: its error and ident."""
    outcome: dict = {"error": None}

    def _runner():
        outcome["ident"] = threading.get_ident()
        try:
            target()
        except BaseException as error:  # pytest.fail raises BaseException
            outcome["error"] = error

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join(30)
    assert not thread.is_alive(), "the thread did not finish"
    return outcome


# ---------------------------------------------------------------------------
# Tool starts: what tests/unit/conftest.py fails a unit test on
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="runs the POSIX stand-in")
def test_a_stand_in_asked_to_run_is_a_tool_start_and_its_answered_probe_is_not(
    monkeypatch, tmp_path_factory
):
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _probe(guard.directory / "semgrep", "--version")
    _probe(guard.directory / "semgrep", "--version")
    subprocess.run(["semgrep", "--version"], check=False, capture_output=True)
    subprocess.run(["checkov", "scan"], check=False)

    assert guard.tool_starts == ["checkov scan"], guard.tool_starts
    # The answered probes are starts all the same, for a test of the locator.
    assert len(guard.started) == 3, guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="runs POSIX scripts")
def test_a_guarded_tool_by_its_path_is_a_tool_start_unless_the_test_owns_it(
    monkeypatch, tmp_path_factory
):
    """The host's ``/home/user/.local/bin/uv``, run by its path, never meets a
    stand-in; a fake ``uv`` the test wrote under its own directory is not a tool."""
    host = tmp_path_factory.mktemp("host-bin")
    owned = tmp_path_factory.mktemp("owned")
    _host_tool(host, "uv")
    _host_tool(owned, "uv")
    guard = install_tool_guard(
        monkeypatch, tmp_path_factory.mktemp("guard-bin"), own_directories=(owned,)
    )

    subprocess.run([str(host / "uv"), "tool", "list"], check=True)
    subprocess.run([str(owned / "uv"), "tool", "list"], check=True)

    assert guard.tool_starts == [f"{host / 'uv'} tool list (not through a stand-in)"], (
        guard.tool_starts
    )
    assert len(guard.started) == 2, guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup and links")
def test_a_tool_is_known_by_the_file_it_resolves_to(monkeypatch, tmp_path_factory):
    """By the name a bare one resolves to on the child's PATH, and by the name of
    the file a link points at: a link of the test's own named ``uv`` to ``true`` is
    not uv, and a link named anything to a uv outside it is."""
    host = tmp_path_factory.mktemp("host-bin")
    owned = tmp_path_factory.mktemp("owned")
    real_uv = _host_tool(host, "uv")
    (owned / "uv").symlink_to(_host_tool(host, "true-ish"))
    (owned / "renamed").symlink_to(real_uv)
    guard = install_tool_guard(
        monkeypatch, tmp_path_factory.mktemp("guard-bin"), own_directories=(owned,)
    )

    _popen_event(["uv", "tool", "list"], env={"PATH": str(host)})
    _popen_event([str(owned / "uv"), "tool", "list"])
    _popen_event([str(owned / "renamed"), "tool", "list"])
    _popen_event(["no-such-tool-anywhere"], env={"PATH": str(host)})
    _popen_event([str(host / "missing" / "uv"), "tool", "list"])

    assert guard.tool_starts == [
        "uv tool list (not through a stand-in)",
        f"{owned / 'renamed'} tool list (not through a stand-in)",
    ], guard.tool_starts


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")
def test_a_relative_program_is_found_from_the_childs_directory(
    monkeypatch, tmp_path_factory
):
    host = tmp_path_factory.mktemp("host")
    _host_tool(host / "bin", "uv")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(["./bin/uv", "tool", "list"], cwd=str(host))
    _popen_event(["uv", "tool", "list"], env={"PATH": "bin"}, cwd=str(host))

    assert guard.tool_starts == [
        "./bin/uv tool list (not through a stand-in)",
        "uv tool list (not through a stand-in)",
    ], guard.tool_starts


@pytest.mark.parametrize(
    "args",
    [
        ["-m", "uv", "tool", "list"],
        ["-I", "-m", "uv"],
        ["-Im", "uv"],
        ["-muv"],
        ["-W", "ignore", "-X", "utf8", "-m", "uv.__main__"],
        ["--check-hash-based-pycs", "never", "-m", "bandit"],
        ["-m", "detect_secrets.main"],
        ["-m", "nbconvert"],
    ],
)
def test_a_python_running_a_tools_module_is_a_tool_start(
    monkeypatch, tmp_path_factory, args
):
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event([sys.executable, *args])

    assert len(guard.tool_starts) == 1, guard.tool_starts


@pytest.mark.parametrize(
    "args",
    [
        ["-m", "pytest"],
        ["-c", "import uv"],
        ["-Wignore", "-c", "pass"],
        ["script.py", "-m", "uv"],
        ["-", "-m", "uv"],
        ["-X", "-m", "-c", "pass"],
    ],
)
def test_a_python_running_anything_else_is_no_tool_start(
    monkeypatch, tmp_path_factory, args
):
    """``-X -m`` gives -X the value ``-m``; what follows a script or ``-`` is its own."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event([sys.executable, *args])

    assert guard.tool_starts == [], guard.tool_starts
    assert len(guard.started) == 1, guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links and PATH lookup")
def test_only_the_real_git_is_let_through(monkeypatch, tmp_path_factory):
    """By the file git resolves to: a link named git to another program, or another
    git first on a child's PATH, is a start like any other."""
    links = tmp_path_factory.mktemp("links")
    (links / "git").symlink_to(_host_tool(tmp_path_factory.mktemp("host"), "not-git"))
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    subprocess.run(["git", "--version"], check=True, capture_output=True)
    subprocess.run([str(links / "git"), "--version"], check=True)
    _popen_event(["git", "status"], env={"PATH": str(links)})

    assert guard.started == [
        f"{links / 'git'} --version (not through a stand-in)",
        "git status (not through a stand-in)",
    ], guard.started


def test_a_fork_or_a_library_lookup_is_no_tool_start(monkeypatch, tmp_path_factory):
    """What either starts is not seen, so neither names a tool."""
    from tests.utils import tool_guard

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    tool_guard._audit("os.fork", ())
    tool_guard._audit("ctypes.dlsym", (None, "system"))

    assert len(guard.started) == 2, guard.started
    assert guard.tool_starts == [], guard.tool_starts


def _probe_answers() -> list:
    """What ASH's probes answer, asked without starting anything once stubbed."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base,
    )
    from automated_security_helper.utils import (
        content_db_staleness,
        pre_installed_tool,
        uv_tool_runner,
    )

    def _trivy_db_age():
        try:
            content_db_staleness.MEASURERS["trivy-db"](None)
        except ValueError as error:
            # The error's first clause; the rest names the stub or trivy's stderr.
            return str(error).split(":", 1)[0]
        return "a trivy database was dated"

    return [
        uv_tool_runner.UVToolRunner(uv_executable="uv").is_uv_available(),
        uv_tool_runner.find_uv_or_none(),
        uv_tool_runner.get_uv_tool_command("no-such-tool-anywhere"),
        pre_installed_tool._run(["uv", "--version"], 5),
        OpengrepScanner._get_opengrep_version(None),
        _trivy_scanner_base.trivy_default_misconfig_scanners("trivy", ["repository"]),
        _trivy_db_age(),
    ]


def test_the_child_probe_stubs_answer_as_stub_tool_probes_does(monkeypatch, tmp_path):
    """In a child started with ``-I``, as the MCP session tests start theirs, and with
    an empty PATH, so a probe that was not stubbed fails rather than finds a uv."""
    from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS, stub_tool_probes

    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(
                CHILD_TOOL_PROBE_STUBS
                + "import json\n"
                + inspect.getsource(_probe_answers)
                + "print(json.dumps(_probe_answers()))\n"
            ),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(tmp_path)},
        cwd=tmp_path,
        check=True,
    )
    stub_tool_probes(monkeypatch)
    monkeypatch.setenv("PATH", str(tmp_path))
    reset_tool_lookup_caches()

    assert json.loads(child.stdout.strip().splitlines()[-1]) == _probe_answers()
    assert _probe_answers() == [
        False,
        None,
        None,
        None,
        None,
        None,
        "`trivy version --format json` printed nothing (exit 1)",
    ]


# ---------------------------------------------------------------------------
# The unit tests' opt-out and HOME check
# ---------------------------------------------------------------------------


def test_the_real_tools_opt_out_needs_a_listed_module_and_a_reason():
    from tests.utils.tool_guard import real_tools_opt_out_refusal

    allowed = frozenset({"test_listed.py"})

    assert real_tools_opt_out_refusal("why", "test_listed.py", allowed) is None
    unlisted = real_tools_opt_out_refusal("why", "test_other.py", allowed)
    assert unlisted is not None and "test_other.py" in unlisted, unlisted
    for reason in (None, "", "   "):
        missing = real_tools_opt_out_refusal(reason, "test_listed.py", allowed)
        assert missing is not None and "reason" in missing, missing


def test_every_file_left_in_a_home_is_listed(tmp_path):
    from tests.utils.tool_guard import files_left_in

    (tmp_path / ".config" / "tool").mkdir(parents=True)
    (tmp_path / ".cache").mkdir()
    (tmp_path / ".config" / "tool" / "settings.yml").write_text("x", encoding="utf-8")
    (tmp_path / ".lock").write_text("", encoding="utf-8")

    assert files_left_in(tmp_path) == [".config/tool/settings.yml", ".lock"]


def test_ashs_own_state_is_not_a_tools_file(tmp_path):
    """Install receipts, the MCP session configs and the container records are ASH's,
    written into the test's HOME on purpose; a name that only begins like one of them
    is not. Nor is the rest of ``.ash``: a tool copied into ``.ash/bin`` ran as one of
    the test's own programs, and was never seen."""
    from tests.utils.tool_guard import tool_files_left_in

    for name in (
        ".ash/install-receipts/abc/tool.json",
        ".ash/state/containers/ash-scan-1-0a1b2c3d.json",
        ".ash/state/other/file",
        ".ash/bin/grype",
        ".ash/other",
        ".cache/ash-mcp/session/config/ash.yaml",
        ".ash-other/file",
        ".cache/ash-mcp-other/file",
        ".cache/checkov/update_checker_cache.json",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    assert tool_files_left_in(tmp_path) == [
        ".ash-other/file",
        ".ash/bin/grype",
        ".ash/other",
        ".ash/state/other/file",
        ".cache/ash-mcp-other/file",
        ".cache/checkov/update_checker_cache.json",
    ]


# ---------------------------------------------------------------------------
# Starts with no event of their own, and starts through a launcher
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="no _posixsubprocess on Windows")
def test_a_direct_fork_exec_is_recorded(monkeypatch, tmp_path_factory):
    """fork_exec raises no audit event. subprocess calls the one it bound when it was
    imported, and raises its own; a test calling fork_exec started a tool unseen."""
    import _posixsubprocess

    calls = []

    def no_process(*args, **kwargs):
        calls.append(args)
        return 4242

    monkeypatch.setattr(_posixsubprocess, "fork_exec", no_process)
    host = _host_tool(tmp_path_factory.mktemp("host-bin"), "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    pid = _posixsubprocess.fork_exec(
        [str(host), "scan"], [os.fsencode(host)], True, (), None, None
    )

    assert (pid, len(calls)) == (4242, 1)
    assert guard.tool_starts == [f"{host} scan (not through a stand-in)"], (
        guard.tool_starts
    )


def test_a_process_a_running_forkserver_forks_is_recorded(
    monkeypatch, tmp_path_factory
):
    """Once the forkserver runs, a new process is asked for over its socket: no
    event, and the guard's spawnv_passfds wrapper saw only the server's own start."""
    from multiprocessing import forkserver

    asked = []

    def no_process(fds):
        asked.append(list(fds))
        return 3, 4

    monkeypatch.setattr(forkserver, "connect_to_new_process", no_process)
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    assert forkserver.connect_to_new_process([]) == (3, 4)

    assert asked == [[]]
    assert guard.started == [
        (
            "multiprocessing forkserver start (a child the forkserver forks, "
            "whose starts are not recorded)"
        )
    ], guard.started
    assert guard.tool_starts == []


@pytest.mark.parametrize(
    "name", ["syscall", "clone", "clone3", "_Fork", "wordexp", "pidfd_spawn"]
)
def test_each_c_route_to_a_new_process_is_recorded_when_looked_up(
    monkeypatch, tmp_path_factory, name
):
    """syscall(SYS_clone) then execv, _Fork() then execv, and wordexp("$(tool)")
    started a tool with only the lookup to see."""
    from tests.utils import tool_guard

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    tool_guard._audit("ctypes.dlsym", (None, name))

    assert guard.started == [
        f"ctypes {name}() (looked up from a C library; what it starts is not recorded)"
    ], guard.started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup")
@pytest.mark.parametrize(
    "launch",
    [
        pytest.param(
            lambda host: ["env", f"PATH={host}", "semgrep", "scan"], id="path"
        ),
        pytest.param(
            lambda host: ["env", "-i", f"PATH={host}", "semgrep", "scan"], id="cleared"
        ),
        pytest.param(
            lambda host: ["/usr/bin/env", "--", str(host / "semgrep"), "scan"],
            id="by-path",
        ),
        pytest.param(
            lambda host: ["env", "-S", f"{host / 'semgrep'} scan"], id="split-string"
        ),
        pytest.param(
            lambda host: [
                "env",
                "-u",
                "HOME",
                "env",
                f"PATH={host}",
                "semgrep",
                "scan",
            ],
            id="env-in-env",
        ),
    ],
)
def test_a_tool_started_through_env_is_a_tool_start(
    monkeypatch, tmp_path_factory, launch
):
    """``env PATH=<dir> tool`` ran the tool found on the PATH it gave: the start was
    judged as env."""
    host = tmp_path_factory.mktemp("host-bin")
    _host_tool(host, "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(launch(host))

    assert len(guard.tool_starts) == 1, guard.tool_starts
    assert guard.tool_starts[0].endswith(" scan (not through a stand-in)"), (
        guard.tool_starts
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup")
def test_env_running_anything_else_is_no_tool_start(monkeypatch, tmp_path_factory):
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(["env"])
    _popen_event(["env", "FOO=1", "true"])

    assert len(guard.started) == 2, guard.started
    assert guard.tool_starts == [], guard.tool_starts


# ---------------------------------------------------------------------------
# A probe is a stand-in's own answer
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")
@pytest.mark.parametrize("linked_as", ["semgrep-host", "semgrep"])
def test_a_host_tool_in_the_stand_in_directory_is_no_probe(
    monkeypatch, tmp_path_factory, linked_as
):
    """A lone --version to any file in the stand-ins' directory counted as a probe,
    so a host tool linked there, under another name or in place of a stand-in, ran
    and passed. A stand-in writes a line for the probe it answers; that tool did not.
    """
    host = _host_tool(tmp_path_factory.mktemp("host-bin"), "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    link = guard.directory / linked_as
    link.unlink(missing_ok=True)
    link.symlink_to(host)

    subprocess.run([str(link), "--version"], check=True)

    assert guard.probes == [], guard.probes
    assert guard.tool_starts == [
        f"{link} --version (a --version call no stand-in answered)"
    ], guard.tool_starts


# ---------------------------------------------------------------------------
# git, and what its configuration tells it to run
# ---------------------------------------------------------------------------


def _clean_git_env(tmp_path: Path) -> dict:
    """os.environ as checkout_context leaves it: no system config, an empty global
    one, none of git's program variables, and the search for a repository stopping
    at *tmp_path*."""
    from tests.utils.tool_guard import GIT_PROGRAM_VARIABLES

    env = {
        name: value
        for name, value in os.environ.items()
        if name not in GIT_PROGRAM_VARIABLES and not name.startswith("GIT_CONFIG")
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CEILING_DIRECTORIES=str(tmp_path),
    )
    return env


def _repository(tmp_path: Path, config: str = "", hook: bool = False) -> Path:
    """A directory with a ``.git`` holding what ``git init`` writes, plus *config*."""
    repo = tmp_path / "repo"
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit.sample").write_text("#!/bin/sh\n", encoding="utf-8")
    if hook:
        (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        (hooks / "pre-commit").chmod(0o755)
    (repo / ".git" / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n" + config,
        encoding="utf-8",
    )
    return repo


GIT_RUNNING_A_PROGRAM = [
    pytest.param(["-c", "alias.x=!true", "x"], {}, "", False, id="c-alias"),
    pytest.param(
        ["-c", "core.fsmonitor=true-ish", "status"], {}, "", False, id="c-fsmonitor"
    ),
    pytest.param(["--exec-path=/nowhere", "status"], {}, "", False, id="exec-path"),
    pytest.param(
        ["st"],
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "alias.st",
            "GIT_CONFIG_VALUE_0": "!true",
        },
        "",
        False,
        id="env-config-count",
    ),
    pytest.param(
        ["diff"], {"GIT_EXTERNAL_DIFF": "true"}, "", False, id="env-external-diff"
    ),
    pytest.param(
        ["status"], {}, "[core]\n\tfsmonitor = /bin/true\n", False, id="repo-fsmonitor"
    ),
    pytest.param(["log"], {}, "[core]\n\tpager = less\n", False, id="repo-pager"),
    pytest.param(
        ["status"],
        {},
        "[include]\n\tpath = elsewhere.gitconfig\n",
        False,
        id="repo-include",
    ),
]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.parametrize("args,env,config,allowed", GIT_RUNNING_A_PROGRAM)
def test_a_git_told_to_run_a_program_is_not_only_git(
    tmp_path, args, env, config, allowed
):
    """The real git ran a hook, with refused=[], in each of these ways."""
    from tests.utils.tool_guard import popen_runs_only_git, real_git

    git = real_git()
    if git is None:
        pytest.skip("no git on PATH")
    repo = _repository(tmp_path, config)

    # Each answer is taken into a local before it is asserted on: the environment
    # is os.environ's, and a failing assertion would print it as the call's argument.
    only_git = popen_runs_only_git(
        git, ["git", *args], env={**_clean_git_env(tmp_path), **env}, cwd=repo
    )
    assert only_git is allowed


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
def test_a_repository_with_a_hook_or_a_config_naming_a_program(tmp_path):
    from tests.utils.tool_guard import why_git_may_run_a_program

    hooked = _repository(tmp_path / "a", hook=True)
    env = _clean_git_env(tmp_path)
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text("[alias]\n\tx = !true\n", encoding="utf-8")
    plain = _repository(tmp_path / "b")

    # Each answer is taken into a local before it is asserted on: env is
    # os.environ's, and a failing assertion would print it as the call's argument.
    hooks = why_git_may_run_a_program(["git", "commit"], env, str(hooked)) or ""
    assert "hooks" in hooks
    hooks_off = why_git_may_run_a_program(
        ["git", "-c", f"core.hooksPath={os.devnull}", "commit"], env, str(hooked)
    )
    assert hooks_off is None
    global_alias = (
        why_git_may_run_a_program(
            ["git", "x"], {**env, "GIT_CONFIG_GLOBAL": str(global_config)}, str(plain)
        )
        or ""
    )
    assert "global.gitconfig" in global_alias
    no_system = {k: v for k, v in env.items() if k != "GIT_CONFIG_NOSYSTEM"}
    system = why_git_may_run_a_program(["git", "status"], no_system, str(plain)) or ""
    assert "system config" in system


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(
            [
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "--literal-pathspecs",
                "ls-files",
                "-z",
                "--",
                ".",
            ],
            id="ash-ls-files",
        ),
        pytest.param(
            ["-c", "core.quotePath=false", "diff", "--name-only", "-z", "main...HEAD"],
            id="ash-diff",
        ),
        pytest.param(
            ["-c", f"core.excludesFile={os.devnull}", "init", "-q"], id="test-git"
        ),
        pytest.param(["rev-parse", "--show-toplevel"], id="plain"),
    ],
)
def test_the_git_ash_starts_is_only_git(tmp_path, args):
    """ASH's own git commands, in a repository whose config sets an fsmonitor: its
    ls-files turns that off on the command line, which git reads in its place."""
    from tests.utils.tool_guard import popen_runs_only_git, real_git

    git = real_git()
    if git is None:
        pytest.skip("no git on PATH")
    fsmonitor = (
        "[core]\n\tfsmonitor = /bin/true\n"
        if args[1:2] == ["core.fsmonitor=false"]
        else ""
    )
    repo = _repository(tmp_path, fsmonitor)

    # Out of the assertion: the environment is os.environ's.
    only_git = popen_runs_only_git(
        git, ["git", *args], env=_clean_git_env(tmp_path), cwd=repo
    )
    assert only_git


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
def test_the_git_directory_read_is_the_one_git_uses(tmp_path):
    """--git-dir wins over GIT_DIR, and GIT_COMMON_DIR names where the shared config
    is, as git takes them. Read the other way, the guard judged a config git does not
    read, and missed the one it does."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    env = _clean_git_env(tmp_path)
    runs = _repository(tmp_path / "runs", "[core]\n\tfsmonitor = /bin/true\n") / ".git"
    plain = _repository(tmp_path / "plain") / ".git"

    def why(args, **extra):
        return why_git_may_run_a_program(
            ["git", *args], {**env, **extra}, str(tmp_path)
        )

    assert why([f"--git-dir={runs}", "status"], GIT_DIR=str(plain)) is not None
    assert why([f"--git-dir={plain}", "status"], GIT_DIR=str(runs)) is None
    assert why(["status"], GIT_DIR=str(plain), GIT_COMMON_DIR=str(runs)) is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.parametrize(
    "args,config",
    [
        pytest.param(
            ["-c", "diff.foo.textconv=", "diff"],
            '[diff "Foo"]\n\ttextconv = /bin/true\n',
            id="a-subsection-keeps-its-case",
        ),
        pytest.param(
            ["log"],
            "[alias]\n\tx = \\\n!true\n",
            id="a-value-continued-on-the-next-line",
        ),
        pytest.param(
            ["log"],
            "\tlogallrefupdates = true # a note \\\n\tfsmonitor = /bin/true\n",
            id="a-backslash-in-a-value-comment-continues-nothing",
        ),
        pytest.param(
            ["log"],
            "\t# a note \\\n\tfsmonitor = /bin/true\n",
            id="a-backslash-in-a-comment-line-continues-nothing",
        ),
        pytest.param(
            ["log"],
            '[alias]\n\tx = "!true\r"\n',
            id="a-lone-cr-inside-quotes-is-part-of-the-value",
        ),
    ],
)
def test_a_config_is_read_as_git_reads_it(tmp_path, args, config):
    """A -c setting stands in only for the same key, subsection case included; a
    value continued by a backslash is the whole value, and a backslash inside a
    comment continues nothing, so the next line's setting is still read."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    repo = _repository(tmp_path, config)

    # Out of the assertion: the environment is os.environ's.
    reason = why_git_may_run_a_program(
        ["git", *args], _clean_git_env(tmp_path), str(repo)
    )
    assert reason is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
def test_a_byte_order_mark_hides_no_setting(tmp_path):
    """git skips a byte order mark at the start of a config file; read as text, it
    took the first section header with it."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    repo = _repository(tmp_path)
    (repo / ".git" / "config").write_bytes(
        b"\xef\xbb\xbf[core]\n\tfsmonitor = /bin/true\n"
    )

    # Out of the assertion: the environment is os.environ's.
    reason = why_git_may_run_a_program(
        ["git", "log"], _clean_git_env(tmp_path), str(repo)
    )
    assert reason is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.parametrize("named_by", ["a-git-file", "commondir"])
def test_a_cr_in_a_directory_git_is_pointed_at_is_part_of_its_name(tmp_path, named_by):
    """git reads a ``.git`` file and ``commondir`` as bytes, so a CR in the path
    either one holds is part of the name (git 2.50.1 resolves both that way). Read
    with universal newlines, the CR became an LF, and the guard read the config of
    a directory that does not exist."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    shared = tmp_path / "main\rrepo"
    shared.mkdir()
    (shared / "config").write_bytes(b"[core]\n\tfsmonitor = /bin/true\n")
    if named_by == "a-git-file":
        git_dir = shared
    else:
        git_dir = tmp_path / "worktree-admin"
        git_dir.mkdir()
        (git_dir / "commondir").write_bytes(str(shared).encode() + b"\n")
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_bytes(b"gitdir: " + str(git_dir).encode() + b"\n")

    # Out of the assertion: the environment is os.environ's.
    reason = why_git_may_run_a_program(
        ["git", "status"], _clean_git_env(tmp_path), str(worktree)
    )
    assert reason == (
        f"{shared / 'config'} sets core.fsmonitor, which names a program for git to run"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize(
    "named_by,ending",
    [
        pytest.param("a-git-file", b"\n", id="git-file"),
        pytest.param("a-git-file", b"\r\n", id="git-file-crlf"),
        pytest.param("a-git-file", b"", id="git-file-no-newline"),
        pytest.param("commondir", b"\n", id="commondir"),
        pytest.param("commondir", b"\r\n", id="commondir-crlf"),
    ],
)
def test_a_path_git_is_pointed_at_keeps_its_trailing_spaces(tmp_path, named_by, ending):
    """git drops only the CRs and LFs that end a .git file or a commondir, and takes
    the path after ``gitdir: `` as written, so a directory whose name ends in a space
    is the one it reads (git 2.50.1). ``.strip()`` dropped the space, and the guard
    read the config of a directory that does not exist. Which directory git reads is
    asked of git itself, with the file's fsmonitor turned off on its command line."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    tmp_path = tmp_path.resolve()
    env = _clean_git_env(tmp_path)
    shared = tmp_path / "shared-git "
    init = ["git", "init", "-q", "--bare"]
    subprocess.run([*init, str(shared)], env=env, check=True, capture_output=True)
    with (shared / "config").open("ab") as config:
        config.write(b"[core]\n\tfsmonitor = /bin/true\n")
    pointer_ending = ending
    if named_by == "a-git-file":
        git_dir = shared
    else:
        git_dir = tmp_path / "worktree-admin"
        subprocess.run([*init, str(git_dir)], env=env, check=True, capture_output=True)
        (git_dir / "commondir").write_bytes(str(shared).encode() + ending)
        pointer_ending = b"\n"
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_bytes(
        b"gitdir: " + str(git_dir).encode() + pointer_ending
    )

    read_by_git = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    assert os.path.realpath(read_by_git.rstrip("\n")) == str(shared)

    # Out of the assertion: env is os.environ's.
    reason = why_git_may_run_a_program(["git", "status"], env, str(worktree))
    assert reason == (
        f"{shared / 'config'} sets core.fsmonitor, which names a program for git to run"
    )


#: Config files read by both git and the guard. Whitespace inside a value is left
#: out: git 2.50 keeps it as it is, and older versions write each as a space.
_GIT_CONFIG_CASES = [
    b"[core]\n\tpager = less\n",
    b"[alias]\n\tx = \\\n!true\n",
    b"[core]\n\tbare = false # a note \\\n\tfsmonitor = /bin/true\n",
    b"[core]\n\t# a note \\\n\tfsmonitor = /bin/true\n",
    b'[diff "Foo"]\n\ttextconv = /bin/true\n',
    b"[Diff.Foo]\n\ttextconv = /bin/true\n",
    b'[core]\n\tpager = "less -R" ; comment\n',
    b'[core]\n\tpager = "a # b" x\n',
    b'[core]\n\tpager = a\\tb\\"c\\\\d\n',
    b'[core]\n\tpager = "  keep  "\n',
    b"[core]\n\tbare\n\tfsmonitor\n",
    b"[core] fsmonitor = /bin/true\n",
    b"\xef\xbb\xbf[core]\n\tfsmonitor = /bin/true\n",
    b"[core]\r\n\tfsmonitor = /bin/true\r\n",
    b'[url "https://a.b/c"]\n\tinsteadOf = x\n',
    b'[sec "a\\"b"]\n\tKey = v\n',
    b"[core]\n\tpager = a\\\nb\\\nc\n",
    b'[core]\n\tpager = "a\\\nb"\n',
    b"[core]\n\tFsMonitor = /bin/true\n",
    b"[core]\n\tpager = x\\",
    b'[alias]\n\tx = "!true\r"\n',
    b"[core]\n\t# a note\r\tfsmonitor = /bin/true\n",
    b"[core]\r\tfsmonitor = /bin/true\n",
]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("config", _GIT_CONFIG_CASES, ids=repr)
def test_the_config_reader_reads_what_git_reads(tmp_path, config):
    """The guard's reading of a config file is git's: ``git config --file --list``,
    which reads the file and runs nothing, lists the same settings."""
    from tests.utils.tool_guard import _git_config_file_settings

    path = tmp_path / "config"
    path.write_bytes(config)
    listed = subprocess.run(
        ["git", "--no-pager", "config", "--file", str(path), "--list", "--null"],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        },
        capture_output=True,
        check=True,
    )
    by_git = []
    for entry in listed.stdout.decode("utf-8").split("\0"):
        if entry:
            key, newline, value = entry.partition("\n")
            by_git.append((key, value if newline else None))

    assert _git_config_file_settings(path) == by_git


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX git and paths")
@pytest.mark.parametrize("name", ["EDITOR", "VISUAL", "SSH_ASKPASS"])
def test_the_editors_and_askpass_git_falls_back_to_count(tmp_path, name):
    """git commit and git config --edit run EDITOR or VISUAL when no git setting names
    an editor."""
    from tests.utils.tool_guard import why_git_may_run_a_program

    repo = _repository(tmp_path)

    # Out of the assertion: the environment is os.environ's.
    reason = why_git_may_run_a_program(
        ["git", "commit"], {**_clean_git_env(tmp_path), name: "true"}, str(repo)
    )
    assert reason == f"{name} is set"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PATH lookup")
@pytest.mark.parametrize(
    "launch",
    [
        pytest.param(lambda host: ["env", "-iS", f"{host / 'semgrep'} scan"], id="-iS"),
        pytest.param(
            lambda host: ["env", "-iu", "HOME", str(host / "semgrep"), "scan"], id="-iu"
        ),
        pytest.param(
            lambda host: ["env", "-uHOME", f"PATH={host}", "semgrep", "scan"],
            id="-uNAME",
        ),
    ],
)
def test_env_short_options_cluster(monkeypatch, tmp_path_factory, launch):
    """getopt clusters env's short options; read option by option, ``-iS`` and
    ``-iu`` were not options, and the tool was judged as env."""
    host = tmp_path_factory.mktemp("host-bin")
    _host_tool(host, "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    _popen_event(launch(host))

    assert len(guard.tool_starts) == 1, guard.tool_starts
    assert guard.tool_starts[0].endswith(" scan (not through a stand-in)"), (
        guard.tool_starts
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")
@pytest.mark.parametrize("how", ["link", "copy"])
def test_a_probe_line_does_not_answer_for_a_tool_put_in_the_stand_ins_place(
    monkeypatch, tmp_path_factory, how
):
    """A child the guard cannot see probed the stand-in, which wrote its line; then
    the test put a host tool where the stand-in was and ran ``--version`` on it.
    The line matched, and the host tool's run passed as the probe."""
    host = _host_tool(tmp_path_factory.mktemp("host-bin"), "semgrep")
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    stand_in = guard.directory / "semgrep"
    with guard.probe_log.open("a", encoding="utf-8") as log:
        log.write(f"{stand_in}\n")
    stand_in.unlink()
    if how == "link":
        stand_in.symlink_to(host)
    else:
        shutil.copy2(host, stand_in)

    subprocess.run([str(stand_in), "--version"], check=True)

    # The child's probe stands as its own; the swapped tool's run is a tool start.
    assert guard.probes == ["semgrep --version"], guard.probes
    assert guard.tool_starts == [
        f"{stand_in} --version (a --version call no stand-in answered)"
    ], guard.tool_starts


#: A Python child that does nothing: a start these tests expect refused that is not
#: refused runs nothing that writes, wherever its HOME is.
_QUIET_PYTHON = [sys.executable, "-I", "-S", "-c", "pass"]


def _developer_env(developer_home: Path) -> dict:
    home = str(developer_home)
    return {**os.environ, "HOME": home, "USERPROFILE": home}


def _start_event(event: str, env: dict) -> tuple:
    """The audit event *event* raises for a start of _QUIET_PYTHON with *env*."""
    if event == "os.posix_spawn":
        return (sys.executable, list(_QUIET_PYTHON), env)
    if event == "os.exec":
        return (sys.executable, list(_QUIET_PYTHON), env)
    if event == "os.spawn":
        return (os.P_NOWAIT, sys.executable, list(_QUIET_PYTHON), env)
    import shlex

    assignments = " ".join(
        f"{name}={shlex.quote(env[name])}" for name in ("HOME", "USERPROFILE")
    )
    return (f"{assignments} {shlex.join(_QUIET_PYTHON)}",)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX starts")
@pytest.mark.parametrize(
    "event", ["os.posix_spawn", "os.exec", "os.spawn", "os.system"]
)
def test_a_start_that_skips_popen_is_held_to_the_home_rule(
    monkeypatch, tmp_path_factory, developer_home, event
):
    """tests/conftest.py applies the HOME rule at subprocess.Popen; these starts never
    reach it. The recorder sees them, so it asks the same rule (tests/utils/
    home_rule.py): a Python child given the developer's HOME is refused before it
    starts, and the refusal is kept for the unit tests' teardown check."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    sys.audit(event, *_start_event(event, dict(os.environ)))
    assert guard.home_refusals == []

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        sys.audit(event, *_start_event(event, _developer_env(developer_home)))
    assert len(guard.home_refusals) == 1, guard.home_refusals
    assert guard.home_refusals[0].startswith(event), guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX starts")
@pytest.mark.parametrize(
    "event,args",
    [
        pytest.param("os.fork", (), id="fork"),
        pytest.param("os.forkpty", (), id="forkpty"),
        pytest.param("ctypes.dlsym", (None, "system"), id="ctypes-system"),
        pytest.param("ctypes.dlsym/handle", (0, "posix_spawn"), id="ctypes-handle"),
    ],
)
def test_a_child_of_this_interpreter_is_held_to_the_home_rule(
    monkeypatch, tmp_path_factory, developer_home, event, args
):
    """A fork, or a process that a C function looked up through ctypes starts,
    inherits this process's environment, whatever it then runs: with the
    developer's HOME there it is refused, as a Python child given it would be."""
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    sys.audit(event, *args)
    assert guard.home_refusals == []

    for name, value in _developer_env(developer_home).items():
        if name in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(name, value)
    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        sys.audit(event, *args)
    assert len(guard.home_refusals) == 1, guard.home_refusals


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX starts")
def test_a_posix_spawn_given_the_developers_home_does_not_start(
    monkeypatch, tmp_path_factory, developer_home
):
    """The refusal comes from the audit event, before the child exists."""
    install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        pid = os.posix_spawn(
            sys.executable, list(_QUIET_PYTHON), _developer_env(developer_home)
        )
        os.waitpid(pid, 0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX starts")
@pytest.mark.parametrize("route", ["spawnv_passfds", "fork_exec", "fork_exec-env"])
def test_the_starts_without_an_audit_event_are_held_to_the_home_rule(
    monkeypatch, tmp_path_factory, developer_home, route
):
    """multiprocessing's spawn and forkserver starts (``spawnv_passfds``) and a direct
    ``_posixsubprocess.fork_exec`` raise no event; the guard's wrappers ask the rule
    before they start anything. Here they wrap fakes, so nothing starts."""
    import _posixsubprocess
    from multiprocessing import util

    started = []
    if route == "spawnv_passfds":
        monkeypatch.setattr(
            util, "spawnv_passfds", lambda *args: started.append(args) or 0
        )
    else:
        monkeypatch.setattr(
            _posixsubprocess, "fork_exec", lambda *args: started.append(args) or 0
        )
    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    developer = _developer_env(developer_home)
    env_list = None
    if route == "fork_exec-env":
        env_list = [os.fsencode(f"{k}={v}") for k, v in developer.items()]
    else:
        monkeypatch.setenv("HOME", developer["HOME"])
        monkeypatch.setenv("USERPROFILE", developer["USERPROFILE"])

    with pytest.raises(pytest.fail.Exception, match="HOME in the developer home"):
        if route == "spawnv_passfds":
            util.spawnv_passfds(sys.executable, list(_QUIET_PYTHON), ())
        else:
            _posixsubprocess.fork_exec(
                [os.fsencode(a) for a in _QUIET_PYTHON],
                [os.fsencode(sys.executable)],
                True,
                (),
                None,
                env_list,
            )
    assert started == []
    assert len(guard.home_refusals) == 1, guard.home_refusals
