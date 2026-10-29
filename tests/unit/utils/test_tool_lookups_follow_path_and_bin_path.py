# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool lookup answers for the PATH and ASH_BIN_PATH of the call that makes it.

subprocess_utils.find_executable, uv_tool_runner.find_executable,
find_uv_or_none and get_uv_tool_command remember their answers for the life of
the process. What they find depends on the directories searched, so an answer is
remembered for the PATH and ASH_BIN_PATH it was found under: after either one
changes, the next call searches again and answers what the new value finds. Under
an unchanged PATH and ASH_BIN_PATH the remembered answer is given without a new
search.

Only what was found is remembered, and only while it can still run. A lookup that
found nothing searches again on the next call, so a tool installed after it is
found; get_uv_tool_command remembers a None only once its uv probe has run. A
remembered path that has lost its execute bit or is gone is not given again: the
next call searches anew.

No tool is started here: the files are only looked up.
"""

import os
import stat
import subprocess
import threading
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits"),
]

#: A name no directory searched outside this test's own holds.
TOOL = "ash-lookup-probe-tool"


def _tool(directory: Path, name: str = TOOL) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.as_posix()


@pytest.fixture
def fresh_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty caches, and no uv installed with ASH, so PATH decides."""
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    monkeypatch.setattr(uv_tool_runner, "_executable_cache", {})
    monkeypatch.setattr(uv_tool_runner, "_uv_executable_cache", {})
    monkeypatch.setattr(uv_tool_runner, "_uv_command_cache", {})
    monkeypatch.setattr(uv_tool_runner, "_uv_command_binary", {})
    monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: None)


@pytest.fixture
def no_uv(monkeypatch: pytest.MonkeyPatch) -> None:
    """No uv at all, so get_uv_tool_command probes nothing and answers the tool's
    own executable. find_executable also searches ASH's own environment, whose bin
    directory holds the uv ASH depends on, so PATH alone would not hide it."""
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)


@pytest.mark.usefixtures("fresh_lookups")
class TestALookupFollowsPath:
    def test_subprocess_find_executable(self, tmp_path, monkeypatch):
        first = _tool(tmp_path / "a")
        second = _tool(tmp_path / "b")
        monkeypatch.setenv("PATH", str(tmp_path / "a"))
        assert subprocess_utils.find_executable(TOOL) == first
        monkeypatch.setenv("PATH", str(tmp_path / "b"))
        assert subprocess_utils.find_executable(TOOL) == second

    def test_uv_tool_runner_find_executable(self, tmp_path, monkeypatch):
        first = _tool(tmp_path / "a")
        second = _tool(tmp_path / "b")
        monkeypatch.setenv("PATH", str(tmp_path / "a"))
        assert uv_tool_runner.find_executable(TOOL) == first
        monkeypatch.setenv("PATH", str(tmp_path / "b"))
        assert uv_tool_runner.find_executable(TOOL) == second

    def test_find_uv_or_none(self, tmp_path, monkeypatch):
        first = _tool(tmp_path / "a", "uv")
        second = _tool(tmp_path / "b", "uv")
        monkeypatch.setenv("PATH", str(tmp_path / "a"))
        assert uv_tool_runner.find_uv_or_none() == first
        monkeypatch.setenv("PATH", str(tmp_path / "b"))
        assert uv_tool_runner.find_uv_or_none() == second

    @pytest.mark.usefixtures("no_uv")
    def test_get_uv_tool_command_answers_the_tool_the_new_path_holds(
        self, tmp_path, monkeypatch
    ):
        """With no uv on either PATH, the command is the tool's own executable."""
        first = _tool(tmp_path / "a")
        second = _tool(tmp_path / "b")
        monkeypatch.setenv("PATH", str(tmp_path / "a"))
        assert uv_tool_runner.get_uv_tool_command(TOOL) == [first]
        monkeypatch.setenv("PATH", str(tmp_path / "b"))
        assert uv_tool_runner.get_uv_tool_command(TOOL) == [second]


@pytest.mark.usefixtures("fresh_lookups")
class TestALookupFollowsAshBinPath:
    def test_subprocess_find_executable(self, tmp_path, monkeypatch):
        first = _tool(tmp_path / "a")
        second = _tool(tmp_path / "b")
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "a"))
        assert subprocess_utils.find_executable(TOOL) == first
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "b"))
        assert subprocess_utils.find_executable(TOOL) == second

    @pytest.mark.usefixtures("no_uv")
    def test_get_uv_tool_command(self, tmp_path, monkeypatch):
        first = _tool(tmp_path / "a")
        second = _tool(tmp_path / "b")
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "a"))
        assert uv_tool_runner.get_uv_tool_command(TOOL) == [first]
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "b"))
        assert uv_tool_runner.get_uv_tool_command(TOOL) == [second]


@pytest.fixture
def path_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only PATH is searched: not ASH_BIN_PATH, ASH's own environment, whose bin
    directory holds the uv ASH depends on, or /usr/local/bin. A name missing from
    PATH is then missing."""
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", list)


def _empty(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _cannot_run(path: str, how: str) -> None:
    if how == "execute bit":
        os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) & ~0o111)
    else:
        os.remove(path)


LOOKUPS = {
    "subprocess_utils.find_executable": lambda: subprocess_utils.find_executable(TOOL),
    "uv_tool_runner.find_executable": lambda: uv_tool_runner.find_executable(TOOL),
    "find_uv_or_none": uv_tool_runner.find_uv_or_none,
}
#: The file each lookup in LOOKUPS looks for.
LOOKED_FOR = {
    "subprocess_utils.find_executable": TOOL,
    "uv_tool_runner.find_executable": TOOL,
    "find_uv_or_none": "uv",
}


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
class TestAMissIsSearchedForAgain:
    """A tool installed after a lookup found nothing is found by the next lookup."""

    @pytest.mark.parametrize("lookup", sorted(LOOKUPS))
    def test_a_find_helper(self, tmp_path, monkeypatch, lookup):
        monkeypatch.setenv("PATH", str(_empty(tmp_path / "a")))
        assert LOOKUPS[lookup]() is None
        installed = _tool(tmp_path / "a", LOOKED_FOR[lookup])
        assert LOOKUPS[lookup]() == installed

    @pytest.mark.usefixtures("no_uv")
    def test_get_uv_tool_command_with_no_uv_to_probe(self, tmp_path, monkeypatch):
        """Nothing was probed, so its None is not remembered."""
        monkeypatch.setenv("PATH", str(_empty(tmp_path / "a")))
        assert uv_tool_runner.get_uv_tool_command(TOOL) is None
        installed = _tool(tmp_path / "a")
        assert uv_tool_runner.get_uv_tool_command(TOOL) == [installed]


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
class TestARememberedPathThatCannotRunIsNotGivenAgain:
    """The next lookup searches again: here it finds the copy later on PATH."""

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root may execute a file without its execute bit",
    )
    @pytest.mark.parametrize("lookup", sorted(LOOKUPS))
    @pytest.mark.parametrize("how", ["execute bit", "file"])
    def test_a_find_helper(self, tmp_path, monkeypatch, lookup, how):
        first = _tool(tmp_path / "a", LOOKED_FOR[lookup])
        second = _tool(tmp_path / "b", LOOKED_FOR[lookup])
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")])
        )
        assert LOOKUPS[lookup]() == first
        _cannot_run(first, how)
        assert LOOKUPS[lookup]() == second


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
@pytest.mark.parametrize("lookup", sorted(LOOKUPS))
def test_an_unchanged_environment_with_the_tool_present_is_not_searched_again(
    tmp_path, monkeypatch, lookup
):
    """The control: a found path that can still run is answered from memory."""
    found = _tool(tmp_path / "a", LOOKED_FOR[lookup])
    monkeypatch.setenv("PATH", str(tmp_path / "a"))
    searches = []
    real_which = subprocess_utils.shutil.which

    def counting_which(name, *args, **kwargs):
        searches.append(name)
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(subprocess_utils.shutil, "which", counting_which)

    assert LOOKUPS[lookup]() == found
    after_first = len(searches)
    assert after_first > 0
    assert LOOKUPS[lookup]() == found
    assert len(searches) == after_first


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
@pytest.mark.parametrize(
    "lookup", ["subprocess_utils.find_executable", "uv_tool_runner.find_executable"]
)
def test_an_unset_path_and_an_empty_one_are_answered_apart(monkeypatch, lookup):
    """With PATH unset, ``shutil.which`` searches the system's default directories;
    with PATH empty it searches none. An answer found under one is not the
    other's."""
    find = {
        "subprocess_utils.find_executable": subprocess_utils.find_executable,
        "uv_tool_runner.find_executable": uv_tool_runner.find_executable,
    }[lookup]
    monkeypatch.delenv("PATH", raising=False)
    assert find("sh") is not None, "no sh in the default search path"
    monkeypatch.setenv("PATH", "")
    assert find("sh") is None


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
@pytest.mark.parametrize("lookup", sorted(LOOKUPS))
def test_a_copy_installed_ahead_is_found_once_the_cache_is_cleared(
    tmp_path, monkeypatch, lookup
):
    """clear_find_executable_cache, called after an install, makes every lookup
    search again: one through uv_tool_runner, whose own answers it forgets too,
    finds a copy put ahead of the one found before."""
    later = _tool(tmp_path / "b", LOOKED_FOR[lookup])
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(_empty(tmp_path / "a")), str(tmp_path / "b")])
    )
    assert LOOKUPS[lookup]() == later
    ahead = _tool(tmp_path / "a", LOOKED_FOR[lookup])
    subprocess_utils.clear_find_executable_cache()
    assert LOOKUPS[lookup]() == ahead


@pytest.mark.usefixtures("fresh_lookups", "no_uv")
def test_an_unchanged_environment_is_answered_without_a_new_search(
    tmp_path, monkeypatch
):
    """The control: the answers are still remembered, for the same PATH and
    ASH_BIN_PATH."""
    found = _tool(tmp_path / "a")
    monkeypatch.setenv("PATH", str(tmp_path / "a"))
    searches = []
    real_which = subprocess_utils.shutil.which

    def counting_which(name, *args, **kwargs):
        searches.append(name)
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(subprocess_utils.shutil, "which", counting_which)

    assert uv_tool_runner.get_uv_tool_command(TOOL) == [found]
    after_first = len(searches)
    assert after_first > 0
    assert uv_tool_runner.get_uv_tool_command(TOOL) == [found]
    assert subprocess_utils.find_executable(TOOL) == found
    assert uv_tool_runner.find_executable(TOOL) == found
    assert len(searches) == after_first


@pytest.mark.usefixtures("fresh_lookups", "path_alone", "no_uv")
def test_get_uv_tool_command_finds_a_copy_installed_ahead_once_the_cache_is_cleared(
    tmp_path, monkeypatch
):
    """With no uv, get_uv_tool_command answers the tool's own executable and
    remembers that command. clear_find_executable_cache forgets it too, so the copy
    put ahead is the next answer."""
    later = _tool(tmp_path / "b")
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(_empty(tmp_path / "a")), str(tmp_path / "b")])
    )
    assert uv_tool_runner.get_uv_tool_command(TOOL) == [later]
    ahead = _tool(tmp_path / "a")
    subprocess_utils.clear_find_executable_cache()
    assert uv_tool_runner.get_uv_tool_command(TOOL) == [ahead]


class _SearchHeldOpen:
    """subprocess_utils' ``shutil.which`` with its first call held open until the
    test lets it go: it then gives ``answer``, what it found when it began, as a
    search that started before an install does. Later calls search for real."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, answer: str) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.answer = answer
        self.calls = 0
        self.real = subprocess_utils.shutil.which
        monkeypatch.setattr(subprocess_utils.shutil, "which", self)

    def __call__(self, name, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            self.entered.set()
            assert self.release.wait(30), "the test never let the search go"
            return self.answer
        return self.real(name, *args, **kwargs)


def _started(target) -> Tuple[threading.Thread, dict]:
    result: dict = {}

    def run() -> None:
        result["value"] = target()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
def test_a_search_begun_before_a_clear_leaves_no_answer_behind_it(
    tmp_path, monkeypatch
):
    """A lookup whose search began before an install's clear_find_executable_cache
    answers what it found, but that answer is not remembered: the next lookup
    finds the copy installed ahead."""
    later = _tool(tmp_path / "b")
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(_empty(tmp_path / "a")), str(tmp_path / "b")])
    )
    held = _SearchHeldOpen(monkeypatch, later)
    first, result = _started(lambda: subprocess_utils.find_executable(TOOL))
    assert held.entered.wait(30)

    ahead = _tool(tmp_path / "a")
    subprocess_utils.clear_find_executable_cache()
    held.release.set()
    first.join(30)

    assert result["value"] == later
    assert subprocess_utils.find_executable(TOOL) == ahead


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
def test_a_uv_tool_runner_search_begun_before_a_clear_leaves_no_answer_behind_it(
    tmp_path, monkeypatch
):
    """The same through uv_tool_runner.find_executable, which holds its lock for
    the whole lookup, so the clear's second half waits for it. The clear's first
    half, subprocess_utils' own cache, has already run: the held search must not
    write its answer back there."""
    later = _tool(tmp_path / "b")
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(_empty(tmp_path / "a")), str(tmp_path / "b")])
    )
    held = _SearchHeldOpen(monkeypatch, later)
    forgetting = threading.Event()
    forget = uv_tool_runner._forget_lookups

    def announced_forget() -> None:
        forgetting.set()
        forget()

    monkeypatch.setattr(uv_tool_runner, "_forget_lookups", announced_forget)
    first, result = _started(lambda: uv_tool_runner.find_executable(TOOL))
    assert held.entered.wait(30)

    ahead = _tool(tmp_path / "a")
    clear, _ = _started(subprocess_utils.clear_find_executable_cache)
    assert forgetting.wait(30)
    held.release.set()
    first.join(30)
    clear.join(30)

    assert result["value"] == later
    assert uv_tool_runner.find_executable(TOOL) == ahead


@pytest.mark.usefixtures("fresh_lookups", "path_alone")
def test_a_probe_begun_before_a_clear_leaves_no_command_behind_it(
    tmp_path, monkeypatch
):
    """get_uv_tool_command runs its uv probe without its lock held, so a clear can
    finish while the probe runs. The command the probe gives is not remembered
    then: the next call probes again, and here answers the tool's own executable,
    as the uv no longer runs the tool."""
    uv = _tool(tmp_path / "uv-dir", "uv")
    direct = _tool(tmp_path / "a")
    monkeypatch.setenv("PATH", str(tmp_path / "a"))
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: uv)
    entered, release = threading.Event(), threading.Event()
    probes: List[List[str]] = []

    def probe(command, **kwargs):
        probes.append(list(command))
        if len(probes) == 1:
            entered.set()
            assert release.wait(30), "the test never let the probe go"
            return subprocess.CompletedProcess(command, 0, "1.0\n", "")
        return subprocess.CompletedProcess(command, 1, "", "not installed\n")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", probe)
    first, result = _started(lambda: uv_tool_runner.get_uv_tool_command(TOOL))
    assert entered.wait(30)

    subprocess_utils.clear_find_executable_cache()
    release.set()
    first.join(30)

    assert result["value"] == ["uv", "tool", "run", TOOL]
    assert uv_tool_runner.get_uv_tool_command(TOOL) == [direct]
    assert len(probes) == 2
