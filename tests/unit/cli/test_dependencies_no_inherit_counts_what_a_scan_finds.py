# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--no-inherit-system-tools`` counts a tool only where a scan would find it.

The sweep after an install decides whether each tool is present. By default it looks
a tool up as a scan of the working directory does: a copy inside that tree is
refused, and a virtualenv's scripts directory is searched only when it is on PATH
(a scan never searches a directory it was not given). With
``--no-inherit-system-tools`` the sweep reads only the locations ASH or its provider
manages, by those same two rules, so it does not report installed a tool that the
default run and the scan call absent.

The tool here has a name no machine has: ASH's own environment directories, which
both modes search, can then never satisfy it.

The answer is also the same on every platform. ``shutil.which`` searches the working
directory before the directory it is asked about on Windows, and the working directory
is the scanned tree, so a same-named file at the root of that tree, which the sweep
refuses, would answer for every directory in turn and hide the managed copy. The tests
that put such a file there emulate that order where it is not native, and one runs the
real Windows lookup.

A scan reaches a virtualenv's scripts directory only as a PATH entry, and on Windows
``shutil.which`` reads a name there through PATHEXT: a file with no extension is not
found, and ``<tool>.com`` is. The sweep reads that directory the same way. The tests
that put those files there emulate the Windows names and that rule where they are not
native, and two run the real lookup. Python applies PATHEXT to a command with a
directory part, as the scan's PATH entries are read, from 3.12; before it such a path
is checked as written, so those two tests run from 3.12.

A PATH entry can name the scripts directory in a spelling that a real path keeps apart
from the directory's own: another letter case on a case-insensitive volume (the macOS
default), or a bind mount at another path. A scan finds the tool through that entry as
it is spelled, so the sweep counts it too: it takes two paths for one directory when
their device and inode agree. The test that puts such a variant on PATH emulates the
volume where it can, with a link and a ``realpath`` that keeps the variant as written;
the one beside it runs only where the volume folds case.

The run says which copy it counted (the "Resolved to" cell) and which it set aside as
a system tool (an "Ignoring" line). One file is never both, however each lookup spells
its path: a PATH entry that names the scripts directory through a link, or, on
Windows, forward slashes against backslashes. A hard link of the counted copy on PATH
is the same file under a second name. A different copy on PATH is still set aside.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.install_providers import venv_scripts_dir
from tests.unit.cli.dependencies_install_support import build_scene, run_install
from tests.utils.stand_ins import on_windows, write_stand_in

pytestmark = pytest.mark.unit

TOOL = "ash-sweep-probe-tool"

#: The default run and the no-inherit run answer these cases alike.
MODES = pytest.mark.parametrize(
    "mode",
    [
        pytest.param([], id="default"),
        pytest.param(["--no-inherit-system-tools"], id="no-inherit"),
    ],
)


def _scan_lookup(command):
    """The lookup a scan of the working directory makes, which is the default run's."""
    return subprocess_utils.find_executable_for_scan(command, Path.cwd())


def _scene(monkeypatch, tmp_path):
    """One fake scanner whose tool is TOOL; the run's working directory is tmp_path,
    so the bin directory under it is inside the scanned tree."""
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    return build_scene(
        monkeypatch,
        tmp_path,
        name="sweep-probe",
        command=TOOL,
        uv_managed=False,
        declared=[["uv", "tool", "install", TOOL]],
        find_on_path=_scan_lookup,
    )


def _scene_beside_a_tree(monkeypatch, tmp_path):
    """The same run from a tree of its own: the bin directory and any virtualenv
    under tmp_path are outside it."""
    scene = _scene(monkeypatch, tmp_path)
    tree = tmp_path / "src-tree"
    tree.mkdir()
    monkeypatch.chdir(tree)
    return scene


def _bin_directory_holding_the_tool(tmp_path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stand_in(bin_dir, TOOL, "")
    return bin_dir


def _prepared_virtualenv(path: Path) -> Path:
    """A virtualenv ASH takes for prepared (it holds ``pyvenv.cfg``); its scripts
    directory, empty."""
    path.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
    scripts = venv_scripts_dir(path)
    scripts.mkdir()
    return scripts


def _venv_holding_the_tool(path: Path) -> Path:
    """A prepared virtualenv whose scripts directory holds the tool; that directory."""
    scripts = _prepared_virtualenv(path)
    write_stand_in(scripts, TOOL, "")
    return scripts


def _program(path: Path) -> Path:
    """One executable file under exactly the name given: no launcher beside it, and
    nothing runs it."""
    path.write_bytes(b"")
    path.chmod(0o755)
    return path


def _launcher(directory: Path) -> Path:
    """The file of ``write_stand_in(directory, TOOL, ...)`` that a lookup finds: the
    script on POSIX, its ``.bat`` launcher on Windows."""
    return directory / (f"{TOOL}.bat" if on_windows() else TOOL)


def _on_path_first(monkeypatch, directory: str) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join([directory, os.environ.get("PATH", "")]))


def _real(path: str | os.PathLike[str]) -> str:
    """The file a path names, spelled one way, to compare files rather than spellings."""
    return os.path.normcase(os.path.realpath(path))


#: The characters that draw the results table: the box-drawing block, and a plain bar.
_TABLE_BORDERS = re.compile(f"[{chr(0x2500)}-{chr(0x257F)}|]")


def _resolved_to(text: str) -> str:
    """What the "Resolved to" cell of the results table says about TOOL."""
    for line in text.splitlines():
        cells = [cell.strip() for cell in _TABLE_BORDERS.split(line)]
        if TOOL in cells:
            return cells[-2]
    raise AssertionError(f"the results table has no row for {TOOL}:\n{text}")


def _ignored_files(text: str) -> list[str]:
    """The files the run says it set aside as system tools, one per "Ignoring" line."""
    return re.findall(r"Ignoring (.+?): --no-inherit-system-tools", text)


def _working_directory_first(monkeypatch) -> None:
    """Give ``shutil.which`` the order it has on Windows, on whatever platform runs this.

    CPython's Windows ``which`` puts the working directory ahead of the directories in
    ``path=``, so a file there answers for every directory a caller asks about. This
    replaces ``shutil.which``, for every caller, with one that puts ``os.curdir`` ahead
    of ``path`` itself.
    """
    real_which = shutil.which

    def which(cmd, mode=os.F_OK | os.X_OK, path=None):
        if path is None:
            path = os.environ.get("PATH", "")
        return real_which(cmd, mode, os.curdir + os.pathsep + path)

    monkeypatch.setattr(shutil, "which", which)


def _volume_folds_case(directory: Path) -> bool:
    """Whether the volume under ``directory`` gives one file two spellings that differ
    in letter case: the default macOS volume does, and Linux's usual ones do not."""
    (directory / "Case-Probe").write_bytes(b"")
    return (directory / "case-probe").exists()


def _realpath_keeps_the_spelling_of(monkeypatch, variant: Path) -> None:
    """Make ``os.path.realpath`` answer for ``variant`` as it does on a volume that
    folds letter case.

    posixpath's ``realpath`` replaces symbolic links and keeps every other component as
    it is written, so on such a volume a path spelled in another case comes back in that
    case. Here ``variant`` is a link, which a volume that tells cases apart resolves:
    a path at or under it is returned as written, after ``os.path.abspath``, and every
    other path goes to the real function.
    """
    real_realpath = os.path.realpath
    written = os.path.abspath(variant)

    def realpath(path, *args, **kwargs):
        spelled = os.path.abspath(path)
        if isinstance(spelled, str) and (
            spelled == written or spelled.startswith(written + os.sep)
        ):
            return spelled
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", realpath)


#: The suffixes CPython's Windows ``shutil.which`` adds to a name, in order.
_WINDOWS_PATHEXT = (".com", ".exe", ".bat", ".cmd")

#: The two tests that run the real Windows lookup: from Python 3.12 ``shutil.which``
#: applies PATHEXT to a command with a directory part, as a PATH entry is read; before
#: it, that path is checked as written, so a file with no extension is found there.
_REAL_PATHEXT_LOOKUP = pytest.mark.skipif(
    sys.platform != "win32" or sys.version_info < (3, 12),
    reason="Windows reads a command with a directory part through PATHEXT from 3.12",
)


def _windows_which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """CPython's Windows ``shutil.which`` (3.12 and later), on whatever platform runs
    this: a name is read with each suffix of PATHEXT, and as it is only when it
    already ends in one.

    So a file with no extension is not found, and ``<tool>.com`` is. A command with a
    directory part is looked up in that directory alone; a bare name is looked up in
    each directory of ``path``.
    """
    directory, name = os.path.split(cmd)
    if directory:
        directories = [directory]
    else:
        searched = os.environ.get("PATH", "") if path is None else path
        directories = [entry for entry in searched.split(os.pathsep) if entry]
    files = [name + suffix for suffix in _WINDOWS_PATHEXT]
    if name.lower().endswith(_WINDOWS_PATHEXT):
        files.insert(0, name)
    for entry in directories:
        for file in files:
            candidate = os.path.join(entry, file)
            if os.path.isfile(candidate) and os.access(candidate, mode):
                return candidate
    return None


def _windows_lookup(monkeypatch) -> None:
    """Give a scan's lookup and the sweep's the file names and the PATHEXT rule Windows
    has: the names are the lookup's own, read as it reads them there."""
    real_names = subprocess_utils._executable_candidate_names

    def names(command):
        with patch.object(subprocess_utils.platform, "system", return_value="Windows"):
            return real_names(command)

    monkeypatch.setattr(subprocess_utils, "_executable_candidate_names", names)
    monkeypatch.setattr(shutil, "which", _windows_which)


@MODES
def test_a_copy_in_a_bin_directory_inside_the_tree_is_absent(
    tmp_path, monkeypatch, mode
):
    """A scan refuses a tool found inside the tree it scans, so the run that
    installed one there has not made the tool available."""
    scene = _scene(monkeypatch, tmp_path)
    _bin_directory_holding_the_tool(tmp_path)

    run_install(scene, monkeypatch, tmp_path, *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@MODES
def test_the_in_tree_opt_in_admits_the_copy(tmp_path, monkeypatch, mode):
    """The control: the operator's opt-in lets a scan run a tool from the tree, and
    it lets the sweep count one."""
    scene = _scene(monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
    _bin_directory_holding_the_tool(tmp_path)

    run_install(scene, monkeypatch, tmp_path, *mode)

    assert scene.result.exit_code == 0, scene.text


def test_a_refused_in_tree_copy_is_passed_over_for_the_next_managed_directory(
    tmp_path, monkeypatch
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    # An environment directory ASH runs from, inside the tree, holding a copy too:
    # it comes before the bin directory in the search.
    in_tree = tmp_path / "src-tree" / "environment-bin"
    in_tree.mkdir()
    write_stand_in(in_tree, TOOL, "")
    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", lambda: [in_tree])

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert str(bin_dir / TOOL) in scene.text, scene.text
    assert str(in_tree) not in scene.text, scene.text


def test_a_same_named_file_in_the_working_directory_does_not_hide_the_managed_copy(
    tmp_path, monkeypatch
):
    """On Windows a lookup searches the working directory before the directory it was
    asked about, and the working directory is the scanned tree. A file at the root of
    that tree, which the sweep refuses, must not stand in front of the managed copy
    for every directory in turn: a scan finds the copy in the bin directory."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    write_stand_in(tmp_path / "src-tree", TOOL, "")
    _working_directory_first(monkeypatch)

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(_launcher(bin_dir)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


def test_the_managed_copy_is_counted_when_the_working_directory_holds_no_such_file(
    tmp_path, monkeypatch
):
    """The control: the same lookup order with nothing at the root of the tree."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    _working_directory_first(monkeypatch)

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(_launcher(bin_dir)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@pytest.mark.skipif(
    sys.platform != "win32", reason="only Windows searches the working directory first"
)
def test_a_batch_file_at_the_root_of_the_tree_does_not_hide_the_managed_copy(
    tmp_path, monkeypatch
):
    """The real Windows lookup, with nothing replaced: ``<tool>.bat`` at the root of
    the scanned tree, and the managed copy in a bin directory outside it."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    (tmp_path / "src-tree" / f"{TOOL}.bat").write_bytes(b"@echo off\r\n")

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(_launcher(bin_dir)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@MODES
def test_a_tool_only_in_a_virtualenv_that_is_off_path_is_absent(
    tmp_path, monkeypatch, mode
):
    """A scan looks in a virtualenv's scripts directory only when PATH names it."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    _venv_holding_the_tool(venv)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@MODES
def test_a_tool_in_a_virtualenv_whose_scripts_directory_is_on_path_is_present(
    tmp_path, monkeypatch, mode
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    _on_path_first(monkeypatch, str(_venv_holding_the_tool(venv)))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text


@MODES
def test_a_relative_path_entry_does_not_put_the_scripts_directory_on_path(
    tmp_path, monkeypatch, mode
):
    """A scan never searches through the working directory, so a PATH entry that is
    relative names nothing it would look in, whatever directory it points at."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    _on_path_first(monkeypatch, os.path.relpath(scripts, Path.cwd()))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text


@pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows"
)
@MODES
def test_a_path_entry_that_is_another_name_for_the_scripts_directory_counts(
    tmp_path, monkeypatch, mode
):
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    alias = tmp_path / "scripts-alias"
    alias.symlink_to(scripts, target_is_directory=True)
    _on_path_first(monkeypatch, str(alias))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text


@pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows"
)
def test_a_copy_counted_through_another_name_for_the_scripts_directory_is_not_ignored(
    tmp_path, monkeypatch
):
    """PATH names the scripts directory through a link, so a scan finds the tool under
    the link's name and the sweep under the virtualenv's own. It is one file, and the
    run does not set aside the copy it counted."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    alias = tmp_path / "scripts-alias"
    alias.symlink_to(scripts, target_is_directory=True)
    _on_path_first(monkeypatch, str(alias))

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(venv),
        "--no-inherit-system-tools",
    )

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(scripts / TOOL), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a link needs a privilege on Windows, and normcase folds case there already",
)
def test_a_path_entry_spelling_the_scripts_directory_in_another_case_counts_when_realpath_keeps_it(
    tmp_path, monkeypatch
):
    """PATH names the scripts directory in another letter case. A real path keeps the
    case a component is written in, so on a volume that folds case the entry and the
    directory have two real paths, and ``normcase`` changes neither off Windows. A scan
    reads the entry as spelled and runs the tool there, so the sweep counts it, and
    does not report the file it counted as a system tool it set aside.

    Emulated where the volume tells cases apart: the variant is a link to the
    directory, and ``os.path.realpath`` keeps a path at or under it as written. The
    next test runs the same input on a volume that folds case, with nothing replaced."""
    if _volume_folds_case(tmp_path):
        pytest.skip("this volume folds case; the next test runs this input unemulated")
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    variant = scripts.with_name(scripts.name.swapcase())
    variant.symlink_to(scripts, target_is_directory=True)
    _realpath_keeps_the_spelling_of(monkeypatch, variant)
    _on_path_first(monkeypatch, str(variant))

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(venv),
        "--no-inherit-system-tools",
    )

    assert scene.result.exit_code == 0, scene.text
    assert os.path.samefile(_resolved_to(scene.text), _launcher(scripts)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@pytest.mark.skipif(
    sys.platform == "win32", reason="normcase folds case on Windows already"
)
def test_a_path_entry_spelling_the_scripts_directory_in_another_case_counts_on_a_case_insensitive_volume(
    tmp_path, monkeypatch
):
    """The same input as the test before it, with nothing emulated: no link, and the
    real ``os.path.realpath``. It runs only where the volume under ``tmp_path`` folds
    case, which is the default macOS volume, and skips elsewhere."""
    if not _volume_folds_case(tmp_path):
        pytest.skip(
            "this volume tells cases apart; the test before this one emulates it"
        )
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    venv = tmp_path / "venv"
    scripts = _venv_holding_the_tool(venv)
    _on_path_first(monkeypatch, str(scripts.with_name(scripts.name.swapcase())))

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(venv),
        "--no-inherit-system-tools",
    )

    assert scene.result.exit_code == 0, scene.text
    assert os.path.samefile(_resolved_to(scene.text), _launcher(scripts)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


def test_a_different_copy_on_path_outside_the_managed_directories_is_still_ignored(
    tmp_path, monkeypatch
):
    """The control: a scan finds a copy on PATH ahead of the managed one, the sweep
    counts the managed one, and the other file is named as set aside."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    system_dir = tmp_path / "system-bin"
    system_dir.mkdir()
    write_stand_in(system_dir, TOOL, "")
    _on_path_first(monkeypatch, str(system_dir))

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(_launcher(bin_dir)), scene.text
    assert [_real(file) for file in _ignored_files(scene.text)] == [
        _real(_launcher(system_dir))
    ], scene.text


def test_a_hard_link_of_the_counted_copy_on_path_is_not_ignored(tmp_path, monkeypatch):
    """The control's scene, with one difference: the copy on PATH is a hard link of the
    counted one. A scan finds the tool under the link's name and the sweep counts it
    under its own, two paths whose real paths differ for one file, so it is
    ``os.path.samefile`` that tells the run it set nothing aside. A different file under
    the same name, which the control keeps, is set aside."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    bin_dir = _bin_directory_holding_the_tool(tmp_path)
    system_dir = tmp_path / "system-bin"
    system_dir.mkdir()
    os.link(_launcher(bin_dir), system_dir / _launcher(bin_dir).name)
    _on_path_first(monkeypatch, str(system_dir))

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert scene.result.exit_code == 0, scene.text
    assert os.path.samefile(_resolved_to(scene.text), _launcher(bin_dir)), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@MODES
def test_pathext_leaves_a_file_with_no_extension_in_the_scripts_directory_absent(
    tmp_path, monkeypatch, mode
):
    """Where Windows reads names through PATHEXT, a file with no extension in a
    directory on PATH is not a tool a scan finds: a scan reads a name with each suffix
    of PATHEXT, and as it is only when it already ends in one. The sweep reads the
    scripts directory the same way, so it does not count the file either."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    _windows_lookup(monkeypatch)
    venv = tmp_path / "venv"
    scripts = _prepared_virtualenv(venv)
    _program(scripts / TOOL)
    _on_path_first(monkeypatch, str(scripts))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@MODES
def test_pathext_finds_a_com_file_in_the_scripts_directory(tmp_path, monkeypatch, mode):
    """The other direction: ``<tool>.com`` is not among the names a scan tries, but
    ``which`` finds it through PATHEXT when its directory is on PATH, so a scan runs it
    and the sweep counts it."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    _windows_lookup(monkeypatch)
    venv = tmp_path / "venv"
    scripts = _prepared_virtualenv(venv)
    counted = _program(scripts / f"{TOOL}.com")
    _on_path_first(monkeypatch, str(scripts))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(counted), scene.text
    assert _ignored_files(scene.text) == [], scene.text


@_REAL_PATHEXT_LOOKUP
@MODES
def test_on_windows_a_file_with_no_extension_in_the_scripts_directory_is_absent(
    tmp_path, monkeypatch, mode
):
    """The real lookup, with nothing replaced."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    venv = tmp_path / "venv"
    scripts = _prepared_virtualenv(venv)
    _program(scripts / TOOL)
    _on_path_first(monkeypatch, str(scripts))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 1, scene.text
    assert "still absent after install" in " ".join(scene.text.split()), scene.text


@_REAL_PATHEXT_LOOKUP
@MODES
def test_on_windows_a_com_file_in_the_scripts_directory_is_present(
    tmp_path, monkeypatch, mode
):
    """The real lookup, with nothing replaced."""
    scene = _scene_beside_a_tree(monkeypatch, tmp_path)
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    venv = tmp_path / "venv"
    scripts = _prepared_virtualenv(venv)
    counted = _program(scripts / f"{TOOL}.com")
    _on_path_first(monkeypatch, str(scripts))

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(venv), *mode)

    assert scene.result.exit_code == 0, scene.text
    assert _real(_resolved_to(scene.text)) == _real(counted), scene.text
    assert _ignored_files(scene.text) == [], scene.text
