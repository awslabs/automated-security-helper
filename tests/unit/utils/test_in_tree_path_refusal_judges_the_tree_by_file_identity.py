"""``in_tree_path_refusal`` judges "inside the scanned tree" by device and inode too.

``ash dependencies install`` refuses a ``--virtualenv-path`` or a ``--binary-path``
inside the scanned tree unless ``ASH_ALLOW_IN_TREE_TOOLS`` is set. A real path keeps
the letter case of every component that is not a link, so comparing real paths as
text takes the tree named in another case on a volume that ignores case, or reached
through a bind mount, for a different directory. A scan also compares the tree with
the path's real path and each of its parents by device and inode, and treats that
spelling as inside; the installer's refusal has to agree.

The tests stand in for such a spelling with a link to the tree and a ``realpath`` that
keeps a path under the link as written, which is what ``realpath`` returns for a case
variant or a bind mount. ``os.stat`` is left alone: it reads through the link and
reports the tree's device and inode, as it would for either. The test that replaces
nothing runs only where the volume under ``tmp_path`` ignores letter case.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

from automated_security_helper.utils import install_providers as ip
from automated_security_helper.utils import scanned_tree
from tests.utils.stand_ins import write_stand_in

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows"
)

INSIDE = "inside the scanned source tree"


@pytest.fixture(autouse=True)
def _without_the_in_tree_opt_in(monkeypatch):
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)


def _realpath_keeps_the_spelling_of(monkeypatch, variant: Path) -> None:
    """Make ``os.path.realpath`` answer for ``variant`` as it does for another spelling
    of the tree that a real path keeps apart from the tree's own.

    ``realpath`` replaces symbolic links and keeps every other component as it is
    written, so a path spelled in another letter case on a volume that ignores case,
    or through a bind mount, comes back as written. Here ``variant`` is a link, which
    a volume that tells cases apart resolves: a path at or under it is returned as
    written, after ``os.path.abspath``, and every other path goes to the real function.
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


def _tree_and_its_other_spelling(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    """A tree holding a ``venv`` directory, and a link beside it that names the tree."""
    tree = tmp_path / "tree"
    (tree / "venv").mkdir(parents=True)
    link = tmp_path / "tree-alias"
    link.symlink_to(tree, target_is_directory=True)
    _realpath_keeps_the_spelling_of(monkeypatch, link)
    return tree, link


def _assert_the_other_spelling_reads_as_outside_by_text(
    tree: Path, link: Path, path: Path
) -> None:
    """What makes ``path`` a spelling the text compare misses and identity finds."""
    assert (os.stat(link).st_dev, os.stat(link).st_ino) == (
        os.stat(tree).st_dev,
        os.stat(tree).st_ino,
    ), "the link is not the same directory as the tree"
    assert os.path.realpath(path) == os.path.abspath(path), (
        "realpath did not keep the spelling under the link"
    )
    assert os.path.commonpath(
        [os.path.realpath(path), os.path.realpath(tree)]
    ) != os.path.realpath(tree), "the text compare would already find the path inside"


def _tree_and_a_sibling(tmp_path: Path) -> tuple[Path, Path]:
    """The tree and a directory beside it, each holding a ``venv`` directory."""
    tree = tmp_path / "tree"
    (tree / "venv").mkdir(parents=True)
    sibling = tmp_path / "sibling"
    (sibling / "venv").mkdir(parents=True)
    return tree, sibling


def _stat_like(found, **replaced):
    """``found``, an ``os.stat`` result, with some fields replaced."""
    fields = {
        name: getattr(found, name) for name in dir(found) if name.startswith("st_")
    }
    fields.update(replaced)
    return types.SimpleNamespace(**fields)


def _volume_ignores_letter_case(directory: Path) -> bool:
    """Whether the volume under ``directory`` gives one file two spellings that differ
    in letter case: the default macOS and Windows volumes do, Linux's usual ones do
    not."""
    (directory / "Case-Probe").write_bytes(b"")
    return (directory / "case-probe").exists()


@needs_symlinks
def test_a_path_through_another_spelling_of_the_tree_is_refused(tmp_path, monkeypatch):
    """The path's real path is not under the tree's as text, yet the tree is the path's
    parent by device and inode: the check refuses it as it refuses the tree's own."""
    tree, link = _tree_and_its_other_spelling(monkeypatch, tmp_path)
    path = link / "venv"
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, path)
    shown = f"--virtualenv-path {path}"

    refusal = ip.in_tree_path_refusal(shown, path, tree)

    assert refusal is not None
    assert refusal.startswith(f"{shown}:"), refusal
    assert INSIDE in refusal, refusal


@needs_symlinks
def test_a_path_not_made_yet_under_another_spelling_of_the_tree_is_refused(
    tmp_path, monkeypatch
):
    """The target of ``--create-virtualenv`` does not exist: the walk skips the
    components that are missing and reads the link, which is the tree."""
    tree, link = _tree_and_its_other_spelling(monkeypatch, tmp_path)
    path = link / "not-yet" / "made"
    assert not (tree / "not-yet").exists()
    assert not (tree / "not-yet" / "made").exists()
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, path)
    shown = f"--virtualenv-path {path}"

    refusal = ip.in_tree_path_refusal(shown, path, tree)

    assert refusal is not None
    assert refusal.startswith(f"{shown}:"), refusal
    assert INSIDE in refusal, refusal


@needs_symlinks
def test_a_forced_binary_named_through_another_spelling_of_the_tree_is_refused(
    tmp_path, monkeypatch
):
    """A program inside the tree, named through the link, is refused before it is
    hashed; the file is never started."""
    tree, link = _tree_and_its_other_spelling(monkeypatch, tmp_path)
    marker = tmp_path / "RAN"
    program = write_stand_in(
        tree, "checkov", f"open({str(marker)!r}, 'w').close()\n"
    ).files[-1]
    path_text = str(link / program.name)
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, Path(path_text))

    result = ip.validate_forced_binary("checkov", path_text, tree)

    assert isinstance(result, str), result
    assert result.startswith(f"--binary-path checkov={path_text}:"), result
    assert INSIDE in result, result
    assert not marker.exists()


def test_a_sibling_directory_on_the_same_device_is_admitted(tmp_path):
    """A directory beside the tree shares its device and not its inode: a compare of
    the device alone would call it inside."""
    tree, sibling = _tree_and_a_sibling(tmp_path)
    assert os.stat(sibling).st_dev == os.stat(tree).st_dev
    assert os.stat(sibling).st_ino != os.stat(tree).st_ino
    path = sibling / "venv"

    assert ip.in_tree_path_refusal(f"--virtualenv-path {path}", path, tree) is None


def test_the_trees_own_parent_is_admitted(tmp_path):
    """The walk goes up from the path, so the tree's parent is outside it: the tree
    is not an ancestor of its own parent."""
    tree = tmp_path / "tree"
    (tree / "venv").mkdir(parents=True)

    refusal = ip.in_tree_path_refusal(f"--virtualenv-path {tmp_path}", tmp_path, tree)

    assert refusal is None


def test_without_inode_numbers_the_real_path_compare_alone_decides(
    tmp_path, patch_module_os
):
    """A filesystem that reports no inode numbers (st_ino 0) is judged by the text
    compare: the tree's own directory is still refused, and a sibling is not taken
    for the tree on a device number alone."""
    tree, sibling = _tree_and_a_sibling(tmp_path)
    real_stat = os.stat

    def stat_without_inode_numbers(path, *args, **kwargs):
        return _stat_like(real_stat(path, *args, **kwargs), st_ino=0)

    patch_module_os(ip, stat=stat_without_inode_numbers)
    patch_module_os(scanned_tree, stat=stat_without_inode_numbers)
    assert scanned_tree.os.stat(tree).st_ino == 0
    assert scanned_tree.os.stat(sibling).st_ino == 0
    outside = sibling / "venv"
    inside = tree / "venv"

    assert (
        ip.in_tree_path_refusal(f"--virtualenv-path {outside}", outside, tree) is None
    )
    refusal = ip.in_tree_path_refusal(f"--virtualenv-path {inside}", inside, tree)
    assert refusal is not None
    assert INSIDE in refusal, refusal


def test_another_device_reporting_the_trees_inode_number_is_admitted(
    tmp_path, patch_module_os
):
    """Inode numbers are only unique within one device: a directory that reports the
    tree's inode number on another device is not the tree."""
    tree, sibling = _tree_and_a_sibling(tmp_path)
    real_stat = os.stat
    tree_stat = real_stat(tree)
    sibling_stat = real_stat(sibling)
    sibling_identity = (sibling_stat.st_dev, sibling_stat.st_ino)

    def stat_of_another_device(path, *args, **kwargs):
        found = real_stat(path, *args, **kwargs)
        if (found.st_dev, found.st_ino) == sibling_identity:
            return _stat_like(
                found, st_dev=tree_stat.st_dev + 1, st_ino=tree_stat.st_ino
            )
        return found

    patch_module_os(ip, stat=stat_of_another_device)
    patch_module_os(scanned_tree, stat=stat_of_another_device)
    reported = scanned_tree.os.stat(sibling)
    assert reported.st_ino == tree_stat.st_ino
    assert reported.st_dev != tree_stat.st_dev
    assert scanned_tree.os.stat(tree).st_dev == tree_stat.st_dev
    path = sibling / "venv"

    assert ip.in_tree_path_refusal(f"--virtualenv-path {path}", path, tree) is None


@needs_symlinks
def test_the_in_tree_opt_in_admits_a_path_through_another_spelling_of_the_tree(
    tmp_path, monkeypatch
):
    """The opt-in is read after the decision that the path is inside, so it admits a
    path found inside by identity as it admits one found inside by text."""
    tree, link = _tree_and_its_other_spelling(monkeypatch, tmp_path)
    path = link / "venv"
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, path)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")

    assert ip.in_tree_path_refusal(f"--virtualenv-path {path}", path, tree) is None


def test_a_path_holding_a_nul_character_is_answered_as_before(tmp_path):
    """A path no operating system call accepts is outside the tree, as it was before
    the identity compare: the call answers None and raises nothing."""
    tree, sibling = _tree_and_a_sibling(tmp_path)
    path = sibling / "venv\x00"

    result = ip.in_tree_path_refusal(f"--virtualenv-path {path}", path, tree)

    assert result is None


def test_the_tree_named_in_another_letter_case_is_refused_on_a_case_insensitive_volume(
    tmp_path,
):
    """Replaces nothing: where the volume ignores letter case, the tree named in
    another case is the tree."""
    if not _volume_ignores_letter_case(tmp_path):
        pytest.skip("this volume tells letter cases apart")
    tree, _ = _tree_and_a_sibling(tmp_path)
    path = tmp_path / tree.name.upper() / "venv"
    assert path.is_dir()
    shown = f"--virtualenv-path {path}"

    refusal = ip.in_tree_path_refusal(shown, path, tree)

    assert refusal is not None
    assert refusal.startswith(f"{shown}:"), refusal
    assert INSIDE in refusal, refusal
