"""``--virtualenv-path`` refuses a virtualenv inside the scanned tree under any spelling.

The command treats its working directory as the scanned source tree and refuses a
virtualenv inside it (its interpreter is a program the tree can supply and the install
commands would run), unless ``ASH_ALLOW_IN_TREE_TOOLS`` is set. The tree named in
another letter case on a volume that ignores case, or reached through a bind mount, is
the same directory under another spelling, and a scan counts it as the tree. The
refusal has to agree, or the flag is a way around it.

The tests that make a link stand in for such a spelling: a link beside the tree names
it, and ``os.path.realpath`` keeps a path under the link as written, which is what it
returns for a case variant or a bind mount. ``os.stat`` is left alone: it reads
through the link and reports the tree's device and inode, as it would for either. The
test that replaces nothing runs only where the volume under ``tmp_path`` ignores
letter case.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="a symlink needs a privilege on Windows"
)

INSIDE = "inside the scanned source tree"


def _venv(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
    return path


def _scene(monkeypatch, tmp_path, **kwargs):
    scene = build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=lambda cmd: f"/venv/bin/{cmd}",
        **kwargs,
    )
    # The command's working directory is the scanned source tree.
    tree = tmp_path / "src-tree"
    tree.mkdir(exist_ok=True)
    monkeypatch.chdir(tree)
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    return scene


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


def _a_link_to_the_tree(monkeypatch, tmp_path: Path) -> Path:
    """A link beside the working tree that names it, as another spelling of it."""
    link = tmp_path / "src-tree-alias"
    link.symlink_to(tmp_path / "src-tree", target_is_directory=True)
    _realpath_keeps_the_spelling_of(monkeypatch, link)
    return link


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


def _volume_ignores_letter_case(directory: Path) -> bool:
    """Whether the volume under ``directory`` gives one file two spellings that differ
    in letter case: the default macOS and Windows volumes do, Linux's usual ones do
    not."""
    (directory / "Case-Probe").write_bytes(b"")
    return (directory / "case-probe").exists()


@needs_symlinks
def test_a_virtualenv_inside_the_tree_named_through_another_spelling_is_refused(
    tmp_path, monkeypatch
):
    """The virtualenv is in the tree; the flag names it through a link to the tree,
    so its real path is not under the tree's as text. It is refused before anything
    is installed, as it is when named through the tree's own spelling."""
    scene = _scene(monkeypatch, tmp_path)
    tree = tmp_path / "src-tree"
    _venv(tree / ".venv")
    link = _a_link_to_the_tree(monkeypatch, tmp_path)
    named = link / ".venv"
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, named)

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(named))

    assert scene.result.exit_code == 3, scene.text
    assert INSIDE in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


@needs_symlinks
def test_create_never_vends_a_virtualenv_inside_the_tree_named_through_another_spelling(
    tmp_path, monkeypatch
):
    """With ``--create-virtualenv`` the target does not exist yet: the refusal comes
    before anything is created, so no virtualenv is made inside the tree."""

    def on_run(cmd):
        if cmd[:2] == ["uv", "venv"]:
            _venv(Path(cmd[-1]))
        return 0

    scene = _scene(monkeypatch, tmp_path, on_run=on_run)
    tree = tmp_path / "src-tree"
    link = _a_link_to_the_tree(monkeypatch, tmp_path)
    named = link / "fresh-venv"
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, named)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--virtualenv-path",
        str(named),
        "--create-virtualenv",
    )

    assert scene.result.exit_code == 3, scene.text
    assert INSIDE in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls
    assert not (tree / "fresh-venv").exists()


@needs_symlinks
def test_the_in_tree_opt_in_admits_a_tree_virtualenv_named_through_another_spelling(
    tmp_path, monkeypatch
):
    """An operator who owns the tree can say so: the opt-in is read after the
    decision that the path is inside, whichever spelling found it inside."""
    scene = _scene(monkeypatch, tmp_path)
    tree = tmp_path / "src-tree"
    _venv(tree / ".venv")
    link = _a_link_to_the_tree(monkeypatch, tmp_path)
    named = link / ".venv"
    _assert_the_other_spelling_reads_as_outside_by_text(tree, link, named)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(named))

    assert scene.result.exit_code == 0, scene.text
    assert [c[:2] for c in scene.argvs] == [["uv", "pip"]], scene.argvs


def test_a_virtualenv_named_with_the_tree_in_another_letter_case_is_refused_on_a_case_insensitive_volume(
    tmp_path, monkeypatch
):
    """Replaces nothing: where the volume ignores letter case, the tree named in
    another case is the tree."""
    if not _volume_ignores_letter_case(tmp_path):
        pytest.skip("this volume tells letter cases apart")
    scene = _scene(monkeypatch, tmp_path)
    tree = tmp_path / "src-tree"
    _venv(tree / ".venv")
    named = tmp_path / tree.name.upper() / ".venv"
    assert named.is_dir()

    run_install(scene, monkeypatch, tmp_path, "--virtualenv-path", str(named))

    assert scene.result.exit_code == 3, scene.text
    assert INSIDE in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls
