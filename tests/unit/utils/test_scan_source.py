# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where a scan looked, as the scan records it on its results.

The aws-security-hub reporter archives a stored finding only when it was found
under the same scope, and the scope starts with the scanned directory relative
to its git repository's root. The scan records the label while the directory
exists. A reporter working it out when it runs, from the directory the results
name, would fail for a collector running ``ash merge`` without the checkout, or
``ash report`` on another host: those cannot see that directory, would get an
absolute path instead of the shards' ``.``, and would archive nothing.

Tests that build real repositories do it under ``isolated_tmp``: tmp_path made an
empty repository that excludes everything, with GIT_CEILING_DIRECTORIES there
(tests/utils/git_isolation.py). A repository below an enclosing one records
nothing by design, and a ceiling hides the repositories at and above it only when
none of them tracks or lists what is below it. So the tests that expect "." need
tmp_path outside every repository, as it is in CI; inside a checkout that lists
it, those roots are nested.
"""

import errno
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import automated_security_helper.config.sandbox_grants as sandbox_grants
from automated_security_helper.utils.get_scan_set import (
    get_changed_files,
    git_common_dir,
    git_index_paths_below,
    git_repository_root,
    git_untracked_paths_below,
    git_worktree_paths,
)
from automated_security_helper.utils.scan_source import (
    NO_SCAN_SOURCE_CASES,
    SCAN_SOURCE_ENV,
    _gitfile_shaped,
    _marks_a_checkout,
    host_scan_source_label,
    is_relative_scan_source,
    recorded_scan_source,
    repository_is_nested,
    scan_source_label,
)
from tests.utils.git_isolation import isolate_git_at
from tests.utils.helpers import importing_this_checkout

#: What a scan the container launcher started sees: the ASH image sets
#: ASH_IN_CONTAINER (Dockerfile: ENV ASH_IN_CONTAINER="YES"), and the launcher
#: (run_ash_container) sets ASH_ACTUAL_SOURCE_DIR to the host directory and
#: ASH_SCAN_SOURCE to the label it worked out there, "" when it could not.
#: The legacy wrappers (./ash, ash_helpers.ps1) set ASH_ACTUAL_SOURCE_DIR and
#: mount /src too, but pass no ASH_SCAN_SOURCE.
WRAPPER = {"ASH_IN_CONTAINER": "YES", "ASH_ACTUAL_SOURCE_DIR": "/host/checkout"}


def _launcher(label):
    return {**WRAPPER, SCAN_SOURCE_ENV: label}


#: The ASH image run without the launcher, a wrapper or a /src mount (as a CI job
#: image, say): ASH_IN_CONTAINER only.
IMAGE_ONLY = {"ASH_IN_CONTAINER": "YES"}


def _not_nested(root):
    return False


@pytest.mark.unit
def test_the_repository_root_is_dot(tmp_path):
    assert scan_source_label(tmp_path, tmp_path) == "."


@pytest.mark.unit
def test_a_directory_below_the_root_is_relative_to_it(tmp_path):
    narrow = tmp_path / "services" / "api"
    narrow.mkdir(parents=True)
    assert scan_source_label(narrow, tmp_path) == "services/api"


@pytest.mark.unit
def test_outside_a_repository_the_absolute_path_is_used(tmp_path):
    assert scan_source_label(tmp_path, None) == tmp_path.resolve().as_posix()


@pytest.mark.unit
def test_a_root_that_does_not_contain_the_directory_gives_its_absolute_path(
    tmp_path,
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    assert scan_source_label(elsewhere, root) == elsewhere.resolve().as_posix()


@pytest.mark.unit
def test_a_relative_source_dir_is_resolved_first(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    assert scan_source_label(Path("app"), tmp_path) == "app"


# --------------------------------------------------------------------------- #
# What a scan records, with a stand-in for git
# --------------------------------------------------------------------------- #
#
# In container mode the scanned directory is always /src, and git there often
# cannot see the repository: a subdirectory mount has no .git, a linked
# worktree's .git file names a host path, and git refuses a mount it does not
# own. Every such scan recorded "/src", so container scans of services/api and
# services/web shared one scope and the second archived the first's findings.
# These tests stand in for git and for the enclosing-repository check.


def _root_at(root):
    calls = []

    def find_root(path):
        calls.append(path)
        return root

    find_root.calls = calls
    return find_root


def _record(source, root, environ, **kwargs):
    return recorded_scan_source(
        source, _root_at(root), environ, is_nested=_not_nested, **kwargs
    )


def _repository_at(root):
    """*root*, holding a .git entry as a repository root does, for a stand-in git
    that names it as the root."""
    (root / ".git").mkdir()
    return root


@pytest.mark.unit
def test_outside_the_container_the_scan_works_it_out(tmp_path):
    narrow = tmp_path / "services" / "api"
    narrow.mkdir(parents=True)
    assert _record(narrow, _repository_at(tmp_path), {}) == "services/api"


@pytest.mark.unit
def test_outside_the_container_the_variable_is_ignored(tmp_path):
    """Only the ASH image sets ASH_IN_CONTAINER; a host environment that happens
    to carry ASH_SCAN_SOURCE does not choose the scope."""
    environ = {SCAN_SOURCE_ENV: "services/web"}
    assert _record(tmp_path, _repository_at(tmp_path), environ) == "."


@pytest.mark.unit
def test_inside_the_container_the_launchers_label_wins(tmp_path):
    find_root = _root_at(tmp_path)
    environ = _launcher("services/api")

    assert recorded_scan_source(
        tmp_path, find_root, environ, is_nested=_not_nested
    ) == ("services/api")
    assert find_root.calls == []


@pytest.mark.unit
def test_the_launchers_empty_label_records_nothing(tmp_path):
    """The launcher passes "" when the host saw no repository, or one nested in
    another. Git in the container sees only the mount, so it would call a nested
    clone's root "." like the outer repository's; it is not asked."""
    find_root = _root_at(tmp_path)

    assert (
        recorded_scan_source(tmp_path, find_root, _launcher(""), is_nested=_not_nested)
        is None
    )
    assert find_root.calls == []


@pytest.mark.unit
def test_a_wrapper_run_records_nothing_even_where_git_sees_a_repository(tmp_path):
    """The legacy wrappers pass no label at all. Git in the container sees only
    the mount, so a nested clone's mount, or a subdirectory mount of a linked
    worktree git still reads, would be "." like the whole repository's. The scan
    records nothing, and git is not asked."""
    find_root = _root_at(tmp_path)

    assert (
        recorded_scan_source(tmp_path, find_root, WRAPPER, is_nested=_not_nested)
        is None
    )
    assert find_root.calls == []


@pytest.mark.unit
def test_a_wrapper_run_git_cannot_see_into_records_nothing_rather_than_src(
    tmp_path,
):
    """No label and no repository: no scan_source, so the scan archives nothing,
    instead of a "/src" every container scan would share."""
    assert _record(tmp_path, None, WRAPPER) is None


@pytest.mark.parametrize(
    "label",
    [
        "",
        "../other-repo",
        "services/../../other",
        "/abs/path",
        "services;converted=yes",
        "services\\api",
        "services//api",
        "services/api/",
        "services\napi",
        "C:/Users/x",
        "C:",
        "c:/x",
        "a:b/c",
        "caf\udce9",
    ],
    ids=[
        "empty",
        "parent",
        "parent-inside",
        "absolute",
        "semicolon",
        "backslash",
        "empty-segment",
        "trailing-slash",
        "control",
        "windows-drive",
        "bare-drive",
        "lowercase-drive",
        "drive-like-segment",
        "not-utf-8",
    ],
)
@pytest.mark.unit
def test_a_label_that_is_not_a_plain_relative_path_is_not_used(tmp_path, label):
    """And git in the container is not asked instead: the root it would find
    is the one the label already failed to describe."""
    assert not is_relative_scan_source(label)
    assert _record(tmp_path, tmp_path, _launcher(label)) is None


@pytest.mark.parametrize("label", [".", "app", "services/api", "a-b_c.d/e"])
@pytest.mark.unit
def test_plain_relative_labels_are_used(tmp_path, label):
    assert _record(tmp_path, None, _launcher(label)) == label


# --------------------------------------------------------------------------- #
# Workspace projects inside the launcher's container
# --------------------------------------------------------------------------- #
#
# The launcher's label names the workspace mount, not its projects. A project
# records its own directory, as git in the container sees it, only when the
# host says the mount is a repository's root ("."): below a nested root, or a
# subdirectory of a repository, git in the container sees a different root.


@pytest.mark.unit
def test_a_workspace_project_under_a_mount_at_a_repository_root_lets_git_decide(
    tmp_path,
):
    project = tmp_path / "api"
    project.mkdir()
    root = _repository_at(tmp_path)
    assert _record(project, root, _launcher("."), workspace_project=True) == ("api")


@pytest.mark.parametrize("mount_label", ["", "services"])
@pytest.mark.unit
def test_a_workspace_project_under_any_other_mount_records_nothing(
    tmp_path, mount_label
):
    project = tmp_path / "api"
    project.mkdir()
    environ = _launcher(mount_label)
    assert _record(project, tmp_path, environ, workspace_project=True) is None


@pytest.mark.unit
def test_a_workspace_project_in_a_wrapper_run_records_nothing(tmp_path):
    project = tmp_path / "api"
    project.mkdir()
    assert _record(project, tmp_path, WRAPPER, workspace_project=True) is None


# --------------------------------------------------------------------------- #
# The image without the launcher
# --------------------------------------------------------------------------- #
#
# The ASH image used as a CI job image (a GitLab `image:`, a GitHub `container:`)
# sets ASH_IN_CONTAINER and passes no label. Unless it mounts the directory at
# /src or sets ASH_ACTUAL_SOURCE_DIR (as the legacy wrappers and a hand-written
# `docker run -v "$PWD:/src"` do, which count as the launcher's), such a run
# scans its own directory, often one git cannot see (not a repository, or
# refused as owned by another user), and records it as a scan on a host would:
# recording nothing meant it never archived.


@pytest.mark.unit
def test_the_image_without_the_launcher_records_the_directory_as_a_host_would(
    tmp_path,
):
    builds = tmp_path / "builds" / "group" / "project"
    builds.mkdir(parents=True)
    assert _record(builds, None, IMAGE_ONLY) == builds.resolve().as_posix()


@pytest.mark.unit
def test_the_image_without_the_launcher_ignores_a_label(tmp_path):
    environ = {**IMAGE_ONLY, SCAN_SOURCE_ENV: "services/api"}
    assert _record(tmp_path, _repository_at(tmp_path), environ) == "."


@pytest.mark.unit
def test_a_scan_of_src_inside_the_image_counts_as_the_launchers(tmp_path):
    """The legacy wrapper mounts the source at /src and passes no label, so the
    scan records nothing, even where git there reports a repository root above
    /src (here "/", which would label it "src")."""
    assert _record(Path("/src"), Path("/"), IMAGE_ONLY) is None


# --------------------------------------------------------------------------- #
# Real repositories: submodules, nested clones, linked worktrees
# --------------------------------------------------------------------------- #
#
# git_repository_root answers with the innermost repository, so a submodule's
# root (and a nested clone's) was labeled "." like the superproject's own root.
# A monorepo scanned per directory under one findings_scope then gave its
# vendor/lib scan the root scan's scope, and archiving archived the root scan's
# findings outside vendor/lib. Nesting is decided on the filesystem, not by
# asking git about the parent, which fails open where git cannot read it.


def _git(*args, cwd):
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "protocol.file.allow=always",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _repo_with_a_commit(path: Path) -> Path:
    path.mkdir(parents=True)
    _git("init", "-q", cwd=path)
    (path / "README.md").write_text("fixture\n", encoding="utf-8")
    _git("add", "README.md", cwd=path)
    _git("commit", "-qm", "fixture", cwd=path)
    return path


@pytest.fixture
def isolated_tmp(tmp_path, monkeypatch):
    """A directory below tmp_path, with git and the nesting check kept from
    looking above tmp_path.

    tmp_path is an empty repository that excludes everything, and the ceiling
    (GIT_CEILING_DIRECTORIES) is there: git does not move up into it, and the
    repository it hides holds nothing below it, so the nesting check honors it.
    A tmp_path inside some other work tree (a basetemp under a worktree, a CI
    workspace) changes nothing here. The ceiling is ``isolated_tmp.parent``.
    """
    isolate_git_at(tmp_path, monkeypatch)
    below = tmp_path / "fx"
    below.mkdir()
    return below


@pytest.fixture
def superproject(isolated_tmp):
    """A repository with a file:// submodule at vendor/lib."""
    library = _repo_with_a_commit(isolated_tmp / "library")
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("submodule", "add", "-q", library.as_uri(), "vendor/lib", cwd=root)
    return root


@pytest.mark.integration
def test_a_submodule_records_no_scan_source(superproject):
    lib = superproject / "vendor" / "lib"
    assert git_repository_root(lib) == lib.resolve()  # the innermost repository

    assert recorded_scan_source(lib, git_repository_root, {}) is None
    assert host_scan_source_label(lib, git_repository_root) is None


# --------------------------------------------------------------------------- #
# GIT_CEILING_DIRECTORIES
# --------------------------------------------------------------------------- #
#
# git does not move up into a directory the variable lists, so with the ceiling
# at the superproject, at vendor, or at a symlinked path to either, git never
# sees the superproject from vendor/lib. A nesting walk that stopped there too
# would have vendor/lib, a nested clone and a planted gitfile record "." like the
# superproject's root: their scopes would collide, and archiving could mark the
# superproject's ACTIVE findings ARCHIVED. A ceiling is honored only when
# the repository it hides neither tracks the root, or a path between them, nor
# lists the root as untracked and not ignored. It stays the opt-out for a
# checkout under an enclosing repository that ignores it (a home directory kept
# in git).


@pytest.mark.integration
def test_a_ceiling_at_the_superproject_leaves_its_submodule_nested(
    superproject, monkeypatch
):
    """git cannot see the superproject from vendor, and still the submodule
    records nothing: the superproject tracks vendor/lib as a gitlink."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject))
    lib = superproject / "vendor" / "lib"
    assert git_repository_root(superproject / "vendor") is None

    assert repository_is_nested(lib)
    assert recorded_scan_source(lib, git_repository_root, {}) is None
    assert host_scan_source_label(lib, git_repository_root) is None


@pytest.mark.integration
def test_with_no_ceiling_a_repository_inside_another_is_nested(
    isolated_tmp, monkeypatch
):
    outer = _repo_with_a_commit(isolated_tmp / "outer")
    inner = _repo_with_a_commit(outer / "third_party" / "inner")
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES")

    assert repository_is_nested(inner)


@pytest.mark.integration
def test_with_no_ceiling_a_repository_outside_every_other_records_dot(
    tmp_path, monkeypatch
):
    """With no ceiling set, a repository with no .git above it is its own
    root. Every other real-git test here sets a ceiling, so this is the one that
    runs the walk to the top of the file system."""
    if any(
        _marks_a_checkout(parent / ".git") for parent in (tmp_path, *tmp_path.parents)
    ):
        pytest.skip("tmp_path is inside a repository here")
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    root = _repo_with_a_commit(tmp_path / "solo")

    assert repository_is_nested(root) is False
    assert recorded_scan_source(root, git_repository_root, {}) == "."


@pytest.mark.integration
def test_the_superprojects_own_root_is_dot(superproject):
    assert recorded_scan_source(superproject, git_repository_root, {}) == "."
    assert host_scan_source_label(superproject, git_repository_root) == "."


@pytest.mark.integration
def test_a_clone_nested_in_another_repository_records_no_scan_source(isolated_tmp):
    outer = _repo_with_a_commit(isolated_tmp / "outer")
    inner = _repo_with_a_commit(outer / "third_party" / "inner")

    assert repository_is_nested(inner)
    assert recorded_scan_source(inner, git_repository_root, {}) is None
    assert host_scan_source_label(inner, git_repository_root) is None
    assert host_scan_source_label(outer / "third_party", git_repository_root) == (
        "third_party"
    )


@pytest.mark.integration
def test_an_empty_git_directory_above_the_root_does_not_nest_it(isolated_tmp):
    """What a stray mkdir or a transient mount point leaves in an ancestor.

    git's own discovery would not open an empty ``.git`` directory, so it
    must not mark every repository below it nested and cost them their scan
    source."""
    holder = isolated_tmp / "share"
    (holder / ".git").mkdir(parents=True)
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root) is False
    assert recorded_scan_source(root, git_repository_root, {}) == "."


@pytest.mark.integration
def test_a_git_file_without_the_gitfile_format_above_the_root_does_not_nest_it(
    isolated_tmp,
):
    """A stray regular file named ``.git`` whose content is not
    ``gitdir: <path>`` is nothing git would read, so it is no repository
    marker either."""
    holder = isolated_tmp / "share"
    holder.mkdir()
    (holder / ".git").write_text("not a gitfile\n", encoding="utf-8")
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root) is False
    assert recorded_scan_source(root, git_repository_root, {}) == "."


@pytest.mark.integration
def test_a_gitfile_above_the_root_nests_it(isolated_tmp):
    """An ancestor whose ``.git`` is a gitfile in git's format -- a linked
    worktree created outside its checkout (``git worktree add ../wt``) -- is
    a repository above the root. The worktree sits beside the checkout, not
    inside it, so its gitfile is the only marker between the clone and the
    ceiling: this cell fails if the gitfile branch of ``_marks_a_checkout``
    stops counting it, where a worktree inside the checkout would still be
    nested by the checkout's own ``.git`` directory."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "../wt", cwd=checkout)
    inner = _repo_with_a_commit(isolated_tmp / "wt" / "third_party" / "inner")
    assert not os.path.lexists(isolated_tmp / ".git")

    assert repository_is_nested(inner)
    assert recorded_scan_source(inner, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_hand_made_git_directory_with_a_head_above_the_root_nests_it(isolated_tmp):
    """A ``.git`` directory holding ``HEAD`` is the shape git's discovery
    opens, so it counts even when git itself cannot use it (no objects or
    refs here): wrongly answering "not nested" is the unsafe direction."""
    holder = isolated_tmp / "share"
    (holder / ".git").mkdir(parents=True)
    (holder / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root)
    assert recorded_scan_source(root, git_repository_root, {}) is None


_POSIX_MODES_NEEDED = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="file modes do not refuse the read here (Windows, or root)",
)

#: The owner cells need os.geteuid, which Windows lacks; they inject owners
#: through stand-ins and need no mode to refuse a read, so a root runner
#: keeps them.
_GETEUID_NEEDED = pytest.mark.skipif(
    os.name == "nt", reason="os.geteuid is absent on Windows"
)


@pytest.mark.integration
def test_a_git_symlink_to_a_real_git_dir_above_the_root_nests_it(isolated_tmp):
    """git follows a ``.git`` symlink to a real git directory, so an ancestor
    laid out that way is a repository above the root. This pins the link arm
    of ``_marks_a_checkout``: without it, such an ancestor would stop
    nesting, a real fail-open."""
    other = _repo_with_a_commit(isolated_tmp / "other")
    holder = isolated_tmp / "share"
    holder.mkdir()
    _symlink_or_skip(holder / ".git", str(other / ".git"))
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root)
    assert recorded_scan_source(root, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_dangling_git_symlink_above_the_root_nests_it(isolated_tmp):
    """A ``.git`` symlink above the root counts even dangling: placed
    content, so the conservative answer stands. ``os.path.lexists`` used to
    cover this for free; now the link arm of ``_marks_a_checkout`` does, and
    this cell fails without it."""
    holder = isolated_tmp / "share"
    holder.mkdir()
    _symlink_or_skip(holder / ".git", str(holder / "nowhere"))
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root)
    assert recorded_scan_source(root, git_repository_root, {}) is None


@_POSIX_MODES_NEEDED
@pytest.mark.integration
def test_an_unreadable_git_file_above_the_root_nests_it(isolated_tmp):
    """A regular ``.git`` file whose first bytes cannot be read counts: a
    repository marker cannot be ruled out there, so the walk fails closed
    rather than let an unreadable gitfile hide a repository above the
    root."""
    holder = isolated_tmp / "share"
    holder.mkdir()
    marker = holder / ".git"
    marker.write_text("gitdir: elsewhere\n", encoding="utf-8")
    # Where the mode does not refuse the read, the content would count on
    # its own and this cell would pin nothing: skip by name there.
    _mode_zero_refuses_or_skip(marker, marker.read_bytes, 0o644)
    try:
        root = _repo_with_a_commit(holder / "repo")

        assert repository_is_nested(root)
        assert recorded_scan_source(root, git_repository_root, {}) is None
    finally:
        os.chmod(marker, 0o644)


@pytest.mark.integration
def test_a_gitfile_without_gits_trailing_space_above_the_root_nests_it(isolated_tmp):
    """``_GITFILE_PREFIX`` is deliberately one byte looser than git's
    ``"gitdir: "``: ``gitdir:/x``, which git refuses, still counts, the side
    that errs toward "nested". This cell goes red if someone tightens the
    prefix to git's exact form believing it already matches git."""
    holder = isolated_tmp / "share"
    holder.mkdir()
    (holder / ".git").write_text("gitdir:/x\n", encoding="utf-8")
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root)
    assert recorded_scan_source(root, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_fifo_git_above_the_root_does_not_nest_it(isolated_tmp):
    """A FIFO named ``.git`` is nothing git opens, and reading it could wait
    on a writer: the walk answers from the lstat alone, with no open."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    holder = isolated_tmp / "share"
    holder.mkdir()
    os.mkfifo(holder / ".git")
    root = _repo_with_a_commit(holder / "repo")

    assert repository_is_nested(root) is False
    assert recorded_scan_source(root, git_repository_root, {}) == "."


@pytest.mark.integration
def test_a_git_entry_swapped_for_a_fifo_after_the_type_check_counts(
    isolated_tmp, monkeypatch
):
    """The race branch of ``_gitfile_shaped``: ``_marks_a_checkout``'s lstat
    saw a regular file and the entry became a FIFO before the open. What was
    opened is not a regular file, so a marker cannot be ruled out: fail
    closed, without reading it. The no-read half is asserted by counting:
    on POSIX the nonblocking open means a read could not wait anyway, so
    only the count shows one moving ahead of the ``fstat`` refusal, and on
    Windows, where the open flags are 0, that read is the wait on the
    writer the refusal prevents."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    swapped = isolated_tmp / ".git"
    os.mkfifo(swapped)
    reads = []
    real_read = os.read

    def counting(fd, size):
        reads.append(size)
        return real_read(fd, size)

    monkeypatch.setattr(os, "read", counting)

    assert _gitfile_shaped(swapped) is True
    assert reads == []


@pytest.mark.parametrize(
    ("exc_type", "err"),
    [
        pytest.param(PermissionError, errno.EACCES, id="EACCES"),
        pytest.param(OSError, errno.EIO, id="EIO"),
        pytest.param(OSError, errno.ESTALE, id="ESTALE"),
    ],
)
@pytest.mark.integration
def test_a_git_entry_whose_lookup_is_refused_counts(
    isolated_tmp, monkeypatch, exc_type, err
):
    """An ancestor ``.git`` whose lstat itself is refused or fails (an ACL
    denying attribute reads, a failing disk, a stale network handle) cannot
    be ruled out, so it counts: wrongly answering "not nested" is the unsafe
    direction. Only a lookup that proves there is no entry (ENOENT, ENOTDIR)
    answers False. The holder is plain -- nothing else nests ``root`` -- so
    the nesting answer is the injected failure's alone, and the control
    proves it: with no injection, nothing counts."""
    holder = isolated_tmp / "share"
    holder.mkdir()
    root = _repo_with_a_commit(holder / "repo")
    assert repository_is_nested(root) is False

    target = os.fspath(holder / ".git")
    real = os.lstat
    hits = []

    def refusing(name, *args, **kwargs):
        if not isinstance(name, int) and os.fspath(name) == target:
            hits.append(name)
            raise exc_type(err, "lookup refused", target)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", refusing)

    assert _marks_a_checkout(holder / ".git") is True
    assert repository_is_nested(root)
    assert hits


@_POSIX_MODES_NEEDED
@pytest.mark.integration
def test_an_unsearchable_git_directory_above_the_root_nests_it(isolated_tmp):
    """A ``.git`` directory whose ``HEAD`` the scanning user cannot look up
    counts: a repository cannot be ruled out there, so the walk fails closed
    rather than let an unsearchable directory hide one."""
    holder = isolated_tmp / "share"
    unsearchable = holder / ".git"
    unsearchable.mkdir(parents=True)
    # Where the mode does not refuse the lookup, the probe reaches a missing
    # HEAD instead of a refusal and the premise is gone: skip by name there.
    _mode_zero_refuses_or_skip(
        unsearchable, lambda: os.lstat(unsearchable / "HEAD"), 0o755
    )
    try:
        root = _repo_with_a_commit(holder / "repo")

        assert repository_is_nested(root)
        assert recorded_scan_source(root, git_repository_root, {}) is None
    finally:
        os.chmod(unsearchable, 0o755)


@pytest.mark.integration
def test_an_empty_git_directory_at_a_ceiling_does_not_nest_the_root(
    isolated_tmp, monkeypatch
):
    """The field shape: GIT_CEILING_DIRECTORIES names a shared directory (the
    system temp directory, in the container launcher's environment), and a
    transient empty ``.git`` sits at that ceiling. The hidden-repository walk
    behind the ceiling judges candidates by the same git shape as the main
    walk, so that entry holds nothing."""
    holder = isolated_tmp / "share"
    (holder / ".git").mkdir(parents=True)
    root = _repo_with_a_commit(holder / "repo")
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join([os.environ["GIT_CEILING_DIRECTORIES"], str(holder)]),
    )

    assert repository_is_nested(root) is False
    assert recorded_scan_source(root, git_repository_root, {}) == "."


def _reported_owner_of(monkeypatch, attribute, path, uid):
    """``os.stat``/``os.lstat`` stand-in: *path* reports *uid* as its owner.

    An unprivileged run cannot create a foreign-owned file, so the
    stranger shapes inject one. Everything else -- file descriptors
    included -- passes through to the real call.
    """
    real = getattr(os, attribute)
    target = os.fspath(path)

    def stand_in(name, *args, **kwargs):
        result = real(name, *args, **kwargs)
        if not isinstance(name, int) and os.fspath(name) == target:
            fields = list(result)
            fields[4] = uid  # st_uid
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(os, attribute, stand_in)


@_GETEUID_NEEDED
@pytest.mark.integration
def test_a_strangers_repository_in_a_shared_drop_still_nests_the_root(
    isolated_tmp, monkeypatch
):
    """Ownership stays out of the nesting walk. A stranger's repository above
    the root still covers the root in its own scans, so for nesting the
    stranger's ``.git`` counts; the checkout boundary keeps its own owner
    rule (``sandbox_grants._left_by_a_trusted_user``), which would refuse
    this same entry. This cell goes red if an owner check is put back into
    the walk."""
    outer = _repo_with_a_commit(isolated_tmp / "drop")
    root = _repo_with_a_commit(outer / "vendor" / "inner")
    os.chmod(outer, 0o1777)
    try:
        stranger = os.geteuid() + 1
        _reported_owner_of(monkeypatch, "lstat", outer / ".git", stranger)
        _reported_owner_of(monkeypatch, "stat", outer, 0)
        # The stand-ins are live: the boundary's owner rule refuses the entry.
        assert sandbox_grants._left_by_a_trusted_user(outer / ".git") is False

        assert repository_is_nested(root)
        assert recorded_scan_source(root, git_repository_root, {}) is None
    finally:
        os.chmod(outer, 0o755)


@pytest.mark.integration
def test_a_nested_clone_seen_alone_in_the_launchers_container_records_nothing(
    isolated_tmp,
):
    """Inside the container only the mount is visible, so git there calls a
    nested clone's root "." with nothing above it to say otherwise. The host
    knew, and passed an empty label."""
    mount = _repo_with_a_commit(isolated_tmp / "src")
    assert git_repository_root(mount) == mount.resolve()

    assert recorded_scan_source(mount, git_repository_root, _launcher("")) is None


@pytest.mark.integration
def test_a_linked_worktree_inside_the_checkout_keeps_its_own_label(isolated_tmp):
    """A worktree of the same repository (git worktree add inside the checkout,
    as agent tooling does) is not a nested repository."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = checkout / "wt" / "x"
    (worktree / "services").mkdir()

    assert not repository_is_nested(worktree)
    assert recorded_scan_source(worktree, git_repository_root, {}) == "."
    assert host_scan_source_label(worktree / "services", git_repository_root) == (
        "services"
    )


@pytest.mark.integration
def test_a_repository_below_an_enclosing_one_records_nothing(isolated_tmp):
    """A home directory kept in git encloses every checkout below it."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    project = _repo_with_a_commit(home / "src" / "project")

    assert recorded_scan_source(project, git_repository_root, {}) is None


# --------------------------------------------------------------------------- #
# A .git that points at the outer repository is not a worktree of it
# --------------------------------------------------------------------------- #
#
# An exception for a linked worktree of only "this repository's
# --git-common-dir is the ancestor's" would be too wide: a .git file (or
# symlink) planted in a subdirectory and pointing at the outer repository's git
# directory has that common dir too, so git would call the subdirectory a root,
# the scan would record "." for it, and archiving would read the whole
# repository's findings outside it as fixed. git does not check such a path out
# from a repository, but a tree writer can leave one (a vendored tarball, a
# build step, a copied worktree).
# A directory is exempt only when the ancestor's `git worktree list` names
# it, as git printed it, and its own --git-common-dir is the ancestor's. Each
# check catches cases the other misses: a symlink at a listed path, or a gitfile
# naming a real worktree's admin dir, shares the common dir; a listed path that
# now holds another repository is still listed.


def _forged(parent: Path, name: str, gitdir: str) -> Path:
    forged = parent / "forged" / name
    forged.mkdir(parents=True)
    (forged / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    return forged


@pytest.mark.integration
def test_a_gitfile_pointing_at_the_outer_git_dir_is_nested(isolated_tmp):
    root = _repo_with_a_commit(isolated_tmp / "super")
    forged = _forged(root, "gf_rel", "../../.git")
    # git takes it for a root of its own, which is what made it look like a
    # worktree of the outer repository.
    assert git_repository_root(forged) == forged.resolve()

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None
    assert host_scan_source_label(forged, git_repository_root) is None


@pytest.mark.integration
def test_a_gitfile_pointing_at_a_real_worktrees_admin_dir_is_nested(isolated_tmp):
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    admin = root / ".git" / "worktrees" / "x"
    assert admin.is_dir()
    forged = _forged(root, "gf_wtadmin", admin.as_posix())
    assert git_repository_root(forged) == forged.resolve()

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None
    # The worktree that admin dir belongs to is still exempt.
    assert recorded_scan_source(root / "wt" / "x", git_repository_root, {}) == "."


@pytest.mark.integration
def test_git_dir_set_to_a_worktree_admin_dir_does_not_move_the_root(
    isolated_tmp, monkeypatch
):
    """A pre-commit hook in a linked worktree runs with GIT_DIR set to that
    worktree's admin dir and no GIT_WORK_TREE (git 2.50.1). git then calls the
    current directory the root, so a scan of services/api from the hook was
    labeled ".", and later recorded nothing. The root lookup now leaves GIT_DIR
    out and lets git discover the repository from the scanned directory, so the
    root is the real one and the label is the directory's own."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    api = root / "services" / "api"
    api.mkdir(parents=True)
    monkeypatch.setenv("GIT_DIR", (root / ".git" / "worktrees" / "x").as_posix())
    assert git_repository_root(api) == root.resolve()

    assert recorded_scan_source(api, git_repository_root, {}) == "services/api"
    assert host_scan_source_label(api, git_repository_root) == "services/api"


@pytest.mark.integration
def test_a_hook_scanning_a_subdirectory_joins_the_diff_onto_the_real_root(
    isolated_tmp, monkeypatch
):
    """With GIT_DIR and no GIT_WORK_TREE, ``rev-parse --show-toplevel`` in
    ``<worktree>/src`` named ``<worktree>/src`` while ``diff --name-only`` named
    ``src/app.py`` from the real root, so a ``--source-dir src
    --changed-files-only`` scan from a pre-commit hook joined ``<worktree>/src/
    src/app.py``, matched no finding, and reported nothing at exit 0."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    worktree = root / "wt" / "x"
    src = worktree / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "src/app.py", cwd=worktree)
    _git("commit", "-qm", "add app", cwd=worktree)
    monkeypatch.setenv("GIT_DIR", (root / ".git" / "worktrees" / "x").as_posix())
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)

    found_root = git_repository_root(src)
    changed = get_changed_files("HEAD~1", cwd=src)

    assert found_root == worktree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]
    joined = [found_root / p for p in changed]
    assert all(p.is_file() for p in joined), joined


def _bare_repository_with_a_deployed_tree(parent: Path) -> "tuple[Path, Path]":
    """A bare clone and a checkout-less tree of its tip: (bare, tree).

    The tip's second commit changes ``src/app.py``; the tree holds that file and no
    ``.git`` entry, as a post-receive hook's deployment target does.
    """
    source = _repo_with_a_commit(parent / "source")
    (source / "src").mkdir()
    (source / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "src/app.py", cwd=source)
    _git("commit", "-qm", "add app", cwd=source)
    bare = parent / "deploy.git"
    _git("clone", "-q", "--bare", source.as_posix(), bare.as_posix(), cwd=parent)
    tree = parent / "deployed"
    (tree / "src").mkdir(parents=True)
    shutil.copyfile(source / "src" / "app.py", tree / "src" / "app.py")
    return bare, tree


@pytest.mark.integration
def test_a_bare_repository_named_with_its_work_tree_keeps_its_root_and_diff(
    isolated_tmp, monkeypatch
):
    """A post-receive hook deploys a checkout by running git as ``GIT_DIR=<bare>
    GIT_WORK_TREE=<tree>``; the tree has no ``.git`` entry for discovery to find.
    Dropping both variables for the root lookup made such a scan read "not a
    repository" and lose its changed-file filter. When the caller names an
    existing work tree, the pair is passed through as it was, and the root and the
    diff describe the repository the operator named."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    monkeypatch.setenv("GIT_DIR", bare.as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", tree.as_posix())
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    found_root = git_repository_root(tree / "src")
    changed = get_changed_files("HEAD~1", cwd=tree / "src")

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]
    assert all((found_root / p).is_file() for p in changed), changed


@pytest.mark.integration
def test_a_git_work_tree_naming_no_directory_is_not_honored(isolated_tmp, monkeypatch):
    """git answers ``rev-parse --show-toplevel`` with GIT_WORK_TREE as given, even
    when nothing exists there, so a stale export in a hook's environment would have
    joined the diff's paths onto a path that is not there. Only an existing
    directory is honored; otherwise the variables are dropped and the root is the
    one git discovers, as for a hook that exports GIT_DIR alone."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    api = root / "services" / "api"
    api.mkdir(parents=True)
    monkeypatch.setenv("GIT_DIR", (root / ".git" / "worktrees" / "x").as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", (isolated_tmp / "nowhere").as_posix())

    assert git_repository_root(api) == root.resolve()
    assert recorded_scan_source(api, git_repository_root, {}) == "services/api"


@pytest.mark.integration
def test_a_relative_git_work_tree_is_read_against_this_process_directory(
    isolated_tmp, monkeypatch
):
    """A relative GIT_WORK_TREE means "relative to the directory of the process
    that exported it", which is this process's own directory. Read against the
    scanned directory instead, ``deployed`` exported from the tree's parent named
    ``<tree>/src/deployed``, which does not exist, so the variables were dropped
    and the tree, which has no ``.git`` entry, read as no repository. The value
    is made absolute against this process's directory before git is started in
    the scanned one, and the root and the diff describe the named tree."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    monkeypatch.chdir(isolated_tmp)
    monkeypatch.setenv("GIT_DIR", bare.as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", "deployed")
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)
    assert not (tree / "src" / "deployed").exists()

    found_root = git_repository_root(tree / "src")
    changed = get_changed_files("HEAD~1", cwd=tree / "src")

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]
    assert all((found_root / p).is_file() for p in changed), changed


@pytest.mark.integration
def test_git_dir_alone_is_kept_when_the_repository_names_its_own_work_tree(
    isolated_tmp, monkeypatch
):
    """With ``core.worktree`` set, GIT_DIR alone describes the layout: git takes
    its working directory for the top only when neither GIT_WORK_TREE nor
    ``core.worktree`` is given. The drop of GIT_DIR alone (the hook shape, where
    the working directory would be taken for the top) also dropped this layout,
    and discovery from a tree with no ``.git`` entry answered "not a repository"
    where the base, passing GIT_DIR through, answered the configured tree."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    _git("config", "core.worktree", tree.as_posix(), cwd=source)
    monkeypatch.setenv("GIT_DIR", (source / ".git").as_posix())
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    found_root = git_repository_root(tree / "src")
    changed = get_changed_files("HEAD~1", cwd=tree / "src")

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_a_stale_git_dir_naming_another_repositorys_tree_is_not_honored(
    isolated_tmp, monkeypatch
):
    """A GIT_DIR left exported for another repository whose config sets
    ``core.worktree`` to its own tree is honored by git from any directory: the
    root lookup answered that other tree and the diff ran against that other
    history, so a scan of this repository read a root it was not in and a changed
    set that intersected the scanned directory to nothing. GIT_DIR alone is kept
    only when the configured tree holds the directory git starts in; otherwise
    the variable is dropped and this repository's own git answers."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    other = _repo_with_a_commit(isolated_tmp / "other")
    _git("config", "core.worktree", other.as_posix(), cwd=other)
    monkeypatch.setenv("GIT_DIR", (other / ".git").as_posix())
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    found_root = git_repository_root(source / "src")
    changed = get_changed_files("HEAD~1", cwd=source / "src")

    assert found_root == source.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_an_empty_git_work_tree_is_read_as_unset(isolated_tmp, monkeypatch):
    """A hook that exports ``GIT_WORK_TREE=`` (empty) means "not set"; git refuses
    the empty string as a path ("The empty string is not a valid path", exit 128)
    on the root lookup and the diff alike. Passed through beside a GIT_DIR whose
    repository names its tree with ``core.worktree``, the empty value turned a
    layout git honors with GIT_DIR alone into no root and every finding reported.
    An empty location variable is left out of the copy git is started with."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    _git("config", "core.worktree", tree.as_posix(), cwd=source)
    monkeypatch.setenv("GIT_DIR", (source / ".git").as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", "")
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    found_root = git_repository_root(tree / "src")
    changed = get_changed_files("HEAD~1", cwd=tree / "src")

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_a_foreign_object_store_does_not_hide_the_diffs_revision(
    isolated_tmp, monkeypatch
):
    """The changed-file diff compares two commits (``<base>...HEAD``), read from
    the object store; an exported GIT_OBJECT_DIRECTORY naming another store (a
    hook's quarantine left in the environment, a stale export) made that
    revision unreadable ("bad revision", exit 128), so the filter fell back to
    every finding. With no layout named, the diff reads the discovered
    repository's own objects."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    elsewhere = isolated_tmp / "empty-objects"
    elsewhere.mkdir()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", elsewhere.as_posix())

    changed = get_changed_files("HEAD~1", cwd=source / "src")

    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_a_relative_core_worktree_is_read_against_the_git_directory(
    isolated_tmp, monkeypatch
):
    """git reads a relative ``core.worktree`` against the git directory itself
    (``<source>/.git/../../deployed`` is ``<parent>/deployed``), and ``config
    --get`` prints it as written. The containment check joins it onto GIT_DIR
    before asking whether the tree holds the scanned directory; joined onto the
    scanned directory instead, ``<tree>/../../deployed`` would name nothing and
    the variable would be dropped, leaving a tree with no ``.git`` entry."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    _git("config", "core.worktree", "../../deployed", cwd=source)
    monkeypatch.setenv("GIT_DIR", (source / ".git").as_posix())
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)
    assert not (tree / ".." / ".." / "deployed").exists()

    found_root = git_repository_root(tree)
    changed = get_changed_files("HEAD~1", cwd=tree)

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_a_work_tree_named_without_its_repository_is_not_honored(
    isolated_tmp, monkeypatch
):
    """GIT_WORK_TREE alone makes git discover the repository from the directory it
    is started in and still report the named directory as the top, so the root
    and the diff's names described two trees. Only a pair (GIT_DIR too) names a
    layout; alone, the variable is dropped and the root is the discovered one."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.setenv("GIT_WORK_TREE", tree.as_posix())
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    assert git_repository_root(source / "src") == source.resolve()


@pytest.mark.integration
def test_a_pair_whose_tree_does_not_hold_the_scanned_directory_is_not_honored(
    isolated_tmp, monkeypatch
):
    """A pair left exported for another checkout names a tree the scanned directory
    is not in; honored, the scan read that checkout's root and changes, the
    changed set intersected to nothing, and every finding was discarded at exit
    0. The pair is honored only when the scanned directory is at or below the
    named tree; otherwise discovery answers for the directory itself."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    source = isolated_tmp / "source"
    monkeypatch.setenv("GIT_DIR", bare.as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", tree.as_posix())
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    assert git_repository_root(source / "src") == source.resolve()
    changed = get_changed_files("HEAD~1", cwd=source / "src")
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_a_hooks_relative_git_dir_names_the_repository_it_was_exported_in(
    isolated_tmp, monkeypatch
):
    """receive-pack starts a post-receive hook inside the repository with
    ``GIT_DIR=.`` exported; the hook exports the tree it deploys to and scans it.
    Passed on as written to a git started in the scanned tree, ``.`` named that
    tree and git answered "not a git repository: '.'", so the root lookup gave
    None and the diff fell back to every finding. Made absolute against this
    process's directory, the repository the hook runs in, both answer for it."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    monkeypatch.chdir(bare)
    monkeypatch.setenv("GIT_DIR", ".")
    monkeypatch.setenv("GIT_WORK_TREE", tree.as_posix())
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    found_root = git_repository_root(tree / "src")
    changed = get_changed_files("HEAD~1", cwd=tree / "src")

    assert found_root == tree.resolve()
    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_the_diff_with_no_directory_reads_a_work_tree_from_this_process_directory(
    isolated_tmp, monkeypatch
):
    """``get_changed_files`` takes no directory by default and git then starts in
    this process's own directory, so a GIT_WORK_TREE named there is read against
    it. Joining the value onto a missing directory raised TypeError instead, out
    of a ``try`` that catches only a missing git and a timeout, so a hook that
    exported GIT_DIR and GIT_WORK_TREE and called the default crashed the scan."""
    bare, tree = _bare_repository_with_a_deployed_tree(isolated_tmp)
    monkeypatch.chdir(tree / "src")
    monkeypatch.setenv("GIT_DIR", bare.as_posix())
    # From <tree>/src the tree itself is ../../deployed (it is <parent>/deployed).
    monkeypatch.setenv("GIT_WORK_TREE", "../../deployed")
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    changed = get_changed_files("HEAD~1")

    assert changed is not None and [p.as_posix() for p in changed] == ["src/app.py"]


@pytest.mark.integration
def test_the_list_check_holds_against_a_git_that_cannot_list_worktrees(
    isolated_tmp, monkeypatch
):
    """The list check fails closed when git cannot say which worktrees the
    ancestor has: a git older than 2.36 has no `worktree list -z`, and git
    refuses a repository another user owns (safe.directory). A real linked
    worktree then counts as nested and records nothing. With the admin-dir
    check this is defense in depth; this stub is what holds it."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = checkout / "wt" / "x"
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.git_worktree_paths",
        lambda path: None,
    )

    assert repository_is_nested(worktree)
    assert recorded_scan_source(worktree, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_worktree_whose_common_dir_git_cannot_give_is_nested(
    isolated_tmp, monkeypatch
):
    """Fail closed for the other check too: a listed worktree whose
    --git-common-dir git cannot give counts as nested."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = checkout / "wt" / "x"
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.git_common_dir",
        lambda path: None,
    )

    assert repository_is_nested(worktree)
    assert recorded_scan_source(worktree, git_repository_root, {}) is None


@pytest.mark.integration
def test_the_common_dir_check_holds_against_an_admin_commondir_edited_in_the_outer_git_dir(
    isolated_tmp,
):
    """wt/x's admin dir in checkout/.git still records wt/x, and git still lists
    it, but its commondir file is edited to name another repository's git dir,
    so git gives wt/x that repository's common dir. Only a write inside the
    outer git dir can do this; the common-dir check is defense in depth, and
    this is the layout that reaches it."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    other = _repo_with_a_commit(isolated_tmp / "other")
    (checkout / ".git" / "worktrees" / "x" / "commondir").write_text(
        f"{(other / '.git').resolve().as_posix()}\n", encoding="utf-8"
    )
    assert git_common_dir(worktree) == (other / ".git").resolve()

    assert repository_is_nested(worktree)
    assert recorded_scan_source(worktree, git_repository_root, {}) is None


def _registered_within(seconds: float, root: Path, common: Path):
    """_registered_worktree's answers, and whether it was still running after
    *seconds*."""
    from automated_security_helper.utils.scan_source import _registered_worktree

    answers: list = []
    thread = threading.Thread(
        target=lambda: answers.append(_registered_worktree(root, common)),
        daemon=True,
    )
    thread.start()
    thread.join(seconds)
    return thread.is_alive(), answers


@pytest.mark.parametrize(
    "kind", ["fifo", "symlink", "directory", "oversized", "unreadable"]
)
@pytest.mark.integration
def test_an_admin_gitdir_that_is_not_a_small_regular_file_is_not_a_record(
    isolated_tmp, kind
):
    """The admin dir's gitdir file is read with O_NOFOLLOW and O_NONBLOCK, must
    be a regular file, and is read up to PATH_MAX + 1 bytes. A FIFO or a symlink
    there is no record: the open neither blocks on the FIFO nor follows the
    link. Each answers "not registered" at once."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    common = git_common_dir(checkout)
    record = checkout / ".git" / "worktrees" / "x" / "gitdir"
    assert _registered_within(2, worktree, common) == (False, [True])
    text = record.read_text(encoding="utf-8")
    record.unlink()
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("no FIFOs here")
        os.mkfifo(record)
    elif kind == "symlink":
        (record.parent / "gitdir.real").write_text(text, encoding="utf-8")
        try:
            os.symlink("gitdir.real", record)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"cannot make a symlink here: {error}")
    elif kind == "directory":
        record.mkdir()
    elif kind == "oversized":
        # Still the right path once normalized: only its length is wrong.
        record.write_text(text.removesuffix("\n") + "/" * 8192 + "\n", encoding="utf-8")
    else:
        if os.name == "nt" or os.geteuid() == 0:
            pytest.skip("mode 0000 does not stop this user reading")
        record.write_text(text, encoding="utf-8")
        # Where the mode does not refuse the read, the record stays readable
        # and the row would fail on a correct answer: skip by name there.
        _mode_zero_refuses_or_skip(record, record.read_bytes, 0o644)

    try:
        still_running, answers = _registered_within(2, worktree, common)
    finally:
        if kind == "fifo":
            # Release a reader blocked in open(), so the thread ends.
            try:
                os.close(os.open(record, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        if kind == "unreadable":
            record.chmod(0o644)

    assert not still_running
    assert answers == [False]


@pytest.mark.integration
def test_a_record_ending_in_crlf_is_read_as_git_reads_it(isolated_tmp):
    """git trims the line end of the gitdir record when it reads it, and lists
    the worktree; a record written with CRLF (an editor, a Windows checkout of
    the admin dir) was read here with its carriage return, named another path,
    and made a real worktree nested."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    common = git_common_dir(checkout)
    record = checkout / ".git" / "worktrees" / "x" / "gitdir"
    text = record.read_text(encoding="utf-8").removesuffix("\n")
    record.write_bytes((text + "\r\n").encode("utf-8"))

    assert _registered_within(2, worktree, common) == (False, [True])
    assert not repository_is_nested(worktree)


def _git_lists_it(checkout: Path, worktree: Path) -> bool:
    """Whether ``git worktree list`` lists *worktree* and does not call it
    prunable: git read its admin dir's record as naming it."""
    listing = subprocess.run(
        ["git", "worktree", "list", "--porcelain", "-z"],
        cwd=checkout,
        capture_output=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    entries: list = []
    for field in listing.split(b"\0"):
        if field.startswith(b"worktree "):
            entries.append([os.fsdecode(field[len(b"worktree ") :]), []])
        elif field and entries:
            entries[-1][1].append(field)
    return any(
        path == str(worktree)
        and not any(attribute.startswith(b"prunable") for attribute in attributes)
        for path, attributes in entries
    )


@pytest.mark.parametrize(
    "ending",
    [
        "",
        "\n",
        "\r\n",
        "\r",
        "\n\n",
        "\r\r",
        "\n\r",
        "\r\r\n",
        " ",
        "\t",
        "\v",
        "\f",
        " \n",
        " \t\r\n",
    ],
    ids=[
        "none",
        "LF",
        "CRLF",
        "CR",
        "LFLF",
        "CRCR",
        "LFCR",
        "CRCRLF",
        "space",
        "tab",
        "VT",
        "FF",
        "space-LF",
        "mixed",
    ],
)
@pytest.mark.integration
def test_a_records_line_end_is_trimmed_as_git_trims_it(isolated_tmp, ending):
    """Where git lists the worktree after reading the gitdir record back, so
    does this check, and where git does not, neither does it: the answer is
    git's, measured here, for each ending. git 2.50 trims any run of carriage
    returns and newlines at the end, and no other whitespace; a lone carriage
    return was read here as part of the path, and made a real worktree
    nested."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    common = git_common_dir(checkout)
    record = checkout / ".git" / "worktrees" / "x" / "gitdir"
    text = record.read_text(encoding="utf-8").removesuffix("\n")
    record.write_bytes((text + ending).encode("utf-8"))
    listed = _git_lists_it(checkout, worktree)

    assert _registered_within(2, worktree, common) == (False, [listed])
    assert repository_is_nested(worktree) is not listed


@pytest.mark.skipif(os.name == "nt", reason="no file name holds a carriage return")
@pytest.mark.parametrize(
    "checkout_name, worktree_name",
    [("checkout", f"a{chr(13)}b"), (f"check{chr(13)}out", "x")],
    ids=["in the worktree's name", "in the checkout's name"],
)
@pytest.mark.integration
def test_a_carriage_return_in_a_worktree_path_is_read_as_written(
    isolated_tmp, checkout_name, worktree_name
):
    """git prints the paths as they are. Read in text mode, a lone carriage
    return in one became a newline, so git's listing named another path and a
    real linked worktree was nested."""
    checkout = _repo_with_a_commit(isolated_tmp / checkout_name)
    _git("worktree", "add", "-q", "-b", "side", f"wt/{worktree_name}", cwd=checkout)
    worktree = (checkout / "wt" / worktree_name).resolve()

    assert worktree in (git_worktree_paths(checkout) or set())
    assert git_common_dir(worktree) == (checkout / ".git").resolve()
    assert not repository_is_nested(worktree)


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
@pytest.mark.integration
def test_a_record_is_refused_where_the_open_cannot_refuse_it(
    isolated_tmp, monkeypatch, kind
):
    """Windows has neither O_NOFOLLOW nor O_NONBLOCK, so there the open follows
    a symlink, and fstat sees its target, a regular file. Both flags are dropped
    here, as they are there, and the entry's own type still refuses the record.
    (A FIFO stands in for what a flagless open would wait on.)"""
    from automated_security_helper.utils import scan_source

    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    common = git_common_dir(checkout)
    record = checkout / ".git" / "worktrees" / "x" / "gitdir"
    text = record.read_text(encoding="utf-8")
    record.unlink()
    if kind == "symlink":
        (record.parent / "gitdir.real").write_text(text, encoding="utf-8")
        try:
            os.symlink("gitdir.real", record)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"cannot make a symlink here: {error}")
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("no FIFOs here")
        os.mkfifo(record)
    release = os.O_WRONLY | getattr(os, "O_NONBLOCK", 0)
    monkeypatch.setattr(scan_source, "_RECORD_OPEN_FLAGS", os.O_RDONLY)

    try:
        still_running, answers = _registered_within(2, worktree, common)
    finally:
        if kind == "fifo":
            try:
                os.close(os.open(record, release))
            except OSError:
                pass

    assert not still_running
    assert answers == [False]


def _fifo_holding(record: Path, text: str) -> int:
    """A FIFO at *record* that holds *text* and has no writer, so a reader that
    opens it reads *text* and then end of file, with nothing to wait for.
    Returns the read end that keeps the text in it; the caller closes it."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    os.mkfifo(record)
    keep = os.open(record, os.O_RDONLY | os.O_NONBLOCK)
    writer = os.open(record, os.O_WRONLY | os.O_NONBLOCK)
    os.write(writer, text.encode("utf-8"))
    os.close(writer)
    return keep


@pytest.mark.integration
def test_a_fifo_its_writer_filled_and_closed_is_not_a_record(isolated_tmp):
    """O_NONBLOCK keeps an empty FIFO from blocking, but a writer can put the
    record into the FIFO and close it, and a read then returns the record. A
    regular-file check refuses it."""
    from automated_security_helper.utils import scan_source

    record = isolated_tmp / "gitdir"
    keep = _fifo_holding(record, "/somewhere/.git\n")
    try:
        assert scan_source._read_gitdir_record(record) is None
    finally:
        os.close(keep)


@pytest.mark.integration
def test_a_record_replaced_by_a_fifo_after_the_entry_check_is_refused(
    isolated_tmp, monkeypatch
):
    """The entry is checked before the open, so a FIFO renamed into its place in
    between is what gets opened, and fstat refuses it. A test cannot time that
    swap, so the entry check is made to pass instead: this holds the fstat
    check, which the entry check otherwise answers for first."""
    from automated_security_helper.utils import scan_source

    regular = isolated_tmp / "regular"
    regular.write_text("/somewhere/.git\n", encoding="utf-8")
    assert scan_source._read_gitdir_record(regular) == "/somewhere/.git\n"
    record = isolated_tmp / "gitdir"
    keep = _fifo_holding(record, "/somewhere/.git\n")
    monkeypatch.setattr(scan_source, "_is_regular_file", lambda path: True)
    try:
        assert scan_source._read_gitdir_record(record) is None
    finally:
        os.close(keep)


def _answer_within(seconds: float, call):
    """*call*'s answers, and whether it was still running after *seconds*."""
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(call()), daemon=True)
    thread.start()
    thread.join(seconds)
    return thread.is_alive(), answers


@pytest.mark.parametrize("entry", ["gitdir", "HEAD", "a linked admin dir"])
@pytest.mark.integration
def test_a_fifo_in_a_peers_admin_dir_makes_the_worktree_nested_at_once(
    isolated_tmp, entry
):
    """git worktree list reads every worktree's admin dir, and waits on a FIFO
    there for its 30 s timeout: in a peer's gitdir or HEAD (git 2.50, measured),
    or in an admin dir that is a symlink, which git follows. The admin dirs are
    checked first, and anything there that is not a regular file or a directory
    answers "nested" without running git."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    _git("worktree", "add", "-q", "-b", "peer", "wt/y", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    assert _answer_within(10, lambda: repository_is_nested(worktree)) == (
        False,
        [False],
    )
    fifo = _peer_admin_entry_made_a_fifo(checkout, isolated_tmp, entry)

    still_running, answers = _nested_within(1, worktree, fifo)

    assert not still_running
    assert answers == [True]


def _peer_admin_entry_made_a_fifo(checkout: Path, parent: Path, entry: str) -> Path:
    """Turn *entry* of worktree y's admin dir into a FIFO, or, for "a linked
    admin dir", move the admin dir to *parent*, link it back and make its gitdir
    the FIFO. Returns the FIFO."""
    admin = checkout / ".git" / "worktrees" / "y"
    if entry == "a linked admin dir":
        moved = parent / "elsewhere-admin"
        admin.rename(moved)
        _symlink_or_skip(admin, str(moved))
        fifo = moved / "gitdir"
    else:
        fifo = admin / entry
    fifo.unlink()
    os.mkfifo(fifo)
    return fifo


def _nested_within(seconds: float, root: Path, fifo: Path):
    """``_answer_within`` for ``repository_is_nested(root)``, then releasing a git
    blocked opening *fifo*, so the thread ends."""
    try:
        return _answer_within(seconds, lambda: repository_is_nested(root))
    finally:
        try:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass


@pytest.mark.parametrize("entry", ["gitdir", "HEAD", "a linked admin dir"])
@pytest.mark.integration
def test_a_fifo_in_the_admin_dirs_of_a_repository_a_ceiling_hides_holds_the_root_at_once(
    isolated_tmp, monkeypatch, entry
):
    """With GIT_CEILING_DIRECTORIES at wt, the walk from wt/x stops there and asks
    the repository the ceiling hides whether it holds wt/x, starting with its
    worktree list. git worktree list waited on a FIFO in a peer's admin dir for
    git's 30 s, as it does with no ceiling. The admin dirs are checked first
    there too, and anything that is not a regular file or a directory counts as
    holding wt/x: git could not be asked, so it is nested."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    _git("worktree", "add", "-q", "-b", "peer", "wt/y", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(checkout / "wt"))
    # The control: with plain admin dirs, the hidden repository lists wt/x as
    # its own worktree and does not hold it.
    assert _answer_within(10, lambda: repository_is_nested(worktree)) == (
        False,
        [False],
    )
    fifo = _peer_admin_entry_made_a_fifo(checkout, isolated_tmp, entry)

    still_running, answers = _nested_within(1, worktree, fifo)

    assert not still_running
    assert answers == [True]


def _socket_at(path: Path) -> None:
    """A Unix socket entry at *path*, as macOS's builtin fsmonitor leaves one."""
    import socket as socket_module
    import stat

    try:
        os.mknod(path, 0o600 | stat.S_IFSOCK)
        return
    except (AttributeError, OSError):
        pass
    if not hasattr(socket_module, "AF_UNIX"):
        pytest.skip("no Unix sockets here")
    listener = socket_module.socket(socket_module.AF_UNIX)
    try:
        listener.bind(str(path))
    except OSError as error:
        pytest.skip(f"cannot make a socket here: {error}")
    finally:
        listener.close()


@pytest.mark.parametrize("whose", ["its own", "a peer's"])
@pytest.mark.integration
def test_an_fsmonitor_socket_in_an_admin_dir_is_not_nesting(isolated_tmp, whose):
    """git's builtin fsmonitor on macOS keeps its socket in a linked worktree's
    admin dir (fsm-ipc-darwin's default path), so every worktree of such a
    checkout counted as nested. git cannot open a socket (ENXIO), so it cannot
    wait on one."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    _git("worktree", "add", "-q", "-b", "peer", "wt/y", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    admin = checkout / ".git" / "worktrees" / ("x" if whose == "its own" else "y")
    _socket_at(admin / "fsmonitor--daemon.ipc")

    assert not repository_is_nested(worktree)


@pytest.mark.parametrize(
    "where",
    [
        "a per-worktree ref a peer's HEAD names",
        "the branch a peer's HEAD names",
        "the branch the main worktree's HEAD names",
        "packed-refs, with the refs packed",
        "packed-refs, a symlink to a FIFO outside the git dir",
    ],
)
@pytest.mark.integration
def test_a_fifo_git_reads_to_list_the_worktrees_makes_them_nested_at_once(
    isolated_tmp, where
):
    """Besides each admin dir, git worktree list reads each worktree's HEAD
    target, and packed-refs when a ref is packed. A FIFO at any of those held
    it for 30 s (git 2.50, measured), so each is checked before git runs, and
    so is a symlink there, which git follows to wherever it points.
    Other loose refs are not read, and a FIFO among them does not stall it."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    _git("worktree", "add", "-q", "-b", "peer", "wt/y", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    git_dir = checkout / ".git"
    if where == "a per-worktree ref a peer's HEAD names":
        (git_dir / "worktrees" / "y" / "HEAD").write_text(
            "ref: refs/worktree/w\n", encoding="utf-8"
        )
        fifo = git_dir / "worktrees" / "y" / "refs" / "worktree" / "w"
        fifo.parent.mkdir(parents=True)
    elif where == "the branch a peer's HEAD names":
        fifo = git_dir / "refs" / "heads" / "peer"
        fifo.unlink()
    elif where == "the branch the main worktree's HEAD names":
        branch = (git_dir / "HEAD").read_text(encoding="utf-8").split("/")[-1]
        fifo = git_dir / "refs" / "heads" / branch.strip()
        fifo.unlink()
    elif where == "packed-refs, with the refs packed":
        _git("pack-refs", "--all", cwd=checkout)
        fifo = git_dir / "packed-refs"
        fifo.unlink()
    else:
        _git("pack-refs", "--all", cwd=checkout)
        (git_dir / "packed-refs").unlink()
        fifo = isolated_tmp / "outside" / "packed-refs"
        fifo.parent.mkdir()
        _symlink_or_skip(git_dir / "packed-refs", str(fifo))
    os.mkfifo(fifo)

    try:
        still_running, answers = _answer_within(
            1, lambda: repository_is_nested(worktree)
        )
    finally:
        try:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass

    assert not still_running
    assert answers == [True]
    # The notice that nothing was archived names this cause.
    assert "a FIFO or a symlink where git reads its worktrees" in (NO_SCAN_SOURCE_CASES)


@pytest.mark.integration
def test_a_head_naming_a_ref_outside_the_refs_is_not_followed(isolated_tmp):
    """git refuses a ref name with a ".." part; the check does not follow one out
    of the common dir, and counts it as not plain rather than as nothing."""
    from automated_security_helper.utils.scan_source import _head_target_is_plain

    common = isolated_tmp / "common"
    common.mkdir()
    (common / "HEAD").write_text("ref: refs/../nowhere\n", encoding="utf-8")

    assert not _head_target_is_plain(common / "HEAD", common)


def _git_follows_side(checkout: Path, worktree: Path) -> bool:
    """Whether ``git worktree list`` names refs/heads/side as *worktree*'s
    branch: git read its HEAD as naming that ref."""
    listing = subprocess.run(
        ["git", "worktree", "list", "--porcelain", "-z"],
        cwd=checkout,
        capture_output=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    entry = None
    for field in listing.split(b"\0"):
        if field.startswith(b"worktree "):
            entry = os.fsdecode(field[len(b"worktree ") :])
        elif entry == str(worktree) and field == b"branch refs/heads/side":
            return True
    return False


_HEAD_PREFIXES = {
    "colon-space": "ref: ",
    "colon": "ref:",
    "colon-tab": "ref:\t",
    "colon-two-spaces": "ref:  ",
    "colon-LF": "ref:\n",
}
_HEAD_ENDINGS = {
    "none": "",
    "LF": "\n",
    "CRLF": "\r\n",
    "CR": "\r",
    "LFLF": "\n\n",
    "space": " ",
    "tab": "\t",
    "VT": "\v",
    "FF": "\f",
    "space-LF": " \n",
}
#: Each case's last value is the check's answer where git does not follow the
#: HEAD (git opens no branch then): plain, except for a name git refuses that
#: the check does not follow out of the refs, which counts as not plain.
_HEAD_CASES = [
    pytest.param("linked", prefix, ending, True, id=f"linked-{p}+{e}")
    for p, prefix in _HEAD_PREFIXES.items()
    for e, ending in _HEAD_ENDINGS.items()
] + [
    pytest.param("linked", "ref:\v", "\n", False, id="linked-colon-VT+LF"),
    pytest.param("linked", " ref: ", "\n", True, id="linked-leading-space+LF"),
    pytest.param("linked", "REF: ", "\n", True, id="linked-upper+LF"),
    pytest.param("linked", "ref: ", "\0junk", True, id="linked-colon-space+NUL-junk"),
    pytest.param("linked", "ref: ", "\0\n", True, id="linked-colon-space+NUL-LF"),
    pytest.param("main", "ref: ", "\r\n", True, id="main-colon-space+CRLF"),
    pytest.param("main", "ref:", "\n", True, id="main-colon+LF"),
    pytest.param("main", "ref: ", " \n", True, id="main-colon-space+space-LF"),
]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
@pytest.mark.parametrize("kind, prefix, ending, unfollowed", _HEAD_CASES)
@pytest.mark.integration
def test_a_head_is_read_as_git_reads_it(isolated_tmp, kind, prefix, ending, unfollowed):
    """Where git follows a HEAD to the branch, so does this check: the answer is
    git's, measured here. git 2.50 drops trailing spaces, tabs, carriage returns
    and newlines from a HEAD, reads "ref:", then any run of them, then the
    name, and ends the name at a NUL. Only a final newline was dropped here, so a
    CRLF HEAD was followed to "side" with a carriage return, a file that is not
    there, and "ref:" with no space was not followed at all: a FIFO as the branch
    git reads was not seen, and the listing waited on it. A NUL went into the
    name, and lstat raised ValueError. Where git does not follow the HEAD, the
    check's answer is *unfollowed*, with the branch a file or a FIFO."""
    from automated_security_helper.utils.scan_source import _head_target_is_plain

    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    common = (checkout / ".git").resolve()
    if kind == "linked":
        _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
        worktree = (checkout / "wt" / "x").resolve()
        head = common / "worktrees" / "x" / "HEAD"
    else:
        _git("branch", "side", cwd=checkout)
        worktree = checkout.resolve()
        head = common / "HEAD"
    head.write_bytes((prefix + "refs/heads/side" + ending).encode("utf-8"))
    follows = _git_follows_side(checkout, worktree)
    plain_before = _head_target_is_plain(head, common)
    branch = common / "refs" / "heads" / "side"
    branch.unlink()
    os.mkfifo(branch)

    plain_after = _head_target_is_plain(head, common)

    if follows:
        assert plain_before
        assert not plain_after
    else:
        assert plain_before is unfollowed
        assert plain_after is unfollowed


@pytest.mark.skipif(os.name == "nt", reason="file names are not bytes here")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
@pytest.mark.integration
def test_a_branch_whose_name_is_not_utf8_is_followed_as_git_follows_it(
    isolated_tmp,
):
    """git follows a peer's HEAD to refs/heads/caf\\xe9 as the bytes of its name.
    Read as strict UTF-8, that HEAD was no record, so it counted as plain, and a
    FIFO as that branch held the listing."""
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    _git("worktree", "add", "-q", "-b", "peer", "wt/y", cwd=checkout)
    worktree = (checkout / "wt" / "x").resolve()
    git_dir = checkout / ".git"
    name = os.fsdecode(b"caf\xe9")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        capture_output=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    branch = git_dir / "refs" / "heads" / name
    branch.write_bytes(commit)
    (git_dir / "worktrees" / "y" / "HEAD").write_bytes(b"ref: refs/heads/caf\xe9\n")
    listing = subprocess.run(
        ["git", "worktree", "list", "--porcelain", "-z"],
        cwd=checkout,
        capture_output=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    assert b"branch refs/heads/caf\xe9" in listing.split(b"\0")
    branch.unlink()
    os.mkfifo(branch)

    try:
        still_running, answers = _answer_within(
            1, lambda: repository_is_nested(worktree)
        )
    finally:
        try:
            os.close(os.open(branch, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass

    assert not still_running
    assert answers == [True]


@pytest.mark.unit
def test_a_name_holding_a_nul_is_not_plain():
    """lstat refuses a path with a NUL (ValueError). The check never builds one
    from a HEAD, and if it is ever given one, the entry counts as not plain
    rather than raising out of the scan."""
    from automated_security_helper.utils.scan_source import _plain_entry

    assert _plain_entry(Path("refs") / f"side{chr(0)}junk") is False


@pytest.mark.integration
def test_a_chain_of_nested_worktrees_costs_one_git_call_per_ancestor(
    isolated_tmp, monkeypatch
):
    """Each worktree of the chain sits inside the one before, so every ancestor of
    the innermost holds a .git entry and shares one common dir. Each was listed
    and checked again: 3 git runs per ancestor, so 200 nested worktrees took 28 s,
    and 497 s with 10,000 admin entries. An ancestor whose common dir is already
    verified gives the same answer, and costs its one common-dir lookup."""
    from automated_security_helper.utils import get_scan_set

    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    depth = 10
    path = checkout
    for level in range(depth):
        path = path / f"w{level}"
        _git("worktree", "add", "-q", "-b", f"b{level}", str(path), cwd=checkout)
    innermost = path.resolve()
    real_run = get_scan_set.subprocess.run
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0] if args else kwargs.get("args"))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(get_scan_set.subprocess, "run", counted)

    assert not repository_is_nested(innermost)
    assert len(calls) <= 2 * depth + 3, calls


@pytest.mark.integration
def test_a_verified_worktree_of_a_nested_repository_is_still_nested(isolated_tmp):
    """The skip covers only ancestors of the common dir already verified. wt/x is
    a worktree of the inner clone, and that clone sits inside another
    repository, whose own common dir still makes wt/x nested."""
    outer = _repo_with_a_commit(isolated_tmp / "outer")
    inner = _repo_with_a_commit(outer / "vendor" / "inner")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=inner)

    assert repository_is_nested((inner / "wt" / "x").resolve())


#: Every git helper in get_scan_set.py, with what it takes after the directory.
#: The two listings are what the GIT_CEILING_DIRECTORIES check asks the
#: repository a ceiling hides.
_GIT_HELPERS = [
    ("git_repository_root", ()),
    ("git_common_dir", ()),
    ("git_absolute_git_dir", ()),
    ("git_worktree_paths", ()),
    ("git_index_paths_below", ("x",)),
    ("git_untracked_paths_below", ("x",)),
]


@pytest.mark.parametrize(
    "helper, rest", _GIT_HELPERS, ids=[name for name, _ in _GIT_HELPERS]
)
@pytest.mark.unit
def test_each_git_helper_gives_git_no_stdin(tmp_path, monkeypatch, helper, rest):
    """Each git helper gives git /dev/null as stdin, so a file a repository links
    to /dev/stdin reads nothing from ASH's terminal."""
    from automated_security_helper.utils import get_scan_set

    calls = []

    def recorded(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr(get_scan_set.subprocess, "run", recorded)

    getattr(get_scan_set, helper)(tmp_path, *rest)

    assert calls and all(call.get("stdin") is subprocess.DEVNULL for call in calls)


@pytest.mark.unit
def test_the_index_listing_for_output_dirs_gives_git_no_stdin(tmp_path, monkeypatch):
    """git_index_below names the repository on git's command line, and git still
    reads the files its git dir names: with a worktree's admin commondir linked
    to /dev/stdin, ``git --git-dir=... ls-files`` waited on an open stdin (git
    2.50.1, measured) and returned at once on /dev/null."""
    from automated_security_helper.utils import scan_output_dirs, subprocess_utils

    (tmp_path / ".git").mkdir()
    calls = []

    def recorded(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess_utils, "spawn_run", recorded)

    scan_output_dirs.git_index_below(tmp_path)

    assert calls and all(call.get("stdin") is subprocess.DEVNULL for call in calls)


@pytest.mark.unit
def test_get_changed_files_gives_git_no_stdin(tmp_path, monkeypatch):
    from automated_security_helper.utils import get_scan_set

    calls = []

    def recorded(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr(get_scan_set.subprocess, "run", recorded)

    get_scan_set.get_changed_files("origin/main", cwd=tmp_path)

    assert calls and all(call.get("stdin") is subprocess.DEVNULL for call in calls)


_COMMON_DIR_OF = """
import sys
from pathlib import Path
from automated_security_helper.utils.get_scan_set import git_common_dir
print(git_common_dir(Path(sys.argv[1])))
"""


@pytest.mark.integration
def test_a_commondir_linked_to_stdin_does_not_wait_on_the_callers_stdin(
    isolated_tmp,
):
    """The real case: wt/x's admin commondir is a symlink to /dev/stdin, and the
    process asking has a stdin that is open and silent (a terminal nobody types
    into). git gets /dev/null as stdin, so it answers at once."""
    if not os.path.exists("/dev/stdin"):
        pytest.skip("no /dev/stdin here")
    checkout = _repo_with_a_commit(isolated_tmp / "checkout")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=checkout)
    commondir = checkout / ".git" / "worktrees" / "x" / "commondir"
    commondir.unlink()
    _symlink_or_skip(commondir, "/dev/stdin")
    child = subprocess.Popen(  # nosec B603 - this interpreter, fixed code
        [
            sys.executable,
            "-c",
            importing_this_checkout(_COMMON_DIR_OF),
            str(checkout / "wt" / "x"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # The child's stdin stays open through the wait, as a silent terminal's
    # does: communicate() would close it at once, and git would read end of
    # file. Only once the verdict is in does communicate() run, and it closes
    # the pipe itself: closing it first makes Python 3.12's communicate()
    # flush a closed file and raise.
    try:
        child.wait(timeout=10)
        waited = False
    except subprocess.TimeoutExpired:
        waited = True
        # The wedge the cell exists to catch: end the child so the reads below
        # return, and the assertion reports the wait.
        child.kill()
    finally:
        out, err = child.communicate()

    assert not waited, "git waited on the caller's stdin"
    assert child.returncode == 0, err
    assert out.decode().strip() == "None"


def _symlink_or_skip(link: Path, target: str) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"cannot make a directory symlink here: {error}")


def _mode_zero_refuses_or_skip(path: Path, probe, restore: int) -> None:
    """``chmod 0`` on *path*, checking that *probe* is then really refused.

    The cells this guards are premised on the mode denying an access. Where
    an ACL or a filesystem ignores mode 0, the probe succeeds, or fails some
    other way (a lookup inside the directory reaches a missing name), and
    the premise is gone: restore *restore* and skip by name, instead of
    failing on a correct answer or asserting a refusal that is not there.
    Under a binding chmod the cell runs, so its arm's mutants still turn it
    red."""
    os.chmod(path, 0)
    refused = False
    try:
        probe()
    except PermissionError:
        refused = True
    except OSError:
        refused = False
    if not refused:
        os.chmod(path, restore)
        pytest.skip("mode 0000 does not refuse the access on this filesystem")


@pytest.fixture
def checkout_with_worktree(isolated_tmp):
    """A repository with a linked worktree at wt/x."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    return root


@pytest.mark.integration
def test_a_listed_worktree_path_symlinked_to_a_nested_clone_is_nested(
    checkout_with_worktree,
):
    """git still lists wt/x after it is replaced by a symlink to vendor/lib, a
    clone. The listed path is compared unresolved, so the clone behind the link
    counts as nested and records nothing."""
    root = checkout_with_worktree
    lib = _repo_with_a_commit(root / "vendor" / "lib")
    shutil.rmtree(root / "wt" / "x")
    _symlink_or_skip(root / "wt" / "x", os.path.join("..", "vendor", "lib"))

    assert repository_is_nested(lib)
    assert recorded_scan_source(lib, git_repository_root, {}) is None
    assert recorded_scan_source(root / "wt" / "x", git_repository_root, {}) is None


@pytest.mark.integration
def test_a_symlinked_parent_of_a_listed_worktree_exempts_nothing_it_reaches(
    checkout_with_worktree,
):
    """wt, the listed path's parent, replaced by a symlink to forged/, where
    forged/x is a clone: the listed wt/x resolved to forged/x."""
    root = checkout_with_worktree
    shutil.rmtree(root / "wt")
    clone = _repo_with_a_commit(root / "forged" / "x")
    _symlink_or_skip(root / "wt", "forged")

    assert repository_is_nested(clone)
    assert recorded_scan_source(clone, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_listed_worktree_path_now_holding_another_repository_is_nested(
    checkout_with_worktree,
):
    """wt/x deleted without `git worktree prune`, so git still lists it, and a
    new repository made there. The path is listed exactly; only its own
    --git-common-dir says it is not the ancestor's worktree."""
    root = checkout_with_worktree
    shutil.rmtree(root / "wt" / "x")
    other = root / "wt" / "x"
    other.mkdir()
    _git("init", "-q", cwd=other)
    assert git_repository_root(other) == other.resolve()

    assert repository_is_nested(other)
    assert recorded_scan_source(other, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_listed_worktree_path_symlinked_to_a_forged_gitfile_is_nested(
    checkout_with_worktree,
):
    """wt/x replaced by a symlink to forged/gf_wtadmin, whose .git names wt/x's
    own admin dir. It shares the ancestor's common dir, so only the listed path,
    compared as git printed it, tells it from the worktree; the common-dir check
    alone does not."""
    root = checkout_with_worktree
    forged = _forged(root, "gf_wtadmin", (root / ".git" / "worktrees" / "x").as_posix())
    shutil.rmtree(root / "wt" / "x")
    _symlink_or_skip(root / "wt" / "x", os.path.join("..", "forged", "gf_wtadmin"))
    assert git_repository_root(forged) == forged.resolve()

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None
    assert recorded_scan_source(root / "wt" / "x", git_repository_root, {}) is None


@pytest.mark.integration
def test_a_worktree_of_a_checkout_reached_through_a_symlink_keeps_its_label(
    isolated_tmp,
):
    """git lists real paths, and the root it gives is real, so comparing the
    listed path unresolved still exempts a worktree reached through a link."""
    real = isolated_tmp / "real"
    root = _repo_with_a_commit(real / "super")
    _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=root)
    (root / "wt" / "x" / "services").mkdir()
    _symlink_or_skip(isolated_tmp / "link", "real")
    via_link = isolated_tmp / "link" / "super" / "wt" / "x"

    assert recorded_scan_source(via_link, git_repository_root, {}) == "."
    assert host_scan_source_label(via_link / "services", git_repository_root) == (
        "services"
    )


@pytest.mark.integration
def test_a_worktree_whose_path_holds_a_newline_is_read_whole(isolated_tmp):
    """`git worktree list --porcelain -z` ends each field with NUL. Split on
    newlines instead, the worktree at "wt/a<newline>b" reads as wt/a: the
    worktree itself is no longer listed, and a gitfile at wt/a naming its admin
    dir is."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    try:
        (isolated_tmp / "a\nb").mkdir()
    except OSError as error:
        pytest.skip(f"this filesystem refuses a newline in a name: {error}")
    _git("worktree", "add", "-q", "-b", "side", "wt/a\nb", cwd=root)
    worktree = root / "wt" / "a\nb"
    [admin] = list((root / ".git" / "worktrees").iterdir())
    forged = root / "wt" / "a"
    forged.mkdir()
    (forged / ".git").write_text(f"gitdir: {admin.as_posix()}\n", encoding="utf-8")
    assert git_repository_root(forged) == forged.resolve()

    assert recorded_scan_source(worktree, git_repository_root, {}) == "."
    assert recorded_scan_source(forged, git_repository_root, {}) is None


# With worktree.useRelativePaths (git 2.48+) git records a worktree's path
# relative to its admin dir, and `git worktree list` resolves that path when it
# prints it, following a symlink put at or above it. So the listed path is
# wherever the symlink now points, and comparing it unresolved does not help.


@pytest.fixture
def checkout_with_relative_worktree(isolated_tmp):
    """A repository with a linked worktree at wt/x, its paths recorded relative."""
    root = _repo_with_a_commit(isolated_tmp / "super")
    _git(
        "-c",
        "worktree.useRelativePaths=true",
        "worktree",
        "add",
        "-q",
        "-b",
        "side",
        "wt/x",
        cwd=root,
    )
    recorded = (root / ".git" / "worktrees" / "x" / "gitdir").read_text(
        encoding="utf-8"
    )
    if os.path.isabs(recorded.strip()):
        pytest.skip("this git records worktree paths absolute (before 2.48)")
    return root


@pytest.mark.integration
def test_a_relative_worktree_keeps_its_label(checkout_with_relative_worktree):
    root = checkout_with_relative_worktree
    worktree = root / "wt" / "x"
    (worktree / "services").mkdir()

    assert not repository_is_nested(worktree)
    assert recorded_scan_source(worktree, git_repository_root, {}) == "."
    assert host_scan_source_label(worktree / "services", git_repository_root) == (
        "services"
    )


@pytest.mark.integration
def test_a_relative_worktrees_path_symlinked_to_a_forged_gitfile_is_nested(
    checkout_with_relative_worktree,
):
    """wt/x replaced by a symlink to forged/gf_wtadmin, whose .git names wt/x's
    admin dir: git lists forged/gf_wtadmin, and its common dir is the outer
    one."""
    root = checkout_with_relative_worktree
    forged = _forged(root, "gf_wtadmin", (root / ".git" / "worktrees" / "x").as_posix())
    shutil.rmtree(root / "wt" / "x")
    _symlink_or_skip(root / "wt" / "x", os.path.join("..", "forged", "gf_wtadmin"))

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None
    assert recorded_scan_source(root / "wt" / "x", git_repository_root, {}) is None


@pytest.mark.integration
def test_a_relative_worktrees_path_symlinked_to_an_outer_gitfile_is_nested(
    checkout_with_relative_worktree,
):
    """wt/x replaced by a symlink to forged/gf_rel, a .git file naming the outer
    git dir itself."""
    root = checkout_with_relative_worktree
    forged = _forged(root, "gf_rel", "../../.git")
    shutil.rmtree(root / "wt" / "x")
    _symlink_or_skip(root / "wt" / "x", os.path.join("..", "forged", "gf_rel"))

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_relative_worktrees_parent_symlinked_to_a_forged_gitfile_is_nested(
    checkout_with_relative_worktree,
):
    """wt replaced by a symlink to forged/, where forged/x is a .git file naming
    the outer git dir."""
    root = checkout_with_relative_worktree
    shutil.rmtree(root / "wt")
    forged = _forged(root, "x", "../../.git")
    _symlink_or_skip(root / "wt", "forged")

    assert repository_is_nested(forged)
    assert recorded_scan_source(forged, git_repository_root, {}) is None


@pytest.mark.parametrize(
    "records_itself", [False, True], ids=["plain", "with-its-own-gitdir-file"]
)
@pytest.mark.integration
def test_a_git_dir_at_a_listed_path_sharing_the_outer_common_dir_is_nested(
    checkout_with_worktree, records_itself
):
    """wt/x deleted without prune and replaced by a git directory of its own
    whose commondir file names the outer git dir. It is listed, and its common
    dir is the outer one, but its git dir is not an admin dir in the outer
    repository's worktrees/, even when it holds a gitdir file naming itself."""
    root = checkout_with_worktree
    shutil.rmtree(root / "wt" / "x")
    git_dir = root / "wt" / "x" / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/side\n", encoding="utf-8")
    (git_dir / "commondir").write_text("../../../.git\n", encoding="utf-8")
    if records_itself:
        (git_dir / "gitdir").write_text("../.git\n", encoding="utf-8")
    other = root / "wt" / "x"
    assert git_repository_root(other) == other.resolve()

    assert repository_is_nested(other)
    assert recorded_scan_source(other, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_relative_worktree_of_a_checkout_reached_through_a_symlink_keeps_its_label(
    isolated_tmp,
):
    """The admin dir's relative record, joined to the admin dir's real path,
    names the worktree's real path, which is the root git gives."""
    real = isolated_tmp / "real"
    root = _repo_with_a_commit(real / "super")
    _git(
        "-c",
        "worktree.useRelativePaths=true",
        "worktree",
        "add",
        "-q",
        "-b",
        "side",
        "wt/x",
        cwd=root,
    )
    recorded = (root / ".git" / "worktrees" / "x" / "gitdir").read_text(
        encoding="utf-8"
    )
    if os.path.isabs(recorded.strip()):
        pytest.skip("this git records worktree paths absolute (before 2.48)")
    _symlink_or_skip(isolated_tmp / "link", "real")
    via_link = isolated_tmp / "link" / "super" / "wt" / "x"

    assert recorded_scan_source(via_link, git_repository_root, {}) == "."


@pytest.mark.integration
def test_git_location_variables_do_not_answer_for_the_ancestor(
    isolated_tmp, monkeypatch
):
    """GIT_DIR in the environment names one repository whatever the working
    directory; the ancestor's worktree list is read without it. With GIT_DIR at
    the nested clone's own git dir, a list read with it would name the clone."""
    outer = _repo_with_a_commit(isolated_tmp / "outer")
    inner = _repo_with_a_commit(outer / "third_party" / "inner")
    monkeypatch.setenv("GIT_DIR", (inner / ".git").as_posix())

    assert repository_is_nested(inner)
    assert recorded_scan_source(inner, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_below_the_superproject_leaves_its_submodule_nested(
    superproject, monkeypatch
):
    """With the ceiling at vendor, the repository it hides is the superproject,
    which tracks the path below vendor as a gitlink."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject / "vendor"))
    lib = superproject / "vendor" / "lib"

    assert repository_is_nested(lib)
    assert recorded_scan_source(lib, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_through_a_symlinked_path_leaves_the_submodule_nested(
    superproject, isolated_tmp, monkeypatch
):
    """git resolves the entry, so a link to the superproject is a ceiling at it."""
    _symlink_or_skip(isolated_tmp / "fxlink", ".")
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES", str(isolated_tmp / "fxlink" / "super")
    )
    lib = superproject / "vendor" / "lib"
    assert git_repository_root(superproject / "vendor") is None

    assert recorded_scan_source(lib, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_leaves_a_clone_inside_a_gitlink_path_nested(
    superproject, monkeypatch
):
    """The submodule is not checked out (deinit), and a clone sits inside its
    path. The superproject's gitlink is a path between it and the clone's root,
    and git does not list anything below a gitlink as untracked."""
    _git("submodule", "deinit", "-q", "-f", "vendor/lib", cwd=superproject)
    inner = _repo_with_a_commit(superproject / "vendor" / "lib" / "inner")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject / "vendor"))
    assert git_repository_root(inner) == inner.resolve()

    assert repository_is_nested(inner)
    assert recorded_scan_source(inner, git_repository_root, {}) is None


@pytest.mark.parametrize("ceiling", ["outer", "outer/third_party"])
@pytest.mark.integration
def test_a_ceiling_leaves_a_nested_clone_nested(isolated_tmp, monkeypatch, ceiling):
    """The outer repository lists third_party/x as untracked."""
    outer = _repo_with_a_commit(isolated_tmp / "outer")
    inner = _repo_with_a_commit(outer / "third_party" / "x")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(isolated_tmp / ceiling))

    assert recorded_scan_source(inner, git_repository_root, {}) is None
    assert host_scan_source_label(inner, git_repository_root) is None


@pytest.mark.integration
def test_a_ceiling_leaves_a_planted_gitfile_nested(isolated_tmp, monkeypatch):
    root = _repo_with_a_commit(isolated_tmp / "super")
    forged = _forged(root, "gf_rel", "../../.git")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(root / "forged"))
    assert git_repository_root(forged) == forged.resolve()

    assert recorded_scan_source(forged, git_repository_root, {}) is None


def _planted_in_ignored_build(superproject: Path, kind: str) -> Path:
    """build/x in *superproject*, which ignores build/, made a repository root
    that shares the superproject's git dir: a .git file naming it (``gf_rel``),
    a .git file naming a linked worktree's admin dir (``gf_wtadmin``), or a
    .git symlink to it (``sym_in``). A build step can write any of these."""
    planted = superproject / "build" / "x"
    planted.mkdir(parents=True)
    if kind == "gf_rel":
        (planted / ".git").write_text("gitdir: ../../.git\n", encoding="utf-8")
    elif kind == "gf_wtadmin":
        _git("worktree", "add", "-q", "-b", "side", "wt/x", cwd=superproject)
        admin = superproject / ".git" / "worktrees" / "x"
        assert admin.is_dir()
        (planted / ".git").write_text(f"gitdir: {admin.as_posix()}\n", encoding="utf-8")
    else:
        _symlink_or_skip(planted / ".git", "../../.git")
    return planted


@pytest.mark.parametrize("ceiling", ["super", "super/build"])
@pytest.mark.parametrize("kind", ["gf_rel", "gf_wtadmin", "sym_in"])
@pytest.mark.integration
def test_a_ceiling_leaves_a_root_sharing_the_hidden_git_dir_nested(
    isolated_tmp, monkeypatch, ceiling, kind
):
    """The superproject ignores build/, so it neither tracks nor lists build/x,
    but build/x is a root that shares its git dir and is none of its worktrees.
    A scan there reads the superproject's index, and its "." would be the
    superproject's."""
    superproject = _repo_with_a_commit(isolated_tmp / "super")
    (superproject / ".gitignore").write_text("/build/\n/wt/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=superproject)
    _git("commit", "-qm", "ignore", cwd=superproject)
    planted = _planted_in_ignored_build(superproject, kind)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(isolated_tmp / ceiling))
    assert git_repository_root(planted) == planted.resolve()

    assert repository_is_nested(planted)
    assert recorded_scan_source(planted, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_root_git_cannot_give_a_common_dir_for_below_a_ceiling_is_nested(
    isolated_tmp, monkeypatch
):
    """Fail closed: the home repository would neither track nor list the
    checkout, but without the checkout's own common dir the check can't tell it
    from a root sharing the home repository's git dir."""
    from automated_security_helper.utils import scan_source

    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))
    assert not repository_is_nested(project)
    real_common_dir = scan_source.git_common_dir
    asked = []

    def no_answer_for_the_checkout(path):
        if Path(path).resolve() == project.resolve():
            asked.append(path)
            return None
        return real_common_dir(path)

    monkeypatch.setattr(scan_source, "git_common_dir", no_answer_for_the_checkout)

    assert repository_is_nested(project)
    # The check asked about the checkout itself, and got no answer.
    assert asked, "the checkout's own common dir was never asked for"


@pytest.mark.integration
def test_a_ceiling_keeps_a_linked_worktree_of_the_hidden_repository_its_label(
    checkout_with_worktree, monkeypatch
):
    """The outer repository lists wt/x as untracked, but git also lists it as
    one of its worktrees, sharing its git directory: not nested, ceiling or not."""
    root = checkout_with_worktree
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(root / "wt"))

    assert recorded_scan_source(root / "wt" / "x", git_repository_root, {}) == "."


def _home_with_a_project(parent: Path, ignore: str = "") -> "tuple[Path, Path]":
    """A home directory kept in git, with a checkout at src/project.

    *ignore* is the home repository's committed .gitignore.
    """
    home = _repo_with_a_commit(parent / "home")
    if ignore:
        (home / ".gitignore").write_text(ignore, encoding="utf-8")
        _git("add", ".gitignore", cwd=home)
        _git("commit", "-qm", "ignore", cwd=home)
    project = _repo_with_a_commit(home / "src" / "project")
    return home, project


@pytest.mark.integration
def test_a_ceiling_at_a_home_repository_that_ignores_the_checkout_is_honored(
    isolated_tmp, monkeypatch
):
    """The opt-out: the home repository would neither track nor list the
    checkout, so with the ceiling there it records its own root."""
    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    assert recorded_scan_source(project, git_repository_root, {}) is None
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))

    assert not repository_is_nested(project)
    assert recorded_scan_source(project, git_repository_root, {}) == "."
    assert host_scan_source_label(project, git_repository_root) == "."


@pytest.mark.integration
def test_a_ceiling_at_a_home_repository_that_lists_the_checkout_changes_nothing(
    isolated_tmp, monkeypatch
):
    """The opt-out does not apply: `git status` in the home directory would show
    src/ as untracked, and a scan of the home directory would cover it."""
    home, project = _home_with_a_project(isolated_tmp)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))

    assert repository_is_nested(project)
    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_at_a_submodule_that_ignores_a_clone_leaves_it_nested(
    isolated_tmp, monkeypatch
):
    """mega tracks mid as a gitlink, mid ignores lib/, and mid/lib is a clone.
    With the ceiling at mid, the nearest repository it hides, mid, holds
    nothing below it, but mega, above it, tracks mid, a path between it and
    the clone."""
    library = _repo_with_a_commit(isolated_tmp / "library")
    mega = _repo_with_a_commit(isolated_tmp / "mega")
    _git("submodule", "add", "-q", library.as_uri(), "mid", cwd=mega)
    mid = mega / "mid"
    (mid / ".gitignore").write_text("/lib/\n", encoding="utf-8")
    clone = _repo_with_a_commit(mid / "lib")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(mid))
    assert git_repository_root(clone) == clone.resolve()

    assert repository_is_nested(clone)
    assert recorded_scan_source(clone, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_at_a_repository_a_home_repository_lists_leaves_its_clone_nested(
    isolated_tmp, monkeypatch
):
    """The home repository lists super/ as untracked, super ignores build/, and
    build/x is a clone. With the ceiling at super, super holds nothing below
    it, but a scan of the home directory covers super/."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    superproject = _repo_with_a_commit(home / "super")
    (superproject / ".gitignore").write_text("/build/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=superproject)
    _git("commit", "-qm", "ignore", cwd=superproject)
    clone = _repo_with_a_commit(superproject / "build" / "x")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject))
    assert git_untracked_paths_below(home, "super") == ["super/"]

    assert repository_is_nested(clone)
    assert recorded_scan_source(clone, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_at_a_repository_nothing_above_holds_keeps_its_ignored_clone_dot(
    isolated_tmp, monkeypatch
):
    """The control for the two above: the home repository ignores super/, so
    no repository at or above the ceiling holds build/x."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    (home / ".gitignore").write_text("/super/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=home)
    _git("commit", "-qm", "ignore", cwd=home)
    superproject = _repo_with_a_commit(home / "super")
    (superproject / ".gitignore").write_text("/build/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=superproject)
    _git("commit", "-qm", "ignore", cwd=superproject)
    clone = _repo_with_a_commit(superproject / "build" / "x")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject))

    assert not repository_is_nested(clone)
    assert recorded_scan_source(clone, git_repository_root, {}) == "."


@pytest.mark.integration
def test_a_ceiling_at_a_repository_that_tracks_files_in_the_checkout_changes_nothing(
    isolated_tmp, monkeypatch
):
    """The home repository ignores src/ but already tracks a file in what is now
    the checkout, so its scans cover the checkout's files."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    notes = home / "src" / "project" / "notes.txt"
    notes.parent.mkdir(parents=True)
    notes.write_text("notes\n", encoding="utf-8")
    (home / ".gitignore").write_text("/src/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=home)
    _git("add", "-f", "src/project/notes.txt", cwd=home)
    _git("commit", "-qm", "notes", cwd=home)
    project = notes.parent
    _git("init", "-q", cwd=project)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))
    assert git_repository_root(project) == project.resolve()

    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.parametrize(
    "ceilings", [["super"], ["super/vendor"], ["super", "super/vendor"]]
)
@pytest.mark.integration
def test_a_vendored_copy_with_a_git_dir_of_its_own_is_held_by_its_tracked_files(
    isolated_tmp, monkeypatch, ceilings
):
    """The superproject commits vendor/copy/a.c, a vendored copy, and
    vendor/copy also has a .git of its own. The superproject holds no gitlink
    there, but the files it tracks below the root hold it: a scan of the
    superproject covers vendor/copy/a.c under its own ".". If only a gitlink
    held a root, the copy would record "." under each of these ceilings."""
    superproject = _repo_with_a_commit(isolated_tmp / "super")
    vendored = superproject / "vendor" / "copy" / "a.c"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("int a;\n", encoding="utf-8")
    _git("add", "vendor/copy/a.c", cwd=superproject)
    _git("commit", "-qm", "vendor a copy", cwd=superproject)
    copy = vendored.parent
    _git("init", "-q", cwd=copy)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join(str(isolated_tmp / ceiling) for ceiling in ceilings),
    )
    assert git_repository_root(copy) == copy.resolve()

    assert repository_is_nested(copy)
    assert recorded_scan_source(copy, git_repository_root, {}) is None


@pytest.mark.integration
def test_the_hidden_repository_is_not_listed_beside_the_root(isolated_tmp, monkeypatch):
    """Only the root, what is below it and the paths between it and the hidden
    repository are looked up. A listing of the top directory the root is in
    reads every path beside the root too, which in a monorepo is most of the
    index, and git's answer is read whole within one timeout."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    beside = home / "src" / "other" / "beside.txt"
    beside.parent.mkdir(parents=True)
    beside.write_text("beside\n", encoding="utf-8")
    (home / ".gitignore").write_text("/src/project/\n", encoding="utf-8")
    _git("add", ".gitignore", "src/other/beside.txt", cwd=home)
    _git("commit", "-qm", "beside", cwd=home)
    (home / "src" / "other" / "untracked-beside.txt").write_text(
        "u\n", encoding="utf-8"
    )
    project = _repo_with_a_commit(home / "src" / "project")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))
    outputs = []
    real_run = subprocess.run

    def recording_run(*args, **kwargs):
        result = real_run(*args, **kwargs)
        if isinstance(result.stdout, (bytes, str)):
            outputs.append(os.fsencode(result.stdout))
        return result

    monkeypatch.setattr(subprocess, "run", recording_run)

    assert repository_is_nested(project) is False
    assert outputs
    assert not [output for output in outputs if b"beside" in output]


@pytest.mark.integration
def test_a_ceiling_at_a_repository_that_tracks_a_file_where_the_checkout_now_is(
    isolated_tmp, monkeypatch
):
    """The home repository tracks src as a file, and src is now a directory
    holding the checkout: src is a path between them."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    (home / "src").write_text("a file\n", encoding="utf-8")
    (home / ".gitignore").write_text("/src/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=home)
    _git("add", "-f", "src", cwd=home)
    _git("commit", "-qm", "src", cwd=home)
    (home / "src").unlink()
    project = _repo_with_a_commit(home / "src" / "project")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))

    assert repository_is_nested(project)
    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_leaves_a_clone_inside_a_conflicted_gitlink_path_nested(
    isolated_tmp, monkeypatch
):
    """A merge left the superproject's gitlink at vendor/lib unmerged, so the
    index holds it only at the conflict stages, and a clone sits inside its
    path. The gitlink is still a path between them."""
    superproject = _repo_with_a_commit(isolated_tmp / "super")
    entries = "".join(
        f"160000 {digit * 40} {stage}\tvendor/lib\n"
        for digit, stage in (("1", 1), ("2", 2), ("3", 3))
    )
    subprocess.run(
        ["git", "update-index", "--index-info"],
        cwd=superproject,
        input=entries.encode(),
        check=True,
        capture_output=True,
    )
    inner = _repo_with_a_commit(superproject / "vendor" / "lib" / "inner")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(superproject / "vendor"))
    assert git_untracked_paths_below(superproject, "vendor/lib/inner") == []

    assert repository_is_nested(inner)
    assert recorded_scan_source(inner, git_repository_root, {}) is None


@pytest.mark.skipif(os.name == "nt", reason="no file name holds a carriage return")
@pytest.mark.integration
def test_a_carriage_return_in_a_path_the_hidden_repository_tracks_is_read_as_written(
    isolated_tmp, monkeypatch
):
    """git ls-files prints the paths as they are. Read as bytes, a carriage
    return in one stays part of the path, so the file the home repository tracks
    in the checkout is seen below it and the ceiling is not honored."""
    home = _repo_with_a_commit(isolated_tmp / "home")
    tracked = f"src/pro{chr(13)}ject/notes.txt"
    notes = home / tracked
    notes.parent.mkdir(parents=True)
    notes.write_text("notes\n", encoding="utf-8")
    (home / ".gitignore").write_text("/src/\n", encoding="utf-8")
    _git("add", ".gitignore", cwd=home)
    _git("add", "-f", "--", tracked, cwd=home)
    _git("commit", "-qm", "notes", cwd=home)
    project = notes.parent
    _git("init", "-q", cwd=project)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))
    assert git_repository_root(project) == project.resolve()

    assert git_index_paths_below(home, "src") == [tracked]
    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.parametrize(
    "helper",
    ["git_index_paths_below", "git_untracked_paths_below"],
)
@pytest.mark.integration
def test_a_hidden_repository_git_cannot_answer_for_makes_it_nested(
    isolated_tmp, monkeypatch, helper
):
    """Fail closed: when git cannot say what the hidden repository holds (it
    refuses the repository under safe.directory, say), the ceiling is not
    honored."""
    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home))
    assert recorded_scan_source(project, git_repository_root, {}) == "."
    monkeypatch.setattr(
        f"automated_security_helper.utils.scan_source.{helper}",
        lambda *args, **kwargs: None,
    )

    assert repository_is_nested(project)
    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.integration
def test_an_entry_after_an_empty_entry_is_compared_as_written(
    isolated_tmp, monkeypatch
):
    """git resolves symlinks in an entry only before the first empty entry
    (setup.c, canonicalize_ceiling_entry). Here the link to the home directory
    comes after one, so it matches nothing: git finds the home repository from
    src/, and the checkout is nested."""
    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    _symlink_or_skip(isolated_tmp / "fxlink", ".")
    link = str(isolated_tmp / "fxlink" / "home")
    barrier = str(isolated_tmp.parent)

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.pathsep.join([barrier, link]))
    assert git_repository_root(home / "src") is None
    assert recorded_scan_source(project, git_repository_root, {}) == "."

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.pathsep.join([barrier, "", link]))
    assert git_repository_root(home / "src") == home.resolve()
    assert repository_is_nested(project)
    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.integration
def test_an_entry_git_cannot_resolve_is_dropped_as_git_drops_it(
    isolated_tmp, monkeypatch
):
    """`home/missing/../` names the home directory only once `..` is taken
    literally; git's realpath fails on the missing directory and drops it."""
    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    entry = os.path.join(str(home), "missing", "..")
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES", os.pathsep.join([str(isolated_tmp.parent), entry])
    )
    assert git_repository_root(home / "src") == home.resolve()

    assert recorded_scan_source(project, git_repository_root, {}) is None


@pytest.mark.integration
def test_a_ceiling_with_a_trailing_separator_is_the_directory(
    isolated_tmp, monkeypatch
):
    home, project = _home_with_a_project(isolated_tmp, ignore="/src/\n")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(home) + "/")
    assert git_repository_root(home / "src") is None

    assert recorded_scan_source(project, git_repository_root, {}) == "."


@pytest.mark.integration
def test_a_relative_ceiling_entry_is_ignored_as_git_ignores_it(
    superproject, isolated_tmp, monkeypatch
):
    """ "super", relative to the current directory, would name the superproject."""
    monkeypatch.chdir(isolated_tmp)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES", os.pathsep.join(["super", str(isolated_tmp.parent)])
    )
    lib = superproject / "vendor" / "lib"

    assert repository_is_nested(lib)
    assert recorded_scan_source(lib, git_repository_root, {}) is None


@pytest.mark.integration
def test_the_ceiling_is_the_processs_as_it_is_for_git(superproject):
    """GIT_CEILING_DIRECTORIES comes from the process environment, where git
    reads it too, not from the mapping recorded_scan_source is given: the walk
    has to agree with the root git found. Here the mapping names a ceiling at
    the superproject and the process does not, so vendor/lib is still nested."""
    lib = superproject / "vendor" / "lib"
    environ = {"GIT_CEILING_DIRECTORIES": str(superproject)}

    assert recorded_scan_source(lib, git_repository_root, environ) is None


# --------------------------------------------------------------------------- #
# Paths that are not UTF-8
# --------------------------------------------------------------------------- #
#
# A label is written into ash_aggregated_results.json, which is UTF-8: a
# directory name that is not (it arrives as surrogates) made model_dump_json
# raise and the results write fail. git_repository_root reads the root as
# bytes (os.fsdecode); decoding git's output strictly would raise
# UnicodeDecodeError out of the container launcher on the host for a repository
# root that is not UTF-8. So such a repository is one like any other,
# and its labels are relative to its root. Only some filesystems can hold such
# a name: Windows cannot decode it, and APFS refuses it.


def _not_utf8_dir(parent: Path) -> Path:
    if not sys.platform.startswith("linux"):
        pytest.skip("only Linux filesystems take a name that is not UTF-8")
    try:
        odd = parent / os.fsdecode(b"caf\xe9")
        odd.mkdir()
    except (UnicodeDecodeError, OSError) as error:
        pytest.skip(f"this filesystem refuses a name that is not UTF-8: {error}")
    return odd


@pytest.mark.unit
def test_a_directory_name_that_is_not_utf8_records_no_scan_source(tmp_path):
    odd = _not_utf8_dir(tmp_path)
    assert _record(odd, tmp_path, {}) is None
    assert _record(odd, None, {}) is None


@pytest.mark.integration
def test_a_repository_root_that_is_not_utf8_is_still_the_root(isolated_tmp):
    """git works in such a checkout, and the labels recorded for it are relative
    to its root, so none of them holds the name the results file cannot."""
    odd = _not_utf8_dir(isolated_tmp)
    _git("init", "-q", cwd=odd)
    (odd / "sub").mkdir()

    assert git_repository_root(odd) == odd.resolve()
    assert host_scan_source_label(odd, git_repository_root) == "."
    assert host_scan_source_label(odd / "sub", git_repository_root) == "sub"
    assert recorded_scan_source(odd, git_repository_root, {}) == "."
    assert recorded_scan_source(odd / "sub", git_repository_root, {}) == "sub"


@pytest.mark.integration
def test_a_directory_that_is_not_utf8_below_a_utf8_root_records_no_label(
    isolated_tmp,
):
    """Its path relative to the root holds the name, so neither the launcher nor
    a local scan records a label for it, or for a directory below it."""
    root = isolated_tmp / "repo"
    root.mkdir()
    _git("init", "-q", cwd=root)
    odd = _not_utf8_dir(root)
    deeper = odd / "deeper"
    deeper.mkdir()

    assert git_repository_root(odd) == root.resolve()
    for directory in (odd, deeper):
        assert host_scan_source_label(directory, git_repository_root) is None
        assert recorded_scan_source(directory, git_repository_root, {}) is None


@pytest.mark.unit
class TestTheGitEntryWalkStopsWhereGitsDiscoveryStops:
    """``_a_git_entry_may_exist`` against GIT_CEILING_DIRECTORIES, directly.

    The walk decides whether git is started at all, so each boundary is pinned
    on the function itself: a ``.git`` above a ceiling must not be found (git
    would not find it either, so starting git only proves the absence), the
    source's own entry always counts (a ceiling hides proper ancestors only),
    and a ceiling's own entry is never read (the walk turns back at the
    boundary, before looking). Entry parsing is pinned where it decides the
    answer: relative and unresolvable entries are dropped, which errs toward
    starting git, and an entry after an empty element matches only the spelling
    it was written with, as git's canonicalize_ceiling_entry reads it.

    Every cell lists ``tmp_path`` as a final bounding ceiling, so no walk here
    depends on what sits above the test's own tree.
    """

    @staticmethod
    def _walks_to_git(monkeypatch, source, ceilings, environ=None):
        from automated_security_helper.utils import scan_source

        monkeypatch.setenv(
            "GIT_CEILING_DIRECTORIES",
            os.pathsep.join(str(entry) for entry in ceilings),
        )
        return scan_source._a_git_entry_may_exist(source, environ or {})

    @staticmethod
    def _tree(tmp_path):
        deepest = tmp_path / "tree" / "a" / "b" / "c"
        deepest.mkdir(parents=True)
        return deepest

    def test_a_git_entry_above_a_ceiling_is_not_found(self, tmp_path, monkeypatch):
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()

        assert not self._walks_to_git(monkeypatch, source, [source.parent, tmp_path])

    def test_a_work_tree_alone_in_the_environment_does_not_start_git(
        self, tmp_path, monkeypatch
    ):
        """GIT_WORK_TREE without GIT_DIR points git at no repository: the root
        lookup drops it and git discovers from the directory, so the walk decides
        and finds nothing here. GIT_DIR alone still does, so git is started."""
        source = self._tree(tmp_path)
        elsewhere = {"GIT_WORK_TREE": str(tmp_path / "elsewhere")}

        assert not self._walks_to_git(monkeypatch, source, [tmp_path], elsewhere)
        assert self._walks_to_git(
            monkeypatch, source, [tmp_path], {"GIT_DIR": str(tmp_path / "r.git")}
        )

    def test_a_ceiling_naming_the_source_itself_does_not_stop_the_walk(
        self, tmp_path, monkeypatch
    ):
        """git hides listed proper ancestors only, never the start itself."""
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()

        assert self._walks_to_git(monkeypatch, source, [source, tmp_path])

    def test_a_ceilings_own_git_entry_is_not_read(self, tmp_path, monkeypatch):
        """The walk turns back at the boundary before looking at its entry."""
        source = self._tree(tmp_path)
        (source.parent / ".git").mkdir()

        assert not self._walks_to_git(monkeypatch, source, [source.parent, tmp_path])

    def test_the_sources_own_git_entry_counts_even_when_listed(
        self, tmp_path, monkeypatch
    ):
        source = self._tree(tmp_path)
        (source / ".git").mkdir()

        assert self._walks_to_git(monkeypatch, source, [source, tmp_path])

    def test_a_git_entry_below_the_ceiling_is_found(self, tmp_path, monkeypatch):
        source = self._tree(tmp_path)
        (source.parent / ".git").mkdir()

        assert self._walks_to_git(monkeypatch, source, [source.parents[1], tmp_path])

    def test_git_dir_in_the_environment_wins_over_any_ceiling(
        self, tmp_path, monkeypatch
    ):
        source = self._tree(tmp_path)

        assert self._walks_to_git(
            monkeypatch,
            source,
            [source.parent, tmp_path],
            environ={"GIT_DIR": str(tmp_path / "elsewhere")},
        )

    def test_a_relative_ceiling_entry_is_dropped(self, tmp_path, monkeypatch):
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()

        assert self._walks_to_git(
            monkeypatch, source, [os.path.join("tree", "a", "b"), tmp_path]
        )

    def test_an_unresolvable_ceiling_entry_is_dropped(self, tmp_path, monkeypatch):
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()

        assert self._walks_to_git(
            monkeypatch, source, [tmp_path / "tree" / "gone", tmp_path]
        )

    def test_an_entry_before_an_empty_element_is_resolved(self, tmp_path, monkeypatch):
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()
        link = tmp_path / "link"
        link.symlink_to(source.parent)

        assert not self._walks_to_git(monkeypatch, source, [link, "", tmp_path])

    def test_an_entry_after_an_empty_element_matches_only_as_written(
        self, tmp_path, monkeypatch
    ):
        """Kept as written, a symlink's spelling names no directory the walk
        spells by its real path, so it hides nothing."""
        source = self._tree(tmp_path)
        (source.parents[1] / ".git").mkdir()
        link = tmp_path / "link"
        link.symlink_to(source.parent)

        assert self._walks_to_git(monkeypatch, source, ["", link, tmp_path])


# (name, source relative to the parity tree, ceiling value as a function of the
# tree). The ceiling spellings are the ones git's canonicalize_ceiling_entry
# treats differently: exact, after an empty element, through a symlink, with a
# trailing slash, with a dotdot, and with a missing entry before a valid one.
_PARITY_SCENARIOS = [
    ("ceiling-below-root", "repo/a/b", lambda t: str(t / "repo" / "a")),
    ("ceiling-at-root", "repo/a", lambda t: str(t / "repo")),
    ("empty-then-exact", "repo/a/b", lambda t: os.pathsep + str(t / "repo" / "a")),
    ("symlink-spelling-before-empty", "repo/a/b", lambda t: str(t / "link" / "a")),
    ("source-via-symlink", "link/a/b", lambda t: str(t / "repo" / "a")),
    ("source-and-ceiling-via-symlink", "link/a/b", lambda t: str(t / "link" / "a")),
    ("trailing-slash", "repo/a/b", lambda t: str(t / "repo" / "a") + "/"),
    ("dotdot-before-empty", "repo/a/b", lambda t: str(t / "repo" / "a" / ".." / "a")),
    (
        "missing-then-valid",
        "repo/a/b",
        lambda t: str(t / "repo" / "zz") + os.pathsep + str(t / "repo" / "a"),
    ),
]

_SOURCE_IS_CEILING = [
    ("source-is-ceiling-root", "repo", lambda t: str(t / "repo")),
    ("source-is-ceiling-sub", "repo/a", lambda t: str(t / "repo" / "a")),
]

# Entries after an empty element are kept as written, so these spellings name
# no directory the walk or git spells by its real path and hide nothing. A
# walk that normalized them would turn each into a ceiling at repo/a and hide
# the repository git still reports. Real git finds the repository here, so
# these feed only the parity cell, not the no-start one.
_AFTER_EMPTY_AS_WRITTEN = [
    (
        "dotdot-after-empty",
        "repo/a/b",
        lambda t: os.pathsep + str(t / "repo" / "a" / ".." / "a"),
    ),
    (
        "double-slash-after-empty",
        "repo/a/b",
        lambda t: os.pathsep + str(t) + "//repo/a",
    ),
]


@pytest.mark.integration
class TestTheWalkAgreesWithRealGitDiscovery:
    """The git-entry walk read against real git itself, scenario by scenario.

    Two properties, each on a tree holding one repository reached directly and
    through a symlink:

    - where the walk says no repository can exist, real git (``rev-parse
      --show-toplevel`` and ``--absolute-git-dir``) finds none either, so the
      walk never hides a repository git would report;
    - where real git finds no repository, ``recorded_scan_source`` starts no
      git at all, measured by a git stand-in planted first on PATH that logs
      every start. Real git's own answer is read first, by absolute path, with
      the stand-in not yet planted.
    """

    @staticmethod
    def _tree(isolated_tmp):
        repo = isolated_tmp / "repo"
        (repo / "a" / "b").mkdir(parents=True)
        _git("init", "-q", cwd=repo)
        (isolated_tmp / "home").mkdir()
        (isolated_tmp / "link").symlink_to(repo, target_is_directory=True)
        return isolated_tmp

    @staticmethod
    def _real_git_answers(source, home, ceiling):
        """(toplevel, git dir) real git gives at *source*, or Nones.

        By absolute path, with a minimal environment, so neither a planted
        stand-in nor this process's git configuration reaches it."""
        real = shutil.which("git")
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "LC_ALL": "C",
            "GIT_CEILING_DIRECTORIES": ceiling,
        }

        def _ask(*args):
            done = subprocess.run(
                [real, *args], cwd=source, env=env, capture_output=True, text=True
            )
            return done.stdout.strip() if done.returncode == 0 else None

        return (
            _ask("rev-parse", "--show-toplevel"),
            _ask("rev-parse", "--absolute-git-dir"),
        )

    @staticmethod
    def _stand_in_git(isolated_tmp, monkeypatch):
        """A git first on PATH that logs each start and answers as git does
        outside a repository. Returns the log it writes."""
        log = isolated_tmp / "git-starts.log"
        bin_dir = isolated_tmp / "stand-in-bin"
        bin_dir.mkdir()
        stand_in = bin_dir / "git"
        stand_in.write_text(
            "#!/bin/sh\n"
            f'printf \'%s cwd=%s args=%s\\n\' "$$" "$(pwd -P)" "$*" >> "{log}"\n'
            'echo "fatal: not a git repository'
            ' (or any of the parent directories): .git" >&2\n'
            "exit 128\n",
            encoding="utf-8",
        )
        stand_in.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        return log

    @pytest.mark.parametrize(
        "name,source,ceiling_fn",
        _PARITY_SCENARIOS + _SOURCE_IS_CEILING + _AFTER_EMPTY_AS_WRITTEN,
        ids=[
            s[0]
            for s in _PARITY_SCENARIOS + _SOURCE_IS_CEILING + _AFTER_EMPTY_AS_WRITTEN
        ],
    )
    def test_no_repository_git_finds_is_missed(
        self, isolated_tmp, monkeypatch, name, source, ceiling_fn
    ):
        from automated_security_helper.utils import scan_source

        tree = self._tree(isolated_tmp)
        ceiling = ceiling_fn(tree)
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", ceiling)
        src = tree / source

        walk = scan_source._a_git_entry_may_exist(src, dict(os.environ))
        top, gitdir = self._real_git_answers(src, tree / "home", ceiling)

        if not walk:
            assert top is None, (name, top)
            assert gitdir is None, (name, gitdir)

    @pytest.mark.parametrize(
        "name,source,ceiling_fn",
        _PARITY_SCENARIOS,
        ids=[s[0] for s in _PARITY_SCENARIOS],
    )
    def test_no_git_start_where_real_git_finds_no_repository(
        self, isolated_tmp, monkeypatch, name, source, ceiling_fn
    ):
        tree = self._tree(isolated_tmp)
        ceiling = ceiling_fn(tree)
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", ceiling)
        src = tree / source
        top, gitdir = self._real_git_answers(src, tree / "home", ceiling)
        if top is not None or gitdir is not None:
            pytest.skip("real git finds a repository here")
        log = self._stand_in_git(isolated_tmp, monkeypatch)

        recorded_scan_source(src, git_repository_root, os.environ)

        starts = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        assert starts == [], (name, starts)

    def test_control_the_stand_in_counts_a_start(self, isolated_tmp, monkeypatch):
        """Must-fire for the start counter: a source inside the repository,
        with no scenario ceiling, makes the stand-in run and log it."""
        tree = self._tree(isolated_tmp)
        log = self._stand_in_git(isolated_tmp, monkeypatch)

        recorded_scan_source(tree / "repo" / "a", git_repository_root, os.environ)

        starts = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        assert any("rev-parse" in line for line in starts), starts
