# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every git command ``get_scan_set`` starts runs the resolved git, anchored.

Why this exists
---------------
``get_scan_set`` runs git inside the directory it scans. On Windows a program
started by its bare name is looked for in the working directory before PATH, so
a ``git.exe`` committed to the scanned repository would have run for the four
lookups the nesting check makes (common dir, git dir, worktrees, ls-files),
which passed ``git_argv``'s default program to ``subprocess`` while the
repository-root lookup and the diff resolved it. Those four also handed git a
raw copy of the environment, whose PATH may hold relative or empty entries that
let a program git starts by name be found through the working directory.

The tests pin the shape every spawn now has: ``argv[0]`` is the path
``_git_executable`` resolved, the environment's PATH holds anchored entries
only, and GIT_DIR, GIT_WORK_TREE and GIT_COMMON_DIR are left out, by the
repository-root lookup and the diff as well as by the four nesting lookups. A
git hook exports GIT_DIR without GIT_WORK_TREE, and git then takes its working
directory for the top of the work tree, so the root lookup in a subdirectory
named that subdirectory while the diff kept naming files from the real root.
One exception: when the caller names an existing work tree (``GIT_DIR=<bare>
GIT_WORK_TREE=<tree>``, a post-receive hook deploying a checkout), the root
lookup and the diff pass the variables through, since the tree has no ``.git``
entry to discover; the four nesting lookups still drop them.
``test_scan_source`` pins the end-to-end shapes with real repositories. Nothing
is started here: ``subprocess.run`` is replaced by a recorder.
"""

from __future__ import annotations

import ast
import os
import subprocess  # nosec B404
from pathlib import Path

import pytest

from automated_security_helper.utils import get_scan_set as gss

pytestmark = pytest.mark.unit

RESOLVED = "/opt/resolved/bin/git"

LOCATION_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")

STATE_VARIABLES = (
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)

#: Each helper that starts git, with how it is asked about a directory.
HELPERS = [
    pytest.param(lambda d: gss.git_repository_root(d), id="rev-parse --show-toplevel"),
    pytest.param(lambda d: gss.git_common_dir(d), id="rev-parse --git-common-dir"),
    pytest.param(
        lambda d: gss.git_absolute_git_dir(d), id="rev-parse --absolute-git-dir"
    ),
    pytest.param(lambda d: gss.git_worktree_paths(d), id="worktree list"),
    pytest.param(lambda d: gss.git_index_paths_below(d, "src"), id="ls-files"),
    pytest.param(
        lambda d: gss.git_untracked_paths_below(d, "src"), id="ls-files --others"
    ),
    pytest.param(lambda d: gss.get_changed_files("main", cwd=d), id="diff"),
]

#: The two helpers that answer for the layout the caller names: the root lookup
#: and the diff, whose names are joined onto that root.
LAYOUT_HELPERS = [HELPERS[0], HELPERS[-1]]

#: The lookups the nesting check makes, which always discover from the directory.
NESTING_HELPERS = HELPERS[1:-1]


@pytest.fixture
def recorded(monkeypatch):
    """Record each ``subprocess.run`` call instead of starting git."""
    calls: list[tuple[list[str], dict]] = []

    def run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(list(argv), 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(gss.subprocess, "run", run)
    monkeypatch.setattr(gss, "_git_executable", lambda: RESOLVED)
    return calls


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_runs_the_resolved_git(tmp_path, recorded, ask):
    ask(tmp_path)

    assert recorded, "git was not started"
    assert [argv[0] for argv, _ in recorded] == [RESOLVED] * len(recorded)


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_leaves_the_repository_location_variables_out(
    tmp_path, monkeypatch, recorded, ask
):
    """GIT_DIR and its siblings would make git answer about another repository, or,
    set by a hook without GIT_WORK_TREE, take the working directory for the top of
    the work tree. GIT_WORK_TREE names no directory here (a stale export), which
    no helper honors."""
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(elsewhere))
    monkeypatch.setenv("GIT_COMMON_DIR", str(elsewhere / ".git"))

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert env is not os.environ
        assert not set(env) & set(LOCATION_VARIABLES), sorted(env)


def _name_a_deployed_tree(tmp_path, monkeypatch) -> "tuple[str, str]":
    """GIT_DIR and GIT_WORK_TREE as a post-receive deployment exports them: a
    bare repository and an existing tree with no ``.git`` entry."""
    tree = tmp_path / "deployed"
    tree.mkdir()
    bare = str(tmp_path / "deploy.git")
    monkeypatch.setenv("GIT_DIR", bare)
    monkeypatch.setenv("GIT_WORK_TREE", str(tree))
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)
    return bare, str(tree)


@pytest.mark.parametrize("ask", LAYOUT_HELPERS)
def test_the_root_lookup_and_the_diff_keep_a_work_tree_the_caller_names(
    tmp_path, monkeypatch, recorded, ask
):
    """The tree a bare repository is deployed to holds no ``.git`` entry, so git
    discovers nothing there; the variables the caller set are what name the
    repository and its top, and for a directory inside that tree they are passed
    through as they are."""
    bare, tree = _name_a_deployed_tree(tmp_path, monkeypatch)

    ask(Path(tree))

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert env is not os.environ
        assert (env.get("GIT_DIR"), env.get("GIT_WORK_TREE")) == (bare, tree)


@pytest.mark.parametrize("ask", LAYOUT_HELPERS)
def test_the_root_lookup_and_the_diff_make_a_relative_location_absolute(
    tmp_path, monkeypatch, recorded, ask
):
    """A relative GIT_DIR or GIT_WORK_TREE is relative to the directory of the
    process that exported it, this one; git is started in the scanned directory,
    where ``.`` would name something else, so each is made absolute first."""
    (tmp_path / "deployed").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_DIR", "deploy.git")
    monkeypatch.setenv("GIT_WORK_TREE", "deployed")
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)
    here = os.getcwd()

    ask(tmp_path / "deployed")

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert env["GIT_DIR"] == os.path.join(here, "deploy.git")
        assert env["GIT_WORK_TREE"] == os.path.join(here, "deployed")


@pytest.mark.parametrize("ask", LAYOUT_HELPERS)
def test_the_core_worktree_read_for_git_dir_alone_is_anchored_too(
    tmp_path, monkeypatch, recorded, ask
):
    """GIT_DIR without GIT_WORK_TREE makes the root lookup and the diff ask the
    repository whether ``core.worktree`` names its tree; that read runs the
    resolved git with the anchored environment and no location variable of its
    own. The recorder answers every call with an empty stdout, so the key reads as
    unset and the lookup itself then drops the variables as before."""
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "repo.git"))
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    monkeypatch.delenv("GIT_COMMON_DIR", raising=False)

    ask(tmp_path)

    assert len(recorded) == 2, [argv for argv, _ in recorded]
    probe_argv, probe_kwargs = recorded[0]
    assert probe_argv[0] == RESOLVED
    assert probe_argv[-3:] == ["config", "--get", "core.worktree"]
    assert "--git-dir" in probe_argv
    assert not set(probe_kwargs["env"]) & set(LOCATION_VARIABLES)
    _lookup_argv, lookup_kwargs = recorded[1]
    assert not set(lookup_kwargs["env"]) & set(LOCATION_VARIABLES)


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_leaves_the_index_and_object_store_overrides_out(
    tmp_path, monkeypatch, recorded, ask
):
    """GIT_INDEX_FILE replaces the index the diff reads the working tree through,
    and the object-store variables replace where revisions are read from; with
    no layout named, every helper reads the discovered repository's own."""
    for name in STATE_VARIABLES:
        monkeypatch.setenv(name, str(tmp_path / "elsewhere" / name.lower()))
    for name in LOCATION_VARIABLES:
        monkeypatch.delenv(name, raising=False)

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        assert not set(kwargs["env"]) & set(STATE_VARIABLES), sorted(kwargs["env"])


@pytest.mark.parametrize("ask", LAYOUT_HELPERS)
def test_a_kept_layout_drops_the_index_override_and_keeps_the_object_stores(
    tmp_path, monkeypatch, recorded, ask
):
    """With a layout the caller names (GIT_DIR and an existing GIT_WORK_TREE), the
    copy git is started with keeps the object-store variables (a pre-receive
    hook's quarantine is readable only through them) and never GIT_INDEX_FILE:
    the diff's working-tree side is read through the named repository's own
    index."""
    bare, tree = _name_a_deployed_tree(tmp_path, monkeypatch)
    objects = str(tmp_path / "quarantine")
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "foreign.index"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", objects)
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", bare + "/objects")

    ask(Path(tree))

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        env = kwargs["env"]
        assert (env.get("GIT_DIR"), env.get("GIT_WORK_TREE")) == (bare, tree)
        assert "GIT_INDEX_FILE" not in env
        assert env["GIT_OBJECT_DIRECTORY"] == objects
        assert env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] == bare + "/objects"


@pytest.mark.parametrize("ask", NESTING_HELPERS)
def test_the_nesting_lookups_discover_even_when_the_caller_names_a_work_tree(
    tmp_path, monkeypatch, recorded, ask
):
    """A nesting lookup asks about the directory it is started in, never about the
    repository the environment names, so the variables are dropped there still."""
    _name_a_deployed_tree(tmp_path, monkeypatch)

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        assert not set(kwargs["env"]) & set(LOCATION_VARIABLES)


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_gives_git_an_anchored_path(tmp_path, monkeypatch, recorded, ask):
    """A relative or empty PATH entry names a directory under the working directory."""
    anchored = str(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", "", anchored]))

    ask(tmp_path)

    assert recorded, "git was not started"
    for _argv, kwargs in recorded:
        assert kwargs["env"]["PATH"] == anchored


@pytest.mark.parametrize("ask", HELPERS)
def test_each_helper_starts_nothing_when_no_git_is_found(tmp_path, monkeypatch, ask):
    """With no git on an anchored PATH, no bare name is handed to the OS to look up."""
    calls = []
    monkeypatch.setattr(gss.subprocess, "run", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(gss, "_git_executable", lambda: None)

    assert ask(tmp_path) is None
    assert calls == []


def _git_argv_calls_without_a_program(path: Path) -> list[int]:
    """Lines of ``git_argv(...)`` calls in *path* that pass no ``program=``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "git_argv"
        and not any(keyword.arg == "program" for keyword in node.keywords)
    ]


def test_every_git_argv_in_the_module_names_its_program():
    """The gate: a new spawn that takes ``git_argv``'s default fails here."""
    assert _git_argv_calls_without_a_program(Path(gss.__file__)) == []


def test_the_gate_sees_a_call_that_takes_the_default(tmp_path):
    """The gate's own control: the shape it looks for is found when present."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from automated_security_helper.utils.git_command import git_argv\n"
        'a = git_argv("status")\n'
        'b = git_argv("status", program="/opt/git")\n',
        encoding="utf-8",
    )
    assert _git_argv_calls_without_a_program(sample) == [2]
