# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every file the build hook writes into the source tree is gitignored.

hatch_build.py stages files into the tree it builds, an editable install's
included: the Dockerfile and the package files it COPYs, the commit record, and
the GenAI guide. Only .gitignore keeps them out of `git status`, so a staged file
with no entry of its own leaves every checkout that builds with an untracked
file. A tree without the guide's entry got an untracked
automated_security_helper/assets/genai-steering-guide.md.

The hook runs here on a copy of its own inputs, so the paths checked are the
ones it writes, a new one included, and not a list kept beside it.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess  # nosec B404 - runs git in temporary directories, fixed argv
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_git_config_from_the_host(monkeypatch, tmp_path):
    """No system or user git config, and no GIT_* variable from the caller: a
    user's global excludes file would hide a missing entry, and GIT_DIR from a
    hook would point git at another repository. git looks for no repository
    above tmp_path, so the hook's own git finds none for its copy."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))


def _load(monkeypatch, path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def _files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }


def _copy_in(relative: str, tree: Path) -> None:
    target = tree / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_ROOT / relative, target)


def _staged_by_the_hook(monkeypatch, tree: Path) -> tuple[set[str], object]:
    """(the files the hook's initialize writes into ``tree``, the hook module
    loaded from ``tree``). ``tree`` gets the hook and the inputs it reads."""
    real = _load(monkeypatch, REPO_ROOT / "hatch_build.py", "hatch_build_inputs")
    tree.mkdir()
    inputs = ["hatch_build.py", "Dockerfile"]
    inputs += [
        f"automated_security_helper/{source}"
        for source, _ in real.DOCKERFILE_STAGED_PACKAGE_FILES
    ]
    inputs.append(real.GENAI_GUIDE_SOURCE.relative_to(real.ASH_REPO_ROOT).as_posix())
    for relative in inputs:
        _copy_in(relative, tree)
    hook = _load(monkeypatch, tree / "hatch_build.py", "hatch_build_staging")
    before = _files(tree)
    build_data: dict = {"force_include": {}}
    object.__new__(hook.CustomBuildHook).initialize("standard", build_data)
    staged = _files(tree) - before
    # The control: the staging finished, and the guide was included. An error
    # while staging the Dockerfile fails the build, so reaching here means the
    # generated Dockerfile was written, which is checked below. The record is
    # also checked, since "build-error" there means the commit step failed.
    generated = hook.ASH_ASSETS_PATH.joinpath("Dockerfile")
    assert generated.relative_to(hook.ASH_REPO_ROOT).as_posix() in staged, staged
    assert hook.ASH_INSTALLED_REVISION_PATH.read_text() != "build-error"
    assert build_data["force_include"], build_data
    return staged, hook


def _ignored(paths: set[str], tree: Path) -> dict[str, bool]:
    """Whether the repository's .gitignore files ignore each path, in a fresh
    repository holding only them: no info/exclude and no global excludes file."""
    tree.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=tree, check=True)  # nosec B603 B607
    for path in paths:
        parts = Path(path).parts
        for depth in range(len(parts)):
            gitignore = Path(*parts[:depth], ".gitignore")
            if (REPO_ROOT / gitignore).is_file() and not (tree / gitignore).exists():
                _copy_in(gitignore.as_posix(), tree)
    answers = {}
    for path in sorted(paths):
        done = subprocess.run(  # nosec B603 B607 - fixed git argv in a temporary repository
            ["git", "check-ignore", "--no-index", "--quiet", "--", path],
            cwd=tree,
            capture_output=True,
        )
        assert done.returncode in (0, 1), done.stderr
        answers[path] = done.returncode == 0
    return answers


def test_every_file_the_build_hook_stages_is_gitignored(monkeypatch, tmp_path):
    staged, hook = _staged_by_the_hook(monkeypatch, tmp_path / "tree")
    # The control: the files written are at least those the hook's constants
    # name, so a hook that staged nothing cannot pass.
    root = hook.ASH_REPO_ROOT
    named = {
        hook.ASH_INSTALLED_REVISION_PATH.relative_to(root).as_posix(),
        hook.GENAI_GUIDE_PACKAGE_PATH,
    } | {
        hook.ASH_ASSETS_PATH.joinpath(name).relative_to(root).as_posix()
        for _, name in hook.DOCKERFILE_STAGED_PACKAGE_FILES
    }
    assert named <= staged, (named, staged)

    answers = _ignored(staged, tmp_path / "ignores")

    assert [path for path, ignored in answers.items() if not ignored] == []


def test_control_the_check_sees_a_path_no_entry_ignores(tmp_path):
    """The check can fail: the hook itself, tracked, is not ignored."""
    assert _ignored({"hatch_build.py"}, tmp_path / "ignores") == {
        "hatch_build.py": False
    }
