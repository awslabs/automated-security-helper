# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hatch_build.py fails the build on a missing staged source, and reads utf-8.

Why this file exists
--------------------
Two failures of the asset staging were silent.

The staging loop raises FileNotFoundError when a file the Dockerfile COPYs from
outside assets/ is missing, with a comment saying the build must fail rather than
ship a Dockerfile that fails at image build time. The enclosing ``except
Exception`` caught that very exception, printed it, wrote "build-error" as the
commit record and let the build continue: the exact outcome the raise exists to
refuse, reached through the raise itself.

The Dockerfile was read and written with ``read_text()`` and ``write_text()`` and
no encoding, which take the console's encoding. Its first lines hold characters
outside every ANSI code page, so on a Windows host whose code page is not utf-8
the read raised UnicodeDecodeError, no assets/Dockerfile was generated, and the
same handler recorded "build-error".

The first fix re-raised FileNotFoundError, which covers more than the staging
assertion. ``_get_commit_sha`` runs git with ``subprocess.run`` and handles only
``CalledProcessError``: a git that ``shutil.which`` finds but that cannot be run
(its interpreter missing, say) raises FileNotFoundError with ENOENT, and that
re-raise failed the build where an unrunnable git is meant to record
"build-error" and continue (test_hatch_build_records_commit.py pins that for
PermissionError). The missing staged source now raises its own class, so the two are
told apart; since then every error of the Dockerfile staging fails the build (see
test_hatch_build_staging_edges.py), and only the commit step records "build-error".

What is asserted
----------------
``_stage_assets`` on a tree whose staged sources are absent raises
FileNotFoundError and records no "build-error". The raise comes before the hook
runs git, so nothing here starts a process; the hook is loaded from a copy in
``tmp_path`` so its paths point there. With the staged sources present and a
``subprocess.run`` that raises FileNotFoundError for git, ``_stage_assets``
records "build-error" and returns. The encoding is a static read of the hook's
own source: every text read and write of the Dockerfile names utf-8.
"""

from __future__ import annotations

import ast
import errno
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / "hatch_build.py"


def _load(monkeypatch, path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_a_missing_staged_source_fails_the_build(monkeypatch, tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copyfile(HOOK, tree / "hatch_build.py")
    shutil.copyfile(REPO_ROOT / "Dockerfile", tree / "Dockerfile")
    hook = _load(monkeypatch, tree / "hatch_build.py", "hatch_build_missing_source")
    # The control: the copy has a Dockerfile and none of the sources it stages.
    assert hook.DOCKERFILE_STAGED_PACKAGE_FILES
    for source_rel, _staged in hook.DOCKERFILE_STAGED_PACKAGE_FILES:
        assert not (tree / "automated_security_helper" / source_rel).exists()

    with pytest.raises(FileNotFoundError, match="Dockerfile stages"):
        object.__new__(hook.CustomBuildHook)._stage_assets()

    revision = hook.ASH_INSTALLED_REVISION_PATH
    assert not revision.exists() or revision.read_text() != "build-error", (
        "the missing source was swallowed and recorded as a build error instead "
        "of failing the build"
    )


def test_a_git_that_cannot_be_run_still_records_build_error(monkeypatch, tmp_path):
    """Only a missing staged source fails the build. A FileNotFoundError from
    running git is an error like any other of the hook's: "build-error" is
    recorded and the build continues."""
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copyfile(HOOK, tree / "hatch_build.py")
    shutil.copyfile(REPO_ROOT / "Dockerfile", tree / "Dockerfile")
    hook = _load(monkeypatch, tree / "hatch_build.py", "hatch_build_git_not_runnable")
    # The control: every staged source is present, so the staging assertion
    # does not fire and the hook reaches git.
    for source_rel, _staged in hook.DOCKERFILE_STAGED_PACKAGE_FILES:
        source = tree / "automated_security_helper" / source_rel
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("# staged\n", encoding="utf-8")
    git_path = str(tree / "bin" / "git")
    monkeypatch.setattr(hook.shutil, "which", lambda name: git_path)

    def run(*args, **kwargs):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", git_path)

    monkeypatch.setattr(hook.subprocess, "run", run)

    object.__new__(hook.CustomBuildHook)._stage_assets()

    assert hook.ASH_INSTALLED_REVISION_PATH.read_text() == "build-error"


def test_the_dockerfile_is_read_and_written_as_utf8():
    tree = ast.parse(HOOK.read_text(encoding="utf-8"))
    text_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("read_text", "write_text")
    ]
    # The control: the hook reads and writes text files at all.
    assert text_calls
    without_encoding = [
        f"line {node.lineno}: {node.func.attr}"
        for node in text_calls
        if not any(
            keyword.arg == "encoding"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "utf-8"
            for keyword in node.keywords
        )
        # The commit record is ASCII by construction; the Dockerfile is not.
        and node.lineno in _dockerfile_text_lines(HOOK)
    ]
    assert without_encoding == [], without_encoding


def _dockerfile_text_lines(hook: Path) -> set[int]:
    """Line numbers of the read_text/write_text calls on the Dockerfile and its copy."""
    lines = hook.read_text(encoding="utf-8").splitlines()
    return {
        number
        for number, line in enumerate(lines, start=1)
        if (
            "dockerfile_path.read_text(" in line
            or "dockerfile_copy_path.write_text(" in line
        )
    }
