# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hatch_build.py prints safely, stages the same Dockerfile everywhere, and keeps the commit.

Why this file exists
--------------------
Three edges of the hook's staging were wrong.

``_include_genai_guide`` printed the checkout's absolute path with a plain
``print``, outside any handler. pip runs a build hook with its output on a pipe, and
on Windows that takes the ANSI code page, so a checkout path with a character the
code page lacks raised UnicodeEncodeError and failed the whole build instead of
printing the warning that the guide is missing. ``_say`` exists for exactly this.

The staged assets/Dockerfile was written in text mode with no newline argument,
which on Windows turns each line break into a carriage return and a line feed, so
the same sources staged a different file there.

Staging the Dockerfile and recording the commit shared one handler. An error while
staging (a Dockerfile that would not write, say) was caught by the handler that
records "build-error", which overwrote the commit record before the commit was ever
looked up, although git could still name it.

What is asserted
----------------
Each runs the hook from a copy in ``tmp_path``. The console is a cp1252 wrapper
over a byte buffer; the Windows write is modeled by a path class whose
``write_text`` translates line breaks as a Windows text-mode write does unless the
caller passes ``newline``; git is a stub that answers with a commit id, so nothing
here starts a process.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / "hatch_build.py"


def _hook_in(monkeypatch, tree: Path):
    """hatch_build.py, loaded from a copy in ``tree`` so its paths point there."""
    tree.mkdir()
    shutil.copyfile(HOOK, tree / "hatch_build.py")
    spec = importlib.util.spec_from_file_location(
        "hatch_build_staging_edges", tree / "hatch_build.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _give_it_its_inputs(hook, dockerfile_text: str) -> None:
    """The Dockerfile and the package files it stages, so no staging assertion fires."""
    (hook.ASH_REPO_ROOT / "Dockerfile").write_text(dockerfile_text, encoding="utf-8")
    for source_rel, _staged in hook.DOCKERFILE_STAGED_PACKAGE_FILES:
        source = hook.ASH_REPO_ROOT / "automated_security_helper" / source_rel
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("# staged\n", encoding="utf-8")


def test_the_missing_guide_warning_survives_a_console_that_cannot_encode_the_path(
    monkeypatch, tmp_path
):
    """Red at the base: the warning's plain print raised UnicodeEncodeError."""
    hook = _hook_in(monkeypatch, tmp_path / ("ash" + chr(0x2717)))
    assert not hook.GENAI_GUIDE_SOURCE.exists()
    console = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", console)
    build_data: dict = {"force_include": {}}

    object.__new__(hook.CustomBuildHook)._include_genai_guide(build_data)

    console.flush()
    assert b"ash\\u2717" in console.buffer.getvalue()
    assert build_data["force_include"] == {}


class _WindowsLikePath(type(Path())):
    """A path whose ``write_text`` translates "\\n" to "\\r\\n" unless the caller
    names a ``newline``, as a text-mode write does on Windows."""

    def write_text(self, data, encoding=None, errors=None, newline=None):
        if newline is None:
            data = data.replace("\n", "\r\n")
        return super().write_text(data, encoding=encoding, errors=errors, newline="")


def test_the_staged_dockerfile_has_unix_line_breaks_on_every_host(
    monkeypatch, tmp_path
):
    """Red at the base: write_text named no newline, so the Windows model wrote
    "\\r\\n" into the staged file."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _give_it_its_inputs(hook, "FROM scratch\nRUN true\n")
    monkeypatch.setattr(hook.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        hook,
        "ASH_ASSETS_PATH",
        _WindowsLikePath(hook.ASH_REPO_ROOT, "automated_security_helper", "assets"),
    )

    object.__new__(hook.CustomBuildHook)._stage_assets()

    staged = hook.ASH_ASSETS_PATH.joinpath("Dockerfile").read_bytes()
    assert staged == b"FROM scratch\nRUN true\n"


def test_an_error_while_staging_the_dockerfile_keeps_the_commit(monkeypatch, tmp_path):
    """Red at the base: the staging error was handled by the code that records
    "build-error", which ran before the commit was looked up."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _give_it_its_inputs(hook, "FROM scratch\n")
    sha = hashlib.sha1(b"a commit", usedforsecurity=False).hexdigest()

    def boom(content):
        raise RuntimeError("the Dockerfile would not stage")

    monkeypatch.setattr(hook, "staged_dockerfile_text", boom)
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def run(*args, **kwargs):
        return hook.subprocess.CompletedProcess(
            args[0], 0, stdout=b"\n" + sha.encode("ascii") + b"\n", stderr=b""
        )

    monkeypatch.setattr(hook.subprocess, "run", run)

    object.__new__(hook.CustomBuildHook)._stage_assets()

    assert hook.ASH_INSTALLED_REVISION_PATH.read_text() == sha
