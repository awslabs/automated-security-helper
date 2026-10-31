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
looked up, although git could still name it. Both handlers also printed the same
"asset staging error" line, whichever step had failed; each now prints one line
that names its step.

Splitting the handlers then left a staging error printed and skipped, with a valid
commit recorded: the artifact shipped a stale or missing assets/Dockerfile beside a
healthy-looking revision, and nothing machine-readable showed it. A staging error
now fails the build, like the missing staged source before it; a commit-step error
still records "build-error" and lets the build go on, since it costs the revision
and leaves the artifact complete.

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


@pytest.mark.parametrize(
    ("staging_fails", "commit_fails", "message"),
    [
        pytest.param(
            True,
            False,
            "Error staging the Dockerfile, failing the build",
            id="staging-only",
        ),
        pytest.param(
            False,
            True,
            "Unexpected error recording the commit, continuing the build",
            id="commit-only",
        ),
        # The staging error ends the hook before the commit step runs.
        pytest.param(
            True,
            True,
            "Error staging the Dockerfile, failing the build",
            id="both",
        ),
    ],
)
def test_each_failing_step_prints_one_message_naming_it(
    monkeypatch, tmp_path, capsys, staging_fails, commit_fails, message
):
    """Red at the base: both handlers printed the same two lines ("Unexpected
    error in build hook" and "Continuing build despite asset staging error"), so
    a commit-record failure said it was a staging error, and both failing printed
    the pair twice with nothing to tell the steps apart. Red before the staging
    error failed the build: the staging message said it was continuing."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _give_it_its_inputs(hook, "FROM scratch\n")
    sha = hashlib.sha1(b"a commit", usedforsecurity=False).hexdigest()
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def staged(content):
        raise RuntimeError("the Dockerfile would not stage")

    def run(*args, **kwargs):
        if commit_fails:
            raise PermissionError(13, "Permission denied", "/usr/bin/git")
        return hook.subprocess.CompletedProcess(
            args[0], 0, stdout=b"\n" + sha.encode("ascii") + b"\n", stderr=b""
        )

    if staging_fails:
        monkeypatch.setattr(hook, "staged_dockerfile_text", staged)
    monkeypatch.setattr(hook.subprocess, "run", run)

    if staging_fails:
        with pytest.raises(RuntimeError, match="would not stage"):
            object.__new__(hook.CustomBuildHook)._stage_assets()
    else:
        object.__new__(hook.CustomBuildHook)._stage_assets()

    messages = [
        line for line in capsys.readouterr().out.splitlines() if "the build:" in line
    ]
    assert len(messages) == 1, messages
    assert message in messages[0], messages


def test_an_error_while_staging_the_dockerfile_fails_the_build(monkeypatch, tmp_path):
    """Red before: the staging error was printed and skipped, and the hook went on
    to record a valid commit beside a stale or missing assets/Dockerfile, with
    nothing machine-readable to show it."""
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

    with pytest.raises(RuntimeError, match="would not stage"):
        object.__new__(hook.CustomBuildHook)._stage_assets()

    # The build stopped before it recorded a healthy-looking commit.
    assert not hook.ASH_INSTALLED_REVISION_PATH.exists()


@pytest.mark.parametrize(
    "fault",
    [
        pytest.param("unreadable", id="read-error"),
        pytest.param("unwritable", id="write-error"),
    ],
)
def test_a_dockerfile_that_cannot_be_read_or_written_fails_the_build(
    monkeypatch, tmp_path, fault
):
    """Red before: a decode error on the root Dockerfile and a write error on
    assets/Dockerfile were printed and the build went on."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _give_it_its_inputs(hook, "FROM scratch\n")
    # No git: should the staging error not stop the hook, nothing is started.
    monkeypatch.setattr(hook.shutil, "which", lambda name: None)
    if fault == "unreadable":
        # Bytes that are not utf-8, in place of the text _give_it_its_inputs wrote.
        dockerfile = hook.ASH_REPO_ROOT / "Dockerfile"
        dockerfile.write_bytes(b"FROM scratch\n# \xff\xfe\n")
    else:
        # A directory where the generated file goes: opening it to write fails.
        (hook.ASH_ASSETS_PATH / "Dockerfile").mkdir(parents=True)

    with pytest.raises((UnicodeDecodeError, OSError)):
        object.__new__(hook.CustomBuildHook)._stage_assets()

    assert not hook.ASH_INSTALLED_REVISION_PATH.exists()
