# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--no-inherit-system-tools`` narrows the pinned-install skip to the destination.

A byte-identical copy of a pinned tool found through PATH or a system directory skips
the pinned install by default. Under ``inherit_system_tools=False`` it does not: the
install runs. The file at the install destination is the install's own output and is
still judged by its digest.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils, tool_downloads
from automated_security_helper.utils.download_utils import (
    _PINNED_TOOL_INSTALL_SCRIPT_NO_INHERIT,
    ToolNotProvisionableError,
    create_pinned_tool_install_command,
    find_verified_pinned_executable,
    install_pinned_tool,
    pinned_command_without_system_tools,
    pinned_install_already_satisfied,
)
from automated_security_helper.utils.tool_downloads import (
    _ASSET_TABLES,
    _DIGESTS,
    _EXECUTABLE_DIGESTS,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("receipt_home")]

PINNED_GRYPE = b"\x7fELF pinned grype v0.111.0 build\n"
GRYPE_ASSET = _ASSET_TABLES["grype"][("linux", "amd64")]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tarball(member_bytes: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo("grype")
        info.size = len(member_bytes)
        info.mtime = 0
        bundle.addfile(info, io.BytesIO(member_bytes))
    return buffer.getvalue()


@pytest.fixture
def pins():
    archive = _tarball(PINNED_GRYPE)
    with (
        patch.object(
            tool_downloads, "_DIGESTS", {**_DIGESTS, GRYPE_ASSET: _sha(archive)}
        ),
        patch.object(
            tool_downloads,
            "_EXECUTABLE_DIGESTS",
            {**_EXECUTABLE_DIGESTS, GRYPE_ASSET: _sha(PINNED_GRYPE)},
        ),
    ):
        yield archive


@pytest.fixture
def on_path(tmp_path, monkeypatch):
    """find_executable resolves grype to the file the test chooses; the directories
    every scan searches are ``ash-bin`` and ``usr-local-bin`` under tmp_path."""
    resolved = SimpleNamespace(grype=None)
    monkeypatch.setattr(
        subprocess_utils,
        "find_executable",
        lambda command, *a, **k: (
            str(resolved.grype) if command == "grype" and resolved.grype else None
        ),
    )
    monkeypatch.setattr(
        subprocess_utils,
        "path_independent_dirs",
        lambda: [tmp_path / "ash-bin", tmp_path / "usr-local-bin"],
    )
    return resolved


def _binary(directory: Path, data: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "grype"
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def test_the_default_accepts_a_byte_identical_copy_found_on_the_search_path(
    tmp_path, pins, on_path
):
    on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)

    present = find_verified_pinned_executable(
        "grype", "linux", "amd64", tmp_path / "dest"
    )

    assert present is not None and present.path == on_path.grype


def test_no_inherit_ignores_a_path_found_pinned_copy_and_installs(
    tmp_path, pins, on_path
):
    on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)

    present = find_verified_pinned_executable(
        "grype", "linux", "amd64", tmp_path / "dest", inherit_system_tools=False
    )

    assert present is None


def test_no_inherit_still_accepts_the_byte_identical_copy_at_the_destination(
    tmp_path, pins, on_path
):
    destination = tmp_path / "dest"
    at_destination = _binary(destination, PINNED_GRYPE)

    present = find_verified_pinned_executable(
        "grype", "linux", "amd64", destination, inherit_system_tools=False
    )

    assert present is not None and present.path == at_destination


def test_no_inherit_reaches_the_installer_through_the_argv_check(
    tmp_path, pins, on_path
):
    on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
    argv = list(
        create_pinned_tool_install_command(
            "grype", "linux", "amd64", str(tmp_path / "dest")
        ).args
    )

    assert pinned_install_already_satisfied(argv) is not None
    assert pinned_install_already_satisfied(argv, inherit_system_tools=False) is None


def test_the_child_install_honors_no_inherit_too(tmp_path, pins, on_path, monkeypatch):
    """``install_pinned_tool`` is the CHILD the declared pinned command runs, and it
    re-checks for an already-present copy before downloading. Under the flag a
    byte-identical PATH copy no longer stands in there either: offline, with no
    cached asset, the default returns the PATH copy while the flag makes the
    install really try -- and refuse for being offline, downloading nothing and
    installing nothing it did not verify."""
    on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
    monkeypatch.setenv("ASH_OFFLINE", "true")

    taken = install_pinned_tool("grype", "linux", "amd64", tmp_path / "dest")
    assert taken == on_path.grype

    with pytest.raises(ToolNotProvisionableError):
        install_pinned_tool(
            "grype", "linux", "amd64", tmp_path / "dest", inherit_system_tools=False
        )
    assert not (tmp_path / "dest" / "grype").exists()


def test_the_retold_command_is_judged_no_inherit_whatever_the_keyword_says(
    tmp_path, pins, on_path
):
    """The rewrite the installer applies under --no-inherit-system-tools: the same
    argv with the no-inherit script, so the child's re-check honors the flag. The
    command itself is the stricter record, the destination copy still satisfies it
    (the install's own output), and any other argv comes back unchanged."""
    on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
    argv = list(
        create_pinned_tool_install_command(
            "grype", "linux", "amd64", str(tmp_path / "dest")
        ).args
    )

    retold = pinned_command_without_system_tools(argv)

    assert (
        retold[3:] == argv[3:] and retold[2] == _PINNED_TOOL_INSTALL_SCRIPT_NO_INHERIT
    )
    compile(retold[2], "<pinned-install>", "exec")
    assert retold == list(
        create_pinned_tool_install_command(
            "grype",
            "linux",
            "amd64",
            str(tmp_path / "dest"),
            inherit_system_tools=False,
        ).args
    )
    # The stricter record wins over the keyword: the PATH copy does not satisfy it.
    assert pinned_install_already_satisfied(retold) is None
    # The destination copy is the install's own output and still does.
    at_destination = _binary(tmp_path / "dest", PINNED_GRYPE)
    present = pinned_install_already_satisfied(retold)
    assert present is not None and present.path == at_destination
    # Any other argv is returned unchanged.
    assert pinned_command_without_system_tools(["ls", "-l"]) == ["ls", "-l"]
