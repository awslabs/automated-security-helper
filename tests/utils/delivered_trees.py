# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers for tests that deliver a tree to the MCP server and follow its links.

A tree is delivered through the real ``set_source_git``, cloning a local
repository, because a git clone keeps symlinks (a zip upload refuses them).
``reads`` records every config file resolution reads, resolved, so a test can
show a file was never opened.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def clone(
    tmp: Path, files: Dict[str, str], links: Dict[str, Path], session_id: str
) -> Path:
    """Deliver a tree holding ``files`` and ``links`` through the real git clone."""
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    origin = tmp / "origin"
    origin.mkdir()
    for name, text in files.items():
        write(origin / name, text)
    for name, target in links.items():
        symlink(origin / name, target)
    _git(origin, "init", "-q")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "tree")
    # set_source_git clones from a remote https or ssh host only. These tests
    # need the real clone (a zip upload refuses symlinks) without a network, so
    # the host check alone is bypassed for the local fixture origin; every other
    # validation and the clone itself stay real.
    with patch.object(
        source_delivery, "remote_clone_host", lambda url: "origin.invalid"
    ):
        source = set_source_git(url=origin.as_uri(), session_id=session_id)
    for name in links:
        assert (source / name).is_symlink(), f"the clone dropped the link {name}"
    return source


def reads(during: Callable[[], Any]) -> List[Path]:
    """The config files read while ``during`` runs, resolved."""
    from automated_security_helper.config import config_sources

    read: List[Path] = []
    real = config_sources.read_config_file

    def recording(path: Path, *args: Any, **kwargs: Any) -> Any:
        read.append(Path(path).resolve())
        return real(path, *args, **kwargs)

    with patch.object(config_sources, "read_config_file", recording):
        during()
    return read
