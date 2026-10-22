# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers for tests that deliver a tree to the MCP server and follow its links.

A tree is delivered by cloning a local repository into the session, because a
git clone keeps symlinks (a zip upload refuses them). ``set_source_git`` itself
refuses a local clone source and lets git use only https and ssh, so
``deliver_local_repository`` runs the clone step that follows those checks
(``_clone_into_session``), with git's file protocol allowed for that clone
only. ``reads`` records every config file resolution reads, resolved, so a test
can show a file was never opened.
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


def deliver_local_repository(origin: Path, session_id: str) -> Path:
    """Clone the repository at ``origin`` into ``session_id``'s workspace.

    The step ``set_source_git`` runs once the url is checked: the session's
    source is replaced and the clone runs with the session's git environment.
    """
    from automated_security_helper.cli.mcp import source_delivery as sd

    with patch.object(
        sd, "_GIT_ARGV", (*sd._GIT_ARGV, "-c", "protocol.file.allow=always")
    ):
        return sd._clone_into_session(
            origin.as_uri(), None, depth=1, workspace_root=None, session_id=session_id
        )


def clone(
    tmp: Path, files: Dict[str, str], links: Dict[str, Path], session_id: str
) -> Path:
    """Deliver a tree holding ``files`` and ``links`` through a real git clone."""
    origin = tmp / "origin"
    origin.mkdir()
    for name, text in files.items():
        write(origin / name, text)
    for name, target in links.items():
        symlink(origin / name, target)
    _git(origin, "init", "-q")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "tree")
    source = deliver_local_repository(origin, session_id)
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
