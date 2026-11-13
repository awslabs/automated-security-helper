# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ``extends`` base is judged on the file that is opened, and that file is read.

A base is opened first. The caller's gate (``permit_base``) is asked about the
path the descriptor leads to, and the read is held to that descriptor's
(device, inode). The cell here changes what a directory of the base's path leads
to while the base is checked, and expects the chain to be refused with nothing
of the ungranted file in the message. The control cell leaves the directory
alone and expects the base to be read.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, List

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

CANARY = "ungranted-base-canary-3b9e"


class _Tree:
    """``granted/.ash.yaml`` extends ``dir_a/base.yaml``. ``dir_a`` can be taken
    out of the way and replaced by a link to the ungranted ``outside/``."""

    def __init__(self, tmp_path: Path) -> None:
        tmp_path = tmp_path.resolve()
        self.granted = tmp_path / "granted"
        self.granted.mkdir()
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        (self.outside / "base.yaml").write_text(
            f"project_name: {CANARY}\n", encoding="utf-8"
        )
        self.dir_a = self.granted / "dir_a"
        self.dir_a.mkdir()
        (self.dir_a / "base.yaml").write_text("project_name: granted\n", "utf-8")
        self.held_back = self.granted / "dir_a.held"
        self.root = self.granted / ".ash.yaml"
        self.root.write_text("extends: dir_a/base.yaml\n", encoding="utf-8")
        self.base = self.dir_a / "base.yaml"

    def is_linked(self) -> bool:
        return self.dir_a.is_symlink()

    def link_to_the_ungranted_directory(self) -> None:
        if self.is_linked():
            return
        try:
            self.dir_a.rename(self.held_back)
            self.dir_a.symlink_to(self.outside, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"cannot make a symbolic link here: {error}")

    def be_the_granted_directory(self) -> None:
        if not self.is_linked():
            return
        self.dir_a.unlink()
        self.held_back.rename(self.dir_a)

    def permits(self, path: Path) -> bool:
        """The gate: a path is permitted unless it resolves to the ungranted
        directory."""
        return not Path(os.path.realpath(path)).is_relative_to(self.outside)


def _resolve(tree: _Tree, permit: Callable[[Path], bool]) -> Any:
    return config_sources.resolve_config_document(
        tree.root, confine_to=tree.granted, permit_base=permit
    )


def test_control_the_base_of_a_granted_directory_is_read(tmp_path) -> None:
    tree = _Tree(tmp_path)

    document = _resolve(tree, tree.permits)

    assert document.data["project_name"] == "granted", document.data


def test_a_base_whose_directory_led_elsewhere_while_it_was_checked_is_refused(
    tmp_path, monkeypatch
) -> None:
    """The directory leads to the ungranted one while the base's identity is
    taken, to the granted one while the gate answers, and to the ungranted one
    again once it has answered. The gate's answer is about the granted file and
    the read would open the other one.

    The steps are driven from the two places the check passes through: the
    identity of the base's path (``config_sources.file_identity``) and the gate.
    """
    tree = _Tree(tmp_path)
    real_file_identity = config_sources.file_identity
    seen: List[str] = []

    def identity_of_the_ungranted_file(path: Path) -> Any:
        if Path(path) == tree.base:
            tree.link_to_the_ungranted_directory()
            identity = real_file_identity(path)
            tree.be_the_granted_directory()
            seen.append("identity")
            return identity
        return real_file_identity(path)

    def gate_that_sees_the_granted_file(path: Path) -> bool:
        permitted = tree.permits(path)
        if Path(path) == tree.base:
            tree.link_to_the_ungranted_directory()
            seen.append("gate")
        return permitted

    monkeypatch.setattr(config_sources, "file_identity", identity_of_the_ungranted_file)

    with pytest.raises(ASHConfigSourceError) as refused:
        _resolve(tree, gate_that_sees_the_granted_file)

    assert "gate" in seen, "the gate was not asked about the base"
    assert CANARY not in str(refused.value), str(refused.value)
