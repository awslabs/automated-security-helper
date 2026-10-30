# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How utils/package_manager_child.py reads the files it copies, and what it keeps.

Four shapes the module missed:

- A ``package.json`` nested past the interpreter's recursion limit made
  ``json.loads`` raise ``RecursionError``, not ``ValueError``, so under
  ``--ignore-suppressions`` the copy step crashed instead of handing the manifest
  to the tool as it was.
- pnpm 10 reads its advisory ignore lists (``auditConfig``) from
  ``pnpm-workspace.yaml`` as well as from the manifest, and the copy left that
  file out, so a repository's suppressions kept there were dropped although the
  module says repository suppressions are honored. Only that key crosses; the
  registry and every other setting in the file stay out.
- Each input was checked by name and then read by name, so a file swapped for a
  link out of the tree between the two was read through the link. The copy now
  opens the file first and judges the open descriptor.
- A lockfile that was a link to nothing read as "no lockfile", so the package
  was passed over with nothing recorded; it is listed as an input and refused.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils import package_manager_child
from automated_security_helper.utils.package_manager_child import (
    LINK_LEAVES_TREE,
    NOT_A_REGULAR_FILE,
    package_manager_child as child_of,
    package_manager_inputs,
    refused_inputs,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="symlinks and POSIX paths"),
]

MARKER = "outside-tree-marker-7c1e"
AUDIT_CONFIG = {"ignoreCves": ["CVE-2026-0001"], "ignoreGhsas": ["GHSA-aaaa-bbbb-cccc"]}


def _package(root: Path, lock_name: str, manifest: bytes | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_bytes(
        manifest if manifest is not None else json.dumps({"name": root.name}).encode()
    )
    (root / lock_name).write_text("{}\n", encoding="utf-8")
    return root


def _copy(binary: str, package: Path, tmp_path: Path, **options) -> dict:
    """The files the tool would see in its private directory, by name."""
    parent = tmp_path / "out"
    parent.mkdir(exist_ok=True)
    with child_of(
        binary, package, parent=parent, scan_root=tmp_path / "repo", **options
    ) as child:
        return {
            p.name: p.read_bytes() for p in Path(child.cwd).iterdir() if p.is_file()
        }


class TestADeeplyNestedManifest:
    def test_is_handed_to_the_tool_as_it_is_under_ignore_suppressions(self, tmp_path):
        """json.loads refuses it with RecursionError; the copy keeps the bytes."""
        depth = 50_000
        nested = b'{"name": "deep", "a": ' + b"[" * depth + b"]" * depth + b"}"
        package = _package(tmp_path / "repo" / "deep", "package-lock.json", nested)

        copied = _copy("npm", package, tmp_path, ignore_suppressions=True)

        assert copied["package.json"] == nested


class TestPnpmWorkspaceSettings:
    def _workspace(self, tmp_path: Path, text: str) -> Path:
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        (package / "pnpm-workspace.yaml").write_text(text, encoding="utf-8")
        return package

    def test_the_audit_config_crosses_and_nothing_else_does(self, tmp_path):
        package = self._workspace(
            tmp_path,
            yaml.safe_dump(
                {
                    "packages": ["packages/*"],
                    "registry": "https://registry.example/",
                    "auditConfig": AUDIT_CONFIG,
                }
            ),
        )

        copied = _copy("pnpm", package, tmp_path)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {
            "auditConfig": AUDIT_CONFIG
        }
        assert b"registry.example" not in copied["pnpm-workspace.yaml"]

    def test_nothing_crosses_under_ignore_suppressions(self, tmp_path):
        package = self._workspace(
            tmp_path, yaml.safe_dump({"auditConfig": AUDIT_CONFIG})
        )

        copied = _copy("pnpm", package, tmp_path, ignore_suppressions=True)

        assert "pnpm-workspace.yaml" not in copied

    def test_a_file_without_the_key_gives_no_file(self, tmp_path):
        """Control: the settings-only file the module distrusts stays out."""
        package = self._workspace(
            tmp_path, 'packages: []\nregistry: "https://registry.example/"\n'
        )

        copied = _copy("pnpm", package, tmp_path)

        assert "pnpm-workspace.yaml" not in copied
        assert set(copied) == {"package.json", "pnpm-lock.yaml"}

    def test_the_workspace_file_is_an_input_of_pnpm(self, tmp_path):
        """A linked one that leaves the tree refuses the package like any input."""
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        outside = tmp_path / "elsewhere" / "pnpm-workspace.yaml"
        outside.parent.mkdir()
        outside.write_text("auditConfig: {}\n", encoding="utf-8")
        os.symlink(outside, package / "pnpm-workspace.yaml")

        refused = refused_inputs("pnpm", package, roots=[tmp_path / "repo"])

        assert refused == [(package / "pnpm-workspace.yaml", LINK_LEAVES_TREE)]


class TestAnInputSwappedAfterItsCheck:
    def test_is_not_read_through_the_new_link(self, tmp_path, monkeypatch):
        """The lockfile is a regular file when its name is checked and a link to a
        file outside the tree when it is read: the copy never holds the outside
        file's content, and the lockfile is left out of the copy."""
        package = _package(tmp_path / "repo" / "web", "package-lock.json")
        outside = tmp_path / "elsewhere" / "package-lock.json"
        outside.parent.mkdir()
        outside.write_text(MARKER, encoding="utf-8")
        lockfile = package / "package-lock.json"
        real_refusal = package_manager_child.input_refusal
        swapped = []

        def swap_after_the_first_check(path, roots):
            if Path(path) == lockfile and not swapped:
                # The check ran on the regular file; now it is a link elsewhere.
                answer = real_refusal(path, roots)
                lockfile.unlink()
                os.symlink(outside, lockfile)
                swapped.append(path)
                return answer
            return real_refusal(path, roots)

        monkeypatch.setattr(
            package_manager_child, "input_refusal", swap_after_the_first_check
        )

        copied = _copy("npm", package, tmp_path)

        assert swapped, "the check never ran, so the swap was not exercised"
        assert all(MARKER.encode() not in data for data in copied.values()), copied
        assert "package-lock.json" not in copied


class TestADanglingLockfileLink:
    @pytest.mark.parametrize(
        "binary,lock_name",
        [
            ("npm", "package-lock.json"),
            ("pnpm", "pnpm-lock.yaml"),
            ("yarn", "yarn.lock"),
        ],
    )
    def test_is_listed_and_refused_with_its_reason(self, tmp_path, binary, lock_name):
        package = tmp_path / "repo" / "web"
        package.mkdir(parents=True)
        (package / "package.json").write_text('{"name": "web"}', encoding="utf-8")
        # The link's target would be inside the tree, so the one reason left
        # is that nothing is there to read.
        os.symlink(package / "gone" / lock_name, package / lock_name)

        listed = package_manager_inputs(binary, package)
        refused = refused_inputs(binary, package, roots=[tmp_path / "repo"])

        assert package / lock_name in listed
        assert (package / lock_name, NOT_A_REGULAR_FILE) in refused


class TestWithinByIdentity:
    def test_a_root_named_through_a_link_still_holds_its_tree(self, tmp_path):
        """The containment test compares files, not real-path strings, so a root
        spelled through a link (or, where the filesystem has them, a bind mount
        or another letter case) still holds the paths below it."""
        root = tmp_path / "repo"
        (root / "sub").mkdir(parents=True)
        alias = tmp_path / "alias"
        os.symlink(root, alias)

        assert package_manager_child._within(root / "sub", alias) is True
        assert package_manager_child._within(tmp_path / "elsewhere", alias) is False
