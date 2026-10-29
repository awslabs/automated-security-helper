# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The files utils/package_manager_child.py hands a package manager, and the copy.

Three shapes the module missed:

- A ``package.json`` that starts with a UTF-8 byte order mark is JSON to the
  package managers, and ``json.loads`` refuses the mark, so under
  ``--ignore-suppressions`` the ``pnpm.auditConfig`` (pnpm's advisory ignore
  lists) stayed in the copy and pnpm applied the repository's suppressions under
  the flag that lifts every suppression.
- A ``skip`` directory that holds the package itself (ASH's output directory, when
  the package sits in the converted work directory below it) pruned every
  directory of the package, so a yarn workspace's member manifests there were
  neither refusal-checked nor copied.
- A linked directory was listed for its own ``package.json`` only; yarn walks it
  for workspace members like any other directory, so a member two levels below
  the link was neither refused nor copied.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.utils.package_manager_child import (
    LINK_LEAVES_TREE,
    package_manager_child,
    package_manager_inputs,
    refused_inputs,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="symlinks and POSIX paths"),
]

AUDIT_CONFIG = {"ignoreCves": ["CVE-2026-0001"], "ignoreGhsas": ["GHSA-aaaa-bbbb-cccc"]}


def _manifest(directory: Path, name: str, **extra) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "package.json"
    path.write_text(json.dumps({"name": name, **extra}), encoding="utf-8")
    return path


def _yarn_package(root: Path) -> Path:
    package = root / "web"
    _manifest(package, "web", workspaces=["packages/*"])
    (package / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
    return package


def _rel(paths, base: Path) -> list[str]:
    return sorted(Path(p).relative_to(base).as_posix() for p in paths)


class TestManifestWithAByteOrderMark:
    def test_the_audit_config_is_dropped_under_ignore_suppressions(self, tmp_path):
        package = tmp_path / "repo" / "web"
        package.mkdir(parents=True)
        manifest = {"name": "web", "pnpm": {"auditConfig": AUDIT_CONFIG}}
        (package / "package.json").write_bytes(
            b"\xef\xbb\xbf" + json.dumps(manifest, indent=2).encode("utf-8")
        )
        (package / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        parent = tmp_path / "out"
        parent.mkdir()

        with package_manager_child(
            "pnpm",
            package,
            parent=parent,
            scan_root=tmp_path / "repo",
            ignore_suppressions=True,
        ) as child:
            copied = (child.cwd / "package.json").read_bytes()

        assert not copied.startswith(b"\xef\xbb\xbf"), copied[:8]
        decoded = json.loads(copied.decode("utf-8"))
        assert "auditConfig" not in decoded.get("pnpm", {}), decoded
        assert decoded["name"] == "web"

    def test_the_audit_config_stays_when_suppressions_apply(self, tmp_path):
        """Control: without the flag the repository's suppression is honored, and
        the manifest is copied as it is, mark included."""
        package = tmp_path / "repo" / "web"
        package.mkdir(parents=True)
        manifest = {"name": "web", "pnpm": {"auditConfig": AUDIT_CONFIG}}
        raw = b"\xef\xbb\xbf" + json.dumps(manifest).encode("utf-8")
        (package / "package.json").write_bytes(raw)
        (package / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        parent = tmp_path / "out"
        parent.mkdir()

        with package_manager_child(
            "pnpm", package, parent=parent, scan_root=tmp_path / "repo"
        ) as child:
            copied = (child.cwd / "package.json").read_bytes()

        assert copied == raw


class TestSkipHoldingThePackage:
    def test_a_package_below_the_skipped_output_dir_keeps_its_members(self, tmp_path):
        """The converted work directory sits below ASH's output directory, which
        the scanner passes as ``skip``. The skip must not prune the package's own
        directories."""
        output = tmp_path / "out"
        work = output / "converted" / "archive-extracted"
        package = _yarn_package(work)
        _manifest(package / "packages" / "api", "api")
        _manifest(package / "packages" / "ui", "ui")

        listed = package_manager_inputs("yarn", package, skip=[output])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "packages/ui/package.json",
            "yarn.lock",
        ]

    def test_a_skip_below_the_package_is_still_pruned(self, tmp_path):
        """Control: an output directory inside the scanned package is left out,
        as before."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "api", "api")
        output = package / ".ash" / "ash_output"
        _manifest(output / "converted" / "dep", "copied-dep")

        listed = package_manager_inputs("yarn", package, skip=[output])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "yarn.lock",
        ]


class TestLinkedDirectories:
    def test_members_below_a_linked_directory_inside_the_tree_are_listed(
        self, tmp_path
    ):
        """``packages/shared`` links to a sibling directory inside the scanned
        tree, which holds members of its own below it."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared, "shared")
        _manifest(shared / "nested" / "deep", "deep")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "shared", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/shared/nested/deep/package.json",
            "packages/shared/package.json",
            "yarn.lock",
        ]
        assert refused_inputs("yarn", package, roots=[repo]) == []

    def test_a_linked_directory_leaving_the_tree_is_refused_and_not_walked(
        self, tmp_path
    ):
        """Only the linked directory's own manifest is listed, and it is refused,
        so nothing below the link is read from outside the tree."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        outside = tmp_path / "outside"
        _manifest(outside, "outside")
        _manifest(outside / "nested", "nested-outside")
        (package / "packages").mkdir()
        os.symlink(outside, package / "packages" / "vendored", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])
        refused = refused_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/vendored/package.json",
            "yarn.lock",
        ]
        assert [(p.relative_to(package).as_posix(), why) for p, why in refused] == [
            ("packages/vendored/package.json", LINK_LEAVES_TREE)
        ]

    def test_a_link_back_into_the_walked_tree_ends(self, tmp_path):
        """A link to an ancestor would walk forever; each real directory is
        walked once, so every manifest is listed once."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "api", "api")
        os.symlink(package, package / "packages" / "loop", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "yarn.lock",
        ]

    def test_without_roots_a_linked_directory_is_not_walked(self, tmp_path):
        """A caller that names no roots gets the earlier shape: the linked
        directory's own manifest and nothing below it."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared, "shared")
        _manifest(shared / "nested", "nested")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "shared", target_is_directory=True)

        listed = package_manager_inputs("yarn", package)

        assert _rel(listed, package) == [
            "package.json",
            "packages/shared/package.json",
            "yarn.lock",
        ]

    def test_the_copy_holds_the_members_below_a_linked_directory(self, tmp_path):
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared, "shared")
        _manifest(shared / "nested", "nested")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "shared", target_is_directory=True)
        parent = tmp_path / "out"
        parent.mkdir()

        with package_manager_child(
            "yarn", package, parent=parent, scan_root=repo, yarn_major=1
        ) as child:
            copied = sorted(
                p.relative_to(child.cwd).as_posix()
                for p in child.cwd.rglob("*")
                if p.is_file()
            )

        assert copied == [
            "package.json",
            "packages/shared/nested/package.json",
            "packages/shared/package.json",
            "yarn.lock",
        ]
