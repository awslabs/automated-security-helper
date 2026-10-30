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
    """json.loads refuses it with RecursionError; V8's parser does not."""

    def _nested(self, tmp_path: Path, **keys) -> Path:
        depth = 50_000
        body = json.dumps({"name": "deep", **keys})[1:-1].encode()
        nested = b"{" + body + b', "a": ' + b"[" * depth + b"]" * depth + b"}"
        return _package(tmp_path / "repo" / "deep", "package-lock.json", nested)

    def test_is_handed_to_the_tool_as_it_is_without_the_flag(self, tmp_path):
        """Control: with suppressions in force the copy keeps the bytes."""
        package = self._nested(tmp_path)

        copied = _copy("npm", package, tmp_path, ignore_suppressions=False)

        assert copied["package.json"] == (package / "package.json").read_bytes()

    def test_is_refused_under_ignore_suppressions(self, tmp_path):
        """The copy kept the bytes, ``pnpm.auditConfig`` included, so the tool
        parsed what this interpreter could not and applied the repository's
        ignore lists under the flag that lifts them. The package is refused
        with the reason; the scan loop records it."""
        package = self._nested(tmp_path, pnpm={"auditConfig": AUDIT_CONFIG})

        with pytest.raises(
            package_manager_child.SuppressionsNotLiftable, match="auditConfig"
        ):
            _copy("npm", package, tmp_path, ignore_suppressions=True)


class TestAManifestWithAnInvalidByte:
    def test_loses_its_audit_config_under_the_flag(self, tmp_path):
        """Node decodes an invalid byte as U+FFFD and parses on, so the manifest
        is JSON to the tool; a strict decode refused it here and the copy kept
        the ignore lists. It is decoded as Node decodes it, and the key goes."""
        manifest = (
            b'{"name": "odd\xff", "pnpm": {"auditConfig": '
            + json.dumps(AUDIT_CONFIG).encode()
            + b"}}"
        )
        package = _package(tmp_path / "repo" / "odd", "pnpm-lock.yaml", manifest)

        copied = _copy("pnpm", package, tmp_path, ignore_suppressions=True)

        written = json.loads(copied["package.json"])
        assert "auditConfig" not in written.get("pnpm", {})
        assert written["name"] == "odd�"


class TestAnUnreadableInput:
    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads any mode"
    )
    def test_is_a_raised_failure_not_a_silent_drop(self, tmp_path):
        """A mode-000 manifest passes the scanner's stat check, and the copy
        then lacked a file the tool reads in place, with nothing recorded. The
        open failure is raised with the file named, for the scan loop to record
        as the audit's failure."""
        package = _package(tmp_path / "repo" / "quiet", "package-lock.json")
        (package / "package.json").chmod(0)
        try:
            with pytest.raises(
                package_manager_child.InputUnreadable, match="quiet/package.json"
            ):
                _copy("npm", package, tmp_path)
        finally:
            (package / "package.json").chmod(0o644)


class TestTheOpenedFileIsJudged:
    @pytest.mark.skipif(
        not os.path.islink("/proc/self/fd/0"), reason="no descriptor paths here"
    )
    def test_by_the_descriptors_own_path_where_the_platform_names_one(self, tmp_path):
        """Linux names an open file at /proc/self/fd/N as it is NOW, so the
        place is read from the open file, not from a name that can be moved
        between the open and the check."""
        repo = tmp_path / "repo"
        inside = _package(repo / "app", "package-lock.json") / "package.json"
        outside = tmp_path / "elsewhere" / "package.json"
        outside.parent.mkdir()
        outside.write_text("{}", encoding="utf-8")
        for path, expected in ((inside, True), (outside, False)):
            fd = os.open(path, os.O_RDONLY)
            try:
                assert package_manager_child._descriptor_within(fd, [repo]) is expected
            finally:
                os.close(fd)

    def test_answers_none_where_no_descriptor_path_exists(self, monkeypatch):
        """Elsewhere the name, tied to the open file by identity, is judged."""
        monkeypatch.setattr(os.path, "islink", lambda p: False)

        assert package_manager_child._descriptor_within(0, []) is None


class TestPnpmWorkspaceSettings:
    def _workspace(self, tmp_path: Path, text: str) -> Path:
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        (package / "pnpm-workspace.yaml").write_text(text, encoding="utf-8")
        return package

    def test_the_audit_config_and_the_member_globs_cross_and_nothing_else_does(
        self, tmp_path
    ):
        """``packages`` rides along with ``auditConfig``: the member globs name
        no registry or path outside the package, and a workspace file without
        them is one some pnpm releases refuse as an invalid workspace
        configuration, so the cut-down copy failed an audit that ran with no
        file. The registry, a setting the repository may not set, stays out."""
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
            "packages": ["packages/*"],
            "auditConfig": AUDIT_CONFIG,
        }
        assert b"registry.example" not in copied["pnpm-workspace.yaml"]

    def test_a_packages_value_that_is_not_a_list_of_globs_stays_out(self, tmp_path):
        """Control: only the list-of-strings shape pnpm defines crosses; a
        mapping or a list with other members is not the member globs."""
        package = self._workspace(
            tmp_path,
            yaml.safe_dump(
                {"packages": {"glob": "packages/*"}, "auditConfig": AUDIT_CONFIG}
            ),
        )

        copied = _copy("pnpm", package, tmp_path)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {
            "auditConfig": AUDIT_CONFIG
        }

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


class TestTheReadWhereThePlatformHasNoNonblockingOpen:
    """Windows has no ``O_NONBLOCK``, and its ``os.set_blocking`` (3.12 and
    later) accepts pipes only: on a file handle it raises
    ERROR_INVALID_PARAMETER, which every lockfile's audit then reported as
    ``the audit raised OSError: [WinError 87]``. The read clears only a flag it
    set. Both tests shape ``os`` the way that platform has it; the file itself
    runs on POSIX."""

    def test_a_plain_open_is_read_without_touching_the_blocking_mode(
        self, tmp_path, monkeypatch
    ):
        package = _package(tmp_path / "repo" / "web", "package-lock.json")
        monkeypatch.delattr(os, "O_NONBLOCK", raising=False)

        def refuse_a_file_handle(fd, blocking):
            raise OSError(22, "The parameter is incorrect")

        monkeypatch.setattr(os, "set_blocking", refuse_a_file_handle)

        data = package_manager_child._read_admitted(
            package / "package-lock.json", [tmp_path / "repo"]
        )

        assert data == b"{}\n"

    @pytest.mark.skipif(
        not hasattr(os, "O_NONBLOCK"), reason="no nonblocking open on this platform"
    )
    def test_the_control_a_nonblocking_open_is_made_blocking_before_the_read(
        self, tmp_path, monkeypatch
    ):
        package = _package(tmp_path / "repo" / "web", "package-lock.json")
        real_set_blocking = os.set_blocking
        calls = []

        def record(fd, blocking):
            calls.append(blocking)
            real_set_blocking(fd, blocking)

        monkeypatch.setattr(os, "set_blocking", record)

        data = package_manager_child._read_admitted(
            package / "package-lock.json", [tmp_path / "repo"]
        )

        assert data == b"{}\n"
        assert calls == [True]


class TestTheReadOpensInBinaryMode:
    def test_the_open_carries_o_binary_where_the_platform_has_it(
        self, tmp_path, monkeypatch
    ):
        """os.open adds no O_BINARY of its own, and on Windows a descriptor in
        the C runtime's text mode turns CRLF into LF and reads Ctrl-Z as the end
        of the file, so the bytes handed to the tool were not the file's.
        O_BINARY is absent on POSIX, so a spare bit stands in for it here and is
        taken off again before the real open."""
        package = _package(tmp_path / "repo" / "web", "package-lock.json")
        stand_in = 1 << 30
        monkeypatch.setattr(os, "O_BINARY", stand_in, raising=False)
        seen = []
        real_open = os.open

        def recording_open(path, flags, *args, **kwargs):
            seen.append(flags)
            return real_open(path, flags & ~stand_in, *args, **kwargs)

        monkeypatch.setattr(os, "open", recording_open)

        data = package_manager_child._read_admitted(
            package / "package-lock.json", [tmp_path / "repo"]
        )

        assert data == b"{}\n"
        assert seen and all(flags & stand_in for flags in seen), [hex(f) for f in seen]


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
