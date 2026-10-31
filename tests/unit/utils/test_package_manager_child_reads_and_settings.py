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
            "auditConfig": AUDIT_CONFIG,
            "packages": ["."],
        }

    def test_nothing_crosses_under_ignore_suppressions(self, tmp_path):
        """``auditConfig`` is a suppression, so the flag drops it; the copy keeps
        a workspace file of its own with the package alone."""
        package = self._workspace(
            tmp_path, yaml.safe_dump({"auditConfig": AUDIT_CONFIG})
        )

        copied = _copy("pnpm", package, tmp_path, ignore_suppressions=True)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {"packages": ["."]}

    def test_a_file_without_the_key_gives_the_default_file(self, tmp_path):
        """Control: the settings-only file the module distrusts stays out, and
        the copy holds the default one in its place."""
        package = self._workspace(
            tmp_path, 'packages: []\nregistry: "https://registry.example/"\n'
        )

        copied = _copy("pnpm", package, tmp_path)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {"packages": ["."]}
        assert b"registry.example" not in copied["pnpm-workspace.yaml"]
        assert set(copied) == {"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"}

    def test_a_repository_without_a_workspace_file_gets_one_in_the_copy(self, tmp_path):
        """pnpm 10 walks up from the copy to the nearest workspace root and
        reads its ``.npmrc``; the copy sits below the output directory, inside
        the scanned tree by default, so with no file of its own its root was
        the repository's and the audit went to the registry that repository
        names. The copy is its own workspace root whatever the repository
        holds (pnpm 10.34.9 made two requests to the repository's registry
        without it; pnpm 12.17.0 made none)."""
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        assert not (package / "pnpm-workspace.yaml").exists()

        copied = _copy("pnpm", package, tmp_path)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {"packages": ["."]}
        assert set(copied) == {"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"}

    def test_a_refused_workspace_file_still_leaves_the_copy_a_default_one(
        self, tmp_path
    ):
        """A workspace file the scanner refuses (a link out of the tree) is
        skipped by the copy, which then holds the default file, not none."""
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        outside = tmp_path / "elsewhere" / "pnpm-workspace.yaml"
        outside.parent.mkdir()
        outside.write_text(
            'registry: "https://registry.example/"\nauditConfig: {}\n', encoding="utf-8"
        )
        os.symlink(outside, package / "pnpm-workspace.yaml")

        copied = _copy("pnpm", package, tmp_path)

        assert yaml.safe_load(copied["pnpm-workspace.yaml"]) == {"packages": ["."]}
        assert b"registry.example" not in copied["pnpm-workspace.yaml"]

    @pytest.mark.parametrize(
        ("binary", "lockfile"),
        [("npm", "package-lock.json"), ("yarn", "yarn.lock")],
    )
    def test_npm_and_yarn_copies_get_no_workspace_file(
        self, tmp_path, binary, lockfile
    ):
        """Control: the file is pnpm's; the other two copies are unchanged."""
        package = _package(tmp_path / "repo" / "web", lockfile)

        copied = _copy(binary, package, tmp_path, yarn_major=1)

        assert "pnpm-workspace.yaml" not in copied

    def test_the_workspace_file_is_an_input_of_pnpm(self, tmp_path):
        """A linked one that leaves the tree refuses the package like any input."""
        package = _package(tmp_path / "repo" / "web", "pnpm-lock.yaml")
        outside = tmp_path / "elsewhere" / "pnpm-workspace.yaml"
        outside.parent.mkdir()
        outside.write_text("auditConfig: {}\n", encoding="utf-8")
        os.symlink(outside, package / "pnpm-workspace.yaml")

        refused = refused_inputs("pnpm", package, roots=[tmp_path / "repo"])

        assert refused == [(package / "pnpm-workspace.yaml", LINK_LEAVES_TREE)]


class TestAnInputSwappedAroundItsOpen:
    """The lockfile is a regular file in the tree when the scanner checks it and
    its name points at a file outside the tree a moment later. The copy judges
    the OPEN file, not the name, so the outside file's content never reaches it
    whichever side of the open the swap lands on. (The name check ran inside the
    read before the copy judged the descriptor; a hook on that check no longer
    sees the read on a platform that names open files, so the swap is made from
    the open itself and from the descriptor judgement.)"""

    def _package_and_outside(self, tmp_path):
        package = _package(tmp_path / "repo" / "web", "package-lock.json")
        outside = tmp_path / "elsewhere" / "package-lock.json"
        outside.parent.mkdir()
        outside.write_text(MARKER, encoding="utf-8")
        return package, package / "package-lock.json", outside

    def test_swapped_for_an_outside_link_before_its_open_is_left_out(
        self, tmp_path, monkeypatch
    ):
        """The open follows the new link to the outside file, which is judged by
        where it IS: outside every root, so it is not copied and the lockfile's
        name is absent from the copy."""
        package, lockfile, outside = self._package_and_outside(tmp_path)
        real_open = os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if not swapped and os.fspath(path) == str(lockfile):
                lockfile.unlink()
                os.symlink(outside, lockfile)
                swapped.append(path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", swap_then_open)

        copied = _copy("npm", package, tmp_path)

        assert swapped, "the lockfile was never opened, so the swap was not exercised"
        assert all(MARKER.encode() not in data for data in copied.values()), copied
        assert "package-lock.json" not in copied

    @pytest.mark.skipif(
        not os.path.islink("/proc/self/fd/0"), reason="no descriptor paths here"
    )
    def test_moved_aside_after_its_open_is_read_as_the_file_that_was_opened(
        self, tmp_path, monkeypatch
    ):
        """Between the open and the judgement the regular file is renamed within
        the tree and its old name becomes a link to the outside file. The
        descriptor still names the regular file, inside the tree, so its own
        bytes are copied under the lockfile's name; the outside file is never
        read."""
        package, lockfile, outside = self._package_and_outside(tmp_path)
        identity = (lockfile.stat().st_dev, lockfile.stat().st_ino)
        real_within = package_manager_child._descriptor_within
        swapped = []

        def swap_then_judge(fd, roots):
            opened = os.fstat(fd)
            if not swapped and (opened.st_dev, opened.st_ino) == identity:
                lockfile.rename(lockfile.with_name("package-lock.json.moved"))
                os.symlink(outside, lockfile)
                swapped.append(fd)
            return real_within(fd, roots)

        monkeypatch.setattr(
            package_manager_child, "_descriptor_within", swap_then_judge
        )

        copied = _copy("npm", package, tmp_path)

        assert swapped, "the lockfile was never judged, so the swap was not exercised"
        assert copied["package-lock.json"] == b"{}\n"
        assert all(MARKER.encode() not in data for data in copied.values()), copied


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
