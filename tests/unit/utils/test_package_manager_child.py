# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The files utils/package_manager_child.py hands a package manager, and the copy.

Two groups of tests. ``TestWhereYarnsCopyGoes`` reads where yarn's unsandboxed
copy is placed and why each candidate (the output directory, the operator's
cache directory, the runtime directory) is passed over: the scanned tree, the
system temporary directory, an ancestor another account can write, an ancestor
holding a settings file, a directory that cannot be made; with the real checks
and with them stood down. The rest reads the inputs the module lists and copies
(the byte order mark, the skip that holds the package, links of every shape:
inside the tree, out of it, back into it, into ``node_modules``, aliases). The
shapes the module first missed:

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
import stat
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.utils import package_manager_child as child_module
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


def _settings_holder_above(path: Path, monkeypatch):
    """The nearest directory above ``path`` holding a yarn settings file, with the
    operator's real home counted.

    ``_settings_file_ancestor`` leaves the operator's home out (the files there
    are the operator's own, and yarn reads them wherever it runs). A test that
    then fakes ``Path.home`` stops leaving the REAL home out, so a ``.npmrc`` or
    ``.yarnrc`` in the real home above the run's temporary root passes every
    candidate over and fails those tests for a reason none of them is about.
    The guard that decides whether such a test can run therefore asks with the
    home pointed at a directory that is no ancestor of ``path``.
    """
    with monkeypatch.context() as scope:
        scope.setattr(Path, "home", classmethod(lambda cls: path / "no-home"))
        return child_module._settings_file_ancestor(path)


@pytest.fixture
def trusted_copy_dirs(monkeypatch, tmp_path):
    """Stand down the two shared-directory checks on yarn's copy placement.

    tmp_path, and the HOME the run gives each test, sit under the system
    temporary directory, whose ancestors every account can write, so the
    placement would pass over every directory a test offers it. A test about
    where the copy goes for another reason uses this; the checks themselves are
    read in ``TestWhereYarnsCopyGoes`` without it.
    """
    # The settings-file check stays real for the tests that read it; a
    # settings file above the run's temporary root (a checkout holding
    # .npmrc with --basetemp inside it, a TMPDIR under a home with .yarnrc)
    # would pass every candidate over for a reason no test here is about, so
    # the run says so instead of failing those tests. The real home counts
    # here (``_settings_holder_above``), since the tests that fake the home
    # would otherwise see its files as the repository's.
    holder = _settings_holder_above(tmp_path, monkeypatch)
    if holder is not None:
        pytest.skip(
            f"{holder[1]} in {holder[0]}, above the test's temporary root, would "
            "disqualify every copy directory offered here"
        )
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(system_tmp))
    monkeypatch.setattr(child_module, "_untrusted_ancestor", lambda path: None)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    return system_tmp


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


class TestAnUnparsableManifestBelowAYarnPackage:
    def test_it_is_copied_as_it_is_under_ignore_suppressions(
        self, tmp_path, trusted_copy_dirs
    ):
        """yarn's copy holds every ``package.json`` below the package, and a
        parser's broken-input fixture or a template with ``{{deps}}`` is among
        them. Under ``--ignore-suppressions`` one such file failed the whole
        package's audit, with a message about ``pnpm.auditConfig``, a key yarn
        never reads. The bytes are copied as they were."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        broken = package / "packages" / "parser" / "fixtures" / "broken"
        broken.mkdir(parents=True)
        raw = b"{{deps}}\n"
        (broken / "package.json").write_bytes(raw)
        parent = tmp_path / "out"
        parent.mkdir()

        with package_manager_child(
            "yarn",
            package,
            parent=parent,
            scan_root=repo,
            yarn_major=1,
            ignore_suppressions=True,
        ) as child:
            copied = (
                child.cwd / "packages/parser/fixtures/broken/package.json"
            ).read_bytes()

        assert child.cwd != package
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


class TestWhereYarnsCopyGoes:
    def test_with_no_scan_root_the_copy_leaves_the_package(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """A caller that passes only ``parent`` (a results directory under the
        package) and no scan_root got the copy under the package, where yarn
        read the package's own .npmrc and .yarnrc as parent-directory files.
        The package directory is the tree the copy has to leave, as it is the
        root the copied files have to resolve inside."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        parent = package / ".ash" / "ash_output" / "scanners" / "npm-audit"
        parent.mkdir(parents=True)
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))

        with package_manager_child(
            "yarn", package, parent=parent, yarn_major=1
        ) as child:
            cwd = child.cwd

        assert not cwd.is_relative_to(package), cwd
        assert cwd.is_relative_to(cache_home / "ash"), cwd
        assert child.leading_args == ()

    def test_a_candidate_under_the_system_temporary_directory_is_passed_over(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """``--output-dir /tmp/ash-out`` is outside the scanned tree and was
        taken, which put ``/tmp``, writable by every account, back among yarn's
        parent directories. The operator's cache directory is used instead."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        parent = trusted_copy_dirs / "ash-out"
        parent.mkdir()
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))

        with package_manager_child(
            "yarn", package, parent=parent, scan_root=repo, yarn_major=1
        ) as child:
            cwd = child.cwd

        assert not cwd.is_relative_to(trusted_copy_dirs), cwd
        assert cwd.is_relative_to(cache_home / "ash"), cwd
        # The reason, read at the placement itself: a rejection for any other
        # cause would have placed the copy the same way.
        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)
        assert chosen == cache_home / "ash", (chosen, passed_over)
        assert len(passed_over) == 1, passed_over
        assert "system temporary directory" in passed_over[0], passed_over

    @pytest.mark.parametrize(
        "variable", ["XDG_CACHE_HOME", "XDG_RUNTIME_DIR"], ids=["cache", "runtime"]
    )
    def test_a_cache_or_runtime_directory_under_the_system_temporary_directory_is_passed_over(
        self, tmp_path, monkeypatch, trusted_copy_dirs, variable
    ):
        """``HOME=/tmp`` (containers with arbitrary UIDs) and
        ``XDG_RUNTIME_DIR=/tmp/runtime-$USER`` (a fallback some tools set) put
        the cache or the runtime directory under /tmp, which every account can
        write: a planted /tmp/.npmrc would be back on yarn's path. Only the
        output directory was ever checked by a test; the other two candidates
        are held to the same check, and the reason names it."""
        repo = tmp_path / "repo"
        _yarn_package(repo)
        parent = repo / ".ash" / "ash_output"
        parent.mkdir(parents=True)
        under_tmp = trusted_copy_dirs / "runtime-me"
        under_tmp.mkdir()
        monkeypatch.setenv("XDG_CACHE_HOME", str(repo / ".cache-inside"))
        monkeypatch.setenv(variable, str(under_tmp))

        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)

        assert chosen is None, (chosen, passed_over)
        assert any(
            str(under_tmp) in reason and "system temporary directory" in reason
            for reason in passed_over
        ), passed_over

    def test_a_candidate_below_a_directory_another_account_can_write_is_passed_over(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """An output directory inside a larger checkout above the scanned tree
        (``--source-dir mono/sub --output-dir mono/out``) puts that checkout's
        .npmrc and .yarnrc on yarn's path. The ancestor check names such a
        directory; here it names the output directory's parent, and the cache
        directory is used instead."""
        repo = tmp_path / "mono" / "sub"
        _yarn_package(repo)
        parent = tmp_path / "mono" / "out"
        parent.mkdir()
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
        monkeypatch.setattr(
            child_module,
            "_untrusted_ancestor",
            lambda path: tmp_path / "mono" if path == parent else None,
        )

        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)

        assert chosen == cache_home / "ash", (chosen, passed_over)
        assert len(passed_over) == 1 and str(tmp_path / "mono") in passed_over[0]

    def test_a_candidate_below_a_directory_holding_a_settings_file_is_passed_over(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """``--source-dir ./src --output-dir ./ash-out`` inside a checkout the
        operator owns: every ancestor passes the ownership check, and the
        checkout's root holds the repository's own .npmrc, which yarn would read
        from the copy below it. The settings-file check names that directory
        and the file; the cache directory is used instead."""
        checkout = tmp_path / "checkout"
        repo = checkout / "src"
        _yarn_package(repo)
        parent = checkout / "ash-out"
        parent.mkdir()
        (checkout / ".npmrc").write_text(
            "registry=https://registry.example/\n", encoding="utf-8"
        )
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))

        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)

        assert chosen == cache_home / "ash", (chosen, passed_over)
        assert len(passed_over) == 1, passed_over
        assert str(checkout) in passed_over[0] and ".npmrc" in passed_over[0]

    def test_the_operators_own_settings_file_does_not_disqualify_the_home(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """Control: ~/.npmrc is the operator's and yarn reads it wherever it
        runs, so the cache directory below the home is still taken."""
        home = tmp_path / "home"
        (home / ".cache").mkdir(parents=True)
        (home / ".npmrc").write_text("registry=https://mine.example/\n")
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
        repo = tmp_path / "repo"
        _yarn_package(repo)
        parent = repo / "out"

        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)

        assert chosen == home / ".cache" / "ash", (chosen, passed_over)

    def test_the_fixture_guard_counts_the_operators_real_home(
        self, tmp_path, monkeypatch
    ):
        """The home holds ``.npmrc`` and the run's temporary root sits below it
        (a TMPDIR under a home, as on a developer's machine): the guard names
        the home, where ``_settings_file_ancestor`` alone, with that home as
        ``Path.home``, leaves it out and finds nothing nearer."""
        home = tmp_path / "me"
        start = home / "scratch" / "run"
        start.mkdir(parents=True)
        (home / ".npmrc").write_text("registry=https://mine.example/\n")
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

        assert _settings_holder_above(start, monkeypatch) == (home, ".npmrc")
        assert Path.home() == home, "the guard left the faked home in place"

    @pytest.mark.parametrize("home_through_the_link", [True, False])
    def test_a_home_spelled_through_a_link_is_still_the_home(
        self, tmp_path, monkeypatch, home_through_the_link, trusted_copy_dirs
    ):
        """``/home`` linking to ``/local/home`` is a common layout: ``HOME``
        carries one spelling and the cache path under it may carry the other.
        A string compare of the two spellings missed the home, so the
        operator's own ~/.npmrc disqualified the cache directory below it. The
        home is matched by real path, whichever side carries the link."""
        real_home = tmp_path / "local" / "home" / "me"
        real_home.mkdir(parents=True)
        (tmp_path / "home").symlink_to(tmp_path / "local" / "home")
        link_home = tmp_path / "home" / "me"
        (real_home / ".npmrc").write_text(
            "registry=https://mine.example/\n", encoding="utf-8"
        )
        home, cache = (
            (link_home, real_home) if home_through_the_link else (real_home, link_home)
        )
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

        assert (
            child_module._settings_file_ancestor(cache / ".cache" / "ash" / "copies")
            is None
        )

    def test_the_settings_file_check_names_the_nearest_holder(self, tmp_path):
        """Read with the real check: the nearest directory above the candidate
        that holds one of the three files is named, with the file."""
        outer = tmp_path / "outer"
        inner = outer / "inner"
        inner.mkdir(parents=True)
        (outer / ".yarnrc").write_text("", encoding="utf-8")
        (inner / ".yarnrc.yml").write_text("", encoding="utf-8")

        assert child_module._settings_file_ancestor(inner / "ash" / "copies") == (
            inner,
            ".yarnrc.yml",
        )

    @pytest.mark.parametrize(
        "mode",
        [0o777, 0o1777, 0o775],
        ids=["world-writable", "sticky-world-writable", "group-writable"],
    )
    def test_the_ancestor_check_names_a_directory_another_account_can_write(
        self, tmp_path, mode
    ):
        """Read with the real check: a directory any account (or the group) can
        write, planted above the candidate, is named; the nearest such
        directory is returned, which is why the planted one is found before
        ``/tmp`` is. The sticky bit changes nothing: ``/tmp`` itself is 1777,
        and sticky stops no one from planting a NEW file beside the copy, so a
        "sticky is safe" rule would pass exactly the directory the check is
        for. Group-writable counts too: another account in the group writes
        there."""
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(mode)
        candidate = shared / "ash" / "copies"

        assert child_module._untrusted_ancestor(candidate) == shared

    def test_the_ancestor_check_passes_an_owner_only_chain_up_to_the_temp_root(
        self, tmp_path
    ):
        """Control: a 0700 chain below tmp_path names nothing of its own; what
        the check returns, if anything, lies at or above tmp_path (the run's
        temporary root), never inside the chain."""
        own = tmp_path / "own" / "ash"
        own.mkdir(parents=True)
        (tmp_path / "own").chmod(0o700)
        own.chmod(0o700)

        named = child_module._untrusted_ancestor(own / "copies")

        assert named is None or not named.is_relative_to(tmp_path / "own"), named
        if named is not None:
            mode = os.stat(named).st_mode
            assert mode & (stat.S_IWGRP | stat.S_IWOTH) or os.stat(
                named
            ).st_uid not in (os.getuid(), 0)

    def test_the_ancestor_check_walks_the_real_path_of_a_linked_cache(self, tmp_path):
        """``~/.cache -> /scratch/me/cache`` with ``/scratch`` at 1777: yarn's
        working directory is the resolved path, so it reads ``/scratch/.npmrc``,
        which any account can write. A walk of the path as written judged the
        home's ancestors and passed; the walk of the real path names the shared
        directory."""
        scratch = tmp_path / "scratch"
        cache = scratch / "me" / "cache"
        cache.mkdir(parents=True)
        scratch.chmod(0o1777)
        home = tmp_path / "home"
        home.mkdir()
        (home / ".cache").symlink_to(cache, target_is_directory=True)

        named = child_module._untrusted_ancestor(home / ".cache" / "ash" / "copies")

        assert named == scratch, named

    def test_the_settings_file_check_walks_the_real_path_of_a_linked_cache(
        self, tmp_path, monkeypatch
    ):
        """The same layout with ``/scratch/.npmrc`` planted: the settings-file
        check names the target's parent and the file, where a walk of the path
        as written saw only the home's ancestors."""
        scratch = tmp_path / "scratch"
        cache = scratch / "me" / "cache"
        cache.mkdir(parents=True)
        (scratch / ".npmrc").write_text(
            "registry=https://planted.example/\n", encoding="utf-8"
        )
        home = tmp_path / "home"
        home.mkdir()
        (home / ".cache").symlink_to(cache, target_is_directory=True)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

        assert child_module._settings_file_ancestor(
            home / ".cache" / "ash" / "copies"
        ) == (scratch, ".npmrc")

    def test_the_cache_directory_is_made_owner_only_whatever_the_umask(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """Under umask 002 ``Path.mkdir`` made ``~/.cache/ash`` group-writable:
        the first run copied below a directory the check had never seen, and
        the next run's check named it and fell to in-place yarn. Each missing
        part is made with mode 0700."""
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
        repo = tmp_path / "repo"
        _yarn_package(repo)
        previous = os.umask(0o002)
        try:
            chosen, passed_over = child_module._yarn_copy_parent(repo / "out", repo)
        finally:
            os.umask(previous)

        assert chosen == cache_home / "ash", (chosen, passed_over)
        assert stat.S_IMODE(os.stat(cache_home / "ash").st_mode) == 0o700
        assert stat.S_IMODE(os.stat(cache_home).st_mode) == 0o700

    def test_a_directory_that_fails_the_check_once_made_is_passed_over(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """The ancestor check runs on the nearest EXISTING directory before the
        candidate is made, and again on the candidate as made: a part that
        comes out shared (made meanwhile by another process, or found half-way
        with a lax mode) is named, and the candidate is passed over."""
        cache_home = tmp_path / "cache-home"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
        repo = tmp_path / "repo"
        _yarn_package(repo)
        monkeypatch.setattr(
            child_module,
            "_untrusted_ancestor",
            lambda path: path if path.exists() else None,
        )

        chosen, passed_over = child_module._yarn_copy_parent(repo / "out", repo)

        assert chosen is None, (chosen, passed_over)
        assert any(
            str(cache_home / "ash") in p and "another account" in p for p in passed_over
        ), passed_over

    def test_the_runtime_directory_holds_the_copy_when_the_home_cannot(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """A container with HOME unset or read-only has no usable cache
        directory, and the default output directory is inside the tree, so yarn
        fell to running in place and dropped the operator's settings. The
        user's runtime directory (``/run/user/<uid>``, 0700, root-owned
        ancestors) is the third candidate."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        parent = repo / ".ash" / "ash_output"
        parent.mkdir(parents=True)
        monkeypatch.setenv("XDG_CACHE_HOME", str(repo / ".cache-inside"))
        runtime = tmp_path / "run" / "user" / "1000"
        runtime.mkdir(parents=True)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

        with package_manager_child(
            "yarn", package, parent=parent, scan_root=repo, yarn_major=1
        ) as child:
            cwd, leading = child.cwd, child.leading_args

        assert cwd.is_relative_to(runtime / "ash"), cwd
        assert leading == ()

    def test_a_home_that_cannot_be_found_falls_to_the_runtime_directory(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """HOME unset with no passwd entry (arbitrary UIDs in a container):
        ``Path.home`` raises, so there is no cache directory to try, and the
        runtime directory is chosen with the cache named as not known. The
        raise never reaches the scan."""
        repo = tmp_path / "repo"
        _yarn_package(repo)
        parent = repo / ".ash" / "ash_output"
        parent.mkdir(parents=True)
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)

        def no_home(cls):
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.setattr(Path, "home", classmethod(no_home))
        runtime = tmp_path / "run" / "user" / "1000"
        runtime.mkdir(parents=True)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

        chosen, passed_over = child_module._yarn_copy_parent(parent, repo)

        assert chosen == runtime / "ash", (chosen, passed_over)
        assert any("cache directory is not known" in p for p in passed_over), (
            passed_over
        )

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes any mode"
    )
    def test_a_cache_directory_that_cannot_be_made_falls_to_the_runtime_directory(
        self, tmp_path, monkeypatch, trusted_copy_dirs
    ):
        """A read-only cache home (0500): making ``ash`` below it raises
        PermissionError, which is a reason to pass the candidate over, not a
        failure of the scan; the runtime directory is chosen."""
        repo = tmp_path / "repo"
        _yarn_package(repo)
        parent = repo / ".ash" / "ash_output"
        parent.mkdir(parents=True)
        cache_home = tmp_path / "cache-home"
        cache_home.mkdir()
        cache_home.chmod(0o500)
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
        runtime = tmp_path / "run" / "user" / "1000"
        runtime.mkdir(parents=True)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        try:
            chosen, passed_over = child_module._yarn_copy_parent(parent, repo)
        finally:
            cache_home.chmod(0o700)

        assert chosen == runtime / "ash", (chosen, passed_over)
        assert any(
            str(cache_home / "ash") in p and "cannot be made" in p for p in passed_over
        ), passed_over

    def test_a_relative_runtime_directory_is_ignored(self, monkeypatch):
        monkeypatch.setenv("XDG_RUNTIME_DIR", "run")
        assert child_module._runtime_dir() is None
        monkeypatch.delenv("XDG_RUNTIME_DIR")
        assert child_module._runtime_dir() is None

    def test_yarn_running_in_place_unsandboxed_is_logged(
        self, tmp_path, monkeypatch, trusted_copy_dirs, caplog
    ):
        """When no candidate will do, yarn runs in place with --no-default-rc,
        which drops ~/.npmrc (the operator's registry and credentials) with no
        way to add it back. Nothing recorded it; the warning names the package
        directory and why each candidate was passed over."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        parent = repo / ".ash" / "ash_output"
        parent.mkdir(parents=True)
        monkeypatch.setenv("XDG_CACHE_HOME", str(repo / ".cache-inside"))

        with caplog.at_level("WARNING"):
            with package_manager_child(
                "yarn", package, parent=parent, scan_root=repo, yarn_major=1
            ) as child:
                cwd, leading = child.cwd, child.leading_args

        assert cwd == package and leading == ("--no-default-rc",)
        assert "every settings file dropped" in caplog.text
        assert str(package) in caplog.text
        assert "inside the scanned tree" in caplog.text
        assert "runtime directory is not known" in caplog.text

    def test_a_copy_that_is_made_logs_no_warning(
        self, tmp_path, monkeypatch, trusted_copy_dirs, caplog
    ):
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        parent = tmp_path / "out"
        parent.mkdir()

        with caplog.at_level("WARNING"):
            with package_manager_child(
                "yarn", package, parent=parent, scan_root=repo, yarn_major=1
            ) as child:
                cwd = child.cwd

        assert cwd.is_relative_to(parent), cwd
        assert "settings file dropped" not in caplog.text

    def test_a_relative_xdg_cache_home_is_ignored(self, tmp_path, monkeypatch):
        """The specification and the tools that read it ignore a relative value,
        which would name a directory under whatever the current directory is.
        A leading ``~`` is expanded first, as the tools do."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))

        monkeypatch.setenv("XDG_CACHE_HOME", "rel-cache")
        assert child_module._operator_cache_dir() == home / ".cache" / "ash"
        monkeypatch.setenv("XDG_CACHE_HOME", "~/caches")
        assert child_module._operator_cache_dir() == home / "caches" / "ash"
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert child_module._operator_cache_dir() == tmp_path / "xdg" / "ash"


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

    def test_a_linked_directory_leaving_the_tree_is_refused_without_a_top_manifest(
        self, tmp_path
    ):
        """The outside tree holds members only deeper down (``/elsewhere/x``),
        so the link's own manifest does not exist. It was listed only when it
        existed, so nothing was listed and nothing refused, and in-place yarn
        expanded ``packages/**`` into the outside tree. The link's manifest is
        listed whether or not it exists; the refusal reads the link."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        outside = tmp_path / "outside"
        _manifest(outside / "x", "x-outside")
        (package / "packages").mkdir()
        os.symlink(outside, package / "packages" / "ext", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])
        refused = refused_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/ext/package.json",
            "yarn.lock",
        ]
        assert [(p.relative_to(package).as_posix(), why) for p, why in refused] == [
            ("packages/ext/package.json", LINK_LEAVES_TREE)
        ]

    def test_a_linked_directory_inside_the_tree_without_a_top_manifest_lists_its_members(
        self, tmp_path
    ):
        """``packages/inner -> ../../shared`` where ``shared`` holds members only
        deeper down (``shared/x/package.json``): the link resolves inside the
        tree, so it is walked like a directory, the member below it is listed
        under the link's name, and no manifest that does not exist is listed
        at the link's top (that is the out-of-tree shape, where the missing
        manifest stands in for the refusal). Nothing is refused."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared / "x", "x-inside")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "inner", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/inner/x/package.json",
            "yarn.lock",
        ]
        assert refused_inputs("yarn", package, roots=[repo]) == []

    def test_the_copy_holds_the_members_below_a_linked_directory_without_a_top_manifest(
        self, tmp_path, trusted_copy_dirs
    ):
        """The same layout through the copy: the member is copied at the
        link's path, and the copy neither fails on a manifest that does not
        exist nor drops the member."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared / "x", "x-inside")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "inner", target_is_directory=True)
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
            "packages/inner/x/package.json",
            "yarn.lock",
        ]

    def test_a_link_back_into_the_walked_tree_ends(self, tmp_path):
        """A link to an ancestor would walk forever; each real directory is
        walked once. The link's own manifest is still a file yarn reads at that
        path (``packages/loop/package.json`` is the root manifest to it), so it
        is listed under the link's name; nothing below it is walked again."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "api", "api")
        os.symlink(package, package / "packages" / "loop", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "packages/loop/package.json",
            "yarn.lock",
        ]

    def test_members_below_a_directory_first_reached_through_a_link_are_listed_at_their_real_path(
        self, tmp_path
    ):
        """With ``ui -> packages/ui`` the link is met first (os.walk hands the
        parent's linked directories to the walk before it descends the real
        ones), and a set of every walked real path then cut everything below
        the real ``packages/ui`` when os.walk reached it: ``packages/ui/plugins/x``
        was listed under the link's name only, and a workspace glob
        ``packages/ui/plugins/*`` found nothing in yarn's copy. A link into the
        package is not walked at all: the real directory is listed at its own
        path in full, and the link's name gets the manifests found below its
        target listed afterwards, with no second walk (the walk-count test
        below pins that). (The earlier cure walked the real directory a second
        time through the link; with two links per level that was 2^N walks, a
        bound the repository could remove.)"""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "ui", "ui")
        _manifest(package / "packages" / "ui" / "plugins" / "x", "x")
        os.symlink(
            package / "packages" / "ui", package / "ui", target_is_directory=True
        )

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/ui/package.json",
            "packages/ui/plugins/x/package.json",
            "ui/package.json",
            "ui/plugins/x/package.json",
            "yarn.lock",
        ]

    @pytest.mark.parametrize("inside_the_package", [True, False], ids=["in", "out"])
    def test_each_real_directory_is_walked_once_whatever_the_links_to_it(
        self, tmp_path, monkeypatch, inside_the_package
    ):
        """Twelve real directories, each holding two links to the next. A walk
        that re-entered a directory once per link chain made 2^12 walks here
        (and the listing ran twice per package); each real directory is walked
        once. With the chain inside the package no link is walked at all (the
        real directories are reached by os.walk); with the chain beside the
        package, inside the scanned tree, each real directory is entered once
        through the first link that reaches it. The walk's starts are counted
        through os.walk, which the walk calls once per directory it enters."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        base = package / "chain" if inside_the_package else repo / "chain"
        depth = 12
        levels = [base / f"d{i}" for i in range(depth + 1)]
        for level in levels:
            _manifest(level, level.name)
        for current, following in zip(levels, levels[1:]):
            os.symlink(following, current / "a", target_is_directory=True)
            os.symlink(following, current / "b", target_is_directory=True)
        os.symlink(levels[0], package / "entry", target_is_directory=True)
        starts: list[str] = []
        real_walk = os.walk

        def counting_walk(top, *args, **kwargs):
            starts.append(os.path.realpath(top))
            for root, dirs, files in real_walk(top, *args, **kwargs):
                # The filesystem's listing order decides which of the two
                # links is met first, and the deep-path assertion below needs
                # ``a`` met before ``b`` at every level. Sorted in place: it is
                # the list os.walk recurses through and the walk prunes, so
                # both still see the one list.
                dirs.sort()
                yield root, dirs, files

        monkeypatch.setattr(os, "walk", counting_walk)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert len(starts) == len(set(starts)), starts
        manifests = [p for p in _rel(listed, package) if p.endswith("package.json")]
        assert len(manifests) == len(set(manifests)), manifests
        if inside_the_package:
            # One walk, the package's. Listed: the root manifest, the 13 real
            # directories at their own paths, and the own manifest of every
            # link (entry, and a and b at each of the 12 levels that have them).
            assert len(starts) == 1, starts
            assert len(manifests) == 1 + (depth + 1) + 1 + 2 * depth, manifests
            assert "chain/d12/package.json" in manifests
            assert "entry/package.json" in manifests
        else:
            # The package's walk plus one per real directory (13), each entered
            # through the first link that reached it. Listed: the root
            # manifest, d0 under entry, and at each later level one walked
            # manifest (through a, met first by the sort above) and one alias
            # manifest (b's own).
            assert len(starts) == depth + 2, starts
            assert len(manifests) == 1 + 1 + 2 * depth, manifests
            assert "entry/" + "a/" * depth + "package.json" in manifests

    def test_a_package_reaching_too_many_linked_directories_is_refused(
        self, tmp_path, monkeypatch
    ):
        """The hard bound behind the once-per-directory rule: past the cap of
        distinct linked directories entered, the package is refused with the
        reason (the scan loop records it), not walked on. The cap is
        monkeypatched low; the fixture is a chain of five real directories
        beside the package, each reached through a link."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        levels = [repo / "chain" / f"d{i}" for i in range(5)]
        for level in levels:
            _manifest(level, level.name)
        for current, following in zip(levels, levels[1:]):
            os.symlink(following, current / "next", target_is_directory=True)
        os.symlink(levels[0], package / "entry", target_is_directory=True)
        monkeypatch.setattr(child_module, "_MAX_LINKED_DIRECTORY_WALKS", 3)

        with pytest.raises(
            child_module.TooManyLinkedDirectories, match="more than 3 linked"
        ):
            package_manager_inputs("yarn", package, roots=[repo])

        monkeypatch.setattr(child_module, "_MAX_LINKED_DIRECTORY_WALKS", 5)
        listed = package_manager_inputs("yarn", package, roots=[repo])
        assert "entry/next/next/next/next/package.json" in _rel(listed, package)

    def test_a_link_back_to_a_directory_being_walked_lists_its_manifest_only(
        self, tmp_path
    ):
        """``packages/ui/self -> packages/ui``: walking the link would walk the
        directory again under another name, without end. Its manifest is a file
        yarn reads at the link's path, so that is listed; nothing below it."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "ui", "ui")
        os.symlink(
            package / "packages" / "ui",
            package / "packages" / "ui" / "self",
            target_is_directory=True,
        )

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/ui/package.json",
            "packages/ui/self/package.json",
            "yarn.lock",
        ]

    def test_a_member_reached_first_through_a_link_is_still_listed(self, tmp_path):
        """A convenience link ``ui -> packages/ui`` is met before os.walk reaches
        the real ``packages/ui``, and the walk through the link marked the real
        directory as seen, so the member's manifest at its real path was dropped
        and yarn's copy had no ``packages/ui``: the workspace member it names
        went unaudited with no error. Both paths are listed."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "ui", "ui")
        os.symlink(
            package / "packages" / "ui", package / "ui", target_is_directory=True
        )

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/ui/package.json",
            "ui/package.json",
            "yarn.lock",
        ]

    def test_members_below_a_link_into_the_package_are_listed_under_the_links_name(
        self, tmp_path
    ):
        """``packages/foo -> ../libs/foo`` where ``libs/foo`` holds a member of its
        own (``plugins/x``). The link is not walked, so only its own manifest
        was listed under its name, and a member that yarn reaches through the
        link's path (a nested workspace glob ``plugins/*`` read from
        ``packages/foo``) was missing from yarn's copy and went unaudited. The
        members found below the target are listed under the link's name too."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "libs" / "foo", "foo", workspaces=["plugins/*"])
        _manifest(package / "libs" / "foo" / "plugins" / "x", "x")
        (package / "packages").mkdir()
        os.symlink("../libs/foo", package / "packages" / "foo")

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "libs/foo/package.json",
            "libs/foo/plugins/x/package.json",
            "package.json",
            "packages/foo/package.json",
            "packages/foo/plugins/x/package.json",
            "yarn.lock",
        ]
        assert refused_inputs("yarn", package, roots=[repo]) == []

    def test_members_below_a_linked_group_directory_are_listed_under_the_links_name(
        self, tmp_path
    ):
        """A glob such as ``packages/*/*`` reaches a member only through the
        linked group directory's path: ``libs/group/a`` is a member at
        ``packages/group/a``. The group directory holds no manifest of its own,
        so the link has none to list, and its member was the only thing to find."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "libs" / "group" / "a", "a")
        (package / "packages").mkdir()
        os.symlink("../libs/group", package / "packages" / "group")

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "libs/group/a/package.json",
            "package.json",
            "packages/group/a/package.json",
            "yarn.lock",
        ]

    def test_each_of_two_links_to_one_directory_beside_the_package_lists_its_members(
        self, tmp_path
    ):
        """Two links to ``shared`` beside the package: the first met is walked,
        and the other is not (a real directory is walked once), but its name gets
        the members of the walked one, whichever link os.walk meets first."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        shared = repo / "shared"
        _manifest(shared, "shared")
        _manifest(shared / "nested", "nested")
        (package / "packages").mkdir()
        os.symlink(shared, package / "packages" / "a", target_is_directory=True)
        os.symlink(shared, package / "packages" / "b", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/a/nested/package.json",
            "packages/a/package.json",
            "packages/b/nested/package.json",
            "packages/b/package.json",
            "yarn.lock",
        ]

    def test_the_copy_holds_the_members_below_a_link_into_the_package(
        self, tmp_path, trusted_copy_dirs
    ):
        """The copy yarn audits from has the member at the link's path."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "libs" / "foo", "foo", workspaces=["plugins/*"])
        _manifest(package / "libs" / "foo" / "plugins" / "x", "x")
        (package / "packages").mkdir()
        os.symlink("../libs/foo", package / "packages" / "foo")
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

        assert "packages/foo/plugins/x/package.json" in copied, copied
        assert "libs/foo/plugins/x/package.json" in copied, copied

    def test_the_manifests_listed_under_links_are_bounded(self, tmp_path, monkeypatch):
        """A link to a directory with many members would list every one of them
        again under the link's name; past the cap the package is refused with the
        reason, as for too many linked directories. The cap is monkeypatched low;
        the fixture is four members below one linked directory."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        for index in range(4):
            _manifest(package / "libs" / "foo" / f"m{index}", f"m{index}")
        (package / "packages").mkdir()
        os.symlink("../libs/foo", package / "packages" / "foo")
        monkeypatch.setattr(child_module, "_MAX_LINK_ALIAS_MANIFESTS", 3)

        with pytest.raises(
            child_module.TooManyLinkedDirectories, match="more than 3 manifests"
        ):
            package_manager_inputs("yarn", package, roots=[repo])

        monkeypatch.setattr(child_module, "_MAX_LINK_ALIAS_MANIFESTS", 4)
        listed = package_manager_inputs("yarn", package, roots=[repo])
        assert "packages/foo/m3/package.json" in _rel(listed, package)

    def test_a_sibling_alias_of_a_member_lists_both_paths(self, tmp_path):
        """``packages/ui-alias -> ui`` beside the real member: whichever os.walk
        meets first, both manifests are listed."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "ui", "ui")
        os.symlink("ui", package / "packages" / "ui-alias", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/ui-alias/package.json",
            "packages/ui/package.json",
            "yarn.lock",
        ]

    def test_a_link_into_node_modules_is_not_walked(self, tmp_path):
        """``node_modules`` itself is pruned by name; a link to it was walked in
        full, every installed package's manifest listed, refusal-checked and
        copied (three times per yarn package). The link's target decides."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "api", "api")
        _manifest(package / "node_modules" / "dep", "dep")
        _manifest(package / "node_modules" / "dep" / "node_modules" / "sub", "sub")
        os.symlink("node_modules", package / "deps", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "yarn.lock",
        ]

    def test_a_link_to_an_ancestor_lists_its_manifest_and_is_not_walked(self, tmp_path):
        """``packages/root -> ../..`` resolves to the scanned tree's root, above
        the package (``..`` alone would be the package itself, the loop case):
        walking it would walk the whole scanned tree, the package included,
        under the link's name. Its own manifest is a file yarn reads at that
        path, so it is listed; nothing below it is."""
        repo = tmp_path / "repo"
        _manifest(repo, "mono")
        _manifest(repo / "other", "other")
        package = _yarn_package(repo)
        _manifest(package / "packages" / "api", "api")
        (package / "packages").mkdir(exist_ok=True)
        os.symlink("../..", package / "packages" / "root", target_is_directory=True)

        listed = package_manager_inputs("yarn", package, roots=[repo])

        assert _rel(listed, package) == [
            "package.json",
            "packages/api/package.json",
            "packages/root/package.json",
            "yarn.lock",
        ]

    def test_the_copy_holds_a_member_reached_first_through_a_link(
        self, tmp_path, trusted_copy_dirs
    ):
        """The copy yarn audits from has the real member at its real path."""
        repo = tmp_path / "repo"
        package = _yarn_package(repo)
        _manifest(package / "packages" / "ui", "ui")
        os.symlink(
            package / "packages" / "ui", package / "ui", target_is_directory=True
        )
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

        assert child.cwd != package
        assert "packages/ui/package.json" in copied, copied

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

    def test_the_copy_holds_the_members_below_a_linked_directory(
        self, tmp_path, trusted_copy_dirs
    ):
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
