#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the MCP scan-target root policy.

The policy answers one question: may the MCP server accept this directory as a
scan target? It deliberately says nothing about whether the directory exists --
that stays with ``validate_directory_path`` -- so these tests exercise policy
decisions in isolation, including on paths that were never created.
"""

import os
import platform
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    _allowed_roots,
    _denied_root_values,
    _denied_roots,
    _is_filesystem_root,
    validate_scan_target,
)


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    """Every test starts from an unconfigured policy unless it says otherwise."""
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


# ---------------------------------------------------------------------------
# Default policy: no allowlist configured.
# ---------------------------------------------------------------------------


class TestDefaultPolicy:
    """With no allowlist set, a small fixed set of system directories is refused."""

    def test_ordinary_project_directory_is_accepted(self, tmp_path):
        """Positive control: the default policy must not refuse normal targets.

        This is the test that catches the single most dangerous way to get this
        wrong -- treating the filesystem root as a *containment* rule rather
        than an equality rule, which refuses every path on the system.
        """
        project = tmp_path / "myrepo"
        project.mkdir()

        assert validate_scan_target(project) is None

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX system paths")
    @pytest.mark.parametrize("denied", ["/etc", "/proc", "/root"])
    def test_named_system_directory_is_refused(self, denied):
        """A refused directory named directly is refused."""
        error = validate_scan_target(denied)

        assert error is not None
        assert error.context["error_category"] == "invalid_path"

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX system paths")
    def test_directory_inside_a_refused_root_is_refused(self):
        """Containment, not just equality: a child of a refused root is refused."""
        assert validate_scan_target("/etc/ssl") is not None

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX filesystem root")
    def test_filesystem_root_is_refused(self):
        """The filesystem root itself is refused, by equality."""
        assert validate_scan_target("/") is not None

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX system paths")
    def test_sibling_sharing_a_name_prefix_is_accepted(self):
        """A path whose *string* starts with a refused root is not inside it.

        ``/etcfoo`` is a sibling of ``/etc``, not a child. A ``startswith``
        implementation refuses it; a path-component implementation does not.
        This test is the discriminator between the two.
        """
        assert validate_scan_target("/etcfoo") is None

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX system paths")
    def test_traversal_into_a_refused_root_is_refused(self, tmp_path, monkeypatch):
        """A target that only reaches a refused root after resolution is refused.

        The caller-supplied string here is neither absolute nor obviously
        pointed at a system directory; it becomes one only once ``..``
        components are collapsed. This proves the policy resolves its input
        itself rather than trusting an already-canonical path.
        """
        monkeypatch.chdir(tmp_path)
        depth = len(tmp_path.resolve().parts) - 1
        traversal = os.path.join(*([".."] * depth), "etc")

        assert Path(traversal).resolve() == Path("/etc")
        assert validate_scan_target(traversal) is not None

    def test_nonexistent_path_is_still_judged_by_policy(self, tmp_path):
        """Policy is evaluated without regard to existence, in both directions.

        Existence is checked later, by ``validate_directory_path``. If the
        policy started rejecting or accepting on existence grounds, the order
        of the two checks would silently change meaning, so both branches are
        pinned here on paths that were never created.
        """
        missing_ok = tmp_path / "never-created"
        assert not missing_ok.exists()
        assert validate_scan_target(missing_ok) is None

        if platform.system() != "Windows":
            missing_denied = Path("/proc/never-created-either")
            assert not missing_denied.exists()
            assert validate_scan_target(missing_denied) is not None

    def test_error_message_names_the_variable_that_grants_access(self, tmp_path):
        """A refusal has to tell the operator how to allow the path."""
        if platform.system() == "Windows":
            pytest.skip("POSIX system paths")

        error = validate_scan_target("/etc")

        assert ASH_MCP_ALLOWED_ROOTS_ENV in str(error)


class TestDeniedRootSet:
    """The refused set is platform-specific; its contents are pinned here."""

    def test_posix_set(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        assert set(_denied_root_values()) == {
            "/boot",
            "/dev",
            "/etc",
            "/proc",
            "/root",
            "/sys",
        }

    def test_filesystem_root_is_not_in_the_containment_list(self, monkeypatch):
        """The root is handled by equality, and must not leak into containment.

        Every path is beneath ``/``. If the root ever appeared in the list that
        is tested with ``is_relative_to``, the policy would refuse the whole
        filesystem -- which the accepted-project test above would catch, but
        this states the invariant directly.
        """
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        assert Path("/") not in _denied_roots()

    def test_filesystem_root_predicate(self, tmp_path):
        assert _is_filesystem_root(Path("/"))
        assert not _is_filesystem_root(tmp_path)

    def test_refused_roots_are_resolved(self, tmp_path, monkeypatch):
        """A refused root that is itself a symlink still matches.

        This is macOS, where /etc, /tmp and /var are symlinks into /private. The
        target gets resolved before the comparison, so an unresolved "/etc"
        entry would be compared against a target that resolved to
        "/private/etc" and would never match -- the entry would name a
        directory it did not actually refuse. On Linux the same entries are not
        symlinks, so nothing here would fail on Linux without the symlink being
        constructed explicitly.
        """
        import automated_security_helper.cli.mcp.scan_target as scan_target

        real = tmp_path / "private" / "etc"
        real.mkdir(parents=True)
        link = tmp_path / "etc"
        link.symlink_to(real, target_is_directory=True)

        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(scan_target, "_POSIX_DENIED_ROOTS", (str(link),))

        assert _denied_roots() == [real]

    def test_symlinked_refused_root_is_refused_by_either_name(
        self, tmp_path, monkeypatch
    ):
        """The end-to-end form of the case above, through the public function.

        Both the symlink and its target have to be refused. Naming the target
        directly is the bypass that an unresolved root would leave open.
        """
        import automated_security_helper.cli.mcp.scan_target as scan_target

        real = tmp_path / "private" / "etc"
        (real / "ssl").mkdir(parents=True)
        link = tmp_path / "etc"
        link.symlink_to(real, target_is_directory=True)

        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(scan_target, "_POSIX_DENIED_ROOTS", (str(link),))

        assert validate_scan_target(link) is not None
        assert validate_scan_target(real) is not None
        assert validate_scan_target(real / "ssl") is not None
        assert validate_scan_target(tmp_path / "unrelated") is None

    def test_windows_set_is_derived_from_the_environment(self, monkeypatch):
        """On Windows the refused set follows the shell's own directory vars.

        Hardcoding ``C:\\Windows`` is wrong on a machine whose system drive is
        not C:. The comparison semantics on Windows are supplied by
        ``WindowsPath`` itself, which compares case-insensitively; what this
        test pins is the *contents* of the set.
        """
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setenv("SystemRoot", r"D:\Windows")
        monkeypatch.setenv("ProgramFiles", r"D:\Program Files")
        monkeypatch.setenv("ProgramData", r"D:\ProgramData")
        monkeypatch.delenv("ProgramFiles(x86)", raising=False)

        names = set(_denied_root_values())

        assert r"D:\Windows" in names
        assert r"D:\Program Files" in names
        assert r"D:\ProgramData" in names
        assert not any("C:" in n for n in names)

    def test_windows_set_falls_back_when_the_environment_is_bare(self, monkeypatch):
        """Without the shell variables, the conventional locations are used."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            monkeypatch.delenv(var, raising=False)

        names = set(_denied_root_values())

        assert names == {
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\ProgramData",
        }


# ---------------------------------------------------------------------------
# Configured allowlist.
# ---------------------------------------------------------------------------


class TestConfiguredAllowlist:
    """When the variable is set, it is the whole policy."""

    def test_target_inside_a_configured_root_is_accepted(self, tmp_path, monkeypatch):
        root = tmp_path / "repos"
        (root / "project").mkdir(parents=True)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root))

        assert validate_scan_target(root / "project") is None

    def test_target_equal_to_a_configured_root_is_accepted(self, tmp_path, monkeypatch):
        root = tmp_path / "repos"
        root.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root))

        assert validate_scan_target(root) is None

    def test_same_target_flips_on_the_variable_alone(self, tmp_path, monkeypatch):
        """One target, two policies, opposite verdicts.

        Nothing about the target changes between the two halves -- same path,
        same filesystem, same process. Only the variable moves. A check that
        silently accepted everything, or that refused everything, could not
        produce both halves.
        """
        target = tmp_path / "repos" / "project"
        target.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()

        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target.parent))
        assert validate_scan_target(target) is None

        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(elsewhere))
        assert validate_scan_target(target) is not None

    def test_second_of_several_roots_matches(self, tmp_path, monkeypatch):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        (second / "project").mkdir(parents=True)
        monkeypatch.setenv(
            ASH_MCP_ALLOWED_ROOTS_ENV, os.pathsep.join([str(first), str(second)])
        )

        assert validate_scan_target(second / "project") is None

    def test_sibling_sharing_a_name_prefix_is_refused(self, tmp_path, monkeypatch):
        """The allowlist side of the ``startswith`` discriminator."""
        root = tmp_path / "repos"
        root.mkdir()
        sibling = tmp_path / "repos-backup"
        sibling.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root))

        assert validate_scan_target(sibling) is not None

    def test_symlink_escaping_an_allowed_root_is_refused(self, tmp_path, monkeypatch):
        """Resolution has to happen before containment is tested.

        The link lives inside the allowed root, so a containment check on the
        unresolved path accepts it. Its target does not, so a check on the
        resolved path refuses it. This is the property that makes
        ``resolve()`` load-bearing for confinement rather than merely for
        existence.
        """
        root = tmp_path / "repos"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        link = root / "escape"
        link.symlink_to(outside, target_is_directory=True)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root))

        assert link.is_relative_to(root)
        assert validate_scan_target(link) is not None

    def test_allowlist_replaces_the_default_refusal_set(self, tmp_path, monkeypatch):
        """The documented escape hatch.

        An operator who genuinely must scan a system directory names it. The
        allowlist is the only control, so setting it to a refused-by-default
        path grants exactly that path and nothing else.
        """
        if platform.system() == "Windows":
            pytest.skip("POSIX system paths")

        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, "/etc")

        assert validate_scan_target("/etc") is None
        assert validate_scan_target("/etc/ssl") is None
        assert validate_scan_target(tmp_path) is not None

    def test_session_workspace_root_is_allowed_implicitly(self, tmp_path, monkeypatch):
        """Source-delivery trees stay scannable when an allowlist is set.

        ``set_source_git`` and ``set_source_zip_finalize`` clone or extract
        into the per-session MCP workspace and hand the caller that path to
        scan. An allowlist that named only the operator's own repositories
        would otherwise refuse every uploaded tree.
        """
        workspace = tmp_path / "cache" / "ash-mcp"
        session = workspace / "session-1"
        session.mkdir(parents=True)
        repos = tmp_path / "repos"
        repos.mkdir()

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(repos))

        assert validate_scan_target(session) is None


class TestAllowlistParsing:
    """Parsing edge cases, each of which fails open if handled carelessly."""

    def test_empty_entries_do_not_allowlist_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        """``"".split(os.pathsep)`` is ``[""]`` and ``Path("").resolve()`` is the cwd.

        So an empty or whitespace-only entry -- a trailing separator is enough
        to produce one -- would silently admit the process working directory
        and everything under it. Empty entries must be dropped, not resolved.
        """
        root = tmp_path / "repos"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        monkeypatch.chdir(outside)

        for raw in (
            os.pathsep.join([str(root), ""]),
            os.pathsep.join(["", str(root)]),
            os.pathsep.join([str(root), "   "]),
        ):
            monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, raw)
            assert validate_scan_target(root) is None, raw
            assert validate_scan_target(outside) is not None, raw

    def test_all_empty_value_is_treated_as_unconfigured(self, tmp_path, monkeypatch):
        """A variable set to nothing but separators falls back to the default.

        Failing closed here would break a deployment over a stray character in
        a compose file; failing open would admit the working directory. The
        default refusal set is the third option and the right one.
        """
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, os.pathsep + "  ")

        assert _allowed_roots() == []
        assert validate_scan_target(tmp_path) is None
        if platform.system() != "Windows":
            assert validate_scan_target("/etc") is not None

    def test_user_home_shorthand_is_expanded(self, tmp_path, monkeypatch):
        """``~`` is expanded, matching how ASH_MCP_WORKSPACE_ROOT is read."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, "~/repos")
        target = tmp_path / "repos" / "project"
        target.mkdir(parents=True)

        assert validate_scan_target(target) is None

    def test_whitespace_around_entries_is_stripped(self, tmp_path, monkeypatch):
        root = tmp_path / "repos"
        root.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, f"  {root}  ")

        assert validate_scan_target(root) is None
