# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session id has to name one directory beneath the workspace root, and nothing else.

What was wrong
--------------
``resolve_session_id`` refused four shapes -- over-length, ``/`` or ``\\``,
exactly ``.`` or ``..``, and control characters -- and had no charset check.
``:`` is in none of those, and a drive-relative id needs no separator at all.
``source_delivery._session_workspace`` re-derived three of the same predicates
rather than calling the stronger one, so the rule existed twice and neither copy
covered the drive family.

Why ``:`` is not a cosmetic omission
------------------------------------
``pathlib`` treats a bare drive specifier as the anchor of the path it is joined
onto, so joining one whose drive matches the base yields the base itself. That is
measured directly in :class:`TestTheJoinArithmeticBeingClosed` rather than
asserted from memory, using ``PureWindowsPath`` so the measurement runs on any
host. With ``'C:'`` accepted, ``_session_workspace(root, 'C:')`` returned the
shared workspace *root*, and ``clear_source`` then removed every live session's
extracted tree, chunk parts and recorded ``source_dir``, and reported success.
A non-matching drive is worse still: the join yields a drive-relative path with
no relation to the workspace at all.

Two preconditions bound the damage and neither makes it theoretical: the host
must be Windows, which this project supports -- it ships PowerShell wrappers and
``cli/mcp/scan_target.py`` carries a Windows-specific denied-root list -- and the
drive has to match, which for a server installed on the system drive is the
common case.

What these tests can and cannot show on a POSIX host
----------------------------------------------------
The ``rmtree`` of the workspace root cannot be reproduced here, because
``PurePosixPath('/ws') / 'C:'`` is ``/ws/C:``, an ordinary directory name. So the
refusal itself is what is asserted against the functions, and the join arithmetic
that makes the refusal necessary is measured separately through
``PureWindowsPath``. Together those are the whole claim; neither alone is.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import (
    MCP_SESSION_ID_HEADER,
    resolve_session_id,
    validate_path_component,
)

# Shapes a client legitimately mints. A UUID, a JWT and a base64url token all
# have to keep working; the charset was chosen against this list rather than
# tightened until the tests passed.
ACCEPTED = [
    "abc123",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "0123456789abcdef0123456789abcdef",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1",
    "tenant-a",
    "session_test",
    DEFAULT_SESSION_ID,
    "tok+en=",
    "a~b",
    "a" * 128,
]

# Shapes that cannot name one directory beneath the root on every platform.
REFUSED = [
    "",
    ".",
    "..",
    "../other-session",
    "a/b",
    "/absolute",
    "trailing/",
    "back\\slash",
    "..\\windows",
    "C:",
    "C:sessions",
    "C:\\Windows",
    "\\\\server\\share",
    "sess\x00evil",
    "sess\nid",
    "sess\x7f",
    "a" * 129,
    # Characters outside the allowlist that a filesystem reads as structure, or
    # that shell and glob handling elsewhere would have to be audited for.
    "sess:1",
    "sess*1",
    "sess?1",
    'sess"1',
    "sess<1",
    "sess|1",
    "sess 1",
]


class TestTheJoinArithmeticBeingClosed:
    """Measured, not recalled: why a session id with a drive specifier escapes.

    These assertions are about ``pathlib`` rather than about ASH. They are here
    because the guard they justify looks arbitrary without them, and because the
    behavior is platform-specific in a way that is easy to get wrong from memory:
    ``PureWindowsPath`` gives the Windows answer on a POSIX host.
    """

    def test_a_matching_drive_specifier_joins_to_the_base_itself(self):
        root = PureWindowsPath("C:/ash-mcp")
        assert root / "C:" == root

    def test_a_non_matching_drive_specifier_discards_the_base(self):
        assert PureWindowsPath("D:/ash-mcp") / "C:" == PureWindowsPath("C:")

    def test_a_drive_relative_id_keeps_the_drive_and_drops_the_directory(self):
        assert PureWindowsPath("C:/ash-mcp") / "C:sessions" == PureWindowsPath(
            "C:/ash-mcp/sessions"
        )

    def test_is_absolute_is_not_a_containment_check_on_windows(self):
        """A root-anchored POSIX path is not absolute on Windows, and still escapes.

        Named here because ``is_absolute()`` is the check a reader expects to find
        instead of the charset, and it would not have closed this.
        """
        assert PureWindowsPath("/ash-mcp/x").is_absolute() is False
        assert PureWindowsPath("C:/ash-mcp") / "/elsewhere" == PureWindowsPath(
            "C:/elsewhere"
        )

    def test_the_same_id_is_an_ordinary_directory_name_on_posix(self):
        """Why the escape cannot be reproduced against the filesystem on this host."""
        assert PurePosixPath("/ash-mcp") / "C:" == PurePosixPath("/ash-mcp/C:")


class TestValidatePathComponent:
    """One validator, and the rule set it enforces."""

    @pytest.mark.parametrize("candidate", ACCEPTED)
    def test_accepted(self, candidate):
        assert validate_path_component(candidate, "session_id") == candidate

    @pytest.mark.parametrize("candidate", REFUSED)
    def test_refused(self, candidate):
        with pytest.raises(ValueError):
            validate_path_component(candidate, "session_id")

    @pytest.mark.parametrize("candidate", REFUSED)
    def test_the_refusal_names_the_label_so_the_message_is_actionable(self, candidate):
        with pytest.raises(ValueError, match="upload_id"):
            validate_path_component(candidate, "upload_id")

    @pytest.mark.parametrize("candidate", ACCEPTED)
    def test_an_accepted_id_is_one_level_below_the_root_on_either_platform(
        self, candidate
    ):
        """The property the validator exists to guarantee, over both path flavors.

        This is what makes the charset checkable rather than a matter of taste: if
        a future widening admitted a value that collapsed the join or anchored
        elsewhere, this fails without anyone having to think of that value as a
        test case.
        """
        for flavor, root in (
            (PurePosixPath, PurePosixPath("/ash-mcp")),
            (PureWindowsPath, PureWindowsPath("C:/ash-mcp")),
            (PureWindowsPath, PureWindowsPath("D:/ash-mcp")),
        ):
            joined = root / candidate
            assert joined != root, (flavor, candidate)
            assert joined.parent == root, (flavor, candidate)
            assert joined.name == candidate, (flavor, candidate)


class TestResolveSessionId:
    """The header path. Every existing behavior is unchanged; ``:`` is now refused."""

    def test_a_drive_specifier_header_is_refused(self):
        with pytest.raises(ValueError, match=MCP_SESSION_ID_HEADER):
            resolve_session_id({MCP_SESSION_ID_HEADER: "C:"})

    @pytest.mark.parametrize("candidate", REFUSED)
    def test_every_unusable_shape_is_refused_rather_than_coerced(self, candidate):
        if candidate == "":
            # An empty or whitespace-only header means "no session supplied" and
            # resolves to the default; only a present, non-empty, unusable value
            # is an error. Asserted rather than skipped so the distinction stays
            # covered.
            assert resolve_session_id({MCP_SESSION_ID_HEADER: candidate}) == (
                DEFAULT_SESSION_ID
            )
            return
        with pytest.raises(ValueError):
            resolve_session_id({MCP_SESSION_ID_HEADER: candidate})

    @pytest.mark.parametrize("candidate", ACCEPTED)
    def test_every_legitimate_shape_still_resolves_to_itself(self, candidate):
        assert resolve_session_id({MCP_SESSION_ID_HEADER: candidate}) == candidate


class TestSessionWorkspaceSharesTheOneValidator:
    """``_session_workspace`` is the second entry point and must not be weaker.

    It is reachable without the header path: the ``mcp_tools`` wrappers take
    ``session_id`` as an argument, so the workspace builder is a boundary in its
    own right.
    """

    @pytest.mark.parametrize("candidate", REFUSED)
    def test_every_shape_the_header_path_refuses_is_refused_here_too(
        self, candidate, tmp_path
    ):
        with pytest.raises(ValueError, match="session_id"):
            sd._session_workspace(tmp_path, candidate)

    @pytest.mark.parametrize("candidate", ACCEPTED)
    def test_an_accepted_id_names_a_child_of_the_workspace_root(
        self, candidate, tmp_path
    ):
        assert sd._session_workspace(tmp_path, candidate) == tmp_path / candidate

    def test_clear_source_refuses_a_drive_specifier_instead_of_wiping_the_root(
        self, tmp_path
    ):
        """The consequence the guard exists for, as far as it is observable here.

        On Windows the unguarded call resolved to ``tmp_path`` itself and removed
        every session under it. On this host it resolved to ``tmp_path / 'C:'``,
        so what is asserted is the refusal and that the root and its neighbours
        are untouched -- the refusal is what fails against the unfixed module.
        """
        (tmp_path / "session-other").mkdir()
        (tmp_path / "session-other" / "source").mkdir()
        (tmp_path / "session-other" / "source" / "keep.py").write_text("x = 1\n")

        with pytest.raises(ValueError, match="session_id"):
            sd.clear_source("C:", workspace_root=tmp_path)

        assert tmp_path.exists()
        assert (tmp_path / "session-other" / "source" / "keep.py").exists()

    def test_the_join_cannot_collapse_even_if_the_charset_is_widened(self, tmp_path):
        """The post-condition in ``_session_workspace``, stated as its own case.

        Unreachable while the validator runs first -- no value it accepts can
        collapse the join, which :class:`TestValidatePathComponent` asserts
        directly. It is kept because the collapse is silent, and it is named here
        so a reader does not mistake it for a live second opinion on the id.
        """
        built = sd._session_workspace(tmp_path, "session-ok")
        assert built.parent == Path(tmp_path)
        assert built != Path(tmp_path)
