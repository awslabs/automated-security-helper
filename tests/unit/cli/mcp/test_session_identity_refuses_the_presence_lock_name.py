# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The presence registries' guard file name is a reserved session id.

Each presence registry under the workspace root (``.stdio-servers``,
``.ash-mcp-scans``) is locked through a guard file named ``.lock``
(``sessions.PRESENCE_LOCK_NAME``). Under the scans' registry a session's holder
directory shares the registry's parent with that file, so a session called
``.lock`` could register no scan and its workspace would never be swept. The
identity layer refuses the name first, in every spelling a case-insensitive
filesystem or Windows folds onto it, so a caller naming it gets the reserved-name
refusal rather than a ``ValueError`` out of the registry later. A name that only
resembles it stays an ordinary id.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.session_identity import (
    MCP_SESSION_ID_HEADER,
    is_reserved_session_id,
    resolve_session_id,
)
from automated_security_helper.cli.mcp.sessions import PRESENCE_LOCK_NAME

pytestmark = pytest.mark.unit

RESERVED_SPELLINGS = [PRESENCE_LOCK_NAME, ".LOCK", ".Lock", ".lock.", ".lock. "]

ORDINARY = ["lock", "lock~1", ".locks", "a.lock", "lock.file"]


class TestTheGuardFileNameIsReserved:
    """``.lock`` is the server's, under every registry, in every folded spelling."""

    def test_the_constant_is_the_name_the_registries_lock(self):
        assert PRESENCE_LOCK_NAME == ".lock"

    @pytest.mark.parametrize("spelling", RESERVED_SPELLINGS)
    def test_every_spelling_of_the_guard_file_name_is_reserved(self, spelling):
        assert is_reserved_session_id(spelling) is True

    @pytest.mark.parametrize("spelling", RESERVED_SPELLINGS)
    def test_a_header_naming_the_guard_file_is_refused(self, spelling):
        with pytest.raises(ValueError, match="is reserved and cannot name a session"):
            resolve_session_id({MCP_SESSION_ID_HEADER: spelling})


class TestTheSessionLayerReadsTheNameThroughTheIdentityCheckAlone:
    """The session registry refuses the name, and the session removal clears only
    the in-memory state for it, each through ``is_reserved_session_id``. The
    sessions module once compared the name a second time through a helper of its
    own, after the identity check had already answered for every spelling, so
    the second comparison could never be the one that decided; these pin what
    the identity check alone gives, so the helper's removal changes nothing."""

    @pytest.mark.parametrize(
        "spelling", [s for s in RESERVED_SPELLINGS if s == s.rstrip(". ")]
    )
    def test_the_registry_refuses_the_guard_file_name(self, spelling):
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        with pytest.raises(ValueError, match="names a directory the server keeps"):
            get_default_registry().session_for(spelling)

    @pytest.mark.parametrize("spelling", RESERVED_SPELLINGS)
    def test_ending_the_guard_file_name_touches_nothing_on_disk(
        self, spelling, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli.mcp.sessions import (
            _remove_unless_a_scan_elsewhere_holds,
        )

        root = tmp_path / "workspaces"
        root.mkdir()
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))

        assert _remove_unless_a_scan_elsewhere_holds(spelling) is True
        assert list(root.iterdir()) == [], "the removal opened a registry or a dir"


class TestNamesThatOnlyResembleItStayOrdinary:
    """Positive control: the refusal reaches the guard file's name and no other."""

    @pytest.mark.parametrize("ordinary", ORDINARY)
    def test_a_name_that_only_resembles_the_guard_file_is_not_reserved(self, ordinary):
        assert is_reserved_session_id(ordinary) is False
