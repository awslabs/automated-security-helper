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


class TestNamesThatOnlyResembleItStayOrdinary:
    """Positive control: the refusal reaches the guard file's name and no other."""

    @pytest.mark.parametrize("ordinary", ORDINARY)
    def test_a_name_that_only_resembles_the_guard_file_is_not_reserved(self, ordinary):
        assert is_reserved_session_id(ordinary) is False
