#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""check_installation names the session of the request it answers.

Why this file exists
--------------------
The tool resolves the caller's session with ``resolve_caller_session_id`` before
it asks the installation check anything. That name has to be in scope in
``mcp_server``: a call to a name the module does not import raises
``NameError``, which the tool's ``except ValueError`` does not catch, so the tool
failed on every request, whatever the headers held.

Here the tool is called with a stand-in context that carries a session header
(``resolve_caller_session_id`` reads a stand-in's headers; a context the SDK
built is read from the transport, see
``test_check_installation_headerless_network_caller.py``) and the installation
check is replaced by a double, so the test reads the session id the tool passed
on. With the name missing the tool raises before the double is reached.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_server

pytestmark = pytest.mark.unit

_SERVER = "automated_security_helper.cli.mcp_server"


def test_check_installation_passes_on_the_session_the_request_names():
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": "client-session-1"}
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    answer = {"success": True, "installed": True}

    with patch(
        f"{_SERVER}.mcp_check_installation",
        new_callable=AsyncMock,
        return_value=answer,
    ) as check:
        result = asyncio.run(mcp_server.check_installation(ctx))

    assert result == answer
    check.assert_awaited_once_with(session_id="client-session-1")
