# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-test restore of uvicorn's handle_exit keeps sse-starlette's own patch.

Why this exists
---------------
``tests/conftest.py`` puts back a ``uvicorn.server.Server.handle_exit`` a test
replaced. sse-starlette replaces it too, once, when it is first imported, so that
a server's exit ends every open event stream. When uvicorn.server was imported
before the test that first imported sse-starlette, the restore took that patch
for a test's and undid it, and the import never happens again in the process, so
every later server in the worker stopped without ending its event streams.
"""

from __future__ import annotations


def test_sse_starlettes_import_time_patch_is_kept() -> None:
    import sse_starlette.sse as sse
    import uvicorn.server

    from tests.conftest import _sse_flag_cleared_and_handle_exit_restored

    server = uvicorn.server.Server
    found = server.__dict__.get("handle_exit")
    try:
        # Before sse-starlette's import: uvicorn's own handler.
        server.handle_exit = sse.AppStatus.original_handler
        with _sse_flag_cleared_and_handle_exit_restored():
            # What sse-starlette's import does.
            server.handle_exit = sse.AppStatus.handle_exit
        kept = server.__dict__.get("handle_exit")
    finally:
        server.handle_exit = found

    assert kept is sse.AppStatus.handle_exit


def test_control_a_handler_a_test_replaced_is_put_back() -> None:
    import uvicorn.server

    from tests.conftest import _sse_flag_cleared_and_handle_exit_restored

    server = uvicorn.server.Server
    found = server.__dict__.get("handle_exit")

    def replaced(*args, **kwargs) -> None:
        return None

    try:
        with _sse_flag_cleared_and_handle_exit_restored():
            server.handle_exit = replaced
        restored = server.__dict__.get("handle_exit")
    finally:
        server.handle_exit = found

    assert restored is found
