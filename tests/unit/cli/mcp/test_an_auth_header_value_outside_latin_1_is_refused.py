# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The static header auth compares header bytes, so a value with none is refused.

An HTTP header value is bytes, and Starlette reads them as latin-1, so the auth
middleware compares the latin-1 encoding of the configured value with that of the
received one. A character outside latin-1 has no such byte. The middleware encoded
with ``errors="replace"``, which gave "?" for each one, so two values that differ
only in those characters were the same value.

The middleware encodes strictly now:

- a configured value with a character outside latin-1 is refused when the
  middleware is built (and so by both app builders), and by the option check
  ``ash mcp`` runs first, with a message that does not repeat the value;
- a received value that has no header bytes does not match.

Values that latin-1 can carry compare as they did: by their latin-1 bytes.
"""

from __future__ import annotations

import asyncio

import pytest
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import (
    _build_auth_middleware,
    _validate_auth_options,
    build_sse_app,
    build_streamable_http_app,
)
from automated_security_helper.core.exceptions import ASHValidationError
from tests.utils.mcp_transport_harness import LOOPBACK_PORT

pytestmark = pytest.mark.unit

HEADER = "X-Ash-Token"
#: Two characters outside latin-1, named by code point.
OUTSIDE_LATIN_1 = chr(0x4E2D) + chr(0x6587)
SECRET = "token-" + OUTSIDE_LATIN_1
#: A character latin-1 does carry, and the one header byte it is.
E_ACUTE = chr(0xE9)


def _app(value: str) -> Starlette:
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(_build_auth_middleware(HEADER, value))
    return app


class _Request:
    """The part of a request the middleware reads: ``headers.get``."""

    def __init__(self, headers) -> None:
        self.headers = headers


def _on_the_wire(value: bytes) -> _Request:
    """A request whose header holds these raw bytes, read as Starlette reads them.

    Starlette's own ``Headers`` over the raw pair, which decodes the value as latin-1.
    """
    return _Request(Headers(raw=[(HEADER.lower().encode("ascii"), value)]))


def _status(configured: str, request: _Request) -> int:
    """The status the middleware built for ``configured`` answers ``request`` with."""

    async def run() -> int:
        guard = _build_auth_middleware(HEADER, configured)(None)

        async def call_next(_request):
            return PlainTextResponse("ok")

        response = await guard.dispatch(request, call_next)
        return response.status_code

    return asyncio.run(run())


# -- a configured value with no header bytes is refused ---------------------


def test_the_middleware_refuses_a_value_outside_latin_1() -> None:
    with pytest.raises(ASHValidationError, match="outside latin-1"):
        _build_auth_middleware(HEADER, SECRET)


def test_the_refusal_does_not_repeat_the_value() -> None:
    with pytest.raises(ASHValidationError) as caught:
        _build_auth_middleware(HEADER, SECRET)

    assert SECRET not in str(caught.value)
    assert OUTSIDE_LATIN_1 not in str(caught.value)


@pytest.mark.parametrize(
    "build",
    [build_streamable_http_app, build_sse_app],
    ids=["streamable-http", "sse"],
)
def test_both_app_builders_refuse_it(build) -> None:
    with pytest.raises(ASHValidationError, match="outside latin-1"):
        build(auth_header_name=HEADER, auth_header_value=SECRET, port=LOOPBACK_PORT)


def test_the_option_check_refuses_it_before_anything_is_built() -> None:
    with pytest.raises(ASHValidationError, match="outside latin-1"):
        _validate_auth_options(HEADER, SECRET)


@pytest.mark.parametrize("value", ["ascii-token", "caf" + E_ACUTE])
def test_a_value_latin_1_carries_passes_the_option_check(value: str) -> None:
    """Control: the option check refuses nothing latin-1 can carry.

    A file or a descriptor can hand the server any such byte. The command-line form
    is narrower, visible ASCII, and is checked before this check runs
    (``test_a_command_line_auth_value_is_checked_in_the_bytes_the_header_carries``).
    """
    _validate_auth_options(HEADER, value)


# -- a received value with no header bytes does not match --------------------


def test_a_received_value_outside_latin_1_matches_no_question_mark_value() -> None:
    """The replacement form was the one a "?" value matched; it matches nothing now.

    Starlette decodes a received header as latin-1, so a real request cannot carry
    such a character; the request here is the part of one the middleware reads.
    """

    async def run():
        middleware = _build_auth_middleware(HEADER, "?" * len(OUTSIDE_LATIN_1))
        guard = middleware(None)
        reached = []

        async def call_next(request):
            reached.append(request)
            return PlainTextResponse("ok")

        request = _Request({HEADER.lower(): OUTSIDE_LATIN_1})
        response = await guard.dispatch(request, call_next)
        return response.status_code, reached

    status, reached = asyncio.run(run())

    assert status == 401
    assert reached == []


def test_the_header_bytes_of_a_value_are_its_latin_1_encoding() -> None:
    from automated_security_helper.cli import mcp as mcp_cli

    assert mcp_cli._header_wire_bytes("caf" + E_ACUTE) == b"caf" + bytes([0xE9])
    assert mcp_cli._header_wire_bytes(OUTSIDE_LATIN_1) is None


# -- values latin-1 carries compare as they did ------------------------------


def test_an_ascii_value_authenticates_only_when_it_matches() -> None:
    """Control: an exact match passes; a wrong or missing value gets 401."""
    client = TestClient(_app("secret"))

    assert client.get("/", headers={HEADER: "secret"}).status_code == 200
    assert client.get("/", headers={HEADER: "wrong"}).status_code == 401
    assert client.get("/").status_code == 401


def test_a_latin_1_value_is_compared_as_its_wire_bytes() -> None:
    """Control: the header bytes a client sends are compared with the value's latin-1 bytes.

    The raw bytes go into the request's headers directly. Starlette's in-process
    test client cannot carry them: it re-encodes a header value as UTF-8, so a lone
    latin-1 byte reaches the app as two.
    """
    value = "caf" + E_ACUTE

    assert _status(value, _on_the_wire(value.encode("latin-1"))) == 200
    assert _status(value, _on_the_wire(value.encode("utf-8"))) == 401
    assert _status(value, _on_the_wire(b"caf?")) == 401
