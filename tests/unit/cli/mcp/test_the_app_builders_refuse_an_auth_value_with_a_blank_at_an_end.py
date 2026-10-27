# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The app builders refuse an auth value that starts or ends with a space or tab.

An HTTP implementation drops a space or tab from each end of a header value, so a
value that has one can never be matched by a request, and a server configured with
it answers 401 to every request. ``ash mcp`` refuses such a value in all three of
its forms (the command line, a file and a descriptor). ``build_streamable_http_app``
and ``build_sse_app`` are public and take the value as a string, so they used to
build an app that rejected every request.

The check now sits in ``_build_auth_middleware``, the one function every entry
point builds the middleware through, so a library caller gets the same refusal as
the command line, before the shared server is touched.

The same holds for a control byte (0x00 to 0x1F except the tab, and 0x7F), which a
conforming client never sends: a library caller that reads the value from a secret
file keeps its line ending, and the app it got answered 401 to every request.

An auth header name given without a value, or a value without a name, is refused as
the command line refuses it. The builders used to read it as "no authentication" and
returned an app that let every request through.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import (
    _auth_middleware_if_configured,
    _build_auth_middleware,
    build_sse_app,
    build_streamable_http_app,
)
from automated_security_helper.cli.mcp_server import mcp as shared_server
from automated_security_helper.core.exceptions import ASHValidationError
from tests.utils.mcp_transport_harness import LOOPBACK_PORT

HEADER = "X-Ash-Token"

#: The refusal's wording, the same for every form that carries the value.
EDGE_BLANK_MESSAGE = "starts or ends with a space or tab"

#: Values that start or end with a space or a tab, each with the end it is on.
EDGE_BLANK = {
    "leading-space": " tok-a",
    "trailing-space": "tok-a ",
    "both-spaces": " tok-a ",
    "leading-tab": "\ttok-a",
    "trailing-tab": "tok-a\t",
    "only-a-space": " ",
    "only-a-tab": "\t",
}

#: The refusal's wording for a control byte, the same as a file's or a descriptor's.
CONTROL_MESSAGE = "control character"

#: Values with a control byte, each named by the byte and where it sits. The command
#: line, a file and a descriptor refuse every one of them.
CONTROL_VALUES = {
    "trailing-line-feed": "tok-a\n",
    "trailing-carriage-return": "tok-a\r",
    "trailing-crlf": "tok-a\r\n",
    "trailing-form-feed": "tok-a\x0c",
    "trailing-delete": "tok-a\x7f",
    "leading-line-feed": "\ntok-a",
    "nul-inside": "tok\x00-a",
    "escape-inside": "tok\x1b-a",
    "unit-separator-inside": "tok\x1f-a",
}

#: The command line's wording for a name or a value given without the other.
PAIR_MESSAGE = "must be set together"

#: A name or a value given without the other, each as (name, value).
HALF_SET = {
    "name-and-empty-value": (HEADER, ""),
    "name-and-no-value": (HEADER, None),
    "value-and-empty-name": ("", "tok-a"),
    "value-and-no-name": (None, "tok-a"),
}

#: Each builder with the method of the shared server it builds the app with.
BUILDERS = [
    pytest.param(
        build_streamable_http_app, "streamable_http_app", id="streamable-http"
    ),
    pytest.param(build_sse_app, "sse_app", id="sse"),
]


def _spy_on(monkeypatch, method: str) -> list:
    """Count calls to ``shared_server.<method>``, still running the real one."""
    calls: list = []
    real = getattr(shared_server, method)

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(shared_server, method, spy)
    return calls


@pytest.mark.parametrize("value", EDGE_BLANK.values(), ids=EDGE_BLANK.keys())
@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_both_app_builders_refuse_a_value_with_a_blank_at_an_end(
    build, method: str, value: str
) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        build(auth_header_name=HEADER, auth_header_value=value, port=LOOPBACK_PORT)


@pytest.mark.parametrize("value", EDGE_BLANK.values(), ids=EDGE_BLANK.keys())
def test_the_middleware_builder_refuses_it(value: str) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        _build_auth_middleware(HEADER, value)


@pytest.mark.parametrize("value", EDGE_BLANK.values(), ids=EDGE_BLANK.keys())
def test_the_helper_the_builders_call_refuses_it(value: str) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        _auth_middleware_if_configured(HEADER, value)


def test_the_refusal_does_not_repeat_the_value() -> None:
    with pytest.raises(ASHValidationError) as caught:
        build_streamable_http_app(
            auth_header_name=HEADER,
            auth_header_value="zq9distinct ",
            port=LOOPBACK_PORT,
        )

    assert "zq9distinct" not in str(caught.value)


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_refused_build_never_calls_into_the_shared_server(
    monkeypatch, build, method: str
) -> None:
    calls = _spy_on(monkeypatch, method)

    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        build(auth_header_name=HEADER, auth_header_value="tok-a ", port=LOOPBACK_PORT)

    assert calls == []


@pytest.mark.parametrize(("build", "method"), BUILDERS)
@pytest.mark.parametrize(
    "value",
    ["ascii-token", "Bearer abc 123", "tok\tvalue"],
    ids=["token", "space-inside", "tab-inside"],
)
def test_a_value_with_a_blank_only_between_characters_still_builds(
    monkeypatch, build, method: str, value: str
) -> None:
    """Control: the end check leaves a space or tab inside the value alone."""
    calls = _spy_on(monkeypatch, method)

    app = build(auth_header_name=HEADER, auth_header_value=value, port=LOOPBACK_PORT)

    assert app is not None
    assert len(calls) == 1


@pytest.mark.parametrize("value", CONTROL_VALUES.values(), ids=CONTROL_VALUES.keys())
@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_both_app_builders_refuse_a_value_with_a_control_byte(
    build, method: str, value: str
) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        build(auth_header_name=HEADER, auth_header_value=value, port=LOOPBACK_PORT)


@pytest.mark.parametrize("value", CONTROL_VALUES.values(), ids=CONTROL_VALUES.keys())
def test_the_middleware_builder_refuses_a_control_byte(value: str) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _build_auth_middleware(HEADER, value)


@pytest.mark.parametrize("value", CONTROL_VALUES.values(), ids=CONTROL_VALUES.keys())
def test_the_helper_the_builders_call_refuses_a_control_byte(value: str) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _auth_middleware_if_configured(HEADER, value)


def test_the_control_byte_refusal_does_not_repeat_the_value() -> None:
    with pytest.raises(ASHValidationError) as caught:
        build_streamable_http_app(
            auth_header_name=HEADER,
            auth_header_value="zq9distinct\n",
            port=LOOPBACK_PORT,
        )

    assert "zq9distinct" not in str(caught.value)


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_refused_for_a_control_byte_never_calls_into_the_shared_server(
    monkeypatch, build, method: str
) -> None:
    calls = _spy_on(monkeypatch, method)

    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        build(auth_header_name=HEADER, auth_header_value="tok-a\n", port=LOOPBACK_PORT)

    assert calls == []


@pytest.mark.parametrize(("build", "method"), BUILDERS)
@pytest.mark.parametrize(
    "value",
    ["tok-\xe9", "tok-\xff", "tok-\x80-a"],
    ids=["e-acute", "y-diaeresis", "c1-control-inside"],
)
def test_a_value_with_a_byte_from_0x80_to_0xff_still_builds(
    monkeypatch, build, method: str, value: str
) -> None:
    """Control: the bytes 0x80 to 0xFF are header bytes, kept as the file form keeps them."""
    calls = _spy_on(monkeypatch, method)

    app = build(auth_header_name=HEADER, auth_header_value=value, port=LOOPBACK_PORT)

    assert app is not None
    assert len(calls) == 1


@pytest.mark.parametrize(("name", "value"), HALF_SET.values(), ids=HALF_SET.keys())
@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_both_app_builders_refuse_a_name_or_a_value_given_alone(
    build, method: str, name, value
) -> None:
    with pytest.raises(ASHValidationError, match=PAIR_MESSAGE):
        build(auth_header_name=name, auth_header_value=value, port=LOOPBACK_PORT)


@pytest.mark.parametrize(("name", "value"), HALF_SET.values(), ids=HALF_SET.keys())
def test_the_helper_the_builders_call_refuses_a_name_or_a_value_given_alone(
    name, value
) -> None:
    with pytest.raises(ASHValidationError, match=PAIR_MESSAGE):
        _auth_middleware_if_configured(name, value)


def test_the_refusal_of_a_value_given_alone_does_not_repeat_it() -> None:
    with pytest.raises(ASHValidationError) as caught:
        build_streamable_http_app(
            auth_header_name="", auth_header_value="zq9distinct", port=LOOPBACK_PORT
        )

    assert "zq9distinct" not in str(caught.value)


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_refused_for_a_half_set_pair_never_calls_into_the_shared_server(
    monkeypatch, build, method: str
) -> None:
    calls = _spy_on(monkeypatch, method)

    with pytest.raises(ASHValidationError, match=PAIR_MESSAGE):
        build(auth_header_name=HEADER, auth_header_value="", port=LOOPBACK_PORT)

    assert calls == []


@pytest.mark.parametrize(
    ("name", "value"),
    [(None, None), ("", ""), ("", None), (None, "")],
    ids=["none-none", "empty-empty", "empty-none", "none-empty"],
)
def test_neither_option_set_is_no_authentication(name, value) -> None:
    """Control: giving neither the name nor the value still builds no middleware."""
    assert _auth_middleware_if_configured(name, value) is None


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_with_neither_option_set_still_builds(
    monkeypatch, build, method: str
) -> None:
    """Control: the pair rule leaves an app with no authentication alone."""
    calls = _spy_on(monkeypatch, method)

    app = build(auth_header_name="", auth_header_value="", port=LOOPBACK_PORT)

    assert app is not None
    assert len(calls) == 1
