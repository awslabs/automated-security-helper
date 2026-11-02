# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A download follows a redirect only to https, and a refusal is an integrity error.

Properties of ``utils/download_utils.py`` that nothing else pins:

- the redirect handler refuses a ``Location`` that is not https before the request
  it names is made, so an https -> http -> https chain no longer sends its middle
  request in the clear (the check on the URL the response landed at passes that
  chain, since its last hop is https);
- a relative ``Location`` is joined to the URL that answered, as urllib joins it,
  and followed when the result is https;
- every redirect status urllib hands to a handler is held to the same rule;
- the refusal names the URLs without their query strings, which carry a signed
  download's credential;
- ``_open_url`` builds its opener with that handler;
- the refusal is a ``ToolDownloadIntegrityError`` (and still a ``ValueError``, as it
  was), so the rules bundle installer lets it out as the integrity failure it is,
  not as a raw ``ValueError`` and not as the network failure it words differently.

Nothing here reaches the network.
"""

from __future__ import annotations

import http.client
import sys
import urllib.request

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import download_utils as du
from automated_security_helper.utils.rules_bundles import install_rules_bundle
from automated_security_helper.utils.tool_downloads import RULES_BUNDLES

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _downloads_open_through_urlopen():
    """This module tests ``_open_url`` itself, so it is left as it is."""


class _Parent:
    """What a redirect handler's opener does with the request it builds: records
    the URL it was asked to open and answers with a marker."""

    def __init__(self):
        self.opened = []

    def open(self, request, data=None, timeout=None):
        self.opened.append(request.full_url)
        return "followed"


class _Answer:
    def __init__(self):
        self.closed = False

    def read(self):
        return b""

    def close(self):
        self.closed = True


def _redirect(handler_name, location, code=302, answered="https://example.com/tool"):
    """Hand a redirect to a fresh handler: ``(parent, answer, result or error)``."""
    handler = du._HttpsOnlyRedirects()
    handler.parent = _Parent()
    request = urllib.request.Request(answered)
    # An opener sets this on every request it opens; the handler passes it on.
    request.timeout = None
    headers = http.client.HTTPMessage()
    headers["Location"] = location
    answer = _Answer()
    try:
        outcome = getattr(handler, handler_name)(
            request, answer, code, "Found", headers
        )
    except du.InsecureRedirectError as refused:
        outcome = refused
    return handler.parent, answer, outcome


_HANDLERS = [
    ("http_error_301", 301),
    ("http_error_302", 302),
    ("http_error_303", 303),
    ("http_error_307", 307),
    ("http_error_308", 308),
]


@pytest.mark.parametrize("handler_name, code", _HANDLERS)
def test_a_redirect_to_plain_http_is_refused_before_it_is_requested(handler_name, code):
    parent, answer, outcome = _redirect(
        handler_name, "http://mirror.example.com/tool", code=code
    )
    assert isinstance(outcome, du.InsecureRedirectError)
    assert parent.opened == []
    assert answer.closed
    assert "http://mirror.example.com/tool" in str(outcome)


@pytest.mark.parametrize(
    "handler_name, code",
    [
        pytest.param(
            name,
            code,
            marks=pytest.mark.skipif(
                code == 308 and sys.version_info < (3, 11),
                reason="urllib follows a 308 only from Python 3.11",
            ),
        )
        for name, code in _HANDLERS
    ],
)
def test_control_a_redirect_to_https_is_followed(handler_name, code):
    parent, _answer, outcome = _redirect(
        handler_name, "https://cdn.example.com/tool?sig=1", code=code
    )
    assert outcome == "followed"
    assert parent.opened == ["https://cdn.example.com/tool?sig=1"]


def test_control_a_relative_redirect_keeps_the_scheme_that_answered():
    parent, _answer, outcome = _redirect(
        "http_error_302", "/other/tool", answered="https://example.com/tool"
    )
    assert outcome == "followed"
    assert parent.opened == ["https://example.com/other/tool"]


def test_a_redirect_to_another_scheme_is_refused_as_not_https():
    parent, _answer, outcome = _redirect("http_error_302", "ftp://mirror.example.com/t")
    assert isinstance(outcome, du.InsecureRedirectError)
    assert parent.opened == []


def test_the_refusal_names_no_query_string():
    _parent, _answer, outcome = _redirect(
        "http_error_302",
        "http://mirror.example.com/tool?sig=secret",
        answered="https://example.com/tool?token=other",
    )
    message = str(outcome)
    assert "secret" not in message
    assert "token=other" not in message
    assert "https://example.com/tool" in message


def test_open_url_builds_its_opener_with_the_https_only_handler(monkeypatch):
    built = []

    class _Opener:
        def open(self, url, timeout=None):
            built.append((url, timeout))
            return "response"

    def build_opener(*handlers):
        built.append(handlers)
        return _Opener()

    monkeypatch.setattr(du.urllib.request, "build_opener", build_opener)
    assert du._open_url("https://example.com/tool", 7.0) == "response"
    assert built == [(du._HttpsOnlyRedirects,), ("https://example.com/tool", 7.0)]


class _LandedOffHttps:
    """A response that says it was read from plain http, and counts its reads."""

    def __init__(self):
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def geturl(self):
        return "http://mirror.example.com/rules.zip?sig=secret"

    def read(self, *_args):
        self.reads += 1
        return b""


def test_a_bundle_download_redirected_off_https_is_an_integrity_error(
    monkeypatch, tmp_path
):
    """``install_rules_bundle`` lets an integrity failure out as itself: it was a
    bare ``ValueError`` there, which no caller of the installer is told to expect."""
    landed = _LandedOffHttps()
    monkeypatch.setattr(du, "_open_url", lambda url, timeout: landed)
    monkeypatch.setattr(
        "automated_security_helper.utils.tool_downloads.get_rules_bundle",
        lambda name: RULES_BUNDLES[name],
    )
    name = next(iter(RULES_BUNDLES))
    with pytest.raises(ToolDownloadIntegrityError) as raised:
        install_rules_bundle(name, root=tmp_path / "rules")
    assert isinstance(raised.value, du.InsecureRedirectError)
    assert "secret" not in str(raised.value)
    assert landed.reads == 0
