# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``download_file``'s byte bound: the cap holds on the wire, not after it.

Each test pins one property of the ``max_bytes`` bound:

- a response that DECLARES a body over the bound is refused before any byte of
  the body is read;
- a body with no usable declared length (chunked, or a lying server) is aborted
  mid-stream the moment the bound passes, never drained and then discarded;
- a body exactly at the bound lands whole, so the bound is a bound and not an
  off-by-one;
- the abort is never retried: the same URL would serve the same body again, so
  a retry only repeats the cost the bound exists to refuse.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from automated_security_helper.utils import download_utils

pytestmark = pytest.mark.unit

URL = "https://files.test.invalid/bounded.bin"


class _Response(io.BytesIO):
    """A response body with an ``http.client``-shaped declared length."""

    def __init__(self, body: bytes, declared: "int | None"):
        super().__init__(body)
        #: ``_declared_body_length`` reads ``length`` first, as http.client
        #: parses it: None for a chunked or unusable value, else the byte count.
        self.length = declared
        #: Bytes the download actually read. Counted here because the download's
        #: ``with`` block closes the response, after which ``tell()`` raises.
        self.consumed = 0

    def read(self, *args, **kwargs) -> bytes:
        data = super().read(*args, **kwargs)
        self.consumed += len(data)
        return data


class _Opener:
    """Counts ``_open_url`` calls, so "never retried" is a measured count."""

    def __init__(self, response: _Response):
        self.response = response
        self.calls = 0

    def __call__(self, url: str, timeout: float) -> _Response:
        self.calls += 1
        return self.response


def test_declared_oversize_body_is_refused_before_any_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.core.exceptions import DownloadTooLargeError

    class _NeverRead(_Response):
        def read(self, *args, **kwargs):  # pragma: no cover - the refusal is first
            raise AssertionError("a refused transfer must not read the body")

    opener = _Opener(_NeverRead(b"x" * 64, declared=64))
    monkeypatch.setattr(download_utils, "_open_url", opener)

    with pytest.raises(DownloadTooLargeError):
        download_utils.download_file(URL, tmp_path, max_bytes=16)

    assert opener.calls == 1, "an oversize body is final, never retried"
    assert list(tmp_path.iterdir()) == [], "nothing may land at the destination"


def test_undeclared_body_is_aborted_once_the_bound_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.core.exceptions import DownloadTooLargeError

    body = bytes(8 * 1024 * 1024)
    response = _Response(body, declared=None)
    opener = _Opener(response)
    monkeypatch.setattr(download_utils, "_open_url", opener)

    with pytest.raises(DownloadTooLargeError):
        download_utils.download_file(URL, tmp_path, max_bytes=1024 * 1024)

    assert response.consumed < len(body), "the stream must be cut, not drained"
    assert opener.calls == 1, "an oversize body is final, never retried"
    assert list(tmp_path.iterdir()) == [], "nothing may land at the destination"


def test_body_exactly_at_the_bound_lands_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b"a" * 4096
    monkeypatch.setattr(
        download_utils, "_open_url", _Opener(_Response(body, declared=len(body)))
    )

    landed = download_utils.download_file(URL, tmp_path, max_bytes=len(body))

    assert landed.read_bytes() == body
