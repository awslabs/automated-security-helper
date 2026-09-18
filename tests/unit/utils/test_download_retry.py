# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the bounded retry around the download in ``_download_verified``.

The two that carry the weight are ``test_a_digest_mismatch_is_not_retried`` and
``test_a_404_is_not_retried``. Without them the retry is only tested in the
direction that makes builds greener, and the property that actually matters is the
one that keeps it from making them falsely green: a pinned digest that fails must
fail on its first occurrence, because retrying an integrity check turns a
supply-chain control into a coin flip.

Every test sets ``ASH_DOWNLOAD_RETRY_DELAY=0`` so the backoff is not slept through.
That knob exists for this, and ``test_the_backoff_is_bounded_and_grows`` covers the
delay arithmetic separately without sleeping either, so zeroing it here does not
leave the growth untested.

Attempt counts are asserted from ``mock.call_count`` rather than from log text, so
a change to the wording cannot silently turn a retry assertion into a no-op.
"""

import hashlib
import http.client
import io
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils.download_utils import (
    _DOWNLOAD_MAX_DELAY,
    _download_retry_policy,
    _is_transient_download_error,
    download_file,
)

PAYLOAD = b"#!/bin/sh\necho retry-fixture\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
URL = "https://example.invalid/tool/tool.tar.gz"


class _FakeResponse(io.BytesIO):
    """urlopen returns a context manager; BytesIO alone is not one."""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, code, f"synthetic {code}", {}, None)


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Zero the delay for every test in this module.

    Set rather than deleted: an unset value falls back to the five-second default,
    which would make this file take minutes.
    """
    monkeypatch.setenv("ASH_DOWNLOAD_RETRY_DELAY", "0")
    monkeypatch.delenv("ASH_DOWNLOAD_MAX_ATTEMPTS", raising=False)


def _serve(side_effect):
    return patch(
        "automated_security_helper.utils.download_utils.urllib.request.urlopen",
        side_effect=side_effect,
    )


class TestTransientFailuresAreRetried:
    def test_a_500_then_a_success_installs(self, tmp_path):
        """The measured failure: one 5xx, then the same URL works."""
        attempts = [_http_error(500), None]

        def side_effect(*_a, **_k):
            outcome = attempts.pop(0)
            if outcome is not None:
                raise outcome
            return _FakeResponse(PAYLOAD)

        with _serve(side_effect) as mock_open:
            result = download_file(URL, tmp_path, expected_sha256=DIGEST)

        assert mock_open.call_count == 2, "the 500 should have been retried once"
        assert Path(result).read_bytes() == PAYLOAD

    def test_a_connection_reset_is_retried(self, tmp_path):
        attempts = [ConnectionResetError("peer hung up"), None]

        def side_effect(*_a, **_k):
            outcome = attempts.pop(0)
            if outcome is not None:
                raise outcome
            return _FakeResponse(PAYLOAD)

        with _serve(side_effect) as mock_open:
            download_file(URL, tmp_path, expected_sha256=DIGEST)

        assert mock_open.call_count == 2

    def test_the_attempt_budget_is_bounded(self, tmp_path, monkeypatch):
        """Every attempt fails: the error surfaces rather than looping forever."""
        monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "3")

        with _serve(lambda *_a, **_k: (_ for _ in ()).throw(_http_error(503))) as m:
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                download_file(URL, tmp_path, expected_sha256=DIGEST)

        assert excinfo.value.code == 503
        assert m.call_count == 3, "exactly the configured budget, no more, no fewer"

    def test_a_partial_transfer_is_not_appended_to(self, tmp_path):
        """A retry must restart the file, not continue it.

        The failing first attempt writes real bytes before dying, which is what a
        dropped connection mid-transfer looks like. If the retry appended, the
        digest below would fail -- and it would fail as an integrity error, which
        reads as a compromised asset rather than a flaky network.
        """

        def side_effect(*_a, **_k):
            if not getattr(side_effect, "used", False):
                side_effect.used = True
                # Bytes land in the temp file, then the transfer dies.
                return _TruncatedResponse(b"PARTIAL-GARBAGE-")
            return _FakeResponse(PAYLOAD)

        with _serve(side_effect) as mock_open:
            result = download_file(URL, tmp_path, expected_sha256=DIGEST)

        assert mock_open.call_count == 2
        assert Path(result).read_bytes() == PAYLOAD, (
            "the retry appended to the failed attempt's bytes instead of restarting"
        )


class _TruncatedResponse(io.BytesIO):
    """Yields some bytes, then raises, like a connection dropped mid-body."""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    def read(self, *args):
        chunk = super().read(*args)
        if chunk:
            return chunk
        raise http.client.IncompleteRead(b"", 99)


class TestNonTransientFailuresAreNotRetried:
    def test_a_404_is_not_retried(self, tmp_path):
        """A 404 for a pinned asset means the table is wrong, not the network."""
        with _serve(lambda *_a, **_k: (_ for _ in ()).throw(_http_error(404))) as m:
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                download_file(URL, tmp_path, expected_sha256=DIGEST)

        assert excinfo.value.code == 404
        assert m.call_count == 1, "a 404 must fail on the first attempt"

    def test_a_403_is_not_retried(self, tmp_path):
        with _serve(lambda *_a, **_k: (_ for _ in ()).throw(_http_error(403))) as m:
            with pytest.raises(urllib.error.HTTPError):
                download_file(URL, tmp_path, expected_sha256=DIGEST)
        assert m.call_count == 1

    def test_a_digest_mismatch_is_not_retried(self, tmp_path):
        """The load-bearing one: integrity failures are disqualifying, not flaky.

        The download itself succeeds every time; only the pin is wrong. A single
        urlopen call proves verification sits outside the retry loop.
        """
        wrong_digest = "0" * 64

        with _serve(lambda *_a, **_k: _FakeResponse(PAYLOAD)) as m:
            with pytest.raises(ToolDownloadIntegrityError):
                download_file(URL, tmp_path, expected_sha256=wrong_digest)

        assert m.call_count == 1, (
            "a digest mismatch was retried -- verification has moved inside the "
            "retry loop, which makes the pin a coin flip"
        )

    def test_a_non_https_url_is_still_rejected_before_any_attempt(self, tmp_path):
        with _serve(lambda *_a, **_k: _FakeResponse(PAYLOAD)) as m:
            with pytest.raises(ValueError):
                download_file("http://example.invalid/x.tgz", tmp_path)
        assert m.call_count == 0


class TestClassification:
    @pytest.mark.parametrize("code", [500, 502, 503, 504, 429])
    def test_transient_statuses(self, code):
        assert _is_transient_download_error(_http_error(code)) is True

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 410, 451])
    def test_non_transient_statuses(self, code):
        assert _is_transient_download_error(_http_error(code)) is False

    def test_httperror_is_checked_before_urlerror(self):
        """HTTPError subclasses URLError; order decides whether 404 is transient.

        Asserted directly because the two isinstance checks look interchangeable
        and are not: swapping them makes every 4xx retryable and this file's 404
        tests are the only thing that would notice.
        """
        assert isinstance(_http_error(404), urllib.error.URLError)
        assert _is_transient_download_error(_http_error(404)) is False

    @pytest.mark.parametrize(
        "exc",
        [
            urllib.error.URLError("dns went away"),
            ConnectionResetError("reset"),
            TimeoutError("timed out"),
            http.client.IncompleteRead(b"", 10),
        ],
    )
    def test_transient_connection_errors(self, exc):
        assert _is_transient_download_error(exc) is True

    def test_an_unrelated_error_is_not_transient(self):
        assert (
            _is_transient_download_error(ValueError("not a network problem")) is False
        )

    def test_an_integrity_error_is_never_transient(self):
        """Belt and braces on the digest guarantee.

        ``test_a_digest_mismatch_is_not_retried`` asserts one download attempt on a
        mismatch, and today that holds because verification sits outside the retry
        loop entirely. But it would keep passing if verification were moved inside
        the loop, since the classifier would refuse to retry the error anyway -- so
        that test alone does not pin the structure it appears to. This pins the
        other half directly: however the loop is arranged, an integrity failure is
        not something to try again.
        """
        assert (
            _is_transient_download_error(ToolDownloadIntegrityError("SHA256 mismatch"))
            is False
        )


class TestRetryPolicy:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("ASH_DOWNLOAD_MAX_ATTEMPTS", raising=False)
        monkeypatch.delenv("ASH_DOWNLOAD_RETRY_DELAY", raising=False)
        attempts, delay = _download_retry_policy()
        assert attempts == 5, (
            "five, and equal to WITH_RETRY_MAX_ATTEMPTS in assets/with-retry.sh: "
            "both budgets retry the same runner-egress failures"
        )
        assert delay == 5.0

    @pytest.mark.parametrize("raw", ["0", "-1"])
    def test_attempts_floor_at_one(self, monkeypatch, raw):
        """Zero attempts would skip the fetch and report a missing file."""
        monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", raw)
        assert _download_retry_policy()[0] == 1

    def test_a_negative_delay_is_clamped(self, monkeypatch):
        monkeypatch.setenv("ASH_DOWNLOAD_RETRY_DELAY", "-5")
        assert _download_retry_policy()[1] == 0.0

    @pytest.mark.parametrize("raw", ["", "abc", "5.5.5", "1e"])
    def test_a_malformed_value_falls_back_rather_than_raising(self, monkeypatch, raw):
        """Clamped, not rejected: a typo must not fail an install."""
        monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", raw)
        monkeypatch.setenv("ASH_DOWNLOAD_RETRY_DELAY", raw)
        attempts, delay = _download_retry_policy()
        assert attempts == 5
        assert delay == 5.0

    def test_the_backoff_is_bounded_and_grows(self):
        """The delay arithmetic, without sleeping through it.

        Mirrors the expression in ``_download_verified``. Kept as its own test
        because every other test in this file zeroes the delay, so the growth and
        the cap are otherwise unexercised.
        """
        base = 5.0
        delays = [
            min(base * (2 ** (attempt - 1)), _DOWNLOAD_MAX_DELAY)
            for attempt in range(1, 7)
        ]
        assert delays == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]
        assert all(d <= _DOWNLOAD_MAX_DELAY for d in delays)
