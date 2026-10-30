# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker leaves out a baseline entry the audit accepted, but
only for a baseline the operator named.

The worker loads the baseline into the collection it then scans into, so every
baseline entry was in its output, and the scanner turned each into a failure:
one the baseline's audit had marked ``is_secret: false`` (accepted as not a
secret) was reported as a finding all the same. An unaudited entry, or one
audited as a secret, is still reported. The drop is gated on the request's
``baseline_trusted`` flag: a baseline the scanned repository wrote (the in-tree
default) may mark an entry but may not remove it, so without the flag every entry
is reported as before. The values here are placeholders, never credentials.
"""

from __future__ import annotations

import multiprocessing

import pytest

from automated_security_helper.utils import detect_secrets_worker

pytestmark = pytest.mark.unit

ACCEPTED_VALUE = "example-placeholder-one"
UNAUDITED_VALUE = "example-placeholder-two"

SETTINGS = {"plugins_used": [{"name": "KeywordDetector"}], "filters_used": []}


def _hashed(value: str) -> str:
    from detect_secrets.core.potential_secret import PotentialSecret

    return PotentialSecret.hash_secret(value)


def _baseline(entries):
    return {
        "version": "1.5.0",
        "plugins_used": SETTINGS["plugins_used"],
        "filters_used": [],
        "results": {
            "f.txt": [
                {
                    "type": "Secret Keyword",
                    "hashed_secret": _hashed(value),
                    "is_verified": False,
                    "line_number": line,
                    **({} if is_secret is None else {"is_secret": is_secret}),
                }
                for value, line, is_secret in entries
            ]
        },
    }


@pytest.fixture
def quiet_worker(monkeypatch):
    """run() without its process-wide side effects: the requests patch and the
    multiprocessing start method are not this test's subject."""
    monkeypatch.setattr(detect_secrets_worker, "refuse_http_requests", lambda: None)
    monkeypatch.setattr(multiprocessing, "set_start_method", lambda *a, **k: None)
    # run() sets the refusal variable while it scans and puts it back. Set, then
    # delete, so the teardown records the key as absent: a delenv of an absent key
    # records no undo, and a restore that regressed would leave the variable set
    # for every later worker in the session.
    monkeypatch.setenv(detect_secrets_worker.REFUSE_HTTP_ENV, "")
    monkeypatch.delenv(detect_secrets_worker.REFUSE_HTTP_ENV)


#: ``_request``'s default: the flag is left out of the request. ``None`` is a
#: value, sent as JSON null.
_ABSENT = object()


def _request(tmp_path, baseline, trusted=_ABSENT):
    """A worker request; the default leaves the flag out, as a scanner that
    loaded the repository's own in-tree baseline does, and ``None`` sends null."""
    target = tmp_path / "f.txt"
    target.write_text(
        'password = "' + ACCEPTED_VALUE + '"\n'  # pragma: allowlist secret
        'secret = "' + UNAUDITED_VALUE + '"\n',  # pragma: allowlist secret
        encoding="utf-8",
    )
    request = {
        "root": str(tmp_path),
        "baseline": baseline,
        "settings": SETTINGS,
        "paths": [str(target)],
        "verify": False,
    }
    if trusted is not _ABSENT:
        request[detect_secrets_worker.BASELINE_TRUSTED_KEY] = trusted
    return request


def _hashes(result):
    return sorted(
        secret["hashed_secret"] for _key, secrets in result for secret in secrets
    )


def test_an_entry_the_audit_accepted_is_left_out(tmp_path, quiet_worker):
    baseline = _baseline([(ACCEPTED_VALUE, 1, False), (UNAUDITED_VALUE, 2, None)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline, trusted=True))

    assert _hashed(ACCEPTED_VALUE) not in _hashes(result)
    assert _hashed(UNAUDITED_VALUE) in _hashes(result)


def test_an_accepted_entry_of_an_untrusted_baseline_is_still_reported(
    tmp_path, quiet_worker
):
    """The in-tree baseline is the repository's own text: its audit may not drop a
    finding, so a request that does not mark the baseline trusted reports the
    accepted entry as before."""
    baseline = _baseline([(ACCEPTED_VALUE, 1, False), (UNAUDITED_VALUE, 2, None)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline))

    # The baseline's own entries are in OUTPUT beside the scan's (under the
    # baseline's key), so the accepted value appears twice and nothing is left
    # out: the set of hashes is both values, and the accepted one is present.
    assert set(_hashes(result)) == {_hashed(ACCEPTED_VALUE), _hashed(UNAUDITED_VALUE)}
    assert _hashes(result).count(_hashed(ACCEPTED_VALUE)) >= 1


@pytest.mark.parametrize("value", [False, "true", 1, None], ids=repr)
def test_only_the_json_true_marks_a_baseline_trusted(tmp_path, quiet_worker, value):
    """``None`` is sent as JSON null: the case where the flag is left out is the
    untrusted-baseline test above."""
    baseline = _baseline([(ACCEPTED_VALUE, 1, False)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline, trusted=value))

    assert _hashed(ACCEPTED_VALUE) in _hashes(result)


def test_an_entry_audited_as_a_secret_is_reported(tmp_path, quiet_worker):
    baseline = _baseline([(ACCEPTED_VALUE, 1, True)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline, trusted=True))

    assert _hashed(ACCEPTED_VALUE) in _hashes(result)
    assert _hashed(UNAUDITED_VALUE) in _hashes(result)


def test_without_a_baseline_every_secret_is_reported(tmp_path, quiet_worker):
    result = detect_secrets_worker.run(_request(tmp_path, None))

    assert _hashes(result) == sorted(
        [_hashed(ACCEPTED_VALUE), _hashed(UNAUDITED_VALUE)]
    )
