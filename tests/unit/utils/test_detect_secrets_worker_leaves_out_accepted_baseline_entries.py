# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker leaves out a baseline entry the audit accepted.

The worker loads the baseline into the collection it then scans into, so every
baseline entry was in its output, and the scanner turned each into a failure:
one the baseline's audit had marked ``is_secret: false`` (accepted as not a
secret) was reported as a finding all the same. An unaudited entry, or one
audited as a secret, is still reported. The values here are placeholders, never
credentials.
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


def _request(tmp_path, baseline):
    target = tmp_path / "f.txt"
    target.write_text(
        'password = "' + ACCEPTED_VALUE + '"\n'  # pragma: allowlist secret
        'secret = "' + UNAUDITED_VALUE + '"\n',  # pragma: allowlist secret
        encoding="utf-8",
    )
    return {
        "root": str(tmp_path),
        "baseline": baseline,
        "settings": SETTINGS,
        "paths": [str(target)],
        "verify": False,
    }


def _hashes(result):
    return sorted(
        secret["hashed_secret"] for _key, secrets in result for secret in secrets
    )


def test_an_entry_the_audit_accepted_is_left_out(tmp_path, quiet_worker):
    baseline = _baseline([(ACCEPTED_VALUE, 1, False), (UNAUDITED_VALUE, 2, None)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline))

    assert _hashed(ACCEPTED_VALUE) not in _hashes(result)
    assert _hashed(UNAUDITED_VALUE) in _hashes(result)


def test_an_entry_audited_as_a_secret_is_reported(tmp_path, quiet_worker):
    baseline = _baseline([(ACCEPTED_VALUE, 1, True)])

    result = detect_secrets_worker.run(_request(tmp_path, baseline))

    assert _hashed(ACCEPTED_VALUE) in _hashes(result)
    assert _hashed(UNAUDITED_VALUE) in _hashes(result)


def test_without_a_baseline_every_secret_is_reported(tmp_path, quiet_worker):
    result = detect_secrets_worker.run(_request(tmp_path, None))

    assert _hashes(result) == sorted(
        [_hashed(ACCEPTED_VALUE), _hashed(UNAUDITED_VALUE)]
    )
