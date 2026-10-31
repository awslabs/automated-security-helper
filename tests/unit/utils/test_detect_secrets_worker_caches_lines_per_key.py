# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker's line cache lives for one key, not the whole run.

The column a secret starts at is read from its file's lines, cached so a file is
read once however many secrets it holds. The cache used to be one dict for the
whole collection, so by the end of a run it held every finding file's lines at
once. It is now built per key (every secret under one key is in one file) and
released with that key's records. The values here are placeholders.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.utils import detect_secrets_worker

pytestmark = pytest.mark.unit


def _secret(filename: str, value: str, line: int) -> SimpleNamespace:
    return SimpleNamespace(
        filename=filename,
        secret_value=value,
        line_number=line,
        type="Secret Keyword",
        secret_hash="h-" + value,
        is_secret=None,
        json=lambda: {"filename": filename, "line_number": line},
    )


def test_the_cache_holds_one_file_and_starts_afresh_for_each_key(tmp_path, monkeypatch):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("a = placeholder-one\nb = placeholder-two\n", encoding="utf-8")
    second.write_text("c = placeholder-three\n", encoding="utf-8")
    caches: list = []
    real = detect_secrets_worker._with_column

    #: What each cache held right after the column was read, copied then: the
    #: worker may release a cache sooner, and the dict is read after that.
    held: list = []

    def observed(secret, lines_by_file):
        result = real(secret, lines_by_file)
        caches.append(lines_by_file)
        held.append(set(lines_by_file))
        return result

    monkeypatch.setattr(detect_secrets_worker, "_with_column", observed)

    records = {
        key: detect_secrets_worker._records_of(key, secrets, set(), str(tmp_path))
        for key, secrets in {
            "first.txt": [
                _secret(str(first), "placeholder-one", 1),
                _secret(str(first), "placeholder-two", 2),
            ],
            "second.txt": [_secret(str(second), "placeholder-three", 1)],
        }.items()
    }

    # The columns were read: every record carries one.
    assert [
        r[detect_secrets_worker.START_COLUMN_KEY] for r in records["first.txt"]
    ] == [5, 5]
    assert records["second.txt"][0][detect_secrets_worker.START_COLUMN_KEY] == 5
    # Two keys, two caches; the second key's cache never saw the first file.
    assert len(caches) == 3
    assert caches[0] is caches[1] and caches[2] is not caches[0]
    assert held[0] == {str(first)}
    assert held[2] == {str(second)}
