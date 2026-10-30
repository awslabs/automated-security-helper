# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the detect-secrets worker writes, and how it finds a secret's column.

Four readings of the worker's OUTPUT. A secret both in the baseline and still in
the code is in the collection twice (the baseline's copy under the file name the
baseline wrote, the scanned copy under the absolute name), and was reported twice;
the baseline's copy is now left out where the scan found the secret again. A
baseline with no ``results`` mapping made ``load_from_baseline`` raise and failed
the scan; it now loads as an empty collection. The column was the first occurrence
of the value in its line, which was wrong when the value started a longer secret
earlier in the line or spelled the variable it is assigned to; a whole token that
is not a key is preferred. And OUTPUT was created with the default mode where the
request file beside it is 0600. The values here are placeholders.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import detect_secrets_worker

pytestmark = pytest.mark.unit


def _secret(filename: str, value, line: int = 1, kind: str = "Secret Keyword"):
    return SimpleNamespace(
        filename=filename,
        secret_value=value,
        line_number=line,
        type=kind,
        secret_hash="h-" + (value or "baseline"),
        is_secret=None,
        json=lambda: {"filename": filename, "line_number": line, "type": kind},
    )


@pytest.mark.parametrize(
    ("line", "value", "index"),
    [
        # The value starts a longer secret earlier in the line: the whole token wins.
        ("key=ABCDEF other=ABC", "ABC", 17),
        # The value spells the variable it is assigned to: the key is passed over.
        ("password=password", "password", 9),
        ("password: password", "password", 10),
        # The same with spaces around the operator, and with the key quoted as
        # JSON, TOML / HCL and PHP write it: the quote and the spaces between the
        # key and its operator do not make the key a value.
        ("password = password", "password", 11),
        ('{"password": "password"}', "password", 14),
        ('"password" = "password"', "password", 14),
        ("'password' => 'password'", "password", 15),
        # A quoted value followed by a comma or a bracket is still the value.
        ('["password", "other"]', "password", 2),
        # The only occurrence, bounded or not, is still found.
        ("token=ABC", "ABC", 6),
        ("xABCx", "ABC", 1),
        ("nothing here", "ABC", -1),
    ],
)
def test_the_column_prefers_a_whole_token_that_is_not_a_key(line, value, index):
    assert detect_secrets_worker._value_index(line, value) == index


def test_the_baselines_copy_of_a_secret_found_again_is_reported_once(tmp_path):
    root = str(tmp_path)
    scanned = _secret(os.path.join(root, "a.txt"), "placeholder-one")
    from_baseline = _secret("a.txt", None)
    from_baseline.secret_hash = scanned.secret_hash
    still_only_in_baseline = _secret("b.txt", None)
    collection = SimpleNamespace(
        root=root,
        data={
            # A multi-file scan: both copies under the relative key.
            "a.txt": [from_baseline, scanned],
            "b.txt": [still_only_in_baseline],
        },
    )

    output = detect_secrets_worker._output_of(collection, set())

    assert [(key, len(records)) for key, records in output] == [
        ("a.txt", 1),
        ("b.txt", 1),
    ]
    assert output[0][1][0]["filename"] == scanned.filename


def test_a_lone_files_absolute_key_matches_the_baselines_relative_key(tmp_path):
    root = str(tmp_path)
    absolute = os.path.join(root, "a.txt")
    scanned = _secret(absolute, "placeholder-one")
    from_baseline = _secret("a.txt", None)
    from_baseline.secret_hash = scanned.secret_hash
    collection = SimpleNamespace(
        root=root, data={"a.txt": [from_baseline], absolute: [scanned]}
    )

    output = detect_secrets_worker._output_of(collection, set())

    assert [(key, len(records)) for key, records in output] == [
        ("a.txt", 0),
        (absolute, 1),
    ]


def test_a_baseline_without_results_loads_as_an_empty_collection():
    pytest.importorskip("detect_secrets")
    for baseline in ({"version": "1.5.0"}, {"version": "1.5.0", "results": None}, None):
        collection = detect_secrets_worker._collection_from(baseline)
        assert dict(collection.data) == {}
    loaded = detect_secrets_worker._collection_from(
        {
            "version": "1.5.0",
            "results": {
                "a.txt": [
                    {
                        "type": "Secret Keyword",
                        "hashed_secret": "0" * 40,
                        "line_number": 1,
                    }
                ]
            },
        }
    )
    assert list(loaded.data) == ["a.txt"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_output_is_created_readable_by_this_account_alone(tmp_path):
    output = tmp_path / "out.json"
    detect_secrets_worker._write_output(str(output), [["a.txt", []]])
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == [["a.txt", []]]
    with pytest.raises(FileExistsError):
        detect_secrets_worker._write_output(str(output), [])
