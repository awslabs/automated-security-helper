# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The run of identities as a frame: ``utils/finding_identity._identity_frame``.

The columns are documented in the module docstring of ``finding_identity``; this
pins them, and that the frame says what ``identity_keys`` says.
"""

from __future__ import annotations

import polars as pl
import pytest

from automated_security_helper.utils.finding_identity import (
    _identity_frame,
    canonical,
    finding_id,
    finding_identity,
    identity_keys,
)
from automated_security_helper.utils.frame_text import unwire, wire

pytestmark = pytest.mark.unit


def ident(scanner="s", rule="r", file="a.py", start=1, end=1, message="m", **extra):
    return finding_identity(
        scanner=scanner,
        rule_id=rule,
        file_path=file,
        line_start=start,
        line_end=end,
        message=message,
        **extra,
    )


SCHEMA = {
    "i": pl.Int64,
    "scanner": pl.String,
    "rule": pl.String,
    "file": pl.String,
    "key": pl.String,
    "fingerprinted": pl.Boolean,
    "occurrence": pl.String,
    "ordinal": pl.Int64,
}


def test_the_columns_and_their_types_are_the_documented_ones():
    frame = _identity_frame([ident()])
    assert dict(frame.schema) == SCHEMA
    assert list(frame.columns) == list(SCHEMA)


def test_the_id_column_is_there_only_when_asked_for():
    assert "id" not in _identity_frame([ident()]).columns
    frame = _identity_frame([ident()], ids=True)
    assert list(frame.columns) == [*SCHEMA, "id"]
    assert frame.schema["id"] == pl.String


def test_an_empty_run_is_an_empty_frame_with_the_schema():
    frame = _identity_frame([])
    assert frame.height == 0
    assert dict(frame.schema) == SCHEMA


def test_the_rows_say_what_the_keys_say():
    identities = [
        ident(message="x"),
        ident(message="x"),
        ident(message="y"),
        ident(file=None, rule=None, start=7, end=8),
        ident(
            scanner="t",
            start=3,
            end=3,
            fingerprints=(("fingerprints", (("k", "v"),)),),
        ),
    ]
    keys = identity_keys(identities)
    frame = _identity_frame(identities, ids=True)
    assert frame["i"].to_list() == list(range(5))
    assert frame["key"].to_list() == [canonical(key) for key in keys]
    assert frame["scanner"].to_list() == [key["scanner"] for key in keys]
    assert frame["rule"].to_list() == [key["rule"] for key in keys]
    assert frame["file"].to_list() == [key["file"] for key in keys]
    assert frame["fingerprinted"].to_list() == [False, False, False, False, True]
    assert frame["occurrence"].to_list() == [key.get("occurrence") for key in keys]
    assert frame["ordinal"].to_list() == [None, 1, None, None, None]
    assert frame["id"].to_list() == [finding_id(key) for key in keys]
    assert frame["rule"][3] == "unknown" and frame["file"][3] is None


def test_the_default_project_reaches_the_key_column():
    frame = _identity_frame([ident()], "dflt")
    assert '"project":"dflt"' in frame["key"][0]


def test_a_lone_surrogate_is_carried_and_comes_back():
    path = "dir/\udcff.py"
    identities = [ident(file=path), ident(file=path, message="n")]
    frame = _identity_frame(identities)
    assert frame["file"][0] == wire(path)
    assert unwire(frame["file"][0]) == path
    keys = identity_keys(identities)
    assert [unwire(text) for text in frame["key"]] == [canonical(key) for key in keys]
    # told apart from the same name with another undecodable byte
    other = _identity_frame([ident(file="dir/\udcfe.py")])
    assert other["file"][0] != frame["file"][0]


def test_the_id_of_a_key_that_holds_a_lone_surrogate_raises_as_finding_id_does():
    identities = [ident(file="dir/\udcff.py")]
    with pytest.raises(UnicodeEncodeError):
        finding_id(identity_keys(identities)[0])
    with pytest.raises(UnicodeEncodeError):
        _identity_frame(identities, ids=True)
    assert _identity_frame(identities).height == 1


def test_a_line_larger_than_64_bits_is_only_in_the_key_text():
    big = 10**30
    frame = _identity_frame([ident(start=big, end=big)])
    assert str(big) in frame["key"][0]
    assert dict(frame.schema) == SCHEMA


def test_the_keys_of_two_runs_join_on_the_key_column():
    before = _identity_frame([ident(message="a"), ident(start=9, end=9)])
    after = _identity_frame([ident(start=9, end=9), ident(start=2, end=2)])
    joined = before.join(after, on="key", suffix="_a")
    assert joined.select("i", "i_a").rows() == [(1, 0)]
