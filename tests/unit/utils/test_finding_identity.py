# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared finding identity in ``utils/finding_identity.py``.

The flattened findings' ``id`` and the Security Hub reporter's ``Id`` are both taken
from these keys, so their shape is pinned here: a change to it re-keys every finding
in both places at once.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import Message, Result
from automated_security_helper.utils.finding_identity import (
    canonical,
    finding_id,
    finding_identity,
    identity_key,
    identity_keys,
    occurrence_digest,
    relative_path,
    result_fingerprints,
)

pytestmark = pytest.mark.unit


def _identity(**overrides):
    values = {
        "scanner": "bandit",
        "rule_id": "B602",
        "file_path": "src/app.py",
        "line_start": 3,
        "line_end": 4,
    }
    values.update(overrides)
    return finding_identity(**values)


def _fingerprinted(value: str, line: int, scanner: str = "semgrep", **overrides):
    return _identity(
        scanner=scanner,
        rule_id="r",
        line_start=line,
        line_end=line,
        fingerprints=(("fingerprints", (("matchBasedId/v1", value),)),),
        **overrides,
    )


def test_the_key_for_fixed_inputs_is_pinned():
    """Pinned as literals, so the flat ids and the Security Hub reporter, which
    hashes this key with the scan target, notice the same drift."""
    identity = _identity(
        package_name="left-pad",
        package_path="node_modules/left-pad",
        workspace_project="api",
        column=7,
        message="a secret",
    )

    key = identity_key(identity)

    assert key == {
        "scanner": "bandit",
        "rule": "B602",
        "file": "src/app.py",
        "package": ["left-pad", "node_modules/left-pad"],
        "project": "api",
        "startLine": 3,
        "endLine": 4,
    }
    assert canonical(key) == (
        '{"endLine":4,"file":"src/app.py","package":["left-pad",'
        '"node_modules/left-pad"],"project":"api","rule":"B602","scanner":"bandit",'
        '"startLine":3}'
    )
    assert finding_id(key) == "bandit-B602-39694db619d2"


def test_the_occurrence_is_sha256_of_json_dumps_of_the_column_and_message():
    """json.dumps with its defaults, as the Security Hub reporter computes it."""
    assert (
        occurrence_digest(7, "a secret")
        == (hashlib.sha256(b'[7, "a secret"]').hexdigest()[:8])
    )
    assert occurrence_digest(None, "m") == hashlib.sha256(b'[-1, "m"]').hexdigest()[:8]
    assert occurrence_digest(0, "m") == hashlib.sha256(b'[0, "m"]').hexdigest()[:8]
    assert (
        occurrence_digest(1, "caf\u00e9")
        == (hashlib.sha256(b'[1, "caf\\u00e9"]').hexdigest()[:8])
    )


def test_findings_sharing_a_key_carry_occurrences_and_duplicates_ordinals():
    same = _identity(column=7, message="a secret")
    other = _identity(column=9, message="a secret")

    keys = identity_keys([same, other, same, same])

    assert [key["occurrence"] for key in keys] == [
        occurrence_digest(7, "a secret"),
        occurrence_digest(9, "a secret"),
        occurrence_digest(7, "a secret"),
        occurrence_digest(7, "a secret"),
    ]
    assert [key.get("ordinal") for key in keys] == [None, None, 1, 2]


def test_a_finding_alone_with_its_key_has_no_occurrence():
    key = identity_key(_identity(column=7, message="m"))

    assert not {"occurrence", "ordinal"} & set(key)


def test_rewording_a_finding_alone_with_its_key_keeps_its_id():
    assert _ids(_identity(message="old wording")) == _ids(
        _identity(message="new wording")
    )


def test_a_second_finding_with_the_key_of_one_alone_moves_its_id():
    """The cost of keeping rewording from re-keying a lone finding."""
    alone = _ids(_identity(column=5, message="m"))
    paired = _ids(_identity(column=5, message="m"), _identity(column=9, message="m"))

    assert paired[0] != alone[0]


def _ids(*identities):
    return [finding_id(key) for key in identity_keys(identities)]


def test_a_newcomer_at_an_earlier_column_moves_no_id():
    first, second = _identity(column=20, message="m"), _identity(column=40, message="m")
    newcomer = _identity(column=5, message="m")

    before = _ids(first, second)
    after = _ids(newcomer, first, second)

    assert after[1:] == before
    assert len(set(after)) == 3


def test_fixing_one_finding_moves_no_other_id():
    one, two, three = (_identity(column=c, message="m") for c in (5, 20, 40))

    before = _ids(one, two, three)

    assert _ids(one, three) == [before[0], before[2]]


def test_rewording_one_of_two_messages_without_a_column_moves_only_its_id():
    before = _ids(_identity(message="first"), _identity(message="second"))
    after = _ids(_identity(message="first"), _identity(message="second, reworded"))

    assert after[0] == before[0]
    assert after[1] != before[1]


def test_a_finding_with_no_location_is_told_apart_by_its_message():
    nowhere = {"file_path": None, "line_start": None, "line_end": None}
    keys = identity_keys(
        [
            _identity(message="the first message", **nowhere),
            _identity(message="the second message", **nowhere),
        ]
    )

    assert keys[0] != keys[1]
    assert "the first message" not in canonical(keys[0])


def test_a_unique_fingerprint_replaces_the_lines_and_keeps_the_file():
    key = identity_key(_fingerprinted("abc", 10, package_name="p"))

    assert key["fingerprints"] == [["matchBasedId/v1", "abc"]]
    assert key["file"] == "src/app.py"
    assert key["package"] == ["p", None]
    assert not {"startLine", "endLine", "occurrence", "ordinal"} & set(key)


def test_a_fingerprinted_finding_keeps_its_id_when_it_moves():
    assert _ids(_fingerprinted("abc", 10)) == _ids(_fingerprinted("abc", 42))


def test_fingerprinted_findings_at_one_location_get_no_occurrence():
    """Two unique fingerprints on one line, with different columns and messages:
    keyed by the fingerprints alone, with no occurrence and no ordinal."""
    keys = identity_keys(
        [
            _fingerprinted("abc", 10, column=3, message="one"),
            _fingerprinted("def", 10, column=30, message="two"),
        ]
    )

    assert keys[0] != keys[1]
    for key in keys:
        assert not {"occurrence", "ordinal", "startLine"} & set(key), key


def test_one_fingerprint_at_one_location_twice_gets_occurrences_and_ordinals():
    """Two results of one scanner and rule carrying the same fingerprint value at
    the same lines and column: the value is shared only across locations, so it
    stayed the key of both and they had one finding id and one Security Hub Id."""
    keys = identity_keys(
        [
            _fingerprinted("abc", 10, column=3, message="one"),
            _fingerprinted("abc", 10, column=3, message="two"),
            _fingerprinted("abc", 10, column=3, message="two"),
        ]
    )

    assert all("fingerprints" in key for key in keys)
    assert len({canonical(key) for key in keys}) == 3
    assert [key.get("ordinal") for key in keys] == [None, None, 1]
    assert keys[0]["occurrence"] != keys[1]["occurrence"]


def test_one_fingerprint_at_two_columns_of_a_line_counts_as_absent():
    """A location is the file, the lines and the column."""
    keys = identity_keys(
        [
            _fingerprinted("abc", 10, column=3, message="m"),
            _fingerprinted("abc", 10, column=30, message="m"),
        ]
    )

    assert all("fingerprints" not in key for key in keys)
    assert keys[0]["occurrence"] != keys[1]["occurrence"]


def test_a_placeholder_fingerprint_counts_as_absent():
    """semgrep 1.180 writes this on every result; compared in any case."""
    for value in ("requires login", " Requires Login"):
        result = Result(
            ruleId="r",
            message=Message(text="m"),
            fingerprints={"matchBasedId/v1": value},
        )

        assert result_fingerprints(result) == ()


def test_a_fingerprint_shared_by_results_at_different_locations_counts_as_absent():
    keys = identity_keys([_fingerprinted("same", 10), _fingerprinted("same", 20)])

    assert all("fingerprints" not in key for key in keys)
    assert keys[0] != keys[1]


def test_a_fingerprint_another_scanner_carries_is_not_shared():
    """Counted per scanner, rule, file, package, project and tree, which the key
    holds already, so the same value from another scanner still tells the two
    findings apart."""
    keys = identity_keys(
        [_fingerprinted("same", 10), _fingerprinted("same", 20, scanner="other")]
    )

    assert [key.get("fingerprints") for key in keys] == [
        [["matchBasedId/v1", "same"]],
        [["matchBasedId/v1", "same"]],
    ]
    assert keys[0] != keys[1]


def test_a_fingerprint_in_another_file_moves_no_id():
    """A value both files carry: fixing the finding in one file re-keys nothing
    in the other, and another scanner's finding with that value in a third file
    re-keys nothing either."""
    a = _fingerprinted("same", 10, file_path="src/a.py")
    b = _fingerprinted("same", 20, file_path="src/b.py")
    elsewhere = _fingerprinted("same", 30, scanner="other", file_path="src/c.py")

    alone = _ids(a)

    assert _ids(a, b)[0] == alone[0]
    assert _ids(b, a)[1] == alone[0]
    assert _ids(a, elsewhere)[0] == alone[0]
    assert _ids(a, b)[1] == _ids(b)[0]
    assert len(set(_ids(a, b, elsewhere))) == 3


def test_a_fingerprint_in_another_project_moves_no_id():
    a = _fingerprinted("same", 10, workspace_project="api")
    b = _fingerprinted("same", 20, workspace_project="web")

    assert _ids(a, b)[0] == _ids(a)[0]


def test_a_fingerprint_shared_under_the_runs_project_counts_as_absent():
    """The run's project stands in before the count, so a result that names the
    project and one that takes it from the run are counted together: their keys
    are otherwise the same."""
    keys = identity_keys(
        [
            _fingerprinted("same", 10),
            _fingerprinted("same", 20, workspace_project="api"),
        ],
        default_project="api",
    )

    assert all("fingerprints" not in key for key in keys)
    assert keys[0] != keys[1]


def test_the_runs_project_stands_in_for_a_result_without_one():
    keys = identity_keys(
        [_identity(), _identity(workspace_project="web")], default_project="api"
    )

    assert [key["project"] for key in keys] == ["api", "web"]


def test_fingerprints_win_over_partial_fingerprints_and_placeholders_are_dropped():
    result = Result(
        ruleId="R",
        message=Message(text="m"),
        fingerprints={"b": "2", "a": "1", "c": "requires login"},
        partialFingerprints={"c": "3"},
    )

    assert result_fingerprints(result) == (
        ("fingerprints", (("a", "1"), ("b", "2"))),
        ("partialFingerprints", (("c", "3"),)),
    )


def test_a_missing_rule_reads_unknown():
    assert identity_key(_identity(rule_id=None))["rule"] == "unknown"


def test_a_converted_file_is_keyed_in_its_own_tree():
    key = identity_key(_identity(file_path="jupyter/nb-converted.py", converted=True))

    assert key["tree"] == "converted"
    assert key != identity_key(_identity(file_path="jupyter/nb-converted.py"))


def test_the_id_is_scanner_rule_and_twelve_hex_digits():
    scanner, rule, digest = finding_id(identity_key(_identity())).rsplit("-", 2)

    assert (scanner, rule) == ("bandit", "B602")
    assert len(digest) == 12
    int(digest, 16)


def test_paths_are_normalized_the_same_way_everywhere(tmp_path):
    assert relative_path("./src/app.py") == "src/app.py"
    assert relative_path("src/./app.py") == "src/app.py"
    assert relative_path("sub/../src/app.py") == "src/app.py"
    # A relative path's backslash is part of a POSIX file name; a drive-letter
    # path's backslashes are separators.
    assert relative_path("src\\win\\app.py") == "src\\win\\app.py"
    assert relative_path("C:\\repo\\src\\app.py") == "C:/repo/src/app.py"
    assert relative_path(str(tmp_path / "src" / "app.py"), tmp_path) == "src/app.py"
    assert relative_path(f"{tmp_path}/x/../src/app.py", tmp_path) == "src/app.py"
    assert relative_path("C:\\repo\\src\\app.py", "C:\\repo") == "src/app.py"
    outside = Path("/elsewhere/app.py")
    assert relative_path(str(outside), tmp_path) == outside.as_posix()
    assert relative_path(None) is None
