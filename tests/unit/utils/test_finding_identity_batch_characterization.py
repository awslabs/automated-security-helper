# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization of the batch layer: identity keys, ids, and flat suppressed counts.

What a run's results get for identity (``identity_keys``), the id each flattened
finding carries (``finding_id`` over that key), the occurrence digest, and the
per-scanner suppressed count ``to_flat_vulnerabilities`` sets are pinned here in
two ways.

* Scenarios whose expected value is written by hand as a literal: the key
  mappings, their key order, which findings carry an ``occurrence`` and an
  ``ordinal``, and the counts.
* A differential against ``_oracle_keys``, a verbatim copy of the pure-Python
  ``identity_keys`` and of the old suppressed-count loop as they stood before the
  batch layer moved onto a frame. The oracle never changes: a red here means the
  change is not behavior-identical. It runs over seeded random runs built from
  small alphabets, so that colliding keys, shared fingerprint values and exact
  duplicates are the common case, and over text a frame column cannot hold (a lone
  surrogate in a path, unbounded line numbers).

A golden is never edited to make a change pass.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_identity import (
    FINGERPRINT_KINDS,
    FindingIdentity,
    canonical,
    finding_id,
    finding_identity,
    identity_key,
    identity_keys,
    occurrence_digest,
)
from tests.unit.models._suppressed_count_helpers import (
    OTHER,
    SCANNER,
    build_model,
    dict_report,
    suppressed_result,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# The oracle: the implementation before the batch layer moved onto a frame
# --------------------------------------------------------------------------- #


def _oracle_shared(identities, bases):
    locations: Dict[Any, set] = defaultdict(set)
    for identity, base in zip(identities, bases):
        for kind, pairs in identity.fingerprints:
            for name, value in pairs:
                locations[(base, kind, name, value)].add(identity.location)
    return {entry for entry, where in locations.items() if len(where) > 1}


def _oracle_keys(identities, default_project=None):
    bases = []
    for identity in identities:
        base = dict(identity.base)
        if base.get("project") is None and default_project:
            base["project"] = default_project
        bases.append(base)
    canonical_bases = [canonical(base) for base in bases]
    shared = _oracle_shared(identities, canonical_bases)
    keys = []
    by_location: Dict[str, List[int]] = defaultdict(list)
    for index, identity in enumerate(identities):
        key = dict(bases[index])
        for kind, pairs in identity.fingerprints:
            usable = [
                [name, value]
                for name, value in pairs
                if (canonical_bases[index], kind, name, value) not in shared
            ]
            if usable:
                key[kind] = usable
                break
        else:
            key["startLine"], key["endLine"] = identity.lines
        by_location[canonical(key)].append(index)
        keys.append(key)
    for members in by_location.values():
        if len(members) < 2:
            continue
        seen: Dict[str, int] = defaultdict(int)
        for index in members:
            occurrence = identities[index].occurrence
            keys[index]["occurrence"] = occurrence
            if seen[occurrence]:
                keys[index]["ordinal"] = seen[occurrence]
            seen[occurrence] += 1
    return keys


def _oracle_id(key):
    digest = hashlib.sha256(canonical(key).encode("utf-8")).hexdigest()
    return f"{key.get('scanner')}-{key.get('rule') or 'unknown'}-{digest[:12]}"


def _oracle_occurrence(column, message):
    text = json.dumps([-1 if column is None else column, message or ""])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def _oracle_suppressed_flat_counts(flat_vulns):
    counts: Dict[str, int] = {}
    for flat_vuln in flat_vulns:
        if flat_vuln.is_suppressed:
            scanner_key = (flat_vuln.scanner or "").lower()
            counts[scanner_key] = counts.get(scanner_key, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def ident(
    scanner="s",
    rule="r",
    file="a.py",
    start=1,
    end=1,
    message="m",
    column=None,
    fingerprints=(),
    **extra,
):
    return finding_identity(
        scanner=scanner,
        rule_id=rule,
        file_path=file,
        line_start=start,
        line_end=end,
        message=message,
        column=column,
        fingerprints=fingerprints,
        **extra,
    )


def fp(value, kind="fingerprints", name="k"):
    return ((kind, ((name, value),)),)


def assert_same_as_oracle(identities, default_project=None):
    got = identity_keys(identities, default_project)
    want = _oracle_keys(identities, default_project)
    assert got == want
    # the dicts' own key order is part of the contract: a consumer iterating a key
    # sees the fields in this order
    assert [list(key) for key in got] == [list(key) for key in want]
    assert [canonical(key) for key in got] == [canonical(key) for key in want]
    return got


# --------------------------------------------------------------------------- #
# Hand-written scenarios
# --------------------------------------------------------------------------- #

BASE = {
    "scanner": "s",
    "rule": "r",
    "file": "a.py",
    "package": [None, None],
    "project": None,
}


def test_an_empty_run_has_no_keys():
    assert identity_keys([]) == []
    assert identity_keys([], "proj") == []


def test_a_lone_finding_is_keyed_by_its_lines_with_no_occurrence():
    (key,) = identity_keys([ident(start=3, end=4)])
    assert key == {**BASE, "startLine": 3, "endLine": 4}
    assert list(key) == [*BASE, "startLine", "endLine"]


def test_a_lone_findings_key_is_the_same_whether_alone_or_asked_for_singly():
    identity = ident(start=3, end=4, message="x", fingerprints=fp("v"))
    assert identity_key(identity) == identity_keys([identity])[0]
    assert identity_key(identity, "p") == identity_keys([identity], "p")[0]


def test_results_sharing_a_location_get_an_occurrence_and_exact_duplicates_an_ordinal():
    one = ident(message="first")
    twin_a = ident(message="second")
    twin_b = ident(message="second")
    keys = identity_keys([one, twin_a, twin_b])
    assert keys[0]["occurrence"] == occurrence_digest(None, "first")
    assert "ordinal" not in keys[0]
    assert keys[1]["occurrence"] == occurrence_digest(None, "second")
    assert "ordinal" not in keys[1]
    assert keys[2]["occurrence"] == keys[1]["occurrence"]
    assert keys[2]["ordinal"] == 1
    assert list(keys[2]) == [*BASE, "startLine", "endLine", "occurrence", "ordinal"]


def test_the_third_exact_duplicate_is_ordinal_two_and_order_is_the_runs():
    keys = identity_keys([ident(message="m"), ident(message="m"), ident(message="m")])
    assert [key.get("ordinal") for key in keys] == [None, 1, 2]


def test_a_column_tells_two_results_of_one_place_apart():
    keys = identity_keys([ident(column=1), ident(column=2), ident(column=1)])
    assert [key.get("ordinal") for key in keys] == [None, None, 1]
    assert keys[0]["occurrence"] == occurrence_digest(1, "m")
    assert keys[1]["occurrence"] == occurrence_digest(2, "m")


def test_a_fingerprint_unique_to_one_location_keys_the_finding():
    (key,) = identity_keys([ident(fingerprints=fp("v1"))])
    assert key == {**BASE, "fingerprints": [["k", "v1"]]}
    assert list(key) == [*BASE, "fingerprints"]


def test_a_fingerprint_value_at_two_locations_counts_as_absent_for_both():
    keys = identity_keys(
        [
            ident(start=1, end=1, fingerprints=fp("v")),
            ident(start=9, end=9, fingerprints=fp("v")),
        ]
    )
    assert keys[0] == {**BASE, "startLine": 1, "endLine": 1}
    assert keys[1] == {**BASE, "startLine": 9, "endLine": 9}


def test_the_same_value_in_another_file_or_scanner_does_not_count_as_shared():
    keys = identity_keys(
        [
            ident(file="a.py", fingerprints=fp("v")),
            ident(file="b.py", fingerprints=fp("v")),
            ident(scanner="t", fingerprints=fp("v")),
        ]
    )
    assert all("fingerprints" in key for key in keys)


def test_the_same_value_at_one_place_twice_is_not_shared_but_is_an_occurrence():
    keys = identity_keys(
        [
            ident(message="a", fingerprints=fp("v")),
            ident(message="a", fingerprints=fp("v")),
        ]
    )
    assert keys[0] == {
        **BASE,
        "fingerprints": [["k", "v"]],
        "occurrence": occurrence_digest(None, "a"),
    }
    assert keys[1]["ordinal"] == 1


def test_only_the_shared_pairs_of_a_kind_are_dropped():
    keys = identity_keys(
        [
            ident(
                start=1,
                end=1,
                fingerprints=(("fingerprints", (("a", "same"), ("b", "u1"))),),
            ),
            ident(
                start=2,
                end=2,
                fingerprints=(("fingerprints", (("a", "same"), ("b", "u2"))),),
            ),
        ]
    )
    assert keys[0]["fingerprints"] == [["b", "u1"]]
    assert keys[1]["fingerprints"] == [["b", "u2"]]


def test_a_fingerprint_kind_whose_pairs_are_all_shared_falls_to_the_next_kind():
    both = (
        ("fingerprints", (("k", "shared"),)),
        ("partialFingerprints", (("p", "own"),)),
    )
    other = (
        ("fingerprints", (("k", "shared"),)),
        ("partialFingerprints", (("p", "own2"),)),
    )
    keys = identity_keys(
        [ident(start=1, end=1, fingerprints=both), ident(start=2, end=2, fingerprints=other)]
    )
    assert keys[0]["partialFingerprints"] == [["p", "own"]]
    assert "fingerprints" not in keys[0]
    assert keys[1]["partialFingerprints"] == [["p", "own2"]]


def test_a_kinds_order_in_the_identity_is_the_preference_order():
    reversed_kinds = (
        ("partialFingerprints", (("p", "x"),)),
        ("fingerprints", (("k", "y"),)),
    )
    (key,) = identity_keys([ident(fingerprints=reversed_kinds)])
    assert "partialFingerprints" in key and "fingerprints" not in key


def test_every_fingerprint_all_shared_falls_back_to_lines():
    keys = identity_keys(
        [
            ident(start=1, end=2, fingerprints=fp("v")),
            ident(start=3, end=4, fingerprints=fp("v")),
        ]
    )
    assert [(key["startLine"], key["endLine"]) for key in keys] == [(1, 2), (3, 4)]


def test_the_default_project_is_folded_in_only_where_the_result_names_none():
    named = ident(workspace_project="mine")
    unnamed = ident(file="b.py")
    keys = identity_keys([named, unnamed], "default")
    assert keys[0]["project"] == "mine"
    assert keys[1]["project"] == "default"
    assert identity_keys([unnamed], None)[0]["project"] is None
    assert identity_keys([unnamed], "")[0]["project"] is None


def test_the_default_project_is_applied_before_fingerprint_values_are_counted():
    # without the default these two have different bases (project None vs "p") and
    # so do not share the value; with it they have one base and do
    named = ident(start=1, end=1, workspace_project="p", fingerprints=fp("v"))
    unnamed = ident(start=2, end=2, fingerprints=fp("v"))
    keys = identity_keys([named, unnamed], "p")
    assert all("fingerprints" not in key for key in keys)
    keys = identity_keys([named, unnamed], None)
    assert all("fingerprints" in key for key in keys)


def test_a_converted_file_is_keyed_apart_from_the_same_path_unconverted():
    keys = identity_keys([ident(), ident(converted=True)])
    assert "tree" not in keys[0]
    assert keys[1]["tree"] == "converted"
    assert "occurrence" not in keys[0] and "occurrence" not in keys[1]


def test_unbounded_line_numbers_and_columns_are_keyed_and_told_apart():
    big = 10**30
    keys = identity_keys(
        [
            ident(start=big, end=big + 1, column=2**80),
            ident(start=big, end=big + 1, column=2**80),
            ident(start=big, end=big + 2, column=2**80),
        ]
    )
    assert keys[0]["startLine"] == big and keys[0]["endLine"] == big + 1
    assert keys[1].get("ordinal") == 1
    assert "occurrence" not in keys[2]


def test_unbounded_columns_that_differ_are_two_locations_for_a_shared_value():
    a = ident(start=1, end=1, column=2**70, fingerprints=fp("v"))
    b = ident(start=1, end=1, column=2**70 + 1, fingerprints=fp("v"))
    keys = identity_keys([a, b])
    assert all("fingerprints" not in key for key in keys)


def test_text_a_frame_column_cannot_hold_is_keyed_and_told_apart():
    surrogate = "dir/\udcff.py"
    other = "dir/\udcfe.py"
    keys = assert_same_as_oracle(
        [
            ident(file=surrogate, start=1, end=1, fingerprints=fp("v\udcff")),
            ident(file=surrogate, start=2, end=2, fingerprints=fp("v\udcff")),
            ident(file=other, start=1, end=1, fingerprints=fp("v\udcff")),
            ident(file=surrogate, start=1, end=1, message="x\udcff"),
            ident(file=surrogate, start=1, end=1, message="x\udcff"),
            ident(scanner="s\udcff", rule="r\udcff"),
        ]
    )
    assert keys[0]["file"] == surrogate and keys[2]["file"] == other
    # the surrogate-named file's value is shared across its two locations; the other
    # file's copy of the same value stays unique to it
    assert "fingerprints" not in keys[0] and "fingerprints" not in keys[1]
    assert "fingerprints" in keys[2]
    assert keys[3].get("ordinal") is None and keys[4].get("ordinal") == 1


def test_text_that_is_one_to_one_under_latin_1_stays_two_things():
    # "é" is one character, "Ã©" is its UTF-8 bytes read as Latin-1:
    # a carrier that decoded them alike would merge two files
    keys = assert_same_as_oracle(
        [ident(file="é.py"), ident(file="Ã©.py")]
    )
    assert "occurrence" not in keys[0] and "occurrence" not in keys[1]


def test_the_finding_id_of_a_key_is_the_scanner_rule_and_twelve_hex_digits():
    (key,) = identity_keys([ident(scanner="bandit", rule="B1")])
    assert finding_id(key) == _oracle_id(key)
    assert finding_id(key).startswith("bandit-B1-") and len(finding_id(key)) == 22


def test_the_ids_of_a_run_are_the_oracles():
    identities = [ident(message="m"), ident(message="m"), ident(start=7, end=7)]
    got = [finding_id(key) for key in identity_keys(identities)]
    assert got == [_oracle_id(key) for key in _oracle_keys(identities)]
    assert len(set(got)) == 3


def test_the_occurrence_digest_is_pinned():
    assert occurrence_digest(None, None) == _oracle_occurrence(None, None)
    assert occurrence_digest(0, "x") == _oracle_occurrence(0, "x")
    assert occurrence_digest(0, "x") != occurrence_digest(None, "x")
    assert occurrence_digest(3, "café \udcff") == _oracle_occurrence(
        3, "café \udcff"
    )
    assert len(occurrence_digest(1, "m")) == 8


# --------------------------------------------------------------------------- #
# Differential: seeded random runs against the oracle
# --------------------------------------------------------------------------- #

_SCANNERS = ["s", "t", "s\udcff"]
_RULES = ["r", "q", None]
_FILES = ["a.py", "b.py", "a\udcff.py", None]
_VALUES = ["v1", "v2", "", "v\udcff"]
_MESSAGES = ["m", "n", None, "m\udcff"]


def _random_identity(rng: random.Random) -> FindingIdentity:
    fingerprints = []
    for kind in rng.sample(list(FINGERPRINT_KINDS), rng.randint(0, 2)):
        pairs = tuple(
            sorted(
                {
                    (rng.choice(["a", "b"]), rng.choice(_VALUES))
                    for _ in range(rng.randint(1, 3))
                }
            )
        )
        fingerprints.append((kind, pairs))
    start = rng.choice([1, 2, None, 10**25])
    return finding_identity(
        scanner=rng.choice(_SCANNERS),
        rule_id=rng.choice(_RULES),
        file_path=rng.choice(_FILES),
        line_start=start,
        line_end=rng.choice([start, 3, None]),
        package_name=rng.choice([None, "p"]),
        package_path=rng.choice([None, "x/p"]),
        workspace_project=rng.choice([None, None, "w"]),
        fingerprints=tuple(fingerprints),
        column=rng.choice([None, 0, 1, 2**70]),
        message=rng.choice(_MESSAGES),
        converted=rng.random() < 0.2,
    )


@pytest.mark.parametrize("seed", range(40))
def test_random_runs_are_keyed_as_the_oracle_keys_them(seed):
    rng = random.Random(seed)
    identities = [_random_identity(rng) for _ in range(rng.randint(1, 40))]
    default_project = rng.choice([None, "", "dflt"])
    assert_same_as_oracle(identities, default_project)


def test_a_large_run_of_one_place_is_keyed_as_the_oracle_keys_it():
    rng = random.Random(7)
    identities = [
        ident(message=rng.choice(["a", "b", "c"]), column=rng.choice([None, 1]))
        for _ in range(600)
    ]
    keys = assert_same_as_oracle(identities)
    assert max(key.get("ordinal", 0) for key in keys) > 50


def test_a_run_of_unshared_fingerprints_is_keyed_as_the_oracle_keys_it():
    identities = [
        ident(start=i, end=i, fingerprints=fp(f"v{i}"), file=f"f{i % 7}.py")
        for i in range(300)
    ]
    keys = assert_same_as_oracle(identities)
    assert all("fingerprints" in key for key in keys)


# --------------------------------------------------------------------------- #
# The flattened run: ids and the suppressed counts
# --------------------------------------------------------------------------- #


def _flat(model: AshAggregatedResults) -> List[FlatVulnerability]:
    return model.to_flat_vulnerabilities()


def test_the_flat_ids_of_a_run_are_the_oracles_over_its_identities():
    model = build_model(
        sarif_results=[
            suppressed_result(SCANNER, "R1"),
            suppressed_result(SCANNER, "R1"),
            suppressed_result(SCANNER, "R2"),
        ]
    )
    flat = _flat(model)
    assert len(flat) == 3
    identities = [vuln.identity for vuln in flat]
    assert all(identity is not None for identity in identities)
    want = [_oracle_id(key) for key in _oracle_keys(identities)]
    assert [vuln.id for vuln in flat] == want
    assert len({vuln.id for vuln in flat}) == 3
    assert [vuln.identity_base for vuln in flat] == [
        {k: v for k, v in key.items() if k not in {"startLine", "endLine", "occurrence", "ordinal", *FINGERPRINT_KINDS}}
        for key in _oracle_keys(identities)
    ]


def test_the_flat_ids_follow_the_workspace_project_of_the_results():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    plain = _flat(model)[0].id
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    model.metadata.workspace_project = "proj"
    flat = _flat(model)
    assert flat[0].id != plain
    assert flat[0].id == _oracle_id(_oracle_keys([flat[0].identity], "proj")[0])


def test_a_blank_workspace_project_is_no_project():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    plain = _flat(model)[0].id
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    model.metadata.workspace_project = "   "
    assert _flat(model)[0].id == plain


def test_an_additional_report_row_with_its_own_id_is_left_alone():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    model.additional_reports = {
        "plug": [
            {"id": "own-1", "title": "t", "severity": "HIGH"},
            {"title": "no id", "severity": "LOW", "rule_id": "z", "file_path": "f.py"},
        ]
    }
    flat = _flat(model)
    assert [vuln.source_report for vuln in flat] == [None, "plug", "plug"]
    assert flat[1].id == "plug-own-1"
    assert flat[1].identity is None
    assert flat[2].id.startswith("plug-z-")


def test_the_suppressed_counts_by_scanner_and_their_order_are_pinned():
    model = build_model(
        reports={SCANNER: dict_report(2), OTHER: dict_report(5, scanner=OTHER)},
        sarif_results=[
            suppressed_result(SCANNER, "R1"),
            suppressed_result(SCANNER, "R2"),
        ],
    )
    populate_metrics_from_unified_source(model)
    flat = _flat(model)
    counts = model._suppressed_by_scanner(flat)
    assert counts == {SCANNER: 4, OTHER: 5}
    assert list(counts) == [SCANNER, OTHER]
    assert model.metadata.summary_stats.suppressed == 9


@pytest.mark.parametrize(
    "scanners",
    [
        [],
        ["Alpha", "alpha", "ALPHA"],
        ["b", "a", "b", "c", "a"],
        ["İstanbul", "i̇stanbul"],
        ["sc\udcff", "SC\udcff", "sc\udcfe"],
        ["", None, "x"],
    ],
)
def test_the_flat_suppressed_counts_are_the_oracles(scanners):
    model = build_model()
    vulns = []
    for index, scanner in enumerate(scanners):
        vuln = FlatVulnerability.from_additional_report(
            {"id": f"id{index}", "title": "t", "severity": "LOW"}, scanner or "x"
        )
        vuln.scanner = scanner
        vuln.is_suppressed = index % 3 != 1
        vulns.append(vuln)
    got = model._suppressed_by_scanner(vulns)
    want = _oracle_suppressed_flat_counts(vulns)
    assert got == want
    assert list(got) == list(want)


def test_a_scanner_the_flat_run_names_by_another_case_still_counts_once():
    model = build_model(
        reports={SCANNER: dict_report(1)},
        sarif_results=[suppressed_result(SCANNER.upper(), "R1")],
    )
    populate_metrics_from_unified_source(model)
    flat = _flat(model)
    counts = model._suppressed_by_scanner(flat)
    assert counts == {SCANNER.lower(): 2}
