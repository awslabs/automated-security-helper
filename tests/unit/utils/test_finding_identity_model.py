# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the ``FindingIdentity`` conversion to pydantic keeps.

The frozen dataclass became a frozen pydantic model so the frame layer reads
one mechanism (``model_fields`` and the drift gate) across every model it
projects. These pins are the conversion's contract: immutability, the
dataclass's equality semantics (field-wise, same-class), the ``location``
property, and the one mutation site copying without a per-row validate or dump
(the boundary rule).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.finding_identity import (
    FindingIdentity,
    finding_identity,
    identity_key,
    relative_to_scan_root,
)

pytestmark = pytest.mark.unit


def _identity(**overrides):
    fields = {
        "scanner": "sc",
        "rule_id": "r1",
        "file_path": "/root/dir/a.py",
        "line_start": 3,
        "line_end": 9,
        "fingerprints": (("fingerprints", (("k", "v"),)),),
        "column": 2,
        "message": "m",
    }
    fields.update(overrides)
    return finding_identity(**fields)


def test_equality_is_field_wise_and_same_class():
    one, same = _identity(), _identity()
    assert one is not same and one == same
    assert one != _identity(line_start=4)

    class _Subclass(FindingIdentity):
        pass

    twin = _Subclass(
        **{name: getattr(one, name) for name in FindingIdentity.model_fields}
    )
    assert one != twin  # the dataclass compared same-class only; so does this


def test_assignment_raises_and_the_mapping_base_keeps_it_unhashable():
    identity = _identity()
    with pytest.raises(ValidationError):
        identity.occurrence = "overwritten"
    # Never hashed at runtime; the generated field-based hash raises on the
    # Mapping base exactly as the frozen dataclass's did, so no live hashing
    # behavior changed with the conversion.
    with pytest.raises(TypeError):
        hash(identity)


def test_construction_validates_the_field_shapes():
    with pytest.raises(ValidationError):
        FindingIdentity(base={}, lines=("x", None))


def test_location_reads_tree_file_lines_and_column():
    converted = _identity(converted=True)
    assert converted.location == ("converted", "/root/dir/a.py", 3, 9, 2)


def test_relative_to_scan_root_copies_without_validating_or_dumping(monkeypatch):
    identity = _identity()

    def refuse(*_args, **_kwargs):
        raise AssertionError("the copy touched pydantic per row")

    for attribute in ("model_validate", "model_dump", "__init__"):
        monkeypatch.setattr(FindingIdentity, attribute, refuse)
    moved = relative_to_scan_root(identity, "/root")
    assert moved is not identity
    assert moved.base["file"] == "dir/a.py"
    assert identity.base["file"] == "/root/dir/a.py"  # the original is untouched
    for name in ("lines", "column", "fingerprints", "occurrence"):
        assert getattr(moved, name) == getattr(identity, name)
    # a path the root does not change answers the same instance, as before
    assert relative_to_scan_root(moved, "/elsewhere") is moved


def test_the_derived_key_is_what_the_dataclass_derived():
    key = identity_key(_identity())
    assert key == {
        "scanner": "sc",
        "rule": "r1",
        "file": "/root/dir/a.py",
        "package": [None, None],
        "project": None,
        "fingerprints": [["k", "v"]],
    }
