"""The redaction walk visits each container once.

``_string_leaves`` gathers the strings of a refused input so the refusal's
message can be redacted. The input comes from the document the loader built,
and YAML aliases survive that load as shared containers, so one container can
be reachable along many paths: a walk that re-visits it does the work once per
path, which an alias-amplified document makes exponential. Visiting each
container once bounds the walk by the document's size. A cyclic structure
cannot reach this walk through the loader (the load itself fails first), so
the once-only visit is hardening there, not a reachable contract.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import _string_leaves

pytestmark = pytest.mark.unit


def test_leaves_keep_the_documents_own_order():
    """Depth-first, left to right, as the file wrote them: the downstream
    replacement sees the leaves as written."""
    value = {"a": ["one", {"b": "two"}], "c": "three"}
    assert _string_leaves(value) == ["one", "two", "three"]


def test_a_shared_container_is_walked_once():
    """Two aliases of one sequence are one container: its leaf is collected
    once, and the walk's work is bounded by the document, not by the number
    of paths to each part. One leaf per path made an alias-amplified
    document exponential to walk."""
    shared = ["canary-leaf"]
    assert _string_leaves([shared, shared]) == ["canary-leaf"]


def test_a_cyclic_structure_ends_with_its_reachable_leaves():
    """A container holding itself cannot be built by the config loader (the
    load fails before any refusal is described), so this pins the walk's own
    hardening: it terminates and answers the reachable leaves instead of
    looping."""
    cycle: list = ["before-the-loop"]
    cycle.append(cycle)
    cycle.append("after-the-loop")
    assert _string_leaves({"k": cycle}) == ["before-the-loop", "after-the-loop"]


def test_distinct_equal_containers_are_each_walked():
    """The bound is identity, not equality: two containers that merely look
    alike each contribute their leaves."""
    assert _string_leaves([["twin"], ["twin"]]) == ["twin", "twin"]
