# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refusal context is redacted without breaking the shape its readers use.

``_context_without_values`` runs between the producer that raised an
MCPResourceError and the readers of its context: the response builder takes
``suggestions`` and ``error_category`` from the redacted mapping by key. The
redaction must hide values without rewriting those structural keys, and must
rebuild any sequence shape a producer used (a namedtuple's constructor does
not take one iterable): it runs inside the error handler, where a raise
replaces the refusal with a crash.
"""

from __future__ import annotations

from typing import Any, NamedTuple

SECRET = "/opt/qz4b/config"


class _Spec(NamedTuple):
    path: str
    port: int


def _redacted(context: Any, values: tuple) -> Any:
    from automated_security_helper.cli.mcp_tools import _context_without_values

    return _context_without_values(context, values)


def test_a_value_matching_inside_a_structural_key_leaves_it_readable() -> None:
    # "r_ca" holds "_", so it is replaced anywhere, "error_category" included;
    # "ggestion" is long enough to be replaced inside "suggestions". A reader
    # takes both entries by key after redaction, so the keys must survive.
    values = ("r_ca", "ggestion", SECRET)
    context = {
        "error_category": "validation_error",
        "suggestions": ["Remove the stale lock"],
        "error_message": f"could not read {SECRET}",
    }

    out = _redacted(context, values)

    assert out["error_category"] == "validation_error"
    assert out["suggestions"] == ["Remove the stale lock"]
    # The skip is for the KEY only: the structural entry's value still hides.
    assert "qz4b" not in out["error_message"]


def test_control_a_producer_key_carrying_a_value_is_still_redacted() -> None:
    # Green before and after: the structural-key skip reaches only the known
    # names at the mapping's top level. A producer's own key hides its value,
    # and a NESTED key spelled like a structural one is a producer's data too.
    values = (SECRET,)
    context = {
        f"read {SECRET}": "refused",
        "detail": {f"suggestions for {SECRET}": "x"},
    }

    out = _redacted(context, values)

    assert "qz4b" not in "".join(str(key) for key in out)
    (nested_key,) = out["detail"]
    assert "qz4b" not in nested_key


def test_a_namedtuple_value_is_redacted_as_a_plain_sequence() -> None:
    out = _redacted({"spec": _Spec(SECRET, 1)}, (SECRET,))

    assert out["spec"] == ("<value>", 1)
    assert type(out["spec"]) is tuple


def test_a_namedtuple_key_is_redacted_as_a_plain_sequence() -> None:
    out = _redacted({_Spec(SECRET, 2): "item"}, (SECRET,))

    assert out == {("<value>", 2): "item"}


def test_two_keys_hiding_to_the_same_text_both_survive() -> None:
    first, second = "alpha-qz4b-key", "beta-qz4b-key"
    context = {first: "first item", second: "second item"}

    out = _redacted(context, (first, second))

    assert out == {"<value>": "first item", "<value>#2": "second item"}


def test_a_context_that_contains_itself_comes_back_finite() -> None:
    context: dict = {"holds": SECRET}
    context["loop"] = context

    out = _redacted(context, (SECRET,))

    assert out["holds"] == "<value>"
    assert out["loop"] == "(cyclic reference)"


def test_a_numeric_leaf_printing_a_read_value_is_hidden() -> None:
    out = _redacted({"port": 8443, "ratio": 3.1415}, ("8443", "3.1415"))

    assert out["port"] == "<value>"
    assert out["ratio"] == "<value>"


def test_control_a_short_numeric_leaf_and_a_bool_stay_as_they_are() -> None:
    # "443" is below the redaction floor, and True is a flag, not a value a
    # config read: both leaves keep their type and value.
    out = _redacted({"port": 443, "flag": True}, ("443", "True"))

    assert out["port"] == 443
    assert out["port"] is not True
    assert out["flag"] is True


def test_control_a_shared_subtree_is_redacted_in_both_places() -> None:
    # Green with the cycle guard in place: it tracks the walk's own stack, not
    # everything seen, so one dict referenced twice is redacted twice, never
    # replaced by the cycle note.
    shared = {"holds": SECRET}
    context = {"first": shared, "second": shared}

    out = _redacted(context, (SECRET,))

    assert out["first"] == {"holds": "<value>"}
    assert out["second"] == {"holds": "<value>"}


def test_a_leaf_whose_str_raises_is_shown_as_a_note() -> None:
    class _Hostile:
        def __str__(self) -> str:
            raise RuntimeError(f"renderer read {SECRET}")

    out = _redacted({"obj": _Hostile()}, (SECRET,))

    assert out["obj"] == "(not shown)"
