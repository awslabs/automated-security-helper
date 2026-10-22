# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cyclic container at a section field is answered, never walked forever.

No config file parser produces a cycle (the YAML loader refuses recursive
aliases, and TOML and JSON cannot write one), so a cycle only ever arrives
from a Python caller handing a built structure to a section model or to the
walks directly. Both walks in ``utils/redacted_model`` track containers by
id: the detector answers from what the structure holds, and the rebuild
refuses the cycle, because there is no acyclic downcast copy to build.

A shared (non-cyclic) container is not a cycle: it is downcast once and the
copy is shared, exactly as the input shared it.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

import pytest

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    _holds_env_scalar,
    env_resolved_scalar,
    without_env_scalars,
)

CANARY = "ash-canary-cyc7"
VARIABLE = "ASH_CYCLE_CANARY"


class _Holder(RedactedSection):
    items: Optional[Any] = None


def _bounded(call, seconds: float = 10.0):
    """Run *call* on a worker and fail loudly if it is still walking after
    *seconds*: the pre-fix shape of this defect is an unbounded loop, and a
    cell that hangs the whole run reports nothing."""
    outcome: dict = {}

    def run():
        try:
            outcome["value"] = call()
        except BaseException as error:  # noqa: BLE001 -- recorded and asserted
            outcome["error"] = error

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"still walking after {seconds} s"
    return outcome


def test_a_cyclic_value_at_a_section_field_is_answered_not_spun():
    cyclic: list = []
    cyclic.append(cyclic)

    outcome = _bounded(lambda: _Holder.model_validate({"items": cyclic}))

    # Accepted (no marker inside, nothing to downcast) or refused by
    # validation: either is an answer. Spinning is the defect.
    assert "value" in outcome or type(outcome["error"]).__name__ == (
        "ValidationError"
    ), outcome


def test_a_cyclic_value_holding_a_marker_is_refused_not_spun():
    cyclic: list = [env_resolved_scalar(CANARY, VARIABLE)]
    cyclic.append(cyclic)

    outcome = _bounded(lambda: _Holder.model_validate({"items": cyclic}))

    # A marker inside a cycle cannot be downcast (there is no acyclic copy),
    # so the section refuses the value instead of walking forever.
    assert "error" in outcome, outcome
    assert type(outcome["error"]).__name__ == "ValidationError", outcome


def test_the_detector_answers_on_a_cycle():
    plain: list = []
    plain.append(plain)
    marked: dict = {"value": env_resolved_scalar(CANARY, VARIABLE)}
    marked["self"] = marked

    outcome = _bounded(lambda: (_holds_env_scalar(plain), _holds_env_scalar(marked)))

    assert outcome.get("value") == (False, True), outcome


def test_the_rebuild_refuses_a_cycle():
    cyclic: dict = {"value": env_resolved_scalar(CANARY, VARIABLE)}
    cyclic["self"] = cyclic

    outcome = _bounded(lambda: without_env_scalars(cyclic))

    assert isinstance(outcome.get("error"), ValueError), outcome
    assert "contains itself" in str(outcome["error"]), outcome


def test_a_shared_container_is_downcast_once_not_refused():
    """The must-not-flag control: sharing is not a cycle. The shared entry
    is rebuilt once and both parents hold the same downcast copy."""
    shared = [env_resolved_scalar(CANARY, VARIABLE)]
    value = {"a": shared, "b": shared, "c": [shared]}

    rebuilt = without_env_scalars(value)

    assert rebuilt["a"] == [CANARY]
    assert type(rebuilt["a"][0]) is str
    assert rebuilt["a"] is rebuilt["b"]
    assert rebuilt["c"][0] is rebuilt["a"]


def test_a_repeated_entry_under_one_parent_is_not_a_cycle():
    shared = {"value": env_resolved_scalar(CANARY, VARIABLE)}
    rebuilt = without_env_scalars([shared, shared])

    assert rebuilt == [{"value": CANARY}, {"value": CANARY}]
    assert rebuilt[0] is rebuilt[1]


def test_an_acyclic_deep_value_is_still_rebuilt():
    """The guard changes nothing for the deep-but-finite shape the iterative
    walk exists for."""
    value: Any = env_resolved_scalar(CANARY, VARIABLE)
    for _ in range(5000):
        value = [value]
    rebuilt = without_env_scalars(value)
    for _ in range(5000):
        assert isinstance(rebuilt, list) and len(rebuilt) == 1
        rebuilt = rebuilt[0]
    assert rebuilt == CANARY and type(rebuilt) is str


@pytest.mark.parametrize("shape", ["list", "dict"])
def test_the_detector_still_finds_a_marker_beside_a_cycle(shape):
    """A cycle must not eat the answer: a marker elsewhere in the structure
    is still found."""
    cyclic: list = []
    cyclic.append(cyclic)
    marker = env_resolved_scalar(CANARY, VARIABLE)
    value: Any = [cyclic, marker] if shape == "list" else {"a": cyclic, "b": marker}

    outcome = _bounded(lambda: _holds_env_scalar(value))

    assert outcome.get("value") is True, outcome
