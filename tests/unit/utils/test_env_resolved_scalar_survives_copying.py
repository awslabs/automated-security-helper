# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The slots of an env-resolved scalar travel through copy, deepcopy and pickle.

``EnvResolvedScalar`` defines no constructor of its own, so what carries its
slots (``variable``, ``shown`` and ``from_environment``) through a copy is
str's own copy protocol. A summary row reads ``shown`` off the marker and falls
back to the bare reference rebuilt from ``variable`` only for a marker that
lost the slot (the statistics calculator's degrade, pinned by
tests/unit/core/test_a_threshold_marker_without_its_shown_slot_degrades.py).
These tests are what keeps that fallback a degrade for foreign state and not
the path a copy takes: a slot added to the class but not carried by the
protocol fails here, and not as a silently rebuilt name in a report.
"""

from __future__ import annotations

import copy
import pickle

import pytest

from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_SLOT_VARIABLE"
SHOWN = "${" + VARIABLE + "}tail"
VALUE = "zz-slot-value-krw"


def _marker() -> EnvResolvedScalar:
    # from_environment=False is the non-default value, so a slot reset to its
    # default shows as a difference.
    return env_resolved_scalar(VALUE + "tail", VARIABLE, SHOWN, from_environment=False)


def _copies():
    original = _marker()
    yield "copy", copy.copy(original)
    yield "deepcopy", copy.deepcopy(original)
    for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
        yield (
            f"pickle-{protocol}",
            pickle.loads(pickle.dumps(original, protocol=protocol)),
        )


_CASES = list(_copies())


@pytest.mark.parametrize("how,duplicate", _CASES, ids=[how for how, _ in _CASES])
def test_a_copy_keeps_every_slot(how, duplicate):
    assert type(duplicate) is EnvResolvedScalar, how
    assert str(duplicate) == VALUE + "tail", how
    assert duplicate.variable == VARIABLE, how
    assert duplicate.shown == SHOWN, how
    assert duplicate.from_environment is False, how


def test_the_maker_never_leaves_shown_empty():
    """``shown`` is what a summary row prints; the maker answers the bare
    reference for a caller that gives none, an empty one included."""
    assert env_resolved_scalar("x", VARIABLE).shown == "${" + VARIABLE + "}"
    assert env_resolved_scalar("x", VARIABLE, "").shown == "${" + VARIABLE + "}"
    assert env_resolved_scalar("x", VARIABLE).from_environment is True


def test_the_marker_is_no_file_like_object():
    """A str with a ``read`` attribute passes the ``hasattr(x, "read")`` test
    that file-like duck typing uses (``ElementTree.parse`` calls it)."""
    marker = _marker()
    assert not hasattr(marker, "read")
    assert not hasattr(marker, "write")
