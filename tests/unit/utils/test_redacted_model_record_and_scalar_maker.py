# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The record of carried values survives pickle and copy, and the scalar maker
keeps the shown text it is given.

A section's record of the values its configuration read is pickled and copied
with the section. Pickle protocols 0 and 1 skip ``__setstate__`` when
``__getstate__`` is falsy, and a record with no values (the empty tuple) is, so
the restored record had no ``values`` slot and every read of it raised
AttributeError.

``env_resolved_scalar`` keeps a shown text it is given and answers the bare
reference when none is given. An empty shown text is also answered with the
bare reference, by design; tests/unit/utils/test_env_resolved_scalar_survives_
copying.py pins that.
"""

import copy
import pickle

import pytest

from automated_security_helper.utils.redacted_model import (
    _EnvironmentRecord,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_MAKER_CANARY"


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
@pytest.mark.parametrize(
    "values",
    [(), ("held-value-one",), ("held-value-one", "held-value-two")],
    ids=["no-values", "one-value", "two-values"],
)
def test_a_record_survives_every_pickle_protocol(protocol, values):
    restored = pickle.loads(pickle.dumps(_EnvironmentRecord(values), protocol=protocol))
    assert restored.values == values


def test_a_record_with_no_values_survives_copying():
    record = _EnvironmentRecord()
    assert copy.copy(record).values == ()
    assert copy.deepcopy(record).values == ()


def test_a_copied_record_is_a_record_of_its_own():
    record = _EnvironmentRecord(("held-value-one",))
    copied = copy.deepcopy(record)
    assert copied is not record
    assert copied.values == ("held-value-one",)


def test_a_shown_text_left_out_is_the_bare_reference():
    assert env_resolved_scalar("text", VARIABLE).shown == "${" + VARIABLE + "}"
    assert env_resolved_scalar("text", VARIABLE, None).shown == "${" + VARIABLE + "}"


def test_a_shown_text_given_is_kept():
    scalar = env_resolved_scalar("text", VARIABLE, shown="${ASH_OTHER}tail")
    assert scalar.shown == "${ASH_OTHER}tail"
