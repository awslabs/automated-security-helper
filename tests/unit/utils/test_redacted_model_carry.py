# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section keeps the environment values it was given, wherever it is put.

``carry_environment_values`` replaced each section's record with the values of
the holder it was handed to. A configured section put into a holder that
carries none lost its values, and a section shared by two holders kept only
the second's, so its text printed what the first holder had hidden. The record
is now merged. The walk also reads through a RootModel (a wrapper over one
section), and an assignment carries into what the section stored: the object
a model built when it validated the assignment, or an extra it keeps.

``__pretty__`` is the printer of devtools; pydantic serves it each field's raw
value, around the redaction the repr applies.
"""

from typing import Optional

import pytest
from pydantic import ConfigDict, RootModel

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    carry_environment_values,
)

pytestmark = pytest.mark.unit

FIRST = "zzcarryfirst-4471"
SECOND = "zzcarrysecond-8820"


class _Inner(RedactedSection):
    name: str = ""


class _Wrapper(RootModel[_Inner]):
    pass


class _Outer(RedactedSection):
    wrapped: Optional[_Wrapper] = None


class _Validating(RedactedSection):
    model_config = ConfigDict(validate_assignment=True)

    inner: _Inner = _Inner()


class _Open(RedactedSection):
    model_config = ConfigDict(extra="allow")


def test_a_section_put_in_a_holder_with_no_values_keeps_its_own():
    inner = _Inner()
    carry_environment_values(inner, (FIRST,))
    carry_environment_values(inner, ())
    assert inner.redaction_values() == (FIRST,)


def test_a_section_put_in_a_second_holder_keeps_the_first_holders_values():
    inner = _Inner()
    carry_environment_values(inner, (FIRST,))
    carry_environment_values(inner, (SECOND,))
    assert inner.redaction_values() == (FIRST, SECOND)


def test_a_value_carried_twice_is_held_once():
    inner = _Inner()
    carry_environment_values(inner, (FIRST,))
    carry_environment_values(inner, (FIRST, SECOND))
    assert inner.redaction_values() == (FIRST, SECOND)


def test_a_section_behind_a_root_model_receives_the_values():
    outer = _Outer(wrapped=_Wrapper(_Inner()))
    carry_environment_values(outer, (FIRST,))
    assert outer.wrapped is not None
    assert outer.wrapped.root.redaction_values() == (FIRST,)


def test_an_assignment_the_model_validates_carries_into_the_section_it_stored():
    holder = _Validating()
    carry_environment_values(holder, (FIRST,))
    holder.inner = {"name": "built-from-a-dict"}  # type: ignore[assignment]
    assert isinstance(holder.inner, _Inner)
    assert holder.inner.redaction_values() == (FIRST,)


def test_an_extra_assigned_to_a_section_receives_the_values():
    holder = _Open()
    carry_environment_values(holder, (FIRST,))
    holder.child = _Inner()
    assert holder.child.redaction_values() == (FIRST,)


def test_a_section_pretty_printed_shows_its_redacted_repr():
    class Secretive(RedactedSection):
        token: str = ""

    section = Secretive(token=FIRST)
    carry_environment_values(section, (FIRST,))
    if FIRST in repr(section):
        raise RuntimeError("control: the repr does not redact the carried value")
    printed = "".join(
        part for part in section.__pretty__(repr) if isinstance(part, str)
    )
    assert FIRST not in printed, printed
