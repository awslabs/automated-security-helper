# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reporter's license walk reaches every license list the module can hold.

``cyclonedx_reporter._conforming_licenses`` rewrites the license lists of a BOM
for the document the reporter writes. It follows a ``LicenseChoice``, a model
(over its set fields) and a ``list``. A ``LicenseChoice`` held in a field typed
as a dict or a tuple, directly or inside a model that sits in one, would be
written as stored. No field of the CycloneDX module is typed that way, so the
walk is complete today; this test says so and fails the day a regeneration of
the module brings in a dict, tuple or set annotation, instead of leaving the
walk short without a message.
"""

from __future__ import annotations

import inspect
import types
import typing

import pytest
from pydantic import BaseModel

import automated_security_helper.schemas.cyclonedx_bom_1_6_schema as module
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import LicenseChoice

pytestmark = pytest.mark.unit

#: The generic forms the walk can see through: an optional or union member, an
#: annotated member, a literal and a list. Anything else is a container the walk
#: does not enter.
_SEEN_THROUGH = {typing.Union, types.UnionType, typing.Annotated, typing.Literal, list}


def _origins(annotation: object) -> set:
    """Every generic origin an annotation uses, at any depth."""
    found = set()
    origin = typing.get_origin(annotation)
    if origin is not None:
        found.add(origin)
    for argument in typing.get_args(annotation):
        found |= _origins(argument)
    return found


def _holds(annotation: object, target: type) -> bool:
    if annotation is target:
        return True
    return any(_holds(argument, target) for argument in typing.get_args(annotation))


def _fields() -> dict:
    """The annotation of every field of every model the module defines."""
    return {
        (cls.__name__, name): info.annotation
        for cls in vars(module).values()
        if inspect.isclass(cls)
        and issubclass(cls, BaseModel)
        and cls.__module__ == module.__name__
        for name, info in cls.model_fields.items()
    }


def test_control_the_origin_reader_flags_a_dict_a_tuple_and_a_set():
    """The must-flag input: without it, an empty answer below could be a reader
    that sees nothing."""
    assert dict in _origins(typing.Dict[str, LicenseChoice])
    assert tuple in _origins(typing.Optional[typing.Tuple[LicenseChoice, ...]])
    assert set in _origins(typing.List[typing.Set[LicenseChoice]])
    assert _origins(typing.Optional[typing.List[LicenseChoice]]) <= _SEEN_THROUGH


def test_no_field_of_the_module_is_typed_as_a_container_the_walk_skips():
    fields = _fields()
    skipped = {}
    for key, annotation in fields.items():
        unseen = _origins(annotation) - _SEEN_THROUGH
        if unseen:
            skipped[key] = sorted(origin.__name__ for origin in unseen)
    assert not skipped, (
        "a field typed with a container that _conforming_licenses does not walk; "
        "teach the walk about it or keep license lists out of it: " + repr(skipped)
    )
    # The floors keep this from reading nothing: the module has hundreds of
    # fields, lists among them, and four fields hold a license list directly.
    assert len(fields) >= 100, len(fields)
    assert any(list in _origins(annotation) for annotation in fields.values())
    holders = [
        key for key, annotation in fields.items() if _holds(annotation, LicenseChoice)
    ]
    assert len(holders) >= 4, holders
