# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config fields typed by a wire-spelled enum share one validator and serializer.

``sandbox.mode`` and ``output_formats`` read a name, hold the member and dump the
name. The conversion and the dump live in ``config/wire_enum.py``; this file pins
what a field built from them does, including the dump of a value that names no
member, which must neither raise nor quote the value.
"""

from __future__ import annotations

from enum import Enum

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic import BeforeValidator, field_serializer
from typing import Annotated

from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.wire_enum import (
    wire_enum_validator,
    wire_value,
)

pytestmark = pytest.mark.unit


class Color(str, Enum):
    RED = "red"
    BLUE = "blue"


def _refuse_color(value):
    if isinstance(value, str):
        raise ValueError("not a color")
    return value


class _Sample(BaseModel):
    model_config = ConfigDict(strict=True)

    color: Annotated[
        Color, BeforeValidator(wire_enum_validator(Color, _refuse_color, strip=True))
    ] = Color.RED

    @field_serializer("color")
    def _color_value(self, v):
        return wire_value(v)


def test_a_third_enum_round_trips_through_the_shared_pieces():
    sample = _Sample(color=" blue ")
    assert sample.color is Color.BLUE
    assert sample.model_dump() == {"color": "blue"}
    assert sample.model_dump(mode="json") == {"color": "blue"}
    assert _Sample(color=Color.RED).color is Color.RED


def test_the_shared_validator_hands_the_refusal_to_the_field():
    with pytest.raises(ValidationError, match="not a color"):
        _Sample(color="green")
    # A non-text input is the refusal's to leave for pydantic's own type check.
    with pytest.raises(ValidationError):
        _Sample(color=3)


@pytest.mark.parametrize("mode", ["python", "json"])
def test_a_sandbox_mode_assigned_a_non_mode_dumps_without_raising(mode):
    config = SandboxConfig()
    config.mode = "bogus"  # the model does not validate assignment

    dumped = config.model_dump(mode=mode)

    assert dumped["mode"] == "bogus"


def test_a_valid_sandbox_mode_still_dumps_as_its_name():
    assert SandboxConfig(mode="auto").model_dump()["mode"] == "auto"
    assert SandboxConfig(mode="auto").model_dump(mode="json")["mode"] == "auto"


def test_the_sandbox_mode_refusal_text_is_unchanged():
    with pytest.raises(ValidationError) as excinfo:
        SandboxConfig(mode="bogus")
    assert (
        "Input should be 'off', 'auto', 'bwrap', 'firejail', 'landlock' or "
        "'sandbox-exec'"
    ) in str(excinfo.value)


def test_the_output_format_refusal_names_the_valid_formats_not_the_entry():
    with pytest.raises(ValidationError) as excinfo:
        AshConfig(project_name="t", output_formats=["not-a-format"])
    assert "Valid formats are:" in str(excinfo.value)
