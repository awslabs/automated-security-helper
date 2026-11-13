# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""normalize_tool_type (utils/scanner_tool_types.py) returns ScannerToolType values only.

Any non-empty text other than UNKNOWN used to come back upper-cased as a type of
its own: the "None" a ``tool_type::None`` tag was formatted with, pydantic's
undefined-default marker read from a scanner class whose ``tool_type`` field has
a default factory or no default, free text. A finding then carried a type no
caller knows, and the Bedrock reporter's unknown-type handling was off for it.
"""

from __future__ import annotations

from typing import Literal

import pytest
from pydantic import Field
from pydantic_core import PydanticUndefined

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.utils.scanner_tool_types import (
    KNOWN_TOOL_TYPES,
    normalize_tool_type,
    result_tool_types,
    scanner_tool_type,
)

pytestmark = pytest.mark.unit


def test_the_known_types_are_the_enum_values_without_unknown():
    assert KNOWN_TOOL_TYPES == {m.value for m in ScannerToolType} - {"UNKNOWN"}
    assert "UNKNOWN" not in KNOWN_TOOL_TYPES


@pytest.mark.parametrize(
    "value",
    ["None", "none", "PydanticUndefined", PydanticUndefined, "free text", "SASTX"],
)
def test_text_that_is_no_scanner_tool_type_gives_none(value):
    assert normalize_tool_type(value) is None


@pytest.mark.parametrize("member", [m for m in ScannerToolType if m.value != "UNKNOWN"])
def test_every_declared_type_is_still_given(member):
    assert normalize_tool_type(member) == member.value
    assert normalize_tool_type(member.value.lower()) == member.value


def test_a_tool_type_none_tag_gives_the_result_no_type():
    result = {
        "properties": {"scanner_name": "acme-scanner", "tags": ["tool_type::None"]}
    }
    assert result_tool_types(result) == set()


def test_a_loaded_scanner_with_a_default_factory_has_no_type():
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )

    class AcmeFactoryScannerConfig(ScannerPluginConfigBase):
        name: Literal["acme-factory"] = "acme-factory"

    class AcmeFactoryScanner(ScannerPluginBase[AcmeFactoryScannerConfig]):
        tool_type: ScannerToolType = Field(default_factory=lambda: ScannerToolType.SAST)
        config: AcmeFactoryScannerConfig | None = None

        def validate_plugin_dependencies(self):
            return True

        def scan(self, *args, **kwargs):
            return None

    assert AcmeFactoryScanner.model_fields["tool_type"].default is PydanticUndefined
    assert scanner_tool_type("acme-factory") is None
