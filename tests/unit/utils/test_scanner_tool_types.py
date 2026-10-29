# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which kind of scanner reported a result (``utils/scanner_tool_types.py``).

``SCANNER_TOOL_TYPES`` declares each shipped scanner's tool type because a scanner
sets ``tool_type`` in ``model_post_init``, and building one probes its tool. The
first test reads the assignment from each scanner's own ``model_post_init`` and
checks the table against it, so a scanner whose type changes, or a scanner added
without an entry, fails here.
"""

import ast
import inspect
import textwrap

import pytest

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.utils.scanner_names import (
    SCANNER_TAG_NAMES,
    SCANNER_TOOL_TYPES,
)
from automated_security_helper.utils.scanner_tool_types import (
    normalize_tool_type,
    result_tool_types,
    scanner_tool_type,
)
from tests.unit.utils.test_scanner_names_registry_agreement import (
    _declared_config_name,
    _registry_scanner_classes,
)

pytestmark = pytest.mark.unit


def _tool_type_assigned_in_post_init(cls):
    """The ``ScannerToolType`` member ``model_post_init`` assigns to ``self.tool_type``."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls.model_post_init)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "tool_type"
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "ScannerToolType"
            ):
                return ScannerToolType[node.value.attr].value
    return None


def test_the_declared_tool_types_are_the_ones_each_scanner_sets():
    found = {}
    for cls in _registry_scanner_classes():
        name = _declared_config_name(cls)
        found[name] = _tool_type_assigned_in_post_init(cls)

    assert None not in found.values(), found
    assert dict(SCANNER_TOOL_TYPES) == found
    assert SCANNER_TAG_NAMES == set(found)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("SECRETS", "SECRETS"),
        ("SECRET", "SECRETS"),
        ("secrets", "SECRETS"),
        ("ScannerToolType.SECRETS", "SECRETS"),
        (ScannerToolType.SECRETS, "SECRETS"),
        ("SAST", "SAST"),
        ("UNKNOWN", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_tool_type(value, expected):
    assert normalize_tool_type(value) == expected


def test_a_shipped_scanner_has_its_declared_type():
    assert scanner_tool_type("detect-secrets") == "SECRETS"
    assert scanner_tool_type("ferret-scan") == "SECRETS"
    assert scanner_tool_type("bandit") == "SAST"


def test_an_unregistered_scanner_has_no_type():
    assert scanner_tool_type("not-a-registered-scanner") is None
    assert scanner_tool_type(None) is None


@pytest.mark.parametrize(
    "tag", ["tool_type::SECRETS", "tool_type::ScannerToolType.SECRETS"]
)
def test_a_tool_type_tag_gives_the_type_in_either_spelling(tag):
    result = {"properties": {"scanner_name": "acme-scanner", "tags": [tag]}}

    assert result_tool_types(result) == {"SECRETS"}


def test_the_scanner_name_gives_the_type_without_tags():
    result = {"properties": {"scanner_name": "detect-secrets"}}

    assert result_tool_types(result) == {"SECRETS"}


def test_a_result_with_neither_has_no_type():
    assert result_tool_types({"properties": {"scanner_name": "acme-linter"}}) == set()
    assert result_tool_types({}) == set()


def test_a_loaded_scanner_that_declares_its_type_on_the_class_is_found():
    """A third-party scanner ASH does not ship, known only by its class."""
    from typing import Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )

    class AcmeKeysScannerConfig(ScannerPluginConfigBase):
        name: Literal["acme-keys"] = "acme-keys"

    class AcmeKeysScanner(ScannerPluginBase[AcmeKeysScannerConfig]):
        tool_type: ScannerToolType = ScannerToolType.SECRETS
        config: AcmeKeysScannerConfig | None = None

        def validate_plugin_dependencies(self):
            return True

        def scan(self, *args, **kwargs):
            return None

    assert scanner_tool_type("acme-keys") == "SECRETS"
    assert AcmeKeysScanner.model_fields["tool_type"].default == "SECRETS"
