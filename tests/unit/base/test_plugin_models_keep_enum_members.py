# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin model holds enum members; values appear only where it is written out.

``PluginBase`` and the three plugin config segments used to set
``use_enum_values=True``. That coerced an enum-typed field to its bare string
when a model was built from a value, which defeated member-identity checks
downstream (``reporter_plugin.workspace_behaviour`` is a ``ClassVar`` for that
reason). The flag is off; the vocabulary rule is members in memory and values at
the boundary.

Two kinds of test live here.

* Characterization: what a plugin or a config segment writes out (JSON, YAML)
  must not change when the flag goes off. These passed on the base before the
  flip, with the same expected values.
* Red-first: a field built from a value now holds the member.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar, Literal

import pytest
import yaml

import automated_security_helper
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import (
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

pytestmark = pytest.mark.unit


class _StubConfig(ScannerPluginConfigBase):
    name: Literal["stub"] = "stub"


def _scanner(plugin_context, **fields):
    """A scanner that leaves ``tool_type`` as constructed (no post-init assignment)."""

    class StubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    return StubScanner(config=_StubConfig(), context=plugin_context, **fields)


# --- characterization: what is written out does not change -------------------


@pytest.mark.parametrize("built_from", ["value", "member", "default"])
def test_a_scanner_writes_its_tool_type_as_the_value(plugin_context, built_from):
    fields = {
        "value": {"tool_type": "SCA"},
        "member": {"tool_type": ScannerToolType.SCA},
        "default": {},
    }[built_from]
    expected = "UNKNOWN" if built_from == "default" else "SCA"

    scanner = _scanner(plugin_context, **fields)

    assert scanner.model_dump(mode="json", include={"tool_type"}) == {
        "tool_type": expected
    }
    assert (
        yaml.safe_dump(scanner.model_dump(mode="json", include={"tool_type"}))
        == f"tool_type: {expected}\n"
    )
    assert f'"tool_type":"{expected}"' in scanner.model_dump_json(
        include={"tool_type"}
    ).replace(" ", "")


@pytest.mark.parametrize("built_from", ["value", "member"])
def test_a_scanner_tool_type_still_equals_its_value(plugin_context, built_from):
    scanner = _scanner(
        plugin_context,
        tool_type="SAST" if built_from == "value" else ScannerToolType.SAST,
    )

    assert scanner.tool_type == "SAST"
    assert scanner.tool_type == ScannerToolType.SAST


SEGMENTS = {
    ScannerConfigSegment: {"bandit": {"enabled": False}},
    ReporterConfigSegment: {"sarif": {"enabled": False}},
    ConverterConfigSegment: {"archive": {"enabled": False}},
}


@pytest.mark.parametrize("segment", list(SEGMENTS))
def test_a_config_segment_round_trips_through_json_and_yaml(segment):
    """A segment read from a file writes the same document back.

    Compared against its own first dump, so the pin holds whatever the plugin
    models default to, and the second pass proves nothing in the dump is a
    Python-only object (a member, a path) that a YAML writer could not store.
    """
    first = segment.model_validate(SEGMENTS[segment])

    as_json = first.model_dump(mode="json")
    again = segment.model_validate(as_json)
    as_yaml = yaml.safe_dump(first.model_dump(mode="json"), sort_keys=True)

    assert again.model_dump(mode="json") == as_json
    assert yaml.safe_load(as_yaml) == as_json
    assert (
        segment.model_validate(yaml.safe_load(as_yaml)).model_dump(mode="json")
        == as_json
    )


# --- red first: members in memory --------------------------------------------


def test_a_scanner_built_from_a_value_holds_the_member(plugin_context):
    scanner = _scanner(plugin_context, tool_type="SCA")

    assert scanner.tool_type is ScannerToolType.SCA


def test_a_plugin_field_holding_an_enum_keeps_member_identity(plugin_context):
    """The hazard ``workspace_behaviour`` is a ClassVar to avoid, as a field."""

    class FieldReporter(ReporterPluginBase):
        behaviour: ReporterWorkspaceBehaviour = ReporterWorkspaceBehaviour.PER_PROJECT

        def report(self, model):  # pragma: no cover - never invoked
            return ""

    built = FieldReporter(context=plugin_context, behaviour="merged")

    assert built.behaviour is ReporterWorkspaceBehaviour.MERGED


@pytest.mark.parametrize(
    "model",
    [
        ScannerPluginBase,
        ReporterPluginBase,
        ScannerConfigSegment,
        ReporterConfigSegment,
        ConverterConfigSegment,
    ],
)
def test_no_plugin_model_stores_enum_values(model):
    assert not model.model_config.get("use_enum_values", False)


def test_the_scanner_tool_type_tag_writes_the_value(plugin_context):
    """The tag a scanner puts on its results carries the value, not ``Enum.__str__``.

    ``f"{member}"`` is the value on Python 3.10 and 3.11 and ``ClassName.MEMBER``
    on 3.12; the tag is a wire spelling, so it is written from ``.value``.
    """
    scanner = _scanner(plugin_context, tool_type=ScannerToolType.SECRETS)

    assert scanner.tool_type_tag() == "tool_type::SECRETS"


# --- the drift gate: where the flag may still appear -------------------------

#: Generated or vendored schema models keep the flag: their consumers read dumped
#: dicts, and the gitlab family is plain ``Enum`` and needs it to serialize.
ALLOWED_PREFIXES = ("schemas/",)


def _files_setting_use_enum_values(root: Path) -> set[str]:
    found = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "use_enum_values":
                found.add(path.relative_to(root).as_posix())
            elif (
                isinstance(node, ast.Constant) and node.value == "use_enum_values"
            ):  # a dict-style model_config
                found.add(path.relative_to(root).as_posix())
    return found


def test_only_the_generated_schemas_set_use_enum_values():
    root = Path(automated_security_helper.__file__).parent

    offenders = {
        name
        for name in _files_setting_use_enum_values(root)
        if not name.startswith(ALLOWED_PREFIXES)
    }

    assert offenders == set()


def test_the_gate_flags_a_planted_use_enum_values(tmp_path):
    (tmp_path / "planted.py").write_text(
        "from pydantic import ConfigDict\ncfg = ConfigDict(use_enum_values=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")

    assert _files_setting_use_enum_values(tmp_path) == {"planted.py"}
