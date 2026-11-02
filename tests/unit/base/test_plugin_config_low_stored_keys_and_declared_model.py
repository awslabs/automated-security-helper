# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three small contracts of base/plugin_config.py.

* Under the stored-config tolerance, a key a plugin's section does not declare is
  recorded as ``UNKNOWN_KEY_NOTE`` located by its section, the way an options key
  is, and never as the refusal text that names the key.
* ``config_validated_by_declared_model`` re-validates a config of another class
  from its dump by alias, so a field the plugin's model declares under an alias
  keeps its value instead of falling to the default.
* It validates under the validation context of the field it stands in for when
  the caller passes the wrap validator's ``info``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Literal, Optional, Union

import pytest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from automated_security_helper.base.plugin_config import (
    config_validated_by_declared_model,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScannerConfig,
)
from automated_security_helper.utils.unknown_keys import (
    TOLERATE_STORED_CONFIG,
    UNKNOWN_KEY_NOTE,
)

pytestmark = pytest.mark.unit


def _notes_for(section: dict) -> list:
    notes: list = []
    kept = BanditScannerConfig.model_validate(
        section, context={TOLERATE_STORED_CONFIG: notes}
    )
    assert kept.model_extra, "the stored section keeps its undeclared keys"
    return notes


def test_an_undeclared_key_is_noted_by_its_section_not_by_its_name():
    notes = _notes_for({"enabled": True, "severity_threshold": "HIGH"})

    assert notes == [f"{UNKNOWN_KEY_NOTE} in 'scanners.bandit'"], notes


def test_each_kept_key_records_one_note_and_none_names_a_key():
    notes = _notes_for(
        {"enabled": True, "colour": "blue", "severity_threshold": "HIGH"}
    )

    assert notes == [f"{UNKNOWN_KEY_NOTE} in 'scanners.bandit'"] * 2, notes
    assert "colour" not in " ".join(notes)
    assert "severity_threshold" not in " ".join(notes)


def test_an_internal_only_field_is_noted_by_its_section_too():
    notes = _notes_for({"enabled": True, "install_timeout": 300})

    assert notes == [f"{UNKNOWN_KEY_NOTE} in 'scanners.bandit'"], notes


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    enabled: bool = True


class _Declared(_Base):
    name: Literal["probe"] = "probe"
    region: Optional[str] = Field(default=None, alias="Region")
    saw_context: bool = False

    @model_validator(mode="before")
    @classmethod
    def _read_context(cls, data, info):
        if isinstance(data, dict) and (info.context or {}).get("probe"):
            return {**data, "saw_context": True}
        return data


class _Sibling(_Base):
    name: Literal["probe"] = "probe"
    region: Optional[str] = Field(default=None, alias="Region")


class _Plugin:
    """What config_validated_by_declared_model reads of a plugin class."""

    model_fields = {
        "config": SimpleNamespace(annotation=Union[_Declared, _Base, None]),
    }


def _handler(value):
    raise AssertionError("the plugin's own model validates, not the union")


def test_an_aliased_field_survives_the_hand_over_to_the_declared_model():
    given = _Sibling(Region="eu-west-1")

    built = config_validated_by_declared_model(_Plugin, _Base, given, _handler)

    assert isinstance(built, _Declared)
    assert built.region == "eu-west-1"
    assert built.name == "probe"


def test_the_declared_model_validates_under_the_fields_context():
    info = SimpleNamespace(context={"probe": True})

    built = config_validated_by_declared_model(
        _Plugin, _Base, {"enabled": False}, _handler, info
    )

    assert built.saw_context is True
    assert built.enabled is False


def test_without_info_the_declared_model_sees_no_context():
    built = config_validated_by_declared_model(
        _Plugin, _Base, {"enabled": False}, _handler
    )

    assert built.saw_context is False
