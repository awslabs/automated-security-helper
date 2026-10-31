# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin segment built from a dict reads two spellings of one section as the
document loader does.

``_PluginConfigSegment`` folds the Python field-name spelling (``cdk_nag``) and
any other spelling (``Cdk-Nag``) of a declared plugin section into the declared
key (``cdk-nag``). Two things went wrong in that fold:

* The field-name spelling and a variant beside it were merged in silently,
  while the document loader (``plugin_section_names.fold_known_plugin_sections``)
  refuses the same pair as ambiguous: the loader does not take the field-name
  spelling for the declared one. Red at the base: the pair validated, so
  ``pytest.raises`` saw no error.
* A model instance under the declared key was dumped with every default before
  the key-by-key merge, so each default it was never given replaced the value
  the field-name spelling set. Red at the base: ``enabled`` read True, the
  instance's own default, where the field-name spelling wrote False.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import ScannerConfigSegment
from automated_security_helper.config.plugin_section_names import (
    AmbiguousPluginSpellings,
    fold_known_plugin_sections,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScannerConfig,
)

pytestmark = pytest.mark.unit


def test_a_variant_beside_the_field_name_spelling_is_refused_as_ambiguous():
    with pytest.raises(ValidationError) as refused:
        ScannerConfigSegment.model_validate(
            {"cdk_nag": {"enabled": True}, "Cdk-Nag": {"enabled": False}}
        )

    message = str(refused.value)
    assert "ambiguous" in message, message
    assert "cdk_nag" in message and "Cdk-Nag" in message, message


def test_the_document_loader_refuses_the_same_pair():
    """The control: the rule the segment now applies is the loader's own."""
    with pytest.raises(AmbiguousPluginSpellings):
        fold_known_plugin_sections(
            {"scanners": {"cdk_nag": {"enabled": True}, "Cdk-Nag": {"enabled": False}}}
        )


def test_a_variant_alone_still_reaches_the_declared_section():
    """The control: one non-declared spelling has no rival and folds."""
    segment = ScannerConfigSegment.model_validate({"Cdk-Nag": {"enabled": False}})

    assert segment.cdk_nag.enabled is False
    assert "Cdk-Nag" not in (segment.model_extra or {})


def test_the_field_name_beside_the_declared_spelling_still_merges():
    """The control: the declared spelling beside the field-name spelling is
    the round trip ``apply_config_overrides`` makes, and stays a merge."""
    segment = ScannerConfigSegment.model_validate(
        {
            "cdk_nag": {"enabled": False},
            "cdk-nag": {"options": {"nag_packs": {"PCIDSS321Checks": True}}},
        }
    )

    assert segment.cdk_nag.enabled is False
    assert segment.cdk_nag.options.nag_packs.PCIDSS321Checks is True


def test_an_instance_under_the_declared_key_keeps_what_the_field_name_set():
    overlay = CdkNagScannerConfig.model_validate(
        {"options": {"nag_packs": {"PCIDSS321Checks": True}}}
    )

    segment = ScannerConfigSegment.model_validate(
        {"cdk_nag": {"enabled": False}, "cdk-nag": overlay}
    )

    assert segment.cdk_nag.enabled is False
    assert segment.cdk_nag.options.nag_packs.PCIDSS321Checks is True


def test_an_instance_still_wins_where_it_sets_the_same_key():
    """The control: a key the instance was built with still wins."""
    overlay = CdkNagScannerConfig.model_validate({"enabled": False})

    segment = ScannerConfigSegment.model_validate(
        {"cdk_nag": {"enabled": True}, "cdk-nag": overlay}
    )

    assert segment.cdk_nag.enabled is False
