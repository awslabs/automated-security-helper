# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The root config's plugin sections come from manifest rows, and a bad row is refused by name.

When the sections were written out in a class body, a reviewer saw a duplicate field,
a name pydantic treats specially, or a spelling that collides with another. Built
from rows, the same mistakes were dropped or reshaped in silence: ``fields[name] =``
overwrote an earlier plugin's section, a leading ``_`` made a private attribute that
is missing from the schema, and a name that shadows a ``BaseModel`` attribute drew
only a warning. ``plugin_section_fields`` and ``build_segment`` now refuse each, at
the moment the model is built. The helpers that read the manifests refuse a kind or a
class name they cannot place, instead of answering with the wrong rows.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from automated_security_helper.base.plugin_manifest import ConfigSection
from automated_security_helper.config import plugin_sections
from automated_security_helper.plugin_manifests import (
    ManifestRegistryError,
    plugin_config_sections,
)

pytestmark = pytest.mark.unit

#: Any importable class that builds with no arguments will do for a row: the
#: checks run on the names.
_SECTION = ConfigSection(
    model="automated_security_helper.config.ash_config:AshConfig",
    description="a section",
)


def _rows(monkeypatch, *names):
    monkeypatch.setattr(
        plugin_sections,
        "plugin_config_sections",
        lambda kind: tuple((name, _SECTION) for name in names),
    )


@pytest.mark.parametrize("kind", ["scanners", "reporters", "converters"])
def test_control_the_shipped_rows_build_one_field_per_plugin(kind):
    fields = plugin_sections.plugin_section_fields(kind)

    assert len(fields) == len(plugin_config_sections(kind)) > 0


def test_two_plugins_with_one_field_name_are_refused(monkeypatch):
    """Red at the base: the later plugin's section replaced the earlier one's."""
    _rows(monkeypatch, "cfn-lint", "cfn_lint")

    with pytest.raises(ValueError, match="twice"):
        plugin_sections.plugin_section_fields("scanners")


def test_two_plugins_that_fold_to_one_section_name_are_refused(monkeypatch):
    _rows(monkeypatch, "trivy-repo", "trivyrepo")

    with pytest.raises(ValueError, match="one section name"):
        plugin_sections.plugin_section_fields("scanners")


@pytest.mark.parametrize("name", ["_hidden", "-lead"])
def test_a_name_with_a_leading_underscore_is_refused(monkeypatch, name):
    """Red at the base: pydantic kept it out of the model's fields."""
    _rows(monkeypatch, name)

    with pytest.raises(ValueError, match="start with '_'"):
        plugin_sections.plugin_section_fields("scanners")


@pytest.mark.parametrize("name", ["9lives", "a.b", "class", "with space"])
def test_a_name_that_is_not_a_usable_field_name_is_refused(monkeypatch, name):
    _rows(monkeypatch, name)

    with pytest.raises(ValueError, match="not usable"):
        plugin_sections.plugin_section_fields("scanners")


@pytest.mark.parametrize("name", ["json", "copy", "schema", "model-dump"])
def test_a_name_that_shadows_an_attribute_of_the_base_is_refused(monkeypatch, name):
    """Red at the base: pydantic warned and the section replaced the method."""
    _rows(monkeypatch, name)

    with pytest.raises(ValueError, match="shadow"):
        plugin_sections.build_segment("Segment", BaseModel, dict, "scanners", __name__)


def test_a_kind_the_literal_does_not_name_is_refused():
    """Red at the base: ``Literal`` is not checked at run time, so a misspelled
    kind was answered with the scanner rows."""
    with pytest.raises(ValueError, match="not a plugin kind"):
        plugin_config_sections("scanner")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not a plugin kind"):
        plugin_config_sections("Reporters")  # type: ignore[arg-type]


def test_a_builtin_options_class_without_the_suffix_is_refused_by_scanner_name():
    from automated_security_helper.plugin_manifests.builtin import _builtin

    with pytest.raises(ManifestRegistryError, match="'bandit'.*'Options'"):
        _builtin("bandit", "bandit_scanner", "BanditScanner", "BanditScannerConfig")


def test_a_builtin_scanner_without_a_description_is_refused_by_name():
    from automated_security_helper.plugin_manifests.builtin import _builtin

    with pytest.raises(ManifestRegistryError, match="'no-such-scanner'"):
        _builtin("no-such-scanner", "m", "Scanner", "ScannerConfigOptions")
