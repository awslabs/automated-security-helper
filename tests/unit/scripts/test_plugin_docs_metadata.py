# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs metadata the built-in plugin classes declare, and the generator that reads it.

* every built-in scanner and converter class declares a non-empty ``docs_summary``
  (read from the class, no instance);
* ``display_name``, when declared, is text, and ``covers`` is a list of text;
* the three attributes are ClassVars, so none of them is a model field or reaches a
  JSON schema (the schema files are held byte-identical by the schema checks);
* the generator's completeness check names a featured scanner that declares no
  ``docs_summary`` or ``covers``, and a converter that declares no ``docs_summary``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.plugin_modules import ash_builtin

pytestmark = pytest.mark.unit

BUILTIN_SCANNERS = list(ash_builtin.ASH_SCANNERS)
BUILTIN_CONVERTERS = list(ash_builtin.ASH_CONVERTERS)
BUILTIN_PLUGINS = BUILTIN_SCANNERS + BUILTIN_CONVERTERS


@pytest.fixture
def generator(script_loader):
    return script_loader("generate_plugin_data_partial")


def test_the_registry_lists_are_not_empty() -> None:
    # A loop over an empty list passes whatever it asserts.
    assert len(BUILTIN_SCANNERS) >= 16
    assert len(BUILTIN_CONVERTERS) >= 2


@pytest.mark.parametrize("plugin_cls", BUILTIN_PLUGINS, ids=lambda c: c.__name__)
def test_every_builtin_plugin_declares_a_docs_summary(plugin_cls) -> None:
    summary = plugin_cls.docs_summary
    assert isinstance(summary, str) and summary.strip(), (
        f"{plugin_cls.__name__} declares no docs_summary; set it as a class attribute"
    )


@pytest.mark.parametrize("plugin_cls", BUILTIN_PLUGINS, ids=lambda c: c.__name__)
def test_a_declared_display_name_is_text(plugin_cls) -> None:
    name = plugin_cls.display_name
    assert name is None or (isinstance(name, str) and name.strip())


@pytest.mark.parametrize("plugin_cls", BUILTIN_SCANNERS, ids=lambda c: c.__name__)
def test_a_declared_covers_is_a_list_of_text(plugin_cls) -> None:
    covers = plugin_cls.covers
    assert covers is None or (
        isinstance(covers, list)
        and covers
        and all(isinstance(item, str) and item.strip() for item in covers)
    )


@pytest.mark.parametrize(
    "base,fields",
    [
        (PluginBase, ("display_name", "docs_summary")),
        (ScannerPluginBase, ("display_name", "docs_summary", "covers")),
    ],
)
def test_the_metadata_stays_out_of_the_model(base, fields) -> None:
    for field in fields:
        assert field not in base.model_fields
        assert field in base.__class_vars__


def test_a_featured_scanner_without_docs_is_reported(generator) -> None:
    featured = next(iter(generator.SCANNER_DOCS))
    tool_types = {featured: "SAST"}
    problems = generator.editorial_problems(
        tool_types, set(), set(), {featured: {"display_name": "X"}}
    )
    assert any("declares no docs_summary" in p and featured in p for p in problems)
    assert any("declares no covers" in p and featured in p for p in problems)


def test_a_featured_scanner_with_docs_is_not_reported(generator) -> None:
    featured = next(iter(generator.SCANNER_DOCS))
    docs = {featured: {"docs_summary": "Checks", "covers": ["Python"]}}
    problems = generator.editorial_problems({featured: "SAST"}, set(), set(), docs)
    assert not [p for p in problems if "declares no" in p]


def test_a_converter_without_a_summary_is_reported(generator) -> None:
    problems = generator.converter_problems({"x": None}, summaries={"x": None})
    assert problems == ["converter 'x' declares no docs_summary"]
    assert generator.converter_problems({"x": None}, summaries={"x": "does it"}) == []


def test_display_name_falls_back_to_the_config_name(generator) -> None:
    assert generator.display_name("npm-audit", {}) == "npm-audit"
    assert generator.display_name("npm-audit", {"display_name": "npm audit"}) == (
        "npm audit"
    )
