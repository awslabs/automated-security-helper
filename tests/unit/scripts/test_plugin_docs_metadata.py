# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs metadata the built-in plugin classes declare, and the generator that reads it.

* every built-in scanner and converter class declares a non-empty ``docs_summary``
  (read from the class, no instance);
* each built-in declares its own ``display_name``, ``docs_summary`` and (scanners)
  ``covers``, not an inherited value; ``covers`` is a tuple of text;
* the jupyter converter's summary names the command the converter runs;
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
    assert len(BUILTIN_SCANNERS) >= 15
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


@pytest.mark.parametrize("plugin_cls", BUILTIN_PLUGINS, ids=lambda c: c.__name__)
def test_a_builtin_declares_its_own_metadata_not_its_parents(plugin_cls) -> None:
    """A subclass that forgot to set its text would inherit a parent's, silently."""
    own = vars(plugin_cls)
    assert "docs_summary" in own, f"{plugin_cls.__name__} inherits its docs_summary"
    assert "display_name" in own, f"{plugin_cls.__name__} inherits its display_name"


@pytest.mark.parametrize("plugin_cls", BUILTIN_SCANNERS, ids=lambda c: c.__name__)
def test_a_builtin_scanner_declares_covers_as_a_tuple_of_text(plugin_cls) -> None:
    assert "covers" in vars(plugin_cls), f"{plugin_cls.__name__} inherits its covers"
    covers = plugin_cls.covers
    assert (
        isinstance(covers, tuple)
        and covers
        and all(isinstance(item, str) and item.strip() for item in covers)
    )


def test_the_jupyter_summary_names_the_converters_command(script_loader) -> None:
    """The summary used to be filled from the command; it is text now, so tie them."""
    reference = script_loader("_plugin_reference")
    plugins = [p for p in reference.discover("converter") if p.name == "jupyter"]
    assert len(plugins) == 1
    reference.instantiate(plugins)
    instance = plugins[0].instance
    assert instance is not None, plugins[0].instance_error
    assert instance.command
    assert instance.command in plugins[0].cls.docs_summary


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


def test_a_registered_featured_scanner_absent_from_the_docs_is_reported(
    generator,
) -> None:
    featured = next(iter(generator.SCANNER_DOCS))
    problems = generator.editorial_problems({featured: "SAST"}, set(), set(), {})
    assert any("no class docs" in p and featured in p for p in problems)


def test_a_featured_scanner_with_docs_is_not_reported(generator) -> None:
    featured = next(iter(generator.SCANNER_DOCS))
    docs = {featured: {"docs_summary": "Checks", "covers": ("Python",)}}
    problems = generator.editorial_problems({featured: "SAST"}, set(), set(), docs)
    assert not [p for p in problems if "declares no" in p]


def test_a_converter_without_a_summary_is_reported(generator) -> None:
    none = frozenset()
    problems = generator.converter_problems({"x": None}, none, {"x": None})
    assert problems == ["converter 'x' declares no docs_summary"]
    assert generator.converter_problems({"x": None}, none, {"x": "does it"}) == []


def test_display_name_falls_back_to_the_config_name(generator) -> None:
    assert generator.display_name("npm-audit", {}) == "npm-audit"
    assert generator.display_name("npm-audit", {"display_name": "npm audit"}) == (
        "npm audit"
    )
