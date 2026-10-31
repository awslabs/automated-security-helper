# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_reporter_docs.py: the registry read and the rendered sentences.

* only reporters defined under the built-in package are built-in rows, whatever
  else the process imported into the plugin registry;
* a reporter's config class is the model member of its ``config`` annotation,
  and its defaults are read without instantiating a model that needs a field;
* the defaults sentence and the table render for one, none, and a reporter with
  no extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, TypeVar, Union

import pytest
from pydantic import BaseModel

pytestmark = pytest.mark.unit

SCRIPTS_DIR = Path(__file__).resolve().parents[3] / "scripts"


@pytest.fixture
def generator(script_loader, monkeypatch):
    # _reference_table imports a sibling module by name; the script itself puts
    # its directory on sys.path only inside render_reference_page.
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    return script_loader("generate_reporter_docs")


class _Config(BaseModel):
    name: str = "demo"
    extension: Optional[str] = "demo.json"
    enabled: bool = False


class _NeedsAField(BaseModel):
    name: str = "needy"
    extension: Optional[str] = None
    enabled: bool = True
    required_setting: str


T = TypeVar("T")


class TestBuiltinFilter:
    def test_only_the_builtin_package_counts(self, generator):
        """At the base every registered reporter was a built-in row."""

        class Builtin:
            __module__ = (
                "automated_security_helper.plugin_modules.ash_builtin.reporters.x"
            )

        class Aws:
            __module__ = "automated_security_helper.plugin_modules.ash_aws_plugins.y"

        class Foreign:
            __module__ = "tests.unit.fake_plugin"

        assert generator.is_builtin_reporter(Builtin)
        assert not generator.is_builtin_reporter(Aws)
        assert not generator.is_builtin_reporter(Foreign)


class TestConfigClass:
    def test_the_model_member_is_found_in_any_position(self, generator):
        """At the base args[0] was taken, which for Union[None, Config] is NoneType."""
        assert generator.config_class_of(Optional[_Config]) is _Config
        assert generator.config_class_of(Union[None, _Config]) is _Config
        assert generator.config_class_of(_Config) is _Config

    def test_a_typevar_annotation_is_none_not_a_typeerror(self, generator):
        assert generator.config_class_of(T) is None

    def test_defaults_are_read_without_instantiating_a_needy_model(self, generator):
        """At the base config_cls() raised on a model with a required field."""
        assert generator.config_defaults(_NeedsAField) == {
            "name": "needy",
            "extension": None,
            "enabled": True,
        }

    def test_defaults_of_a_plain_model_come_from_an_instance(self, generator):
        assert generator.config_defaults(_Config) == {
            "name": "demo",
            "extension": "demo.json",
            "enabled": False,
        }


class TestSentences:
    def test_an_empty_name_list_renders_without_an_index_error(self, generator):
        """At the base _prose_list([]) raised IndexError on ticked[-1]."""
        assert generator._prose_list([]) == "none"

    def test_one_enabled_reporter_takes_a_singular_verb(self, generator):
        rows = [
            {"name": "a", "enabled": True, "extension": "a"},
            {"name": "b", "enabled": False, "extension": "b"},
        ]
        sentence = generator.defaults_sentence(rows)
        assert "1 is enabled by default: `a`." in sentence
        assert "`b` is available but disabled by default." in sentence

    def test_no_enabled_reporter_renders(self, generator):
        rows = [{"name": "a", "enabled": False, "extension": "a"}]
        assert generator.defaults_sentence(rows).startswith(
            "Of the 1 built-in reporters, none is enabled by default."
        )


class TestReferenceTable:
    def test_a_reporter_without_an_extension_reads_none_not_dot_none(
        self, generator, monkeypatch
    ):
        """At the base the entry rendered the literal `.None`."""
        monkeypatch.setitem(
            generator.REPORTER_DOCS,
            "demo",
            {"title": "Demo", "use_case": "u", "standard": "s"},
        )
        rows = [{"name": "demo", "enabled": True, "extension": None}]
        table = "\n".join(generator._reference_table(rows))
        assert "| none |" in table
        assert ".None" not in table

    def test_the_ocsf_standard_names_the_version_the_reporter_stamps(self, generator):
        assert "OCSF 1.1.0" in generator.REPORTER_DOCS["ocsf"]["standard"]
