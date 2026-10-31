# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's section carries its context's environment values however it got there.

A built plugin has its section given those values by a model validator
(``_give_its_section_the_environment_values``) and by ``__setattr__``. Two ways
of making a plugin run neither: ``model_construct`` skips every validator, and
``model_copy(update=...)`` writes the fields straight into the copy. A section
put in by either printed the values in clear. Both now carry them.

``is_python_only`` is covered here too: a dependency installed with uv is a
Python package, as one installed with pip is.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_base import PluginBase, PluginDependency
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import PackageManager

pytestmark = pytest.mark.unit

#: Long enough that a redaction replaces it wherever it is printed.
ENV_VALUE = "ENVCANARY-u33a-4417"


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


class _Plugin(PluginBase):
    """A plugin that adds nothing to the base class."""


class _ReadsAValue(_Plugin):
    """A plugin whose values hook names one value its context read."""

    def _values_to_redact(self):
        return (ENV_VALUE,)


# -- model_construct and model_copy ----------------------------------------------


def test_model_construct_carries_the_values_into_its_section(plugin_context):
    section = PluginConfigBase(name="probe")
    assert section.redaction_values() == ()

    built = _ReadsAValue.model_construct(context=plugin_context, config=section)

    assert built.config.redaction_values() == (ENV_VALUE,)


def test_model_construct_without_a_section_still_builds():
    built = _ReadsAValue.model_construct()

    assert built.config is None


def test_a_copy_given_a_section_carries_the_values_into_it(plugin_context):
    plugin = _ReadsAValue(context=plugin_context, config=PluginConfigBase(name="probe"))
    replacement = PluginConfigBase(name="other")
    assert replacement.redaction_values() == ()

    copied = plugin.model_copy(update={"config": replacement})

    assert copied.config.name == "other"
    assert copied.config.redaction_values() == (ENV_VALUE,)


class _ReadsItsContext(_Plugin):
    """A plugin whose values hook names its context's output directory."""

    def _values_to_redact(self):
        return (self.context.output_dir.name,)


def _context_with_output_dir_named(tmp_path, name):
    source_dir = tmp_path / f"source-{name}"
    source_dir.mkdir()
    output_dir = tmp_path / name
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def test_a_copy_given_a_context_carries_its_values_into_the_shared_section(tmp_path):
    first = _context_with_output_dir_named(tmp_path, "FIRSTCANARY-u33a-1")
    second = _context_with_output_dir_named(tmp_path, "SECONDCANARY-u33a-2")
    plugin = _ReadsItsContext(context=first, config=PluginConfigBase(name="probe"))
    assert plugin.config.redaction_values() == ("FIRSTCANARY-u33a-1",)

    copied = plugin.model_copy(update={"context": second})

    values = copied.config.redaction_values()
    assert "SECONDCANARY-u33a-2" in values
    # The values the section already held are kept beside the new ones.
    assert "FIRSTCANARY-u33a-1" in values


def test_a_copy_with_no_new_section_keeps_the_values_it_shares(plugin_context):
    plugin = _ReadsAValue(context=plugin_context, config=PluginConfigBase(name="probe"))
    assert plugin.config.redaction_values() == (ENV_VALUE,)

    copied = plugin.model_copy()

    assert copied.config.redaction_values() == (ENV_VALUE,)
    assert plugin.config.redaction_values() == (ENV_VALUE,)


# -- is_python_only --------------------------------------------------------------


def _plugin_declaring(plugin_context, *managers):
    dependencies = {
        "linux": {
            "amd64": [
                PluginDependency(name=f"dep-{index}", package_manager=manager)
                for index, manager in enumerate(managers)
            ]
        }
    }
    return _Plugin(context=plugin_context, dependencies=dependencies)


@pytest.mark.parametrize(
    ("managers", "python_only"),
    [
        ((), True),
        ((PackageManager.PIP,), True),
        ((PackageManager.UV,), True),
        ((PackageManager.PIP, PackageManager.UV), True),
        ((PackageManager.UV, PackageManager.APT), False),
        ((PackageManager.NPM,), False),
    ],
    ids=["none", "pip", "uv", "pip-and-uv", "uv-and-apt", "npm"],
)
def test_a_plugin_whose_dependencies_are_python_packages_is_python_only(
    plugin_context, managers, python_only
):
    plugin = _plugin_declaring(plugin_context, *managers)

    assert plugin.is_python_only() is python_only
