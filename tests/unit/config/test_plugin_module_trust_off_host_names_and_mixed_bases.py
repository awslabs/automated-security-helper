# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two judgments of the off-host plugin packages in ``plugin_module_trust``.

* A name is an off-host package's whatever its case. An import on a
  case-insensitive file system with ``PYTHONCASEOK`` set loads the package's
  files under a differently cased module name, and the name check has to
  treat that name as the package.
* A class that mixes in two off-host classes from different modules of one
  package is kept only when the trusted names cover both. Looking at the first
  one per package kept the class when only that one's module was trusted.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_module_trust import (
    drop_untrusted_off_host_plugins,
    off_host_package,
)

pytestmark = pytest.mark.unit

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"


def _class(name: str, module: str, *bases: type) -> type:
    made = type(name, bases, {})
    made.__module__ = module
    return made


def test_a_differently_cased_name_is_still_the_off_host_package():
    assert off_host_package(AWS) == AWS
    assert off_host_package(AWS.upper()) == AWS
    assert off_host_package(f"{AWS.title()}.reporters") == AWS
    # The control: a name that only starts like the package is not inside it.
    assert off_host_package(f"{AWS}_extras") is None


def _drop(plugins, trusted):
    config = AshConfig()
    config._trusted_plugin_modules = ()
    return drop_untrusted_off_host_plugins(config, plugins, trusted)


def test_a_class_mixing_in_a_second_off_host_module_needs_both_trusted():
    first = _class("FirstReporter", f"{AWS}.first_reporter")
    second = _class("SecondReporter", f"{AWS}.second_reporter")
    mixed = _class("MixedReporter", "other_ash_plugins.reporter", first, second)
    plugins = {"reporter": [mixed]}

    assert _drop(plugins, [f"{AWS}.first_reporter"]) == {"reporter": []}
    assert _drop(plugins, [f"{AWS}.second_reporter"]) == {"reporter": []}
    # Both modules, or the package around them, cover the class.
    both = [f"{AWS}.first_reporter", f"{AWS}.second_reporter"]
    assert _drop(plugins, both) == plugins
    assert _drop(plugins, [AWS]) == plugins


def test_a_base_of_a_trusted_modules_class_is_covered_with_it():
    """The control: trusting the module of a class covers what that class
    derives from in its own package."""
    root = _class("RootReporter", f"{AWS}.root_reporter")
    leaf = _class("LeafReporter", f"{AWS}.leaf_reporter", root)
    derived = _class("DerivedReporter", "other_ash_plugins.reporter", leaf)
    plugins = {"reporter": [derived]}

    assert _drop(plugins, [f"{AWS}.leaf_reporter"]) == plugins
    assert _drop(plugins, [f"{AWS}.root_reporter"]) == {"reporter": []}
