# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint, cfn-lint, cfn-guard, gitleaks, trivy and zizmor are builtin and on by default.

They are loaded with every other builtin scanner (no ``ash_plugin_modules`` entry),
each has a declared field on ``ScannerConfigSegment`` so the config schema and
validation cover it, and each is enabled unless the config turns it off. A default
scan therefore runs them.
"""

import pytest

from automated_security_helper.config.ash_config import ScannerConfigSegment
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin import scanners

NEW_BUILTINS = {
    "actionlint": ("ActionlintScanner", "actionlint"),
    "cfn-guard": ("CfnGuardScanner", "cfn_guard"),
    "cfn-lint": ("CfnLintScanner", "cfn_lint"),
    "gitleaks": ("GitleaksScanner", "gitleaks"),
    "trivy": ("TrivyScanner", "trivy"),
    "zizmor": ("ZizmorScanner", "zizmor"),
}


@pytest.mark.parametrize("name", sorted(NEW_BUILTINS))
def test_each_is_exported_with_the_builtin_scanners(name):
    class_name, _ = NEW_BUILTINS[name]
    assert class_name in scanners.__all__
    cls = getattr(scanners, class_name)
    assert cls.__module__.startswith(
        "automated_security_helper.plugin_modules.ash_builtin.scanners."
    )


@pytest.mark.parametrize("name", sorted(NEW_BUILTINS))
def test_each_has_a_declared_config_field_that_defaults_to_enabled(name):
    _, field = NEW_BUILTINS[name]
    assert field in ScannerConfigSegment.model_fields
    config = getattr(get_default_config().scanners, field)
    assert config.name == name
    assert config.enabled is True


def test_load_internal_plugins_registers_them(monkeypatch):
    from automated_security_helper.plugins.loader import load_internal_plugins

    loaded = load_internal_plugins()
    names = {cls.__name__ for cls in loaded["scanners"]}
    assert {class_name for class_name, _ in NEW_BUILTINS.values()} <= names


@pytest.mark.parametrize("name", sorted(NEW_BUILTINS))
def test_a_config_can_turn_each_off(name):
    from automated_security_helper.config.ash_config import AshConfig

    _, field = NEW_BUILTINS[name]
    config = AshConfig.model_validate(
        {"project_name": "x", "scanners": {name: {"enabled": False}}}
    )
    assert getattr(config.scanners, field).enabled is False
