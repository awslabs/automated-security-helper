# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``get_installation_commands`` override declares what the base method returns.

The base method returns ``List[List[str] | CustomCommand]``: a custom install
command comes back as the ``CustomCommand`` it was declared as, so its ``shell``
flag reaches the installer. Two scanners override the method, build on
``super()`` and append argument lists, and still declared ``List[List[str]]``.
A type checker then reads the override as narrower than the base, and an author
who copies an override as a pattern drops the second shape from their own
signature. The overrides now declare the same type as the base.
"""

from __future__ import annotations

import typing

import pytest

from automated_security_helper.base.plugin_base import CustomCommand, PluginBase
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)

pytestmark = pytest.mark.unit


def _return_type(owner) -> object:
    return typing.get_type_hints(owner.get_installation_commands)["return"]


def test_the_base_method_declares_both_shapes():
    """The control: the type the overrides have to match."""
    declared = _return_type(PluginBase)

    (item,) = typing.get_args(declared)
    assert CustomCommand in typing.get_args(item)


@pytest.mark.parametrize("scanner", [CdkNagScanner, FerretScanScanner])
def test_an_override_declares_the_base_return_type(scanner):
    assert scanner.get_installation_commands is not PluginBase.get_installation_commands

    assert _return_type(scanner) == _return_type(PluginBase)
