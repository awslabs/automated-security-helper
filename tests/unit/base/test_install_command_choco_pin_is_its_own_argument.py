# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A chocolatey version pin is its own argv element.

``_INSTALL_COMMAND_BUILDERS`` renders a version-pinned chocolatey dependency.
Argv elements do not word-split, so a pin rendered inside the package-name
element ("tool --version=1.2") asked chocolatey for a package of that name: the
install could not succeed and the pin was never applied.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_base import (
    _INSTALL_COMMAND_BUILDERS,
    PluginDependency,
)
from automated_security_helper.core.enums import PackageManager

pytestmark = pytest.mark.unit


def _choco(name: str, version: str) -> list[str]:
    dependency = PluginDependency(
        name=name, package_manager=PackageManager.CHOCO, version=version
    )
    return _INSTALL_COMMAND_BUILDERS[PackageManager.CHOCO](dependency)


def test_a_pinned_dependency_names_the_package_and_the_pin_apart():
    argv = _choco("semgrep", "1.2.3")

    assert argv == ["choco", "install", "-y", "semgrep", "--version=1.2.3"], argv
    # The fact the base got wrong: no element holds both the name and the pin.
    assert not any(" " in element for element in argv), argv


def test_an_unpinned_dependency_renders_no_version_flag():
    assert _choco("semgrep", "latest") == ["choco", "install", "-y", "semgrep"]
