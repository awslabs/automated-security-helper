# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The namespace the documentation and the shipped example use must load.

The defect
----------
``load_additional_plugin_modules`` validated ``ash_plugin_modules`` entries against
a prefix list of ``automated_security_helper.``, ``ash_plugins.`` and
``ash_plugins``. Five documentation pages and
``examples/ash_plugins_example/.ash/.ash.yaml`` all name ``my_ash_plugins``, which
starts with none of them -- so the loader logged "Skipping module with unexpected
namespace" and every plugin in the package went unregistered.

It did not fail everywhere, which is why it survived. ``execution_engine`` also
calls ``discover_plugins``, which matches ``name == namespace`` against
``pkgutil.iter_modules()`` and does import the package, so a single-project scan
loaded it anyway. The consumers with no such fallback -- ``workspace.execution``,
``core.scanner_inventory``, ``load_plugins`` itself -- did not. The documented
arrangement therefore worked in a single-project scan and silently dropped every
custom plugin in a workspace run.

What was NOT the defect, and is asserted here so it is not re-broken: a
documented-namespace plugin being *rejected outright* so that a scan exits 0 with
the custom scanner never run. That reading does not hold, for the
``discover_plugins`` reason above. The divergence is between the two loaders, not
between the loader and the operator.

The namespace check is kept rather than removed. Its purpose is to stop a config
file from naming an arbitrary importable module, and the last test here is the one
that holds that purpose.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.plugins.loader import (
    _ALLOWED_TOP_LEVEL_SUFFIX,
    _is_allowed_module_path,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_CONFIG = REPO_ROOT / "examples" / "ash_plugins_example" / ".ash" / ".ash.yaml"


def test_the_shipped_examples_own_namespace_is_accepted():
    """The example ships a config ASH would have refused to honour.

    Read out of the file rather than repeated as a literal, so renaming the example
    package without updating the loader reddens this instead of passing.
    """
    config = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    declared = config["ash_plugin_modules"]
    assert declared, EXAMPLE_CONFIG

    for module_path in declared:
        assert _is_allowed_module_path(module_path), (
            f"{EXAMPLE_CONFIG} declares {module_path!r}, which the loader's namespace "
            "check rejects -- so every plugin the shipped example defines goes "
            "unregistered in any path without a discover_plugins fallback"
        )


@pytest.mark.parametrize(
    "module_path",
    [
        "my_ash_plugins",
        "my_ash_plugins.scanners",
        "my_custom_ash_plugins",
        "ash_plugins",
        "ash_plugins.scanners",
        "automated_security_helper.plugin_modules.ash_builtin",
    ],
)
def test_documented_namespaces_are_accepted(module_path):
    """Every spelling the documentation uses, including submodule paths.

    The top-level package is what is tested, so ``my_ash_plugins.scanners`` is
    accepted on the strength of ``my_ash_plugins`` rather than needing its own rule.
    """
    assert _is_allowed_module_path(module_path)


@pytest.mark.parametrize(
    "module_path",
    [
        "evil_package.backdoor",
        "os",
        "subprocess",
        "requests",
        "ash_plugins_but_not_really.payload",
    ],
)
def test_arbitrary_modules_are_still_refused(module_path):
    """The control, and the reason this widened rather than removed the check.

    A config file naming an arbitrary importable module is what the check exists to
    stop, and it still does. ``TestPluginLoaderNamespaceValidation`` in
    tests/unit/test_defense_in_depth.py holds the same line from the log side.

    ``ash_plugins_but_not_really`` is the case a naive ``"ash_plugins" in name``
    would let through: the convention is a SUFFIX, so a package merely mentioning
    the namespace does not join it.
    """
    assert not _is_allowed_module_path(module_path)


def test_the_suffix_matches_the_convention_used_elsewhere():
    """One naming rule, not two.

    ``core.scanner_inventory._discover_external_scanner_plugin_packages`` selects
    installed distributions with ``startswith("ash_") and endswith("_plugins")``.
    The loader's suffix has to agree with that, or an installed plugin distribution
    would be discoverable by one and unloadable by the other.
    """
    assert _ALLOWED_TOP_LEVEL_SUFFIX == "ash_plugins"
    assert f"ash_{_ALLOWED_TOP_LEVEL_SUFFIX[4:]}".endswith("_plugins")
