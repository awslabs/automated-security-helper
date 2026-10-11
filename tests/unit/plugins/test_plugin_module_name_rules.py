# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``ash_plugin_modules`` names a scan accepts, and which plugins each name selects.

``plugins/loader.py`` holds two rules that decide what a scan runs:

* ``refuse_plugin_modules_outside_namespace``, which refuses a name with exit code 3
  before anything is imported. A name must be a dotted path of ASCII identifiers in
  ASH's plugin namespace (``automated_security_helper.``, ``ash_plugins``, or a
  top-level package named ``ash_plugins`` or ending in ``_ash_plugins``), and must not
  be ASH's plugin root ``automated_security_helper.plugin_modules`` or above it, which
  holds every plugin package ASH ships and names none of them.
* ``scan_plugin_filter``, which selects from the process-wide registry: ASH's
  built-in plugins (defined in ``ash_builtin``), plugins defined in or below a module
  the scan names, and plugins a named module lists in its ``ASH_*`` declarations. A
  name that holds other plugin packages (the plugin root, or a namespace package)
  selects nothing below it.

The classes here are plain objects with ``__module__`` set, or classes in temporary
packages, so the process-wide registry is never touched.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins.loader import (
    PluginModuleNamespaceError,
    refuse_plugin_modules_outside_namespace,
    scan_plugin_filter,
)

PLUGIN_ROOT = "automated_security_helper.plugin_modules"
SNYK_PACKAGE = f"{PLUGIN_ROOT}.ash_snyk_plugins"


def _plugin(module: str, name: str = "SomeScanner") -> type:
    """A class that claims to be defined in *module*; nothing registers it."""
    return type(name, (), {"__module__": module, "ash_plugin_type": "scanner"})


def _write(root: Path, relative: str, text: str = "") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def site(tmp_path, monkeypatch):
    """A directory on sys.path for temporary packages, forgotten afterwards."""
    root = tmp_path / "site"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    before = set(sys.modules)
    yield root
    for name in set(sys.modules) - before:
        del sys.modules[name]
    importlib.invalidate_caches()


class TestThePluginRootIsRefused:
    @pytest.mark.parametrize("name", [PLUGIN_ROOT, "automated_security_helper"])
    def test_a_name_at_or_above_the_plugin_root_refuses_the_scan(self, name):
        with pytest.raises(PluginModuleNamespaceError) as raised:
            refuse_plugin_modules_outside_namespace([name])

        assert isinstance(raised.value, ASHConfigValidationError)
        assert repr(name) in str(raised.value)

    def test_a_package_below_the_plugin_root_is_accepted(self):
        refuse_plugin_modules_outside_namespace(
            [SNYK_PACKAGE, f"{SNYK_PACKAGE}.snyk_code_scanner"]
        )

    def test_the_plugin_root_selects_nothing_below_it(self):
        """Even if a caller skipped the refusal, the root admits no shipped plugin."""
        snyk = _plugin(f"{SNYK_PACKAGE}.snyk_code_scanner", "SnykCodeScanner")
        aws = _plugin(f"{PLUGIN_ROOT}.ash_aws_plugins.s3_reporter", "S3Reporter")

        admits = scan_plugin_filter([PLUGIN_ROOT])

        assert not admits(snyk)
        assert not admits(aws)

    def test_naming_the_package_itself_still_selects_it(self):
        """Control for the test above: the same class through its own package."""
        snyk = _plugin(f"{SNYK_PACKAGE}.snyk_code_scanner", "SnykCodeScanner")

        assert scan_plugin_filter([SNYK_PACKAGE])(snyk)


class TestANamespacePackageSelectsNothingBelowIt:
    def test_a_namespace_package_does_not_select_its_portions(self, site):
        """A PEP 420 package holds other packages; naming it names none of them."""
        _write(site, "zzshared_ash_plugins/vendor_a/__init__.py")
        _write(site, "zzshared_ash_plugins/vendor_b/__init__.py")
        importlib.invalidate_caches()
        importlib.import_module("zzshared_ash_plugins.vendor_b")
        other_vendor = _plugin("zzshared_ash_plugins.vendor_b", "VendorBScanner")

        assert not scan_plugin_filter(["zzshared_ash_plugins"])(other_vendor)
        assert scan_plugin_filter(["zzshared_ash_plugins.vendor_b"])(other_vendor)


class TestNameSpelling:
    @pytest.mark.parametrize(
        "name",
        [
            "hash_plugins",
            "dash_plugins",
            "flash_plugins.scanners",
            "myash_plugins",
            "automated_security_helper.",
            "automated_security_helper..x",
            "ash_plugins..x",
            " my_ash_plugins",
            "my_ash_plugins ",
            "zz_other,my_ash_plugins",
            "ｍy_ash_plugins",
            "my-ash_plugins",
        ],
    )
    def test_a_name_that_is_not_a_plugin_module_path_is_refused(self, name):
        with pytest.raises(PluginModuleNamespaceError):
            refuse_plugin_modules_outside_namespace([name])

    @pytest.mark.parametrize(
        "name",
        [
            "my_ash_plugins",
            "my_ash_plugins.scanners",
            "ash_plugins",
            "ash_plugins.vendor",
            "acme2_ash_plugins",
            SNYK_PACKAGE,
        ],
    )
    def test_a_plugin_module_path_is_accepted(self, name):
        refuse_plugin_modules_outside_namespace([name])


class TestBuiltInPlugins:
    def test_a_plugin_defined_in_ash_builtin_is_selected_without_being_named(self):
        builtin = _plugin(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner",
            "BanditScanner",
        )

        assert scan_plugin_filter([])(builtin)

    @pytest.mark.parametrize(
        "module",
        [
            "automated_security_helper.core.zz_plugin",
            "automated_security_helper.utils.zz_plugin",
            "automated_security_helper.plugin_modules.ash_builtin_extra.zz_plugin",
        ],
    )
    def test_a_plugin_elsewhere_in_the_package_is_not_built_in(self, module):
        assert not scan_plugin_filter([])(_plugin(module))
