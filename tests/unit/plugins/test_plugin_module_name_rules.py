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
  built-in plugins (defined in ``ash_builtin``), and for each module the scan names,
  the plugins defined in that module itself, bound in its namespace (imported into
  it), or listed in its ``ASH_*`` declarations. A plugin defined only in a submodule
  of a named package is not selected through the package, because whether that
  submodule is imported depends on what else ran in the process.

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

    def test_naming_the_module_that_defines_a_class_selects_it(self):
        """Control for the test above: the same class through the module defining it.

        Naming the package above that module does not select the class: the package
        neither binds nor lists this one (it binds and lists ASH's own snyk scanner,
        a different class), and a class whose module is below a named package is
        not selected for that alone.
        """
        snyk = _plugin(f"{SNYK_PACKAGE}.snyk_code_scanner", "SnykCodeScanner")

        assert scan_plugin_filter([f"{SNYK_PACKAGE}.snyk_code_scanner"])(snyk)
        assert not scan_plugin_filter([SNYK_PACKAGE])(snyk)


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


class TestWhatANamedModuleSelects:
    def test_a_class_another_package_defines_and_the_named_one_lists(self, site):
        _write(
            site,
            "zzhelper_pkg/__init__.py",
            "class HelperScanner:\n    ash_plugin_type = 'scanner'\n",
        )
        _write(
            site,
            "zzlists_ash_plugins/__init__.py",
            "from zzhelper_pkg import HelperScanner\nASH_SCANNERS = [HelperScanner]\n",
        )
        importlib.invalidate_caches()
        importlib.import_module("zzlists_ash_plugins")
        helper = sys.modules["zzhelper_pkg"].HelperScanner

        assert scan_plugin_filter(["zzlists_ash_plugins"])(helper)
        assert not scan_plugin_filter([])(helper), "control: unnamed, unselected"

    def test_a_class_only_in_a_submodule_with_no_declarations(self, site):
        """Naming the package or a package between does not select it.

        The submodule is imported here, the state an earlier scan that named it
        leaves behind. A scan naming only the package never imports it, so what the
        package selects must not depend on that import.
        """
        _write(site, "zzsub_ash_plugins/__init__.py")
        _write(site, "zzsub_ash_plugins/scanners/__init__.py")
        _write(
            site,
            "zzsub_ash_plugins/scanners/deep.py",
            "class DeepScanner:\n    ash_plugin_type = 'scanner'\n",
        )
        importlib.invalidate_caches()
        deep = importlib.import_module("zzsub_ash_plugins.scanners.deep").DeepScanner

        assert not scan_plugin_filter(["zzsub_ash_plugins"])(deep)
        assert not scan_plugin_filter(["zzsub_ash_plugins.scanners"])(deep)
        assert scan_plugin_filter(["zzsub_ash_plugins.scanners.deep"])(deep), (
            "control: the module that defines the class selects it"
        )

    def test_a_class_the_named_package_imports_into_its_namespace(self, site):
        """Bound in the package's namespace: selected, and only that class object."""
        _write(
            site,
            "zzbind_ash_plugins/__init__.py",
            "from zzbind_ash_plugins.scanners import BoundScanner\n",
        )
        _write(
            site,
            "zzbind_ash_plugins/scanners.py",
            "class BoundScanner:\n    ash_plugin_type = 'scanner'\n",
        )
        importlib.invalidate_caches()
        importlib.import_module("zzbind_ash_plugins")
        bound = sys.modules["zzbind_ash_plugins.scanners"].BoundScanner
        same_name = _plugin("zzbind_ash_plugins.scanners", "BoundScanner")

        assert scan_plugin_filter(["zzbind_ash_plugins"])(bound)
        assert not scan_plugin_filter(["zzbind_ash_plugins"])(same_name), (
            "a different class with the bound class's name and module was selected"
        )

    def test_a_handler_the_named_module_declares(self, site):
        _write(
            site, "zzhandlers_pkg/__init__.py", "def on_event(**kwargs):\n    pass\n"
        )
        _write(
            site,
            "zzevents2_ash_plugins/__init__.py",
            "from zzhandlers_pkg import on_event\n"
            "ASH_EVENT_HANDLERS = {'scan_complete': [on_event]}\n",
        )
        importlib.invalidate_caches()
        importlib.import_module("zzevents2_ash_plugins")
        handler = sys.modules["zzhandlers_pkg"].on_event

        assert scan_plugin_filter(["zzevents2_ash_plugins"])(handler)
        assert not scan_plugin_filter([])(handler)


class TestTheWorkspacePrewarmRefusesBeforeImporting:
    def test_an_accepted_name_beside_a_refused_one_is_not_imported(
        self, site, tmp_path
    ):
        """The pre-warm refuses first; it does not import the names it accepts."""
        from automated_security_helper.workspace.execution import (
            ProjectScanSettings,
            prewarm_plugin_registry,
        )
        from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

        for name in ("zzprewarm_ash_plugins", "zz_prewarm_refused"):
            _write(site, f"{name}/__init__.py", "LOADED = True\n")
        importlib.invalidate_caches()
        plan = WorkspacePlan(
            workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            projects=[
                ProjectPlan(
                    key="api",
                    relative_path="api",
                    path=(tmp_path / "api").as_posix(),
                    label="api",
                    display_label="api",
                    severity_threshold="MEDIUM",
                    ash_plugin_modules=["zzprewarm_ash_plugins", "zz_prewarm_refused"],
                )
            ],
        )

        with pytest.raises(PluginModuleNamespaceError):
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )

        assert "zzprewarm_ash_plugins" not in sys.modules
        assert "zz_prewarm_refused" not in sys.modules
