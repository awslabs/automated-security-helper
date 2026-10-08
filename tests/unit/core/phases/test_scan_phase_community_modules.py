# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Community scanners that ship with ASH run only when their module is listed.

Why this exists
---------------
gitleaks, zizmor, actionlint, cfn-lint, cfn-guard and trivy live in community
plugin modules (``plugin_modules/ash_*_plugins``). Listing a module is the opt-in: a run that does not list it never loads its scanners, so a
default scan is unchanged by them. Two things follow, and are tested here:

* ``--scanners gitleaks`` without ``ash_gitleaks_plugins`` listed names a scanner
  ASH has but did not load. It is refused with the module to add, rather than
  read as a typo, and refused even when other names in the selection resolved.
* With the module loaded, its scanner is an ordinary scanner and runs by default.

The scan-phase tests drive the real ``ScanPhase`` with plain scanner classes that
are never registered globally, so nothing leaks into other tests.
"""

import importlib
from pathlib import Path
from typing import List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.community_scanners import (
    community_module_for,
    community_scanner_modules,
)
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

PKG = "automated_security_helper.plugin_modules"
CONTROL_NAME = "dummy-control"


def _sarif(tool: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": tool}}, "results": []}],
        }
    )


class _ControlConfig(ScannerPluginConfigBase):
    name: Literal["dummy-control"] = CONTROL_NAME
    enabled: bool = True


class DummyControlScanner(ScannerPluginBase[_ControlConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _ControlConfig()
        self.command = "dummy-control-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        return _sarif(CONTROL_NAME)


class _RaisingConfig(ScannerPluginConfigBase):
    name: Literal["dummy-raising"] = "dummy-raising"
    enabled: bool = True


class RaisingScanner(ScannerPluginBase[_RaisingConfig]):
    def model_post_init(self, context):
        raise RuntimeError("cannot be built")

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


def _context(tmp_path: Path) -> PluginContext:
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "app.py").write_text("print('hello')\n")
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )


def _scan(context, plugins, enabled_scanners: List[str]) -> AshAggregatedResults:
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=list(plugins),
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated,
        enabled_scanners=enabled_scanners,
        parallel=False,
    )
    return populate_metrics_from_unified_source(aggregated_results=results)


# --------------------------------------------------------------------------- #
# The name-to-module map
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scanner,module",
    [
        ("actionlint", "ash_actionlint_plugins"),
        ("cfn-guard", "ash_cfn_plugins"),
        ("cfn-lint", "ash_cfn_plugins"),
        ("gitleaks", "ash_gitleaks_plugins"),
        ("trivy", "ash_trivy_plugins"),
        ("trivy-repo", "ash_trivy_plugins"),
        ("zizmor", "ash_zizmor_plugins"),
    ],
)
def test_each_community_scanner_maps_to_its_module(scanner, module):
    assert community_module_for(scanner) == f"{PKG}.{module}"
    assert community_module_for(f"  {scanner.upper()} ") == f"{PKG}.{module}"


def test_builtin_scanners_are_not_community_scanners():
    for builtin in ("bandit", "semgrep", "detect-secrets", "grype", "checkov"):
        assert community_module_for(builtin) is None


def test_the_map_agrees_with_what_each_module_registers():
    """Read from source; checked here against the classes the modules export."""
    by_module = {}
    for name, module in community_scanner_modules().items():
        by_module.setdefault(module, set()).add(name)
    for module, names in by_module.items():
        exported = importlib.import_module(module).ASH_SCANNERS
        declared = set()
        for cls in exported:
            config_cls = cls.model_fields["config"].annotation
            for arg in getattr(config_cls, "__args__", (config_cls,)):
                field = (getattr(arg, "model_fields", None) or {}).get("name")
                if field is not None and isinstance(field.default, str):
                    declared.add(field.default.lower())
        assert names == declared, module


# --------------------------------------------------------------------------- #
# The scan phase
# --------------------------------------------------------------------------- #


def test_an_unloaded_community_scanner_is_refused_with_its_module(tmp_path):
    with pytest.raises(ScannerSelectionError) as raised:
        _scan(_context(tmp_path), [DummyControlScanner], ["gitleaks"])
    message = str(raised.value)
    assert "gitleaks is a community scanner" in message
    assert f"{PKG}.ash_gitleaks_plugins" in message
    assert f"--ash-plugin-modules {PKG}.ash_gitleaks_plugins" in message


def test_a_partly_resolved_selection_warns_with_the_module(tmp_path, caplog):
    """Main's rule for a partly unresolved selection holds: warn and continue.

    A CI matrix whose runners load different plugin modules produces this shape
    legitimately, so it is not refused. The warning names the module to add.
    """
    import logging

    with caplog.at_level(logging.WARNING):
        results = _scan(
            _context(tmp_path), [DummyControlScanner], [CONTROL_NAME, "zizmor"]
        )
    assert CONTROL_NAME in results.scanner_results
    assert "zizmor is a community scanner" in caplog.text
    assert f"--ash-plugin-modules {PKG}.ash_zizmor_plugins" in caplog.text


def test_a_scanner_that_failed_to_construct_is_not_called_unloaded(tmp_path):
    """Its module supplied the class; the ERROR row is the answer, not a refusal."""
    from automated_security_helper.plugin_modules.ash_gitleaks_plugins import (
        ASH_SCANNERS,
    )

    (gitleaks,) = ASH_SCANNERS

    class Broken(gitleaks):
        def model_post_init(self, context):
            raise RuntimeError("cannot be built")

    Broken.__module__ = gitleaks.__module__
    results = _scan(_context(tmp_path), [DummyControlScanner, Broken], ["gitleaks"])
    assert str(results.scanner_results["gitleaks"].status).upper().endswith("ERROR")


def test_a_loaded_module_without_the_name_gets_the_generic_message(tmp_path):
    """The module hint would send the operator to add a module already listed."""

    class FromTheModule(DummyControlScanner):
        pass

    FromTheModule.__module__ = f"{PKG}.ash_gitleaks_plugins.gitleaks_scanner"
    with pytest.raises(ScannerSelectionError) as raised:
        _scan(_context(tmp_path), [FromTheModule], ["gitleaks"])
    assert "None of the requested scanners exist" in str(raised.value)
    assert "not loaded" not in str(raised.value)


def test_the_trivy_refusal_says_it_is_off_by_default(tmp_path):
    with pytest.raises(ScannerSelectionError) as raised:
        _scan(_context(tmp_path), [DummyControlScanner], ["trivy"])
    message = str(raised.value)
    assert f"{PKG}.ash_trivy_plugins" in message
    assert "scanners.trivy.enabled: true" in message


def test_the_enable_hint_uses_the_normalized_name(tmp_path):
    with pytest.raises(ScannerSelectionError) as raised:
        _scan(_context(tmp_path), [DummyControlScanner], ["  TRIVY "])
    assert "scanners.trivy.enabled: true" in str(raised.value)


def test_only_trivy_is_off_by_default():
    from automated_security_helper.core.community_scanners import (
        community_scanners_off_by_default,
    )

    assert community_scanners_off_by_default() == {"trivy"}


def test_several_unloaded_scanners_name_every_module_once(tmp_path):
    with pytest.raises(ScannerSelectionError) as raised:
        _scan(
            _context(tmp_path),
            [DummyControlScanner],
            ["cfn-lint", "cfn-guard", "gitleaks"],
        )
    message = str(raised.value)
    assert "are community scanners" in message
    assert message.count(f"--ash-plugin-modules {PKG}.ash_cfn_plugins") == 1
    assert f"{PKG}.ash_gitleaks_plugins" in message


def test_a_plain_typo_keeps_the_generic_refusal(tmp_path):
    with pytest.raises(ScannerSelectionError, match="None of the requested"):
        _scan(_context(tmp_path), [DummyControlScanner], ["not-a-scanner"])


def test_with_the_module_loaded_its_scanner_resolves_and_runs(tmp_path):
    """Negative control for the refusal: the same name, its class loaded."""
    from automated_security_helper.plugin_modules.ash_gitleaks_plugins import (
        ASH_SCANNERS,
    )

    (gitleaks,) = ASH_SCANNERS

    class Present(gitleaks):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            return _sarif("gitleaks")

    results = _scan(_context(tmp_path), [DummyControlScanner, Present], ["gitleaks"])
    assert "gitleaks" in results.scanner_results


@pytest.mark.parametrize(
    "module,scanners",
    [
        ("ash_actionlint_plugins", {"actionlint"}),
        ("ash_cfn_plugins", {"cfn-lint", "cfn-guard"}),
        ("ash_gitleaks_plugins", {"gitleaks"}),
        ("ash_zizmor_plugins", {"zizmor"}),
    ],
)
def test_a_listed_modules_scanners_are_on_by_default(module, scanners):
    """Listing the module is the opt-in, as for every community plugin."""
    exported = importlib.import_module(f"{PKG}.{module}").ASH_SCANNERS
    on = {}
    for cls in exported:
        config_cls = cls.model_fields["config"].annotation
        for arg in getattr(config_cls, "__args__", (config_cls,)):
            fields = getattr(arg, "model_fields", None) or {}
            name = getattr(fields.get("name"), "default", None)
            if isinstance(name, str) and "enabled" in fields:
                on[name] = arg().enabled
    assert on == dict.fromkeys(scanners, True)


def test_the_trivy_fs_scanner_stays_off_beside_trivy_repo():
    """The trivy module already held trivy-repo; listing it must not add trivy."""
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_scanner import (
        TrivyScannerConfig,
    )

    assert TrivyRepoScannerConfig().enabled is True
    assert TrivyScannerConfig().enabled is False


def test_a_scanner_that_cannot_be_built_is_an_error_under_its_declared_name(
    tmp_path,
):
    """Not under its class name (``raisingscanner``), which nothing else matches."""
    results = _scan(
        _context(tmp_path),
        [DummyControlScanner, RaisingScanner],
        [CONTROL_NAME, "dummy-raising"],
    )
    assert "dummy-raising" in results.scanner_results, list(results.scanner_results)
    assert results.scanner_results["dummy-raising"].status.value == "ERROR"
    assert "raisingscanner" not in results.scanner_results
