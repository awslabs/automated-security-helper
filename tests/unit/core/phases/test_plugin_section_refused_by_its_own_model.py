# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner or converter section its own config model refuses fails that plugin.

``ScannerPluginBase`` and ``ConverterPluginBase`` type ``config`` as the plugin's
own model, the base config model, or None. Given a section the plugin's model
refused, pydantic built the base model from it and raised nothing, so the
plugin's validators were skipped: a plugin scanner's section, which ``AshConfig``
keeps as a plain dict, reached the scanner unchecked. ``snyk-code`` ran with
``honor_tree_exclusions: "flase"`` kept as a truthy string. Other scanners failed
later, on an attribute the base options model lacks, with an error that named
neither the option nor the scanner's own name.

``AshConfig`` validates the built-in scanners' and converters' sections when the
config is loaded, so the built-in cases below hand the phase the section through
its config lookup, as for a section that reached it some other way. The plugin
scanner's section goes through ``AshConfig`` itself.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.interactions.run_ash_scan import (
    incomplete_converters,
    incomplete_scanners,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)

pytestmark = pytest.mark.unit


def _healthy_scanner(name="bandit"):
    """A scanner double that passes every filter and is queued for execution."""

    class _Healthy:
        def __init__(self, config=None, context=None):
            self.config = MagicMock()
            self.config.name = name
            self.config.enabled = True
            self.dependencies_satisfied = True

        def is_python_only(self):
            return True

        def unsupported_platform_reason(self):
            return None

        def validate_plugin_dependencies(self):
            return True

    _Healthy.__name__ = name
    return _Healthy


def _context(tmp_path, config: AshConfig) -> PluginContext:
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
    )


def _run_scan_phase(context, plugin_classes) -> AshAggregatedResults:
    """Run ScanPhase; the executor double records PASSED for each queued scanner."""
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=list(plugin_classes),
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    double = MagicMock()
    double.completed_scanners = []

    def _run(model):
        for scanner_name, _instance, _tasks in phase._scanner_tasks:
            model.scanner_results[scanner_name] = ScannerStatusInfo(
                status=ScannerStatus.PASSED,
                excluded=False,
                dependencies_satisfied=True,
            )
            double.completed_scanners.append(scanner_name)
            phase.validation_manager.update_scanner_state(
                scanner_name, execution_completed=True
            )
        return model

    double.run_parallel.side_effect = _run
    double.run_sequential.side_effect = _run
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        executor.return_value = double
        return phase._execute_phase(aggregated_results=aggregated)


def _looked_up_as(wanted_type: str, key: str, section: Dict[str, Any]):
    """Have the config lookup return ``section`` for one plugin."""
    original = AshConfig.get_plugin_config

    def lookup(self, plugin_type, plugin_name):
        if plugin_type == wanted_type and plugin_name == key:
            return dict(section)
        return original(self, plugin_type=plugin_type, plugin_name=plugin_name)

    return patch.object(AshConfig, "get_plugin_config", lookup)


def _recorded_text(results: AshAggregatedResults) -> str:
    return str(results.additional_reports) + str(
        results.metadata.model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "section",
    [
        {"options": {"honor_tree_exclusions": "flase"}},
        {"name": "snyk-code", "options": {"honor_tree_exclusions": "flase"}},
    ],
    ids=["without-name", "with-name"],
)
def test_a_plugin_scanner_section_its_model_refuses_fails_that_scanner(
    section, tmp_path
):
    config = AshConfig.model_validate({"scanners": {"snyk-code": section}})

    results = _run_scan_phase(
        _context(tmp_path, config), [SnykCodeScanner, _healthy_scanner()]
    )

    assert "snyk-code" in results.scanner_results, sorted(results.scanner_results)
    assert results.scanner_results["snyk-code"].status == ScannerStatus.ERROR
    assert "honor_tree_exclusions" in _recorded_text(results)
    assert incomplete_scanners(results) == [("snyk-code", "ERROR")]


_BUILT_IN_SCANNER_CASES = [
    (
        CdkNagScanner,
        "cdk-nag",
        {"name": "cdk-nag", "options": {"nag_packs": "all"}},
        "nag_packs",
    ),
    (
        OpengrepScanner,
        "opengrep",
        {"name": "opengrep", "options": {"sha256": {"linux/amd64": "not-a-digest"}}},
        "sha256",
    ),
]


@pytest.mark.parametrize(
    "scanner_class,key,section,option",
    _BUILT_IN_SCANNER_CASES,
    ids=[case[1] for case in _BUILT_IN_SCANNER_CASES],
)
def test_a_built_in_scanner_section_its_model_refuses_fails_that_scanner(
    scanner_class, key, section, option, tmp_path
):
    with pytest.raises(ValidationError):
        AshConfig.model_validate({"scanners": {key: section}})

    with _looked_up_as("scanner", key, section):
        results = _run_scan_phase(
            _context(tmp_path, AshConfig()), [scanner_class, _healthy_scanner()]
        )

    assert key in results.scanner_results, sorted(results.scanner_results)
    assert results.scanner_results[key].status == ScannerStatus.ERROR
    assert option in _recorded_text(results)
    assert incomplete_scanners(results) == [(key, "ERROR")]


def test_a_converter_section_its_model_refuses_fails_that_converter(tmp_path):
    section = {"name": "jupyter", "options": {"install_timeout": "soon"}}
    with pytest.raises(ValidationError):
        AshConfig.model_validate({"converters": {"jupyter": section}})

    context = _context(tmp_path, AshConfig())
    aggregated = AshAggregatedResults(
        name="test", description="test", ash_config=context.config
    )
    progress = MagicMock()
    progress.add_task.return_value = 0
    phase = ConvertPhase(
        plugins=[JupyterConverter, ArchiveConverter],
        plugin_context=context,
        progress_display=progress,
        asharp_model=aggregated,
    )
    # Nothing here may install nbconvert.
    with (
        _looked_up_as("converter", "jupyter", section),
        patch.object(
            JupyterConverter, "validate_plugin_dependencies", return_value=False
        ),
    ):
        results = phase.execute(aggregated_results=aggregated)

    failures = {
        name: row.failure
        for name, row in results.converter_results.items()
        if row.failure is not None
    }
    # Keyed by the name the operator wrote in the config, as a converter that
    # was built is, not by the class name.
    assert list(failures) == ["jupyter"], failures
    assert "ValidationError" in failures["jupyter"], failures
    assert "install_timeout" in failures["jupyter"], failures
    assert results.converter_results["archive"].failure is None
    assert [row.name for row in incomplete_converters(results)] == ["jupyter"]
