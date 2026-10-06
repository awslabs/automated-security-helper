# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin configured under its documented key runs with that configuration.

Why this file exists
--------------------
The scan, report and convert phases looked each plugin's config up by
``plugin_class.__name__.lower()``, and ``get_plugin_config`` then squeezed that
and every config key into a common form, hoping the two would meet. They do for
most plugins because the class name happens to spell the key. They do not for
two that ship in this package:

* ``GHASReporter`` reduces to ``ghas``, its key ``github-ghas`` to ``githubghas``.
* ``SecurityHubReporter`` reduces to ``securityhub``, its key
  ``aws-security-hub`` to ``awssecurityhub``.

For those, the lookup returned nothing and the reporter ran with its defaults,
whatever the config said. The lookup now keys on the name the plugin declares
for itself -- its config class's ``name`` -- which is also the key it is
documented and configured under.

Each case below is one registered plugin, taken from the plugin registry after
importing every plugin package this distribution ships, and the assertion is on
the plugin instance the real phase builds. Nothing here lists plugins by hand.
"""

import ast
import importlib
import pkgutil
import typing
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import automated_security_helper
import automated_security_helper.plugin_modules as plugin_packages
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import (
    AshConfig,
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager

for _module in pkgutil.iter_modules(plugin_packages.__path__):
    importlib.import_module(f"{plugin_packages.__name__}.{_module.name}")

SHIPPED_PREFIX = f"{plugin_packages.__name__}."
SEGMENTS = {
    "scanner": ("scanners", ScannerConfigSegment),
    "reporter": ("reporters", ReporterConfigSegment),
    "converter": ("converters", ConverterConfigSegment),
}
MARKER = "reached-the-plugin"


def _config_class(plugin_class):
    annotation = plugin_class.model_fields["config"].annotation
    args = [a for a in typing.get_args(annotation) if a is not type(None)]
    return args[0] if args else annotation


def _documented_key(plugin_type, plugin_class) -> str:
    """The key the docs and the schema tell a user to write.

    For a plugin with a declared segment field that is the field's alias, or its
    name when it has none. A plugin with no declared field (the AWS and other
    optional packages) is configured through ``extra="allow"`` under its own
    config name.
    """
    _, segment_cls = SEGMENTS[plugin_type]
    config_cls = _config_class(plugin_class)
    for field_name, info in segment_cls.model_fields.items():
        if info.annotation is config_cls:
            return info.alias or field_name
    return config_cls().name


def _shipped(plugin_type):
    return [
        cls
        for cls in ash_plugin_manager.plugin_modules(plugin_type)
        if cls.__module__.startswith(SHIPPED_PREFIX)
    ]


def _cases(plugin_type):
    return [
        pytest.param(cls, id=_documented_key(plugin_type, cls))
        for cls in _shipped(plugin_type)
    ]


def _probe_config(plugin_type, enabled: bool = False) -> AshConfig:
    segment_key, _ = SEGMENTS[plugin_type]
    return AshConfig.model_validate(
        {
            "project_name": "probe",
            segment_key: {
                _documented_key(plugin_type, cls): {
                    "enabled": enabled,
                    "options": {"probe_marker": MARKER},
                }
                for cls in _shipped(plugin_type)
            },
        }
    )


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    work = tmp_path / "out" / "work"
    work.mkdir(parents=True)
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=work,
        config=config,
    )


def _assert_reached(instance, enabled: bool = False):
    assert instance.config.enabled is enabled, (
        f"{type(instance).__name__} runs with enabled={instance.config.enabled}; "
        "its configuration never reached it"
    )
    assert getattr(instance.config.options, "probe_marker", None) == MARKER


def test_every_shipped_plugin_type_is_represented():
    """Guards the derivation: an empty registry would make every case vacuous."""
    for plugin_type in SEGMENTS:
        assert _shipped(plugin_type), f"no shipped {plugin_type} is registered"


# --------------------------------------------------------------------------- #
# The phases, each run for real, with the plugin instances captured as built.
# --------------------------------------------------------------------------- #


def _build_scan_phase_instances(context):
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    phase = ScanPhase(
        plugin_context=context,
        plugins=_shipped("scanner"),
        progress_display=LiveProgressDisplay(show_progress=False),
    )
    captured = {}
    original = phase.validation_manager.validate_registered_scanners

    def capture(instances):
        captured.update({type(i): i for i in instances})
        return original(instances)

    phase.validation_manager.validate_registered_scanners = capture
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor_cls:
        results = AshAggregatedResults()
        executor = MagicMock()
        executor.completed_scanners = []
        executor.run_parallel.return_value = results
        executor.run_sequential.return_value = results
        executor_cls.return_value = executor
        phase._execute_phase(
            aggregated_results=results, python_based_plugins_only=False
        )
    return captured


@pytest.fixture(scope="module")
def scan_phase_instances(tmp_path_factory):
    return _build_scan_phase_instances(
        _context(tmp_path_factory.mktemp("scan"), _probe_config("scanner"))
    )


@pytest.fixture(scope="module")
def scan_phase_enabled_instances(tmp_path_factory):
    """Every scanner configured enabled: true, for the opt-in ones.

    An opt-in scanner whose config says enabled: false is not built at all
    (core/scanner_opt_in.py), so the probe above cannot reach it; enabling it in
    config is the documented way to turn it on, and that config must arrive.
    """
    return _build_scan_phase_instances(
        _context(
            tmp_path_factory.mktemp("scan-enabled"),
            _probe_config("scanner", enabled=True),
        )
    )


@pytest.mark.parametrize("plugin_class", _cases("scanner"))
def test_scan_phase_builds_each_scanner_with_its_config(
    scan_phase_instances, scan_phase_enabled_instances, plugin_class
):
    from automated_security_helper.core.scanner_opt_in import is_opt_in

    if is_opt_in(plugin_class):
        assert plugin_class not in scan_phase_instances, (
            "an opt-in scanner configured enabled: false was built; it must be "
            "left out of the run entirely"
        )
        assert plugin_class in scan_phase_enabled_instances, (
            "the scan phase never built it when its config enabled it"
        )
        _assert_reached(scan_phase_enabled_instances[plugin_class], enabled=True)
        return
    assert plugin_class in scan_phase_instances, "the scan phase never built it"
    _assert_reached(scan_phase_instances[plugin_class])


def _captured_by_filter(phase_cls, plugin_type, tmp_path, run):
    context = _context(tmp_path, _probe_config(plugin_type))
    phase = phase_cls(
        plugins=_shipped(plugin_type),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    captured = {}
    original = phase.filter_enabled_plugins

    def capture(plugin_instances, *args, **kwargs):
        captured.update({type(i): i for i in plugin_instances})
        return original(plugin_instances, *args, **kwargs)

    phase.filter_enabled_plugins = capture
    run(phase, tmp_path)
    return captured


@pytest.fixture(scope="module")
def report_phase_instances(tmp_path_factory):
    from automated_security_helper.core.phases.report_phase import ReportPhase

    def run(phase, tmp_path):
        phase._execute_phase(
            report_dir=tmp_path / "out" / "reports",
            cli_output_formats=None,
            aggregated_results=AshAggregatedResults(),
            python_based_plugins_only=False,
        )

    return _captured_by_filter(
        ReportPhase, "reporter", tmp_path_factory.mktemp("report"), run
    )


@pytest.mark.parametrize("plugin_class", _cases("reporter"))
def test_report_phase_builds_each_reporter_with_its_config(
    report_phase_instances, plugin_class
):
    assert plugin_class in report_phase_instances, "the report phase never built it"
    _assert_reached(report_phase_instances[plugin_class])


@pytest.fixture(scope="module")
def convert_phase_instances(tmp_path_factory):
    from automated_security_helper.core.phases.convert_phase import ConvertPhase

    def run(phase, tmp_path):
        phase._execute_phase(aggregated_results=AshAggregatedResults())

    return _captured_by_filter(
        ConvertPhase, "converter", tmp_path_factory.mktemp("convert"), run
    )


@pytest.mark.parametrize("plugin_class", _cases("converter"))
def test_convert_phase_builds_each_converter_with_its_config(
    convert_phase_instances, plugin_class
):
    assert plugin_class in convert_phase_instances, "the convert phase never built it"
    _assert_reached(convert_phase_instances[plugin_class])


@pytest.mark.parametrize("plugin_class", _cases("reporter"))
def test_workspace_reporting_builds_each_reporter_with_its_config(
    tmp_path, plugin_class
):
    """Workspace-level reporting builds reporters through its own call site."""
    from automated_security_helper.workspace.reporting import _build_instance

    config = _probe_config("reporter")
    context = _context(tmp_path, config)

    def config_lookup(plugin_name):
        return config.get_plugin_config(plugin_type="reporter", plugin_name=plugin_name)

    instance = _build_instance(plugin_class, context, config_lookup)
    assert instance is not None
    _assert_reached(instance)


# --------------------------------------------------------------------------- #
# Every call site, including the ones not driven above.
# --------------------------------------------------------------------------- #


def _names_bound_from_class_name(function: ast.AST) -> set:
    """Local names whose value is built from a ``__name__`` attribute or string."""
    bound = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            source = ast.dump(node.value)
            if "'__name__'" in source or "attr='__name__'" in source:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.add(target.id)
    return bound


def _plugin_name_argument(call: ast.Call):
    for keyword in call.keywords:
        if keyword.arg == "plugin_name":
            return keyword.value
    return call.args[1] if len(call.args) > 1 else None


def test_no_call_site_looks_config_up_by_class_name():
    """Direct runs above cover the phases; this covers every other caller.

    A ``get_plugin_config`` call whose name argument is derived from a class's
    ``__name__`` is the pattern that missed GHASReporter and SecurityHubReporter.
    Such callers must use ``plugin_config_key`` instead.
    """
    package_root = Path(automated_security_helper.__file__).parent
    offenders = []
    for path in sorted(package_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            from_class_name = _names_bound_from_class_name(function)
            for call in ast.walk(function):
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "get_plugin_config"
                ):
                    continue
                argument = _plugin_name_argument(call)
                if argument is None:
                    continue
                used = {n.id for n in ast.walk(argument) if isinstance(n, ast.Name)}
                source = ast.dump(argument)
                if used & from_class_name or "'__name__'" in source:
                    offenders.append(
                        f"{path.relative_to(package_root)}:{call.lineno} "
                        f"({function.name})"
                    )
    assert offenders == [], (
        f"these look plugin config up by class name; use plugin_config_key: {offenders}"
    )


def test_the_guard_above_catches_the_pattern_it_names():
    source = (
        "def f(plugin_class, config):\n"
        "    plugin_name = getattr(plugin_class, '__name__', 'x')\n"
        "    return config.get_plugin_config(plugin_type='reporter',"
        " plugin_name=plugin_name.lower())\n"
    )
    function = ast.parse(source).body[0]
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and getattr(n.func, "attr", "") == "get_plugin_config"
    )
    used = {
        n.id for n in ast.walk(_plugin_name_argument(call)) if isinstance(n, ast.Name)
    }
    assert used & _names_bound_from_class_name(function)
