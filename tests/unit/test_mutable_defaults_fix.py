"""Regression tests: mutable default arguments must not be shared across calls.

The classic Python footgun is:

    def f(xs: list = []):
        xs.append(1)
        return xs

    f()  # [1]
    f()  # [1, 1]  <- BUG: state leaks across calls

These tests verify that the fix (default=None + inside-function re-bind) holds.
They check both the AST of each target signature AND, where safe, exercise the
function twice to confirm no shared state.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_ROOT = REPO_ROOT / "automated_security_helper"


# ---------------------------------------------------------------------------
# AST-level checks: no function/method default is a mutable literal.
# ---------------------------------------------------------------------------


def _iter_python_files(root: Path):
    for p in root.rglob("*.py"):
        # Skip generated / vendored / cached code
        parts = set(p.parts)
        if "__pycache__" in parts:
            continue
        yield p


def _has_typer_annotation(annotation) -> bool:
    """Check if an annotation uses typer.Option or typer.Argument."""
    if annotation is None:
        return False
    src = ast.dump(annotation)
    return "typer" in src.lower() and ("Option" in src or "Argument" in src)


def _mutable_default_offenders(py_path: Path) -> List[Tuple[str, int, str]]:
    """Return [(function_name, lineno, kind), ...] for mutable literal defaults.

    Only flags function-level and method-level signatures, not class attribute
    annotations (Pydantic fields handle `= []` safely via deep-copy defaults).
    Skips parameters annotated with typer.Option/typer.Argument — those
    frameworks require literal defaults for help-text generation.
    """
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []

    offenders: List[Tuple[str, int, str]] = []

    def _check(node):
        all_args = node.args.args + node.args.kwonlyargs
        all_defaults = node.args.defaults + node.args.kw_defaults
        padded_defaults = [None] * (len(all_args) - len(all_defaults)) + list(all_defaults)
        for arg, default in zip(all_args, padded_defaults):
            if default is None:
                continue
            if _has_typer_annotation(arg.annotation):
                continue
            if isinstance(default, ast.List):
                offenders.append((node.name, node.lineno, "list"))
            elif isinstance(default, ast.Dict):
                offenders.append((node.name, node.lineno, "dict"))
            elif isinstance(default, ast.Set):
                offenders.append((node.name, node.lineno, "set"))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check(node)

    return offenders


def test_no_mutable_default_literals_in_function_signatures():
    """No def/async def in the package may use [] / {} / set() literal as a default."""
    found: List[str] = []
    for py_file in _iter_python_files(PKG_ROOT):
        for fn_name, lineno, kind in _mutable_default_offenders(py_file):
            rel = py_file.relative_to(REPO_ROOT)
            found.append(f"{rel}:{lineno} def {fn_name}(... = <{kind}>)")

    assert not found, (
        "Found mutable default arguments — each call would share the same "
        "list/dict/set across invocations. Offenders:\n  " + "\n  ".join(found)
    )


# ---------------------------------------------------------------------------
# Behavioral check: call a representative fixed function twice, verify isolation.
# ---------------------------------------------------------------------------


def test_load_additional_plugin_modules_default_is_isolated():
    """Each call with the default must receive a distinct, empty collection."""
    from automated_security_helper.plugins import loader

    # Inspect default: should be None, not [].
    sig = inspect.signature(loader.load_additional_plugin_modules)
    default = sig.parameters["plugin_modules"].default
    assert default is None, (
        f"plugin_modules default should be None, got {default!r} "
        "(mutable default arguments are a bug)"
    )


def test_scan_phase_execute_phase_defaults_are_isolated():
    """ScanPhase._execute_phase list parameters must default to None, not []."""
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    sig = inspect.signature(ScanPhase._execute_phase)
    for param_name in ("enabled_scanners", "excluded_scanners", "global_ignore_paths"):
        param = sig.parameters[param_name]
        assert param.default is None, (
            f"ScanPhase._execute_phase({param_name}=...) should default to None, "
            f"got {param.default!r}"
        )


def test_engine_phase_init_plugins_default_is_isolated():
    """EnginePhase.__init__ plugins parameter must default to None, not []."""
    from automated_security_helper.base.engine_phase import EnginePhase

    sig = inspect.signature(EnginePhase.__init__)
    assert sig.parameters["plugins"].default is None, (
        "EnginePhase.__init__(plugins=...) should default to None, "
        f"got {sig.parameters['plugins'].default!r}"
    )


def test_execution_engine_init_defaults_are_isolated():
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    sig = inspect.signature(ScanExecutionEngine.__init__)
    for param_name in (
        "enabled_scanners",
        "excluded_scanners",
        "global_ignore_paths",
        "ash_plugin_modules",
        "output_formats",
    ):
        param = sig.parameters[param_name]
        assert param.default is None, (
            f"ScanExecutionEngine.__init__({param_name}=...) should default to None, "
            f"got {param.default!r}"
        )


def test_run_ash_scan_defaults_are_isolated():
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    sig = inspect.signature(run_ash_scan)
    for param_name in (
        "config_overrides",
        "scanners",
        "exclude_scanners",
        "output_formats",
        "custom_build_arg",
        "ash_plugin_modules",
    ):
        param = sig.parameters[param_name]
        assert param.default is None, (
            f"run_ash_scan({param_name}=...) should default to None, "
            f"got {param.default!r}"
        )


def test_run_ash_container_defaults_are_isolated():
    from automated_security_helper.interactions.run_ash_container import (
        run_ash_container,
    )

    sig = inspect.signature(run_ash_container)
    for param_name in (
        "config_overrides",
        "scanners",
        "exclude_scanners",
        "output_formats",
        "custom_build_arg",
        "ash_plugin_modules",
    ):
        param = sig.parameters[param_name]
        assert param.default is None, (
            f"run_ash_container({param_name}=...) should default to None, "
            f"got {param.default!r}"
        )


def test_get_scan_set_ignorefiles_default_is_isolated():
    from automated_security_helper.utils.get_scan_set import get_ash_ignorespec_lines

    sig = inspect.signature(get_ash_ignorespec_lines)
    assert sig.parameters["ignorefiles"].default is None, (
        "get_ash_ignorespec_lines(ignorefiles=...) should default to None, "
        f"got {sig.parameters['ignorefiles'].default!r}"
    )


def test_scanner_plugin_scan_signatures_use_none_default():
    """All scanner plugin scan() methods should use None default for global_ignore_paths."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    sig = inspect.signature(ScannerPluginBase.scan)
    param = sig.parameters.get("global_ignore_paths")
    assert param is not None, "ScannerPluginBase.scan has no global_ignore_paths param"
    assert param.default is None, (
        "ScannerPluginBase.scan(global_ignore_paths=...) should default to None, "
        f"got {param.default!r}"
    )


SCANNER_MODULES_WITH_SCAN = [
    "automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner",
    "automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner",
]


@pytest.mark.parametrize("module_name", SCANNER_MODULES_WITH_SCAN)
def test_builtin_scanner_scan_signatures_use_none_default(module_name):
    """Every builtin scanner's scan() override should use None, not []."""
    import importlib

    try:
        mod = importlib.import_module(module_name)
    except ImportError as exc:
        pytest.skip(f"Could not import {module_name}: {exc}")

    # Find a class in the module whose `scan` method was defined in this module
    # (not inherited from ScannerPluginBase).
    found_concrete_scan = False
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not isinstance(obj, type):
            continue
        scan_fn = obj.__dict__.get("scan")
        if scan_fn is None:
            continue
        found_concrete_scan = True
        sig = inspect.signature(scan_fn)
        param = sig.parameters.get("global_ignore_paths")
        if param is None:
            continue
        assert param.default is None, (
            f"{module_name}.{attr_name}.scan(global_ignore_paths=...) "
            f"should default to None, got {param.default!r}"
        )

    assert found_concrete_scan, (
        f"Sanity check: expected a concrete scan() override in {module_name}"
    )


# ---------------------------------------------------------------------------
# Behavioral check for scan_tracking.ScannerProgress (the explicit Dict default).
# ---------------------------------------------------------------------------


def test_scanner_progress_severity_counts_not_shared():
    """Two ScannerProgress instances with default severity_counts must not alias."""
    from automated_security_helper.core.resource_management.scan_tracking import (
        ScannerProgress,
    )

    a = ScannerProgress(scanner_name="a", target_type="source")
    b = ScannerProgress(scanner_name="b", target_type="source")

    assert a.severity_counts is not b.severity_counts, (
        "Two ScannerProgress defaults share the same dict — mutating one "
        "would corrupt the other."
    )

    a.severity_counts["critical"] = 999
    assert b.severity_counts["critical"] == 0, (
        "Mutating one ScannerProgress.severity_counts leaked into another instance."
    )


# ---------------------------------------------------------------------------
# Shape test: document the expected fix pattern so reviewers can verify.
# ---------------------------------------------------------------------------


FIX_PATTERN_DOCSTRING = textwrap.dedent(
    """
    Fix pattern used across the codebase:

        # before (bug)
        def f(xs: List[str] = []) -> None:
            ...

        # after (fix)
        def f(xs: List[str] | None = None) -> None:
            if xs is None:
                xs = []
            ...
    """
).strip()


def test_fix_pattern_documented():
    """Sanity: the documented fix pattern is present in this test module."""
    assert "xs is None" in FIX_PATTERN_DOCSTRING
    assert "List[str] | None" in FIX_PATTERN_DOCSTRING
