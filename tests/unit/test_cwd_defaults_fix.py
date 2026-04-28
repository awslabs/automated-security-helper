"""Regression tests: Path.cwd() / os.getcwd() must not be captured at import time.

The bug being fixed:

    def f(x: Path = Path.cwd()):   # evaluated ONCE at module import
        ...

If the process's working directory changes between import and call, the function
uses the stale import-time directory. The fix is the standard Python idiom:

    def f(x: Path | None = None):
        if x is None:
            x = Path.cwd()

These tests:

1. Scan the source AST for any function signature whose default expression
   still calls Path.cwd() or os.getcwd() (directly or through chained calls
   like Path.cwd().joinpath(...)).
2. Exercise a few specific functions to prove the default resolves at call time
   after monkeypatching the working directory.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_ROOT = REPO_ROOT / "automated_security_helper"


# ---------------------------------------------------------------------------
# AST-level check: no function signature default should call Path.cwd() or
# os.getcwd(), even transitively (e.g., Path.cwd().joinpath(...)).
# ---------------------------------------------------------------------------


def _iter_python_files(root: Path):
    for p in root.rglob("*.py"):
        if "__pycache__" in set(p.parts):
            continue
        yield p


def _default_calls_cwd(default_node: ast.AST) -> bool:
    """Return True if this default expression calls Path.cwd() or os.getcwd().

    Walks the subtree — catches both direct calls (`Path.cwd()`) and chained
    calls (`Path.cwd().joinpath(...).as_posix()`).
    """
    for node in ast.walk(default_node):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # os.getcwd()
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "getcwd"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return True
        # Path.cwd()
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "cwd"
            and isinstance(func.value, ast.Name)
            and func.value.id == "Path"
        ):
            return True
    return False


def _cwd_default_offenders(py_path: Path) -> List[Tuple[str, int, str]]:
    """Return [(function_name, lineno, source_snippet), ...] for offenders."""
    try:
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return []

    lines = source.splitlines()
    offenders: List[Tuple[str, int, str]] = []

    def _check(node):
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if _default_calls_cwd(default):
                lineno = default.lineno
                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                offenders.append((node.name, lineno, snippet))

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check(n)

    return offenders


def test_no_cwd_captured_in_function_defaults():
    """No production function may evaluate Path.cwd()/os.getcwd() at import time."""
    all_offenders: List[Tuple[Path, str, int, str]] = []
    for py_path in _iter_python_files(PKG_ROOT):
        for name, lineno, snippet in _cwd_default_offenders(py_path):
            all_offenders.append((py_path, name, lineno, snippet))

    if all_offenders:
        rel = [
            f"{p.relative_to(REPO_ROOT)}:{lineno} in {name}  --  {snippet}"
            for (p, name, lineno, snippet) in all_offenders
        ]
        pytest.fail(
            "Functions still evaluate Path.cwd()/os.getcwd() at import time:\n"
            + "\n".join(rel)
        )


# ---------------------------------------------------------------------------
# Behavioral spot-checks: prove defaults resolve at call time.
# ---------------------------------------------------------------------------


def test_scan_tracking_check_scan_completion_uses_runtime_cwd(monkeypatch, tmp_path):
    """check_scan_completion's default output_dir must track the current CWD."""
    from automated_security_helper.core.resource_management import scan_tracking

    # Set up a fake runtime cwd with no aggregated results file.
    monkeypatch.chdir(tmp_path)

    # With no file at .ash/ash_output/ash_aggregated_results.json, the call
    # should return False — and critically, it must be looking at tmp_path,
    # not the import-time cwd of the test process.
    assert scan_tracking.check_scan_completion() is False

    # Now create the file relative to the new cwd and re-call.
    (tmp_path / ".ash" / "ash_output").mkdir(parents=True)
    (tmp_path / ".ash" / "ash_output" / "ash_aggregated_results.json").write_text("{}")

    assert scan_tracking.check_scan_completion() is True


def test_scan_tracking_find_scanner_result_files_uses_runtime_cwd(
    monkeypatch, tmp_path
):
    """find_scanner_result_files's default output_dir must track the current CWD."""
    from automated_security_helper.core.resource_management import scan_tracking

    monkeypatch.chdir(tmp_path)

    # No scanners dir yet under the new cwd.
    assert scan_tracking.find_scanner_result_files() == {}


def test_scan_tracking_get_completed_scanners_uses_runtime_cwd(monkeypatch, tmp_path):
    from automated_security_helper.core.resource_management import scan_tracking

    monkeypatch.chdir(tmp_path)
    assert scan_tracking.get_completed_scanners() == set()


def test_scan_tracking_get_scanner_progress_uses_runtime_cwd(monkeypatch, tmp_path):
    from automated_security_helper.core.resource_management import scan_tracking

    monkeypatch.chdir(tmp_path)
    assert scan_tracking.get_scanner_progress() == {}


def test_get_scan_set_uses_runtime_cwd(monkeypatch, tmp_path):
    """scan_set's default source must resolve at call time."""
    from automated_security_helper.utils import get_scan_set

    # Create an empty git-tracked-looking directory (no files).
    monkeypatch.chdir(tmp_path)

    # The call should operate on tmp_path, not the original cwd.
    # Empty directory -> empty list of files.
    result = get_scan_set.scan_set()
    assert isinstance(result, list)


def test_resolve_config_uses_runtime_cwd(monkeypatch, tmp_path):
    """resolve_config's default source_dir must resolve at call time."""
    from automated_security_helper.config import resolve_config as rc

    monkeypatch.chdir(tmp_path)

    # With no config files present at the new cwd, we fall back to default.
    config = rc.resolve_config()
    assert config is not None


def test_ash_config_load_config_uses_runtime_cwd(monkeypatch, tmp_path):
    """AshConfig.load_config's default source_dir must resolve at call time."""
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.chdir(tmp_path)

    # With no config in tmp_path, load_config should still succeed (default
    # config) without blowing up trying to read from the import-time cwd.
    config = AshConfig.load_config()
    assert config is not None


# ---------------------------------------------------------------------------
# The interaction entry points (run_ash_scan, run_ash_container) have
# enormous side effects, so we don't call them end-to-end. Instead we assert
# by signature inspection that the defaults are None.
# ---------------------------------------------------------------------------


def test_run_ash_scan_defaults_are_none():
    import inspect
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    sig = inspect.signature(run_ash_scan)
    assert sig.parameters["source_dir"].default is None
    assert sig.parameters["output_dir"].default is None


def test_run_ash_container_defaults_are_none():
    import inspect
    from automated_security_helper.interactions.run_ash_container import (
        run_ash_container,
    )

    sig = inspect.signature(run_ash_container)
    assert sig.parameters["source_dir"].default is None
    assert sig.parameters["output_dir"].default is None


def test_scan_tracking_signatures_are_none():
    import inspect
    from automated_security_helper.core.resource_management import scan_tracking

    for fname in [
        "check_scan_completion",
        "find_scanner_result_files",
        "get_completed_scanners",
        "get_scanner_progress",
        "parse_scanner_result_file",
        "parse_aggregated_results",
        "get_scan_progress_info",
        "get_scan_results",
    ]:
        fn = getattr(scan_tracking, fname)
        sig = inspect.signature(fn)
        # Each of these has an output_dir or result_file parameter.
        target_param = next(
            p for p in sig.parameters.values() if p.name in {"output_dir", "result_file"}
        )
        assert target_param.default is None, (
            f"{fname}: {target_param.name} default must be None, got {target_param.default!r}"
        )


def test_create_scan_progress_from_files_signature_is_none():
    import inspect
    from automated_security_helper.core.resource_management.scan_tracking import (
        create_scan_progress_from_files,
    )

    sig = inspect.signature(create_scan_progress_from_files)
    assert sig.parameters["output_dir"].default is None


def test_resolve_config_signature_is_none():
    import inspect
    from automated_security_helper.config.resolve_config import resolve_config

    sig = inspect.signature(resolve_config)
    assert sig.parameters["source_dir"].default is None


def test_ash_config_load_config_signature_is_none():
    import inspect
    from automated_security_helper.config.ash_config import AshConfig

    sig = inspect.signature(AshConfig.load_config)
    assert sig.parameters["source_dir"].default is None


def test_scan_set_signature_is_none():
    import inspect
    from automated_security_helper.utils.get_scan_set import scan_set

    sig = inspect.signature(scan_set)
    assert sig.parameters["source"].default is None
