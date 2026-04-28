"""Regression tests for os.environ mutation in scanner code.

Several scanners previously mutated the process-global ``os.environ`` dict
before running subprocesses. In parallel scan mode (ThreadPoolExecutor),
concurrent scanners race on shared global state, and mutations may leak
between scans.

The fix: build a local ``env`` dict (e.g. ``{**os.environ, **env_vars}``)
and pass it as the ``env=`` kwarg to the subprocess call, leaving
``os.environ`` untouched.

These tests pin the fix by scanning the source for the ``os.environ[X] =
...`` mutation pattern, and by confirming ``_run_subprocess`` accepts and
forwards ``env=``.
"""

import ast
import os
from pathlib import Path
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _snapshot_env() -> dict:
    return dict(os.environ)


def _find_environ_assignments(source_path: Path) -> list[ast.Assign]:
    """Return AST Assign nodes that write to ``os.environ[<key>]``.

    This catches the offending pattern
    ``os.environ["X"] = "value"`` / ``os.environ['X'] = os.environ[...]``
    but not ``os.environ.get(...)`` reads.
    """
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    mutations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Subscript):
                continue
            val = target.value
            # Match os.environ[...]
            if (
                isinstance(val, ast.Attribute)
                and val.attr == "environ"
                and isinstance(val.value, ast.Name)
                and val.value.id == "os"
            ):
                mutations.append(node)
    return mutations


# ---------------------------------------------------------------------------
# Site 1: semgrep_scanner.py — scan() must not mutate os.environ
# ---------------------------------------------------------------------------
def test_semgrep_scanner_source_has_no_os_environ_mutation():
    """The semgrep scanner module must not contain ``os.environ[k] = v``.

    Any such write leaks into the parent process and races with other
    scanners running in parallel threads.
    """
    path = (
        _REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_builtin"
        / "scanners"
        / "semgrep_scanner.py"
    )
    mutations = _find_environ_assignments(path)
    assert mutations == [], (
        f"semgrep_scanner.py still mutates os.environ at lines: "
        f"{[m.lineno for m in mutations]}"
    )


# ---------------------------------------------------------------------------
# Site 2: opengrep_scanner.py — scan() must not mutate os.environ
# ---------------------------------------------------------------------------
def test_opengrep_scanner_source_has_no_os_environ_mutation():
    path = (
        _REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_builtin"
        / "scanners"
        / "opengrep_scanner.py"
    )
    mutations = _find_environ_assignments(path)
    assert mutations == [], (
        f"opengrep_scanner.py still mutates os.environ at lines: "
        f"{[m.lineno for m in mutations]}"
    )


# ---------------------------------------------------------------------------
# Site 3: grype_scanner.py — _process_config_options must not mutate
# os.environ (no restoration today; fully leaks offline flags).
# ---------------------------------------------------------------------------
def test_grype_scanner_source_has_no_os_environ_mutation():
    path = (
        _REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_builtin"
        / "scanners"
        / "grype_scanner.py"
    )
    mutations = _find_environ_assignments(path)
    assert mutations == [], (
        f"grype_scanner.py still mutates os.environ at lines: "
        f"{[m.lineno for m in mutations]}"
    )


# ---------------------------------------------------------------------------
# Site 4: snyk_code_scanner.py — env_vars block was dead; must no longer
# contain os.environ writes.
# ---------------------------------------------------------------------------
def test_snyk_code_scanner_source_has_no_os_environ_mutation():
    path = (
        _REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_snyk_plugins"
        / "snyk_code_scanner.py"
    )
    mutations = _find_environ_assignments(path)
    assert mutations == [], (
        f"snyk_code_scanner.py still mutates os.environ at lines: "
        f"{[m.lineno for m in mutations]}"
    )


# ---------------------------------------------------------------------------
# Site 5: cdk_nag_wrapper.py — JSII reads env at import; we accept
# mutation here, but ONLY inside a try/finally that restores os.environ
# back to its starting state. A separate behavior test below proves it.
# ---------------------------------------------------------------------------
def test_cdk_nag_wrapper_restores_os_environ():
    """cdk_nag_wrapper must restore os.environ even if the wrapped code
    raises.

    JSII (used by cdk_nag) reads NODE_NO_WARNINGS and
    JSII_SILENCE_WARNING_* at Python module import time, so env= on a
    subprocess cannot be used. Instead the wrapper must save and restore
    os.environ around the work.
    """
    from automated_security_helper.utils import cdk_nag_wrapper

    watched_keys = (
        "NODE_NO_WARNINGS",
        "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION",
        "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION",
    )
    # Clear watched keys in a context-managed way so test teardown
    # restores whatever was there originally.
    with patch.dict(os.environ, {}, clear=False):
        for key in watched_keys:
            os.environ.pop(key, None)

        before = _snapshot_env()

        # Force early failure so we don't need real CDK machinery.
        with patch(
            "automated_security_helper.utils.cdk_nag_wrapper.get_model_from_template",
            side_effect=RuntimeError("forced-exit"),
        ):
            fake_template = Path("/nonexistent/template.yaml")
            try:
                cdk_nag_wrapper.run_cdk_nag_against_cfn_template(fake_template)
            except Exception:
                # We injected the failure. We only care about env state.
                pass

        after = _snapshot_env()
        leaked = {k: after.get(k) for k in watched_keys if k in after and k not in before}
        assert not leaked, (
            f"cdk_nag_wrapper leaked env vars after exit: {leaked}"
        )
        assert before == after, (
            f"cdk_nag_wrapper left os.environ in a different state. "
            f"Added: {set(after) - set(before)}, "
            f"Removed: {set(before) - set(after)}"
        )


# ---------------------------------------------------------------------------
# Plumbing test: _run_subprocess in plugin_base must accept env= kwarg and
# forward it to run_command_with_output_handling.
# ---------------------------------------------------------------------------
def test_plugin_base_run_subprocess_accepts_and_forwards_env(tmp_path):
    """The plugin base class must plumb env= through to subprocess."""
    import inspect

    from automated_security_helper.base.plugin_base import PluginBase

    sig = inspect.signature(PluginBase._run_subprocess)
    assert "env" in sig.parameters, (
        f"_run_subprocess must accept an 'env' kwarg. Signature: {sig}"
    )

    # Build a minimal plugin instance bypassing validators.
    plugin = PluginBase.model_construct()
    plugin.config = MagicMock()
    plugin.config.name = "test-plugin"
    plugin.context = MagicMock()
    plugin.context.source_dir = str(tmp_path)
    plugin.use_uv_tool = False
    plugin.command = None
    plugin.output = []
    plugin.errors = []
    plugin.exit_code = 0

    captured = {}

    def fake_run_cmd(**kwargs):
        captured.update(kwargs)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    with patch(
        "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
        side_effect=fake_run_cmd,
    ):
        plugin._run_subprocess(
            command=["echo", "hi"],
            results_dir=tmp_path,
            env={"FOO": "bar"},
        )

    assert captured.get("env") == {"FOO": "bar"}, (
        f"env not forwarded to run_command_with_output_handling: "
        f"{captured.get('env')}"
    )


# ---------------------------------------------------------------------------
# Additional behavioral check: actually run a subprocess via the util with
# env= and confirm the environment arrives at the child process.
# ---------------------------------------------------------------------------
def test_run_command_with_output_handling_forwards_env_to_subprocess(tmp_path):
    """Sanity check: subprocess_utils already accepts env= and subprocess.run
    passes it through. This pins that contract — the scanners depend on it.
    """
    from automated_security_helper.utils.subprocess_utils import (
        run_command_with_output_handling,
    )

    # Use `python -c` to echo the env var we injected.
    import sys

    response = run_command_with_output_handling(
        command=[sys.executable, "-c", "import os; print(os.environ.get('ASH_TEST_ENV', 'MISSING'))"],
        results_dir=None,
        stdout_preference="return",
        stderr_preference="return",
        env={
            "ASH_TEST_ENV": "propagated",
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", ""),
            "COMSPEC": os.environ.get("COMSPEC", ""),
        },
    )
    assert "propagated" in response.get("stdout", ""), (
        f"env= was not forwarded to subprocess. stdout={response.get('stdout')!r}"
    )
