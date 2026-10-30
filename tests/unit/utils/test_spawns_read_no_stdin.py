# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scanners and tools ASH starts get an empty standard input.

ASH's own standard input is not theirs. Under ``ash mcp`` it carries the MCP
client's messages, and in a terminal a tool that waits for input stops the scan.
Every spawn route gives the child ``subprocess.DEVNULL``, so a child that reads
standard input sees end-of-file at once. A call that passes ``input=`` keeps it.

Each test replaces ASH's file descriptor 0 with a pipe that holds data, for the
duration of the call only (pytest's own capture puts ``/dev/null`` there between
phases), and starts a probe that records what it read. A child that inherited
ASH's input records that data; one given ``DEVNULL`` records ``b''``.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the probes use select() on a pipe"
)
pytestmark = posix_only

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALL_PINNED_TOOL = (
    REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
)

PARENT_INPUT = b"input meant for ASH"

# Waits up to 2 s for input, so a child that inherited an empty pipe records
# that instead of blocking the test.
PROBE = (
    "import os, select, sys\n"
    "ready = select.select([0], [], [], 2)[0]\n"
    "data = os.read(0, 64) if ready else b'<waiting>'\n"
    "with open(sys.argv[1], 'a', encoding='utf-8') as f:\n"
    "    f.write(repr(data) + '\\n')\n"
)


@contextlib.contextmanager
def ash_stdin_holding_data() -> Iterator[None]:
    """File descriptor 0 is a pipe holding PARENT_INPUT while the block runs."""
    read_end, write_end = os.pipe()
    os.write(write_end, PARENT_INPUT)
    saved = os.dup(0)
    os.dup2(read_end, 0)
    try:
        yield
    finally:
        os.dup2(saved, 0)
        for fd in (saved, read_end, write_end):
            os.close(fd)


def _reads(record: Path) -> List[str]:
    assert record.exists(), "the probe did not run, or could not read fd 0"
    return record.read_text(encoding="utf-8").splitlines()


def _probe_argv(record: Path) -> List[str]:
    return [sys.executable, "-I", "-c", PROBE, str(record)]


def _fake_tool(directory: Path, name: str, record: Path, stdout: str = "") -> Path:
    """A ``name`` on PATH that records what it read from standard input."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(
        f"#!{sys.executable} -I\n"
        "import sys\n"
        f"sys.argv[1:] = [{str(record)!r}]\n"
        f"{PROBE}"
        f"print({stdout!r})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.fixture
def tools(tmp_path, monkeypatch):
    """An absolute PATH entry for fake tools, and nothing else to find them in."""
    directory = tmp_path / "tools"
    directory.mkdir()
    no_tools = tmp_path / "ash-bin"
    no_tools.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join([str(directory), "/usr/bin", "/bin"]))
    monkeypatch.setenv("ASH_BIN_PATH", str(no_tools))
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", lambda: [no_tools])
    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner.reset_uv_tool_runner()
    yield directory
    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner.reset_uv_tool_runner()


# ---------------------------------------------------------------------------
# The spawn helpers
# ---------------------------------------------------------------------------


def _via_run_command(argv):
    subprocess_utils.run_command(argv)


def _via_run_command_get_output(argv):
    subprocess_utils.run_command_get_output(argv)


def _via_output_handling(argv):
    subprocess_utils.run_command_with_output_handling(
        argv, stdout_preference="return", stderr_preference="return"
    )


def _via_stream_output(argv):
    subprocess_utils.run_command_stream_output(argv)


def _via_pipes(argv):
    subprocess_utils.create_process_with_pipes(argv).communicate()


def _via_spawn_run(argv):
    subprocess_utils.spawn_run(argv, capture_output=True, text=True)


def _via_run_stoppable(argv):
    # The runner sandboxed spawns use.
    subprocess_utils._run_stoppable(argv, capture_output=True, text=True)


SPAWN_HELPERS = {
    "run_command": _via_run_command,
    "run_command_get_output": _via_run_command_get_output,
    "run_command_with_output_handling": _via_output_handling,
    "run_command_stream_output": _via_stream_output,
    "create_process_with_pipes": _via_pipes,
    "spawn_run": _via_spawn_run,
    "_run_stoppable": _via_run_stoppable,
}


@pytest.mark.parametrize("helper", sorted(SPAWN_HELPERS))
@pytest.mark.integration
def test_a_spawn_helper_gives_the_child_an_empty_stdin(tmp_path, helper):
    record = tmp_path / "read.log"
    with ash_stdin_holding_data():
        SPAWN_HELPERS[helper](_probe_argv(record))
    assert _reads(record) == ["b''"]


@pytest.mark.integration
def test_the_scanner_runner_gives_the_tool_an_empty_stdin(tmp_path):
    """``ScannerPluginBase._run_subprocess``, which every scanner's tool goes through."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.config.ash_config import AshConfig

    record = tmp_path / "read.log"

    class _Config(ScannerPluginConfigBase):
        name: str = "stdin-probe"

    class _ProbeScanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, *args, **kwargs):
            raise NotImplementedError

    source = tmp_path / "source"
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )
    scanner = _ProbeScanner(config=_Config(), context=context)
    with ash_stdin_holding_data():
        scanner._run_subprocess(_probe_argv(record), results_dir=tmp_path / "results")
    assert _reads(record) == ["b''"]


@pytest.mark.integration
def test_input_passed_to_spawn_run_still_reaches_the_child(tmp_path):
    """A call that pipes input deliberately keeps doing so."""
    code = (
        "import os, select\n"
        "ready = select.select([0], [], [], 2)[0]\n"
        "print((os.read(0, 64) if ready else b'<waiting>').decode().upper())\n"
    )
    with ash_stdin_holding_data():
        result = subprocess_utils.spawn_run(
            [sys.executable, "-I", "-c", code],
            input="given",
            capture_output=True,
            text=True,
        )
        stoppable = subprocess_utils._run_stoppable(
            [sys.executable, "-I", "-c", code],
            input="given",
            capture_output=True,
            text=True,
        )
    assert result.stdout.strip() == "GIVEN"
    assert stoppable.stdout.strip() == "GIVEN"


# ---------------------------------------------------------------------------
# Callers that start a process themselves
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_changed_files_mode_gives_git_an_empty_stdin(tmp_path, tools):
    from automated_security_helper.utils.get_scan_set import (
        get_changed_files,
        git_repository_root,
    )

    record = tmp_path / "read.log"
    _fake_tool(tools, "git", record, stdout=str(tmp_path))
    with ash_stdin_holding_data():
        git_repository_root(tmp_path)
    with ash_stdin_holding_data():
        get_changed_files("main", cwd=tmp_path)
    assert _reads(record) == ["b''", "b''"]


@pytest.mark.integration
def test_mcp_source_delivery_gives_git_an_empty_stdin(tmp_path, tools):
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    record = tmp_path / "read.log"
    _fake_tool(tools, "git", record)
    with ash_stdin_holding_data():
        set_source_git(
            "https://example.invalid/project.git",
            session_id="stdin-session",
            workspace_root=tmp_path / "workspace",
        )
    # The clone, then the rev-parse that refuses a clone which produced no
    # commit (this fake's does): each git the delivery starts reads nothing.
    assert _reads(record) == ["b''", "b''"]


@pytest.mark.integration
def test_nix_mode_gives_nix_an_empty_stdin(tmp_path, tools, monkeypatch):
    from automated_security_helper.interactions.run_ash_nix import (
        ASH_IN_NIX_ENV_VAR,
        run_ash_nix,
    )

    monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
    record = tmp_path / "read.log"
    _fake_tool(tools, "nix", record)
    with ash_stdin_holding_data():
        run_ash_nix(argv=["scan"], flake_ref=f"path:{tmp_path}")
    assert _reads(record) == ["b''"]


@pytest.mark.integration
def test_the_sandbox_probes_give_the_probe_an_empty_stdin(tmp_path):
    from automated_security_helper.utils.sandbox import backends

    record = tmp_path / "read.log"
    with ash_stdin_holding_data():
        backends._probe_process(_probe_argv(record))
    assert _reads(record) == ["b''"]


@pytest.mark.unit
def test_the_trust_root_export_gives_security_an_empty_stdin(tmp_path, monkeypatch):
    """macOS only in use; the call's arguments are checked here instead."""
    from automated_security_helper.utils.sandbox import backends

    keychain = tmp_path / "System.keychain"
    keychain.write_text("", encoding="utf-8")
    calls = []

    def run(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
    monkeypatch.setattr(backends.subprocess, "run", run)
    backends._system_trust_roots()
    assert calls and all(c.get("stdin") is subprocess.DEVNULL for c in calls)


@pytest.mark.integration
def test_the_jupyter_converter_gives_jupyter_an_empty_stdin(
    tmp_path, tools, test_plugin_context, monkeypatch
):
    """The direct nbconvert run. The version check goes through ``spawn_run``,
    which the helper cells above cover."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )
    from tests.unit.converters.nbconvert_routes import use_stand_in_nbconvert

    record = tmp_path / "read.log"
    nbconvert = _fake_tool(tools, "jupyter-nbconvert", record)
    converter = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    use_stand_in_nbconvert(monkeypatch, converter, path=str(nbconvert))

    staged = tmp_path / "staged"
    staged.mkdir()
    notebook = staged / "notebook.ipynb"
    notebook.write_text("{}", encoding="utf-8")
    with ash_stdin_holding_data():
        converter._run_nbconvert(notebook, tmp_path / "out" / "nb.py", "nb.ipynb")
    assert _reads(record) == ["b''"]


def _load_install_pinned_tool():
    spec = importlib.util.spec_from_file_location(
        "_install_pinned_tool_stdin", INSTALL_PINNED_TOOL
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_the_image_build_checks_give_the_tool_an_empty_stdin(tmp_path, tools):
    installer = _load_install_pinned_tool()
    record = tmp_path / "read.log"
    _fake_tool(tools, "uv", record, stdout=str(tmp_path))
    version_probe = _fake_tool(tools, "some-tool", record, stdout="1.0.0")
    with ash_stdin_holding_data():
        installer.uv_tool_dir()
    with ash_stdin_holding_data():
        installer.version_output(str(version_probe))
    assert _reads(record) == ["b''", "b''"]
