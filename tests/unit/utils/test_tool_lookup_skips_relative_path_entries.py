# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH looks tools up through absolute PATH entries only.

A PATH entry that is relative (``bin``, ``.``) or empty names a directory under
the working directory, and ASH usually runs from, or starts its tools in, the
repository it scans. A tool reachable only through such an entry is reported as
not found, the same way a missing tool is, and nothing starts it.

Every lookup route is covered: ``subprocess_utils.find_executable`` and the spawn
helpers that resolve a command through it, ``uv_tool_runner``'s lookups, and each
module that used ``shutil.which`` or split PATH itself. Each test plants a tool
that records its own start in a marker file, so a test can tell "not found" from
"found and started".
"""

from __future__ import annotations

import importlib.util
import json
import ntpath
import os
import posixpath
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the planted tools are POSIX shell scripts"
)

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALL_PINNED_TOOL = (
    REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
)

# A scanner's tool name, so the lookups under test are the ones a scan makes.
TOOL = "grype"


def _plant(directory: Path, name: str, marker: Path, stdout: str = "") -> Path:
    """An executable ``name`` in ``directory`` that appends a line to ``marker``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    printed = stdout or f"{name} 0.0.0"
    path.write_text(
        f"#!/bin/sh\necho \"$0\" >> '{marker}'\necho '{printed}'\n", encoding="utf-8"
    )
    path.chmod(0o755)
    return path


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A scanned tree as the working directory, and an absolute PATH entry with no tools.

    ASH's own bin directories are pointed at an empty directory, so a tool can only
    be found through PATH.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    anchored = tmp_path / "anchored"
    anchored.mkdir()
    no_tools = tmp_path / "ash-bin"
    no_tools.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", str(no_tools))
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", lambda: [no_tools])
    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner.reset_uv_tool_runner()
    yield SimpleNamespace(
        root=tmp_path, repo=repo, anchored=anchored, marker=tmp_path / "started.log"
    )
    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner.reset_uv_tool_runner()


# (PATH as entries, directory under the tree that the non-absolute entry names).
# "{anchored}" is replaced by the absolute directory that holds no tools.
LAYOUTS = {
    "relative-entry": (["bin", "{anchored}"], "bin"),
    "dot-entry": ([".", "{anchored}"], "."),
    "leading-empty-entry": (["", "{anchored}"], "."),
    "trailing-empty-entry": (["{anchored}", ""], "."),
}


def _use_layout(tree, monkeypatch, layout: str, name: str = TOOL) -> Path:
    entries, holder = LAYOUTS[layout]
    path_value = os.pathsep.join(e.format(anchored=tree.anchored) for e in entries)
    monkeypatch.setenv("PATH", path_value)
    return _plant(tree.repo / holder, name, tree.marker)


# ---------------------------------------------------------------------------
# find_executable and uv_tool_runner
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_find_executable_does_not_answer_from_a_non_absolute_entry(
    tree, monkeypatch, layout
):
    _use_layout(tree, monkeypatch, layout)
    assert subprocess_utils.find_executable(TOOL) is None


@posix_only
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_uv_tool_runner_lookups_do_not_answer_from_a_non_absolute_entry(
    tree, monkeypatch, layout
):
    _use_layout(tree, monkeypatch, layout)
    assert uv_tool_runner.find_executable(TOOL) is None
    # uv is not installed here either, so the direct binary is the only route.
    assert uv_tool_runner.get_uv_tool_command(TOOL) is None
    assert not tree.marker.exists()


@posix_only
def test_a_tool_on_an_absolute_entry_is_found(tree, monkeypatch):
    """The control: an absolute entry is still searched."""
    planted = _plant(tree.anchored, TOOL, tree.marker)
    monkeypatch.setenv("PATH", str(tree.anchored))
    assert subprocess_utils.find_executable(TOOL) == str(planted)
    assert uv_tool_runner.find_executable(TOOL) == str(planted)


@posix_only
def test_an_absolute_copy_after_a_relative_entry_is_the_answer(tree, monkeypatch):
    _plant(tree.repo / "bin", TOOL, tree.marker)
    planted = _plant(tree.anchored, TOOL, tree.marker)
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(tree.anchored)]))
    assert subprocess_utils.find_executable(TOOL) == str(planted)


@posix_only
def test_a_relative_command_path_is_not_answered(tree, monkeypatch):
    _plant(tree.repo / "bin", TOOL, tree.marker)
    monkeypatch.setenv("PATH", str(tree.anchored))
    assert subprocess_utils.find_executable(f"bin/{TOOL}") is None
    assert subprocess_utils.find_executable(f"./bin/{TOOL}") is None


@pytest.mark.parametrize(
    ("pathmod", "path", "anchored"),
    [
        (posixpath, "/usr/bin", True),
        (posixpath, "bin", False),
        (posixpath, ".", False),
        (posixpath, "", False),
        (ntpath, "C:\\tools", True),
        (ntpath, "\\\\server\\share\\tools", True),
        (ntpath, "\\tools", False),
        (ntpath, "tools", False),
    ],
)
def test_an_entry_is_anchored_only_when_it_does_not_depend_on_the_cwd(
    pathmod, path, anchored
):
    assert subprocess_utils._is_anchored(path, pathmod) is anchored


# ---------------------------------------------------------------------------
# The spawn helpers: a bare name the OS would find through a non-absolute entry
# ---------------------------------------------------------------------------


def _via_run_command(cwd):
    return subprocess_utils.run_command([TOOL, "--version"], cwd=cwd).returncode


def _via_run_command_get_output(cwd):
    return subprocess_utils.run_command_get_output([TOOL, "--version"], cwd=cwd)[0]


def _via_output_handling(cwd):
    return subprocess_utils.run_command_with_output_handling(
        [TOOL, "--version"],
        cwd=cwd,
        stdout_preference="return",
        stderr_preference="return",
    )["returncode"]


def _via_stream_output(cwd):
    return subprocess_utils.run_command_stream_output([TOOL, "--version"], cwd=cwd)


def _via_pipes(cwd):
    try:
        process = subprocess_utils.create_process_with_pipes(
            [TOOL, "--version"], cwd=cwd
        )
    except OSError:
        return SPAWN_FAILURE_RETURNCODE
    process.communicate()
    return process.returncode


def _via_spawn_run(cwd):
    try:
        return subprocess_utils.spawn_run(
            [TOOL, "--version"], cwd=cwd, capture_output=True, text=True
        ).returncode
    except OSError:
        return SPAWN_FAILURE_RETURNCODE


SPAWN_HELPERS = {
    "run_command": _via_run_command,
    "run_command_get_output": _via_run_command_get_output,
    "run_command_with_output_handling": _via_output_handling,
    "run_command_stream_output": _via_stream_output,
    "create_process_with_pipes": _via_pipes,
    "spawn_run": _via_spawn_run,
}


@posix_only
@pytest.mark.parametrize("helper", sorted(SPAWN_HELPERS))
@pytest.mark.parametrize("layout", ["relative-entry", "leading-empty-entry"])
@pytest.mark.parametrize("where", ["ash-cwd", "child-cwd"])
def test_a_spawn_helper_does_not_start_a_tool_from_a_non_absolute_entry(
    tree, monkeypatch, helper, layout, where
):
    """Not started, and reported as a command that could not start.

    ``child-cwd`` runs ASH from elsewhere and gives the tool the tree as its working
    directory: on POSIX the child's own PATH search resolves a non-absolute entry
    after it changes directory, so ASH's lookup failing is not enough.
    """
    _use_layout(tree, monkeypatch, layout)
    cwd = None
    if where == "child-cwd":
        elsewhere = tree.root / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        cwd = tree.repo
    returncode = SPAWN_HELPERS[helper](cwd)
    assert not tree.marker.exists(), tree.marker.read_text()
    assert returncode == SPAWN_FAILURE_RETURNCODE


@posix_only
@pytest.mark.parametrize("helper", sorted(SPAWN_HELPERS))
def test_a_spawn_helper_still_starts_a_tool_on_an_absolute_entry(
    tree, monkeypatch, helper
):
    """The control for the test above."""
    _plant(tree.anchored, TOOL, tree.marker)
    monkeypatch.setenv("PATH", str(tree.anchored))
    assert SPAWN_HELPERS[helper](tree.repo) == 0
    assert tree.marker.read_text().strip() == str(tree.anchored / TOOL)


@posix_only
@pytest.mark.parametrize("layout", ["relative-entry", "leading-empty-entry"])
def test_the_refusal_says_why_the_tool_did_not_start(tree, monkeypatch, layout):
    """Refused by ASH with a reason, not left to the child's own failed search."""
    _use_layout(tree, monkeypatch, layout)
    with pytest.raises(FileNotFoundError, match="through the working directory"):
        subprocess_utils.resolve_command([TOOL, "--version"], cwd=tree.repo)
    result = subprocess_utils.run_command([TOOL, "--version"], cwd=tree.repo)
    assert "through the working directory" in result.stderr
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_a_relative_program_path_is_refused(tree, monkeypatch):
    _plant(tree.repo / "bin", TOOL, tree.marker)
    monkeypatch.setenv("PATH", str(tree.anchored))
    with pytest.raises(FileNotFoundError, match="relative to the working directory"):
        subprocess_utils.resolve_command([f"./bin/{TOOL}", "--version"])
    result = subprocess_utils.run_command([f"bin/{TOOL}", "--version"])
    assert result.returncode == SPAWN_FAILURE_RETURNCODE
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_a_child_gets_only_the_absolute_path_entries(tree, monkeypatch):
    """The child's own lookups (a ``#!/usr/bin/env`` line, a binstub) see them too."""
    monkeypatch.setenv(
        "PATH", os.pathsep.join(["bin", "", str(tree.anchored), ".", "/usr/bin"])
    )
    result = subprocess_utils.run_command(
        [sys.executable, "-c", "import os; print(os.environ['PATH'])"], cwd=tree.repo
    )
    assert result.stdout.strip() == os.pathsep.join([str(tree.anchored), "/usr/bin"])


@posix_only
def test_a_child_whose_path_has_no_absolute_entry_gets_the_default_path(
    tree, monkeypatch
):
    """Not an empty PATH, which a child's search reads as the working directory."""
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", "."]))
    result = subprocess_utils.run_command(
        [sys.executable, "-c", "import os; print(os.environ['PATH'])"], cwd=tree.repo
    )
    assert result.stdout.strip() == os.defpath


# ---------------------------------------------------------------------------
# Modules that used shutil.which or split PATH themselves
# ---------------------------------------------------------------------------


@posix_only
def test_the_sandbox_does_not_take_its_programs_from_a_relative_entry(
    tree, monkeypatch
):
    from automated_security_helper.utils.sandbox import backends

    for name in ("bwrap", "firejail", "true"):
        _plant(tree.repo / "bin", name, tree.marker)
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(tree.anchored)]))

    reason = backends.BwrapBackend()._probe()
    assert reason is not None and "not installed" in reason
    reason = backends.FirejailBackend()._probe()
    assert reason is not None and "not installed" in reason
    assert os.path.isabs(backends._true())
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_the_sandbox_policy_does_not_mount_a_relative_entry_tool_prefix(
    tree, monkeypatch
):
    from automated_security_helper.utils.sandbox import policy

    _use_layout(tree, monkeypatch, "relative-entry")
    assert policy._executable_prefix(TOOL) == []


@posix_only
def test_a_shebang_interpreter_is_looked_up_through_absolute_entries(tree, monkeypatch):
    from automated_security_helper.utils.sandbox import policy

    script = tree.anchored / "tool-script"
    script.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    _plant(tree.repo / "bin", "node", tree.marker)
    real_node = _plant(tree.root / "node-install" / "bin", "node", tree.marker)
    monkeypatch.setenv(
        "PATH", os.pathsep.join(["bin", str(tree.anchored), str(real_node.parent)])
    )
    assert policy._shebang_interpreter(script) == real_node


@posix_only
def test_a_pre_installed_tool_interpreter_is_not_taken_from_a_relative_entry(
    tree, monkeypatch
):
    from automated_security_helper.utils.pre_installed_tool import (
        find_tool_interpreter,
    )

    script = tree.anchored / TOOL
    script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    script.chmod(0o755)
    _plant(tree.repo / "bin", "python3", tree.marker)
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(tree.anchored)]))
    assert find_tool_interpreter(str(script)) is None


@posix_only
def test_changed_files_mode_does_not_start_git_from_a_relative_entry(tree, monkeypatch):
    from automated_security_helper.utils.get_scan_set import (
        get_changed_files,
        git_repository_root,
    )

    _use_layout(tree, monkeypatch, "relative-entry", name="git")
    assert git_repository_root(tree.repo) is None
    assert get_changed_files("main", cwd=tree.repo) is None
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_mcp_source_delivery_does_not_start_git_from_a_relative_entry(
    tree, monkeypatch
):
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    _use_layout(tree, monkeypatch, "leading-empty-entry", name="git")
    with pytest.raises(RuntimeError, match="git was not found"):
        set_source_git(
            "https://example.invalid/project.git",
            session_id="lookup-session",
            workspace_root=tree.root / "workspace",
        )
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_the_jupyter_converter_does_not_start_jupyter_from_a_relative_entry(
    tree, monkeypatch, test_plugin_context
):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    _use_layout(tree, monkeypatch, "relative-entry", name="jupyter")
    converter = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    converter.use_uv_tool = False
    assert converter.validate_plugin_dependencies() is False
    assert not tree.marker.exists(), tree.marker.read_text()


def _load_install_pinned_tool():
    spec = importlib.util.spec_from_file_location(
        "_install_pinned_tool_lookup", INSTALL_PINNED_TOOL
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@posix_only
def test_the_image_check_counts_copies_on_absolute_entries_only(tree, monkeypatch):
    installer = _load_install_pinned_tool()
    _plant(tree.repo / "bin", TOOL, tree.marker)
    planted = _plant(tree.anchored, TOOL, tree.marker)
    search_path = os.pathsep.join(["bin", ".", "", str(tree.anchored)])
    assert installer._copies_on_path(TOOL, search_path) == [str(planted)]


@posix_only
def test_the_image_build_does_not_start_uv_from_a_relative_entry(tree, monkeypatch):
    installer = _load_install_pinned_tool()
    _use_layout(tree, monkeypatch, "relative-entry", name="uv")
    with pytest.raises(SystemExit, match="uv"):
        installer.uv_tool_dir()
    assert not tree.marker.exists(), tree.marker.read_text()


# ---------------------------------------------------------------------------
# A scan
# ---------------------------------------------------------------------------


def _scan_status(tree) -> str:
    """Run a local, offline scan of the tree with only TOOL's scanner; its status."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    (tree.repo / "main.py").write_text("print('hello')\n", encoding="utf-8")
    output = tree.root / "out"
    run_ash_scan(
        source_dir=str(tree.repo),
        output_dir=str(output),
        mode=RunMode.local,
        scanners=[TOOL],
        offline=True,
        progress=False,
        show_summary=False,
        quiet=True,
        fail_on_findings=False,
        fail_on_incomplete_scanners=False,
    )
    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return results["scanner_results"][TOOL]["status"]


@posix_only
@pytest.mark.parametrize("layout", ["relative-entry", "leading-empty-entry"])
def test_a_scan_reports_a_tool_on_a_non_absolute_entry_as_missing(
    tree, monkeypatch, layout
):
    _use_layout(tree, monkeypatch, layout)
    assert _scan_status(tree) == "MISSING"
    assert not tree.marker.exists(), tree.marker.read_text()


@posix_only
def test_a_scan_starts_the_tool_on_an_absolute_entry(tree, monkeypatch):
    """The control: the same scan with the tool on an absolute entry starts it."""
    _plant(tree.anchored, TOOL, tree.marker)
    monkeypatch.setenv("PATH", str(tree.anchored))
    assert _scan_status(tree) != "MISSING"
    assert str(tree.anchored / TOOL) in tree.marker.read_text()
