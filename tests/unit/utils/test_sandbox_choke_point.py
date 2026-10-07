# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH code must start processes through utils/subprocess_utils.py.

The scanner sandbox rewrites a command in exactly one place,
``subprocess_utils._prepare_spawn``, which every helper there calls. Code that called
``subprocess.run`` itself would run a scanner unsandboxed under ``--sandbox`` without
any error, so this test fails on any direct process-starting call anywhere in the
package outside the listed exemptions.
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

#: Files that start processes directly, and why each may. Everything else in the
#: package must go through utils/subprocess_utils.py. Listing exemptions rather than
#: guarded files is deliberate: a guarded list had to be kept in step with every new
#: module that might spawn, and missed two (pre_installed_tool.py and
#: content_db_staleness.py ran scanner binaries unsandboxed under --sandbox).
EXEMPT = {
    "utils/subprocess_utils.py": "the choke point itself",
    "utils/sandbox/backends.py": "probes whether a sandbox backend can start",
    "utils/sandbox/landlock_exec.py": "execs the scanner after restricting itself",
    "utils/get_scan_set.py": "ASH's own git calls, never inside a scanner",
    "interactions/run_ash_nix.py": "re-executes ASH itself inside nix develop",
    "cli/mcp/source_delivery.py": "git clone and checkout for MCP source delivery",
    "plugin_modules/ash_builtin/converters/jupyter_converter.py": "converter, runs before any scanner",
}

GUARDED = sorted(
    p for p in PACKAGE.rglob("*.py") if p.relative_to(PACKAGE).as_posix() not in EXEMPT
)

SPAWNING_CALLS = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("pty", "spawn"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "posix_spawn"),
    ("os", "posix_spawnp"),
    *(
        ("os", f"{family}{suffix}")
        for family in ("exec", "spawn")
        for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")
    ),
}
SPAWNING_MODULES = {module for module, _ in SPAWNING_CALLS}


def _direct_spawns(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # Local name -> module, so `import subprocess as sp` is caught as sp.run.
    module_names = {module: module for module in SPAWNING_MODULES}
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in SPAWNING_MODULES:
                    module_names[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in SPAWNING_MODULES:
            for alias in node.names:
                if (node.module, alias.name) in SPAWNING_CALLS:
                    imported_names.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in module_names
            and (module_names[func.value.id], func.attr) in SPAWNING_CALLS
        ):
            yield f"{path.relative_to(PACKAGE)}:{node.lineno} {func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name) and func.id in imported_names:
            yield f"{path.relative_to(PACKAGE)}:{node.lineno} {func.id}"


def test_the_guarded_set_is_not_empty():
    # A glob that silently matched nothing would make the test below vacuous.
    names = {p.name for p in GUARDED}
    assert {
        "bandit_scanner.py",
        "uv_tool_runner.py",
        "plugin_base.py",
        "pre_installed_tool.py",
        "content_db_staleness.py",
    } <= names
    assert len(GUARDED) > 100


def test_every_exemption_still_exists():
    # A stale exemption is a gap waiting for the next file of that name.
    for relative in EXEMPT:
        assert (PACKAGE / relative).is_file(), relative


@pytest.mark.parametrize("path", GUARDED, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_no_direct_process_spawn(path):
    found = list(_direct_spawns(path))
    assert not found, (
        "start processes through utils/subprocess_utils.py (run_command, "
        "run_command_with_output_handling or spawn_run) so the scanner sandbox can "
        f"wrap them: {found}"
    )


def test_the_detector_sees_a_direct_spawn(tmp_path):
    """The positive control: the walker flags each spelling it is meant to."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import subprocess, os\n"
        "import subprocess as sp\n"
        "import pty\n"
        "from subprocess import Popen as P\n"
        "from os import execlp\n"
        "subprocess.run(['x'])\n"
        "sp.check_output(['x'])\n"
        "P(['x'])\n"
        "os.system('x')\n"
        "os.spawnlp(os.P_WAIT, 'x', 'x')\n"
        "execlp('x', 'x')\n"
        "pty.spawn(['x'])\n"
    )
    global PACKAGE
    saved = PACKAGE
    PACKAGE = tmp_path
    try:
        found = list(_direct_spawns(sample))
    finally:
        PACKAGE = saved
    assert len(found) == 7, found


SCANNER_MODULES = sorted(
    {
        *PACKAGE.glob("plugin_modules/*/scanners/*.py"),
        *PACKAGE.glob("plugin_modules/*/*scanner*.py"),
    }
)


def _unguarded_writes(path: Path):
    """open(..., "w"/"a"...) and Path.write_text/write_bytes calls in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in (
            "write_text",
            "write_bytes",
        ):
            yield f"{path.relative_to(PACKAGE)}:{node.lineno} .{func.attr}()"
        elif isinstance(func, ast.Name) and func.id == "open":
            mode = None
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if isinstance(mode, str) and any(c in mode for c in "wax+"):
                yield f"{path.relative_to(PACKAGE)}:{node.lineno} open(mode={mode!r})"


@pytest.mark.parametrize(
    "path", SCANNER_MODULES, ids=lambda p: str(p.relative_to(PACKAGE))
)
def test_scanners_write_through_the_guarded_opener(path):
    """A scanner writes into a results directory a sandboxed tool could also write,
    so its writes go through fs_guard.open_for_write, which follows no link."""
    found = list(_unguarded_writes(path))
    assert not found, (
        "write through utils/sandbox/fs_guard.open_for_write, not open() or "
        f"Path.write_text: {found}"
    )


def test_the_write_detector_sees_each_spelling(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from pathlib import Path\n"
        "open('a', 'w')\n"
        "open('a', mode='a')\n"
        "open('a')\n"
        "Path('a').write_text('x')\n"
    )
    global PACKAGE
    saved = PACKAGE
    PACKAGE = tmp_path
    try:
        found = list(_unguarded_writes(sample))
    finally:
        PACKAGE = saved
    assert len(found) == 3, found
