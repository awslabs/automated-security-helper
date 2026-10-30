# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's own Python children import nothing from the directory they start in.

``python -m`` and ``python -c`` put the working directory first on ``sys.path``
(``-c`` as ``''``, which follows a later ``chdir``). ASH usually runs inside the
repository it scans, ``ash dependencies install`` takes the current directory as the
source tree, and a scanner's subprocesses default to the scanned tree, so a ``pip/``
or ``automated_security_helper/`` there was imported in place of the real module.

Each call site gets a planted package that appends its name to a marker file when
imported. A control runs the same argv from the planted directory the way the call
site used to, so a clean result means the call site, not a plant that never loads.

The static half reads the package source: a Python child is started through
``utils.python_child.python_child``, which picks the working directory itself, and a
raw ``[sys.executable, "-m" | "-c", ...]`` list appears only where this file says why.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils.download_utils import (
    create_pinned_tool_install_command,
    current_bin_path,
)
from automated_security_helper.utils.rules_bundles import (
    create_rules_bundle_install_command,
)
from tests.utils.helpers import bound_run_command

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPO_ROOT / "automated_security_helper"
# pragma: allowlist nextline secret
DETECT_SECRETS_WORKER = "automated_security_helper.utils.detect_secrets_worker"


def _plant(directory: Path, package: str, marker: Path) -> None:
    """A package named ``package`` in ``directory`` that records its import."""
    init = directory / package / "__init__.py"
    init.parent.mkdir(parents=True, exist_ok=True)
    init.write_text(
        f"open({str(marker)!r}, 'a', encoding='utf-8').write({package + chr(10)!r})\n",
        encoding="utf-8",
    )


def _child_env() -> dict:
    """The test's environment without PYTHONSAFEPATH, which would hide the plant."""
    return {k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"}


# ---------------------------------------------------------------------------
# ash dependencies install: every plugin install command runs through run_command
# ---------------------------------------------------------------------------


def _pinned_install_argv(tmp_path: Path) -> List[str]:
    # A tool with no pinned asset fails in get_tool_asset, before any download.
    return create_pinned_tool_install_command(
        "no-such-tool", "linux", "amd64", destination=str(tmp_path / "bin")
    ).args


def _rules_bundle_install_argv(tmp_path: Path) -> List[str]:
    # A bundle with no pin fails in get_rules_bundle, before any download.
    return create_rules_bundle_install_command("no-such-bundle").args


INSTALL_COMMANDS = [
    ("pip", lambda tmp_path: [sys.executable, "-m", "pip", "--version"]),
    ("automated_security_helper", _pinned_install_argv),
    ("automated_security_helper", _rules_bundle_install_argv),
]
INSTALL_IDS = [
    "python -m pip",
    "pinned-tool install script",
    "rules-bundle install script",
]


@pytest.mark.parametrize(("package", "argv"), INSTALL_COMMANDS, ids=INSTALL_IDS)
@pytest.mark.integration
def test_control_the_install_command_imports_the_planted_package_from_its_cwd(
    tmp_path, package, argv
):
    repo, marker = tmp_path / "repo", tmp_path / "IMPORTED"
    _plant(repo, package, marker)
    subprocess.run(
        argv(tmp_path),
        cwd=repo,
        env=_child_env(),
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert marker.read_text(encoding="utf-8") == f"{package}\n"


@pytest.mark.parametrize(("package", "argv"), INSTALL_COMMANDS, ids=INSTALL_IDS)
@pytest.mark.integration
def test_the_installer_runs_python_commands_outside_the_current_directory(
    tmp_path, monkeypatch, package, argv
):
    repo, marker = tmp_path / "repo", tmp_path / "IMPORTED"
    _plant(repo, package, marker)
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.chdir(repo)
    bound_run_command(monkeypatch)
    dependencies_module.run_command(argv(tmp_path))
    assert not marker.exists(), marker.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# detect-secrets: the scan runs in `python -m ...detect_secrets_worker`
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_control_the_detect_secrets_worker_imports_the_planted_package(tmp_path):
    repo, marker = tmp_path / "repo", tmp_path / "IMPORTED"
    _plant(repo, "automated_security_helper", marker)
    subprocess.run(
        [sys.executable, "-m", DETECT_SECRETS_WORKER, "request.json", "out.json"],
        cwd=repo,
        env=_child_env(),
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert marker.read_text(encoding="utf-8") == "automated_security_helper\n"


@pytest.mark.integration
def test_the_detect_secrets_worker_imports_nothing_from_the_tree_or_its_results(
    tmp_path, monkeypatch
):
    """The worker used to start in the scanner's results directory.

    That directory is inside the scanned tree by default (``.ash/ash_output``), so
    the plant goes there as well as at the top of the tree, where ASH itself runs.
    """
    source = tmp_path / "src"
    context = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    marker = tmp_path / "IMPORTED"
    results = Path(scanner.results_dir)
    for directory in (source, results, results / "source"):
        _plant(directory, "automated_security_helper", marker)
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.chdir(source)
    scanner.scan(target=source, target_type="source")
    assert not marker.exists(), marker.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ASH_BIN_PATH: a relative value names one directory however a child's cwd is set
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_relative_bin_path_is_made_absolute_where_it_is_read(tmp_path, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_BIN_PATH", "rel/bin")
    assert current_bin_path() == tmp_path / "rel" / "bin"
    assert subprocess_utils._bin_path() == tmp_path / "rel" / "bin"
    assert subprocess_utils.path_independent_dirs()[0].is_absolute()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("rel/bin", "{cwd}/rel/bin"), ("", "{home}/.ash/bin")],
    ids=["relative", "empty"],
)
@pytest.mark.integration
def test_the_bin_path_constant_is_absolute(tmp_path, value, expected):
    """``core.constants.ASH_BIN_PATH`` is computed at import, so it is read in a child.

    An empty value used to become ``Path("")``, the current directory.
    """
    home = tmp_path / "home"
    home.mkdir()
    # USERPROFILE is the home directory on Windows; HOME is not read there.
    env = {
        **_child_env(),
        "ASH_BIN_PATH": value,
        "HOME": str(home),
        "USERPROFILE": str(home),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from automated_security_helper.core.constants import ASH_BIN_PATH; "
                "print(ASH_BIN_PATH)"
            ),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    printed = Path(result.stdout.strip())
    assert printed == Path(expected.format(cwd=tmp_path, home=home)), result.stdout


@pytest.mark.unit
def test_the_installer_exports_an_absolute_bin_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Set first so the value the command exports is undone after the test.
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "unused"))
    CliRunner().invoke(
        dependencies_module.dependencies_app,
        ["--bin-path", "rel/bin", "--tool", "no-such-tool"],
    )
    assert os.environ["ASH_BIN_PATH"] == str(tmp_path / "rel" / "bin")
    # The unknown tool is refused before the bin directory is made: the command
    # creates it just before the installs run, after every refusal of its own
    # (tests/unit/cli/test_dependencies_refuses_before_creating.py), so the
    # export is this run's only effect.
    assert not (tmp_path / "rel").exists()


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_helper_starts_a_child_in_an_empty_directory_it_removes(tmp_path):
    from automated_security_helper.utils.python_child import python_child

    with python_child("-c", "pass", parent=tmp_path) as child:
        assert child.cwd.parent == tmp_path
        assert list(child.cwd.iterdir()) == []
        assert child.argv[0] == sys.executable
        assert child.argv[-2:] == ["-c", "pass"]
        assert ("-P" in child.argv) is (sys.version_info >= (3, 11))
    assert not child.cwd.exists()


@pytest.mark.integration
def test_the_helper_adds_no_directory_of_the_child_to_sys_path(tmp_path):
    from automated_security_helper.utils.python_child import python_child

    code = "import os, sys; print(os.getcwd() in sys.path or '' in sys.path)"
    with python_child("-c", code, parent=tmp_path) as child:
        result = subprocess.run(
            child.argv,
            cwd=child.cwd,
            env=_child_env(),
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    # On 3.10 there is no -P, and the entry Python adds names the empty directory.
    expected = "True" if sys.version_info < (3, 11) else "False"
    assert result.stdout.strip() == expected


# ---------------------------------------------------------------------------
# Static: every Python child in the package is started this way
# ---------------------------------------------------------------------------

#: Where a raw ``[sys.executable, "-m" | "-c", ...]`` list may appear, by file and
#: enclosing function (or module-level assignment), and why.
#:
#: Install commands: plugins declare them as argv lists and only
#: ``ash dependencies install`` runs them, through ``cli.dependencies.run_command``,
#: which starts each Python one through ``python_child`` (tested above). The pip
#: install that plugin_base, cdk-nag and ferret declare is built in one place,
#: ``python_package_install_command``, and a command that can only refuse by
#: ``refusing_install_command``.
#:
#: ``_ash_environment_install`` compares an install command's prefix with this
#: list and starts nothing. ``_with_path_imported`` rebuilds a declared opengrep
#: download command with ``Path`` imported and returns it; the rebuilt argv runs
#: through ``run_command`` like the one it replaces.
#:
#: The cdk-nag worker: its ``-c`` source drops ``sys.path[0]`` before importing
#: anything, and it starts in a directory it has just created; see
#: test_the_child_does_not_import_from_the_scanned_directory in test_cdk_nag_worker.py.
RAW_PYTHON_ARGV_ALLOWED = {
    ("utils/python_installer.py", "python_package_install_command"),
    ("utils/download_utils.py", "refusing_install_command"),
    ("cli/dependencies.py", "_ash_environment_install"),
    ("utils/download_utils.py", "create_pinned_tool_install_command"),
    ("utils/download_utils.py", "create_url_download_command"),
    ("utils/rules_bundles.py", "create_rules_bundle_install_command"),
    (
        "plugin_modules/ash_builtin/scanners/opengrep_scanner.py",
        "_refuse_unverified_install_command",
    ),
    ("cli/dependencies.py", "_with_path_imported"),
    ("utils/cdk_nag_worker.py", "_run_child"),
}

#: Spawn helpers a Python child may be handed to.
SPAWNERS = {
    "run",
    "Popen",
    "check_output",
    "check_call",
    "call",
    "spawn_run",
    "run_cmd",
    "run_command",
    "run_command_with_output_handling",
    "run_command_get_output",
    "run_command_stream_output",
    "_run_subprocess",
}


def _is_sys_executable(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "executable"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _scopes(tree: ast.AST) -> Iterator[Tuple[ast.AST, str]]:
    """Every node with the name of its enclosing function or module-level target."""

    def walk(node: ast.AST, scope: str) -> Iterator[Tuple[ast.AST, str]]:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = child.name
            elif scope == "<module>" and isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = (
                    child.targets if isinstance(child, ast.Assign) else [child.target]
                )
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                inner = names[0] if names else scope
            yield child, inner
            yield from walk(child, inner)

    yield from walk(tree, "<module>")


def raw_python_argv(source: str) -> List[Tuple[str, int]]:
    """``(scope, line)`` of each list starting ASH's interpreter with -m or -c, not -I."""
    found = []
    for node, scope in _scopes(ast.parse(source)):
        if not isinstance(node, ast.List) or not node.elts:
            continue
        if not _is_sys_executable(node.elts[0]):
            continue
        flags = [e.value for e in node.elts[1:4] if isinstance(e, ast.Constant)]
        if "-I" in flags or not {"-m", "-c"} & set(flags):
            continue
        found.append((scope, node.lineno))
    return found


def _call_name(call: ast.Call) -> Optional[str]:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def python_child_spawn_problems(source: str) -> List[Tuple[int, str]]:
    """Spawns of a ``python_child`` argv that do not use the cwd it chose."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            call = item.context_expr
            if not (isinstance(call, ast.Call) and _call_name(call) == "python_child"):
                continue
            if not isinstance(item.optional_vars, ast.Name):
                problems.append((node.lineno, "python_child() without `as <name>`"))
                continue
            name = item.optional_vars.id

            def is_field(expr: ast.AST, field: str) -> bool:
                return (
                    isinstance(expr, ast.Attribute)
                    and expr.attr == field
                    and isinstance(expr.value, ast.Name)
                    and expr.value.id == name
                )

            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call) or _call_name(inner) not in SPAWNERS:
                    continue
                values = [*inner.args, *(k.value for k in inner.keywords)]
                if not any(is_field(v, "argv") for v in values):
                    continue
                cwd = [k.value for k in inner.keywords if k.arg == "cwd"]
                if not (cwd and is_field(cwd[0], "cwd")):
                    problems.append(
                        (inner.lineno, f"{name}.argv spawned without cwd={name}.cwd")
                    )
    return problems


def _package_sources() -> Iterator[Tuple[str, str]]:
    for path in sorted(PACKAGE.rglob("*.py")):
        yield path.relative_to(PACKAGE).as_posix(), path.read_text(encoding="utf-8")


@pytest.mark.unit
def test_control_the_static_check_reports_a_raw_child_and_a_spawn_in_the_tree():
    source = (
        "import subprocess, sys\n"
        "def scan(self):\n"
        "    subprocess.run([sys.executable, '-m', 'pip', 'list'], cwd=self.source_dir)\n"
        "    subprocess.run([sys.executable, '-I', '-c', 'pass'])\n"
        "def other(self):\n"
        "    with python_child('-m', 'x') as child:\n"
        "        run_command_with_output_handling(command=child.argv, cwd=self.source_dir)\n"
        "        run_command_with_output_handling(command=child.argv, cwd=child.cwd)\n"
    )
    assert raw_python_argv(source) == [("scan", 3)]
    assert python_child_spawn_problems(source) == [
        (7, "child.argv spawned without cwd=child.cwd")
    ]


@pytest.mark.unit
def test_no_python_child_in_the_package_starts_without_the_helper():
    found: Set[Tuple[str, str]] = set()
    unexpected = []
    for relative, source in _package_sources():
        if relative == "utils/python_child.py":
            continue
        for scope, line in raw_python_argv(source):
            found.add((relative, scope))
            if (relative, scope) not in RAW_PYTHON_ARGV_ALLOWED:
                unexpected.append(f"{relative}:{line} in {scope}")
    assert unexpected == []
    # Every allowance still names a list, so the table cannot outlive its reason.
    assert RAW_PYTHON_ARGV_ALLOWED - found == set()


@pytest.mark.unit
def test_every_python_child_spawn_uses_the_directory_the_helper_chose():
    users = set()
    problems = []
    for relative, source in _package_sources():
        if "python_child(" not in source or relative == "utils/python_child.py":
            continue
        users.add(relative)
        problems += [
            f"{relative}:{line}: {why}"
            for line, why in python_child_spawn_problems(source)
        ]
    assert problems == []
    assert {
        "cli/dependencies.py",
        "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
    } <= users, users
