# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner module run as a script prints its SARIF with its CI commands broken.

Why this exists
---------------
bandit_scanner, cdk_nag_scanner and npm_audit_scanner each scan the working
directory when run with ``python -m`` and print the SARIF with ``echo_raw``. The
SARIF repeats the scanned tree's file names and finding text, and a runner reads
"##" with a name and "[" after it ("##vso[", "##[cmd]") as a command anywhere in
a line. They print through ``json_commands_broken``, which writes the first
"#" of each as JSON's own escape, so the document is still the same JSON. A "::"
at a line start can't occur in the indented JSON they print.

The blocks scan the real working directory, so the cells read each one's source:
the text its ``echo_raw`` prints is a ``json_commands_broken`` call, and every
import in the block resolves. A block imports its helpers only after the scan, so
a name its module doesn't have would end the run with an ImportError and no SARIF.

One cell runs a scanner module as ``python -m`` does, in a child whose working
directory is a scratch directory holding a file named with "##vso[". Its scan is a
stand-in that reports each file there, so no tool runs, and the SARIF the block
prints names that file: the cell reads it from the child's stdout.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import json
import re
import subprocess  # nosec B404 - a module run as a script is the property under test
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

ROOT = Path(__file__).resolve().parents[3]
SCANNERS = (
    ROOT / "automated_security_helper" / "plugin_modules" / "ash_builtin" / "scanners"
)
PACKAGE = "automated_security_helper.plugin_modules.ash_builtin.scanners"
MODULES = ["bandit_scanner.py", "cdk_nag_scanner.py", "npm_audit_scanner.py"]

#: A file in the scanned directory whose name holds Azure Pipelines' command form.
PLANTED = "a##vso[task.setvariable variable=x]1.txt"

#: Run in the child, which then runs the module named in its first argument as
#: ``python -m`` does. The scanner class that module defines, decorated with its own
#: ``@ash_scanner_plugin``, gets a stand-in scan: one result per file in the scanned
#: directory, with the file's name as its location, so no tool runs.
_DRIVER = """
import runpy
import sys
from pathlib import Path

from automated_security_helper.plugins import decorators
from automated_security_helper.schemas.sarif_schema_model import SarifReport


def scan(self, target, target_type="source", *args, **kwargs):
    results = [
        {
            "ruleId": "STAND-IN",
            "message": {"text": "found in " + path.name},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": path.name}}}
            ],
        }
        for path in sorted(Path(target).iterdir())
        if path.is_file()
    ]
    run = {"tool": {"driver": {"name": "stand-in"}}, "results": results}
    return SarifReport.model_validate({"version": "2.1.0", "runs": [run]})


registering = decorators.ash_scanner_plugin


def ash_scanner_plugin(cls=None, **kwargs):
    if cls is not None and cls.__module__ == "__main__":
        cls.scan = scan
    return registering(cls, **kwargs)


decorators.ash_scanner_plugin = ash_scanner_plugin
module = sys.argv.pop(1)
runpy.run_module(module, run_name="__main__", alter_sys=True)
"""


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_main_guard(test: ast.AST) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and any(
            isinstance(c, ast.Constant) and c.value == "__main__"
            for c in test.comparators
        )
    )


def _main_blocks(path: Path) -> list:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node
        for node in tree.body
        if isinstance(node, ast.If) and _is_main_guard(node.test)
    ]


def _echo_raw_calls_in_main(path: Path) -> list:
    return [
        node
        for main in _main_blocks(path)
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and _name(node.func) == "echo_raw"
    ]


def _imports_in_main(path: Path) -> list:
    return [
        node
        for main in _main_blocks(path)
        for node in ast.walk(main)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]


def _resolves(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
    except ImportError:
        return False
    return True


def _unresolved(node: ast.Import | ast.ImportFrom) -> list:
    """The names in one import that the running block would fail to import."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names if not _resolves(alias.name)]
    source = importlib.util.resolve_name(
        "." * node.level + (node.module or ""), PACKAGE
    )
    if not _resolves(source):
        return [source]
    module = importlib.import_module(source)
    # As "from x import y" does: an attribute of x, or else the submodule x.y.
    return [
        f"{source}.{alias.name}"
        for alias in node.names
        if alias.name != "*"
        and not hasattr(module, alias.name)
        and not _resolves(f"{source}.{alias.name}")
    ]


@pytest.mark.parametrize("module", MODULES)
def test_a_scanners_main_prints_its_sarif_with_commands_broken(module):
    calls = _echo_raw_calls_in_main(SCANNERS / module)

    # The control: the module's __main__ block prints with echo_raw.
    assert calls, f"{module}: no echo_raw in its __main__ block"
    for call in calls:
        printed = call.args[0]
        assert isinstance(printed, ast.Call), ast.unparse(printed)
        assert _name(printed.func) == "json_commands_broken", ast.unparse(printed)


@pytest.mark.parametrize("module", MODULES)
def test_every_import_in_a_scanners_main_resolves(module):
    imports = _imports_in_main(SCANNERS / module)
    bound = {
        alias.asname or alias.name
        for node in imports
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }

    # The control: the block imports the two helpers it prints through.
    assert {"echo_raw", "json_commands_broken"} <= bound, sorted(bound)
    unresolved = [
        f"{ast.unparse(node)}: {name}" for node in imports for name in _unresolved(node)
    ]
    assert not unresolved, f"{module}: {unresolved}"


@pytest.mark.parametrize("module", MODULES)
def test_a_scanner_run_as_a_script_prints_no_named_command_a_file_name_holds(
    module, tmp_path
):
    (tmp_path / PLANTED).write_text("x = 1\n", encoding="utf-8")
    name = f"{PACKAGE}.{module.removesuffix('.py')}"

    # The child's tool probes are answered first: the module's own
    # ``@ash_scanner_plugin`` class probes its tool when built, with the uv
    # installed beside the interpreter, which left uv's cache in the test's HOME.
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(CHILD_TOOL_PROBE_STUBS + _DRIVER),
            name,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
    )

    assert completed.returncode == 0, completed.stderr[-3000:]
    report = json.loads(completed.stdout)
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in report["runs"][0]["results"]
        for location in result["locations"]
    ]
    # The control: the SARIF names the planted file as it is written.
    assert PLANTED in uris, uris
    assert not [
        line
        for line in completed.stdout.splitlines()
        if re.search(r"##[A-Za-z]*\[", line)
    ], completed.stdout[-3000:]


def test_json_commands_broken_keeps_the_document():
    from automated_security_helper.utils.command_safe_stream import json_commands_broken

    document = json.dumps(
        {"uri": "a##vso[task.setvariable variable=x]y.txt", "note": "a\\##[warning]b"},
        indent=2,
    )

    broken = json_commands_broken(document)

    # The control: the document held both forms.
    assert "##vso[" in document and "##[warning]" in document
    assert "##vso[" not in broken and "##[" not in broken
    assert json.loads(broken) == json.loads(document)
