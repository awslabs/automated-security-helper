# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""`ash --version` must not import the scan engine, the config model or the plugins.

The startup regression this pins against: cli/main.py (or a module it imports at
module scope) grows an import of config.ash_config, models.asharp_model, the
built-in plugin tree or one of the generated schema models, and every `ash`
invocation -- `--version`, `--help`, a usage error -- pays for the whole scan
engine again (measured at ~1.4 s of a 1.43 s `ash --version` before the lazy
registration in cli/main.py and the deferred imports in cli/scan.py).

Budgeted by NAME and COUNT, never by wall time: CI timing flakes, module sets do
not. The check runs in a fresh subprocess so it measures a cold interpreter's
imports rather than whatever this test session has already loaded.
"""

import json
import subprocess  # nosec B404 - fixed argv, sys.executable, no shell
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

#: Module trees that must stay OUT of `ash --version`. Each one names a root
#: whose import pulls hundreds of modules; a prefix match catches any submodule.
#: If one of these turns up, find the module-scope import that pulled it (python
#: -X importtime names the chain) and defer it into the function that uses it,
#: as cli/scan.py and cli/main.py's _LAZY_SUBCOMMANDS do.
FORBIDDEN_AT_VERSION_TIME = (
    # the config model: 4800 lines of pydantic models, imports every plugin
    "automated_security_helper.config.ash_config",
    # the aggregated-results model and the generated schema models under it
    "automated_security_helper.models.asharp_model",
    "automated_security_helper.schemas.sarif_schema_model",
    "automated_security_helper.schemas.cyclonedx_bom_1_6_schema",
    "automated_security_helper.schemas.ocsf",
    # the built-in plugin tree (scanners, reporters, converters, handlers)
    "automated_security_helper.plugin_modules",
    # the scan engine and the container runner
    "automated_security_helper.interactions.run_ash_scan",
    "automated_security_helper.interactions.run_ash_container",
    "automated_security_helper.core.orchestrator",
    # workspace resolution (pulls the config model)
    "automated_security_helper.workspace",
    "automated_security_helper.models.workspace",
    # the source-archive rules `ash scan fs --archive` extracts with: read when an
    # archive is given, never to print the option
    "automated_security_helper.utils.source_archive",
    # the lazily-registered subcommand modules themselves
    "automated_security_helper.cli.config",
    "automated_security_helper.cli.dependencies",
    "automated_security_helper.cli.image",
    "automated_security_helper.cli.inspect",
    "automated_security_helper.cli.merge",
    "automated_security_helper.cli.plugin",
    "automated_security_helper.cli.report",
    "automated_security_helper.cli.mcp",
    # the inspect UI framework
    "textual",
)

#: Ceiling on the number of entries in sys.modules after a full `--version`
#: run. The named list above is the precise guard; the count catches a NEW
#: heavy import that none of the names cover. Measured 356 on CPython 3.12
#: after the lazy registration landed (970 before it); the headroom absorbs
#: interpreter and dependency drift across the CI matrix without letting a
#: plugin-tree-sized regression (which adds 400+) through.
MODULE_COUNT_CEILING = 550

_HARNESS = """
import json
import sys

from typer.testing import CliRunner

from automated_security_helper.cli.main import app

forbidden = {forbidden!r}
result = CliRunner().invoke(app, {args!r})
present = sorted(
    name
    for name in sys.modules
    if any(name == root or name.startswith(root + ".") for root in forbidden)
)
print(
    json.dumps(
        {{
            "exit_code": result.exit_code,
            "output": result.output,
            "present": present,
            "module_count": len(sys.modules),
        }}
    )
)
"""


def _version_run_report(args: tuple[str, ...] = ("--version",)) -> dict:
    # importing_this_checkout routes the child at this checkout (and exits 86 if
    # ASH still resolves from elsewhere), so the budget measured is this tree's,
    # not an installed copy's — and the child-launch scan in
    # tests/unit/test_child_processes_import_this_checkout.py requires every -c
    # child that imports ASH to go through it.
    completed = subprocess.run(  # nosec B603 - fixed argv, no shell
        [
            sys.executable,
            "-c",
            importing_this_checkout(
                _HARNESS.format(forbidden=FORBIDDEN_AT_VERSION_TIME, args=list(args))
            ),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"the --version harness itself failed:\n{completed.stderr}"
    )
    return json.loads(completed.stdout.splitlines()[-1])


def test_version_imports_no_forbidden_module():
    report = _version_run_report()
    assert report["exit_code"] == 0, report["output"]
    assert report["present"] == [], (
        "`ash --version` imported modules that must stay lazy: "
        f"{report['present']}. A module-scope import crept into cli/main.py's "
        "import tree; run python -X importtime -c 'import "
        "automated_security_helper.cli.main' to find the chain, and defer it "
        "(see cli/scan.py's module comment and cli/main.py's _LAZY_SUBCOMMANDS)."
    )


def test_version_module_count_stays_bounded():
    report = _version_run_report()
    assert report["module_count"] <= MODULE_COUNT_CEILING, (
        f"`ash --version` now loads {report['module_count']} modules "
        f"(ceiling {MODULE_COUNT_CEILING}). Something new is imported at module "
        "scope on the startup path; find it with python -X importtime and defer "
        "it. Raise the ceiling only for a measured, wanted dependency."
    )


def test_scan_help_imports_no_forbidden_module():
    """`ash scan --help` lists the scan's subjects from the group's own help.

    ``scan`` is a group, and its subjects ``fs`` and ``workspace`` are built from the
    scan engine's signature; none of that may pull the engine, the config model or
    the plugins in to print the list.
    """
    report = _version_run_report(("scan", "--help"))
    assert report["exit_code"] == 0, report["output"]
    assert "Subjects of `ash scan`: fs" in report["output"]
    assert report["present"] == [], (
        "`ash scan --help` imported modules that must stay lazy: "
        f"{report['present']}. Defer the import that pulled them (cli/scan_group.py "
        "builds `fs` and `workspace` from cli/scan.py's signature and must import "
        "nothing heavy)."
    )


def test_scan_help_module_count_stays_bounded():
    report = _version_run_report(("scan", "--help"))
    assert report["module_count"] <= MODULE_COUNT_CEILING, (
        f"`ash scan --help` now loads {report['module_count']} modules "
        f"(ceiling {MODULE_COUNT_CEILING})."
    )


def test_scan_workspace_help_imports_no_forbidden_module():
    """`ash scan workspace --help` prints the subject's options from its signature.

    The workspace subject is the one most likely to be given an import of the
    workspace resolution (``automated_security_helper.workspace`` and its models),
    which are named above: the file it takes is resolved by the engine when the scan
    runs, never to print its help.
    """
    report = _version_run_report(("scan", "workspace", "--help"))
    assert report["exit_code"] == 0, report["output"]
    assert "FILE" in report["output"]
    assert "--dry-run" in report["output"]
    assert "Subjects of `ash scan`: fs" in report["output"]
    assert report["present"] == [], (
        "`ash scan workspace --help` imported modules that must stay lazy: "
        f"{report['present']}. Defer the import that pulled them (cli/scan_group.py "
        "builds `workspace` from cli/scan.py's signature and must import nothing "
        "heavy)."
    )


def test_scan_workspace_help_module_count_stays_bounded():
    report = _version_run_report(("scan", "workspace", "--help"))
    assert report["module_count"] <= MODULE_COUNT_CEILING, (
        f"`ash scan workspace --help` now loads {report['module_count']} modules "
        f"(ceiling {MODULE_COUNT_CEILING})."
    )


def test_scan_fs_help_imports_no_forbidden_module():
    """`ash scan fs --help` lists `--archive` without importing the archive rules.

    The option is declared from the subject's signature; the module that reads the zip
    is imported when an archive is given, so printing the option must not pay for it.
    """
    report = _version_run_report(("scan", "fs", "--help"))
    assert report["exit_code"] == 0, report["output"]
    assert "--archive" in report["output"]
    assert report["present"] == [], (
        "`ash scan fs --help` imported modules that must stay lazy: "
        f"{report['present']}. Defer the import that pulled them (cli/scan_group.py "
        "imports utils/source_archive inside the function that extracts an archive)."
    )


def test_scan_fs_help_module_count_stays_bounded():
    report = _version_run_report(("scan", "fs", "--help"))
    assert report["module_count"] <= MODULE_COUNT_CEILING, (
        f"`ash scan fs --help` now loads {report['module_count']} modules "
        f"(ceiling {MODULE_COUNT_CEILING})."
    )
