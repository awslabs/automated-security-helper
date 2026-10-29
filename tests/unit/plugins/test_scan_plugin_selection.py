# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each scan in a process gets the plugins its own module list names, no more and no less.

The behavior these tests hold
-----------------------------
A process can run several scans: an MCP server does, and so does a program that
calls ``run_ash_scan`` more than once. Each scan's scanners, converters, reporters
and event handlers are ASH's built-in ones plus those of the modules that scan's
own ``ash_plugin_modules`` names. Two consequences:

* A module a later scan names takes part in that scan even though an earlier scan
  already resolved the plugin registry. Its scanner gets a row in the results, and
  the row is MISSING when the scanner's tool is absent, so the completeness gate
  sees it.
* A module an earlier scan named does not take part in a later scan that does not
  name it, whether it contributed a scanner or an event handler.

The registry's resolved list is also checked directly on a private
``AshPluginManager``: a plugin registered after the first resolve is in the next
one.

Why the end-to-end cases run in a fresh interpreter
---------------------------------------------------
The registry is process-global and what is under test is the order of scans in one
process, so each sequence runs in its own subprocess. HOME is a temporary
directory, PATH holds stub installers, the interpreter's directory and the system
directories, every tool directory is under the test's temporary directory
(``tests/utils/isolated_tool_env.py``) and every scan runs with ``offline=True``,
so no tool reaches the network or writes to the real home. The built-in scanners are excluded so that each scan is quick.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugins.plugin_manager import AshPluginManager
from tests.utils.isolated_tool_env import (
    install_refusing_installers,
    isolated_tool_env,
    without_inherited_aws,
)
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

SNYK_MODULE = "automated_security_helper.plugin_modules.ash_snyk_plugins"
FERRET_MODULE = "automated_security_helper.plugin_modules.ash_ferret_plugins"

#: A plugin package outside the scanned trees that subscribes one event handler.
HANDLER_PACKAGE = "zzevents_ash_plugins"

#: A plugin package outside the scanned trees with one reporter, enabled by
#: default, that writes ``ash.zzmark`` per project and once per workspace.
REPORTER_PACKAGE = "zzreport_ash_plugins"

_REPORT_PREFIX = "PLUGIN-SELECTION-REPORT "

_HANDLER_INIT = """
import os
from pathlib import Path

from automated_security_helper.plugins.events import AshEventType


def record_execution_start(*args, **kwargs):
    source_dir = kwargs.get("source_dir")
    Path(os.environ["PLUGIN_SELECTION_MARKERS"], Path(str(source_dir)).name).write_text(
        "started", encoding="utf-8"
    )
    return True


def _event_recorder(event):
    # Appends "<scan index> <event>" for each notification it receives; the probe
    # program sets the index before each scan.
    def record(*args, **kwargs):
        with open(os.environ["PLUGIN_SELECTION_EVENTS"], "a", encoding="utf-8") as log:
            log.write(os.environ.get("PLUGIN_SELECTION_SCAN", "?") + " " + event.name + "\\n")
        return True

    record.__name__ = "record_" + event.name.lower()
    return record


ASH_EVENT_HANDLERS = {AshEventType.EXECUTION_START: [record_execution_start]}
for _event in RECORDED_EVENTS:
    ASH_EVENT_HANDLERS.setdefault(_event, []).append(_event_recorder(_event))
"""

#: The events ``HANDLER_PACKAGE`` records: the scan's start and end, the start of
#: each default phase, and ERROR. The INSPECT phase is not a default phase, so its
#: events are not recorded here.
_RECORDED_EVENT_NAMES = (
    "EXECUTION_START",
    "CONVERT_PHASE_START",
    "SCAN_PHASE_START",
    "REPORT_PHASE_START",
    "EXECUTION_COMPLETE",
    "ERROR",
)

_HANDLER_INIT = _HANDLER_INIT.replace(
    "\nASH_EVENT_HANDLERS = {",
    "\nRECORDED_EVENTS = ["
    + ", ".join(f"AshEventType.{name}" for name in _RECORDED_EVENT_NAMES)
    + "]\n\nASH_EVENT_HANDLERS = {",
    1,
)

#: A plugin package outside the scanned trees with one converter, enabled by
#: default, whose convert() writes ``converted-<tree name>`` to the markers.
CONVERTER_PACKAGE = "zzconvert_ash_plugins"

_CONVERTER_INIT = """
import os
from pathlib import Path
from typing import Literal

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.plugins.decorators import ash_converter_plugin


class ZzMarkConverterConfig(ConverterPluginConfigBase):
    name: Literal["zz-mark-converter"] = "zz-mark-converter"
    enabled: bool = True
    options: ConverterOptionsBase = ConverterOptionsBase()


@ash_converter_plugin
class ZzMarkConverter(ConverterPluginBase[ZzMarkConverterConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = ZzMarkConverterConfig()
        return super().model_post_init(context)

    def convert(self, target=None):
        name = "converted-" + Path(str(self.context.source_dir)).name
        Path(os.environ["PLUGIN_SELECTION_MARKERS"], name).write_text(
            "converted", encoding="utf-8"
        )
        return []


ASH_CONVERTERS = [ZzMarkConverter]
"""

#: A plugin package whose CONVERT_PHASE_START handler raises, so a scan naming it
#: fails inside the phases and the engine notifies ERROR.
RAISING_PACKAGE = "zzraise_ash_plugins"

_RAISING_INIT = """
from automated_security_helper.plugins.events import AshEventType


def stop_the_convert_phase(*args, **kwargs):
    raise RuntimeError("zzraise_ash_plugins stops the convert phase")


ASH_EVENT_HANDLERS = {AshEventType.CONVERT_PHASE_START: [stop_the_convert_phase]}
"""

_REPORTER_INIT = """
from typing import Literal

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class ZzMarkReporterConfig(ReporterPluginConfigBase):
    name: Literal["zz-mark"] = "zz-mark"
    extension: str = "zzmark"
    enabled: bool = True
    options: ReporterOptionsBase = ReporterOptionsBase()


@ash_reporter_plugin
class ZzMarkReporter(ReporterPluginBase[ZzMarkReporterConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = ZzMarkReporterConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return "marked\\n"


ASH_REPORTERS = [ZzMarkReporter]
"""


def _mark_reporter_init(class_name: str, config_name: str, extension: str) -> str:
    """``_REPORTER_INIT`` with its class, config name and extension renamed."""
    return (
        _REPORTER_INIT.replace("ZzMarkReporter", class_name)
        .replace('"zz-mark"', f'"{config_name}"')
        .replace('"zzmark"', f'"{extension}"')
    )


def _reports(output_dir: Path, extension: str) -> List[str]:
    """The ``*.<extension>`` reports under *output_dir*, relative to it."""
    if not output_dir.is_dir():
        return []
    return sorted(
        p.relative_to(output_dir).as_posix() for p in output_dir.rglob(f"*.{extension}")
    )


#: argv[1] is a JSON list of steps. A scan is ``{"source_dir", "output_dir",
#: "modules"}``, or ``{"workspace_file", "output_dir"}`` for a workspace scan;
#: ``{"list": true}`` calls the MCP ``list_scanners`` tool function, which imports the
#: community scanner packages; ``{"subscribe": true}`` subscribes a handler defined in
#: this program to EXECUTION_START, the way embedding code calls
#: ``ash_plugin_manager.subscribe``, which writes ``embedded-<tree name>``. Prints one
#: report line: per scan, the exit code, each scanner row's status, and the scan's
#: "not used by this scan" log records with their levels.
#: The child's tool probes are answered first (CHILD_TOOL_PROBE_STUBS): it finds the
#: uv installed with ASH beside its interpreter whatever PATH it is given, and ran
#: it, which left uv's cache in the test's HOME.
_PROGRAM = (
    CHILD_TOOL_PROBE_STUBS
    + r"""
import json
import logging
import os
import sys
from pathlib import Path

from automated_security_helper.plugins.loader import load_internal_plugins

#: The "not used by this scan" log records of the scan running now, at every
#: level. A filter on ASH's logger sees each record before any handler does, and
#: survives the handler reset each scan's logging setup makes.
LEFT_OUT = []


class _LeftOutRecorder(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        if "not used by this scan" in message:
            LEFT_OUT.append({"level": record.levelname, "message": message})
        return True


logging.getLogger("ash").addFilter(_LeftOutRecorder())


def record_embedded_start(*args, **kwargs):
    name = "embedded-" + Path(str(kwargs.get("source_dir"))).name
    Path(os.environ["PLUGIN_SELECTION_MARKERS"], name).write_text(
        "started", encoding="utf-8"
    )
    return True


def _config_name(cls):
    field = getattr(cls, "model_fields", {}).get("config")
    for arg in getattr(getattr(field, "annotation", None), "__args__", None) or ():
        fields = getattr(arg, "model_fields", None) or {}
        if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig") and "name" in fields:
            if fields["name"].default:
                return fields["name"].default
    raise RuntimeError("no config name for " + cls.__name__)


# Imported before the built-in plugins load, an order a program embedding ASH can
# produce.
for name in json.loads(os.environ.get("PLUGIN_SELECTION_PREIMPORT") or "[]"):
    __import__(name)

BUILTINS = sorted({_config_name(c) for c in load_internal_plugins()["scanners"]})

# Imported after the built-in plugins load, the order an `ash` process has.
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

scans = []
for step in json.loads(sys.argv[1]):
    if step.get("list"):
        from automated_security_helper.cli.mcp_tools import mcp_list_scanners

        mcp_list_scanners()
        continue
    if step.get("subscribe"):
        from automated_security_helper.plugins import ash_plugin_manager
        from automated_security_helper.plugins.events import AshEventType

        ash_plugin_manager.subscribe(AshEventType.EXECUTION_START, record_embedded_start)
        continue
    if "workspace_file" in step:
        from automated_security_helper.workspace.resolver import resolve_workspace

        target = {"workspace_plan": resolve_workspace(Path(step["workspace_file"]))}
    else:
        target = {"source_dir": step["source_dir"]}
    LEFT_OUT.clear()
    os.environ["PLUGIN_SELECTION_SCAN"] = str(len(scans))
    try:
        run_ash_scan(
            **target,
            output_dir=step["output_dir"],
            mode=RunMode.local,
            offline=True,
            exclude_scanners=list(BUILTINS),
            ash_plugin_modules=step.get("modules") or None,
            fail_on_findings=False,
            show_summary=False,
            progress=False,
        )
        code = 0
    except SystemExit as exc:
        code = exc.code
    except Exception as exc:
        code = "raised " + type(exc).__name__
    results = Path(step["output_dir"]) / "ash_aggregated_results.json"
    rows = None
    if results.is_file():
        data = json.loads(results.read_text(encoding="utf-8"))
        rows = {
            name: (info or {}).get("status")
            for name, info in data.get("scanner_results", {}).items()
            if name not in BUILTINS
        }
    scans.append({"exit": code, "rows": rows, "left_out": list(LEFT_OUT)})

print("PLUGIN-SELECTION-REPORT " + json.dumps(scans), flush=True)
"""
)


class _Process:
    """One interpreter running a sequence of scans."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.site = tmp_path / "site"
        (self.site / HANDLER_PACKAGE).mkdir(parents=True)
        (self.site / HANDLER_PACKAGE / "__init__.py").write_text(
            _HANDLER_INIT, encoding="utf-8"
        )
        (self.site / REPORTER_PACKAGE).mkdir()
        (self.site / REPORTER_PACKAGE / "__init__.py").write_text(
            _REPORTER_INIT, encoding="utf-8"
        )
        (self.site / RAISING_PACKAGE).mkdir()
        (self.site / RAISING_PACKAGE / "__init__.py").write_text(
            _RAISING_INIT, encoding="utf-8"
        )
        (self.site / CONVERTER_PACKAGE).mkdir()
        (self.site / CONVERTER_PACKAGE / "__init__.py").write_text(
            _CONVERTER_INIT, encoding="utf-8"
        )
        self.markers = tmp_path / "markers"
        self.markers.mkdir()
        self.events_log = tmp_path / "events.log"
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.stubs = tmp_path / "stubs"
        install_refusing_installers(self.stubs)
        self.workdir = tmp_path / "cwd"
        self.workdir.mkdir()
        #: Modules the program imports before ASH's built-in plugins load.
        self.preimport: List[str] = []

    def tree(self, name: str) -> Path:
        tree = self.root / name
        tree.mkdir()
        (tree / "app.py").write_text("x = 1\n", encoding="utf-8")
        return tree

    def _env(self) -> Dict[str, str]:
        env = without_inherited_aws(
            {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("ASH_", "SNYK_", "TRIVY_", "FERRET_"))
            }
        )
        python_path = [str(self.site)]
        if env.get("PYTHONPATH"):
            python_path.append(env["PYTHONPATH"])
        if platform.system().lower() != "windows":
            env["PATH"] = os.pathsep.join(
                [str(self.stubs), str(Path(sys.executable).parent), "/usr/bin", "/bin"]
            )
        else:
            env["PATH"] = os.pathsep.join([str(self.stubs), env.get("PATH", "")])
        env.update(
            {
                "PYTHONPATH": os.pathsep.join(python_path),
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "PLUGIN_SELECTION_MARKERS": str(self.markers),
                "PLUGIN_SELECTION_PREIMPORT": json.dumps(self.preimport),
                "PLUGIN_SELECTION_EVENTS": str(self.events_log),
                "PYTHONIOENCODING": "utf-8",
                # Includes no usable AWS settings and a refusing endpoint: an
                # in-process scan builds ASH's reporters.
                **isolated_tool_env(self.root / "tool-env"),
            }
        )
        return env

    def run(self, scans: List[dict]) -> List[dict]:
        completed = subprocess.run(
            [sys.executable, "-c", _PROGRAM, json.dumps(scans)],
            cwd=self.workdir,
            env=self._env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        self.output = completed.stdout + completed.stderr
        for line in completed.stdout.splitlines():
            if _REPORT_PREFIX in line:
                return json.loads(line.split(_REPORT_PREFIX, 1)[1])
        raise AssertionError(
            f"the probe printed no report (exit {completed.returncode}).\n"
            f"stdout tail:\n{completed.stdout[-3000:]}\n"
            f"stderr tail:\n{completed.stderr[-3000:]}"
        )

    def started(self) -> List[str]:
        return sorted(p.name for p in self.markers.iterdir())

    def events(self, scan_index: int) -> List[str]:
        """The events ``HANDLER_PACKAGE`` recorded during the scan at *scan_index*."""
        if not self.events_log.is_file():
            return []
        lines = self.events_log.read_text(encoding="utf-8").splitlines()
        return sorted(
            event
            for index, event in (line.split(" ", 1) for line in lines)
            if index == str(scan_index)
        )


def _rows(scan: dict) -> Dict[str, str]:
    assert scan["rows"] is not None, f"the scan wrote no results: {scan}"
    return {
        name.replace("_", "-").lower(): status for name, status in scan["rows"].items()
    }


def _assert_no_snyk_on_the_scans_path(proc: _Process) -> None:
    """The MISSING snyk-code row below depends on snyk being absent from that PATH."""
    assert shutil.which("snyk", path=proc._env()["PATH"]) is None, (
        "precondition: these tests need no snyk on the PATH the scans get, so that "
        "a scan naming the snyk plugin gets a MISSING snyk-code row; this host has one"
    )


@pytest.mark.integration
class TestALaterScansModulesTakePart:
    def test_a_module_only_the_second_scan_names_gets_a_missing_row(self, tmp_path):
        """The first scan resolves the registry; the second names snyk, absent here."""
        proc = _Process(tmp_path)
        _assert_no_snyk_on_the_scans_path(proc)
        first, second = proc.tree("first"), proc.tree("second")
        unnamed, named = proc.run(
            [
                {"source_dir": str(first), "output_dir": str(tmp_path / "out1")},
                {
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [SNYK_MODULE],
                },
            ]
        )

        assert "snyk-code" not in _rows(unnamed), unnamed
        assert _rows(named).get("snyk-code") == "MISSING", (
            "the second scan named the snyk plugin module, whose tool is absent, "
            f"but its results have no MISSING snyk-code row: {named}"
        )

    def test_each_scan_gets_rows_for_its_own_modules_only(self, tmp_path):
        """Two scans naming two different modules: each sees its own scanner only."""
        proc = _Process(tmp_path)
        _assert_no_snyk_on_the_scans_path(proc)
        first, second = proc.tree("first"), proc.tree("second")
        ferret_scan, snyk_scan = proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [FERRET_MODULE],
                },
                {
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [SNYK_MODULE],
                },
            ]
        )

        assert "ferret-scan" in _rows(ferret_scan), ferret_scan
        assert "snyk-code" not in _rows(ferret_scan), ferret_scan
        assert _rows(snyk_scan).get("snyk-code") == "MISSING", snyk_scan
        assert "ferret-scan" not in _rows(snyk_scan), (
            f"the second scan ran ferret-scan, which only the first scan named: {snyk_scan}"
        )


_WRAPPER_INIT = """
import zzhelper_scanners  # registers HelperScanner; this package does not list it
"""

_HELPER_INIT = """
from automated_security_helper.plugins.decorators import ash_scanner_plugin


@ash_scanner_plugin
class HelperScanner:
    pass
"""


def _left_out_messages(output_dir: Path) -> List[str]:
    """The scan's "not used by this scan" log lines, from the ``ash.log`` it wrote.

    Read from the file, one record per line, rather than the console, which wraps
    long lines; and from this scan's own output directory, so another scan's log
    line cannot count.
    """
    log_file = output_dir / "ash.log"
    if not log_file.is_file():
        return []
    return [
        line
        for line in log_file.read_text(encoding="utf-8").splitlines()
        if "not used by this scan" in line
    ]


def _records(scan: dict, level: str) -> List[str]:
    """The scan's "not used by this scan" log messages at *level*, from any handler."""
    return [r["message"] for r in scan["left_out"] if r["level"] == level]


@pytest.mark.integration
class TestWhatAScanLeavesOutIsLogged:
    """A scan counts the registered plugins it leaves out at INFO, and names them at DEBUG.

    The names stay out of ``ash.log``, which records INFO and above: in a process
    that runs several scans, they are what other scans named.
    """

    def test_a_module_an_earlier_scan_named(self, tmp_path):
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        scan1, scan2 = proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [FERRET_MODULE],
                },
                {"source_dir": str(second), "output_dir": str(tmp_path / "out2")},
            ]
        )

        assert _left_out_messages(tmp_path / "out1") == []
        assert scan1["left_out"] == []
        (line,) = _left_out_messages(tmp_path / "out2")
        assert "1 registered plugin" in line, line
        assert "FerretScanScanner" not in line, (
            "the scan's ash.log names a plugin only an earlier scan named"
        )
        (info,) = _records(scan2, "INFO")
        assert "FerretScanScanner" not in info
        (debug,) = _records(scan2, "DEBUG")
        assert "FerretScanScanner" in debug, debug

    def test_a_scanner_a_named_package_registers_without_listing_it(self, tmp_path):
        proc = _Process(tmp_path)
        (proc.site / "zzwrap_ash_plugins").mkdir()
        (proc.site / "zzwrap_ash_plugins" / "__init__.py").write_text(
            _WRAPPER_INIT, encoding="utf-8"
        )
        (proc.site / "zzhelper_scanners").mkdir()
        (proc.site / "zzhelper_scanners" / "__init__.py").write_text(
            _HELPER_INIT, encoding="utf-8"
        )
        tree = proc.tree("tree")

        (scan,) = proc.run(
            [
                {
                    "source_dir": str(tree),
                    "output_dir": str(tmp_path / "out"),
                    "modules": ["zzwrap_ash_plugins"],
                }
            ]
        )

        assert "helperscanner" not in {name.lower() for name in scan["rows"] or {}}
        (line,) = _left_out_messages(tmp_path / "out")
        assert "HelperScanner" not in line, line
        (debug,) = _records(scan, "DEBUG")
        assert "HelperScanner" in debug, debug


@pytest.mark.integration
class TestThePluginRootNamesNoPlugin:
    """ASH's plugin root holds every package ASH ships; naming it refuses the scan.

    The scans here run after ``list_scanners`` has imported the ferret-scan,
    snyk-code and trivy-repo packages, and none of their scanners gets a row.
    """

    def test_an_in_tree_config_naming_it_after_list_scanners_refuses(self, tmp_path):
        proc = _Process(tmp_path)
        tree = proc.tree("tree")
        (tree / ".ash").mkdir()
        (tree / ".ash" / ".ash.yaml").write_text(
            "project_name: tree\nash_plugin_modules:\n"
            "  - automated_security_helper.plugin_modules\n",
            encoding="utf-8",
        )

        (scan,) = proc.run(
            [
                {"list": True},
                {"source_dir": str(tree), "output_dir": str(tmp_path / "out")},
            ]
        )

        assert scan["exit"] == 3, (scan, proc.output[-3000:])
        assert scan["rows"] is None, scan

    def test_the_python_api_naming_it_refuses(self, tmp_path):
        proc = _Process(tmp_path)
        tree = proc.tree("tree")

        (scan,) = proc.run(
            [
                {"list": True},
                {
                    "source_dir": str(tree),
                    "output_dir": str(tmp_path / "out"),
                    "modules": ["automated_security_helper.plugin_modules"],
                },
            ]
        )

        assert scan["exit"] == 3, (scan, proc.output[-3000:])
        assert scan["rows"] is None, scan


@pytest.mark.integration
class TestEventHandlersFollowTheScansModules:
    def test_a_handler_an_earlier_scan_named_does_not_fire_in_a_later_scan(
        self, tmp_path
    ):
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [HANDLER_PACKAGE],
                },
                {"source_dir": str(second), "output_dir": str(tmp_path / "out2")},
            ]
        )

        assert "first" in proc.started(), (
            "control: the handler of the module the first scan named did not fire "
            "for that scan, so this harness cannot observe a call"
        )
        assert "second" not in proc.started(), (
            "an event handler from a module only the first scan named fired for the "
            "second scan"
        )

    def test_each_phase_event_reaches_only_the_scan_that_named_the_module(
        self, tmp_path
    ):
        """The engine's own events and each default phase's start event.

        Not covered here: INSPECT, which is not a default phase, and the per-plugin
        events such as SCAN_START, which the phases send through the same filter.
        """
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [HANDLER_PACKAGE],
                },
                {"source_dir": str(second), "output_dir": str(tmp_path / "out2")},
            ]
        )

        expected = sorted(name for name in _RECORDED_EVENT_NAMES if name != "ERROR")
        assert proc.events(0) == expected, (
            "control: the scan that named the module did not get each event once",
            proc.output[-3000:],
        )
        assert proc.events(1) == [], (
            "events reached a handler from a module only the earlier scan named"
        )

    def test_error_reaches_only_the_scan_that_named_the_module(self, tmp_path):
        """A handler in RAISING_PACKAGE stops the convert phase, so ERROR is notified."""
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        scan1, scan2 = proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [HANDLER_PACKAGE, RAISING_PACKAGE],
                },
                {
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [RAISING_PACKAGE],
                },
            ]
        )

        assert scan1["exit"] != 0 and scan2["exit"] != 0, (scan1, scan2)
        assert "ERROR" in proc.events(0), (
            "control: the failing scan that named the module notified no ERROR to it",
            proc.events(0),
            proc.output[-3000:],
        )
        assert "ERROR" not in proc.events(1), (
            "ERROR reached a handler from a module only the earlier scan named"
        )

    def test_a_handler_the_calling_program_subscribes_fires_in_every_scan(
        self, tmp_path
    ):
        """Defined outside the plugin namespace: the program's own, not a plugin's."""
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {"subscribe": True},
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [HANDLER_PACKAGE],
                },
                {"source_dir": str(second), "output_dir": str(tmp_path / "out2")},
            ]
        )

        started = proc.started()
        assert "embedded-first" in started and "embedded-second" in started, (
            (
                "a handler the calling program subscribed did not fire in each of "
                f"its scans: {started}"
            ),
            proc.output[-3000:],
        )
        assert "first" in started and "second" not in started, (
            "control: the plugin module's handler still follows the scan's modules: "
            f"{started}"
        )


@pytest.mark.integration
class TestConvertersFollowTheScansModules:
    def test_a_converter_an_earlier_scan_named_does_not_run_in_a_later_scan(
        self, tmp_path
    ):
        proc = _Process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [CONVERTER_PACKAGE],
                },
                {"source_dir": str(second), "output_dir": str(tmp_path / "out2")},
            ]
        )

        assert "converted-first" in proc.started(), (
            (
                "control: the converter of the module the first scan named did not "
                "run for that scan"
            ),
            proc.output[-3000:],
        )
        assert "converted-second" not in proc.started(), (
            "a converter from a module only the first scan named ran in the second"
        )


@pytest.mark.integration
class TestReportersFollowTheScansModules:
    def test_a_reporter_an_earlier_scan_named_does_not_run_in_a_workspace_scan(
        self, tmp_path
    ):
        """Per-project report phases and the workspace-level reports alike."""
        proc = _Process(tmp_path)
        first = proc.tree("first")
        workspace = tmp_path / "ws"
        workspace.mkdir()
        for key in ("api", "web"):
            project = workspace / key
            (project / ".ash").mkdir(parents=True)
            (project / "app.py").write_text("x = 1\n", encoding="utf-8")
            (project / ".ash" / ".ash.yaml").write_text(
                f"project_name: {key}\n", encoding="utf-8"
            )
        workspace_file = workspace / "dev.code-workspace"
        workspace_file.write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [REPORTER_PACKAGE],
                },
                {
                    "workspace_file": str(workspace_file),
                    "output_dir": str(tmp_path / "out2"),
                },
            ]
        )

        assert sorted((tmp_path / "out1").rglob("*.zzmark")), (
            "control: the reporter of the module the first scan named wrote no "
            "report for that scan"
        )
        unexpected = sorted(
            p.relative_to(tmp_path).as_posix()
            for p in (tmp_path / "out2").rglob("*.zzmark")
        )
        assert unexpected == [], (
            "a reporter from a module only the first scan named ran in the "
            f"workspace scan: {unexpected}"
        )

    def test_a_reporter_the_workspace_scan_names_itself_writes_every_report(
        self, tmp_path
    ):
        """Named by the scan's own argument, not by a project config.

        The projects' reports and the workspace-level report, which comes from the
        workspace's own reporter list rather than any project's engine.
        """
        proc = _Process(tmp_path)
        workspace = tmp_path / "ws"
        for key in ("api", "web"):
            project = workspace / key
            (project / ".ash").mkdir(parents=True)
            (project / "app.py").write_text("x = 1\n", encoding="utf-8")
            (project / ".ash" / ".ash.yaml").write_text(
                f"project_name: {key}\n", encoding="utf-8"
            )
        workspace_file = workspace / "dev.code-workspace"
        workspace_file.write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )
        proc.run(
            [
                {
                    "workspace_file": str(workspace_file),
                    "output_dir": str(tmp_path / "out"),
                    "modules": [REPORTER_PACKAGE],
                }
            ]
        )

        assert _reports(tmp_path / "out", "zzmark") == [
            "projects/api/reports/ash.zzmark",
            "projects/web/reports/ash.zzmark",
            "reports/ash.zzmark",
        ], proc.output[-3000:]


#: A regular package whose ``__init__`` imports nothing, and a subpackage of it
#: holding one reporter that writes ``ash.zzcloud``.
PARENT_PACKAGE = "zzparent_ash_plugins"
CHILD_PACKAGE = f"{PARENT_PACKAGE}.cloud"


@pytest.mark.integration
class TestAPackageDoesNotSelectItsSubpackagesPlugins:
    """Naming a package selects what it defines, imports or lists, in either order.

    A scan naming only the parent never imports the subpackage, so a parent that
    selected its subpackages' plugins would select them only after another scan in
    the process had imported one.
    """

    def _process(self, tmp_path: Path) -> _Process:
        proc = _Process(tmp_path)
        child = proc.site / PARENT_PACKAGE / "cloud"
        child.mkdir(parents=True)
        (proc.site / PARENT_PACKAGE / "__init__.py").write_text("", encoding="utf-8")
        (child / "__init__.py").write_text(
            _mark_reporter_init("ZzCloudMarkReporter", "zz-cloud-mark", "zzcloud"),
            encoding="utf-8",
        )
        return proc

    def test_the_parent_after_a_scan_that_named_the_subpackage(self, tmp_path):
        proc = self._process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [CHILD_PACKAGE],
                },
                {
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [PARENT_PACKAGE],
                },
            ]
        )

        assert _reports(tmp_path / "out1", "zzcloud"), (
            "control: the subpackage the first scan named wrote no report for it",
            proc.output[-3000:],
        )
        assert _reports(tmp_path / "out2", "zzcloud") == [], (
            "a scan naming only the parent package ran the reporter of a subpackage "
            "that an earlier scan had imported"
        )

    def test_the_subpackage_after_a_scan_that_named_the_parent(self, tmp_path):
        proc = self._process(tmp_path)
        first, second = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [PARENT_PACKAGE],
                },
                {
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [CHILD_PACKAGE],
                },
            ]
        )

        assert _reports(tmp_path / "out1", "zzcloud") == [], (
            "a scan naming only the parent package ran its subpackage's reporter"
        )
        assert _reports(tmp_path / "out2", "zzcloud"), (
            "control: the subpackage the second scan named wrote no report for it",
            proc.output[-3000:],
        )


@pytest.mark.integration
class TestPluginClassesWithTheSameName:
    """Registrations are told apart by module path and class name.

    Two packages here each define a reporter class named ``ZzSharedReporter``, with
    their own config names and report extensions, and a third defines one named
    like ASH's built-in ``JunitXmlReporter``.
    """

    def _process(self, tmp_path: Path) -> _Process:
        proc = _Process(tmp_path)
        for prefix in ("zzaa", "zzbb"):
            package = proc.site / f"{prefix}_ash_plugins"
            package.mkdir()
            (package / "__init__.py").write_text(
                _mark_reporter_init("ZzSharedReporter", f"{prefix}-shared", prefix),
                encoding="utf-8",
            )
        package = proc.site / "zzshadow_ash_plugins"
        package.mkdir()
        (package / "__init__.py").write_text(
            _mark_reporter_init("JunitXmlReporter", "zz-shadow", "zzshadow"),
            encoding="utf-8",
        )
        return proc

    @pytest.mark.parametrize("first, second", [("zzaa", "zzbb"), ("zzbb", "zzaa")])
    def test_each_scan_runs_the_class_of_the_package_it_names(
        self, tmp_path, first, second
    ):
        proc = self._process(tmp_path)
        tree1, tree2 = proc.tree("first"), proc.tree("second")
        proc.run(
            [
                {
                    "source_dir": str(tree1),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [f"{first}_ash_plugins"],
                },
                {
                    "source_dir": str(tree2),
                    "output_dir": str(tmp_path / "out2"),
                    "modules": [f"{second}_ash_plugins"],
                },
            ]
        )

        assert _reports(tmp_path / "out1", first), proc.output[-3000:]
        assert _reports(tmp_path / "out1", second) == []
        assert _reports(tmp_path / "out2", second), (
            (
                f"the second scan named {second}_ash_plugins, whose reporter has "
                f"the class name of the one {first}_ash_plugins registered first, "
                "and its reporter did not run"
            ),
            proc.output[-3000:],
        )
        assert _reports(tmp_path / "out2", first) == []

    def test_one_scan_naming_both_packages_runs_both_classes(self, tmp_path):
        proc = self._process(tmp_path)
        tree = proc.tree("tree")
        proc.run(
            [
                {
                    "source_dir": str(tree),
                    "output_dir": str(tmp_path / "out"),
                    "modules": ["zzaa_ash_plugins", "zzbb_ash_plugins"],
                }
            ]
        )

        assert _reports(tmp_path / "out", "zzaa"), proc.output[-3000:]
        assert _reports(tmp_path / "out", "zzbb"), proc.output[-3000:]

    @pytest.mark.parametrize("before_builtins", [False, True])
    def test_a_class_named_like_a_built_in_neither_replaces_nor_hides_it(
        self, tmp_path, before_builtins
    ):
        """Imported before or after the built-ins register, in a scan naming it or not."""
        proc = self._process(tmp_path)
        if before_builtins:
            proc.preimport = ["zzshadow_ash_plugins"]
        named, unnamed = proc.tree("named"), proc.tree("unnamed")
        proc.run(
            [
                {
                    "source_dir": str(named),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": ["zzshadow_ash_plugins"],
                },
                {"source_dir": str(unnamed), "output_dir": str(tmp_path / "out2")},
            ]
        )

        assert _reports(tmp_path / "out1", "zzshadow"), (
            "control: the named package's reporter wrote no report",
            proc.output[-3000:],
        )
        for out in ("out1", "out2"):
            assert "reports/ash.junit.xml" in _reports(tmp_path / out, "xml"), (
                f"the built-in JunitXmlReporter wrote no report in {out}",
                proc.output[-3000:],
            )
        assert _reports(tmp_path / "out2", "zzshadow") == []


def _plugin_module(root: Path, name: str, class_name: str) -> type:
    """An importable module holding one scanner-shaped class, registered nowhere."""
    (root / f"{name}.py").write_text(
        f"class {class_name}:\n    ash_plugin_type = 'scanner'\n", encoding="utf-8"
    )
    importlib.invalidate_caches()
    return getattr(importlib.import_module(name), class_name)


@pytest.mark.unit
class TestTheResolvedListFollowsRegistration:
    """On a private manager, so the process-wide registry is not touched."""

    def test_a_plugin_registered_after_a_resolve_is_in_the_next_one(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.syspath_prepend(str(tmp_path))
        early = _plugin_module(tmp_path, "zzselect_early_mod", "EarlyScanner")
        late = _plugin_module(tmp_path, "zzselect_late_mod", "LateScanner")
        manager = AshPluginManager()

        manager.register_plugin_module("scanner", early, "zzselect_early_mod")
        assert manager.plugin_modules("scanner") == [early]

        manager.register_plugin_module("scanner", late, "zzselect_late_mod")
        assert manager.plugin_modules("scanner") == [early, late], (
            "a scanner registered after the first resolve is missing from the next "
            "one, so a module a later scan names would get no row"
        )

    def test_the_filter_applies_to_the_current_list(self, tmp_path, monkeypatch):
        monkeypatch.syspath_prepend(str(tmp_path))
        early = _plugin_module(tmp_path, "zzselect_kept_mod", "KeptScanner")
        late = _plugin_module(tmp_path, "zzselect_other_mod", "OtherScanner")
        manager = AshPluginManager()
        manager.register_plugin_module("scanner", early, "zzselect_kept_mod")
        manager.plugin_modules("scanner")
        manager.register_plugin_module("scanner", late, "zzselect_other_mod")

        assert manager.plugin_modules(
            "scanner", lambda cls: cls.__module__ == "zzselect_other_mod"
        ) == [late]


@pytest.mark.unit
class TestRegistrationsAreKeyedByModuleAndName:
    """On a private manager, so the process-wide registry is not touched."""

    def test_a_same_named_class_from_another_module_registers_too(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.syspath_prepend(str(tmp_path))
        one = _plugin_module(tmp_path, "zzsame_one_mod", "SameScanner")
        two = _plugin_module(tmp_path, "zzsame_two_mod", "SameScanner")
        manager = AshPluginManager()

        manager.register_plugin_module("scanner", one, "zzsame_one_mod")
        manager.register_plugin_module("scanner", two, "zzsame_two_mod")

        assert manager.plugin_modules("scanner") == [one, two]

    def test_registering_a_class_again_adds_nothing(self, tmp_path, monkeypatch):
        monkeypatch.syspath_prepend(str(tmp_path))
        one = _plugin_module(tmp_path, "zzsame_again_mod", "AgainScanner")
        manager = AshPluginManager()

        manager.register_plugin_module("scanner", one, "zzsame_again_mod")
        manager.register_plugin_module("scanner", one, "zzsame_again_mod")

        assert manager.plugin_modules("scanner") == [one]

    @pytest.mark.parametrize("built_in_first", [True, False])
    def test_a_built_in_and_a_class_named_like_it_both_resolve(
        self, tmp_path, monkeypatch, built_in_first
    ):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        monkeypatch.syspath_prepend(str(tmp_path))
        named_alike = _plugin_module(tmp_path, "zzsame_bandit_mod", "BanditScanner")
        order = [BanditScanner, named_alike]
        if not built_in_first:
            order.reverse()
        manager = AshPluginManager()

        for cls in order:
            manager.register_plugin_module("scanner", cls, cls.__module__)
        resolved = manager.plugin_modules("scanner")

        assert BanditScanner in resolved, resolved
        assert named_alike in resolved, resolved
