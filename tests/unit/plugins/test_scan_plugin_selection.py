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
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from automated_security_helper.plugins.plugin_manager import AshPluginManager
from tests.utils.isolated_tool_env import (
    install_refusing_installers,
    isolated_tool_env,
)

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


ASH_EVENT_HANDLERS = {AshEventType.EXECUTION_START: [record_execution_start]}
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

#: argv[1] is a JSON list of scans. A scan is ``{"source_dir", "output_dir",
#: "modules"}``, or ``{"workspace_file", "output_dir"}`` for a workspace scan.
#: Prints one report line: per scan, the exit code and each scanner row's status.
_PROGRAM = r"""
import json
import sys
from pathlib import Path

from automated_security_helper.plugins.loader import load_internal_plugins


def _config_name(cls):
    field = getattr(cls, "model_fields", {}).get("config")
    for arg in getattr(getattr(field, "annotation", None), "__args__", None) or ():
        fields = getattr(arg, "model_fields", None) or {}
        if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig") and "name" in fields:
            if fields["name"].default:
                return fields["name"].default
    raise RuntimeError("no config name for " + cls.__name__)


BUILTINS = sorted({_config_name(c) for c in load_internal_plugins()["scanners"]})

# Imported after the built-in plugins load, the order an `ash` process has.
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

scans = []
for step in json.loads(sys.argv[1]):
    if "workspace_file" in step:
        from automated_security_helper.workspace.resolver import resolve_workspace

        target = {"workspace_plan": resolve_workspace(Path(step["workspace_file"]))}
    else:
        target = {"source_dir": step["source_dir"]}
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
    results = Path(step["output_dir"]) / "ash_aggregated_results.json"
    rows = None
    if results.is_file():
        data = json.loads(results.read_text(encoding="utf-8"))
        rows = {
            name: (info or {}).get("status")
            for name, info in data.get("scanner_results", {}).items()
            if name not in BUILTINS
        }
    scans.append({"exit": code, "rows": rows})

print("PLUGIN-SELECTION-REPORT " + json.dumps(scans), flush=True)
"""


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
        self.markers = tmp_path / "markers"
        self.markers.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.stubs = tmp_path / "stubs"
        install_refusing_installers(self.stubs)
        self.workdir = tmp_path / "cwd"
        self.workdir.mkdir()

    def tree(self, name: str) -> Path:
        tree = self.root / name
        tree.mkdir()
        (tree / "app.py").write_text("x = 1\n", encoding="utf-8")
        return tree

    def _env(self) -> Dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("ASH_", "SNYK_", "TRIVY_", "FERRET_", "AWS_"))
        }
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
                "PYTHONIOENCODING": "utf-8",
                # No usable cloud credentials and a refusing endpoint, whatever
                # the host has: an in-process scan builds ASH's reporters.
                "AWS_CONFIG_FILE": os.devnull,
                "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
                "AWS_REGION": "us-east-1",
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


def _rows(scan: dict) -> Dict[str, str]:
    assert scan["rows"] is not None, f"the scan wrote no results: {scan}"
    return {
        name.replace("_", "-").lower(): status for name, status in scan["rows"].items()
    }


class TestALaterScansModulesTakePart:
    def test_a_module_only_the_second_scan_names_gets_a_missing_row(self, tmp_path):
        """The first scan resolves the registry; the second names snyk, absent here."""
        proc = _Process(tmp_path)
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
        leaked = sorted(
            p.relative_to(tmp_path).as_posix()
            for p in (tmp_path / "out2").rglob("*.zzmark")
        )
        assert leaked == [], (
            "a reporter from a module only the first scan named ran in the "
            f"workspace scan: {leaked}"
        )


def _plugin_module(root: Path, name: str, class_name: str) -> type:
    """An importable module holding one scanner-shaped class, registered nowhere."""
    (root / f"{name}.py").write_text(
        f"class {class_name}:\n    ash_plugin_type = 'scanner'\n", encoding="utf-8"
    )
    importlib.invalidate_caches()
    return getattr(importlib.import_module(name), class_name)


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
