# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin module outside ASH's namespace is never imported, and refuses the scan.

The behavior these tests hold
-----------------------------
``load_additional_plugin_modules`` refuses a name outside the plugin namespace
(``automated_security_helper.``, ``ash_plugins``, or a top-level package ending in
``ash_plugins``; see ``plugins/loader.py``). The scan engine and workspace mode then
call ``discover_plugins`` with the same list, so whatever the loader refused must
not be imported there either: importing a package runs its ``__init__``.

A refused name is also an error in the configuration, not a hint. Naming one, from
any source ASH reads ``ash_plugin_modules`` from, refuses the scan with the
invalid-configuration exit code, 3, rather than warning and scanning on.

How "imported" is observed
--------------------------
In-process tests create a top-level package under ``tmp_path``, put it on
``sys.path``, and check ``sys.modules`` afterwards. End-to-end tests run ASH in a
fresh interpreter, because ``sys.modules`` there is the only one that shows what a
real run imported; the package's ``__init__`` writes a marker file, and the test
reads the marker and the exit code. The packages live outside the scanned tree,
so the in-tree config's installed-module rule (``config/plugin_module_trust.py``)
keeps them and the namespace rule is the one under test.

Each end-to-end scan runs ``detect-secrets`` only, which is a Python dependency of
ASH, with HOME a temporary directory, PATH reduced to the interpreter's directory and
stub installers, and every tool directory under the test's temporary directory
(``tests/utils/isolated_tool_env.py``), so nothing reaches the network or the real
home.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from tests.utils.isolated_tool_env import (
    install_refusing_installers,
    isolated_tool_env,
)

#: Refused by the loader. The second and third are what a prefix test written as
#: ``startswith("ash_plugins")`` or ``startswith("automated_security_helper")`` would
#: wrongly accept: the rule is a dotted prefix or a top-level suffix.
REFUSED = "zz_unlisted_pkg"
REFUSED_SPELLINGS = [REFUSED, "ash_plugins_extra", "automated_security_helper_extra"]

#: Accepted by the loader: a top-level package whose name ends in ``ash_plugins``.
ACCEPTED = "zzctl_ash_plugins"

EXIT_INVALID_CONFIG = 3

_MARKER_ENV = "PLUGIN_IMPORT_MARKER"

_PACKAGE_INIT = (
    "import os, pathlib\n"
    "LOADED = True\n"
    f"_marker = os.environ.get({_MARKER_ENV!r})\n"
    "if _marker:\n"
    "    pathlib.Path(_marker, __name__).write_text('imported', encoding='utf-8')\n"
)


def _site(root: Path, names: List[str]) -> Path:
    """A directory outside every scanned tree holding one package per name."""
    site = root / "site"
    for name in names:
        (site / name).mkdir(parents=True, exist_ok=True)
        (site / name / "__init__.py").write_text(_PACKAGE_INIT, encoding="utf-8")
    return site


@pytest.fixture
def packages(tmp_path, monkeypatch):
    """Every package these tests name, importable, and forgotten afterwards."""
    names = REFUSED_SPELLINGS + [ACCEPTED]
    site = _site(tmp_path, names)
    monkeypatch.syspath_prepend(str(site))
    yield site
    for name in [n for n in sys.modules if n.split(".", 1)[0] in names]:
        del sys.modules[name]


def _tolerating_refusal(call, *args, **kwargs) -> None:
    """Run ``call``; a configuration refusal is an allowed outcome, nothing else is.

    The required behavior is that the refused name is not imported. Whether the
    refusal surfaces from this function or from the scan above it is the
    implementation's choice, so ``ASHConfigValidationError`` is accepted here and
    the scan-level tests below hold the exit code.
    """
    try:
        call(*args, **kwargs)
    except ASHConfigValidationError:
        pass


def _plan(tmp_path: Path, modules: List[str]) -> WorkspacePlan:
    return WorkspacePlan(
        workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=(tmp_path / "api").as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
                ash_plugin_modules=list(modules),
            )
        ],
    )


class TestDiscoveryHonorsTheNamespace:
    @pytest.mark.parametrize("name", REFUSED_SPELLINGS)
    def test_discover_plugins_does_not_import_a_name_outside_the_namespace(
        self, packages, name
    ):
        _tolerating_refusal(discover_plugins, plugin_modules=[name])

        assert name not in sys.modules, (
            f"discover_plugins imported {name!r}, a name the plugin loader refuses"
        )

    def test_discover_plugins_imports_a_package_inside_the_namespace(self, packages):
        """Control: an accepted top-level package is still imported."""
        discover_plugins(plugin_modules=[ACCEPTED])

        assert ACCEPTED in sys.modules


class TestWorkspacePrewarmHonorsTheNamespace:
    @pytest.mark.parametrize("source", ["project", "cli"])
    def test_prewarm_does_not_import_a_name_outside_the_namespace(
        self, packages, tmp_path, source
    ):
        """Workspace mode registers plugins once, from the projects and the CLI."""
        plan = _plan(tmp_path, [REFUSED] if source == "project" else [])
        settings = ProjectScanSettings(
            output_dir=tmp_path / "out",
            ash_plugin_modules=(REFUSED,) if source == "cli" else (),
        )

        _tolerating_refusal(prewarm_plugin_registry, plan, settings)

        assert REFUSED not in sys.modules, (
            f"workspace pre-warm imported {REFUSED!r} from the {source} module list"
        )

    def test_prewarm_imports_a_package_inside_the_namespace(self, packages, tmp_path):
        """Control: the same path imports an accepted package."""
        plan = _plan(tmp_path, [ACCEPTED])
        settings = ProjectScanSettings(output_dir=tmp_path / "out")

        prewarm_plugin_registry(plan, settings)

        assert ACCEPTED in sys.modules


# --------------------------------------------------------------------------- end to end

_PROGRAM = r"""
import asyncio
import json
import sys

mode, spec = sys.argv[1], json.loads(sys.argv[2])

if mode == "cli":
    from automated_security_helper.cli.entrypoint import main

    sys.argv = ["ash"] + spec["args"]
    main()
    raise SystemExit(0)

if mode == "api":
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    run_ash_scan(
        source_dir=spec["source_dir"],
        output_dir=spec["output_dir"],
        mode=RunMode.local,
        scanners=["detect-secrets"],
        ash_plugin_modules=spec["modules"],
        fail_on_findings=False,
        show_summary=False,
        progress=False,
    )
    raise SystemExit(0)

if mode == "mcp":
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.plugins.loader import load_internal_plugins

    def _config_name(cls):
        field = getattr(cls, "model_fields", {}).get("config")
        for arg in getattr(getattr(field, "annotation", None), "__args__", None) or ():
            fields = getattr(arg, "model_fields", None) or {}
            if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig") and "name" in fields:
                if fields["name"].default:
                    return fields["name"].default
        raise RuntimeError("no config name for " + cls.__name__)

    lines = ["project_name: refused-module-probe", "ash_plugin_modules:"]
    lines += ["  - " + name for name in spec["modules"]]
    lines.append("scanners:")
    for cls in load_internal_plugins()["scanners"]:
        name = _config_name(cls)
        if name != "detect-secrets":
            lines += ["  " + name + ":", "    enabled: false"]
    with open(spec["config"], "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    async def _go():
        started = await mcp_scan_directory(spec["source_dir"], config_path=spec["config"])
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending)
        return started

    started = asyncio.run(_go())
    entry = get_scan_registry().get_scan(started["scan_id"]) if started.get("success") else None
    print(
        "MCP-SCAN "
        + json.dumps(
            {
                "started": bool(started.get("success")),
                "status": getattr(getattr(entry, "status", None), "value", None),
                "error": getattr(entry, "error_message", None) or started.get("error"),
            }
        ),
        flush=True,
    )
    raise SystemExit(0)

raise SystemExit("unknown mode " + mode)
"""


class _Run:
    """One ASH process in a fresh interpreter, with the packages on its path."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.site = _site(tmp_path, REFUSED_SPELLINGS + [ACCEPTED])
        self.markers = tmp_path / "markers"
        self.markers.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.stubs = tmp_path / "stubs"
        install_refusing_installers(self.stubs)
        self.workdir = tmp_path / "cwd"
        self.workdir.mkdir()
        self.tree = tmp_path / "tree"
        self.tree.mkdir()
        (self.tree / "app.py").write_text("x = 1\n", encoding="utf-8")

    def env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_")}
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
                _MARKER_ENV: str(self.markers),
                "ASH_MCP_ALLOWED_ROOTS": str(self.root),
                "PYTHONIOENCODING": "utf-8",
                **isolated_tool_env(self.root / "tool-env"),
            }
        )
        env.update(extra or {})
        return env

    def run(
        self, mode: str, spec: dict, extra_env: Optional[Dict[str, str]] = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", _PROGRAM, mode, json.dumps(spec)],
            cwd=self.workdir,
            env=self.env(extra_env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )

    def scan_args(self, *extra: str) -> List[str]:
        return [
            "--source-dir",
            str(self.tree),
            "--output-dir",
            str(self.root / "out"),
            "--mode",
            "local",
            "--scanners",
            "detect-secrets",
            "--phases",
            "scan",
            "--no-progress",
            *extra,
        ]

    def imported(self) -> List[str]:
        return sorted(p.name for p in self.markers.iterdir())


def _tail(completed: subprocess.CompletedProcess) -> str:
    return f"stdout:\n{completed.stdout[-2500:]}\nstderr:\n{completed.stderr[-2500:]}"


def _assert_refused(run: _Run, completed: subprocess.CompletedProcess) -> None:
    assert REFUSED not in run.imported(), (
        f"ASH imported {REFUSED!r}, a plugin module outside its namespace\n"
        + _tail(completed)
    )
    assert completed.returncode == EXIT_INVALID_CONFIG, (
        f"naming {REFUSED!r} must refuse the scan with exit {EXIT_INVALID_CONFIG}, "
        f"got {completed.returncode}\n" + _tail(completed)
    )


class TestARefusedModuleRefusesTheScan:
    def test_the_ash_plugin_modules_flag(self, tmp_path):
        run = _Run(tmp_path)
        completed = run.run(
            "cli", {"args": run.scan_args("--ash-plugin-modules", REFUSED)}
        )
        _assert_refused(run, completed)

    def test_the_ash_plugin_modules_environment_variable(self, tmp_path):
        run = _Run(tmp_path)
        completed = run.run(
            "cli", {"args": run.scan_args()}, {"ASH_PLUGIN_MODULES": REFUSED}
        )
        _assert_refused(run, completed)

    def test_a_config_file_inside_the_scanned_tree(self, tmp_path):
        run = _Run(tmp_path)
        (run.tree / ".ash").mkdir()
        (run.tree / ".ash" / ".ash.yaml").write_text(
            f"project_name: tree\nash_plugin_modules:\n  - {REFUSED}\n",
            encoding="utf-8",
        )
        completed = run.run("cli", {"args": run.scan_args()})
        _assert_refused(run, completed)

    def test_an_operator_config_file_outside_the_tree(self, tmp_path):
        run = _Run(tmp_path)
        config = tmp_path / "operator.yaml"
        config.write_text(
            f"project_name: tree\nash_plugin_modules:\n  - {REFUSED}\n",
            encoding="utf-8",
        )
        completed = run.run("cli", {"args": run.scan_args("--config", str(config))})
        _assert_refused(run, completed)

    def test_a_config_override(self, tmp_path):
        run = _Run(tmp_path)
        completed = run.run(
            "cli",
            {
                "args": run.scan_args(
                    "--config-overrides", f'ash_plugin_modules+=["{REFUSED}"]'
                )
            },
        )
        _assert_refused(run, completed)

    def test_a_comma_joined_entry_beside_an_accepted_one(self, tmp_path):
        """A config entry is split on commas; an accepted name beside it changes nothing."""
        run = _Run(tmp_path)
        config = tmp_path / "operator.yaml"
        config.write_text(
            f'project_name: tree\nash_plugin_modules:\n  - "{ACCEPTED},{REFUSED}"\n',
            encoding="utf-8",
        )
        completed = run.run("cli", {"args": run.scan_args("--config", str(config))})
        _assert_refused(run, completed)

    def test_the_python_api(self, tmp_path):
        run = _Run(tmp_path)
        completed = run.run(
            "api",
            {
                "source_dir": str(run.tree),
                "output_dir": str(tmp_path / "out"),
                "modules": [REFUSED],
            },
        )
        _assert_refused(run, completed)

    def test_a_workspace_project_config(self, tmp_path):
        """Workspace mode reads each project's list; the refusal is exit 3 there too."""
        run = _Run(tmp_path)
        workspace = tmp_path / "ws"
        for key in ("api", "web"):
            (workspace / key / ".ash").mkdir(parents=True)
            (workspace / key / "app.py").write_text("x = 1\n", encoding="utf-8")
            (workspace / key / ".ash" / ".ash.yaml").write_text(
                f"project_name: {key}\nash_plugin_modules:\n  - {REFUSED}\n",
                encoding="utf-8",
            )
        workspace_file = workspace / "dev.code-workspace"
        workspace_file.write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )
        completed = run.run(
            "cli",
            {
                "args": [
                    "--workspace",
                    str(workspace_file),
                    "--output-dir",
                    str(tmp_path / "out"),
                    "--mode",
                    "local",
                    "--scanners",
                    "detect-secrets",
                    "--no-progress",
                ]
            },
        )
        _assert_refused(run, completed)

    def test_an_mcp_scan_config(self, tmp_path):
        """The MCP scan tool records the refusal as a failed scan with exit 3."""
        run = _Run(tmp_path)
        completed = run.run(
            "mcp",
            {
                "source_dir": str(run.tree),
                "config": str(tmp_path / "operator.yaml"),
                "modules": [REFUSED],
            },
        )
        reports = [
            json.loads(line.split("MCP-SCAN ", 1)[1])
            for line in completed.stdout.splitlines()
            if "MCP-SCAN " in line
        ]
        assert reports, "the MCP probe printed no report\n" + _tail(completed)
        report = reports[0]

        assert REFUSED not in run.imported(), (
            f"an MCP scan imported {REFUSED!r}\n" + _tail(completed)
        )
        assert report["started"], report
        assert report["status"] == "failed", report
        assert f"code {EXIT_INVALID_CONFIG}" in (report["error"] or ""), report

    def test_an_accepted_module_is_imported_and_the_scan_runs(self, tmp_path):
        """Control: a package inside the namespace, outside the tree, still loads.

        A plugin installed on the system keeps working, and the marker shows the
        harness observes an import when one happens.
        """
        run = _Run(tmp_path)
        completed = run.run(
            "cli", {"args": run.scan_args("--ash-plugin-modules", ACCEPTED)}
        )

        assert ACCEPTED in run.imported(), _tail(completed)
        assert completed.returncode == 0, _tail(completed)
