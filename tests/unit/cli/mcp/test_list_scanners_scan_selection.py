# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan selects from its own plugin modules, whatever ``list_scanners`` loaded.

The behavior these tests hold
-----------------------------
``mcp_list_scanners()`` reports every scanner ASH ships, including the community
scanners in ``plugin_modules/ash_*_plugins`` that ``load_internal_plugins()`` does
not load. Reporting them must not make them part of a later scan. A scan's
scanners are the built-in set plus the modules that scan's own resolved
``ash_plugin_modules`` names, so asking which scanners exist turns none of them on
for a scan. ``snyk-code``, for example, runs ``snyk code test`` on the scanned tree
only in a scan whose modules name ``ash_snyk_plugins``.

Why every case runs in a fresh interpreter
------------------------------------------
The plugin registry and its memoised resolve are process-global, and both the
listing and the order of listing and scanning are what is under test. A pytest
worker has an unknown history, so each sequence runs in its own subprocess, the
way one MCP server process would see it.

Why the community tools are fakes
---------------------------------
``snyk``, ``trivy`` and ``ferret-scan`` on PATH are recorders that write their
argv and cwd to a log and talk to no network. HOME is a temporary directory and
PATH holds only the fakes and the interpreter's own directory, so no real tool or
credential on the host is reachable. Every directory a tool or installer writes to,
and stubs for the installers themselves, come from ``tests/utils/isolated_tool_env.py``,
so nothing is written outside the test's temporary directory. A tool "started against the tree" is one
whose argv names the scanned directory or whose cwd is inside it; a version probe
is neither, and is allowed.

The built-in scanners are excluded from every scan so that nothing else runs,
which keeps each case to a few seconds. The community set is not hard-coded: it
is whatever ``mcp_list_scanners()`` reports beyond the built-ins, so a community
package added later is covered without editing this file.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from tests.utils.isolated_tool_env import (
    install_refusing_installers,
    isolated_tool_env,
)

SNYK_MODULE = "automated_security_helper.plugin_modules.ash_snyk_plugins"

_REPORT_PREFIX = "SCAN-SELECTION-REPORT "

#: Runs one sequence of steps in a fresh interpreter and prints what it saw.
#:
#: argv[1] is a JSON object with a ``steps`` list. A step is one of
#: ``{"op": "list"}``; ``{"op": "scan", "source_dir", "output_dir", "modules"?}``,
#: through the Python API ``run_ash_scan`` the MCP scan tool calls;
#: ``{"op": "mcp_scan", "source_dir", "config"}``, through the MCP tool
#: ``mcp_scan_directory`` itself; or ``{"op": "workspace_scan", "workspace_file",
#: "output_dir"}``.
_PROGRAM = r"""
import asyncio
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


def _scanner_results(paths):
    names = set()
    found = False
    for path in paths:
        if path.is_file():
            found = True
            names.update(json.loads(path.read_text(encoding="utf-8")).get("scanner_results", {}))
    return sorted(names) if found else None


def _run_api_scan(**kwargs):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            mode=RunMode.local,
            exclude_scanners=list(BUILTINS),
            fail_on_findings=False,
            show_summary=False,
            progress=False,
            **kwargs,
        )
        return 0
    except SystemExit as exc:
        return exc.code


def _run_mcp_scan(source_dir, config):
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    lines = ["project_name: selection-probe", "scanners:"]
    for name in BUILTINS:
        lines += ["  " + name + ":", "    enabled: false"]
    Path(config).write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def _go():
        started = await mcp_scan_directory(source_dir, config_path=config)
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending)
        return started

    return asyncio.run(_go())


report = {"builtins": BUILTINS, "lists": [], "scans": []}
for step in json.loads(sys.argv[1])["steps"]:
    op = step["op"]
    if op == "list":
        from automated_security_helper.cli.mcp_tools import mcp_list_scanners

        report["lists"].append(sorted(entry["name"] for entry in mcp_list_scanners()))
    elif op == "scan":
        code = _run_api_scan(
            source_dir=step["source_dir"],
            output_dir=step["output_dir"],
            ash_plugin_modules=step.get("modules") or None,
        )
        results = Path(step["output_dir"]) / "ash_aggregated_results.json"
        report["scans"].append({"exit": code, "scanners": _scanner_results([results])})
    elif op == "mcp_scan":
        started = _run_mcp_scan(step["source_dir"], step["config"])
        output = Path(started.get("output_directory") or step["source_dir"])
        report["scans"].append(
            {
                "started": bool(started.get("success")),
                "scanners": _scanner_results([output / "ash_aggregated_results.json"]),
            }
        )
    elif op == "workspace_scan":
        from automated_security_helper.workspace.resolver import resolve_workspace

        plan = resolve_workspace(Path(step["workspace_file"]))
        code = _run_api_scan(workspace_plan=plan, output_dir=step["output_dir"])
        results = sorted(Path(step["output_dir"]).rglob("ash_aggregated_results.json"))
        report["scans"].append({"exit": code, "scanners": _scanner_results(results)})
    else:
        raise SystemExit("unknown step " + op)

print("SCAN-SELECTION-REPORT " + json.dumps(report), flush=True)
"""

#: Body of each fake community tool. Records the call and answers a version probe;
#: ``snyk`` also writes an empty SARIF log where ASH asked for one.
_RECORDER = r"""
import json
import os
import sys

argv = sys.argv[1:]
with open(os.environ["SELECTION_FAKE_TOOL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": TOOL, "argv": argv, "cwd": os.getcwd()}) + "\n")
if argv[:1] in (["--version"], ["-v"], ["version"]):
    print("0.0.0")
    raise SystemExit(0)
sarif = None
for index, arg in enumerate(argv):
    if arg.startswith("--sarif-file-output="):
        sarif = arg.split("=", 1)[1]
    elif arg == "--sarif-file-output" and index + 1 < len(argv):
        sarif = argv[index + 1]
if sarif:
    with open(sarif, "w", encoding="utf-8") as handle:
        json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": TOOL}}, "results": []}]}, handle)
raise SystemExit(0)
"""


_FAKE_TOOLS = ("snyk", "trivy", "ferret-scan")


def _install_fake(bin_dir: Path, name: str) -> None:
    """Put a recorder named ``name`` on PATH, shaped like a real install's launcher.

    An executable file on POSIX; a ``.cmd`` shim on Windows, where a shebang script
    cannot be started and ``find_executable`` tries ``.cmd`` before the bare name.
    """
    script = bin_dir / f"_fake_{name.replace('-', '_')}.py"
    script.write_text(f"TOOL = {name!r}\n" + _RECORDER, encoding="utf-8")
    if platform.system().lower() == "windows":
        (bin_dir / f"{name}.cmd").write_text(
            f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
        )
        return
    launcher = bin_dir / name
    launcher.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _source(root: Path, name: str) -> Path:
    tree = root / name
    tree.mkdir(parents=True)
    (tree / "app.py").write_text(
        'import os\npassword = "hunter2"\nos.system("echo " + input())\n',
        encoding="utf-8",
    )
    return tree


class _Sequence:
    """One fresh interpreter, the fakes it sees, and what it reported."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.bin_dir = tmp_path / "bin"
        self.bin_dir.mkdir()
        for name in _FAKE_TOOLS:
            _install_fake(self.bin_dir, name)
        install_refusing_installers(self.bin_dir)
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.log = tmp_path / "fake-tools.log"
        self.workdir = tmp_path / "cwd"
        self.workdir.mkdir()

    def _env(self) -> Dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("ASH_", "SNYK_", "TRIVY_", "FERRET_"))
        }
        if platform.system().lower() == "windows":
            path = os.pathsep.join([str(self.bin_dir), env.get("PATH", "")])
        else:
            path = os.pathsep.join(
                [
                    str(self.bin_dir),
                    str(Path(sys.executable).parent),
                    "/usr/bin",
                    "/bin",
                ]
            )
        env.update(
            {
                "PATH": path,
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "SELECTION_FAKE_TOOL_LOG": str(self.log),
                "ASH_MCP_ALLOWED_ROOTS": str(self.root),
                "PYTHONIOENCODING": "utf-8",
                **isolated_tool_env(self.root / "tool-env"),
            }
        )
        return env

    def run(self, steps: List[dict]) -> dict:
        completed = subprocess.run(
            [sys.executable, "-c", _PROGRAM, json.dumps({"steps": steps})],
            cwd=self.workdir,
            env=self._env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        for line in completed.stdout.splitlines():
            # Split rather than startswith: a progress display can leave a terminal
            # control sequence at the start of the line.
            if _REPORT_PREFIX in line:
                return json.loads(line.split(_REPORT_PREFIX, 1)[1])
        raise AssertionError(
            f"the probe printed no report (exit {completed.returncode}).\n"
            f"stdout tail:\n{completed.stdout[-3000:]}\n"
            f"stderr tail:\n{completed.stderr[-3000:]}"
        )

    def calls(self) -> List[dict]:
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def started_against(self, tree: Path) -> List[dict]:
        """Fake-tool calls that name ``tree`` or run inside it."""
        target = os.path.realpath(tree)
        hits = []
        for call in self.calls():
            cwd = os.path.realpath(call["cwd"])
            in_tree = cwd == target or cwd.startswith(target + os.sep)
            named = any(target in arg or str(tree) in arg for arg in call["argv"])
            if in_tree or named:
                hits.append(call)
        return hits


def _norm(name: str) -> str:
    return name.replace("-", "_").lower()


def _community(report: dict) -> set:
    """Scanners ``mcp_list_scanners()`` reported beyond the built-in set."""
    builtins = {_norm(name) for name in report["builtins"]}
    listed = {_norm(name) for names in report["lists"] for name in names}
    return listed - builtins


def _selected(scan: dict) -> set:
    assert scan["scanners"] is not None, f"the scan wrote no results: {scan}"
    return {_norm(name) for name in scan["scanners"]}


def _assert_lists_the_community_scanners(report: dict) -> set:
    community = _community(report)
    assert "snyk_code" in community, (
        "mcp_list_scanners() must keep reporting the community scanners ASH ships; "
        f"beyond the built-ins it reported {sorted(community)}"
    )
    return community


class TestListScannersDoesNotSelectScanners:
    def test_a_scan_after_list_scanners_selects_no_community_scanner(self, tmp_path):
        """list_scanners, then a default scan: no community scanner takes part."""
        seq = _Sequence(tmp_path)
        tree = _source(tmp_path, "tree")
        report = seq.run(
            [
                {"op": "list"},
                {
                    "op": "scan",
                    "source_dir": str(tree),
                    "output_dir": str(tmp_path / "out"),
                },
            ]
        )

        community = _assert_lists_the_community_scanners(report)
        selected = _selected(report["scans"][0])
        assert not selected & community, (
            f"listing made {sorted(selected & community)} part of a scan that named "
            "no plugin module"
        )
        assert seq.started_against(tree) == []

    def test_scan_then_list_then_scan_selects_no_community_scanner(self, tmp_path):
        """The other order: a scan, list_scanners, another scan. Neither scan has one."""
        seq = _Sequence(tmp_path)
        first = _source(tmp_path, "first")
        second = _source(tmp_path, "second")
        report = seq.run(
            [
                {
                    "op": "scan",
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                },
                {"op": "list"},
                {
                    "op": "scan",
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                },
            ]
        )

        community = _assert_lists_the_community_scanners(report)
        for scan in report["scans"]:
            assert not _selected(scan) & community, scan
        assert seq.started_against(first) == []
        assert seq.started_against(second) == []

    def test_an_mcp_scan_after_list_scanners_starts_no_community_tool(self, tmp_path):
        """The reported path end to end: the MCP list tool, then the MCP scan tool."""
        seq = _Sequence(tmp_path)
        tree = _source(tmp_path, "tree")
        report = seq.run(
            [
                {"op": "list"},
                {
                    "op": "mcp_scan",
                    "source_dir": str(tree),
                    "config": str(tmp_path / "operator.yaml"),
                },
            ]
        )

        community = _assert_lists_the_community_scanners(report)
        scan = report["scans"][0]
        assert scan["started"], scan
        assert not _selected(scan) & community, (
            f"an MCP scan ran {sorted(_selected(scan) & community)} after list_scanners"
        )
        assert seq.started_against(tree) == [], (
            "a community tool was started on the scanned tree: "
            f"{seq.started_against(tree)}"
        )

    def test_a_workspace_scan_after_list_scanners_selects_no_community_scanner(
        self, tmp_path
    ):
        """Workspace mode pre-warms the registry once; listing must not feed it."""
        seq = _Sequence(tmp_path)
        workspace = tmp_path / "ws"
        projects = [_source(workspace, key) for key in ("api", "web")]
        for project in projects:
            (project / ".ash").mkdir()
            (project / ".ash" / ".ash.yaml").write_text(
                f"project_name: {project.name}\n", encoding="utf-8"
            )
        workspace_file = workspace / "dev.code-workspace"
        workspace_file.write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )
        report = seq.run(
            [
                {"op": "list"},
                {
                    "op": "workspace_scan",
                    "workspace_file": str(workspace_file),
                    "output_dir": str(tmp_path / "out"),
                },
            ]
        )

        community = _assert_lists_the_community_scanners(report)
        selected = _selected(report["scans"][0])
        assert not selected & community, (
            f"a workspace scan ran {sorted(selected & community)} after list_scanners"
        )
        for project in projects:
            assert seq.started_against(project) == [], project.name


class TestSelectionFollowsTheScansOwnModules:
    def test_a_scan_does_not_inherit_a_module_an_earlier_scan_named(self, tmp_path):
        """A module one scan named stays out of the next scan, which names none."""
        seq = _Sequence(tmp_path)
        first = _source(tmp_path, "first")
        second = _source(tmp_path, "second")
        report = seq.run(
            [
                {
                    "op": "scan",
                    "source_dir": str(first),
                    "output_dir": str(tmp_path / "out1"),
                    "modules": [SNYK_MODULE],
                },
                {
                    "op": "scan",
                    "source_dir": str(second),
                    "output_dir": str(tmp_path / "out2"),
                },
                {"op": "list"},
            ]
        )

        _assert_lists_the_community_scanners(report)
        named, unnamed = report["scans"]
        assert "snyk_code" in _selected(named), named
        assert "snyk_code" not in _selected(unnamed), (
            "the second scan named no plugin module but ran snyk-code because an "
            "earlier scan in the same process had named its module"
        )
        assert seq.started_against(second) == []

    def test_a_module_named_for_the_scan_runs_its_scanner(self, tmp_path):
        """Control: naming the module for a scan still runs its scanner on that tree.

        Shows the recorder sees a real invocation, so the empty results above are
        not an artifact of a harness that cannot observe one.
        """
        seq = _Sequence(tmp_path)
        tree = _source(tmp_path, "tree")
        report = seq.run(
            [
                {
                    "op": "scan",
                    "source_dir": str(tree),
                    "output_dir": str(tmp_path / "out"),
                    "modules": [SNYK_MODULE],
                },
                {"op": "list"},
            ]
        )

        assert "snyk_code" in _selected(report["scans"][0])
        snyk_calls = [c for c in seq.started_against(tree) if c["tool"] == "snyk"]
        assert snyk_calls, f"snyk was never started on the tree: {seq.calls()}"
        assert snyk_calls[0]["argv"][:2] == ["code", "test"]
