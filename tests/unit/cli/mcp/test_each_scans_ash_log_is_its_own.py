# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each MCP scan's ash.log holds its own lines and no other scan's.

The MCP server runs scans in one process, and every scan's log handlers sit
on the one process-wide "ash" logger. Without a run scope, a finished scan's
ash.log keeps taking lines until the next scan's setup replaces its handlers,
so it ends holding the next scan's start; and a scan that sets up while
another runs takes the running scan's handlers off mid-run, so the last scan
to set up gets every scan's records and the earlier scan's log stops short.

Each cell runs the real MCP tools in one child interpreter per cell: one
process for both scans is the defect's shape. The controls assert that the
failing scan really reached its import refusal and that the concurrent pair
really overlapped, and raise RuntimeError rather than AssertionError, so only
the isolation assertions can fail a cell.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    install_stand_in_uv,
    reaching_the_stand_in,
    stand_in_env,
)
from tests.utils.tool_guard import CHILD_TRIVY_PROBE_STUBS

pytestmark = pytest.mark.integration

BROKEN = "zq8broken_ash_plugins"
DEPENDENCY = "zq8dep_pkg"
GOOD = "zq8good_ash_plugins"
#: A line the clean scan's scanner logs after its release, which the driver
#: writes once the other scan's setup has come and gone. One token: the driver
#: compares whitespace-flattened text.
LATE_MARKER = "zq8late_marker_line"
#: A line the driver logs after both sequential runs ended, outside any run:
#: with each finished run's handlers off the logger, it reaches neither log.
AFTER_MARKER = "zq8after_runs_marker"

BUILT_INS = (
    "bandit",
    "cdk-nag",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "grype",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
)

GOOD_SOURCE = textwrap.dedent(
    """
    import logging
    import os
    import time
    from typing import Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_scanner_plugin
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    EVENTS = []


    class Zq8GoodScannerConfig(ScannerPluginConfigBase):
        name: Literal["zq8good-scanner"] = "zq8good-scanner"


    @ash_scanner_plugin
    class Zq8GoodScanner(ScannerPluginBase[Zq8GoodScannerConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = Zq8GoodScannerConfig()
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
            self._pre_scan(target=target, target_type=target_type, config=config)
            EVENTS.append(("start", time.time()))
            # The driver writes the release once the choreography the mode needs
            # has happened; a sleep here lost to suite load. The sequential modes
            # pre-write it, so they never wait.
            sync = os.environ["ZQ8_SYNC"]
            open(os.path.join(sync, "good-started"), "w").close()
            deadline = time.monotonic() + 240
            while not os.path.exists(os.path.join(sync, "good-release")):
                if time.monotonic() > deadline:
                    raise RuntimeError("nobody released the clean scan's scanner")
                time.sleep(0.05)
            EVENTS.append(("end", time.time()))
            # After the release, so after any mid-run setup by the other scan:
            # this line belongs in this scan's ash.log and no other.
            logging.getLogger("ash").info("zq8late_marker_line")
            self._post_scan(target=target, target_type=target_type)
            return SarifReport.model_validate(
                {"version": "2.1.0",
                 "runs": [{"tool": {"driver": {"name": "zq8good-scanner"}},
                           "results": []}]}
            )
    """
)

DRIVER = reaching_the_stand_in(
    """
    import asyncio
    import json
    import sys
    import time
    from pathlib import Path

    layout = Path(sys.argv[2])
    mode = sys.argv[3]
    sys.path.insert(0, str(layout / "modules"))

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )


    def flat(text):
        return "".join(text.split()) if text is not None else None


    def report(answer):
        entry = get_scan_registry().get_scan(answer["scan_id"]) if answer.get("scan_id") else None
        out = Path(entry.output_directory) if entry is not None else None
        path = out / "ash.log" if out is not None else None
        log_text = (
            path.read_text(encoding="utf-8", errors="replace")
            if path is not None and path.is_file()
            else None
        )
        return {
            "scan_id": answer.get("scan_id"),
            "log_text": flat(log_text),
            "start_success": answer.get("success"),
            "status": entry.status.value if entry is not None else None,
            "exit_code": entry.exit_code if entry is not None else None,
            "error": entry.error_message if entry is not None else answer.get("error"),
            "start_time": entry.start_time.timestamp() if entry is not None else None,
            "end_time": entry.end_time.timestamp() if entry is not None and entry.end_time else None,
        }


    async def start(target, config, session):
        return await mcp_tools.mcp_scan_directory(
            directory_path=str(layout / "allowed" / target),
            config_path=str(layout / "configs" / config),
            session_id=session,
        )


    # The shared helper, loaded by path: the child runs with -I and the
    # checkout's tests directory is not a regular package.
    import importlib.util
    import automated_security_helper as _ash_pkg

    _tasks_spec = importlib.util.spec_from_file_location(
        "ash_tests_tasks",
        Path(_ash_pkg.__file__).resolve().parents[1] / "tests" / "utils" / "tasks.py",
    )
    _tasks = importlib.util.module_from_spec(_tasks_spec)
    _tasks_spec.loader.exec_module(_tasks)


    async def drain():
        # An exception or a cancellation that escapes a scan task fails the
        # driver, which the test reads as a failed child.
        await _tasks.drain_clean(tasks=list(mcp_tools._scan_tasks))


    async def main():
        result = {}
        sync = layout / "sync"

        async def arrived(name):
            deadline = time.monotonic() + 240
            while not (sync / name).exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("the clean scan's scanner never started")
                await asyncio.sleep(0.05)

        async def ended(answer):
            deadline = time.monotonic() + 240
            while True:
                entry = (
                    get_scan_registry().get_scan(answer["scan_id"])
                    if answer.get("scan_id")
                    else None
                )
                if entry is not None and entry.end_time is not None:
                    return
                if time.monotonic() > deadline:
                    raise RuntimeError("the failing scan never ended")
                await asyncio.sleep(0.05)

        if mode == "clean_after":
            import logging

            # Sequential runs: neither barrier has an ordering to hold.
            (sync / "good-release").touch()
            (sync / "broken-gate").touch()
            first = await start("t1", "broken.yaml", "s1")
            await drain()
            result["first"] = report(first)
            second = await start("t2", "clean.yaml", "s2")
            await drain()
            # Logged after both runs ended, outside any run: a finished run's
            # handlers are off the logger, so this reaches neither ash.log.
            logging.getLogger("ash").info("zq8after_runs_marker")
            result["second"] = report(second)
            # The first scan's surfaces again, read after the second scan ended.
            result["first_after"] = report(first)
        else:
            if mode == "concurrent_clean_first":
                # The failing scan starts only once the clean scan's scanner
                # runs, and the scanner is released only once the failing scan
                # ended: the failing scan's whole run sits inside the scanner's.
                (sync / "broken-gate").touch()
                clean = await start("t2", "clean.yaml", "s2")
                await arrived("good-started")
                failing = await start("t1", "broken.yaml", "s1")
                await ended(failing)
                (sync / "good-release").touch()
            else:
                # The failing scan starts first, and its refusal waits on the
                # gate, written only after the clean scan registered: the
                # failing scan ends after the clean one started.
                (sync / "good-release").touch()
                failing = await start("t1", "broken.yaml", "s1")
                clean = await start("t2", "clean.yaml", "s2")
                (sync / "broken-gate").touch()
            await drain()
            import zq8good_ash_plugins

            result["first"] = report(failing)
            result["second"] = report(clean)
            result["good_events"] = list(zq8good_ash_plugins.EVENTS)
        print(json.dumps(result))


    asyncio.run(main())
    """
)


@pytest.fixture
def layout(tmp_path) -> Path:
    modules = tmp_path / "modules"
    (modules / BROKEN).mkdir(parents=True)
    # The import refusal waits for the driver's gate, so a mode that needs the
    # failing scan to end after some other step can hold it open; the modes
    # with no such need write the gate before any scan starts.
    (modules / BROKEN / "__init__.py").write_text(
        "import os as _os\n"
        "import time as _time\n"
        "_gate = _os.path.join(_os.environ['ZQ8_SYNC'], 'broken-gate')\n"
        "_deadline = _time.monotonic() + 240\n"
        "while not _os.path.exists(_gate) and _time.monotonic() < _deadline:\n"
        "    _time.sleep(0.05)\n"
        "import %s  # noqa: F401\n"
        "ASH_REPORTERS = []\n" % DEPENDENCY,
        encoding="utf-8",
    )
    (modules / GOOD).mkdir()
    (modules / GOOD / "__init__.py").write_text(GOOD_SOURCE, encoding="utf-8")
    for target in ("t1", "t2"):
        (tmp_path / "allowed" / target).mkdir(parents=True)
        (tmp_path / "allowed" / target / "app.py").write_text(
            "x = 1\n", encoding="utf-8"
        )
    configs = tmp_path / "configs"
    configs.mkdir()
    disabled = "".join("  %s:\n    enabled: false\n" % name for name in BUILT_INS)
    scanners = "scanners:\n%s  zq8good-scanner:\n    enabled: true\n" % disabled
    (configs / "broken.yaml").write_text(
        "project_name: demo\nash_plugin_modules:\n  - %s\n  - %s\n%s"
        % (GOOD, BROKEN, scanners),
        encoding="utf-8",
    )
    (configs / "clean.yaml").write_text(
        "project_name: demo\nash_plugin_modules:\n  - %s\n"
        "fail_on_incomplete_scanners: true\n%s" % (GOOD, scanners),
        encoding="utf-8",
    )
    (tmp_path / "workspaces").mkdir()
    return tmp_path


def _run(layout: Path, mode: str) -> dict:
    (layout / "sync").mkdir(exist_ok=True)
    bin_dir, log = install_stand_in_uv(layout / "uv-stand-in")
    env = stand_in_env(bin_dir, log, dict(os.environ))
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_MCP_TRANSPORT"):
        env.pop(name, None)
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "250",
            "ASH_MCP_ALLOWED_ROOTS": str(layout / "allowed"),
            "ASH_MCP_ALLOWED_CONFIG_ROOTS": str(layout / "configs"),
            "ASH_MCP_WORKSPACE_ROOT": str(layout / "workspaces"),
            "ZQ8_SYNC": str(layout / "sync"),
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            # The child keeps the stand-in uv (its subject); only trivy's probes are
            # answered, because the trivy scanner read its database's age with a
            # real `trivy version`, which reached the parent's guard stand-in.
            importing_this_checkout(CHILD_TRIVY_PROBE_STUBS + DRIVER),
            str(layout / "modules"),
            str(layout),
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        cwd=layout,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _refused(first: dict, name: str) -> None:
    """Control: the failing scan reached the import refusal (exit 3, its text).
    Raises RuntimeError, so only the isolation assertions can fail a cell."""
    held = (
        first["status"] == "failed"
        and first["exit_code"] == 3
        and "failed to import" in (first["error"] or "")
        and name in (first["error"] or "")
    )
    if not held:
        raise RuntimeError("control: the failing scan did not refuse: %r" % first)


def _overlapped(outcome: dict, mode: str) -> None:
    """Control: the two scans really overlapped."""
    events = dict(outcome["good_events"])
    if mode == "concurrent_clean_first":
        # The failing scan ended while the clean scan's scanner ran.
        held = events["start"] < outcome["first"]["end_time"] < events["end"]
    else:
        # The clean scan had started before the failing one ended.
        held = outcome["second"]["start_time"] < outcome["first"]["end_time"]
    if not held:
        raise RuntimeError("control: the scans did not overlap: %r" % outcome)


def _logs_are_their_own(outcome: dict) -> None:
    """The isolation assertions: each scan's ash.log holds its own scan id, and
    neither holds the other scan's id or the failing module's name."""
    first, second = outcome["first"], outcome["second"]
    if not (
        first["log_text"]
        and second["log_text"]
        and first["scan_id"]
        and second["scan_id"]
    ):
        raise RuntimeError(
            "control: a scan wrote no ash.log or has no id: %r" % outcome
        )
    assert first["scan_id"] in first["log_text"], "failing scan's log lacks its own id"
    assert second["scan_id"] in second["log_text"], "clean scan's log lacks its own id"
    assert second["scan_id"] not in first["log_text"], (
        "failing scan's log holds the clean scan's lines"
    )
    assert first["scan_id"] not in second["log_text"], (
        "clean scan's log holds the failing scan's lines"
    )
    assert BROKEN not in second["log_text"], "clean scan's log names the failing module"


def test_a_finished_scans_ash_log_takes_no_later_scans_lines(layout):
    outcome = _run(layout, "clean_after")
    _refused(outcome["first"], BROKEN)
    _logs_are_their_own({"first": outcome["first_after"], "second": outcome["second"]})
    # A line logged after both runs ended belongs to neither: a finished run's
    # handlers came off the logger with it, not merely stopped matching.
    for scan in (outcome["first_after"], outcome["second"]):
        assert AFTER_MARKER not in scan["log_text"], (
            "a finished scan's ash.log took a line logged after every run ended"
        )


@pytest.mark.parametrize("mode", ["concurrent_clean_first", "concurrent_broken_first"])
def test_each_concurrent_scans_ash_log_holds_only_its_own_lines(layout, mode):
    outcome = _run(layout, mode)
    _refused(outcome["first"], BROKEN)
    _overlapped(outcome, mode)
    _logs_are_their_own(outcome)


def test_a_scan_keeps_its_log_for_its_whole_run_through_anothers_setup(layout):
    """The clean scan's scanner logs a line after its release, so after the
    failing scan has set up and finished in the middle of the clean scan's run.
    The line belongs to the clean scan's ash.log: a setup that takes a running
    scan's handlers off leaves the rest of its run unlogged."""
    outcome = _run(layout, "concurrent_clean_first")
    _refused(outcome["first"], BROKEN)
    _overlapped(outcome, "concurrent_clean_first")
    clean, failing = outcome["second"], outcome["first"]
    if not (clean["log_text"] and failing["log_text"]):
        raise RuntimeError("control: a scan wrote no ash.log: %r" % outcome)
    assert LATE_MARKER in clean["log_text"], (
        "the clean scan's log lost the lines after the other scan's setup"
    )
    assert LATE_MARKER not in failing["log_text"], (
        "the failing scan's log holds the clean scan's lines"
    )
