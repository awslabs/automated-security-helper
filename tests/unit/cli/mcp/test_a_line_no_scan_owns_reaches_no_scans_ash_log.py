# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A line no MCP scan owns reaches no scan's ash.log, and is not lost.

The MCP server runs scans in one process, each inside a run log scope of its
own (utils/log.py). A line logged from a thread that did not carry a scan's
context belongs to no scan: the server cannot tell whose it is, so while the
server runs any scan it goes to the handlers that belong to no run (the
server's own log) and, when there are none, to the server's last resort on
stderr, never into a session's ash.log. A thread ASH or a plugin starts
through ash_thread carries the context, so its lines are its scan's own.

A run that is the process's only run, a CLI scan, has nobody else's lines to
keep out: such a line reaches its handlers as it always did.

Each cell runs the real MCP tools in one child interpreter per mode. The
controls raise RuntimeError rather than AssertionError, so only the routing
assertions can fail a cell.
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

#: Every built-in scanner, disabled in the test configs so each scan runs only
#: its own zq9 scanner: a built-in left enabled whose tool is absent (gitleaks,
#: trivy) is MISSING, and run_ash_scan ends the scan "incomplete", which the
#: controls below read as a scan that did not complete.
BUILT_INS = (
    "actionlint",
    "bandit",
    "cdk-nag",
    "cfn-guard",
    "cfn-lint",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "gitleaks",
    "grype",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
    "trivy",
    "zizmor",
)

SCANNER_SOURCE = textwrap.dedent(
    """
    import threading
    import time
    import os
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    from typing import Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_scanner_plugin
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils import log as ash_log
    from automated_security_helper.utils.log import ASH_LOGGER

    EVENTS = []


    def warn(kind):
        ASH_LOGGER.warning("zq9NAME_TOKEN-" + kind + "-marker")


    def await_file(path):
        deadline = time.monotonic() + 240
        while not path.exists():
            if time.monotonic() > deadline:
                raise RuntimeError("nobody wrote %s" % path)
            time.sleep(0.05)


    class Zq9NAME_TOKENConfig(ScannerPluginConfigBase):
        name: Literal["zq9NAME_TOKEN-scanner"] = "zq9NAME_TOKEN-scanner"


    @ash_scanner_plugin
    class Zq9NAME_TOKENScanner(ScannerPluginBase[Zq9NAME_TOKENConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = Zq9NAME_TOKENConfig()
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
            self._pre_scan(target=target, target_type=target_type, config=config)
            sync = Path(os.environ["ZQ9_SYNC"])
            # A floor on the whole run, so the executor's heartbeat beats some
            # times while the scan runs; it holds nothing in order, so it can
            # never make the choreography miss.
            floor = time.time() + float(os.environ.get("ZQ9_MIN_RUN", "0"))
            EVENTS.append(("start", time.time(), ash_log._RUN_LOG_SCOPE.get()))
            (sync / "NAME_TOKEN-started").touch()
            # The release comes once every scan the mode runs beside this one
            # has started, so every line below is logged while all of them run;
            # a sleep in place of this wait lost to suite load.
            await_file(sync / "release")
            warn("direct")
            raw = threading.Thread(target=warn, args=("rawthread",))
            raw.start()
            raw.join()
            with ThreadPoolExecutor(1) as pool:
                pool.submit(warn, "plainpool").result()
            try:
                from automated_security_helper.utils.log import ash_thread
            except ImportError:
                ash_thread = None
            if ash_thread is not None:
                helper = ash_thread(warn, args=("helperthread",))
                helper.start()
                helper.join()
            (sync / "NAME_TOKEN-logged").touch()
            # The finish comes once every such scan has logged its lines, so
            # each scan's handlers are still up while the others log.
            await_file(sync / "finish")
            while time.time() < floor:
                time.sleep(0.05)
            EVENTS.append(("end", time.time(), None))
            self._post_scan(target=target, target_type=target_type)
            return SarifReport.model_validate(
                {"version": "2.1.0",
                 "runs": [{"tool": {"driver": {"name": "zq9NAME_TOKEN-scanner"}},
                           "results": []}]}
            )
    """
)

DRIVER = reaching_the_stand_in(
    """
    import asyncio
    import json
    import logging
    import sys
    import threading
    import time
    from pathlib import Path

    layout = Path(sys.argv[2])
    mode = sys.argv[3]
    sys.path.insert(0, str(layout / "modules"))

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.utils import log as ash_log

    # Short enough that each scan's scanner beats while both scans run.
    scanner_executor.SCANNER_HEARTBEAT_INTERVAL_SECONDS = 0.3


    def handler_state():
        logger = logging.getLogger("ash")
        return {
            "scoped": [getattr(h, "_ash_run_log_scope", None) for h in logger.handlers
                       if getattr(h, "_ash_run_log_scope", None) is not None],
            "active": sorted(ash_log._ACTIVE_RUN_LOG_SCOPES),
        }


    def report(answer):
        entry = get_scan_registry().get_scan(answer["scan_id"]) if answer.get("scan_id") else None
        out = Path(entry.output_directory) if entry is not None else None
        path = out / "ash.log" if out is not None else None
        return {
            "log": path.read_text(encoding="utf-8", errors="replace")
            if path is not None and path.is_file() else None,
            "status": entry.status.value if entry is not None else None,
            "error": entry.error_message if entry is not None else answer.get("error"),
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
        sync = layout / ("sync-" + mode)

        async def arrived(*names):
            deadline = time.monotonic() + 240
            while not all((sync / name).exists() for name in names):
                if time.monotonic() > deadline:
                    raise RuntimeError(("a scanner never reached", names))
                await asyncio.sleep(0.05)

        if mode in ("pair", "pair_server_log"):
            if mode == "pair_server_log":
                # The server's own log: a handler on "ash" that belongs to no run,
                # as an operator or an embedding process adds one.
                server_log = logging.FileHandler(str(layout / "server.log"), encoding="utf-8")
                server_log.setLevel(logging.INFO)
                logging.getLogger("ash").addHandler(server_log)
            a = await start("t1", "alpha.yaml", "s1")
            b = await start("t2", "beta.yaml", "s2")
            await arrived("alpha-started", "beta-started")
            (sync / "release").touch()
            await arrived("alpha-logged", "beta-logged")
            (sync / "finish").touch()
            await drain()
            result = {"a": report(a), "b": report(b), "after": handler_state()}
            if mode == "pair_server_log":
                server_log.close()
                result["server_log"] = (layout / "server.log").read_text(encoding="utf-8")
        elif mode == "cli":
            from automated_security_helper.utils.log import ASH_LOGGER, get_logger, run_log_scope

            out = layout / "cli-out"
            out.mkdir()
            with run_log_scope():
                get_logger(level=logging.INFO, output_dir=out, show_progress=False, use_color=False)
                inside = handler_state()
                raw = threading.Thread(target=ASH_LOGGER.warning, args=("zq9cli-rawthread-marker",))
                raw.start()
                raw.join()
                ASH_LOGGER.warning("zq9cli-inside-marker")
            result = {"inside": inside, "after": handler_state(),
                      "log": (out / "ash.log").read_text(encoding="utf-8")}
        elif mode == "workspace":
            from automated_security_helper.cli.mcp import workspace as workspace_module
            from automated_security_helper.utils.log import ASH_LOGGER

            real = workspace_module.execute_workspace
            seen = {}

            def recording(*args, **kwargs):
                scope = ash_log._RUN_LOG_SCOPE.get()
                seen.update({"scope": scope, "time": time.time(),
                             "active": scope in ash_log._ACTIVE_RUN_LOG_SCOPES})
                ASH_LOGGER.warning("zq9workspace-own-marker")
                return real(*args, **kwargs)

            workspace_module.execute_workspace = recording
            a = await start("t1", "alpha.yaml", "s1")
            # The workspace scan runs only once the directory scan's scanner
            # does, and that scanner is released only afterwards: the workspace
            # scan's whole run sits inside the directory scan's.
            await arrived("alpha-started")
            answer = await workspace_module.mcp_scan_workspace(
                workspace_file=str(layout / "allowed" / "ws" / "dev.code-workspace"),
                output_dir=str(layout / "allowed" / "ws" / "out"),
            )
            (sync / "release").touch()
            (sync / "finish").touch()
            await drain()
            result = {"a": report(a), "seen": seen, "answered": "success" in answer,
                      "after": handler_state()}
        # Imported after the scans, which loaded them as their plugin modules.
        import zq9alpha_ash_plugins
        import zq9beta_ash_plugins

        result["alpha_events"] = list(zq9alpha_ash_plugins.EVENTS)
        result["beta_events"] = list(zq9beta_ash_plugins.EVENTS)
        print(json.dumps(result))


    asyncio.run(main())
    """
)

_OUTCOMES: dict = {}


@pytest.fixture(scope="module")
def layout(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("noscope")
    modules = root / "modules"
    for name in ("alpha", "beta"):
        package = modules / ("zq9%s_ash_plugins" % name)
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(
            SCANNER_SOURCE.replace("NAME_TOKEN", name), encoding="utf-8"
        )
    for target in ("t1", "t2"):
        (root / "allowed" / target).mkdir(parents=True)
        (root / "allowed" / target / "app.py").write_text("x = 1\n", encoding="utf-8")
    disabled = "".join("  %s:\n    enabled: false\n" % name for name in BUILT_INS)
    configs = root / "configs"
    configs.mkdir()
    for name in ("alpha", "beta"):
        (configs / ("%s.yaml" % name)).write_text(
            "project_name: demo\nash_plugin_modules:\n  - zq9%s_ash_plugins\n"
            "scanners:\n%s  zq9%s-scanner:\n    enabled: true\n"
            % (name, disabled, name),
            encoding="utf-8",
        )
    # A one-project workspace whose project runs no scanner.
    workspace = root / "allowed" / "ws"
    (workspace / "api" / ".ash").mkdir(parents=True)
    (workspace / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "api" / ".ash" / ".ash.yaml").write_text(
        "project_name: api\nscanners:\n%s" % disabled, encoding="utf-8"
    )
    (workspace / "dev.code-workspace").write_text(
        '{"folders": [{"path": "api"}]}', encoding="utf-8"
    )
    (root / "workspaces").mkdir()
    return root


def _outcome(layout: Path, mode: str) -> dict:
    """The child's result and its stderr, for *mode*; one child per mode."""
    if mode in _OUTCOMES:
        return _OUTCOMES[mode]
    (layout / ("sync-" + mode)).mkdir(exist_ok=True)
    bin_dir, log = install_stand_in_uv(layout / ("uv-stand-in-" + mode))
    env = stand_in_env(bin_dir, log, dict(os.environ))
    for name in (
        "ASH_PLUGIN_MODULES",
        "ASH_CONFIG",
        "ASH_MCP_TRANSPORT",
        "ASH_LOG_TO_STDERR",
    ):
        env.pop(name, None)
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "250",
            "ASH_MCP_ALLOWED_ROOTS": str(layout / "allowed"),
            "ASH_MCP_ALLOWED_CONFIG_ROOTS": os.pathsep.join(
                [str(layout / "configs"), str(layout / "allowed" / "ws")]
            ),
            "ASH_MCP_WORKSPACE_ROOT": str(layout / "workspaces"),
            "ZQ9_SYNC": str(layout / ("sync-" + mode)),
            "ZQ9_MIN_RUN": "2.0",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
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
    if completed.returncode != 0:
        raise RuntimeError(
            (
                "control: the driver failed",
                mode,
                completed.returncode,
                completed.stderr[-4000:],
            )
        )
    lines = completed.stdout.strip().splitlines()
    outcome = {
        "result": json.loads(lines[-1]),
        # What the scans' console handlers printed: the driver's stdout before
        # its result line.
        "stdout": "\n".join(lines[:-1]),
        "stderr": completed.stderr,
    }
    _OUTCOMES[mode] = outcome
    return outcome


def _overlapping_logs(outcome: dict) -> tuple:
    """Control: both scans completed with an ash.log, and their scanners' waits
    overlapped, so every line was logged while both scans ran."""
    result = outcome["result"]
    a, b = result["a"], result["b"]
    if (
        not (a["log"] and b["log"])
        or a["status"] != "completed"
        or b["status"] != "completed"
    ):
        raise RuntimeError(("control: a scan did not complete with an ash.log", a, b))
    alpha = {e[0]: e[1] for e in result["alpha_events"]}
    beta = {e[0]: e[1] for e in result["beta_events"]}
    if not (alpha["start"] < beta["end"] and beta["start"] < alpha["end"]):
        raise RuntimeError(("control: the scans did not overlap", alpha, beta))
    if (
        "zq9alpha-direct-marker" not in a["log"]
        or "zq9beta-direct-marker" not in b["log"]
    ):
        raise RuntimeError("control: a scan's own scanner line is not in its ash.log")
    return a["log"], b["log"]


def _no_run_left(result: dict) -> None:
    assert result["after"] == {"scoped": [], "active": []}, result["after"]


@pytest.mark.parametrize("kind", ["rawthread", "plainpool"])
def test_a_line_from_a_thread_without_the_scans_context_reaches_no_scans_log(
    layout, kind
):
    """Both scans' scanners log from a thread that did not copy the context:
    the line belongs to no scan, so neither ash.log takes it, the other
    session's least of all."""
    log_a, log_b = _overlapping_logs(_outcome(layout, "pair"))
    for name in ("alpha", "beta"):
        line = "zq9%s-%s-marker" % (name, kind)
        assert line not in log_a, (line, "alpha's ash.log took a line no scan owns")
        assert line not in log_b, (line, "beta's ash.log took a line no scan owns")


@pytest.mark.parametrize("kind", ["rawthread", "plainpool"])
def test_with_no_server_log_a_line_no_scan_owns_reaches_the_last_resort(layout, kind):
    """A stock MCP server adds no handler of its own to "ash": a line no scan
    owns is not lost, it goes to the server's last resort on stderr, as such a
    line does when no scan runs."""
    outcome = _outcome(layout, "pair")
    _overlapping_logs(outcome)
    for name in ("alpha", "beta"):
        line = "zq9%s-%s-marker" % (name, kind)
        assert line in outcome["stderr"], (
            line,
            "the line reached no handler",
            outcome["stderr"][-2000:],
        )


@pytest.mark.parametrize("kind", ["rawthread", "plainpool"])
def test_the_server_log_takes_a_line_no_scan_owns(layout, kind):
    """With a handler of the server's own on "ash", that handler takes the line,
    and still neither scan's ash.log does."""
    outcome = _outcome(layout, "pair_server_log")
    log_a, log_b = _overlapping_logs(outcome)
    server_log = outcome["result"]["server_log"]
    if "zq9alpha-direct-marker" not in server_log:
        raise RuntimeError("control: the server's handler took no line at all")
    for name in ("alpha", "beta"):
        line = "zq9%s-%s-marker" % (name, kind)
        assert line in server_log, (line, "the server's own log lacks the line")
        assert line not in log_a and line not in log_b, (
            line,
            "a scan's ash.log took it",
        )


def test_a_thread_started_with_ash_thread_logs_into_its_own_scans_log(layout):
    log_a, log_b = _overlapping_logs(_outcome(layout, "pair"))
    assert "zq9alpha-helperthread-marker" in log_a, (
        "alpha's log lacks its own thread's line"
    )
    assert "zq9beta-helperthread-marker" in log_b, (
        "beta's log lacks its own thread's line"
    )
    assert "zq9beta-helperthread-marker" not in log_a, "alpha's log holds beta's line"
    assert "zq9alpha-helperthread-marker" not in log_b, "beta's log holds alpha's line"


def test_a_scanners_heartbeat_lands_only_in_its_own_scans_log(layout):
    """ASH's own heartbeat thread is a scanner's, so its "still running" lines
    are its scan's."""
    log_a, log_b = _overlapping_logs(_outcome(layout, "pair"))
    assert "zq9alpha-scanner still running" in log_a, (
        "alpha's log lacks its own heartbeat"
    )
    assert "zq9beta-scanner still running" in log_b, (
        "beta's log lacks its own heartbeat"
    )
    assert "zq9beta-scanner still running" not in log_a, (
        "alpha's log holds beta's heartbeat"
    )
    assert "zq9alpha-scanner still running" not in log_b, (
        "beta's log holds alpha's heartbeat"
    )


def test_no_run_scope_outlives_the_two_scans(layout):
    outcome = _outcome(layout, "pair")
    _overlapping_logs(outcome)
    _no_run_left(outcome["result"])


def test_a_cli_runs_handlers_take_a_line_from_a_thread_without_its_context(layout):
    """The CLI's scan is the process's only run: a line from a thread that did
    not copy the context is that run's, and reaches its ash.log and console as
    it always did."""
    outcome = _outcome(layout, "cli")
    result = outcome["result"]
    if not result["inside"]["scoped"]:
        raise RuntimeError(
            ("control: get_logger added no handler of the run's", result["inside"])
        )
    if (
        "zq9cli-inside-marker" not in result["log"]
        or "zq9cli-inside-marker" not in outcome["stdout"]
    ):
        raise RuntimeError(
            "control: the run's own line is not in its ash.log and console"
        )
    assert "zq9cli-rawthread-marker" in result["log"], result["log"][-2000:]
    assert "zq9cli-rawthread-marker" in outcome["stdout"], outcome["stdout"][-2000:]
    _no_run_left(result)


def _workspace(layout: Path) -> dict:
    outcome = _outcome(layout, "workspace")
    result = outcome["result"]
    a, seen = result["a"], result["seen"]
    if not a["log"] or a["status"] != "completed":
        raise RuntimeError(
            ("control: the directory scan did not complete with an ash.log", a)
        )
    if not seen or not result["answered"]:
        raise RuntimeError(
            ("control: the workspace scan did not run", seen, result["answered"])
        )
    alpha = {e[0]: e[1] for e in result["alpha_events"]}
    if not alpha["start"] < seen["time"] < alpha["end"]:
        raise RuntimeError(
            ("control: the workspace scan ran outside the other scan", alpha, seen)
        )
    return outcome


def test_an_mcp_workspace_scan_runs_in_a_log_scope_of_its_own(layout):
    outcome = _workspace(layout)
    result = outcome["result"]
    seen = result["seen"]
    alpha_scope = next(e[2] for e in result["alpha_events"] if e[0] == "start")
    assert seen["scope"] is not None, "the workspace scan runs in no log scope"
    assert seen["active"], "the workspace scan's log scope is not an open one"
    assert seen["scope"] != alpha_scope, (
        "the workspace scan shares the other scan's scope"
    )
    _no_run_left(result)


def test_a_workspace_scans_line_reaches_no_concurrent_scans_log(layout):
    outcome = _workspace(layout)
    log_a = outcome["result"]["a"]["log"]
    assert "zq9workspace-own-marker" not in log_a, (
        "the directory scan's ash.log took the workspace's line"
    )
    # Not lost: the workspace scan has no ash.log of its own, so its line goes
    # where the server's own lines go.
    assert "zq9workspace-own-marker" in outcome["stderr"], outcome["stderr"][-2000:]
