# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the MCP server hosts leaves the server's last-resort gate where its start put it.

The gate is process-wide, and the MCP server sets it once, at its start, from its
log-level option. Every hosted scan then runs inside that process: the server's
lifespan, its ``run_ash_scan`` tool, the scan tool it calls, the scan runner's
logger setup and ``get_logger`` with the options a hosted scan passes (color on,
progress off). A gate write anywhere on that path moves the server's gate for
every later line, for every session.

The cell drives the server object itself through the SDK's in-memory client, in
one child process with no server spawn: it sets the gate to ERROR as
``ash mcp --log-level error`` does, runs one hosted scan through the
``run_ash_scan`` tool, and reads the gate after the scan and again after the
session ends. A homeless INFO line logged last must not reach stderr. The scan
runs one plugin scanner that spawns nothing and returns no findings, with every
built-in scanner disabled, a stand-in uv first on PATH and the network off.

Pinned this way: a gate write in the server's lifespan or tool wrapper, in the
scan runner's logger setup, or in ``get_logger`` on any branch a hosted scan
takes (its color branch included). The in-process cells in
tests/unit/utils/test_the_last_resort_takes_what_the_logger_allows.py pin
``get_logger`` and the gate on their own; this one pins the hosted path through
them.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    install_stand_in_uv,
    reaching_the_stand_in,
    stand_in_env,
)

_PLUGIN_PACKAGE = "hosted_scan_probe_ash_plugins"
_MARKER = "hosted-scan-gate-marker-after-the-scan"

_PLUGIN_SOURCE = '''\
import os
from pathlib import Path
from typing import Any, Literal

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class GateProbeScannerConfigOptions(ScannerOptionsBase):
    pass


class GateProbeScannerConfig(ScannerPluginConfigBase):
    name: Literal["gate-probe"] = "gate-probe"
    enabled: bool = True
    options: GateProbeScannerConfigOptions = GateProbeScannerConfigOptions()


@ash_scanner_plugin
class GateProbeScanner(ScannerPluginBase[GateProbeScannerConfig]):
    """A scanner that runs nothing and finds nothing, and records each call in
    the file GATE_PROBE_RAN names: the one mark only a scan that reached its
    scanners can leave."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = GateProbeScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        raise NotImplementedError("scan() is overridden")

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Any = None,
        *args,
        **kwargs,
    ) -> dict:
        self._pre_scan(target, target_type, config)
        with open(os.environ["GATE_PROBE_RAN"], "a", encoding="utf-8") as ran:
            ran.write(f"{target_type}\\n")
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [GateProbeScanner]
'''

_DRIVER = reaching_the_stand_in(
    f"""
    import asyncio
    import json
    import sys
    import threading
    from pathlib import Path

    layout = Path(sys.argv[2])
    sys.path.insert(0, str(layout / "modules"))

    from automated_security_helper.utils import log as ash_log
    from automated_security_helper.utils.log import (
        ASH_LOGGER,
        configure_last_resort_level,
    )

    # As the server's start sets it for `ash mcp --log-level error`.
    configure_last_resort_level("ERROR")

    from mcp import Client

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

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp_server import mcp
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )


    def homeless(marker):
        # A thread with no run scope: no scan's handler takes the line.
        thread = threading.Thread(target=ASH_LOGGER.info, args=(marker,))
        thread.start()
        thread.join()
        sys.stderr.flush()


    async def main():
        out = {{"gate_at_start": ash_log._LAST_RESORT.level}}
        async with Client(mcp, raise_exceptions=True) as client:
            started = await client.call_tool(
                "run_ash_scan",
                {{
                    "source_dir": str(layout / "allowed" / "target"),
                    "config_path": str(layout / "configs" / "plugin-only.yaml"),
                }},
            )
            payload = started.structured_content["result"]
            out["started"] = bool(payload.get("success"))
            # A refused start names its refusal in the control's message.
            out["error"] = payload.get("error")
            out["error_type"] = payload.get("error_type")
            # An exception or a cancellation that escapes a scan task fails the
            # driver, which the test reads as a failed child.
            await _tasks.drain_clean(tasks=list(mcp_tools._scan_tasks))
            scan_id = payload.get("scan_id")
            entry = get_scan_registry().get_scan(scan_id) if scan_id else None
            out["status"] = entry.status.value if entry is not None else None
            out["gate_after_scan"] = ash_log._LAST_RESORT.level
        out["gate_after_session"] = ash_log._LAST_RESORT.level
        homeless({_MARKER!r})
        print(json.dumps(out))


    asyncio.run(main())
    """
)


def _built_in_scanner_names() -> list:
    """Every built-in scanner's config name, as the server's resources name them
    (cli/mcp_server.py, _builtin_scanner_lines), so a scanner added to
    ash_builtin is disabled here without this file changing."""
    from automated_security_helper.core.scanner_inventory import (
        _declared_config_class,
        _scanner_name_from_class,
    )
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    names = []
    for scanner_class in ASH_SCANNERS:
        config_class = _declared_config_class(scanner_class)
        name = (
            getattr(config_class(), "name", None) if config_class is not None else None
        ) or _scanner_name_from_class(scanner_class)
        names.append(name)
    return names


def _layout(root: Path) -> Path:
    package = root / "modules" / _PLUGIN_PACKAGE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_PLUGIN_SOURCE, encoding="utf-8")
    target = root / "allowed" / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    built_ins = _built_in_scanner_names()
    if "bandit" not in built_ins:
        raise RuntimeError(("control: the built-in scanner names", built_ins))
    disabled = "".join(f"  {name}:\n    enabled: false\n" for name in built_ins)
    (root / "configs").mkdir()
    (root / "configs" / "plugin-only.yaml").write_text(
        f"project_name: hosted-gate\nash_plugin_modules:\n  - {_PLUGIN_PACKAGE}\n"
        f"scanners:\n{disabled}  gate-probe:\n    enabled: true\n",
        encoding="utf-8",
    )
    (root / "workspaces").mkdir()
    return root


def test_a_hosted_scan_through_the_servers_tool_leaves_its_gate(tmp_path):
    layout = _layout(tmp_path / "layout")
    ran = tmp_path / "gate-probe-ran.txt"
    bin_dir, log = install_stand_in_uv(tmp_path / "uv-stand-in")
    env = stand_in_env(bin_dir, log, dict(os.environ))
    for name in (
        "ASH_PLUGIN_MODULES",
        "ASH_CONFIG",
        "ASH_MCP_TRANSPORT",
        "ASH_LOG_TO_STDERR",
        "ASH_LOG_LEVEL",
    ):
        env.pop(name, None)
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "250",
            "ASH_MCP_ALLOWED_ROOTS": str(layout / "allowed"),
            "ASH_MCP_ALLOWED_CONFIG_ROOTS": str(layout / "configs"),
            "ASH_MCP_WORKSPACE_ROOT": str(layout / "workspaces"),
            "GATE_PROBE_RAN": str(ran),
        }
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(_DRIVER),
            str(layout / "modules"),
            str(layout),
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
                completed.returncode,
                completed.stderr[-4000:],
            )
        )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    if result.get("gate_at_start") != logging.ERROR:
        raise RuntimeError(("control: the gate did not start at ERROR", result))
    if not result.get("started"):
        raise RuntimeError(("control: the tool did not start the scan", result))
    if result.get("status") not in ("completed", "incomplete"):
        # The runner's logger setup runs only for a scan that got under way.
        raise RuntimeError(
            ("control: the hosted scan did not run", result, completed.stderr[-3000:])
        )
    # The status alone cannot tell a scan from none: a runner that returns
    # before its scanners still ends "completed". Only a scan that reached the
    # scanners leaves the probe's mark, so a gate write past an early return in
    # the runner cannot hide behind a scan that never ran.
    if not ran.exists() or "source" not in ran.read_text(encoding="utf-8").split():
        raise RuntimeError(
            (
                "control: the gate-probe scanner never ran",
                result,
                completed.stderr[-3000:],
            )
        )
    assert result["gate_after_scan"] == logging.ERROR, (
        "the hosted scan moved the server's gate",
        result,
    )
    assert result["gate_after_session"] == logging.ERROR, (
        "the server's session moved its gate",
        result,
    )
    assert _MARKER not in completed.stderr, (
        "an INFO line no run owns reached stderr past an ERROR gate",
        completed.stderr[-2000:],
    )
