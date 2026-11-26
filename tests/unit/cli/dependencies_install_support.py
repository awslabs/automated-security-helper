# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A one-scanner ``ash dependencies install`` run the provider-flag tests share.

The command is driven for real, with the plugin set replaced by one fake scanner
whose declared install commands the test chooses, and the runner replaced by a
recorder: nothing installs, no network is reached, and what the command ran is the
list the test reads back. Nothing here executes a tool.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Callable, List, Optional
from unittest.mock import MagicMock

from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app

CHECKOV_COMMAND = [
    "uv",
    "tool",
    "install",
    "--python",
    ">=3.10,<3.14",
    "--with",
    "requests>=2",
    "checkov>=3,<4",
]


class Scene:
    """What a run did: the commands it ran and the text it printed."""

    def __init__(self) -> None:
        self.calls: List[tuple] = []
        self.text = ""
        self.result = None
        self.created: List[Path] = []

    @property
    def argvs(self) -> List[List[str]]:
        return [list(cmd) for cmd, _shell in self.calls]


def build_scene(
    monkeypatch,
    tmp_path: Path,
    *,
    name: str = "checkov",
    command: Optional[str] = "checkov",
    declared: Optional[list] = None,
    uv_managed: bool = True,
    find_on_path: Optional[Callable[[str], Optional[str]]] = None,
    uv_listing: Optional[Callable[[str], Optional[str]]] = None,
    on_run: Optional[Callable[[list], int]] = None,
) -> Scene:
    """Replace the plugin set with one fake scanner and the runner with a recorder.

    ``find_on_path`` is the lookup a scan makes (``find_executable_for_scan``);
    ``uv_listing`` is uv's tool listing. ``on_run`` may act when a command is
    "run" (create a directory, say) and returns its exit code.
    """
    scene = Scene()
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(exist_ok=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "load_plugins", lambda *_a, **_k: {})

    fake = MagicMock()
    fake.config = SimpleNamespace(name=name)
    fake.command = command
    fake.use_uv_tool = uv_managed
    fake.external_executables = ()
    fake.runs_in_ash_interpreter = False
    fake.get_installation_commands.return_value = (
        declared if declared is not None else [list(CHECKOV_COMMAND)]
    )
    monkeypatch.setattr(
        dependencies_module,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: fake] if kind == "scanner" else []
            )
        ),
    )

    def run_command(cmd, shell=False):
        scene.calls.append((list(cmd), shell))
        return on_run(list(cmd)) if on_run is not None else 0

    monkeypatch.setattr(dependencies_module, "run_command", run_command)
    monkeypatch.setattr(
        dependencies_module,
        "find_executable_for_scan",
        lambda cmd, root: find_on_path(cmd) if find_on_path else None,
    )
    monkeypatch.setattr(
        dependencies_module,
        "_uv_tool_executable",
        lambda cmd: uv_listing(cmd) if uv_listing else None,
    )
    return scene


def run_install(scene: Scene, monkeypatch, tmp_path: Path, *args: str) -> Scene:
    """Invoke the command with ``args``; fill ``scene.text`` and ``scene.result``."""
    import io

    sink = io.StringIO()
    monkeypatch.setattr(
        dependencies_module, "console", Console(file=sink, width=300, no_color=True)
    )
    scene.result = CliRunner().invoke(
        dependencies_app,
        [
            "--plugin-type",
            "scanner",
            "--bin-path",
            str(tmp_path / "bin"),
            *args,
        ],
        env={"COLUMNS": "300"},
    )
    scene.text = sink.getvalue() + scene.result.output
    return scene
