# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The checkout, the machine and the CLI call the ``ash build-image`` cells run.

``test_build_image.py`` and the routing cells of operator paths import these; this
module imports no test file. ``_machine_inputs`` and ``_restore_loggers`` are autouse
fixtures: a cell file that imports them has them applied to each of its cells.
``inner_ash`` is what the in-container ASH writes to ``/out``: an empty result marked
complete with this run's ID.
"""

from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import pytest
from typer.testing import CliRunner

# Imported first, as the `ash` process does. Importing run_ash_scan (or cli.image,
# which imports it) before the built-in plugin package makes ash_builtin.reporters
# fail with a circular import, which leaves every built-in reporter unregistered for
# the rest of the worker, whichever module asks next.
import automated_security_helper.cli.main  # noqa: F401  # isort: skip
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.characterization._harness import ToolCall
from tests.unit.characterization._run_ash_container_double import (
    CHECKOUT_DOCKERFILE,
    CHECKOUT_PYPROJECT,
    IdDouble,
    RuntimeDouble,
    _FrozenDatetime,
    _Sys,
)

SOURCE_FILE = (
    "# characterization: the scanned source in the checkout\n"
    "def greet(name):\n"
    "    return 'hello ' + name\n"
)


@pytest.fixture(autouse=True)
def _machine_inputs(monkeypatch):
    monkeypatch.setattr(rac, "datetime", _FrozenDatetime)
    monkeypatch.setattr(rac, "sys", _Sys(tty=False))
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")


@pytest.fixture(autouse=True)
def _restore_loggers():
    """run_ash_scan replaces ASH's log handlers with ones writing into the output dir."""
    saved = {
        logger: (list(logger.handlers), logger.level, logger.propagate)
        for logger in (ASH_LOGGER, logging.getLogger())
    }
    yield
    for logger, (handlers, level, propagate) in saved.items():
        for handler in logger.handlers:
            if handler not in handlers:
                handler.close()
        logger.handlers = handlers
        logger.setLevel(level)
        logger.propagate = propagate


def inner_ash(run_id_key: str = "ASH_OUTER_RUN_ID"):
    """What the in-container ASH writes to /out: an empty result marked complete."""

    def write(call: ToolCall, mounts: Dict[str, Path], env: Dict[str, str]) -> None:
        document = {
            "validation_checkpoints": [
                {
                    "type": "run_completed",
                    "severity": "info",
                    "message": "The run completed.",
                    "metadata": {"run_id": env.get(run_id_key, "")},
                }
            ]
        }
        call.write(
            mounts["/out"] / "ash_aggregated_results.json",
            (json.dumps(document, indent=2) + "\n").encode("utf-8"),
        )

    return write


def _checkout(char) -> Path:
    """The working directory: an ASH checkout, which is also the scanned source.

    A plain chdir: the harness puts the working directory back when the test ends,
    before it removes the test's directory.
    """
    root = char.tmp / "checkout"
    char.write_source(
        {
            "Dockerfile": CHECKOUT_DOCKERFILE,
            "pyproject.toml": CHECKOUT_PYPROJECT,
            "app.py": SOURCE_FILE,
        },
        root=root,
    )
    os.chdir(root)
    return root


def _world(
    char,
    double: Optional[RuntimeDouble] = None,
    runtimes: Sequence[str] = ("docker",),
) -> RuntimeDouble:
    _checkout(char)
    char.set_env(COLUMNS="132", LINES="43")
    char.tool("id", IdDouble(), on="sysbin")
    double = double or RuntimeDouble(on_run=inner_ash())
    for name in runtimes:
        char.tool(name, double)
    char.absent(
        *[n for n in ("finch", "docker", "nerdctl", "podman") if n not in runtimes]
    )
    return double


def _invoke(char, *args: str) -> Dict[str, Any]:
    from automated_security_helper.cli.main import app

    char.begin()
    with char.phase("build-image"):
        result = CliRunner().invoke(app, ["build-image", *args], catch_exceptions=True)
    exception = result.exception
    if exception is not None and not isinstance(exception, SystemExit):
        raise exception
    return {"exit_code": result.exit_code}
