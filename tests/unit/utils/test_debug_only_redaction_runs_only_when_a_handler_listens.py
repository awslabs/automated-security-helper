# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DEBUG-only redaction work runs only when a handler would take the record.

The runner's stderr dump and the spawn plan's sandbox line exist only at
DEBUG, and each walks a whole tool output through the redaction before
logging. The CLI's logger sits at TRACE with its file handlers at INFO, so
``isEnabledFor(DEBUG)`` is always true there and the work ran for records no
handler took. The guard is ``delivers`` (utils/log.py), the predicate
``_pre_scan`` already uses: it reads the HANDLERS' levels, so the work is
skipped exactly when nothing would receive it, and still runs for any
listening DEBUG handler.

The handler swap is a context manager used INSIDE each test body, not a
fixture: pytest attaches a level-0 capture handler to the non-propagating
``ash`` logger at call-phase entry, after fixtures ran, and that handler
takes DEBUG, so a fixture-time swap measures pytest's capture, not the CLI's
shape.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, List

import pytest

from automated_security_helper.utils.log import ASH_LOGGER, TRACE_LEVEL

_FAILING = [
    sys.executable,
    "-c",
    "import sys; sys.stderr.write('boom from the tool'); sys.exit(2)",
]


@contextmanager
def _handlers_at(level: int) -> Iterator[None]:
    saved_handlers = ASH_LOGGER.handlers[:]
    saved_level = ASH_LOGGER.level
    saved_propagate = ASH_LOGGER.propagate
    handler = logging.NullHandler()
    handler.setLevel(level)
    ASH_LOGGER.handlers = [handler]
    # The CLI's shape: the logger itself admits everything, the handlers
    # decide. propagate off keeps pytest's own root handlers out of the walk.
    ASH_LOGGER.setLevel(TRACE_LEVEL)
    ASH_LOGGER.propagate = False
    try:
        yield
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)
        ASH_LOGGER.propagate = saved_propagate


def _recorded_lines(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    from automated_security_helper.utils import subprocess_utils

    lines: List[str] = []
    real = subprocess_utils._logged_without

    def recorder(text: str, values) -> str:
        lines.append(text)
        return real(text, values)

    monkeypatch.setattr(subprocess_utils, "_logged_without", recorder)
    return lines


def test_a_failed_commands_stderr_dump_is_skipped_without_a_debug_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from automated_security_helper.utils.subprocess_utils import run_command

    lines = _recorded_lines(monkeypatch)

    with _handlers_at(logging.INFO):
        result = run_command(_FAILING, check=False)

    assert result.returncode == 2
    assert not [line for line in lines if line.startswith("Command stderr:")]


def test_the_raising_arms_stderr_dump_is_skipped_without_a_debug_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from automated_security_helper.utils.subprocess_utils import run_command

    lines = _recorded_lines(monkeypatch)

    with _handlers_at(logging.INFO):
        with pytest.raises(subprocess.CalledProcessError):
            run_command(_FAILING, check=True)

    assert not [line for line in lines if line.startswith("Command stderr:")]


def test_control_the_stderr_dump_is_built_for_a_listening_debug_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from automated_security_helper.utils.subprocess_utils import run_command

    lines = _recorded_lines(monkeypatch)

    with _handlers_at(logging.DEBUG):
        result = run_command(_FAILING, check=False)

    assert result.returncode == 2
    dumped = [line for line in lines if line.startswith("Command stderr:")]
    assert dumped and "boom from the tool" in dumped[0]


def _spawn_plan_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """prepare_spawn under a real scanner scope with a recording backend;
    the sandbox line's builder (scope_shown_text) is wrapped to count."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SpawnPlan
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements

    class _Backend:
        name = "recorder"

        def plan(self, argv, env, policy):
            return SpawnPlan(argv=list(argv), env=dict(env))

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: _Backend())
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    lines: List[str] = []
    real = scope_module.scope_shown_text

    def recorder(text: str, values=()) -> str:
        lines.append(text)
        return real(text, values)

    monkeypatch.setattr(scope_module, "scope_shown_text", recorder)

    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: sample\nsandbox:\n  mode: bwrap\n"
    )
    config = resolve_config(source_dir=source)
    context = SimpleNamespace(
        config=config, source_dir=source, output_dir=tmp_path / "out"
    )
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="sample"),
        sandbox_requirements=SandboxRequirements(),
        results_dir=None,
    )
    scope = scope_module.scanner_sandbox_scope(plugin, context, source)
    with scope_module.sandbox_scope(scope):
        plan = scope_module.prepare_spawn([sys.executable, "--version"], {}, None)
    assert plan is not None
    return lines


def test_a_spawn_plans_sandbox_line_is_skipped_without_a_debug_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _handlers_at(logging.INFO):
        lines = _spawn_plan_lines(tmp_path, monkeypatch)

    assert not [line for line in lines if line.startswith("Scanner sandbox")]


def test_control_the_sandbox_line_is_built_for_a_listening_debug_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _handlers_at(logging.DEBUG):
        lines = _spawn_plan_lines(tmp_path, monkeypatch)

    assert [line for line in lines if line.startswith("Scanner sandbox")]
