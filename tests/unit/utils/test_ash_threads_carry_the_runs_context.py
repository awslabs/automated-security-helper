# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every thread ASH starts carries the run's context, and the factory is neutral.

A thread made with threading.Thread starts in an empty context: a line it logs
belongs to no run, so during a hosted scan it reaches no scan's ash.log, and a
cancel check in it reads no cancel scope. ash_thread copies the context at
creation, so these cells hold the package to it: a bare threading.Thread in
production is a failure here until it is converted or named below with its
reason, and so is a pool submit that does not run under a copied context.

ash_thread itself lives in a module of its own: it carries thread and
cancellation semantics, not logging ones, and it is documented plugin API, so
its import path must not pin it inside the logging module.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests.unit.walked_package import PACKAGE, package_sources

#: The one module that may call threading.Thread: the factory's own home.
_THREAD_FACTORY = "utils/threads.py"

#: Pool submits that run their work without a copied context, each with the
#: measured reason it stays. New entries need the same measurement.
_PLAIN_SUBMITS = {
    # The workspace project pool: each worker enters its own project's cancel
    # scope, and carrying the workspace thread's context in would carry the
    # workspace-wide scope with it. Its engines' lines are the projects' own
    # concern; the pool is plain by design (cli/mcp/workspace.py's round).
    "workspace/execution.py",
}


def _calls(source: Path) -> ast.Module:
    return ast.parse(source.read_text(encoding="utf-8"), filename=str(source))


def _is_threading_thread(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "Thread":
        value = func.value
        return isinstance(value, ast.Name) and value.id == "threading"
    return isinstance(func, ast.Name) and func.id == "Thread"


def _runs_a_copied_context(argument: ast.expr) -> bool:
    """Whether *argument* is ``contextvars.copy_context().run`` (or ``...run``)."""
    return (
        isinstance(argument, ast.Attribute)
        and argument.attr == "run"
        and isinstance(argument.value, ast.Call)
        and isinstance(argument.value.func, (ast.Attribute, ast.Name))
        and (
            getattr(argument.value.func, "attr", None) == "copy_context"
            or getattr(argument.value.func, "id", None) == "copy_context"
        )
    )


def test_no_production_thread_is_started_without_the_runs_context():
    offenders: list[str] = []
    for source in package_sources():
        part = source.relative_to(PACKAGE).as_posix()
        if part == _THREAD_FACTORY:
            continue
        for node in ast.walk(_calls(source)):
            if isinstance(node, ast.Call) and _is_threading_thread(node):
                offenders.append(f"{part}:{node.lineno}")
    assert not offenders, (
        "threading.Thread starts a thread in an empty context; start it with "
        f"ash_thread (automated_security_helper/{_THREAD_FACTORY}) instead, or "
        f"name the site here with its measured reason: {sorted(offenders)}"
    )


def test_every_pool_submit_runs_under_a_copied_context_or_is_named():
    offenders: list[str] = []
    for source in package_sources():
        part = source.relative_to(PACKAGE).as_posix()
        if part in _PLAIN_SUBMITS:
            continue
        for node in ast.walk(_calls(source)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr == "submit" and node.args:
                if not _runs_a_copied_context(node.args[0]):
                    offenders.append(f"{part}:{node.lineno}")
            if func.attr == "run_in_executor" and len(node.args) >= 2:
                if not _runs_a_copied_context(node.args[1]):
                    offenders.append(f"{part}:{node.lineno}")
    assert not offenders, (
        "a pool submit without contextvars.copy_context().run runs its work in "
        f"an empty context; wrap it, or name the site in _PLAIN_SUBMITS with "
        f"its measured reason: {sorted(offenders)}"
    )


def test_the_thread_factory_lives_in_its_own_module_and_the_guide_names_it():
    from automated_security_helper.utils import log as ash_log
    from automated_security_helper.utils import threads

    assert threads.ash_thread is ash_log.ash_thread, (
        "the re-export from utils.log is not the factory itself"
    )
    guide = (
        Path(PACKAGE).parents[0] / "docs" / "content" / "plugins" / "write-a-scanner.md"
    ).read_text(encoding="utf-8")
    assert "from automated_security_helper.utils.threads import" in guide, (
        "the plugin guide does not import the thread factory from its own module"
    )
    assert "utils.log import ASH_LOGGER, ash_thread" not in guide, (
        "the plugin guide still pins the factory to the logging module"
    )
