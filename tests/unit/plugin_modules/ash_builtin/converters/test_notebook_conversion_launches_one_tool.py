# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A notebook conversion launches nbconvert once, the way the dependency check chose.

The jupyter converter's dependency check chooses how nbconvert runs: through uv
(``uv tool run`` with the converter's requirement) when uv can run it, or a
``jupyter-nbconvert`` it verified against that requirement, by the path it
verified. The conversion then launches that one, once:

* a uv run that started keeps its own outcome, whether it exited non-zero, timed
  out or raised, and nothing is run again;
* when uv could not run nbconvert at all (uv unavailable, or the launch did not
  start), the notebook is not converted, with uv's reason, and no other copy of
  nbconvert runs in uv's place;
* a copy the check verified is launched by that path, and uv is not;
* the converter is ready only with a verified copy or a uv that can run
  nbconvert; a ``jupyter-nbconvert`` on PATH that is not verified, or one that
  answers a probe by name, does not make it ready.

Every launch is a stand-in: uv's runner, and each process launcher the converter
module holds, are replaced, so no program starts. That a real uv under
``--quiet`` keeps its resolver and installer lines off stderr while printing
its error diagnostics is uv's contract, exercised against a real uv in the
pre-completion wave rather than here.
"""

from __future__ import annotations

import importlib
import json
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner
from automated_security_helper.utils.subprocess_utils import (
    SpawnFailedProcess,
    TimedOutProcess,
)

#: The real verification, bound at import, before any fixture replaces the
#: module attribute: the real-messages cell puts it back. Module imports do
#: not touch the attribute, so binding it after them changes nothing; only a
#: fixture, which runs later, replaces it.
_REAL_VERIFY = pre_installed_tool.verify_pre_installed_tool

MODULE = importlib.import_module(
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)
JupyterConverter = MODULE.JupyterConverter
JupyterConverterConfig = MODULE.JupyterConverterConfig

AshConfig.model_rebuild()
PluginContext.model_rebuild()

#: The names a converter module can hold a process launcher under. Each one it
#: holds is replaced by the recorder.
LAUNCHERS = ("spawn_run", "run_ended_with_the_server")

NOTEBOOK = {
    "cells": [
        {
            "cell_type": "code",
            "metadata": {},
            "source": ["import os\n"],
            "outputs": [],
            "execution_count": None,
        }
    ],
    "metadata": {"language_info": {"name": "python"}},
    "nbformat": 4,
    "nbformat_minor": 5,
}


def _write_output(args: List[str]) -> None:
    """Write what nbconvert would for ``args``: ``--output`` plus ``.py``, in
    ``--output-dir`` when one is given."""
    args = [str(a) for a in args]
    if "--output" not in args:
        return
    output = args[args.index("--output") + 1]
    if "--output-dir" in args:
        target = Path(args[args.index("--output-dir") + 1]) / (output + ".py")
    else:
        target = Path(output + ".py")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("import os\n", encoding="utf-8")


class _Uv:
    """Stands in for uv's tool runner. ``outcome`` is what its run does."""

    def __init__(self, outcome: str = "ok", available: bool = True) -> None:
        self.outcome = outcome
        self.available = available
        self.runs: List[List[str]] = []

    def is_uv_available(self) -> bool:
        return self.available

    def unavailable_reason(self) -> str:
        return "uv is not on PATH"

    def run_tool(
        self, tool_name: str, package_name: str, args: List[str], **kwargs: Any
    ):
        argv = ["uv", "tool", "run", "--from", str(package_name), tool_name, *args]
        self.runs.append(argv)
        if self.outcome == "ok":
            _write_output(args)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if self.outcome == "exit-1":
            return subprocess.CompletedProcess(
                argv, 1, "", "Traceback (most recent call last):\nValueError: bad\n"
            )
        if self.outcome == "timed-out":
            return TimedOutProcess(argv, 124, "", "", "timed out after 60 s")
        if self.outcome == "raised-after-start":
            raise RuntimeError("the runner failed after nbconvert started")
        if self.outcome == "not-started":
            return SpawnFailedProcess(argv, 127, "", "[Errno 2] No such file", "no uv")
        raise AssertionError(self.outcome)


class _Launches:
    """Records every process the converter module launches other than through uv."""

    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.argvs: List[List[str]] = []

    def __call__(self, args: Any, *rest: Any, **kwargs: Any):
        argv = [str(a) for a in args]
        self.argvs.append(argv)
        if self.returncode == 0:
            _write_output(argv)
        return subprocess.CompletedProcess(argv, self.returncode, "", "")


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A tree with one notebook, a converter, and stand-ins for every launch."""
    source = tmp_path / "repo"
    source.mkdir()
    notebook = source / "analysis.ipynb"
    notebook.write_text(json.dumps(NOTEBOOK), encoding="utf-8")
    output = tmp_path / "out"
    (output / "work").mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "work",
        config=AshConfig(project_name="notebooks"),
    )
    installed = tmp_path / "installed" / "bin" / "jupyter-nbconvert"
    installed.parent.mkdir(parents=True)
    installed.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    installed.chmod(0o755)

    uv = _Uv()
    launches = _Launches()
    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: uv)
    for name in LAUNCHERS:
        monkeypatch.setattr(MODULE, name, launches, raising=False)
    monkeypatch.setattr(MODULE.subprocess, "run", launches)
    monkeypatch.setattr(MODULE, "scan_set", lambda **kwargs: [str(notebook)])
    monkeypatch.setattr(
        MODULE,
        "lookup_for_scan",
        lambda command, source_dir: (str(installed), None),
        raising=False,
    )
    verified: Dict[str, str] = {"status": "satisfied"}
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda executable, package, *a, **k: pre_installed_tool.PreInstalledToolVerdict(
            verified["status"], executable, package, "installed nbconvert is 7.0.0"
        ),
    )
    for name in ("_resolve_deferred_tool_version", "resolve_deferred_tool_version"):
        monkeypatch.setattr(JupyterConverter, name, lambda self: None, raising=False)
    monkeypatch.setattr(
        JupyterConverter, "_get_uv_tool_version", lambda self, *a, **k: "7.16.4"
    )
    converter = JupyterConverter(context=context, config=JupyterConverterConfig())
    return SimpleNamespace(
        converter=converter,
        uv=uv,
        launches=launches,
        installed=installed,
        verified=verified,
        monkeypatch=monkeypatch,
    )


def _installation(
    world, info: Dict[str, Any], installs: Optional[bool] = None
) -> List[Any]:
    """Stub the installation info and the install, and return the install's
    recorded calls."""
    world.monkeypatch.setattr(
        JupyterConverter, "_get_tool_installation_info", lambda self: dict(info)
    )
    install_calls: List[Any] = []

    def _install(self, *args: Any, **kwargs: Any) -> bool:
        install_calls.append(kwargs)
        return bool(installs)

    world.monkeypatch.setattr(JupyterConverter, "_install_uv_tool", _install)
    return install_calls


def _uv_chosen(world) -> None:
    """The check finds nbconvert installed through uv, so uv runs it."""
    _installation(world, {"available": True, "preferred_source": "uv"})
    assert world.converter.validate_plugin_dependencies() is True


def _convert(world) -> List[Path]:
    try:
        return list(world.converter.convert() or [])
    except Exception:  # A converter that raises converted nothing.
        return []


# ---------------------------------------------------------------------------
# One launch, by uv, and nothing in uv's place


@pytest.mark.parametrize("outcome", ["exit-1", "timed-out", "raised-after-start"])
@pytest.mark.unit
def test_a_uv_run_that_started_keeps_its_outcome_and_runs_once(world, outcome):
    _uv_chosen(world)
    world.uv.outcome = outcome

    converted = _convert(world)

    assert converted == []
    assert len(world.uv.runs) == 1, world.uv.runs
    assert world.launches.argvs == []


@pytest.mark.unit
def test_a_uv_run_that_did_not_start_runs_nothing_in_its_place(world):
    _uv_chosen(world)
    world.uv.outcome = "not-started"

    converted = _convert(world)

    assert converted == []
    assert len(world.uv.runs) == 1, world.uv.runs
    assert world.launches.argvs == []


@pytest.mark.unit
def test_uv_unavailable_at_conversion_runs_nothing_in_its_place(world):
    _uv_chosen(world)
    world.uv.available = False

    converted = _convert(world)

    assert converted == []
    assert world.uv.runs == []
    assert world.launches.argvs == []


@pytest.mark.unit
def test_control_a_uv_run_that_succeeds_converts_the_notebook_once(world):
    _uv_chosen(world)

    converted = _convert(world)

    assert len(converted) == 1, converted
    assert len(world.uv.runs) == 1
    assert world.launches.argvs == []


# ---------------------------------------------------------------------------
# The copy the check verified


@pytest.mark.unit
def test_a_copy_the_check_verified_is_launched_by_that_path(world):
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
    )
    assert world.converter.validate_plugin_dependencies() is True
    assert world.launches.argvs == [], "the check itself launched a copy"

    converted = _convert(world)

    assert len(converted) == 1, converted
    assert world.uv.runs == []
    assert [argv[0] for argv in world.launches.argvs] == [str(world.installed)]


@pytest.mark.unit
def test_the_conversion_launches_the_copy_the_check_recorded(world, tmp_path):
    """The conversion runs the copy the check recorded, not a fresh lookup's
    answer: a PATH that changed between the check and the conversion would
    otherwise run a copy under the verdict given for another one."""
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
    )
    assert world.converter.validate_plugin_dependencies() is True

    elsewhere = str(tmp_path / "elsewhere" / "jupyter-nbconvert")
    world.monkeypatch.setattr(
        MODULE,
        "lookup_for_scan",
        lambda command, source_dir: (elsewhere, None),
        raising=False,
    )

    converted = _convert(world)

    assert len(converted) == 1, converted
    assert world.uv.runs == []
    assert [argv[0] for argv in world.launches.argvs] == [str(world.installed)]


@pytest.mark.unit
def test_a_healthy_check_that_chooses_uv_logs_no_warning(world, caplog):
    """A PATH copy that does not verify, replaced by an install through uv
    that succeeds, is a healthy run: the fallback's detail is DEBUG, and a
    WARNING saying the copy "cannot be used" reads as something to fix on a
    run where nothing failed."""
    world.verified["status"] = "unsatisfied"
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=True,
    )

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert world.converter.validate_plugin_dependencies() is True

    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert warnings == [], warnings


# ---------------------------------------------------------------------------
# Readiness: a verified copy, or a uv that can run nbconvert


@pytest.mark.unit
def test_a_copy_on_path_that_does_not_verify_leaves_the_converter_missing(world):
    world.uv.available = False
    world.verified["status"] = "unsatisfied"
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
    )

    assert world.converter.validate_plugin_dependencies() is False

    reason = getattr(world.converter, "dependency_unavailable_reason", None) or ""
    assert "nbconvert" in reason, reason
    assert world.launches.argvs == []
    assert world.uv.runs == []


@pytest.mark.unit
def test_a_copy_that_fails_verification_is_replaced_by_an_install_through_uv(world):
    """The install carries the converter's requirement, so what uv runs after it
    is a version the check vouched for, not whatever uv resolves."""
    world.verified["status"] = "unsatisfied"
    install_calls = _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=True,
    )

    assert world.converter.validate_plugin_dependencies() is True

    assert install_calls, "nothing was installed before choosing the uv route"
    converted = _convert(world)
    assert len(converted) == 1, converted
    assert [argv[:3] for argv in world.uv.runs] == [["uv", "tool", "run"]]
    # The run's one --from spec is the requirement itself.
    assert world.uv.runs[0][4] == "nbconvert>=7.16.0,<8.0.0", world.uv.runs
    assert world.launches.argvs == []


@pytest.mark.unit
def test_a_copy_that_fails_verification_with_no_install_leaves_it_missing(world):
    """uv being present is not a way to run nbconvert: with the install failing
    (offline, say), the converter is missing, with the verification's reason,
    rather than ready with every notebook failing at conversion."""
    world.verified["status"] = "unsatisfied"
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=False,
    )

    assert world.converter.validate_plugin_dependencies() is False

    reason = getattr(world.converter, "dependency_unavailable_reason", None) or ""
    assert "cannot be used" in reason, reason
    assert world.uv.runs == []
    assert world.launches.argvs == []


@pytest.mark.unit
def test_after_a_failed_install_a_copy_answering_by_name_does_not_make_it_ready(
    world,
):
    world.verified["status"] = "unsatisfied"
    _installation(world, {"available": False}, installs=False)

    assert world.converter.validate_plugin_dependencies() is False

    # Nothing is probed by name: the copy is judged only by the verification.
    assert world.launches.argvs == []
    reason = getattr(world.converter, "dependency_unavailable_reason", None) or ""
    assert "nbconvert" in reason, reason


@pytest.mark.unit
def test_after_a_failed_install_the_verified_copy_is_ready_and_launched_by_its_path(
    world,
):
    _installation(world, {"available": False}, installs=False)

    assert world.converter.validate_plugin_dependencies() is True

    converted = _convert(world)
    assert len(converted) == 1, converted
    assert world.uv.runs == []
    assert [argv[0] for argv in world.launches.argvs] == [str(world.installed)]


def _a_refusing_lookup(world, refusal: str) -> None:
    """The lookup refuses every copy it sees, with ``refusal`` as the reason."""
    world.monkeypatch.setattr(
        MODULE,
        "lookup_for_scan",
        lambda command, source_dir: (None, refusal),
        raising=False,
    )


@pytest.mark.unit
def test_a_copy_the_lookup_refuses_is_not_run_even_when_found_first(world):
    """The path the installation info found goes through the same lookup that
    can refuse a copy (one inside the scanned tree, say): a refused copy starts
    nothing, whoever found it first, and with no install the converter is
    missing with the refusal's reason."""
    _a_refusing_lookup(world, "the jupyter-nbconvert found is inside the scanned tree")
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=False,
    )

    assert world.converter.validate_plugin_dependencies() is False

    # The check itself launched nothing and ran nothing through uv; a converter
    # whose check failed is dropped by the plugin filter before convert().
    assert world.launches.argvs == [], "a refused copy was launched"
    assert world.uv.runs == []
    reason = getattr(world.converter, "dependency_unavailable_reason", None) or ""
    assert "inside the scanned tree" in reason, reason


@pytest.mark.unit
def test_a_refused_copy_is_replaced_by_an_install_through_uv(world):
    _a_refusing_lookup(world, "the jupyter-nbconvert found is inside the scanned tree")
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=True,
    )

    assert world.converter.validate_plugin_dependencies() is True

    converted = _convert(world)
    assert len(converted) == 1, converted
    assert [argv[:3] for argv in world.uv.runs] == [["uv", "tool", "run"]]
    assert world.launches.argvs == []


@pytest.mark.unit
def test_an_unverified_copys_recorded_reason_names_no_path(world):
    """dependency_unavailable_reason reaches the results, so the copy's host
    path stays in the log and out of the record, as a failed input's reason
    does."""
    world.verified["status"] = "unsatisfied"
    _installation(
        world,
        {
            "available": True,
            "preferred_source": "pre_installed",
            "pre_installed_path": str(world.installed),
        },
        installs=False,
    )

    assert world.converter.validate_plugin_dependencies() is False

    reason = getattr(world.converter, "dependency_unavailable_reason", None) or ""
    assert "cannot be used" in reason, reason
    assert str(world.installed) not in reason, reason
    assert "/" not in reason, reason


@pytest.mark.integration
def test_the_real_verifications_recorded_reason_names_no_path_or_output(world):
    """The reason built from the real check's verdict, not the fixture's
    stand-in, carries neither the copy's path nor the probe's own words: the
    real ``detail`` holds both, and only ``summary`` may reach the record."""
    world.monkeypatch.setattr(
        pre_installed_tool, "verify_pre_installed_tool", _REAL_VERIFY
    )
    pre_installed_tool.reset_pre_installed_tool_cache()
    world.installed.write_text(
        '#!/bin/sh\necho "CARRIED-VALUE $0" >&2\nexit 7\n', encoding="utf-8"
    )

    found = world.converter._verified_direct_nbconvert(str(world.installed))

    assert found.path is None
    # The log's detail names the copy and quotes the probe (controls that the
    # real messages ran).
    assert str(world.installed) in found.detail, found.detail
    assert "CARRIED-VALUE" in found.detail, found.detail
    assert "exited 7" in found.reason, found.reason
    assert str(world.installed) not in found.reason, found.reason
    assert "CARRIED-VALUE" not in found.reason, found.reason
