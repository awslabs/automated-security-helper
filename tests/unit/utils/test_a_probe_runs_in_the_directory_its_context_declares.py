# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A content-database probe runs in the directory its context declares, and in no other.

A probe reads files from its working directory: trivy loads ``trivy.yaml`` from
there, and that file's ``cache.dir`` decides which database ``trivy version``
reports. The directory therefore belongs to the probe's context
(``ProbeContext.cwd``, a directory outside the scanned tree) and is not an
argument a call site computes and hands over. ``_run_json`` takes the context and
nothing else about where to run: there is no working-directory parameter, and
everything after ``env`` is keyword-only, so a path passed in the third position
is refused and not run in.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.utils import content_db_staleness as staleness

COMMAND = ["grype", "db", "status", "-o", "json"]


class _Spawn:
    """Stands in for ``spawn_run``: records each call, answers with a fixed stdout."""

    def __init__(self, stdout: Dict[str, Any]) -> None:
        self.stdout = json.dumps(stdout)
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, command, **kwargs):
        self.calls.append({"command": list(command), **kwargs})
        return SimpleNamespace(returncode=0, stdout=self.stdout, stderr="")


@pytest.fixture
def spawn(monkeypatch) -> _Spawn:
    stand_in = _Spawn({"built": "2026-10-01T00:00:00Z"})
    monkeypatch.setattr(staleness, "spawn_run", stand_in)
    return stand_in


def test_the_probe_runs_in_the_directory_the_context_declares(tmp_path, spawn):
    ctx = staleness.ProbeContext(env={}, cwd=str(tmp_path))

    staleness._run_json(COMMAND, {}, ctx=ctx)

    (call,) = spawn.calls
    assert call["cwd"] == str(tmp_path)


def test_a_context_that_declares_none_runs_the_probe_at_the_temp_root(spawn):
    ctx = staleness.ProbeContext(env={})

    staleness._run_json(COMMAND, {}, ctx=ctx)

    (call,) = spawn.calls
    assert call["cwd"] == Path(Path(tempfile.gettempdir()).absolute()).anchor


def test_the_environment_is_the_callers_not_the_contexts(tmp_path, spawn):
    """grype adds its cache setting to a copy; that copy is what the probe gets."""
    ctx = staleness.ProbeContext(env={"FROM_CONTEXT": "1"}, cwd=str(tmp_path))

    staleness._run_json(COMMAND, {"FROM_CALLER": "1"}, ctx=ctx)

    (call,) = spawn.calls
    assert call["env"] == {"FROM_CALLER": "1"}


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(
            lambda run, ctx: run(COMMAND, {}, "/elsewhere"), id="third-positional"
        ),
        pytest.param(
            lambda run, ctx: run(COMMAND, {}, ctx=ctx, cwd="/elsewhere"),
            id="cwd-keyword",
        ),
        pytest.param(
            lambda run, ctx: run(COMMAND, {}, ctx=ctx, values=("x",)),
            id="values-keyword",
        ),
        pytest.param(lambda run, ctx: run(COMMAND, {}, ctx), id="context-positional"),
        pytest.param(lambda run, ctx: run(COMMAND, {}), id="no-context"),
    ],
)
def test_there_is_no_other_way_to_name_where_the_probe_runs(tmp_path, spawn, call):
    ctx = staleness.ProbeContext(env={}, cwd=str(tmp_path))

    with pytest.raises(TypeError):
        call(staleness._run_json, ctx)

    assert spawn.calls == []


def test_the_grype_probe_runs_in_the_directory_its_context_declares(tmp_path, spawn):
    ctx = staleness.ProbeContext(env={}, executable="grype", cwd=str(tmp_path))

    built, _ = staleness._built_from_grype(ctx)

    assert built.year == 2026
    (call,) = spawn.calls
    assert call["cwd"] == str(tmp_path)


def test_the_trivy_probe_runs_in_the_directory_its_context_declares(
    tmp_path, monkeypatch
):
    stand_in = _Spawn({"VulnerabilityDB": {"UpdatedAt": "2026-10-01T00:00:00Z"}})
    monkeypatch.setattr(staleness, "spawn_run", stand_in)
    ctx = staleness.ProbeContext(env={}, executable="trivy", cwd=str(tmp_path))

    built, _ = staleness._built_from_trivy(ctx)

    assert built.year == 2026
    (call,) = stand_in.calls
    assert call["cwd"] == str(tmp_path)


def test_the_values_that_redact_a_probes_excerpt_come_from_the_context(
    tmp_path, monkeypatch
):
    value = "EDGE-SECRET-3317"
    printed = SimpleNamespace(returncode=1, stdout="", stderr=f"failed for {value}")
    monkeypatch.setattr(staleness, "spawn_run", lambda command, **kwargs: printed)
    ctx = staleness.ProbeContext(env={}, cwd=str(tmp_path), values=(value,))

    with pytest.raises(ValueError) as raised:
        staleness._run_json(COMMAND, {}, ctx=ctx)

    assert "printed nothing" in str(raised.value)
    assert value not in str(raised.value)
