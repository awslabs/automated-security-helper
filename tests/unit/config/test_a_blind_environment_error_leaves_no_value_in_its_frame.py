# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment-blind refusal of a chain carries no environment value in its frame.

``resolve_config_document`` rebuilds a refusal that could quote a value read from
the environment as an environment-blind error and raises it outside the handler,
so neither exception chain holds the value. The fresh error's traceback still
carried this function's own frame, whose locals held the values: ``state``
(every reference the chain read, with its value) and the refused error itself. A
debugger or a verbose traceback renderer that prints frame locals printed them.
Both locals are now dropped from the frame before the raise.

Red at the base: the ``resolve_config_document`` frame on the error's traceback
held a local whose repr contained the value read from the environment.
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

MARKER = "sekrit-value-u35"


def _config_sources_frames(traceback):
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("config_sources.py"):
            yield frame
        traceback = traceback.tb_next


def _chain(error: BaseException):
    """``error`` and every exception reachable from it through ``__context__``
    and ``__cause__``: what a chain walker (a traceback renderer that ignores
    ``__suppress_context__``, a debugger) prints."""
    seen = set()
    pending = [error]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending.append(current.__context__)
        pending.append(current.__cause__)


def test_the_resolving_frame_holds_no_environment_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASH_U35_READ", MARKER)
    monkeypatch.delenv("ASH_U35_UNSET", raising=False)
    (tmp_path / "base.yaml").write_text(
        "global_settings:\n  severity_threshold: ${ASH_U35_UNSET}\n", encoding="utf-8"
    )
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: base.yaml\nproject_name: ${ASH_U35_READ}\n", encoding="utf-8"
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(root)

    assert MARKER not in str(refused.value)
    frames = list(_config_sources_frames(refused.tb))
    assert frames, "the refusal's traceback holds no config_sources frame"
    for frame in frames:
        for name, value in frame.f_locals.items():
            assert MARKER not in repr(value), (frame.f_code.co_name, name)


def test_a_missing_base_is_refused_as_itself_with_a_cause_that_names_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing base is refused as itself, with the environment set.

    The refusal names the base and quotes no value, so it is raised as it is
    rather than rebuilt environment-blind (the route the other tests here
    drive). It keeps the cause that says which path problem it is, because
    ``config_load_category`` reads the chain to answer the MCP category as a
    path problem. That cause is rebuilt without the OSError's file name, so
    nothing on the chain holds the value the root read."""
    monkeypatch.setenv("ASH_U35_READ", MARKER)
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: missing-base.yaml\nproject_name: ${ASH_U35_READ}\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(root)

    assert "missing-base.yaml" in str(refused.value), str(refused.value)
    cause = refused.value.__cause__
    assert isinstance(cause, OSError), repr(cause)
    assert cause.errno == errno.ENOENT, repr(cause)
    assert cause.filename is None, repr(cause)
    for linked in _chain(refused.value):
        assert MARKER not in str(linked), linked
        assert MARKER not in repr(linked), linked


def test_the_literal_route_returns_an_error_with_no_traceback(tmp_path: Path) -> None:
    """The other arm: when the chain fails without the environment too, and
    that failure names no reference, the literal resolution's own error is the
    reason. It used to be returned with its traceback, which ran through
    ``_environment_blind_error``'s frame (local ``error``: the refused error,
    whose text can quote a value) and kept the real resolution's frames alive;
    the outer ``raise ... from None`` cuts the exception chain but not a
    traceback carried on the error itself. Red at the base: the returned
    error's traceback held that frame, with the refused error among its locals.
    """
    from automated_security_helper.config.config_sources import (
        _environment_blind_error,
    )

    root = tmp_path / ".ash.yaml"
    root.write_text("extends: missing-base.yaml\nproject_name: p\n", encoding="utf-8")
    refused = ASHConfigSourceError(f"quotes a value: {MARKER}")

    result = _environment_blind_error(root, tmp_path, None, refused)

    assert isinstance(result, ASHConfigSourceError)
    assert result is not refused
    assert "${" not in str(result) and MARKER not in str(result)
    assert result.__traceback__ is None


def test_the_same_chain_loads_once_the_variable_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the chain reads both values when the second is set."""
    monkeypatch.setenv("ASH_U35_READ", MARKER)
    monkeypatch.setenv("ASH_U35_UNSET", "HIGH")
    (tmp_path / "base.yaml").write_text(
        "global_settings:\n  severity_threshold: ${ASH_U35_UNSET}\n", encoding="utf-8"
    )
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: base.yaml\nproject_name: ${ASH_U35_READ}\n", encoding="utf-8"
    )

    document = resolve_config_document(root)

    assert document.data["project_name"] == MARKER
    assert {r.written for r in document.environment_references} == {
        "${ASH_U35_READ}",
        "${ASH_U35_UNSET}",
    }
