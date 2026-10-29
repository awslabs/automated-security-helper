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
