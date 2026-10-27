# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config named inside the scanned tree whose real path cannot be read.

The host resolves the name to a real path before it judges where the file
lands. When that resolution fails (a link the process cannot read, or a
platform that reports a link it cannot read as one and raises ValueError), the
run is refused with exit 3 and the refusal says the name cannot be resolved. It
does not claim the name leads outside the tree, and no exception escapes the
pre-run check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_container as rac

CONFIG_TEXT = "project_name: unreadable-name\n"


@pytest.fixture
def layout(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    config = source / "ash.yaml"
    config.write_text(CONFIG_TEXT, encoding="utf-8")
    return {"source": source, "out": out, "config": config}


def _failing_real_path(monkeypatch, config: Path, error: Exception) -> None:
    real = rac._real_path

    def fake(path):
        if str(path) == str(config):
            raise error
        return real(path)

    monkeypatch.setattr(rac, "_real_path", fake)


@pytest.mark.parametrize("error", [OSError("unreadable"), ValueError("not a link")])
def test_a_name_whose_real_path_cannot_be_read_is_refused_as_unresolvable(
    layout, monkeypatch, error
):
    _failing_real_path(monkeypatch, layout["config"], error)

    with pytest.raises(rac.ContainerInputError) as raised:
        rac._refuse_config_linked_out_of_the_tree(
            str(layout["config"]), layout["source"]
        )

    message = str(raised.value)
    assert "cannot be resolved" in message, message
    assert "a link on the way cannot be read" in message, message
    assert "which is outside it" not in message, message


@pytest.mark.parametrize("error", [OSError("unreadable"), ValueError("not a link")])
def test_the_pre_run_check_returns_a_refusal_for_a_name_it_cannot_resolve(
    layout, monkeypatch, error
):
    _failing_real_path(monkeypatch, layout["config"], error)

    refusal = rac.container_input_refusal(
        layout["source"], layout["out"], str(layout["config"])
    )

    assert isinstance(refusal, str), refusal
    assert "cannot be resolved" in refusal, refusal


def test_a_name_that_resolves_inside_the_tree_is_not_refused(layout):
    """The must-not twin: nothing here fails, so nothing is refused."""
    refusal = rac.container_input_refusal(
        layout["source"], layout["out"], str(layout["config"])
    )

    assert refusal is None, refusal
