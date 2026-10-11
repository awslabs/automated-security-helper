# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``run_ash_scan(mode=container)`` honors ``ASH_CONFIG`` the way a local scan does.

The CLI reads ``ASH_CONFIG`` as ``--config``, so a CLI run hands the file to the
container. A library caller passes ``config=None``, and a local scan then uses
``ASH_CONFIG``'s file when no config is found in the source directory
(config/default_config.py). The scan inside the container sees neither the host's
environment nor that file, so container mode names the file for it, in exactly the
case a local scan would use it.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture
def handed_over(monkeypatch) -> Dict[str, Any]:
    """What run_ash_scan hands the container runner; nothing is started."""
    seen: Dict[str, Any] = {}

    def fake_run_ash_container(**kwargs):
        seen.update(kwargs)
        return rac._not_started(create_completed_process(args=[], returncode=4))

    monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return seen


def _scan(tmp_path, **kwargs) -> None:
    with pytest.raises(SystemExit):
        ras.run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.container,
            **kwargs,
        )


@pytest.fixture
def operator_config(tmp_path):
    (tmp_path / "src").mkdir()
    config = tmp_path / "operator.yaml"
    config.write_text("project_name: operator\n", encoding="utf-8")
    return config


def test_ash_config_is_handed_to_the_container_when_the_tree_has_no_config(
    handed_over, operator_config, monkeypatch, tmp_path
):
    monkeypatch.setenv("ASH_CONFIG", str(operator_config))

    _scan(tmp_path)

    assert handed_over["config"] == str(operator_config)


def test_a_config_in_the_tree_wins_over_ash_config_as_in_a_local_scan(
    handed_over, operator_config, monkeypatch, tmp_path
):
    (tmp_path / "src" / ".ash").mkdir()
    (tmp_path / "src" / ".ash" / ".ash.yaml").write_text(
        "project_name: repo\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator_config))

    _scan(tmp_path)

    assert handed_over["config"] is None


def test_an_explicit_config_wins_over_ash_config(
    handed_over, operator_config, monkeypatch, tmp_path
):
    named = tmp_path / "named.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator_config))

    _scan(tmp_path, config=str(named))

    assert handed_over["config"] == str(named)


def test_without_ash_config_nothing_is_named(handed_over, operator_config, tmp_path):
    """Control."""
    _scan(tmp_path)

    assert handed_over["config"] is None
