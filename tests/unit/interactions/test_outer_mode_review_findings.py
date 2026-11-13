# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Outer-mode (container and Nix wrapper) details a review found.

* A library caller's upper-case ``min_severity`` is forwarded lower-cased, since the
  inner CLI's choice is case-sensitive.
* Nix mode answers an inner exit 2 with no results file the way container mode does.
* Comparing ``existing_results`` to the output directory's own file survives a
  symbolic link loop.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit


def _opts(tmp_path, **options):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        progress=False,
        show_summary=False,
        **options,
    )


@pytest.mark.parametrize("given", ["HIGH", "High", "high"])
def test_min_severity_is_forwarded_in_lower_case(tmp_path, given):
    opts = _opts(tmp_path, min_severity=given)

    argv = ras._nix_inner_argv(opts)

    assert argv[argv.index("--min-severity") + 1] == "high"


@pytest.fixture
def inner_exit(monkeypatch):
    """Stand in for the Nix shell, exiting with the code in ``code['value']``."""
    code = {"value": 2}

    def fake_run_ash_nix(**_kwargs):
        return create_completed_process(
            args=[], returncode=code["value"], stdout="", stderr=""
        )

    monkeypatch.setattr(ras, "run_ash_nix", fake_run_ash_nix)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_a, **_k: [])
    return code


def test_an_inner_usage_error_in_nix_mode_is_explained_and_exits_3(
    tmp_path, inner_exit
):
    logger = MagicMock()

    with pytest.raises(SystemExit) as exited:
        ras._run_nix_mode(_opts(tmp_path), logger)

    assert exited.value.code == 3
    said = " ".join(str(call.args[0]) for call in logger.error.call_args_list)
    assert "exited 2 without writing a results file" in said
    assert "Results file not found" not in said


def test_other_codes_without_a_results_file_still_exit_1(tmp_path, inner_exit):
    inner_exit["value"] = 1

    with pytest.raises(SystemExit) as exited:
        ras._run_nix_mode(_opts(tmp_path), MagicMock())

    assert exited.value.code == 1


def _loop(tmp_path):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    link = tmp_path / "loop"
    os.symlink(link, link)
    return link


def test_a_looping_link_is_another_file_not_a_traceback(tmp_path):
    link = _loop(tmp_path)
    opts = _opts(tmp_path, existing_results=str(link))

    assert ras._names_the_output_directorys_own_results(opts) is False


def test_nix_mode_refuses_a_looping_results_link(tmp_path, inner_exit):
    link = _loop(tmp_path)
    opts = _opts(tmp_path, existing_results=str(link))

    with pytest.raises(SystemExit) as exited:
        ras._run_nix_mode(opts, MagicMock())

    assert exited.value.code == 3
