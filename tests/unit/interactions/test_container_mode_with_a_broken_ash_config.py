# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode with a broken ASH_CONFIG refuses before the runner.

The scan inside the container sees neither the host's environment nor the
file ASH_CONFIG names, so container mode mounts that file's chain read-only
and passes the variables the operator's files read into the container by
name. Both need the file read on the host: a file that does not parse cannot
be handed over, so the run is refused with exit 3 before any image is built,
on the API path and the CLI path alike. The two routes refuse through
different checks -- the API path through the input handoff
(run_ash_container.operator_environment_names, which cannot read the
variables the file reads), the CLI path through the parse pre-check, because
``--config``'s envvar is ASH_CONFIG and the broken file IS the ``--config``
file there.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

BROKEN_YAML = "project_name: [unclosed\n"


def _make_opts(tmp_path):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    return ScanOptions(source_dir=src, output_dir=out, mode=RunMode.container)


@pytest.fixture
def broken_ash_config(tmp_path, monkeypatch) -> Path:
    broken = tmp_path / "operator-broken.yaml"
    broken.write_text(BROKEN_YAML, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(broken))
    return broken


def test_an_api_run_with_no_config_refuses_before_the_runner(
    tmp_path, broken_ash_config, capsys
):
    """An API caller with no ``--config`` and a broken ASH_CONFIG file: the
    file is the base the scan inside is handed (mounted, with the variables
    its chain reads passed by name), so a file whose variables cannot be read
    refuses the run with exit 3 before the runner starts. The refusal names
    the input, not the parser's own text."""
    from automated_security_helper.interactions.run_ash_scan import _run_container_mode

    opts = _make_opts(tmp_path)
    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        new=runner,
    ):
        with pytest.raises(SystemExit) as refused:
            _run_container_mode(opts, MagicMock())

    assert refused.value.code == 3
    assert runner.call_count == 0
    message = capsys.readouterr().err
    assert "Could not read the variables" in message, message
    assert broken_ash_config.name in message, message


def test_the_cli_envvar_route_refuses_before_the_runner(
    tmp_path, monkeypatch, broken_ash_config
):
    """``--config``'s envvar is ASH_CONFIG, so on the CLI the broken file is
    the ``--config`` file: the pre-check refuses it with exit 3, naming it,
    and no image is built."""
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        new=runner,
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                "container",
                "--source-dir",
                str(tmp_path / "src"),
                "--output-dir",
                str(tmp_path / "out"),
            ],
        )

    assert result.exit_code == 3, result.output
    assert broken_ash_config.name in result.output, result.output
    assert runner.call_count == 0
