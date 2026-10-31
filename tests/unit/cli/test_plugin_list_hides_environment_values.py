# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash plugin list --include-plugin-config` prints no environment-read value.

The config column dumps each plugin's typed options. An option a config file
reads from ``${V}`` is the environment's: the listing's error row already
prints such values masked (error_text with the config's recorded values), and
the config column must agree rather than print them in clear. The control
pins the column uncropped -- bandit's default tool_version printed whole --
so a value's absence is the mask's doing, not the table cropping it away.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

VARIABLE = "ASH_PLUGIN_LIST_NEEDLE"
#: Bandit's default tool_version, printed whole only when the column is wide.
UNCROPPED = '">=1.7.8,<2.0.0"'
WIDE = {"COLUMNS": "1000", "NO_COLOR": "1"}


def _listing(tmp_path, monkeypatch, body: str) -> tuple[int, str]:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(source)
    # The config lives outside the scanned tree, so its values are the
    # operator's and nothing is dropped before the listing.
    folder = tmp_path / "cfg"
    folder.mkdir()
    config = folder / "probe.ash.yaml"
    config.write_text(body, encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["plugin", "list", "--include-plugin-config", "--config", str(config)],
        env=WIDE,
    )
    return result.exit_code, result.output


def test_an_env_read_option_value_is_not_in_the_config_column(tmp_path, monkeypatch):
    value = "zq7listcanary-0123"
    monkeypatch.setenv(VARIABLE, value)

    code, raw = _listing(
        tmp_path,
        monkeypatch,
        "project_name: probe\nscanners:\n  bandit:\n    options:\n"
        f"      config_file: ${{{VARIABLE}}}\n",
    )

    assert code == 0, (code, raw[-1500:])
    # The control: the column is not cropped.
    assert UNCROPPED in raw, raw[-3000:]
    assert value not in raw, raw[-3000:]
    assert "<value>" in raw, raw[-3000:]


def test_a_numeric_string_value_is_masked_at_the_number_boundary(tmp_path, monkeypatch):
    """A short signed numeric value takes the number-bounded needle, so its
    absence is checked the way the needles match: not continued by a digit,
    or a dot attached to a digit, on either side. The dump quotes it
    ("config_file": "-321.50"), and a quote is a boundary."""
    from automated_security_helper.utils.numeric_text import bounded_number_pattern

    written = "-321.50"
    monkeypatch.setenv(VARIABLE, written)

    code, raw = _listing(
        tmp_path,
        monkeypatch,
        "project_name: probe\nscanners:\n  bandit:\n    options:\n"
        f"      config_file: ${{{VARIABLE}}}\n",
    )

    assert code == 0, (code, raw[-1500:])
    assert UNCROPPED in raw, raw[-3000:]
    assert re.search(bounded_number_pattern(written), raw) is None, raw[-3000:]


def test_an_error_row_masks_an_env_read_value(tmp_path, monkeypatch):
    """The error row's guards are load-bearing: an instantiation failure
    whose message quotes an environment-read value prints it masked, through
    error_text on the message and the row mask before markup escaping."""
    value = "zq7errcanary-9876"
    monkeypatch.setenv(VARIABLE, value)
    from automated_security_helper.config.ash_config import AshConfig

    def raising(self, *args, **kwargs):
        raise ValueError(f"cannot build options from '{value}'")

    monkeypatch.setattr(AshConfig, "get_plugin_config", raising)
    code, raw = _listing(
        tmp_path,
        monkeypatch,
        "project_name: probe\nscanners:\n  bandit:\n    options:\n"
        f"      config_file: ${{{VARIABLE}}}\n",
    )

    assert code == 0, (code, raw[-1500:])
    # The control: error rows rendered at all.
    assert "Error:" in raw, raw[-3000:]
    assert value not in raw, raw[-3000:]
    assert "<value>" in raw, raw[-3000:]


def test_an_error_rows_carried_value_is_masked_without_the_config(
    tmp_path, monkeypatch
):
    """error_text is load-bearing on its own: an error can CARRY values the
    failing code read (carry_environment_values) that the config never did,
    and the row mask, built from the config's recorded values, cannot hide
    those."""
    carried = "zq7carried-5432"
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.error_text import carry_environment_values

    def raising(self, *args, **kwargs):
        error = ValueError(f"prewarm read '{carried}' and failed")
        carry_environment_values(error, [carried])
        raise error

    monkeypatch.setattr(AshConfig, "get_plugin_config", raising)
    code, raw = _listing(tmp_path, monkeypatch, "project_name: probe\n")

    assert code == 0, (code, raw[-1500:])
    # The control: error rows rendered at all.
    assert "Error:" in raw, raw[-3000:]
    assert carried not in raw, raw[-3000:]


def test_the_listing_without_the_config_column_stays_plain(tmp_path, monkeypatch):
    """The control at the other flag value: without --include-plugin-config
    the column is empty and the value never had a path into the output."""
    value = "zq7listcanary-0123"
    monkeypatch.setenv(VARIABLE, value)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(source)
    folder = tmp_path / "cfg"
    folder.mkdir()
    config = folder / "probe.ash.yaml"
    config.write_text(
        "project_name: probe\nscanners:\n  bandit:\n    options:\n"
        f"      config_file: ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app, ["plugin", "list", "--config", str(config)], env=WIDE
    )

    assert result.exit_code == 0, (result.exit_code, result.output[-1500:])
    assert value not in result.output, result.output[-3000:]
