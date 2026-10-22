# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config get`` refuses an out-of-namespace module in its own words.

With no config file to check, the command's invalid-configuration printer
shows the raised refusal verbatim, and that refusal carried the scan's
closing sentences: they say nothing was scanned and name options
(``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``) this command does not
have. The command's own check (``refuse_plugin_modules_a_scan_refuses``)
now closes in words that fit a configuration check instead.

The entry comes from ``--config-overrides`` in list form, an operator
source, which reaches the loader's judgment as a scan's would. No config
file exists anywhere under the working directory, so the printer has no
file to re-check and the exception's own text is what the operator reads.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

WORDS = "is not a plugin module ASH imports"

OUTSIDE = "outside_module"
OVERRIDE = f'ash_plugin_modules+=["{OUTSIDE}"]'


@pytest.fixture
def planted_module(tmp_path, monkeypatch):
    """An importable module on sys.path that writes a marker when imported."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    modules = tmp_path / "modules"
    modules.mkdir()
    (modules / f"{OUTSIDE}.py").write_text(
        "from pathlib import Path\n"
        "Path(__file__).with_suffix('.imported').write_text('ran')\n"
    )
    monkeypatch.delitem(sys.modules, OUTSIDE, raising=False)
    monkeypatch.syspath_prepend(str(modules))
    yield modules
    sys.modules.pop(OUTSIDE, None)


@pytest.mark.parametrize("entry_source", ["config-file", "overrides"])
def test_with_a_config_file_present_the_refusal_closes_in_the_commands_words(
    tmp_path, planted_module, entry_source
):
    """The common case: a config file exists, so the invalid-configuration
    printer re-checks it and printed the validator's message, whose namespace
    closing offers only the config file - wrong when the entry came from
    --config-overrides, which these commands take. The raised refusal is the
    whole verdict, so the printer closes it in the commands' own words, which
    name both removal routes, whichever source held the entry."""
    # The scanned tree is a subdirectory, so the config file and the planted
    # module sit outside it: an in-tree config entry that resolves in-tree is
    # ignored with a warning rather than refused, which is another cell's
    # contract.
    source = planted_module.parent / "src"
    source.mkdir()
    config_path = planted_module.parent / ".ash.yaml"
    if entry_source == "config-file":
        config_path.write_text(
            f"project_name: demo\nash_plugin_modules:\n  - {OUTSIDE}\n",
            encoding="utf-8",
        )
        arguments = [
            "config",
            "get",
            "--config",
            str(config_path),
            "--source-dir",
            str(source),
        ]
    else:
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        arguments = [
            "config",
            "get",
            "--config",
            str(config_path),
            "--source-dir",
            str(source),
            "--config-overrides",
            OVERRIDE,
        ]

    result = CliRunner().invoke(app, arguments)

    output = result.output
    assert result.exit_code == 3, (output, repr(result.exception))
    assert WORDS in output, output
    assert "Nothing was imported" in output, output
    # The commands' closing, not the validator's: both removal routes named.
    assert "remove the entry from the config file or --config-overrides" in output, (
        output
    )
    assert "nothing was scanned" not in output, output
    assert "--ash-plugin-modules" not in output, output
    assert OUTSIDE not in sys.modules
    assert not (planted_module / f"{OUTSIDE}.imported").exists()


def test_config_get_refuses_it_with_exit_3_and_imports_nothing(
    tmp_path, planted_module, monkeypatch
):
    import io

    from rich.console import Console

    from automated_security_helper.utils import console as console_module

    # Pinned to a buffer this test owns, like the report/dependencies cells:
    # CliRunner's capture can miss text printed through the global console
    # after ASH's first log record on a worker's first invocation.
    sink = io.StringIO()
    monkeypatch.setattr(
        console_module,
        "global_console",
        lambda: Console(file=sink, width=400, no_color=True),
    )

    result = CliRunner().invoke(app, ["config", "get", "--config-overrides", OVERRIDE])

    output = result.output + sink.getvalue()
    assert result.exit_code == 3, (output, repr(result.exception))
    assert WORDS in output, output
    # The command closes in its own words, not the scan's: it checked a
    # configuration, scanned nothing either way, and has no
    # --ash-plugin-modules to remove an entry from.
    assert "Nothing was imported" in output, output
    assert "nothing was scanned" not in output, output
    assert "--ash-plugin-modules" not in output, output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert OUTSIDE not in sys.modules
    assert not (planted_module / f"{OUTSIDE}.imported").exists()
