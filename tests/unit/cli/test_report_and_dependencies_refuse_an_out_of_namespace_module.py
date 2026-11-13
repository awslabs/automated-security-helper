# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` and ``ash dependencies install`` refuse an out-of-namespace module.

Both read a config's ``ash_plugin_modules`` through ``load_plugins``, whose
refusal (PluginModuleNamespaceError) escaped these two commands uncaught: the
process ended with a traceback and exit 1, and the refusal's words reached
nobody. Each command now shows the refusal in its own invalid-configuration
form and exits 3, like ``ash plugin list``.

The entry comes from ``--config-overrides`` in list form, an operator source,
which reaches ``load_plugins`` as a scan's would.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

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


@pytest.mark.parametrize("command", ["report", "dependencies-install"])
def test_the_command_refuses_it_with_exit_3_and_imports_nothing(
    tmp_path, planted_module, monkeypatch, command
):
    import io

    from rich.console import Console

    from automated_security_helper.utils import console as console_module

    # The install's refusal goes through the global print, and CliRunner's
    # capture can miss text printed after ASH's first log record on a worker's
    # first invocation (the measured note on TestToolSelection in
    # test_dependencies_verdict.py). Pinned to a buffer this test owns, and the
    # install's bin path kept out of the real home: without --bin-path the
    # command mkdirs ~/.ash/bin and sets ASH_BIN_PATH for the whole worker
    # before the refusal runs (monkeypatch.setenv restores it either way).
    sink = io.StringIO()
    monkeypatch.setattr(
        console_module,
        "global_console",
        lambda: Console(file=sink, width=400, no_color=True),
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    if command == "report":
        args = ["report", "--config-overrides", OVERRIDE]
    else:
        args = [
            "dependencies",
            "install",
            "--config-overrides",
            OVERRIDE,
            "--bin-path",
            str(tmp_path / "bin"),
        ]

    result = CliRunner().invoke(app, args)

    output = result.output + sink.getvalue()
    assert result.exit_code == 3, (output, repr(result.exception))
    assert WORDS in output, output
    # Each command closes in its own words, not the scan's: neither scanned
    # anything either way, and neither has --ash-plugin-modules to remove.
    closing = (
        "no report was rendered" if command == "report" else ("nothing was installed")
    )
    assert closing in output, output
    assert "nothing was scanned" not in output, output
    assert "--ash-plugin-modules" not in output, output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert OUTSIDE not in sys.modules
    assert not (planted_module / f"{OUTSIDE}.imported").exists()


@pytest.mark.parametrize("command", ["report", "dependencies-install"])
def test_any_other_loading_refusal_still_exits_3(tmp_path, monkeypatch, command):
    """A plugin-loading refusal that is not about ``ash_plugin_modules`` still
    maps to exit 3 with the invalid-configuration line, not a traceback with
    exit 1: the arms above it name the module refusals to pick their closing
    words, and the trailing arm keeps every other ASHConfigValidationError on
    the exit code the type documents."""
    import io

    from rich.console import Console

    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils import console as console_module

    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    sink = io.StringIO()
    monkeypatch.setattr(
        console_module,
        "global_console",
        lambda: Console(file=sink, width=400, no_color=True),
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))

    def refuse(*args, **kwargs):
        raise ASHConfigValidationError("the-loaded-plugins-refuse-this-config")

    if command == "report":
        monkeypatch.setattr("automated_security_helper.cli.report.load_plugins", refuse)
        args = ["report"]
    else:
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.load_plugins", refuse
        )
        args = ["dependencies", "install", "--bin-path", str(tmp_path / "bin")]

    result = CliRunner().invoke(app, args)

    output = result.output + sink.getvalue()
    assert result.exit_code == 3, (output, repr(result.exception))
    assert "Invalid configuration" in output, output
    assert "the-loaded-plugins-refuse-this-config" in output, output
    assert result.exception is None or isinstance(result.exception, SystemExit)


BROKEN = "broken_ash_plugins"


@pytest.mark.parametrize("command", ["report", "dependencies-install"])
def test_the_command_refuses_a_module_that_fails_to_import_with_exit_3(
    tmp_path, monkeypatch, command
):
    """A module inside the namespace that fails to import: the loader records
    the failure and refuses it (PluginModuleImportError), and each command
    shows that in its own invalid-configuration form, closing in its own words,
    and exits 3, as for the out-of-namespace module above."""
    import io

    from rich.console import Console

    from automated_security_helper.utils import console as console_module

    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    site = tmp_path / "site"
    (site / BROKEN).mkdir(parents=True)
    (site / BROKEN / "__init__.py").write_text(
        "import ash_probe_dependency_that_is_not_installed\n", encoding="utf-8"
    )
    monkeypatch.delitem(sys.modules, BROKEN, raising=False)
    monkeypatch.syspath_prepend(str(site))
    sink = io.StringIO()
    monkeypatch.setattr(
        console_module,
        "global_console",
        lambda: Console(file=sink, width=400, no_color=True),
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    override = f'ash_plugin_modules+=["{BROKEN}"]'
    if command == "report":
        args = ["report", "--config-overrides", override]
    else:
        args = [
            "dependencies",
            "install",
            "--config-overrides",
            override,
            "--bin-path",
            str(tmp_path / "bin"),
        ]

    try:
        result = CliRunner().invoke(app, args)
    finally:
        sys.modules.pop(BROKEN, None)

    output = result.output + sink.getvalue()
    assert result.exit_code == 3, (output, repr(result.exception))
    assert "failed to import" in output, output
    closing = (
        "no report was rendered" if command == "report" else "nothing was installed"
    )
    assert closing in output.lower(), output
    assert "nothing was scanned" not in output.lower(), output
    assert result.exception is None or isinstance(result.exception, SystemExit)
