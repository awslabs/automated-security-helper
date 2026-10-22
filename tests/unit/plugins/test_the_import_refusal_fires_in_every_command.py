# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every command that loads a config's plugin modules refuses an import failure.

``ash report``, ``ash dependencies install`` and ``ash plugin list`` each load
the configuration's plugin modules through ``load_plugins``; a configured
module that fails to import refuses each of them with exit 3 and the refusal's
composed text, as the scan is refused. These cells exist because each command's
wiring is its own: removing the load (or its refusal) from any one of them
breaks no scan cell.

The broken package imports a dependency that does not exist, so the import
fails and nothing registers in this process; the cells run in-process.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

BROKEN = "cmdbroken_ash_plugins"
DEPENDENCY = "cmdbrokendep_for_refusal"

#: The refusal's composed text, which only refuse_failed_plugin_imports writes.
REFUSAL = f"ash_plugin_modules names '{BROKEN}'"


@pytest.fixture
def broken_config(tmp_path, monkeypatch):
    """A config naming the broken module, with the cwd inside an empty source
    tree so nothing else is picked up."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    modules = tmp_path / "modules"
    (modules / BROKEN).mkdir(parents=True)
    (modules / BROKEN / "__init__.py").write_text(
        f"import {DEPENDENCY}  # noqa: F401\nASH_REPORTERS = []\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, BROKEN, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        f"project_name: probe\nash_plugin_modules:\n  - {BROKEN}\n", encoding="utf-8"
    )
    yield config_file
    sys.modules.pop(BROKEN, None)


def _streams(result) -> str:
    try:
        stderr = result.stderr
    except ValueError:
        stderr = ""
    return " ".join((result.output + stderr).split())


def test_report_refuses(tmp_path, broken_config):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results_dir = tmp_path / "src" / ".ash" / "ash_output"
    results_dir.mkdir(parents=True)
    (results_dir / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(), encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["report", "--config", str(broken_config)])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert REFUSAL in output, output[-2000:]
    assert "No report was rendered" in output, output[-2000:]


def test_dependencies_install_refuses(tmp_path, broken_config, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))

    # --tool nonexistent: the plugins load first, so the healthy path refuses
    # the import with exit 3 before the name is read; a path that lost the load
    # rejects the unknown name right after it, before any install can start.
    result = CliRunner().invoke(
        app,
        [
            "dependencies",
            "install",
            "--config",
            str(broken_config),
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "nonexistent",
        ],
    )

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert REFUSAL in output, output[-2000:]
    assert "Nothing was installed" in output, output[-2000:]


@pytest.fixture
def bare_project(tmp_path, monkeypatch):
    """A cwd with no config file, so an overrides-only refusal reaches the
    printer raw rather than through the file check."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    return source


def test_config_get_gives_an_override_namespace_refusal_its_own_words(bare_project):
    """With no config file, `config get --config-overrides` printed str(error),
    the scan's closing: a run this command does not make, and option spellings
    it does not take."""
    result = CliRunner().invoke(
        app,
        ["config", "get", "--config-overrides", 'ash_plugin_modules+=["wsgiref"]'],
    )

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "Nothing was imported" in output, output[-2000:]
    # Case-insensitive: this refusal's scan closing says "Nothing was imported
    # and nothing was scanned", so the capital-N absence could never fail on
    # the defect it guards (and the positive assert above is satisfied by the
    # defect form too; only together with this one does the pair discriminate).
    assert "nothing was scanned" not in output.lower(), output[-2000:]
    assert "ASH_PLUGIN_MODULES" not in output, output[-2000:]


def test_config_get_gives_an_override_import_refusal_its_own_words(bare_project):
    result = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config-overrides",
            'ash_plugin_modules+=["absent_ash_plugins"]',
        ],
    )

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "Nothing was imported" in output, output[-2000:]
    # Case-insensitive, as above: one absence wording for both refusal arms.
    assert "nothing was scanned" not in output.lower(), output[-2000:]
    assert "ASH_PLUGIN_MODULES" not in output, output[-2000:]


def test_config_validate_without_a_file_keeps_its_exit_for_a_bare_call(bare_project):
    """The control: with no config file and no --config-overrides there is
    nothing to validate, and the command keeps saying so with exit 1."""
    result = CliRunner().invoke(app, ["config", "validate"])

    output = _streams(result)
    assert result.exit_code == 1, (result.exit_code, output[-2000:])
    assert "No config file found" in output, output[-2000:]


@pytest.mark.parametrize(
    "entry", ["wsgiref", "absent_ash_plugins"], ids=["namespace", "unfindable"]
)
def test_config_validate_with_overrides_and_no_file_agrees_with_get(
    bare_project, entry
):
    """A scan given --config-overrides and no config file runs on the defaults
    with the overrides applied, and `config get` refuses this same input with
    exit 3: `config validate` answering exit 1 without checking the overrides
    judged a different question. The overrides-only invocation validates the
    effective config through the same resolution path get uses."""
    override = f'ash_plugin_modules+=["{entry}"]'
    refused = CliRunner().invoke(app, ["config", "get", "--config-overrides", override])
    if refused.exit_code != 3:
        raise RuntimeError(
            ("control: get did not refuse the override", refused.exit_code)
        )

    result = CliRunner().invoke(
        app, ["config", "validate", "--config-overrides", override]
    )

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "Nothing was imported" in output, output[-2000:]
    assert "No config file found" not in output, output[-2000:]


def test_config_validate_judges_an_env_named_module_beside_a_file(
    tmp_path, bare_project, monkeypatch
):
    """ASH_PLUGIN_MODULES is a scan input (the scan option's envvar), so a
    validate that ignores it prints "A scan accepts it" about a configuration
    the scan refuses with exit 3."""
    config = tmp_path / "env-beside-file.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "wsgiref")

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "wsgiref" in output, output[-2000:]


def test_config_validate_judges_an_env_named_module_with_no_file(
    bare_project, monkeypatch
):
    """With no config file, an environment-named module is still what a scan
    of this directory runs with, so there is something to judge."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "absent_ash_plugins")

    result = CliRunner().invoke(app, ["config", "validate"])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "No config file found" not in output, output[-2000:]


def test_config_get_judges_an_env_named_module(bare_project, monkeypatch):
    """get refuses the same scan inputs validate refuses: a configuration it
    prints as usable while a scan refuses it misleads the operator."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "wsgiref")

    result = CliRunner().invoke(app, ["config", "get"])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])


def test_config_validate_accepts_a_valid_env_named_module(
    tmp_path, bare_project, monkeypatch
):
    """The control against over-refusal: an environment-named module the
    checks accept (in the namespace, findable) leaves validate at exit 0."""
    site = tmp_path / "site"
    (site / "envok_ash_plugins").mkdir(parents=True)
    (site / "envok_ash_plugins" / "__init__.py").write_text(
        "ASH_REPORTERS = []\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, "envok_ash_plugins", raising=False)
    config = tmp_path / "env-valid.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "envok_ash_plugins")

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    output = _streams(result)
    assert result.exit_code == 0, (result.exit_code, output[-2000:])


def test_config_validate_with_valid_overrides_and_no_file_succeeds(bare_project):
    """The positive half: valid overrides over the defaults are the config a
    scan runs with, so validate accepts them with exit 0 rather than
    reporting there is nothing to check."""
    result = CliRunner().invoke(
        app, ["config", "validate", "--config-overrides", "fail_on_findings=false"]
    )

    output = _streams(result)
    assert result.exit_code == 0, (result.exit_code, output[-2000:])
    assert "Configuration is valid" in output, output[-2000:]


REGISTER_BAD = "cmdregister_ash_plugins"
#: Only the registration refusal says this.
REGISTER_NAMING = "could not be registered"
IMPORT_ADVICE = "Install what the module needs"
REGISTER_ADVICE = "Fix the module's ASH_EVENT_HANDLERS or ASH_* lists"


@pytest.fixture
def register_failing_config(tmp_path, monkeypatch):
    """A config naming a module that imports but cannot register. Each
    command's closing has to carry the register stage's own advice: telling
    the operator to install what the module needs points at dependencies that
    are not the problem, when the loss is in what the module declares."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    modules = tmp_path / "modules"
    (modules / REGISTER_BAD).mkdir(parents=True)
    (modules / REGISTER_BAD / "__init__.py").write_text(
        "ASH_SCANNERS = 'not-a-list'\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, REGISTER_BAD, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        f"project_name: probe\nash_plugin_modules:\n  - {REGISTER_BAD}\n",
        encoding="utf-8",
    )
    yield config_file
    sys.modules.pop(REGISTER_BAD, None)


def _declaration_advice(result, output):
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    if REGISTER_NAMING not in output:
        raise RuntimeError(("control: not the registration refusal", output[-2000:]))
    assert IMPORT_ADVICE not in output, output[-2000:]
    assert REGISTER_ADVICE in output, output[-2000:]


def test_plugin_list_gives_a_registration_refusal_the_declaration_advice(
    register_failing_config,
):
    result = CliRunner().invoke(
        app, ["plugin", "list", "--config", str(register_failing_config)]
    )

    output = _streams(result)
    _declaration_advice(result, output)
    assert "Nothing was listed" in output, output[-2000:]


def test_report_gives_a_registration_refusal_the_declaration_advice(
    tmp_path, register_failing_config
):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results_dir = tmp_path / "src" / ".ash" / "ash_output"
    results_dir.mkdir(parents=True)
    (results_dir / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(), encoding="utf-8"
    )

    result = CliRunner().invoke(
        app, ["report", "--config", str(register_failing_config)]
    )

    output = _streams(result)
    _declaration_advice(result, output)
    assert "No report was rendered" in output, output[-2000:]


def test_dependencies_install_gives_a_registration_refusal_the_declaration_advice(
    tmp_path, register_failing_config, monkeypatch
):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))

    result = CliRunner().invoke(
        app,
        [
            "dependencies",
            "install",
            "--config",
            str(register_failing_config),
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "nonexistent",
        ],
    )

    output = _streams(result)
    _declaration_advice(result, output)
    assert "Nothing was installed" in output, output[-2000:]


def test_merge_gives_a_registration_refusal_the_declaration_advice(
    tmp_path, register_failing_config
):
    from tests.unit.cli.test_merge import build_shards, write_shards

    args = ["merge"]
    for path in write_shards(tmp_path / "artifacts", build_shards(2)):
        args += ["--results", path]
    args += [
        "--output-dir",
        str(tmp_path / "merged"),
        "--no-color",
        "--config",
        str(register_failing_config),
    ]

    result = CliRunner().invoke(app, args)

    output = _streams(result)
    _declaration_advice(result, output)
    assert "Nothing was merged" in output, output[-2000:]


def test_plugin_list_gives_a_namespace_entry_the_namespace_advice(
    tmp_path, monkeypatch
):
    """A namespace refusal keeps its own advice in the listing: catching it as
    a plain import failure told the operator to install what a standard-library
    module needs instead of naming the packages inside the entry. report,
    merge and dependencies each keep this separate arm already."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "ns.yaml"
    config_file.write_text(
        "project_name: probe\nash_plugin_modules:\n  - wsgiref\n", encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(config_file)])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert "Nothing was listed" in output, output[-2000:]
    assert "Install what the module needs" not in output, output[-2000:]


def test_plugin_list_refuses(broken_config):
    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(broken_config)])

    output = _streams(result)
    assert result.exit_code == 3, (result.exit_code, output[-2000:])
    assert REFUSAL in output, output[-2000:]
    assert "Invalid configuration" in output, output[-2000:]
    # In the listing's own closing words: the scan's closing ("nothing was
    # scanned" in either casing, ASH_PLUGIN_MODULES) describes a run this
    # command does not make and an option spelling it does not take.
    assert "Nothing was listed" in output, output[-2000:]
    assert "nothing was scanned" not in output.lower(), output[-2000:]
