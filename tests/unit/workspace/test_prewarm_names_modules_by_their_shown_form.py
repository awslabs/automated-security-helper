# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace prewarm's module refusal names entries by their shown form.

A project config can read a plugin-module entry from the environment, and the
refusal has to name such an entry by its masked form, never by the value. The
map rides the plan (``ProjectPlan.plugin_module_names``), filled at resolution
from the project's own config; a name in no project's map, the command line's,
is named as it is. Every log line written about such an entry, from the prewarm
down through the import and discovery of the module, names it the same way.
"""

import sys

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.plugins.loader import (
    PluginModuleImportError,
    PluginModuleNamespaceError,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
)
from automated_security_helper.workspace.resolver import resolve_workspace


def test_the_refusal_masks_an_env_read_entry(tmp_path):
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = resolve_workspace(workspace_file)
    # As resolution records them for a config whose entry was read from the
    # environment: the module list holds the value, the map its masked form.
    # os.path is outside the plugin namespace, so the prewarm refuses it.
    project = plan.projects[0].model_copy(
        update={
            "ash_plugin_modules": ["os.path"],
            "plugin_module_names": {"os.path": "${PLUGIN_MODULE}"},
        }
    )
    plan = plan.model_copy(update={"projects": [project]})
    settings = ProjectScanSettings(output_dir=tmp_path / "out")

    with pytest.raises(PluginModuleNamespaceError) as refusal:
        prewarm_plugin_registry(plan, settings)

    message = str(refusal.value)
    assert "${PLUGIN_MODULE}" in message, message
    assert "os.path" not in message, message


def test_a_command_line_name_is_shown_as_it_is(tmp_path):
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = resolve_workspace(workspace_file)
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", ash_plugin_modules=("os.path",)
    )

    with pytest.raises(PluginModuleNamespaceError) as refusal:
        prewarm_plugin_registry(plan, settings)

    assert "os.path" in str(refusal.value), str(refusal.value)


#: In every entry name below. No log record may carry it, at any level.
_FROM_THE_ENVIRONMENT = "from_the_environment"


def _plan_whose_config_read(tmp_path, module):
    """A one-project plan whose config read ``module`` from the environment, as
    resolution records it: the module list holds the value, the map its masked
    form."""
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = resolve_workspace(workspace_file)
    project = plan.projects[0].model_copy(
        update={
            "ash_plugin_modules": [module],
            "plugin_module_names": {module: ENVIRONMENT_VALUE_SHOWN},
        }
    )
    return plan.model_copy(update={"projects": [project]})


def _records_naming(caplog, text):
    return [
        record.getMessage() for record in caplog.records if text in record.getMessage()
    ]


class TestARealWorkspaceRunNamesAnEnvReadEntryMasked:
    """End to end, nothing patched: a project whose config read a plugin-module
    entry from the environment is scanned, and no log record of the whole run
    carries the value -- the prewarm's lines, the import and discovery lines,
    and each project engine's own "Loading plugin modules" line alike.

    The selection names one registered scanner that the project's own config
    disables, so the run completes without starting any tool (the test
    environment's guard fails a test on any real start); the engine
    construction, where the import lines fire, happens either way.
    """

    def test_no_record_of_the_run_carries_the_value(
        self, tmp_path, caplog, monkeypatch
    ):
        from typer.testing import CliRunner

        from automated_security_helper.cli.main import app

        caplog.set_level(1, logger="ash")
        package = f"wsvalue_{_FROM_THE_ENVIRONMENT}_ash_plugins"
        # Outside the workspace root: an in-tree module is dropped by the
        # plugin-module trust rule before any import, and nothing would fire.
        site = tmp_path / "site"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.setenv("ASH_WS_CANARY", package)
        workspace_root = tmp_path / "ws"
        (workspace_root / "api").mkdir(parents=True)
        (workspace_root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
        config_dir = workspace_root / "api" / ".ash"
        config_dir.mkdir()
        (config_dir / ".ash.yaml").write_text(
            "project_name: api\n"
            "ash_plugin_modules:\n  - !ENV ${ASH_WS_CANARY}\n"
            "scanners:\n  bandit:\n    enabled: false\n",
            encoding="utf-8",
        )
        workspace_file = workspace_root / "dev.code-workspace"
        workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
        monkeypatch.chdir(workspace_root)

        try:
            result = CliRunner().invoke(
                app,
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    "dev.code-workspace",
                    "--output-dir",
                    "out",
                    "--scanners",
                    "bandit",
                ],
            )
        finally:
            sys.modules.pop(package, None)

        # The run ran: the project was scanned (whatever its verdict), so the
        # engine was built and the import lines fired.
        assert _records_naming(caplog, "Loading workspace plugin modules"), caplog.text
        assert _records_naming(caplog, "Importing additional plugin module"), (
            result.output,
            caplog.text,
        )
        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert package not in result.output, result.output


class TestEveryProjectEngineNamesTheModuleByTheRunsMap:
    """Two projects name one module: one reads it from the environment, the
    other writes it literally. The prewarm masks it from the run-wide map; each
    project's own engine then logs its import and discovery lines too, and names
    the module by the run's map, so a literal project's lines mask a name
    another project read from the environment. Within one run, a value read
    from the environment anywhere stays out of that run's output, in either
    folder order."""

    @pytest.mark.parametrize(
        "env_read_first", [True, False], ids=["env-first", "lit-first"]
    )
    def test_no_record_of_the_run_carries_the_value(
        self, tmp_path, caplog, monkeypatch, env_read_first
    ):
        from typer.testing import CliRunner

        from automated_security_helper.cli.main import app

        caplog.set_level(1, logger="ash")
        package = f"cross_{_FROM_THE_ENVIRONMENT}_ash_plugins"
        site = tmp_path / "site"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.setenv("ASH_CROSS_CANARY", package)
        root = tmp_path / "ws"
        disabled = "scanners:\n  bandit:\n    enabled: false\n"
        entries = {
            "envread": "ash_plugin_modules:\n  - !ENV ${ASH_CROSS_CANARY}\n",
            "literal": f"ash_plugin_modules:\n  - {package}\n",
        }
        for name, modules in entries.items():
            (root / name / ".ash").mkdir(parents=True)
            (root / name / "app.py").write_text("x = 1\n", encoding="utf-8")
            (root / name / ".ash" / ".ash.yaml").write_text(
                f"project_name: {name}\n{modules}{disabled}", encoding="utf-8"
            )
        order = ["envread", "literal"] if env_read_first else ["literal", "envread"]
        folders = ", ".join(f'{{"path": "{name}"}}' for name in order)
        (root / "dev.code-workspace").write_text(
            f'{{"folders": [{folders}]}}', encoding="utf-8"
        )
        monkeypatch.chdir(root)

        try:
            result = CliRunner().invoke(
                app,
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    "dev.code-workspace",
                    "--output-dir",
                    "out",
                    "--scanners",
                    "bandit",
                ],
            )
        finally:
            sys.modules.pop(package, None)

        # Both projects' engines ran their plugin loading, so their lines fired.
        assert len(_records_naming(caplog, "Loading plugin modules")) >= 2, (
            result.output,
            caplog.text,
        )
        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert package not in result.output, result.output


class TestTheUnionKeepsTheMaskedFormWhateverTheProjectOrder:
    """One name, two projects: one read it from the environment, one wrote it.

    The union labels the whole workspace's log lines, and a plain dict update
    is last-wins. The masked form wins per key, in either order, because one
    project having read the name from the environment is enough to make showing
    it a leak.
    """

    @pytest.mark.parametrize(
        "literal_last", [False, True], ids=["env-last", "lit-last"]
    )
    def test_the_masked_form_wins(self, tmp_path, caplog, literal_last):
        caplog.set_level(1, logger="ash")
        module = f"value_{_FROM_THE_ENVIRONMENT}"
        for name in ("api", "web"):
            (tmp_path / name).mkdir()
        workspace_file = tmp_path / "dev.code-workspace"
        workspace_file.write_text(
            '{"folders": [{"path": "api"}, {"path": "web"}]}', encoding="utf-8"
        )
        plan = resolve_workspace(workspace_file)
        env_read = plan.projects[0].model_copy(
            update={
                "ash_plugin_modules": [module],
                "plugin_module_names": {module: ENVIRONMENT_VALUE_SHOWN},
            }
        )
        literal = plan.projects[1].model_copy(
            update={
                "ash_plugin_modules": [module],
                "plugin_module_names": {module: module},
            }
        )
        ordered = [env_read, literal] if literal_last else [literal, env_read]
        plan = plan.model_copy(update={"projects": ordered})

        with pytest.raises(PluginModuleNamespaceError) as refusal:
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "o")
            )

        assert module not in str(refusal.value), str(refusal.value)
        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert _records_naming(caplog, "Loading workspace plugin modules"), caplog.text


class TestNoLogLineNamesAnEntryReadFromTheEnvironment:
    """The refusal names an entry a config read from the environment by its
    masked form, and so does every log line written about that entry, at every
    level: the prewarm's own, and the import and discovery lines below it, for
    an entry refused, imported, or not importable."""

    def test_a_refused_entry(self, tmp_path, caplog):
        caplog.set_level(1, logger="ash")
        # Outside the plugin namespace, so the prewarm refuses it.
        plan = _plan_whose_config_read(tmp_path, f"value_{_FROM_THE_ENVIRONMENT}")

        with pytest.raises(PluginModuleNamespaceError):
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )

        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        # Control: the line is still written, with the entry by its masked form.
        assert _records_naming(caplog, "Loading workspace plugin modules"), caplog.text

    def test_an_imported_entry(self, tmp_path, caplog, monkeypatch):
        caplog.set_level(1, logger="ash")
        package = f"value_{_FROM_THE_ENVIRONMENT}_ash_plugins"
        site = tmp_path / "site"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        plan = _plan_whose_config_read(tmp_path, package)

        try:
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )
            # Control: the package was imported, so its import and discovery
            # lines were written.
            assert package in sys.modules
        finally:
            sys.modules.pop(package, None)

        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert _records_naming(caplog, "Importing additional plugin module"), (
            caplog.text
        )

    def test_an_entry_whose_package_declares_event_handlers(
        self, tmp_path, caplog, monkeypatch
    ):
        """The loader's DEBUG line about a package's event handlers ("Found
        event handlers in ...") names an env-read entry masked too. A pin with
        its own fixture package, because no shipped package declares
        ASH_EVENT_HANDLERS and the line was otherwise never written. The
        declaration is empty: the line is written for the declaration, nothing
        is subscribed to the process-wide manager, and so nothing needs
        removing afterwards."""
        caplog.set_level(1, logger="ash")
        package = f"value_{_FROM_THE_ENVIRONMENT}_handlers_ash_plugins"
        site = tmp_path / "site"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text(
            "ASH_EVENT_HANDLERS = {}\n", encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(site))
        plan = _plan_whose_config_read(tmp_path, package)

        try:
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )
        finally:
            sys.modules.pop(package, None)

        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert _records_naming(caplog, "Found event handlers in <value>"), caplog.text

    def test_an_entry_that_does_not_import(self, tmp_path, caplog):
        caplog.set_level(1, logger="ash")
        # In the namespace, and nothing by that name exists: the import fails,
        # and its error's own text quotes the name.
        plan = _plan_whose_config_read(
            tmp_path, f"missing_{_FROM_THE_ENVIRONMENT}_ash_plugins"
        )

        with pytest.raises(PluginModuleImportError) as refused:
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )

        assert _records_naming(caplog, _FROM_THE_ENVIRONMENT) == []
        assert _records_naming(caplog, "Failed to import plugin module"), caplog.text
        # The refusal the failure now raises names the entry masked too.
        assert _FROM_THE_ENVIRONMENT not in str(refused.value), refused.value
