# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Plugin module names given on the command line, and what `ash plugin list` shows.

The defects
-----------
* ``ScanExecutionEngine`` split the config file's ``ash_plugin_modules`` entries on
  commas but took ``--ash-plugin-modules`` and ``ASH_PLUGIN_MODULES`` as given, so
  ``--ash-plugin-modules "a_ash_plugins, b_ash_plugins"`` tried to import one module
  named ``a_ash_plugins, b_ash_plugins`` and loaded neither. A workspace scan, which
  registers the modules before any project's engine runs, had the same gap, and so
  did ``ash plugin list`` for both sources.
* ``ash plugin list`` listed each package's ``ASH_SCANNERS``/``ASH_REPORTERS``/
  ``ASH_CONVERTERS`` lists, which register nothing. A decorated plugin a package did
  not list was missing from the table, and a listed class that was never registered
  was shown, although no scan would run it.

The scans and listings run in a child interpreter, with two small plugin packages
on ``sys.path``, because their decorators register into the process-wide plugin
manager.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    UV_PROBED_TOOLS,
    assert_reached_the_stand_in,
    calls_naming,
    install_stand_in_uv,
    probe_bandit_in_a_child,
    reaching_the_stand_in,
    recorded_calls,
    stand_in_env,
)

SCANNER_MODULE = textwrap.dedent(
    """
    import builtins
    from typing import Literal

    # The order the packages are imported in, for the loader test.
    builtins.__dict__.setdefault("_ASH_TEST_IMPORT_ORDER", []).append(__name__)

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_scanner_plugin
    from automated_security_helper.schemas.sarif_schema_model import SarifReport


    class {cls}Config(ScannerPluginConfigBase):
        name: Literal["{name}"] = "{name}"


    @ash_scanner_plugin
    class {cls}(ScannerPluginBase[{cls}Config]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = {cls}Config()
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
            self._pre_scan(target=target, target_type=target_type, config=config)
            self._post_scan(target=target, target_type=target_type)
            return SarifReport.model_validate(
                {{"version": "2.1.0",
                  "runs": [{{"tool": {{"driver": {{"name": "{name}"}}}}, "results": []}}]}}
            )
    """
)

# beta also lists a class it never registers, which is what the old listing showed.
BETA_EXTRA = textwrap.dedent(
    """

    class NotRegisteredScanner(ScannerPluginBase[BetaScannerConfig]):
        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError


    ASH_SCANNERS = [NotRegisteredScanner]
    """
)

DRIVER = reaching_the_stand_in(
    """
    import sys

    sys.path.insert(0, sys.argv[1])

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", *sys.argv[2:]]
    app()
    """
)


@pytest.fixture(scope="module")
def plugin_packages(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("plugin-packages")
    for package, cls, name, extra in (
        ("alpha_ash_plugins", "AlphaScanner", "alpha-scanner", ""),
        ("beta_ash_plugins", "BetaScanner", "beta-scanner", BETA_EXTRA),
    ):
        (root / package).mkdir()
        (root / package / "__init__.py").write_text(
            SCANNER_MODULE.format(cls=cls, name=name) + extra, encoding="utf-8"
        )
    return root


def _child_env(cwd: Path, extra_env=None):
    # Offline keeps uv and the selected tools off the network, and no unselected
    # scanner asks uv about its tool: the stand-in uv, first on PATH and reached
    # through DRIVER, records any call in <cwd>/uv-stand-in/uv.log (see the scan
    # test below).
    bin_dir, log = install_stand_in_uv(cwd / "uv-stand-in")
    env = stand_in_env(bin_dir, log, dict(os.environ))
    env.pop("ASH_PLUGIN_MODULES", None)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "250"})
    env.update(extra_env or {})
    return env


def _ash(packages: Path, args, cwd: Path, extra_env=None):
    return subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
            str(packages),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=_child_env(cwd, extra_env),
        cwd=cwd,
    )


def _scan(packages: Path, tmp_path: Path, plugin_args, extra_env=None):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    completed = _ash(
        packages,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--scanners",
            "alpha-scanner",
            "--scanners",
            "beta-scanner",
            "--no-progress",
            *plugin_args,
        ],
        cwd=tmp_path,
        extra_env=extra_env,
    )
    results_file = output / "ash_aggregated_results.json"
    assert results_file.is_file(), completed.stdout[-4000:] + completed.stderr[-4000:]
    rows = json.loads(results_file.read_text(encoding="utf-8"))["scanner_results"]
    return completed, rows


def test_a_comma_list_in_the_flag_loads_each_module(plugin_packages, tmp_path):
    completed, rows = _scan(
        plugin_packages,
        tmp_path,
        ["--ash-plugin-modules", "alpha_ash_plugins, beta_ash_plugins"],
    )

    assert completed.returncode == 0, completed.stdout[-4000:]
    assert rows["alpha-scanner"]["status"] == "PASSED", rows.get("alpha-scanner")
    assert rows["beta-scanner"]["status"] == "PASSED", rows.get("beta-scanner")
    # The built-in scanners are constructed but not selected, so none of them asks
    # uv about its tool, and the child did reach the stand-in that would record it.
    calls = recorded_calls(tmp_path / "uv-stand-in" / "uv.log")
    assert_reached_the_stand_in(calls)
    assert calls_naming(calls, UV_PROBED_TOOLS) == [], calls


@pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in uv is a POSIX shell script"
)
def test_the_stand_in_uv_records_a_probe_under_the_scan_environment(tmp_path):
    """Control: a probing scanner, in the scan's environment, lands in the log.

    So the empty log above means no scanner asked, not that ASH found some other uv.
    """
    completed = probe_bandit_in_a_child(_child_env(tmp_path), tmp_path)

    assert completed.returncode == 0, completed.stderr[-4000:]
    calls = recorded_calls(tmp_path / "uv-stand-in" / "uv.log")
    assert calls_naming(calls, ["bandit"]), calls


def test_a_comma_list_in_the_environment_loads_each_module(plugin_packages, tmp_path):
    completed, rows = _scan(
        plugin_packages,
        tmp_path,
        [],
        extra_env={"ASH_PLUGIN_MODULES": "alpha_ash_plugins, beta_ash_plugins"},
    )

    assert completed.returncode == 0, completed.stdout[-4000:]
    assert rows["alpha-scanner"]["status"] == "PASSED", rows.get("alpha-scanner")
    assert rows["beta-scanner"]["status"] == "PASSED", rows.get("beta-scanner")


def test_a_comma_list_in_the_flag_loads_each_module_in_a_workspace_scan(
    plugin_packages, tmp_path
):
    """Workspace mode registers the modules before any project's engine runs.

    ``prewarm_plugin_registry`` loads them once for every project and resolves the
    registry, so a name it cannot import is missing for the whole run, whatever the
    engine does later.
    """
    root = tmp_path / "workspace"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
    output = tmp_path / "out"

    completed = _ash(
        plugin_packages,
        [
            "scan",
            "--workspace",
            str(workspace_file),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--scanners",
            "alpha-scanner",
            "--scanners",
            "beta-scanner",
            "--no-progress",
            "--ash-plugin-modules",
            "alpha_ash_plugins, beta_ash_plugins",
        ],
        cwd=root,
    )

    results = sorted(output.glob("projects/*/ash_aggregated_results.json"))
    assert len(results) == 1, completed.stdout[-4000:] + completed.stderr[-4000:]
    rows = json.loads(results[0].read_text(encoding="utf-8"))["scanner_results"]
    assert completed.returncode == 0, completed.stdout[-4000:]
    assert rows["alpha-scanner"]["status"] == "PASSED", rows.get("alpha-scanner")
    assert rows["beta-scanner"]["status"] == "PASSED", rows.get("beta-scanner")


def test_a_module_outside_the_namespace_refuses_a_workspace_scan(
    plugin_packages, tmp_path
):
    """A workspace scan with a module outside the namespace exits 3 with the
    refusal and writes no project results. The pre-warm checks the modules
    before any project runs (workspace/execution.prewarm_plugin_registry), and
    each project's engine refuses the same way behind it: measured, the run
    still exits 3 with the pre-warm's check disabled, and accepts only when
    refuse_plugin_modules_outside_namespace itself is disabled."""
    root = tmp_path / "workspace"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
    output = tmp_path / "out"

    completed = _ash(
        plugin_packages,
        [
            "scan",
            "--workspace",
            str(workspace_file),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--no-progress",
            "--ash-plugin-modules",
            "outside_module",
        ],
        cwd=root,
    )

    streams = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, streams[-2000:]
    assert "is not a plugin module ASH imports" in streams, streams[-2000:]
    assert not list(output.glob("projects/*/ash_aggregated_results.json")), streams[
        -2000:
    ]


def test_the_engine_splits_and_strips_names_from_both_sources(monkeypatch, tmp_path):
    """In-process, for the Python API: CLI names first, then the config's, once each."""
    from automated_security_helper.core import execution_engine
    from automated_security_helper.plugins import loader

    loaded: list = []
    monkeypatch.setattr(
        loader,
        "load_additional_plugin_modules",
        lambda modules, shown=None, record=None, values=(): loaded.append(modules),
    )
    monkeypatch.setattr(execution_engine, "discover_plugins", lambda **kwargs: None)
    context = MagicMock()
    context.config = AshConfig(
        project_name="plugin-lists",
        ash_plugin_modules=["gamma_ash_plugins, alpha_ash_plugins"],
    )
    context.source_dir = tmp_path
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "work"

    execution_engine.ScanExecutionEngine(
        context=context,
        ash_plugin_modules=[" alpha_ash_plugins ,beta_ash_plugins"],
        asharp_model=MagicMock(),
    )

    assert loaded == [["alpha_ash_plugins", "beta_ash_plugins", "gamma_ash_plugins"]]


LOAD_PLUGINS_DRIVER = textwrap.dedent(
    """
    import builtins, json, logging, sys
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugins.loader import load_plugins
    from automated_security_helper.utils.log import ASH_LOGGER


    class Warnings(logging.Handler):
        def __init__(self):
            super().__init__(level=logging.WARNING)
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())


    warnings = Warnings()
    ASH_LOGGER.addHandler(warnings)
    work = Path(sys.argv[2])
    context = PluginContext(
        source_dir=work,
        output_dir=work / "out",
        config=AshConfig(project_name="plugin-lists", ash_plugin_modules=[sys.argv[3]]),
    )
    load_plugins(plugin_context=context)
    if len(sys.argv) > 4 and sys.argv[4]:
        # The tolerant path: a direct load warns and records a failed import
        # rather than refusing, for a caller loading its own fixed list.
        from automated_security_helper.plugins.loader import (
            load_additional_plugin_modules,
        )

        load_additional_plugin_modules([sys.argv[4]])
    print(json.dumps({
        "imported": getattr(builtins, "_ASH_TEST_IMPORT_ORDER", []),
        "warnings": warnings.messages,
    }))
    """
)


def _load_plugins(plugin_packages, tmp_path, entry, direct=""):
    """load_plugins in a child, with ``entry`` as the config's one module entry.

    ``direct`` is handed to a bare ``load_additional_plugin_modules`` call
    afterwards: the tolerant path a configured entry no longer takes.
    """
    env = dict(os.environ)
    env.pop("ASH_PLUGIN_MODULES", None)
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(LOAD_PLUGINS_DRIVER),
            str(plugin_packages),
            str(tmp_path),
            entry,
            direct,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_load_plugins_imports_each_module_of_a_comma_list_in_order(
    plugin_packages, tmp_path
):
    """The path `ash report`, `ash dependencies install` and `ash merge` load through.

    load_plugins hands the config's entries to load_additional_plugin_modules, which
    imported each entry whole: "beta_ash_plugins, alpha_ash_plugins" was one module
    that does not exist, and neither package loaded.
    """
    loaded = _load_plugins(
        plugin_packages, tmp_path, "beta_ash_plugins, alpha_ash_plugins"
    )

    assert loaded["imported"] == ["beta_ash_plugins", "alpha_ash_plugins"], loaded


def test_load_plugins_drops_the_empty_names_of_a_doubled_or_trailing_comma(
    plugin_packages, tmp_path
):
    """An empty name is neither imported nor refused: it was never a module name."""
    loaded = _load_plugins(
        plugin_packages, tmp_path, "beta_ash_plugins,,alpha_ash_plugins, ,"
    )

    assert loaded["imported"] == ["beta_ash_plugins", "alpha_ash_plugins"], loaded
    assert loaded["warnings"] == [], loaded["warnings"]


def test_the_warnings_recorder_sees_a_failed_import(plugin_packages, tmp_path):
    """Control: the empty warnings list above is the loader's, not a deaf recorder.

    A configured module that fails to import now refuses the run
    (PluginModuleImportError), like a name outside the namespace, so the
    warning this control listens for comes from the tolerant direct load: the
    path a caller with its own fixed list (the vendored inventory) still takes.
    """
    loaded = _load_plugins(
        plugin_packages, tmp_path, "beta_ash_plugins", direct="ghost_ash_plugins"
    )

    assert loaded["imported"] == ["beta_ash_plugins"], loaded
    assert any("ghost_ash_plugins" in message for message in loaded["warnings"]), loaded


def test_split_plugin_modules_drops_empty_and_repeated_names():
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    assert split_plugin_modules(
        ["beta_ash_plugins, ,alpha_ash_plugins,", None, "", ",", "beta_ash_plugins"]
    ) == ["beta_ash_plugins", "alpha_ash_plugins"]


def test_plugin_list_shows_what_is_registered(plugin_packages, tmp_path):
    completed = _ash(
        plugin_packages,
        [
            "plugin",
            "list",
            "--ash-plugin-modules",
            "alpha_ash_plugins, beta_ash_plugins",
        ],
        cwd=tmp_path,
    )

    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-2000:]
    )
    # Registered by their decorators, though neither package lists them.
    assert "AlphaScanner" in completed.stdout, completed.stdout[-4000:]
    assert "BetaScanner" in completed.stdout, completed.stdout[-4000:]
    # Listed in ASH_SCANNERS, never registered: no scan runs it.
    assert "NotRegisteredScanner" not in completed.stdout
    # The built-in scanners are still there, in the order the package lists them.
    assert "BanditScanner" in completed.stdout
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    names = [cls.__name__ for cls in ASH_SCANNERS]
    positions = [re.search(rf"\b{name}\b", completed.stdout).start() for name in names]
    assert positions == sorted(positions), [
        name for _, name in sorted(zip(positions, names))
    ]
