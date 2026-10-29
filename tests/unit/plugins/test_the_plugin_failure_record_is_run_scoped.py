# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin import-failure record belongs to one run, not to the process.

A process-wide record poisons every later run in the same interpreter, and the
MCP server runs many scans in one process: a scan whose configured module
failed leaves its failure behind, so a later scan with a clean config reports
an error it never had (and the failed module's name, which can come from the
environment, lands in that run's results); a rerun after the operator installs
the missing dependency still refuses on the stale record; and the vendored
inventory's tolerant load leaks its own failures into scans that never named
the module.

Each cell runs TWO runs in ONE child interpreter: one process for both runs is
the defect's shape, and a child keeps the plugin registrations out of this
process. The runs select the planted good scanner, which runs in-process, so
no real tool starts either way.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    install_stand_in_uv,
    reaching_the_stand_in,
    stand_in_env,
)

pytestmark = pytest.mark.integration

DEPENDENCY = "runscopedep_for_record"
BROKEN_PACKAGE = "runscope_ash_plugins"
INVENTORY_GHOST = "runscope_ghost_ash_plugins"
#: Installed between the runs into a directory that did not exist at start.
LATE_PACKAGE = "runscopelate_ash_plugins"

GOOD_PACKAGE_SOURCE = textwrap.dedent(
    """
    from typing import Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_scanner_plugin
    from automated_security_helper.schemas.sarif_schema_model import SarifReport


    class GoodScannerConfig(ScannerPluginConfigBase):
        name: Literal["good-scanner"] = "good-scanner"


    @ash_scanner_plugin
    class GoodScanner(ScannerPluginBase[GoodScannerConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = GoodScannerConfig()
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
            self._pre_scan(target=target, target_type=target_type, config=config)
            self._post_scan(target=target, target_type=target_type)
            return SarifReport.model_validate(
                {"version": "2.1.0",
                 "runs": [{"tool": {"driver": {"name": "good-scanner"}},
                           "results": []}]}
            )
    """
)

#: The child: two scans in one interpreter. argv[2]=layout dir; argv[3]=mode
#: ("rerun" plants the dependency between the runs, "clean" switches to the
#: clean config, "inventory" does a tolerant direct load then one clean scan).
DRIVER = reaching_the_stand_in(
    """
    import json
    import sys
    from pathlib import Path

    layout = Path(sys.argv[2])
    mode = sys.argv[3]
    sys.path.insert(0, str(layout / "modules"))
    # A site directory that does not exist yet: the import system caches the
    # miss, which is the "lateinstall" mode's point.
    sys.path.insert(1, str(layout / "modules-late"))

    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app


    def scan(config_name, out_name):
        return CliRunner().invoke(
            app,
            [
                "scan", "--mode", "local", "--no-progress",
                "--source-dir", str(layout / "src"),
                "--output-dir", str(layout / out_name),
                "--config", str(layout / config_name),
                "--scanners", "good-scanner",
            ],
        )


    def load_errors(out_name):
        results = layout / out_name / "ash_aggregated_results.json"
        if not results.is_file():
            return None
        return json.loads(results.read_text(encoding="utf-8"))["metadata"][
            "plugin_load_errors"
        ]


    if mode == "inventory":
        from automated_security_helper.plugins.loader import (
            load_additional_plugin_modules,
        )

        load_additional_plugin_modules(["{INVENTORY_GHOST}"])
        second = scan("clean.yaml", "out2")
        first_exit = None
    elif mode == "lateinstall":
        first = scan("late.yaml", "out1")
        first_exit = first.exit_code
        late = layout / "modules-late" / "{LATE_PACKAGE}"
        late.mkdir(parents=True)
        (late / "__init__.py").write_text("ASH_REPORTERS = []", encoding="utf-8")
        second = scan("late.yaml", "out2")
    else:
        first = scan("broken.yaml", "out1")
        first_exit = first.exit_code
        if mode == "rerun":
            (layout / "modules" / "{DEPENDENCY}.py").write_text(
                "", encoding="utf-8"
            )
            second = scan("broken.yaml", "out2")
        else:
            second = scan("clean.yaml", "out2")

    print(json.dumps({
        "first_exit": first_exit,
        "second_exit": second.exit_code,
        "second_errors": load_errors("out2"),
        "second_mentions_module": "{BROKEN_PACKAGE}" in second.output
        or "{INVENTORY_GHOST}" in second.output,
    }))
    """.replace("{LATE_PACKAGE}", LATE_PACKAGE)
    .replace("{INVENTORY_GHOST}", INVENTORY_GHOST)
    .replace("{DEPENDENCY}", DEPENDENCY)
    .replace("{BROKEN_PACKAGE}", BROKEN_PACKAGE)
)


@pytest.fixture
def layout(tmp_path) -> Path:
    modules = tmp_path / "modules"
    (modules / BROKEN_PACKAGE).mkdir(parents=True)
    (modules / BROKEN_PACKAGE / "__init__.py").write_text(
        f"import {DEPENDENCY}  # noqa: F401\nASH_REPORTERS = []\n",
        encoding="utf-8",
    )
    (modules / "good_ash_plugins").mkdir()
    (modules / "good_ash_plugins" / "__init__.py").write_text(
        GOOD_PACKAGE_SOURCE, encoding="utf-8"
    )
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.yaml").write_text(
        "project_name: demo\n"
        f"ash_plugin_modules:\n  - good_ash_plugins\n  - {BROKEN_PACKAGE}\n",
        encoding="utf-8",
    )
    (tmp_path / "clean.yaml").write_text(
        "project_name: demo\nash_plugin_modules:\n  - good_ash_plugins\n",
        encoding="utf-8",
    )
    (tmp_path / "late.yaml").write_text(
        "project_name: demo\n"
        f"ash_plugin_modules:\n  - good_ash_plugins\n  - {LATE_PACKAGE}\n",
        encoding="utf-8",
    )
    return tmp_path


def _run(layout: Path, mode: str) -> dict:
    bin_dir, log = install_stand_in_uv(layout / "uv-stand-in")
    env = stand_in_env(bin_dir, log, dict(os.environ))
    env.pop("ASH_PLUGIN_MODULES", None)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "250"})
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
            str(layout / "modules"),
            str(layout),
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=layout,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_rerun_after_the_dependency_is_installed_scans(layout):
    """The operator installs what the module needs and runs again in the same
    process: the module imports now, so the rerun scans instead of refusing on
    a stale record."""
    outcome = _run(layout, "rerun")

    assert outcome["first_exit"] == 3, outcome
    assert outcome["second_exit"] == 0, outcome


def test_a_clean_runs_results_carry_no_earlier_runs_failure(layout):
    """A later run with a clean config inherits nothing: its results record no
    load error and never name a module its configuration did not."""
    outcome = _run(layout, "clean")

    assert outcome["first_exit"] == 3, outcome
    assert outcome["second_exit"] == 0, outcome
    assert outcome["second_errors"] == {}, outcome
    assert not outcome["second_mentions_module"], outcome


def test_a_module_installed_into_a_new_directory_is_found_on_rerun(layout):
    """The rerun promise holds for a site directory that did not exist when
    the interpreter started: the import system caches the miss for a sys.path
    entry it could not read, so without invalidating the caches a module
    installed there is never found and the rerun keeps refusing."""
    outcome = _run(layout, "lateinstall")

    assert outcome["first_exit"] == 3, outcome
    assert outcome["second_exit"] == 0, outcome


def test_the_inventorys_tolerant_load_leaks_into_no_scan(layout):
    """The vendored inventory loads its own fixed list and tolerates a failure;
    that failure is the inventory's, and a scan in the same process that never
    named the module must not report it."""
    outcome = _run(layout, "inventory")

    assert outcome["second_exit"] == 0, outcome
    assert outcome["second_errors"] == {}, outcome
    assert not outcome["second_mentions_module"], outcome
