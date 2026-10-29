# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configured plugin module that fails to import refuses the scan with exit 3.

A module the configuration names (``ash_plugin_modules``), or whose scanner the
config enables by name, that raises on import refuses the scan with exit 3,
naming the module, before any scanner runs. Importing nothing of what the
operator configured is the same class of defect as an entry outside the plugin
namespace, so it gets the same answer: a named refusal and exit 3, before any
scanner runs.

The broken package raises ImportError from its ``__init__`` (a missing
dependency); the control plants the dependency and shows the same scanner
running. The scans run in a child interpreter because plugin decorators
register into the process-wide manager.

The default-selection cell disables every built-in scanner in its config, so
the run selects nothing even in the fail-open state and no cell can start a
real tool. (An earlier revision claimed a default-selection cell necessarily
starts real tools; that holds only with the built-ins left enabled, which was
the measured shape -- the tool guard caught syft and grype -- not a property
of default selection.)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.helpers import builtin_scanner_config_names, importing_this_checkout
from tests.utils.stand_in_uv import (
    install_stand_in_uv,
    reaching_the_stand_in,
    stand_in_env,
)

pytestmark = pytest.mark.integration

#: The missing dependency the broken package imports; the control plants it.
DEPENDENCY = "brokendep_for_import_refusal"

BROKEN_PACKAGE = "broken_ash_plugins"

PACKAGE_SOURCE = textwrap.dedent(
    f"""
    import {DEPENDENCY}  # noqa: F401 - the dependency this plugin needs
    from typing import Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_scanner_plugin
    from automated_security_helper.schemas.sarif_schema_model import SarifReport


    class BrokenDepScannerConfig(ScannerPluginConfigBase):
        name: Literal["brokendep-scanner"] = "brokendep-scanner"


    @ash_scanner_plugin
    class BrokenDepScanner(ScannerPluginBase[BrokenDepScannerConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = BrokenDepScannerConfig()
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
                  "runs": [{{"tool": {{"driver": {{"name": "brokendep-scanner"}}}},
                             "results": []}}]}}
            )
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


@pytest.fixture
def plugin_packages(tmp_path) -> Path:
    root = tmp_path / "plugin-packages"
    (root / BROKEN_PACKAGE).mkdir(parents=True)
    (root / BROKEN_PACKAGE / "__init__.py").write_text(PACKAGE_SOURCE, encoding="utf-8")
    return root


def _ash(packages: Path, args, cwd: Path):
    bin_dir, log = install_stand_in_uv(cwd / "uv-stand-in")
    env = stand_in_env(bin_dir, log, dict(os.environ))
    env.pop("ASH_PLUGIN_MODULES", None)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "250"})
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
        env=env,
        cwd=cwd,
    )


def _scan_args(source: Path, output: Path, *extra: str) -> list:
    return [
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--mode",
        "local",
        "--no-progress",
        *extra,
    ]


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return source


def test_a_config_enabled_scanner_of_a_broken_module_refuses_the_scan(
    plugin_packages, tmp_path
):
    """The sharpest form: the config names the module and enables its scanner by
    name, with fail_on_incomplete_scanners on. Importing nothing of that is an
    invalid run, not a warning: exit 3 and a refusal naming the module.

    The selection narrows the run to the broken scanner beside detect-secrets
    (which runs in-process): without the refusal the run proceeds, and a
    default selection with the built-ins enabled would start real tools."""
    source = _source(tmp_path)
    (source / ".ash.yaml").write_text(
        "project_name: demo\n"
        f"ash_plugin_modules:\n  - {BROKEN_PACKAGE}\n"
        "fail_on_incomplete_scanners: true\n"
        "scanners:\n  brokendep-scanner:\n    enabled: true\n",
        encoding="utf-8",
    )

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            tmp_path / "out",
            "--scanners",
            "brokendep-scanner",
            "--scanners",
            "detect-secrets",
        ),
        cwd=tmp_path,
    )

    output = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, (completed.returncode, output[-2000:])
    assert BROKEN_PACKAGE in output, output[-2000:]
    assert "failed to import" in output, output[-2000:]
    assert "Traceback" not in completed.stderr, completed.stderr[-2000:]


def test_a_mixed_selection_with_the_broken_module_refuses_too(
    plugin_packages, tmp_path
):
    """The configured module's scanner requested beside detect-secrets: the
    refusal still exits 3 before either one runs. It is selection-independent,
    so this exits 3 like the config-enabled case (both selected scanners run
    in-process, so the cell is safe on either outcome)."""
    source = _source(tmp_path)
    (source / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {BROKEN_PACKAGE}\n",
        encoding="utf-8",
    )

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            tmp_path / "out",
            "--scanners",
            "brokendep-scanner",
            "--scanners",
            "detect-secrets",
        ),
        cwd=tmp_path,
    )

    output = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, (completed.returncode, output[-2000:])
    assert BROKEN_PACKAGE in output, output[-2000:]
    assert "failed to import" in output, output[-2000:]


def test_requesting_only_the_broken_modules_scanner_refuses_in_the_refusals_words(
    plugin_packages, tmp_path
):
    """The configured module's scanner requested alone: exit 3 with the
    refusal's own composed text naming the module -- not only the loader's
    warning line, which also says "import" and would satisfy a looser check."""
    source = _source(tmp_path)
    (source / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {BROKEN_PACKAGE}\n",
        encoding="utf-8",
    )

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            tmp_path / "out",
            "--scanners",
            "brokendep-scanner",
        ),
        cwd=tmp_path,
    )

    output = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, (completed.returncode, output[-2000:])
    assert f"ash_plugin_modules names '{BROKEN_PACKAGE}'" in output, output[-2000:]
    assert "which failed to import" in output, output[-2000:]


def test_the_default_selection_refuses_with_the_built_ins_disabled(
    plugin_packages, tmp_path
):
    """No --scanners at all: the refusal is selection-independent, so the
    default selection exits 3 like every other shape. Every built-in scanner is
    disabled in the config, so even the fail-open state would select nothing
    and no real tool can start."""
    source = _source(tmp_path)
    # Derived from the registry, not a literal list: a newly shipped built-in
    # scanner would silently fall out of a hardcoded pin.
    disabled = "".join(
        f"  {name}:\n    enabled: false\n" for name in builtin_scanner_config_names()
    )
    (source / ".ash.yaml").write_text(
        "project_name: demo\n"
        f"ash_plugin_modules:\n  - {BROKEN_PACKAGE}\n"
        f"scanners:\n{disabled}",
        encoding="utf-8",
    )

    completed = _ash(
        plugin_packages,
        _scan_args(source, tmp_path / "out"),
        cwd=tmp_path,
    )

    output = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, (completed.returncode, output[-2000:])
    assert f"ash_plugin_modules names '{BROKEN_PACKAGE}'" in output, output[-2000:]


def test_a_module_that_crashes_at_import_refuses_the_scan_the_same_way(
    plugin_packages, tmp_path
):
    """A configured module whose import raises something other than
    ImportError -- a RuntimeError from its module body, say -- is the same
    loss: none of the plugins the operator asked for are loaded. It takes the
    same exit-3 named refusal, not an unrecorded crash."""
    crashing = "crashing_ash_plugins"
    (plugin_packages / crashing).mkdir()
    (plugin_packages / crashing / "__init__.py").write_text(
        'raise RuntimeError("broken at import time")\n', encoding="utf-8"
    )
    source = _source(tmp_path)
    (source / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {crashing}\n",
        encoding="utf-8",
    )

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            tmp_path / "out",
            "--scanners",
            "detect-secrets",
        ),
        cwd=tmp_path,
    )

    output = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 3, (completed.returncode, output[-2000:])
    assert f"ash_plugin_modules names '{crashing}'" in output, output[-2000:]
    assert "RuntimeError" in output, output[-2000:]
    assert "which failed to import" in output, output[-2000:]


def test_requesting_only_an_unknown_scanner_keeps_its_own_refusal(
    plugin_packages, tmp_path
):
    """The pin: with the module not configured, requesting only its scanner is
    a selection of a name no loaded plugin has, and that refusal stays as it
    is: none of the requested scanners exist, exit 5."""
    source = _source(tmp_path)

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            tmp_path / "out",
            "--scanners",
            "brokendep-scanner",
        ),
        cwd=tmp_path,
    )

    assert completed.returncode == 5, (
        completed.returncode,
        (completed.stdout + completed.stderr)[-2000:],
    )


def test_the_control_scanner_runs_when_its_dependency_is_present(
    plugin_packages, tmp_path
):
    """The control: with the dependency present the module imports, and the
    same configuration runs its scanner to a recorded result."""
    (plugin_packages / f"{DEPENDENCY}.py").write_text("", encoding="utf-8")
    source = _source(tmp_path)
    (source / ".ash.yaml").write_text(
        "project_name: demo\n"
        f"ash_plugin_modules:\n  - {BROKEN_PACKAGE}\n"
        "fail_on_incomplete_scanners: true\n"
        "scanners:\n  brokendep-scanner:\n    enabled: true\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    completed = _ash(
        plugin_packages,
        _scan_args(
            source,
            output_dir,
            "--scanners",
            "brokendep-scanner",
        ),
        cwd=tmp_path,
    )

    streams = " ".join((completed.stdout + completed.stderr).split())
    assert completed.returncode == 0, (completed.returncode, streams[-2000:])
    results_file = output_dir / "ash_aggregated_results.json"
    assert results_file.is_file(), streams[-2000:]
    rows = json.loads(results_file.read_text(encoding="utf-8"))["scanner_results"]
    assert rows["brokendep-scanner"]["status"] == "PASSED", rows.get(
        "brokendep-scanner"
    )
