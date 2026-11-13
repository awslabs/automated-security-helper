# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandboxed scanner reads the config files ASH wrote for it, and cannot change them.

ASH writes the config it hands a scanner's tool (an empty one, when the operator
names none) in a directory of the scanner run's own, outside the scanned tree
(``utils/tool_config_dir``). Every backend hides that location by default (bwrap
and firejail give the scanner a private ``/tmp``, sandbox-exec denies the shared
temporary directories), so the policy grants the directory read-only. These run
the real backends: a shell inside the sandbox reads the file, then tries to change
it and to add one beside it. The last test runs syft through the scanner executor
under bwrap, which fails if syft cannot read the ``--config`` it is handed.

A backend that is not available is skipped, unless ASH_REQUIRE_SANDBOX_BACKENDS
names it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs the sandboxed command under test
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    SandboxUnavailable,
    prepare_spawn,
    sandbox_scope,
)
from automated_security_helper.utils.tool_config_dir import tool_config_scope

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="no sandbox backend on Windows"),
]

_PROBE = """
cat "$1" || echo "UNREAD"
if printf 'x\\n' >> "$1" 2>/dev/null; then echo "CHANGED"; fi
if : > "$2" 2>/dev/null; then echo "ADDED"; fi
"""


def _require(name: str):
    clear_backend_cache()
    try:
        return resolve_backend(name)
    except SandboxUnavailable as e:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if name in [n.strip() for n in required]:
            pytest.fail(f"{name} is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {e}")
        pytest.skip(f"{name} unavailable: {e}")


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".git").mkdir()
    (source / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    (output / "converted").mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("bwrap", marks=pytest.mark.requires_userns),
        "firejail",
        "landlock",
        "sandbox-exec",
    ],
)
def test_the_directory_is_readable_and_not_writable(tmp_path: Path, name: str) -> None:
    backend = _require(name)
    context = _context(tmp_path, AshConfig())
    results = Path(context.output_dir) / "scanners" / "probe"
    results.mkdir(parents=True)
    # The spawn goes through prepare_spawn, as a scanner's does, so the grant
    # it tests is the one the active run's scope hands the policy.
    scope = SandboxScope(
        backend=backend,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=Path(context.source_dir),
        output_dir=Path(context.output_dir),
        results_dir=results,
        scan_target=Path(context.source_dir),
        offline=True,
    )
    with sandbox_scope(scope), tool_config_scope(context):
        config = empty_tool_config("probe-empty.yaml", "{}\n", context=context)
        plan = prepare_spawn(
            [
                "/bin/sh",
                "-c",
                _PROBE,
                "probe",
                config.as_posix(),
                (config.parent / "added.yaml").as_posix(),
            ],
            {"PATH": "/usr/bin:/bin"},
            results,
        )
        assert plan is not None
        result = subprocess.run(  # nosec B603 - argv built by the backend under test
            plan.argv,
            env=plan.env,
            cwd=results,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        plan.run_cleanup()
        assert result.stdout == "{}\n", (result.stdout, result.stderr)
        assert config.read_text(encoding="utf-8") == "{}\n"
        assert sorted(p.name for p in config.parent.iterdir()) == ["probe-empty.yaml"]
    assert not config.parent.exists()


@pytest.mark.requires_userns
def test_syft_reads_its_config_under_bwrap(tmp_path: Path) -> None:
    from automated_security_helper.config.path_trust import in_scanned_tree
    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )

    if shutil.which("syft") is None:
        pytest.skip("syft is not installed")
    _require("bwrap")
    context = _context(
        tmp_path, AshConfig(sandbox=SandboxConfig(mode="bwrap"), project_name="t")
    )
    scanner = SyftScanner(context=context, config=SyftScannerConfig())
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    commands = []
    real_run = scanner._run_subprocess

    def recording_run(*args, **kwargs):
        commands.append([str(a) for a in kwargs["command"]])
        return real_run(*args, **kwargs)

    with patch.object(scanner, "_run_subprocess", side_effect=recording_run):
        (container,) = executor._execute_scanner(
            "syft", scanner, [{"path": context.source_dir, "type": "source"}]
        )

    sbom = Path(scanner.results_dir) / "source" / "syft.cdx.json"
    assert sbom.is_file(), container.errors
    names = {c["name"] for c in json.loads(sbom.read_text()).get("components", [])}
    assert "requests" in names
    (argv,) = commands
    config = Path(argv[argv.index("--config") + 1])
    assert not in_scanned_tree(config, context.source_dir)
    assert not config.parent.exists()
