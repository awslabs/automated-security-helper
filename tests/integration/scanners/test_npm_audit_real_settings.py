# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the real npm, pnpm and yarn read, with ASH's invocation and without it.

The unit cells (tests/unit/plugin_modules/ash_builtin/test_npm_audit_project_rc_ignored.py)
pin where npm-audit starts each package manager and what that directory holds. These
run the real tool there: each reads the registry a marker in the test's own home
names (the operator's settings), not the one the repository's files name, and yarn
runs no ``yarn-path`` the repository wrote. Each control first shows the repository's
setting winning in the repository's own directory. ``config get`` reads settings only,
so no cell reaches a registry. A cell skips where its tool is not installed or does
not run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils import package_manager_child as child_module
from automated_security_helper.utils.package_manager_child import (
    package_manager_child,
)
from automated_security_helper.utils.process_env import snapshot_environ

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

REPOSITORY_REGISTRY = "http://127.0.0.1:9/marker-from-the-repository/"
OPERATOR_REGISTRY = "http://127.0.0.1:9/marker-from-the-operator/"


def _repository(root: Path, lockfile: str) -> Path:
    """A package whose directory carries every settings file a package manager reads."""
    package = root / "web"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "web", "version": "1.0.0", "dependencies": {}}),
        encoding="utf-8",
    )
    (package / lockfile).write_text("{}\n", encoding="utf-8")
    (package / ".npmrc").write_text(
        f"registry={REPOSITORY_REGISTRY}\n", encoding="utf-8"
    )
    (package / "pnpm-workspace.yaml").write_text(
        f'packages: []\nregistry: "{REPOSITORY_REGISTRY}"\n', encoding="utf-8"
    )
    (package / ".yarnrc").write_text(
        f'registry "{REPOSITORY_REGISTRY}"\nyarn-path "./marker.js"\n',
        encoding="utf-8",
    )
    (package / ".yarnrc.yml").write_text(
        f'yarnPath: ./marker.js\nnpmRegistryServer: "{REPOSITORY_REGISTRY}"\n',
        encoding="utf-8",
    )
    (package / "marker.js").write_text(
        "require('fs').writeFileSync(__dirname + '/MARKER_RAN', 'ran');\n"
        "process.stdout.write('1.22.22\\n');\n",
        encoding="utf-8",
    )
    return package


def _scanner(tmp_path: Path) -> NpmAuditScanner:
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return NpmAuditScanner(context=context, config=NpmAuditScannerConfig())


def _require_working(binary: str) -> None:
    """Skip unless ``binary`` is installed and runs."""
    found = shutil.which(binary)
    if found is None:
        pytest.skip(f"{binary} is not installed")
    probe = subprocess.run(  # nosec B603 - fixed argv, a test
        [found, "--version"], capture_output=True, timeout=60, check=False
    )
    if probe.returncode != 0:
        pytest.skip(f"{binary} does not run here")


def _config_registry(binary, cwd: Path, env: Dict[str, str], leading=()) -> str:
    result = subprocess.run(  # nosec B603 - fixed argv, a test
        [binary, *leading, "config", "get", "registry"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    lines = (result.stdout or "").strip().splitlines()
    return lines[-1].strip() if lines else ""


def _operator_home(tmp_path: Path) -> Dict[str, str]:
    """The test's own home, holding the operator's settings, in an environment."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    (home / ".npmrc").write_text(f"registry={OPERATOR_REGISTRY}\n", encoding="utf-8")
    (home / ".yarnrc").write_text(f'registry "{OPERATOR_REGISTRY}"\n', encoding="utf-8")
    env = snapshot_environ()
    for key in list(env):
        if key.lower().startswith(("npm_config_", "yarn_")):
            del env[key]
    env["HOME"] = str(home)
    return env


def _same(left: str, right: str) -> bool:
    return left.rstrip("/") == right.rstrip("/")


@pytest.mark.parametrize(
    ("binary", "lockfile"), [("npm", "package-lock.json"), ("pnpm", "pnpm-lock.yaml")]
)
def test_the_real_tool_reads_the_operator_s_registry_not_the_repository_s(
    tmp_path, binary, lockfile
):
    _require_working(binary)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, lockfile)
    operator = _operator_home(tmp_path)

    # Control: run in the repository's own directory, the repository's file wins.
    assert _same(_config_registry(binary, package, operator), REPOSITORY_REGISTRY)

    with package_manager_child(
        binary, package, parent=scanner.context.output_dir
    ) as child:
        env = {**child.env, "HOME": operator["HOME"]}
        for key in list(env):
            if key.lower().startswith("npm_config_"):
                del env[key]
        registry = _config_registry(binary, child.cwd, env)

    assert _same(registry, OPERATOR_REGISTRY), registry


def test_the_real_yarn_reads_the_operator_s_settings_and_runs_no_yarn_path(tmp_path):
    _require_working("yarn")
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    operator = _operator_home(tmp_path)
    ran = package / "MARKER_RAN"

    # Control: in the package directory yarn 1 runs the repository's yarn-path.
    _config_registry("yarn", package, operator)
    assert ran.exists(), "the control did not reach the repository's yarn-path"
    ran.unlink()

    with package_manager_child(
        "yarn",
        package,
        parent=scanner.context.output_dir,
        scan_root=scanner.context.source_dir,
        yarn_major=1,
    ) as child:
        env = {**child.env, "HOME": operator["HOME"]}
        registry = _config_registry("yarn", child.cwd, env, child.leading_args)

    assert not ran.exists(), "yarn ran the repository's yarn-path under ASH's call"
    assert _same(registry, OPERATOR_REGISTRY), registry


def test_the_real_sandboxed_yarn_reads_no_settings_and_runs_no_yarn_path(
    tmp_path, monkeypatch
):
    _require_working("yarn")
    monkeypatch.setattr(child_module, "_sandboxed", lambda: True)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    operator = _operator_home(tmp_path)
    ran = package / "MARKER_RAN"

    with package_manager_child(
        "yarn", package, parent=scanner.context.output_dir, yarn_major=1
    ) as child:
        env = {**child.env, "HOME": operator["HOME"]}
        registry = _config_registry("yarn", child.cwd, env, child.leading_args)

    assert not ran.exists()
    assert registry and not _same(registry, REPOSITORY_REGISTRY), registry
