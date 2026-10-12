# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit's package managers read no settings file the scanned repository wrote.

npm, pnpm and yarn read settings files from the directory they run in: npm and
pnpm the project's ``.npmrc`` (pnpm also the settings in ``pnpm-workspace.yaml``),
yarn 1 ``.yarnrc`` and ``.npmrc`` from the directory and every parent, yarn 2+
``.yarnrc.yml``. ASH ran them in the package's directory in the scanned tree, so
the repository chose the registry the dependency list goes to, the proxy, the TLS
settings and the cache. Worse, yarn honors ``yarn-path`` (``.yarnrc``) and
``yarnPath`` (``.yarnrc.yml``) and runs the JavaScript file they name instead of
itself, so ASH's own ``yarn --version`` ran code the repository supplied. Measured
with npm 10.9.4, pnpm 12.6.0 and yarn 1.22.22: each applied a marker registry from
the repository's file, and yarn ran a marker script from both ``yarn-path`` and
``yarnPath``.

Now:

* npm and pnpm run from a new directory holding copies of ``package.json`` and the
  lockfile only. Neither has an option to skip the project's file; both read it
  only from the directory they run in, so the copy has none. Measured: the copies'
  audit requests are identical to the in-tree ones, workspaces included.
* yarn runs in the package directory with ``YARN_IGNORE_PATH=1`` (no ``yarn-path``
  or ``yarnPath``), ``YARN_RC_FILENAME`` naming no file (yarn 2+ reads no
  ``.yarnrc.yml``), and for yarn 1 ``--no-default-rc`` (no ``.yarnrc`` or
  ``.npmrc`` in any parent either).
* Every one of them gets an empty user and global settings file of ASH's
  (``npm_config_userconfig``, ``npm_config_globalconfig`` and pnpm's
  ``pnpm_config_*``), so the operator's environment variables are the only
  settings left.

Offline nothing runs (npm-audit records each lockfile as not scanned), unchanged.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner as npm_audit_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from tests.utils.helpers import require_scanner_binary
from tests.utils.refusing_proxy import scrub_cloud_credentials

MARKER_REGISTRY = "http://127.0.0.1:9/marker-from-the-repository/"
NO_ADVISORIES = json.dumps(
    {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}
)
# yarn 1 prints NDJSON events and closes a clean report with an auditSummary.
YARN_1_NO_ADVISORIES = (
    '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,'
    '"low":0,"moderate":0,"high":0,"critical":0}}}\n'
)


def _repository(root: Path, lockfile: str) -> Path:
    """A package whose directory carries every settings file a package manager reads."""
    package = root / "web"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "web", "version": "1.0.0", "dependencies": {}}),
        encoding="utf-8",
    )
    (package / lockfile).write_text("{}\n", encoding="utf-8")
    (package / ".npmrc").write_text(f"registry={MARKER_REGISTRY}\n", encoding="utf-8")
    (package / "pnpm-workspace.yaml").write_text(
        f'packages: []\nregistry: "{MARKER_REGISTRY}"\n', encoding="utf-8"
    )
    (package / ".yarnrc").write_text(
        f'registry "{MARKER_REGISTRY}"\nyarn-path "./marker.js"\n', encoding="utf-8"
    )
    (package / ".yarnrc.yml").write_text(
        f'yarnPath: ./marker.js\nnpmRegistryServer: "{MARKER_REGISTRY}"\n',
        encoding="utf-8",
    )
    (package / "marker.js").write_text(
        "require('fs').writeFileSync(__dirname + '/MARKER_RAN', 'ran');\n"
        "process.stdout.write('1.22.22\\n');\n",
        encoding="utf-8",
    )
    return package


@pytest.fixture
def online(monkeypatch):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return monkeypatch


def _scanner(tmp_path: Path) -> NpmAuditScanner:
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def _record(monkeypatch, yarn_version: str = "1.22.22") -> List[Dict[str, Any]]:
    """Every spawn npm-audit makes, with its cwd and environment, and the files there."""
    spawns: List[Dict[str, Any]] = []

    def fake_run(self, command, **kwargs):
        cwd = kwargs.get("cwd")
        env = dict(kwargs.get("env") or {})
        spawns.append(
            {
                "command": [str(part) for part in command],
                "cwd": Path(cwd) if cwd is not None else None,
                "files": sorted(p.name for p in Path(cwd).iterdir()) if cwd else [],
                "env": env,
                # Read now: the private directory is removed after the tool runs.
                "empty_settings": {
                    key: Path(env[key]).is_file() and Path(env[key]).read_text() == ""
                    for key in ("npm_config_userconfig", "npm_config_globalconfig")
                    if key in env
                },
            }
        )
        if "--version" in command:
            return {"stdout": f"{yarn_version}\n", "returncode": 0}
        if command[0] == "yarn" and "npm" not in command:
            return {"stdout": YARN_1_NO_ADVISORIES, "returncode": 0}
        return {"stdout": NO_ADVISORIES, "returncode": 0}

    monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
    monkeypatch.setattr(
        NpmAuditScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(
        npm_audit_module, "find_executable", lambda name: f"/usr/local/bin/{name}"
    )
    return spawns


def _audits(spawns) -> List[Dict[str, Any]]:
    return [s for s in spawns if "audit" in s["command"]]


def _assert_private_settings(spawn: Dict[str, Any]) -> None:
    env = spawn["env"]
    assert spawn["empty_settings"] == {
        "npm_config_userconfig": True,
        "npm_config_globalconfig": True,
    }, spawn["empty_settings"]
    for key in ("pnpm_config_userconfig", "pnpm_config_globalconfig"):
        assert env.get(key) == env["npm_config_userconfig"], key


@pytest.mark.parametrize(
    ("binary", "lockfile"), [("npm", "package-lock.json"), ("pnpm", "pnpm-lock.yaml")]
)
def test_npm_and_pnpm_run_from_a_copy_without_the_repository_s_files(
    online, tmp_path, binary, lockfile
):
    spawns = _record(online)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, lockfile)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["command"][0] == binary
    assert audit["cwd"] != package
    assert not audit["cwd"].is_relative_to(scanner.context.source_dir) or (
        audit["cwd"].is_relative_to(scanner.context.output_dir)
    ), audit["cwd"]
    assert audit["files"] == sorted(["package.json", lockfile]), audit["files"]
    _assert_private_settings(audit)


def test_yarn_1_reads_no_settings_file_and_runs_no_yarn_path(online, tmp_path):
    spawns = _record(online, yarn_version="1.22.22")
    scanner = _scanner(tmp_path)
    _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    probes = [s for s in spawns if s["command"][-1] == "--version"]
    assert probes and all(p["env"].get("YARN_IGNORE_PATH") == "1" for p in probes)
    (audit,) = _audits(spawns)
    assert audit["command"][:2] == ["yarn", "--no-default-rc"], audit["command"]
    assert audit["env"].get("YARN_IGNORE_PATH") == "1"
    assert audit["env"].get("YARN_RC_FILENAME")
    assert not (audit["cwd"] / audit["env"]["YARN_RC_FILENAME"]).exists()
    _assert_private_settings(audit)


def test_yarn_2_and_later_read_no_yarnrc_yml(online, tmp_path):
    spawns = _record(online, yarn_version="4.5.0")
    scanner = _scanner(tmp_path)
    _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["command"][:3] == ["yarn", "npm", "audit"], audit["command"]
    assert "--no-default-rc" not in audit["command"]  # a yarn 1 flag only
    assert audit["env"].get("YARN_IGNORE_PATH") == "1"
    assert audit["env"].get("YARN_RC_FILENAME") not in (None, ".yarnrc.yml")


def test_the_variables_reach_a_sandboxed_package_manager():
    """The sandbox passes only listed variables; these must be among them."""
    from automated_security_helper.utils.sandbox.policy import (
        BASE_ENV_NAMES,
        BASE_ENV_PREFIXES,
    )

    requirements = NpmAuditScanner.sandbox_requirements
    prefixes = BASE_ENV_PREFIXES + tuple(requirements.env_prefixes)
    names = set(BASE_ENV_NAMES) | set(requirements.env_names)
    for key in (
        "npm_config_userconfig",
        "npm_config_globalconfig",
        "pnpm_config_userconfig",
        "pnpm_config_globalconfig",
        "YARN_IGNORE_PATH",
        "YARN_RC_FILENAME",
    ):
        assert key in names or key.startswith(prefixes), key


# ---------------------------------------------------------------------------
# The real tools: what each one reads, with ASH's invocation and without it
# ---------------------------------------------------------------------------


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
    return (result.stdout or "").strip().splitlines()[-1] if result.stdout else ""


def _plain_env(tmp_path: Path) -> Dict[str, str]:
    from automated_security_helper.utils.process_env import snapshot_environ

    env = snapshot_environ()
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    return env


@pytest.mark.parametrize(
    ("binary", "lockfile"), [("npm", "package-lock.json"), ("pnpm", "pnpm-lock.yaml")]
)
def test_the_real_tool_reads_the_repository_registry_only_without_ash(
    online, tmp_path, binary, lockfile
):
    require_scanner_binary(binary)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, lockfile)
    plain = _plain_env(tmp_path)

    # Control: run where ASH used to, and the repository's registry applies.
    assert _config_registry(binary, package, plain) == MARKER_REGISTRY

    invocation = scanner._package_manager_invocation(
        binary, package, scanner.context.output_dir
    )
    env = {**plain, **invocation.env, "HOME": plain["HOME"]}
    assert _config_registry(binary, invocation.cwd, env) != MARKER_REGISTRY


def test_the_real_yarn_reads_the_repository_settings_only_without_ash(online, tmp_path):
    require_scanner_binary("yarn")
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    plain = _plain_env(tmp_path)
    ran = package / "MARKER_RAN"

    # Control: in the package directory yarn 1 runs the repository's yarn-path.
    _config_registry("yarn", package, plain)
    assert ran.exists(), "the control did not reach the repository's yarn-path"
    ran.unlink()

    invocation = scanner._package_manager_invocation(
        "yarn", package, scanner.context.output_dir, yarn_major=1
    )
    env = {**plain, **invocation.env, "HOME": plain["HOME"]}
    registry = _config_registry(
        "yarn", invocation.cwd, env, leading=invocation.leading_args
    )

    assert not ran.exists(), "yarn ran the repository's yarn-path under ASH's call"
    assert registry and registry.rstrip("/") != MARKER_REGISTRY.rstrip("/")
