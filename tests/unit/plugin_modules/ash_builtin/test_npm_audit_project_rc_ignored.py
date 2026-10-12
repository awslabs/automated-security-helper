# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit's package managers read the operator's settings, not the repository's.

npm, pnpm and yarn read settings files from the directory they run in: npm and
pnpm the project's ``.npmrc`` (pnpm also the settings in ``pnpm-workspace.yaml``),
yarn 1 ``.yarnrc`` and ``.npmrc`` from the directory and every parent, yarn 2+
``.yarnrc.yml``. ASH ran them in the package's directory in the scanned tree, so
the repository chose the registry the dependency list goes to, the proxy, the TLS
settings and the cache. yarn also honors ``yarn-path`` (``.yarnrc``) and
``yarnPath`` (``.yarnrc.yml``) and runs the JavaScript file they name instead of
itself, so ASH's own ``yarn --version`` ran code the repository supplied. Measured
with npm 10.9.4, pnpm 12.6.0 and yarn 1.22.22.

The operator's own files (``~/.npmrc``, ``~/.yarnrc``) are trusted and still apply,
because a private registry's address and credentials live there. Here a marker
registry in the test's own home stands for them, and a second marker in the
repository's files for what must not apply. utils/package_manager_child.py does
the work; see its docstring for what was measured.

``pnpm.auditConfig`` in the repository's ``package.json`` is a suppression the
repository holds; it stays, except under ``--ignore-suppressions``.
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
from automated_security_helper.utils import package_manager_child as child_module
from automated_security_helper.utils.package_manager_child import (
    package_manager_child,
)
from automated_security_helper.utils.process_env import snapshot_environ
from tests.utils.helpers import require_scanner_binary
from tests.utils.refusing_proxy import scrub_cloud_credentials

REPOSITORY_REGISTRY = "http://127.0.0.1:9/marker-from-the-repository/"
OPERATOR_REGISTRY = "http://127.0.0.1:9/marker-from-the-operator/"
NO_ADVISORIES = json.dumps(
    {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}
)
# yarn 1 prints NDJSON events and closes a clean report with an auditSummary.
YARN_1_NO_ADVISORIES = (
    '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,'
    '"low":0,"moderate":0,"high":0,"critical":0}}}\n'
)
AUDIT_CONFIG = {"ignoreCves": ["CVE-2026-0001"], "ignoreGhsas": ["GHSA-aaaa-bbbb-cccc"]}


def _repository(root: Path, lockfile: str) -> Path:
    """A package whose directory carries every settings file a package manager reads."""
    package = root / "web"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps(
            {
                "name": "web",
                "version": "1.0.0",
                "dependencies": {},
                "pnpm": {"auditConfig": AUDIT_CONFIG},
            }
        ),
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


@pytest.fixture
def online(monkeypatch):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return monkeypatch


def _scanner(tmp_path: Path, *, ignore_suppressions: bool = False) -> NpmAuditScanner:
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
        ignore_suppressions=ignore_suppressions,
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def _record(monkeypatch, yarn_version: str = "1.22.22") -> List[Dict[str, Any]]:
    """Every spawn npm-audit makes: argv, cwd, the files there (read now), env."""
    spawns: List[Dict[str, Any]] = []

    def fake_run(self, command, **kwargs):
        cwd = Path(kwargs["cwd"]) if kwargs.get("cwd") is not None else None
        files = {}
        if cwd is not None:
            for path in sorted(cwd.rglob("*")):
                if path.is_file():
                    files[path.relative_to(cwd).as_posix()] = path.read_text()
        spawns.append(
            {
                "command": [str(part) for part in command],
                "cwd": cwd,
                "files": files,
                "env": dict(kwargs.get("env") or {}),
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


def _assert_operator_settings_untouched(env: Dict[str, str]) -> None:
    """Nothing points the tool away from the operator's own settings files."""
    inherited = snapshot_environ()
    for key in ("npm_config_userconfig", "npm_config_globalconfig", "HOME"):
        assert env.get(key) == inherited.get(key), key
    assert {k: v for k, v in env.items() if not k.startswith("YARN_")} == {
        k: v for k, v in inherited.items() if not k.startswith("YARN_")
    }


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
    assert sorted(audit["files"]) == sorted(["package.json", lockfile])
    _assert_operator_settings_untouched(audit["env"])


def test_unsandboxed_yarn_runs_from_a_copy_outside_the_scanned_tree(online, tmp_path):
    spawns = _record(online, yarn_version="1.22.22")
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    member = package / "packages" / "api"
    member.mkdir(parents=True)
    (member / "package.json").write_text('{"name": "api"}', encoding="utf-8")
    (package / "node_modules" / "dep").mkdir(parents=True)
    (package / "node_modules" / "dep" / "package.json").write_text("{}")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    probes = [s for s in spawns if s["command"][-1] == "--version"]
    assert probes and all(p["env"].get("YARN_IGNORE_PATH") == "1" for p in probes)
    (audit,) = _audits(spawns)
    assert audit["command"] == ["yarn", "audit", "--json"], audit["command"]
    assert not audit["cwd"].is_relative_to(scanner.context.source_dir)
    # The workspace's manifests at their places, so yarn finds its members; no
    # settings file and no installed package.
    assert sorted(audit["files"]) == [
        "package.json",
        "packages/api/package.json",
        "yarn.lock",
    ]
    assert audit["env"].get("YARN_IGNORE_PATH") == "1"
    assert "YARN_RC_FILENAME" not in audit["env"]
    _assert_operator_settings_untouched(audit["env"])


@pytest.mark.parametrize(
    ("version", "expected_command", "rc_filename"),
    [
        ("1.22.22", ["yarn", "--no-default-rc", "audit", "--json"], False),
        ("4.5.0", ["yarn", "npm", "audit", "--json", "--recursive"], True),
    ],
)
def test_sandboxed_yarn_reads_no_settings_file(
    online, tmp_path, version, expected_command, rc_filename
):
    """Under a sandbox the home is private and the copy could not be seen outside
    the tree, so yarn runs in place with every settings file dropped."""
    online.setattr(child_module, "_sandboxed", lambda: True)
    spawns = _record(online, yarn_version=version)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["command"] == expected_command
    assert audit["cwd"] == package
    assert audit["env"].get("YARN_IGNORE_PATH") == "1"
    assert (audit["env"].get("YARN_RC_FILENAME") is not None) is rc_filename


@pytest.mark.parametrize("ignore_suppressions", [False, True])
def test_pnpm_audit_config_is_a_suppression_the_flag_lifts(
    online, tmp_path, ignore_suppressions
):
    spawns = _record(online)
    scanner = _scanner(tmp_path, ignore_suppressions=ignore_suppressions)
    _repository(scanner.context.source_dir, "pnpm-lock.yaml")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    copied = json.loads(audit["files"]["package.json"])
    if ignore_suppressions:
        assert "auditConfig" not in copied.get("pnpm", {}), copied
    else:
        assert copied["pnpm"]["auditConfig"] == AUDIT_CONFIG


def test_the_yarn_variables_reach_a_sandboxed_yarn():
    """The sandbox passes only listed variables; these two must be among them."""
    from automated_security_helper.utils.sandbox.policy import (
        BASE_ENV_NAMES,
        BASE_ENV_PREFIXES,
    )

    requirements = NpmAuditScanner.sandbox_requirements
    prefixes = BASE_ENV_PREFIXES + tuple(requirements.env_prefixes)
    names = set(BASE_ENV_NAMES) | set(requirements.env_names)
    for key in ("YARN_IGNORE_PATH", "YARN_RC_FILENAME"):
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
    online, tmp_path, binary, lockfile
):
    require_scanner_binary(binary)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, lockfile)
    operator = _operator_home(tmp_path)

    # Control: where ASH used to run it, the repository's file wins.
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


def test_the_real_yarn_reads_the_operator_s_settings_and_runs_no_yarn_path(
    online, tmp_path
):
    require_scanner_binary("yarn")
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
    online, tmp_path
):
    require_scanner_binary("yarn")
    online.setattr(child_module, "_sandboxed", lambda: True)
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
