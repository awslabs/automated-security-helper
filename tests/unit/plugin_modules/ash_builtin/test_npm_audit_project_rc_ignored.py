# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit's package managers read the operator's settings, not the repository's.

npm, pnpm and yarn read settings files from the directory they run in: npm and
pnpm the project's ``.npmrc`` (pnpm also the settings in ``pnpm-workspace.yaml``),
yarn 1 ``.yarnrc`` and ``.npmrc`` from the directory and every parent, yarn 2+
``.yarnrc.yml``. ASH runs them where the repository's settings files are not
read, so the registry the dependency list goes to, the proxy, the TLS settings
and the cache come from the operator's own files. yarn also honors ``yarn-path``
(``.yarnrc``) and
``yarnPath`` (``.yarnrc.yml``) and runs the JavaScript file they name instead of
itself. Measured with npm 10.9.4, pnpm 12.6.0 and yarn 1.22.22.

The operator's own files (``~/.npmrc``, ``~/.yarnrc``) are trusted and still apply,
because a private registry's address and credentials live there. Here a marker
registry in the test's own home stands for them, and a second marker in the
repository's files for what must not apply. utils/package_manager_child.py does
the work; see its docstring for what was measured.

``pnpm.auditConfig`` in the repository's ``package.json`` is a suppression the
repository holds; it stays, except under ``--ignore-suppressions``.

What the real npm, pnpm and yarn read, with ASH's invocation and without it, is in
tests/integration/scanners/test_npm_audit_real_settings.py: unit tests start no real
tool.
"""

from __future__ import annotations

import json
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
from automated_security_helper.utils.package_manager_child import NO_YARNRC
from automated_security_helper.utils.process_env import snapshot_environ
from tests.utils.aws_isolation import isolate_from_aws
from tests.utils.env_assertions import differing_names
from tests.utils.npm_audit_reports import (
    NPM_CLEAN,
    PNPM_CLEAN,
    YARN_1_NO_ADVISORIES,
    YARN_BERRY_NO_ADVISORIES,
)

pytestmark = pytest.mark.unit

REPOSITORY_REGISTRY = "http://127.0.0.1:9/marker-from-the-repository/"
OPERATOR_REGISTRY = "http://127.0.0.1:9/marker-from-the-operator/"
#: Each tool's own clean report (tests/utils/npm_audit_reports.py): pnpm's is
#: keyed advisories, so an npm-shaped document is not a pnpm report. The yarn
#: shapes are the module's captures too: yarn 1's auditSummary NDJSON and
#: yarn 2/3's npm v1 document (classic-clean.json and berry3-clean.json).
NO_ADVISORIES = NPM_CLEAN
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
def online(monkeypatch, tmp_path):
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    # An inherited value would satisfy the cells that expect ASH to set these.
    for name in ("YARN_IGNORE_PATH", "YARN_RC_FILENAME"):
        monkeypatch.delenv(name, raising=False)
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


def _record(
    monkeypatch,
    yarn_version: str = "1.22.22",
    yarn_berry_response: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """Every spawn npm-audit makes: argv, cwd, the files there (read now), env.

    ``yarn_berry_response`` replaces the clean yarn 2+ answer, for the one cell
    that audits an advisory-bearing capture."""
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
        if command[0] == "yarn":
            if yarn_berry_response is not None:
                return dict(yarn_berry_response)
            # Version-true: yarn 4 prints nothing for a clean audit and exits 0;
            # yarn 2 and 3 print the advisories document.
            if int(yarn_version.split(".")[0]) >= 4:
                return {"stdout": "", "returncode": 0}
            return {"stdout": YARN_BERRY_NO_ADVISORIES, "returncode": 0}
        if command[0] == "pnpm":
            return {"stdout": PNPM_CLEAN, "returncode": 0}
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
    # Values of the names asked about, and names otherwise: a failure would print
    # the whole environment.
    for key in ("npm_config_userconfig", "npm_config_globalconfig", "HOME"):
        passed, expected = env.get(key), inherited.get(key)
        assert passed == expected, key
    passed_rest = {k: v for k, v in env.items() if not k.startswith("YARN_")}
    inherited_rest = {k: v for k, v in inherited.items() if not k.startswith("YARN_")}
    assert differing_names(passed_rest, inherited_rest) == []


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
    assert all(p["cwd"] != package for p in probes)
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
    # The one value and the names, not the mapping, which a failure would print.
    ignore_path = audit["env"].get("YARN_IGNORE_PATH")
    names = set(audit["env"])
    assert ignore_path == "1"
    assert "YARN_RC_FILENAME" not in names
    _assert_operator_settings_untouched(audit["env"])


@pytest.mark.parametrize(
    ("version", "expected_command", "rc_filename"),
    [
        ("1.22.22", ["yarn", "--no-default-rc", "audit", "--json"], False),
        # yarn 3 and 4 share the >=2 handling (YARN_RC_FILENAME, no leading
        # args); their stand-in answers differ, the document against nothing.
        ("3.8.7", ["yarn", "npm", "audit", "--json", "--all", "--recursive"], True),
        ("4.5.0", ["yarn", "npm", "audit", "--json", "--all", "--recursive"], True),
    ],
)
def test_sandboxed_yarn_reads_no_settings_file(
    online, tmp_path, version, expected_command, rc_filename
):
    """Under a sandbox the home is private and the copy could not be seen outside
    the tree, so yarn runs in place with every settings file dropped."""
    from automated_security_helper.utils import package_manager_child as child_module

    online.setattr(child_module, "_sandboxed", lambda: True)
    spawns = _record(online, yarn_version=version)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["command"] == expected_command
    assert audit["cwd"] == package
    # The two values, not the mapping, which a failure would print.
    ignore_path = audit["env"].get("YARN_IGNORE_PATH")
    rc_value = audit["env"].get("YARN_RC_FILENAME")
    assert ignore_path == "1"
    assert rc_value == (NO_YARNRC if rc_filename else None)


def _probes(spawns) -> List[Dict[str, Any]]:
    return [s for s in spawns if s["command"][-1] == "--version"]


def _assert_probe_reads_no_settings(probe: Dict[str, Any]) -> None:
    """The version probe does not know the major, so it gets the flags every yarn
    accepts: no yarn-path, and a settings file name no directory has."""
    assert probe["command"] == ["yarn", "--version"]
    ignore_path = probe["env"].get("YARN_IGNORE_PATH")
    rc_value = probe["env"].get("YARN_RC_FILENAME")
    assert ignore_path == "1"
    assert rc_value == NO_YARNRC


@pytest.mark.parametrize("version", ["1.22.22", "3.8.7"])
def test_unsandboxed_version_probe_reads_no_settings_file(online, tmp_path, version):
    spawns = _record(online, yarn_version=version)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (probe,) = _probes(spawns)
    assert probe["cwd"] != package
    _assert_probe_reads_no_settings(probe)


@pytest.mark.parametrize("version", ["1.22.22", "3.8.7"])
def test_sandboxed_version_probe_reads_no_settings_file(online, tmp_path, version):
    from automated_security_helper.utils import package_manager_child as child_module

    online.setattr(child_module, "_sandboxed", lambda: True)
    spawns = _record(online, yarn_version=version)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (probe,) = _probes(spawns)
    assert probe["cwd"] == package
    _assert_probe_reads_no_settings(probe)


@pytest.mark.parametrize(
    ("version", "expected_command", "rc_value"),
    [
        ("1.22.22", ["yarn", "--no-default-rc", "audit", "--json"], None),
        (
            "3.8.7",
            ["yarn", "npm", "audit", "--json", "--all", "--recursive"],
            NO_YARNRC,
        ),
    ],
)
def test_yarn_runs_in_place_when_the_system_tmpdir_is_inside_the_scanned_tree(
    online, tmp_path, version, expected_command, rc_value
):
    """No copy can be made outside the tree, so the probe and the audit run in the
    package directory with the repository's settings files dropped."""
    import tempfile

    spawns = _record(online, yarn_version=version)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    inside = scanner.context.source_dir / ".tmp-inside"
    inside.mkdir()
    online.setattr(tempfile, "gettempdir", lambda: str(inside))

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (probe,) = _probes(spawns)
    assert probe["cwd"] == package
    _assert_probe_reads_no_settings(probe)
    (audit,) = _audits(spawns)
    assert audit["cwd"] == package
    assert audit["command"] == expected_command
    ignore_path = audit["env"].get("YARN_IGNORE_PATH")
    audit_rc = audit["env"].get("YARN_RC_FILENAME")
    assert ignore_path == "1"
    assert audit_rc == rc_value


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


def test_a_linked_node_modules_is_not_on_the_tool_s_path(online, tmp_path):
    """The copy holds the manifest and the lockfile only: an installed package the
    repository linked out of the tree is not where the tool runs."""
    spawns = _record(online)
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "package-lock.json")
    outside = tmp_path / "outside-modules"
    (outside / "dep").mkdir(parents=True)
    (outside / "dep" / "package.json").write_text('{"name": "outside"}')
    (package / "node_modules").symlink_to(outside, target_is_directory=True)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert not (audit["cwd"] / "node_modules").exists()
    assert "node_modules/dep/package.json" not in audit["files"]


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


def test_a_yarn_3_advisory_reaches_the_report_through_the_isolation(online, tmp_path):
    """The yarn cells above answer clean documents, which the exit-0 arm alone
    would also accept, so none of them can see a broken berry document parse.
    This audit answers yarn 3.8.7's advisory-bearing capture (berry3-vuln.json):
    each advisory, its module and its installed version come out of the parsed
    document as findings, so a parse that stops reading the document turns this
    red instead of reporting the repository clean."""
    capture = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "test_data"
            / "scanners"
            / "npmaudit"
            / "yarn"
            / "berry3-vuln.json"
        ).read_text(encoding="utf-8")
    )
    spawns = _record(
        online,
        yarn_version=capture["yarn_version"],
        yarn_berry_response={
            "stdout": capture["stdout"],
            "returncode": capture["returncode"],
        },
    )
    scanner = _scanner(tmp_path)
    _repository(scanner.context.source_dir, "yarn.lock")

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    # The capture was produced without --all, which widens the workspaces
    # audited and changes nothing in the document's format.
    assert [p for p in audit["command"] if p != "--all"] == capture["command"]
    assert "--all" in audit["command"], audit["command"]
    document = json.loads(capture["stdout"])
    expected = sorted(
        {
            (
                advisory["github_advisory_id"],
                advisory["module_name"],
                finding["version"],
            )
            for advisory in document["advisories"].values()
            for finding in advisory["findings"]
        }
    )
    found = sorted(
        {
            (
                result.ruleId,
                result.properties.model_extra["package_name"],
                result.properties.model_extra["installed_version"],
            )
            for result in report.runs[0].results
        }
    )
    assert found == expected
    counted = sum(document["metadata"]["vulnerabilities"].values())
    assert len(report.runs[0].results) == counted
