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
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner as npm_audit_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils import package_manager_child
from automated_security_helper.utils.package_manager_child import (
    NO_YARNRC_PREFIX,
    is_no_yarnrc_name,
)
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
    for name in ("YARN_IGNORE_PATH", "YARN_RC_FILENAME", "XDG_RUNTIME_DIR"):
        monkeypatch.delenv(name, raising=False)
    # tmp_path (and the test's HOME) sit under the system temporary directory,
    # whose ancestors every account can write, so yarn's copy placement would
    # pass over every directory this module offers it. The tests here are about
    # which directory is chosen for which reason, not about that check, which
    # tests/unit/utils/test_package_manager_child.py reads on its own.
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(system_tmp))
    monkeypatch.setattr(package_manager_child, "_untrusted_ancestor", lambda path: None)
    # The settings-file check is stood down too: a .npmrc, .yarnrc or
    # .yarnrc.yml in any directory above pytest's basetemp (a checkout holding
    # one, a TMPDIR under a real home) would pass every candidate over and
    # fail the placement tests for a reason that has nothing to do with them.
    monkeypatch.setattr(
        package_manager_child, "_settings_file_ancestor", lambda path: None
    )
    return monkeypatch


def _scanner(
    tmp_path: Path,
    *,
    ignore_suppressions: bool = False,
    output_dir: Path | None = None,
) -> NpmAuditScanner:
    """A scanner over tmp_path/repo; its output beside the repository unless
    ``output_dir`` says otherwise (the default output directory is inside it)."""
    output = output_dir if output_dir is not None else tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=output,
        work_dir=output / "converted",
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
    files = dict(audit["files"])
    if binary == "pnpm":
        # The copy is its own pnpm workspace root, with the package alone and
        # none of the repository's file (its registry marker stays out).
        workspace = files.pop("pnpm-workspace.yaml")
        assert yaml.safe_load(workspace) == {"packages": ["."]}
        assert REPOSITORY_REGISTRY not in workspace
    assert sorted(files) == sorted(["package.json", lockfile])
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
    if rc_filename:
        assert is_no_yarnrc_name(rc_value), rc_value
    else:
        assert rc_value is None


def _probes(spawns) -> List[Dict[str, Any]]:
    return [s for s in spawns if s["command"][-1] == "--version"]


def _assert_probe_reads_no_settings(probe: Dict[str, Any]) -> None:
    """The version probe does not know the major, so it gets the flags every yarn
    accepts: no yarn-path, and a settings file name no directory has."""
    assert probe["command"] == ["yarn", "--version"]
    ignore_path = probe["env"].get("YARN_IGNORE_PATH")
    rc_value = probe["env"].get("YARN_RC_FILENAME")
    assert ignore_path == "1"
    assert is_no_yarnrc_name(rc_value), rc_value


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
    ("version", "expected_command", "rc_filename"),
    [
        ("1.22.22", ["yarn", "--no-default-rc", "audit", "--json"], False),
        (
            "3.8.7",
            ["yarn", "npm", "audit", "--json", "--all", "--recursive"],
            True,
        ),
    ],
)
def test_yarn_runs_in_place_when_no_directory_outside_the_tree_can_hold_the_copy(
    online, tmp_path, version, expected_command, rc_filename
):
    """The output directory and the operator's cache directory are both inside the
    scanned tree, so no copy can be made outside it: the probe and the audit run
    in the package directory with the repository's settings files dropped."""
    spawns = _record(online, yarn_version=version)
    repo = tmp_path / "repo"
    scanner = _scanner(tmp_path, output_dir=repo / ".ash" / "ash_output")
    package = _repository(scanner.context.source_dir, "yarn.lock")
    online.setenv("XDG_CACHE_HOME", str(repo / ".cache-inside"))

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
    if rc_filename:
        assert is_no_yarnrc_name(audit_rc), audit_rc
    else:
        assert audit_rc is None


def test_unsandboxed_yarn_copy_is_made_under_the_scan_s_output_directory(
    online, tmp_path
):
    """yarn reads .yarnrc, .npmrc and .yarnrc.yml from its directory and every
    parent. The copy used to be made under the system temporary directory, whose
    ancestors on a shared host (/tmp) every user can write to, so a settings file
    planted there would have redirected the audit. With the output directory
    outside the scanned tree the copy goes there, as npm's and pnpm's do, and the
    temporary directory is not on yarn's path. The ``online`` fixture is what
    points the temporary directory at ``system-tmp``."""
    spawns = _record(online, yarn_version="1.22.22")
    scanner = _scanner(tmp_path)
    _repository(scanner.context.source_dir, "yarn.lock")
    system_tmp = tmp_path / "system-tmp"

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    for spawn in _probes(spawns) + _audits(spawns):
        cwd = spawn["cwd"]
        assert cwd.is_relative_to(scanner.context.output_dir), cwd
        assert not cwd.is_relative_to(system_tmp), cwd
        assert not cwd.is_relative_to(scanner.context.source_dir), cwd
    (audit,) = _audits(spawns)
    assert audit["command"] == ["yarn", "audit", "--json"]
    assert "YARN_RC_FILENAME" not in audit["env"]
    _assert_operator_settings_untouched(audit["env"])


def test_unsandboxed_yarn_copy_uses_the_operator_s_cache_when_the_output_is_inside(
    online, tmp_path
):
    """The default output directory is inside the scanned tree, where a copy would
    put the repository's own settings files on yarn's path. The copy then goes
    under the operator's cache directory ($XDG_CACHE_HOME/ash), whose ancestors
    are the operator's own, not under the system temporary directory, and yarn
    still reads the operator's settings (no --no-default-rc, no YARN_RC_FILENAME
    on the audit). The ``online`` fixture is what points the temporary directory
    at ``system-tmp``."""
    spawns = _record(online, yarn_version="1.22.22")
    repo = tmp_path / "repo"
    scanner = _scanner(tmp_path, output_dir=repo / ".ash" / "ash_output")
    _repository(scanner.context.source_dir, "yarn.lock")
    cache_home = tmp_path / "cache-home"
    online.setenv("XDG_CACHE_HOME", str(cache_home))
    system_tmp = tmp_path / "system-tmp"

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    for spawn in _probes(spawns) + _audits(spawns):
        cwd = spawn["cwd"]
        assert cwd.is_relative_to(cache_home / "ash"), cwd
        assert not cwd.is_relative_to(system_tmp), cwd
        assert not cwd.is_relative_to(repo), cwd
    (audit,) = _audits(spawns)
    assert audit["command"] == ["yarn", "audit", "--json"]
    assert "YARN_RC_FILENAME" not in audit["env"]
    assert sorted(audit["files"]) == ["package.json", "yarn.lock"]
    # The copy is removed when the child's block ends: the directories the
    # tool ran in no longer exist. A glob on the copy's name prefix passed
    # with nothing matched when the prefix differed, and said nothing.
    for spawn in _probes(spawns) + _audits(spawns):
        assert not spawn["cwd"].exists(), spawn["cwd"]


def test_the_settings_file_yarn_is_told_to_read_is_never_one_the_package_holds(
    online, tmp_path
):
    """In-place yarn 2+ runs in the package directory and is told the settings
    file name to look for. With a fixed, published name, a package that holds a
    file of that name would have yarn read it as its settings, yarnPath and
    registry included. What this pins: the name is of the published random
    shape, it is not the former fixed name (planted here) nor the bare prefix
    (planted too), no file in the package matches it, and the probe's and the
    audit's names differ. It does NOT pin collision handling: a planted name
    with a guessed token matches a fresh 128-bit token with probability about
    2^-128, so such a plant tells nothing and none is made."""
    from automated_security_helper.utils import package_manager_child as child_module

    online.setattr(child_module, "_sandboxed", lambda: True)
    spawns = _record(online, yarn_version="3.8.7")
    scanner = _scanner(tmp_path)
    package = _repository(scanner.context.source_dir, "yarn.lock")
    # The former fixed name and the bare published prefix: the two names a
    # regression to a fixed or an empty token would produce.
    for planted in (
        ".ash-no-yarnrc.yml",
        f"{NO_YARNRC_PREFIX}.yml",
    ):
        (package / planted).write_text(
            f'yarnPath: ./marker.js\nnpmRegistryServer: "{REPOSITORY_REGISTRY}"\n',
            encoding="utf-8",
        )

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (probe,) = _probes(spawns)
    (audit,) = _audits(spawns)
    names = [probe["env"]["YARN_RC_FILENAME"], audit["env"]["YARN_RC_FILENAME"]]
    for name in names:
        assert is_no_yarnrc_name(name), name
        assert not (package / name).exists(), name
        assert not (package / name).is_symlink(), name
    assert names[0] != names[1], names


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
