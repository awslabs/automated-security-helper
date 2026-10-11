# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under offline mode no scanner runs an update, telemetry or version check.

What was measured
-----------------
Every scanner was run as ASH runs it under ``--offline`` (local mode, no sandbox) in
a network namespace whose only route is a logging proxy that answers 403, plus a
logging DNS server for tools that ignore proxies, with a fresh home directory so no
tool could answer from a cache it filled earlier:

* trivy-repo contacted ``check.trivy.dev`` on every run. ``--skip-check-update``,
  which ASH passes, only skips the misconfiguration checks bundle; trivy's version
  check is ``--skip-version-check``. trivy sends the request whenever either the
  version check or telemetry is on, so ``--disable-telemetry`` is needed as well,
  and that one comes from the ``disable_telemetry`` option, which any config can
  set to false.
* trivy-repo runs with the scanned directory as its working directory, where trivy
  reads ``trivy.yaml``. Such a file in the scanned repository turned on a VEX
  repository download (``api.github.com``) and client/server mode (the scan sent
  its analysis to a host the file named), with every offline flag ASH passes in
  place.
* semgrep contacted ``semgrep.dev`` from both ``semgrep scan`` and
  ``semgrep --version``: its version check is on unless ``--disable-version-check``
  or ``SEMGREP_ENABLE_VERSION_CHECK=0``. ASH passes ``--metrics off`` only, which is
  a different switch. A warm version cache hides it for a day, which is why a scan
  on a developer machine usually shows nothing.
* syft reads ``.syft.yaml`` from the scanned tree (ASH passes the file with
  ``--config``, and syft also finds it in its working directory, which is the
  scanned tree). With ``golang.search-remote-licenses`` (or ``enrich``) set there it
  contacted ``proxy.golang.org`` and ``github.com`` offline. Setting
  ``SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false`` in the environment overrode the file.
* grype (GRYPE_CHECK_FOR_APP_UPDATE, GRYPE_DB_AUTO_UPDATE), checkov
  (``--skip-download``), opengrep, bandit, cfn-nag, cdk-nag and npm-audit
  (``--offline``) made no request; snyk-code does not run offline.

How these tests observe it
--------------------------
No tool binary is needed and nothing is started: the spawn helper behind
``PluginBase._run_subprocess`` is replaced by a recorder, each scanner is built and
its ``scan`` driven with ``ASH_OFFLINE=YES``, and the assertions read the argv,
environment and working directory the scanner handed over. A flag or its
environment-variable form is accepted wherever the tool documents both, so the
tests hold whichever one a fix uses. The semgrep version probe runs through
``subprocess.run`` with a fake semgrep on PATH (the same harness as
``scanners/test_pre_installed_tool_offline.py``).

``ASH_OFFLINE`` is set directly rather than through ``--offline`` because offline
mode is documented as either: ``--offline``, or ``ASH_OFFLINE`` in the environment
(an image built with ``--offline`` sets it).
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.pre_installed_tool import (
    reset_pre_installed_tool_cache,
)
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

_FALSE = {"0", "false", "f", "no", "n", "off"}
_TRUE = {"1", "true", "t", "yes", "y", "on"}


@dataclass
class Spawn:
    command: List[str]
    env: Dict[str, str]
    cwd: Path

    def has_flag(self, flag: str) -> bool:
        return any(arg == flag or arg.startswith(f"{flag}=") for arg in self.command)

    def flag_values(self, *names: str) -> List[str]:
        values = []
        for index, arg in enumerate(self.command):
            for name in names:
                if arg == name and index + 1 < len(self.command):
                    values.append(self.command[index + 1])
                elif arg.startswith(f"{name}="):
                    values.append(arg.split("=", 1)[1])
        return values

    def env_is(self, name: str, accepted: set) -> bool:
        return str(self.env.get(name, "")).strip().lower() in accepted


class SpawnRecorder:
    """Stands in for ``run_command_with_output_handling`` and starts nothing."""

    def __init__(self) -> None:
        self.spawns: List[Spawn] = []

    def __call__(self, command, *args, **kwargs):
        env = kwargs.get("env")
        cwd = kwargs.get("cwd")
        self.spawns.append(
            Spawn(
                command=[str(part) for part in command],
                env=dict(env) if env is not None else dict(os.environ),
                cwd=Path(cwd) if cwd is not None else Path.cwd(),
            )
        )
        return {"returncode": 0, "stdout": "", "stderr": ""}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Nothing here should start a real tool; if one did, it reaches only this."""
    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    yield proxy
    proxy.close()
    assert proxy.external_requests() == [], proxy.requests


def _inside(path: Path, root: Path) -> bool:
    return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(root)))


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    for name in (
        "TRIVY_CONFIG",
        "TRIVY_SKIP_VERSION_CHECK",
        "TRIVY_DISABLE_TELEMETRY",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "SYFT_CONFIG",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return monkeypatch


@pytest.fixture
def rules_cache(tmp_path, monkeypatch):
    """A local rule cache, without which offline semgrep and opengrep do not run."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "local.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(rules))
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(rules))
    return rules


@pytest.fixture
def context(tmp_path) -> PluginContext:
    """A scanned tree with a tool config of every kind in it, and a converted dir."""
    ctx = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    (ctx.source_dir / "go.mod").write_text("module example.com/m\n\ngo 1.21\n")
    (ctx.work_dir / "nb-converted.py").write_text("print('hi')\n")
    # What a repository can commit to change how the tool behaves.
    (ctx.source_dir / "trivy.yaml").write_text(
        "vulnerability:\n  vex:\n    - repo\nserver:\n  addr: http://ash-test.invalid:4954\n"
    )
    (ctx.source_dir / ".syft.yaml").write_text(
        "golang:\n  search-remote-licenses: true\nenrich: [all]\n"
    )
    return ctx


def _target(ctx: PluginContext, target_type: str) -> Path:
    return ctx.source_dir if target_type == "source" else ctx.work_dir


def _drive_scan(scanner, target: Path, target_type: str):
    """Run ``scanner.scan``; return its result, or the exception it raised.

    No tool runs in these tests, so a scanner that goes on to read its result file
    raises. The tests read the recorded spawns, not the scan's outcome.
    """
    try:
        return scanner.scan(target=target, target_type=target_type)
    except Exception as error:
        return error


def _record_scan(scanner, ctx: PluginContext, target_type: str, monkeypatch) -> Spawn:
    """Drive ``scanner.scan`` with the spawn recorded; return the tool's scan call."""
    recorder = SpawnRecorder()
    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", recorder)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    if "use_uv_tool" in type(scanner).model_fields:
        scanner.use_uv_tool = False
    target = _target(ctx, target_type)
    _drive_scan(scanner, target, target_type)
    calls = [
        spawn
        for spawn in recorder.spawns
        if any(target.as_posix() in arg for arg in spawn.command)
    ]
    assert calls, (
        f"{type(scanner).__name__} started no scan of {target}: {recorder.spawns}"
    )
    return calls[-1]


TARGET_TYPES = pytest.mark.parametrize("target_type", ["source", "converted"])


# ---------------------------------------------------------------------------
# trivy-repo
# ---------------------------------------------------------------------------


def _trivy(ctx, **options) -> TrivyRepoScanner:
    return TrivyRepoScanner(
        context=ctx,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


class TestTrivyRepoOffline:
    @TARGET_TYPES
    def test_version_check_is_off(self, offline, context, target_type):
        spawn = _record_scan(_trivy(context), context, target_type, offline)

        assert spawn.has_flag("--skip-version-check") or spawn.env_is(
            "TRIVY_SKIP_VERSION_CHECK", _TRUE
        ), (
            "offline trivy runs its version check against check.trivy.dev: "
            f"{spawn.command}"
        )

    @TARGET_TYPES
    def test_telemetry_is_off_even_when_the_config_turns_it_on(
        self, offline, context, target_type
    ):
        """``disable_telemetry: false`` is settable from any config, the repository's
        included; trivy then still contacts check.trivy.dev to send usage data."""
        spawn = _record_scan(
            _trivy(context, disable_telemetry=False), context, target_type, offline
        )

        assert spawn.has_flag("--disable-telemetry") or spawn.env_is(
            "TRIVY_DISABLE_TELEMETRY", _TRUE
        ), f"offline trivy sends telemetry: {spawn.command}"

    @TARGET_TYPES
    def test_trivy_yaml_in_the_scanned_tree_is_not_read(
        self, offline, context, target_type
    ):
        """trivy reads ``--config`` (default ``trivy.yaml`` in its working directory).

        The fixture tree's trivy.yaml turns on a VEX repository download and
        client/server mode, both of which reach the network with every offline flag
        in place.
        """
        spawn = _record_scan(_trivy(context), context, target_type, offline)

        named = spawn.flag_values("--config", "-c")
        if named:
            config_files = [
                Path(value) if Path(value).is_absolute() else spawn.cwd / value
                for value in named
            ]
        elif spawn.env.get("TRIVY_CONFIG"):
            config_files = [Path(spawn.env["TRIVY_CONFIG"])]
        else:
            config_files = [spawn.cwd / "trivy.yaml"]
        in_tree = [
            path.as_posix()
            for path in config_files
            if _inside(path, context.source_dir) or _inside(path, context.output_dir)
        ]
        assert in_tree == [], (
            f"offline trivy reads its config from the scanned tree ({in_tree}); "
            f"cwd={spawn.cwd}, argv={spawn.command}"
        )

    @TARGET_TYPES
    def test_control_database_and_checks_updates_are_off(
        self, offline, context, target_type
    ):
        spawn = _record_scan(_trivy(context), context, target_type, offline)

        for flag in (
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--skip-check-update",
        ):
            assert spawn.has_flag(flag), (flag, spawn.command)

    def test_control_online_scan_is_not_offline(self, online, context):
        spawn = _record_scan(_trivy(context), context, "source", online)

        assert not spawn.has_flag("--offline-scan"), spawn.command


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


def _semgrep_version_check_off(spawn: Spawn) -> bool:
    return spawn.has_flag("--disable-version-check") or spawn.env_is(
        "SEMGREP_ENABLE_VERSION_CHECK", _FALSE
    )


class TestSemgrepOffline:
    @TARGET_TYPES
    def test_version_check_is_off(self, offline, rules_cache, context, target_type):
        scanner = SemgrepScanner(context=context, config=SemgrepScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert _semgrep_version_check_off(spawn), (
            "offline semgrep checks semgrep.dev for a newer version: "
            f"argv={spawn.command}, "
            f"SEMGREP_ENABLE_VERSION_CHECK={spawn.env.get('SEMGREP_ENABLE_VERSION_CHECK')!r}"
        )

    @TARGET_TYPES
    def test_control_metrics_are_off(self, offline, rules_cache, context, target_type):
        scanner = SemgrepScanner(context=context, config=SemgrepScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert spawn.flag_values("--metrics") == ["off"], spawn.command


class TestOpengrepOffline:
    @TARGET_TYPES
    def test_control_rules_come_only_from_local_files(
        self, offline, rules_cache, context, target_type
    ):
        scanner = OpengrepScanner(context=context, config=OpengrepScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        configs = spawn.flag_values("--config")
        assert configs, spawn.command
        assert all(Path(value).exists() for value in configs), (
            f"offline opengrep names a rule source that is not a local path: {configs}"
        )
        assert spawn.flag_values("--metrics") in ([], ["off"]), spawn.command


# ---------------------------------------------------------------------------
# syft
# ---------------------------------------------------------------------------

#: The syft settings that reach the network (``syft config``, syft 1.42), and the
#: value that turns each off. ``enrich`` only switches these on, so forcing them
#: off in the environment overrides an ``enrich`` from a config file (measured for
#: golang).
SYFT_NETWORK_SWITCHES = (
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES",
    "SYFT_GOLANG_USE_PACKAGES_LIB",
    "SYFT_JAVA_USE_NETWORK",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES",
    "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE",
)


class TestSyftOffline:
    @TARGET_TYPES
    def test_syft_yaml_in_the_scanned_tree_cannot_turn_on_network_lookups(
        self, offline, context, target_type
    ):
        """Either syft never reads the tree's .syft.yaml, or every setting that
        reaches the network is forced off in its environment (which overrides a
        config file)."""
        scanner = SyftScanner(context=context, config=SyftScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        named = [
            Path(value) if Path(value).is_absolute() else spawn.cwd / value
            for value in spawn.flag_values("--config", "-c")
        ]
        reads_tree_config = any(
            _inside(path, context.source_dir) for path in named
        ) or (not named and _inside(spawn.cwd, context.source_dir))
        forced_off = all(spawn.env_is(name, _FALSE) for name in SYFT_NETWORK_SWITCHES)

        assert not reads_tree_config or forced_off, (
            "offline syft reads the scanned tree's .syft.yaml, which can turn on "
            f"remote license and package lookups: cwd={spawn.cwd}, "
            f"argv={spawn.command}, "
            f"switches={ {n: spawn.env.get(n) for n in SYFT_NETWORK_SWITCHES} }"
        )

    @TARGET_TYPES
    def test_control_app_update_check_is_off(self, offline, context, target_type):
        scanner = SyftScanner(context=context, config=SyftScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert spawn.env_is("SYFT_CHECK_FOR_APP_UPDATE", _FALSE), spawn.env.get(
            "SYFT_CHECK_FOR_APP_UPDATE"
        )


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------


def _checkov_update_check_off(spawn: Spawn) -> bool:
    # checkov.common.util.banner runs the PyPI check at import, for every command,
    # unless CKV_SKIP_PACKAGE_UPDATE_CHECK is true; --skip-download does not cover it.
    return spawn.env_is("CKV_SKIP_PACKAGE_UPDATE_CHECK", _TRUE)


class TestCheckovOffline:
    @TARGET_TYPES
    def test_package_update_check_is_off(self, offline, context, target_type):
        scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert _checkov_update_check_off(spawn), (
            "offline checkov asks pypi.org for a newer checkov: "
            f"CKV_SKIP_PACKAGE_UPDATE_CHECK={spawn.env.get('CKV_SKIP_PACKAGE_UPDATE_CHECK')!r}"
        )

    @TARGET_TYPES
    def test_control_downloads_nothing_and_runs_outside_the_tree(
        self, offline, context, target_type
    ):
        scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert spawn.has_flag("--skip-download"), spawn.command
        assert not _inside(spawn.cwd, context.source_dir), spawn.cwd


# ---------------------------------------------------------------------------
# npm-audit
# ---------------------------------------------------------------------------


def _npm_update_notifier_off(spawn: Spawn) -> bool:
    if spawn.has_flag("--no-update-notifier"):
        return True
    if "false" in [v.lower() for v in spawn.flag_values("--update-notifier")]:
        return True
    return any(
        name.lower() == "npm_config_update_notifier"
        and str(value).strip().lower() in _FALSE
        for name, value in spawn.env.items()
    )


def _npm_audit_spawns(context, lock_name: str, binary: str, monkeypatch) -> List[Spawn]:
    """Drive npm-audit over one project whose lockfile picks ``binary``."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        npm_audit_scanner as npm_audit_module,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
        NpmAuditScannerConfig,
    )

    project = context.source_dir / "web"
    project.mkdir()
    (project / "package.json").write_text('{"name": "web", "version": "1.0.0"}')
    (project / lock_name).write_text("{}" if lock_name.endswith(".json") else "")
    report = {"npm": '{"vulnerabilities": {}}', "pnpm": '{"advisories": {}}'}

    spawns: List[Spawn] = []

    def fake_run(command, **kwargs):
        env = kwargs.get("env")
        spawns.append(
            Spawn(
                command=[str(part) for part in command],
                env=dict(env) if env is not None else dict(os.environ),
                cwd=Path(kwargs.get("cwd") or context.source_dir),
            )
        )
        return {"stdout": report.get(binary, "{}"), "returncode": 0}

    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(
        npm_audit_module, "find_executable", lambda name: f"/usr/local/bin/{name}"
    )
    monkeypatch.setattr(
        npm_audit_module, "scan_set", lambda **kwargs: [str(project / "package.json")]
    )
    monkeypatch.setattr(type(scanner), "_pre_scan", lambda self, **kwargs: True)
    monkeypatch.setattr(type(scanner), "_post_scan", lambda self, **kwargs: None)
    monkeypatch.setattr(
        type(scanner),
        "_run_subprocess",
        lambda self, command, **kwargs: fake_run(command, **kwargs),
    )
    _drive_scan(scanner, context.source_dir, "source")
    return [
        s for s in spawns if Path(s.command[0]).name == binary and "audit" in s.command
    ]


class TestNpmAuditOffline:
    def test_offline_npm_audit_starts_no_npm(self, offline, context):
        """``npm audit --offline`` still asked registry.npmjs.org whether a newer
        npm exists (measured with npm 10.9.4 and an empty npm cache), and audited
        nothing: the advisories come from the registry. Offline no npm runs."""
        audits = _npm_audit_spawns(context, "package-lock.json", "npm", offline)

        assert audits == [], (
            f"offline npm-audit started npm: {[s.command for s in audits]}"
        )

    def test_offline_npm_audit_records_the_lockfile_as_not_audited(
        self, offline, context, monkeypatch
    ):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
            NpmAuditScanner,
        )

        recorded = {}
        original = NpmAuditScanner._skip_offline

        def spy(self, *args, **kwargs):
            original(self, *args, **kwargs)
            recorded["inputs"] = list(self.inputs_not_scanned)

        monkeypatch.setattr(NpmAuditScanner, "_skip_offline", spy)
        _npm_audit_spawns(context, "package-lock.json", "npm", offline)

        assert [entry["path"] for entry in recorded.get("inputs", [])] == [
            "web/package-lock.json"
        ]

    def test_pnpm_audit_is_not_started(self, offline, context):
        """``pnpm audit --offline`` sends the dependency list to the registry's
        advisory endpoint anyway (measured with pnpm 12.6.0, the version the image's
        ``corepack prepare pnpm@latest`` installs today), so offline it cannot run;
        it is recorded as not audited, as ``yarn npm audit`` already is."""
        audits = _npm_audit_spawns(context, "pnpm-lock.yaml", "pnpm", offline)

        assert audits == [], (
            f"offline scan started pnpm audit: {[s.command for s in audits]}"
        )


# ---------------------------------------------------------------------------
# Scanners that already run with their checks off (controls)
# ---------------------------------------------------------------------------


class TestScannersAlreadyOfflineClean:
    @TARGET_TYPES
    def test_grype_database_and_update_checks_are_off(
        self, offline, context, target_type
    ):
        scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
        spawn = _record_scan(scanner, context, target_type, offline)

        assert spawn.env_is("GRYPE_CHECK_FOR_APP_UPDATE", _FALSE), spawn.env
        assert spawn.env_is("GRYPE_DB_AUTO_UPDATE", _FALSE), spawn.env

    def test_snyk_code_does_not_run_offline(self, offline, context):
        scanner = SnykCodeScanner(context=context)

        assert scanner.validate_plugin_dependencies() is False


# ---------------------------------------------------------------------------
# Version probes: every process of the tool, not only the scan
# ---------------------------------------------------------------------------

_EMPTY_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "fake"}}, "results": []}],
    }
)


class _FakeToolHost:
    """``tool`` installed in a venv on PATH; uv's tool dir and cache empty.

    Every ``subprocess.run`` is answered here and recorded with its environment,
    so the ``--version`` probe of the dependency check is seen as well as the scan.
    Same layout as ``scanners/test_pre_installed_tool_offline.py``.
    """

    def __init__(self, tmp_path: Path, tool: str) -> None:
        self.tool = tool
        venv_bin = tmp_path / "tool-venv" / "bin"
        venv_bin.mkdir(parents=True)
        for name in ("python", tool):
            path = venv_bin / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        self.tool_path = str(venv_bin / tool)
        self.calls: List[Spawn] = []

    def run(self, argv, *args, **kwargs):
        argv = [str(part) for part in argv]
        env = kwargs.get("env")
        self.calls.append(
            Spawn(
                command=argv,
                env=dict(env) if env is not None else dict(os.environ),
                cwd=Path(kwargs.get("cwd") or Path.cwd()),
            )
        )
        exe = Path(argv[0]).name
        if exe in ("uv", "uv.exe"):
            if argv[1:] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, "uv 0.12.19\n", "")
            if argv[1:3] == ["tool", "list"]:
                return subprocess.CompletedProcess(argv, 0, "No tools installed\n", "")
            if argv[1:3] == ["pip", "install"] and "--dry-run" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, "", "Would make no changes\n"
                )
            return subprocess.CompletedProcess(argv, 1, "", "network is disabled\n")
        if exe == self.tool:
            if "--version" in argv:
                return subprocess.CompletedProcess(argv, 0, "3.2.400\n", "")
            if "--sarif-output" in argv:
                Path(argv[argv.index("--sarif-output") + 1]).write_text(_EMPTY_SARIF)
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    def tool_processes(self) -> List[Spawn]:
        """Calls that start the tool, directly or through ``uv tool run``."""
        started = []
        for spawn in self.calls:
            exe = Path(spawn.command[0]).name
            if exe == self.tool:
                started.append(spawn)
            elif exe in ("uv", "uv.exe") and spawn.command[1:3] == ["tool", "run"]:
                if any(Path(arg).name == self.tool for arg in spawn.command[3:]):
                    started.append(spawn)
        return started


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="fakes a POSIX venv layout (bin/python next to the tool)",
)
@pytest.mark.parametrize(
    "scanner_cls, config_cls, tool, check_off",
    [
        (SemgrepScanner, SemgrepScannerConfig, "semgrep", _semgrep_version_check_off),
        (CheckovScanner, CheckovScannerConfig, "checkov", _checkov_update_check_off),
    ],
    ids=["semgrep", "checkov"],
)
def test_every_tool_process_runs_with_its_update_check_off(
    offline,
    rules_cache,
    context,
    tmp_path,
    monkeypatch,
    scanner_cls,
    config_cls,
    tool,
    check_off,
):
    """``semgrep --version`` and ``checkov --version`` run the same network check
    as their scans (measured), and ASH runs them while checking dependencies."""
    host = _FakeToolHost(tmp_path, tool)
    monkeypatch.setenv(
        "PATH", f"{Path(host.tool_path).parent}{os.pathsep}{os.environ['PATH']}"
    )
    monkeypatch.setattr(subprocess, "run", host.run)
    resets = (
        uv_tool_runner._reset_uv_tool_runner_caches,
        uv_tool_runner.reset_uv_tool_runner,
        subprocess_utils.clear_find_executable_cache,
        reset_pre_installed_tool_cache,
    )
    for reset in resets:
        reset()
    try:
        scanner = scanner_cls(context=context, config=config_cls())
        assert scanner.validate_plugin_dependencies() is True
        _drive_scan(scanner, context.source_dir, "source")
    finally:
        for reset in resets:
            reset()

    started = host.tool_processes()
    assert any("--version" in s.command for s in started), (
        f"the harness did not reach the {tool} version probe: {host.calls}"
    )
    assert any("--version" not in s.command for s in started), (
        f"the harness did not reach the {tool} scan: {host.calls}"
    )
    checking = [s.command for s in started if not check_off(s)]
    assert checking == [], (
        f"offline {tool} processes that run the tool's own update check: {checking}"
    )
