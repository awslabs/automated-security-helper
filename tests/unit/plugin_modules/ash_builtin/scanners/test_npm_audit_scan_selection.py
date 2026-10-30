# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which packages npm-audit selects, and which lockfiles it records offline.

Three shapes of the selection:

- ``scan()`` discarded the ``global_ignore_paths`` it was handed and recomputed
  its own list from the config, so ``--ignore-suppressions`` (which lifts every
  ignore path) and the client-supplied carve-out (whose entries are left to the
  SARIF step) did not reach npm-audit's file selection.
- Offline, the not-scanned record looked for yarn.lock, pnpm-lock.yaml and
  package-lock.json only, so a package with npm-shrinkwrap.json alone recorded
  nothing and the scan returned a clean, empty report instead of MISSING.
- The scan set was taken without the workspace's output directory, which every
  other reader of the scan set leaves out like the project's own.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from tests.utils.aws_isolation import isolate_from_aws
from tests.utils.npm_audit_reports import NPM_CLEAN

pytestmark = pytest.mark.unit


@pytest.fixture
def online(monkeypatch, tmp_path):
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: f"/usr/local/bin/{name}"
    )
    monkeypatch.setattr(
        NpmAuditScanner, "validate_plugin_dependencies", lambda self: True
    )
    return monkeypatch


def _context(tmp_path: Path, **extra) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
        **extra,
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return context


def _scanner(context: PluginContext) -> NpmAuditScanner:
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def _package(root: Path, lockfile: str = "package-lock.json") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": root.name}))
    (root / lockfile).write_text("{}\n", encoding="utf-8")
    return root


def _audited(monkeypatch) -> list:
    """The manifest name of each package npm-audit started an audit in.

    Read while the audit runs: the audit's working directory is the private
    copy of the package, which is removed once the audit returns."""
    started = []

    def fake_run(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4\n", "returncode": 0}
        manifest = Path(kwargs["cwd"]) / "package.json"
        started.append(json.loads(manifest.read_text())["name"])
        return {"stdout": NPM_CLEAN, "returncode": 0}

    monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
    return started


def _names(started) -> list:
    return sorted(started)


class TestTheHandedIgnoreList:
    def test_the_list_scan_is_given_decides_the_selection(self, online, tmp_path):
        """The config names no ignore path; the orchestrator's list does. The
        package under it is not audited."""
        context = _context(tmp_path)
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/", reason="vendored")
            ],
        )

        assert _names(started) == ["app"]

    def test_an_empty_list_lifts_the_config_s_ignore_paths(self, online, tmp_path):
        """Under --ignore-suppressions the orchestrator hands an empty list: the
        config's ignore paths no longer keep a package out of the audit."""
        context = _context(tmp_path, ignore_suppressions=True)
        context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/", reason="vendored")
        ]
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir, target_type="source", global_ignore_paths=[]
        )

        assert _names(started) == ["app", "vendor"]

    def test_an_empty_list_lifts_the_config_s_paths_with_suppressions_honored(
        self, online, tmp_path
    ):
        """The test above runs under --ignore-suppressions, where a list
        recomputed from the config is empty too, so it could not tell the
        handed empty list from a recomputed one. Here suppressions are honored:
        the config's vendor/ would keep its package out, and the handed empty
        list is what applies, so both packages are audited."""
        context = _context(tmp_path)
        context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/", reason="vendored")
        ]
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir, target_type="source", global_ignore_paths=[]
        )

        assert _names(started) == ["app", "vendor"]

    def test_the_handed_list_replaces_the_config_s_paths_rather_than_joining_them(
        self, online, tmp_path
    ):
        """The config names app/ and the handed list names vendor/: app is
        audited, so the config's entry did not apply beside the handed list,
        and vendor is not."""
        context = _context(tmp_path)
        context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="app/", reason="the config's entry")
        ]
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/", reason="the orchestrator's")
            ],
        )

        assert _names(started) == ["app"]

    def test_without_a_list_the_config_s_paths_apply_as_the_orchestrator_applies_them(
        self, online, tmp_path
    ):
        """Called with no list (a direct caller), the selection computes the
        orchestrator's list from the config: the operator's entry keeps its
        package out, a client-supplied entry does not (its findings are left to
        the SARIF step), and under --ignore-suppressions none applies."""
        context = _context(tmp_path)
        context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/", reason="vendored"),
            IgnorePathWithReason(
                path="client/", reason="the delivered config", client_supplied=True
            ),
        ]
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        _package(context.source_dir / "client")
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert _names(started) == ["app", "client"]

    def test_without_a_list_ignore_suppressions_lifts_the_config_s_paths(
        self, online, tmp_path
    ):
        context = _context(tmp_path, ignore_suppressions=True)
        context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/", reason="vendored")
        ]
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert _names(started) == ["app", "vendor"]

    def test_an_expired_entry_in_the_handed_list_keeps_nothing_out(
        self, online, tmp_path
    ):
        """Every reader of an ignore list drops the entries whose expiration has
        passed; the handed list was used as given, so an expired entry still
        kept its package out of the audit."""
        context = _context(tmp_path)
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(
                    path="vendor/", reason="vendored", expiration="2000-01-01"
                )
            ],
        )

        assert _names(started) == ["app", "vendor"]

    def test_nothing_to_scan_reason_answers_from_the_handed_list(
        self, online, tmp_path
    ):
        """The one package is under the handed ignore path, so the scan audits
        nothing; the reason the executor then asks for has to say so, from the
        same selection, where a list recomputed from the config found the
        package and answered None."""
        context = _context(tmp_path)
        _package(context.source_dir / "vendor")
        started = _audited(online)
        scanner = _scanner(context)

        scanner.scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/", reason="vendored")
            ],
        )

        assert _names(started) == []
        reason = scanner.nothing_to_scan_reason()
        assert reason is not None and "no lockfile" in reason, reason
        # A scanner that was never handed a list still answers from the config.
        assert _scanner(context).nothing_to_scan_reason() is None

    def test_nothing_to_scan_reason_follows_the_last_scan_on_a_reused_instance(
        self, online, tmp_path
    ):
        """The same instance, scanned twice: first with the ignore path, then
        with no list. The reason follows the LAST call's list, so after the
        second scan the package is found again and the answer is None; a list
        kept from the first call would still say the package was ignored."""
        context = _context(tmp_path)
        _package(context.source_dir / "vendor")
        started = _audited(online)
        scanner = _scanner(context)

        scanner.scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/", reason="vendored")
            ],
        )
        assert scanner.nothing_to_scan_reason() is not None
        scanner.scan(target=context.source_dir, target_type="source")

        assert _names(started) == ["vendor"]
        assert scanner.nothing_to_scan_reason() is None


class TestOfflineShrinkwrap:
    def test_a_shrinkwrap_only_package_is_recorded_as_not_audited(
        self, tmp_path, monkeypatch
    ):
        """Offline, the lockfile npm would audit (npm-shrinkwrap.json) is named in
        inputs_not_scanned and scan() returns False, as for the other lockfiles,
        instead of an empty report that read as a clean audit."""
        monkeypatch.setenv("ASH_OFFLINE", "true")
        context = _context(tmp_path)
        _package(context.source_dir / "app", "npm-shrinkwrap.json")
        scanner = _scanner(context)
        monkeypatch.setattr(
            npm_audit_scanner, "find_executable", lambda name: f"/usr/local/bin/{name}"
        )

        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(NpmAuditScanner, "_run_subprocess", autospec=True) as run,
        ):
            result = scanner.scan(target=context.source_dir, target_type="source")

        assert run.call_count == 0
        assert result is False
        assert [entry["path"] for entry in scanner.inputs_not_scanned] == [
            "app/npm-shrinkwrap.json"
        ]

    def test_a_shrinkwrap_beside_a_package_lock_is_the_one_recorded(
        self, tmp_path, monkeypatch
    ):
        """npm reads npm-shrinkwrap.json ahead of package-lock.json, and scan()
        audits by that order (LOCKFILE_NAMES); the offline record names the same
        file scan() would have audited."""
        monkeypatch.setenv("ASH_OFFLINE", "true")
        context = _context(tmp_path)
        app = _package(context.source_dir / "app", "npm-shrinkwrap.json")
        (app / "package-lock.json").write_text("{}\n", encoding="utf-8")
        scanner = _scanner(context)
        # As in the test above: the tool lookup is stood in for, so the
        # answer does not depend on whether npm is installed where this runs,
        # and an audit that ran anyway is caught.
        monkeypatch.setattr(
            npm_audit_scanner, "find_executable", lambda name: f"/usr/local/bin/{name}"
        )

        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(NpmAuditScanner, "_run_subprocess", autospec=True) as run,
        ):
            result = scanner.scan(target=context.source_dir, target_type="source")

        assert run.call_count == 0
        assert result is False
        assert [entry["path"] for entry in scanner.inputs_not_scanned] == [
            "app/npm-shrinkwrap.json"
        ]


class TestWorkspaceOutputDirectory:
    def test_the_workspace_output_directory_is_left_out_of_the_selection(
        self, online, tmp_path
    ):
        """In a workspace scan the scan set is read with the workspace's output
        directory, so it is left out of the walk like the project's own and every
        reader of the scan set agrees on the set: a package another project's
        converted tree left there is not audited as this project's. The
        directory sits under the scanned tree, where ignoring the argument would
        change the selection."""
        workspace_output = tmp_path / "repo" / "workspace-out"
        context = _context(tmp_path, workspace_output_dir=workspace_output)
        _package(context.source_dir / "app")
        _package(workspace_output / "other" / "converted" / "lib")
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert _names(started) == ["app"]

    def test_the_workspace_output_directory_is_skipped_by_the_package_manager_walk(
        self, tmp_path
    ):
        """The package manager's own walk (a yarn project's member manifests,
        the inputs it refuses) prunes the skip directories; only the project's
        output directory was in the list, so under a yarn project at the
        workspace root the walk went into the workspace output below it."""
        workspace_output = tmp_path / "repo" / "workspace-out"
        context = _context(tmp_path, workspace_output_dir=workspace_output)

        options = _scanner(context)._package_manager_options(
            context.output_dir / "scanners" / "npm-audit", context.source_dir
        )

        assert options["skip"] == [Path(context.output_dir), workspace_output]

    def test_no_workspace_skips_the_output_directory_only(self, tmp_path):
        context = _context(tmp_path)

        options = _scanner(context)._package_manager_options(
            context.output_dir / "scanners" / "npm-audit", context.source_dir
        )

        assert options["skip"] == [Path(context.output_dir)]

    def test_without_a_workspace_the_same_directory_is_audited(self, online, tmp_path):
        """Control: outside a workspace scan nothing names that directory, so a
        package under it is audited like any other."""
        context = _context(tmp_path)
        _package(context.source_dir / "app")
        _package(context.source_dir / "workspace-out" / "other" / "converted" / "lib")
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert _names(started) == ["app", "lib"]
