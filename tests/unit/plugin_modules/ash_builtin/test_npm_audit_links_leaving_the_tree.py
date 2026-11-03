# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit audits no file that is a link leaving the scanned tree.

npm, pnpm and yarn read whatever a link points at (npm 10.9.4, pnpm 12.6.0 and
yarn 1.22.22), and none of the three has an option not to follow links, so every
file a package manager would read has to resolve inside the scanned tree.

Every file the package manager reads from the package (the manifest, each lockfile it
would read, and for yarn every workspace manifest below it) must resolve inside
the scanned tree and be a regular file. When one does not, that package is not
audited, and the scan fails naming the file with the reason "link leaves the scanned
tree", as it does for any lockfile that went unaudited online. A link that stays
inside the tree is followed as before.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.core.exceptions import ScannerError
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
from tests.utils.aws_isolation import isolate_from_aws
from tests.utils.npm_audit_reports import (
    NPM_CLEAN,
    PNPM_CLEAN,
    YARN_1_NO_ADVISORIES,
)

pytestmark = pytest.mark.unit

#: In every file outside the scanned tree; it must reach no output.
MARKER = "outside-content-7f3a"
REASON = "link leaves the scanned tree"
#: Each tool's own clean report (tests/utils/npm_audit_reports.py): pnpm's is
#: keyed advisories, so an npm-shaped document is not a pnpm report. yarn 1's
#: clean report is the module's capture too (classic-clean.json).
NO_ADVISORIES = NPM_CLEAN
LOCKFILES = {
    "npm": "package-lock.json",
    "pnpm": "pnpm-lock.yaml",
    "yarn": "yarn.lock",
}


@pytest.fixture
def online(monkeypatch, tmp_path):
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return monkeypatch


@pytest.fixture
def spawns(monkeypatch) -> List[Dict[str, Any]]:
    """Every command npm-audit starts, with the files in its directory (read then)."""
    started: List[Dict[str, Any]] = []

    def fake_run(self, command, **kwargs):
        cwd = Path(kwargs["cwd"]) if kwargs.get("cwd") is not None else None
        files = {}
        if cwd is not None:
            for path in sorted(cwd.rglob("*")):
                if path.is_file():
                    files[path.relative_to(cwd).as_posix()] = path.read_text()
        started.append({"command": [str(p) for p in command], "files": files})
        if "--version" in command:
            return {"stdout": "1.22.22\n", "returncode": 0}
        if command[0] == "yarn":
            return {"stdout": YARN_1_NO_ADVISORIES, "returncode": 0}
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
    return started


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


def _outside(tmp_path: Path, name: str, text: str | None = None) -> Path:
    """A file outside the scanned tree holding the marker."""
    path = tmp_path / "outside" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        text if text is not None else json.dumps({"name": MARKER}), encoding="utf-8"
    )
    return path


def _package(root: Path, lockfile: str, name: str = "web") -> Path:
    package = root / name
    package.mkdir(parents=True, exist_ok=True)
    (package / "package.json").write_text(json.dumps({"name": name}), encoding="utf-8")
    (package / lockfile).write_text("{}\n", encoding="utf-8")
    return package


def _link(link: Path, target: Path) -> None:
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink(target, link)


def _audits(spawns) -> List[Dict[str, Any]]:
    return [s for s in spawns if "audit" in s["command"]]


def _no_marker_under(directory: Path) -> None:
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert MARKER not in path.read_bytes().decode("utf-8", "replace"), path


def _refused(scanner: NpmAuditScanner, *shown: str) -> ScannerError:
    """The scan fails, naming each refused file once with the reason."""
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=scanner.context.source_dir, target_type="source")
    message = str(raised.value)
    assert MARKER not in message
    assert f"could not audit {len(shown)} lockfile(s)" in message, message
    for path in shown:
        assert message.count(f"{path}: {REASON}") == 1, message
    return raised.value


@pytest.mark.parametrize("binary", sorted(LOCKFILES))
def test_a_linked_lockfile_that_leaves_the_tree_is_not_audited(
    online, spawns, tmp_path, binary
):
    scanner = _scanner(tmp_path)
    lockfile = LOCKFILES[binary]
    package = _package(scanner.context.source_dir, lockfile)
    _link(package / lockfile, _outside(tmp_path, lockfile))

    _refused(scanner, f"web/{lockfile}")

    assert spawns == [], "a package manager was started for the linked lockfile"
    _no_marker_under(scanner.context.output_dir)


def test_a_linked_manifest_that_leaves_the_tree_is_not_audited(
    online, spawns, tmp_path
):
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "package-lock.json")
    _link(package / "package.json", _outside(tmp_path, "package.json"))

    _refused(scanner, "web/package.json")

    assert spawns == []
    _no_marker_under(scanner.context.output_dir)


# The scan set leaves out a file link whose target is outside the tree, so a linked
# package.json never reaches npm-audit through it. The package is found from its
# lockfile instead, when a package.json sits beside it that the scan set left out.


def test_a_linked_manifest_still_counts_as_something_to_scan(online, tmp_path):
    """The selection the scan makes is the one that says whether to run at all."""
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "package-lock.json")
    _link(package / "package.json", _outside(tmp_path, "package.json"))

    assert scanner.nothing_to_scan_reason() is None


def test_a_dangling_manifest_link_beside_a_lockfile_is_not_audited(
    online, spawns, tmp_path
):
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "package-lock.json")
    _link(package / "package.json", tmp_path / "outside" / "missing.json")

    _refused(scanner, "web/package.json")

    assert spawns == []


def test_a_package_with_several_lockfiles_is_refused_once(online, spawns, tmp_path):
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "package-lock.json")
    for lockfile in ("pnpm-lock.yaml", "yarn.lock"):
        (package / lockfile).write_text("\n", encoding="utf-8")
    _link(package / "package.json", _outside(tmp_path, "package.json"))

    _refused(scanner, "web/package.json")

    assert spawns == []


def test_an_ignored_package_whose_manifest_links_out_is_not_a_failure(
    online, spawns, tmp_path
):
    """Under a global ignore path the package is not one npm-audit audits, so its
    linked manifest neither starts a tool nor fails the scan."""
    from automated_security_helper.models.core import IgnorePathWithReason

    scanner = _scanner(tmp_path)
    scanner.context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="vendor/", reason="vendored")
    ]
    package = _package(scanner.context.source_dir / "vendor", "package-lock.json")
    _link(package / "package.json", _outside(tmp_path, "package.json"))

    result = scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert result is not False
    assert spawns == []


def test_an_orphan_lockfile_is_left_as_before(online, spawns, tmp_path):
    """A lockfile with no package.json beside it is not a package: nothing is
    started and nothing fails, as before."""
    scanner = _scanner(tmp_path)
    orphan = scanner.context.source_dir / "web"
    orphan.mkdir()
    (orphan / "package-lock.json").write_text("{}\n", encoding="utf-8")

    result = scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert result is not False
    assert spawns == []


def _whole_scan(tmp_path: Path, monkeypatch) -> tuple[int, Dict[str, Any]]:
    """An online npm-audit-only scan of tmp_path/repo; its exit code and results."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    code = 0
    try:
        run_ash_scan(
            source_dir=str(tmp_path / "repo"),
            output_dir=str(tmp_path / "out"),
            offline=False,
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            show_summary=True,
            quiet=False,
            color=False,
            scanners=["npm-audit"],
        )
    except SystemExit as exit_:
        code = int(exit_.code or 0)
    results = json.loads((tmp_path / "out" / "ash_aggregated_results.json").read_text())
    return code, results


def test_the_whole_scan_fails_for_a_linked_manifest(
    online, spawns, tmp_path, monkeypatch
):
    package = _package(tmp_path / "repo", "package-lock.json")
    _link(package / "package.json", _outside(tmp_path, "package.json"))

    code, results = _whole_scan(tmp_path, monkeypatch)

    assert code == 1, "a package left unaudited must fail the scan"
    assert results["scanner_results"]["npm-audit"]["status"] == "ERROR"
    assert spawns == []
    _no_marker_under(tmp_path / "out")


def test_when_the_manifest_and_the_lockfile_both_link_out_nothing_is_audited(
    online, spawns, tmp_path, monkeypatch
):
    """Nothing of the package is in the tree, so there is nothing to start."""
    package = _package(tmp_path / "repo", "package-lock.json")
    _link(package / "package.json", _outside(tmp_path, "package.json"))
    _link(package / "package-lock.json", _outside(tmp_path, "lock.json"))

    _whole_scan(tmp_path, monkeypatch)

    assert spawns == []
    _no_marker_under(tmp_path / "out")


def test_a_linked_shrinkwrap_beside_a_regular_lockfile_is_not_audited(
    online, spawns, tmp_path
):
    """npm reads npm-shrinkwrap.json ahead of package-lock.json, so it counts too."""
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "package-lock.json")
    _link(package / "npm-shrinkwrap.json", _outside(tmp_path, "shrinkwrap.json"))

    _refused(scanner, "web/npm-shrinkwrap.json")

    assert spawns == []


@pytest.mark.parametrize("sandboxed", [False, True])
@pytest.mark.parametrize("linked", ["manifest", "directory"])
def test_a_yarn_workspace_member_linked_outside_is_not_audited(
    online, spawns, tmp_path, sandboxed, linked
):
    """yarn reads every member's manifest: from the copy, and in place under a
    sandbox, where it would follow the link itself."""
    online.setattr(child_module, "_sandboxed", lambda: sandboxed)
    scanner = _scanner(tmp_path)
    package = _package(scanner.context.source_dir, "yarn.lock")
    members = package / "packages"
    members.mkdir()
    outside_manifest = _outside(tmp_path, "api/package.json")
    if linked == "manifest":
        (members / "api").mkdir()
        _link(members / "api" / "package.json", outside_manifest)
    else:
        _link(members / "api", outside_manifest.parent)

    _refused(scanner, "web/packages/api/package.json")

    assert spawns == []


def test_another_package_is_still_audited(online, spawns, tmp_path):
    """Only the package whose file leaves the tree goes unaudited."""
    scanner = _scanner(tmp_path)
    linked = _package(scanner.context.source_dir, "package-lock.json", name="web")
    _link(linked / "package-lock.json", _outside(tmp_path, "lock.json"))
    _package(scanner.context.source_dir, "package-lock.json", name="api")

    _refused(scanner, "web/package-lock.json")

    (audit,) = _audits(spawns)
    assert json.loads(audit["files"]["package.json"]) == {"name": "api"}


def test_control_an_in_tree_regular_lockfile_is_audited(online, spawns, tmp_path):
    scanner = _scanner(tmp_path)
    _package(scanner.context.source_dir, "package-lock.json")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert sorted(audit["files"]) == ["package-lock.json", "package.json"]


@pytest.mark.parametrize("binary", sorted(LOCKFILES))
def test_an_in_tree_link_to_an_in_tree_lockfile_is_still_audited(
    online, spawns, tmp_path, binary
):
    scanner = _scanner(tmp_path)
    lockfile = LOCKFILES[binary]
    package = _package(scanner.context.source_dir, lockfile)
    shared = scanner.context.source_dir / "shared" / lockfile
    shared.parent.mkdir()
    shared.write_text("# the shared lockfile\n", encoding="utf-8")
    _link(package / lockfile, shared)

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["files"][lockfile] == "# the shared lockfile\n"


def test_a_link_into_another_project_of_the_workspace_is_audited(
    online, spawns, tmp_path
):
    """In workspace mode the scanned tree is the workspace root."""
    workspace = tmp_path / "ws"
    context = PluginContext(
        source_dir=workspace / "web",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    context.config._scanned_root = workspace
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    package = _package(context.source_dir, "package-lock.json", name="app")
    sibling = _package(workspace, "package-lock.json", name="api")
    (sibling / "package-lock.json").write_text("# the api lockfile\n")
    _link(package / "package-lock.json", sibling / "package-lock.json")

    scanner.scan(target=context.source_dir, target_type="source")

    (audit,) = _audits(spawns)
    assert audit["files"]["package-lock.json"] == "# the api lockfile\n"


@pytest.mark.parametrize("binary", ["npm", "pnpm", "yarn"])
def test_the_child_copies_no_file_that_leaves_the_tree(tmp_path, binary):
    """Called directly, without the scanner's refusal: the copy holds no outside
    file. It refuses the package instead of copying without the lockfile; yarn
    run in place (no directory outside the tree could hold its copy) copies
    nothing and is started in the package directory."""
    root = tmp_path / "repo"
    lockfile = LOCKFILES[binary]
    package = _package(root, lockfile)
    _link(package / lockfile, _outside(tmp_path, lockfile))
    results = tmp_path / "results"
    results.mkdir()

    try:
        with package_manager_child(
            binary, package, parent=results, scan_root=root, yarn_major=1
        ) as child:
            assert binary == "yarn" and child.cwd == package
    except child_module.InputRefused as refused:
        assert MARKER not in str(refused)
        assert lockfile in str(refused)


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_an_input_refused_as_the_copy_opens_it_fails_that_audit(
    online, spawns, tmp_path, binary
):
    """The package passes the scanner's check, and the copy then finds the open
    file outside the tree (a swap between the two; hooked here through the
    descriptor's own place). The copy used to leave the file out and the audit
    ran on what was left with nothing recorded; the refusal is raised and the
    scan loop records it for the lockfile. The emitter of the
    "the audit raised" text is the scan loop's failure list
    (npm_audit_scanner.py, ``audit_failures``)."""
    online.setattr(child_module, "_descriptor_within", lambda fd, roots: False)
    scanner = _scanner(tmp_path)
    lockfile = LOCKFILES[binary]
    _package(scanner.context.source_dir, lockfile)

    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=scanner.context.source_dir, target_type="source")

    message = str(raised.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert f"web/{lockfile}: the audit raised InputRefused" in message, message
    assert _audits(spawns) == [], "an audit was started on a copy missing a file"


def test_the_whole_scan_reports_it_and_no_outside_content_reaches_any_output(
    online, spawns, tmp_path, monkeypatch, capsys, caplog
):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    package = _package(tmp_path / "repo", "package-lock.json")
    _link(package / "package-lock.json", _outside(tmp_path, "lock.json"))
    output = tmp_path / "out"
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    code = 0
    try:
        run_ash_scan(
            source_dir=str(tmp_path / "repo"),
            output_dir=str(output),
            offline=False,
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            show_summary=True,
            quiet=False,
            color=False,
            scanners=["npm-audit"],
        )
    except SystemExit as exit_:
        code = int(exit_.code or 0)

    assert code == 1, "a package left unaudited must fail the scan"
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    # ERROR, as when an audit fails: those dependencies were not checked.
    assert results["scanner_results"]["npm-audit"]["status"] == "ERROR"
    assert spawns == []
    _no_marker_under(output)
    captured = capsys.readouterr()
    assert MARKER not in captured.out and MARKER not in captured.err
    assert MARKER not in caplog.text
