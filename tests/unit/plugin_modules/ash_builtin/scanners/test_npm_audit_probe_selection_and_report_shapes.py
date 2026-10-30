# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit's dependency probe, its package selection, and report shapes it misread.

The dependency check
--------------------
``npm --version`` ran with no timeout, in the scanned root (where npm reads the
repository's ``.npmrc``), and its raw stdout, line feed included, became the SARIF
driver version, with a literal ``1.0.0`` when nothing was printed. The check also
keyed on npm alone, so a yarn- or pnpm-only project was MISSING when npm alone was
absent though yarn or pnpm could audit it.

The selection
-------------
A lockfile re-added its package.json after an ignore path had dropped that
manifest; the lockfile beside a manifest was chosen from the filesystem, so an
ignored lockfile won over the one the scan set kept; and a lockfile that was a
link to nothing read as "no lockfile", passing the package over silently.

The reports
-----------
An error document's message, code and summary reached the error text unredacted;
a yarn 4 line the reader could not parse, or an error event, counted as a clean
report; a URL ending in ``/`` gave an empty rule id; an advisory without a URL
raised in the SARIF model; an entry or a via of the wrong type crashed the
conversion; one GHSA with several ranges was reported once per range on a copy
whose version is unknown; the vulnerable range stood in for the installed
version; a linked lockfile was placed at its target; yarn and pnpm results named
no project; a target that is a file raised a raw OS error; and the exception
text of a failed audit was logged unredacted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    _YARN_ADVISORIES_KEY,
    NpmAuditScanner,
    NpmAuditScannerConfig,
)

# Read by name, not imported: a tree without the probe timeout (the base this
# file is also run against) then fails the one assertion that reads it, instead
# of refusing to collect the whole module.
PROBE_TIMEOUT = getattr(npm_audit_scanner, "_VERSION_PROBE_TIMEOUT_SECONDS", None)
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.package_manager_child import NOT_A_REGULAR_FILE
from tests.utils.aws_isolation import isolate_from_aws
from tests.utils.npm_audit_reports import NPM_CLEAN

pytestmark = pytest.mark.unit

TOKEN = "Zq7Kx9Lm2Pw4Nv"
GHSA = "https://github.com/advisories/GHSA-xvch-5gv4-984h"


@pytest.fixture
def context(tmp_path, monkeypatch):
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return context


@pytest.fixture
def online(context, monkeypatch):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: f"/usr/local/bin/{name}"
    )
    monkeypatch.setattr(
        NpmAuditScanner, "validate_plugin_dependencies", lambda self: True
    )
    return monkeypatch


def _scanner(context: PluginContext) -> NpmAuditScanner:
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def _package(root: Path, lockfile: str = "package-lock.json") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": root.name}))
    (root / lockfile).write_text("{}\n", encoding="utf-8")
    return root


def _audited(monkeypatch, respond=None) -> list:
    """The package managers npm-audit started an audit with, in order."""
    started = []

    def fake_run(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4\n", "returncode": 0}
        started.append(command[0])
        if respond is not None:
            return respond(Path(kwargs["cwd"]))
        return {"stdout": NPM_CLEAN, "returncode": 0}

    monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
    return started


def _via(rng, url=GHSA, **extra):
    via = {
        "source": 1179,
        "name": "minimist",
        "title": "Prototype Pollution in minimist",
        "severity": "critical",
        "cwe": ["CWE-1321"],
        "range": rng,
    }
    if url is not None:
        via["url"] = url
    via.update(extra)
    return via


def _npm_report(vias, nodes=("node_modules/minimist",)):
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {
                "name": "minimist",
                "severity": "critical",
                "via": vias,
                "range": " || ".join(v["range"] for v in vias if isinstance(v, dict)),
                "nodes": list(nodes),
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"critical": 1}},
    }


def _unknown_versions(monkeypatch):
    """Stand in for the lockfile index: no node has a known installed version."""

    def identity(pkg_name, node_path, lock_rel, lock_index):
        return identity_properties(pkg_name, None, node_path)

    monkeypatch.setattr(NpmAuditScanner, "_node_identity", staticmethod(identity))


# ---------------------------------------------------------------------------
# The dependency check


class TestTheVersionProbe:
    def _probe(self, context, response, monkeypatch, present=("npm",)):
        monkeypatch.setattr(
            npm_audit_scanner,
            "find_executable",
            lambda name: f"/usr/bin/{name}" if name in present else None,
        )
        scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
        calls = []

        def fake_run(self, command, **kwargs):
            calls.append((list(command), kwargs))
            return response

        monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
        satisfied = scanner.validate_plugin_dependencies()
        return scanner, satisfied, calls

    def test_the_version_is_kept_trimmed(self, context, monkeypatch):
        scanner, satisfied, _ = self._probe(
            context, {"stdout": "10.9.4\n", "stderr": "", "returncode": 0}, monkeypatch
        )

        assert satisfied is True
        assert scanner.tool_version == "10.9.4"

    def test_a_probe_that_printed_nothing_leaves_the_version_unknown(
        self, context, monkeypatch
    ):
        """No made-up 1.0.0: the SARIF driver then carries no version."""
        scanner, _, _ = self._probe(context, {"returncode": 0}, monkeypatch)

        assert scanner.tool_version is None

    def test_the_probe_is_bounded_and_runs_outside_the_scanned_tree(
        self, context, monkeypatch
    ):
        scanner, _, calls = self._probe(
            context, {"stdout": "10.9.4\n", "returncode": 0}, monkeypatch
        )

        ((command, kwargs),) = calls
        assert command == ["npm", "--version"]
        assert PROBE_TIMEOUT is not None, "the probe has no timeout constant"
        assert kwargs.get("timeout") == PROBE_TIMEOUT
        cwd = kwargs.get("cwd")
        assert cwd is not None, "the probe ran in the scanned root"
        assert Path(cwd).is_relative_to(scanner.results_dir), cwd
        assert not Path(cwd).is_relative_to(context.source_dir), cwd
        assert not Path(cwd).exists(), "the probe directory is removed after the probe"

    def test_the_probe_directory_is_a_project_of_its_own(self, context, monkeypatch):
        """npm 7+ walks up from its working directory to the nearest package.json
        to find the project whose .npmrc it reads before answering --version.
        The results directory sits under the scanned root by default, so an
        empty probe directory still read the repository's .npmrc; a manifest
        in the probe directory stops the walk there."""
        (context.source_dir / ".npmrc").write_text(
            "//registry.example/:_authToken=${NPM_TOKEN}\n", encoding="utf-8"
        )
        monkeypatch.setattr(
            npm_audit_scanner, "find_executable", lambda name: f"/usr/bin/{name}"
        )
        scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
        seen = {}

        def fake_run(self, command, **kwargs):
            manifest = Path(kwargs["cwd"]) / "package.json"
            seen["manifest"] = manifest.read_text() if manifest.exists() else None
            return {"stdout": "10.9.4\n", "returncode": 0}

        monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)

        assert scanner.validate_plugin_dependencies() is True
        assert seen["manifest"] is not None, "the probe directory held no manifest"
        assert json.loads(seen["manifest"]) == {}


class TestWhichPackageManagersTheCheckNeeds:
    def _check(self, context, monkeypatch, present):
        monkeypatch.setattr(
            npm_audit_scanner,
            "find_executable",
            lambda name: f"/usr/bin/{name}" if name in present else None,
        )
        scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
        with patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            return_value={"stdout": "1.22.22\n", "returncode": 0},
        ):
            return scanner, scanner.validate_plugin_dependencies()

    def test_a_yarn_only_project_is_audited_without_npm(self, context, monkeypatch):
        _package(context.source_dir / "web", "yarn.lock")

        scanner, satisfied = self._check(context, monkeypatch, present={"yarn"})

        assert satisfied is True
        assert scanner.tool_version is None, "yarn's version is not npm's"

    def test_with_no_manager_installed_the_reason_names_the_needed_ones(
        self, context, monkeypatch
    ):
        _package(context.source_dir / "web", "yarn.lock")
        _package(context.source_dir / "api", "pnpm-lock.yaml")

        scanner, satisfied = self._check(context, monkeypatch, present=set())

        assert satisfied is False
        reason = scanner.dependency_unavailable_reason or ""
        assert "yarn" in reason and "pnpm" in reason, reason

    def test_with_npm_installed_a_lockfile_whose_manager_is_absent_is_scanned(
        self, context, monkeypatch
    ):
        """npm present and the tree's own managers absent: the check passes and
        scan() records each such lockfile as a failed target naming its
        manager (the absent-package-manager tests), as it did before the check
        learned about yarn and pnpm. Refusing here reported the whole scanner
        MISSING instead."""
        _package(context.source_dir / "web", "yarn.lock")
        _package(context.source_dir / "api", "pnpm-lock.yaml")

        scanner, satisfied = self._check(context, monkeypatch, present={"npm"})

        assert satisfied is True
        assert scanner.dependency_unavailable_reason is None

    def test_a_tree_with_no_lockfile_still_asks_for_npm(self, context, monkeypatch):
        scanner, satisfied = self._check(context, monkeypatch, present=set())

        assert satisfied is False
        assert "npm" in (scanner.dependency_unavailable_reason or "")

    def test_with_npm_installed_the_check_reads_no_tree(self, context, monkeypatch):
        """With npm on PATH the answer is True whatever the tree holds, so the
        check does not walk the scanned tree for the managers its lockfiles
        need: that walk, a full selection on every call, decided nothing."""
        _package(context.source_dir / "web", "yarn.lock")
        walks = []
        real_walk = NpmAuditScanner._package_manifests

        def counting(self, *args, **kwargs):
            walks.append(args)
            return real_walk(self, *args, **kwargs)

        monkeypatch.setattr(NpmAuditScanner, "_package_manifests", counting)

        scanner, satisfied = self._check(context, monkeypatch, present={"npm"})

        assert satisfied is True
        assert walks == [], walks

    def test_without_npm_the_check_reads_the_tree_once(self, context, monkeypatch):
        """Control: npm absent, the tree decides, and it is read once."""
        _package(context.source_dir / "web", "yarn.lock")
        walks = []
        real_walk = NpmAuditScanner._package_manifests

        def counting(self, *args, **kwargs):
            walks.append(args)
            return real_walk(self, *args, **kwargs)

        monkeypatch.setattr(NpmAuditScanner, "_package_manifests", counting)

        scanner, satisfied = self._check(context, monkeypatch, present={"yarn"})

        assert satisfied is True
        assert walks == [("source",)], walks


# ---------------------------------------------------------------------------
# The selection


class TestTheSelection:
    def test_an_ignored_manifest_is_not_re_added_from_its_lockfile(
        self, context, online
    ):
        """The ignore path names the package.json alone; the lockfile stays in
        the scan set and used to bring the manifest back into the audit."""
        _package(context.source_dir / "app")
        _package(context.source_dir / "vendor")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/package.json", reason="vendored")
            ],
        )

        assert started == ["npm"], started

    def test_an_ignored_lockfile_is_not_the_one_audited(self, context, online):
        """yarn.lock is ignored and package-lock.json kept: npm audits the
        package, where the filesystem probe chose yarn.lock first."""
        package = _package(context.source_dir / "app", "yarn.lock")
        (package / "package-lock.json").write_text("{}\n", encoding="utf-8")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="app/yarn.lock", reason="not this one")
            ],
        )

        assert started == ["npm"], started

    def test_a_lockfile_an_ignore_file_leaves_out_is_not_the_one_audited(
        self, context, online
    ):
        """yarn.lock is gitignored and package-lock.json kept: the walk never
        listed the yarn.lock, so the dropped-lockfile set never held it, and
        the filesystem probe still chose it. The lookup now chooses among the
        lockfiles the selection kept; npm audits the package."""
        package = _package(context.source_dir / "app", "yarn.lock")
        (package / "package-lock.json").write_text("{}\n", encoding="utf-8")
        (context.source_dir / ".gitignore").write_text("yarn.lock\n", encoding="utf-8")
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert started == ["npm"], started

    def test_a_sole_lockfile_an_ignore_file_leaves_out_is_still_audited(
        self, context, online
    ):
        """A library that lists package-lock.json in its .gitignore: the walk
        never lists the lockfile, so the selection kept none beside the
        manifest. The lookup then falls back to the one on disk, as it did
        before the selection existed; refusing it skipped the package with
        nothing recorded."""
        _package(context.source_dir / "lib", "package-lock.json")
        (context.source_dir / ".gitignore").write_text(
            "package-lock.json\n", encoding="utf-8"
        )
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert started == ["npm"], started

    def test_a_sole_lockfile_outside_the_scan_set_is_still_audited(
        self, context, online, monkeypatch
    ):
        """The shape the scanner's older tests use: the scan set is stubbed with
        the manifest alone. The lockfile beside it is not kept and not ignored,
        so it is the one audited. The fixture is an npm package because the
        audit fake answers npm's report shape; a yarn.lock here made the yarn
        parser refuse the answer and the scan raise before the assertion."""
        package = _package(context.source_dir / "app", "package-lock.json")
        monkeypatch.setattr(
            npm_audit_scanner,
            "scan_set",
            lambda **kwargs: [str(package / "package.json")],
        )
        started = _audited(online)

        _scanner(context).scan(target=context.source_dir, target_type="source")

        assert started == ["npm"], started

    def test_a_sole_lockfile_an_ignore_path_names_is_not_audited(self, context, online):
        """Control for the fallback: a lockfile an ignore path names stays
        passed over even when it is the only one beside the manifest."""
        _package(context.source_dir / "app", "yarn.lock")
        started = _audited(online)

        _scanner(context).scan(
            target=context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="app/yarn.lock", reason="not this one")
            ],
        )

        assert started == [], started

    def test_the_lookup_reads_the_selection_of_the_manifests_own_tree(
        self, context, online
    ):
        """Two trees selected in turn, as nothing_to_scan_reason does: the
        source tree's kept set is read for a source manifest after the
        converted tree's selection ran, where one set for the whole scanner
        belonged to whichever selection ran last."""
        package = _package(context.source_dir / "app", "yarn.lock")
        (package / "package-lock.json").write_text("{}\n", encoding="utf-8")
        (context.source_dir / ".gitignore").write_text("yarn.lock\n", encoding="utf-8")
        converted = _package(context.work_dir / "gen", "package-lock.json")
        scanner = _scanner(context)

        scanner._package_manifests("source")
        scanner._package_manifests("converted")

        assert scanner._lockfile_beside(package / "package.json") == (
            package / "package-lock.json"
        )
        assert scanner._lockfile_beside(converted / "package.json") == (
            converted / "package-lock.json"
        )

    def test_a_converted_manifest_under_the_source_tree_reads_the_converted_set(
        self, tmp_path, online
    ):
        """The default layout: the work directory sits under the scanned source
        tree (<source>/.ash/ash_output/converted), so a converted manifest is
        under both recorded roots. The source selection leaves the output
        directory out, so read against it every converted lockfile is "not
        kept" and the package is skipped; the deepest holding root, the
        converted tree's, is the one read."""
        source = tmp_path / "src"
        output = source / ".ash" / "ash_output"
        work = output / "converted"
        work.mkdir(parents=True)
        nested = PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=work,
            config=get_default_config(),
        )
        _package(source / "app", "yarn.lock")
        converted = _package(work / "gen", "package-lock.json")
        scanner = _scanner(nested)

        scanner._package_manifests("source")
        scanner._package_manifests("converted")

        assert scanner._lockfile_beside(converted / "package.json") == (
            converted / "package-lock.json"
        )
        assert scanner._lockfile_beside(source / "app" / "package.json") == (
            source / "app" / "yarn.lock"
        )

    @pytest.mark.skipif(os.name == "nt", reason="symlinks")
    def test_a_lockfile_that_is_a_link_to_nothing_is_recorded(self, context, online):
        package = context.source_dir / "app"
        package.mkdir()
        (package / "package.json").write_text('{"name": "app"}', encoding="utf-8")
        os.symlink(
            package / "gone" / "package-lock.json", package / "package-lock.json"
        )
        started = _audited(online)
        scanner = _scanner(context)

        with pytest.raises(ScannerError, match=r"could not audit 1 lockfile"):
            scanner.scan(target=context.source_dir, target_type="source")

        assert started == []
        assert scanner.inputs_not_scanned == [
            {"path": "app/package-lock.json", "reason": NOT_A_REGULAR_FILE}
        ]


# ---------------------------------------------------------------------------
# The reports


class TestTheErrorDocument:
    def test_its_text_is_redacted_with_the_env_read_values(self):
        document = {
            "message": f"request to https://x:{TOKEN}@registry.example/ failed",
            "error": {"code": "E500", "summary": f"token {TOKEN} rejected"},
        }

        reason = NpmAuditScanner._audit_failure(
            "npm", {"stdout": json.dumps(document), "returncode": 1}, document, (TOKEN,)
        )

        assert reason is not None and reason.startswith("npm audit reported an error")
        assert TOKEN not in reason
        assert "E500" in reason

    def test_its_text_is_dropped_when_the_values_hook_raised(self):
        document = {"message": f"secret {TOKEN}", "error": {"code": "E500"}}

        reason = NpmAuditScanner._audit_failure(
            "npm", {"stdout": json.dumps(document), "returncode": 1}, document, None
        )

        assert reason is not None and TOKEN not in reason and "E500" not in reason


class TestYarn4Lines:
    def test_an_advisory_line_the_reader_cannot_read_is_not_a_clean_report(self):
        stdout = '{"value": "lodash", "children": "not a mapping"}\n'

        report, reason = NpmAuditScanner._parse_yarn_audit(
            4, {"stdout": stdout, "stderr": "", "returncode": 1}, ()
        )

        assert report is None
        assert reason is not None and "reported an error" in reason

    def test_an_error_event_is_not_narration(self):
        stdout = '{"type": "error", "data": "Response code 500"}\n'

        report, reason = NpmAuditScanner._parse_yarn_audit(
            4, {"stdout": stdout, "stderr": "", "returncode": 0}, ()
        )

        assert report is None
        assert reason is not None and "Response code 500" in reason

    def test_a_deprecation_line_is_still_evidence_of_a_report(self):
        """Control: yarn 4 lists deprecations in the advisory stream."""
        stdout = (
            '{"value": "mkdirp", "children": {"ID": "mkdirp (deprecation)", '
            '"Issue": "Legacy versions of mkdirp are no longer supported."}}\n'
        )

        report, reason = NpmAuditScanner._parse_yarn_audit(
            4, {"stdout": stdout, "stderr": "", "returncode": 1}, ()
        )

        assert reason is None
        assert report == {_YARN_ADVISORIES_KEY: [], "metadata": {"vulnerabilities": {}}}


def test_a_url_ending_in_a_slash_gives_the_package_rule_id():
    """Trailing slashes are dropped before the last segment is read, so an
    advisory URL with one keeps its id; a URL with no segment left at all (the
    empty string used to be the rule id, shared by every such advisory) falls
    back to the package's own id, carrying the tool's advisory id when the entry
    gives one. A URL whose last segment is a collection, not an advisory
    ("https://x/advisories/"), is read as that segment: no shape of an advisory
    id is assumed."""
    assert NpmAuditScanner._advisory_id("lodash", {"url": "///"}) == "npm-lodash"
    assert NpmAuditScanner._advisory_id("lodash", {"url": ""}) == "npm-lodash"
    assert NpmAuditScanner._advisory_id("lodash", {"url": "", "source": 42}) == (
        "npm-lodash-42"
    )
    assert NpmAuditScanner._advisory_id("lodash", {"url": f"{GHSA}/"}) == (
        "GHSA-xvch-5gv4-984h"
    )


class TestTheNpmConversion:
    @pytest.fixture
    def scanner(self, context):
        return NpmAuditScanner(context=context, config=NpmAuditScannerConfig())

    def test_an_advisory_without_a_url_gets_a_rule_with_no_help_uri(
        self, scanner, monkeypatch
    ):
        _unknown_versions(monkeypatch)
        report = _npm_report([_via("<0.2.4", url=None)])

        try:
            sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")
        except ValidationError as raised:  # pragma: no cover - the defect's shape
            pytest.fail(f"an empty helpUri reached the SARIF model: {raised}")

        (rule,) = sarif.runs[0].tool.driver.rules
        assert rule.id == "npm-minimist-1179"
        assert rule.helpUri is None

    def test_two_url_less_advisories_on_one_package_are_two_rules(
        self, scanner, monkeypatch
    ):
        """Both fell back to the package's own id, so the dedupe by (rule,
        place) folded the second into the first and its severity, CWE and
        CVSS were gone from the report. npm's ``source`` tells them apart."""
        _unknown_versions(monkeypatch)
        report = _npm_report(
            [
                _via("<0.2.4", url=None),
                _via(">=1.0.0 <1.2.6", url=None, source=1180, severity="low"),
            ]
        )

        sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")

        assert sorted(rule.id for rule in sarif.runs[0].tool.driver.rules) == [
            "npm-minimist-1179",
            "npm-minimist-1180",
        ]
        assert sorted(r.ruleId for r in sarif.runs[0].results) == [
            "npm-minimist-1179",
            "npm-minimist-1180",
        ]

    def test_a_yarn_record_without_a_url_gets_a_rule_with_no_help_uri(self, scanner):
        record = {
            "package": "lodash",
            "id": 1065,
            "title": "Prototype Pollution",
            "url": "",
            "severity": "high",
            "cvss": {},
            "cwe": [],
            "vulnerable_versions": "<4.17.12",
            "patched_versions": ">=4.17.12",
            "versions": {"4.17.11": [".>lodash"]},
            "paths_key": "dependency_paths",
        }

        sarif = scanner._convert_npm_audit_to_sarif(
            {_YARN_ADVISORIES_KEY: [record], "metadata": {}}, "/fake"
        )

        (rule,) = sarif.runs[0].tool.driver.rules
        assert rule.helpUri is None
        assert rule.id == "npm-lodash-1065", "the record's own id tells it apart"

    def test_an_entry_that_is_not_an_object_is_named(self, scanner):
        report = {"vulnerabilities": {"left-pad": "not an object"}, "metadata": {}}

        with pytest.raises(ScannerError, match=r"left-pad.*not an object"):
            scanner._convert_npm_audit_to_sarif(report, "/fake")

    def test_a_via_of_another_type_is_skipped(self, scanner, monkeypatch):
        _unknown_versions(monkeypatch)
        report = _npm_report([_via("<0.2.4"), 42])

        sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")

        assert [r.ruleId for r in sarif.runs[0].results] == ["GHSA-xvch-5gv4-984h"]

    def test_one_advisory_with_two_ranges_is_one_result_on_a_copy_of_unknown_version(
        self, scanner, monkeypatch
    ):
        _unknown_versions(monkeypatch)
        report = _npm_report([_via("<0.2.4"), _via(">=1.0.0 <1.2.6")])

        sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")

        results = sarif.runs[0].results
        assert len(results) == 1, [(r.ruleId, r.message.root.text) for r in results]
        (result,) = results
        assert (
            result.properties.model_extra["vulnerable_versions"]
            == "<0.2.4 || >=1.0.0 <1.2.6"
        ), "the kept result names every range of the advisory"

    def test_two_yarn_records_for_one_advisory_and_copy_are_one_result(self, scanner):
        """yarn and pnpm list an advisory once per vulnerable range; two records
        sharing a URL and naming no version were two identical rows, where the
        npm path already made them one. One result, both ranges named."""

        def record(rng):
            return {
                "package": "lodash",
                "id": 1065,
                "title": "Prototype Pollution",
                "url": GHSA,
                "severity": "high",
                "cvss": {},
                "cwe": [],
                "vulnerable_versions": rng,
                "patched_versions": None,
                "versions": {},
                "paths_key": "dependents",
            }

        rules, results = {}, []
        scanner._add_yarn_results(
            [record("<4.17.12"), record(">=4.17.15 <4.17.19")], rules, results
        )

        (result,) = results
        props = result.properties.model_extra
        assert props["vulnerable_versions"] == "<4.17.12 || >=4.17.15 <4.17.19"
        assert "<4.17.12 || >=4.17.15 <4.17.19" in result.message.root.text
        assert list(rules) == ["GHSA-xvch-5gv4-984h"]

    def test_an_unknown_installed_version_is_not_the_range(self, scanner, monkeypatch):
        _unknown_versions(monkeypatch)
        report = _npm_report([_via("<0.2.4")])

        sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")

        (result,) = sarif.runs[0].results
        props = result.properties.model_extra
        assert "installed_version" not in props, props
        assert props["vulnerable_versions"] == "<0.2.4"

    def test_a_transitive_result_with_an_unknown_version_has_none(
        self, scanner, monkeypatch
    ):
        _unknown_versions(monkeypatch)
        report = _npm_report([_via("<0.2.4")])
        report["vulnerabilities"]["mkdirp"] = {
            "name": "mkdirp",
            "severity": "critical",
            "via": ["minimist"],
            "range": "0.4.1 - 0.5.1",
            "nodes": ["node_modules/mkdirp"],
            "fixAvailable": True,
        }

        sarif = scanner._convert_npm_audit_to_sarif(report, "/fake")

        (transitive,) = [
            r
            for r in sarif.runs[0].results
            if r.ruleId.startswith("npm-audit-transitive")
        ]
        assert "installed_version" not in transitive.properties.model_extra

    def test_yarn_and_pnpm_results_name_their_lockfile(self, scanner, tmp_path):
        record = {
            "package": "lodash",
            "id": 1065,
            "title": "Prototype Pollution",
            "url": GHSA,
            "severity": "high",
            "cvss": {},
            "cwe": [],
            "vulnerable_versions": "<4.17.12",
            "patched_versions": None,
            "versions": {},
            "paths_key": "dependents",
        }
        target = tmp_path / "repo"

        sarif = scanner._convert_npm_audit_to_sarif(
            {_YARN_ADVISORIES_KEY: [record], "metadata": {}},
            target,
            lock_file=target / "web" / "yarn.lock",
        )

        (result,) = sarif.runs[0].results
        props = result.properties.model_extra
        assert props["lockfile"] == "web/yarn.lock"
        assert "installed_version" not in props, "no version is known for this record"


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_a_linked_lockfile_is_placed_where_it_sits(tmp_path):
    target = tmp_path / "repo"
    (target / "a").mkdir(parents=True)
    (target / "b").mkdir()
    real = target / "b" / "package-lock.json"
    real.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
    os.symlink(real, target / "a" / "package-lock.json")

    rel, index = NpmAuditScanner._lock_context(
        target / "a" / "package-lock.json", target
    )

    assert rel == "a/package-lock.json"
    assert index is not None


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_a_root_named_through_a_link_still_places_its_lockfile(tmp_path):
    """The walk hands the scanner the lockfile's real path while the target
    was named through a link: the lexical compare raised, the context was
    (None, None), and every result of the lockfile lost its package identity
    with the range exclusion silently off. The resolved paths place it."""
    real = tmp_path / "repo"
    (real / "a").mkdir(parents=True)
    lockfile = real / "a" / "package-lock.json"
    lockfile.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
    alias = tmp_path / "alias"
    os.symlink(real, alias)

    rel, index = NpmAuditScanner._lock_context(lockfile, alias)

    assert rel == "a/package-lock.json"
    assert index is not None
    # The lexical answer still wins where it exists: a lockfile named through
    # the alias is placed under the alias, not under the real root's spelling.
    through_alias = alias / "a" / "package-lock.json"
    assert npm_audit_scanner._shown_lockfile(through_alias, alias) == (
        "a/package-lock.json"
    )


class TestTheScanLoop:
    def test_a_target_that_is_a_file_is_a_scanner_error(self, context, online):
        target = context.source_dir / "not-a-directory"
        target.write_text("x", encoding="utf-8")

        with pytest.raises(ScannerError, match=r"cannot be read"):
            _scanner(context).scan(target=target, target_type="source")

    def test_a_raised_audit_is_logged_and_recorded_redacted(self, context, online):
        _package(context.source_dir / "app")
        scanner = _scanner(context)

        def fake_run(self, command, **kwargs):
            if "--version" in command:
                return {"stdout": "10.9.4\n", "returncode": 0}
            raise OSError(f"spawn failed for https://x:{TOKEN}@registry.example/")

        online.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
        with (
            patch.object(NpmAuditScanner, "_values_to_redact", return_value=(TOKEN,)),
            pytest.raises(ScannerError) as raised,
        ):
            scanner.scan(target=context.source_dir, target_type="source")

        assert "the audit raised OSError" in str(raised.value)
        assert TOKEN not in str(raised.value)

    def test_results_json_keeps_both_lockfiles_nodes_for_one_package(
        self, context, online
    ):
        """Two lockfiles vulnerable in one package: the raw artifact keeps the
        nodes of both, where the merge kept the last lockfile's entry."""
        _package(context.source_dir / "app")
        _package(context.source_dir / "lib")

        def respond(cwd: Path):
            name = json.loads((cwd / "package.json").read_text())["name"]
            report = _npm_report(
                [_via("<0.2.4")],
                nodes=[f"node_modules/{name}-dep/node_modules/minimist"],
            )
            return {"stdout": json.dumps(report), "returncode": 1}

        _audited(online, respond)
        scanner = _scanner(context)

        scanner.scan(target=context.source_dir, target_type="source")

        written = json.loads(
            (scanner.results_dir / "source" / "results.json").read_text(
                encoding="utf-8"
            )
        )
        assert sorted(written["vulnerabilities"]["minimist"]["nodes"]) == [
            "node_modules/app-dep/node_modules/minimist",
            "node_modules/lib-dep/node_modules/minimist",
        ]
