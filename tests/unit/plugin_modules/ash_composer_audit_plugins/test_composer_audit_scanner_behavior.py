# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ComposerAuditScanner: invocation, conversion, severity and failure handling.

The audit documents below are written by hand from the key list in Composer's
``Auditor::audit`` at 2.11.3 (``advisories``, ``abandoned``, ``filter``, ``cooldown``,
``unreachable-repositories``; each advisory has ``advisoryId``, ``packageName``,
``affectedVersions``, ``title``, ``cve``, ``link``, ``reportedAt``, ``sources`` and
``severity``, and each filter-list entry ``packageName``, ``listName``, ``constraint``,
``url``, ``reason``, ``id`` and ``source``). They are NOT output captured from a
Composer run. Every package name, advisory id, list entry and CVE number is fabricated.
The scan() tests replace the subprocess with a fake, so they run on every platform
without Composer or PHP.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_composer_audit_plugins as pkg
from automated_security_helper.plugin_modules.ash_composer_audit_plugins import (
    composer_audit_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    ComposerAuditScanner,
    ComposerAuditScannerConfig,
    ComposerAuditScannerConfigOptions,
    filter_severity_for,
    package_line,
    parse_audit_document,
    severity_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: A lock file whose package lines are known: alpha 4, beta 8, gamma 12, old 18, dead 22.
LOCK_TEXT = """{
    "packages": [
        {
            "name": "acme/alpha",
            "version": "1.1.0"
        },
        {
            "name": "acme/beta",
            "version": "2.0.0"
        },
        {
            "name": "acme/gamma",
            "version": "3.4.5"
        }
    ],
    "packages-dev": [
        {
            "name": "acme/old",
            "version": "0.9.0"
        },
        {
            "name": "acme/dead",
            "version": "0.1.0"
        }
    ]
}
"""


def _advisory(
    advisory_id: str,
    package: str,
    severity: Any,
    title: str,
    cve: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "advisoryId": advisory_id,
        "packageName": package,
        "affectedVersions": "<9.9.9",
        "title": title,
        "cve": cve,
        "link": f"https://example.invalid/advisory/{advisory_id}",
        "reportedAt": "2099-01-01 00:00:00",
        "sources": [{"name": "FakeSource", "remoteId": advisory_id}],
        "severity": severity,
    }


POSITIVE: Dict[str, Any] = {
    "advisories": {
        "acme/alpha": [
            _advisory("PKSA-0001", "acme/alpha", "critical", "Alpha RCE", "CVE-2099-1")
        ],
        "acme/beta": [
            _advisory("PKSA-0002", "acme/beta", "high", "Beta bypass", "CVE-2099-2"),
            _advisory("PKSA-0003", "acme/beta", None, "Beta unrated"),
        ],
        "acme/gamma": [
            _advisory("PKSA-0004", "acme/gamma", "medium", "Gamma leak", "CVE-2099-4"),
            _advisory("PKSA-0005", "acme/gamma", "low", "Gamma note", "CVE-2099-5"),
        ],
    },
    "abandoned": {"acme/old": "acme/new", "acme/dead": None},
}

#: (ruleId, SARIF level, ASH severity, uri, line), written out by hand.
POSITIVE_EXPECTED = [
    ("PKSA-0001", "error", "CRITICAL", "composer.lock", 4),
    ("PKSA-0002", "error", "HIGH", "composer.lock", 8),
    ("PKSA-0003", "warning", "MEDIUM", "composer.lock", 8),
    ("PKSA-0004", "warning", "MEDIUM", "composer.lock", 12),
    ("PKSA-0005", "note", "LOW", "composer.lock", 12),
    ("COMPOSER-ABANDONED", "note", "LOW", "composer.lock", 22),
    ("COMPOSER-ABANDONED", "note", "LOW", "composer.lock", 18),
]

#: A clean project: PHP encodes the empty maps as [].
NEGATIVE: Dict[str, Any] = {"advisories": [], "abandoned": []}


def _filter_entry(
    package: str,
    list_name: str,
    constraint: str,
    *,
    url: Optional[str] = None,
    reason: Optional[str] = None,
    entry_id: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "packageName": package,
        "listName": list_name,
        "constraint": constraint,
        "url": url,
        "reason": reason,
        "id": entry_id,
        "source": source,
    }


#: Composer 2.11's filter-list matches: the built-in malware list and a project list.
FILTERED: Dict[str, Any] = {
    "advisories": [],
    "abandoned": [],
    "filter": {
        "acme/alpha": [
            _filter_entry(
                "acme/alpha",
                "malware",
                "1.1.0",
                url="https://example.invalid/malware/MAL-0001",
                reason="Exfiltrates environment variables",
                entry_id="MAL-0001",
                source="example-repository",
            )
        ],
        "acme/gamma": [_filter_entry("acme/gamma", "acme-blocklist", ">=3.0")],
    },
    "cooldown": {
        "acme/beta": {
            "prettyVersion": "2.0.0",
            "releaseDate": "2099-01-01T00:00:00+00:00",
            "availableIn": "2 days",
            "source": "published-time",
        }
    },
}

#: (ruleId, SARIF level, ASH severity, uri, line) for FILTERED, written out by hand.
FILTERED_EXPECTED = [
    ("COMPOSER-FILTER-malware", "error", "CRITICAL", "composer.lock", 4),
    ("COMPOSER-FILTER-acme-blocklist", "error", "HIGH", "composer.lock", 12),
]


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine,
            )
        )
    return out


class FakeComposer:
    """Stands in for _run_subprocess: records argv, env and timeout, serves JSON."""

    def __init__(
        self,
        document: Any = POSITIVE,
        stdout: Optional[str] = None,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout = json.dumps(document) if stdout is None else stdout
        self.exit_code, self.stderr, self.timed_out = exit_code, stderr, timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, **_):
            self.calls.append({"argv": list(command), "env": env, "timeout": timeout})
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> ComposerAuditScanner:
    return ComposerAuditScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=get_default_config(),
        ),
        config=ComposerAuditScannerConfig(
            enabled=True, options=ComposerAuditScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "composer.json").write_text('{"name": "acme/app"}\n')
    (src / "composer.lock").write_text(LOCK_TEXT)
    (src / "index.php").write_text("<?php echo 1;\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: ComposerAuditScanner, fake: FakeComposer, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert ComposerAuditScannerConfig().enabled is True
        assert ComposerAuditScannerConfig().name == "composer-audit"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "composer-audit")
        assert not hasattr(get_default_config().scanners, "composer_audit")

    def test_the_module_exports_the_scanner(self):
        assert pkg.ASH_SCANNERS == [ComposerAuditScanner]
        assert pkg.ASH_REPORTERS == []

    def test_declared_class_variables(self):
        assert ComposerAuditScanner.python_only is False
        assert ComposerAuditScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert ComposerAuditScanner.success_exit_codes == {0, 1, 2, 3}
        assert ComposerAuditScanner.sandbox_requirements == SandboxRequirements(
            network=True
        )

    def test_the_tool_type_is_sca(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).tool_type is ScannerToolType.SCA


class TestInvocation:
    def test_every_fixed_flag(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1
        assert fake.calls[0]["argv"] == [
            "composer",
            "audit",
            "--locked",
            "--format=json",
            "--abandoned=report",
            "--no-plugins",
            "--no-scripts",
            "--no-interaction",
            "--no-ansi",
            f"--working-dir={tree.absolute().as_posix()}",
        ]

    @pytest.mark.parametrize(
        "flag",
        [
            "--ignore-severity",
            "--ignore-unreachable",
            "--abandoned=ignore",
            "--abandoned=fail",
            "--no-dev",
            "--direct",
        ],
    )
    def test_flags_that_hide_findings_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        _run(scanner, fake, monkeypatch)
        assert flag not in fake.calls[0]["argv"]

    def test_one_run_per_lock_file_in_its_own_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        sub = tree / "services" / "api"
        sub.mkdir(parents=True)
        (sub / "composer.json").write_text("{}\n")
        (sub / "composer.lock").write_text(LOCK_TEXT)
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        report = _run(scanner, fake, monkeypatch)
        dirs = [c["argv"][-1] for c in fake.calls]
        assert dirs == [
            f"--working-dir={tree.absolute().as_posix()}",
            f"--working-dir={sub.absolute().as_posix()}",
        ]
        uris = {f[3] for f in _findings(report)}
        assert uris == {"composer.lock", "services/api/composer.lock"}
        assert scanner.targets_attempted == 2

    def test_installed_dependencies_lock_files_are_not_audited(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        dep = tree / "vendor" / "acme" / "lib"
        dep.mkdir(parents=True)
        (dep / "composer.lock").write_text(LOCK_TEXT)
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_ignore_paths_exclude_a_lock_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        report = _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="composer.lock", reason="test")
            ],
        )
        assert fake.calls == []
        assert _findings(report) == []

    def test_invocation_env_vars_are_removed_and_others_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("COMPOSER_POLICY", "0")
        monkeypatch.setenv("COMPOSER_AUDIT_ABANDONED", "ignore")
        monkeypatch.setenv("COMPOSER_HOME", "/fake/home")
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        _run(scanner, fake, monkeypatch)
        env = fake.calls[0]["env"]
        assert "COMPOSER_POLICY" not in env
        assert "COMPOSER_AUDIT_ABANDONED" not in env
        assert env["COMPOSER_HOME"] == "/fake/home"

    def test_no_lock_file_means_nothing_to_audit(self, tmp_path, on_path, monkeypatch):
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.php").write_text("<?php echo 1;\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeComposer()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert _findings(report) == []


class TestReport:
    def test_findings_are_rated_and_located(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED
        assert scanner.targets_failed == 0

    def test_a_finding_carries_the_package_and_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(), monkeypatch)
        first = report.get_all_results()[0].model_dump(mode="json", by_alias=True)
        assert "acme/alpha 1.1.0" in first["message"]["text"]
        assert "CVE-2099-1" in first["message"]["text"]
        # The package identity keys the flat row, reports and package-scoped
        # suppressions read; no second, scanner-specific copy of them.
        assert first["properties"]["package_name"] == "acme/alpha"
        assert first["properties"]["package_version"] == "1.1.0"
        assert "package_path" not in first["properties"]
        assert "composer_package" not in first["properties"]
        assert first["partialFingerprints"]["composer-audit/v1"]

    def test_an_advisory_with_no_cve_names_no_cve(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(), monkeypatch)
        unrated = next(r for r in report.get_all_results() if r.ruleId == "PKSA-0003")
        text = unrated.message.root.text
        assert "CVE" not in text and "(None)" not in text, text
        assert text == (
            "acme/beta 2.0.0: Beta unrated. Affected versions: <9.9.9. "
            "https://example.invalid/advisory/PKSA-0003"
        )
        assert getattr(unrated.properties, "cve", None) is None

    def test_each_advisory_rule_links_its_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(), monkeypatch)
        rules = {r.id: r for r in report.runs[0].tool.driver.rules}
        assert str(rules["PKSA-0001"].helpUri) == (
            "https://example.invalid/advisory/PKSA-0001"
        )
        assert rules["COMPOSER-ABANDONED"].helpUri is None

    def test_a_link_that_is_not_a_url_leaves_the_rule_without_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        advisory = _advisory("PKSA-0009", "acme/alpha", "low", "Alpha")
        advisory["link"] = "see the vendor's notice"
        doc = {"advisories": {"acme/alpha": [advisory]}, "abandoned": []}
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(doc), monkeypatch)
        (rule,) = report.runs[0].tool.driver.rules
        assert rule.helpUri is None
        assert _findings(report) == [("PKSA-0009", "note", "LOW", "composer.lock", 4)]

    def test_negative_control_clean_project_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(NEGATIVE, exit_code=0), monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 0

    def test_the_report_is_written_and_round_trips(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeComposer(), monkeypatch)
        written = list((tmp_path / "out").rglob("composer-audit.sarif"))
        assert len(written) == 1
        again = SarifReport.model_validate_json(written[0].read_text())
        assert _findings(again) == POSITIVE_EXPECTED

    def test_the_same_advisory_twice_is_reported_once(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        doc = {
            "advisories": {
                "acme/alpha": [
                    _advisory("PKSA-0001", "acme/alpha", "high", "Alpha"),
                    _advisory("PKSA-0001", "acme/alpha", "high", "Alpha"),
                ]
            },
            "abandoned": [],
        }
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(doc), monkeypatch)
        assert len(_findings(report)) == 1


class TestFilterLists:
    """Composer 2.11's ``filter`` key: packages matching a filter list."""

    def test_a_filter_list_match_is_reported_and_rated(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(FILTERED), monkeypatch)
        assert _findings(report) == FILTERED_EXPECTED
        assert scanner.targets_failed == 0

    def test_a_match_names_the_list_entry_and_the_locked_version(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(FILTERED), monkeypatch)
        by_rule = {r.ruleId: r for r in report.get_all_results()}
        malware = by_rule["COMPOSER-FILTER-malware"]
        assert malware.message.root.text == (
            "acme/alpha 1.1.0 matches the malware filter list (MAL-0001): "
            "Exfiltrates environment variables. Listed versions: 1.1.0. "
            "https://example.invalid/malware/MAL-0001"
        )
        properties = malware.model_dump(mode="json", by_alias=True)["properties"]
        assert properties["package_name"] == "acme/alpha"
        assert properties["package_version"] == "1.1.0"
        assert properties["filter_list"] == "malware"
        assert properties["filter_id"] == "MAL-0001"
        assert properties["filter_source"] == "example-repository"
        # The adapter's tags, then the scanner name the scan appends to every result.
        assert properties["tags"] == [
            "sca",
            "dependency",
            "php",
            "filter-list",
            "malware",
            "composer-audit",
        ]
        blocklisted = by_rule["COMPOSER-FILTER-acme-blocklist"]
        assert blocklisted.message.root.text == (
            "acme/gamma 3.4.5 matches the acme-blocklist filter list. "
            "Listed versions: >=3.0"
        )

    def test_cooldown_entries_are_not_reported(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(FILTERED), monkeypatch)
        packages = {
            getattr(r.properties, "package_name", None)
            for r in report.get_all_results()
        }
        assert "acme/beta" not in packages

    def test_the_same_list_entry_twice_is_reported_once(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        entry = _filter_entry("acme/alpha", "malware", "1.1.0", entry_id="MAL-0001")
        doc = {
            "advisories": [],
            "abandoned": [],
            "filter": {"acme/alpha": [entry, dict(entry)]},
        }
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(doc), monkeypatch)
        assert _findings(report) == [FILTERED_EXPECTED[0]]

    def test_two_entries_of_one_list_are_two_findings_with_two_fingerprints(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        doc = {
            "advisories": [],
            "abandoned": [],
            "filter": {
                "acme/alpha": [
                    _filter_entry("acme/alpha", "malware", "1.1.0", entry_id="M-1"),
                    _filter_entry("acme/alpha", "malware", "1.1.0", entry_id="M-2"),
                ]
            },
        }
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(doc), monkeypatch)
        prints = {
            r.partialFingerprints["composer-audit/v1"] for r in report.get_all_results()
        }
        assert len(_findings(report)) == 2 and len(prints) == 2


class TestSeverity:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("critical", ("CRITICAL", "error")),
            ("high", ("HIGH", "error")),
            ("medium", ("MEDIUM", "warning")),
            ("low", ("LOW", "note")),
            ("HIGH", ("HIGH", "error")),
        ],
    )
    def test_documented_severities(self, raw, expected):
        assert severity_for(raw) == expected

    def test_a_missing_severity_is_medium(self):
        assert severity_for(None) == ("MEDIUM", "warning")

    @pytest.mark.parametrize("raw", ["urgent", "", 7, ["high"]])
    def test_an_unknown_severity_is_high(self, raw):
        assert severity_for(raw) == ("HIGH", "error")

    def test_a_malware_match_is_critical_and_any_other_list_high(self):
        assert filter_severity_for("malware") == ("CRITICAL", "error")
        assert filter_severity_for("acme-blocklist") == ("HIGH", "error")
        assert filter_severity_for("Malware") == ("HIGH", "error")


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1, 2, 3])
    def test_a_run_that_completed_succeeds_with_findings(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeComposer(exit_code=code), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    @pytest.mark.parametrize("code", [4, 100, 126, 127, 137, 255])
    def test_any_other_exit_fails_even_with_a_document(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="did not complete"):
            _run(scanner, FakeComposer(exit_code=code), monkeypatch)
        assert scanner.targets_failed == 1

    def test_exit_one_with_a_message_and_no_document_fails(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # A text message where the document should be is not an audit result.
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer(stdout="No packages - skipping audit.\n", exit_code=1)
        with pytest.raises(ScannerError, match="not JSON"):
            _run(scanner, fake, monkeypatch)

    @pytest.mark.parametrize("code", [0, 1])
    def test_a_run_that_writes_no_document_fails_whatever_it_exits(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        # Composer 2.11.3 writes no JSON for a lock with no packages: it exits 0
        # (composer.json requires nothing) or 1 (it requires something), with its
        # message on stderr. Neither is read as a clean audit.
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer(
            stdout="", exit_code=code, stderr="No packages - skipping audit."
        )
        with pytest.raises(ScannerError, match="wrote no output"):
            _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 1

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeComposer(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_the_timeout_is_one_budget_for_every_lock_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        sub = tree / "app"
        sub.mkdir()
        (sub / "composer.json").write_text("{}\n")
        (sub / "composer.lock").write_text(LOCK_TEXT)
        clock = iter([100.0, 100.0, 103.0, 103.0, 103.0, 103.0])
        monkeypatch.setattr(cs, "_now", lambda: next(clock))
        scanner = _scanner(tree, tmp_path, scan_timeout=10)
        fake = FakeComposer()
        _run(scanner, fake, monkeypatch)
        timeouts = [c["timeout"] for c in fake.calls]
        assert len(timeouts) == 2
        assert timeouts[0] == pytest.approx(10.0)
        assert timeouts[1] == pytest.approx(7.0)

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "   \n",
            "not json at all",
            "[1, 2]",
            '"a string"',
            '{"abandoned": []}',
            '{"advisories": "nope"}',
            '{"advisories": [], "abandoned": "nope"}',
            '{"advisories": [], "filter": "nope"}',
            '{"advisories": {',
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="did not complete"):
            _run(scanner, FakeComposer(stdout=stdout, exit_code=0), monkeypatch)
        assert scanner.targets_failed == 1

    def test_an_unreachable_repository_is_a_failed_target_not_a_clean_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        doc = {**NEGATIVE, "unreachable-repositories": ["https://example.invalid"]}
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="could not reach"):
            _run(scanner, FakeComposer(doc, exit_code=0), monkeypatch)

    def test_a_lock_file_with_no_composer_json_is_a_failed_target(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "composer.json").unlink()
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer()
        with pytest.raises(ScannerError, match="no composer.json"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_one_failed_lock_does_not_hide_the_others_findings_on_disk(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        bad = tree / "bad"
        bad.mkdir()
        (bad / "composer.lock").write_text(LOCK_TEXT)
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="1 of 2"):
            _run(scanner, FakeComposer(), monkeypatch)
        written = next((tmp_path / "out").rglob("composer-audit.sarif"))
        again = SarifReport.model_validate_json(written.read_text())
        assert _findings(again) == POSITIVE_EXPECTED

    def test_stderr_text_is_never_copied_into_the_failure(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeComposer(
            stdout="", exit_code=255, stderr="quoted-from-the-scanned-project"
        )
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert "quoted-from-the-scanned-project" not in str(raised.value)
        assert not any("quoted-from-the-scanned-project" in e for e in scanner.errors)


class TestDependencyCheck:
    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        fake = FakeComposer()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    def test_present_binary_satisfies_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_composer_without_php_is_unsatisfied(self, tree, tmp_path, monkeypatch):
        # The phar ASH installs runs through `#!/usr/bin/env php`; ASH never
        # installs PHP, so a composer on PATH with no php cannot run an audit.
        monkeypatch.setattr(
            cs, "find_executable", lambda cmd: None if cmd == "php" else f"/bin/{cmd}"
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        fake = FakeComposer()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    @pytest.mark.parametrize(
        "platform, arch",
        [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
        ],
    )
    def test_the_pinned_phar_is_installed_on_linux_and_macos(
        self, platform, arch, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        (command,) = _scanner(tree, tmp_path).get_installation_commands(platform, arch)
        assert command.shell is False
        assert "install_composer" in " ".join(command.args)

    def test_windows_is_not_installed(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.get_installation_commands("windows", "amd64") == []


class TestNothingToScan:
    def test_a_lock_file_means_something_to_scan(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_no_lock_file_is_a_reason(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "composer.json").write_text("{}\n")
        reason = _scanner(src, tmp_path).nothing_to_scan_reason()
        assert reason and "composer.lock" in reason

    def test_a_vendored_lock_file_is_not_something_to_scan(self, tmp_path):
        src = tmp_path / "src"
        (src / "vendor" / "acme").mkdir(parents=True)
        (src / "vendor" / "acme" / "composer.lock").write_text(LOCK_TEXT)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None

    def test_a_lock_file_the_last_scan_ignored_is_not_something_to_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(
            scanner,
            FakeComposer(NEGATIVE),
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="composer.lock", reason="test")
            ],
        )
        assert scanner.nothing_to_scan_reason() is not None


class TestHelpers:
    def test_parse_accepts_php_empty_arrays(self):
        assert parse_audit_document('{"advisories": [], "abandoned": []}')

    def test_package_line_matches_the_exact_name_only(self):
        assert package_line(LOCK_TEXT, "acme/alpha") == 4
        assert package_line(LOCK_TEXT, "acme/alph") == 1
        assert package_line(None, "acme/alpha") == 1
