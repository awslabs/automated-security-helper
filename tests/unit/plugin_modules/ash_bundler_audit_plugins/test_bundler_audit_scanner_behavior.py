# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BundlerAuditScanner: the invocation, the report conversion and the failure cases.

The report tests read the JSON that bundler-audit 0.9.3 (the pinned gem version) wrote
with ``check --format=json --output=<file>`` over the Gemfile.lock held in ``LOCKFILE``
below and a fresh ruby-advisory-db clone on 2026-11-19. Only the advisory
descriptions are shortened and the database path is replaced; every other field is
as written. The scan() tests replace the subprocess with a fake that serves that
report, so they run on every platform without Ruby.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_bundler_audit_plugins
from automated_security_helper.plugin_modules.ash_bundler_audit_plugins import (
    bundler_audit_scanner as bas,
)
from automated_security_helper.plugin_modules.ash_bundler_audit_plugins.bundler_audit_scanner import (
    BUNDLER_AUDIT_GEM_VERSION,
    BundlerAuditScanner,
    BundlerAuditScannerConfig,
    BundlerAuditScannerConfigOptions,
    convert_bundler_audit_report,
    rate_criticality,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.package_identity import (
    PACKAGE_NAME_KEY,
    PACKAGE_PATH_KEY,
    PACKAGE_VERSION_KEY,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: The lockfile the capture was taken over. Line numbers in POSITIVE_EXPECTED are
#: lines of this text: ``rack`` is line 4, ``actionpack`` line 5, the git remote line 8.
LOCKFILE = """\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.1)
    actionpack (5.0.0)

GIT
  remote: git://github.com/example/legacy.git
  revision: 0000000000000000000000000000000000000000
  specs:
    legacy (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack
  legacy!

BUNDLED WITH
   2.4.0
"""

DB = "/home/user/.local/share/ruby-advisory-db/gems"


def _unpatched(
    name: str, version: str, advisory_id: str, criticality: Optional[str], **extra: Any
) -> Dict[str, Any]:
    advisory: Dict[str, Any] = {
        "path": f"{DB}/{name}/{advisory_id}.yml",
        "id": advisory_id,
        "url": "https://github.com/rails/rails/releases/tag/v7.0.4.1",
        "title": f"Title of {advisory_id}",
        "date": "2023-01-18",
        "description": "Shortened.",
        "cvss_v2": None,
        "cvss_v3": None,
        "cve": None,
        "osvdb": None,
        "ghsa": None,
        "unaffected_versions": [],
        "patched_versions": [">= 7.0.4.1"],
        "criticality": criticality,
    }
    advisory.update(extra)
    return {
        "type": "unpatched_gem",
        "gem": {"name": name, "version": version},
        "advisory": advisory,
    }


#: bundler-audit 0.9.3's report over LOCKFILE, trimmed to six of its 56 results (one
#: per criticality it printed, the unscored one and the insecure source).
POSITIVE_REPORT: Dict[str, Any] = {
    "version": "0.9.3",
    "created_at": "2026-11-19 15:49:42 +0000",
    "results": [
        {"type": "insecure_source", "source": "git://github.com/example/legacy.git"},
        {
            "type": "unpatched_gem",
            "gem": {"name": "actionpack", "version": "5.0.0"},
            "advisory": {
                "path": f"{DB}/actionpack/CVE-2020-8164.yml",
                "id": "CVE-2020-8164",
                "url": "https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY",
                "title": "Possible Strong Parameters Bypass in ActionPack",
                "date": "2020-05-18",
                "description": "There is a strong parameters bypass vector in",
                "cvss_v2": None,
                "cvss_v3": 7.5,
                "cve": "2020-8164",
                "osvdb": None,
                "ghsa": "8727-m6gj-mc37",
                "unaffected_versions": ["< 4.0.0"],
                "patched_versions": ["~> 5.2.4, >= 5.2.4.3", ">= 6.0.3.1"],
                "criticality": "high",
            },
        },
        {
            "type": "unpatched_gem",
            "gem": {"name": "actionpack", "version": "5.0.0"},
            "advisory": {
                "path": f"{DB}/actionpack/CVE-2020-8166.yml",
                "id": "CVE-2020-8166",
                "url": "https://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw",
                "title": "Ability to forge per-form CSRF tokens given a global CSRF token",
                "date": "2020-05-18",
                "description": "It is possible to possible to, given a global CSRF token",
                "cvss_v2": None,
                "cvss_v3": 4.3,
                "cve": "2020-8166",
                "osvdb": None,
                "ghsa": "jp5v-5gx4-jmj9",
                "unaffected_versions": [],
                "patched_versions": ["~> 5.2.4, >= 5.2.4.3", ">= 6.0.3.1"],
                "criticality": "medium",
            },
        },
        {
            "type": "unpatched_gem",
            "gem": {"name": "actionpack", "version": "5.0.0"},
            "advisory": {
                "path": f"{DB}/actionpack/CVE-2023-22792.yml",
                "id": "CVE-2023-22792",
                "url": "https://github.com/rails/rails/releases/tag/v7.0.4.1",
                "title": "ReDoS based DoS vulnerability in Action Dispatch",
                "date": "2023-01-18",
                "description": "There is a possible regular expression based DoS",
                "cvss_v2": None,
                "cvss_v3": None,
                "cve": "2023-22792",
                "osvdb": None,
                "ghsa": "p84v-45xj-wwqj",
                "unaffected_versions": ["< 3.0.0"],
                "patched_versions": ["~> 5.2.8", "~> 6.1.7, >= 6.1.7.1", ">= 7.0.4.1"],
                "criticality": None,
            },
        },
        {
            "type": "unpatched_gem",
            "gem": {"name": "actionpack", "version": "5.0.0"},
            "advisory": {
                "path": f"{DB}/actionpack/GHSA-gmj8-hvj3-49mw.yml",
                "id": "GHSA-gmj8-hvj3-49mw",
                "url": "https://github.com/rails/rails/security/advisories/GHSA-gmj8-hvj3-49mw",
                "title": "Missing SameSite attribute on session cookies from Action Pack session stores",
                "date": "2026-11-04",
                "description": "Action Pack session stores other than",
                "cvss_v2": None,
                "cvss_v3": 3.1,
                "cve": None,
                "osvdb": None,
                "ghsa": "gmj8-hvj3-49mw",
                "unaffected_versions": [],
                "patched_versions": ["~> 8.0.5, >= 8.0.5.2", ">= 8.1.4.1"],
                "criticality": "low",
            },
        },
        {
            "type": "unpatched_gem",
            "gem": {"name": "rack", "version": "2.0.1"},
            "advisory": {
                "path": f"{DB}/rack/CVE-2022-30123.yml",
                "id": "CVE-2022-30123",
                "url": "https://groups.google.com/g/ruby-security-ann/c/LWB10kWzag8",
                "title": "Possible shell escape sequence injection vulnerability in Rack",
                "date": "2022-06-27",
                "description": "There is a possible shell escape sequence injection",
                "cvss_v2": None,
                "cvss_v3": 10.0,
                "cve": "2022-30123",
                "osvdb": None,
                "ghsa": "wq4h-7r42-5hrr",
                "unaffected_versions": [],
                "patched_versions": [
                    "~> 2.0.9, >= 2.0.9.1",
                    "~> 2.1.4, >= 2.1.4.1",
                    ">= 2.2.3.1",
                ],
                "criticality": "critical",
            },
        },
    ],
}

#: bundler-audit's report over a Gemfile.lock with nothing to report (a rake-only lock).
NEGATIVE_REPORT: Dict[str, Any] = {
    "version": "0.9.3",
    "created_at": "2026-11-19 15:50:05 +0000",
    "results": [],
}

#: (ruleId, SARIF level, ASH severity, uri, line), in report order, written out by hand
#: from the capture and LOCKFILE, not derived from the code under test.
POSITIVE_EXPECTED = [
    ("insecure-source", "warning", "MEDIUM", "Gemfile.lock", 8),
    ("CVE-2020-8164", "error", "HIGH", "Gemfile.lock", 5),
    ("CVE-2020-8166", "warning", "MEDIUM", "Gemfile.lock", 5),
    ("CVE-2023-22792", "warning", "MEDIUM", "Gemfile.lock", 5),
    ("GHSA-gmj8-hvj3-49mw", "note", "LOW", "Gemfile.lock", 5),
    ("CVE-2022-30123", "error", "CRITICAL", "Gemfile.lock", 4),
]


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, in order."""
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


class FakeBundlerAudit:
    """Stands in for _run_subprocess: records argv, writes the report it was given."""

    def __init__(
        self,
        report: Optional[Dict[str, Any]] = None,
        exit_code: int = 1,
        report_text: Optional[str] = None,
        write: bool = True,
        response: Optional[Dict[str, Any]] = None,
    ):
        self.report = POSITIVE_REPORT if report is None else report
        self.exit_code, self.report_text = exit_code, report_text
        self.write, self.response = write, response
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            output_arg = next(a for a in command if a.startswith("--output="))
            path = Path(output_arg.split("=", 1)[1])
            if self.write:
                text = (
                    self.report_text
                    if self.report_text is not None
                    else json.dumps(self.report)
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            if self.response is not None:
                return self.response
            return {"returncode": self.exit_code, "stdout": "", "stderr": ""}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> BundlerAuditScanner:
    output = tmp_path / "out"
    return BundlerAuditScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=BundlerAuditScannerConfig(
            enabled=True, options=BundlerAuditScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "Gemfile.lock").write_text(LOCKFILE)
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(bas, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


@pytest.fixture(autouse=True)
def online(monkeypatch):
    """No test depends on the offline mode of the machine that runs it."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _run(
    scanner: BundlerAuditScanner,
    fake: FakeBundlerAudit,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    """The value of the ``--flag=value`` token starting ``prefix``, or None."""
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert BundlerAuditScannerConfig().enabled is True
        assert BundlerAuditScannerConfig().name == "bundler_audit"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "bundler_audit")

    def test_the_module_exports_the_scanner(self):
        assert ash_bundler_audit_plugins.ASH_SCANNERS == [BundlerAuditScanner]
        assert ash_bundler_audit_plugins.ASH_REPORTERS == []

    def test_the_database_is_updated_by_default(self):
        assert BundlerAuditScannerConfigOptions().update_database is True

    def test_declarations(self):
        from automated_security_helper.core.enums import OfflineStrategy

        assert BundlerAuditScanner.python_only is False
        assert BundlerAuditScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert BundlerAuditScanner.success_exit_codes == {0, 1}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["bundler-audit", "check"]
        for expected in (
            "--format=json",
            "--quiet",
            "--gemfile-lock=Gemfile.lock",
            "--update",
        ):
            assert expected in argv
        # "--" ends option parsing; the source target is "." from the source dir.
        assert argv[-2:] == ["--", "."]
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_every_option_value_is_one_token_with_an_equals_sign(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        for flag in ("--format", "--output", "--config", "--gemfile-lock"):
            assert flag not in fake.argv, f"{flag} must be one --flag=value token"
            assert _flag(fake.argv, f"{flag}=") is not None

    def test_update_database_off_drops_only_the_update_flag(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, update_database=False)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        assert "--update" not in fake.argv
        assert "--format=json" in fake.argv

    @pytest.mark.parametrize("forbidden", ["--ignore", "--database", "--verbose"])
    def test_flags_that_hide_findings_or_name_a_path_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_config_is_an_ash_file_that_ignores_nothing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Without --config the tool reads .bundler-audit.yml from the scanned tree."""
        (tree / ".bundler-audit.yml").write_text("ignore:\n  - CVE-2020-8164\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        config = Path(_flag(fake.argv, "--config="))
        assert config.is_absolute()
        assert tree not in config.parents
        assert config.read_text() == "ignore: []\n"

    def test_the_report_goes_to_the_results_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        output = Path(_flag(fake.argv, "--output="))
        assert output.is_absolute()
        assert output.name == "bundler-audit.json"
        assert output.parent.name == "source"

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "Gemfile.lock").write_text(LOCKFILE)
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]


class TestNothingToScan:
    def test_a_target_without_a_lockfile_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.rb").write_text("puts 1\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_lockfile_below_the_root_is_not_read(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        (src / "svc").mkdir(parents=True)
        (src / "svc" / "Gemfile.lock").write_text(LOCKFILE)
        scanner = _scanner(src, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.nothing_to_scan_reason() is not None

    @pytest.mark.skipif(os.name == "nt", reason="needs symbolic links")
    def test_a_lockfile_that_is_a_symbolic_link_is_not_read(
        self, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "elsewhere.lock"
        outside.write_text(LOCKFILE)
        src = tmp_path / "src"
        src.mkdir()
        (src / "Gemfile.lock").symlink_to(outside)
        scanner = _scanner(src, tmp_path)
        fake = FakeBundlerAudit()
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_the_reason_is_none_when_the_source_has_a_lockfile(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_the_reason_is_given_when_neither_tree_has_one(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        assert "Gemfile.lock" in _scanner(src, tmp_path).nothing_to_scan_reason()


class TestReport:
    def test_the_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakeBundlerAudit(report=NEGATIVE_REPORT, exit_code=0), monkeypatch
        )
        assert _findings(report) == []
        assert report.runs, "a clean scan is a run with no results"

    def test_a_gem_result_names_the_package_and_its_fix(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        rack = [r for r in report.get_all_results() if r.ruleId == "CVE-2022-30123"][0]
        props = rack.properties.model_dump()
        assert props[PACKAGE_NAME_KEY] == "rack"
        assert props[PACKAGE_VERSION_KEY] == "2.0.1"
        assert props[PACKAGE_PATH_KEY] == "Gemfile.lock"
        assert "rack 2.0.1" in rack.message.root.text
        assert ">= 2.2.3.1" in rack.message.root.text
        assert {"sca", "dependency"} <= set(props["tags"])

    def test_the_insecure_source_names_the_source_and_no_package(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        source = report.get_all_results()[0]
        assert "git://github.com/example/legacy.git" in source.message.root.text
        assert PACKAGE_NAME_KEY not in source.properties.model_dump()

    def test_the_advisory_database_path_is_not_copied_into_the_report(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        assert "ruby-advisory-db" not in report.model_dump_json()

    def test_the_driver_carries_the_tool_version_and_one_rule_per_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        driver = report.runs[0].tool.driver
        assert driver.name == "bundler-audit"
        assert driver.version == "0.9.3"
        assert [r.id for r in driver.rules] == [e[0] for e in POSITIVE_EXPECTED]

    def test_a_platform_suffix_in_the_lockfile_still_finds_the_line(self):
        lockfile = "GEM\n  specs:\n    nokogiri (1.15.0-x86_64-linux)\n"
        document = {
            "version": "0.9.3",
            "results": [_unpatched("nokogiri", "1.15.0", "CVE-1", "high")],
        }
        sarif = convert_bundler_audit_report(
            document, lockfile_uri="Gemfile.lock", lines=lockfile.splitlines()
        )
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        assert region["startLine"] == 3

    def test_a_gem_missing_from_the_lockfile_text_is_located_at_line_one(self):
        document = {
            "version": "0.9.3",
            "results": [_unpatched("ghost", "1.0.0", "CVE-1", "low")],
        }
        sarif = convert_bundler_audit_report(
            document, lockfile_uri="Gemfile.lock", lines=[]
        )
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        assert region["startLine"] == 1

    def test_the_sarif_round_trips(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        again = SarifReport.model_validate_json(report.model_dump_json(by_alias=True))
        assert _findings(again) == POSITIVE_EXPECTED

    def test_an_advisory_url_sarif_cannot_hold_is_left_off_the_rule(self):
        document = {
            "version": "0.9.3",
            "results": [
                _unpatched("a", "1.0", "CVE-1", "low", url="not a url"),
                _unpatched("b", "1.0", "CVE-2", "low", url=None),
            ],
        }
        sarif = convert_bundler_audit_report(
            document, lockfile_uri="Gemfile.lock", lines=[]
        )
        assert all(
            "helpUri" not in rule
            for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        )


class TestSeverity:
    """Every row of the module's severity table, both the ASH severity and the level."""

    @pytest.mark.parametrize(
        ("criticality", "expected"),
        [
            ("critical", ("CRITICAL", "error")),
            ("high", ("HIGH", "error")),
            ("medium", ("MEDIUM", "warning")),
            ("low", ("LOW", "note")),
            ("none", ("INFO", "none")),
            ("HIGH", ("HIGH", "error")),
        ],
    )
    def test_each_criticality(self, criticality, expected):
        assert rate_criticality(criticality) == expected

    @pytest.mark.parametrize("unscored", [None, "", "unknown", "severe", 7, ["high"]])
    def test_no_score_or_an_unknown_value_is_medium(self, unscored):
        assert rate_criticality(unscored) == ("MEDIUM", "warning")

    def test_the_level_and_issue_severity_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBundlerAudit(), monkeypatch)
        for _, level, severity, _, _ in _findings(report):
            assert {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
                "INFO": "none",
            }[severity] == level


class TestExitStatus:
    def test_one_with_findings_is_a_success(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBundlerAudit(exit_code=1), monkeypatch)
        assert scanner.exit_code == 1
        assert scanner._exit_code_accepted()

    def test_zero_with_no_findings_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(
            scanner, FakeBundlerAudit(report=NEGATIVE_REPORT, exit_code=0), monkeypatch
        )
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [2, 126, 127, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBundlerAudit(exit_code=code), monkeypatch)

    def test_exit_one_with_no_report_is_a_failed_run_not_a_finding(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """bundler-audit exits 1 for a failed download too, and writes no file then."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBundlerAudit(write=False, exit_code=1), monkeypatch)

    def test_exit_one_with_an_empty_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="lists no vulnerabilities"):
            _run(
                scanner,
                FakeBundlerAudit(report=NEGATIVE_REPORT, exit_code=1),
                monkeypatch,
            )

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeBundlerAudit()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--output="))
        assert report.exists(), "the first run left its report"
        second = FakeBundlerAudit(write=False, exit_code=1)
        with pytest.raises(ScannerError):
            _run(scanner, second, monkeypatch)
        assert not report.exists()

    def test_a_source_run_that_failed_does_not_fail_a_clean_converted_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "Gemfile.lock").write_text(LOCKFILE)
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBundlerAudit(exit_code=1), monkeypatch)
        _run(
            scanner,
            FakeBundlerAudit(report=NEGATIVE_REPORT, exit_code=0),
            monkeypatch,
            target=converted,
            target_type="converted",
        )
        assert scanner.exit_code == 0

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=45)
        fake = FakeBundlerAudit(
            write=False,
            exit_code=124,
            response={"returncode": 124, "stdout": "", "stderr": "", "timed_out": True},
        )
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert timeout is not None and 0 < timeout <= 45


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            '{"version": "0.9.3", "results": [',
            "[]",
            "{}",
            '{"version": "0.9.3", "results": "none"}',
            '{"version": "0.9.3", "results": [1]}',
            '{"version": "0.9.3", "results": [{"type": "something_new"}]}',
            '{"version": "0.9.3", "results": [{"type": "unpatched_gem", "gem": {}}]}',
            '{"version": "0.9.3", "results": [{"type": "insecure_source"}]}',
        ],
    )
    def test_output_that_is_not_a_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(
                scanner,
                FakeBundlerAudit(report_text=text, exit_code=1),
                monkeypatch,
            )

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBundlerAudit(report_text="", exit_code=0), monkeypatch)


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bas, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_binary_never_starts_the_tool(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(bas, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeBundlerAudit()
        try:
            _run(scanner, fake, monkeypatch)
        except ScannerError:
            pass
        assert fake.calls == []

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_offline_the_scanner_does_not_run_and_says_why(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert "offline" in scanner.dependency_unavailable_reason

    def test_a_recorded_unavailable_reason_wins(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        """A gem is platform-neutral, so every platform ASH supports gets the command."""
        monkeypatch.setattr(bas, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
        monkeypatch.setattr(bas, "current_bin_path", lambda: tmp_path)
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
            ("windows", "arm64"),
        ]:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            text = str(commands[0])
            assert "bundler-audit" in text
            assert BUNDLER_AUDIT_GEM_VERSION in text
            assert "--user-install" in text

    def test_no_rubygems_declares_no_command(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bas, "find_executable", lambda cmd: None)
        monkeypatch.setattr(bas, "install_story_is_declared", lambda: False)
        scanner = _scanner(tmp_path, tmp_path)
        assert not scanner.get_installation_commands("linux", "amd64")

    def test_the_pin_is_a_released_three_part_version(self):
        parts = BUNDLER_AUDIT_GEM_VERSION.split(".")
        assert len(parts) == 3 and all(p.isdigit() for p in parts)


class TestSandboxDeclaration:
    def test_the_network_and_the_database_directory_are_declared(self):
        requirements = BundlerAuditScanner.sandbox_requirements
        assert requirements != SandboxRequirements()
        assert requirements.network is True
        assert requirements.cache_paths == ("~/.local/share/ruby-advisory-db",)
        assert requirements.env_names == ()
        assert requirements.env_prefixes == ()
        assert not requirements.network_requires_grant
