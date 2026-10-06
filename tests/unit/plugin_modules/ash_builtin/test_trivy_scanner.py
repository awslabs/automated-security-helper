# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builtin trivy scanner without the trivy binary.

Parsing is tested against REAL trivy output. ``trivy-0.69.3.vuln.sarif`` and
``trivy-0.69.3.all.sarif`` were written by the pinned trivy v0.69.3 scanning
``tests/test_data/scanners/trivy/fixture_repo`` from inside that directory::

    trivy fs --format sarif --scanners vuln --disable-telemetry --skip-db-update . \\
        --output trivy-0.69.3.vuln.sarif
    trivy fs --format sarif --scanners vuln,secret,misconfig,license \\
        --disable-telemetry --skip-db-update . --output trivy-0.69.3.all.sarif

against the vulnerability database published 2026-10-06T13:07:05Z. The only edit
is ``originalUriBaseIds.ROOTPATH``, rewritten to ``file:///src/`` so the capture
names no local path. The database grows daily, so the integration test
(``tests/integration/scanners/test_trivy_real_binary.py``) re-runs the binary
and checks the advisories this file is built around are still reported, rather
than an exact match.

Every parser assertion goes through ``_assert_expected``, and
``test_the_parser_assertions_fail_on_a_mutated_finding`` shows it fails when a
rule id, severity or location is wrong.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.scanner_opt_in import (
    is_opt_in,
    opt_in_scanner_enabled,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    get_severity_metrics_from_sarif,
)

PluginContext.model_rebuild()

DATA = Path(__file__).parents[3] / "test_data" / "scanners" / "trivy"
VULN_SARIF = DATA / "trivy-0.69.3.vuln.sarif"
ALL_SARIF = DATA / "trivy-0.69.3.all.sarif"

#: What trivy v0.69.3 reports for the fixture's two manifests, as
#: (rule id, uri, start line, ASH severity, package, package_path). The negatives,
#: six 1.17.0 in requirements.txt and ms 2.1.3 in package-lock.json, are absent:
#: neither has a published advisory.
EXPECTED = {
    (
        "CVE-2021-23337",
        "package-lock.json",
        13,
        "HIGH",
        "lodash",
        "node_modules/lodash",
    ),
    ("CVE-2026-4800", "package-lock.json", 13, "HIGH", "lodash", "node_modules/lodash"),
    (
        "CVE-2020-28500",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    (
        "CVE-2025-13465",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    (
        "CVE-2026-2950",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    ("CVE-2018-18074", "requirements.txt", 2, "HIGH", "requests", None),
    ("CVE-2023-32681", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2024-35195", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2024-47081", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2026-25645", "requirements.txt", 2, "MEDIUM", "requests", None),
}


def _raw(path: Path = VULN_SARIF) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    source = tmp_path / "src"
    if not source.exists():
        # The lockfile is read to tie each npm result to its package copy.
        shutil.copytree(DATA / "fixture_repo", source)
    output = source / ".ash" / "ash_output"
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config or AshConfig(),
    )


def _scanner(tmp_path: Path, **options) -> TrivyScanner:
    options.setdefault("offline", False)
    return TrivyScanner(
        context=_context(tmp_path),
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(**options)
        ),
    )


def _parse(scanner: TrivyScanner, raw: dict) -> SarifReport:
    report = SarifReport.model_validate(raw)
    return scanner._post_process_sarif(report, [], scanner.context.source_dir)


def _findings(report: SarifReport) -> set:
    found = set()
    for result in report.get_all_results():
        physical = result.locations[0].physicalLocation.root
        props = result.properties
        found.add(
            (
                result.ruleId,
                physical.artifactLocation.uri,
                physical.region.startLine,
                getattr(props, "issue_severity", None),
                getattr(props, "package_name", None),
                getattr(props, "package_path", None),
            )
        )
    return found


def _assert_expected(report: SarifReport) -> None:
    assert _findings(report) == EXPECTED


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    """No test here inherits ASH_OFFLINE from the shell running it."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


# --------------------------------------------------------------------------- #
# Opt-in and defaults
# --------------------------------------------------------------------------- #


def test_trivy_is_opt_in_and_off_by_default():
    assert is_opt_in(TrivyScanner)
    assert TrivyScannerConfig().enabled is False
    assert AshConfig().scanners.trivy.enabled is False


@pytest.mark.parametrize(
    "plugin_config, selection, expected",
    [
        (None, None, False),
        ({"enabled": True}, None, True),
        ({"enabled": False}, ["trivy"], True),
        (None, ["trivy-repo"], False),
    ],
)
def test_enabled_only_by_config_or_selection(plugin_config, selection, expected):
    assert opt_in_scanner_enabled(TrivyScanner, plugin_config, selection) is expected


def test_the_community_plugin_stays_on_by_default_and_is_not_opt_in():
    """trivy-repo is unchanged: on once its module is loaded, and not opt-in."""
    assert not is_opt_in(TrivyRepoScanner)
    assert TrivyRepoScannerConfig().enabled is True


def test_default_options_run_vuln_only_and_keep_unfixed():
    options = TrivyScannerConfigOptions(offline=False)
    assert options.scanners == ["vuln"]
    assert options.ignore_unfixed is False
    assert options.license_full is False
    assert options.disable_telemetry is True


def test_an_empty_scanner_list_is_refused():
    """trivy given no --scanners would run its own default set, not nothing."""
    with pytest.raises(ValueError):
        TrivyScannerConfigOptions(scanners=[])


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #


def _argv(scanner: TrivyScanner, target: Path) -> list[str]:
    final_args, results_file, env = scanner._execute_scan(target, "source", [])
    return final_args


def test_default_argv(tmp_path):
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    argv = _argv(scanner, source)
    results = scanner.results_dir / "source" / "results_sarif.sarif"
    assert argv == [
        "trivy",
        "fs",
        "--format",
        "sarif",
        "--scanners",
        "vuln",
        "--disable-telemetry",
        "--timeout=1800s",
        "--skip-dirs=.ash/ash_output",
        source.as_posix(),
        "--output",
        results.as_posix(),
    ]


def test_output_dir_outside_the_target_is_not_skipped(tmp_path):
    scanner = _scanner(tmp_path)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    assert not any(a.startswith("--skip-dirs") for a in _argv(scanner, elsewhere))


def test_an_unbounded_scan_timeout_leaves_trivys_own(tmp_path):
    scanner = _scanner(tmp_path, scan_timeout=None)
    argv = _argv(scanner, scanner.context.source_dir)
    assert not any(a.startswith("--timeout") for a in argv)


def test_options_become_flags(tmp_path):
    scanner = _scanner(
        tmp_path,
        scanners=["vuln", "license"],
        license_full=True,
        ignore_unfixed=True,
        disable_telemetry=False,
        severity_threshold="HIGH",
    )
    argv = _argv(scanner, scanner.context.source_dir)
    assert argv[argv.index("--scanners") + 1] == "vuln,license"
    assert "--license-full" in argv
    assert "--ignore-unfixed" in argv
    assert "--disable-telemetry" not in argv
    assert argv[argv.index("--severity") + 1] == "HIGH,CRITICAL"


def test_ignore_unfixed_is_warned_about(tmp_path, caplog):
    caplog.set_level("WARNING")
    _scanner(tmp_path, ignore_unfixed=True)
    assert "withheld" in caplog.text


@pytest.mark.parametrize("how", ["option", "env"])
def test_offline_skips_every_update(tmp_path, monkeypatch, how):
    if how == "env":
        # The --offline CLI path: ASH_OFFLINE is set after the option's default
        # was computed, so the option alone still says online.
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        scanner = _scanner(tmp_path, offline=False)
    else:
        scanner = _scanner(tmp_path, offline=True)
    argv = _argv(scanner, scanner.context.source_dir)
    for flag in (
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-check-update",
    ):
        assert flag in argv


def test_online_passes_no_update_flags(tmp_path):
    argv = _argv(_scanner(tmp_path), tmp_path / "src")
    assert "--skip-db-update" not in argv


def test_a_stale_report_is_removed_before_the_run(tmp_path):
    scanner = _scanner(tmp_path)
    stale = scanner.results_dir / "source" / "results_sarif.sarif"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}")
    _argv(scanner, scanner.context.source_dir)
    assert not stale.exists()


def test_a_failing_exit_code_refuses_even_a_present_report(tmp_path):
    scanner = _scanner(tmp_path)
    report = tmp_path / "r.sarif"
    report.write_text(VULN_SARIF.read_text(encoding="utf-8"))
    scanner.exit_code = 1
    with pytest.raises(ScannerError, match="trivy exited 1"):
        scanner._read_results_file(report)
    scanner.exit_code = 0
    assert scanner._read_results_file(report)["runs"]


def test_the_community_plugin_command_line_is_unchanged(tmp_path):
    """trivy-repo's flags, in order, exactly as before the shared base existed."""
    scanner = TrivyRepoScanner(
        context=_context(tmp_path), config=TrivyRepoScannerConfig()
    )
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert args == [
        "trivy",
        "repository",
        "--format",
        "sarif",
        "--scanners",
        "vuln,secret,misconfig,license",
        "--license-full",
        "--ignore-unfixed",
        "--disable-telemetry",
        "/t",
        "--output",
        "/r.sarif",
    ]


# --------------------------------------------------------------------------- #
# Offline without a database, and the content database
# --------------------------------------------------------------------------- #


def _found_binary(monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")


def test_offline_without_a_database_is_missing_with_the_reason(tmp_path, monkeypatch):
    _found_binary(monkeypatch)

    def no_db(ctx):
        raise ValueError("no trivy database was found")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_db)
    scanner = _scanner(tmp_path, offline=True)
    assert scanner.validate_plugin_dependencies() is False
    assert "no vulnerability database" in scanner.dependency_unavailable_reason
    assert "no trivy database was found" in scanner.dependency_unavailable_reason


def test_offline_with_a_database_is_satisfied(tmp_path, monkeypatch):
    _found_binary(monkeypatch)
    monkeypatch.setattr(staleness, "_built_from_trivy", lambda ctx: (None, "x"))
    assert _scanner(tmp_path, offline=True).validate_plugin_dependencies() is True


def test_offline_without_vuln_needs_no_database(tmp_path, monkeypatch):
    _found_binary(monkeypatch)

    def boom(ctx):  # pragma: no cover - must not be reached
        raise AssertionError("probed a database the scan does not read")

    monkeypatch.setattr(staleness, "_built_from_trivy", boom)
    scanner = _scanner(tmp_path, offline=True, scanners=["misconfig"])
    assert scanner.validate_plugin_dependencies() is True


def test_online_does_not_probe_the_database(tmp_path, monkeypatch):
    """Online, trivy downloads a database itself; there is nothing to require."""
    _found_binary(monkeypatch)

    def boom(ctx):  # pragma: no cover - must not be reached
        raise AssertionError("probed online")

    monkeypatch.setattr(staleness, "_built_from_trivy", boom)
    assert _scanner(tmp_path).validate_plugin_dependencies() is True


def test_missing_binary_is_reported_unavailable(tmp_path, monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: None)
    assert _scanner(tmp_path).validate_plugin_dependencies() is False


def test_the_vulnerability_database_is_measured_when_vuln_runs(tmp_path):
    assert [e.name for e in _scanner(tmp_path).content_databases_in_use()] == [
        "trivy-db"
    ]
    assert _scanner(tmp_path, scanners=["secret"]).content_databases_in_use() == []


def test_the_registry_declares_the_database_for_both_trivy_scanners():
    entry = cdb.get("trivy-db")
    assert entry.scanner == "trivy"
    assert entry.readers == ("trivy", "trivy-repo")


@pytest.mark.parametrize(
    "reader, recorded",
    [("trivy", "trivy"), ("trivy-repo", "trivy-repo"), ("x", "trivy")],
)
def test_a_measurement_is_recorded_under_the_scanner_that_read_it(reader, recorded):
    record = staleness.measure(
        cdb.get("trivy-db"),
        staleness.ProbeContext(env={}),
        cdb.STALENESS_FAIL,
        scanner=reader,
    )
    assert record.scanner == recorded


# --------------------------------------------------------------------------- #
# Parsing real output
# --------------------------------------------------------------------------- #


def test_captured_report_parses_to_the_expected_findings(tmp_path):
    _assert_expected(_parse(_scanner(tmp_path), _raw()))


def _set_rule_tag(raw: dict, rule_id: str, severity: str) -> None:
    for rule in raw["runs"][0]["tool"]["driver"]["rules"]:
        if rule["id"] == rule_id:
            tags = rule["properties"]["tags"]
            rule["properties"]["tags"] = [
                t
                for t in tags
                if t not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            ] + [severity]


def _mutate_rule_id(raw):
    raw["runs"][0]["results"][0]["ruleId"] = "CVE-0000-0000"


def _mutate_line(raw):
    loc = raw["runs"][0]["results"][-1]["locations"][0]["physicalLocation"]
    loc["region"]["startLine"] = 3


def _mutate_uri(raw):
    loc = raw["runs"][0]["results"][-1]["locations"][0]["physicalLocation"]
    loc["artifactLocation"]["uri"] = "other.txt"


def _mutate_severity(raw):
    _set_rule_tag(raw, "CVE-2018-18074", "LOW")


@pytest.mark.parametrize(
    "mutate", [_mutate_rule_id, _mutate_line, _mutate_uri, _mutate_severity]
)
def test_the_parser_assertions_fail_on_a_mutated_finding(tmp_path, mutate):
    raw = copy.deepcopy(_raw())
    mutate(raw)
    with pytest.raises(AssertionError):
        _assert_expected(_parse(_scanner(tmp_path), raw))


def test_trivys_severity_wins_over_the_cvss_score(tmp_path):
    """CVE-2023-32681 has CVSS 6.1 (MEDIUM band); rated CRITICAL by trivy, it is CRITICAL."""
    raw = _raw()
    _set_rule_tag(raw, "CVE-2023-32681", "CRITICAL")
    report = _parse(_scanner(tmp_path), raw)
    severities = {
        r.ruleId: r.properties.issue_severity for r in report.get_all_results()
    }
    assert severities["CVE-2023-32681"] == "CRITICAL"
    counts = get_severity_metrics_from_sarif(report, _scanner(tmp_path).context)
    assert (counts.critical, counts.high, counts.medium) == (1, 3, 6)


def test_unknown_severity_falls_back_to_the_generic_mapping(tmp_path):
    raw = _raw()
    _set_rule_tag(raw, "CVE-2023-32681", "UNKNOWN")
    report = _parse(_scanner(tmp_path), raw)
    result = next(r for r in report.get_all_results() if r.ruleId == "CVE-2023-32681")
    assert getattr(result.properties, "issue_severity", None) is None
    counts = get_severity_metrics_from_sarif(report, _scanner(tmp_path).context)
    # CVSS 6.1 -> MEDIUM, as ASH maps any SARIF security-severity.
    assert (counts.high, counts.medium) == (3, 7)


def test_misconfiguration_results_take_trivys_severity_too(tmp_path):
    report = _parse(_scanner(tmp_path), _raw(ALL_SARIF))
    by_rule = {r.ruleId: r.properties.issue_severity for r in report.get_all_results()}
    assert (by_rule["DS-0001"], by_rule["DS-0002"], by_rule["DS-0026"]) == (
        "MEDIUM",
        "HIGH",
        "LOW",
    )


def test_the_severity_counts_match_trivys_ratings(tmp_path):
    scanner = _scanner(tmp_path)
    counts = get_severity_metrics_from_sarif(_parse(scanner, _raw()), scanner.context)
    assert (counts.critical, counts.high, counts.medium, counts.low) == (0, 3, 7, 0)


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


def _suppressed(tmp_path, suppressions) -> set:
    config = AshConfig(global_settings={"suppressions": suppressions})
    scanner = _scanner(tmp_path)
    context = _context(tmp_path, config)
    report = apply_suppressions_to_sarif(_parse(scanner, _raw()), context)
    return {r.ruleId for r in report.get_all_results() if r.suppressions}


def test_no_suppressions_suppresses_nothing(tmp_path):
    assert _suppressed(tmp_path, []) == set()


def test_a_rule_suppression_suppresses_that_advisory(tmp_path):
    assert _suppressed(
        tmp_path,
        [AshSuppression(rule_id="CVE-2018-18074", path="requirements.txt", reason="t")],
    ) == {"CVE-2018-18074"}


def test_a_line_pinned_suppression_on_the_wrong_line_suppresses_nothing(tmp_path):
    assert (
        _suppressed(
            tmp_path,
            [
                AshSuppression(
                    rule_id="CVE-2018-18074",
                    path="requirements.txt",
                    line_start=3,
                    line_end=3,
                    reason="t",
                )
            ],
        )
        == set()
    )


def test_a_path_suppression_suppresses_the_whole_manifest(tmp_path):
    assert _suppressed(
        tmp_path, [AshSuppression(path="package-lock.json", reason="t")]
    ) == {
        "CVE-2021-23337",
        "CVE-2026-4800",
        "CVE-2020-28500",
        "CVE-2025-13465",
        "CVE-2026-2950",
    }


def test_a_package_scoped_suppression_matches_only_that_copy(tmp_path):
    hit = _suppressed(
        tmp_path,
        [
            AshSuppression(
                rule_id="CVE-2021-23337",
                path="package-lock.json",
                package_name="lodash",
                package_version="4.17.20",
                package_path="node_modules/lodash",
                reason="t",
            )
        ],
    )
    assert hit == {"CVE-2021-23337"}
    miss = _suppressed(
        tmp_path,
        [
            AshSuppression(
                rule_id="CVE-2021-23337",
                path="package-lock.json",
                package_name="lodash",
                package_version="4.17.20",
                package_path="node_modules/other/node_modules/lodash",
                reason="t",
            )
        ],
    )
    assert miss == set()
