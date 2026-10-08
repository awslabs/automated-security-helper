# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builtin trivy scanner without the trivy binary.

Parsing is tested against REAL trivy output. ``trivy-0.69.3.vuln.sarif`` and
``trivy-0.69.3.all.sarif`` were written by the pinned trivy v0.69.3 scanning
the fixture repository as ``tests/utils/trivy_fixture.py`` materializes it (the
committed ``.fixture`` suffixes removed), from inside that directory::

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
from pathlib import Path

import pytest

from tests.utils.trivy_fixture import materialize

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
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
from automated_security_helper.utils.config_trust import record_provenance
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
        materialize(source)
    output = source / ".ash" / "ash_output"
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config or AshConfig(),
    )


def _scanner(
    tmp_path: Path, *, operator: bool = False, overrides: tuple = (), **options
) -> TrivyScanner:
    """A scanner whose config came from the scanned tree unless ``operator`` is set."""
    options.setdefault("offline", False)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    # operator=True: built from no file in the scanned tree. Otherwise from the
    # tree's .ash/.ash.yaml, judged against the defaults plus ``overrides``.
    record_provenance(
        context.config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    return TrivyScanner(
        context=context,
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
# Defaults
# --------------------------------------------------------------------------- #


def test_trivy_is_a_builtin_on_by_default_beside_the_community_trivy_repo():
    assert TrivyScannerConfig().enabled is True
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
        f"--config={(scanner.results_dir / 'trivy-config.yaml').resolve().as_posix()}",
        f"--ignorefile={(scanner.results_dir / 'trivyignore.txt').resolve().as_posix()}",
        f"--secret-config={(scanner.results_dir / 'trivy-secret.yaml').resolve().as_posix()}",
        source.as_posix(),
        "--output",
        results.as_posix(),
    ]


def test_output_dir_outside_the_target_is_not_skipped(tmp_path):
    scanner = _scanner(tmp_path)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    assert not any(a.startswith("--skip-dirs") for a in _argv(scanner, elsewhere))


def test_an_unbounded_scan_timeout_is_unbounded_in_trivy_too(tmp_path):
    """null means unbounded in ASH; trivy's 0s means no deadline (its default is 5m)."""
    scanner = _scanner(tmp_path, scan_timeout=None)
    argv = _argv(scanner, scanner.context.source_dir)
    assert [a for a in argv if a.startswith("--timeout")] == ["--timeout=0s"]


def test_the_ash_config_and_ignore_files_are_empty(tmp_path):
    """The files ASH passes hold nothing, so the repository's own are simply unread."""
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    (source / "trivy.yaml").write_text("severity: [CRITICAL]\n", encoding="utf-8")
    (source / ".trivyignore").write_text("CVE-2018-18074\n", encoding="utf-8")
    argv = _argv(scanner, source)
    for flag, content in (
        ("--config=", ""),
        ("--ignorefile=", ""),
        # An empty secret config is a decode error in trivy; an empty mapping is not.
        ("--secret-config=", "{}\n"),
    ):
        value = next(a for a in argv if a.startswith(flag))[len(flag) :]
        assert Path(value).is_file() and Path(value).read_text() == content
        assert Path(value).is_relative_to(scanner.results_dir.resolve())


@pytest.mark.parametrize(
    "option, flag, name",
    [
        ("config_file", "--config", "trivy.yaml"),
        ("ignore_file", "--ignorefile", ".trivyignore"),
        ("secret_config_file", "--secret-config", "trivy-secret.yaml"),
    ],
)
def test_an_operator_chosen_trivy_file_is_passed(tmp_path, option, flag, name):
    chosen = tmp_path / "operator" / name
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, **{option: str(chosen)})
    argv = _argv(scanner, scanner.context.source_dir)
    assert f"{flag}={chosen.resolve().as_posix()}" in argv


@pytest.mark.parametrize(
    "option, flag, name",
    [
        ("ignore_file", "--ignorefile", ".trivyignore"),
        ("secret_config_file", "--secret-config", "trivy-secret.yaml"),
    ],
)
def test_pattern_files_from_the_scanned_tree_are_still_passed(
    tmp_path, option, flag, name
):
    # They hold patterns, not code; only config_file can load modules.
    probe = _scanner(tmp_path)
    (probe.context.source_dir / name).write_text("", encoding="utf-8")
    scanner = _scanner(tmp_path, **{option: name})
    argv = _argv(scanner, scanner.context.source_dir)
    expected = (scanner.context.source_dir / name).resolve().as_posix()
    assert f"{flag}={expected}" in argv


_MODULE_CONFIG = "module:\n  dir: ./trivy-modules\n  enable-modules: [planted]\n"


@pytest.mark.parametrize("spelling", ["relative", "absolute"])
def test_a_trivy_config_set_by_the_scanned_tree_is_not_passed(
    tmp_path, caplog, spelling
):
    probe = _scanner(tmp_path)
    planted = probe.context.source_dir / "trivy.yaml"
    planted.write_text(_MODULE_CONFIG, encoding="utf-8")
    value = "trivy.yaml" if spelling == "relative" else planted.as_posix()
    scanner = _scanner(tmp_path, config_file=value)

    with caplog.at_level("WARNING"):
        argv = _argv(scanner, scanner.context.source_dir)

    (config_arg,) = [a for a in argv if a.startswith("--config=")]
    assert config_arg.endswith("/trivy-config.yaml")
    assert planted.resolve().as_posix() not in " ".join(argv)
    assert "scanners.trivy.options.config_file" in caplog.text


def test_the_operator_cannot_name_a_trivy_config_inside_the_tree(tmp_path):
    probe = _scanner(tmp_path)
    planted = probe.context.source_dir / "trivy.yaml"
    planted.write_text(_MODULE_CONFIG, encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, config_file=planted.as_posix())

    argv = _argv(scanner, scanner.context.source_dir)

    assert planted.resolve().as_posix() not in " ".join(argv)


def test_an_operator_override_names_a_trivy_config_outside_the_tree(tmp_path):
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")
    scanner = _scanner(
        tmp_path,
        overrides=(f"scanners.trivy.options.config_file={chosen}",),
        config_file=str(chosen),
    )

    argv = _argv(scanner, scanner.context.source_dir)

    assert f"--config={chosen.resolve().as_posix()}" in argv


@pytest.mark.parametrize("option", ["config_file", "ignore_file", "secret_config_file"])
def test_a_configured_trivy_file_that_does_not_exist_fails_the_scan(tmp_path, option):
    scanner = _scanner(
        tmp_path, operator=True, **{option: str(tmp_path / "operator" / "nope.yaml")}
    )
    with pytest.raises(ScannerError, match=option):
        _argv(scanner, scanner.context.source_dir)


@pytest.mark.parametrize("cls", [TrivyScanner, TrivyRepoScanner])
def test_both_scanners_install_the_pinned_trivy(tmp_path, cls):
    from automated_security_helper.utils.download_utils import (
        pinned_tool_install_commands,
    )

    expected = pinned_tool_install_commands("trivy")
    assert expected
    scanner = cls(context=_context(tmp_path))
    for key, value in expected.items():
        assert scanner.custom_install_commands[key] == value


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
    report.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
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
    # Declared for trivy-repo, the Trivy plugin's original scanner, so its messages
    # and attribution are unchanged; trivy reads the same database.
    assert entry.scanner == "trivy-repo"
    assert entry.readers == ("trivy-repo", "trivy")


@pytest.mark.parametrize(
    "reader, recorded",
    [("trivy", "trivy"), ("trivy-repo", "trivy-repo"), ("x", "trivy-repo")],
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


# --------------------------------------------------------------------------- #
# trivy-repo through the shared base: what must not change
# --------------------------------------------------------------------------- #


def _repo_scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfigOptions,
    )

    return TrivyRepoScanner(
        context=_context(tmp_path),
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


def test_the_community_plugin_offline_command_line_is_unchanged(tmp_path):
    """Every flag trivy-repo can emit, in the order it always emitted them."""
    scanner = _repo_scanner(tmp_path, offline=True, severity_threshold="MEDIUM")
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
        "--severity",
        "MEDIUM,HIGH,CRITICAL",
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-check-update",
        "/t",
        "--output",
        "/r.sarif",
    ]


def test_the_community_plugin_follows_ash_offline_mode(tmp_path, monkeypatch):
    """trivy-repo and trivy read offline the same way (_scanner_offline, #748).

    ``offline: false`` follows ASH: under ASH_OFFLINE trivy-repo skips its
    database update even though its own option says false, and with ASH online
    and the option false it does not.
    """
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    scanner = _repo_scanner(tmp_path, offline=False)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert "--skip-db-update" in args

    monkeypatch.delenv("ASH_OFFLINE")
    scanner = _repo_scanner(tmp_path, offline=False)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert "--skip-db-update" not in args


def test_the_community_plugin_still_reads_the_trivy_database(tmp_path):
    scanner = _repo_scanner(tmp_path)
    assert [e.name for e in scanner.content_databases_in_use()] == ["trivy-db"]


def test_the_community_plugin_scan_still_ties_results_to_package_copies(
    tmp_path, monkeypatch
):
    """trivy-repo's own scan() path, with trivy replaced by the captured report."""
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path, offline=False)
    scanner.dependencies_satisfied = True
    source = scanner.context.source_dir

    def fake_run(command, results_dir, env=None, timeout=None, **kwargs):
        out = Path(command[command.index("--output") + 1])
        out.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
        scanner.exit_code = 0
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kw: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    report = scanner.scan(target=source, target_type="source")
    lodash = [
        r for r in report.get_all_results() if r.properties.package_name == "lodash"
    ]
    assert len(lodash) == 5
    assert {r.properties.package_path for r in lodash} == {"node_modules/lodash"}
    assert {r.properties.scanner_name for r in report.get_all_results()} == {
        "trivy-repo"
    }


def test_an_assessment_that_cannot_ask_trivy_repo_still_records_trivy_db():
    """The fallback path names trivy-repo's database too, under trivy-repo."""

    class Broken:
        config = type("Config", (), {"name": "trivy-repo"})()

        def content_databases_in_use(self):
            raise RuntimeError("boom")

        def content_database_probe_context(self):  # pragma: no cover
            raise AssertionError("not reached")

    records = staleness.assess_scanner(
        Broken(), SarifReport(version="2.1.0", runs=[]), cdb.STALENESS_FAIL
    )
    assert [(r.name, r.scanner, r.stale) for r in records] == [
        ("trivy-db", "trivy-repo", True)
    ]


# --------------------------------------------------------------------------- #
# Defensive branches
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name, expected",
    [
        (".ash/ash_output", ".ash/ash_output"),
        ("c,[d]", '"c,\\[d\\]"'),
        ('e"f', '"e""f"'),
        ("g\\h", "g\\\\h"),
        ("q{z}", "q\\{z\\}"),
    ],
)
def test_skip_dirs_values_are_escaped_as_trivy_reads_them(name, expected):
    """Each expected value was checked against trivy 0.69.3: it skips that directory."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        skip_dirs_value,
    )

    assert skip_dirs_value(name) == expected


def test_a_rule_index_that_points_at_another_rule_falls_back_to_the_rule_id(
    tmp_path,
):
    raw = _raw()
    result = next(
        r for r in raw["runs"][0]["results"] if r["ruleId"] == "CVE-2018-18074"
    )
    rules = raw["runs"][0]["tool"]["driver"]["rules"]
    medium = next(i for i, r in enumerate(rules) if "MEDIUM" in r["properties"]["tags"])
    result["ruleIndex"] = medium
    report = _parse(_scanner(tmp_path), raw)
    found = next(r for r in report.get_all_results() if r.ruleId == "CVE-2018-18074")
    assert found.properties.issue_severity == "HIGH"


def test_two_severity_tags_give_no_verdict(tmp_path):
    raw = _raw()
    for rule in raw["runs"][0]["tool"]["driver"]["rules"]:
        if rule["id"] == "CVE-2018-18074":
            rule["properties"]["tags"] = ["vulnerability", "LOW", "HIGH"]
    report = _parse(_scanner(tmp_path), raw)
    found = next(r for r in report.get_all_results() if r.ruleId == "CVE-2018-18074")
    assert getattr(found.properties, "issue_severity", None) is None


# --------------------------------------------------------------------------- #
# trivy-repo always names its config file and modules directory, so trivy does
# not load a trivy.yaml from the directory it runs in.
# --------------------------------------------------------------------------- #

_PLANTED_TRIVY_YAML = "severity: [CRITICAL]\nmodule:\n  dir: ./trivy-modules-in-tree\n"


def _repo_scan_argv(
    tmp_path, monkeypatch, *, operator=False, overrides=(), **options
) -> tuple:
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path, offline=True, **options)
    source = Path(scanner.context.source_dir)
    record_provenance(
        scanner.context.config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    scanner.dependencies_satisfied = True
    calls = []

    def fake_run(command, results_dir, env=None, timeout=None, **kwargs):
        calls.append(list(command))
        out = Path(command[command.index("--output") + 1])
        out.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
        scanner.exit_code = 0
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kw: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    scanner.scan(target=source, target_type="source")
    (argv,) = calls
    return scanner, source, argv


def _flag(argv, name):
    (value,) = [a.split("=", 1)[1] for a in argv if a.startswith(f"{name}=")]
    return Path(value)


def test_trivy_repo_passes_its_own_config_and_an_empty_modules_dir(
    tmp_path, monkeypatch
):
    probe = _repo_scanner(tmp_path)
    planted = Path(probe.context.source_dir) / "trivy.yaml"
    planted.write_text(_PLANTED_TRIVY_YAML, encoding="utf-8")

    scanner, source, argv = _repo_scan_argv(tmp_path, monkeypatch)

    results = Path(scanner.results_dir) / "source"
    config = _flag(argv, "--config")
    modules = _flag(argv, "--module-dir")
    assert config == (results / "trivy-config.yaml").resolve()
    assert config.read_text() == ""
    assert modules == (results / "trivy-modules").resolve()
    assert list(modules.iterdir()) == []
    assert planted.resolve().as_posix() not in " ".join(argv)
    # Both flags precede the target, which trivy reads as its last positional.
    assert argv.index(f"--config={config.as_posix()}") < argv.index(str(source))


def test_trivy_repo_empties_a_modules_dir_left_in_the_output(tmp_path, monkeypatch):
    probe = _repo_scanner(tmp_path)
    left = Path(probe.results_dir) / "source" / "trivy-modules"
    left.mkdir(parents=True)
    (left / "planted.wasm").write_bytes(b"\0asm")

    _, _, argv = _repo_scan_argv(tmp_path, monkeypatch)

    assert list(_flag(argv, "--module-dir").iterdir()) == []


def test_trivy_repo_ignores_a_config_file_the_scanned_tree_sets(
    tmp_path, monkeypatch, caplog
):
    probe = _repo_scanner(tmp_path)
    planted = Path(probe.context.source_dir) / "trivy.yaml"
    planted.write_text(_PLANTED_TRIVY_YAML, encoding="utf-8")

    with caplog.at_level("WARNING"):
        scanner, _, argv = _repo_scan_argv(
            tmp_path, monkeypatch, config_file="trivy.yaml", module_dir="."
        )

    assert _flag(argv, "--config").name == "trivy-config.yaml"
    assert _flag(argv, "--module-dir").name == "trivy-modules"
    assert planted.resolve().as_posix() not in " ".join(argv)
    assert "scanners.trivy-repo.options.config_file" in caplog.text
    assert "scanners.trivy-repo.options.module_dir" in caplog.text


def test_trivy_repo_uses_an_operator_config_and_modules_outside_the_tree(
    tmp_path, monkeypatch
):
    operator = tmp_path / "operator"
    (operator / "modules").mkdir(parents=True)
    (operator / "trivy.yaml").write_text("", encoding="utf-8")

    _, _, argv = _repo_scan_argv(
        tmp_path,
        monkeypatch,
        operator=True,
        config_file=str(operator / "trivy.yaml"),
        module_dir=str(operator / "modules"),
    )

    assert _flag(argv, "--config") == (operator / "trivy.yaml").resolve()
    assert _flag(argv, "--module-dir") == (operator / "modules").resolve()


def test_trivy_repo_honors_an_override_for_its_config(tmp_path, monkeypatch):
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")

    _, _, argv = _repo_scan_argv(
        tmp_path,
        monkeypatch,
        overrides=(f"scanners.trivy-repo.options.config_file={chosen}",),
        config_file=str(chosen),
    )

    assert _flag(argv, "--config") == chosen.resolve()
