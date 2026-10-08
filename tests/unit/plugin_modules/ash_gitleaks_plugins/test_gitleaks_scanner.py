# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks scanner without the gitleaks binary.

Parsing is tested against REAL gitleaks output: ``gitleaks-8.30.1.sarif`` was
written by the pinned gitleaks 8.30.1 scanning the fixture repository that
``tests/utils/gitleaks_fixture.py`` materializes from ``repo_template``
with the exact argv ``GitleaksScanner`` builds. The integration test
``tests/integration/scanners/test_gitleaks_real_binary.py`` re-runs the binary and
fails if its output stops matching this file, so the capture cannot go stale
silently.

Every parser assertion goes through ``_assert_expected_findings``, and
``test_the_parser_assertions_fail_on_a_mutated_finding`` feeds it mutated
reports to show it fails when a rule id, level or location is wrong. Without
that, a check that compared nothing would pass here too.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_gitleaks_plugins.gitleaks_scanner import (
    LEAKS_EXIT_CODE,
    REDACTED,
    GitleaksScanner,
    GitleaksScannerConfig,
    GitleaksScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    get_severity_metrics_from_sarif,
)

PluginContext.model_rebuild()

DATA = Path(__file__).parents[3] / "test_data" / "scanners" / "gitleaks"
CAPTURED_SARIF = DATA / "gitleaks-8.30.1.sarif"

#: What gitleaks 8.30.1 reports for the fixture repo: (rule id, uri, line).
#: The negatives -- clean.py, inline_allowed.py, fingerprint_ignored.py and
#: docs/example.md -- are absent by construction; the integration test proves
#: each one is found once its allow mechanism is removed.
EXPECTED = {
    ("aws-access-token", "app/settings.py", 5),
    ("github-pat", "app/settings.py", 4),
    ("slack-bot-token", "app/settings.py", 6),
}


def _raw_report() -> dict:
    return json.loads(CAPTURED_SARIF.read_text(encoding="utf-8"))


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = source / ".ash" / "ash_output"
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config or AshConfig(),
    )


def _scanner(tmp_path: Path, **options) -> GitleaksScanner:
    return GitleaksScanner(
        context=_context(tmp_path),
        config=GitleaksScannerConfig(
            enabled=True, options=GitleaksScannerConfigOptions(**options)
        ),
    )


def _parse(scanner: GitleaksScanner, raw: dict) -> SarifReport:
    report = SarifReport.model_validate(raw)
    return scanner._post_process_sarif(report, [], scanner.context.source_dir)


def _findings(report: SarifReport) -> set:
    found = set()
    for result in report.get_all_results():
        physical = result.locations[0].physicalLocation.root
        found.add(
            (
                result.ruleId,
                physical.artifactLocation.uri,
                physical.region.startLine,
                getattr(result.level, "value", result.level),
            )
        )
    return found


def _assert_expected_findings(report: SarifReport) -> None:
    assert _findings(report) == {(*e, "error") for e in EXPECTED}


# --------------------------------------------------------------------------- #
# A community plugin: on once its module is listed
# --------------------------------------------------------------------------- #


def test_gitleaks_is_on_by_default_once_its_module_is_listed():
    assert GitleaksScannerConfig().enabled is True
    assert not hasattr(AshConfig().scanners, "gitleaks"), (
        "a community scanner has no declared field on the builtin config segment"
    )


# --------------------------------------------------------------------------- #
# argv
# --------------------------------------------------------------------------- #


def test_argv_for_the_source_target(tmp_path):
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    results = tmp_path / "out.sarif"
    args = scanner._build_arguments(source, results)
    assert args[:2] == ["gitleaks", "dir"]
    for flag in (
        "--report-format=sarif",
        f"--report-path={results.as_posix()}",
        "--redact=100",
        f"--exit-code={LEAKS_EXIT_CODE}",
        "--no-banner",
        "--no-color",
        f"--gitleaks-ignore-path={source.as_posix()}",
    ):
        assert flag in args
    # Source-relative paths: "." from the source directory, after "--".
    assert args[-2:] == ["--", "."]
    assert not any(a.startswith("--config") for a in args)


def test_argv_for_the_converted_target_is_absolute(tmp_path):
    scanner = _scanner(tmp_path)
    converted = scanner.context.work_dir
    converted.mkdir(parents=True)
    args = scanner._build_arguments(converted, tmp_path / "out.sarif")
    assert args[-2:] == ["--", converted.absolute().as_posix()]


def test_every_option_is_one_token_so_no_value_can_become_a_flag(tmp_path):
    """A path starting with "-" stays a value, and the scan path follows "--"."""
    scanner = _scanner(
        tmp_path,
        config_file="-c-evil.toml",
        baseline_path="--baseline.json",
        max_target_megabytes=5,
    )
    source = scanner.context.source_dir
    (source / "-c-evil.toml").write_text("[extend]\nuseDefault = true\n")
    (source / "--baseline.json").write_text("[]")
    args = scanner._build_arguments(source, tmp_path / "out.sarif")
    flags = args[2 : args.index("--")]
    assert all(a.startswith("--") for a in flags), flags
    assert args[args.index("--") + 1 :] == ["."]
    assert f"--config={(source / '-c-evil.toml').resolve().as_posix()}" in flags
    assert (
        f"--baseline-path={(source / '--baseline.json').resolve().as_posix()}" in flags
    )
    assert "--max-target-megabytes=5" in flags


@pytest.mark.parametrize("name", [".gitleaks.toml", ".ash/.gitleaks.toml"])
def test_a_config_in_the_source_dir_is_discovered(tmp_path, monkeypatch, name):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner = _scanner(tmp_path)
    found = scanner.context.source_dir / name
    found.parent.mkdir(parents=True, exist_ok=True)
    found.write_text("[extend]\nuseDefault = true\n")
    args = scanner._build_arguments(scanner.context.work_dir, tmp_path / "o.sarif")
    # Passed explicitly, so the converted target gets the source's rules too.
    assert f"--config={found.resolve().as_posix()}" in args


def test_root_config_wins_over_the_ash_dir_one(tmp_path, monkeypatch):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    (source / ".ash").mkdir()
    (source / ".ash" / ".gitleaks.toml").write_text("")
    (source / ".gitleaks.toml").write_text("")
    args = scanner._build_arguments(source, tmp_path / "o.sarif")
    assert f"--config={(source / '.gitleaks.toml').resolve().as_posix()}" in args


@pytest.mark.parametrize("variable", ["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"])
def test_a_gitleaks_config_env_var_is_left_to_gitleaks(tmp_path, monkeypatch, variable):
    monkeypatch.setenv(variable, "anything")
    scanner = _scanner(tmp_path)
    (scanner.context.source_dir / ".gitleaks.toml").write_text("")
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert not any(a.startswith("--config") for a in args)


def test_config_file_option_wins_over_env_and_discovery(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLEAKS_CONFIG", "elsewhere.toml")
    scanner = _scanner(tmp_path, config_file="rules/custom.toml")
    source = scanner.context.source_dir
    (source / ".gitleaks.toml").write_text("")
    (source / "rules").mkdir()
    (source / "rules" / "custom.toml").write_text("")
    args = scanner._build_arguments(source, tmp_path / "o.sarif")
    configs = [a for a in args if a.startswith("--config")]
    assert configs == [
        f"--config={(source / 'rules/custom.toml').resolve().as_posix()}"
    ]


@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
def test_a_configured_path_that_does_not_exist_fails_the_scan(tmp_path, option):
    """Falling back to default rules would scan with rules nobody asked for."""
    scanner = _scanner(tmp_path, **{option: "missing.file"})
    with pytest.raises(ScannerError, match=f"scanners.gitleaks.options.{option}"):
        scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")


def test_a_stale_report_is_removed_before_the_run(tmp_path):
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    stale = scanner.results_dir / "source" / "gitleaks.sarif"
    stale.parent.mkdir(parents=True)
    stale.write_text(CAPTURED_SARIF.read_text(encoding="utf-8"))
    _, results_file, _ = scanner._execute_scan(source, "source", [])
    assert results_file == stale
    assert not stale.exists()


# --------------------------------------------------------------------------- #
# Exit codes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("code", [0, LEAKS_EXIT_CODE])
def test_success_exit_codes_read_the_report(tmp_path, code):
    scanner = _scanner(tmp_path)
    scanner.exit_code = code
    assert scanner._read_results_file(CAPTURED_SARIF)["version"] == "2.1.0"


@pytest.mark.parametrize("code", [1, 3, 126, -9])
def test_a_failing_exit_code_refuses_even_a_present_report(tmp_path, code):
    """gitleaks exits 1 on every fatal error, so 1 must never read as "leaks"."""
    scanner = _scanner(tmp_path)
    scanner.exit_code = code
    with pytest.raises(ScannerError, match=f"gitleaks exited {code}"):
        scanner._read_results_file(CAPTURED_SARIF)


def test_a_tool_that_hangs_is_killed_and_reported_as_timed_out(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, scan_timeout=1)
    source = scanner.context.source_dir
    (source / "a.txt").write_text("x")
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_build_arguments",
        lambda target, results: [sys.executable, "-c", "import time; time.sleep(60)"],
    )
    with pytest.raises(ScannerError, match="timed out after 1"):
        scanner.scan(target=source, target_type="source")


def test_missing_binary_is_reported_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    monkeypatch.setattr(
        "automated_security_helper.base.scanner_plugin.find_executable",
        lambda command: None,
    )
    scanner = _scanner(tmp_path)
    assert scanner.validate_plugin_dependencies() is False


# --------------------------------------------------------------------------- #
# Parsing real gitleaks output
# --------------------------------------------------------------------------- #


def test_captured_report_parses_to_the_expected_findings(tmp_path):
    _assert_expected_findings(_parse(_scanner(tmp_path), _raw_report()))


def _mutate_rule(raw):
    raw["runs"][0]["results"][0]["ruleId"] = "generic-api-key"


def _mutate_line(raw):
    region = raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    region["startLine"] += 1


def _mutate_uri(raw):
    location = raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    location["artifactLocation"]["uri"] = "app/other.py"


def _drop_result(raw):
    raw["runs"][0]["results"].pop()


@pytest.mark.parametrize(
    "mutate", [_mutate_rule, _mutate_line, _mutate_uri, _drop_result]
)
def test_the_parser_assertions_fail_on_a_mutated_finding(tmp_path, mutate):
    raw = _raw_report()
    mutate(raw)
    with pytest.raises(AssertionError):
        _assert_expected_findings(_parse(_scanner(tmp_path), raw))


def test_the_parser_assertions_fail_on_a_wrong_level(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    report.runs[0].results[0].level = "warning"
    with pytest.raises(AssertionError):
        _assert_expected_findings(report)


def test_the_level_is_written_out_rather_than_left_to_a_default(tmp_path):
    """gitleaks writes no level; the scanner writes one that survives serialization.

    ASH's SARIF model defaults an absent result level to "error", but a default
    is not in ``model_fields_set``, so every ``exclude_unset`` dump -- which is
    how ASH writes its SARIF -- drops it again. A consumer of that file then
    applies the SARIF spec's own default for an absent level, "warning", which is
    not the rating ASH reported. Setting it makes "error" part of the finding.
    """
    raw = _raw_report()
    assert all("level" not in r for r in raw["runs"][0]["results"]), (
        "the capture should be gitleaks' own output, with no level"
    )
    unrated = SarifReport.model_validate(raw)
    dumped = json.loads(unrated.model_dump_json(exclude_unset=True))
    assert all("level" not in r for r in dumped["runs"][0]["results"])

    rated = _parse(_scanner(tmp_path), raw)
    dumped = json.loads(rated.model_dump_json(exclude_unset=True))
    assert [r["level"] for r in dumped["runs"][0]["results"]] == ["error"] * len(
        EXPECTED
    )


def test_every_finding_is_critical_like_detect_secrets(tmp_path):
    scanner = _scanner(tmp_path)
    report = _parse(scanner, _raw_report())
    counts = get_severity_metrics_from_sarif(report, scanner.context)
    assert counts.critical == len(EXPECTED)
    assert (counts.high, counts.medium, counts.low, counts.info) == (0, 0, 0, 0)


def test_tags_mark_findings_as_secrets(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    for result in report.get_all_results():
        assert {"secret", "security"} <= set(result.properties.tags)


def test_snippets_are_redacted(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    snippets = [
        r.locations[0].physicalLocation.root.region.snippet.text
        for r in report.get_all_results()
    ]
    assert snippets == [REDACTED] * len(EXPECTED)


def test_an_unredacted_snippet_is_overwritten(tmp_path):
    """Defense in depth: a snippet carrying a value never reaches ASH's outputs."""
    raw = _raw_report()
    region = raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    region["snippet"]["text"] = "value-that-must-not-survive"
    report = _parse(_scanner(tmp_path), raw)
    assert "value-that-must-not-survive" not in report.model_dump_json()


def test_empty_fingerprints_and_the_wrong_version_are_dropped(tmp_path):
    raw = _raw_report()
    assert raw["runs"][0]["tool"]["driver"]["semanticVersion"] == "v8.0.0"
    report = _parse(_scanner(tmp_path), raw)
    assert all(r.partialFingerprints is None for r in report.get_all_results())
    assert report.runs[0].tool.driver.semanticVersion is None


def test_a_non_empty_fingerprint_is_kept(tmp_path):
    raw = _raw_report()
    raw["runs"][0]["results"][0]["partialFingerprints"]["commitSha"] = "abc123"
    report = _parse(_scanner(tmp_path), raw)
    kept = [
        r.partialFingerprints for r in report.get_all_results() if r.partialFingerprints
    ]
    assert kept == [{"commitSha": "abc123"}]


# --------------------------------------------------------------------------- #
# ASH suppressions over gitleaks findings
# --------------------------------------------------------------------------- #


def _suppressed(tmp_path, *, suppressions=(), ignore_paths=()) -> dict:
    config = AshConfig.model_validate(
        {
            "project_name": "gitleaks-suppressions",
            "global_settings": {
                "suppressions": [s.model_dump(exclude_none=True) for s in suppressions],
                "ignore_paths": [p.model_dump() for p in ignore_paths],
            },
        }
    )
    context = _context(tmp_path, config)
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    report = apply_suppressions_to_sarif(_parse(scanner, _raw_report()), context)
    return {
        result.ruleId: bool(result.suppressions) for result in report.get_all_results()
    }


def test_no_suppressions_suppresses_nothing(tmp_path):
    state = _suppressed(tmp_path)
    assert state == {rule: False for rule, _, _ in EXPECTED}


def test_a_line_pinned_rule_suppression_suppresses_only_that_finding(tmp_path):
    state = _suppressed(
        tmp_path,
        suppressions=[
            AshSuppression(
                rule_id="github-pat",
                path="app/settings.py",
                line_start=4,
                line_end=4,
                reason="fixture",
            )
        ],
    )
    assert state == {
        "github-pat": True,
        "aws-access-token": False,
        "slack-bot-token": False,
    }


def test_a_suppression_on_the_wrong_line_suppresses_nothing(tmp_path):
    state = _suppressed(
        tmp_path,
        suppressions=[
            AshSuppression(
                rule_id="github-pat",
                path="app/settings.py",
                line_start=5,
                line_end=5,
                reason="fixture",
            )
        ],
    )
    assert not any(state.values())


def test_a_path_suppression_suppresses_every_finding_in_the_file(tmp_path):
    state = _suppressed(
        tmp_path,
        suppressions=[AshSuppression(path="app/settings.py", reason="fixture")],
    )
    assert state == {rule: True for rule, _, _ in EXPECTED}


def test_a_global_ignore_path_removes_the_findings(tmp_path):
    state = _suppressed(
        tmp_path,
        ignore_paths=[IgnorePathWithReason(path="app/**", reason="fixture")],
    )
    assert state == {}


def test_findings_under_the_output_dir_are_dropped(tmp_path):
    """The tool is not told to skip ASH's output dir; this pass removes them."""
    raw = _raw_report()
    moved = copy.deepcopy(raw["runs"][0]["results"][0])
    moved["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        ".ash/ash_output/reports/copied.py"
    )
    raw["runs"][0]["results"].append(moved)
    context = _context(tmp_path)
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    report = apply_suppressions_to_sarif(_parse(scanner, raw), context)
    uris = [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.get_all_results()
    ]
    assert len(uris) == len(EXPECTED)
    assert not any(u.startswith(".ash/") for u in uris)
