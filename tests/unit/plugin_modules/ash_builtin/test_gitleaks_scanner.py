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
import errno
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    DEFAULT_RULES_CONFIG,
    LEAKS_EXIT_CODE,
    REDACTED,
    GitleaksScanner,
    GitleaksScannerConfig,
    GitleaksScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    get_severity_metrics_from_sarif,
)

PluginContext.model_rebuild()

DATA = Path(__file__).parents[3] / "test_data" / "scanners" / "gitleaks"
CAPTURED_SARIF = DATA / "gitleaks-8.30.1.sarif"

#: What gitleaks 8.30.1 writes for the fixture repo with ASH's argv: (rule id, uri,
#: line). docs/example.md is in it because ASH does not pass the tree's
#: .gitleaks.toml, whose allowlist covers it. app/fingerprint_ignored.py is not:
#: gitleaks itself applies the tree's root .gitleaksignore, and ASH's re-scan adds
#: that finding back (tested here with a fake run, and against the binary in the
#: integration test). app/inline_allowed.py is in it because ASH passes
#: --ignore-gitleaks-allow; clean.py is absent by construction.
EXPECTED = {
    ("aws-access-token", "app/settings.py", 5),
    ("github-pat", "app/inline_allowed.py", 2),
    ("github-pat", "app/settings.py", 4),
    ("github-pat", "docs/example.md", 5),
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


def _scanner(
    tmp_path: Path, *, operator: bool | None = None, **options
) -> GitleaksScanner:
    """A scanner whose options came from the operator (True), the scanned tree
    (False), or a config with no recorded provenance (None, which counts as the
    tree's)."""
    context = _context(tmp_path)
    if operator is not None:
        source = Path(context.source_dir)
        record_provenance(
            context.config,
            in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
            trusted=AshConfig(),
        )
    return GitleaksScanner(
        context=context,
        config=GitleaksScannerConfig(
            enabled=True, options=GitleaksScannerConfigOptions(**options)
        ),
    )


def _ashs_own(path: Path, source: Path) -> bool:
    """Whether ``path`` is one ASH made for this run's gitleaks.

    ``config/tool_config_trust`` makes it in a directory of the scanner run's own,
    outside the scanned tree.
    """
    return not path.resolve().is_relative_to(Path(source).resolve()) and any(
        parent.name.startswith(TOOL_CONFIG_DIR_PREFIX) for parent in path.parents
    )


def _passes_the_default_rules(args: list, source: Path) -> bool:
    """Whether ``args`` give gitleaks ASH's default-rules config, and no other."""
    configs = [a for a in args if a.startswith("--config")]
    if len(configs) != 1 or not configs[0].startswith("--config="):
        return False
    path = Path(configs[0].split("=", 1)[1])
    return (
        path.name == "ash-gitleaks-default-rules.toml"
        and _ashs_own(path, source)
        and path.read_text() == DEFAULT_RULES_CONFIG
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
# A builtin scanner, on by default
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_gitleaks_is_on_by_default():
    assert GitleaksScannerConfig().enabled is True
    assert AshConfig().scanners.gitleaks.enabled is True


# --------------------------------------------------------------------------- #
# argv
# --------------------------------------------------------------------------- #


@pytest.mark.unit
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
    ):
        assert flag in args
    (no_ignore,) = [
        Path(a.split("=", 1)[1])
        for a in args
        if a.startswith("--gitleaks-ignore-path=")
    ]
    assert no_ignore.name == "ash-no-gitleaksignore"
    assert _ashs_own(no_ignore, source)
    assert no_ignore.is_dir() and not any(no_ignore.iterdir())
    assert _passes_the_default_rules(args, source)
    # Source-relative paths: "." from the source directory, after "--".
    assert args[-2:] == ["--", "."]
    # gitleaks then reads no file a symlink in the tree names.
    assert "--follow-symlinks" not in args


@pytest.mark.unit
def test_inline_allow_comments_are_off_by_default(tmp_path):
    """A gitleaks:allow comment in the scanned tree drops a finding before ASH sees
    it, so it would be neither reported nor counted as suppressed."""
    scanner = _scanner(tmp_path)
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert "--ignore-gitleaks-allow" in args[: args.index("--")]


@pytest.mark.unit
def test_the_operator_can_honor_inline_allow_comments(tmp_path):
    scanner = _scanner(tmp_path, operator=True, honor_inline_ignores=True)
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert "--ignore-gitleaks-allow" not in args


@pytest.mark.parametrize("operator", [False, None])
@pytest.mark.unit
def test_honor_inline_ignores_from_the_scanned_tree_is_ignored(
    tmp_path, caplog, operator
):
    scanner = _scanner(tmp_path, operator=operator, honor_inline_ignores=True)
    with caplog.at_level("WARNING"):
        args = scanner._build_arguments(
            scanner.context.source_dir, tmp_path / "o.sarif"
        )
        scanner._build_arguments(scanner.context.source_dir, tmp_path / "o2.sarif")
    assert "--ignore-gitleaks-allow" in args
    assert caplog.text.count("scanners.gitleaks.options.honor_inline_ignores") == 1


@pytest.mark.parametrize("operator", [False, None])
@pytest.mark.unit
def test_max_target_megabytes_from_the_scanned_tree_is_ignored(
    tmp_path, caplog, operator
):
    """A tree that raised gitleaks' size floor would skip any file it chose."""
    scanner = _scanner(tmp_path, operator=operator, max_target_megabytes=1)
    with caplog.at_level("WARNING"):
        args = scanner._build_arguments(
            scanner.context.source_dir, tmp_path / "o.sarif"
        )
        scanner._build_arguments(scanner.context.source_dir, tmp_path / "o2.sarif")
    assert not any(a.startswith("--max-target-megabytes") for a in args)
    assert caplog.text.count("scanners.gitleaks.options.max_target_megabytes") == 1


@pytest.mark.unit
def test_the_operators_max_target_megabytes_applies(tmp_path):
    scanner = _scanner(tmp_path, operator=True, max_target_megabytes=3)
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert "--max-target-megabytes=3" in args


@pytest.mark.unit
def test_the_re_scan_skips_large_files_only_at_the_operators_limit(
    tmp_path, monkeypatch
):
    """The tree's limit is not the re-scan's either: it copies what the first run
    was told to read."""
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {}, operator=False, max_target_megabytes=1
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/big.py", "x" * 1_500_000)
    (source / ".gitleaksignore").write_text("app/big.py:github-pat:1\n")
    _add_back(scanner, source, _report(), tmp_path)
    assert [call["files"] for call in calls] == [["app/big.py"]]


@pytest.mark.unit
def test_argv_for_the_converted_target_is_absolute(tmp_path):
    scanner = _scanner(tmp_path)
    converted = scanner.context.work_dir
    converted.mkdir(parents=True)
    args = scanner._build_arguments(converted, tmp_path / "out.sarif")
    assert args[-2:] == ["--", converted.absolute().as_posix()]


@pytest.mark.unit
def test_every_option_is_one_token_so_no_value_can_become_a_flag(tmp_path):
    """A path starting with "-" stays a value, and the scan path follows "--"."""
    scanner = _scanner(
        tmp_path,
        operator=True,
        config_file="-c-dash.toml",
        baseline_path="--baseline.json",
        max_target_megabytes=5,
    )
    source = scanner.context.source_dir
    (source / "-c-dash.toml").write_text("[extend]\nuseDefault = true\n")
    (source / "--baseline.json").write_text("[]")
    args = scanner._build_arguments(source, tmp_path / "out.sarif")
    flags = args[2 : args.index("--")]
    assert all(a.startswith("--") for a in flags), flags
    assert args[args.index("--") + 1 :] == ["."]
    assert f"--config={(source / '-c-dash.toml').resolve().as_posix()}" in flags
    assert (
        f"--baseline-path={(source / '--baseline.json').resolve().as_posix()}" in flags
    )
    assert "--max-target-megabytes=5" in flags


@pytest.mark.parametrize("name", [".gitleaks.toml", ".ash/.gitleaks.toml"])
@pytest.mark.unit
def test_a_gitleaks_config_in_the_scanned_tree_is_not_read(
    tmp_path, monkeypatch, caplog, name
):
    """It could replace the rules or allowlist everything, unreported."""
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner = _scanner(tmp_path)
    found = scanner.context.source_dir / name
    found.parent.mkdir(parents=True, exist_ok=True)
    found.write_text("[extend]\nuseDefault = true\n[allowlist]\npaths = ['.*']\n")
    with caplog.at_level("INFO"):
        args = scanner._build_arguments(
            scanner.context.source_dir, tmp_path / "o.sarif"
        )
    assert _passes_the_default_rules(args, scanner.context.source_dir)
    assert f"{name} in the scanned tree is not read" in caplog.text


@pytest.mark.parametrize("variable", ["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"])
@pytest.mark.unit
def test_a_gitleaks_config_env_var_is_left_to_gitleaks(tmp_path, monkeypatch, variable):
    """The operator's environment, not the tree: gitleaks resolves it.

    An absolute ``GITLEAKS_CONFIG``, or ``GITLEAKS_CONFIG_TOML`` (the config's
    text), needs nothing from ASH. A RELATIVE ``GITLEAKS_CONFIG`` is the one
    value gitleaks would resolve against its working directory, the scanned
    tree, so ASH anchors that one where the operator set it and passes it as
    ``--config`` (the test below)."""
    value = (
        str(tmp_path / "operator.toml")
        if variable == "GITLEAKS_CONFIG"
        else 'title = "inline"\n'
    )
    # Only the variable under test is set: the other one, if the runner's
    # environment carries it, would add a second route to the same answer.
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.setenv(variable, value)
    scanner = _scanner(tmp_path)
    (scanner.context.source_dir / ".gitleaks.toml").write_text("")
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert not any(a.startswith("--config") for a in args)


@pytest.mark.unit
def test_the_operators_config_file_wins_over_env_and_the_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLEAKS_CONFIG", "elsewhere.toml")
    scanner = _scanner(tmp_path, operator=True, config_file="rules/custom.toml")
    source = scanner.context.source_dir
    (source / ".gitleaks.toml").write_text("")
    (source / "rules").mkdir()
    (source / "rules" / "custom.toml").write_text("")
    args = scanner._build_arguments(source, tmp_path / "o.sarif")
    configs = [a for a in args if a.startswith("--config")]
    assert configs == [
        f"--config={(source / 'rules/custom.toml').resolve().as_posix()}"
    ]


@pytest.mark.parametrize("operator", [False, None])
@pytest.mark.unit
def test_config_file_and_baseline_from_the_scanned_tree_are_ignored(
    tmp_path, monkeypatch, caplog, operator
):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner = _scanner(
        tmp_path,
        operator=operator,
        config_file="rules/custom.toml",
        baseline_path="baseline.json",
    )
    source = scanner.context.source_dir
    (source / "rules").mkdir()
    (source / "rules" / "custom.toml").write_text("")
    (source / "baseline.json").write_text("[]")
    with caplog.at_level("WARNING"):
        args = scanner._build_arguments(source, tmp_path / "o.sarif")
    assert _passes_the_default_rules(args, scanner.context.source_dir)
    assert not any(a.startswith("--baseline-path") for a in args)
    for option in ("config_file", "baseline_path"):
        assert f"scanners.gitleaks.options.{option}" in caplog.text


@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
@pytest.mark.unit
def test_an_operator_path_that_does_not_exist_fails_the_scan(tmp_path, option):
    """Falling back to default rules would scan with rules nobody asked for."""
    scanner = _scanner(tmp_path, operator=True, **{option: "missing.file"})
    with pytest.raises(ScannerError, match=f"scanners.gitleaks.options.{option}"):
        scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")


@pytest.mark.unit
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
@pytest.mark.unit
def test_success_exit_codes_read_the_report(tmp_path, code):
    scanner = _scanner(tmp_path)
    scanner.exit_code = code
    assert scanner._read_results_file(CAPTURED_SARIF)["version"] == "2.1.0"


@pytest.mark.parametrize("code", [1, 3, 126, -9])
@pytest.mark.unit
def test_a_failing_exit_code_refuses_even_a_present_report(tmp_path, code):
    """gitleaks exits 1 on every fatal error, so 1 must never read as "leaks"."""
    scanner = _scanner(tmp_path)
    scanner.exit_code = code
    with pytest.raises(ScannerError, match=f"gitleaks exited {code}"):
        scanner._read_results_file(CAPTURED_SARIF)


@pytest.mark.integration
def test_a_tool_that_hangs_is_killed_and_reported_as_timed_out(tmp_path, monkeypatch):
    """The error names the scanner and the limit as the configuration guide shows
    it, ``<scanner> timed out after '1800' s``: the limit is its own quoted token,
    never ``after 1s``."""
    scanner = _scanner(tmp_path, scan_timeout=1)
    source = scanner.context.source_dir
    (source / "a.txt").write_text("x")
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_build_arguments",
        lambda target, results: [sys.executable, "-c", "import time; time.sleep(60)"],
    )
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=source, target_type="source")
    message = str(raised.value)
    assert "GitleaksScanner timed out after '1' s and was killed" in message, message
    assert "scanners.gitleaks.options.scan_timeout" in message, message
    # What the executor reads instead of the message. A stop that failed is
    # recorded here and said in the message instead of "was killed".
    assert scanner.scan_timed_out_after == 1
    assert scanner.scan_could_not_stop is None


@pytest.mark.unit
def test_a_tool_that_finishes_under_the_limit_is_not_reported_as_timed_out(
    tmp_path, monkeypatch
):
    """The hang test's control: the same scanner and limit, with a tool that exits
    in time. It is bounded by the limit, and its report is read."""
    from automated_security_helper.utils import subprocess_utils

    scanner = _scanner(tmp_path, scan_timeout=1)
    source = scanner.context.source_dir
    (source / "a.txt").write_text("x")
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    limits = []

    def launch(command, **kwargs):
        limits.append(kwargs.get("timeout"))
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(CAPTURED_SARIF.read_text(encoding="utf-8"))
        return {"returncode": LEAKS_EXIT_CODE}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", launch)
    report = scanner.scan(target=source, target_type="source")
    _assert_expected_findings(report)
    assert limits == [1.0]
    assert scanner.scan_timed_out_after is None
    assert scanner.scan_could_not_stop is None


@pytest.mark.unit
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


@pytest.mark.unit
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
@pytest.mark.unit
def test_the_parser_assertions_fail_on_a_mutated_finding(tmp_path, mutate):
    raw = _raw_report()
    mutate(raw)
    with pytest.raises(AssertionError):
        _assert_expected_findings(_parse(_scanner(tmp_path), raw))


@pytest.mark.unit
def test_the_parser_assertions_fail_on_a_wrong_level(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    report.runs[0].results[0].level = "warning"
    with pytest.raises(AssertionError):
        _assert_expected_findings(report)


@pytest.mark.unit
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


@pytest.mark.unit
def test_every_finding_is_critical_like_detect_secrets(tmp_path):
    scanner = _scanner(tmp_path)
    report = _parse(scanner, _raw_report())
    counts = get_severity_metrics_from_sarif(report, scanner.context)
    assert counts.critical == len(EXPECTED)
    assert (counts.high, counts.medium, counts.low, counts.info) == (0, 0, 0, 0)


@pytest.mark.unit
def test_the_flat_reports_read_critical_too(tmp_path):
    """A bare level "error" reads HIGH in the flat reporters (flat JSON, CSV)."""
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

    report = _parse(_scanner(tmp_path), _raw_report())
    results = report.runs[0].results
    assert results  # not vacuous
    flat = [
        FlatVulnerability.from_sarif_result(r, "gitleaks", "SECRETS") for r in results
    ]
    assert {f.severity for f in flat} == {"CRITICAL"}


@pytest.mark.unit
def test_tags_mark_findings_as_secrets(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    for result in report.get_all_results():
        assert {"secret", "security"} <= set(result.properties.tags)


@pytest.mark.unit
def test_snippets_are_redacted(tmp_path):
    report = _parse(_scanner(tmp_path), _raw_report())
    snippets = [
        r.locations[0].physicalLocation.root.region.snippet.text
        for r in report.get_all_results()
    ]
    assert snippets == [REDACTED] * len(EXPECTED)


@pytest.mark.unit
def test_an_unredacted_snippet_is_overwritten(tmp_path):
    """Defense in depth: a snippet carrying a value never reaches ASH's outputs."""
    raw = _raw_report()
    region = raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    region["snippet"]["text"] = "value-that-must-not-survive"
    report = _parse(_scanner(tmp_path), raw)
    assert "value-that-must-not-survive" not in report.model_dump_json()


@pytest.mark.unit
def test_empty_fingerprints_and_the_wrong_version_are_dropped(tmp_path):
    raw = _raw_report()
    assert raw["runs"][0]["tool"]["driver"]["semanticVersion"] == "v8.0.0"
    report = _parse(_scanner(tmp_path), raw)
    assert all(r.partialFingerprints is None for r in report.get_all_results())
    assert report.runs[0].tool.driver.semanticVersion is None


@pytest.mark.unit
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
        (
            result.ruleId,
            result.locations[0].physicalLocation.root.artifactLocation.uri,
        ): bool(result.suppressions)
        for result in report.get_all_results()
    }


@pytest.mark.unit
def test_no_suppressions_suppresses_nothing(tmp_path):
    state = _suppressed(tmp_path)
    assert state == {(rule, uri): False for rule, uri, _ in EXPECTED}


@pytest.mark.unit
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
        ("github-pat", "app/settings.py"): True,
        ("github-pat", "app/inline_allowed.py"): False,
        ("github-pat", "docs/example.md"): False,
        ("aws-access-token", "app/settings.py"): False,
        ("slack-bot-token", "app/settings.py"): False,
    }


@pytest.mark.unit
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


@pytest.mark.unit
def test_a_path_suppression_suppresses_every_finding_in_the_file(tmp_path):
    state = _suppressed(
        tmp_path,
        suppressions=[AshSuppression(path="app/settings.py", reason="fixture")],
    )
    assert state == {(rule, uri): uri == "app/settings.py" for rule, uri, _ in EXPECTED}


@pytest.mark.unit
def test_a_global_ignore_path_removes_the_findings(tmp_path):
    state = _suppressed(
        tmp_path,
        ignore_paths=[IgnorePathWithReason(path="app/**", reason="fixture")],
    )
    assert state == {("github-pat", "docs/example.md"): False}


def _with_copies_at(raw: dict, *uris: str) -> dict:
    """``raw`` plus a copy of its first result at each of ``uris``."""
    for uri in uris:
        moved = copy.deepcopy(raw["runs"][0]["results"][0])
        moved["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
        raw["runs"][0]["results"].append(moved)
    return raw


#: Where the source run finds copies of a secret under ASH's default output
#: directory: the converted copy of an archive's file (in work_dir, which ASH's
#: suppression pass keeps, because the converted run's findings live there), a
#: report from an earlier run, and the same converted file spelled with "./".
OUTPUT_DIR_COPIES = (
    ".ash/ash_output/converted/archive/bundle_zip/conf/settings.py",
    ".ash/ash_output/reports/copied.py",
    "./.ash/ash_output/converted/archive/bundle_zip/conf/other.py",
)


@pytest.mark.unit
def test_findings_under_the_output_dir_are_dropped(tmp_path):
    """The source run reads ASH's output directory, gitleaks having no flag to skip
    it. The converted target's run already reports the converted files, so a copy
    found there is the same secret a second time: the scanner drops every source-run
    finding under the output directory, work_dir included."""
    raw = _with_copies_at(_raw_report(), *OUTPUT_DIR_COPIES)
    context = _context(tmp_path)
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    parsed = _parse(scanner, raw)
    _assert_expected_findings(parsed)
    # And nothing comes back through ASH's own suppression pass.
    _assert_expected_findings(apply_suppressions_to_sarif(parsed, context))


@pytest.mark.unit
def test_the_converted_runs_findings_under_work_dir_are_kept(tmp_path):
    """The converted target is work_dir itself, under the output directory: its
    findings are the converted files' only report."""
    context = _context(tmp_path)
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    work = Path(context.work_dir)
    work.mkdir(parents=True)
    uri = (work / "archive" / "bundle_zip" / "conf" / "settings.py").as_posix()
    report = SarifReport.model_validate(_report(_result(uri, "github-pat", 1)))
    kept = scanner._post_process_sarif(report, [], work)
    assert [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in kept.get_all_results()
    ] == [uri]


@pytest.mark.unit
def test_nothing_is_dropped_when_the_output_dir_is_outside_the_source(tmp_path):
    """A path that only looks like ASH's default output directory is the tree's."""
    source = tmp_path / "src"
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=AshConfig(),
    )
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    raw = _with_copies_at(_raw_report(), *OUTPUT_DIR_COPIES)
    parsed = scanner._post_process_sarif(SarifReport.model_validate(raw), [], source)
    assert len(parsed.get_all_results()) == len(EXPECTED) + len(OUTPUT_DIR_COPIES)


#: Under ASH's default output directory, what a repository can commit there, and
#: what ASH writes there itself: a report from an earlier run, and the converted
#: copy of an archive's file. The second pair is on disk and never staged.
COMMITTED_IN_OUTPUT_DIR = (
    ".ash/ash_output/hidden/app.py",
    ".ash/ash_output/hidden/settings.py",
)
ASH_WROTE_IN_OUTPUT_DIR = (
    ".ash/ash_output/reports/copied.py",
    ".ash/ash_output/converted/archive/bundle_zip/conf/settings.py",
)


def _commit_files_under_the_output_dir(source: Path) -> None:
    """Make ``source`` a git checkout that tracks ``COMMITTED_IN_OUTPUT_DIR``.

    Every file of both tuples is on disk, as after a scan; only the first tuple's
    are staged, so git tells the repository's files from ASH's.
    """
    from tests.unit.workspace.test_execution import _git

    for name in (*COMMITTED_IN_OUTPUT_DIR, *ASH_WROTE_IN_OUTPUT_DIR):
        _write(source, name, "value = 'x'\n")
    assert _git(source, "init", "-q").returncode == 0
    added = _git(source, "add", *COMMITTED_IN_OUTPUT_DIR)
    assert added.returncode == 0, added.stderr


def _uris_under_the_output_dir(report: SarifReport) -> list[str]:
    return sorted(
        uri
        for uri in (
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.get_all_results()
        )
        if uri.startswith(".ash/")
    )


@pytest.mark.usefixtures("no_checkout_above_tmp_path")
@pytest.mark.integration
def test_findings_in_files_the_repository_committed_under_the_output_dir_are_kept(
    tmp_path,
):
    """The output directory is a path in the tree that a repository can commit files
    to, and ``.ash/ash_output`` is the default. A secret in a committed file is in
    the repository, whatever the directory is called: the drop removes what ASH
    wrote there, and leaves the findings in the files git tracks."""
    context = _context(tmp_path)
    _commit_files_under_the_output_dir(Path(context.source_dir))
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    raw = _with_copies_at(
        _raw_report(), *COMMITTED_IN_OUTPUT_DIR, *ASH_WROTE_IN_OUTPUT_DIR
    )

    parsed = _parse(scanner, raw)

    assert _uris_under_the_output_dir(parsed) == sorted(COMMITTED_IN_OUTPUT_DIR)
    assert len(parsed.get_all_results()) == len(EXPECTED) + len(COMMITTED_IN_OUTPUT_DIR)


@pytest.mark.usefixtures("no_checkout_above_tmp_path")
@pytest.mark.integration
def test_what_ash_wrote_under_the_output_dir_is_still_dropped_beside_committed_files(
    tmp_path,
):
    """The control for the test above: in the same tree, with the committed files
    tracked beside them, the findings in what ASH wrote under the same directory
    are dropped, and the tree's findings outside it stay."""
    context = _context(tmp_path)
    _commit_files_under_the_output_dir(Path(context.source_dir))
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    raw = _with_copies_at(_raw_report(), *ASH_WROTE_IN_OUTPUT_DIR)

    parsed = _parse(scanner, raw)

    assert _uris_under_the_output_dir(parsed) == []
    _assert_expected_findings(parsed)


@pytest.mark.unit
def test_post_processing_with_a_context_finds_the_output_dir_in_the_base(tmp_path):
    """``_post_process_sarif`` asks the scanner base where ASH's output directory
    sits (``ScannerPluginBase._output_dir_inside``) before it reads a result. The
    base once lost that helper while this scanner, trivy and snyk-code still called
    it, and every scan with a plugin context then died in post-processing with an
    AttributeError and reported no findings."""
    context = _context(tmp_path)
    scanner = GitleaksScanner(context=context, config=GitleaksScannerConfig())
    source = Path(context.source_dir)
    assert scanner._output_dir_inside(source) == Path(".ash/ash_output")
    # The converted target, work_dir, lives under the output directory, which
    # therefore contains it: nothing to skip there.
    assert scanner._output_dir_inside(Path(context.work_dir)) is None
    _assert_expected_findings(_parse(scanner, _raw_report()))


@pytest.mark.unit
def test_gitleaks_config_variables_are_left_to_gitleaks_outside_a_sandbox(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    (scanner.context.source_dir / ".gitleaks.toml").write_text('title = "repo"\n')
    monkeypatch.setenv("GITLEAKS_CONFIG", str(tmp_path / "operator.toml"))

    assert scanner._resolve_config_file() is None


@pytest.mark.unit
def test_under_a_sandbox_gitleaks_config_variables_give_the_default_rules(
    tmp_path, monkeypatch, caplog
):
    """The sandbox drops GITLEAKS_*, so leaving resolution to gitleaks would quietly
    pick the scanned tree's .gitleaks.toml. ASH passes gitleaks' default rules."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    scanner = _scanner(tmp_path)
    (scanner.context.source_dir / ".gitleaks.toml").write_text('title = "repo"\n')
    monkeypatch.setenv("GITLEAKS_CONFIG", str(tmp_path / "operator.toml"))
    monkeypatch.setattr(module, "active_scope", lambda: object())

    with caplog.at_level("INFO"):
        chosen = scanner._resolve_config_file()

    assert chosen is not None and chosen.name == "ash-gitleaks-default-rules.toml"
    assert _ashs_own(chosen, scanner.context.source_dir)
    assert chosen.read_text() == DEFAULT_RULES_CONFIG
    assert "not passed into the scanner sandbox" in caplog.text
    assert ".gitleaks.toml in the scanned tree is not read" in caplog.text


# --------------------------------------------------------------------------- #
# The scanned tree's .gitleaksignore
# --------------------------------------------------------------------------- #


def _result(uri: str, rule: str, line: int, column: int | None = None) -> dict:
    region: dict = {"startLine": line, "snippet": {"text": "REDACTED"}}
    if column is not None:
        # As gitleaks writes a region: the match's start and end on its line.
        region.update(startColumn=column, endLine=line, endColumn=column + 39)
    return {
        "ruleId": rule,
        "message": {"text": f"{rule} has detected secret"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region,
                }
            }
        ],
    }


def _report(*results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": list(results)}],
    }


def _rescan_harness(
    tmp_path,
    monkeypatch,
    per_file: dict,
    code: int = LEAKS_EXIT_CODE,
    operator: bool | None = None,
    **options,
):
    """A scanner whose re-scans stand in for gitleaks over ASH's copies.

    Each run reports ``per_file[<path>]`` for every file under its working
    directory, or for the one file it is given, with the URI gitleaks would write:
    the path relative to that directory. ``calls`` records each run's argv,
    working directory, and the files it found there with their bytes.
    """
    scanner = _scanner(tmp_path, operator=operator, **options)
    calls = []

    def fake_run(command, results_dir=None, timeout=None, cwd=None, **kwargs):
        root = Path(cwd)
        scan = command[-1]
        if scan == ".":
            files = sorted(
                p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
            )
        else:
            files = [scan]
        calls.append(
            {
                "argv": list(command),
                "cwd": root,
                "files": files,
                "contents": {name: (root / name).read_bytes() for name in files},
                "env": kwargs.get("env"),
            }
        )
        found = []
        for name in files:
            for result in per_file.get(name, []):
                result = copy.deepcopy(result)
                result["locations"][0]["physicalLocation"]["artifactLocation"][
                    "uri"
                ] = name
                found.append(result)
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(json.dumps(_report(*found)))
        return {"returncode": code}

    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    return scanner, calls


def _write(source: Path, name: str, text: str = "x") -> Path:
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.mark.unit
def test_findings_the_trees_gitleaksignore_drops_are_added_back(tmp_path, monkeypatch):
    kept = _result("app/settings.py", "aws-access-token", 5)
    dropped = _result("app/settings.py", "github-pat", 4)
    other = _result("docs/example.md", "github-pat", 5)
    scanner, calls = _rescan_harness(
        tmp_path,
        monkeypatch,
        {"app/settings.py": [kept, dropped], "docs/example.md": [other]},
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py", "settings")
    _write(source, "docs/example.md", "example")
    _write(source, "app/unnamed.py", "not named")
    (source / ".gitleaksignore").write_text(
        "# a comment\n"
        "app/settings.py:github-pat:4\n"
        "docs/example.md:github-pat:5\n"
        "0123abc:app/settings.py:github-pat:4\n"  # a git-scan fingerprint
        "../outside.txt:github-pat:1\n"
        "missing.py:github-pat:1\n"
    )
    (tmp_path / "outside.txt").write_text("x")
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    main_args = scanner._build_arguments(source, results_file)
    raw = _report(kept)

    scanner._add_back_gitleaksignore_drops(raw, source, main_args, results_file)

    keys = {
        (r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], r["ruleId"])
        for r in raw["runs"][0]["results"]
    }
    assert keys == {
        ("app/settings.py", "aws-access-token"),
        ("app/settings.py", "github-pat"),
        ("docs/example.md", "github-pat"),
    }
    # One run, over copies of the named files inside the target at their tree
    # paths, with the first run's flags and its own report, scanned as ".".
    [call] = calls
    assert call["files"] == ["app/settings.py", "docs/example.md"]
    assert call["contents"] == {
        "app/settings.py": b"settings",
        "docs/example.md": b"example",
    }
    assert call["argv"][-2:] == ["--", "."]
    assert call["argv"][:-1] != main_args[:-1]
    assert [a for a in call["argv"] if not a.startswith("--report-path=")][:-1] == [
        a for a in main_args if not a.startswith("--report-path=")
    ][:-1]
    # The copies are outside the scanned tree, in the run's own directory; the
    # report stays beside the first run's.
    assert call["cwd"].name == "tree"
    assert call["cwd"].parent.name == "gitleaksignore-rescan"
    assert _ashs_own(call["cwd"], source), call["cwd"]
    rescan_reports = results_file.parent / "gitleaksignore-rescan"
    assert any(
        a == f"--report-path={(rescan_reports / 'tree.sarif').as_posix()}"
        for a in call["argv"]
    )
    # The copies hold the tree's secrets: none is left behind.
    assert not call["cwd"].exists()
    assert not call["cwd"].parent.exists()


@pytest.mark.unit
def test_without_a_gitleaksignore_nothing_is_re_scanned(tmp_path, monkeypatch):
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    results_file = tmp_path / "gitleaks.sarif"
    raw = _report()
    scanner._add_back_gitleaksignore_drops(
        raw, source, scanner._build_arguments(source, results_file), results_file
    )
    assert calls == [] and raw["runs"][0]["results"] == []


@pytest.mark.parametrize("code", [1, 126])
@pytest.mark.unit
def test_a_failed_re_scan_fails_the_scan(tmp_path, monkeypatch, code):
    """Reporting the first run alone would hide what the ignore file dropped."""
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {}, code=code)
    source = Path(scanner.context.source_dir)
    (source / "a.py").write_text("x")
    (source / ".gitleaksignore").write_text("a.py:github-pat:1\n")
    results_file = tmp_path / "gitleaks.sarif"
    with pytest.raises(ScannerError, match="re-scanning the files"):
        scanner._add_back_gitleaksignore_drops(
            _report(),
            source,
            scanner._build_arguments(source, results_file),
            results_file,
        )
    assert calls and not calls[0]["cwd"].exists()


def _add_back(scanner, source: Path, raw: dict, tmp_path: Path) -> list:
    """Run the add-back for ``raw`` and return its (uri, rule, line, column)s."""
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir(exist_ok=True)
    scanner._add_back_gitleaksignore_drops(
        raw, source, scanner._build_arguments(source, results_file), results_file
    )
    return sorted(
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["locations"][0]["physicalLocation"]["region"].get("startColumn"),
        )
        for r in raw["runs"][0]["results"]
    )


@pytest.mark.unit
def test_two_secrets_of_one_rule_on_one_line_are_both_added_back(tmp_path, monkeypatch):
    """A dir-scan fingerprint is <file>:<rule>:<line>, so one .gitleaksignore entry
    hides every match of that rule on the line. The re-scan reports each of them,
    told apart by column, and each is a finding."""
    first = _result("app/two.py", "github-pat", 1, column=6)
    second = _result("app/two.py", "github-pat", 1, column=54)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"app/two.py": [first, second]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/two.py")
    (source / ".gitleaksignore").write_text("app/two.py:github-pat:1\n")

    assert _add_back(scanner, source, _report(), tmp_path) == [
        ("app/two.py", "github-pat", 1, 6),
        ("app/two.py", "github-pat", 1, 54),
    ]
    assert len(calls) == 1


@pytest.mark.unit
def test_a_finding_the_first_run_kept_is_not_added_twice(tmp_path, monkeypatch):
    """The control for the column in the key: the same match, same column, is the
    same finding."""
    hidden = _result("app/two.py", "github-pat", 1, column=6)
    kept = _result("app/two.py", "github-pat", 1, column=54)
    scanner, _ = _rescan_harness(tmp_path, monkeypatch, {"app/two.py": [hidden, kept]})
    source = Path(scanner.context.source_dir)
    _write(source, "app/two.py")
    (source / ".gitleaksignore").write_text("app/two.py:github-pat:1\n")

    assert _add_back(scanner, source, _report(copy.deepcopy(kept)), tmp_path) == [
        ("app/two.py", "github-pat", 1, 6),
        ("app/two.py", "github-pat", 1, 54),
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "./app/settings.py:github-pat:4",
        "app//settings.py:github-pat:4",
        "app/../app/settings.py:github-pat:4",
        "{source}/app/settings.py:github-pat:4",
    ],
)
@pytest.mark.unit
def test_an_entry_spelled_another_way_adds_no_duplicate(tmp_path, monkeypatch, entry):
    """gitleaks reports a file in the spelling it was given. The re-scan reaches
    each file by the path the directory scan does, so its findings match the first
    run's and none is added twice."""
    found = _result("app/settings.py", "github-pat", 4, column=18)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"app/settings.py": [found]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    entry = entry.format(source=source.absolute().as_posix())
    (source / ".gitleaksignore").write_text(entry + "\n")

    assert _add_back(scanner, source, _report(copy.deepcopy(found)), tmp_path) == [
        ("app/settings.py", "github-pat", 4, 18)
    ]
    assert [call["files"] for call in calls] == [["app/settings.py"]]


@pytest.mark.unit
def test_what_the_directory_scan_does_not_read_is_not_re_scanned(tmp_path, monkeypatch):
    """gitleaks follows no symlink, at the file or a parent; skips a FIFO and an
    empty file; and does not scan its own baseline. ASH's output directory is
    read but dropped. None of those is copied; a hard-linked file is."""
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {}, operator=True, baseline_path="baseline.json"
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/real.py")
    _write(source, "app/hard.py", "hard")
    _write(source, "baseline.json", "[]")
    _write(source, ".ash/ash_output/converted/x.py")
    (source / "app" / "empty.py").write_text("")
    entries = [
        "app/real.py",
        "app/link.py",
        "linked/real.py",
        "app/hardlink.py",
        "app/empty.py",
        "baseline.json",
        ".ash/ash_output/converted/x.py",
    ]
    try:
        (source / "app" / "link.py").symlink_to("real.py")
        (source / "linked").symlink_to("app", target_is_directory=True)
        os.link(source / "app" / "hard.py", source / "app" / "hardlink.py")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"links unavailable on this platform: {exc}")
    if hasattr(os, "mkfifo"):
        os.mkfifo(source / "app" / "fifo")
        entries.append("app/fifo")
    (source / ".gitleaksignore").write_text(
        "".join(f"{name}:github-pat:1\n" for name in entries)
    )
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    main_args = scanner._build_arguments(source, results_file)
    assert any(a.startswith("--baseline-path=") for a in main_args)

    scanner._add_back_gitleaksignore_drops(_report(), source, main_args, results_file)

    assert [call["files"] for call in calls] == [["app/hardlink.py", "app/real.py"]]


@pytest.mark.usefixtures("no_checkout_above_tmp_path")
@pytest.mark.integration
def test_only_what_ash_wrote_under_the_output_dir_is_not_re_scanned(
    tmp_path, monkeypatch
):
    """The re-scan leaves out the files under ASH's output directory because the
    scanner drops what it finds there. A file the repository committed there keeps
    its findings, so a finding the tree's ``.gitleaksignore`` hides in it is added
    back like one in any other file. What ASH wrote there is still left out."""
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _commit_files_under_the_output_dir(source)
    (source / ".gitleaksignore").write_text(
        "".join(
            f"{name}:github-pat:1\n"
            for name in (COMMITTED_IN_OUTPUT_DIR[0], *ASH_WROTE_IN_OUTPUT_DIR)
        )
    )
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    main_args = scanner._build_arguments(source, results_file)

    scanner._add_back_gitleaksignore_drops(_report(), source, main_args, results_file)

    assert [call["files"] for call in calls] == [[COMMITTED_IN_OUTPUT_DIR[0]]]


@pytest.mark.unit
def test_a_gitleaksignore_that_names_itself_is_re_scanned_as_a_file(
    tmp_path, monkeypatch
):
    """At the copies' root it would be read as their ignore file, so it is copied
    alone and scanned as a file, which reads none."""
    hidden = _result(".gitleaksignore", "github-pat", 2)
    other = _result("app/x.py", "github-pat", 1)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {".gitleaksignore": [hidden], "app/x.py": [other]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text(
        ".gitleaksignore:github-pat:2\napp/x.py:github-pat:1\n"
    )

    assert _add_back(scanner, source, _report(), tmp_path) == [
        (".gitleaksignore", "github-pat", 2, None),
        ("app/x.py", "github-pat", 1, None),
    ]
    tree, itself = calls
    assert tree["files"] == ["app/x.py"]
    assert itself["argv"][-2:] == ["--", ".gitleaksignore"]
    assert not (itself["cwd"] / ".gitleaksignore").exists()
    assert itself["cwd"] != tree["cwd"]


@pytest.mark.unit
def test_the_converted_targets_re_scan_reports_absolute_uris(tmp_path, monkeypatch):
    """The converted target is scanned by its absolute path, so its first run's
    URIs are absolute, and the re-scan's are made so to compare with them."""
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"a/x.py": [_result("a/x.py", "github-pat", 1)]}
    )
    work = Path(scanner.context.work_dir)
    _write(work, "a/x.py")
    (work / ".gitleaksignore").write_text("a/x.py:github-pat:1\n")

    assert _add_back(scanner, work, _report(), tmp_path) == [
        ((work / "a" / "x.py").absolute().as_posix(), "github-pat", 1, None)
    ]
    assert calls[0]["files"] == ["a/x.py"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
@pytest.mark.unit
def test_the_copies_are_private_to_their_owner(tmp_path, monkeypatch):
    scanner, _ = _rescan_harness(tmp_path, monkeypatch, {})
    modes = []

    def spy(command, cwd=None, **kwargs):
        modes.append(stat.S_IMODE(os.stat(Path(cwd) / "app" / "x.py").st_mode))
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(json.dumps(_report()))
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_run_subprocess", spy)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    _add_back(scanner, source, _report(), tmp_path)
    assert modes == [0o600]


@pytest.mark.unit
def test_a_relative_gitleaks_config_variable_is_anchored_where_the_operator_set_it(
    tmp_path, monkeypatch
):
    """gitleaks resolves a relative GITLEAKS_CONFIG against its working directory,
    the scanned source directory, so the repository would supply the file the
    operator named in ASH's own directory. The scanner anchors the value to the
    directory ASH runs in and passes it as ``--config`` to the first run and the
    re-scans alike; the scanned tree's file of the same name is never read."""
    operator_dir = tmp_path / "operator"
    (operator_dir / "rules").mkdir(parents=True)
    (operator_dir / "rules" / "gl.toml").write_text('title = "operator"\n')
    monkeypatch.chdir(operator_dir)
    monkeypatch.setenv("GITLEAKS_CONFIG", "rules/gl.toml")
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    _write(source, "rules/gl.toml", 'title = "repo"\n')
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    _add_back(scanner, source, _report(), tmp_path)
    anchored = (operator_dir / "rules" / "gl.toml").resolve().as_posix()
    assert f"--config={anchored}" in calls[0]["argv"]
    repo_copy = (source / "rules" / "gl.toml").absolute().as_posix()
    assert calls, "no gitleaks run was made"
    for call in calls:
        # Every run, the first and each re-scan, is handed the anchored file.
        assert f"--config={anchored}" in call["argv"], call["argv"]
        assert not any(repo_copy in a for a in call["argv"])
        # And the environment the child really gets cannot lead gitleaks into
        # the tree: a value set there is resolved where gitleaks runs (the
        # run's working directory, a copy of the tree for a re-scan), and must
        # land in neither the scanned tree nor that directory.
        value = (call["env"] or {}).get("GITLEAKS_CONFIG")
        if value:
            resolved = (Path(call["cwd"]) / value).resolve()
            assert not resolved.is_relative_to(source.resolve()), value
            assert not resolved.is_relative_to(Path(call["cwd"]).resolve()), value


# --------------------------------------------------------------------------- #
# The tree's .gitleaksignore is read as a regular file, and never quoted
# --------------------------------------------------------------------------- #

MARKER = "ash-marker-0b7f3c"


def _refused_ignore_file(tmp_path: Path, kind: str) -> GitleaksScanner:
    """A scanner over a tree whose .gitleaksignore is ``kind``."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    outside = tmp_path / "outside.txt"
    outside.write_text(f"{MARKER}\n")
    ignore = source / ".gitleaksignore"
    if kind == "symlink out of the tree":
        ignore.symlink_to(outside)
    elif kind == "symlink in the tree":
        _write(source, "docs/ignore.txt", f"{MARKER}\n")
        ignore.symlink_to(source / "docs" / "ignore.txt")
    elif kind == "fifo":
        os.mkfifo(ignore)
    elif kind == "directory":
        ignore.mkdir()
    elif kind == "hard link":
        os.link(outside, ignore)
    return scanner


IGNORE_FILE_KINDS = [
    pytest.param(
        "symlink out of the tree",
        marks=pytest.mark.skipif(sys.platform == "win32", reason="symlinks"),
    ),
    pytest.param(
        "symlink in the tree",
        marks=pytest.mark.skipif(sys.platform == "win32", reason="symlinks"),
    ),
    pytest.param(
        "fifo", marks=pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs")
    ),
    pytest.param(
        "hard link", marks=pytest.mark.skipif(not hasattr(os, "link"), reason="links")
    ),
]


@pytest.mark.parametrize("kind", IGNORE_FILE_KINDS)
@pytest.mark.unit
def test_a_gitleaksignore_that_is_not_a_regular_file_stops_the_scan(tmp_path, kind):
    """gitleaks opens the file by name, follows a symlink, blocks on a FIFO, and
    logs every line it cannot parse; ASH refuses before gitleaks runs."""
    scanner = _refused_ignore_file(tmp_path, kind)
    source = Path(scanner.context.source_dir)
    with pytest.raises(ScannerError) as excinfo:
        scanner._execute_scan(source, "source", [])
    message = str(excinfo.value)
    assert ".gitleaksignore" in message and "gitleaks is not run" in message
    assert MARKER not in message


@pytest.mark.parametrize("kind", IGNORE_FILE_KINDS)
@pytest.mark.unit
def test_the_re_scan_reads_no_gitleaksignore_that_is_not_a_regular_file(
    tmp_path, monkeypatch, kind
):
    """Swapped in after gitleaks ran: refused rather than read."""
    scanner = _refused_ignore_file(tmp_path, kind)
    source = Path(scanner.context.source_dir)
    monkeypatch.setattr(
        scanner, "_run_subprocess", lambda *a, **k: pytest.fail("re-scan ran")
    )
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    args = scanner._build_arguments(source, results_file)
    with pytest.raises(ScannerError) as excinfo:
        scanner._add_back_gitleaksignore_drops(_report(), source, args, results_file)
    assert MARKER not in str(excinfo.value)


@pytest.mark.unit
def test_a_regular_gitleaksignore_lets_the_scan_run(tmp_path):
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    final_args, _, _ = scanner._execute_scan(source, "source", [])
    assert final_args[-2:] == ["--", "."]


@pytest.mark.unit
def test_a_failure_names_gitleaks_log_but_does_not_quote_it(tmp_path):
    """gitleaks' stderr can repeat lines of the tree's .gitleaksignore."""
    scanner = _scanner(tmp_path)
    results_file = scanner.results_dir / "source" / "gitleaks.sarif"
    results_file.parent.mkdir(parents=True)
    log = results_file.parent / "GitleaksScanner.stderr.log"
    log.write_text(f"6:52PM WRN Invalid .gitleaksignore entry fingerprint={MARKER}\n")
    scanner.exit_code = 1
    message = scanner._describe_scan_failure(
        ScannerError("gitleaks exited 1"), results_file
    )
    assert MARKER not in message
    assert log.as_posix() in message
    assert "gitleaks exited 1" in message


@pytest.mark.unit
def test_gitleaks_stderr_is_not_kept_as_the_scanners_errors(tmp_path):
    """A timed-out run returns its stderr, which the executor copies into the
    scan's results."""
    scanner = _scanner(tmp_path)
    scanner._process_command_response(
        {"returncode": 124, "timed_out": True, "stderr": f"fingerprint={MARKER}"}
    )
    assert scanner.errors == []
    assert scanner.exit_code == 124


@pytest.mark.unit
def test_a_directory_named_gitleaksignore_is_not_a_reason_to_stop(tmp_path):
    """gitleaks reads the name only when it is not a directory."""
    scanner = _refused_ignore_file(tmp_path, "directory")
    source = Path(scanner.context.source_dir)
    final_args, _, _ = scanner._execute_scan(source, "source", [])
    assert final_args[-2:] == ["--", "."]
    assert scanner._gitleaksignore_files(source) == []


# --------------------------------------------------------------------------- #
# .gitleaksignore is parsed as gitleaks 8.30.1 parses it
# --------------------------------------------------------------------------- #

#: Characters Python's str.splitlines() or str.strip() treat as line breaks or
#: whitespace and gitleaks does not: it splits lines on "\n" alone
#: (bufio.ScanLines) and trims with Go's strings.TrimSpace.
NOT_A_BREAK_TO_GITLEAKS = ["\v", "\f", "\r", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]


def _copied_for(tmp_path, monkeypatch, entries: bytes, *files: bytes) -> list:
    """The files the re-scan copies for an ignore file holding ``entries``."""
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    for name in files:
        path = os.path.join(os.fsencode(source), name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(b"x")
    with open(os.path.join(os.fsencode(source), b".gitleaksignore"), "wb") as handle:
        handle.write(entries)
    _add_back(scanner, source, _report(), tmp_path)
    return [os.fsencode(name) for call in calls for name in call["files"]]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
@pytest.mark.parametrize("char", NOT_A_BREAK_TO_GITLEAKS, ids=repr)
@pytest.mark.unit
def test_a_name_with_a_character_python_breaks_lines_on_is_one_entry(
    tmp_path, monkeypatch, char
):
    name = f"app/a{char}b.py".encode()
    assert _copied_for(tmp_path, monkeypatch, name + b":github-pat:1\n", name) == [name]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
@pytest.mark.parametrize("char", ["\x1c", "\x1d", "\x1e", "\x1f"], ids=repr)
@pytest.mark.unit
def test_a_leading_character_go_does_not_trim_stays_in_the_name(
    tmp_path, monkeypatch, char
):
    """Python's strip() removes these; Go's TrimSpace does not."""
    name = f"{char}app.py".encode()
    assert _copied_for(tmp_path, monkeypatch, name + b":github-pat:1\n", name) == [name]


@pytest.mark.unit
def test_a_backslash_in_the_file_part_is_a_slash(tmp_path, monkeypatch):
    """gitleaks replaces "\\" with "/" in a fingerprint's file before matching."""
    assert _copied_for(
        tmp_path, monkeypatch, b"app\\one.py:github-pat:1\n", b"app/one.py"
    ) == [b"app/one.py"]


@pytest.mark.skipif(sys.platform == "win32", reason="':' in a file name")
@pytest.mark.unit
def test_a_four_part_entry_is_normalized_where_gitleaks_normalizes_it(
    tmp_path, monkeypatch
):
    """Four parts read as commit:file:rule:line, so gitleaks replaces the
    backslashes in the second; matched as a dir fingerprint, the file is a:b/c.py."""
    assert _copied_for(
        tmp_path, monkeypatch, b"a:b\\c.py:github-pat:1\n", b"a:b/c.py"
    ) == [b"a:b/c.py"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
@pytest.mark.unit
def test_a_name_that_is_not_utf_8_is_kept_byte_for_byte(tmp_path, monkeypatch):
    name = b"app/\xff\xfe.py"
    # APFS (the macOS runners) refuses a name that is not valid UTF-8 with
    # EILSEQ, so the fixture cannot exist there; the property is about trees
    # on filesystems that do hold such names.
    probe_dir = tmp_path / "fs-probe"
    probe_dir.mkdir()
    try:
        with open(os.path.join(os.fsencode(probe_dir), b"\xff\xfe"), "wb"):
            pass
    except OSError as error:
        if error.errno in (errno.EILSEQ, errno.EINVAL):
            pytest.skip("this filesystem refuses a non-UTF-8 file name")
        raise
    assert _copied_for(tmp_path, monkeypatch, name + b":github-pat:1\n", name) == [name]


@pytest.mark.unit
def test_gitleaks_stops_reading_at_a_line_it_cannot_buffer(tmp_path, monkeypatch):
    """bufio.Scanner's 64 KiB token limit ends gitleaks' read, unreported, so no
    entry after such a line hides anything."""
    entries = (
        b"app/before.py:github-pat:1\n"
        + b"#" * 65536
        + b"\n"
        + b"app/after.py:github-pat:1\n"
    )
    assert _copied_for(
        tmp_path, monkeypatch, entries, b"app/before.py", b"app/after.py"
    ) == [b"app/before.py"]


@pytest.mark.unit
def test_a_line_gitleaks_can_buffer_is_read(tmp_path, monkeypatch):
    """The control: 65535 bytes and its newline fit."""
    entries = b"#" * 65535 + b"\n" + b"app/after.py:github-pat:1\n"
    assert _copied_for(tmp_path, monkeypatch, entries, b"app/after.py") == [
        b"app/after.py"
    ]


# --------------------------------------------------------------------------- #
# The re-scan is bounded, and what it skips is reported as not evaluated
# --------------------------------------------------------------------------- #


def _capped(tmp_path, monkeypatch, names: list, limit: int):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    monkeypatch.setattr(module, "MAX_RESCAN_FILES", limit)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    for name in names:
        _write(source, name)
    (source / ".gitleaksignore").write_text(
        "".join(f"{name}:github-pat:1\n" for name in names)
    )
    return scanner, calls, source


@pytest.mark.unit
def test_the_re_scan_copies_at_most_the_limit_and_says_how_many_it_skipped(
    tmp_path, monkeypatch, caplog
):
    names = [f"app/f{index}.py" for index in range(5)]
    scanner, calls, source = _capped(tmp_path, monkeypatch, names, limit=2)
    with caplog.at_level("WARNING"):
        _add_back(scanner, source, _report(), tmp_path)
    assert [call["files"] for call in calls] == [["app/f0.py", "app/f1.py"]]
    assert "3 file(s) the scanned tree's .gitleaksignore names were not" in caplog.text
    for name in names:  # the names are the tree's; the warning gives a count
        assert name not in caplog.text


@pytest.mark.unit
def test_files_past_the_limit_are_reported_as_not_evaluated(tmp_path, monkeypatch):
    """An error-level run notification: the scan gate reads it as incomplete."""
    from types import SimpleNamespace

    from automated_security_helper.interactions.run_ash_scan import unevaluated_rules

    names = [f"app/f{index}.py" for index in range(3)]
    scanner, _, source = _capped(tmp_path, monkeypatch, names, limit=1)
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    raw = _report()
    scanner._add_back_gitleaksignore_drops(
        raw, source, scanner._build_arguments(source, results_file), results_file
    )
    report = SarifReport.model_validate(raw)
    scanner._inject_invocation(report, ["gitleaks", "dir"], source)
    report = scanner._post_process_sarif(report, [], source)

    [notification] = report.runs[0].invocations[0].toolExecutionNotifications
    assert getattr(notification.level, "value", notification.level) == "error"
    gap = unevaluated_rules(SimpleNamespace(sarif=report))
    assert len(gap) == 1 and "2 file(s)" in gap[0] and "gitleaks" in gap[0]
    # Reported once: the next target's report does not inherit it.
    again = scanner._post_process_sarif(
        SarifReport.model_validate(_report()), [], source
    )
    assert unevaluated_rules(SimpleNamespace(sarif=again)) == []


@pytest.mark.unit
def test_within_the_limit_nothing_is_reported_as_not_evaluated(tmp_path, monkeypatch):
    names = [f"app/f{index}.py" for index in range(2)]
    scanner, calls, source = _capped(tmp_path, monkeypatch, names, limit=2)
    raw = _report()
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    scanner._add_back_gitleaksignore_drops(
        raw, source, scanner._build_arguments(source, results_file), results_file
    )
    report = SarifReport.model_validate(raw)
    scanner._inject_invocation(report, ["gitleaks", "dir"], source)
    report = scanner._post_process_sarif(report, [], source)
    assert not report.runs[0].invocations[0].toolExecutionNotifications
    assert [call["files"] for call in calls] == [names]


def _another_thread_reads_the_clock() -> None:
    """Read ``time.monotonic`` from another thread, as a thread an earlier test
    left running in this worker can while the clock is replaced."""
    thread = threading.Thread(target=lambda: [time.monotonic() for _ in range(4)])
    thread.start()
    thread.join()


class _Clock:
    """A stand-in for ``_monotonic`` that moves only when the test moves it.

    Time passes in the fake gitleaks run, not per read: the re-scan reads the
    clock when it sets the deadline, before each copy and before each run, and
    a scripted sequence of readings pinned that count, so a check added to the
    copy step read the sequence ahead and timed the first run with a later
    reading.
    """

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _timed_runs(scanner, clock: _Clock, monkeypatch, seconds_per_run: float) -> list:
    """Record each run's timeout and let ``seconds_per_run`` pass during it."""
    timeouts = []
    fake = scanner._run_subprocess

    def timed(command, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        clock.now += seconds_per_run
        return fake(command, **kwargs)

    monkeypatch.setattr(scanner, "_run_subprocess", timed)
    return timeouts


@pytest.mark.unit
def test_the_re_scan_runs_share_one_deadline(tmp_path, monkeypatch):
    """Each run is given what is left of one scan_timeout, not a fresh one."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    clock = _Clock(100.0)
    monkeypatch.setattr(module, "_monotonic", clock)
    _another_thread_reads_the_clock()
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {}, scan_timeout=50)
    timeouts = _timed_runs(scanner, clock, monkeypatch, seconds_per_run=30.0)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text(
        ".gitleaksignore:github-pat:1\napp/x.py:github-pat:1\n"
    )
    _add_back(scanner, source, _report(), tmp_path)
    assert timeouts == [50.0, 20.0]


@pytest.mark.unit
def test_a_re_scan_with_no_time_left_fails_the_scan(tmp_path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    clock = _Clock(100.0)
    monkeypatch.setattr(module, "_monotonic", clock)
    _another_thread_reads_the_clock()
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {}, scan_timeout=50)
    _timed_runs(scanner, clock, monkeypatch, seconds_per_run=60.0)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text(
        ".gitleaksignore:github-pat:1\napp/x.py:github-pat:1\n"
    )
    with pytest.raises(ScannerError, match="timed out"):
        _add_back(scanner, source, _report(), tmp_path)
    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# Each target is judged by its own exit code
# --------------------------------------------------------------------------- #


def _run_targets(tmp_path, monkeypatch, codes: list) -> list:
    """Scan the source and then the converted target with one scanner instance,
    gitleaks exiting with ``codes`` in turn. Only the process launch is replaced,
    so the base class's exit-code accumulation runs as it does in a scan."""
    from automated_security_helper.utils import subprocess_utils

    scanner = _scanner(tmp_path)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    work = Path(scanner.context.work_dir)
    _write(work, "archive/x.py")
    remaining = iter(codes)

    def launch(command, **kwargs):
        # A report whatever the code, so only the exit code decides the outcome.
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(json.dumps(_report()))
        return {"returncode": next(remaining)}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", launch)
    outcomes = []
    for target, kind in ((source, "source"), (work, "converted")):
        try:
            scanner.scan(target=target, target_type=kind)
            outcomes.append("ok")
        except ScannerError:
            outcomes.append("error")
    return outcomes


@pytest.mark.unit
def test_a_failed_source_run_does_not_fail_a_clean_converted_one(tmp_path, monkeypatch):
    assert _run_targets(tmp_path, monkeypatch, [1, 0]) == ["error", "ok"]


@pytest.mark.unit
def test_leaks_in_the_source_do_not_hide_a_failed_converted_run(tmp_path, monkeypatch):
    """The worst code across runs was 2, which is accepted, so exit 1 read as leaks."""
    assert _run_targets(tmp_path, monkeypatch, [LEAKS_EXIT_CODE, 1]) == ["ok", "error"]


@pytest.mark.unit
def test_a_copy_the_re_scan_cannot_write_fails_the_scan(tmp_path, monkeypatch):
    """Skipping it would leave what the tree's file hides there unreported."""
    import errno

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    def full_disk(source, destination):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(module, "_write_private_copy", full_disk)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\nmissing.py:r:1\n")
    with pytest.raises(ScannerError, match="No space left on device"):
        _add_back(scanner, source, _report(), tmp_path)
    assert calls == []


@pytest.mark.unit
def test_a_copies_directory_that_cannot_be_made_fails_the_scan(tmp_path, monkeypatch):
    """The re-scan's directory outside the tree is ASH's to make; without it the
    files the ignore file hides would not be re-scanned."""
    import errno

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        gitleaks_scanner as module,
    )

    real = module.empty_tool_directory

    def no_room_for_copies(name, **kwargs):
        if name == "gitleaksignore-rescan":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(name, **kwargs)

    monkeypatch.setattr(module, "empty_tool_directory", no_room_for_copies)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    with pytest.raises(ScannerError, match="No space left on device"):
        _add_back(scanner, source, _report(), tmp_path)
    assert calls == []


# --------------------------------------------------------------------------- #
# An operator path inside the tree that links out of it
# --------------------------------------------------------------------------- #


def _linked_out(tmp_path: Path, shape: str) -> str:
    """An in-tree path to a file outside the tree, through a link of ``shape``."""
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_text(f"{MARKER}\n")
    if shape == "file":
        (source / "named.toml").symlink_to(outside / "notes.txt")
        return "named.toml"
    if shape == "directory":
        (source / "linked").symlink_to(outside, target_is_directory=True)
        return "linked/notes.txt"
    (source / "deep").mkdir()
    (source / "deep" / "up").symlink_to(outside, target_is_directory=True)
    return "deep/up/notes.txt"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
@pytest.mark.parametrize("shape", ["file", "directory", "nested directory"])
@pytest.mark.unit
def test_an_operator_path_in_the_tree_cannot_link_out_of_it(tmp_path, option, shape):
    """The scanned repository decides what is at a path inside it; a link there
    could hand gitleaks any file the scan can read."""
    value = _linked_out(tmp_path, shape)
    scanner = _scanner(tmp_path, operator=True, **{option: value})
    with pytest.raises(ScannerError) as excinfo:
        scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    message = str(excinfo.value)
    assert f"scanners.gitleaks.options.{option}" in message
    assert "symbolic link" in message and MARKER not in message


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
@pytest.mark.unit
def test_a_link_inside_the_tree_to_a_file_inside_it_is_still_honored(tmp_path, option):
    scanner = _scanner(tmp_path, operator=True, **{option: "named.json"})
    source = Path(scanner.context.source_dir)
    _write(source, "real/file.json", "[]")
    (source / "named.json").symlink_to(source / "real" / "file.json")
    args = scanner._build_arguments(source, tmp_path / "o.sarif")
    flag = "--config=" if option == "config_file" else "--baseline-path="
    assert any(a.startswith(flag) and a.endswith("real/file.json") for a in args)


@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
@pytest.mark.parametrize("written", ["relative", "absolute"])
@pytest.mark.unit
def test_an_operator_path_that_leaves_the_tree_by_dot_dot_is_honored(
    tmp_path, option, written
):
    """``../shared.toml`` from the source directory names a file next to the tree.
    No link in the tree is followed, so the tree did not choose it."""
    source = tmp_path / "src"
    value = "../shared.toml" if written == "relative" else f"{source}/../shared.toml"
    scanner = _scanner(tmp_path, operator=True, **{option: value})
    (tmp_path / "shared.toml").write_text("[]")
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    flag = "--config=" if option == "config_file" else "--baseline-path="
    assert f"{flag}{(tmp_path / 'shared.toml').resolve().as_posix()}" in args


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
@pytest.mark.unit
def test_an_operator_path_outside_the_tree_may_be_a_link(tmp_path):
    """Outside the tree the operator controls both the path and the link."""
    scanner = _scanner(tmp_path, operator=True, baseline_path=str(tmp_path / "b.json"))
    (tmp_path / "real.json").write_text("[]")
    (tmp_path / "b.json").symlink_to(tmp_path / "real.json")
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert f"--baseline-path={(tmp_path / 'real.json').resolve().as_posix()}" in args
