"""Behavior tests for :class:`DetectSecretsScanner`.

Unlike the other scanners in this batch, detect-secrets is a Python dependency
and is importable here, so ``validate_plugin_dependencies()`` always returns
True and there is no subprocess to patch. These tests therefore drive the real
scanner over real files and assert on the findings it genuinely produces --
including one end-to-end scan that must turn a planted credential into a SARIF
result. If the SecretsCollection wiring or the result-building loop broke, that
test fails rather than reporting a clean scan.

The planted credential is assembled at runtime from fragments so that no
contiguous key-shaped literal exists in this file: ASH self-scans its own repo
with this very scanner, and a literal here would be reported as a finding
against the repo.

The baseline-discovery paths (".secrets.baseline" and ".ash/.secrets.baseline")
are resolved relative to the process working directory rather than to
source_dir, so every test that exercises discovery chdirs first. That is a real
property of the code, not a test artifact.
"""

import json
import logging
import multiprocessing
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    detect_secrets_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
    DetectSecretsScanSettingsPluginsUsed,
)

# Assembled at runtime so this file contains no contiguous key-shaped literal.
# The value is AWS's own documentation placeholder. FLY002 is suppressed on
# purpose: collapsing this into one string is exactly what must not happen, or
# ASH's own detect-secrets self-scan reports this file as a finding.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
EXCLUDE_FILTER_PATH = "detect_secrets.filters.regex.should_exclude_file"


def source_with_planted_key(directory, name="settings.py"):
    path = Path(directory) / name
    path.write_text(f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8")
    return path


def baseline_document(plugins=None, filters=None):
    doc = {
        "version": "1.5.0",
        "plugins_used": plugins if plugins is not None else [],
        "filters_used": filters if filters is not None else [],
        "results": {},
        "generated_at": "2026-01-01T00:00:00Z",
    }
    return doc


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )


# ---------------------------------------------------------------------------
# Construction and dependency validation
# ---------------------------------------------------------------------------


def test_scanner_metadata_is_wired(scanner):
    assert scanner.command == "detect-secrets"
    assert scanner.tool_type == ScannerToolType.SECRETS
    assert scanner.tool_version, "the installed detect-secrets version must be recorded"


def test_dependencies_are_always_satisfied_because_the_import_succeeded(scanner):
    """detect-secrets is used in-process, so the import is the only requirement."""
    assert scanner.validate_plugin_dependencies() is True


def test_default_config_enables_every_detect_secrets_plugin(scanner):
    """With no baseline, all detect-secrets plugins are configured."""
    plugins = scanner.config.options.scan_settings.plugins_used

    assert len(plugins) > 10, (
        f"expected the full detect-secrets plugin set, got {len(plugins)}"
    )
    names = {p.name for p in plugins}
    assert "AWSKeyDetector" in names
    assert "Base64HighEntropyString" in names


def test_execute_scan_stub_raises_not_implemented(scanner):
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Baseline discovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "baseline_name", [".secrets.baseline", ".ash/.secrets.baseline"]
)
def test_baseline_is_discovered_in_the_working_directory(
    plugin_context, tmp_path, monkeypatch, baseline_name
):
    """Both default baseline locations are found, relative to the cwd."""
    monkeypatch.chdir(tmp_path)
    baseline = tmp_path / baseline_name
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(json.dumps(baseline_document()), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert Path(scanner.config.options.baseline_file) == Path(baseline_name)


def test_explicitly_configured_baseline_wins_over_the_defaults(
    plugin_context, tmp_path, monkeypatch
):
    """A configured baseline_file is checked before the conventional names."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(baseline_document()), encoding="utf-8"
    )
    chosen = tmp_path / "custom.baseline"
    chosen.write_text(json.dumps(baseline_document()), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=chosen)
        ),
    )

    assert Path(scanner.config.options.baseline_file) == chosen


def test_no_baseline_anywhere_leaves_baseline_file_unset(
    plugin_context, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert scanner.config.options.baseline_file is None


# ---------------------------------------------------------------------------
# Baseline settings propagation
# ---------------------------------------------------------------------------


def test_baseline_plugins_and_filters_are_loaded_into_scan_settings(
    plugin_context, tmp_path, monkeypatch
):
    """SecretsCollection.load_from_baseline only loads results, not settings.

    So the scanner has to propagate plugins_used and filters_used itself, or the
    baseline's configuration silently fails to apply during scanning.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(
            baseline_document(
                plugins=[{"name": "AWSKeyDetector"}, {"name": "JwtTokenDetector"}],
                filters=[{"path": EXCLUDE_FILTER_PATH, "pattern": ["^tests/"]}],
            )
        ),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    plugin_names = [p.name for p in scanner.config.options.scan_settings.plugins_used]
    assert plugin_names == ["AWSKeyDetector", "JwtTokenDetector"], (
        f"baseline plugins were not propagated; got {plugin_names}"
    )
    filter_paths = [f.path for f in scanner.config.options.scan_settings.filters_used]
    assert filter_paths == [EXCLUDE_FILTER_PATH]


def test_explicit_scan_settings_are_not_overwritten_by_the_baseline(
    plugin_context, tmp_path, monkeypatch
):
    """A user-provided scan_settings takes precedence over the baseline's."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(baseline_document(plugins=[{"name": "AWSKeyDetector"}])),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(
                    version="1.5.0",
                    plugins_used=[
                        DetectSecretsScanSettingsPluginsUsed(name="JwtTokenDetector")
                    ],
                )
            )
        ),
    )

    plugin_names = [p.name for p in scanner.config.options.scan_settings.plugins_used]
    assert plugin_names == ["JwtTokenDetector"], (
        f"the baseline overwrote explicit scan_settings; got {plugin_names}"
    )


def test_baseline_without_plugins_or_filters_falls_back_to_all_plugins(
    plugin_context, tmp_path, monkeypatch
):
    """An empty baseline still leaves the scanner with a usable plugin set."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps({"version": "1.5.0", "results": {}}), encoding="utf-8"
    )

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert len(scanner.config.options.scan_settings.plugins_used) > 10


def test_unreadable_baseline_warns_and_falls_back_to_defaults(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """A corrupt baseline must not take the scanner down with it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=plugin_context, config=DetectSecretsScannerConfig()
        )

    assert any(
        "Failed to read baseline file settings" in record.message
        for record in caplog.records
    ), f"expected a baseline warning; got {[r.message for r in caplog.records]}"
    # The fallback still configures the full plugin set, so scanning still works.
    assert len(scanner.config.options.scan_settings.plugins_used) > 10


def test_missing_configured_baseline_warns_and_falls_back(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """A configured baseline that is not on disk is reported, not fatal."""
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=plugin_context,
            config=DetectSecretsScannerConfig(
                options=DetectSecretsScannerConfigOptions(
                    baseline_file=tmp_path / "absent.baseline"
                )
            ),
        )

    assert any(
        "Failed to read baseline file settings" in record.message
        for record in caplog.records
    )
    assert len(scanner.config.options.scan_settings.plugins_used) > 10


# ---------------------------------------------------------------------------
# Exclude-pattern helpers
# ---------------------------------------------------------------------------


def test_exclude_patterns_are_compiled_from_a_pattern_list():
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {
            "filters_used": [
                {"path": EXCLUDE_FILTER_PATH, "pattern": [r"^tests/", r"\.lock$"]}
            ]
        }
    )

    assert len(patterns) == 2
    assert patterns[0].search("tests/test_thing.py")
    assert patterns[1].search("uv.lock")
    assert not patterns[0].search("src/app.py")


def test_a_single_string_pattern_is_accepted():
    """detect-secrets baselines allow `pattern` to be a bare string."""
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {"filters_used": [{"path": EXCLUDE_FILTER_PATH, "pattern": r"^docs/"}]}
    )

    assert len(patterns) == 1
    assert patterns[0].search("docs/index.md")


def test_filters_other_than_should_exclude_file_are_ignored():
    """Only the file-exclusion filter contributes patterns."""
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
                {
                    "path": "detect_secrets.filters.regex.should_exclude_secret",
                    "pattern": [r"^ignored$"],
                },
            ]
        }
    )

    assert patterns == []


def test_no_filters_used_yields_no_patterns():
    assert DetectSecretsScanner._get_baseline_exclude_patterns({}) == []


def test_an_invalid_exclude_pattern_is_warned_about_and_skipped(caplog):
    """One bad regex must not discard the valid patterns beside it."""
    with caplog.at_level(logging.WARNING):
        patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
            {
                "filters_used": [
                    {"path": EXCLUDE_FILTER_PATH, "pattern": ["[unclosed", r"^ok/"]}
                ]
            }
        )

    assert len(patterns) == 1, "the valid pattern should survive"
    assert patterns[0].search("ok/file.py")
    assert any("Invalid exclude pattern" in r.message for r in caplog.records)


def test_file_exclusions_filter_the_matching_paths():
    import re

    files = ["src/app.py", "tests/test_app.py", "docs/index.md"]

    kept = DetectSecretsScanner._apply_file_exclusions(files, [re.compile(r"^tests/")])

    assert kept == ["src/app.py", "docs/index.md"]


def test_no_exclude_patterns_returns_the_list_unchanged():
    files = ["src/app.py", "tests/test_app.py"]

    assert DetectSecretsScanner._apply_file_exclusions(files, []) == files


# ---------------------------------------------------------------------------
# Multiprocessing start method
# ---------------------------------------------------------------------------


def test_fork_start_method_is_requested_on_linux(monkeypatch):
    """detect-secrets uses multiprocessing.Pool; spawn recurses without a guard."""
    calls = []
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "linux")
    monkeypatch.setattr(
        multiprocessing,
        "set_start_method",
        lambda method, force=False: calls.append((method, force)),
    )

    DetectSecretsScanner._ensure_fork_multiprocessing()

    assert calls == [("fork", True)]


def test_an_already_set_start_method_is_tolerated(monkeypatch):
    """A RuntimeError from set_start_method means it is already configured."""
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "linux")

    def _raise(method, force=False):
        raise RuntimeError("context has already been set")

    monkeypatch.setattr(multiprocessing, "set_start_method", _raise)

    DetectSecretsScanner._ensure_fork_multiprocessing()


def test_non_linux_platforms_are_left_alone(monkeypatch):
    calls = []
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "darwin")
    monkeypatch.setattr(
        multiprocessing,
        "set_start_method",
        lambda method, force=False: calls.append(method),
    )

    DetectSecretsScanner._ensure_fork_multiprocessing()

    assert calls == []


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


def test_empty_target_returns_an_empty_report(scanner):
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_pre_scan_failure_returns_false(scanner):
    source_with_planted_key(scanner.context.work_dir)

    with patch.object(
        DetectSecretsScanner, "_pre_scan", autospec=True, return_value=False
    ):
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False


def test_unsatisfied_dependencies_return_false(scanner):
    """The independent post-_pre_scan dependency guard."""
    source_with_planted_key(scanner.context.work_dir)

    with patch.object(
        DetectSecretsScanner, "_pre_scan", autospec=True, return_value=True
    ):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False


def test_a_target_of_only_lockfiles_has_nothing_to_scan(scanner):
    """Lockfiles are excluded by name, so a lockfile-only tree is empty."""
    (scanner.context.work_dir / "package-lock.json").write_text(
        json.dumps({"name": "placeholder", "lockfileVersion": 3}), encoding="utf-8"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any("no scannable files found" in err for err in scanner.errors)


# ---------------------------------------------------------------------------
# End-to-end scanning
# ---------------------------------------------------------------------------


def test_a_planted_credential_becomes_a_sarif_result(scanner):
    """A real detect-secrets scan turns a planted key into a SARIF finding.

    This is the anti-"clean scan" assertion for this module, and it runs the
    genuine scanner rather than a double: if the SecretsCollection wiring or the
    result-building loop regressed, the report would come back empty and look
    like a passing scan.
    """
    planted = source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results = report.runs[0].results
    assert len(results) == 1, (
        f"expected exactly one finding for the planted key in {planted.name}, "
        f"got {len(results)}"
    )
    finding = results[0]
    assert finding.ruleId == "SECRET-AWS-ACCESS-KEY", (
        f"rule id should be derived from the detect-secrets type; got {finding.ruleId}"
    )
    # Level/Kind serialize as their string values on this model.
    assert str(getattr(finding.level, "value", finding.level)) == "error"
    assert str(getattr(finding.kind, "value", finding.kind)) == "fail"
    assert "AWS Access Key" in finding.message.root.text
    assert planted.name in finding.message.root.text

    location = finding.locations[0].physicalLocation.root
    assert location.region.startLine == 1
    assert location.region.endLine == 1
    assert planted.name in str(location.artifactLocation.uri)
    assert "AWS Access Key" in location.region.snippet.text

    tags = finding.properties.tags
    assert "detect-secrets" in tags
    assert "secret" in tags
    assert "tool_name::detect-secrets" in tags


def test_the_planted_secret_value_is_not_echoed_into_the_finding(scanner):
    """The finding names the secret's type and location, not its value.

    Asserted alongside the positive checks in the test above, which prove the
    message is populated at all -- an empty message would satisfy an
    absence-only assertion for the wrong reason.
    """
    source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    finding = report.runs[0].results[0]
    assert finding.message.root.text, "the message must not be empty"
    serialized = report.model_dump_json()
    assert PLANTED_KEY not in serialized, (
        "the raw credential must not be copied into the report"
    )


def test_a_clean_target_produces_no_findings_and_exit_code_zero(scanner):
    """A file with no secrets yields an empty run and resets the exit code."""
    (scanner.context.work_dir / "plain.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    scanner.exit_code = 1

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert scanner.exit_code == 0, (
        "a scan that found nothing must not leave a non-zero exit code behind"
    )


def test_findings_are_written_to_the_results_file(scanner):
    planted = source_with_planted_key(scanner.context.work_dir)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results_file = Path(scanner.results_dir) / "converted" / "results_sarif.sarif"
    assert results_file.is_file(), f"{results_file} was not written"
    written = json.loads(results_file.read_text(encoding="utf-8"))
    rule_ids = [r["ruleId"] for r in written["runs"][0]["results"]]
    assert rule_ids == ["SECRET-AWS-ACCESS-KEY"], (
        f"the persisted report must carry the finding; got {written}"
    )
    assert planted.name in json.dumps(written)


def test_report_invocation_describes_the_ash_run(scanner):
    source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == "ash-detect-secrets-scanner"
    assert "--target" in invocation.arguments
    assert invocation.executionSuccessful is True
    assert report.runs[0].tool.driver.organization == "Yelp"


def test_baseline_results_are_loaded_for_a_source_scan(scanner, tmp_path):
    """A source scan seeds the collection from the baseline before scanning.

    Findings already recorded in the baseline are known-and-accepted, so the
    baseline has to be loaded or every audited secret reappears as new.
    """
    planted = source_with_planted_key(scanner.context.source_dir)
    baseline = tmp_path / "custom.baseline"
    baseline.write_text(
        json.dumps(baseline_document(plugins=[{"name": "AWSKeyDetector"}])),
        encoding="utf-8",
    )
    scanner.config.options.baseline_file = baseline

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    # The planted key is not in the baseline's results, so it is still reported.
    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]
    assert planted.name in report.runs[0].results[0].message.root.text


def test_excluded_files_are_never_handed_to_detect_secrets(scanner, monkeypatch):
    """The exclude patterns are applied to the scan set, not only to findings.

    This is the assertion that actually pins the pre-filter. detect-secrets
    honors should_exclude_file internally too, so a test that only checks the
    finding disappeared passes even when the pre-filter is deleted -- the
    library's own filter catches it downstream. The pre-filter exists to avoid
    the file I/O and entropy work in the first place, and the only place that is
    observable is the argument list handed to scan_files.

    Both directions are asserted: the excluded file is absent and the kept file
    is present, so the test cannot pass by handing over nothing at all.

    The pattern is anchored on a full filename because it is matched against the
    *absolute* path, which includes pytest's per-test tmp directory -- and that
    directory is named after the test. A loose pattern like "excluded_" matches
    the directory name of any test whose own name contains it, silently
    excluding every file and emptying the scan set.
    """
    from detect_secrets import SecretsCollection

    captured = []
    real_scan_files = SecretsCollection.scan_files

    def _capture(self, *filenames):
        captured.extend(filenames)
        return real_scan_files(self, *filenames)

    monkeypatch.setattr(SecretsCollection, "scan_files", _capture)

    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    source_with_planted_key(scanner.context.work_dir, name="keepme_settings.py")
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH, pattern=[r"skipme_settings\.py$"]
        )
    ]

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert captured, "no files were handed to detect-secrets at all"
    assert not any("skipme_settings.py" in f for f in captured), (
        f"the excluded file was still handed to detect-secrets: {captured}"
    )
    assert any("keepme_settings.py" in f for f in captured), (
        f"the kept file should still be scanned: {captured}"
    )


def test_baseline_exclude_patterns_remove_files_before_scanning(scanner, caplog):
    """A planted key inside an excluded file is not reported.

    End-to-end companion to the test above. Note that this outcome is also
    guaranteed by detect-secrets' own should_exclude_file filter, so it does not
    on its own prove the scanner pre-filtered anything.
    """
    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH, pattern=[r"skipme_settings\.py$"]
        )
    ]

    with caplog.at_level(logging.DEBUG):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == [], (
        "the planted key sat in an excluded file and must not be reported"
    )


def test_a_non_matching_exclude_pattern_leaves_the_finding_in_place(scanner):
    """Control for the exclusion test: the filter must be what silenced it."""
    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH, pattern=[r"nothing_matches_this\.py$"]
        )
    ]

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]


def test_global_ignore_paths_exclude_files_from_the_scan(scanner):
    """A globally ignored path is dropped from the scan set."""
    source_with_planted_key(scanner.context.work_dir, name="generated_settings.py")

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/generated_*.py", reason="generated code")
        ],
    )

    assert report.runs[0].results == [], (
        "the planted key was in a globally ignored file and must not be reported"
    )


def test_a_non_matching_global_ignore_leaves_the_finding_in_place(scanner):
    """Control for the global-ignore test above."""
    source_with_planted_key(scanner.context.work_dir, name="generated_settings.py")

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/unrelated_*.py", reason="not this one")
        ],
    )

    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]


def test_multiple_secrets_across_files_all_report(scanner, monkeypatch):
    """Every file with a finding contributes to the results list.

    This is the only test here that hands detect-secrets more than one file, so
    it is the only one that takes SecretsCollection.scan_files' multiprocessing
    branch. That branch keys each finding by
    ``os.path.relpath(secret.filename, self.root)``, and root defaults to "",
    which resolves to the process working directory. The single-file branch
    keys by the path it was handed and computes no relative path at all, which
    is why the rest of this module is indifferent to the cwd.

    Two drives have no relative path between them on Windows, so that relpath
    raises ValueError whenever the scanned tree and the cwd sit on different
    drives -- which is the normal arrangement on hosted Windows runners, where
    the temp directory and the checkout are on different drives. Chdir'ing into
    the scan target puts both on one drive by construction and leaves the keys
    as bare filenames on every platform.
    """
    source_with_planted_key(scanner.context.work_dir, name="first.py")
    source_with_planted_key(scanner.context.work_dir, name="second.py")
    monkeypatch.chdir(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(report.runs[0].results) == 2
    reported_files = " ".join(r.message.root.text for r in report.runs[0].results)
    assert "first.py" in reported_files
    assert "second.py" in reported_files


def test_an_unexpected_failure_is_wrapped_in_scanner_error(scanner, monkeypatch):
    """Errors inside the scan body surface as ScannerError."""
    source_with_planted_key(scanner.context.work_dir)

    def _boom(*args, **kwargs):
        raise RuntimeError("transient settings failed")

    monkeypatch.setattr(detect_secrets_scanner, "transient_settings", _boom)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert "DetectSecretsScanner failed" in str(excinfo.value)
    assert "transient settings failed" in str(excinfo.value)
