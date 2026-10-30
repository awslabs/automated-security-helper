"""Behavior tests for :class:`SnykCodeScanner`.

The snyk CLI is a Node tool and is not installed here, so
``validate_plugin_dependencies()`` returns False and ``scan()`` returns before
resolving a single argument -- the module measured 31% covered, with even
``model_post_init`` unexecuted.

Two seams are patched and nothing else: ``find_executable`` (so the binary
reads as present without installing it) and ``_run_subprocess`` (autospec, so a
call with the wrong signature fails the test). The subprocess double writes its
SARIF to the path it is *told* to write to, parsed out of the ``command`` it
receives -- so a change to the ``--sarif-file-output=`` argument breaks the
tests rather than quietly producing a scan that finds nothing.
"""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    SnykCodeScannerConfigOptions,
)

SARIF_OUTPUT_FLAG = "--sarif-file-output="


def snyk_sarif(rule_id="javascript/NoHardcodedCredentials", uri="app.js"):
    """A SARIF document shaped the way ``snyk code test --sarif`` emits one."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SnykCode",
                            "semanticVersion": "1.0.0",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {
                                        "text": "Hardcoded credential"
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": f"Hardcoded credential in {uri}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


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
def populated_source(plugin_context):
    """A non-empty source tree, so scan() gets past the empty-target check."""
    (plugin_context.source_dir / "app.js").write_text(
        "const token = 'placeholder';\n", encoding="utf-8"
    )
    return plugin_context.source_dir


@pytest.fixture
def scanner(plugin_context):
    return SnykCodeScanner(context=plugin_context, config=SnykCodeScannerConfig())


@pytest.fixture
def snyk_on_path(monkeypatch, tmp_path):
    """Report a snyk binary without installing Node or the CLI."""
    fake_binary = tmp_path / "bin" / "snyk"
    fake_binary.parent.mkdir(parents=True, exist_ok=True)
    fake_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(
        snyk_code_scanner, "find_executable", lambda name: str(fake_binary)
    )
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    return fake_binary


@pytest.fixture
def subprocess_double():
    with patch.object(SnykCodeScanner, "_run_subprocess", autospec=True) as double:
        double.return_value = {"stdout": "", "stderr": "", "returncode": 0}
        yield double


@pytest.fixture
def refusals_set_aside(monkeypatch):
    """Run scan() without the refusals that come before the copy.

    scan() refuses a target that holds ASH's output directory, a link leaving it, or
    a file the operator's ignore paths match, before it copies anything; the other
    snyk-code test files in this directory pin each refusal. The cells that take this
    fixture check what the copy itself leaves out, the second guard, on trees the
    refusals would stop first.
    """
    for refusal in (
        "_refuse_output_dir_inside",
        "_refuse_links_leaving",
        "_refuse_ignored_files",
    ):
        monkeypatch.setattr(
            SnykCodeScanner, refusal, lambda self, *args, **kwargs: None
        )


def writes_sarif(sarif_text, exit_code=0):
    """side_effect that writes SARIF to the path named in the argv it receives.

    Deriving the destination from ``--sarif-file-output=`` rather than
    recomputing it means a scanner that stops passing that flag, or passes a
    different one, makes these tests fail instead of silently finding nothing.
    """

    def _side_effect(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        Path(destination).write_text(sarif_text, encoding="utf-8")
        # scan() holds no exit code until snyk returns one, as the template does.
        self.exit_code = max(self.exit_code or 0, exit_code)
        return {"stdout": "", "stderr": "", "returncode": exit_code}

    return _side_effect


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scanner_wires_the_snyk_code_test_command(scanner):
    """model_post_init sets the command, subcommands and SARIF output flag."""
    assert scanner.command == "snyk"
    assert scanner.subcommands == ["code", "test"]
    assert scanner.tool_type == ScannerToolType.SAST
    assert scanner.args.output_arg == "--sarif-file-output"
    # Snyk takes the target positionally, so there is no scan-path flag.
    assert scanner.args.scan_path_arg is None
    assert scanner.args.format_arg is None


@pytest.mark.unit
def test_config_defaults_are_applied_when_config_is_none(plugin_context):
    scanner = SnykCodeScanner(context=plugin_context)

    assert scanner.config is not None
    assert scanner.config.name == "snyk-code"
    assert scanner.config.enabled is True


@pytest.mark.unit
def test_execute_scan_stub_raises_not_implemented(scanner):
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Dependency validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_offline_mode_fails_dependency_validation(scanner):
    """Snyk needs the network, so offline mode disqualifies it outright."""
    with patch.object(
        SnykCodeScanner, "_is_offline_mode", autospec=True, return_value=True
    ):
        assert scanner.validate_plugin_dependencies() is False


@pytest.mark.unit
def test_missing_snyk_binary_fails_dependency_validation(scanner, monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: None)

    assert scanner.validate_plugin_dependencies() is False


@pytest.mark.unit
def test_snyk_token_in_environment_satisfies_credential_check(
    scanner, snyk_on_path, caplog
):
    """With SNYK_TOKEN set, no credential warning is emitted."""
    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is True

    assert not any(
        "No Snyk credentials found" in record.message for record in caplog.records
    )


@pytest.mark.unit
def test_absent_credentials_warn_but_do_not_block_validation(
    scanner, monkeypatch, tmp_path, caplog
):
    """A missing token and missing configstore file warns, and still validates.

    The scan is allowed to proceed and fail on snyk's own auth error rather
    than being silently skipped, so the warning is the only signal here.
    """
    fake_binary = tmp_path / "bin" / "snyk"
    fake_binary.parent.mkdir(parents=True, exist_ok=True)
    fake_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(
        snyk_code_scanner, "find_executable", lambda name: str(fake_binary)
    )
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    # Point HOME at an empty directory so no configstore credentials exist.
    empty_home = tmp_path / "empty-home"
    empty_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: empty_home))

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is True

    assert any(
        "No Snyk credentials found" in record.message for record in caplog.records
    ), f"expected a credential warning; got {[r.message for r in caplog.records]}"


@pytest.mark.unit
def test_existing_configstore_credentials_suppress_the_warning(
    scanner, monkeypatch, tmp_path, caplog
):
    """A snyk.json under the configstore directory counts as credentials."""
    fake_binary = tmp_path / "bin" / "snyk"
    fake_binary.parent.mkdir(parents=True, exist_ok=True)
    fake_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(
        snyk_code_scanner, "find_executable", lambda name: str(fake_binary)
    )
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    home = tmp_path / "home-with-creds"
    configstore = home / ".config" / "configstore"
    configstore.mkdir(parents=True)
    (configstore / "snyk.json").write_text('{"api": "placeholder"}', encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is True

    assert not any(
        "No Snyk credentials found" in record.message for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Severity threshold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "threshold", [None, "ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
)
@pytest.mark.unit
def test_severity_threshold_is_not_passed_to_snyk(plugin_context, tmp_path, threshold):
    """``severity_threshold`` says which findings count as failures, and ASH applies
    it after the scan. Passed as ``--severity-threshold``, snyk dropped the findings
    below it before ASH saw them, so they were neither reported nor counted."""
    scanner = SnykCodeScanner(
        context=plugin_context,
        config=SnykCodeScannerConfig(
            options=SnykCodeScannerConfigOptions(severity_threshold=threshold)
        ),
    )
    target = tmp_path / "scan-me"
    target.mkdir()

    args = scanner._resolve_arguments(target=target, results_file=None)

    assert "--severity-threshold" not in args, args
    assert all(arg.key != "--severity-threshold" for arg in scanner.args.extra_args)


# ---------------------------------------------------------------------------
# Argument resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_arguments_puts_the_target_positionally_and_output_with_equals(
    scanner, tmp_path
):
    """Snyk requires ``--sarif-file-output=<path>``, not a space-separated pair."""
    target = tmp_path / "scan-me"
    target.mkdir()
    results_file = tmp_path / "results_sarif.sarif"

    args = scanner._resolve_arguments(target=target, results_file=results_file)

    assert args[:3] == ["snyk", "code", "test"]
    assert target.as_posix() in args
    assert f"{SARIF_OUTPUT_FLAG}{results_file.as_posix()}" in args
    # The flag and its value must not be two separate tokens.
    assert "--sarif-file-output" not in args


@pytest.mark.unit
def test_resolve_arguments_omits_the_output_flag_when_no_results_file(
    scanner, tmp_path
):
    target = tmp_path / "scan-me"
    target.mkdir()

    args = scanner._resolve_arguments(target=target, results_file=None)

    assert not any(arg.startswith(SARIF_OUTPUT_FLAG) for arg in args)


@pytest.mark.unit
def test_valueless_extra_args_are_emitted_as_bare_flags(plugin_context, tmp_path):
    """An extra arg with value None becomes one token, not a token pair."""
    from automated_security_helper.models.core import ToolExtraArg

    scanner = SnykCodeScanner(context=plugin_context, config=SnykCodeScannerConfig())
    scanner.args.extra_args.append(ToolExtraArg(key="--json", value=None))
    scanner.args.extra_args.append(ToolExtraArg(key="--org", value="placeholder-org"))
    target = tmp_path / "scan-me"
    target.mkdir()

    args = scanner._resolve_arguments(target=target, results_file=None)

    assert "--json" in args
    assert args[args.index("--org") + 1] == "placeholder-org"
    # A bare flag must not be followed by a stringified None.
    assert "None" not in args


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_empty_target_returns_true_without_running_snyk(
    scanner, snyk_on_path, subprocess_double
):
    """An empty target is a no-op success, not a scanner failure."""
    result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is True
    subprocess_double.assert_not_called()
    assert any("empty or doesn't exist" in err for err in scanner.errors)


@pytest.mark.unit
def test_unsatisfied_dependencies_return_false(
    scanner, populated_source, subprocess_double, monkeypatch
):
    """Without the snyk binary the scanner reports skipped, not clean."""
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: None)

    result = scanner.scan(target=populated_source, target_type="source")

    assert result is False
    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_dependency_flag_is_rechecked_after_pre_scan(
    scanner, populated_source, subprocess_double
):
    """The independent post-_pre_scan dependency guard also returns False."""
    with patch.object(SnykCodeScanner, "_pre_scan", autospec=True, return_value=True):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=populated_source, target_type="source")

    assert result is False
    subprocess_double.assert_not_called()


# ---------------------------------------------------------------------------
# The scan body
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_sarif_written_by_snyk_becomes_the_returned_report(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """A non-empty SARIF file yields a report with non-empty findings.

    This is the anti-"clean scan" assertion: if the results file were ignored
    or parsed into nothing, the scan would look like a pass.
    """
    subprocess_double.side_effect = writes_sarif(snyk_sarif())

    report = scanner.scan(target=populated_source, target_type="source")

    assert subprocess_double.call_count == 1
    results = report.runs[0].results
    assert len(results) == 1, f"expected snyk's one finding, got {len(results)}"
    assert results[0].ruleId == "javascript/NoHardcodedCredentials"
    assert "Hardcoded credential in app.js" in results[0].message.root.text


@pytest.mark.unit
def test_results_file_is_written_under_the_target_type_directory(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """Source and converted scans write to separate results files."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif())

    scanner.scan(target=populated_source, target_type="source")

    expected = Path(scanner.results_dir) / "source" / "results_sarif.sarif"
    assert expected.is_file(), f"{expected} was not written"
    command = subprocess_double.call_args.kwargs["command"]
    assert f"{SARIF_OUTPUT_FLAG}{expected.as_posix()}" in command


@pytest.mark.unit
def test_invocation_records_a_shell_quoted_command_line(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """The recorded commandLine is shlex-joined so it can be copy-pasted."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif())

    report = scanner.scan(target=populated_source, target_type="source")

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine.startswith("snyk code test")
    assert invocation.arguments[0] == "code"
    assert invocation.exitCode == 0
    assert invocation.executionSuccessful is True
    assert invocation.startTimeUtc is not None
    # The scanner records each target's end time when its run is over, before it
    # builds the Invocation, so the record carries one. Before that it built the
    # Invocation first and _post_scan set end_time after, which left endTimeUtc
    # None in every report; this pin moved with the order.
    assert invocation.endTimeUtc is not None
    assert invocation.endTimeUtc >= invocation.startTimeUtc
    assert scanner.end_time == invocation.endTimeUtc


@pytest.mark.unit
def test_scanner_details_are_attached_to_the_run(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """The report identifies snyk-code, not just the SarifReport driver name."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif())

    report = scanner.scan(target=populated_source, target_type="source")

    serialized = report.model_dump_json(exclude_none=True)
    assert "snyk-code" in serialized, (
        "attach_scanner_details should stamp the ASH scanner name onto the report"
    )


@pytest.mark.unit
def test_nonzero_exit_code_raises_scanner_error(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """An exit code snyk uses for real failures aborts the scan loudly."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=2)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=populated_source, target_type="source")

    assert "Snyk Code scan failed" in str(excinfo.value)
    assert "exit code 2" in str(excinfo.value)


@pytest.mark.unit
def test_exit_code_one_means_findings_not_failure(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """Snyk exits 1 when it finds issues; that is a completed scan, not a failure.

    The scan checks the scanner's accepted set, not ``exit_code != 0``, so a snyk run
    that found something reports its findings rather than a scanner failure.
    """
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=1)

    report = scanner.scan(target=populated_source, target_type="source")

    assert len(report.runs[0].results) == 1


@pytest.mark.unit
def test_exit_code_one_is_kept_on_the_scanner_and_its_invocation(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """An accepted 1 is recorded as the tool returned it, as bandit's 1 is."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=1)

    report = scanner.scan(target=populated_source, target_type="source")

    assert scanner.exit_code == 1
    assert report.runs[0].invocations[0].exitCode == 1


@pytest.mark.unit
def test_a_rejected_exit_code_is_kept_on_the_scanner(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=2)

    with pytest.raises(ScannerError):
        scanner.scan(target=populated_source, target_type="source")

    assert scanner.exit_code == 2


@pytest.mark.unit
def test_scan_starts_each_target_with_exit_code_zero(scanner, snyk_on_path):
    """An earlier target's code is not carried into this one (the empty-target path
    returns before snyk runs, so the code it ends with is this target's own)."""
    scanner.exit_code = 3

    result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is True
    assert scanner.exit_code == 0


@pytest.mark.unit
def test_malformed_results_file_logs_an_error_and_returns_none(
    scanner, snyk_on_path, populated_source, subprocess_double, caplog
):
    """A results file that is JSON but not SARIF is reported, not raised."""
    subprocess_double.side_effect = writes_sarif(json.dumps({"not": "sarif"}))

    with caplog.at_level(logging.ERROR):
        result = scanner.scan(target=populated_source, target_type="source")

    assert result is None
    assert any(
        "Failed to parse SnykCodeScanner results as SARIF" in record.message
        for record in caplog.records
    ), f"expected a parse error; got {[r.message for r in caplog.records]}"
    assert any("Failed to parse" in err for err in scanner.errors)


@pytest.mark.unit
def test_missing_results_file_warns_and_returns_none(
    scanner, snyk_on_path, populated_source, subprocess_double, caplog
):
    """When snyk writes no SARIF at all the scan yields None with a warning.

    Returning None rather than an empty report keeps "snyk produced nothing"
    distinguishable from "snyk found nothing".
    """
    subprocess_double.return_value = {"stdout": "", "stderr": "", "returncode": 0}

    with caplog.at_level(logging.WARNING):
        result = scanner.scan(target=populated_source, target_type="source")

    assert result is None
    assert any("No results file found" in record.message for record in caplog.records)
    assert any("No results file found" in err for err in scanner.errors)


@pytest.mark.unit
def test_exit_code_one_without_a_results_file_is_not_a_clean_scan(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """Accepting exit 1 must not make a run that wrote no SARIF look clean.

    scan() returns None, as it does for exit 0 with no file, and the scanner
    executor records a None result as ERROR ("Scanner returned None").
    """

    def _exits_one_without_sarif(self, command, **kwargs):
        self.exit_code = 1
        return {"stdout": "", "stderr": "", "returncode": 1}

    subprocess_double.side_effect = _exits_one_without_sarif

    result = scanner.scan(target=populated_source, target_type="source")

    assert result is None
    assert any("No results file found" in err for err in scanner.errors)


@pytest.mark.unit
def test_unreadable_results_file_is_wrapped_in_scanner_error(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """An error outside the SARIF try block surfaces as ScannerError."""

    def _write_invalid_json(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        # json.load() happens before the try block that catches parse errors.
        Path(destination).write_text("{not valid json at all", encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    subprocess_double.side_effect = _write_invalid_json

    with pytest.raises(ScannerError, match="Snyk Code scan failed"):
        scanner.scan(target=populated_source, target_type="source")


# ---------------------------------------------------------------------------
# Results shaped the way Snyk Code writes them
# ---------------------------------------------------------------------------
#
# snyk_sarif() above is the minimum SARIF. The documents below carry the fields
# Snyk Code's own SARIF output has, taken from the fixtures in the Snyk CLI's test
# suite: rules with defaultConfiguration and properties (cwe, precision), results
# with ruleIndex, a markdown message with arguments, numbered fingerprints,
# codeFlows, a priorityScore property bag, uriBaseId %SRCROOT%, run-level
# coverage properties, `"suppressions": null` on unsuppressed results, and an
# external suppression on an ignored one. Snyk exits 0 when it found nothing and
# 1 when it found something (its documented exit codes; 2 and 3 are failures).


def _snyk_location(uri, line):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {
                "startLine": line,
                "endLine": line,
                "startColumn": 5,
                "endColumn": 17,
            },
        }
    }


def snyk_code_document(findings, suppressed=()):
    """A Snyk Code SARIF document for ``findings``: (rule_id, level, uri, line)."""
    all_findings = [*findings, *suppressed]
    rule_ids = sorted({rule_id for rule_id, _, _, _ in all_findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.split("/")[-1],
            "shortDescription": {"text": rule_id.split("/")[-1]},
            "defaultConfiguration": {"level": "warning"},
            "help": {"markdown": "## Details\n\nPlaceholder.", "text": ""},
            "properties": {
                "tags": ["javascript", "Security"],
                "categories": ["Security"],
                "exampleCommitFixes": [],
                "exampleCommitDescriptions": [],
                "precision": "very-high",
                "repoDatasetSize": 12,
                "cwe": ["CWE-798"],
            },
        }
        for rule_id in rule_ids
    ]

    def result(finding, suppressions):
        rule_id, level, uri, line = finding
        return {
            "ruleId": rule_id,
            "ruleIndex": rule_ids.index(rule_id),
            "level": level,
            "message": {
                "text": f"{rule_id} in {uri}",
                "markdown": "Found {0} in {1}.",
                "arguments": ["[a value](0)", "[here](1)"],
            },
            "locations": [_snyk_location(uri, line)],
            "fingerprints": {"0": f"{uri}:{line}:a", "1": f"{uri}:{line}:b"},
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {"location": {"id": 0, **_snyk_location(uri, line)}}
                            ]
                        }
                    ]
                }
            ],
            "properties": {
                "priorityScore": 500,
                "priorityScoreFactors": [{"label": True, "type": "hotFileSource"}],
                "isAutofixable": False,
            },
            "suppressions": suppressions,
        }

    results = [result(f, None) for f in findings] + [
        result(
            f,
            [
                {
                    "justification": "Accepted for this test",
                    "kind": "external",
                    "properties": {
                        "category": "wont-fix",
                        "expiration": None,
                        "ignoredOn": "2026-01-01T00:00:00.000Z",
                    },
                }
            ],
        )
        for f in suppressed
    ]
    return json.dumps(
        {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SnykCode",
                            "semanticVersion": "1.0.0",
                            "version": "1.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "coverage": [
                            {
                                "files": 3,
                                "isSupported": True,
                                "lang": "JavaScript",
                                "type": "SUPPORTED",
                            }
                        ]
                    },
                }
            ],
        }
    )


SNYK_CASES = {
    "zero findings": {"findings": [], "suppressed": [], "exit_code": 0},
    "one finding": {
        "findings": [("javascript/NoHardcodedPasswords", "error", "app.js", 7)],
        "suppressed": [],
        "exit_code": 1,
    },
    "several findings of different levels": {
        "findings": [
            ("javascript/NoHardcodedPasswords", "error", "app.js", 7),
            (
                "javascript/NoRateLimitingForExpensiveWebOperation",
                "warning",
                "routes/index.js",
                77,
            ),
            ("javascript/HttpToHttps", "note", "db.js", 3),
        ],
        "suppressed": [("javascript/Sqli", "error", "db.js", 12)],
        "exit_code": 1,
    },
}


@pytest.mark.parametrize("case", sorted(SNYK_CASES))
@pytest.mark.unit
def test_snyk_code_results_become_the_report(
    case, scanner, snyk_on_path, populated_source, subprocess_double
):
    """Every result Snyk wrote is returned, at the level Snyk gave it."""
    spec = SNYK_CASES[case]
    subprocess_double.side_effect = writes_sarif(
        snyk_code_document(spec["findings"], spec["suppressed"]),
        exit_code=spec["exit_code"],
    )

    report = scanner.scan(target=populated_source, target_type="source")

    expected = [
        (rule_id, level, uri, line)
        for rule_id, level, uri, line in [*spec["findings"], *spec["suppressed"]]
    ]
    got = [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    ]
    assert got == expected
    invocation = report.runs[0].invocations[0]
    assert invocation.exitCode == spec["exit_code"]
    assert invocation.executionSuccessful is True


@pytest.mark.parametrize("case", sorted(SNYK_CASES))
@pytest.mark.unit
def test_snyk_code_results_are_counted_at_their_severity(
    case, scanner, snyk_on_path, populated_source, subprocess_double, plugin_context
):
    """Counted the way the scan phase counts them: error is CRITICAL, warning
    MEDIUM, note LOW, and a result Snyk marks ignored is suppressed."""
    from automated_security_helper.utils.sarif_utils import (
        get_severity_metrics_from_sarif,
    )

    spec = SNYK_CASES[case]
    subprocess_double.side_effect = writes_sarif(
        snyk_code_document(spec["findings"], spec["suppressed"]),
        exit_code=spec["exit_code"],
    )

    report = scanner.scan(target=populated_source, target_type="source")
    counts = get_severity_metrics_from_sarif(report, plugin_context)

    severity_of = {"error": "critical", "warning": "medium", "note": "low"}
    expected = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for _, level, _, _ in spec["findings"]:
        expected[severity_of[level]] += 1
    assert {k: getattr(counts, k) for k in expected} == expected
    assert counts.suppressed == len(spec["suppressed"])


@pytest.mark.unit
def test_exit_code_three_evaluated_nothing_and_is_not_a_failure(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """Snyk exits 3 when it found no supported files: not a clean scan, not a failure.

    Nothing was evaluated, so scan() records that (``targets_attempted == 0``) and
    the executor grades the row SKIPPED, not PASSED and not ERROR (see
    test_snyk_code_no_supported_files.py and the README's "No supported files (exit
    code 3)"). Exit code 2, a failed run, still raises:
    test_nonzero_exit_code_raises_scanner_error.
    """
    subprocess_double.side_effect = writes_sarif(snyk_code_document([]), exit_code=3)

    result = scanner.scan(target=populated_source, target_type="source")

    assert result is True
    assert scanner.targets_attempted == 0
    assert scanner.exit_code == 3


# ---------------------------------------------------------------------------
# What the scanner executor records
# ---------------------------------------------------------------------------
#
# Snyk exits 1 only when it found issues. A run that exits 1 and reports none has
# not shown what it scanned, so it must not read as a clean scan.

EMPTY_SNYK_DOCUMENTS = {
    "a run with no results": snyk_code_document([]),
    "no runs": json.dumps({"version": "2.1.0", "runs": []}),
    "an empty object": json.dumps({}),
}


def _executor_row(scanner, plugin_context, monkeypatch, ignore_paths=None):
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    # As the scan phase sets it before running the scanners.
    executor._global_ignore_paths = list(ignore_paths or [])
    # The content-database age check is not what is under test here.
    monkeypatch.setattr(executor, "_assess_content_databases", lambda *a, **k: None)
    (row,) = executor._execute_scanner(
        "snyk-code",
        scanner,
        [{"path": plugin_context.source_dir, "type": "source"}],
    )
    return row


@pytest.mark.parametrize("document", sorted(EMPTY_SNYK_DOCUMENTS))
@pytest.mark.unit
def test_exit_code_one_with_no_results_is_an_error_row(
    document,
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    plugin_context,
    monkeypatch,
):
    subprocess_double.side_effect = writes_sarif(
        EMPTY_SNYK_DOCUMENTS[document], exit_code=1
    )

    row = _executor_row(scanner, plugin_context, monkeypatch)

    assert row.status == ScannerStatus.ERROR, (
        f"snyk exited 1 (issues found) and its SARIF held {document}; the row was "
        f"graded {row.status}"
    )


@pytest.mark.parametrize("document", sorted(EMPTY_SNYK_DOCUMENTS))
@pytest.mark.unit
def test_exit_code_one_with_no_results_names_the_contradiction(
    document, scanner, snyk_on_path, populated_source, subprocess_double
):
    subprocess_double.side_effect = writes_sarif(
        EMPTY_SNYK_DOCUMENTS[document], exit_code=1
    )

    with pytest.raises(ScannerError, match="exit code 1.*no results"):
        scanner.scan(target=populated_source, target_type="source")


@pytest.mark.unit
def test_exit_code_zero_with_no_results_is_a_passed_row(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    plugin_context,
    monkeypatch,
):
    """Control: the same empty run with Snyk's no-issues code is a clean scan."""
    subprocess_double.side_effect = writes_sarif(snyk_code_document([]), exit_code=0)

    row = _executor_row(scanner, plugin_context, monkeypatch)

    assert row.status == ScannerStatus.PASSED
    assert row.exit_code == 0


@pytest.mark.unit
def test_the_row_records_exit_code_one_for_a_run_with_findings(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    plugin_context,
    monkeypatch,
):
    subprocess_double.side_effect = writes_sarif(
        snyk_code_document([("javascript/HttpToHttps", "note", "app.js", 1)]),
        exit_code=1,
    )

    row = _executor_row(scanner, plugin_context, monkeypatch)

    assert row.finding_count == 1
    assert row.exit_code == 1


@pytest.mark.unit
def test_the_exit_code_of_each_target_is_its_own(
    scanner, snyk_on_path, populated_source, subprocess_double, plugin_context
):
    """One scanner, two targets: the source run's exit 1 is not the converted run's.

    _process_command_response keeps the largest code any run returned. Without
    _record_target_exit_code, the converted target's clean run (exit 0, no results)
    would be read as exit 1 with no results, which is a scanner error.
    """
    converted = plugin_context.work_dir / "jupyter"
    converted.mkdir(parents=True)
    (converted / "nb-converted.py").write_text("x = 1\n", encoding="utf-8")
    subprocess_double.side_effect = writes_sarif(
        snyk_code_document([("javascript/HttpToHttps", "note", "app.js", 1)]),
        exit_code=1,
    )
    first = scanner.scan(target=populated_source, target_type="source")
    assert len(first.runs[0].results) == 1
    assert scanner.exit_code == 1

    subprocess_double.side_effect = writes_sarif(snyk_code_document([]), exit_code=0)
    second = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert scanner.exit_code == 0
    assert second.runs[0].results in (None, [])


@pytest.mark.parametrize(
    "document, expected",
    [
        ({"runs": [{"results": []}, {"results": [{}, {}]}]}, 2),
        ({"runs": [{"results": [{}]}, {"results": [{}]}, {}]}, 2),
        ({"runs": [{"results": None}, {"results": [{}]}]}, 1),
        ({"runs": [{}, "not a run", {"results": [{}]}]}, 1),
        ({"runs": []}, 0),
        ({"runs": None}, 0),
        ([], 0),
    ],
)
@pytest.mark.unit
def test_results_are_counted_across_every_run(document, expected):
    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        _sarif_result_count,
    )

    assert _sarif_result_count(document) == expected


# ---------------------------------------------------------------------------
# What is sent to Snyk
# ---------------------------------------------------------------------------
#
# snyk code test uploads the directory it is given and has no option that excludes
# a path. The source target is therefore tested as a copy of the scan set less the
# global ignore paths. The double records the directory snyk was given and the
# files in it at the time it ran.


def records_tested_files(seen):
    def _side_effect(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        tested = Path(
            next(
                arg
                for arg in command[3:]
                if not arg.startswith("-") and arg != destination
            )
        )
        seen["tested"] = tested
        seen["files"] = sorted(
            p.relative_to(tested).as_posix() for p in tested.rglob("*") if p.is_file()
        )
        Path(destination).write_text(snyk_code_document([]), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    return _side_effect


def _ignore(*patterns):
    from automated_security_helper.models.core import IgnorePathWithReason

    return [IgnorePathWithReason(path=p, reason="test") for p in patterns]


@pytest.fixture
def tree_with_vendor(populated_source):
    (populated_source / "vendor" / "lib").mkdir(parents=True)
    (populated_source / "vendor" / "lib" / "dep.js").write_text(
        "const v = 1;\n", encoding="utf-8"
    )
    (populated_source / "web").mkdir()
    (populated_source / "web" / "site.min.js").write_text("x\n", encoding="utf-8")
    return populated_source


@pytest.mark.unit
def test_files_under_an_ignore_path_are_not_sent_to_snyk(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, refusals_set_aside
):
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(
        target=tree_with_vendor,
        target_type="source",
        global_ignore_paths=_ignore("vendor/**"),
    )

    assert seen["files"] == ["app.js", "web/site.min.js"]
    assert not seen["tested"].exists(), "the copy is removed after the run"


@pytest.mark.unit
def test_the_copy_is_made_outside_the_scanned_tree_and_the_output_dir(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, plugin_context
):
    """Other scanners walking the tree, or an uploaded output directory, never see it."""
    import tempfile

    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=tree_with_vendor, target_type="source")

    tested = seen["tested"].resolve()
    for inside in (tree_with_vendor, plugin_context.output_dir, scanner.results_dir):
        assert not tested.is_relative_to(Path(inside).resolve()), (tested, inside)
    assert tested.is_relative_to(Path(tempfile.gettempdir()).resolve())


@pytest.mark.unit
def test_the_sarif_names_the_scanned_directory_not_the_deleted_copy(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double
):
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    report = scanner.scan(target=tree_with_vendor, target_type="source")

    invocation = report.runs[0].invocations[0]
    assert tree_with_vendor.as_posix() in invocation.commandLine
    assert seen["tested"].as_posix() not in invocation.commandLine
    assert seen["tested"].as_posix() not in report.model_dump_json()


@pytest.mark.unit
def test_a_full_disk_while_copying_is_a_scanner_error(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, monkeypatch
):
    """ENOSPC while writing the copy must not let Snyk test part of the tree."""
    import errno

    from automated_security_helper.utils.sandbox import fs_guard

    made = {}
    real_open = fs_guard.open_for_write_bytes

    class _FullDisk:
        def __init__(self, path):
            made.setdefault("dirs", set()).add(Path(path).parent)
            self._handle = real_open(path)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()

        def write(self, data):
            raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(fs_guard, "open_for_write_bytes", _FullDisk)

    with pytest.raises(ScannerError, match="No space left on device"):
        scanner.scan(target=tree_with_vendor, target_type="source")

    subprocess_double.assert_not_called()
    assert made["dirs"], "the copy was attempted"
    assert not any(d.exists() for d in made["dirs"]), "the partial copy is removed"


@pytest.mark.unit
def test_a_full_disk_while_copying_is_an_error_row(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    plugin_context,
    monkeypatch,
):
    import errno

    from automated_security_helper.utils.sandbox import fs_guard

    def _no_space(path):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(fs_guard, "open_for_write_bytes", _no_space)

    row = _executor_row(scanner, plugin_context, monkeypatch)

    assert row.status == ScannerStatus.ERROR
    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_an_unreadable_source_file_is_skipped_not_fatal(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, monkeypatch
):
    """A read error is the file's problem: that file is left out, the rest is tested."""
    from automated_security_helper.utils import scanned_tree

    real_open = scanned_tree.open_in_scanned_tree

    def _open(path, root):
        if Path(path).name == "dep.js":
            raise PermissionError(13, "Permission denied")
        return real_open(path, root)

    monkeypatch.setattr(scanned_tree, "open_in_scanned_tree", _open)
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=tree_with_vendor, target_type="source")

    assert seen["files"] == ["app.js", "web/site.min.js"]


@pytest.mark.unit
def test_under_a_sandbox_snyk_is_granted_the_copy(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, plugin_context
):
    """The scope active while snyk runs names the copy as the scan target."""
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements
    from automated_security_helper.utils.sandbox.scope import (
        SandboxScope,
        active_scope,
        sandbox_scope,
    )

    seen = {}
    record = records_tested_files(seen)

    def _side_effect(self, command, **kwargs):
        seen["scope"] = active_scope()
        return record(self, command, **kwargs)

    subprocess_double.side_effect = _side_effect
    outer = SandboxScope(
        backend=MagicMock(),
        scanner_name="snyk-code",
        requirements=SandboxRequirements(),
        source_dir=plugin_context.source_dir,
        output_dir=plugin_context.output_dir,
        results_dir=Path(scanner.results_dir),
        scan_target=tree_with_vendor,
        offline=False,
    )

    with sandbox_scope(outer):
        scanner.scan(target=tree_with_vendor, target_type="source")
        after = active_scope()

    assert seen["scope"].scan_target == seen["tested"]
    assert after is outer, "the grant ends with the run"


@pytest.mark.unit
def test_tmpdir_inside_the_scanned_tree_is_refused(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, monkeypatch
):
    import tempfile

    inside = tree_with_vendor / "tmp"
    inside.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(inside))

    with pytest.raises(ScannerError, match="TMPDIR"):
        scanner.scan(target=tree_with_vendor, target_type="source")
    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_the_copy_log_line_counts_in_english(
    scanner, snyk_on_path, populated_source, subprocess_double, caplog
):
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    with caplog.at_level(logging.INFO):
        scanner.scan(target=populated_source, target_type="source")

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "1 file from the scan set" in messages, messages
    assert "1 files" not in messages


@pytest.mark.parametrize(
    "pattern", ["vendor/**", "**/*.min.js", "app.js", "vendor/lib/dep.js", "nomatch/**"]
)
@pytest.mark.unit
def test_the_copy_matches_ignore_paths_the_way_findings_are_dropped(
    pattern,
    scanner,
    snyk_on_path,
    tree_with_vendor,
    subprocess_double,
    refusals_set_aside,
):
    """The same matcher ASH uses to drop findings under an ignore path."""
    from automated_security_helper.utils.suppression_matcher import file_path_matches

    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)
    everything = ["app.js", "vendor/lib/dep.js", "web/site.min.js"]

    scanner.scan(
        target=tree_with_vendor,
        target_type="source",
        global_ignore_paths=_ignore(pattern),
    )

    assert seen["files"] == [f for f in everything if not file_path_matches(f, pattern)]


@pytest.mark.unit
def test_with_no_ignore_paths_the_whole_scan_set_is_tested(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double
):
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=tree_with_vendor, target_type="source")

    assert seen["files"] == ["app.js", "vendor/lib/dep.js", "web/site.min.js"]


@pytest.mark.unit
def test_when_every_file_is_ignored_nothing_is_sent(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, refusals_set_aside
):
    result = scanner.scan(
        target=tree_with_vendor,
        target_type="source",
        global_ignore_paths=_ignore("**"),
    )

    assert result is True
    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_when_every_file_is_ignored_the_row_is_skipped(
    scanner,
    snyk_on_path,
    tree_with_vendor,
    subprocess_double,
    plugin_context,
    monkeypatch,
    refusals_set_aside,
):
    """Nothing is evaluated and nothing is sent, as for a scan set with no file:
    the row grades SKIPPED (targets_attempted 0), not PASSED for a tool that never
    ran. Pinned here so the all-ignored case cannot drift from the no-file one."""
    row = _executor_row(
        scanner, plugin_context, monkeypatch, ignore_paths=_ignore("**")
    )

    assert row.status == ScannerStatus.SKIPPED, row
    assert scanner.targets_attempted == 0
    subprocess_double.assert_not_called()


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_a_symlink_in_the_tree_is_not_sent(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    tmp_path,
    refusals_set_aside,
):
    outside = tmp_path / "outside.js"
    outside.write_text("const host = 1;\n", encoding="utf-8")
    (populated_source / "link.js").symlink_to(outside)
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=populated_source, target_type="source")

    assert seen["files"] == ["app.js"]


@pytest.mark.unit
def test_the_converted_target_is_tested_in_place(
    scanner, snyk_on_path, plugin_context, subprocess_double
):
    """Only the source directory is copied. An ignore path that matches a converted
    file refuses the target instead (test_snyk_ignored_files_never_reach_snyk.py), so
    the one here matches nothing in it."""
    converted = plugin_context.work_dir / "jupyter"
    converted.mkdir(parents=True)
    (converted / "nb-converted.py").write_text("x = 1\n", encoding="utf-8")
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(
        target=plugin_context.work_dir,
        target_type="converted",
        global_ignore_paths=_ignore("vendor/**"),
    )

    assert seen["tested"] == plugin_context.work_dir
    assert seen["files"] == ["jupyter/nb-converted.py"]


@pytest.mark.unit
def test_ash_output_inside_the_tree_is_not_sent(
    snyk_on_path, tmp_path, subprocess_double, refusals_set_aside
):
    """The default layout puts ASH's output at <source>/.ash/ash_output. With the
    refusal set aside, the copy leaves it out."""
    source = tmp_path / "repo"
    (source / ".ash" / "ash_output").mkdir(parents=True)
    (source / ".ash" / "ash_output" / "ash.log").write_text("log\n", encoding="utf-8")
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        config=get_default_config(),
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=source, target_type="source")

    assert seen["files"] == ["app.js"]


# ---------------------------------------------------------------------------
# Files the copy refuses, and where the copy lives
# ---------------------------------------------------------------------------


def _link_outside(kind, link, outside):
    import os

    outside.write_text("const host = 1;\n", encoding="utf-8")
    if kind == "hardlink":
        os.link(outside, link)
    else:
        link.symlink_to(outside)


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating links needs privileges on Windows"
)
@pytest.mark.parametrize("kind", ["hardlink", "symlink"])
@pytest.mark.unit
def test_when_every_file_is_refused_the_row_is_an_error(
    kind,
    scanner,
    snyk_on_path,
    plugin_context,
    subprocess_double,
    monkeypatch,
    caplog,
    tmp_path,
    refusals_set_aside,
):
    """Nothing was copied because nothing could be: that is not an all-ignored scan.

    The old scanner tested the tree as it stood, so this file was sent. Refusing
    it is right; reporting PASSED with 0 findings for a scan that tested nothing
    is not.

    A symlink whose target leaves the tree never reaches the copy: the scan set
    leaves it out first (the next test). So the symlink here stays inside the tree,
    pointing at the one other file, which is under an ignore path: the copy's own
    refusal of the link is what leaves nothing to send.
    """
    source = plugin_context.source_dir
    ignore_paths = []
    if kind == "hardlink":
        _link_outside(kind, source / "app.js", tmp_path / "outside.js")
    else:
        (source / "vendor").mkdir()
        (source / "vendor" / "real.js").write_text("const v = 1;\n", encoding="utf-8")
        (source / "app.js").symlink_to(source / "vendor" / "real.js")
        ignore_paths = _ignore("vendor/**")

    with caplog.at_level(logging.INFO):
        row = _executor_row(
            scanner, plugin_context, monkeypatch, ignore_paths=ignore_paths
        )

    assert row.status == ScannerStatus.ERROR, row
    subprocess_double.assert_not_called()
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "under an ignore path" not in messages, messages
    assert "1 file in the scan set not copied" in messages, messages


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_a_tree_holding_only_a_link_leaving_it_sends_nothing(
    scanner,
    snyk_on_path,
    plugin_context,
    subprocess_double,
    monkeypatch,
    caplog,
    refusals_set_aside,
):
    """The scan set leaves the link out and warns about it, as it does for every
    scanner, so snyk-code has nothing to send and snyk is not run. Nothing was
    evaluated, so the row grades SKIPPED (targets_attempted 0), not PASSED with
    exit code 0 for a tool that never ran."""
    (plugin_context.source_dir / "app.js").symlink_to(
        plugin_context.source_dir.parent / "outside.js"
    )
    (plugin_context.source_dir.parent / "outside.js").write_text(
        "const host = 1;\n", encoding="utf-8"
    )

    with caplog.at_level(logging.INFO):
        row = _executor_row(scanner, plugin_context, monkeypatch)

    assert row.status == ScannerStatus.SKIPPED, row
    assert scanner.targets_attempted == 0
    subprocess_double.assert_not_called()
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert "Not scanning 'app.js': link leaves the scanned tree" in warnings, warnings
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "The scan set holds no file to send to Snyk" in messages, messages


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating links needs privileges on Windows"
)
@pytest.mark.unit
def test_a_hard_linked_file_is_not_sent_and_the_warning_says_why(
    scanner, snyk_on_path, populated_source, subprocess_double, caplog, tmp_path
):
    """A file with a second hard link may be the same inode as a file outside the
    tree, so it is refused like a symlink, and the warning has to say so."""
    _link_outside("hardlink", populated_source / "linked.js", tmp_path / "outside.js")
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    with caplog.at_level(logging.INFO):
        scanner.scan(target=populated_source, target_type="source")

    assert seen["files"] == ["app.js"]
    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "not copied" in record.getMessage()
    ]
    assert warnings and "hard link" in warnings[0], warnings


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.parametrize("spelled_through_link", ["source", "output"])
@pytest.mark.unit
def test_ash_output_reached_through_a_symlinked_prefix_is_not_sent(
    spelled_through_link, snyk_on_path, tmp_path, subprocess_double
):
    """The output directory inside the tree, with one of the two spelled via a link."""
    real = tmp_path / "real"
    source = real / "repo"
    (source / ".ash" / "out").mkdir(parents=True)
    (source / ".ash" / "out" / "ash.log").write_text("log\n", encoding="utf-8")
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    if spelled_through_link == "source":
        source_dir, output_dir = alias / "repo", source / ".ash" / "out"
    else:
        source_dir, output_dir = source, alias / "repo" / ".ash" / "out"
    context = PluginContext(
        source_dir=source_dir, output_dir=output_dir, config=get_default_config()
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=source_dir, target_type="source")

    assert seen["files"] == ["app.js"]


@pytest.mark.unit
def test_tmpdir_inside_the_output_dir_is_refused(
    snyk_on_path, tmp_path, subprocess_double, monkeypatch
):
    """The output directory outside the source, and TMPDIR inside the output."""
    import tempfile

    source = tmp_path / "src"
    source.mkdir()
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    output = tmp_path / "out"
    (output / "tmp").mkdir(parents=True)
    context = PluginContext(
        source_dir=source, output_dir=output, config=get_default_config()
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    monkeypatch.setattr(tempfile, "tempdir", str(output / "tmp"))

    with pytest.raises(ScannerError, match="inside the output directory.*TMPDIR"):
        scanner.scan(target=source, target_type="source")
    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_a_file_that_fails_partway_through_reading_is_left_out(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double, monkeypatch, caplog
):
    """A read error after the first chunk: the part already written is removed."""
    import io

    from automated_security_helper.utils import scanned_tree

    real_open = scanned_tree.open_in_scanned_tree

    class _FailsAfterOneChunk(io.RawIOBase):
        def __init__(self):
            self.calls = 0

        def read(self, size=-1):
            self.calls += 1
            if self.calls == 1:
                return b"const part = 1;\n"
            raise OSError(5, "Input/output error")

    def _open(path, root):
        if Path(path).name == "dep.js":
            return _FailsAfterOneChunk()
        return real_open(path, root)

    monkeypatch.setattr(scanned_tree, "open_in_scanned_tree", _open)
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    with caplog.at_level(logging.INFO):
        scanner.scan(target=tree_with_vendor, target_type="source")

    assert seen["files"] == ["app.js", "web/site.min.js"]
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "1 file in the scan set not copied" in messages, messages


def _stale_copy(temp_root, name, age_seconds):
    import os
    import time

    copy = temp_root / name
    (copy / "app.js").parent.mkdir(parents=True)
    (copy / "app.js").write_text("const left = 1;\n", encoding="utf-8")
    then = time.time() - age_seconds
    os.utime(copy, (then, then))
    return copy


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
@pytest.mark.unit
def test_a_copy_left_by_a_killed_run_is_removed_by_the_next_run(
    scanner, snyk_on_path, populated_source, subprocess_double, monkeypatch, tmp_path
):
    """A SIGTERM or SIGKILL skips the finally that removes the copy.

    The next snyk-code run removes such a copy once no process holds it and it is
    older than the scan timeout. A copy that is too young, or that a live run still
    holds, or that is not one of these copies, is kept.
    """
    import fcntl
    import os
    import tempfile

    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    timeout = scanner._effective_scan_timeout()
    stale = _stale_copy(temp_root, "ash-snyk-code-stale", timeout + 60)
    fresh = _stale_copy(temp_root, "ash-snyk-code-fresh", 5)
    held = _stale_copy(temp_root, "ash-snyk-code-held", timeout + 60)
    other = _stale_copy(temp_root, "not-a-snyk-copy", timeout + 60)
    held_fd = os.open(held, os.O_RDONLY)
    fcntl.flock(held_fd, fcntl.LOCK_EX)
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    try:
        scanner.scan(target=populated_source, target_type="source")
    finally:
        os.close(held_fd)

    assert not stale.exists(), "a copy no process holds, past the timeout"
    assert fresh.exists(), "a copy younger than the scan timeout"
    assert held.exists(), "a copy a live run holds"
    assert other.exists(), "not one of snyk-code's copies"
    assert seen["files"] == ["app.js"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
@pytest.mark.unit
def test_the_copy_is_held_while_snyk_runs(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """The lock another run's sweep checks is taken before snyk starts."""
    import fcntl
    import os

    seen = {}
    record = records_tested_files(seen)

    def _side_effect(self, command, **kwargs):
        result = record(self, command, **kwargs)
        fd = os.open(seen["tested"], os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen["lockable"] = True
        except BlockingIOError:
            seen["lockable"] = False
        finally:
            os.close(fd)
        return result

    subprocess_double.side_effect = _side_effect

    scanner.scan(target=populated_source, target_type="source")

    assert seen["lockable"] is False


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_nothing_reached_through_a_link_leaving_the_tree_is_copied(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    caplog,
    tmp_path,
    refusals_set_aside,
):
    """Whether the link is the file itself or a directory above the file.

    The copy holds no link and none of the bytes a link outside the tree leads to.
    The scan set leaves out the link to a file outside, and warns about it; a link
    it keeps, one to a file inside the tree, is left out of the copy and named in a
    debug line.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    marker = b"outside-marker-5c1d"
    outside = tmp_path / "outside"
    (outside / "lib").mkdir(parents=True)
    (outside / "marker.js").write_bytes(b"const m = '" + marker + b"';\n")
    (outside / "lib" / "dep.js").write_bytes(b"const d = '" + marker + b"';\n")
    (populated_source / "linked.js").symlink_to(outside / "marker.js")
    (populated_source / "vendor").symlink_to(outside / "lib", target_is_directory=True)
    (populated_source / "linked_in.js").symlink_to(populated_source / "app.js")
    seen = {}

    def _side_effect(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        tested = Path(
            next(
                arg
                for arg in command[3:]
                if not arg.startswith("-") and arg != destination
            )
        )
        entries = list(tested.rglob("*"))
        seen["links"] = [
            p.relative_to(tested).as_posix() for p in entries if p.is_symlink()
        ]
        seen["contents"] = b"".join(
            p.read_bytes() for p in entries if p.is_file() and not p.is_symlink()
        )
        seen["files"] = sorted(
            p.relative_to(tested).as_posix() for p in entries if p.is_file()
        )
        Path(destination).write_text(snyk_code_document([]), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    subprocess_double.side_effect = _side_effect

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        scanner.scan(target=populated_source, target_type="source")

    assert marker not in seen["contents"]
    assert seen["links"] == []
    assert seen["files"] == ["app.js"]
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert "Not scanning 'linked.js': link leaves the scanned tree" in warnings, (
        warnings
    )
    debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("linked_in.js" in m and "not copied" in m for m in debug), debug


@pytest.mark.integration
def test_files_committed_to_this_runs_output_dir_are_sent_and_ashs_are_not(
    snyk_on_path, subprocess_double, tmp_path, refusals_set_aside
):
    """With the default output directory, .ash/ash_output, inside the tree and the
    refusal set aside: the copy holds the files git tracks there and none of the
    files ASH wrote. A repository must not be able to hide a file from Snyk by
    committing it under ASH's output directory."""
    from tests.unit.workspace.test_execution import _git

    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    for relative in (
        "app.js",
        ".ash/ash_output/hidden/key.js",
        ".ash/ash_output/reports/ash.sarif",
        ".ash/ash_output/ash.log",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("const v = 1;\n", encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "add", "app.js", ".ash/ash_output/hidden/key.js")
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    scanner.scan(target=source, target_type="source")

    assert seen["files"] == [".ash/ash_output/hidden/key.js", "app.js"], seen


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_a_linked_output_dir_inside_the_tree_is_refused_when_the_context_is_built(
    tmp_path,
):
    """A repository that commits its output directory as a link into its own source.

    ``.ash/ash_output -> ../src`` would make every file under src/ resolve into the
    output directory, and the scan set, which recognizes the output directory by
    identity, would leave all of src/ out. ASH does not get that far. A context for
    an output directory that is a link is refused when it is built (the output
    guard, ``fs_guard.register_writable_root``), so no scanner is made and snyk-code
    never sees the layout. The refusal is a ValueError: ``OutputLinkRefused`` is
    one, and so is the ``ValidationError`` that pydantic reports a ValueError from a
    model validator as. Nothing is written through the link.
    """
    source = tmp_path / "repo"
    (source / "src" / "lib").mkdir(parents=True)
    (source / "src" / "lib" / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "top.js").write_text("const t = 1;\n", encoding="utf-8")
    (source / ".ash").mkdir()
    (source / ".ash" / "ash_output").symlink_to("../src", target_is_directory=True)

    with pytest.raises(
        ValueError,
        match=(
            "ash_output is a symlink, and ASH does not write through a symlink "
            "at a directory it writes below"
        ),
    ):
        PluginContext(
            source_dir=source,
            output_dir=source / ".ash" / "ash_output",
            config=get_default_config(),
        )

    assert (source / ".ash" / "ash_output").is_symlink()
    assert sorted(entry.name for entry in (source / "src").iterdir()) == ["lib"]


@pytest.mark.unit
def test_the_same_layout_with_a_directory_is_refused_by_snyk_code_by_its_path(
    snyk_on_path, tmp_path, subprocess_double
):
    """The control for the test above: the output directory spelled the same way, but
    a directory and not a link. Its context is built, and snyk-code then refuses the
    source directory that holds it, by the path the output directory is spelled with:
    nothing is copied or sent. The only difference from the test above is the link."""
    source = tmp_path / "repo"
    (source / "src" / "lib").mkdir(parents=True)
    (source / "src" / "lib" / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "top.js").write_text("const t = 1;\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source, output_dir=output, config=get_default_config()
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())

    with pytest.raises(
        ScannerError, match=r"ASH's output directory '\.ash/ash_output' is inside it"
    ):
        scanner.scan(target=source, target_type="source")

    subprocess_double.assert_not_called()


@pytest.mark.unit
def test_an_empty_scan_set_is_not_reported_as_all_ignored(
    scanner, snyk_on_path, plugin_context, subprocess_double, caplog
):
    """Nothing to send because there is nothing, not because of an ignore path."""
    (plugin_context.source_dir / "empty").mkdir()

    with caplog.at_level(logging.INFO):
        result = scanner.scan(target=plugin_context.source_dir, target_type="source")

    assert result is True
    subprocess_double.assert_not_called()
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "under an ignore path" not in messages, messages
    assert "holds no file to send" in messages, messages


@pytest.mark.unit
def test_all_ignored_says_so(
    scanner,
    snyk_on_path,
    tree_with_vendor,
    subprocess_double,
    caplog,
    refusals_set_aside,
):
    with caplog.at_level(logging.INFO):
        scanner.scan(
            target=tree_with_vendor,
            target_type="source",
            global_ignore_paths=_ignore("**"),
        )

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "Every file in the scan set is under an ignore path" in messages, messages
    assert "holds no file to send" not in messages, messages


@pytest.mark.unit
def test_a_refused_target_is_refused_before_the_copy_is_made(
    scanner, snyk_on_path, tree_with_vendor, subprocess_double
):
    """The refusals come first: for a target they stop, no copy of the scan set is
    made at all, let alone sent."""
    with patch.object(SnykCodeScanner, "_stage_source", autospec=True) as stage:
        with pytest.raises(ScannerError, match="global_settings.ignore_paths"):
            scanner.scan(
                target=tree_with_vendor,
                target_type="source",
                global_ignore_paths=_ignore("vendor/**"),
            )

    stage.assert_not_called()
    subprocess_double.assert_not_called()


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    """A TMPDIR of the test's own, so a sweep sees only the copies planted in it."""
    import tempfile

    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
@pytest.mark.unit
def test_the_sweep_leaves_another_users_copies(
    scanner, snyk_on_path, populated_source, subprocess_double, temp_root, monkeypatch
):
    """Only this user's copies are removed, however old and unheld."""
    real_uid = snyk_code_scanner.os.getuid()
    stale = _stale_copy(
        temp_root, "ash-snyk-code-other", scanner._effective_scan_timeout() + 60
    )
    monkeypatch.setattr(snyk_code_scanner.os, "getuid", lambda: real_uid + 1)
    subprocess_double.side_effect = records_tested_files({})

    scanner.scan(target=populated_source, target_type="source")

    assert stale.exists(), "a copy another user owns was removed"


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_the_sweep_does_not_follow_a_link_named_like_a_copy(
    scanner, snyk_on_path, populated_source, subprocess_double, temp_root, tmp_path
):
    """A symlink with a copy's name is not a copy: neither it nor its target goes."""
    import os
    import time

    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep\n", encoding="utf-8")
    then = time.time() - scanner._effective_scan_timeout() - 60
    os.utime(victim, (then, then))
    link = temp_root / "ash-snyk-code-link"
    link.symlink_to(victim, target_is_directory=True)
    subprocess_double.side_effect = records_tested_files({})

    scanner.scan(target=populated_source, target_type="source")

    assert (victim / "keep.txt").exists()
    assert link.is_symlink()


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
@pytest.mark.unit
def test_with_no_scan_timeout_a_copy_is_swept_after_an_hour(
    plugin_context, snyk_on_path, populated_source, subprocess_double, temp_root
):
    """scan_timeout null leaves the scan unbounded; the sweep then waits an hour."""
    scanner = SnykCodeScanner(
        context=plugin_context,
        config=SnykCodeScannerConfig(
            options=SnykCodeScannerConfigOptions(scan_timeout=None)
        ),
    )
    assert scanner._effective_scan_timeout() is None
    half = _stale_copy(temp_root, "ash-snyk-code-half", 1801)
    hour = _stale_copy(temp_root, "ash-snyk-code-hour", 3601)
    subprocess_double.side_effect = records_tested_files({})

    scanner.scan(target=populated_source, target_type="source")

    assert half.exists(), "a copy younger than the hour was removed"
    assert not hour.exists(), "a copy older than the hour was kept"


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
def test_a_file_listed_below_a_symlinked_directory_is_not_copied(
    scanner,
    snyk_on_path,
    populated_source,
    subprocess_double,
    caplog,
    tmp_path,
    monkeypatch,
    refusals_set_aside,
):
    """The directory-link case through the copy itself.

    scan_set does not descend into a symlinked directory, so the case is forced:
    the scan set is made to list vendor/lib/dep.js below vendor -> outside. The copy
    refuses it, logs it, and none of its bytes reach Snyk.
    """
    from automated_security_helper.utils import get_scan_set
    from automated_security_helper.utils.log import ASH_LOGGER

    marker = b"outside-dir-marker-77ab"
    outside = tmp_path / "outside"
    (outside / "lib").mkdir(parents=True)
    (outside / "lib" / "dep.js").write_bytes(b"const d = '" + marker + b"';\n")
    (populated_source / "vendor").symlink_to(outside, target_is_directory=True)
    real_scan_set = get_scan_set.scan_set
    listed = populated_source / "vendor" / "lib" / "dep.js"

    def _with_the_linked_file(*args, **kwargs):
        return [*real_scan_set(*args, **kwargs), str(listed)]

    monkeypatch.setattr(get_scan_set, "scan_set", _with_the_linked_file)
    seen = {}

    def _side_effect(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        tested = Path(
            next(
                arg
                for arg in command[3:]
                if not arg.startswith("-") and arg != destination
            )
        )
        seen["contents"] = b"".join(
            p.read_bytes() for p in tested.rglob("*") if p.is_file()
        )
        seen["files"] = sorted(
            p.relative_to(tested).as_posix() for p in tested.rglob("*") if p.is_file()
        )
        Path(destination).write_text(snyk_code_document([]), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    subprocess_double.side_effect = _side_effect

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        scanner.scan(target=populated_source, target_type="source")

    assert marker not in seen["contents"]
    assert seen["files"] == ["app.js"]
    debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("vendor/lib/dep.js" in m and "not copied" in m for m in debug), debug


@pytest.mark.unit
def test_a_name_ending_in_whitespace_is_copied_under_its_own_name(
    scanner, snyk_on_path, plugin_context, subprocess_double, caplog
):
    """``a.js `` (trailing space) is a different file from ``a.js``.

    The scan-set names were stripped of all surrounding whitespace, so "a.js " was
    read as "a.js": that file was copied twice, the other one never, and the log
    counted two copied files for one name.
    """
    source = plugin_context.source_dir
    (source / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "a.js ").write_text("const b = 2;\n", encoding="utf-8")
    seen = {}
    subprocess_double.side_effect = records_tested_files(seen)

    with caplog.at_level(logging.INFO):
        scanner.scan(target=source, target_type="source")

    assert seen["files"] == ["a.js", "a.js "], seen["files"]
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "Testing a copy of 2 files" in messages, messages
