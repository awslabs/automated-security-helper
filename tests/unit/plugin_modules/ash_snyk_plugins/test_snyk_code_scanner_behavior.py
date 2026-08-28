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
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
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
                                    "shortDescription": {"text": "Hardcoded credential"},
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


def writes_sarif(sarif_text, exit_code=0):
    """side_effect that writes SARIF to the path named in the argv it receives.

    Deriving the destination from ``--sarif-file-output=`` rather than
    recomputing it means a scanner that stops passing that flag, or passes a
    different one, makes these tests fail instead of silently finding nothing.
    """

    def _side_effect(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1]
            for arg in command
            if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        Path(destination).write_text(sarif_text, encoding="utf-8")
        self.exit_code = max(self.exit_code, exit_code)
        return {"stdout": "", "stderr": "", "returncode": exit_code}

    return _side_effect


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_scanner_wires_the_snyk_code_test_command(scanner):
    """model_post_init sets the command, subcommands and SARIF output flag."""
    assert scanner.command == "snyk"
    assert scanner.subcommands == ["code", "test"]
    assert scanner.tool_type == ScannerToolType.SAST
    assert scanner.args.output_arg == "--sarif-file-output"
    # Snyk takes the target positionally, so there is no scan-path flag.
    assert scanner.args.scan_path_arg is None
    assert scanner.args.format_arg is None


def test_config_defaults_are_applied_when_config_is_none(plugin_context):
    scanner = SnykCodeScanner(context=plugin_context)

    assert scanner.config is not None
    assert scanner.config.name == "snyk-code"
    assert scanner.config.enabled is True


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


def test_offline_mode_fails_dependency_validation(scanner):
    """Snyk needs the network, so offline mode disqualifies it outright."""
    with patch.object(
        SnykCodeScanner, "_is_offline_mode", autospec=True, return_value=True
    ):
        assert scanner.validate_plugin_dependencies() is False


def test_missing_snyk_binary_fails_dependency_validation(scanner, monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: None)

    assert scanner.validate_plugin_dependencies() is False


def test_snyk_token_in_environment_satisfies_credential_check(
    scanner, snyk_on_path, caplog
):
    """With SNYK_TOKEN set, no credential warning is emitted."""
    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is True

    assert not any(
        "No Snyk credentials found" in record.message for record in caplog.records
    )


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
# Severity threshold translation
# ---------------------------------------------------------------------------

# Snyk's --severity-threshold accepts low/medium/high and has no "critical"
# level, so ASH's CRITICAL is mapped down to high. HIGH and CRITICAL therefore
# share an outcome on purpose; test_severity_ladder_is_not_vacuous pins that
# the rest of the ladder does not collapse with them.
SEVERITY_LADDER = {
    None: None,
    "ALL": None,
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "high",
}


@pytest.mark.parametrize("threshold, expected", sorted(
    SEVERITY_LADDER.items(), key=lambda kv: str(kv[0])
))
def test_severity_threshold_translates_to_the_snyk_flag(
    plugin_context, threshold, expected
):
    """Each ASH threshold maps to the snyk value, or to no flag at all.

    _process_config_options appends rather than replaces and runs both at
    construction and from _resolve_arguments, so the assertion is on the
    distinct values emitted, not on how many times they appear. See
    test_severity_flag_is_appended_once_per_process_config_options_call.
    """
    scanner = SnykCodeScanner(
        context=plugin_context,
        config=SnykCodeScannerConfig(
            options=SnykCodeScannerConfigOptions(severity_threshold=threshold)
        ),
    )

    values = {
        arg.value
        for arg in scanner.args.extra_args
        if arg.key == "--severity-threshold"
    }
    if expected is None:
        assert values == set(), (
            f"threshold {threshold!r} must not emit --severity-threshold; got {values}"
        )
    else:
        assert values == {expected}, (
            f"threshold {threshold!r} should map to {expected!r}; got {values}"
        )


def test_severity_flag_is_appended_once_per_process_config_options_call(
    plugin_context, tmp_path
):
    """The severity flag accumulates; it is not replaced.

    ScannerPluginBase.model_post_init calls _process_config_options once, and
    _resolve_arguments calls it again, so a single resolved argv carries the
    flag twice. snyk takes the last value, which is why this is benign, but the
    duplication is real and pinning it keeps a future de-duplication honest.
    """
    scanner = SnykCodeScanner(
        context=plugin_context,
        config=SnykCodeScannerConfig(
            options=SnykCodeScannerConfigOptions(severity_threshold="MEDIUM")
        ),
    )
    assert len(scanner.args.extra_args) == 1, (
        "construction should contribute exactly one --severity-threshold"
    )

    target = tmp_path / "scan-me"
    target.mkdir()
    args = scanner._resolve_arguments(target=target, results_file=None)

    occurrences = [a for a in args if a == "--severity-threshold"]
    assert len(occurrences) == 2, (
        f"expected the construction-time flag plus the resolve-time one, got "
        f"{len(occurrences)}: {args}"
    )
    # Every occurrence carries the same value, so the effective setting is
    # unambiguous regardless of which one snyk honors.
    values = {args[i + 1] for i, a in enumerate(args) if a == "--severity-threshold"}
    assert values == {"medium"}


def test_severity_ladder_is_not_vacuous():
    """The ladder must not collapse to a single outcome.

    A parametrized threshold table where every position expects the same thing
    tests one case N times while looking exhaustive. Four distinct outcomes
    across six positions is the intended shape: ALL/None both suppress the
    flag, and HIGH/CRITICAL both map to high because snyk has no critical.
    """
    outcomes = list(SEVERITY_LADDER.values())
    assert len(set(outcomes)) == 4, (
        f"expected 4 distinct outcomes across the ladder, got {sorted(set(map(str, outcomes)))}"
    )
    assert SEVERITY_LADDER["HIGH"] == SEVERITY_LADDER["CRITICAL"] == "high"
    assert SEVERITY_LADDER["LOW"] != SEVERITY_LADDER["MEDIUM"]
    assert SEVERITY_LADDER[None] is SEVERITY_LADDER["ALL"] is None


# ---------------------------------------------------------------------------
# Argument resolution
# ---------------------------------------------------------------------------


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


def test_resolve_arguments_omits_the_output_flag_when_no_results_file(
    scanner, tmp_path
):
    target = tmp_path / "scan-me"
    target.mkdir()

    args = scanner._resolve_arguments(target=target, results_file=None)

    assert not any(arg.startswith(SARIF_OUTPUT_FLAG) for arg in args)


def test_valueless_extra_args_are_emitted_as_bare_flags(plugin_context, tmp_path):
    """An extra arg with value None becomes one token, not a token pair."""
    from automated_security_helper.models.core import ToolExtraArg

    scanner = SnykCodeScanner(
        context=plugin_context, config=SnykCodeScannerConfig()
    )
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


def test_empty_target_returns_true_without_running_snyk(
    scanner, snyk_on_path, subprocess_double
):
    """An empty target is a no-op success, not a scanner failure."""
    result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is True
    subprocess_double.assert_not_called()
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_unsatisfied_dependencies_return_false(
    scanner, populated_source, subprocess_double, monkeypatch
):
    """Without the snyk binary the scanner reports skipped, not clean."""
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: None)

    result = scanner.scan(target=populated_source, target_type="source")

    assert result is False
    subprocess_double.assert_not_called()


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
    # endTimeUtc is None because this scanner builds the Invocation before it
    # calls _post_scan, which is what sets self.end_time. CfnNagScanner does
    # the two in the opposite order and does record an end time. Pinned here so
    # that reordering the two calls surfaces as a test change rather than an
    # unnoticed shift in report contents.
    assert invocation.endTimeUtc is None
    assert scanner.end_time is not None, (
        "the scanner itself does learn its end time -- just after the "
        "Invocation has already been constructed"
    )


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


def test_nonzero_exit_code_raises_scanner_error(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """An exit code snyk uses for real failures aborts the scan loudly."""
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=2)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=populated_source, target_type="source")

    assert "Snyk Code scan failed" in str(excinfo.value)
    assert "exit code 2" in str(excinfo.value)


@pytest.mark.xfail(
    strict=True,
    raises=ScannerError,
    reason=(
        "scan() raises on any non-zero exit code, but snyk exits 1 when it finds "
        "actionable items. _run_subprocess stores that 1 in self.exit_code via "
        "_process_command_response, so the `if self.exit_code != 0` check fires "
        "before the _post_scan override that exists to reset 1 back to 0 -- and "
        "before the base class's own success_exit_codes = {0, 1}. A snyk run that "
        "actually finds something therefore reports a scanner failure instead of "
        "returning its findings. Remove this xfail once the check excludes 1."
    ),
)
def test_exit_code_one_means_findings_not_failure(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """Snyk exits 1 when it finds issues; that is a successful scan.

    The _post_scan override in this module documents exactly this ("Snyk
    returns 1 on a successful scan when actionable items are detected") but
    never gets the chance to act on it during a real scan.
    """
    subprocess_double.side_effect = writes_sarif(snyk_sarif(), exit_code=1)

    report = scanner.scan(target=populated_source, target_type="source")

    assert len(report.runs[0].results) == 1


def test_post_scan_resets_exit_code_one_to_zero(scanner, snyk_on_path):
    """The _post_scan override normalizes snyk's findings-detected exit code.

    Reached here through the empty-target path, which calls _post_scan before
    any exit-code check.
    """
    scanner.exit_code = 1

    result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is True
    assert scanner.exit_code == 0, (
        "exit code 1 must be normalized to 0 so a findings-detected run is not "
        "reported as a scanner failure"
    )


def test_post_scan_leaves_other_exit_codes_alone(scanner, snyk_on_path):
    """Only 1 is normalized; a genuine failure code is preserved."""
    scanner.exit_code = 3

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.exit_code == 3


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


def test_unreadable_results_file_is_wrapped_in_scanner_error(
    scanner, snyk_on_path, populated_source, subprocess_double
):
    """An error outside the SARIF try block surfaces as ScannerError."""

    def _write_invalid_json(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1]
            for arg in command
            if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        # json.load() happens before the try block that catches parse errors.
        Path(destination).write_text("{not valid json at all", encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    subprocess_double.side_effect = _write_invalid_json

    with pytest.raises(ScannerError, match="Snyk Code scan failed"):
        scanner.scan(target=populated_source, target_type="source")
