"""Behavior tests for :class:`CfnNagScanner`.

cfn_nag is a Ruby tool and is not installed here, so
``validate_plugin_dependencies()`` returns False and the scanner short-circuits
before it ever walks the scan set. Every test below patches exactly two seams
-- the dependency probe and ``_run_subprocess`` -- and drives the real scan
body over real files on disk.

``_run_subprocess`` is patched with ``autospec=True`` so a call that passes an
argument the real method does not accept fails the test instead of being
absorbed by a permissive double.

The central risk in this module is a scan that completes having parsed nothing:
cfn_nag writing no stdout, or a SARIF parse failure, both leave the report with
zero results and read as a clean template. ``test_findings_from_stdout_are_
merged_into_the_report`` pins the positive direction (non-empty tool output ->
non-empty findings) and the empty/garbage-stdout tests pin the negative one
without letting it masquerade as a pass.
"""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER

CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

SECOND_CFN_TEMPLATE = """Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: placeholder-queue
"""

NON_CFN_YAML = "services:\n  web:\n    image: nginx\n"

MALFORMED_YAML = "Resources:\n  - this: [is\n   not: valid yaml\n"

# A Resources mapping this repository's pydantic model cannot represent. It is
# CloudFormation -- the Resources key holds a mapping -- so it is a failed target
# rather than the not-a-template skip.
UNMODELABLE_CFN = "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"


def cfn_nag_sarif(rule_id="F38", uri="MyRole.yaml", start_line=3):
    """A SARIF document shaped the way cfn_nag emits one."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {
                                        "text": "IAM policy should not allow *"
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": f"{rule_id} triggered on {uri}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": start_line},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def cfn_nag_sarif_no_results():
    """A SARIF document shaped the way cfn_nag emits one for an unevaluated template.

    This is the exact shape measured from ``cfn_nag_scan --output-format sarif`` on a
    template carrying a ``!Ref`` to an undeclared logical id: a complete document, a
    fully populated rule driver, and an empty result array. It is byte-for-byte the
    same size as the document a genuinely clean template produces, which is why the
    exit code is the only thing that can tell them apart. Reproduce with::

        cfn_nag_scan --print-suppression --output-format sarif --input-path <template>
    """
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {"id": "F38", "shortDescription": {"text": "a rule"}},
                                {"id": "W48", "shortDescription": {"text": "another"}},
                            ],
                        }
                    },
                    "results": [],
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
def scanner(plugin_context):
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def deps_available():
    """Report the Ruby cfn_nag binary as present without installing it."""
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ) as probe:
        yield probe


@pytest.fixture
def subprocess_double():
    """Patch the subprocess boundary, preserving the real signature."""
    with patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double:
        double.return_value = {"stdout": "", "stderr": "", "returncode": 0}
        yield double


def stdout_sequence(*payloads):
    """Return a side_effect that yields one payload per subprocess call."""
    remaining = list(payloads)

    def _side_effect(self, **kwargs):
        return {
            "stdout": remaining.pop(0) if remaining else "",
            "stderr": "",
            "returncode": 0,
        }

    return _side_effect


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_scanner_configures_its_command_and_tool_type(scanner):
    """model_post_init wires the Ruby entrypoint and the IAC tool type."""
    assert scanner.command == "cfn_nag_scan"
    assert scanner.tool_type == ScannerToolType.IAC
    assert scanner.args.format_arg == "--output-format"
    assert scanner.args.format_arg_value == "sarif"
    assert scanner.args.scan_path_arg == "--input-path"

    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--print-suppression" in keys
    assert "--rule-directory" in keys
    rule_dir = next(a for a in scanner.args.extra_args if a.key == "--rule-directory")
    assert rule_dir.value.endswith("appsec_cfn_rules")


def test_ignore_fatal_is_not_passed(scanner):
    """``--ignore-fatal`` must be absent, and its absence is the whole signal.

    The inverse of this assertion used to stand here. cfn_nag's exit status is its
    failing-violation count, and a FATAL violation -- what cfn-model raises for an
    unresolved Ref or GetAtt -- carries no logical resource ids, so SARIF renders
    it as nothing at all. ``--ignore-fatal`` additionally prunes it from the
    failure count, which drops the exit status to 0 and leaves a document
    indistinguishable from a clean template. Measured on both shapes with::

        cfn_nag_scan --print-suppression [--ignore-fatal] \
            --output-format sarif --input-path <template>

    With the flag, an unresolved-Ref template and a clean template both give exit 0
    and zero results. Without it, the unresolved-Ref template gives exit 1 and zero
    results while the clean one gives exit 0, so the pair is separable.
    """
    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--ignore-fatal" not in keys, (
        "passing --ignore-fatal erases the only signal that distinguishes a "
        f"template cfn_nag could not parse from a clean one; keys were {keys}"
    )


def test_custom_rule_exceptions_are_isolated(scanner):
    """A raising custom rule must cost that rule, not the template's whole scan.

    cfn_nag's CustomRuleLoader re-raises a rule's exception unless this flag is
    passed, and the exception escapes every rescue clause above it, so the process
    dies before rendering any output. The blast radius is every rule's verdict on
    that template, not just the broken rule's.
    """
    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--isolate-custom-rule-exceptions" in keys, (
        f"a defect in one shipped rule must not destroy the scan; keys were {keys}"
    )


@pytest.mark.parametrize(
    "level, verbose_expected",
    [(logging.DEBUG, True), (logging.INFO, False), (logging.WARNING, False)],
)
def test_verbose_flag_is_added_only_at_debug_level(
    plugin_context, monkeypatch, level, verbose_expected
):
    """``--verbose`` is passed to cfn_nag only when ASH itself is at DEBUG."""
    monkeypatch.setattr(ASH_LOGGER, "level", level)

    scanner = CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())
    keys = [arg.key for arg in scanner.args.extra_args]

    assert ("--verbose" in keys) is verbose_expected, (
        f"at level {logging.getLevelName(level)} expected verbose="
        f"{verbose_expected}; extra_args keys were {keys}"
    )


def test_config_defaults_are_applied_when_config_is_none(plugin_context):
    """A scanner built without a config gets the cfn-nag default config."""
    scanner = CfnNagScanner(context=plugin_context)

    assert scanner.config is not None
    assert scanner.config.name == "cfn-nag"
    assert scanner.config.enabled is True


def test_execute_scan_stub_raises_not_implemented(scanner):
    """The abstract hook is unreachable because scan() is overridden."""
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    raises=ValidationError,
    reason=(
        "get_shortest_name() returns its input unchanged when the path does not "
        "exist, so a Path argument comes back as a Path rather than the str the "
        "final 'return Path(input).as_posix()' would produce. ArtifactLocation.uri "
        "requires a str, so scan() raises ValidationError at the report-skeleton "
        "step and never reaches its own 'target is empty or doesn't exist' branch. "
        "Remove this xfail once get_shortest_name normalizes its early return."
    ),
)
def test_missing_target_directory_returns_an_empty_report(
    scanner, deps_available, subprocess_double, tmp_path
):
    """A target that does not exist should yield a report, not an exception.

    The scan body has an explicit branch for a missing target, but it is
    unreachable today: the report skeleton is built first and passes the target
    through get_shortest_name, which returns a Path for a non-existent input.
    """
    report = scanner.scan(target=tmp_path / "does-not-exist", target_type="converted")

    assert report.runs[0].results == []
    subprocess_double.assert_not_called()


def test_get_shortest_name_early_return_does_not_normalize_to_str():
    """Pin the root cause of the xfail above at its own source.

    The final ``return Path(input).as_posix()`` yields a str, but the
    not-exists early return hands back whatever it was given. Callers that feed
    the result into a pydantic str field therefore work for existing paths and
    fail for missing ones.
    """
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    existing = get_shortest_name(input=Path.cwd())
    assert isinstance(existing, str)

    missing = get_shortest_name(input=Path.cwd() / "no-such-file-exists-here")
    assert isinstance(missing, Path), (
        "if this now returns str, get_shortest_name was fixed -- drop the "
        "xfail on test_missing_target_directory_returns_an_empty_report"
    )


def test_empty_target_directory_returns_an_empty_report(
    scanner, deps_available, subprocess_double
):
    """An existing but empty target directory is skipped before _pre_scan."""
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert report.runs[0].tool.driver.name == "cfn_nag"
    subprocess_double.assert_not_called()
    # The skip is announced on stderr so the run summary can show it.
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_unsatisfied_dependencies_returns_false(scanner, subprocess_double):
    """With the Ruby binary absent the scanner reports False, not a report.

    False is how the executor distinguishes "skipped" from "scanned clean";
    returning an empty report here would publish a clean result for a scanner
    that never ran.
    """
    (scanner.context.work_dir / "template.yaml").write_text(CFN_TEMPLATE)

    with patch.object(
        CfnNagScanner,
        "validate_plugin_dependencies",
        autospec=True,
        return_value=False,
    ):
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    subprocess_double.assert_not_called()


def test_dependency_flag_is_rechecked_after_pre_scan(scanner, subprocess_double):
    """The post-_pre_scan dependency guard also returns False.

    _pre_scan normally returns False when dependencies are missing; this
    covers the independent second check, which is what protects against a
    _pre_scan override that forgets to set the flag.
    """
    (scanner.context.work_dir / "template.yaml").write_text(CFN_TEMPLATE)

    with patch.object(CfnNagScanner, "_pre_scan", autospec=True, return_value=True):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    subprocess_double.assert_not_called()


def test_target_with_no_yaml_or_json_files_returns_an_empty_report(
    scanner, deps_available, subprocess_double
):
    """Files that cannot be CloudFormation are filtered before any subprocess."""
    (scanner.context.work_dir / "notes.txt").write_text("nothing to scan here")
    (scanner.context.work_dir / "script.py").write_text("print('hello')\n")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    subprocess_double.assert_not_called()
    assert any("No JSON/YAML files found" in err for err in scanner.errors)


# ---------------------------------------------------------------------------
# The scan body
# ---------------------------------------------------------------------------


def test_findings_from_stdout_are_merged_into_the_report(
    scanner, deps_available, subprocess_double
):
    """Non-empty cfn_nag output produces non-empty findings.

    This is the assertion that separates "scanned and found nothing" from
    "parsed nothing and reported clean".
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1
    results = report.runs[0].results
    assert len(results) == 1, (
        f"expected the one cfn_nag result to survive the merge, got {len(results)}"
    )
    assert results[0].ruleId == "F38"
    assert "F38 triggered on" in results[0].message.root.text


def test_every_template_is_scanned_and_all_findings_survive(
    scanner, deps_available, subprocess_double
):
    """Two templates mean two subprocess calls and two merged findings."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.json").write_text(
        json.dumps({"Resources": {"MyQueue": {"Type": "AWS::SQS::Queue"}}})
    )
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml"),
        cfn_nag_sarif(rule_id="W48", uri="queue.json"),
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 2
    rule_ids = sorted(r.ruleId for r in report.runs[0].results)
    assert rule_ids == ["F38", "W48"], (
        f"a finding was dropped during the merge; got {rule_ids}"
    )


def test_each_template_is_passed_to_the_subprocess_as_the_input_path(
    scanner, deps_available, subprocess_double
):
    """The resolved argv names the template, not the containing directory."""
    template = scanner.context.work_dir / "role.yaml"
    template.write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    command = subprocess_double.call_args.kwargs["command"]
    assert command[0] == "cfn_nag_scan"
    assert "--input-path" in command
    assert command[command.index("--input-path") + 1] == template.as_posix()
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "sarif"


def test_non_cloudformation_yaml_is_not_sent_to_the_scanner(
    scanner, deps_available, subprocess_double
):
    """A YAML file with no Resources block is filtered out, not scanned."""
    (scanner.context.work_dir / "compose.yaml").write_text(NON_CFN_YAML)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert report.runs[0].results == []


def test_unparseable_yaml_is_skipped_without_failing_the_scan(
    scanner, deps_available, subprocess_double
):
    """A YAML syntax error in one candidate file does not abort the others."""
    (scanner.context.work_dir / "broken.yaml").write_text(MALFORMED_YAML)
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    # Only the valid template reached the scanner.
    assert subprocess_double.call_count == 1
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]


def test_empty_stdout_is_a_hard_scanner_failure(
    scanner, deps_available, subprocess_double, caplog
):
    """cfn_nag writing nothing is a tool fault, so the scanner fails, not the target.

    This test's predecessor asserted the opposite -- that the scan returned a report
    and raised nothing -- and that is the behavior being corrected. Counting it as
    one failed target among many left ``targets_failed < targets_attempted``, so a
    repository with one crashed template and nine clean ones reported PASSED with
    the crashed template's findings silently absent. An invocation that renders zero
    bytes did not fail to find anything; it failed to run, and the process dying
    before rendering is a property of the tool rather than of that one template.

    The subprocess is still invoked -- the emptiness is in its output, which is
    exactly the case that must not silently become a passing scan.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {"stdout": "   ", "stderr": "", "returncode": 0}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1
    assert "role.yaml" in str(excinfo.value)
    assert any("returned no stdout" in record.message for record in caplog.records), (
        "an empty-stdout scan must leave a trace in the log"
    )


def test_non_sarif_stdout_is_warned_about_and_skipped(
    scanner, deps_available, subprocess_double, caplog
):
    """Output that is not SARIF is logged as a parse failure."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": "Fatal error: could not load rule directory",
        "stderr": "",
        "returncode": 1,
    }

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any(
        "Failed to parse CFN Nag results as SARIF" in record.message
        for record in caplog.records
    ), f"expected a parse warning; got {[r.message for r in caplog.records]}"


def test_partial_failure_keeps_the_findings_that_did_parse(
    scanner, deps_available, subprocess_double
):
    """One unparseable template does not discard another's findings."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        "not json at all", cfn_nag_sarif(rule_id="W48", uri="queue.yaml")
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["W48"]


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------


def test_sarif_output_file_is_written_next_to_the_results(
    scanner, deps_available, subprocess_double
):
    """The merged report is persisted to ``cfn_nag.sarif`` under results_dir."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    output_file = Path(scanner.results_dir) / "converted" / "cfn_nag.sarif"
    assert output_file.is_file(), f"{output_file} was not written"
    written = json.loads(output_file.read_text(encoding="utf-8"))
    rule_ids = [r["ruleId"] for r in written["runs"][0]["results"]]
    assert rule_ids == ["F38"], (
        f"the persisted file must contain the findings, not an empty run; got {written}"
    )


def test_invocation_replaces_the_placeholder_and_records_the_exit_code(
    scanner, deps_available, subprocess_double
):
    """The final report carries exactly one invocation describing the ASH run."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif())

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocations = report.runs[0].invocations
    assert len(invocations) == 1
    invocation = invocations[0]
    assert invocation.commandLine == "ash-CFN Nag-scanner"
    assert "--target" in invocation.arguments
    assert invocation.exitCode == scanner.exit_code
    assert invocation.executionSuccessful is True
    assert invocation.startTimeUtc is not None
    assert invocation.endTimeUtc is not None


@pytest.mark.parametrize(
    "exit_code, successful",
    [(0, True), (1, True), (2, False), (137, False)],
)
def test_execution_successful_treats_zero_and_one_as_success(
    scanner, deps_available, subprocess_double, exit_code, successful
):
    """cfn_nag exits 1 when it finds violations, so 1 is still a success."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif())
    scanner.exit_code = exit_code

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.executionSuccessful is successful
    assert invocation.exitCode == exit_code


# ---------------------------------------------------------------------------
# Failure wrapping
# ---------------------------------------------------------------------------


def test_subprocess_failure_is_wrapped_in_scanner_error(
    scanner, deps_available, subprocess_double
):
    """An unexpected error inside the scan body surfaces as ScannerError."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = OSError("cfn_nag_scan died")

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert "CfnNagScanner failed" in str(excinfo.value)
    assert "cfn_nag_scan died" in str(excinfo.value)


# ---------------------------------------------------------------------------
# source vs converted target selection
# ---------------------------------------------------------------------------


def test_source_target_type_scans_the_source_tree(
    scanner, deps_available, subprocess_double
):
    """A ``source`` scan enumerates the source dir, not the work dir.

    The two branches build the candidate list differently, so a template that
    exists only in work_dir must not be picked up by a source scan.
    """
    (scanner.context.source_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "should-not-be-scanned.yaml").write_text(
        SECOND_CFN_TEMPLATE
    )
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml")
    )

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    scanned = [
        call.kwargs["command"][call.kwargs["command"].index("--input-path") + 1]
        for call in subprocess_double.call_args_list
    ]
    assert any(path.endswith("role.yaml") for path in scanned), (
        f"the source template was never scanned; scanned={scanned}"
    )
    assert not any("should-not-be-scanned" in path for path in scanned), (
        f"a work_dir template leaked into a source scan; scanned={scanned}"
    )
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]


# ---------------------------------------------------------------------------
# Failed targets
#
# cfn_nag failing on a template produces the same empty report as a template with
# nothing wrong in it. The only thing that separates them is the target counters the
# executor reads off the plugin, so these assert the counters rather than the report.
# ---------------------------------------------------------------------------


def _status_for(scanner_plugin):
    """Run the two executor lines that copy the counters, then compute status."""
    from automated_security_helper.core.phases.scanner_executor import (
        _non_negative_int_attr,
        _target_count_attr,
    )
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    container = ScanResultsContainer(scanner_name="cfn-nag")
    container.targets_attempted = _target_count_attr(
        scanner_plugin, "targets_attempted"
    )
    container.targets_failed = _non_negative_int_attr(scanner_plugin, "targets_failed")
    return container.determine_status("MEDIUM"), container


def test_empty_stdout_is_recorded_as_a_failed_target_and_then_raises(
    scanner, deps_available, subprocess_double, caplog
):
    """cfn_nag producing nothing must not resolve to a passing scan.

    The counter assertions are the ones this test always made and they still hold.
    What changed is the tail: the scan now raises rather than returning, because the
    counters alone only reach ERROR when *every* template is in this state. The
    counters are still set so the failure is also visible to
    ``--fail-on-incomplete-scanners``, which reads ``targets_failed``.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {"stdout": "   ", "stderr": "", "returncode": 1}

    with caplog.at_level(logging.ERROR):
        with pytest.raises(ScannerError):
            scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any("role.yaml" in err for err in scanner.errors), scanner.errors
    assert any("NOT a clean scan" in record.message for record in caplog.records), (
        f"a run that evaluated no rule must say so; got {[r.message for r in caplog.records]}"
    )

    status, container = _status_for(scanner)
    assert not container.scan_succeeded
    assert status == ScannerStatus.ERROR


def test_one_empty_stdout_among_two_templates_still_fails_the_scanner(
    scanner, deps_available, subprocess_double
):
    """The case the counters alone cannot reach.

    One crashed template of two leaves ``targets_failed`` (1) below
    ``targets_attempted`` (2), so ``determine_status`` falls through to the severity
    gate over the surviving findings and reports PASSED. This is the specific hole
    that makes an empty-stdout invocation a scanner failure rather than a target
    statistic, and it is why the two tests above were inverted.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml"), ""
    )

    with pytest.raises(ScannerError):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    # Both templates were attempted before the verdict; only the crashed one failed,
    # which is precisely the ratio that used to read as a successful scan.
    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1)
    assert _status_for(scanner)[1].scan_succeeded, (
        "the counters alone still read this as a succeeded scan, which is why the "
        "raise is the load-bearing part of the fix"
    )


def test_a_template_the_model_rejects_is_counted_as_a_failed_target(
    scanner, deps_available, subprocess_double, caplog
):
    """A Resources mapping ASH cannot model is a failure, not an un-counted skip.

    Before the sentinel was split, ``get_model_from_template`` answered None for
    this file just as it does for a file that is not CloudFormation, and the
    ``continue`` sat above ``targets_attempted += 1``. A scan set in which every
    template tripped the model therefore ended at zero attempts, which the
    container reports as SKIPPED with exit code 0 -- and SKIPPED is on the
    completeness allowlist on the grounds that the scanner was not selected, which
    is not what happened.
    """
    (scanner.context.work_dir / "unmodelable.yaml").write_text(UNMODELABLE_CFN)

    with caplog.at_level(logging.ERROR):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert any("unmodelable.yaml" in err for err in scanner.errors), scanner.errors
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


def test_a_non_zero_exit_with_no_results_is_a_failed_target(
    scanner, deps_available, subprocess_double, caplog
):
    """The pruned-FATAL shape: schema-valid SARIF, zero results, non-zero exit.

    cfn-model raises on a ``!Ref`` or ``!GetAtt`` to a logical id not declared in
    the file, cfn_nag turns that into a FATAL violation, and a FATAL violation
    carries no logical resource ids -- so the SARIF renderer, which iterates those
    ids, emits nothing for it. The document is complete and its rule driver is fully
    populated. No rule ran against the template, and without this guard the run is
    indistinguishable from a compliant one.
    """
    (scanner.context.work_dir / "badref.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": cfn_nag_sarif_no_results(),
        "stderr": "",
        "returncode": 1,
    }

    with caplog.at_level(logging.ERROR):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert any("badref.yaml" in err for err in scanner.errors), scanner.errors
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


def test_a_clean_template_with_no_results_is_not_a_failed_target(
    scanner, deps_available, subprocess_double
):
    """Positive control for the guard above: the same empty SARIF at exit 0 passes.

    Without this the guard could be satisfied by rejecting every zero-result run,
    which would fail every compliant template in existence. Measured: a compliant
    template and an unresolved-Ref template produce SARIF documents of identical
    size with zero results each, and differ only in the exit status.
    """
    (scanner.context.work_dir / "clean.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": cfn_nag_sarif_no_results(),
        "stderr": "",
        "returncode": 0,
    }

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert _status_for(scanner)[1].scan_succeeded


def test_unparseable_stdout_is_recorded_as_a_failed_target(
    scanner, deps_available, subprocess_double
):
    """Output that is not SARIF leaves the template unevaluated, same as no output."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": "Fatal error: could not load rule directory",
        "stderr": "",
        "returncode": 1,
    }

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


def test_a_template_that_scanned_is_not_counted_as_failed(
    scanner, deps_available, subprocess_double
):
    """Positive control: the same path with usable output records no failure."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert _status_for(scanner)[1].scan_succeeded


def test_one_failure_among_two_templates_is_not_a_failed_scan(
    scanner, deps_available, subprocess_double
):
    """A partial failure is counted, but the run as a whole still succeeded."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        "not json at all", cfn_nag_sarif(rule_id="W48", uri="queue.yaml")
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1)
    assert _status_for(scanner)[1].scan_succeeded


def test_non_cloudformation_yaml_is_not_counted_as_a_target(
    scanner, deps_available, subprocess_double
):
    """A YAML file that is not a template is a skip, not an attempt or a failure."""
    (scanner.context.work_dir / "compose.yaml").write_text(NON_CFN_YAML)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    assert _status_for(scanner)[1].scan_succeeded
