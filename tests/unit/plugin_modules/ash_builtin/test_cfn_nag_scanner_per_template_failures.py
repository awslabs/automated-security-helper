"""cfn-nag: one template's trouble costs that template, and nothing is hidden.

Pinned here, each against ``CfnNagScanner`` with only its dependency probe and
subprocess boundary faked, as ``test_cfn_nag_scanner_behavior.py`` does:

* a diagnostic line cfn_nag prints to stdout before its SARIF document (its SPCM
  rule does, on a policy shape it cannot read) no longer discards the template's
  findings;
* a rule that raised under ``--isolate-custom-rule-exceptions`` leaves only a
  stderr line and exit 0; the template is now a failed, unevaluated target while
  the other rules' findings are kept;
* a results directory that cannot be created fails that template, not the scan;
* ``self.errors`` is reset per ``scan()`` call, so the converted target's record
  does not carry the source target's lines;
* a finding's URI is made relative to the source directory as given, so a source
  directory reached through a symbolic link does not give ``../``-escaping URIs;
* the sandbox read path for user gems is ``~/.gem/ruby``, not the whole ``~/.gem``
  that also holds the RubyGems credentials file.
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
    _as_cfn_nag_renders,
)

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

SPCM_DIAGNOSTIC = (
    "Unable to parse policy. Please verify the policy document is valid: AccessDenied\n"
)

# What cfn_nag --isolate-custom-rule-exceptions printed for the arity defect: the
# rescued exception handed to puts, so Ruby prints its MESSAGE with no class name
# (measured by tests/integration/scanners/test_cfn_nag_custom_rules.py).
ISOLATED_RULE_STDERR = (
    "wrong number of arguments (given 1, expected 2)\n"
    "wrong number of arguments (given 1, expected 2)\n"
)


def _sarif(rule_id="F38", uri="template.yaml") -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {"id": rule_id, "shortDescription": {"text": "a rule"}}
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": f"{rule_id} triggered"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 3},
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
def scanner(plugin_context):
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def deps_available():
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ) as probe:
        yield probe


@pytest.fixture
def subprocess_double():
    with patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double:
        double.return_value = {"stdout": _sarif(), "stderr": "", "returncode": 0}
        yield double


def test_a_diagnostic_line_before_the_sarif_document_is_dropped():
    text, dropped = cfn_nag_scanner._cfn_nag_sarif_text(SPCM_DIAGNOSTIC + _sarif())
    assert dropped == 1
    assert json.loads(text)["version"] == "2.1.0"
    assert cfn_nag_scanner._cfn_nag_sarif_text(_sarif()) == (_sarif(), 0)


def test_findings_survive_a_diagnostic_line_on_stdout(
    scanner, deps_available, subprocess_double
):
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": SPCM_DIAGNOSTIC + _sarif(),
        "stderr": "",
        "returncode": 0,
    }

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert scanner.targets_failed == 0


def test_rule_exception_lines_read_the_message_form_cfn_nag_prints():
    """cfn_nag hands the rescued exception to puts, so the line is the bare message
    with no class name (the measured form); at the base only a class name matched,
    so a real isolated raise read as a fully evaluated template."""
    # Read through the module so a base without the helper fails this test alone
    # instead of failing the whole file's collection.
    lines = cfn_nag_scanner._rule_exception_lines
    assert len(lines(ISOLATED_RULE_STDERR)) == 2
    assert lines("undefined method `[]' for nil:NilClass\n") == [
        "undefined method `[]' for nil:NilClass"
    ]
    assert lines("") == []


def test_rule_exception_lines_read_the_inspect_and_uncaught_forms_too():
    lines = cfn_nag_scanner._rule_exception_lines
    assert lines("#<ArgumentError: wrong number of arguments (given 1, expected 2)>\n")
    assert lines("rule.rb:9:in 'parse': boom (ArgumentError)\n")
    assert lines("#<CfnNag::RuleRepoError: no such repo>\n")


def test_rule_exception_lines_ignore_warnings_but_read_class_names():
    """A gem's deprecation warning naming an exception class is not a raise, but a
    custom rule's own traceback line, which names its class and a message cfn_nag
    never wrote, is one. At the previous tip the class-name form was dropped
    with the warnings, so such a rule read as a fully evaluated template."""
    lines = cfn_nag_scanner._rule_exception_lines
    assert lines("warning: constant ::Fixnum is deprecated\n") == []
    assert lines("/gems/x.rb:3: warning: ArgumentError will be raised in 4.0\n") == []
    assert lines("/gems/y.rb:8: warning: DeprecationError in 5.0\n") == []
    assert lines("\n   \n") == []
    assert lines("MyRuleError: no such attribute\n") == [
        "MyRuleError: no such attribute"
    ]
    assert lines("custom_rule.rb:12:in `audit_impl': MyRuleException\n")


def test_a_rule_that_raised_marks_the_template_unevaluated_and_keeps_findings(
    scanner, deps_available, subprocess_double
):
    """Exit 0 and a complete document read as evaluated at the base."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": _sarif(),
        "stderr": ISOLATED_RULE_STDERR,
        "returncode": 0,
    }

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any("raised" in line for line in scanner.errors), scanner.errors
    assert scanner.unevaluated_targets, "the template is not recorded as unevaluated"


@pytest.mark.parametrize(
    "stderr, failed",
    [
        pytest.param("MyRuleError: no such attribute\n", 1, id="class-name-raise"),
        pytest.param(
            "/gems/y.rb:8: warning: DeprecationError in 5.0\n", 0, id="warning"
        ),
    ],
)
def test_a_class_named_raise_fails_the_template_but_a_warning_does_not(
    scanner, deps_available, subprocess_double, stderr, failed
):
    """A custom rule's own traceback line names its class; a gem's deprecation
    warning naming a class is noise. At the previous tip both were ignored."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": _sarif(),
        "stderr": stderr,
        "returncode": 0,
    }

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == failed, scanner.errors
    assert bool(scanner.unevaluated_targets) is bool(failed)


def test_an_unwritable_results_directory_fails_only_that_template(
    scanner, deps_available, subprocess_double
):
    (scanner.context.work_dir / "a.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "b.yaml").write_text(CFN_TEMPLATE)
    real_stage = cfn_nag_scanner._stage_cfn_nag_input
    failed_once = []

    def failing_stage(results_file_dir, cfn_file, text):
        if not failed_once:
            failed_once.append(cfn_file)
            raise PermissionError(13, "Permission denied", str(results_file_dir))
        return real_stage(results_file_dir, cfn_file, text)

    with patch.object(cfn_nag_scanner, "_stage_cfn_nag_input", failing_stage):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert failed_once, "the fault was never injected"
    assert subprocess_double.call_count == 1
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert scanner.targets_attempted == 2
    assert scanner.targets_failed == 1
    assert any("could not be written" in line for line in scanner.errors)


def test_a_template_that_cannot_be_decoded_is_named_not_dropped(
    scanner, deps_available, subprocess_double
):
    """At the base the non-UTF-8 file fell into the parser's except at TRACE."""
    (scanner.context.work_dir / "latin.yaml").write_bytes(
        b"Resources:\n  caf\xe9:\n    Type: AWS::SQS::Queue\n"
    )
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 0
    named = [
        e for e in scanner.errors if "latin.yaml" in e and "could not be read" in e
    ]
    assert named, scanner.errors
    assert "UnicodeDecodeError" in named[0]


def test_errors_are_reset_for_each_scan_call(scanner, deps_available):
    """A line recorded by an earlier scan() call is not carried into the next.

    The empty work directory makes the second scan record its own "Target directory
    ... is empty" line (the base class appends it to errors), so the assertion is
    that the stale line is gone, not that the list is empty.
    """
    scanner.errors = ["the source target's line"]
    empty = scanner.context.work_dir
    scanner.scan(target=empty, target_type="converted")
    assert "the source target's line" not in scanner.errors, scanner.errors


@pytest.mark.skipif(os.name != "posix", reason="symbolic links on POSIX")
def test_a_source_directory_behind_a_symlink_gives_a_relative_uri(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    template = link / "stacks" / "template.yaml"
    assert _as_cfn_nag_renders(str(template), link) == "stacks/template.yaml"
    assert _as_cfn_nag_renders(str(real / "x.yaml"), link) == "x.yaml"
    assert _as_cfn_nag_renders("stacks/template.yaml", link) == "stacks/template.yaml"


def test_the_gem_read_path_does_not_cover_the_rubygems_credentials():
    read_paths = CfnNagScanner.sandbox_requirements.read_paths
    assert "~/.gem" not in read_paths, read_paths
    assert "~/.gem/ruby" in read_paths, read_paths
