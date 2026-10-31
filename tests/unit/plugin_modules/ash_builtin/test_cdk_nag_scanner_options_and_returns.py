# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cdk-nag scanner's options, dependency check and early returns.

Each test here was red at the base it was written against:

- an undeclared pack key is read as a boolean, so ``"no"`` disables and ``"maybe"`` is
  refused, and a false key that matches no declared pack is said out loud;
- ``include_compliant_checks`` says that it changes nothing when it is set, and its
  option text says so too;
- the options field describes this scanner, not Bandit;
- a node named by ``JSII_NODE`` satisfies the dependency check as it satisfies jsii;
- a reason already recorded on the plugin makes the check answer False, as the base
  class does;
- a CDK distribution installed outside the extra's bound is unusable, and the install
  command is offered for it;
- the skeleton report names this scanner's own invocation, and the final report's
  working directory is the tree that was scanned;
- a file target does not raise NotADirectoryError;
- every early return runs ``_post_scan``, so ``end_time`` is set;
- a candidate refused by the scanned-tree rule is named in the SKIPPED reason;
- the skip notice for a file that does not parse names the line and says when the
  file could be a damaged template;
- the module run as a script exits 1, not with an AttributeError, when scan() returns
  False.
"""

import logging
from datetime import datetime, timezone
from unittest.mock import create_autospec, patch

import pytest
from pydantic import ValidationError
from yaml import YAMLError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagPacks,
    CdkNagScanner,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
    _rule_help_uri,
    _script_report_json,
    _unsatisfied_cdk_requirements,
)
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils import python_installer
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
from automated_security_helper.utils.cfn_template_model import (
    NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-bucket
"""

#: A template no parser reads that still reads as one: the format version and a
#: resource type survive the damage.
DAMAGED_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "   Properties: [\n"
)

#: A file no parser reads that is not CloudFormation.
NOT_A_TEMPLATE = "site_name: docs\nplugins:\n  - !!python/name:material.plugin\n"


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig())


@pytest.fixture
def cdk_available(monkeypatch, tmp_path):
    """Present the CDK dependencies and node without installing either."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    fake_node = tmp_path / "bin" / "node"
    fake_node.parent.mkdir(parents=True, exist_ok=True)
    fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(fake_node))
    return fake_node


@pytest.fixture
def wrapper_double(monkeypatch):
    double = create_autospec(
        wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
    )
    double.return_value = CdkNagWrapperResponse(results={"AwsSolutions": []})
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return double


# ---------------------------------------------------------------------------
# The help link
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", ["AwsSolutions", "HIPAA.Security", "NIST.800.53.R5"])
def test_a_cdk_nag_rules_help_link_is_the_document_with_no_pack_anchor(pack):
    """At the base every pack's rule linked to ``#errors``, one pack's table."""
    uri = _rule_help_uri(f"{pack}-S1", pack, "Error")
    assert uri == "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md"


def test_a_foreign_rule_still_links_to_the_policy_validation_guide():
    uri = _rule_help_uri("F3017", "CloudFormation Validate", "Warning")
    assert uri.endswith("policy-validation-synthesis.html")


# ---------------------------------------------------------------------------
# Pack flags
# ---------------------------------------------------------------------------


def test_an_undeclared_pack_set_to_no_is_off():
    """At the base the string passed through and the scanner's bool() read it as on."""
    packs = CdkNagPacks.model_validate({"ServerlessChecks": "no"})

    dumped = packs.model_dump(by_alias=True)
    assert dumped["ServerlessChecks"] is False
    enabled = [name for name, value in dumped.items() if bool(value)]
    assert enabled == ["AwsSolutionsChecks"]


def test_an_undeclared_pack_set_to_yes_is_on():
    dumped = CdkNagPacks.model_validate({"ServerlessChecks": "yes"}).model_dump(
        by_alias=True
    )
    assert dumped["ServerlessChecks"] is True


def test_an_undeclared_pack_with_a_value_that_is_not_a_boolean_is_refused():
    with pytest.raises(ValidationError) as excinfo:
        CdkNagPacks.model_validate({"ServerlessChecks": "maybe"})
    assert "nag_packs.ServerlessChecks" in str(excinfo.value)


def test_a_misspelled_declared_pack_set_to_false_is_said_out_loud(caplog, monkeypatch):
    """At the base ``AwsSolutionChecks: false`` disabled nothing and said nothing, and
    the pack it meant stayed at its default."""
    monkeypatch.setattr(cdk_nag_scanner, "_UNDECLARED_PACKS_WARNED", set())
    with caplog.at_level(logging.WARNING, logger="ash"):
        packs = CdkNagPacks.model_validate({"AwsSolutionChecks": False})

    assert packs.AwsSolutionsChecks is True
    lines = [
        r.getMessage() for r in caplog.records if "AwsSolutionChecks" in r.getMessage()
    ]
    assert len(lines) == 1, lines
    assert "disables nothing" in lines[0]
    assert "AwsSolutionsChecks" in lines[0]


def test_a_declared_pack_is_validated_as_before():
    packs = CdkNagPacks.model_validate({"HIPAASecurityChecks": "no"})
    assert packs.HIPAASecurityChecks is False


# ---------------------------------------------------------------------------
# include_compliant_checks
# ---------------------------------------------------------------------------


def test_the_options_field_describes_this_scanner():
    """At the base the text was copied from the Bandit scanner's config."""
    description = CdkNagScannerConfig.model_fields["options"].description
    assert description == "Configure CDK Nag scanner"


def test_include_compliant_checks_says_it_changes_nothing():
    description = CdkNagScannerConfigOptions.model_fields[
        "include_compliant_checks"
    ].description
    assert "changes nothing" in description
    assert "violations only" in description


def test_a_scan_with_include_compliant_checks_set_says_so(
    plugin_context, cdk_available, wrapper_double, caplog
):
    """At the base a run with the option set got the same report and no line."""
    scanner = CdkNagScanner(
        context=plugin_context,
        config=CdkNagScannerConfig(
            options=CdkNagScannerConfigOptions(include_compliant_checks=True)
        ),
    )
    (plugin_context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE, encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="ash"):
        scanner.scan(target=plugin_context.work_dir, target_type="converted")

    lines = [
        r.getMessage()
        for r in caplog.records
        if "include_compliant_checks is set" in r.getMessage()
    ]
    assert len(lines) == 1, lines
    assert "changes nothing" in lines[0]


def test_a_scan_without_include_compliant_checks_says_nothing(
    scanner, cdk_available, wrapper_double, caplog
):
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING, logger="ash"):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert not [
        r for r in caplog.records if "include_compliant_checks" in r.getMessage()
    ]


# ---------------------------------------------------------------------------
# The dependency check
# ---------------------------------------------------------------------------


def test_a_node_named_by_jsii_node_satisfies_the_check(scanner, monkeypatch, tmp_path):
    """At the base only PATH was asked, and the node jsii would have run read MISSING."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: None)
    named = tmp_path / "elsewhere" / "node"
    named.parent.mkdir()
    named.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setenv("JSII_NODE", str(named))

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.dependency_unavailable_reason is None
    assert "node was not found" not in scanner.missing_dependency_reason()


def test_a_jsii_node_that_names_no_file_does_not_satisfy_the_check(
    scanner, monkeypatch, tmp_path
):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: None)
    monkeypatch.setenv("JSII_NODE", str(tmp_path / "missing" / "node"))

    assert scanner.validate_plugin_dependencies() is False
    assert "JSII_NODE" in (scanner.dependency_unavailable_reason or "")
    assert str(tmp_path) not in (scanner.dependency_unavailable_reason or "")


def test_a_recorded_reason_makes_the_check_answer_false(scanner, cdk_available):
    """At the base the override returned True over a recorded refusal."""
    scanner.dependency_unavailable_reason = "the sandbox mode refused this scanner"

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependencies_satisfied is False
    assert scanner.dependency_unavailable_reason == (
        "the sandbox mode refused this scanner"
    )


def test_a_distribution_outside_the_extras_bound_is_unsatisfied():
    """At the base only presence was asked, so an old aws-cdk-lib read as available."""
    unsatisfied = _unsatisfied_cdk_requirements(
        ["cdk-nag>=3.0,<4.0.0", "aws-cdk-lib>=2.273.0,<3.0.0"],
        installed_version=lambda name: {"cdk-nag": "2.9.0", "aws-cdk-lib": "2.280.0"}[
            name
        ],
    )

    assert len(unsatisfied) == 1
    assert unsatisfied[0].startswith("cdk-nag 2.9.0 (the cdk extra needs ")


def test_a_distribution_inside_the_bound_is_satisfied():
    assert (
        _unsatisfied_cdk_requirements(
            ["cdk-nag>=3.0,<4.0.0"], installed_version=lambda name: "3.1.0"
        )
        == []
    )


def test_a_missing_distribution_is_the_presence_probes_finding_not_this_ones():
    def absent(name):
        raise LookupError(name)

    assert (
        _unsatisfied_cdk_requirements(["cdk-nag>=3.0"], installed_version=absent) == []
    )


def test_a_requirement_whose_marker_reads_false_is_not_compared():
    """The metadata reader keeps the interpreter half of a marker. At the base the
    marker was never evaluated, so a requirement this interpreter is not held to was
    held against its installed version anyway."""
    assert (
        _unsatisfied_cdk_requirements(
            ['cdk-nag>=3.0; python_version < "3.0"'],
            installed_version=lambda name: "2.9.0",
        )
        == []
    )


def test_a_requirement_whose_marker_reads_true_is_compared():
    """The control: a marker that applies leaves the comparison in place."""
    unsatisfied = _unsatisfied_cdk_requirements(
        ['cdk-nag>=3.0; python_version >= "3.0"'],
        installed_version=lambda name: "2.9.0",
    )

    assert len(unsatisfied) == 1
    assert unsatisfied[0].startswith("cdk-nag 2.9.0 (the cdk extra needs ")


def test_a_requirement_still_carrying_the_extras_own_clause_is_compared():
    """``packaging`` evaluates ``extra`` as the empty string unless told otherwise, so a
    requirement that still carries ``extra == "cdk"`` read false and was skipped: the
    bound check was a no-op for it, and an out-of-bounds install read as satisfied.
    The marker is evaluated with the extra named."""
    unsatisfied = _unsatisfied_cdk_requirements(
        ['cdk-nag>=3.0,<4.0.0; extra == "cdk"'],
        installed_version=lambda name: "2.9.0",
    )

    assert len(unsatisfied) == 1
    assert unsatisfied[0].startswith("cdk-nag 2.9.0 (the cdk extra needs ")


def test_the_extras_clause_does_not_admit_a_requirement_of_another_extra():
    """The control: a clause naming another extra still reads false."""
    assert (
        _unsatisfied_cdk_requirements(
            ['cdk-nag>=3.0; extra == "symbols"'],
            installed_version=lambda name: "2.9.0",
        )
        == []
    )


def test_an_installed_version_packaging_cannot_read_is_unsatisfied():
    """Fail closed, as the docstring now says: a version that cannot be compared cannot
    be shown inside the bound, and the install this check gates replaces it."""
    assert _unsatisfied_cdk_requirements(
        ["cdk-nag>=3.0"], installed_version=lambda name: "not-a-version"
    ) == ["cdk-nag not-a-version (the cdk extra needs >=3.0)"]


def test_an_out_of_bounds_install_fails_the_check_and_offers_the_install(
    scanner, cdk_available, monkeypatch
):
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_unsatisfied_cdk_requirements",
        lambda: ["aws-cdk-lib 2.100.0 (the cdk extra needs <3.0.0,>=2.273.0)"],
    )
    # The install command is built by the installer that owns the running
    # environment (pip, or uv for a uv-made one) and raises when neither can be
    # found; this test is about WHETHER a command is offered, not which installer
    # writes it, and the venue runs it with neither on PATH.
    monkeypatch.setattr(
        python_installer,
        "python_package_install_command",
        lambda requirements: ["python", "-m", "pip", "install", *requirements],
    )

    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason or ""
    assert "outside the bounds" in reason
    assert "aws-cdk-lib 2.100.0" in reason
    assert "ash dependencies install --tool cdk-nag" in reason

    commands = scanner.get_installation_commands("linux", "amd64")
    assert any("aws-cdk-lib" in " ".join(command) for command in commands)


def test_an_in_bounds_install_offers_no_install_command(scanner, cdk_available):
    commands = scanner.get_installation_commands("linux", "amd64")
    assert not any("aws-cdk-lib" in " ".join(command) for command in commands)


# ---------------------------------------------------------------------------
# Early returns
# ---------------------------------------------------------------------------


def test_a_file_target_does_not_raise(scanner, cdk_available, wrapper_double):
    """At the base ``target.iterdir()`` raised NotADirectoryError for a file target."""
    target = scanner.context.work_dir / "bucket.yaml"
    target.write_text(CFN_TEMPLATE, encoding="utf-8")

    with patch.object(CdkNagScanner, "_pre_scan", autospec=True, return_value=False):
        result = scanner.scan(target=target, target_type="converted")

    assert result is False


def test_an_empty_target_sets_the_end_time(scanner, cdk_available, wrapper_double):
    """At the base the early return skipped _post_scan and end_time stayed unset."""
    scanner.end_time = None

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.end_time is not None


def test_an_empty_target_is_timed_from_its_own_return(
    scanner, cdk_available, wrapper_double
):
    """One instance scans source and then converted. At the base a start_time left by
    the previous target's _pre_scan stood, and the empty tree's duration ran from it."""
    scanner.start_time = datetime(2001, 1, 1, tzinfo=timezone.utc)
    scanner.end_time = None

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.end_time is not None
    assert scanner.start_time == scanner.end_time


def test_a_failed_pre_scan_sets_the_end_time(scanner, cdk_available, wrapper_double):
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )
    scanner.end_time = None

    with patch.object(CdkNagScanner, "_pre_scan", autospec=True, return_value=False):
        assert (
            scanner.scan(target=scanner.context.work_dir, target_type="converted")
            is False
        )

    assert scanner.end_time is not None


def test_the_final_reports_working_directory_is_the_scanned_tree(
    scanner, cdk_available, wrapper_double
):
    """At the base a converted scan named the source directory as its working
    directory while its --source-dir argument named the work directory."""
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    expected = str(get_shortest_name(input=scanner.context.work_dir))
    assert invocation.workingDirectory.uri == expected
    assert list(invocation.arguments)[-1] == expected


# ---------------------------------------------------------------------------
# Candidates the scanned-tree rule refused
# ---------------------------------------------------------------------------


def test_refused_candidates_are_named_in_the_skipped_reason(
    scanner, cdk_available, wrapper_double, monkeypatch
):
    """At the base a target whose every candidate was refused graded SKIPPED with
    "no CloudFormation template" and nothing about the files it did not read."""
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )
    monkeypatch.setattr(
        cdk_nag_scanner,
        "refusal_reason",
        lambda path, root, **options: "it is a symbolic link",
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 0
    wrapper_double.assert_not_called()
    reason = scanner._nothing_scanned_reason or ""
    assert "1 candidate file(s) were skipped unread" in reason
    assert "no CloudFormation template" in reason
    assert any("it is a symbolic link" in err for err in scanner.errors)


def test_an_attempted_template_leaves_the_skipped_reason_alone(
    scanner, cdk_available, wrapper_double
):
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner._nothing_scanned_reason is None


# ---------------------------------------------------------------------------
# The skip notice for a file that does not parse
# ---------------------------------------------------------------------------


def _worker_style_yaml_error():
    """The worker re-raises a parse failure as its class name and text only."""
    return type("ScannerError", (YAMLError,), {})("mapping values are not allowed here")


def test_a_damaged_template_is_told_it_could_be_one_and_at_which_line(
    scanner, cdk_available, wrapper_double
):
    """At the base the notice said the file is not a CloudFormation template and
    named the error type with no line, one statement before the target was recorded
    as a template that could not be parsed."""
    (scanner.context.work_dir / "damaged.yaml").write_text(
        DAMAGED_TEMPLATE, encoding="utf-8"
    )
    wrapper_double.side_effect = _worker_style_yaml_error()

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    notices = [err for err in scanner.errors if "not parseable" in err]
    assert len(notices) == 1, scanner.errors
    assert "could be a damaged CloudFormation template" in notices[0]
    assert "it is not a CloudFormation template" not in notices[0]
    assert " at line " in notices[0]
    assert scanner._nothing_scanned_reason == NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    assert scanner.targets_attempted == 0
    assert scanner.targets_failed == 0


def test_a_file_that_is_not_a_template_is_told_so(
    scanner, cdk_available, wrapper_double
):
    (scanner.context.work_dir / "mkdocs.yml").write_text(
        NOT_A_TEMPLATE, encoding="utf-8"
    )
    wrapper_double.side_effect = _worker_style_yaml_error()

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    notices = [err for err in scanner.errors if "not parseable" in err]
    assert len(notices) == 1, scanner.errors
    assert "it is not a CloudFormation template" in notices[0]
    assert "damaged" not in notices[0]
    assert scanner._nothing_scanned_reason is None


# ---------------------------------------------------------------------------
# The module as a script
# ---------------------------------------------------------------------------


def test_the_script_exits_one_when_scan_returned_false(scanner, caplog, monkeypatch):
    """At the base the script called model_dump_json on False and died with an
    AttributeError."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    with caplog.at_level(logging.ERROR, logger="ash"):
        with pytest.raises(SystemExit) as excinfo:
            _script_report_json(False, scanner)

    assert excinfo.value.code == 1
    assert any("cdk-nag did not scan" in r.getMessage() for r in caplog.records)


def test_the_script_prints_a_report_as_json(scanner, cdk_available, wrapper_double):
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    text = _script_report_json(report, scanner)

    assert text.startswith("{")
    assert '"version": "2.1.0"' in text
