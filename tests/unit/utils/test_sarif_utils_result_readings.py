# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One reading of a SARIF result for every reporter.

Four reporters each carried their own copy of what is not a finding, of a
result's message text, of its rule id and of its scanner, and the copies
disagreed: one left ``notApplicable`` out of the kinds that state no finding, so
a cdk-nag rule that was not evaluated was graded; one read ``ruleId`` alone and
lost the rule of a result that names it through ``rule``; one read the scanner
name alone and not the ``scanner_details.tool_name`` the flattening falls back
to; and a message given by id alone came out as the bare id, never resolved
against the rule's message strings. ``sarif_utils`` now holds the one
definition each reporter imports.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Message,
    Message1,
    Message2,
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorReference1,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    DEFAULT_RESULT_KIND,
    FINDING_KINDS,
    NON_FINDING_KINDS,
    is_not_a_finding,
    normalize_sarif_result_severities,
    result_kind,
    result_message_text,
    result_rule_id,
    result_scanner_name,
    shared_finding_ids,
)

pytestmark = pytest.mark.unit


def _result(**overrides: Any) -> Result:
    fields: dict = {"ruleId": "R1", "message": Message(root=Message1(text="found"))}
    fields.update(overrides)
    return Result(**fields)


class TestTheKindSets:
    def test_the_two_sets_partition_the_schema_kinds(self):
        """A kind the schema adds lands in neither set and fails here, not in a
        reporter at run time."""
        assert NON_FINDING_KINDS == frozenset(
            {"pass", "notApplicable", "informational"}
        )
        assert FINDING_KINDS == frozenset({"fail", "open", "review"})
        assert not NON_FINDING_KINDS & FINDING_KINDS
        assert {kind.value for kind in Kind} == NON_FINDING_KINDS | FINDING_KINDS

    def test_an_absent_kind_is_fail(self):
        assert DEFAULT_RESULT_KIND == "fail"
        assert result_kind(_result()) == "fail"
        assert result_kind(Result.model_validate({"message": {"text": "x"}})) == "fail"
        assert result_kind(object()) == "fail"

    @pytest.mark.parametrize("kind", list(Kind))
    def test_every_schema_kind_reads_as_its_value(self, kind: Kind):
        assert result_kind(_result(kind=kind)) == kind.value

    def test_a_plain_string_and_a_mapping_read_the_same(self):
        class Plain:
            kind = "notApplicable"

        assert result_kind(Plain()) == "notApplicable"
        assert result_kind({"kind": "pass"}) == "pass"
        assert result_kind({"message": {"text": "x"}}) == "fail"


class TestIsNotAFinding:
    @pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
    def test_the_three_non_finding_kinds(self, kind: str):
        assert is_not_a_finding(_result(kind=Kind(kind))) is True

    @pytest.mark.parametrize("kind", ["fail", "open", "review"])
    def test_the_finding_kinds_and_the_default(self, kind: str):
        assert is_not_a_finding(_result(kind=Kind(kind))) is False
        assert is_not_a_finding(_result()) is False

    def test_a_reporter_that_keeps_only_fail_passes_its_own_set(self):
        """GitHub code scanning reads no ``kind``, so that reporter leaves out
        every result but a failing one. Whether open and review belong there is
        not decided here: the set is the caller's."""
        only_fail = frozenset(NON_FINDING_KINDS | {"open", "review"})
        assert is_not_a_finding(_result(kind=Kind.open), only_fail) is True
        assert is_not_a_finding(_result(kind=Kind.review), only_fail) is True
        assert is_not_a_finding(_result(kind=Kind.fail), only_fail) is False
        # The default set still reads open and review as findings.
        assert is_not_a_finding(_result(kind=Kind.open)) is False


class TestResultMessageText:
    def test_text_then_markdown(self):
        assert result_message_text(_result()) == "found"
        markdown_only = _result(
            message=Message(root=Message2(id="m", markdown="**md**"))
        )
        assert result_message_text(markdown_only) == "**md**"

    def test_whitespace_only_text_counts_as_absent(self):
        """One copy tested ``value``, another ``value.strip()``; a message of
        spaces described a finding as spaces under the first."""
        spaces = _result(message=Message(root=Message1(text="   ", markdown="real")))
        assert result_message_text(spaces) == "real"

    def test_an_id_alone_resolves_against_the_rules_message_strings(self):
        rule = ReportingDescriptor(
            id="R1",
            messageStrings={"m": MultiformatMessageString(text="the rule's text")},
            shortDescription=MultiformatMessageString(text="short"),
        )
        id_only = _result(message=Message(root=Message2(id="m")))
        assert result_message_text(id_only, rule) == "the rule's text"

    def test_an_id_the_rule_does_not_name_falls_to_its_short_description(self):
        rule = ReportingDescriptor(
            id="R1",
            messageStrings={"other": MultiformatMessageString(text="not this one")},
            shortDescription=MultiformatMessageString(text="short"),
        )
        id_only = _result(message=Message(root=Message2(id="m")))
        assert result_message_text(id_only, rule) == "short"

    def test_an_id_with_no_rule_is_the_id_itself(self):
        """Never ``Message id: m``, never "No description": the id as the rule
        names it, so a reader can find the string."""
        id_only = _result(message=Message(root=Message2(id="m")))
        assert result_message_text(id_only) == "m"
        assert result_message_text(id_only, ReportingDescriptor(id="R1")) == "m"

    def test_arguments_fill_the_placeholders_of_the_rules_message_string(self):
        """SARIF 3.11.5: the result's ``arguments`` replace ``{N}`` in the rule's
        message string. The placeholder reached the report as written."""
        rule = ReportingDescriptor(
            id="R1",
            messageStrings={"default": MultiformatMessageString(text="Found {0}")},
        )
        with_argument = _result(
            message=Message(root=Message2(id="default", arguments=["x"]))
        )
        assert result_message_text(with_argument, rule) == "Found x"

    def test_arguments_fill_the_placeholders_of_the_text_and_the_markdown(self):
        text = _result(
            message=Message(root=Message1(text="{0} met {1}", arguments=["a", "b"]))
        )
        assert result_message_text(text) == "a met b"
        markdown = _result(
            message=Message(
                root=Message2(id="m", markdown="**{1}** then {0}", arguments=["a", "b"])
            )
        )
        assert result_message_text(markdown) == "**b** then a"

    def test_a_doubled_brace_is_one_literal_brace(self):
        escaped = _result(
            message=Message(
                root=Message1(text="{{0}} is {0}, {{done}}", arguments=["x"])
            )
        )
        assert result_message_text(escaped) == "{0} is x, {done}"

    def test_a_rules_message_string_reads_doubled_braces_with_or_without_arguments(
        self,
    ):
        """A message string is a format string (SARIF 3.11.5), so ``{{x}}`` is
        ``{x}`` whether or not the result carries arguments; read only beside
        arguments, one string rendered two ways."""
        rule = ReportingDescriptor(
            id="R1",
            messageStrings={
                "default": MultiformatMessageString(text="Use {{x}} for {0}")
            },
        )
        without = _result(message=Message(root=Message2(id="default")))
        assert result_message_text(without, rule) == "Use {x} for {0}"
        empty = _result(message=Message(root=Message2(id="default", arguments=[])))
        assert result_message_text(empty, rule) == "Use {x} for {0}"
        with_argument = _result(
            message=Message(root=Message2(id="default", arguments=["y"]))
        )
        assert result_message_text(with_argument, rule) == "Use {x} for y"

    def test_a_placeholder_past_the_last_argument_is_left_as_written(self):
        short = _result(
            message=Message(root=Message1(text="Found {3} and {0}", arguments=["x"]))
        )
        assert result_message_text(short) == "Found {3} and x"
        # A number with more digits than a list could hold, and a word, are not
        # placeholders this function fills.
        text = "{" + "9" * 20 + "} {name}"
        odd = _result(message=Message(root=Message1(text=text, arguments=["x"])))
        assert result_message_text(odd) == text

    def test_a_message_with_no_arguments_is_returned_as_written(self):
        """The control: braces in a scanner's own text are not touched when the
        message has nothing to fill them with, escapes included."""
        braces = _result(message=Message(root=Message1(text="use {0} and {{x}}")))
        assert result_message_text(braces) == "use {0} and {{x}}"
        empty = _result(message=Message(root=Message1(text="use {0}", arguments=[])))
        assert result_message_text(empty) == "use {0}"
        # And a rule's short description, the fallback, is never a format string.
        rule = ReportingDescriptor(
            id="R1", shortDescription=MultiformatMessageString(text="short {0}")
        )
        id_only = _result(message=Message(root=Message2(id="m", arguments=["x"])))
        assert result_message_text(id_only, rule) == "short {0}"

    def test_no_message_gives_the_default(self):
        """A SARIF result always carries a message; a stand-in built on an error
        path may not, and the reading degrades instead of raising."""

        class NoMessage:
            message = None

        assert result_message_text(NoMessage()) is None
        assert result_message_text(NoMessage(), default="") == ""
        assert result_message_text(object(), default="") == ""


class TestResultRuleId:
    def test_rule_id_then_the_rule_reference(self):
        assert result_rule_id(_result()) == "R1"
        by_reference = _result(
            ruleId=None,
            rule=ReportingDescriptorReference(
                root=ReportingDescriptorReference1(id="R2", index=-1)
            ),
        )
        assert result_rule_id(by_reference) == "R2"

    def test_an_empty_rule_id_falls_to_the_reference(self):
        """One copy read ``result.ruleId or ""`` and never looked at the
        reference, so a result naming its rule through ``rule`` lost it."""
        by_reference = _result(
            ruleId="",
            rule=ReportingDescriptorReference(
                root=ReportingDescriptorReference1(id="R2", index=-1)
            ),
        )
        assert result_rule_id(by_reference) == "R2"

    def test_neither_is_none(self):
        assert result_rule_id(_result(ruleId=None)) is None
        no_id_reference = _result(
            ruleId=None,
            rule=ReportingDescriptorReference(
                root=ReportingDescriptorReference1(index=0)
            ),
        )
        assert result_rule_id(no_id_reference) is None
        assert result_rule_id(object()) is None


class TestResultScannerName:
    def test_scanner_name_as_an_extra_property(self):
        result = _result(properties=PropertyBag(scanner_name=" bandit "))
        assert result_scanner_name(result) == "bandit"

    def test_the_tool_name_of_scanner_details_as_the_fallback(self):
        """The flattening reads ``scanner_details.tool_name`` when there is no
        scanner name; one copy did not, so such a result had no scanner in its
        identity and two scanners' findings at one line shared one id."""
        as_dict = _result(
            properties=PropertyBag(scanner_details={"tool_name": "grype"})
        )
        assert result_scanner_name(as_dict) == "grype"

        class Details:
            tool_name = "trivy"

        class Properties:
            scanner_name = None
            model_extra = None
            scanner_details = Details()

        class AsObject:
            properties = Properties()

        assert result_scanner_name(AsObject()) == "trivy"

    def test_blank_or_absent_is_none(self):
        assert result_scanner_name(_result()) is None
        assert (
            result_scanner_name(_result(properties=PropertyBag(scanner_name="  ")))
            is None
        )
        assert (
            result_scanner_name(_result(properties=PropertyBag(scanner_details={})))
            is None
        )

    def test_a_property_bag_that_raises_reads_as_none(self):
        class Raising:
            @property
            def properties(self):
                raise RuntimeError("a stand-in's field raised")

        assert result_scanner_name(Raising()) is None


class TestSharedFindingIds:
    def test_a_flattening_that_raises_vouches_for_no_position(self):
        class Model:
            def to_flat_vulnerabilities(self) -> List[Any]:
                raise ValueError("cannot flatten")

        assert shared_finding_ids(Model(), [_result(), _result()]) == [None, None]

    def test_a_flattening_of_another_length_vouches_only_where_a_row_fits(self):
        """One row for two results: ``shared_ids_by_position`` walks the rows, so
        the row vouches for the first result it describes (same rule, no file, no
        line) and the second result, with no row left, gets None there alone.
        Before the walk a length mismatch gave None at every position, which
        changed every id of a report for one stray row."""

        class Flat:
            id = "f-1"
            rule_id = "R1"
            file_path = None

        class Model:
            def to_flat_vulnerabilities(self) -> List[Any]:
                return [Flat()]

        assert shared_finding_ids(Model(), [_result(), _result()]) == ["f-1", None]

    def test_a_row_that_describes_its_result_gives_its_id(self):
        class Flat:
            id = "f-1"
            rule_id = "R1"
            file_path = None

        class Model:
            def to_flat_vulnerabilities(self) -> List[Any]:
                return [Flat()]

        ids = shared_finding_ids(Model(), [_result()])
        assert ids == ["f-1"]

    def test_a_row_whose_id_read_raises_vouches_for_no_position(self):
        """The pairing runs inside the same fallback as the flattening: a row
        whose ``id`` is a property that raises (``getattr`` with a default
        swallows only AttributeError) gives None at every position instead of
        an exception out of the reporter's report()."""

        class Flat:
            rule_id = "R1"
            file_path = None

            @property
            def id(self) -> str:
                raise RuntimeError("a lazy id that cannot be read")

        class Model:
            def to_flat_vulnerabilities(self) -> List[Any]:
                return [Flat(), Flat()]

        assert shared_finding_ids(Model(), [_result(), _result()]) == [None, None]


class TestSharedFindingIdsLayering:
    """``shared_ids_by_position`` is a utility: it lives under ``utils`` and
    ``sarif_utils`` binds it at load time, so a utility module no longer reaches
    into the reporters package (a utils -> plugin_modules edge, deferred to call
    time to dodge the load-time cycle). The reporters' import spelling is kept
    by a re-export at the old path. The imports sit inside the tests so that,
    before the move, only these three read red and the rest of the file stays
    a measurement."""

    def test_the_helper_lives_under_utils(self):
        from pathlib import Path

        from automated_security_helper.utils import shared_finding_ids as helper

        assert Path(helper.__file__).parent.name == "utils"
        assert callable(helper.shared_ids_by_position)
        assert callable(helper.flat_describes_result)

    def test_the_reporters_path_re_exports_the_same_objects(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters import (
            shared_finding_ids as reporters_path,
        )
        from automated_security_helper.utils import shared_finding_ids as helper

        assert reporters_path.shared_ids_by_position is helper.shared_ids_by_position
        assert reporters_path.flat_describes_result is helper.flat_describes_result
        assert set(reporters_path.__all__) == set(helper.__all__)

    def test_sarif_utils_binds_the_helper_at_load_time(self):
        from automated_security_helper.utils import sarif_utils
        from automated_security_helper.utils import shared_finding_ids as helper

        # A module attribute, not a name resolved inside the function body.
        assert sarif_utils.shared_ids_by_position is helper.shared_ids_by_position


class TestTheSeverityNormalizationKeepsItsKinds:
    def test_an_open_result_is_still_not_graded(self):
        """The normalization skips every result whose kind is not ``fail``;
        this consolidation changes which function says so, not the answer."""
        rule = ReportingDescriptor(
            id="R1", properties=PropertyBag(**{"security-severity": "9.0"})
        )
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="t", rules=[rule])),
                    results=[_result(kind=Kind.open), _result(kind=Kind.fail)],
                )
            ],
        )
        normalize_sarif_result_severities(report)
        open_result, failing = report.runs[0].results
        assert open_result.properties is None
        assert getattr(failing.properties, "issue_severity", None) == "CRITICAL"
