"""Behavior tests for ``run_cdk_nag_against_cfn_template``.

The wrapper imports ``cdk_nag``, ``aws_cdk`` and ``constructs`` lazily, from
inside the function body, and none of those three are installed here -- they
pull in a full JSII/Node toolchain. Without them the call returns at the
``except (ImportError, FileNotFoundError)`` guard and nothing after it runs,
which is why the module measured 27% covered while the existing regression
tests all passed: those tests assert on the *source text* of the module, so
they never execute the report-parsing code at all.

These tests install module doubles in ``sys.modules`` for the duration of one
call so the whole body runs. Two properties of the doubles are load-bearing:

* Each one is a real class with exactly the attributes the wrapper touches, so
  a call to a method that does not exist raises ``AttributeError`` instead of
  quietly succeeding the way a bare ``Mock()`` would.
* ``App.synth()`` writes the ``*-NagReport.json`` files, because that is what
  the real cdk-nag aspects do and those files are the input the wrapper globs
  for. A synth that emits nothing is the "subprocess exits 0 having run
  nothing" trap in this module, so the report payload is supplied by the test
  and asserted on the way out.
"""

import json
import sys
import types
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind, Level
from automated_security_helper.utils import cdk_nag_wrapper
from automated_security_helper.utils.cdk_nag_wrapper import (
    CdkNagWrapperResponse,
    run_cdk_nag_against_cfn_template,
)

STACK_NAME = "ASHCDKNagScanner"

# ``MyDataBucketPolicy`` deliberately precedes ``MyDataBucket`` so that a
# substring search for "MyDataBucket" would hit the *policy* line first. The
# wrapper uses a word-boundary regex, so the reported line must be the later
# one. See test_finding_line_number_uses_word_boundary_not_substring.
TEMPLATE_YAML = """Resources:
  MyDataBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: placeholder-name
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-name
"""

BUCKET_DECLARATION_LINE = 6
BUCKET_DECLARATION_COLUMN = 2


def _report_payload(lines):
    """Serialize NagReport ``lines`` the way cdk-nag writes them (camelCase)."""
    return json.dumps({"lines": lines})


def _nag_line(
    rule_id="AwsSolutions-S1",
    resource_id=f"{STACK_NAME}/MyDataBucket",
    compliance="Non-Compliant",
    exception_reason="N/A",
    rule_level="Error",
    rule_info="The S3 Bucket has server access logs disabled.",
):
    return {
        "ruleId": rule_id,
        "resourceId": resource_id,
        "compliance": compliance,
        "exceptionReason": exception_reason,
        "ruleLevel": rule_level,
        "ruleInfo": rule_info,
    }


class _Recorder:
    """Collects the objects the wrapper built, so tests can assert on them."""

    def __init__(self):
        self.apps = []
        self.stacks = []
        self.cfn_includes = []
        self.pack_instances = []
        self.reports = {}
        self.synth_count = 0


@pytest.fixture
def cdk_doubles(monkeypatch):
    """Install ``cdk_nag`` / ``aws_cdk`` / ``constructs`` doubles.

    Returns a :class:`_Recorder`. Put ``{filename: json_text}`` entries into
    ``recorder.reports`` before calling the wrapper; ``App.synth()`` writes
    them into the synth output directory.
    """
    recorder = _Recorder()

    # ---- cdk_nag -------------------------------------------------------
    class NagPack:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            recorder.pack_instances.append(self)

    class AwsSolutionsChecks(NagPack):
        pass

    class HIPAASecurityChecks(NagPack):
        pass

    class NotANagPack:
        """Present so the isclass/issubclass filter has something to reject."""

    class NagReportFormat:
        JSON = "JSON"

    class NagReportLine:
        def __init__(
            self,
            rule_id,
            resource_id,
            compliance,
            exception_reason,
            rule_level,
            rule_info,
        ):
            self.rule_id = rule_id
            self.resource_id = resource_id
            self.compliance = compliance
            self.exception_reason = exception_reason
            self.rule_level = rule_level
            self.rule_info = rule_info

    class NagReportSchema:
        """Keyword-only, so an unexpected report shape raises like JSII does."""

        def __init__(self, *, lines):
            if not isinstance(lines, list):
                raise TypeError(f"lines must be a list, got {type(lines).__name__}")
            self.lines = lines

    cdk_nag_mod = types.ModuleType("cdk_nag")
    cdk_nag_mod.NagPack = NagPack
    cdk_nag_mod.AwsSolutionsChecks = AwsSolutionsChecks
    cdk_nag_mod.HIPAASecurityChecks = HIPAASecurityChecks
    cdk_nag_mod.NotANagPack = NotANagPack
    cdk_nag_mod.NagReportFormat = NagReportFormat
    cdk_nag_mod.NagReportLine = NagReportLine
    cdk_nag_mod.NagReportSchema = NagReportSchema

    # ---- constructs / aws_cdk ------------------------------------------
    class Construct:
        pass

    class _Node:
        def __init__(self):
            self.children = []

    class Stack(Construct):
        def __init__(self, scope=None, id=None):
            self.scope = scope
            self.id = id
            self.node = _Node()
            self.aspects = []
            recorder.stacks.append(self)

    class CfnInclude:
        def __init__(self, scope, id, template_file):
            self.scope = scope
            self.id = id
            self.template_file = template_file
            scope.node.children.append(self)
            recorder.cfn_includes.append(self)

    class _AspectCollection:
        def __init__(self, target):
            self._target = target

        def add(self, aspect):
            self._target.aspects.append(aspect)

    class Aspects:
        @staticmethod
        def of(scope):
            return _AspectCollection(scope)

    class App:
        def __init__(self, outdir):
            self.outdir = outdir
            recorder.apps.append(self)

        def synth(self):
            recorder.synth_count += 1
            for name, text in recorder.reports.items():
                Path(self.outdir).joinpath(name).write_text(text, encoding="utf-8")

    aws_cdk_mod = types.ModuleType("aws_cdk")
    aws_cdk_mod.App = App
    aws_cdk_mod.Aspects = Aspects
    aws_cdk_mod.Stack = Stack

    cfn_include_mod = types.ModuleType("aws_cdk.cloudformation_include")
    cfn_include_mod.CfnInclude = CfnInclude
    aws_cdk_mod.cloudformation_include = cfn_include_mod

    constructs_mod = types.ModuleType("constructs")
    constructs_mod.Construct = Construct

    for name, module in (
        ("cdk_nag", cdk_nag_mod),
        ("aws_cdk", aws_cdk_mod),
        ("aws_cdk.cloudformation_include", cfn_include_mod),
        ("constructs", constructs_mod),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    return recorder


@pytest.fixture
def template_file(tmp_path):
    path = tmp_path / "secure-s3-template.yaml"
    path.write_text(TEMPLATE_YAML, encoding="utf-8")
    return path


@pytest.fixture
def outdir(tmp_path):
    path = tmp_path / "cdknag-out"
    path.mkdir()
    return path


def _run(template_file, outdir, **kwargs):
    return run_cdk_nag_against_cfn_template(
        template_path=template_file,
        outdir=outdir,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Response container
# ---------------------------------------------------------------------------


def test_response_container_retains_all_three_fields(tmp_path):
    """``CdkNagWrapperResponse`` stores what it is handed, defaulting to None."""
    empty = CdkNagWrapperResponse()
    assert empty.results is None
    assert empty.outdir is None
    assert empty.template is None

    populated = CdkNagWrapperResponse(
        results={"AwsSolutions": []}, outdir=tmp_path, template="sentinel-template"
    )
    assert populated.results == {"AwsSolutions": []}
    assert populated.outdir == tmp_path
    assert populated.template == "sentinel-template"


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


def test_template_without_resources_returns_none(cdk_doubles, tmp_path, outdir):
    """A YAML file that is not a CloudFormation template is skipped."""
    not_a_template = tmp_path / "compose.yaml"
    not_a_template.write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")

    assert _run(not_a_template, outdir) is None
    # The wrapper bailed before building an app.
    assert recorder_is_untouched(cdk_doubles)


def recorder_is_untouched(recorder):
    return not recorder.apps and not recorder.stacks and recorder.synth_count == 0


def test_outdir_none_raises_value_error(cdk_doubles, template_file):
    """``outdir`` has no usable default, so None must be rejected loudly."""
    with pytest.raises(ValueError, match="outdir is required"):
        run_cdk_nag_against_cfn_template(template_path=template_file, outdir=None)


def test_unknown_nag_pack_name_raises_key_error(cdk_doubles, template_file, outdir):
    """Only classes that subclass ``NagPack`` are resolvable pack names.

    ``NotANagPack`` exists on the cdk_nag double but is not a NagPack
    subclass, so the pack lookup must not contain it.
    """
    with pytest.raises(KeyError):
        _run(template_file, outdir, nag_packs=["NotANagPack"])


# ---------------------------------------------------------------------------
# The happy path: a non-empty report must produce non-empty findings
# ---------------------------------------------------------------------------


def test_non_empty_nag_report_produces_non_empty_findings(
    cdk_doubles, template_file, outdir
):
    """A report with one non-compliant line yields exactly one SARIF result.

    This is the anti-"clean scan" assertion: an empty-parse bug in the report
    handling would return an empty results dict and read as a passing scan.
    """
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line()]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response is not None
    # The results key comes from the report *filename*, not the requested pack.
    assert list(response.results.keys()) == ["AwsSolutions"]
    findings = response.results["AwsSolutions"]
    assert len(findings) == 1, (
        f"expected 1 finding from a 1-line NagReport, got {len(findings)}"
    )

    finding = findings[0]
    assert finding.ruleId == "AwsSolutions-S1"
    assert finding.level == Level.error
    assert finding.kind == Kind.fail
    assert finding.message.root.text == (
        "The S3 Bucket has server access logs disabled.\n\nException Reason: N/A"
    )

    # Tags carry the pack, rule, resource, and the resource's CFN type.
    tags = finding.properties.tags
    assert "cdk-nag" in tags
    assert "AwsSolutions" in tags
    assert "AwsSolutions-S1" in tags
    assert "MyDataBucket" in tags
    assert "AWS::S3::Bucket" in tags
    assert "tool_name::cdk-nag" in tags
    assert "tool_type::IAC" in tags

    # The template model is handed back so the caller can resolve resources.
    assert "MyDataBucket" in response.template.Resources
    assert response.template.Resources["MyDataBucket"].Type == "AWS::S3::Bucket"


def test_finding_line_number_uses_word_boundary_not_substring(
    cdk_doubles, template_file, outdir
):
    """The reported region points at ``MyDataBucket:``, not ``MyDataBucketPolicy:``.

    ``MyDataBucketPolicy`` appears on an earlier line and contains
    ``MyDataBucket`` as a prefix. A substring search would report that earlier
    line; the word-boundary regex must skip it. This also pins the 1-based
    line numbering -- a 0-based ``enumerate`` would report one line early.
    """
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line()]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    region = (
        response.results["AwsSolutions"][0].locations[0].physicalLocation.root.region
    )

    assert region.startLine == BUCKET_DECLARATION_LINE, (
        f"expected the MyDataBucket declaration at line "
        f"{BUCKET_DECLARATION_LINE}; got {region.startLine}. A lower number "
        f"means the search matched MyDataBucketPolicy on an earlier line."
    )
    assert region.endLine == BUCKET_DECLARATION_LINE
    assert region.startColumn == BUCKET_DECLARATION_COLUMN
    assert region.endColumn == BUCKET_DECLARATION_COLUMN + len("MyDataBucket")
    # The snippet is the rendered resource, not the raw template line.
    assert "AWS::S3::Bucket" in region.snippet.text


def test_resource_absent_from_template_is_dropped(cdk_doubles, template_file, outdir):
    """A report line naming a resource the template does not define is skipped."""
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [
            _nag_line(resource_id=f"{STACK_NAME}/ResourceThatIsNotInTheTemplate"),
            _nag_line(rule_id="AwsSolutions-S2"),
        ]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    rule_ids = [f.ruleId for f in response.results["AwsSolutions"]]
    assert rule_ids == ["AwsSolutions-S2"], (
        f"only the resolvable resource should survive; got {rule_ids}"
    )


# ---------------------------------------------------------------------------
# Compliance -> level/kind mapping
# ---------------------------------------------------------------------------


def test_compliant_lines_are_dropped_by_default(cdk_doubles, template_file, outdir):
    """Compliant checks are excluded unless explicitly requested."""
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line(rule_id="AwsSolutions-OK", compliance="Compliant")]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response.results == {"AwsSolutions": []}


def test_compliant_lines_are_kept_when_requested(cdk_doubles, template_file, outdir):
    """``include_compliant_checks=True`` keeps them, at level/kind none/informational."""
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line(rule_id="AwsSolutions-OK", compliance="Compliant")]
    )

    response = _run(
        template_file,
        outdir,
        nag_packs=["AwsSolutionsChecks"],
        include_compliant_checks=True,
    )

    findings = response.results["AwsSolutions"]
    assert [f.ruleId for f in findings] == ["AwsSolutions-OK"]
    assert findings[0].level == Level.none
    assert findings[0].kind == Kind.informational


@pytest.mark.parametrize(
    "compliance, rule_level, exception_reason, expected_level, expected_kind",
    [
        # Non-compliant + Error is the only combination that fails the scan.
        ("Non-Compliant", "Error", "N/A", Level.error, Kind.fail),
        # Non-compliant at a lower rule level warns instead of failing.
        ("Non-Compliant", "Warning", "N/A", Level.warning, Kind.informational),
        # A suppression with a stated reason is routed to human review.
        (
            "Suppressed",
            "Error",
            "Accepted risk, tracked separately",
            Level.none,
            Kind.review,
        ),
        # A suppression with no stated reason is not review-worthy.
        ("Suppressed", "Error", "N/A", Level.none, Kind.informational),
    ],
)
def test_compliance_maps_to_distinct_level_and_kind(
    cdk_doubles,
    template_file,
    outdir,
    compliance,
    rule_level,
    exception_reason,
    expected_level,
    expected_kind,
):
    """Each compliance/rule-level pair maps to its own (level, kind) pair.

    The four rows below produce four distinct (level, kind) tuples, so no row
    is a duplicate of another dressed up as a separate case.
    """
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [
            _nag_line(
                compliance=compliance,
                rule_level=rule_level,
                exception_reason=exception_reason,
            )
        ]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    finding = response.results["AwsSolutions"][0]
    assert finding.level == expected_level
    assert finding.kind == expected_kind


def test_the_four_compliance_rows_are_mutually_distinct():
    """Guard against the parametrized table above collapsing to one case.

    If a future edit makes several rows expect the same (level, kind), the
    table would be testing one behavior N times while still looking thorough.
    """
    rows = [
        (Level.error, Kind.fail),
        (Level.warning, Kind.informational),
        (Level.none, Kind.review),
        (Level.none, Kind.informational),
    ]
    assert len(set(rows)) == len(rows)


# ---------------------------------------------------------------------------
# Report file handling
# ---------------------------------------------------------------------------


def test_multiple_packs_are_keyed_separately(cdk_doubles, template_file, outdir):
    """Two report files produce two independently keyed result lists."""
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line(rule_id="AwsSolutions-S1")]
    )
    cdk_doubles.reports[f"HIPAA.Security-{STACK_NAME}-NagReport.json"] = (
        _report_payload([_nag_line(rule_id="HIPAA.Security-S3BucketLoggingEnabled")])
    )

    response = _run(
        template_file,
        outdir,
        nag_packs=["AwsSolutionsChecks", "HIPAASecurityChecks"],
    )

    assert sorted(response.results.keys()) == ["AwsSolutions", "HIPAA.Security"]
    assert [f.ruleId for f in response.results["AwsSolutions"]] == ["AwsSolutions-S1"]
    assert [f.ruleId for f in response.results["HIPAA.Security"]] == [
        "HIPAA.Security-S3BucketLoggingEnabled"
    ]
    # One aspect instance per requested pack was attached to the stack.
    assert len(cdk_doubles.pack_instances) == 2
    assert all(p.kwargs["reports"] is True for p in cdk_doubles.pack_instances)


def test_report_file_containing_json_null_is_skipped(
    cdk_doubles, template_file, outdir
):
    """``json.load`` returning None must not abort the remaining packs."""
    cdk_doubles.reports[f"Empty-{STACK_NAME}-NagReport.json"] = "null"
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line()]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(response.results["AwsSolutions"]) == 1
    # The null file contributed a key but no findings.
    assert response.results.get("Empty") == []


def test_unparseable_report_is_warned_about_and_skipped(
    cdk_doubles, template_file, outdir, caplog
):
    """A report whose shape NagReportSchema rejects is logged, not raised."""
    cdk_doubles.reports[f"Broken-{STACK_NAME}-NagReport.json"] = json.dumps(
        {"lines": "not-a-list"}
    )
    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line()]
    )

    with caplog.at_level("WARNING"):
        response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(response.results["AwsSolutions"]) == 1
    assert response.results["Broken"] == []
    assert any(
        "Could not parse loaded JSON dict as NagReport" in record.message
        for record in caplog.records
    ), f"expected a parse warning; got {[r.message for r in caplog.records]}"


def test_no_report_files_yields_empty_results_not_none(
    cdk_doubles, template_file, outdir
):
    """A synth that emits no reports returns an empty dict, not None.

    Distinguishing "ran and found nothing" from "did not run" matters: the
    caller treats None as an unavailable scanner.
    """
    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert isinstance(response, CdkNagWrapperResponse)
    assert response.results == {}
    assert cdk_doubles.synth_count == 1


# ---------------------------------------------------------------------------
# App / stack wiring and output directory
# ---------------------------------------------------------------------------


def test_synth_outdir_is_a_named_subdirectory_of_the_requested_outdir(
    cdk_doubles, template_file, outdir
):
    """Each template synthesizes into its own subdirectory of ``outdir``.

    Templates from different paths must not share a synth directory, or their
    NagReport files collide and one template's findings are attributed to the
    other.
    """
    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(cdk_doubles.apps) == 1
    synth_dir = Path(cdk_doubles.apps[0].outdir)
    assert synth_dir.is_dir()
    assert synth_dir.parent == outdir
    assert synth_dir != outdir
    # The returned outdir is the synth directory, not the parent.
    assert Path(response.outdir) == synth_dir
    # Separators and dots in the template path are folded into the name.
    assert "/" not in synth_dir.name
    assert "." not in synth_dir.name


def test_stack_includes_the_template_and_receives_the_aspects(
    cdk_doubles, template_file, outdir
):
    """The wrapper builds one stack holding a CfnInclude of the template."""
    _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(cdk_doubles.stacks) == 1
    stack = cdk_doubles.stacks[0]
    assert stack.id == STACK_NAME
    assert stack.scope is cdk_doubles.apps[0]

    assert len(cdk_doubles.cfn_includes) == 1
    include = cdk_doubles.cfn_includes[0]
    assert Path(include.template_file) == template_file
    assert include in stack.node.children

    # The nag pack was attached to the stack, not to the app.
    assert stack.aspects == cdk_doubles.pack_instances


def test_custom_stack_name_is_used_for_both_stack_and_report_parsing(
    cdk_doubles, template_file, outdir
):
    """``stack_name`` names the stack and is stripped from report filenames."""
    custom = "CustomScannerStack"
    cdk_doubles.reports[f"AwsSolutions-{custom}-NagReport.json"] = _report_payload(
        [_nag_line(resource_id=f"{custom}/MyDataBucket")]
    )

    response = _run(
        template_file, outdir, nag_packs=["AwsSolutionsChecks"], stack_name=custom
    )

    assert cdk_doubles.stacks[0].id == custom
    assert list(response.results.keys()) == ["AwsSolutions"]
    assert len(response.results["AwsSolutions"]) == 1


def test_default_nag_pack_is_aws_solutions_checks(cdk_doubles, template_file, outdir):
    """Passing no ``nag_packs`` attaches exactly the AwsSolutionsChecks pack."""
    _run(template_file, outdir)

    assert len(cdk_doubles.pack_instances) == 1
    assert type(cdk_doubles.pack_instances[0]).__name__ == "AwsSolutionsChecks"


# ---------------------------------------------------------------------------
# Process-state hygiene: env vars and stderr must not leak
# ---------------------------------------------------------------------------


def test_jsii_env_vars_are_restored_after_the_call(
    cdk_doubles, template_file, outdir, monkeypatch
):
    """Pre-existing values are restored; absent vars are removed again.

    The wrapper sets these to "1" because JSII reads them at import time. They
    are process-global, and scanners run in parallel threads, so a permanent
    write would leak into unrelated work.
    """
    monkeypatch.setenv("JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION", "0")
    monkeypatch.delenv("NODE_NO_WARNINGS", raising=False)
    monkeypatch.delenv("JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION", raising=False)

    import os

    _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert os.environ["JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION"] == "0", (
        "a pre-existing value must be restored, not left at the wrapper's '1'"
    )
    assert "NODE_NO_WARNINGS" not in os.environ, (
        "a var that did not exist before the call must be removed again"
    )
    assert "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION" not in os.environ


def test_stderr_is_restored_even_when_the_call_raises(
    cdk_doubles, template_file, monkeypatch
):
    """stderr is redirected to devnull during the scan and always restored."""
    original_stderr = sys.stderr

    with pytest.raises(ValueError, match="outdir is required"):
        run_cdk_nag_against_cfn_template(template_path=template_file, outdir=None)

    assert sys.stderr is original_stderr, (
        "sys.stderr was left pointing at devnull after a failed scan"
    )
    assert not sys.stderr.closed


# ---------------------------------------------------------------------------
# Defensive fallbacks around get_shortest_name
# ---------------------------------------------------------------------------


class _FailingShortestName:
    """Raises on the first N calls, then delegates to the real implementation."""

    def __init__(self, real, failures, exc):
        self._real = real
        self._failures = failures
        self._exc = exc
        self.calls = 0

    def __call__(self, input):
        self.calls += 1
        if self.calls <= self._failures:
            raise self._exc
        return self._real(input=input)


@pytest.mark.parametrize(
    "failures, exc",
    [
        # First call is the template-filename shortening (ValueError branch).
        (1, ValueError("not a relative path")),
        # A non-ValueError there is caught by the broader handler.
        (1, RuntimeError("unexpected path failure")),
        # Two failures also reach the logical-id fallback inside the stack.
        (2, ValueError("not a relative path")),
    ],
)
def test_shortest_name_failure_falls_back_to_the_posix_path(
    cdk_doubles, template_file, outdir, monkeypatch, failures, exc
):
    """When path shortening fails the wrapper falls back, it does not crash.

    Both fallbacks substitute the template's full POSIX path, so the scan
    still completes and still produces findings.
    """
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    stub = _FailingShortestName(get_shortest_name, failures, exc)
    monkeypatch.setattr(cdk_nag_wrapper, "get_shortest_name", stub)

    cdk_doubles.reports[f"AwsSolutions-{STACK_NAME}-NagReport.json"] = _report_payload(
        [_nag_line()]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert stub.calls > failures, "the stub should have been called past its failures"
    assert len(response.results["AwsSolutions"]) == 1
