"""Behavior tests for ``run_cdk_nag_against_cfn_template``.

The wrapper imports ``cdk_nag``, ``aws_cdk`` and ``constructs`` lazily, from inside the
function body. Without them the call returns at the ``except (ImportError,
FileNotFoundError)`` guard and nothing after it runs, which is why the module measured 27%
covered while the older regression tests all passed: those tests assert on the *source text*
of the module, so they never execute the report-parsing code at all.

These tests install module doubles in ``sys.modules`` for the duration of one call so the
whole body runs. Three properties of the doubles are load-bearing:

* Each one is a real class with exactly the attributes the wrapper touches, so a call to a
  method that does not exist raises ``AttributeError`` instead of quietly succeeding the way a
  bare ``Mock()`` would.
* ``App.synth()`` writes ``validation-report.json``, because that is what CDK's policy
  validation framework does and that file is the wrapper's only input. A synth that emits
  nothing is the "subprocess exits 0 having run nothing" trap in this module, so the report
  payload is supplied by the test and asserted on the way out.
* The payload shape is copied from a real report produced by aws-cdk-lib 2.267.0 and cdk-nag
  3.x, not from the wrapper's parser. Writing doubles from the parser would make them agree
  with it by construction and prove nothing about whether it reads what cdk-nag writes.

WHY THIS FILE WAS REWRITTEN FOR CDK-NAG 3.x
-------------------------------------------

It was originally written against cdk-nag 2.x and modelled that major faithfully, which is
precisely why it failed the moment the wrapper migrated -- the doubles were right and the
interface had moved. Three things changed, and each one invalidated the *subject* of a test
rather than just its plumbing:

1. Packs were ``IAspect`` and were attached with ``Aspects.of(stack).add(...)``. From 3.0.0
   they are ``IPolicyValidationPlugin`` and are attached with
   ``Validations.of(app).add_plugins(...)`` -- note the app, not the stack. ``Aspects`` is
   deliberately absent from the ``aws_cdk`` double below so a regression to the aspect
   registration fails at import rather than attaching nothing and evaluating no rules.
2. Findings arrived in per-pack ``<Pack>-<Stack>-NagReport.json`` files. They now arrive in a
   single ``validation-report.json``, keyed by ``pluginReports[].pluginName``. The stack name
   no longer participates in locating findings at all.
3. The report carries violations only. There is no compliant record and no suppressed record,
   so ``include_compliant_checks`` has nothing left to include and three of the four rows in
   the compliance mapping are unreachable from a real scan. Those rows are tested against
   :func:`_level_and_kind` directly instead of through a faked report, because a report
   containing a "Compliant" row is a payload cdk-nag cannot produce and asserting on one
   would be asserting on fiction.
"""

import base64
import json
import sys
import types
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind, Kind1, Level
from automated_security_helper.utils import cdk_nag_wrapper
from automated_security_helper.utils.cdk_nag_wrapper import (
    CdkNagWrapperResponse,
    _level_and_kind,
    _normalize_rule_level,
    run_cdk_nag_against_cfn_template,
)

STACK_NAME = "ASHCDKNagScanner"

# The middle segment of a v3 construct path is the shortened template name that CfnInclude was
# given as its logical id. The wrapper reads only the LAST segment, so this value is arbitrary
# -- it is realistic here so the fixture looks like the real report it was copied from.
TEMPLATE_SEGMENT = "--tmp--secure-s3-template--yaml"

# ``MyDataBucketPolicy`` deliberately precedes ``MyDataBucket`` so that a substring search for
# "MyDataBucket" would hit the *policy* line first. The wrapper uses a word-boundary regex, so
# the reported line must be the later one. See
# test_finding_line_number_uses_word_boundary_not_substring.
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

DEFAULT_DESCRIPTION = "The S3 Bucket has server access logs disabled."


def _construct_path(logical_id="MyDataBucket", stack=STACK_NAME):
    """Build a construct path in the shape CfnInclude produces under a validation plugin."""
    return f"{stack}/{TEMPLATE_SEGMENT}/{logical_id}"


def _violation(
    rule_name="AwsSolutions-S1",
    description=DEFAULT_DESCRIPTION,
    severity="error",
    construct_paths=None,
    violating_resources=None,
):
    """One ``pluginReports[].violations[]`` entry, camelCase as CDK writes it.

    ``violatingResources`` is included and left null on purpose. The real report carries both
    keys, with the resources one always null, and the jsii class ``aws_cdk.PolicyViolation``
    exposes it as ``violating_resources`` -- so a parser written from the class rather than
    from the file reads the null key, finds no constructs, and reports a violating template as
    clean. Keeping the decoy in the fixture means that mistake fails a test.
    """
    if construct_paths is None:
        construct_paths = [_construct_path()]
    return {
        "ruleName": rule_name,
        "description": description,
        "severity": severity,
        "violatingConstructs": [
            {
                "constructPath": path,
                "constructFqn": "aws-cdk-lib.aws_s3.CfnBucket",
                "libraryVersion": "2.267.0",
                "stackTraces": ["...aws-cdk-lib, jsii runtime, node internals..."],
            }
            for path in construct_paths
        ],
        "violatingResources": violating_resources,
    }


def _plugin_report(plugin_name="AwsSolutions", violations=None, conclusion="failure"):
    """One ``pluginReports[]`` entry. Keys measured from a real report."""
    return {
        "pluginName": plugin_name,
        "conclusion": conclusion,
        "violations": [] if violations is None else list(violations),
    }


def _report(*plugin_reports):
    """Serialize a whole ``validation-report.json``."""
    return json.dumps(
        {
            "version": "54.0.0",
            "title": "Validation Report",
            "pluginReports": list(plugin_reports),
        }
    )


def _one_violation_report(**violation_kwargs):
    """The common case: one pack, one violation, one construct."""
    return _report(_plugin_report(violations=[_violation(**violation_kwargs)]))


class _Recorder:
    """Collects the objects the wrapper built, so tests can assert on them."""

    def __init__(self):
        self.apps = []
        self.stacks = []
        self.cfn_includes = []
        self.pack_instances = []
        # The text ``App.synth()`` writes to validation-report.json. None means write no file
        # at all, which is how "cdk-nag evaluated nothing" is expressed.
        self.report_text = None
        # Set to an exception instance to make synth raise after writing the report. Real CDK
        # raises when a plugin reports violations, so this is the ordinary path, not an edge
        # case. See test_findings_survive_the_synth_raise_that_violations_cause.
        self.synth_raises = None
        self.synth_count = 0


@pytest.fixture
def cdk_doubles(monkeypatch):
    """Install ``cdk_nag`` / ``aws_cdk`` / ``constructs`` doubles.

    Returns a :class:`_Recorder`. Assign ``recorder.report_text`` before calling the wrapper;
    ``App.synth()`` writes it to ``validation-report.json`` in the synth output directory.
    """
    recorder = _Recorder()

    # ---- cdk_nag -------------------------------------------------------
    class NagPack:
        """Mirrors the real ``NagPack`` constructor signature exactly.

        Measured from cdk_nag 3.x:
        ``(self, scope=None, *, verbose=None, write_suppressions_to_cloud_formation=None)``.
        The signature is copied rather than approximated with ``**kwargs`` so that passing
        ``reports=True`` -- which 2.x accepted and 3.x rejects -- raises ``TypeError`` here
        just as it does against the installed package. A ``**kwargs`` double would swallow it
        and let the wrapper keep passing a dead argument forever.
        """

        def __init__(
            self,
            scope=None,
            *,
            verbose=None,
            write_suppressions_to_cloud_formation=None,
        ):
            self.scope = scope
            self.verbose = verbose
            self.write_suppressions_to_cloud_formation = (
                write_suppressions_to_cloud_formation
            )
            recorder.pack_instances.append(self)

        def validate(self, context):
            """v3 packs are plugins, so they validate. Present so ``hasattr`` agrees."""
            raise AssertionError(
                "validate() is CDK's to call during synth, not the wrapper's"
            )

    class AwsSolutionsChecks(NagPack):
        pass

    class HIPAASecurityChecks(NagPack):
        pass

    class NotANagPack:
        """Present so the isclass/issubclass filter has something to reject."""

    cdk_nag_mod = types.ModuleType("cdk_nag")
    cdk_nag_mod.NagPack = NagPack
    cdk_nag_mod.AwsSolutionsChecks = AwsSolutionsChecks
    cdk_nag_mod.HIPAASecurityChecks = HIPAASecurityChecks
    cdk_nag_mod.NotANagPack = NotANagPack

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
            # Kept so a test can assert it stayed EMPTY. Under 2.x the packs landed here; if
            # they land here again the plugins never register and no rule is evaluated.
            self.aspects = []
            recorder.stacks.append(self)

    class CfnInclude:
        def __init__(self, scope, id, template_file):
            self.scope = scope
            self.id = id
            self.template_file = template_file
            scope.node.children.append(self)
            recorder.cfn_includes.append(self)

    class _ValidationRegistrar:
        def __init__(self, target):
            self._target = target

        def add_plugins(self, *plugins):
            """Variadic, matching ``Validations.add_plugins(self, *plugins)``."""
            self._target.plugins.extend(plugins)

    class Validations:
        @staticmethod
        def of(scope):
            return _ValidationRegistrar(scope)

    class App:
        def __init__(self, outdir):
            self.outdir = outdir
            self.plugins = []
            recorder.apps.append(self)

        def synth(self):
            recorder.synth_count += 1
            if recorder.report_text is not None:
                Path(self.outdir).joinpath("validation-report.json").write_text(
                    recorder.report_text, encoding="utf-8"
                )
            if recorder.synth_raises is not None:
                raise recorder.synth_raises

    aws_cdk_mod = types.ModuleType("aws_cdk")
    aws_cdk_mod.App = App
    aws_cdk_mod.Stack = Stack
    aws_cdk_mod.Validations = Validations
    # NOTE: no ``Aspects``. Its absence is the tripwire described in the module docstring.

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

    ``NotANagPack`` exists on the cdk_nag double but is not a NagPack subclass, so the pack
    lookup must not contain it, and an unresolvable name must raise rather than be skipped.
    Skipping it would let a request for several packs evaluate a subset and still exit zero.
    """
    with pytest.raises(KeyError):
        _run(template_file, outdir, nag_packs=["NotANagPack"])


def test_one_bad_pack_name_fails_the_whole_call_not_just_that_pack(
    cdk_doubles, template_file, outdir
):
    """A misspelled pack among valid ones is fatal, and nothing is synthesized.

    This is the partial-scan case, and it is the one a "log the error and continue" branch
    lets through: two of three requested packs evaluate, the run exits zero, and the only
    record that a third of the requested rules never ran is a log line nobody reads. The
    total-failure guard does not catch it either, because some packs did register.
    """
    cdk_doubles.report_text = _one_violation_report()

    with pytest.raises(KeyError, match="NotANagPack"):
        _run(
            template_file,
            outdir,
            nag_packs=["AwsSolutionsChecks", "NotANagPack", "HIPAASecurityChecks"],
        )

    assert cdk_doubles.synth_count == 0, (
        "the call must fail before synthesis, not scan with a partial pack set"
    )


def test_empty_pack_list_returns_none_rather_than_an_empty_clean_result(
    cdk_doubles, template_file, outdir
):
    """Requesting zero packs cannot produce a report, so it must not look like a clean scan.

    With no pack registered no rule can fire, and the resulting empty findings set is
    indistinguishable from a compliant template. None is the signal the scanner reads as
    "unavailable", which is the honest answer here.
    """
    assert _run(template_file, outdir, nag_packs=[]) is None
    assert cdk_doubles.pack_instances == []


# ---------------------------------------------------------------------------
# The happy path: a non-empty report must produce non-empty findings
# ---------------------------------------------------------------------------


def test_non_empty_validation_report_produces_non_empty_findings(
    cdk_doubles, template_file, outdir
):
    """A report with one violation yields exactly one SARIF result.

    This is the anti-"clean scan" assertion: an empty-parse bug in the report handling would
    return an empty results dict and read as a passing scan, which is the defect the v3
    migration exists to fix.
    """
    cdk_doubles.report_text = _one_violation_report()

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response is not None
    # The results key comes from pluginReports[].pluginName. Under 2.x it came from the report
    # *filename*, which no longer exists.
    assert list(response.results.keys()) == ["AwsSolutions"]
    findings = response.results["AwsSolutions"]
    assert len(findings) == 1, (
        f"expected 1 finding from a 1-violation report, got {len(findings)}"
    )

    finding = findings[0]
    assert finding.ruleId == "AwsSolutions-S1"
    assert finding.level == Level.error
    assert finding.kind == Kind.fail
    assert finding.message.root.text == (
        f"{DEFAULT_DESCRIPTION}\n\nException Reason: N/A"
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

    # The raw record is attached for the scanner, which indexes it by these keys.
    raw = finding.properties.model_extra["cdk_nag_finding"]
    assert raw["rule_id"] == "AwsSolutions-S1"
    assert raw["compliance"] == "Non-Compliant"
    assert raw["rule_level"] == "Error"

    # The template model is handed back so the caller can resolve resources.
    assert "MyDataBucket" in response.template.Resources
    assert response.template.Resources["MyDataBucket"].Type == "AWS::S3::Bucket"


def test_the_parser_reads_violating_constructs_not_violating_resources(
    cdk_doubles, template_file, outdir
):
    """The findings must come from ``violatingConstructs``, the key CDK actually writes.

    Both keys exist in a real report and ``violatingResources`` is always null, while the
    jsii class exposes the resources name in snake_case. A parser written from the class
    reads the null key and reports a violating template as clean -- the exact defect class
    this module is being hardened against, one level down. Populating only the decoy must
    therefore yield nothing.
    """
    decoy_only = _report(
        _plugin_report(
            violations=[
                {
                    "ruleName": "AwsSolutions-S1",
                    "description": DEFAULT_DESCRIPTION,
                    "severity": "error",
                    "violatingConstructs": [],
                    "violatingResources": [
                        {"constructPath": _construct_path(), "constructFqn": "x"}
                    ],
                }
            ]
        )
    )
    cdk_doubles.report_text = decoy_only

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response.results == {"AwsSolutions": []}, (
        "violatingResources must not be read; if it is, the real report's null value "
        "silently yields zero findings"
    )


def test_one_violation_citing_two_constructs_becomes_two_findings(
    cdk_doubles, template_file, outdir
):
    """Each violating construct gets its own SARIF result.

    Measured against the real library: AwsSolutions-S10 cites both the bucket and its policy
    in a single violation. Collapsing them to one finding would report a single location for
    two non-compliant resources, and whichever one lost would look compliant.
    """
    cdk_doubles.report_text = _report(
        _plugin_report(
            violations=[
                _violation(
                    rule_name="AwsSolutions-S10",
                    construct_paths=[
                        _construct_path("MyDataBucket"),
                        _construct_path("MyDataBucketPolicy"),
                    ],
                )
            ]
        )
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    findings = response.results["AwsSolutions"]
    assert len(findings) == 2
    resources = sorted(
        f.properties.model_extra["cdk_nag_finding"]["resource_id"].split("/")[-1]
        for f in findings
    )
    assert resources == ["MyDataBucket", "MyDataBucketPolicy"]


def test_a_construct_with_no_path_is_skipped_not_crashed_on(
    cdk_doubles, template_file, outdir
):
    """A violating construct missing ``constructPath`` cannot be located, so it is dropped."""
    cdk_doubles.report_text = _report(
        _plugin_report(
            violations=[
                {
                    "ruleName": "AwsSolutions-S1",
                    "description": DEFAULT_DESCRIPTION,
                    "severity": "error",
                    "violatingConstructs": [
                        {"constructFqn": "aws-cdk-lib.aws_s3.CfnBucket"},
                        {"constructPath": _construct_path()},
                    ],
                }
            ]
        )
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(response.results["AwsSolutions"]) == 1


def test_finding_line_number_uses_word_boundary_not_substring(
    cdk_doubles, template_file, outdir
):
    """The reported region points at ``MyDataBucket:``, not ``MyDataBucketPolicy:``.

    ``MyDataBucketPolicy`` appears on an earlier line and contains ``MyDataBucket`` as a
    prefix. A substring search would report that earlier line; the word-boundary regex must
    skip it. This also pins the 1-based line numbering -- a 0-based ``enumerate`` would report
    one line early.
    """
    cdk_doubles.report_text = _one_violation_report()

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


def test_only_the_last_construct_path_segment_is_used_as_the_logical_id(
    cdk_doubles, template_file, outdir
):
    """``<stack>/<template>/<LogicalId>`` resolves by its final segment.

    The construct path carries the stack name and the template's CfnInclude id ahead of the
    logical id. Reading any earlier segment, or the whole path, would fail every lookup
    against ``model.Resources`` and return an empty -- clean-looking -- result set.
    """
    cdk_doubles.report_text = _one_violation_report(
        construct_paths=[
            "SomeOtherStackName/an--unrelated--template--yaml/MyDataBucket"
        ]
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    findings = response.results["AwsSolutions"]
    assert len(findings) == 1, (
        "the leading segments are not part of the logical id and must not affect lookup"
    )
    assert "MyDataBucket" in findings[0].properties.tags


def test_resource_absent_from_template_is_dropped(cdk_doubles, template_file, outdir):
    """A violation naming a resource the template does not define is skipped."""
    cdk_doubles.report_text = _report(
        _plugin_report(
            violations=[
                _violation(
                    construct_paths=[_construct_path("ResourceThatIsNotInTheTemplate")]
                ),
                _violation(rule_name="AwsSolutions-S2"),
            ]
        )
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    rule_ids = [f.ruleId for f in response.results["AwsSolutions"]]
    assert rule_ids == ["AwsSolutions-S2"], (
        f"only the resolvable resource should survive; got {rule_ids}"
    )


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity, expected_level, expected_kind",
    [
        # The report writes lower case. Comparing it raw against "Error" fails, which would
        # demote every real error to a warning and slip it under a severity gate.
        ("error", Level.error, Kind.fail),
        ("ERROR", Level.error, Kind.fail),
        ("warning", Level.warning, Kind.informational),
        ("info", Level.warning, Kind.informational),
    ],
)
def test_report_severity_is_normalized_before_the_level_comparison(
    cdk_doubles, template_file, outdir, severity, expected_level, expected_kind
):
    """Severity casing must not decide whether a finding fails the scan."""
    cdk_doubles.report_text = _one_violation_report(severity=severity)

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    finding = response.results["AwsSolutions"][0]
    assert finding.level == expected_level
    assert finding.kind == expected_kind


@pytest.mark.parametrize("severity", ["", None, "catastrophe"])
def test_an_unrecognized_severity_is_treated_as_an_error(
    cdk_doubles, template_file, outdir, severity
):
    """An unmapped severity fails the scan rather than being quietly downgraded.

    A new severity string in a future cdk-nag would otherwise land in the warning bucket and
    stop failing builds, which is the wrong direction for an unknown.
    """
    cdk_doubles.report_text = _one_violation_report(severity=severity)

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response.results["AwsSolutions"][0].level == Level.error


def test_normalize_rule_level_maps_only_the_documented_strings():
    """Direct coverage of the mapping, including the error-on-unknown default."""
    assert _normalize_rule_level("error") == "Error"
    assert _normalize_rule_level("Error") == "Error"
    assert _normalize_rule_level("  warning  ") == "Warning"
    assert _normalize_rule_level("info") == "Info"
    assert _normalize_rule_level("") == "Error"
    assert _normalize_rule_level("something-new") == "Error"


# ---------------------------------------------------------------------------
# Compliance -> level/kind mapping
#
# Tested against _level_and_kind directly. The v3 validation report contains violations only,
# so "Compliant" and "Suppressed" records cannot arise from a real scan and faking a report
# that contains one would assert against a payload cdk-nag cannot write.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "compliance, rule_level, exception_reason, expected_level, expected_kind",
    [
        # Non-compliant + Error is the only combination that fails the scan, and the only one
        # the v3 report can currently produce.
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
        # A compliant record carries no severity signal at all.
        ("Compliant", "Error", "N/A", Level.none, Kind.informational),
    ],
)
def test_compliance_maps_to_distinct_level_and_kind(
    compliance, rule_level, exception_reason, expected_level, expected_kind
):
    """Each compliance/rule-level pair maps to its own (level, kind) pair."""
    assert _level_and_kind(
        compliance=compliance,
        rule_level=rule_level,
        exception_reason=exception_reason,
    ) == (expected_level, expected_kind)


def test_the_four_compliance_rows_are_mutually_distinct():
    """Guard against the parametrized table above collapsing to one case.

    If a future edit makes several rows expect the same (level, kind), the table would be
    testing one behavior N times while still looking thorough. The compliant row is excluded
    because it shares (none, informational) with an unreasoned suppression by design -- the
    four rows below are the ones required to stay distinct.
    """
    rows = [
        (Level.error, Kind.fail),
        (Level.warning, Kind.informational),
        (Level.none, Kind.review),
        (Level.none, Kind.informational),
    ]
    assert len(set(rows)) == len(rows)


def test_every_finding_from_a_v3_report_is_non_compliant(
    cdk_doubles, template_file, outdir
):
    """The report carries violations only, so no other compliance state can be produced.

    This is what makes the three unreachable rows above unreachable, and it is asserted rather
    than assumed because it is the premise the reachability argument rests on.
    """
    cdk_doubles.report_text = _report(
        _plugin_report(
            violations=[_violation(), _violation(rule_name="AwsSolutions-S2")]
        )
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    compliances = {
        f.properties.model_extra["cdk_nag_finding"]["compliance"]
        for f in response.results["AwsSolutions"]
    }
    assert compliances == {"Non-Compliant"}


def test_include_compliant_checks_is_inert_against_a_v3_report(
    cdk_doubles, template_file, outdir
):
    """``include_compliant_checks`` no longer changes the result, and that is a behavior loss.

    Under cdk-nag 2.x the report listed compliant and suppressed checks alongside violations,
    so this flag surfaced them. The v3 validation report has no such records, so the flag has
    nothing to include. It is kept in the signature because callers pass it, but the two
    results are identical and a reader should not expect otherwise.
    """
    cdk_doubles.report_text = _one_violation_report()
    without = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    cdk_doubles.report_text = _one_violation_report()
    with_flag = _run(
        template_file,
        outdir,
        nag_packs=["AwsSolutionsChecks"],
        include_compliant_checks=True,
    )

    assert [f.ruleId for f in without.results["AwsSolutions"]] == [
        f.ruleId for f in with_flag.results["AwsSolutions"]
    ]
    assert len(with_flag.results["AwsSolutions"]) == 1


# ---------------------------------------------------------------------------
# Report file handling
# ---------------------------------------------------------------------------


def test_multiple_packs_are_keyed_separately(cdk_doubles, template_file, outdir):
    """Two plugin reports in one file produce two independently keyed result lists.

    Under 2.x this came from two files. It is now two ``pluginReports[]`` entries in a single
    ``validation-report.json``.
    """
    cdk_doubles.report_text = _report(
        _plugin_report(
            plugin_name="AwsSolutions",
            violations=[_violation(rule_name="AwsSolutions-S1")],
        ),
        _plugin_report(
            plugin_name="HIPAA.Security",
            violations=[_violation(rule_name="HIPAA.Security-S3BucketLoggingEnabled")],
        ),
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
    # One plugin instance per requested pack, each constructed with the only property v3
    # exposes that this wrapper cares about.
    assert len(cdk_doubles.pack_instances) == 2
    assert all(p.verbose is True for p in cdk_doubles.pack_instances)


def test_pack_construction_passes_no_argument_v3_rejects(
    cdk_doubles, template_file, outdir
):
    """The pack is built with kwargs the installed cdk-nag accepts.

    ``reports=True`` and ``report_formats=[...]`` were the 2.x way to get a file report and
    are hard errors in 3.x. That single constructor call is where a breaking major bump lands,
    and while it sat inside the per-template loop the only way to reach it was a full
    synthesis, which nothing in the suite did.

    The second half is a positive control: it proves the double would in fact reject the dead
    argument, so the first half is evidence rather than an artifact of a permissive fake.
    """
    cdk_doubles.report_text = _one_violation_report()

    _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    pack = cdk_doubles.pack_instances[0]
    assert pack.verbose is True
    assert pack.write_suppressions_to_cloud_formation is None

    import cdk_nag  # the double installed by the fixture

    with pytest.raises(TypeError, match="reports"):
        cdk_nag.AwsSolutionsChecks(reports=True)


def test_report_containing_json_null_is_skipped(cdk_doubles, template_file, outdir):
    """A report file holding literal ``null`` must not crash the scanner.

    ``json.loads("null")`` returns None, and calling ``.get`` on it raises AttributeError out
    of the wrapper and into the scanner as an unhandled error. It decodes successfully, so a
    try/except around the parse does not catch it -- the decoded type has to be checked.
    """
    cdk_doubles.report_text = "null"

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert isinstance(response, CdkNagWrapperResponse)
    assert response.results == {}


def test_unparseable_report_is_logged_and_skipped(
    cdk_doubles, template_file, outdir, caplog
):
    """A malformed report is logged at error level, not raised."""
    cdk_doubles.report_text = "{not valid json"

    with caplog.at_level("ERROR"):
        response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response.results == {}
    assert any(
        "Could not parse cdk-nag validation report" in record.message
        for record in caplog.records
    ), f"expected a parse error; got {[r.message for r in caplog.records]}"


def test_a_plugin_report_with_null_violations_yields_an_empty_list_not_a_crash(
    cdk_doubles, template_file, outdir
):
    """``violations: null`` is a plugin that reported nothing, not a broken report."""
    cdk_doubles.report_text = json.dumps(
        {
            "version": "54.0.0",
            "title": "Validation Report",
            "pluginReports": [
                {
                    "pluginName": "AwsSolutions",
                    "conclusion": "success",
                    "violations": None,
                }
            ],
        }
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response.results == {"AwsSolutions": []}


def test_a_missing_report_is_reported_as_nothing_scanned(
    cdk_doubles, template_file, outdir, caplog
):
    """A synth that writes no report must report the failure on the response, not only log it.

    This is the defect that started all of this. An absent report is indistinguishable, in the
    results, from a compliant template: both are an empty findings set. So the distinction is
    carried on ``response.failure``, and that is the assertion that matters here.

    An earlier version of this test asserted only ``results == {}`` plus the log line, while its
    docstring claimed the distinction also lived "in the scanner's target-failure counters". It
    did not: the scanner increments those only from its ``except`` block, and a report-less run
    returned a non-None response and raised nothing, so a template that evaluated no rule was
    counted as clean. The prose asserted more than the test did, which is how the two halves
    were able to drift apart while this file stayed green. The scanner-side half now lives in
    tests/unit/plugin_modules/ash_builtin/test_cdk_nag_scanner_behavior.py.

    An empty dict is still returned rather than None, so the caller can tell "ran and parsed
    nothing" from "the scanner is unavailable".
    """
    cdk_doubles.report_text = None

    with caplog.at_level("ERROR"):
        response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert isinstance(response, CdkNagWrapperResponse)
    assert response.results == {}
    assert cdk_doubles.synth_count == 1
    assert response.failure is not None, (
        "the response must carry the reason no rules were evaluated; a log line alone is not "
        "readable by the scanner, which is what let this pass as a clean scan"
    )
    assert "NOT scanned" in response.failure
    assert any("NOT scanned" in record.message for record in caplog.records), (
        "an absent validation report must be logged as nothing having been scanned; "
        f"got {[r.message for r in caplog.records]}"
    )


@pytest.mark.parametrize(
    "label, report_text, expect_failure",
    [
        # Every way the report can be unreadable must set ``failure``.
        ("no report written", None, True),
        ("literal null", "null", True),
        ("malformed json", "{not valid json", True),
        (
            "parsed but no plugin reported",
            json.dumps(
                {"version": "54.0.0", "title": "Validation Report", "pluginReports": []}
            ),
            True,
        ),
        # And every way it can be readable must leave it None, including the case that looks
        # like the failures above -- a pack that ran and found nothing.
        ("one violation", _one_violation_report(), False),
        (
            "pack ran, zero violations",
            _report(_plugin_report(violations=[], conclusion="success")),
            False,
        ),
        (
            "pack ran, violations null",
            json.dumps(
                {
                    "version": "54.0.0",
                    "title": "Validation Report",
                    "pluginReports": [
                        {
                            "pluginName": "AwsSolutions",
                            "conclusion": "success",
                            "violations": None,
                        }
                    ],
                }
            ),
            False,
        ),
    ],
)
def test_failure_is_set_exactly_when_no_rule_was_evaluated(
    cdk_doubles, template_file, outdir, label, report_text, expect_failure
):
    """``response.failure`` is the scanner's only readable signal, so pin both directions.

    The negative rows are the point. "A pack ran and found nothing" and "no report existed at
    all" both produce an empty findings set, and the whole defect was that the caller could not
    tell them apart. Asserting only the positive rows would pass just as well against a wrapper
    that marked every clean template as a failure, which would turn compliant repositories into
    scanner errors.

    A mutation that hardcoded ``failure=None`` on the response survived the scanner-side tests,
    because those drive a wrapper double and never exercise this return. This is the test that
    catches it.
    """
    cdk_doubles.report_text = report_text

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response is not None
    if expect_failure:
        assert response.failure is not None, (
            f"{label}: no rule was evaluated, so the response must say so"
        )
    else:
        assert response.failure is None, (
            f"{label}: cdk-nag did evaluate this template; got failure={response.failure!r}"
        )


def test_findings_survive_the_synth_raise_that_violations_cause(
    cdk_doubles, template_file, outdir
):
    """CDK raises when a plugin reports violations, and the report is still read.

    This is the ordinary path for a scanner, not an edge case: findings are the product. If
    the raise propagated, every non-compliant template would surface as a scanner error and
    its findings would be lost -- and cdk-nag 2.x, which did not raise, had no equivalent
    behavior for the older tests to cover.
    """
    cdk_doubles.report_text = _one_violation_report()
    cdk_doubles.synth_raises = RuntimeError(
        "Validation failed. See the validation report"
    )

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert response is not None
    assert len(response.results["AwsSolutions"]) == 1


# ---------------------------------------------------------------------------
# App / stack wiring and output directory
# ---------------------------------------------------------------------------


def test_synth_outdir_is_a_named_subdirectory_of_the_requested_outdir(
    cdk_doubles, template_file, outdir
):
    """Each template synthesizes into its own subdirectory of ``outdir``.

    Templates from different paths must not share a synth directory, or their reports collide
    and one template's findings are attributed to the other.
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


def test_stack_includes_the_template_and_the_app_receives_the_plugins(
    cdk_doubles, template_file, outdir
):
    """The wrapper builds one stack holding a CfnInclude, and registers plugins on the app.

    This assertion is inverted from its cdk-nag 2.x form, which required the packs to be on
    the stack and not the app. v3 packs are ``IPolicyValidationPlugin`` -- ``visit`` is absent
    and ``validate`` is present -- so they belong to the app's validation set. Registering
    them as stack aspects attaches nothing and evaluates no rule, which is why the stack is
    asserted to have received none.
    """
    cdk_doubles.report_text = _one_violation_report()

    _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert len(cdk_doubles.stacks) == 1
    stack = cdk_doubles.stacks[0]
    assert stack.id == STACK_NAME
    assert stack.scope is cdk_doubles.apps[0]

    assert len(cdk_doubles.cfn_includes) == 1
    include = cdk_doubles.cfn_includes[0]
    assert Path(include.template_file) == template_file
    assert include in stack.node.children

    # The nag pack was registered on the app, as a validation plugin.
    assert cdk_doubles.apps[0].plugins == cdk_doubles.pack_instances
    assert stack.aspects == [], (
        "packs registered as stack aspects evaluate nothing under cdk-nag 3.x"
    )


def test_custom_stack_name_names_the_stack(cdk_doubles, template_file, outdir):
    """``stack_name`` names the stack; it no longer participates in finding lookup.

    Under 2.x the stack name was embedded in each report's filename and was stripped back off
    to key the results, so a mismatch dropped every finding. v3 keys by plugin name and
    locates resources by the construct path's last segment, so the stack name is now
    incidental -- which is the more robust arrangement, and is asserted here by resolving
    findings whose construct path names a different stack entirely.
    """
    custom = "CustomScannerStack"
    cdk_doubles.report_text = _one_violation_report(
        construct_paths=[_construct_path(stack=custom)]
    )

    response = _run(
        template_file, outdir, nag_packs=["AwsSolutionsChecks"], stack_name=custom
    )

    assert cdk_doubles.stacks[0].id == custom
    assert list(response.results.keys()) == ["AwsSolutions"]
    assert len(response.results["AwsSolutions"]) == 1


def test_default_nag_pack_is_aws_solutions_checks(cdk_doubles, template_file, outdir):
    """Passing no ``nag_packs`` registers exactly the AwsSolutionsChecks pack."""
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

    The wrapper sets these to "1" because JSII reads them at import time. They are
    process-global, and scanners run in parallel threads, so a permanent write would leak into
    unrelated work.
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


def test_env_vars_are_restored_even_when_a_bad_pack_name_raises(
    cdk_doubles, template_file, outdir, monkeypatch
):
    """The restore is in a finally block, so a raise on the way through still runs it.

    Worth its own case now that an unknown pack raises rather than logging: the raise happens
    after the env vars have been set and before the normal return.
    """
    monkeypatch.delenv("NODE_NO_WARNINGS", raising=False)

    import os

    with pytest.raises(KeyError):
        _run(template_file, outdir, nag_packs=["NotANagPack"])

    assert "NODE_NO_WARNINGS" not in os.environ


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

    Both fallbacks substitute the template's full POSIX path, so the scan still completes and
    still produces findings.
    """
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    stub = _FailingShortestName(get_shortest_name, failures, exc)
    monkeypatch.setattr(cdk_nag_wrapper, "get_shortest_name", stub)

    cdk_doubles.report_text = _one_violation_report()

    response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert stub.calls > failures, "the stub should have been called past its failures"
    assert len(response.results["AwsSolutions"]) == 1


# ---------------------------------------------------------------------------
# In-band suppressions: Metadata.cdk_nag.rules_to_suppress
# ---------------------------------------------------------------------------
#
# A template synthesized by a CDK app that ran cdk-nag carries that app's reviewed
# suppressions in its own resource metadata, because that is where NagSuppressions writes
# them and it is the only record that survives into the committed template.
#
# cdk-nag 2.x honored them on a re-scan; its packs were aspects that read construct
# metadata. The 3.x packs are IPolicyValidationPlugins that judge the synthesized template
# and never read that key -- 3.x has no NagSuppressions class at all and only ever WRITES
# the metadata, via WriteNagSuppressionsToCloudFormationAspect. CfnInclude does copy the
# metadata through, so it is present and simply unread.
#
# Measured against the real library at cdk-nag 3.0.2 / aws-cdk-lib 2.267.0: a template
# resource carrying `AwsSolutions-SMG4` in rules_to_suppress has that exact rule reported
# back as a violation with `Exception Reason: N/A`. So without the wrapper honoring it, an
# author's reason applies to nothing.


SUPPRESSED_RULE = "AwsSolutions-S1"
SUPPRESSION_REASON = (
    "Access logs for this bucket are delivered by the bucket in front of it, so pointing "
    "it at itself would recurse."
)
WILDCARD_SUPPRESSION_REASON = (
    "The only wildcard is object access inside a bucket this stack creates."
)

# Shaped like CDK synth output. ``MyDataBucket`` suppresses two rules; ``MyDataBucketPolicy``
# suppresses nothing and is the per-resource negative control -- a suppression must not leak
# from one resource to another in the same template.
TEMPLATE_WITH_SUPPRESSIONS_YAML = f"""Resources:
  MyDataBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: placeholder-name
  MyDataBucket:
    Type: AWS::S3::Bucket
    Metadata:
      cdk_nag:
        rules_to_suppress:
          - id: {SUPPRESSED_RULE}
            reason: "{SUPPRESSION_REASON}"
          - id: AwsSolutions-IAM5
            reason: "{WILDCARD_SUPPRESSION_REASON}"
    Properties:
      BucketName: placeholder-name
"""


@pytest.fixture
def suppressing_template_file(tmp_path):
    path = tmp_path / "suppressed-s3-template.yaml"
    path.write_text(TEMPLATE_WITH_SUPPRESSIONS_YAML, encoding="utf-8")
    return path


def _only_finding(response, pack="AwsSolutions"):
    findings = response.results[pack]
    assert len(findings) == 1, f"expected exactly 1 finding, got {len(findings)}"
    return findings[0]


def test_a_rule_the_template_suppresses_is_marked_suppressed_with_the_templates_reason(
    cdk_doubles, suppressing_template_file, outdir
):
    """The template's own reason becomes the finding's suppression justification."""
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    response = _run(suppressing_template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    finding = _only_finding(response)
    assert finding.suppressions is not None, (
        "the template suppresses this exact rule on this exact resource; reporting it as "
        "unsuppressed makes the author's recorded reason apply to nothing"
    )
    assert len(finding.suppressions) == 1
    suppression = finding.suppressions[0]
    assert suppression.kind == Kind1.inSource
    assert SUPPRESSION_REASON in suppression.justification
    # The prefix names where the suppression came from, so a reader of the report can tell
    # a template-declared acceptance from an .ash.yaml one.
    assert suppression.justification.startswith(
        "(ASH cdk-nag in-template suppression) "
    )


def test_a_suppressed_finding_keeps_the_level_and_kind_cdk_nag_gave_it(
    cdk_doubles, suppressing_template_file, outdir
):
    """Suppression is recorded alongside the verdict, not by rewriting it.

    ASH decides "suppressed" from the ``suppressions`` field and severity from ``level``, so
    demoting the level here would throw away what cdk-nag actually said and make these
    findings render differently from every other suppressed finding in the report.
    """
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(
        _run(suppressing_template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    )

    assert finding.level == Level.error
    assert finding.kind == Kind.fail
    assert finding.properties.model_extra["cdk_nag_finding"]["compliance"] == (
        "Non-Compliant"
    )


def test_a_bare_rule_suppression_covers_the_applies_to_variant(
    cdk_doubles, suppressing_template_file, outdir
):
    """``AwsSolutions-IAM5`` suppresses ``AwsSolutions-IAM5[Resource::*]``.

    cdk-nag reports a wildcard-scoped finding with its scope appended and treats a bare-id
    suppression as covering every variant. Comparing the full rule id only would leave the
    granular findings unsuppressed -- on a real synthesized template those are the majority,
    so the honoring would look implemented and change almost nothing.
    """
    cdk_doubles.report_text = _one_violation_report(
        rule_name="AwsSolutions-IAM5[Resource::*]"
    )

    finding = _only_finding(
        _run(suppressing_template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    )

    assert finding.ruleId == "AwsSolutions-IAM5[Resource::*]", (
        "the reported rule id must be preserved verbatim; only the match is widened"
    )
    assert finding.suppressions is not None
    assert WILDCARD_SUPPRESSION_REASON in finding.suppressions[0].justification


def test_a_rule_the_template_does_not_suppress_stays_actionable(
    cdk_doubles, suppressing_template_file, outdir
):
    """The negative control: honoring metadata must not suppress everything.

    Without this, a bug that returned a reason unconditionally would pass every other test
    in this section while silencing the whole scanner.
    """
    cdk_doubles.report_text = _one_violation_report(rule_name="AwsSolutions-S10")

    finding = _only_finding(
        _run(suppressing_template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    )

    assert finding.suppressions is None


def test_a_suppression_on_one_resource_does_not_cover_another_resource(
    cdk_doubles, suppressing_template_file, outdir
):
    """Matching is per resource, not per template.

    ``MyDataBucketPolicy`` declares no suppressions, so the same rule that is accepted on
    ``MyDataBucket`` must still be reported against the policy.
    """
    cdk_doubles.report_text = _one_violation_report(
        rule_name=SUPPRESSED_RULE,
        construct_paths=[_construct_path(logical_id="MyDataBucketPolicy")],
    )

    finding = _only_finding(
        _run(suppressing_template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    )

    assert "MyDataBucketPolicy" in finding.properties.tags
    assert finding.suppressions is None


def test_honoring_can_be_turned_off_so_ignore_suppressions_still_shows_everything(
    cdk_doubles, suppressing_template_file, outdir
):
    """``honor_template_suppressions=False`` reports the finding unsuppressed.

    This is what ``--ignore-suppressions`` is plumbed to. An audit run with that flag has to
    see what the template accepted in-band, otherwise the flag stops meaning "show me
    everything" as soon as the scanned repository is CDK output.
    """
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(
        _run(
            suppressing_template_file,
            outdir,
            nag_packs=["AwsSolutionsChecks"],
            honor_template_suppressions=False,
        )
    )

    assert finding.suppressions is None


def test_a_template_with_no_cdk_nag_metadata_is_unaffected(
    cdk_doubles, template_file, outdir
):
    """The ordinary case stays ordinary.

    ``template_file`` carries no ``Metadata`` at all, which is what a hand-written template
    looks like. Locked down explicitly so the metadata lookup cannot start inventing
    suppressions for templates that declare none.
    """
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(
        _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])
    )

    assert finding.suppressions is None


def test_a_suppression_with_no_reason_is_honored_and_says_the_reason_is_missing(
    cdk_doubles, tmp_path, outdir
):
    """cdk-nag requires a reason; a hand-edited template can still omit one.

    The suppression is honored because the author's intent is unambiguous, but the report
    says the rationale is missing rather than presenting an empty string as one.
    """
    path = tmp_path / "reasonless-template.yaml"
    path.write_text(
        """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Metadata:
      cdk_nag:
        rules_to_suppress:
          - id: AwsSolutions-S1
    Properties:
      BucketName: placeholder-name
""",
        encoding="utf-8",
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None
    assert finding.suppressions[0].justification == (
        "(ASH cdk-nag in-template suppression) No reason provided"
    )


@pytest.mark.parametrize(
    "metadata_block, why",
    [
        ("    Metadata: not-a-mapping\n", "Metadata is a scalar"),
        ("    Metadata:\n      cdk_nag: not-a-mapping\n", "cdk_nag is a scalar"),
        (
            "    Metadata:\n      cdk_nag:\n        rules_to_suppress: not-a-list\n",
            "rules_to_suppress is a scalar",
        ),
        (
            "    Metadata:\n      cdk_nag:\n        rules_to_suppress:\n          - just-a-string\n",
            "an entry is not a mapping",
        ),
        (
            "    Metadata:\n      cdk_nag:\n        rules_to_suppress:\n          - reason: no id here\n",
            "an entry has no id",
        ),
    ],
)
def test_malformed_suppression_metadata_is_ignored_not_raised(
    cdk_doubles, tmp_path, outdir, metadata_block, why
):
    """Unparseable metadata leaves the finding actionable instead of failing the scan.

    A template is arbitrary user input, and cdk-nag's metadata is a convention rather than a
    validated schema. Raising here would turn one malformed resource into a failed target,
    which this module reports as "the template was NOT scanned" -- a worse outcome than
    reporting the finding.
    """
    path = tmp_path / f"malformed-{abs(hash(why))}.yaml"
    path.write_text(
        "Resources:\n  MyDataBucket:\n    Type: AWS::S3::Bucket\n"
        + metadata_block
        + "    Properties:\n      BucketName: placeholder-name\n",
        encoding="utf-8",
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None, f"{why}: should be ignored, not honored"


# ---------------------------------------------------------------------------
# Granular suppressions: the applies_to scope
# ---------------------------------------------------------------------------
#
# cdk-nag narrows a suppression to particular findings with `appliesTo`, which
# `NagSuppressionHelper.toCfnFormat` renames to `applies_to` on its way into a template. Read
# from the installed bundles rather than from memory: cdk-nag 2.38.2's
# `lib/utils/nag-suppression-helper.js` decides applicability in three steps -- the bare rule
# id must match, a suppression with no `appliesTo` applies to every variant, and a suppression
# WITH one applies only when the finding's own qualifier is a member of it. The last step
# returns false, so a narrow suppression does not fall back to covering everything.
#
# Ignoring the key is more permissive than either cdk-nag major. 2.x rejects the suppression as
# non-matching. 3.0.2 never widens at all: `lib/nag-pack.js` builds the finding's id as
# `${ruleId}[${finding}]` and asks `isAcknowledged`, which is `ids.includes(ruleId)` -- exact
# string equality with no stripping. So a reason written about one S3 prefix must not silence
# `Resource::*`, which is an unrestricted resource wildcard.

# The shape a CDK asset-bucket suppression really has. 123456789012 is the account id AWS's own
# documentation uses as its example, and appears elsewhere in this repository already.
NARROW_SCOPE = "Resource::arn:aws:s3:::cdk-hnb659fds-assets-123456789012-us-east-1/*"
NARROW_SCOPE_REASON = "Only object access inside the CDK asset bucket this stack owns."
SCOPED_RULE = "AwsSolutions-IAM5"

# The qualifier the narrow suppression above must NOT silence. An unrestricted resource
# wildcard is the finding the rule exists to raise.
WILDCARD_QUALIFIER = "Resource::*"


def _scoped_suppression_template(
    tmp_path,
    name,
    scope_block="",
    rule_id=SCOPED_RULE,
    reason=NARROW_SCOPE_REASON,
    extra_entry_lines="",
):
    """One resource whose sole suppression is ``rule_id``, plus whatever scope is given.

    ``scope_block`` and ``extra_entry_lines`` are raw YAML indented to sit inside the
    ``rules_to_suppress`` entry, so a test can express a scope cdk-nag would accept, one it
    would reject, and one this wrapper cannot evaluate -- without a helper that quietly
    normalizes any of them into something well-formed.
    """
    path = tmp_path / f"{name}.yaml"
    path.write_text(
        "Resources:\n"
        "  MyDataBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Metadata:\n"
        "      cdk_nag:\n"
        "        rules_to_suppress:\n"
        f"          - id: {rule_id}\n"
        f'            reason: "{reason}"\n'
        + extra_entry_lines
        + scope_block
        + "    Properties:\n"
        "      BucketName: placeholder-name\n",
        encoding="utf-8",
    )
    return path


def _applies_to_block(*members, key="applies_to"):
    """A YAML ``applies_to`` sequence, or an empty one when no members are given."""
    if not members:
        return f"            {key}: []\n"
    lines = [f"            {key}:\n"]
    lines += [f'              - "{member}"\n' for member in members]
    return "".join(lines)


def test_a_granular_suppression_does_not_cover_a_qualifier_it_does_not_name(
    cdk_doubles, tmp_path, outdir
):
    """The finding this whole section exists for.

    The template accepts wildcard access to one asset bucket's object keys. The finding is
    ``AwsSolutions-IAM5[Resource::*]`` -- permission on every resource in the account. Treating
    the narrow reason as covering it both hides a real finding and attaches a justification
    that is untrue of it, which is worse than reporting it: a reader auditing the suppressed
    column is told the wildcard is scoped to a bucket.
    """
    path = _scoped_suppression_template(
        tmp_path, "narrow-scope", _applies_to_block(NARROW_SCOPE)
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None, (
        "a suppression scoped to one bucket prefix must not silence Resource::*; both "
        "cdk-nag majors refuse this match"
    )


def test_a_granular_suppression_covers_the_qualifier_it_names(
    cdk_doubles, tmp_path, outdir
):
    """The positive half: narrowing must not become "never suppress".

    Without this, a fix that simply stopped honoring any entry carrying ``applies_to`` would
    pass the negative test above while throwing away every scoped suppression an author wrote.
    """
    path = _scoped_suppression_template(
        tmp_path, "narrow-scope-hit", _applies_to_block(NARROW_SCOPE)
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{NARROW_SCOPE}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None, (
        "the finding's qualifier is a member of the declared scope, so the author's reason "
        "applies to exactly this finding"
    )
    assert NARROW_SCOPE_REASON in finding.suppressions[0].justification


def test_one_member_of_a_multi_member_scope_is_enough(cdk_doubles, tmp_path, outdir):
    """Membership, not identity: cdk-nag tests the qualifier against every element."""
    path = _scoped_suppression_template(
        tmp_path,
        "multi-scope",
        _applies_to_block("Action::sts:AssumeRole", NARROW_SCOPE, "Action::kms:Decrypt"),
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[Action::kms:Decrypt]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None


def test_the_camel_case_spelling_of_applies_to_is_also_read(
    cdk_doubles, tmp_path, outdir
):
    """A hand-written template can carry cdk-nag's API spelling.

    ``toCfnFormat`` writes ``applies_to``, but nothing stops an author from writing the
    ``appliesTo`` they read in cdk-nag's own documentation. Reading only the snake_case key
    would treat such an entry as having no scope at all and widen it to every variant -- the
    exact over-suppression this section is about, reintroduced through a spelling.
    """
    path = _scoped_suppression_template(
        tmp_path,
        "camel-scope",
        _applies_to_block(NARROW_SCOPE, key="appliesTo"),
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


def test_a_granular_suppression_does_not_cover_an_unqualified_finding(
    cdk_doubles, tmp_path, outdir
):
    """A scoped suppression says nothing about a rule that reported no scope.

    cdk-nag agrees by construction: ``doesApply`` guards the membership test on ``findingId``
    being non-empty, so a granular suppression cannot match a finding that has no qualifier.
    """
    path = _scoped_suppression_template(
        tmp_path, "scope-vs-bare", _applies_to_block(NARROW_SCOPE)
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SCOPED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


@pytest.mark.parametrize(
    "reported_rule_id",
    [f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]", SCOPED_RULE],
    ids=["qualified-finding", "unqualified-finding"],
)
def test_an_empty_applies_to_covers_nothing(
    cdk_doubles, tmp_path, outdir, reported_rule_id
):
    """``applies_to: []`` is a scope with no members, not an absent scope.

    This is the case a truthiness check gets exactly backwards, and JavaScript is the reason
    it is worth a test: an empty array is truthy, so cdk-nag's ``!suppression.appliesTo``
    shortcut is not taken and the membership test then finds nothing. Reading the key with
    ``if not scope`` in Python would flip "covers nothing" into "covers everything".
    """
    path = _scoped_suppression_template(tmp_path, "empty-scope", _applies_to_block())
    cdk_doubles.report_text = _one_violation_report(rule_name=reported_rule_id)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


def test_a_regex_scoped_suppression_is_not_honored_and_says_so(
    cdk_doubles, tmp_path, outdir, caplog
):
    """The ``{regex: ...}`` scope element form fails closed, loudly.

    cdk-nag 2.x accepts an object element and evaluates it as a JavaScript regular
    expression: ``toRegEx`` parses ``/pattern/flags`` and ``regex.test(findingId)`` runs an
    unanchored partial match. Python's ``re`` is a different engine -- ``\\d`` and ``\\w`` have
    different widths, ``\\A`` means start-of-string here and a literal ``A`` there, ``$``
    tolerates a trailing newline here and not there, and named groups and property escapes
    use incompatible syntax. Translating one into the other would be an approximation, and an
    approximation that matches too much silently over-suppresses, which is the defect this
    whole section removes.

    So the element is refused rather than guessed at. The finding stays actionable and the log
    says which rule was affected, because the alternative -- dropping the suppression with no
    signal -- leaves an author wondering why their reason did nothing.
    """
    path = _scoped_suppression_template(
        tmp_path,
        "regex-scope",
        '            applies_to:\n              - regex: "/^Resource::.*$/"\n',
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    with caplog.at_level("WARNING"):
        finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None
    assert any(
        "regex" in record.message and SCOPED_RULE in record.message
        for record in caplog.records
    ), (
        "an unevaluated suppression must name itself in the log; got "
        f"{[r.message for r in caplog.records]}"
    )


def test_a_non_list_applies_to_is_not_honored(cdk_doubles, tmp_path, outdir):
    """A scalar where cdk-nag requires an array is refused, not coerced.

    cdk-nag types ``appliesTo`` as an array and calls ``.some`` on it, so a bare string makes
    the real library throw. Coercing it to a one-element list here would honor a suppression
    cdk-nag itself would refuse to process, and a substring or membership test against a bare
    string is a different question from membership in a list.
    """
    path = _scoped_suppression_template(
        tmp_path,
        "scalar-scope",
        f'            applies_to: "{WILDCARD_QUALIFIER}"\n',
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


def test_an_explicit_null_applies_to_leaves_the_suppression_ungranular(
    cdk_doubles, tmp_path, outdir
):
    """``applies_to: null`` is how JSON spells absent, and cdk-nag reads it that way.

    ``toApiFormat`` only sets ``appliesTo`` when the value is truthy, so a null leaves the
    suppression non-granular and it covers every variant. Distinguishing this from
    ``applies_to: []`` is why the key's presence cannot be the whole test.
    """
    path = _scoped_suppression_template(
        tmp_path, "null-scope", "            applies_to: null\n"
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None
    assert NARROW_SCOPE_REASON in finding.suppressions[0].justification


# ---------------------------------------------------------------------------
# The cdk-nag 3.x round trip: a qualified id written into the template
# ---------------------------------------------------------------------------
#
# 3.0.2's `WriteNagSuppressionsToCloudFormationAspect` is the only thing in 3.x that writes
# this metadata, and it writes the acknowledged id verbatim -- it strips an `annotation::`
# prefix and nothing else. Since `applyRule` acknowledges granular findings under
# `${ruleId}[${finding}]`, a template synthesized by a 3.x app that used
# `writeSuppressionsToCloudFormation` carries `id: AwsSolutions-IAM5[Resource::*]`, brackets
# included, and carries no `applies_to` at all.
#
# These three lock that shape in. They are guards rather than reproductions: the shipped
# matcher already handles all three, and it is the fix for the section above that could break
# them -- narrowing implemented as "a bracketed rule id requires an applies_to" would refuse
# every 3.x-written suppression.


def test_a_three_x_written_qualified_id_matches_the_finding_verbatim(
    cdk_doubles, tmp_path, outdir
):
    """An id carrying its own qualifier suppresses exactly that finding."""
    qualified = f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    path = _scoped_suppression_template(tmp_path, "v3-roundtrip", rule_id=qualified)
    cdk_doubles.report_text = _one_violation_report(rule_name=qualified)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None, (
        "a 3.x-synthesized template records the acknowledged id with its brackets; refusing "
        "it would discard every suppression such an app wrote"
    )
    assert NARROW_SCOPE_REASON in finding.suppressions[0].justification


def test_a_qualified_id_does_not_widen_to_a_different_qualifier(
    cdk_doubles, tmp_path, outdir
):
    """``id: X[Action::sts:AssumeRole]`` says nothing about ``X[Resource::*]``."""
    path = _scoped_suppression_template(
        tmp_path,
        "v3-other-qualifier",
        rule_id=f"{SCOPED_RULE}[Action::sts:AssumeRole]",
    )
    cdk_doubles.report_text = _one_violation_report(
        rule_name=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]"
    )

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


def test_a_qualified_id_does_not_cover_the_unqualified_rule(
    cdk_doubles, tmp_path, outdir
):
    """Widening runs one way only: bare covers qualified, never the reverse."""
    path = _scoped_suppression_template(
        tmp_path,
        "v3-narrow-vs-bare",
        rule_id=f"{SCOPED_RULE}[{WILDCARD_QUALIFIER}]",
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SCOPED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is None


# ---------------------------------------------------------------------------
# Encoded reasons: is_reason_encoded
# ---------------------------------------------------------------------------
#
# `toCfnFormat` base64-encodes the reason and sets `is_reason_encoded: true` whenever the
# reason contains a codepoint above 255; `toApiFormat` decodes it on the way back. The flag is
# cdk-nag's own, so a template written by any 2.x app whose author used a dash, a quotation
# mark or a non-Latin script carries one.
#
# Taking the stored string verbatim puts base64 in the report's justification field. That
# defeats the reason this module suppresses rather than drops: the whole point is that a
# reviewer can read what was accepted and on what grounds. This is live in this repository --
# deploy/cdk/templates/AshFargate.template.json carries eleven encoded entries, five of them
# on AwsSolutions-ECS2, a rule the AwsSolutions pack does evaluate.

# cdk-nag encodes a reason exactly when some codepoint exceeds 255, so a faithful fixture has
# to contain one. Spelled by codepoint rather than pasted so the trigger is visible.
_ABOVE_LATIN1 = chr(0x2014)
ENCODED_REASON_TEXT = (
    "No secret is in this environment map "
    + _ABOVE_LATIN1
    + " it carries a port, a mount path and two booleans, and the value itself is fetched "
    "inside the container from the ARN named here."
)
ENCODED_REASON_B64 = base64.b64encode(ENCODED_REASON_TEXT.encode("utf-8")).decode(
    "ascii"
)


def test_an_encoded_reason_is_decoded_into_the_justification(
    cdk_doubles, tmp_path, outdir
):
    """The audit trail has to be readable, or suppressing is no better than dropping."""
    assert ENCODED_REASON_B64 != ENCODED_REASON_TEXT, "the fixture must really be encoded"
    path = _scoped_suppression_template(
        tmp_path,
        "encoded-reason",
        rule_id=SUPPRESSED_RULE,
        reason=ENCODED_REASON_B64,
        extra_entry_lines="            is_reason_encoded: true\n",
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None
    justification = finding.suppressions[0].justification
    assert ENCODED_REASON_TEXT in justification, (
        f"expected the decoded reason; got {justification!r}"
    )
    assert ENCODED_REASON_B64 not in justification, (
        "the base64 must not survive into the report"
    )


def test_a_reason_labeled_encoded_that_is_not_base64_falls_back_to_the_raw_text(
    cdk_doubles, tmp_path, outdir
):
    """A mislabeled entry degrades to readable-ish rather than failing the target.

    A hand-edited template can set the flag on plain text. Raising there would turn one
    resource's metadata into a failed target, which this scanner reports as "the template was
    NOT scanned" -- strictly worse than showing the author's own words.
    """
    plain = "Not base64 at all, just a sentence somebody mislabeled."
    path = _scoped_suppression_template(
        tmp_path,
        "mislabeled-reason",
        rule_id=SUPPRESSED_RULE,
        reason=plain,
        extra_entry_lines="            is_reason_encoded: true\n",
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None
    assert plain in finding.suppressions[0].justification


def test_a_reason_not_labeled_encoded_is_left_alone_even_when_it_looks_like_base64(
    cdk_doubles, tmp_path, outdir
):
    """Decoding is driven by the flag, never by whether the string happens to decode.

    The negative control for the decode: ``ENCODED_REASON_B64`` is valid base64, so a
    matcher that tried a decode unconditionally would replace a perfectly good reason with
    whatever those bytes spell.
    """
    path = _scoped_suppression_template(
        tmp_path,
        "unlabeled-reason",
        rule_id=SUPPRESSED_RULE,
        reason=ENCODED_REASON_B64,
    )
    cdk_doubles.report_text = _one_violation_report(rule_name=SUPPRESSED_RULE)

    finding = _only_finding(_run(path, outdir, nag_packs=["AwsSolutionsChecks"]))

    assert finding.suppressions is not None
    assert ENCODED_REASON_B64 in finding.suppressions[0].justification
    assert ENCODED_REASON_TEXT not in finding.suppressions[0].justification
