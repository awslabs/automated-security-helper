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

import json
import sys
import types
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind, Level
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
    """A synth that writes no report must say so at error level.

    This is the defect that started all of this. An absent report is indistinguishable, in the
    results, from a compliant template: both are an empty findings set. The distinction has to
    live in the log and in the scanner's target-failure counters, because the results dict
    cannot carry it. An empty dict is returned rather than None so the caller can tell "ran and
    parsed nothing" from "the scanner is unavailable".
    """
    cdk_doubles.report_text = None

    with caplog.at_level("ERROR"):
        response = _run(template_file, outdir, nag_packs=["AwsSolutionsChecks"])

    assert isinstance(response, CdkNagWrapperResponse)
    assert response.results == {}
    assert cdk_doubles.synth_count == 1
    assert any("NOT scanned" in record.message for record in caplog.records), (
        "an absent validation report must be logged as nothing having been scanned; "
        f"got {[r.message for r in caplog.records]}"
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
