# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KyvernoScanner: report parsing, severity mapping, invocation and failure handling.

The report text in this module is what ``kyverno apply`` 1.19.2 (the pinned version)
printed for the manifests and policies defined below, all captured in one run on Linux
x86_64 with::

    kyverno apply --policy-report --remove-color --output-format=yaml \\
        --resource=bad.yaml --resource=good.yaml -- <policy files>

The result blocks are verbatim, timestamps included. The order of the results inside the
merged cluster report is Kyverno's map order and changes from run to run, so a block
that appears in two fixtures may list its results in a different order.

``CLUSTER_REPORT`` is the output for ``POLICY``, an annotated ``ClusterPolicy`` (one
merged ``ClusterReport``, preceded by the deprecation warning Kyverno prints on stdout).
``NAMESPACED_REPORT`` is the output for ``POLICY`` and ``NAMESPACED_POLICY`` (a
namespaced ``Policy`` with the same name) together: the merged cluster report, then one
``PolicyReport`` per namespace and outcome, each after a ``---`` line.
``DEFAULT_SEVERITY_REPORT`` is the output for ``PLAIN_POLICY``, which carries no
``policies.kyverno.io`` annotations, so its results have neither ``category`` nor
``severity``. ``SKIPPED_REPORT`` is the output when ``INVALID_POLICY`` is loaded beside
``POLICY``: Kyverno prints a "Policies Skipped" block on stdout, before the report.
The scan() tests replace the subprocess with a fake that serves them, so they run on
every platform without the binary.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Callable, Dict, List

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_kyverno_plugins import (
    ASH_SCANNERS,
    kyverno_scanner as ks,
)
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    KYVERNO_SEVERITY_MAP,
    KyvernoScanner,
    KyvernoScannerConfig,
    KyvernoScannerConfigOptions,
    ManifestIndex,
    convert_report_results,
    is_policy_document,
    is_resource_document,
    load_manifest,
    parse_policy_report_output,
    severity_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

_WARNING = (
    "Warning: policy.yaml: kyverno.io/v1 ClusterPolicy is deprecated and will be "
    "removed in a future release; migrate to ValidatingPolicy, MutatingPolicy, "
    "GeneratingPolicy or ImageValidatingPolicy (policies.kyverno.io), see "
    "https://kyverno.io/docs/guides/migration-to-cel/\n"
)

_NS_WARNING = (
    "Warning: nspolicy.yaml: kyverno.io/v1 Policy is deprecated and will be removed "
    "in a future release; migrate to NamespacedValidatingPolicy and the other "
    "namespaced policy types (policies.kyverno.io), see "
    "https://kyverno.io/docs/guides/migration-to-cel/\n"
)

_CLUSTER_BODY = """\
apiVersion: openreports.io/v1alpha1
kind: ClusterReport
metadata:
  name: merged
results:
- category: Best Practices
  message: 'validation error: The label `team` is required. rule check-team-label
    failed at path /metadata/labels/'
  policy: require-team-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: bad-pod
    namespace: default
  result: fail
  rule: check-team-label
  scored: true
  severity: medium
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593737
- category: Best Practices
  message: validation rule 'check-team-label' passed.
  policy: require-team-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: good-pod
    namespace: default
  result: pass
  rule: check-team-label
  scored: true
  severity: medium
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593737
source: ""
summary:
  error: 0
  fail: 1
  pass: 1
  skip: 0
  warn: 0
"""

CLUSTER_REPORT = _WARNING + _CLUSTER_BODY

#: Every result passes: the negative control.
CLEAN_REPORT = (
    _WARNING
    + """\
apiVersion: openreports.io/v1alpha1
kind: ClusterReport
metadata:
  name: merged
results:
- category: Best Practices
  message: validation rule 'check-team-label' passed.
  policy: require-team-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: good-pod
    namespace: default
  result: pass
  rule: check-team-label
  scored: true
  severity: medium
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593739
source: ""
summary:
  error: 0
  fail: 0
  pass: 1
  skip: 0
  warn: 0
"""
)

NAMESPACED_REPORT = (
    _WARNING
    + _NS_WARNING
    + _CLUSTER_BODY
    + """\

---
apiVersion: openreports.io/v1alpha1
kind: PolicyReport
metadata:
  name: require-team-label
  namespace: default
results:
- category: Best Practices
  message: 'validation error: The label `team` is required. rule check-team-label
    failed at path /metadata/labels/'
  policy: default/require-team-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: bad-pod
    namespace: default
  result: fail
  rule: check-team-label
  scored: true
  severity: high
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593738
source: ""
summary:
  error: 0
  fail: 1
  pass: 0
  skip: 0
  warn: 0

---
apiVersion: openreports.io/v1alpha1
kind: PolicyReport
metadata:
  name: require-team-label
  namespace: default
results:
- category: Best Practices
  message: validation rule 'check-team-label' passed.
  policy: default/require-team-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: good-pod
    namespace: default
  result: pass
  rule: check-team-label
  scored: true
  severity: high
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593738
source: ""
summary:
  error: 0
  fail: 0
  pass: 1
  skip: 0
  warn: 0
"""
)

#: A policy with no ``policies.kyverno.io`` annotations: no category, no severity.
DEFAULT_SEVERITY_REPORT = (
    "Warning: plain-policy.yaml: kyverno.io/v1 ClusterPolicy is deprecated and will be "
    "removed in a future release; migrate to ValidatingPolicy, MutatingPolicy, "
    "GeneratingPolicy or ImageValidatingPolicy (policies.kyverno.io), see "
    "https://kyverno.io/docs/guides/migration-to-cel/\n"
    """\
apiVersion: openreports.io/v1alpha1
kind: ClusterReport
metadata:
  name: merged
results:
- message: 'validation error: The label `owner` is required. rule check-owner-label
    failed at path /metadata/labels/'
  policy: require-owner-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: bad-pod
    namespace: default
  result: fail
  rule: check-owner-label
  scored: true
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593738
- message: validation rule 'check-owner-label' passed.
  policy: require-owner-label
  properties:
    process: background scan
  resources:
  - apiVersion: v1
    kind: Pod
    name: good-pod
    namespace: default
  result: pass
  rule: check-owner-label
  scored: true
  source: kyverno
  timestamp:
    nanos: 0
    seconds: 1795593738
source: ""
summary:
  error: 0
  fail: 1
  pass: 1
  skip: 0
  warn: 0
"""
)

#: Kyverno's stdout when one policy of two is invalid: the block, then the report.
SKIPPED_BLOCK = """\
----------------------------------------------------------------------
Policies Skipped:
1. broken-policy: path: spec.rules[0].validate..: only one of pattern, anyPattern, deny, foreach, cel can be specified
----------------------------------------------------------------------
"""

SKIPPED_REPORT = (
    "Warning: invalid-policy.yaml: kyverno.io/v1 ClusterPolicy is deprecated and will "
    "be removed in a future release; migrate to ValidatingPolicy, MutatingPolicy, "
    "GeneratingPolicy or ImageValidatingPolicy (policies.kyverno.io), see "
    "https://kyverno.io/docs/guides/migration-to-cel/\n"
    + _WARNING
    + SKIPPED_BLOCK
    + _CLUSTER_BODY
)

POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-team-label
  annotations:
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
spec:
  validationFailureAction: Audit
  rules:
    - name: check-team-label
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "The label `team` is required."
        pattern:
          metadata:
            labels:
              team: "?*"
"""

NAMESPACED_POLICY = (
    POLICY.replace("kind: ClusterPolicy", "kind: Policy")
    .replace(
        "  name: require-team-label\n",
        "  name: require-team-label\n  namespace: default\n",
    )
    .replace("severity: medium", "severity: high")
)

PLAIN_POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-owner-label
spec:
  validationFailureAction: Audit
  rules:
    - name: check-owner-label
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "The label `owner` is required."
        pattern:
          metadata:
            labels:
              owner: "?*"
"""

INVALID_POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: broken-policy
spec:
  validationFailureAction: Audit
  rules:
    - name: broken-rule
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        pattern:
          metadata:
            labels:
              x: "?*"
        deny: {}
"""

POLICY_EXCEPTION = """\
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: allow-bad-pod
  namespace: default
spec:
  exceptions:
    - policyName: require-team-label
      ruleNames:
        - check-team-label
  match:
    any:
      - resources:
          kinds: [Pod]
          names: [bad-pod]
          namespaces: [default]
"""

BAD_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.27
"""

GOOD_POD = BAD_POD.replace("bad-pod", "good-pod").replace(
    "  namespace: default\n", "  namespace: default\n  labels:\n    team: platform\n"
)

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
"""


def _entry(**overrides) -> Dict[str, object]:
    base: Dict[str, object] = {
        "policy": "p",
        "rule": "r",
        "result": "fail",
        "severity": "medium",
        "message": "m",
        "resources": [{"kind": "Pod", "namespace": "default", "name": "bad-pod"}],
    }
    base.update(overrides)
    return base


def _index() -> ManifestIndex:
    index = ManifestIndex()
    index.add(
        {"kind": "Pod", "metadata": {"name": "bad-pod", "namespace": "default"}},
        "k8s/bad.yaml",
        1,
    )
    return index


def _report_text(*results: Dict[str, object]) -> str:
    """A report in the captured shape holding *results* (``_entry`` dicts)."""
    return _WARNING + yaml.safe_dump(
        {
            "apiVersion": "openreports.io/v1alpha1",
            "kind": "ClusterReport",
            "metadata": {"name": "merged"},
            "results": list(results),
            "source": "",
        },
        sort_keys=True,
    )


def _fail_on(kind: str, name: str, outcome: str = "fail") -> Dict[str, object]:
    return _entry(
        policy="require-team-label",
        rule="check-team-label",
        result=outcome,
        resources=[
            {
                "apiVersion": "apps/v1",
                "kind": kind,
                "name": name,
                "namespace": "default",
            }
        ],
    )


def _resources_in(argv: List[str]) -> List[str]:
    return [a[len("--resource=") :] for a in argv if a.startswith("--resource=")]


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, in order."""
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine if loc.region else None,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------


class TestParse:
    def test_the_warning_before_the_report_is_ignored(self):
        entries = parse_policy_report_output(CLUSTER_REPORT)
        assert [(e["result"], e["resources"][0]["name"]) for e in entries] == [
            ("fail", "bad-pod"),
            ("pass", "good-pod"),
        ]

    def test_a_namespaced_report_after_a_separator_is_read_too(self):
        entries = parse_policy_report_output(NAMESPACED_REPORT)
        assert [e["policy"] for e in entries] == [
            "require-team-label",
            "require-team-label",
            "default/require-team-label",
            "default/require-team-label",
        ]

    def test_the_skipped_policies_block_before_the_report_is_ignored(self):
        entries = parse_policy_report_output(SKIPPED_REPORT)
        assert [e["result"] for e in entries] == ["fail", "pass"]

    @pytest.mark.parametrize("text", ["", "   \n", _WARNING])
    def test_no_report_is_no_results(self, text):
        assert parse_policy_report_output(text) == []

    @pytest.mark.parametrize(
        "text",
        [
            "apiVersion: openreports.io/v1alpha1\nresults: [unclosed\n",
            "apiVersion: openreports.io/v1alpha1\nresults: 7\n",
            "apiVersion: openreports.io/v1alpha1\nresults:\n- just a string\n",
            "apiVersion: x\n---\n- a\n- list\n",
        ],
    )
    def test_a_report_that_cannot_be_read_raises(self, text):
        with pytest.raises(ValueError):
            parse_policy_report_output(text)

    def test_the_skipped_policy_names_are_read_from_the_block(self):
        assert ks.parse_skipped_policies(SKIPPED_REPORT) == ["broken-policy"]

    @pytest.mark.parametrize("text", ["", CLUSTER_REPORT, "Policies Skipped\n"])
    def test_no_skipped_block_is_no_names(self, text):
        assert ks.parse_skipped_policies(text) == []


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    @pytest.mark.parametrize(
        "name, severity, level",
        [
            ("critical", "CRITICAL", "error"),
            ("high", "HIGH", "error"),
            ("medium", "MEDIUM", "warning"),
            ("low", "LOW", "note"),
            ("info", "INFO", "none"),
            ("HIGH", "HIGH", "error"),
            ("Critical", "CRITICAL", "error"),
        ],
    )
    def test_every_row_of_the_table(self, name, severity, level):
        results, _, _ = convert_report_results([_entry(severity=name)], _index(), ".")
        (finding,) = results
        assert finding.properties.issue_severity == severity
        assert getattr(finding.level, "value", finding.level) == level

    def test_the_table_has_the_five_kyverno_names(self):
        assert sorted(KYVERNO_SEVERITY_MAP) == [
            "critical",
            "high",
            "info",
            "low",
            "medium",
        ]

    def test_no_declared_severity_is_medium_for_a_fail_and_low_for_a_warn(self):
        assert severity_for(_entry(severity=None))[0] == "MEDIUM"
        assert severity_for(_entry(severity="", result="fail"))[0] == "MEDIUM"
        assert severity_for(_entry(severity=None, result="warn"))[0] == "LOW"

    def test_an_unknown_severity_is_high(self):
        assert (
            severity_for(_entry(severity="catastrophic"))
            == KYVERNO_SEVERITY_MAP["high"]
        )

    def test_a_declared_severity_wins_over_the_default(self):
        assert severity_for(_entry(severity="low", result="fail"))[0] == "LOW"

    def test_a_real_unannotated_policy_takes_the_default_severity_path(self):
        entries = parse_policy_report_output(DEFAULT_SEVERITY_REPORT)
        assert all("severity" not in e and "category" not in e for e in entries)
        results, rules, failed = convert_report_results(entries, _index(), ".")
        (finding,) = results
        assert finding.ruleId == "require-owner-label/check-owner-label"
        assert finding.properties.issue_severity == "MEDIUM"
        assert getattr(finding.level, "value", finding.level) == "warning"
        assert rules[0].properties.tags == ["kyverno", "kubernetes", "policy"]
        assert failed == []


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------


class TestConvert:
    def test_a_failed_result_is_located_at_its_manifest_line(self):
        entries = parse_policy_report_output(CLUSTER_REPORT)
        results, rules, failed = convert_report_results(entries, _index(), ".")
        assert failed == []
        assert [r.id for r in rules] == ["require-team-label/check-team-label"]
        (finding,) = results
        location = finding.locations[0].physicalLocation.root
        assert location.artifactLocation.uri == "k8s/bad.yaml"
        assert location.region.startLine == 1
        assert finding.ruleId == "require-team-label/check-team-label"
        assert "team" in finding.message.root.text
        assert finding.properties.kyverno_resource == "Pod/default/bad-pod"

    def test_negative_control_a_clean_report_has_no_findings(self):
        entries = parse_policy_report_output(CLEAN_REPORT)
        assert entries and entries[0]["result"] == "pass"
        results, rules, failed = convert_report_results(entries, _index(), ".")
        assert (results, rules, failed) == ([], [], [])

    @pytest.mark.parametrize("outcome", ["pass", "skip"])
    def test_pass_and_skip_are_not_findings(self, outcome):
        results, _, failed = convert_report_results(
            [_entry(result=outcome)], _index(), "."
        )
        assert results == [] and failed == []

    def test_a_warn_is_a_finding_and_says_so(self):
        results, _, _ = convert_report_results(
            [_entry(result="warn", severity=None)], _index(), "."
        )
        (finding,) = results
        assert finding.properties.kyverno_result == "warn"
        assert finding.properties.issue_severity == "LOW"
        assert getattr(finding.level, "value", finding.level) == "note"

    def test_an_error_is_a_failed_target_and_does_not_quote_the_message(self):
        _, _, failed = convert_report_results(
            [
                _entry(
                    result="error",
                    policy="require-xyz",
                    message="SECRET-TEXT-FROM-THE-MANIFEST",
                )
            ],
            _index(),
            ".",
        )
        assert len(failed) == 1
        assert "k8s/bad.yaml" in failed[0]
        assert "require-xyz" in failed[0] and "bad-pod" in failed[0]
        assert "SECRET-TEXT" not in failed[0]

    def test_a_failed_target_knows_the_file_it_belongs_to(self):
        _, _, failed = convert_report_results([_entry(result="error")], _index(), ".")
        assert failed[0].uri == "k8s/bad.yaml"

    def test_a_resource_with_no_manifest_falls_back_to_the_given_uri(self):
        results, _, _ = convert_report_results(
            [_entry(resources=[{"kind": "Pod", "namespace": "x", "name": "ghost"}])],
            _index(),
            "src-dir",
        )
        location = results[0].locations[0].physicalLocation.root
        assert location.artifactLocation.uri == "src-dir"
        assert location.region is None

    def test_a_manifest_without_a_namespace_is_found_by_kind_and_name(self):
        index = ManifestIndex()
        index.add({"kind": "Pod", "metadata": {"name": "bad-pod"}}, "a.yaml", 4)
        assert index.locate("Pod", "default", "bad-pod") == ("a.yaml", 4)

    def test_a_cluster_scoped_resource_has_no_namespace_key_and_is_still_found(self):
        index = ManifestIndex()
        index.add({"kind": "Namespace", "metadata": {"name": "x"}}, "ns.yaml", 3)
        results, _, _ = convert_report_results(
            [_entry(resources=[{"kind": "Namespace", "name": "x"}])], index, "src-dir"
        )
        location = results[0].locations[0].physicalLocation.root
        assert location.artifactLocation.uri == "ns.yaml"
        assert location.region.startLine == 3

    def test_one_result_per_resource_and_no_duplicates(self):
        two = _entry(
            resources=[
                {"kind": "Pod", "namespace": "default", "name": "bad-pod"},
                {"kind": "Pod", "namespace": "default", "name": "bad-pod"},
            ]
        )
        results, _, _ = convert_report_results([two], _index(), ".")
        assert len(results) == 1

    def test_the_message_is_bounded(self):
        results, _, _ = convert_report_results(
            [_entry(message="x " * 5000)], _index(), "."
        )
        assert len(results[0].message.root.text) <= 2000


# ---------------------------------------------------------------------------
# Manifests and policies
# ---------------------------------------------------------------------------


class TestDocuments:
    def test_a_pod_is_a_resource_and_a_cluster_policy_is_not(self):
        pod = yaml.safe_load(BAD_POD)
        policy = yaml.safe_load(POLICY)
        assert is_resource_document(pod) and not is_policy_document(pod)
        assert is_policy_document(policy) and not is_resource_document(policy)

    @pytest.mark.parametrize(
        "api_version, kind",
        [
            ("policies.kyverno.io/v1", "ValidatingPolicy"),
            ("kyverno.io/v1", "Policy"),
            ("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy"),
        ],
    )
    def test_other_policy_kinds_are_policies(self, api_version, kind):
        doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "p"}}
        assert is_policy_document(doc)
        assert not is_resource_document(doc)

    @pytest.mark.parametrize(
        "api_version, kind",
        [
            ("kyverno.io/v2", "PolicyException"),
            ("policies.kyverno.io/v1beta1", "PolicyException"),
            ("kyverno.io/v2", "CleanupPolicy"),
            ("kyverno.io/v2", "ClusterCleanupPolicy"),
            ("kyverno.io/v2alpha1", "GlobalContextEntry"),
        ],
    )
    def test_kyverno_kinds_that_are_not_policies_are_not_passed_as_policies(
        self, api_version, kind
    ):
        doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "p"}}
        assert not is_policy_document(doc)
        assert not is_resource_document(doc)

    @pytest.mark.parametrize(
        "api_version, kind, expected",
        [
            ("kyverno.io/v2", "PolicyException", True),
            ("policies.kyverno.io/v1beta1", "PolicyException", True),
            ("kyverno.io/v1", "ClusterPolicy", False),
            ("kyverno.io/v2", "CleanupPolicy", False),
        ],
    )
    def test_an_exception_document_is_told_from_a_policy(
        self, api_version, kind, expected
    ):
        doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "p"}}
        assert ks.is_exception_document(doc) is expected

    @pytest.mark.parametrize(
        "api_version, kind",
        [
            ("chainsaw.kyverno.io/v1alpha1", "Test"),
            ("chainsaw.kyverno.io/v1alpha1", "Configuration"),
            ("kustomize.config.k8s.io/v1beta1", "Kustomization"),
            ("kustomize.config.k8s.io/v1alpha1", "Component"),
        ],
    )
    def test_chainsaw_and_kustomize_files_are_not_resources(self, api_version, kind):
        doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "t"}}
        assert not is_resource_document(doc)

    @pytest.mark.parametrize(
        "doc",
        [
            {"foo": "bar"},
            {"apiVersion": "v1"},
            {"kind": "Pod"},
            {"apiVersion": "", "kind": "Pod"},
            {"apiVersion": 1, "kind": "Pod"},
            ["a"],
            None,
        ],
    )
    def test_a_document_without_api_version_and_kind_is_neither(self, doc):
        assert not is_resource_document(doc)
        assert not is_policy_document(doc)

    def test_a_multi_document_file_gives_each_object_the_line_that_declares_it(self):
        text = BAD_POD + "---\n" + GOOD_POD
        objects = load_manifest(text)
        assert [(d["metadata"]["name"], line) for d, line in objects] == [
            ("bad-pod", 1),
            ("good-pod", 11),
        ]
        assert text.splitlines()[10] == "apiVersion: v1"

    def test_a_leading_separator_does_not_move_the_line_to_the_separator(self):
        objects = load_manifest("---\n" + BAD_POD)
        assert [(d["metadata"]["name"], line) for d, line in objects] == [
            ("bad-pod", 2)
        ]

    def test_leading_comments_and_a_separator_do_not_move_the_line(self):
        objects = load_manifest("# owner: x\n---\n# note\n" + BAD_POD)
        assert [line for _, line in objects] == [4]

    def test_an_empty_document_between_separators_is_ignored(self):
        assert len(load_manifest("---\n" + BAD_POD + "---\n---\n")) == 1

    @pytest.mark.parametrize(
        "text",
        [
            "foo: bar\nlist: [1, 2]\n",
            "kind: Pod\n  bad: [\n",
            BAD_POD + "---\nfoo: bar\n",
            POLICY,
            "# apiVersion kind\n",
            "",
        ],
    )
    def test_a_file_kyverno_would_stop_on_is_not_passed(self, text):
        assert load_manifest(text) is None

    def test_a_list_is_expanded_into_its_items(self):
        text = (
            "apiVersion: v1\nkind: List\nitems:\n"
            "- {apiVersion: v1, kind: Pod, metadata: {name: a}}\n"
            "- {apiVersion: v1, kind: Pod, metadata: {name: b}}\n"
        )
        assert [d["metadata"]["name"] for d, _ in load_manifest(text)] == ["a", "b"]

    @pytest.mark.parametrize(
        "text, reason",
        [
            (BAD_POD + "---\nfoo: bar\n", "mixed"),
            (POLICY + "---\n" + BAD_POD, "mixed"),
            ("foo: bar\n", None),
            ("kind: Pod\n  bad: [\n", None),
        ],
    )
    def test_a_file_that_holds_a_resource_beside_other_documents_is_named_mixed(
        self, text, reason
    ):
        objects, why = ks.read_manifest(text)
        assert objects is None
        assert why == reason


# ---------------------------------------------------------------------------
# scan()
# ---------------------------------------------------------------------------


class FakeKyverno:
    """Stands in for _run_subprocess: records argv, serves captured output.

    *stdout* and *exit_code* may be callables of the argv, to serve a different answer
    per call. With no *exit_code* the exit is 1 when the output holds a failed or
    errored result and 0 otherwise, as Kyverno's is.
    """

    def __init__(
        self,
        stdout: str | Callable[[List[str]], str] = CLUSTER_REPORT,
        exit_code: int | Callable[[List[str]], int] | None = None,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.stdout, self.exit_code = stdout, exit_code
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[dict] = []

    def _exit_for(self, argv: List[str], out: str) -> int:
        if callable(self.exit_code):
            return self.exit_code(argv)
        if self.exit_code is not None:
            return self.exit_code
        return 1 if ("result: fail" in out or "result: error" in out) else 0

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, **kwargs):
            argv = list(command)
            self.calls.append({"argv": argv, "timeout": timeout, **kwargs})
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            out = self.stdout(argv) if callable(self.stdout) else self.stdout
            code = self._exit_for(argv, out)
            scanner.exit_code = code
            return {"returncode": code, "stdout": out, "stderr": self.stderr}

        return run


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> KyvernoScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return KyvernoScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=KyvernoScannerConfig(
            enabled=True, options=KyvernoScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "k8s").mkdir(parents=True)
    (src / "policies").mkdir()
    (src / "k8s" / "bad.yaml").write_text(BAD_POD)
    (src / "k8s" / "good.yaml").write_text(GOOD_POD)
    (src / "k8s" / "other.yaml").write_text("foo: bar\nlist: [1, 2]\n")
    (src / "k8s" / "broken.yaml").write_text("kind: Pod\n  bad: [\n")
    (src / "policies" / "require-team.yaml").write_text(POLICY)
    (src / "policies" / "junk.yaml").write_text("foo: bar\n")
    (src / "README.md").write_text("hello\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ks, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: KyvernoScanner, fake: FakeKyverno, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


def _logs(scanner: KyvernoScanner, monkeypatch) -> List[tuple]:
    """Capture what the scanner logs as (message, level) pairs."""
    seen: List[tuple] = []

    def record(message, *args, **kwargs):
        seen.append((str(message), kwargs.get("level")))

    monkeypatch.setattr(scanner, "_plugin_log", record)
    return seen


class TestCommunityPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ASH_SCANNERS == [KyvernoScanner]

    def test_the_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert KyvernoScannerConfig().enabled is True
        assert KyvernoScannerConfig().name == "kyverno"

    def test_no_policy_is_configured_by_default(self):
        assert KyvernoScannerConfigOptions().policy_paths == []


class TestTheOptInGate:
    def test_without_policies_nothing_runs_and_the_row_is_skipped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        logs = _logs(scanner, monkeypatch)
        fake = FakeKyverno()
        report = _run(scanner, fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert any("scan was skipped" in m and lvl == 20 for m, lvl in logs)

    def test_without_policies_a_missing_binary_is_not_asked_about(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKyverno(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert scanner.targets_attempted == 0

    def test_a_directory_with_no_policy_document_is_the_same_as_none(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        empty = tree / "empty-policies"
        empty.mkdir()
        (empty / "junk.yaml").write_text("foo: bar\n")
        scanner = _scanner(tree, tmp_path, policy_paths=["empty-policies"])
        fake = FakeKyverno()
        assert isinstance(_run(scanner, fake, monkeypatch), SarifReport)
        assert fake.calls == [] and scanner.targets_attempted == 0

    def test_policy_paths_set_by_the_scanned_tree_are_ignored(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, policy_paths=["policies"])
        fake = FakeKyverno()
        assert isinstance(_run(scanner, fake, monkeypatch), SarifReport)
        assert fake.calls == [] and scanner.targets_attempted == 0

    def test_a_policy_path_that_does_not_exist_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["nope"])
        fake = FakeKyverno()
        with pytest.raises(ScannerError, match="does not exist"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_policy_paths_in_the_config_passed_to_scan_open_the_gate(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        enabling = KyvernoScannerConfig(
            enabled=True,
            options=KyvernoScannerConfigOptions(policy_paths=["policies"]),
        )
        fake = FakeKyverno()
        report = _run(scanner, fake, monkeypatch, config=enabling)
        assert len(fake.calls) == 1
        assert scanner.targets_attempted == 2
        assert len(report.get_all_results()) == 1

    def test_a_directory_holding_only_a_policy_exception_is_the_same_as_none(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        only = tree / "exceptions-only"
        only.mkdir()
        (only / "allow.yaml").write_text(POLICY_EXCEPTION)
        scanner = _scanner(tree, tmp_path, policy_paths=["exceptions-only"])
        fake = FakeKyverno()
        assert isinstance(_run(scanner, fake, monkeypatch), SarifReport)
        assert fake.calls == [] and scanner.targets_attempted == 0


class TestInvocation:
    def test_every_fixed_flag_and_the_resource_and_policy_arguments(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        (call,) = fake.calls
        argv = call["argv"]
        assert argv[:2] == ["kyverno", "apply"]
        assert argv[2:5] == [
            "--policy-report",
            "--remove-color",
            "--output-format=yaml",
        ]
        resources = [a for a in argv if a.startswith("--resource=")]
        assert resources == ["--resource=k8s/bad.yaml", "--resource=k8s/good.yaml"]
        separator = argv.index("--")
        (policy_arg,) = argv[separator + 1 :]
        assert policy_arg.endswith("kyverno-policies.yaml")
        assert all(a.startswith("--") for a in argv[2:separator])
        assert call["stdout_preference"] == "return"

    def test_the_policies_go_to_kyverno_as_one_file_of_policy_documents(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "policies" / "mixed.yaml").write_text(PLAIN_POLICY + "---\nfoo: bar\n")
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        combined = Path(argv[argv.index("--") + 1])
        docs = list(yaml.safe_load_all(combined.read_text()))
        assert sorted(d["metadata"]["name"] for d in docs) == [
            "require-owner-label",
            "require-team-label",
        ]
        assert all(is_policy_document(d) for d in docs)

    def test_a_large_policy_set_does_not_enter_the_command_line(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        many = tree / "vendored"
        many.mkdir()
        for n in range(60):
            (many / f"policy-{n:03d}-{'x' * 80}.yaml").write_text(
                POLICY.replace("require-team-label", f"require-team-label-{n}")
            )
        scanner = _scanner(tree, tmp_path, policy_paths=["vendored"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert len(argv[argv.index("--") + 1 :]) == 1
        assert len(" ".join(argv)) < 1_000
        combined = Path(argv[argv.index("--") + 1])
        assert len(list(yaml.safe_load_all(combined.read_text()))) == 60

    def test_policy_exceptions_are_passed_as_exceptions_not_as_policies(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "policies" / "allow.yaml").write_text(POLICY_EXCEPTION)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        (exception_arg,) = [a for a in argv if a.startswith("--exception=")]
        excepted = list(
            yaml.safe_load_all(Path(exception_arg[len("--exception=") :]).read_text())
        )
        assert [d["kind"] for d in excepted] == ["PolicyException"]
        policies = list(
            yaml.safe_load_all(Path(argv[argv.index("--") + 1]).read_text())
        )
        assert [d["kind"] for d in policies] == ["ClusterPolicy"]

    def test_no_exception_argument_without_an_exception(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert not any(a.startswith("--exception") for a in fake.calls[0]["argv"])

    def test_the_policy_file_is_never_a_resource_and_junk_is_never_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        joined = " ".join(argv)
        for left_out in ("other.yaml", "broken.yaml", "README.md", "junk.yaml"):
            assert left_out not in joined
        assert "--resource=policies/require-team.yaml" not in argv

    def test_every_file_of_a_configured_policy_directory_is_left_out_of_the_resources(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        vendored = tree / "lib" / "disallow-latest" / "tests"
        vendored.mkdir(parents=True)
        (tree / "lib" / "disallow-latest" / "policy.yaml").write_text(POLICY)
        (vendored / "bad-pod.yaml").write_text(BAD_POD)
        (vendored / "chainsaw-test.yaml").write_text(
            "apiVersion: chainsaw.kyverno.io/v1alpha1\nkind: Test\n"
            "metadata:\n  name: t\nspec:\n  steps: []\n"
        )
        scanner = _scanner(tree, tmp_path, policy_paths=["lib"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        resources = _resources_in(fake.calls[0]["argv"])
        assert resources == ["k8s/bad.yaml", "k8s/good.yaml"]
        assert scanner.targets_attempted == 2

    def test_chainsaw_tests_and_kustomizations_are_not_scanned_as_resources(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "chainsaw-test.yaml").write_text(
            "apiVersion: chainsaw.kyverno.io/v1alpha1\nkind: Test\n"
            "metadata:\n  name: t\nspec:\n  steps: []\n"
        )
        (tree / "k8s" / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
            "resources:\n  - bad.yaml\n"
        )
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert _resources_in(fake.calls[0]["argv"]) == [
            "k8s/bad.yaml",
            "k8s/good.yaml",
        ]

    @pytest.mark.parametrize(
        "flag", ["--cluster", "-c", "--registry", "--kubeconfig", "--git-branch"]
    )
    def test_flags_that_reach_the_network_or_a_cluster_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == flag or a.startswith(flag + "=") for a in fake.calls[0]["argv"]
        )

    def test_a_manifest_whose_name_starts_with_a_dash_is_one_token(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "-odd.yaml").write_text(BAD_POD.replace("bad-pod", "odd-pod"))
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert "--resource=k8s/-odd.yaml" in fake.calls[0]["argv"]

    @pytest.mark.parametrize("name", ["a,b.yaml", 'q"x.yaml'])
    def test_a_manifest_name_kyverno_would_split_is_left_out_and_said_so(
        self, name, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / name).write_text(BAD_POD)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        logs = _logs(scanner, monkeypatch)
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        resources = _resources_in(fake.calls[0]["argv"])
        assert resources == ["k8s/bad.yaml", "k8s/good.yaml"]
        assert any(name in m and lvl == 30 for m, lvl in logs)

    def test_an_ignored_path_is_not_passed(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="k8s/good.yaml", reason="test")
            ],
        )
        resources = [a for a in fake.calls[0]["argv"] if a.startswith("--resource=")]
        assert resources == ["--resource=k8s/bad.yaml"]

    def test_a_tree_with_no_manifest_runs_nothing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        for name in ("bad.yaml", "good.yaml"):
            (tree / "k8s" / name).unlink()
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        assert isinstance(_run(scanner, fake, monkeypatch), SarifReport)
        assert fake.calls == [] and scanner.targets_attempted == 0

    def test_a_file_that_mixes_a_resource_with_other_documents_is_left_out_and_said_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "mixed.yaml").write_text(BAD_POD + "---\nfoo: bar\n")
        (tree / "k8s" / "with-policy.yaml").write_text(PLAIN_POLICY + "---\n" + BAD_POD)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        logs = _logs(scanner, monkeypatch)
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert _resources_in(fake.calls[0]["argv"]) == [
            "k8s/bad.yaml",
            "k8s/good.yaml",
        ]
        notice = [m for m, lvl in logs if "k8s/mixed.yaml" in m and lvl == 30]
        assert notice and "k8s/with-policy.yaml" in notice[0]

    def test_a_long_manifest_list_is_split_into_runs_under_the_cap(self):
        base = ["kyverno", "apply"]
        tail = ["--", "p.yaml"]
        paths = [f"dir/{'x' * 200}-{n}.yaml" for n in range(400)]
        chunks = ks._argv_chunks(base, paths, tail)
        assert len(chunks) > 1
        assert [p for chunk in chunks for p in chunk] == paths
        for chunk in chunks:
            full = [*base, *[f"--resource={p}" for p in chunk], *tail]
            assert len(" ".join(full)) <= ks._MAX_COMMAND_LINE_CHARS

    def test_the_tail_counts_toward_every_runs_length(self):
        base = ["kyverno", "apply"]
        tail = ["--", "p" * 5000]
        paths = [f"dir/{'x' * 200}-{n}.yaml" for n in range(400)]
        chunks = ks._argv_chunks(base, paths, tail)
        for chunk in chunks:
            full = [*base, *[f"--resource={p}" for p in chunk], *tail]
            assert len(" ".join(full)) <= ks._MAX_COMMAND_LINE_CHARS

    def test_scan_runs_one_kyverno_per_chunk_and_merges_the_results(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "_MAX_COMMAND_LINE_CHARS", 1)
        ticks = itertools.count(100)
        monkeypatch.setattr(ks, "_now", lambda: next(ticks))
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"], scan_timeout=50)
        fake = FakeKyverno(
            stdout=lambda argv: (
                CLUSTER_REPORT if "--resource=k8s/bad.yaml" in argv else CLEAN_REPORT
            )
        )
        report = _run(scanner, fake, monkeypatch)
        assert [_resources_in(c["argv"]) for c in fake.calls] == [
            ["k8s/bad.yaml"],
            ["k8s/good.yaml"],
        ]
        assert len(report.get_all_results()) == 1
        assert scanner.targets_attempted == 2
        first, second = (c["timeout"] for c in fake.calls)
        assert 0 < second < first <= 50


class TestIdentityCollisions:
    """Two files that declare the same object: kustomize's base and an overlay."""

    @pytest.fixture
    def kustomize(self, tmp_path) -> Path:
        src = tmp_path / "src"
        (src / "base").mkdir(parents=True)
        (src / "overlays" / "prod").mkdir(parents=True)
        (src / "policies").mkdir()
        (src / "base" / "deployment.yaml").write_text(DEPLOYMENT)
        (src / "overlays" / "prod" / "deployment.yaml").write_text(DEPLOYMENT)
        (src / "policies" / "require-team.yaml").write_text(POLICY)
        return src

    def test_a_finding_of_the_overlay_is_reported_at_the_overlay(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(
            stdout=lambda argv: (
                _report_text(_fail_on("Deployment", "app"))
                if "--resource=overlays/prod/deployment.yaml" in argv
                else CLEAN_REPORT
            )
        )
        report = _run(scanner, fake, monkeypatch)
        found = _findings(report)
        assert [f[3] for f in found] == ["overlays/prod/deployment.yaml"]
        assert found[0][4] == 1

    def test_a_finding_in_both_files_is_reported_in_both(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(
            stdout=lambda argv: _report_text(_fail_on("Deployment", "app"))
        )
        report = _run(scanner, fake, monkeypatch)
        assert sorted(f[3] for f in _findings(report)) == [
            "base/deployment.yaml",
            "overlays/prod/deployment.yaml",
        ]
        assert scanner.targets_attempted == 2

    def test_colliding_files_never_share_a_kyverno_run(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=CLEAN_REPORT)
        _run(scanner, fake, monkeypatch)
        assert sorted(tuple(_resources_in(c["argv"])) for c in fake.calls) == [
            ("base/deployment.yaml",),
            ("overlays/prod/deployment.yaml",),
        ]

    def test_files_with_different_objects_still_share_one_run(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        (kustomize / "overlays" / "prod" / "deployment.yaml").write_text(
            DEPLOYMENT.replace("name: app", "name: other")
        )
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=CLEAN_REPORT)
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_the_same_name_in_two_explicit_namespaces_is_not_a_collision(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        (kustomize / "base" / "deployment.yaml").write_text(
            DEPLOYMENT.replace("name: app\n", "name: app\n  namespace: a\n")
        )
        (kustomize / "overlays" / "prod" / "deployment.yaml").write_text(
            DEPLOYMENT.replace("name: app\n", "name: app\n  namespace: b\n")
        )
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=CLEAN_REPORT)
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_one_namespace_less_copy_collides_with_a_namespaced_copy(
        self, kustomize, tmp_path, on_path, monkeypatch
    ):
        (kustomize / "overlays" / "prod" / "deployment.yaml").write_text(
            DEPLOYMENT.replace("name: app\n", "name: app\n  namespace: b\n")
        )
        scanner = _scanner(kustomize, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=CLEAN_REPORT)
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 2


class TestReport:
    def test_findings_are_located_rated_and_counted(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(), monkeypatch)
        assert _findings(report) == [
            (
                "require-team-label/check-team-label",
                "warning",
                "MEDIUM",
                "k8s/bad.yaml",
                1,
            )
        ]
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 0

    def test_a_namespaced_policy_report_adds_its_finding_at_its_own_severity(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(stdout=NAMESPACED_REPORT), monkeypatch)
        found = _findings(report)
        assert [f[:3] for f in found] == [
            ("require-team-label/check-team-label", "warning", "MEDIUM"),
            ("default/require-team-label/check-team-label", "error", "HIGH"),
        ]
        assert {f[3] for f in found} == {"k8s/bad.yaml"}

    def test_negative_control_a_clean_run_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(
            scanner, FakeKyverno(stdout=CLEAN_REPORT, exit_code=0), monkeypatch
        )
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 2

    def test_the_sarif_is_written_where_the_scan_says_and_round_trips(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(), monkeypatch)
        written = list((tmp_path / "out").rglob("kyverno.sarif"))
        assert len(written) == 1
        again = SarifReport.model_validate_json(written[0].read_text())
        assert _findings(again) == _findings(report)

    def test_no_report_at_exit_zero_is_clean_and_warns_that_nothing_matched(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        logs = _logs(scanner, monkeypatch)
        report = _run(scanner, FakeKyverno(stdout=_WARNING, exit_code=0), monkeypatch)
        assert report.get_all_results() == []
        assert any("printed no results" in m and lvl == 30 for m, lvl in logs)

    def test_an_evaluation_error_is_a_failed_target(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        errored = CLUSTER_REPORT.replace("result: fail", "result: error")
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(stdout=errored), monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_failed == 1
        assert any("k8s/bad.yaml" in e for e in scanner.errors)

    def test_failed_targets_count_files_not_resources(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        names = [f"pod-{n}" for n in range(5)]
        (tree / "k8s" / "bad.yaml").unlink()
        (tree / "k8s" / "many.yaml").write_text(
            "---\n".join(BAD_POD.replace("bad-pod", n) for n in names)
        )
        (tree / "k8s" / "good.yaml").unlink()
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        erroring = _report_text(
            *[
                _entry(
                    policy="require-team-label",
                    rule="check-team-label",
                    result="error",
                    resources=[{"kind": "Pod", "namespace": "default", "name": n}],
                )
                for n in names
            ]
        )
        _run(scanner, FakeKyverno(stdout=erroring), monkeypatch)
        assert scanner.targets_attempted == 1
        assert scanner.targets_failed == 1
        assert len(scanner.errors) == 5

    def test_failed_targets_never_exceed_the_targets_attempted(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        ghosts = _report_text(
            *[
                _entry(
                    result="error",
                    resources=[{"kind": "Pod", "namespace": "x", "name": f"g{n}"}],
                )
                for n in range(4)
            ],
            _entry(result="error"),
        )
        _run(scanner, FakeKyverno(stdout=ghosts), monkeypatch)
        assert scanner.targets_failed <= scanner.targets_attempted

    def test_an_invalid_policy_is_a_failed_target_named_by_its_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "policies" / "broken.yaml").write_text(INVALID_POLICY)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(stdout=SKIPPED_REPORT), monkeypatch)
        assert len(report.get_all_results()) == 1
        assert scanner.targets_failed == 1
        (line,) = [e for e in scanner.errors if "broken" in e]
        assert "policies/broken.yaml" in line
        assert "only one of pattern" not in line

    def test_a_policy_exception_waives_a_finding_without_being_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        skipped = CLUSTER_REPORT.replace("result: fail", "result: skip")
        report = _run(scanner, FakeKyverno(stdout=skipped, exit_code=0), monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_failed == 0


class TestExitStatus:
    def test_exit_one_with_findings_is_a_completed_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(exit_code=1), monkeypatch)
        assert len(report.get_all_results()) == 1

    def test_exit_one_without_a_report_is_a_failed_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(
            stdout=_WARNING,
            exit_code=1,
            stderr="Error: failed to load resources (Object 'Kind' is missing in 'x')",
        )
        with pytest.raises(ScannerError, match="without printing a report") as raised:
            _run(scanner, fake, monkeypatch)
        # The stderr can quote scanned text; it must not reach the message.
        assert "Object 'Kind'" not in str(raised.value)
        assert scanner.errors == []

    def test_exit_one_with_a_report_that_holds_no_failure_is_a_failed_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=CLEAN_REPORT, exit_code=1)
        with pytest.raises(ScannerError, match="without printing a report"):
            _run(scanner, fake, monkeypatch)

    def test_the_manifest_kyverno_cannot_load_is_a_failed_target_and_the_rest_is_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "evil.yaml").write_text(BAD_POD.replace("bad-pod", "evil-pod"))
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])

        def serve(argv):
            return "" if "--resource=k8s/evil.yaml" in argv else CLUSTER_REPORT

        fake = FakeKyverno(stdout=serve, exit_code=1)
        report = _run(scanner, fake, monkeypatch)
        assert [f[3] for f in _findings(report)] == ["k8s/bad.yaml"]
        assert scanner.targets_attempted == 3
        assert scanner.targets_failed == 1
        (line,) = scanner.errors
        assert "k8s/evil.yaml" in line

    def test_a_scan_in_which_no_run_loads_anything_is_still_a_failed_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout="", exit_code=1)
        with pytest.raises(ScannerError, match="without printing a report"):
            _run(scanner, fake, monkeypatch)
        assert scanner.errors == []
        assert len(fake.calls) <= 8

    def test_skipped_policies_and_no_report_fail_the_scan_naming_the_policies(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "policies" / "broken.yaml").write_text(INVALID_POLICY)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno(stdout=SKIPPED_BLOCK, exit_code=1)
        with pytest.raises(ScannerError, match="broken-policy"):
            _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    @pytest.mark.parametrize("code", [2, 126, 127, 137])
    def test_any_other_exit_code_fails_even_with_a_report(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        with pytest.raises(ScannerError, match=f"exited {code}"):
            _run(scanner, FakeKyverno(exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"], scan_timeout=5)
        fake = FakeKyverno(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "stdout",
        [
            "apiVersion: openreports.io/v1alpha1\nresults: [unclosed\n",
            "apiVersion: openreports.io/v1alpha1\nresults: 7\n",
            "apiVersion: x\nresults:\n- not a mapping\n",
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        with pytest.raises(ScannerError, match="cannot read"):
            _run(scanner, FakeKyverno(stdout=stdout, exit_code=0), monkeypatch)

    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []


class TestDependencyCheck:
    def test_validate_plugin_dependencies_follows_the_path(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        assert scanner.validate_plugin_dependencies() is False
        monkeypatch.setattr(ks, "find_executable", lambda cmd: "/fake/bin/kyverno")
        assert scanner.validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_reason_wins(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: "/fake/bin/kyverno")
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False
