# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KyvernoScanner: report parsing, severity mapping, invocation and failure handling.

The report text in this module is what ``kyverno apply`` 1.19.2 (the pinned version)
printed for the manifests and policy defined below, captured on Linux x86_64 with::

    kyverno apply --policy-report --remove-color --output-format=yaml \\
        --resource=res/bad.yaml --resource=res/good.yaml -- policy.yaml

``CLUSTER_REPORT`` is the output for a ``ClusterPolicy`` (one merged ``ClusterReport``,
preceded by the deprecation warning Kyverno prints on stdout).
``NAMESPACED_REPORT`` is the output for the same rule as a namespaced ``Policy`` and as
a ``ClusterPolicy`` together: the merged cluster report, then one ``PolicyReport`` per
namespace and result, each after a ``---`` line. The scan() tests replace the
subprocess with a fake that serves them, so they run on every platform without the
binary.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List

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
    seconds: 1795103159
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
    seconds: 1795103159
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
    seconds: 1795103159
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
    seconds: 1795103405
source: ""
summary:
  error: 0
  fail: 1
  pass: 0
  skip: 0
  warn: 0
"""
)

POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-team-label
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
        ]

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
            [_entry(result="error", message="SECRET-TEXT-FROM-THE-MANIFEST")],
            _index(),
            ".",
        )
        assert len(failed) == 1
        assert "k8s/bad.yaml" in failed[0]
        assert "p" in failed[0] and "bad-pod" in failed[0]
        assert "SECRET-TEXT" not in failed[0]

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

    def test_a_multi_document_file_gives_each_object_its_start_line(self):
        # BAD_POD is nine lines, the separator is line 10, and the second object's
        # own first line (its apiVersion) is line 11: the line is the object's, not
        # the separator's.
        text = BAD_POD + "---\n" + GOOD_POD
        assert len(BAD_POD.splitlines()) == 9
        objects = load_manifest(text)
        assert [(d["metadata"]["name"], line) for d, line in objects] == [
            ("bad-pod", 1),
            ("good-pod", 11),
        ]

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


# ---------------------------------------------------------------------------
# scan()
# ---------------------------------------------------------------------------


class FakeKyverno:
    """Stands in for _run_subprocess: records argv, serves captured output."""

    def __init__(
        self,
        stdout: str = CLUSTER_REPORT,
        exit_code: int = 1,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.stdout, self.exit_code = stdout, exit_code
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, **kwargs):
            self.calls.append({"argv": list(command), "timeout": timeout, **kwargs})
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> KyvernoScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash.yaml"],
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


class TestAlphaPlugin:
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
        fake = FakeKyverno()
        report = _run(scanner, fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []
        assert fake.calls == []
        assert scanner.targets_attempted == 0

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
        assert argv[separator + 1 :] == ["policies/require-team.yaml"]
        assert all(a.startswith("--") for a in argv[2:separator])
        assert call["stdout_preference"] == "return"

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
        (tree / "k8s" / "-odd.yaml").write_text(BAD_POD)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert "--resource=k8s/-odd.yaml" in fake.calls[0]["argv"]

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

    def test_a_long_manifest_list_is_split_into_runs_under_the_cap(self):
        base = ["kyverno", "apply"]
        paths = [f"dir/{'x' * 200}-{n}.yaml" for n in range(400)]
        chunks = ks._argv_chunks(base, paths, ["--", "p.yaml"])
        assert len(chunks) > 1
        assert [p for chunk in chunks for p in chunk] == paths
        for chunk in chunks:
            size = sum(len(p) + len("--resource=") + 3 for p in chunk)
            assert size < 24_000


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

    def test_no_report_at_exit_zero_is_clean_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(stdout=_WARNING, exit_code=0), monkeypatch)
        assert report.get_all_results() == []

    def test_an_evaluation_error_is_a_failed_target(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        errored = CLUSTER_REPORT.replace("result: fail", "result: error")
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        report = _run(scanner, FakeKyverno(stdout=errored), monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_failed == 1
        assert any("k8s/bad.yaml" in e for e in scanner.errors)


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


#: What the planted stderr log holds: a line as Kyverno writes it when a manifest does
#: not load, quoting the manifest's own text (a Secret's data among it).
_QUOTED_MANIFEST_TEXT = "S0VZVkVSTk8tTEVBSy1DQU5BUlk="
_STDERR_LOG = (
    "Error: failed to load resources: k8s/secret.yaml: "
    f"data: {{password: {_QUOTED_MANIFEST_TEXT}}}\n"
)


def _fail_after_the_run(tree, tmp_path, monkeypatch) -> tuple:
    """A scan that fails past kyverno's run, with a stderr log quoting a manifest.

    The failure comes from the adapter, after the tool exited 1 with a report, so it
    reaches the ``except Exception`` branch of scan(), which describes it with
    ``_describe_scan_failure``. Returns the message and the log's path.
    """
    scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
    log = (
        Path(scanner.results_dir or scanner.context.output_dir)
        / "source"
        / "KyvernoScanner.stderr.log"
    )
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(_STDERR_LOG, encoding="utf-8")

    def adapter_failure(*args, **kwargs):
        raise RuntimeError("the adapter could not convert the report")

    monkeypatch.setattr(ks, "convert_report_results", adapter_failure)
    with pytest.raises(ScannerError) as raised:
        _run(scanner, FakeKyverno(), monkeypatch)
    return str(raised.value), log


class TestTheStderrLogIsNotQuoted:
    """Kyverno's stderr can quote a scanned file, so a failure never quotes the log.

    The failure text reaches ash.log, the console and every results file. The base
    class quotes the head and tail of the tool's stderr log for a scanner that leaves
    ``quote_tool_stderr`` on; kyverno turns it off, so the text names the log instead.
    """

    def test_the_scanner_turns_quoting_off(self):
        assert KyvernoScanner.quote_tool_stderr is False

    def test_a_failure_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        message, log = _fail_after_the_run(tree, tmp_path, monkeypatch)
        assert "the adapter could not convert the report" in message
        assert _QUOTED_MANIFEST_TEXT not in message
        assert "secret.yaml" not in message
        assert "not quoted here" in message
        assert log.as_posix() in message

    def test_control_with_quoting_on_the_same_failure_quotes_the_log(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Must-flag control: the probe above can see a quoted log."""
        monkeypatch.setattr(KyvernoScanner, "quote_tool_stderr", True)
        message, _log = _fail_after_the_run(tree, tmp_path, monkeypatch)
        assert _QUOTED_MANIFEST_TEXT in message


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
class TestPolicyDirectoryLinks:
    """A file under a policy directory must resolve inside it, or it is not read."""

    @staticmethod
    def _recorded_reads(monkeypatch) -> List[Path]:
        """Every path ``_holds_policy`` is asked to read, which is every file it opens."""
        read: List[Path] = []
        real = KyvernoScanner._holds_policy

        def recording(path: Path) -> bool:
            read.append(Path(path))
            return real(path)

        monkeypatch.setattr(KyvernoScanner, "_holds_policy", staticmethod(recording))
        return read

    @staticmethod
    def _policies_passed(fake: FakeKyverno) -> List[str]:
        argv = fake.calls[0]["argv"]
        return argv[argv.index("--") + 1 :]

    def test_a_file_link_leaving_the_directory_is_skipped_and_not_read(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "elsewhere.yaml").write_text(
            POLICY.replace("require-team-label", "elsewhere")
        )
        (tree / "policies" / "linked.yaml").symlink_to(outside / "elsewhere.yaml")
        read = self._recorded_reads(monkeypatch)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert self._policies_passed(fake) == ["policies/require-team.yaml"]
        # By name: the walk starts at the policy directory as operator_paths resolved
        # it, so a path read is spelled under that, not under the fixture's spelling.
        names = {path.name for path in read}
        assert "linked.yaml" not in names
        assert "require-team.yaml" in names

    def test_a_file_under_a_linked_directory_is_skipped_and_not_read(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside-policies"
        outside.mkdir()
        (outside / "inner.yaml").write_text(
            POLICY.replace("require-team-label", "inner")
        )
        (tree / "policies" / "shared").symlink_to(outside, target_is_directory=True)
        read = self._recorded_reads(monkeypatch)
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert self._policies_passed(fake) == ["policies/require-team.yaml"]
        assert not [path for path in read if "shared" in path.parts]

    def test_control_a_link_that_stays_in_the_directory_is_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Must-not-flag control: what is refused is leaving the directory, not a link."""
        (tree / "policies" / "alias.yaml").symlink_to(
            tree / "policies" / "require-team.yaml"
        )
        scanner = _scanner(tree, tmp_path, policy_paths=["policies"])
        fake = FakeKyverno()
        _run(scanner, fake, monkeypatch)
        assert self._policies_passed(fake) == [
            "policies/alias.yaml",
            "policies/require-team.yaml",
        ]


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
