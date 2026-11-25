# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Kubernetes manifest policy checks with the Kyverno CLI (``kyverno apply``).

What it runs
------------
``kyverno apply --policy-report --remove-color --output-format=yaml
[--exception=<exceptions file>] --resource=<manifest> ... -- <policies file>`` in the
source directory. Kyverno evaluates the operator's policies against the Kubernetes
manifests in the scanned tree, offline: no ``--cluster`` flag is passed, so it makes
no API call, and ``--registry`` (image registry access) is not passed either.

The policies reach Kyverno as one file under the results directory that holds every
policy document found under ``policy_paths`` (so a vendored policy library of hundreds
of files costs one argument, not hundreds), and the ``PolicyException`` documents found
there go to a second file passed as ``--exception=``: Kyverno loads an exception given
as a positional policy path without applying it.

Policies are bring-your-own. Kyverno ships no rules, so with no policy configured the
scanner does nothing: it logs at INFO and reports SKIPPED (``targets_attempted = 0``),
the same outcome ``snyk-code`` gives a tree it has nothing to test in. Name policy
files or directories in ``scanners.kyverno.options.policy_paths``.

This module follows the own-``scan()`` shape of the hadolint plugin, not the template
shape of betterleaks, because Kyverno gives ASH neither SARIF nor a report file and
because it cannot be pointed at a directory (next section).

Measured against the pinned release (v1.19.2)
---------------------------------------------
* The report is written to stdout, after any ``Warning:`` lines Kyverno prints there
  (each legacy ``kyverno.io/v1`` policy draws one deprecation warning). Errors go to
  stderr. With ``--output-format=yaml`` the report is one ``ClusterReport`` document
  merged over all cluster-scoped results, and one ``Report`` document per namespace
  after a ``---`` line. The kind and ``apiVersion`` (``openreports.io/v1alpha1`` in
  1.19.2) are not relied on; the parser reads the ``results`` list of every document.
* A result carries ``policy``, ``rule``, ``result`` (pass, fail, warn, error, skip),
  ``severity``, ``category``, ``scored``, ``message`` and ``resources`` (apiVersion,
  kind, namespace, name). It carries no file path and no line, so ASH reads the
  manifests itself and maps a resource back to the file and line that declares it.
* ``--resource=<directory>`` stops the whole run (exit 1, "failed to load resources")
  at the first YAML file in it that is not a Kubernetes object, and the error text
  quotes that file. So ASH passes each manifest as its own ``--resource=<file>``, after
  checking that it parses and has ``apiVersion`` and ``kind``.
* Exit status: 0 when nothing failed, 1 for a failed result, for a policy evaluation
  error, and also for a run that could not load its inputs. The exit code alone cannot
  tell those apart, so a run that exits 1 counts as complete only when it printed a
  report. Any other exit code fails the scan. ``--warn-exit-code`` is not passed, so a
  ``warn`` result exits 0.
* A policy path that does not exist, and a file that is not a policy, are skipped
  without a word and exit 0, so ASH checks both itself before the run (a missing path
  fails the scan; a tree with no policy document reports SKIPPED).
* An invalid policy among valid ones is skipped: stdout carries a ``Policies Skipped:``
  block (numbered ``<policy name>: path: <reason>`` lines between rows of dashes)
  before the report, and the run still exits by its results. If every policy is
  invalid there is no report and the exit is 1.
* A ``PolicyException`` given as a positional policy path draws a deprecation warning
  and is not applied; given with ``--exception=<file>`` it is, and the rule's result
  becomes ``skip`` (which is not a finding).
* A name given to ``--resource`` is split on commas as CSV by the flag parser, so
  ``a,b.yaml`` becomes the paths ``a`` and ``b.yaml`` (exit 1, "failed to load
  resources"), and a double quote fails the parse. ASH leaves such files out.
* A policy in ``policies.kyverno.io`` (``ValidatingPolicy``) has no named rules, so its
  results carry no ``rule`` and ASH reports them as ``<policy>/unknown-rule``.
* v1.20.0 refuses to load the legacy ``kyverno.io/v1`` ``ClusterPolicy`` and ``Policy``
  kinds. The pin is v1.19.2, the last release that loads both those and the
  ``policies.kyverno.io`` kinds. Moving the pin to 1.20 or later takes a policy
  migration, which is the operator's.

Severity
--------
Kyverno's severity names map one to one: critical is CRITICAL (SARIF ``error``), high
is HIGH (``error``), medium is MEDIUM (``warning``), low is LOW (``note``), info is
INFO (``none``). The SARIF level of a CRITICAL or HIGH finding is ``error``, which is
not a Kyverno severity name; these are policy violations, not demonstrated exploits.
A policy that declares no severity gets MEDIUM for a ``fail`` and LOW for a ``warn``.
The name is matched without regard to case. A severity name outside the five is HIGH,
not CRITICAL, so an unrecognized value is not dropped to a lower level.
``issue_severity`` and the SARIF level are set from the same row.

A ``result: error`` entry is not a finding: Kyverno could not evaluate that rule on
that resource. It is listed in the scan's errors (policy, rule and resource only; the
message is not copied, since it can quote the resource), one line per entry. The scan
counts failed targets as distinct files, not entries: ``targets_failed`` is the number
of manifest files with at least one such entry, plus each invalid policy file and each
manifest Kyverno could not load, and never exceeds ``targets_attempted``.

What is scanned
---------------
The YAML and JSON files of the scan set that hold a Kubernetes object. Kyverno's own
kinds (``kyverno.io``, ``policies.kyverno.io``, ``cli.kyverno.io``), Chainsaw tests
(``chainsaw.kyverno.io``), kustomize files (``kustomize.config.k8s.io``), report kinds
and admission policies are not treated as resources, and neither is anything under a
directory named in ``policy_paths`` (a vendored policy library carries negative test
fixtures that are meant to violate its policies). Files that do not parse, and files
over ``MAX_MANIFEST_BYTES``, are skipped. A file that holds an object beside other
documents is left out whole and named in a WARNING, because Kyverno stops the run at a
document that is not an object. Helm templates and other templated YAML do not reach
Kyverno.

Where a finding lands
---------------------
Kyverno's report names a resource, not a file, so ASH maps ``(kind, namespace, name)``
back to the file that declares it. Two files that declare the same object (a kustomize
base and its overlays) would make that mapping ambiguous, so ASH never gives such files
the same Kyverno run: it plans the runs so that, within one run, every identity is
declared by one file, and maps each run's report with that run's own index. A file
with no namespace collides with a copy of the same kind and name in any namespace,
because Kyverno may report a namespace the manifest does not state.

Offline and sandbox
-------------------
Nothing in a ``kyverno apply`` run without ``--cluster`` reaches the network, so
``offline_strategy`` is BUNDLED. The sandbox requirements are the strict default.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Literal,
    NamedTuple,
    Optional,
    Set,
    Tuple,
)

import yaml
from pydantic import AnyUrl, Field, model_validator
from typing_extensions import Self

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.config_trust import operator_paths
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Kyverno severity name -> (ASH severity, SARIF level). See the module docstring.
KYVERNO_SEVERITY_MAP: Dict[str, Tuple[str, Level]] = {
    "critical": ("CRITICAL", Level.error),
    "high": ("HIGH", Level.error),
    "medium": ("MEDIUM", Level.warning),
    "low": ("LOW", Level.note),
    "info": ("INFO", Level.none),
}

#: Used for a severity name that is not one of the five: the more severe choice.
UNKNOWN_SEVERITY: Tuple[str, Level] = KYVERNO_SEVERITY_MAP["high"]

#: What a policy that declares no severity gets, by result.
DEFAULT_SEVERITY_FAIL = "medium"
DEFAULT_SEVERITY_WARN = "low"

#: Report ``result`` values that are findings.
FINDING_RESULTS = frozenset({"fail", "warn"})

#: API groups of objects that configure or report on Kyverno, not workloads to check.
NON_RESOURCE_GROUPS = frozenset(
    {
        "kyverno.io",
        "policies.kyverno.io",
        "cli.kyverno.io",
        "reports.kyverno.io",
        "wgpolicyk8s.io",
        "openreports.io",
        "chainsaw.kyverno.io",
        "kustomize.config.k8s.io",
    }
)

#: API groups whose kinds Kyverno loads as policies, minus ``NON_POLICY_KYVERNO_KINDS``.
POLICY_GROUPS = ("kyverno.io", "policies.kyverno.io")

#: Kinds of ``POLICY_GROUPS`` that ``kyverno apply`` takes as exceptions.
EXCEPTION_KINDS = frozenset({"PolicyException"})

#: Kinds of ``POLICY_GROUPS`` that are not policies for ``kyverno apply``: exceptions
#: (passed with ``--exception``) and the cleanup and context kinds it has no use for.
NON_POLICY_KYVERNO_KINDS = frozenset(
    {
        *EXCEPTION_KINDS,
        "CleanupPolicy",
        "ClusterCleanupPolicy",
        "DeletingPolicy",
        "NamespacedDeletingPolicy",
        "GlobalContextEntry",
        "UpdateRequest",
    }
)

#: Kinds Kyverno loads as policies although they are Kubernetes' own.
ADMISSION_POLICY_KINDS = frozenset(
    {
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "MutatingAdmissionPolicy",
        "MutatingAdmissionPolicyBinding",
    }
)

#: File suffixes read as manifests and policies.
MANIFEST_SUFFIXES = (".yaml", ".yml", ".json")

#: Largest file read as a manifest. Bigger files are skipped, not partly read.
MAX_MANIFEST_BYTES = 5 * 1024 * 1024

#: Upper bound on one kyverno command line, in characters (Windows caps it at 32,767).
_MAX_COMMAND_LINE_CHARS = 24_000

#: Most extra Kyverno runs one scan spends splitting a run that failed without a report
#: to find the manifest it could not load.
_MAX_BISECTS = 32

#: Longest list of paths named in one notice.
_NOTICE_PATHS = 10

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: Longest message copied from a result into SARIF.
_MAX_MESSAGE_CHARS = 2000

_SEVERITY_TAGS = ["kyverno", "kubernetes", "policy"]


def _group_of(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def is_policy_document(doc: Any) -> bool:
    """Whether a parsed YAML document is a policy ``kyverno apply`` evaluates.

    Exceptions (``is_exception_document``) and the cleanup and context kinds are
    Kyverno's but not policies: counting them would open the opt-in gate for a tree
    that holds nothing to evaluate.
    """
    if not isinstance(doc, dict):
        return False
    api_version, kind = doc.get("apiVersion"), doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return False
    if _group_of(api_version) in POLICY_GROUPS:
        return kind not in NON_POLICY_KYVERNO_KINDS
    return kind in ADMISSION_POLICY_KINDS


def is_exception_document(doc: Any) -> bool:
    """Whether a parsed YAML document is a Kyverno policy exception."""
    if not isinstance(doc, dict):
        return False
    api_version, kind = doc.get("apiVersion"), doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return False
    return _group_of(api_version) in POLICY_GROUPS and kind in EXCEPTION_KINDS


def is_resource_document(doc: Any) -> bool:
    """Whether a parsed YAML document is a Kubernetes object to check."""
    if not isinstance(doc, dict):
        return False
    api_version, kind = doc.get("apiVersion"), doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return False
    if not api_version or not kind:
        return False
    if _group_of(api_version) in NON_RESOURCE_GROUPS:
        return False
    return kind not in ADMISSION_POLICY_KINDS


def _documents(text: str) -> List[Tuple[Any, int]]:
    """Every YAML document of *text* with the 1-based line it starts on.

    Raises ``yaml.YAMLError`` when the text does not parse.
    """
    loader = yaml.SafeLoader(text)
    found: List[Tuple[Any, int]] = []
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                break
            found.append((loader.construct_document(node), node.start_mark.line + 1))
    finally:
        loader.dispose()
    return found


def _identity(doc: Dict[str, Any]) -> Tuple[str, str, str]:
    metadata = doc.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    return (
        str(doc.get("kind")),
        str(namespace) if isinstance(namespace, str) else "",
        str(name) if isinstance(name, str) else "",
    )


class ManifestIndex:
    """Where each Kubernetes object of the scanned files is declared.

    Kyverno's report names a resource, not a file; this maps ``(kind, namespace,
    name)`` back to the file and line. A resource whose manifest sets no namespace is
    found by ``(kind, name)`` alone, because Kyverno may report a namespace the
    manifest does not state. When two files declare the same object the first, in
    sorted order, wins, so a scan builds one index per run of files that do not share
    an identity (``plan_runs``) and the rule never has to choose.
    """

    def __init__(self) -> None:
        self._exact: Dict[Tuple[str, str, str], Tuple[str, int]] = {}
        self._by_name: Dict[Tuple[str, str], Tuple[str, int]] = {}

    def add(self, doc: Dict[str, Any], uri: str, line: int) -> None:
        kind, namespace, name = _identity(doc)
        self._exact.setdefault((kind, namespace, name), (uri, line))
        self._by_name.setdefault((kind, name), (uri, line))

    def locate(self, kind: str, namespace: str, name: str) -> Optional[Tuple[str, int]]:
        return self._exact.get((kind, namespace, name)) or self._by_name.get(
            (kind, name)
        )


class _Manifest(NamedTuple):
    """One manifest file of the scan: where it is, how it is spelled, what it holds."""

    path: Path
    uri: str
    objects: List[Tuple[Dict[str, Any], int]]


class _Run:
    """The manifests one group of Kyverno invocations covers, no two sharing an identity.

    An identity is a ``(kind, namespace, name)``. A manifest with no namespace is
    taken to collide with any namespace of the same kind and name, because
    ``ManifestIndex.locate`` falls back to ``(kind, name)`` for it and Kyverno may
    report a namespace the manifest does not state.
    """

    def __init__(self) -> None:
        self.manifests: List[_Manifest] = []
        self._exact: Set[Tuple[str, str, str]] = set()
        self._any_namespace: Set[Tuple[str, str]] = set()
        self._no_namespace: Set[Tuple[str, str]] = set()

    @staticmethod
    def _identities(manifest: _Manifest) -> Set[Tuple[str, str, str]]:
        found = {_identity(doc) for doc, _ in manifest.objects}
        return {i for i in found if i[2]}

    def accepts(self, manifest: _Manifest) -> bool:
        for kind, namespace, name in self._identities(manifest):
            if (kind, namespace, name) in self._exact:
                return False
            if not namespace and (kind, name) in self._any_namespace:
                return False
            if namespace and (kind, name) in self._no_namespace:
                return False
        return True

    def add(self, manifest: _Manifest) -> None:
        self.manifests.append(manifest)
        for kind, namespace, name in self._identities(manifest):
            self._exact.add((kind, namespace, name))
            self._any_namespace.add((kind, name))
            if not namespace:
                self._no_namespace.add((kind, name))

    def index(self) -> ManifestIndex:
        index = ManifestIndex()
        for manifest in self.manifests:
            for doc, line in manifest.objects:
                index.add(doc, manifest.uri, line)
        return index


def plan_runs(manifests: List[_Manifest]) -> List[_Run]:
    """Group *manifests* (in order) into runs in which no identity has two files.

    Each manifest goes to the first run that does not already hold one of its
    identities, so a tree without collisions is one run and a kustomize tree with N
    overlays of one object is N+1.
    """
    runs: List[_Run] = []
    for manifest in manifests:
        for run in runs:
            if run.accepts(manifest):
                run.add(manifest)
                break
        else:
            run = _Run()
            run.add(manifest)
            runs.append(run)
    return runs


@dataclass
class _Policies:
    """What ``policy_paths`` names: the policy and exception documents and where they are.

    ``dirs`` are the configured directories, so that nothing under one is scanned as
    a resource; ``owners`` maps a policy's name to the files that declare it.
    """

    files: List[Path] = field(default_factory=list)
    exception_files: List[Path] = field(default_factory=list)
    dirs: List[Path] = field(default_factory=list)
    policies: List[Dict[str, Any]] = field(default_factory=list)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)
    owners: Dict[str, List[Path]] = field(default_factory=dict)


@dataclass
class _Outcome:
    """What the Kyverno invocations over one set of manifests came to."""

    entries: List[Dict[str, Any]] = field(default_factory=list)
    skipped_policies: List[str] = field(default_factory=list)
    failed_uris: List[str] = field(default_factory=list)
    completed: int = 0
    final_args: List[str] = field(default_factory=list)


_NO_REPORT_MESSAGE = (
    "kyverno exited 1 without printing a report, which means it failed before "
    "evaluating anything (its message is in the scanner's stderr log and is not "
    "quoted here)"
)


class FailedTarget(str):  # noqa: SLOT000 - one more attribute per line, kept in __dict__
    """One line of the scan's errors, and the file (or ``.``) it counts against."""

    uri: str

    def __new__(cls, text: str, uri: str) -> Self:
        obj = super().__new__(cls, text)
        obj.uri = uri
        return obj


def read_manifest(
    text: str,
) -> Tuple[Optional[List[Tuple[Dict[str, Any], int]]], Optional[str]]:
    """The Kubernetes objects of one file with their start lines, and why not.

    The objects are None for a file that does not parse, that holds no object with
    ``apiVersion`` and ``kind``, or that holds anything else: Kyverno stops the whole
    run at one document that is not an object, so a file is passed only when every
    document in it is one (empty documents, which YAML allows between separators, are
    ignored). A ``kind: List`` is expanded into its items, all located at the list's
    start line.

    The reason is ``"mixed"`` when the objects are None because a file holds an object
    beside a document that is not one (a real workload left out is worth saying so),
    and None otherwise.
    """
    if "apiVersion" not in text or "kind" not in text:
        return None, None
    try:
        documents = _documents(text)
    except yaml.YAMLError:
        return None, None
    objects: List[Tuple[Dict[str, Any], int]] = []
    other = False
    for doc, line in documents:
        if doc is None:
            continue
        if not is_resource_document(doc):
            other = True
            continue
        items = doc.get("items")
        if doc.get("kind") == "List" and isinstance(items, list):
            for item in items:
                if is_resource_document(item):
                    objects.append((item, line))
            continue
        objects.append((doc, line))
    if other:
        return None, "mixed" if objects else None
    return (objects or None), None


def load_manifest(
    text: str,
) -> Optional[List[Tuple[Dict[str, Any], int]]]:
    """The Kubernetes objects of one file, with their start lines; None when none.

    See ``read_manifest`` for which files are passed.
    """
    return read_manifest(text)[0]


_SKIPPED_ENTRY = re.compile(r"^\s*\d+\.\s+(\S.*?):\s+path:", re.MULTILINE)


def parse_skipped_policies(text: str) -> List[str]:
    """The names of the policies Kyverno skipped as invalid, from its stdout.

    Kyverno prints a ``Policies Skipped:`` block (numbered ``<name>: path: <reason>``
    lines between rows of dashes) before the report. Only the names are returned: the
    reason can quote the policy.
    """
    marker = text.find("Policies Skipped:")
    if marker < 0:
        return []
    block = text[marker:]
    end = block.find("\n-----")
    if end >= 0:
        block = block[:end]
    return [m.group(1) for m in _SKIPPED_ENTRY.finditer(block)]


def parse_policy_report_output(text: str) -> List[Dict[str, Any]]:
    """The ``results`` of every report document in ``kyverno apply`` output.

    Text before the first line that starts ``apiVersion:`` (Kyverno's ``Warning:``
    lines, which it prints on stdout) is ignored. Returns an empty list when there is
    no report at all, which Kyverno prints when no policy matched a resource.

    Raises:
        ValueError: when a report is present and cannot be read as one.
    """
    start = None
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.startswith("apiVersion:"):
            start = offset
            break
        offset += len(line)
    if start is None:
        return []
    try:
        documents = [d for d in yaml.safe_load_all(text[start:]) if d is not None]
    except yaml.YAMLError as exc:
        raise ValueError(f"the report is not valid YAML ({type(exc).__name__})")
    results: List[Dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError("the report is not a mapping")
        entries = document.get("results") or []
        if not isinstance(entries, list):
            raise ValueError("the report's results are not a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("a report result is not a mapping")
            results.append(entry)
    return results


def severity_for(entry: Dict[str, Any]) -> Tuple[str, Level]:
    """The ASH severity and SARIF level of a ``fail`` or ``warn`` result."""
    declared = entry.get("severity")
    if declared is None or declared == "":
        declared = (
            DEFAULT_SEVERITY_WARN
            if entry.get("result") == "warn"
            else DEFAULT_SEVERITY_FAIL
        )
    return KYVERNO_SEVERITY_MAP.get(str(declared).strip().lower(), UNKNOWN_SEVERITY)


def _resources_of(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    resources = entry.get("resources")
    if not isinstance(resources, list) or not resources:
        resources = entry.get("subjects")
    return [r for r in resources or [] if isinstance(r, dict)]


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:32]


def _clip(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= _MAX_MESSAGE_CHARS:
        return text
    return text[: _MAX_MESSAGE_CHARS - 3] + "..."


def convert_report_results(
    entries: Iterable[Dict[str, Any]],
    index: ManifestIndex,
    fallback_uri: str = ".",
) -> Tuple[List[Result], List[ReportingDescriptor], List[FailedTarget]]:
    """Kyverno report results as SARIF results, rule descriptors and failed targets.

    ``fail`` and ``warn`` entries become one SARIF result per resource they name.
    ``error`` entries become one line each in the third list: ``"<uri>: ..."``, one
    per resource, naming the policy and rule but not Kyverno's message. Each line is a
    ``FailedTarget``, a string that also knows the file it counts against.
    """
    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}
    failed: List[FailedTarget] = []
    seen: Set[Tuple[Any, ...]] = set()
    for entry in entries:
        outcome = str(entry.get("result") or "").lower()
        policy = str(entry.get("policy") or "unknown-policy")
        rule = str(entry.get("rule") or "unknown-rule")
        resources = _resources_of(entry) or [{}]
        if outcome == "error":
            for resource in resources:
                uri, _ = _place(resource, index, fallback_uri)
                failed.append(
                    FailedTarget(
                        f"{uri}: kyverno could not evaluate policy {policy}, rule "
                        f"{rule}{_describe_resource(resource)}, so it was not checked",
                        uri,
                    )
                )
            continue
        if outcome not in FINDING_RESULTS:
            continue
        severity, level = severity_for(entry)
        rule_id = f"{policy}/{rule}"
        message = _clip(str(entry.get("message") or f"Policy {policy} rule {rule}"))
        category = entry.get("category")
        if rule_id not in rules:
            rules[rule_id] = ReportingDescriptor(
                id=rule_id,
                name=rule,
                shortDescription=MultiformatMessageString(text=message),
                properties=PropertyBag(
                    tags=[*_SEVERITY_TAGS, *([str(category)] if category else [])]
                ),
            )
        for resource in resources:
            uri, line = _place(resource, index, fallback_uri)
            key = (rule_id, uri, line, _describe_resource(resource), outcome)
            if key in seen:
                continue
            seen.add(key)
            physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if line:
                physical["region"] = {"startLine": line}
            properties: Dict[str, Any] = {
                "issue_severity": severity,
                "kyverno_result": outcome,
                "kyverno_policy": policy,
                "kyverno_rule": rule,
                "tags": [*_SEVERITY_TAGS, *([str(category)] if category else [])],
            }
            if resource:
                properties["kyverno_resource"] = (
                    f"{resource.get('kind', '')}"
                    f"{'/' + str(resource['namespace']) if resource.get('namespace') else ''}"
                    f"/{resource.get('name', '')}"
                )
            if entry.get("scored") is False:
                properties["kyverno_scored"] = False
            results.append(
                Result.model_validate(
                    {
                        "ruleId": rule_id,
                        "level": level.value,
                        "message": {"text": message},
                        "locations": [{"physicalLocation": physical}],
                        "partialFingerprints": {
                            "kyverno/v1": _fingerprint(
                                rule_id,
                                uri,
                                resource.get("kind"),
                                resource.get("namespace"),
                                resource.get("name"),
                            )
                        },
                        "properties": properties,
                    }
                )
            )
    return results, [rules[k] for k in sorted(rules)], failed


def _describe_resource(resource: Dict[str, Any]) -> str:
    if not resource:
        return ""
    where = (
        f" in namespace {resource['namespace']}" if resource.get("namespace") else ""
    )
    return f" on {resource.get('kind', 'resource')} {resource.get('name', '')}{where}"


def _place(
    resource: Dict[str, Any], index: ManifestIndex, fallback_uri: str
) -> Tuple[str, Optional[int]]:
    found = index.locate(
        str(resource.get("kind") or ""),
        str(resource.get("namespace") or ""),
        str(resource.get("name") or ""),
    )
    if found is None:
        return fallback_uri, None
    return found


def _argv_chunks(
    base_args: List[str], paths: List[str], tail: List[str]
) -> List[List[str]]:
    """Split the ``--resource=`` tokens so each command line stays under the cap.

    Every chunk has at least one path. *tail* (``--`` and the policy files) is part of
    every command line, so it is counted in the fixed cost.
    """
    fixed = sum(len(a) + 3 for a in [*base_args, *tail])
    chunks: List[List[str]] = []
    current: List[str] = []
    size = fixed
    for path in paths:
        cost = len(path) + len("--resource=") + 3
        if current and size + cost > _MAX_COMMAND_LINE_CHARS:
            chunks.append(current)
            current, size = [], fixed
        current.append(path)
        size += cost
    if current:
        chunks.append(current)
    return chunks


class KyvernoScannerConfigOptions(ScannerOptionsBase):
    policy_paths: Annotated[
        List[Path | str],
        Field(
            description=(
                "Kyverno policy files, or directories of them (YAML or JSON), to "
                "apply to the Kubernetes manifests in the scanned tree. A relative "
                "path is taken from the source directory. Kyverno ships no policies, "
                "so with none the scanner does nothing: it logs at INFO and the scan "
                "reports it as skipped. A path that does not exist fails the scan. "
                f"{SET_BY_THE_OPERATOR} An entry set by such a config is ignored "
                "with a warning."
            ),
        ),
    ] = []


class KyvernoScannerConfig(ScannerPluginConfigBase):
    name: Literal["kyverno"] = "kyverno"
    enabled: bool = True
    options: Annotated[
        KyvernoScannerConfigOptions, Field(description="Configure kyverno")
    ] = KyvernoScannerConfigOptions()


@ash_scanner_plugin
class KyvernoScanner(ScannerPluginBase[KyvernoScannerConfig]):
    """Checks Kubernetes manifests against Kyverno policies with ``kyverno apply``."""

    #: A native binary installed from its pinned release archive.
    python_only: ClassVar[bool | None] = False

    # `kyverno apply` without --cluster makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # 0 nothing failed, 1 a failed result or an error; see "Exit status" above. A run
    # that exits 1 is complete only when it printed a report.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}
    # The strict default: no network, baseline environment only. The scanner reads
    # the policy files and manifests inside the source directory, and the operator's
    # policy paths outside it are not granted to the sandbox yet; grants derived from
    # options wait for the sandbox's grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = KyvernoScannerConfig()
        self.command = "kyverno"
        self.subcommands = ["apply"]
        self.tool_type = ScannerToolType.IAC
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "KyvernoScanner":
        """Install kyverno from its pinned release archive (see tool_downloads).

        A tree whose ``tool_downloads`` has no kyverno table yet (the pin rows land
        with the integration of this plugin) still loads: the scanner then has no
        install command and relies on a ``kyverno`` already on PATH.
        """
        try:
            commands = pinned_tool_install_commands("kyverno")
        except ToolNotProvisionableError:
            ASH_LOGGER.debug(
                "No pinned release table for kyverno; it must already be on PATH."
            )
            return self
        self.custom_install_commands.update(commands)
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: kyverno overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("KyvernoScanner has no plugin context")
        return self.context

    def _options_of(self, config: Any = None) -> KyvernoScannerConfigOptions:
        """The options of *config* (what ``scan()`` was given) or of this scanner.

        ``_pre_scan`` swaps the scanner's config for the one ``scan()`` is given, but
        the opt-in gate runs before it, so the gate has to read the same config.
        """
        source = config if config is not None else self.config
        if isinstance(source, dict):
            options = source.get("options")
        else:
            options = getattr(source, "options", None)
        if isinstance(options, KyvernoScannerConfigOptions):
            return options
        if options is None:
            return KyvernoScannerConfigOptions()
        data = options if isinstance(options, dict) else options.model_dump()
        return KyvernoScannerConfigOptions.model_validate(data)

    def _policy_inputs(self, config: Any = None) -> "_Policies":
        """The policies and exceptions to apply; empty when none is configured.

        Every operator entry is resolved (``operator_paths``); one the scanned tree
        set is ignored with a warning. A file is kept when it holds a policy or an
        exception document. A directory contributes the files under it, and is
        remembered so that nothing under it is scanned as a resource.

        Raises:
            ScannerError: when an entry the operator set does not exist.
        """
        configured = list(self._options_of(config).policy_paths or [])
        found = _Policies()
        if not configured:
            return found
        source_dir = Path(self._ctx.source_dir)
        chosen = operator_paths(
            self._ctx.config,
            "scanners.kyverno.options.policy_paths",
            configured,
            source_dir,
            outside_tree=False,
        )
        seen: Set[Path] = set()
        for entry, candidate in zip(configured, chosen):
            if candidate.path is None:
                self._plugin_log(
                    f"Ignoring scanners.kyverno.options.policy_paths entry "
                    f"{str(entry)!r}: {candidate.refusal}.",
                    level=logging.WARNING,
                )
                continue
            path = candidate.path
            if not path.exists():
                raise ScannerError(
                    f"scanners.kyverno.options.policy_paths names {entry!s}, which "
                    f"does not exist (looked for {path.as_posix()}). Fix the path, "
                    "or remove it to leave the kyverno scanner idle."
                )
            if path.is_dir():
                found.dirs.append(path.resolve())
                candidates = sorted(
                    p for p in path.rglob("*") if p.suffix.lower() in MANIFEST_SUFFIXES
                )
            else:
                candidates = [path]
            for file in candidates:
                resolved = file.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                documents = self._policy_documents(file)
                policies = [d for d in documents if is_policy_document(d)]
                exceptions = [d for d in documents if is_exception_document(d)]
                if policies:
                    found.files.append(file)
                    found.policies.extend(policies)
                    for doc in policies:
                        name = (doc.get("metadata") or {}).get("name")
                        if isinstance(name, str):
                            found.owners.setdefault(name, []).append(file)
                if exceptions:
                    found.exception_files.append(file)
                    found.exceptions.extend(exceptions)
        found.files.sort()
        found.exception_files.sort()
        return found

    @staticmethod
    def _policy_documents(path: Path) -> List[Dict[str, Any]]:
        """The documents of a policy file that are mappings; none for a file not read."""
        try:
            if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
                return []
            text = path.read_text(encoding="utf-8", errors="replace")
            return [doc for doc, _ in _documents(text) if isinstance(doc, dict)]
        except (OSError, yaml.YAMLError):
            return []

    def _manifests(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
        policies: "_Policies",
    ) -> List[_Manifest]:
        """The manifest files under *target* to pass to kyverno, sorted, with objects.

        The source branch reads ASH's scan set, so .gitignore and the rest have
        already removed what they remove, and ASH's own output directory is dropped.
        The converted branch walks ``work_dir``. A file must resolve inside *target*:
        a link leaving the tree is skipped, because kyverno's errors quote the
        file's text. A policy or exception file is never a resource, and neither is
        anything under a configured policy directory. A file whose name Kyverno's
        ``--resource`` flag would split is left out, and so is one that mixes
        objects with other documents; both are named in a WARNING.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()
        excluded_files = {
            p.resolve() for p in [*policies.files, *policies.exception_files]
        }
        # A directory that holds the whole target (policy_paths: ["."]) cannot be
        # used to exclude: nothing would be left to scan.
        excluded_dirs = [d for d in policies.dirs if not root.is_relative_to(d)]
        selected: List[_Manifest] = []
        mixed: List[str] = []
        unsafe: List[str] = []
        for path in sorted(set(candidates)):
            if path.suffix.lower() not in MANIFEST_SUFFIXES:
                continue
            if target_type == "source" and path.absolute().is_relative_to(output_dir):
                continue
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved.stat().st_size > MAX_MANIFEST_BYTES:
                    continue
            except (OSError, RuntimeError):
                continue
            if not resolved.is_relative_to(root):
                self._plugin_log(
                    f"Skipping {path.as_posix()}: it resolves to "
                    f"{resolved.as_posix()}, outside the scanned tree.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
                continue
            if resolved in excluded_files or any(
                resolved.is_relative_to(d) for d in excluded_dirs
            ):
                continue
            if global_ignore_paths and self._ignored(
                path, source_dir, global_ignore_paths
            ):
                continue
            try:
                objects, reason = read_manifest(
                    path.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                continue
            uri = self._argv_path(path)
            if objects is None:
                if reason == "mixed":
                    mixed.append(uri)
                continue
            if "," in uri or '"' in uri:
                unsafe.append(uri)
                continue
            selected.append(_Manifest(path, uri, objects))
        self._notice_paths(
            mixed,
            "Left out {n} file(s) that hold a Kubernetes object beside other "
            "documents (kyverno stops its run at a document that is not an object, "
            "so a file is passed only when every document in it is one): {paths}.",
            target_type,
        )
        self._notice_paths(
            unsafe,
            "Left out {n} file(s) whose names kyverno's --resource flag would split "
            "(a comma or a double quote; rename them to have them scanned): {paths}.",
            target_type,
        )
        return selected

    def _notice_paths(
        self,
        paths: List[str],
        template: str,
        target_type: Literal["source", "converted"],
    ) -> None:
        """Log one WARNING that names (up to ``_NOTICE_PATHS`` of) *paths*."""
        if not paths:
            return
        shown = ", ".join(paths[:_NOTICE_PATHS])
        if len(paths) > _NOTICE_PATHS:
            shown += f", and {len(paths) - _NOTICE_PATHS} more"
        self._plugin_log(
            template.format(n=len(paths), paths=shown),
            target_type=target_type,
            level=logging.WARNING,
        )

    @staticmethod
    def _ignored(
        path: Path, source_dir: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> bool:
        """Whether ``global_settings.ignore_paths`` excludes *path* (hadolint's rule)."""
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        try:
            relative = path.resolve().relative_to(source_dir).as_posix()
        except ValueError:
            relative = path.as_posix()
        return any(
            file_path_matches(relative, ignore_path.path)
            for ignore_path in global_ignore_paths
        )

    def _argv_path(self, path: Path) -> str:
        """How *path* is spelled on the command line and in the report URIs.

        Relative to the source directory, which is the subprocess's working
        directory; a file outside it keeps its absolute path.
        """
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    def _base_args(self) -> List[str]:
        return [
            self.command or "kyverno",
            *self.subcommands,
            "--policy-report",
            "--remove-color",
            "--output-format=yaml",
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Kyverno",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://kyverno.io"),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: KyvernoScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Apply the configured policies to every manifest under *target*."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Reset at the top, above every early return, so a second target never
        # inherits the first target's counts.
        self.targets_attempted = 0
        self.targets_failed = 0

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        # The opt-in gate. Before _pre_scan, so an idle scanner does not ask for a
        # binary it will not run. An empty policy list and a list with no policy
        # document in it are the same outcome: nothing was evaluated, so the row
        # grades SKIPPED (targets_attempted = 0), not PASSED. Only policies count: a
        # directory of exceptions has nothing to evaluate. The gate reads the config
        # scan() was given, which _pre_scan has not yet swapped in.
        policies = self._policy_inputs(config)
        if not policies.files:
            self._plugin_log(
                "Kyverno has no policies to apply, so the scan was skipped. Kyverno "
                "ships none: set scanners.kyverno.options.policy_paths to policy "
                "files or directories to turn it on.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            manifests = self._manifests(
                target, target_type, global_ignore_paths, policies
            )
            if not manifests:
                self._plugin_log(
                    f"No Kubernetes manifests found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(manifests)

            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("kyverno.sarif")
            results_file.unlink(missing_ok=True)

            base_args = self._base_args()
            policy_file = self._write_documents(
                results_dir.joinpath("kyverno-policies.yaml"), policies.policies
            )
            if policies.exceptions:
                exception_file = self._write_documents(
                    results_dir.joinpath("kyverno-exceptions.yaml"), policies.exceptions
                )
                spelled = self._argv_path(exception_file)
                if "," in spelled or '"' in spelled:
                    self._plugin_log(
                        "Policy exceptions were not passed to kyverno: the path of "
                        "the file that holds them contains a comma or a double quote, "
                        "which kyverno's --exception flag would split. Findings that "
                        "an exception waives are reported.",
                        target_type=target_type,
                        level=logging.WARNING,
                    )
                else:
                    base_args.append(f"--exception={spelled}")
            tail = ["--", self._argv_path(policy_file)]

            # One budget for every invocation of this scan, so scan_timeout bounds
            # the scanner and not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            results: List[Result] = []
            rules_by_id: Dict[str, ReportingDescriptor] = {}
            skipped_policies: Set[str] = set()
            failed: List[FailedTarget] = []
            final_args: List[str] = []
            completed = 0
            bisects = [_MAX_BISECTS]
            try:
                for run in plan_runs(manifests):
                    outcome = self._run_manifests(
                        [m.uri for m in run.manifests],
                        base_args,
                        tail,
                        results_dir,
                        deadline,
                        timeout,
                        bisects,
                    )
                    final_args = outcome.final_args or final_args
                    completed += outcome.completed
                    skipped_policies.update(outcome.skipped_policies)
                    run_results, run_rules, run_failed = convert_report_results(
                        outcome.entries, run.index()
                    )
                    results.extend(run_results)
                    for rule in run_rules:
                        rules_by_id.setdefault(rule.id, rule)
                    failed.extend(run_failed)
                    failed.extend(
                        FailedTarget(
                            f"{uri}: kyverno exited without a report for a run that "
                            "held this file, so it was not checked",
                            uri,
                        )
                        for uri in outcome.failed_uris
                    )
                    if not outcome.entries and not outcome.failed_uris:
                        self._plugin_log(
                            "kyverno printed no results: no policy matched a "
                            "manifest, or every policy was skipped as invalid. "
                            "Nothing was reported.",
                            target_type=target_type,
                            level=logging.WARNING,
                        )
                if not completed:
                    raise ScannerError(_NO_REPORT_MESSAGE)
            except ScannerError:
                self._post_scan(target=target, target_type=target_type)
                raise
            self._post_scan(target=target, target_type=target_type)

            for name in sorted(skipped_policies):
                owners = policies.owners.get(name) or []
                uris = [self._argv_path(p) for p in owners] or ["."]
                failed.extend(
                    FailedTarget(
                        f"{uri}: kyverno skipped policy {name[:200]} as invalid, so "
                        "its rules were not applied",
                        uri,
                    )
                    for uri in uris
                )
            rules = [rules_by_id[k] for k in sorted(rules_by_id)]
            for line in failed:
                # An ERROR-level log line is also appended to self.errors, once per
                # entry, so it is not appended here as well.
                self._plugin_log(line, target_type=target_type, level=logging.ERROR)
            # Files, not entries: the framework reads failed >= attempted as a total
            # loss, and one erroring rule on a file of many resources is one file.
            self.targets_failed = min(
                len({f.uri for f in failed}), self.targets_attempted
            )

            report = SarifReport(
                version="2.1.0",
                runs=[
                    Run(
                        tool=Tool(
                            driver=ToolComponent(
                                name="Kyverno",
                                version=self.tool_version,
                                informationUri=AnyUrl("https://kyverno.io"),
                                rules=rules or None,
                            )
                        ),
                        results=results,
                    )
                ],
            )
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(report, final_args, target)
            return report
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    @staticmethod
    def _write_documents(path: Path, documents: List[Dict[str, Any]]) -> Path:
        """Write *documents* to *path* as one multi-document YAML file."""
        with open_for_write(path) as handle:
            handle.write(yaml.safe_dump_all(documents, sort_keys=False))
        return path

    def _run_manifests(
        self,
        uris: List[str],
        base_args: List[str],
        tail: List[str],
        results_dir: Path,
        deadline: Optional[float],
        timeout: Optional[float],
        bisects: List[int],
    ) -> "_Outcome":
        """Run Kyverno over the manifests *uris* in as many invocations as the cap needs.

        A run that exits 1 without a failed or errored result did not evaluate what
        it was given (Kyverno exits 1 for a result that failed and for any command
        error, so only the report says which). Its manifests are split in two and run
        again, so that one manifest Kyverno cannot load costs that manifest alone; a
        single manifest that still fails is returned in ``failed_uris``. ``bisects``
        holds what is left of the scan's budget for such splits. A run that fails
        because every policy is invalid is not split: the policies are the cause.

        Raises:
            ScannerError: on a timeout, an unexpected exit code, a report that cannot
                be read, or when every policy was skipped as invalid.
        """
        outcome = _Outcome()
        pending = _argv_chunks(base_args, uris, tail)
        while pending:
            group = pending.pop(0)
            outcome.final_args = [
                *base_args,
                *[f"--resource={p}" for p in group],
                *tail,
            ]
            response = self._run_until(outcome.final_args, results_dir, deadline)
            exit_code = self.exit_code
            if response.get("timed_out"):
                raise ScannerError(
                    f"kyverno timed out after {timeout}s and was killed, so it "
                    "produced no report. Raise scanners.kyverno.options.scan_timeout "
                    "if these manifests legitimately need longer."
                )
            if exit_code not in self.success_exit_codes:
                raise ScannerError(
                    f"kyverno exited {exit_code}; it exits 0 or 1 when it ran, "
                    "so this run did not complete"
                )
            stdout = response.get("stdout") or ""
            try:
                group_entries = parse_policy_report_output(stdout)
            except ValueError as exc:
                raise ScannerError(f"kyverno wrote a report ASH cannot read: {exc}")
            skipped = parse_skipped_policies(stdout)
            evaluated = any(
                str(e.get("result") or "").lower() in ("fail", "error")
                for e in group_entries
            )
            if exit_code != 1 or evaluated:
                outcome.entries.extend(group_entries)
                outcome.skipped_policies.extend(skipped)
                outcome.completed += 1
                continue
            if skipped and not group_entries:
                raise ScannerError(
                    "kyverno skipped every policy as invalid and evaluated nothing: "
                    + ", ".join(sorted({s[:200] for s in skipped}))
                )
            if len(group) > 1 and bisects[0] > 0:
                bisects[0] -= 1
                middle = len(group) // 2
                pending[:0] = [group[:middle], group[middle:]]
                continue
            outcome.failed_uris.extend(group)
        return outcome

    def _run_until(
        self, argv: List[str], results_dir: Path, deadline: Optional[float]
    ) -> Dict[str, Any]:
        """Run *argv* with whatever is left of the scan's time budget.

        stdout is returned for parsing; stderr goes to the scanner's log file, not
        into ``self.errors``, because Kyverno's errors can quote a scanned file.
        """
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - _now()
            if remaining <= 0:
                return {"timed_out": True}
        response = self._run_subprocess(
            command=argv,
            results_dir=results_dir,
            stdout_preference="return",
            stderr_preference="write",
            timeout=remaining,
        )
        return response if isinstance(response, dict) else {}

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "kyverno")
        if not found:
            ASH_LOGGER.warning(
                "kyverno executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_kyverno_plugins\"]' --tool kyverno`."
            )
        return found is not None


__all__ = [
    "FailedTarget",
    "KYVERNO_SEVERITY_MAP",
    "KyvernoScanner",
    "KyvernoScannerConfig",
    "KyvernoScannerConfigOptions",
    "ManifestIndex",
    "convert_report_results",
    "is_exception_document",
    "is_policy_document",
    "is_resource_document",
    "load_manifest",
    "parse_policy_report_output",
    "parse_skipped_policies",
    "plan_runs",
    "read_manifest",
    "severity_for",
]
