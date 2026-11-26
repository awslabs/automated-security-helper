# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Kubernetes manifest policy checks with the Kyverno CLI (``kyverno apply``).

What it runs
------------
``kyverno apply --policy-report --remove-color --output-format=yaml
--resource=<manifest> ... -- <policy file> ...`` in the source directory. Kyverno
evaluates the operator's policies against the Kubernetes manifests in the scanned
tree, offline: no ``--cluster`` flag is passed, so it makes no API call, and
``--registry`` (image registry access) is not passed either.

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
* v1.20.0 refuses to load the legacy ``kyverno.io/v1`` ``ClusterPolicy`` and ``Policy``
  kinds. The pin is v1.19.2 (``kyverno_install.py``), the last release that loads both
  those and the ``policies.kyverno.io`` kinds. Moving the pin to 1.20 or later takes a
  policy migration, which is the operator's.
* ``kyverno --version`` is an unknown flag (exit 1); ``kyverno version`` prints the
  version, its build time and the git commit it was built from.

Severity
--------
Kyverno's severity names map one to one: critical is CRITICAL (SARIF ``error``), high
is HIGH (``error``), medium is MEDIUM (``warning``), low is LOW (``note``), info is
INFO (``none``). ``error`` is HIGH, not CRITICAL, as for hadolint: these are policy
violations, not demonstrated exploits. A policy that declares no severity gets MEDIUM
for a ``fail`` and LOW for a ``warn``. A severity name outside the five is HIGH, so an
unrecognized value is never under-reported. ``issue_severity`` and the SARIF level are
set from the same row.

A ``result: error`` entry is not a finding: Kyverno could not evaluate that rule on
that resource. It counts as a failed target and is listed in the scan's errors (policy,
rule and resource only; the message is not copied, since it can quote the resource).
``pass`` and ``skip`` entries are not findings.

What is scanned
---------------
The YAML and JSON files of the scan set that hold a Kubernetes object. Kyverno's own
policy kinds (``kyverno.io``, ``policies.kyverno.io``, ``cli.kyverno.io``), report
kinds and admission policies are not treated as resources. Files that do not parse,
and files over ``MAX_MANIFEST_BYTES``, are skipped. Helm templates and other
templated YAML therefore do not reach Kyverno.

Links. A manifest must resolve inside the scanned target, and a file under a policy
directory must resolve inside that directory: a file reached through a link that
leaves it is skipped with a warning and never read, so a link in the scanned tree
cannot hand ASH or Kyverno a file from elsewhere. A policy path the operator names is
checked by ``operator_paths``, which refuses one that leaves the tree through a link.

Offline and sandbox
-------------------
Nothing in a ``kyverno apply`` run without ``--cluster`` reaches the network, so
``offline_strategy`` is BUNDLED. The sandbox requirements are the strict default.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path, PurePosixPath
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

import yaml
from pydantic import AnyUrl, Field, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_install import (
    kyverno_install_commands,
)
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
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    is_exit_code,
)

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

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: Longest message copied from a result into SARIF.
_MAX_MESSAGE_CHARS = 2000

_SEVERITY_TAGS = ["kyverno", "kubernetes", "policy"]


def _group_of(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def is_policy_document(doc: Any) -> bool:
    """Whether a parsed YAML document is a policy Kyverno would load."""
    if not isinstance(doc, dict):
        return False
    api_version, kind = doc.get("apiVersion"), doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return False
    if _group_of(api_version) in ("kyverno.io", "policies.kyverno.io"):
        return True
    return kind in ADMISSION_POLICY_KINDS


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
    sorted order, wins.
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


def load_manifest(
    text: str,
) -> Optional[List[Tuple[Dict[str, Any], int]]]:
    """The Kubernetes objects of one file, with their start lines; None when none.

    None for a file that does not parse, that holds no object with ``apiVersion`` and
    ``kind``, or that holds anything else: Kyverno stops the whole run at one document
    that is not an object, so a file is passed only when every document in it is one
    (empty documents, which YAML allows between separators, are ignored). A
    ``kind: List`` is expanded into its items, all located at the list's start line.
    """
    if "apiVersion" not in text or "kind" not in text:
        return None
    try:
        documents = _documents(text)
    except yaml.YAMLError:
        return None
    objects: List[Tuple[Dict[str, Any], int]] = []
    for doc, line in documents:
        if doc is None:
            continue
        if not is_resource_document(doc):
            return None
        items = doc.get("items")
        if doc.get("kind") == "List" and isinstance(items, list):
            for item in items:
                if is_resource_document(item):
                    objects.append((item, line))
            continue
        objects.append((doc, line))
    return objects or None


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
        documents = [d for d, _ in _documents(text[start:]) if d is not None]
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
) -> Tuple[List[Result], List[ReportingDescriptor], List[str]]:
    """Kyverno report results as SARIF results, rule descriptors and failed targets.

    ``fail`` and ``warn`` entries become one SARIF result per resource they name.
    ``error`` entries become one line each in the third list: ``"<uri>: ..."``, one
    per resource, naming the policy and rule but not Kyverno's message.
    """
    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}
    failed: List[str] = []
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
                    f"{uri}: kyverno could not evaluate policy {policy}, rule {rule}"
                    f"{_describe_resource(resource)}, so it was not checked"
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
    # Kyverno's stderr can quote a scanned file: a "failed to load resources" error
    # names the manifest and its text, and a Secret manifest is a scanned file. So
    # the failure text names the scanner's stderr log and never quotes it, and the
    # stream stays in that log (scanner_plugin.py, quote_tool_stderr).
    quote_tool_stderr: ClassVar[bool] = False
    # The strict default: no network, baseline environment only. The scanner reads
    # the policy files and manifests inside the source directory, and the operator's
    # policy paths outside it are not granted to the sandbox yet; grants derived from
    # options wait for the sandbox's grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name kyverno's own policy report (the
    #: captured report in tests/test_data/scanners/kyverno/captured/).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='report result "policy" and "rule", joined as '
            "<policy>/<rule> into the SARIF ruleId",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='report result "severity" (critical, high, medium, low, '
            "info); a result that declares none gets medium for fail and low for warn",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='(no native path) report result "resources" (kind, '
            "namespace, name), located by ASH in the scanned manifest that "
            "declares the object; the source directory when none does",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native line) the start line of the YAML document of "
            'the report result "resources" object, read from the manifest',
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="kyverno reports no position and the adapter reads the start "
            "line of the document only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='report result "message"',
        ),
        resource_id=FacetDecl(
            state=FacetState.DROPPED,
            native_field='report result "resources" (kind, namespace, name: Pod '
            "default/bad-pod in the captured report)",
            reason="the adapter keeps the object only in the result property "
            "kyverno_resource and writes no ash_resource_id; a resource-scoped "
            "suppression would bind to it, so attaching it is its own later unit",
        ),
        resource_type=FacetDecl(
            state=FacetState.DROPPED,
            native_field='report result "resources" "kind"',
            reason="the object kind is kept only in the result property "
            "kyverno_resource; no ash_resource_type is written (see resource_id)",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="policy results carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="policy results carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="policy results carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="policy violations carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="kyverno results carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='(no native fingerprint) partialFingerprints "kyverno/v1" '
            "computed by the adapter from the rule id, uri and the object's kind, "
            "namespace and name",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="policy results carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="a policy report result carries a message only; remediation "
            "text lives in the operator's policy, which ASH does not read",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a policy report result carries no source text, and the "
            "adapter attaches none",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="a policy report result carries no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='report result "category" (when present) after the '
            "constant tags kyverno, kubernetes, policy, set on the result "
            "properties by the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "kyverno_result", "kyverno_policy", '
            '"kyverno_rule", "kyverno_resource" and (when false) "kyverno_scored" '
            "written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="kyverno",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "kyverno_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: `kyverno apply` without --cluster makes no API "
                    "call and ASH never passes --registry"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="the policy report as YAML on stdout, converted to SARIF by "
                "convert_report_results; kyverno has no SARIF or report-file output",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.IAC_KUBERNETES,),
                tool_type=ScannerToolType.IAC,
                selection="every YAML or JSON file of the scan set whose documents "
                "are all Kubernetes objects (load_manifest), one --resource=<file> "
                "each; policies are the operator's policy_paths",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.MULTI_PASS,
                invocation_note="one `kyverno apply` per chunk of --resource "
                "arguments, so the command line stays under the length cap",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Kyverno.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(kyverno_install.py: linux, darwin and windows, amd64 and arm64), "
                "not by the shared tool_downloads table, so the register lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the policy's own critical/high/medium/low/info maps one to "
                "one; an unrecognized name is HIGH and a policy with none gets "
                "MEDIUM (fail) or LOW (warn)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="kyverno apply reads no ignore file and no inline "
                "comment of the scanned tree; what it skips is the operator's "
                "policy exclusions, which are part of the operator's policies",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="partialFingerprints kyverno/v1 hashes the rule id, uri and "
                "the object's kind, namespace and name, so an edit above the "
                "object does not move it",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.OPERATOR_PATHS,
                env_prefixes=(),
                options_surface="options.policy_paths: operator policy files or "
                "directories; an entry set by the scanned tree is ignored with a "
                "warning, and with none the scanner is skipped",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 nothing failed; 1 a failed result, an evaluation "
                "error or a failed load, which only a printed report tells apart",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_kyverno_plugins in ash_plugin_modules",
                    "options.policy_paths",
                ),
                upstream_license="Apache-2.0 (source: the LICENSE file inside the "
                "v1.19.2 release archives, byte-identical to the repository's at the "
                "release tag's commit, read 2026-11-26; the repository's NOTICE "
                "ships beside it; no license or service gate, the binary is "
                "downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="Kubernetes manifests in the scan set and at least one "
                "policy document under options.policy_paths",
            ),
        )
    )

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
        """Install from the pinned release asset in ``kyverno_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no Kyverno entry in
        its download tables. This table never raises.
        """
        self.custom_install_commands.update(kyverno_install_commands())
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

    @property
    def _options(self) -> KyvernoScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, KyvernoScannerConfigOptions):
            return options
        return KyvernoScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _policy_files(self) -> List[Path]:
        """The policy files to pass to kyverno, sorted; empty when none is configured.

        Every operator entry is resolved (``operator_paths``); one the scanned tree
        set is ignored with a warning, and so is one that leaves the tree through a
        link. A file is kept when it holds a policy document. A directory contributes
        the policy files under it that resolve inside it (``_policy_dir_files``).

        Raises:
            ScannerError: when an entry the operator set does not exist.
        """
        configured = list(self._options.policy_paths or [])
        if not configured:
            return []
        source_dir = Path(self._ctx.source_dir)
        chosen = operator_paths(
            self._ctx.config,
            "scanners.kyverno.options.policy_paths",
            configured,
            source_dir,
            outside_tree=False,
        )
        files: Set[Path] = set()
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
            candidates = self._policy_dir_files(path) if path.is_dir() else [path]
            for file in candidates:
                if self._holds_policy(file):
                    files.add(file)
        return sorted(files)

    def _policy_dir_files(self, directory: Path) -> List[Path]:
        """The ``.yaml``, ``.yml`` and ``.json`` files under a policy *directory*, sorted.

        A file must resolve inside the directory. One reached through a link that
        leaves it (a link to a file elsewhere, or a file under a linked directory) is
        skipped with a warning and never read: a policy directory is often in the
        scanned tree, so its links are the tree's to choose, and ``_holds_policy``
        reads every file it is given. The operator names the directory such a link
        leads to in ``policy_paths`` to have its policies applied.
        """
        base = directory.resolve()
        kept: List[Path] = []
        for path in sorted(directory.rglob("*")):
            if path.suffix.lower() not in MANIFEST_SUFFIXES:
                continue
            try:
                resolved: Optional[Path] = path.resolve()
            except (OSError, RuntimeError):
                resolved = None
            if resolved is None or not resolved.is_relative_to(base):
                where = (
                    "a path that cannot be resolved"
                    if resolved is None
                    else resolved.as_posix()
                )
                self._plugin_log(
                    f"Skipping policy file {path.as_posix()}: it resolves to {where}, "
                    f"outside the policy directory {directory.as_posix()}.",
                    level=logging.WARNING,
                )
                continue
            kept.append(path)
        return kept

    @staticmethod
    def _holds_policy(path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
                return False
            text = path.read_text(encoding="utf-8", errors="replace")
            return any(is_policy_document(doc) for doc, _ in _documents(text))
        except (OSError, yaml.YAMLError):
            return False

    def _manifests(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
        policy_files: List[Path],
    ) -> Tuple[List[Path], ManifestIndex]:
        """The manifest files under *target* to pass to kyverno, sorted, and their index.

        The source branch reads ASH's scan set, so .gitignore and the rest have
        already removed what they remove, and ASH's own output directory is dropped.
        The converted branch walks ``work_dir``. A file must resolve inside *target*:
        a link leaving the tree is skipped, because kyverno's errors quote the
        file's text. A policy file is never a resource.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()
        policies = {p.resolve() for p in policy_files}
        index = ManifestIndex()
        selected: List[Path] = []
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
            if resolved in policies:
                continue
            if global_ignore_paths and self._ignored(
                path, source_dir, global_ignore_paths
            ):
                continue
            try:
                objects = load_manifest(
                    path.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                continue
            if objects is None:
                continue
            uri = self._argv_path(path)
            for doc, line in objects:
                index.add(doc, uri, line)
            selected.append(path)
        return selected, index

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
        # grades SKIPPED (targets_attempted = 0), not PASSED.
        policy_files = self._policy_files()
        if not policy_files:
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
            manifests, index = self._manifests(
                target, target_type, global_ignore_paths, policy_files
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
            base_args = self._base_args()
            tail = ["--", *[self._argv_path(p) for p in policy_files]]
            chunks = _argv_chunks(
                base_args, [self._argv_path(p) for p in manifests], tail
            )

            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("kyverno.sarif")
            results_file.unlink(missing_ok=True)

            # One budget for every invocation of this scan, so scan_timeout bounds
            # the scanner and not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            entries: List[Dict[str, Any]] = []
            final_args: List[str] = []
            for chunk in chunks:
                final_args = [*base_args, *[f"--resource={p}" for p in chunk], *tail]
                response = self._run_until(final_args, results_dir, deadline)
                # The response's own code, not self.exit_code: the base folds every
                # run into the worst code seen, so after one chunk exited 1 a later
                # chunk that exited 0 would still read 1 and be judged on the first
                # chunk's outcome.
                exit_code = response.get("returncode")
                if not is_exit_code(exit_code):
                    exit_code = self.exit_code
                if response.get("timed_out"):
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"kyverno timed out after {timeout}s and was killed, so it "
                        "produced no report. Raise scanners.kyverno.options.scan_timeout "
                        "if these manifests legitimately need longer."
                    )
                if exit_code not in self.success_exit_codes:
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"kyverno exited {exit_code}; it exits 0 or 1 when it ran, "
                        "so this run did not complete"
                    )
                try:
                    chunk_entries = parse_policy_report_output(
                        response.get("stdout") or ""
                    )
                except ValueError as exc:
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(f"kyverno wrote a report ASH cannot read: {exc}")
                if exit_code == 1 and not chunk_entries:
                    # Exit 1 is a violation or a failed load; only a report says which.
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        "kyverno exited 1 without printing a report, which means it "
                        "failed before evaluating anything (its message is in the "
                        "scanner's stderr log and is not quoted here)"
                    )
                entries.extend(chunk_entries)
            self._post_scan(target=target, target_type=target_type)

            if not entries:
                self._plugin_log(
                    "kyverno printed no results: no policy matched a manifest, or "
                    "every policy was skipped as invalid. Nothing was reported.",
                    target_type=target_type,
                    level=logging.WARNING,
                )

            results, rules, failed = convert_report_results(entries, index)
            for line in failed:
                self.targets_failed += 1
                self.errors.append(line)
                self._plugin_log(
                    line,
                    target_type=target_type,
                    level=logging.ERROR,
                    append_to_stream="stderr",
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
    "KYVERNO_SEVERITY_MAP",
    "KyvernoScanner",
    "KyvernoScannerConfig",
    "KyvernoScannerConfigOptions",
    "ManifestIndex",
    "convert_report_results",
    "is_policy_document",
    "is_resource_document",
    "load_manifest",
    "parse_policy_report_output",
    "severity_for",
]
