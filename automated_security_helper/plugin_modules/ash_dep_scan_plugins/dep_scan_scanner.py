# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dep-scan: known-vulnerability findings for the dependencies of a source tree.

OWASP dep-scan (https://github.com/owasp-dep-scan/dep-scan, MIT) builds a CycloneDX
bill of materials for a project with cdxgen, looks every component up in a local
vulnerability database (OSV, NVD, GitHub advisories) and writes a CycloneDX
Vulnerability Disclosure Report (VDR). It can also mark a vulnerability as reachable
from the project's own code.

What was read, and from where
-----------------------------
Everything below was read from the dep-scan ``v6.3.2`` tag (the release on PyPI as
``owasp-depscan``), not guessed:

* ``depscan/cli_options.py``: the flags (``-i/--src``, ``-o/--reports-dir``,
  ``--no-banner``, ``--no-suggest``, ``--no-vuln-table``, ``-q/--quiet``,
  ``--fail-on-error``, ``--reachability-analyzer``, ``--config``).
* ``depscan/cli.py``: the VDR is written to ``<reports-dir>/<bom base name>.vdr.json``
  (``sbom-universal.cdx.json`` becomes ``sbom-universal.vdr.json``), also when no
  vulnerability is found; the process exits through ``sys.exit(1)`` only for unusable
  inputs and, with ``--fail-on-error``, for BOM or analyzer failures. Finding
  vulnerabilities does not change the exit code.
* ``depscan/lib/tomlparse.py``: the parser reads ``$PWD/.config/depscan.toml`` and
  lets it set every option the command line does not name.
* ``test/data/jinja-report.vdr.json``: the shape of a real VDR, which the converter
  below reads.

The ``master`` branch is 7.0.0.dev0 and replaces these flags with ``depscan scan
<target>``; this plugin pins 6.3.2 and does not run it.

What ASH runs
-------------
``depscan --no-banner --no-suggest --no-vuln-table --quiet --fail-on-error
--reachability-analyzer=<x> --config=<empty> --reports-dir=<dir> --src=<target>``,
from the source directory, as a uv tool (``owasp-depscan==6.3.2``). It is the template
scan flow (``_execute_scan`` builds the argv, ``_read_results_file`` converts the
tool's own output), because there is one run per target and the tool picks the name
of its report: ASH reads every ``*.vdr.json`` in the reports directory it handed over.

Why each fixed flag is there
----------------------------
``--no-banner --no-suggest --no-vuln-table --quiet``: console output only, nothing the
conversion reads. ``--fail-on-error``: without it dep-scan "silently degrades" when
cdxgen fails, writes no VDR and exits 0, which would read as a clean scan. With it a
tree that has no dependency manifest also exits 1 ("No packages were found"), so such
a tree reports a scanner failure, not a pass. ``--config=<empty file>``: see below.
Every option is a single ``--flag=value`` token, so no path or value is read as a flag.

Configuration the tree may not choose
-------------------------------------
dep-scan reads ``.config/depscan.toml`` from its working directory, which is the
scanned tree, and applies every key the command line does not name. A tree could set
``severity`` to drop findings, ``custom-data`` to rewrite them, or
``report-template`` to read files. ASH passes ``--config`` with an empty file kept
outside the tree, so the tree's file is never read and nothing from it reaches the
scan. ASH offers no option that points dep-scan at a config file.

Severity
--------
dep-scan's VDR rates each vulnerability with CycloneDX ``ratings`` (CVSS severity).
The highest rating of a vulnerability is used: critical -> CRITICAL / error,
high -> HIGH / error, medium -> MEDIUM / warning, low -> LOW / note,
info or none -> INFO / none. A vulnerability with no rating, or one whose severity is
not one of those words (``unknown``), is MEDIUM / warning: it is a known advisory
that nobody has rated, which is neither safe to hide nor safe to call critical.
``issue_severity`` and the SARIF level always agree, and ``error`` covers both
CRITICAL and HIGH as it does in ASH's other SARIF.

Exit status and output
----------------------
Only exit code 0 is a completed run. Any other code fails the scan even when a report
is on disk. A zero exit with no ``*.vdr.json`` is a failure too, not a clean scan.
A VDR that is not JSON, not a CycloneDX object, or whose ``vulnerabilities`` is not a
list fails the scan. A report left by an earlier run is removed before each run.
dep-scan's stderr is not copied into the scan's errors: it can quote paths and
package names from the scanned tree. It stays in the scanner's log file.

Network, offline and sandbox
----------------------------
The first run downloads the vulnerability database (``appthreat-vulnerability-db``;
``VDB_HOME`` moves its cache) and cdxgen may resolve dependencies through the
network, so the scanner is ``SKIP_OFFLINE``. dep-scan 6.3.2 has no offline flag.
The sandbox requirement declares a network and the database cache directories, and
those directories were not measured here.

cdxgen
------
dep-scan needs ``cdxgen`` (npm ``@cyclonedx/cdxgen``) on ``PATH`` to read a source
tree. ASH does not install it, and the container image, which carries the pinned
dep-scan release, does not carry cdxgen: the dependency check fails, with the install
command, when it is missing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    cast,
)

from pydantic import Field

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base import scanner_operational_facets as opsf
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
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.sandbox.fs_guard import read_bytes_at_most
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The dep-scan release this converter was written against. Exact on purpose: the VDR
#: is a CycloneDX document, but the properties dep-scan adds to it are its own, and
#: 7.x changes the command line. ``options.tool_version`` overrides it.
DEP_SCAN_DEFAULT_VERSION_CONSTRAINT = "==6.3.2"

#: The PyPI package that provides the ``depscan`` command.
DEP_SCAN_PACKAGE = "owasp-depscan"

#: The upstream license of record for the register (opsf requires a source citation).
#: The wheel's dist-info file is byte-identical to the repository LICENSE at the tag.
LICENSE_CITATION = (
    "MIT (source: the owasp-depscan 6.3.2 distribution's licenses/LICENSE, sha256 "
    "a109c26e766d27f34b0dd38b73ead56350f537444d58b1cfa585dc73bef1cd2a, "
    "byte-identical to the repository LICENSE at tag v6.3.2)"
)

#: The SARIF driver ASH writes the converted findings under.
_DRIVER_NAME = "dep-scan"
_INFORMATION_URI = "https://github.com/owasp-dep-scan/dep-scan"

_COMMAND = "depscan"
_CDXGEN_COMMAND = "cdxgen"
_CDXGEN_INSTALL_HINT = "npm install -g @cyclonedx/cdxgen"

#: The directory, beside the results file, that dep-scan is told to write into.
REPORTS_DIR_NAME = "dep_scan_reports"

#: The suffix of the report dep-scan writes for each BOM it examined.
VDR_SUFFIX = ".vdr.json"

#: The most one VDR is read as. A project with thousands of components writes a
#: large document; past this it is not graded.
_VDR_READ_LIMIT = 256 * 1024 * 1024

#: ASH severity and SARIF level for each CycloneDX rating severity, and the
#: rank used to pick the highest of several ratings.
_SEVERITIES: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
    "info": ("INFO", "none"),
    "none": ("INFO", "none"),
}
_UNRATED: Tuple[str, str] = ("MEDIUM", "warning")
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

#: Ids osv.dev serves a page for; the rule's help link is set only for these.
_OSV_ID = re.compile(r"^(CVE|GHSA|PYSEC|GO|RUSTSEC|MAL|OSV)-[A-Za-z0-9._-]+$")

_SOURCE_FILE_PROPERTY = "SrcFile"


def rate_vulnerability(ratings: Any) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for a VDR vulnerability's ``ratings``.

    The highest rating wins. No usable rating is MEDIUM / warning: see "Severity" in
    the module docstring.
    """
    best: Optional[Tuple[str, str]] = None
    if isinstance(ratings, list):
        for rating in ratings:
            if not isinstance(rating, dict):
                continue
            word = str(rating.get("severity") or "").strip().lower()
            entry = _SEVERITIES.get(word)
            if entry is None:
                continue
            if best is None or _SEVERITY_RANK[entry[0]] > _SEVERITY_RANK[best[0]]:
                best = entry
    return best or _UNRATED


def _purl_parts(purl: str) -> Tuple[Optional[str], Optional[str]]:
    """``(name, version)`` read from a package URL, without a purl library.

    ``pkg:maven/io.netty/netty-codec-http2@4.1.94.Final?type=jar`` gives
    ``("io.netty/netty-codec-http2", "4.1.94.Final")``. Either part is None when the
    purl does not carry it.
    """
    text = purl.split("#", 1)[0].split("?", 1)[0]
    if not text.startswith("pkg:") or "/" not in text:
        return None, None
    body = text[len("pkg:") :].split("/", 1)[1]
    name, _, version = body.rpartition("@") if "@" in body else (body, "", "")
    return (name or None), (version or None)


def _relative_uri(value: Any, source_root: Optional[Path]) -> Optional[str]:
    """A source-relative POSIX path for a location dep-scan recorded, or None.

    An absolute path is made relative to ``source_root`` and dropped when it lies
    outside it; a path with a ``..`` part is dropped. Nothing outside the scanned
    tree is ever named in a result.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        if source_root is None:
            return None
        try:
            text = Path(text).relative_to(source_root.absolute()).as_posix()
        except ValueError:
            return None
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _component_uri(component: Optional[Dict[str, Any]], root: Optional[Path]) -> str:
    """Where in the tree a component was found, else ``"."`` (the scan root)."""
    if component:
        evidence = component.get("evidence")
        occurrences = (
            evidence.get("occurrences") if isinstance(evidence, dict) else None
        )
        for occurrence in occurrences or []:
            if isinstance(occurrence, dict):
                found = _relative_uri(occurrence.get("location"), root)
                if found:
                    return found
        for prop in component.get("properties") or []:
            if isinstance(prop, dict) and prop.get("name") == _SOURCE_FILE_PROPERTY:
                found = _relative_uri(prop.get("value"), root)
                if found:
                    return found
    return "."


def _summary(description: Any) -> str:
    """The first meaningful line of an advisory description, at most 300 characters."""
    for line in str(description or "").splitlines():
        text = line.strip().lstrip("#").strip()
        if text:
            return text if len(text) <= 300 else text[:297] + "..."
    return ""


def _properties_named(entity: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for prop in entity.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            out[prop["name"]] = str(prop.get("value", ""))
    return out


def convert_vdr(
    document: Any, *, source_root: Optional[Path] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Convert one dep-scan VDR (CycloneDX JSON) into SARIF result and rule dicts.

    One result per vulnerability per affected component, which is how dep-scan
    writes them (its ``bom-ref`` is ``<id>/<purl>``). The result is located on the
    component's source file when the BOM recorded one, else on the scan root.

    Raises:
        ScannerError: ``document`` is not a CycloneDX object, or its
            ``vulnerabilities`` is not a list of objects that each have an ``id``.
            A clean VDR has no ``vulnerabilities`` or an empty list.
    """
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ScannerError("a dep-scan report is not a CycloneDX document")
    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ScannerError("a dep-scan report's vulnerabilities is not a list")
    components: Dict[str, Dict[str, Any]] = {}
    for component in document.get("components") or []:
        if isinstance(component, dict):
            for key in (component.get("purl"), component.get("bom-ref")):
                if isinstance(key, str):
                    components.setdefault(key, component)

    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    seen: Set[Tuple[str, str]] = set()
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict) or not str(vuln.get("id") or "").strip():
            raise ScannerError("a dep-scan vulnerability is not an object with an id")
        vuln_id = str(vuln["id"]).strip()
        severity, level = rate_vulnerability(vuln.get("ratings"))
        summary = _summary(vuln.get("description"))
        insights = _properties_named(vuln)
        affects = [a for a in vuln.get("affects") or [] if isinstance(a, dict)]
        for affect in affects or [{}]:
            ref = str(affect.get("ref") or "")
            if (vuln_id, ref) in seen:
                continue
            seen.add((vuln_id, ref))
            component = components.get(ref)
            versions = [v for v in affect.get("versions") or [] if isinstance(v, dict)]
            installed = next(
                (v.get("version") for v in versions if v.get("status") == "affected"),
                None,
            )
            fixed = [
                str(v["version"])
                for v in versions
                if v.get("status") == "unaffected" and v.get("version")
            ]
            purl_name, purl_version = _purl_parts(ref)
            name = (component or {}).get("name") or purl_name
            group = (component or {}).get("group")
            if name and group and "/" not in str(name):
                name = f"{group}/{name}"
            version = installed or (component or {}).get("version") or purl_version
            subject = (
                f"{name} {version}" if name and version else (name or "a dependency")
            )
            text = f"{vuln_id} affects {subject}."
            if summary:
                text += f" {summary}"
            if fixed:
                text += f" Fixed in {', '.join(fixed)}."
            tags = ["vulnerability", "dependency"]
            if "reachable" in insights.get("depscan:insights", "").lower():
                tags.append("reachable")
            # The shared pipeline reads a CWE only from ``CWE-<n>`` tags.
            tags.extend(
                f"CWE-{c}"
                for c in vuln.get("cwes") or []
                if isinstance(c, int) and not isinstance(c, bool) and c > 0
            )
            properties: Dict[str, Any] = {
                "issue_severity": severity,
                "tags": tags,
                **identity_properties(
                    str(name) if name else None, str(version) if version else None, None
                ),
            }
            if ref:
                properties["purl"] = ref
            if fixed:
                properties["fixed_versions"] = fixed
                properties["fix_available"] = True
            if isinstance(vuln.get("cwes"), list):
                properties["cwes"] = [c for c in vuln["cwes"] if isinstance(c, int)]
            if "depscan:prioritized" in insights:
                properties["depscan_prioritized"] = (
                    insights["depscan:prioritized"].lower() == "true"
                )
            digest = hashlib.sha256(f"{vuln_id}\0{ref}".encode("utf-8")).hexdigest()
            results.append(
                {
                    "ruleId": vuln_id,
                    "level": level,
                    "message": {"text": text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": _component_uri(component, source_root)
                                }
                            }
                        }
                    ],
                    "partialFingerprints": {"depscan/v1": digest[:32]},
                    "properties": properties,
                }
            )
        if vuln_id not in rules:
            rule: Dict[str, Any] = {
                "id": vuln_id,
                "name": vuln_id,
                "shortDescription": {"text": summary or f"Advisory {vuln_id}"},
                "properties": {"tags": ["dep-scan", "vulnerability"]},
            }
            if _OSV_ID.match(vuln_id):
                rule["helpUri"] = f"https://osv.dev/vulnerability/{vuln_id}"
            rules[vuln_id] = rule
    return results, rules


def sarif_document(
    results: List[Dict[str, Any]], rules: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """The one-run SARIF document ASH reads for ``convert_vdr``'s results and rules.

    The scanner returns this from ``_read_results_file``, and the committed corpus
    (``tests/test_data/scanners/dep-scan/captured/positive.sarif``) is this function's
    output for the captured VDR, so the two cannot drift apart.
    """
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _DRIVER_NAME,
                        "informationUri": _INFORMATION_URI,
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


class DepScanScannerConfigOptions(ScannerOptionsBase):
    reachability_analyzer: Annotated[
        Literal["off", "FrameworkReachability"],
        Field(
            description=(
                "dep-scan's reachability analyzer. FrameworkReachability is dep-scan's "
                "own default and adds a `reachable` tag to findings its analysis could "
                "trace to the project's code. `off` skips that analysis. It never "
                "removes a finding."
            )
        ),
    ] = "FrameworkReachability"
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.dep-scan.options.tool_version"),
        Field(
            description=(
                "Version constraint for the owasp-depscan installation, in pip "
                "requirement syntax. Leave unset to use the scanner's own constraint, "
                "the release the result converter is tested against (6.3.2). A value "
                "that is not a version constraint is ignored with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class DepScanScannerConfig(ScannerPluginConfigBase):
    name: Literal["dep-scan"] = "dep-scan"
    enabled: bool = True
    options: Annotated[
        DepScanScannerConfigOptions,
        Field(description="Configure the dep-scan scanner"),
    ] = DepScanScannerConfigOptions()


@ash_scanner_plugin
class DepScanScanner(ScannerPluginBase[DepScanScannerConfig]):
    """Known-vulnerability findings for a tree's dependencies using OWASP dep-scan."""

    #: Not Python-only: it reads every ecosystem cdxgen reads.
    python_only: ClassVar[bool | None] = False

    # The vulnerability database is downloaded on the first run and dep-scan 6.3.2
    # has no offline flag, so an offline scan skips it.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    success_exit_codes: ClassVar[Set[int]] = {0}
    # A network for the database download and the database's cache directories.
    # The directories are appthreat-vulnerability-db's documented defaults and
    # VDB_HOME; they were not measured on a sandboxed run.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=(
            "$VDB_HOME",
            "~/.local/share/vdb",
            "~/Library/Application Support/vdb",
        ),
    )

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native output is the CycloneDX VDR (tests/test_data/scanners/dep-scan/
    #: captured), converted to SARIF by ``convert_vdr``.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].id (CVE-, GHSA-, BIT- and other advisory ids)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].ratings[].severity (the highest rating)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="components[].evidence.occurrences[].location, else the "
            "component property SrcFile; the scan root '.' when the BOM records neither",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="the converter reads file-level locations only; the captured VDR "
            "records no line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a dependency finding has no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].description (first line), assembled by "
            "the adapter with the id, package, version and fixed versions",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a package version, not a deployable resource; "
            "package identity is declared under the package facets",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a package version, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field="components[].group and name, else the name in "
            "vulnerabilities[].affects[].ref (a package URL)",
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].affects[].versions[] with status "
            "affected, else components[].version",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="dep-scan records the file that declared a component (mapped to "
            "file_path), not an install path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].id, as the rule id, when it is a CVE id",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].cwes, written as CWE-<n> result tags",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["depscan/v1"], a sha256 the adapter '
            "computes over the advisory id and the affected purl (not a native field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].affects[].versions[] with status "
            "unaffected, written as fix_available true",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field="vulnerabilities[].recommendation",
            reason="the fixed versions reach the message; the recommendation text "
            "itself is not copied",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a dependency finding has no code snippet",
        ),
        # Sparse by nature: only an id osv.dev serves (CVE-, GHSA-, PYSEC- and the
        # like) gets the link, so a BIT- or other vendor id has no reference.
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].id, written as the rule's helpUri "
            "https://osv.dev/vulnerability/<id> when osv.dev serves the id; the "
            "shared flat row reads a rule's helpUri as its reference",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result tags vulnerability and dependency (adapter), "
            "reachable from the depscan:insights property, and CWE-<n>",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties purl, fixed_versions, cwes and "
            "depscan_prioritized (from the depscan:prioritized property)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="dep-scan",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.VULN_DB, opsf.Fetched.PACKAGE_METADATA),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason="dep-scan 6.3.2 has no offline flag and downloads its "
                "vulnerability database on the first run, so an offline scan is skipped",
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source="dep_scan_scanner.py offline_strategy and sandbox_requirements; "
                "module docstring, Network, offline and sandbox",
                unconfirmed="the database cache directories and cdxgen's own "
                "network use were not measured on a sandboxed run",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.CYCLONEDX,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="the source directory, as --src=<path>; cdxgen reads every "
                "ecosystem's manifests and lockfiles it recognizes",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=("cdxgen", "node"),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one run per target (source, then converted)",
                python_only=False,
                use_uv_tool=True,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for dep-scan.
            # owasp-depscan 6.3.2 declares requires-python >=3.10, and its 48-package
            # closure resolved wheel-only for CPython 3.12 on x86_64 and aarch64.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv, pinned to its license entry's "
                "release in the container image; cdxgen (npm) is not provisioned by "
                "ASH, in the image or elsewhere, and must be on PATH",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the highest CycloneDX rating severity; an unrated advisory is "
                "MEDIUM",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="the tree's .config/depscan.toml is never read: ASH passes "
                "--config with an empty file kept outside the tree",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under depscan/v1 over the advisory id and purl",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (reachability_analyzer, tool_version, "
                "install_timeout); no rules or config path",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 when dep-scan finishes, findings or not; 1 for unusable "
                "input and, with --fail-on-error, for BOM or analyzer failure",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=(
                    "ash_dep_scan_plugins in ash_plugin_modules",
                    "options.reachability_analyzer",
                ),
                upstream_license=LICENSE_CITATION,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST, opsf.Prerequisite.NODE_RUNTIME),
                note="a dependency manifest in the tree (a tree with none exits 1 under "
                "--fail-on-error); cdxgen needs Node",
            ),
        )
    )

    @property
    def _opts(self) -> DepScanScannerConfigOptions:
        """The options, typed. ``config`` is set in ``model_post_init``."""
        return cast(DepScanScannerConfig, self.config).options

    @property
    def _ctx(self) -> PluginContext:
        """The plugin context, typed."""
        return cast(PluginContext, self.context)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = DepScanScannerConfig()
        elif not isinstance(self.config, DepScanScannerConfig):
            self.config = DepScanScannerConfig.model_validate(
                self.config.model_dump(by_alias=True)
            )
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SCA
        self.use_uv_tool = True
        self.uv_tool_package_name = DEP_SCAN_PACKAGE
        self._setup_uv_tool_install_commands()
        # Recorded, and run once by the dependency check: construction starts nothing.
        self.tool_version = None
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        self.description = "dep-scan reports known vulnerabilities in the dependencies of a source tree."
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token dep-scan would misread.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return DEP_SCAN_DEFAULT_VERSION_CONSTRAINT

    def validate_plugin_dependencies(self) -> bool:
        """cdxgen on PATH, then the uv tool (installed if absent) or a copy on PATH."""
        if self.dependency_unavailable_reason:
            return False
        if find_executable(_CDXGEN_COMMAND) is None:
            ASH_LOGGER.warning(
                "cdxgen executable not found in PATH. dep-scan needs it to read a "
                f"source tree; install it with `{_CDXGEN_INSTALL_HINT}`."
            )
            return False
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False
        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)
            if self._install_uv_tool(timeout=self._opts.install_timeout):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for owasp-depscan",
                level=logging.WARNING,
            )
        found = get_uv_tool_command(_COMMAND) is not None
        if not found:
            ASH_LOGGER.warning(
                "depscan executable not found. Install it with `ash dependencies "
                "install --config-overrides 'ash_plugin_modules+=[\"automated_security_"
                "helper.plugin_modules.ash_dep_scan_plugins\"]' --tool dep-scan`."
            )
        return found

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("DepScanScanner has no plugin context")
        return Path(self.context.source_dir)

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the working directory), else the absolute path."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, reports_dir: Path) -> List[str]:
        """The full dep-scan argv for one target, one ``--flag=value`` per option."""
        # dep-scan reads ./.config/depscan.toml from the scanned tree unless told
        # which file to read; see "Configuration the tree may not choose".
        no_tree_config = empty_tool_config(
            "depscan-empty.toml",
            "# ASH: dep-scan reads no settings from the scanned tree.\n",
            context=self.context,
        )
        return [
            self.command or _COMMAND,
            "--no-banner",
            "--no-suggest",
            "--no-vuln-table",
            "--quiet",
            "--fail-on-error",
            f"--reachability-analyzer={self._opts.reachability_analyzer}",
            f"--config={no_tree_config.resolve().as_posix()}",
            f"--reports-dir={reports_dir.as_posix()}",
            f"--src={self._scan_path(target)}",
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and the results path for one dep-scan run.

        ``global_ignore_paths`` is not given to dep-scan: it is applied to every
        scanner's SARIF by ``apply_suppressions_to_sarif``. The returned results file
        is the name the converted SARIF is "read" under; dep-scan never writes it, and
        ``_read_results_file`` reads the VDRs beside it.
        """
        if self.results_dir is None:
            raise ScannerError("DepScanScanner has no results directory")
        # One instance scans source and then converted; keep the worst code per target.
        self.exit_code = 0
        target_dir = Path(self.results_dir).absolute() / target_type
        reports_dir = target_dir / REPORTS_DIR_NAME
        reports_dir.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        for stale in reports_dir.glob(f"*{VDR_SUFFIX}"):
            stale.unlink(missing_ok=True)
        final_args = self._build_arguments(target, reports_dir)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, target_dir / "dep-scan.sarif", None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Convert the VDRs dep-scan wrote into one SARIF document.

        Refuses a run that did not exit 0 before reading anything, and a zero exit
        that left no VDR: neither is a clean scan.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"depscan exited {self.exit_code}; it exits 0 when it finishes "
                "(findings do not change its exit code), so this run failed"
            )
        reports_dir = Path(results_file).parent / REPORTS_DIR_NAME
        documents = sorted(
            path
            for path in reports_dir.glob(f"*{VDR_SUFFIX}")
            if path.is_file() and not path.is_symlink()
        )
        if not documents:
            raise ScannerError(
                f"depscan exited 0 but wrote no *{VDR_SUFFIX} report, so there is "
                "nothing to grade"
            )
        results: List[Dict[str, Any]] = []
        rules: Dict[str, Dict[str, Any]] = {}
        for path in documents:
            data = read_bytes_at_most(path, _VDR_READ_LIMIT + 1)
            if len(data) > _VDR_READ_LIMIT:
                raise ScannerError(
                    f"{path.name} is larger than {_VDR_READ_LIMIT} bytes, the most "
                    "this scanner reads, so it is not graded"
                )
            try:
                document = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ScannerError(f"{path.name} is not JSON: {exc}")
            found, found_rules = convert_vdr(document, source_root=self._source_dir())
            results.extend(found)
            for rule_id, rule in found_rules.items():
                rules.setdefault(rule_id, rule)
        return sarif_document(results, rules)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep dep-scan's stderr out of ``self.errors``.

        The stderr can name paths and packages of the scanned tree, and the executor
        copies ``errors`` into the scan's results. The stream stays in the log file.
        """
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where dep-scan's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (depscan was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        if self.scan_could_not_stop is not None:
            return (
                f"{detail} (no exit code: ASH could not stop depscan). "
                f"depscan's log is not quoted here; see {log_path.as_posix()}"
            )
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        return (
            f"{detail} (exit code {self.exit_code}: {verdict}). depscan's log is "
            f"not quoted here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _committed_file_test(self) -> Callable[[Path], bool]:
        """A test, of a path, for a file the repository committed under ASH's output."""
        committed: Optional[Set[Path]] = None

        def is_committed(path: Path) -> bool:
            nonlocal committed
            if committed is None:
                committed = committed_output_files(self.context)
            try:
                return path.resolve() in committed
            except (OSError, RuntimeError, ValueError):
                return False

        return is_committed

    def _output_dirs_inside_target(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, relative to it."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return found

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results located under ASH's output directory inside ``target``.

        cdxgen reads manifests wherever it finds them, ASH's converted copies under
        the output directory included. A result in a file the repository committed
        there is kept.
        """
        if self.context is None:
            return
        outputs_inside = self._output_dirs_inside_target(target)
        if not outputs_inside:
            return
        target_abs = Path(target).absolute()
        output_roots = [Path(os.path.normpath(target_abs / o)) for o in outputs_inside]
        committed = self._committed_file_test()

        def under_output_dir(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in output_roots) and (
                    not committed(path)
                ):
                    return True
            return False

        for run in sarif_report.runs or []:
            if run.results:
                run.results = [r for r in run.results if not under_output_dir(r)]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop results in ASH's own output directory."""
        self._drop_results_under_output_dir(sarif_report, target)
        return sarif_report


__all__ = [
    "DEP_SCAN_DEFAULT_VERSION_CONSTRAINT",
    "DEP_SCAN_PACKAGE",
    "DepScanScanner",
    "DepScanScannerConfig",
    "DepScanScannerConfigOptions",
    "LICENSE_CITATION",
    "REPORTS_DIR_NAME",
    "VDR_SUFFIX",
    "convert_vdr",
    "rate_vulnerability",
    "sarif_document",
]
