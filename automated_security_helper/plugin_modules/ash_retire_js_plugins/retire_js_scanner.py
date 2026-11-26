# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""RetireJsScanner: known-vulnerable JavaScript libraries, found by retire.js.

retire.js (https://github.com/RetireJS/retire.js, Apache-2.0) recognizes JavaScript
libraries by file name, file content and file hash, and compares each version it finds
with a vulnerability repository. It finds a vulnerable jQuery copied into ``static/``
that no lockfile names, which is the gap ``npm-audit`` and ``grype`` leave. It does not
read ``package.json`` or a lockfile: at 6.1.1 a ``package.json`` listing a vulnerable
dependency produces no finding (measured on a real run, see
``tests/test_data/scanners/retire-js/captured/README.md``), so dependency manifests stay
with ``npm-audit``. It does read ``bower.json`` files, and checks the name and version
each one declares (``lib/resolve.js`` and ``lib/scanner.js`` of 6.1.1). The module is an
alpha plugin: a scan that does not list it in ``ash_plugin_modules`` is unchanged.

Scan flow
---------
The template flow of ``ScannerPluginBase``: ``_execute_scan`` builds the argv, the base
``scan()`` runs it and reads the results file. retire.js does not write SARIF, so
``_read_results_file`` converts its JSON to a SARIF document (``convert_retire_report``)
and the base validates and finishes that as it does a tool-written report.

Invocation (read from ``lib/cli.js`` and ``lib/parseIgnoreFile.js`` of retire 6.1.1)
------------------------------------------------------------------------------------
Every option is one ``--flag=value`` token.

``--outputformat=json --outputpath=<file>``
    The full JSON object, written to the file (``reporters/json.ts``:
    ``writer.out(JSON.stringify(res))`` through the file writer when an output path is
    set). ``jsonsimple`` is the bare ``data`` array without ``errors``; ``json`` is
    used so the errors the tool recorded are available.
``--path=<dir>``
    The folder to scan: always the target's absolute path. retire.js reports every
    file under it as an absolute path in the spelling it was given (``walkdir`` joins
    the root it is handed), and ``convert_retire_report`` makes each one relative to
    the target again. ``--path=.`` is not used: it would report the working directory
    as Node resolves it, symlinks followed, so the reported paths would depend on the
    working directory rather than on the target.
``--exitwith=13``
    The code retire.js uses when it finds a vulnerability, stated rather than relied on.
    It is the documented default. Without ``--severity`` any finding fails the process
    (the default threshold is ``none``), so 13 means "ran to completion, found
    something".
``--nocache``
    No cache in ``/tmp/.retire-cache``: nothing is written outside the results
    directory, and no earlier run's repository copy is read.
``--ignorefile=<file>``
    An ASH-written JSON ignore file. Without it retire.js reads ``.retireignore`` or
    ``.retireignore.json`` from its working directory, which is the scanned tree, and
    the tree could hide findings before ASH sees them (measured: a planted
    ``.retireignore.json`` naming jquery empties the report). Suppressions belong in
    ASH. The file holds one ``path`` entry for each ASH output directory inside the
    target, its absolute path with a trailing separator, so the copies ASH writes
    there are not scanned a second time. retire.js matches such an entry anywhere in
    a file's path, unanchored (``lib/cli.js`` builds an unanchored regular expression
    from it), and the trailing separator is what keeps ``.ash/ash_output`` from also
    hiding a directory named ``.ash/ash_output2`` (measured on 6.1.1). A directory
    whose path holds ``*``, which retire.js reads as a glob, is left out of the file
    and dropped after the scan instead, as is everything else that reaches the report
    from ASH's output.

Never passed: ``--ignore`` (its entries are resolved against the working directory,
never against ``--path``, and split on commas), ``--jsrepo`` (it points at another
repository of rules, and the tree must not choose that), ``--proxy``, ``--cacert``,
``--insecure``, ``--deep`` (documented as experimental) and ``--includeOsv``.

Exit status
-----------
0: ran, nothing vulnerable. 13: ran, found something. 1: any error (an invalid option,
an unreachable vulnerability repository, a file it could not scan; ``cli.ts`` sets 1 and
the error wins over a finding). ``success_exit_codes`` is ``{0, 13}``; any other code
fails the scan even when a report is on disk.

Severity
--------
retire.js rates each vulnerability ``none``, ``low``, ``medium``, ``high`` or
``critical`` (its ``severityLevels``, 0 to 4). A vulnerability with no rating counts as
critical in retire.js's own exit logic (``severityLevels[v.severity ?? 'critical']``),
and does here. SARIF level and ASH's ``issue_severity`` are set together by
``RETIRE_SEVERITY_MAP``: ``none`` is INFO, at the SARIF level ``note`` (the lowest level
a failing result takes). ``critical`` and ``high`` share the SARIF level ``error``, as
ASH's other scanners do for two ratings over one level. A rating retire.js does not
define is HIGH, the more severe of the two uncertain choices, and is logged.

Rule ids
--------
The vulnerability's first CVE, else its GitHub advisory id, else the first of the
``issue``, ``bug``, ``PR`` and ``retid`` numbers retire.js gives
(``RETIREJS-<component>-<kind>-<number>``), else a twelve-character digest of the
component, the summary and the affected range (``RETIREJS-<component>-<digest>``).
Findings are identified by rule, file and the constant line 1, so two vulnerabilities
of one library given one rule id would merge into one finding and one suppression
would hide both; the chain keeps distinct vulnerabilities apart.

Offline
-------
retire.js fetches its vulnerability repository
(``raw.githubusercontent.com/RetireJS/retire.js``) on every run, so the scanner needs a
network and is skipped under ``--offline`` (``OfflineStrategy.SKIP_OFFLINE``).

Sandbox
-------
``network=True``: the repository fetch. Nothing else is granted. The tool reads the
source tree and writes only the results directory.

Install
-------
``ash dependencies install`` runs ``npm install -g retire@6.1.1`` on every platform npm
runs on. npm checks the tarball it downloads against the integrity the registry
publishes for that version, and the registry never republishes a version, so the
version names the bytes; the 6.1.1 tarball was downloaded and checked against that
integrity on 2026-11-26. The ASH container image does not include retire.js.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PackageManager, PluginDependency
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The npm package that provides the ``retire`` command, and the version ASH installs.
RETIRE_NPM_PACKAGE = "retire"
RETIRE_VERSION = "6.1.1"

#: Exit code retire.js uses when it finds a vulnerability (its documented default),
#: passed as ``--exitwith`` so it is not a default ASH relies on.
VULNERABLE_EXIT_CODE = 13

#: retire.js severity -> (SARIF level, ASH ``issue_severity``). See "Severity" above.
RETIRE_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("error", "CRITICAL"),
    "high": ("error", "HIGH"),
    "medium": ("warning", "MEDIUM"),
    "low": ("note", "LOW"),
    "none": ("note", "INFO"),
}
#: A vulnerability with no severity is critical, as in retire.js's own exit logic.
MISSING_SEVERITY = "critical"
#: A severity string retire.js does not define.
UNKNOWN_SEVERITY: Tuple[str, str] = ("error", "HIGH")

#: The identifiers after the CVE and the GitHub advisory id that a rule id is made
#: from, in order. See "Rule ids" above.
NUMBERED_IDENTIFIERS: Tuple[str, ...] = ("issue", "bug", "PR", "retid")

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://retirejs.github.io/retire.js/"

#: Platforms ``npm install -g`` is declared for. The package is plain JavaScript.
INSTALL_PLATFORMS: Tuple[Tuple[str, str], ...] = tuple(
    (platform, arch)
    for platform in ("linux", "darwin", "windows")
    for arch in ("amd64", "arm64")
)

#: The justification ASH writes beside each path entry of its own ignore file.
_OUTPUT_DIR_JUSTIFICATION = (
    "ASH output directory: ASH's own copies, dropped after the scan in any case"
)


def _identifier_text(value: Any) -> Optional[str]:
    """A string or integer identifier as text; None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _rule_id(component: str, identifiers: Dict[str, Any], vuln: Dict[str, Any]) -> str:
    """The rule id of one vulnerability; see "Rule ids" in the module docstring."""
    cves = identifiers.get("CVE")
    if isinstance(cves, list) and cves and isinstance(cves[0], str) and cves[0].strip():
        return cves[0].strip()
    github_id = identifiers.get("githubID")
    if isinstance(github_id, str) and github_id.strip():
        return github_id.strip()
    for key in NUMBERED_IDENTIFIERS:
        value = _identifier_text(identifiers.get(key))
        if value is not None:
            return f"RETIREJS-{component}-{key}-{value}"
    summary = identifiers.get("summary") or vuln.get("details") or ""
    basis = "\n".join(
        str(part)
        for part in (
            component,
            summary,
            vuln.get("atOrAbove") or "",
            vuln.get("below") or "",
        )
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return f"RETIREJS-{component}-{digest}"


def _severity(raw: Any) -> Tuple[str, str]:
    """``(SARIF level, issue_severity)`` for retire.js's rating of one vulnerability."""
    if raw is None:
        raw = MISSING_SEVERITY
    if isinstance(raw, str) and raw.lower() in RETIRE_SEVERITY_MAP:
        return RETIRE_SEVERITY_MAP[raw.lower()]
    ASH_LOGGER.warning(
        "retire.js reported a severity ASH does not know (%r); rated HIGH.", raw
    )
    return UNKNOWN_SEVERITY


def _separators_read(file_name: str) -> str:
    """The reported path with the platform's own separator read as ``/``.

    A backslash is a separator only where the platform writes one. On POSIX it is a
    character of a file's name, and reading it as a separator would let a file named
    ``.ash\\ash_output\\x.js`` read as a path under ASH's output directory.
    """
    if os.sep != "/":
        return file_name.replace(os.sep, "/")
    return file_name


def _root_spellings(source_root: Path) -> List[str]:
    """The target as retire.js can spell it: as given, absolute, and resolved."""
    candidates = [source_root, source_root.absolute()]
    try:
        candidates.append(source_root.resolve())
    except (OSError, RuntimeError):
        pass
    spellings: List[str] = []
    for candidate in candidates:
        text = candidate.as_posix().rstrip("/")
        if text and text not in spellings:
            spellings.append(text)
    return spellings


def _relative_uri(file_name: str, source_root: Optional[Path]) -> str:
    """The reported file as a target-relative URI with forward slashes.

    retire.js reports the absolute path of each file under ``--path``. A root given
    in POSIX form (``/scan/src``) is matched as written as well as made absolute, so
    the same report reads the same on every platform.
    """
    text = _separators_read(file_name)
    if source_root is not None:
        for root in _root_spellings(Path(source_root)):
            if text.startswith(root + "/"):
                text = text[len(root) + 1 :]
                break
    while text.startswith("./"):
        text = text[2:]
    return text


def _under(uri: str, directories: List[PurePosixPath]) -> bool:
    path = PurePosixPath(uri)
    return any(path == d or d in path.parents for d in directories)


def convert_retire_report(
    document: Any,
    *,
    source_root: Optional[Path] = None,
    drop_under: Optional[List[PurePosixPath]] = None,
) -> Dict[str, Any]:
    """Convert a retire.js ``--outputformat=json`` document to a SARIF dictionary.

    One SARIF result per vulnerability of each vulnerable component in each file.

    Raises:
        ScannerError: the document is not the object retire.js writes (a ``data`` list
            of ``{file, results}`` entries), so a clean-looking result is never made
            out of output ASH could not read.
    """
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise ScannerError(
            "its results file is not a retire.js JSON report (an object with a "
            "'data' list), so its findings could not be graded"
        )
    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    for finding in document["data"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("file"), str):
            raise ScannerError(
                "its results file holds a 'data' entry that is not a retire.js "
                "finding (an object with a 'file' and 'results'), so it was not graded"
            )
        uri = _relative_uri(finding["file"], source_root)
        if drop_under and _under(uri, drop_under):
            continue
        for component in finding.get("results") or []:
            if not isinstance(component, dict):
                continue
            name = str(component.get("component") or "unknown")
            version = str(component.get("version") or "unknown")
            for vuln in component.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                identifiers = vuln.get("identifiers")
                identifiers = identifiers if isinstance(identifiers, dict) else {}
                rule_id = _rule_id(name, identifiers, vuln)
                level, issue_severity = _severity(vuln.get("severity"))
                summary = identifiers.get("summary") or vuln.get("details") or ""
                below = vuln.get("below")
                text = f"{name} {version} has a known vulnerability"
                if below:
                    text += f" (fixed in {below})"
                if summary:
                    text += f": {summary}"
                info = [i for i in vuln.get("info") or [] if isinstance(i, str)]
                cwes = [c for c in vuln.get("cwe") or [] if isinstance(c, str)]
                rules.setdefault(
                    rule_id,
                    {
                        "id": rule_id,
                        "name": name,
                        "shortDescription": {"text": str(summary or rule_id)},
                        **({"helpUri": info[0]} if info else {}),
                    },
                )
                results.append(
                    {
                        "ruleId": rule_id,
                        "kind": "fail",
                        "level": level,
                        "message": {"text": text},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "properties": {
                            "issue_severity": issue_severity,
                            # The CWE ids ride in the tags, where the flat view reads
                            # them (utils/taxonomy_ids.cwes_of_tags).
                            "tags": [
                                "sca",
                                "vulnerable-javascript",
                                "security",
                                *cwes,
                            ],
                            # Only what retire.js named: "unknown" is not an identity.
                            **identity_properties(
                                name if component.get("component") else None,
                                version if component.get("version") else None,
                                None,
                            ),
                            "component": name,
                            "version": version,
                            "detection": component.get("detection"),
                            "cwe": cwes,
                            "references": info,
                        },
                    }
                )
    driver: Dict[str, Any] = {
        "name": "retire.js",
        "informationUri": INFORMATION_URI,
        "rules": list(rules.values()),
    }
    version = document.get("version")
    if isinstance(version, str) and version:
        driver["semanticVersion"] = version
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


class RetireJsScannerConfigOptions(ScannerOptionsBase):
    """No scanner-specific options.

    Nothing the scanned tree can set reaches retire.js: the vulnerability repository,
    the ignore file, the proxy and the certificate flags are fixed (see the module
    docstring). ``severity_threshold``, ``scan_timeout`` and ``offline`` come from the
    base.
    """


class RetireJsScannerConfig(ScannerPluginConfigBase):
    name: Literal["retire-js"] = "retire-js"
    enabled: bool = True
    options: Annotated[
        RetireJsScannerConfigOptions,
        Field(description="Configure the retire-js scanner"),
    ] = RetireJsScannerConfigOptions()


@ash_scanner_plugin
class RetireJsScanner(ScannerPluginBase[RetireJsScannerConfig]):
    """Known-vulnerable JavaScript libraries, by file name, content and hash."""

    #: Not Python-only: retire.js is a Node program installed with npm.
    python_only: ClassVar[bool | None] = False

    # The vulnerability repository is fetched on every run.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    success_exit_codes: ClassVar[Set[int]] = {0, VULNERABLE_EXIT_CODE}
    # The repository fetch is the only network need; nothing else is granted.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True
    )

    # retire.js's stderr names files of the scanned tree it could not read, and the
    # scanner executor copies errors into the scan's results: the base class keeps the
    # stream out of both and out of the failure text. It stays in the log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "retire"

    #: The facets register row (base/scanner_facets.py). The native fields name
    #: retire.js's own JSON (the real capture in
    #: tests/test_data/scanners/retire-js/captured), converted to SARIF by
    #: ``convert_retire_report``.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="data[].results[].vulnerabilities[].identifiers.CVE[0], "
            "else .githubID, else .issue, .bug, .PR or .retid (a "
            "RETIREJS-<component>-<kind>-<number> id), else a digest of the "
            "component, summary and affected range",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="data[].results[].vulnerabilities[].severity (none is "
            "INFO; no rating counts as critical, as retire.js's own exit logic does)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="data[].file (the library file's absolute path under "
            "--path, made target-relative)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native line) retire.js reports a whole file; the "
            "adapter writes the constant startLine 1 to place the result",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="retire.js reports a file, not a position in it",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].identifiers.summary (else .details), "
            "with the component, version and .below assembled into the text by "
            "the adapter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a JavaScript library file and version, not a "
            "deployable resource; library identity is declared under the "
            "package facets",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a JavaScript library file, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field="data[].results[].component, written as the result "
            'property "package_name"',
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field="data[].results[].version, written as the result "
            'property "package_version"',
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the library is the file the result already locates; the "
            "adapter writes package_name and package_version only",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].identifiers.CVE[0], carried as the "
            "rule id, which the flat view reads the CVE from",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].cwe, written into the result tags",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="retire.js writes no finding fingerprint; identity is rule, "
            "file and library through the shared floor",
        ),
        fix_available=FacetDecl(
            state=FacetState.DROPPED,
            native_field="vulnerabilities[].below",
            reason="the fixed-in version is quoted in the message; the flat "
            "fix_available flag is not set",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="retire.js carries no remediation text; the fixed-in version "
            "(.below) is in the message",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="retire.js reports a library file and version, never a code excerpt",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities[].info[0], written as the rule's helpUri, "
            "which the flat references column reads when a result has no "
            "relatedLocations; the whole info list stays in the result property "
            '"references"',
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native tags) constant sca / vulnerable-javascript "
            "/ security tags plus vulnerabilities[].cwe",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties: detection (data[].results[]."
            "detection), cwe, references, issue_severity",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="retire-js",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.VULN_DB,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "retire.js fetches its vulnerability repository "
                    "(raw.githubusercontent.com/RetireJS/retire.js) on every run "
                    "and ASH passes --nocache, so with no network it cannot grade "
                    "anything and the scanner is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "retire_js_scanner.py module docstring (Offline, Sandbox) and "
                    "the offline_strategy and sandbox_requirements declarations"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.PACKAGE_SOURCES,),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "retire.js walks the whole target for JavaScript files (extension "
                    "js), recognizing a library by file name, content and hash, and "
                    "for bower.json files, checking the name and version each "
                    "declares; it reads no package.json or lockfile "
                    "(retire_js_scanner.py _build_arguments, --path)"
                ),
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("node", "npm"),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one retire run per scan target (source, then converted)",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for retire.js.
            # Its Node.js floor is a prerequisite, declared below.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="an npm package (retire@6.1.1) installed with npm install -g; "
                "ASH downloads no binary for it",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="retire.js's none/low/medium/high/critical rating is mapped "
                "(none is INFO); an unrated vulnerability counts as critical",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".retireignore and .retireignore.json in the scanned "
                        "tree",
                        cite="retire_js_scanner.py _execute_scan passes its own "
                        "--ignorefile, so the tree's own files are never read",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="no native fingerprint; identity is rule, file and the "
                "constant line 1, so it moves only when the library file does; "
                "the rule id chain keeps two vulnerabilities of one library apart",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no scanner options; --jsrepo is never passed, so "
                "the tree cannot choose another rule repository",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 13),
                semantics="0 ran and found nothing; 13 ran and found vulnerable "
                "libraries (--exitwith=13 stated); 1 is any error and wins over a "
                "finding",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_retire_js_plugins in ash_plugin_modules",),
                upstream_license=(
                    "Apache-2.0 (source: the LICENSE.md file inside the retire@6.1.1 "
                    "npm tarball, byte-identical to LICENSE.md at the release commit "
                    "9a09cd11ae83, and the package.json license field; read "
                    "2026-11-26)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NODE_RUNTIME,),
                note="Node.js 20.19+ or 22.12+ and npm to install and run retire "
                "(the 6.1.1 package's engines field)",
            ),
        )
    )

    _target: Optional[Path] = PrivateAttr(default=None)
    _dropped_dirs: List[PurePosixPath] = PrivateAttr(default_factory=list)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = RetireJsScannerConfig()
        self.command = "retire"
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _execute_scan; nothing from the base resolver is
        # added to it.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_dependencies(self) -> "RetireJsScanner":
        """Install the pinned version with npm, on every platform npm runs on."""
        self.dependencies = {
            platform: {
                arch: [
                    PluginDependency(
                        name=RETIRE_NPM_PACKAGE,
                        version=RETIRE_VERSION,
                        package_manager=PackageManager.NPM,
                    )
                ]
                for p, arch in INSTALL_PLATFORMS
                if p == platform
            }
            for platform in {p for p, _ in INSTALL_PLATFORMS}
        }
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("RetireJsScanner has no plugin context")
        return Path(self.context.source_dir)

    @staticmethod
    def _scan_path(target: Path) -> str:
        """The target's absolute path, the spelling retire.js reports files under."""
        return str(Path(target).absolute())

    def _ignored_dirs(self, target: Path) -> List[PurePosixPath]:
        """ASH's output directories inside ``target``, relative to it."""
        return [
            PurePosixPath(Path(d).as_posix())
            for d in self._ash_output_dirs_inside(target)
        ]

    def _ignore_entries(
        self, target: Path, ignored: List[PurePosixPath]
    ) -> List[Dict[str, str]]:
        """The ``path`` entries of ASH's ignore file: absolute, with a trailing separator.

        Spelled as retire.js spells the files it reports under ``--path``: the
        platform's own separator, which retire.js matches as a literal character. A
        path holding ``*`` is left out (retire.js reads it as a glob); what it would
        have kept from the tool is dropped from the report after the scan.
        """
        root = Path(self._scan_path(target))
        entries: List[Dict[str, str]] = []
        for directory in ignored:
            path = str(root.joinpath(*directory.parts)) + os.sep
            if "*" in path:
                continue
            entries.append({"path": path, "justification": _OUTPUT_DIR_JUSTIFICATION})
        return entries

    def _build_arguments(
        self,
        target: Path,
        results_file: Path,
        ignore_file: Path,
    ) -> List[str]:
        """The full retire argv for one target; every option is one ``--flag=value``."""
        return [
            self.command or "retire",
            "--outputformat=json",
            f"--outputpath={results_file.as_posix()}",
            f"--exitwith={VULNERABLE_EXIT_CODE}",
            "--nocache",
            f"--ignorefile={ignore_file.as_posix()}",
            f"--path={self._scan_path(target)}",
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one retire run.

        ``global_ignore_paths`` is not passed to retire.js: ASH applies it to every
        scanner's SARIF.
        """
        if self.results_dir is None:
            raise ScannerError("RetireJsScanner has no results directory")
        # One instance scans source and then converted; see BetterleaksScanner.
        self.exit_code = 0
        out_dir = Path(self.results_dir).absolute().joinpath(target_type)
        out_dir.mkdir(exist_ok=True, parents=True)
        results_file = out_dir / "retire-js.json"
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        self._target = Path(target)
        self._dropped_dirs = self._ignored_dirs(target)
        ignore_file = out_dir / "retireignore.json"
        with open_for_write(ignore_file, encoding="utf-8") as handle:
            handle.write(
                json.dumps(self._ignore_entries(target, self._dropped_dirs), indent=2)
                + "\n"
            )
        final_args = self._build_arguments(target, results_file, ignore_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse an unfinished run, then convert retire.js JSON to SARIF."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"retire exited {self.exit_code}; it exits 0 when it finds nothing "
                f"and {VULNERABLE_EXIT_CODE} when it finds vulnerable libraries, so "
                "this run failed"
            )
        try:
            raw = super()._read_results_file(results_file)
        except json.JSONDecodeError as exc:
            raise ScannerError(
                f"its results file is not valid JSON ({exc.msg} at position {exc.pos})"
            ) from exc
        if raw is None:
            return None
        errors = raw.get("errors") if isinstance(raw, dict) else None
        if errors:
            ASH_LOGGER.warning(
                "retire.js recorded %d warning(s) or error(s); see the scanner log.",
                len(errors),
            )
        source = self._target if self._target is not None else self._source_dir()
        return convert_retire_report(
            raw, source_root=source, drop_under=self._dropped_dirs
        )

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "retire")
        if not found:
            ASH_LOGGER.warning(
                "retire executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_retire_js_plugins\"]' --tool retire-js` (needs Node.js 20.19+ "
                "or 22.12+ and npm)."
            )
        return found is not None


__all__ = [
    "INSTALL_PLATFORMS",
    "NUMBERED_IDENTIFIERS",
    "RETIRE_NPM_PACKAGE",
    "RETIRE_SEVERITY_MAP",
    "RETIRE_VERSION",
    "RetireJsScanner",
    "RetireJsScannerConfig",
    "RetireJsScannerConfigOptions",
    "VULNERABLE_EXIT_CODE",
    "convert_retire_report",
]
