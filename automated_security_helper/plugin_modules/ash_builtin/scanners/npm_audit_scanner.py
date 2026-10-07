"""Module containing the NPM Audit security scanner implementation."""

import copy
import json
import logging
import os
import re
from pathlib import Path
from typing import Annotated, ClassVar, Dict, List, Literal, Any

from pydantic import Field, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    MultiformatMessageString,
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    ArtifactLocation,
    Location,
    PhysicalLocation,
    Region,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Invocation,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.package_identity import (
    NPM_LOCKFILE_NAMES,
    PACKAGE_PATH_KEY,
    PACKAGE_VERSION_KEY,
    ROOT_ADVISORIES_KEY,
    NpmLockIndex,
    identity_properties,
    install_path,
)
from automated_security_helper.utils.subprocess_utils import find_executable

# The top-level key each package manager's audit report always carries, clean or
# not. An exit status other than 0 without it means the audit did not run to a
# report. yarn is absent because its output is not one JSON document: see
# _parse_yarn_audit, which decides for yarn whether a report came back.
_REPORT_KEY = {"npm": "vulnerabilities", "pnpm": "advisories"}

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Advisory severity to SARIF level, for npm, yarn and pnpm alike.
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "moderate": "warning",
    "low": "note",
    "info": "note",
}

# Where a yarn audit's advisories sit in the per-lockfile document, after
# _parse_yarn_audit has put all three yarn output formats into one shape.
_YARN_ADVISORIES_KEY = "yarn_advisories"

_SEMVER_MAJOR = re.compile(r"^\s*v?(\d+)\.\d+")

# In a Node crash dump: the "file.js:LINE" header above the offending source
# line, and a line that names its error ("Error: ...", "Ls [RequestError]: ...").
_SOURCE_LOCATION = re.compile(r"^\S+\.[cm]?js:\d+$")
_NAMED_ERROR = re.compile(r"(?:^|\s|\[)\w*Error\]?:\s")


class NpmAuditScannerConfigOptions(ScannerOptionsBase):
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached data. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]


class NpmAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["npm-audit"] = "npm-audit"
    enabled: bool = True
    options: Annotated[
        NpmAuditScannerConfigOptions, Field(description="Configure NpmAudit scanner")
    ] = NpmAuditScannerConfigOptions()


@ash_scanner_plugin
class NpmAuditScanner(ScannerPluginBase[NpmAuditScannerConfig]):
    """NpmAuditScanner implements IaC scanning using `npm/yarn/pnpm audit` based on the lock files discovered in the source directory."""

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.npm",),
        env_prefixes=("npm_config_", "NPM_CONFIG_"),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    def model_post_init(self, context):
        if self.config is None:
            self.config = NpmAuditScannerConfig()
        self.command = "npm"
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="json",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "NpmAuditScanner":
        """Set up custom installation commands for NPM."""
        # Get version and linux_type from config
        # Linux
        if "linux" not in self.custom_install_commands:
            self.custom_install_commands["linux"] = {}
        self.custom_install_commands["linux"]["amd64"] = []
        self.custom_install_commands["linux"]["arm64"] = []
        # macOS
        if "darwin" not in self.custom_install_commands:
            self.custom_install_commands["darwin"] = {}
        self.custom_install_commands["darwin"]["amd64"] = []
        self.custom_install_commands["darwin"]["arm64"] = []
        # Windows
        if "windows" not in self.custom_install_commands:
            self.custom_install_commands["windows"] = {}
        self.custom_install_commands["windows"]["amd64"] = []

        return self

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        found = find_executable(self.command)
        if found:
            self.tool_version = self._run_subprocess(
                command=[self.command, "--version"],
                stderr_preference="return",
                stdout_preference="return",
            ).get("stdout", "1.0.0")

        return found is not None

    def _has_install_commands(self) -> bool:
        """Check if scanner has non-empty custom install commands."""
        import platform
        import struct

        system = platform.system().lower()
        arch = "amd64" if struct.calcsize("P") * 8 == 64 else "arm64"

        if system in self.custom_install_commands:
            if arch in self.custom_install_commands[system]:
                return len(self.custom_install_commands[system][arch]) > 0
        return False

    def _process_config_options(self):
        return super()._process_config_options()

    @staticmethod
    def _lock_context(
        lock_file: Path | None, target_path: Path | str
    ) -> tuple[str | None, NpmLockIndex | None]:
        """The npm lockfile's path relative to the scan root, and an index over it.

        (None, None) when there is no lockfile, it is not an npm lockfile, or it
        is not under the scan root: node paths then cannot be tied to a place.
        """
        if lock_file is None or Path(lock_file).name not in NPM_LOCKFILE_NAMES:
            return None, None
        root = Path(target_path)
        try:
            rel = Path(lock_file).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return None, None
        return rel, NpmLockIndex(root)

    @staticmethod
    def _node_identity(
        pkg_name: str,
        node_path: str,
        lock_rel: str | None,
        lock_index: NpmLockIndex | None,
    ) -> Dict[str, str]:
        """Package identity for one node of an npm audit vulnerability.

        ``package_path`` is the node's lockfile key under the lockfile's
        directory. ``package_version`` is that key's ``version`` in the
        lockfile, because npm audit's own output carries only the advisory
        range, not what is installed.
        """
        if lock_rel is None or lock_index is None:
            return identity_properties(pkg_name, None, None)
        entry = lock_index.entry(lock_rel, str(node_path))
        return identity_properties(
            pkg_name,
            entry.version if entry is not None else None,
            install_path(lock_rel, str(node_path)),
        )

    @staticmethod
    def _audit_failure(
        binary: str, result: Dict[str, Any], audit_results: Any
    ) -> str | None:
        """Why one audit produced no report, or None when it produced one.

        npm exits 1 both for "vulnerabilities found" and for "could not reach
        the audit endpoint", so the exit code alone cannot tell them apart. When
        the endpoint fails (connection refused, a 5xx, a 404, a body that is not
        JSON), `npm audit --json` writes a document with ``message`` and an
        ``error`` object and no ``vulnerabilities`` key. Other npm errors, such
        as ENOLOCK, write ``{"error": {"code": ..., "summary": ...}}``. pnpm
        writes nothing to stdout and its error to stderr. Each of those used to
        convert to zero findings and report PASSED.
        """
        report_key = _REPORT_KEY.get(binary)
        if isinstance(audit_results, dict) and "error" in audit_results:
            if report_key is None or report_key not in audit_results:
                error = audit_results.get("error")
                parts = [str(audit_results.get("message") or "")]
                if isinstance(error, dict):
                    parts += [
                        str(error.get("code") or ""),
                        str(error.get("summary") or ""),
                    ]
                elif error:
                    parts.append(str(error))
                reason = "; ".join(p for p in parts if p) or "no detail given"
                return f"{binary} audit reported an error: {reason}"

        if report_key is None:
            return None
        returncode = result.get("returncode")
        if returncode is None and "error" in result:
            return f"{binary} audit did not run: {result['error']}"
        if returncode in (None, 0):
            return None
        if isinstance(audit_results, dict) and report_key in audit_results:
            return None
        stderr_lines = [
            line.strip()
            for line in _ANSI_ESCAPE.sub(
                "", str(result.get("stderr") or "")
            ).splitlines()
            if line.strip() and "complete log of this run" not in line
        ]
        detail = f": {' / '.join(stderr_lines[:3])[:300]}" if stderr_lines else ""
        return f"{binary} audit exited {returncode} without an audit report{detail}"

    @staticmethod
    def _yarn_major(version_output: Any) -> int | None:
        """The major version in `yarn --version` output, or None if there is none."""
        lines = [
            line
            for line in _ANSI_ESCAPE.sub("", str(version_output or "")).splitlines()
            if line.strip()
        ]
        match = _SEMVER_MAJOR.match(lines[-1]) if lines else None
        return int(match.group(1)) if match else None

    @staticmethod
    def _yarn_error_detail(text: Any) -> str:
        """The lines of yarn output that say what went wrong, joined and capped.

        yarn 1 writes errors as NDJSON ``{"type": "error"}`` events, which are
        reduced to their message. yarn 2+ and crashes write a Node stack trace,
        often after a line of minified source; stack frames and source lines are
        dropped, and lines naming an error (``Error:``, ``[HTTPError]:``) are
        preferred over the rest.
        """
        lines: List[str] = []
        named: List[str] = []
        for raw in _ANSI_ESCAPE.sub("", str(text or "")).splitlines():
            line = raw.strip()
            try:
                event = json.loads(line) if line.startswith("{") else None
            except ValueError:
                event = None
            if isinstance(event, dict) and "type" in event:
                if event.get("type") != "error":
                    continue
                message = str(event.get("data") or "").strip().splitlines()
                if message:
                    named.append(message[0].strip()[:200])
                continue
            if (
                not line
                or line.startswith(("at ", "^", "Node.js v"))
                or len(line) > 200
                or _SOURCE_LOCATION.match(line)
            ):
                continue
            lines.append(line)
            if _NAMED_ERROR.search(line):
                named.append(line)
        return " / ".join((named or lines)[:3])[:300]

    @staticmethod
    def _v1_advisory_record(advisory: Dict[str, Any]) -> Dict[str, Any] | None:
        """One npm v1 advisory (yarn 1 auditAdvisory, yarn 2/3 advisories) as a record."""
        package = advisory.get("module_name")
        if not package:
            return None
        cwe = advisory.get("cwe") or []
        versions: Dict[str, List[str]] = {}
        for finding in advisory.get("findings") or []:
            if not isinstance(finding, dict) or not finding.get("version"):
                continue
            paths = versions.setdefault(str(finding["version"]), [])
            paths.extend(str(p) for p in finding.get("paths") or [] if p not in paths)
        return {
            "package": str(package),
            "id": advisory.get("id"),
            "title": advisory.get("title"),
            "url": advisory.get("url") or "",
            "severity": advisory.get("severity") or "moderate",
            "cvss": advisory.get("cvss")
            if isinstance(advisory.get("cvss"), dict)
            else {},
            "cwe": [cwe] if isinstance(cwe, str) else list(cwe),
            "vulnerable_versions": advisory.get("vulnerable_versions") or "*",
            "patched_versions": advisory.get("patched_versions"),
            "versions": versions,
            "paths_key": "dependency_paths",
        }

    @staticmethod
    def _berry_advisory_record(line: Dict[str, Any]) -> Dict[str, Any] | None:
        """One `yarn npm audit --json` (yarn 4) line as a record, or None.

        None for deprecation notices: yarn 4 lists deprecated packages in the
        same stream, with an ID such as ``"mkdirp (deprecation)"`` and no
        advisory URL. A deprecation is not a vulnerability, and npm audit does
        not report them either.
        """
        children = line.get("children")
        package = line.get("value")
        if not isinstance(children, dict) or not package:
            return None
        advisory_id = children.get("ID")
        if isinstance(advisory_id, str) and advisory_id.endswith("(deprecation)"):
            return None
        return {
            "package": str(package),
            "id": advisory_id,
            "title": children.get("Issue"),
            "url": children.get("URL") or "",
            "severity": children.get("Severity") or "moderate",
            "cvss": {},
            "cwe": [],
            "vulnerable_versions": children.get("Vulnerable Versions") or "*",
            "patched_versions": None,
            "versions": {
                str(v): [str(d) for d in children.get("Dependents") or []]
                for v in children.get("Tree Versions") or []
            },
            "paths_key": "dependents",
        }

    @classmethod
    def _parse_yarn_audit(
        cls, yarn_major: int, result: Dict[str, Any]
    ) -> tuple[Dict[str, Any] | None, str | None]:
        """(report, None) when yarn produced an audit report, else (None, reason).

        yarn writes three formats, all captured from real runs:

        - yarn 1, `yarn audit --json`: NDJSON events. ``auditAdvisory`` lines
          carry npm v1 advisories and an ``auditSummary`` line closes every
          report, clean or not. The exit code is a bitmask of the severities
          found (1 info ... 16 critical), so exit 1 can be a report too. A
          failed request writes an ``error`` event, or a stack trace, and no
          summary.
        - yarn 2 and 3, `yarn npm audit --json`: one npm v1 document with
          ``advisories`` and ``metadata``.
        - yarn 4, `yarn npm audit --json`: one ``{"value", "children"}`` line
          per advisory and package, and nothing at all when clean. A failed
          request exits 1 with nothing on stdout and the error on stderr.

        The report is ``{_YARN_ADVISORIES_KEY: [records], "metadata": ...}``.
        """
        returncode = result.get("returncode")
        if returncode is None and "error" in result:
            return None, f"yarn audit did not run: {result['error']}"
        stdout = _ANSI_ESCAPE.sub("", str(result.get("stdout") or ""))
        detail = cls._yarn_error_detail(result.get("stderr"))

        records: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {}
        is_report = False
        problems: List[str] = []

        if yarn_major < 2:
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    problems.append(line.strip())
                    continue
                if not isinstance(event, dict):
                    continue
                data = event.get("data")
                if event.get("type") == "auditAdvisory" and isinstance(data, dict):
                    advisory = data.get("advisory")
                    record = (
                        cls._v1_advisory_record(advisory)
                        if isinstance(advisory, dict)
                        else None
                    )
                    if record is not None:
                        records.append(record)
                elif event.get("type") == "auditSummary" and isinstance(data, dict):
                    is_report = True
                    metadata = {"vulnerabilities": data.get("vulnerabilities") or {}}
                elif event.get("type") == "error":
                    message = str(data or "").strip().splitlines()
                    problems.append(message[0] if message else "error event")
        else:
            document: Any = None
            try:
                document = json.loads(stdout) if stdout.strip() else None
            except ValueError:
                document = None
            if isinstance(document, dict) and "advisories" in document:
                advisories = document.get("advisories") or {}
                if isinstance(advisories, dict):
                    is_report = True
                    records.extend(cls._v1_advisory_records(advisories))
                    meta = document.get("metadata")
                    if isinstance(meta, dict):
                        metadata = {
                            "vulnerabilities": meta.get("vulnerabilities") or {}
                        }
            else:
                advisory_lines = 0
                for line in stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        problems.append(line.strip())
                        continue
                    if isinstance(entry, dict) and "children" in entry:
                        advisory_lines += 1
                        record = cls._berry_advisory_record(entry)
                        if record is not None:
                            records.append(record)
                # yarn 4 prints nothing when it finds nothing, and exits 0.
                is_report = not problems and (advisory_lines > 0 or returncode == 0)
                counts: Dict[str, int] = {}
                for record in records:
                    severity = str(record["severity"])
                    counts[severity] = counts.get(severity, 0) + 1
                metadata = {"vulnerabilities": counts}

        if problems and not is_report:
            reason = cls._yarn_error_detail("\n".join(problems)) or problems[0][:300]
            if detail:
                reason = f"{reason} / {detail}"[:300]
            return None, f"yarn audit reported an error: {reason}"
        if not is_report:
            suffix = f": {detail}" if detail else ""
            return (
                None,
                f"yarn audit exited {returncode} without an audit report{suffix}",
            )

        # One record per (advisory, package); yarn 1 repeats an advisory once
        # per dependency path that reaches it. Keyed on the advisory's id before
        # its URL: one GHSA can come back as several ids, one per vulnerable
        # range (minimist's GHSA-xvch-5gv4-984h is <0.2.4 and >=1.0.0 <1.2.6),
        # and merging those would report each version under another's range.
        merged: Dict[tuple[str, str], Dict[str, Any]] = {}
        for record in records:
            key = (str(record["id"] or record["url"]), record["package"])
            if key not in merged:
                merged[key] = record
                continue
            for version, paths in record["versions"].items():
                known = merged[key]["versions"].setdefault(version, [])
                known.extend(p for p in paths if p not in known)
        return {_YARN_ADVISORIES_KEY: list(merged.values()), "metadata": metadata}, None

    @classmethod
    def _v1_advisory_records(cls, advisories: Any) -> List[Dict[str, Any]]:
        """Records for an npm v1 ``advisories`` object, as pnpm audit writes it.

        `pnpm audit --json` keys advisories by id, one entry per vulnerable
        range, and lists each installed version that range matches under
        ``findings``. An entry is never repeated, so nothing is merged: a GHSA
        split across ranges stays one record per range, each with its own
        ``vulnerable_versions``.
        """
        if not isinstance(advisories, dict):
            return []
        records = []
        for advisory in advisories.values():
            record = (
                cls._v1_advisory_record(advisory)
                if isinstance(advisory, dict)
                else None
            )
            if record is not None:
                records.append(record)
        return records

    def _add_yarn_results(
        self,
        records: List[Dict[str, Any]],
        rules_dict: Dict[str, ReportingDescriptor],
        results: List[Result],
    ) -> None:
        """Rules and results for yarn and pnpm advisories, in the shape npm's take.

        One result per installed version of the advisory's package. The URI is
        the one the npm path gives a hoisted package, so path-based
        suppressions read the same; neither yarn nor pnpm says where a copy is
        installed, so ``package_path`` is left out.
        """
        for record in records:
            pkg_name = record["package"]
            severity = str(record["severity"])
            level = _SEVERITY_LEVEL.get(severity, "warning")
            vuln_id = self._advisory_id(pkg_name, {"url": record["url"]})
            title = record["title"] or f"Vulnerability in {pkg_name}"
            if vuln_id not in rules_dict:
                rule_props: Dict[str, Any] = {
                    "tags": [
                        "security",
                        "npm-audit",
                        severity,
                        f"tool_name::{self.config.name}",
                        f"tool_type::{self.tool_type or 'UNKNOWN'}",
                    ],
                }
                cvss_score = record["cvss"].get("score")
                if cvss_score is not None:
                    rule_props["security_severity"] = cvss_score
                rules_dict[vuln_id] = ReportingDescriptor(
                    id=vuln_id,
                    name=f"npm-audit-{vuln_id}",
                    shortDescription=MultiformatMessageString(text=title),
                    fullDescription=MultiformatMessageString(
                        text=f"Vulnerability in {pkg_name}: {title}"
                    ),
                    helpUri=record["url"],
                    properties=PropertyBag(**rule_props),
                )
            patched = record["patched_versions"]
            extra: Dict[str, Any] = {}
            if patched is not None:
                extra["patched_versions"] = patched
                extra["fix_available"] = bool(patched) and patched != "<0.0.0"
            for version, paths in sorted(record["versions"].items()):
                per_copy = dict(extra)
                if paths:
                    per_copy[record["paths_key"]] = paths
                results.append(
                    Result(
                        ruleId=vuln_id,
                        level=level,
                        message=Message(
                            text=f"{title} in {pkg_name} {record['vulnerable_versions']}. {record['url']}"
                        ),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    artifactLocation=ArtifactLocation(
                                        uri=f"node_modules/{pkg_name}/package.json"
                                    ),
                                    region=Region(startLine=1, startColumn=1),
                                )
                            )
                        ],
                        properties=PropertyBag(
                            **identity_properties(pkg_name, version, None),
                            installed_version=version,
                            vulnerable_versions=record["vulnerable_versions"],
                            recommendation=f"Update {pkg_name} to a non-vulnerable version",
                            severity=severity,
                            cwe=record["cwe"],
                            cvss=record["cvss"],
                            **per_copy,
                        ),
                    )
                )

    @staticmethod
    def _advisory_id(pkg_name: str, via: Dict[str, Any]) -> str:
        """Rule id of one advisory entry, the same for direct and root findings."""
        return (
            via.get("url", "").split("/")[-1] if via.get("url") else f"npm-{pkg_name}"
        )

    def _root_advisories(
        self,
        pkg_name: str,
        vulnerabilities: Dict[str, Any],
        lock_rel: str | None,
        lock_index: NpmLockIndex | None,
    ) -> List[Dict[str, str]]:
        """The direct findings a transitive package's ``via`` chain leads to.

        One entry per (advisory, installed copy of the advisory's package),
        identified the way that copy's own result is: rule id, ``package_path``
        when the lockfile gives one, and the result URI. Suppression uses these
        to treat the transitive finding as suppressed only when every one of
        those results is. npm audit does not say which copy of a root package a
        dependent resolves to, so every copy is listed.
        """
        roots: Dict[tuple[str, str, str], Dict[str, str]] = {}
        seen: set[str] = set()
        pending = [pkg_name]
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            info = vulnerabilities.get(name) or {}
            via_items = info.get("via", [])
            if not isinstance(via_items, list):
                via_items = [via_items]
            for via in via_items:
                if isinstance(via, str):
                    pending.append(via)
                    continue
                if not isinstance(via, dict):
                    continue
                rule_id = self._advisory_id(name, via)
                for node_path in info.get("nodes", []):
                    identity = self._node_identity(
                        name, node_path, lock_rel, lock_index
                    )
                    location = str(node_path).replace("node_modules/", "")
                    ref = {"rule_id": rule_id}
                    if identity.get(PACKAGE_PATH_KEY):
                        ref["package_path"] = identity[PACKAGE_PATH_KEY]
                    ref["uri"] = f"node_modules/{location}/package.json"
                    roots[(rule_id, ref.get("package_path", ""), ref["uri"])] = ref
        return [roots[key] for key in sorted(roots)]

    def _convert_per_lockfile(
        self,
        per_lock_results: List[tuple[Path, Dict[str, Any]]],
        merged_results: Dict[str, Any],
        target_path: Path,
    ) -> SarifReport:
        """Convert each lockfile's audit output separately and join the runs.

        Converting the merged dict instead loses findings: it is keyed by
        package name, so a package vulnerable in two lockfiles kept only the
        last lockfile's nodes.
        """
        report: SarifReport | None = None
        for lock_file, audit_results in per_lock_results:
            part = self._convert_npm_audit_to_sarif(
                audit_results, target_path, lock_file=lock_file
            )
            if report is None:
                report = part
                continue
            run, part_run = report.runs[0], part.runs[0]
            run.results.extend(part_run.results or [])
            known = {rule.id for rule in run.tool.driver.rules or []}
            for rule in part_run.tool.driver.rules or []:
                if rule.id not in known:
                    run.tool.driver.rules.append(rule)
                    known.add(rule.id)
        if report is None:
            return self._convert_npm_audit_to_sarif(merged_results, target_path)
        report.runs[0].properties = PropertyBag(
            metrics=merged_results.get("metadata", {}).get("vulnerabilities", {})
        )
        return report

    def _convert_npm_audit_to_sarif(
        self,
        npm_audit_results: Dict[str, Any],
        target_path: Path,
        lock_file: Path | None = None,
    ) -> SarifReport:
        """Convert npm audit results to SARIF format.

        Args:
            npm_audit_results: npm audit results in JSON format
            target_path: Path to the scanned directory
            lock_file: The lockfile these results were audited from. When it is
                an npm lockfile under ``target_path``, each result carries
                ``package_version`` and ``package_path`` from it.

        Returns:
            SarifReport: SARIF report containing the scan findings
        """
        lock_rel, lock_index = self._lock_context(lock_file, target_path)
        # Create the basic SARIF structure
        tool_component = ToolComponent(
            name="npm-audit",
            version=self.tool_version,
            informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
            rules=[],
        )

        # Create a dictionary to track unique rules
        rules_dict = {}

        # Create results list for SARIF
        results = []

        # Process vulnerabilities
        if "vulnerabilities" in npm_audit_results:
            for pkg_name, vuln_info in npm_audit_results["vulnerabilities"].items():
                # Get severity
                severity = vuln_info.get("severity", "moderate")

                # Map npm severity to SARIF level
                level = _SEVERITY_LEVEL.get(severity, "warning")

                # Process each vulnerability path
                via_items = vuln_info.get("via", [])
                if not isinstance(via_items, list):
                    via_items = [via_items]

                has_dict_via = False
                for via in via_items:
                    # Skip if it's just a string reference to another package
                    if isinstance(via, str):
                        continue

                    has_dict_via = True

                    # Extract vulnerability details
                    vuln_id = self._advisory_id(pkg_name, via)
                    title = via.get("title", f"Vulnerability in {pkg_name}")
                    description = f"Vulnerability in {pkg_name}: {title}"

                    # Create a rule for this vulnerability if it doesn't exist
                    if vuln_id not in rules_dict:
                        rule_props = {
                            "tags": [
                                "security",
                                "npm-audit",
                                severity,
                                f"tool_name::{self.config.name}",
                                f"tool_type::{self.tool_type or 'UNKNOWN'}",
                            ],
                        }
                        # Only attach security-severity when npm actually reported a
                        # CVSS score. It used to default to 0, which the SARIF severity
                        # normalizer reads as CVSS 0.0 and maps to INFO — downgrading a
                        # critical/high advisory that ships no CVSS number below the
                        # severity threshold (fail-open). Omitting it leaves the
                        # level-based severity in place.
                        cvss_score = via.get("cvss", {}).get("score")
                        if cvss_score is not None:
                            rule_props["security_severity"] = cvss_score
                        rule = ReportingDescriptor(
                            id=vuln_id,
                            name=f"npm-audit-{vuln_id}",
                            shortDescription=MultiformatMessageString(text=title),
                            fullDescription=MultiformatMessageString(text=description),
                            helpUri=via.get("url", ""),
                            properties=PropertyBag(**rule_props),
                        )
                        rules_dict[vuln_id] = rule

                    # Create a result for each installed copy (node)
                    for node_path in vuln_info.get("nodes", []):
                        # The URI keeps its historical shape, which existing
                        # path-based suppressions match; package_path holds
                        # the real install path.
                        pkg_location = str(node_path).replace("node_modules/", "")
                        identity = self._node_identity(
                            pkg_name, node_path, lock_rel, lock_index
                        )
                        result = Result(
                            ruleId=vuln_id,
                            level=level,
                            message=Message(
                                text=f"{title} in {pkg_name} {vuln_info.get('range', '*')}. {via.get('url', '')}"
                            ),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=f"node_modules/{pkg_location}/package.json"
                                        ),
                                        region=Region(startLine=1, startColumn=1),
                                    )
                                )
                            ],
                            properties=PropertyBag(
                                **identity,
                                installed_version=identity.get(
                                    PACKAGE_VERSION_KEY, vuln_info.get("range", "*")
                                ),
                                vulnerable_versions=vuln_info.get("range", "*"),
                                recommendation=f"Update {pkg_name} to a non-vulnerable version",
                                severity=severity,
                                cwe=via.get("cwe", []),
                                cvss=via.get("cvss", {}),
                                fix_available=vuln_info.get("fixAvailable", False),
                            ),
                        )
                        results.append(result)

                # Handle transitive-only vulnerabilities: all via entries
                # are strings referencing other packages, so no Result was
                # created above.  Build a minimal result from vuln_info.
                if not has_dict_via and via_items:
                    vuln_id = f"npm-audit-transitive-{pkg_name}"
                    via_refs = ", ".join(v for v in via_items if isinstance(v, str))
                    title = f"Transitive vulnerability in {pkg_name} (via {via_refs})"
                    description = title

                    if vuln_id not in rules_dict:
                        rule = ReportingDescriptor(
                            id=vuln_id,
                            name=vuln_id,
                            shortDescription=MultiformatMessageString(text=title),
                            fullDescription=MultiformatMessageString(text=description),
                            properties=PropertyBag(
                                tags=[
                                    "security",
                                    "npm-audit",
                                    severity,
                                    f"tool_name::{self.config.name}",
                                    f"tool_type::{self.tool_type or 'UNKNOWN'}",
                                ],
                                # No security-severity: a transitive advisory carries no
                                # CVSS score here, and a hardcoded 0 made the severity
                                # normalizer downgrade it to INFO (fail-open). Absent, the
                                # SARIF level determines severity.
                            ),
                        )
                        rules_dict[vuln_id] = rule

                    # Every direct finding this chain resolves to, so a
                    # suppression on the advisory can reach this result too.
                    root_advisories = self._root_advisories(
                        pkg_name,
                        npm_audit_results["vulnerabilities"],
                        lock_rel,
                        lock_index,
                    )
                    for node_path in vuln_info.get("nodes", []):
                        pkg_location = str(node_path).replace("node_modules/", "")
                        identity = self._node_identity(
                            pkg_name, node_path, lock_rel, lock_index
                        )
                        # Any-valued: root_advisories is a list of refs, unlike
                        # the string identity fields it joins in the PropertyBag.
                        identity_fields: Dict[str, Any] = dict(identity)
                        if root_advisories:
                            identity_fields[ROOT_ADVISORIES_KEY] = root_advisories
                        result = Result(
                            ruleId=vuln_id,
                            level=level,
                            message=Message(
                                text=f"{title} {vuln_info.get('range', '*')}"
                            ),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=f"node_modules/{pkg_location}/package.json"
                                        ),
                                        region=Region(startLine=1, startColumn=1),
                                    )
                                )
                            ],
                            properties=PropertyBag(
                                **identity_fields,
                                installed_version=identity.get(
                                    PACKAGE_VERSION_KEY, vuln_info.get("range", "*")
                                ),
                                vulnerable_versions=vuln_info.get("range", "*"),
                                recommendation=f"Update {pkg_name} to a non-vulnerable version",
                                severity=severity,
                                fix_available=vuln_info.get("fixAvailable", False),
                            ),
                        )
                        results.append(result)

        if _YARN_ADVISORIES_KEY in npm_audit_results:
            self._add_yarn_results(
                npm_audit_results[_YARN_ADVISORIES_KEY], rules_dict, results
            )

        # pnpm audit writes npm's v1 report, ``advisories`` and ``metadata``,
        # where npm 7+ writes ``vulnerabilities``. Read only the vulnerabilities
        # key and a pnpm project with real advisories converted to no findings.
        if "advisories" in npm_audit_results:
            self._add_yarn_results(
                self._v1_advisory_records(npm_audit_results["advisories"]),
                rules_dict,
                results,
            )

        # Add all rules to the tool component
        tool_component.rules = list(rules_dict.values())

        # Create the SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=(
                                self.exit_code == 0 or self.exit_code == 1
                            ),
                            exitCode=self.exit_code,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target_path)
                            ),
                        )
                    ],
                    properties=PropertyBag(
                        metrics=npm_audit_results.get("metadata", {}).get(
                            "vulnerabilities", {}
                        )
                    ),
                )
            ],
        )

        return sarif_report

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — NpmAudit overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: NpmAuditScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute NpmAudit scan and return results.

        Args:
            target: Path to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        tool_component = ToolComponent(
            name="npm-audit",
            version=self.tool_version,
            informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
            rules=[],
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=(
                                self.exit_code == 0 or self.exit_code == 1
                            ),
                            exitCode=self.exit_code,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results.json")
            results_file.parent.mkdir(exist_ok=True, parents=True)

            # Find all files to scan from the scan set
            orig_scannable = (
                list(self.context.work_dir.glob("**/*.*"))
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    # filter_pattern=r"\.(yaml|yml|json)$",
                )
            )

            scannable = []
            for f in orig_scannable:
                pf = Path(f)
                if pf.name == "package.json":
                    scannable.append(pf.as_posix())
            joined_files = "\n- ".join(scannable)
            self._plugin_log(f"Found {len(scannable)} package locks:\n- {joined_files}")

            if len(scannable) == 0:
                self._plugin_log(
                    f"No package lock files found in {target_type} directory to scan. Returning.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            # Run npm audit for each package.json file. all_results is the
            # merged raw output written to results.json; per_lock_results keeps
            # each lockfile's output whole for the SARIF conversion.
            all_results = {}
            per_lock_results: List[tuple[Path, Dict[str, Any]]] = []
            # Lockfiles whose audit produced no report, with the reason. Any
            # entry makes the scan an error: those dependencies were not
            # checked, and reporting the rest as clean would say they were.
            audit_failures: List[str] = []
            lock_files = [
                "yarn.lock",
                "pnpm-lock.yaml",
                "package-lock.json",
            ]
            for item in scannable:
                package_file = Path(item)
                lock_file = None
                for item in lock_files:
                    lf_path = package_file.parent.joinpath(item)
                    if lf_path.exists():
                        lock_file = lf_path
                        break
                if lock_file is not None:
                    package_dir = package_file.parent

                    try:
                        # Run npm audit
                        if lock_file.name == "yarn.lock":
                            binary = "yarn"
                        elif lock_file.name == "pnpm-lock.yaml":
                            binary = "pnpm"
                        else:
                            binary = "npm"

                        # Check that the binary is installed before
                        # attempting to run it (#180).  npm is already
                        # validated in validate_plugin_dependencies, but
                        # yarn and pnpm may not be present.
                        if binary != "npm" and find_executable(binary) is None:
                            ASH_LOGGER.warning(
                                f"{binary} is not installed -- skipping "
                                f"audit for {lock_file}. Install {binary} "
                                "to scan this lock file."
                            )
                            continue

                        # Corepack resolves the package manager version from the
                        # repository's `packageManager` field, and fetches it if the
                        # image has a different one cached. The Dockerfile sets
                        # COREPACK_ENABLE_DOWNLOAD_PROMPT=0 so that fetch cannot
                        # block on a stdin prompt that no one can answer -- but
                        # disabling the prompt only stops the *asking*, not the
                        # download.
                        #
                        # In offline mode a download is the wrong outcome twice
                        # over: there is no network, so it fails, and it fails
                        # instead of using the package manager already cached in the
                        # image. COREPACK_ENABLE_NETWORK=0 makes corepack fall back
                        # to the cached version rather than reach out.
                        subprocess_env = None
                        if self._scanner_offline():
                            subprocess_env = {
                                **os.environ,
                                "COREPACK_ENABLE_NETWORK": "0",
                            }

                        # yarn 2 and later dropped `yarn audit` for `yarn npm
                        # audit`, and print a different report. Which yarn runs
                        # depends on the project (corepack honours its
                        # `packageManager` field), so ask it from there.
                        yarn_major: int | None = None
                        cmd = [binary, "audit", "--json"]
                        if binary == "yarn":
                            version_result = self._run_subprocess(
                                command=[binary, "--version"],
                                stdout_preference="return",
                                stderr_preference="return",
                                cwd=package_dir,
                                env=subprocess_env,
                                timeout=self._effective_scan_timeout(),
                            )
                            yarn_major = self._yarn_major(version_result.get("stdout"))
                            if yarn_major is None:
                                detail = self._yarn_error_detail(
                                    version_result.get("stderr")
                                    or version_result.get("error")
                                )
                                audit_failures.append(
                                    f"{lock_file}: could not tell which yarn "
                                    "version runs here; `yarn --version` printed "
                                    f"{str(version_result.get('stdout') or '').strip()[:80]!r}"
                                    + (f" ({detail})" if detail else "")
                                )
                                continue
                            if yarn_major >= 2:
                                if self._scanner_offline():
                                    # `yarn npm audit` has no offline mode: it
                                    # rejects --offline and always asks the
                                    # registry. Offline, that is an audit that
                                    # cannot run, as it is for npm.
                                    audit_failures.append(
                                        f"{lock_file}: yarn {yarn_major} audits "
                                        "with `yarn npm audit`, which has no "
                                        "offline mode, so it was not run"
                                    )
                                    continue
                                # --recursive: the whole tree, as npm audits
                                # it. Without it yarn checks direct deps only.
                                cmd = [binary, "npm", "audit", "--json", "--recursive"]

                        # Add offline mode if enabled
                        if self._scanner_offline():
                            cmd.append("--offline")
                            ASH_LOGGER.info(
                                f"🔄 Running {binary} audit in offline mode"
                            )

                            # Validate offline mode requirements
                            from automated_security_helper.utils.offline_mode_validator import (
                                validate_npm_audit_offline_mode,
                            )

                            offline_valid, offline_messages = (
                                validate_npm_audit_offline_mode()
                            )
                            if not offline_valid:
                                ASH_LOGGER.warning(
                                    "npm audit offline mode validation failed, but continuing with scan"
                                )

                        # Run from the lock file's parent directory so
                        # that pnpm (and yarn) can locate their lock
                        # files (#99).
                        result = self._run_subprocess(
                            command=cmd,
                            results_dir=target_results_dir,
                            stdout_preference="both",
                            stderr_preference="both",
                            cwd=package_dir,
                            env=subprocess_env,
                            timeout=self._effective_scan_timeout(),
                        )
                        ASH_LOGGER.info(result)

                        # npm audit returns non-zero exit code when vulnerabilities are found
                        # but we still want to process the output
                        audit_results: Any = None
                        if yarn_major is not None:
                            audit_results, failure = self._parse_yarn_audit(
                                yarn_major, result
                            )
                        else:
                            if result.get("stdout", None):
                                try:
                                    audit_results = json.loads(
                                        result.get("stdout", None)
                                    )
                                except json.JSONDecodeError:
                                    ASH_LOGGER.warning(
                                        f"Failed to parse npm audit output for {package_dir}"
                                    )
                            failure = self._audit_failure(binary, result, audit_results)
                        if failure is not None:
                            audit_failures.append(f"{lock_file}: {failure}")
                            continue
                        if audit_results is not None:
                            if isinstance(audit_results, dict):
                                # A copy: the first document becomes
                                # all_results below and is merged into.
                                per_lock_results.append(
                                    (lock_file, copy.deepcopy(audit_results))
                                )
                            # Merge results
                            if not all_results:
                                all_results = audit_results
                            else:
                                # Merge vulnerabilities
                                if "vulnerabilities" in audit_results:
                                    all_results.setdefault(
                                        "vulnerabilities", {}
                                    ).update(audit_results["vulnerabilities"])
                                # pnpm's advisories, so results.json keeps them
                                if isinstance(audit_results.get("advisories"), dict):
                                    all_results.setdefault("advisories", {}).update(
                                        audit_results["advisories"]
                                    )
                                # Update metadata
                                if "metadata" in audit_results:
                                    for key, value in audit_results["metadata"].items():
                                        if key in all_results.get("metadata", {}):
                                            if isinstance(value, dict):
                                                all_results["metadata"][key].update(
                                                    value
                                                )
                                            elif isinstance(value, (int, float)):
                                                all_results["metadata"][key] += value
                                        else:
                                            all_results.setdefault("metadata", {})[
                                                key
                                            ] = value
                    except Exception as e:
                        ASH_LOGGER.warning(
                            f"Failed to run npm audit in {package_dir}: {str(e)}"
                        )
                        audit_failures.append(
                            f"{lock_file}: the audit raised {type(e).__name__}: {e}"
                        )

            # Save the combined results
            if all_results:
                Path(results_file).parent.mkdir(exist_ok=True, parents=True)
                # encoding=None: the locale's, as Path.write_text used.
                with open_for_write(results_file, encoding=None, errors=None) as f:
                    f.write(json.dumps(all_results, default=str))

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            if audit_failures:
                summary = (
                    f"could not audit {len(audit_failures)} lockfile(s), so "
                    "their dependencies were not checked: " + " | ".join(audit_failures)
                )
                if self._scanner_offline():
                    # Offline, an audit that cannot reach its advisory source is
                    # the expected outcome, and offline scans have always gone on
                    # without it. Kept as it was; the warning names what was lost.
                    ASH_LOGGER.warning(f"npm-audit (offline) {summary}")
                else:
                    raise ScannerError(summary)

            # Convert npm audit results to SARIF
            if all_results:
                sarif_report = self._convert_per_lockfile(
                    per_lock_results, all_results, target
                )

                # Save SARIF report
                sarif_file = target_results_dir.joinpath("results_sarif.sarif")
                with open_for_write(sarif_file) as f:
                    f.write(
                        sarif_report.model_dump_json(
                            exclude_none=True,
                            exclude_unset=True,
                        )
                    )

                return sarif_report
            else:
                # Return empty SARIF report
                return SarifReport(
                    version="2.1.0",
                    runs=[
                        Run(
                            tool=Tool(
                                driver=ToolComponent(
                                    name="npm-audit",
                                    version="1.0.0",
                                    informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
                                )
                            ),
                            results=[],
                            invocations=[
                                Invocation(
                                    commandLine="npm audit --json",
                                    executionSuccessful=(
                                        self.exit_code == 0 or self.exit_code == 1
                                    ),
                                    exitCode=self.exit_code,
                                    workingDirectory=ArtifactLocation(
                                        uri=get_shortest_name(input=target)
                                    ),
                                )
                            ],
                        )
                    ],
                )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"NpmAudit scan failed: {str(e)}")


if __name__ == "__main__":
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    AshConfig.model_rebuild()
    ASH_LOGGER.debug("Running NpmAuditScanner via __main__")
    scanner = NpmAuditScanner(
        context=PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        )
    )
    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    if report:
        print(
            report.model_dump_json(
                indent=2,
                by_alias=True,
                exclude_unset=True,
            )
        )
