"""Module containing the NPM Audit security scanner implementation."""

import copy
import json
import logging
import re
import secrets
from pathlib import Path
from typing import Annotated, ClassVar, Dict, List, Literal, Any, Sequence

from pydantic import Field, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
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
from automated_security_helper.utils.error_text import ESCAPE_CODES, shown_tool_stderr
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.link_exclusions import drop_ignored
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
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
from automated_security_helper.utils.package_manager_child import (
    package_manager_child,
    refused_inputs,
)
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.suppression_matcher import active_ignore_paths


# The top-level key each package manager's audit report always carries, clean or
# not. An exit status other than 0 without it means the audit did not run to a
# report. yarn is absent because its output is not one JSON document: see
# _parse_yarn_audit, which decides for yarn whether a report came back.
_REPORT_KEY = {"npm": "vulnerabilities", "pnpm": "advisories"}

# The shared escape pattern: every complete CSI or OSC sequence, the same set
# every other reader of tool output strips, so no side strips a code another
# keeps (a narrower CSI-only copy here left OSC hyperlinks in yarn's version
# answer and its NDJSON stdout).
_ANSI_ESCAPE = ESCAPE_CODES


def _without_an_exit_code(result: Dict[str, Any]) -> str:
    """Why an audit whose response has an error and no exit code produced no
    report. The flags are read before the code: with ``post_run_error`` the audit
    ran and ASH stopped it before it finished; without, it never ran."""
    if result.get("post_run_error") is True:
        return f"did not finish: {result['error']}"
    return f"did not run: {result['error']}"


def _has_problem_text(problems: List[str]) -> bool:
    """Whether the kept segments say anything.

    The parse loops keep every non-event segment, whitespace-only ones
    included, so a value that spans such a line keeps its whole spelling for
    the redaction. Whether yarn REPORTED anything is this question instead:
    whitespace alone is no error of yarn's, and must neither demote a real
    advisory stream nor turn the no-report wording into an error wording
    with nothing to show."""
    return any(piece.strip() for piece in problems)


# Advisory severity to SARIF level, for npm, yarn and pnpm alike.
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "moderate": "warning",
    "low": "note",
    "info": "note",
}

# Advisory severity to the ASH severity a result declares (``issue_severity``,
# which utils/severity_ladder.result_severity reads first) when no CVSS score
# backs its rule. Without it the SARIF level decided, and the ladder reads
# ``error`` as CRITICAL and ``note`` as LOW, so an unscored high advisory was
# graded CRITICAL and an info one LOW. With a usable score the rule's
# security_severity is copied onto the result instead (sarif_utils).
_SEVERITY_GRADE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _usable_cvss_score(cvss: Any) -> float | None:
    """The CVSS score in an advisory's ``cvss`` object, or None when it has none.

    npm writes ``{"score": 0, "vectorString": null}`` for an advisory with no
    CVSS vector, and may write ``null`` for the object itself; pnpm's and yarn's
    v1 advisories may carry no object. A missing object raised on ``.get``, and
    a 0 was attached to the rule as its security-severity, which GHAS forwards
    as "0", below its Low bucket, and which the normalizer skips as no score.
    A score counts when it is a number in (0, 10].
    """
    if not isinstance(cvss, dict):
        return None
    score = cvss.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    if not 0 < score <= 10:
        return None
    return float(score)


# The userinfo of a URL (``https://user:token@host``), masked in log excerpts.
_URL_USERINFO = re.compile(r"(://)[^\s/@]+@")

# One comparator of an npm advisory range: an operator, a version and an
# optional prerelease or build suffix.
_RANGE_COMPARATOR = re.compile(
    r"^(<=|>=|<|>|=)?v?(\d+\.\d+\.\d+)([-+][0-9A-Za-z.+-]*)?$"
)


def _version_in_range(version: Any, vulnerable_range: Any) -> bool | None:
    """Whether ``version`` is inside npm's ``vulnerable_range``, or None.

    npm audit lists every installed copy of a package under each of its
    advisories, so a copy at a fixed version carried the advisory of another
    copy, and one GHSA split into several ranges (minimist's ``<0.2.4`` and
    ``>=1.0.0 <1.2.6``) was reported once per range on every copy. The range
    grammar read here is the one advisories use: alternatives joined by
    ``||``, each a run of comparators (``<``, ``<=``, ``>``, ``>=``, ``=`` or a
    bare version) that all have to hold, and ``*`` for everything.

    None, which the caller reads as "keep the result", whenever the answer is
    not certain: no version, a version or comparator that does not parse
    (``^``, ``~``, ``x`` ranges, hyphen ranges), or a prerelease version or
    bound, whose place in a range npm's semver decides by rules not reproduced
    here. A bound's suffix is never handed to packaging: semver reads
    ``2.0.0-0`` (the upper bound node's semver writes for ``^1``) as a
    prerelease below 2.0.0, while packaging reads it as a post-release above
    it, so ``>=2.0.0-0`` against an installed 2.0.0 would have read False and
    dropped a result the range covers.
    """
    from packaging.version import InvalidVersion, Version

    if not isinstance(version, str) or not isinstance(vulnerable_range, str):
        return None
    try:
        installed = Version(version.strip().lstrip("v"))
    except InvalidVersion:
        return None
    if installed.is_prerelease or installed.local is not None:
        return None
    text = vulnerable_range.strip()
    if text in ("", "*"):
        return True
    outcome = False
    for alternative in text.split("||"):
        holds = True
        for comparator in alternative.split():
            match = _RANGE_COMPARATOR.match(comparator)
            if match is None:
                return None
            operator, bound_text = match.group(1) or "=", match.group(2)
            if match.group(3):
                return None
            try:
                bound = Version(bound_text)
            except InvalidVersion:
                return None
            if operator == "<":
                holds = holds and installed < bound
            elif operator == "<=":
                holds = holds and installed <= bound
            elif operator == ">":
                holds = holds and installed > bound
            elif operator == ">=":
                holds = holds and installed >= bound
            else:
                holds = holds and installed == bound
        outcome = outcome or holds
    return outcome


def _grade_properties(severity: str) -> Dict[str, str]:
    """The ``issue_severity`` a result declares from its advisory's severity word,
    for an advisory with no usable CVSS score; empty for a word not in the table,
    which leaves the SARIF level to decide as before."""
    grade = _SEVERITY_GRADE.get(str(severity).lower())
    return {"issue_severity": grade} if grade else {}


def _ndjson_lines(text: str) -> List[str]:
    """The lines of NDJSON output, split at line feeds only, terminators kept.

    ``str.splitlines`` also splits at U+2028, U+2029, U+0085, U+000B, U+000C
    and the other separators Unicode names, which a JSON string may hold as it
    is (``JSON.stringify`` writes them unescaped), so an advisory title holding
    one broke its event line in two: neither half parsed, and a yarn 1 advisory
    was dropped while a yarn 4 report was read as an error.
    """
    pieces = text.split("\n")
    lines = [piece + "\n" for piece in pieces[:-1]]
    if pieces[-1]:
        lines.append(pieces[-1])
    return lines


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
            description="Treat this scanner as offline. npm, pnpm and yarn audit only against the package registry's advisory service, so offline npm-audit audits nothing: each lockfile is listed as not scanned, with a lockfile the scanner is reported MISSING, and with none it is SKIPPED. When true, this scanner is offline even if ASH is not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]


class NpmAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["npm-audit"] = "npm-audit"
    enabled: bool = True
    options: Annotated[
        NpmAuditScannerConfigOptions, Field(description="Configure NpmAudit scanner")
    ] = NpmAuditScannerConfigOptions()


#: Why npm-audit does not run offline; see NpmAuditScanner.validate_plugin_dependencies.
_OFFLINE_REASON = (
    "offline: npm, yarn and pnpm audit a lockfile by asking the registry for its "
    "advisories, and offline npm audit reads none and reports every lockfile "
    "clean, so ASH does not run it offline. Scan online, or exclude npm-audit "
    "with --exclude-scanners"
)


@ash_scanner_plugin
class NpmAuditScanner(ScannerPluginBase[NpmAuditScannerConfig]):
    """NpmAuditScanner implements IaC scanning using `npm/yarn/pnpm audit` based on the lock files discovered in the source directory."""

    #: npm-audit runs npm, yarn or pnpm. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.npm",),
        # npm cannot audit without writing its cache (the registry metadata the
        # vulnerable ranges come from) and logs, both under npm_config_cache.
        cache_env=("npm_config_cache",),
        env_prefixes=("npm_config_", "NPM_CONFIG_"),
        # How a sandboxed yarn is kept from the repository's settings and from
        # running its yarn-path (see utils/package_manager_child.py).
        env_names=("YARN_IGNORE_PATH", "YARN_RC_FILENAME"),
    )

    # npm, yarn and pnpm audit by asking the registry, so offline there is nothing to
    # run: validate_plugin_dependencies says no, as snyk-code's does.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

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

        False offline, whatever is installed. npm, yarn and pnpm audit a lockfile
        by asking the registry for the advisories that match it, and offline there
        is no registry to ask. npm does not say so: ``npm audit --json --offline``
        on a lockfile pinning lodash 4.17.15, which has published advisories,
        prints ``"vulnerabilities": {}`` and exits 0 (npm 10.9.4), which read as a
        clean audit. The reason is recorded for the MISSING row; with no lockfile to
        audit ScanPhase records the scanner SKIPPED instead.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        if self._scanner_offline():
            self.dependency_unavailable_reason = _OFFLINE_REASON
            # scan() is not called after a False, so the lockfiles the audit
            # would have read are recorded here; ScanPhase copies them onto
            # the MISSING row. The converted tree does not exist yet at this
            # point, so the source tree is what is recorded.
            self.inputs_not_scanned = self._offline_skips(
                self._package_manifests("source"), "source"
            )
            return False
        found = find_executable(self.command)
        if found:
            self.tool_version = self._run_subprocess(
                command=[self.command, "--version"],
                stderr_preference="return",
                stdout_preference="return",
            ).get("stdout", "1.0.0")

        return found is not None

    #: Lockfiles npm-audit audits, in the order it looks for one beside a package.json.
    #: npm reads npm-shrinkwrap.json ahead of package-lock.json when both exist, and
    #: audits either; yarn.lock and pnpm-lock.yaml are audited with their own tools.
    LOCKFILE_NAMES: ClassVar[tuple[str, ...]] = (
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        "package-lock.json",
    )

    def _scan_ignore_paths(self) -> List[IgnorePathWithReason]:
        """The ignore paths that keep a package out of this scan, computed as the
        orchestrator computes the list it hands ``scan()``: the entries that have
        not expired, less those the delivered tree's own config supplied
        (``client_supplied``, left to the SARIF step so their findings show as
        suppressed), and none under ``--ignore-suppressions``, which lifts every
        suppression (``models.core.ignore_paths_that_skip_scanning``)."""
        global_settings = getattr(
            getattr(self.context, "config", None), "global_settings", None
        )
        return ignore_paths_that_skip_scanning(
            active_ignore_paths(getattr(global_settings, "ignore_paths", None) or []),
            ignore_suppressions=bool(
                getattr(self.context, "ignore_suppressions", False)
            ),
        )

    def _package_manifests(
        self,
        target_type: str,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
    ) -> List[str]:
        """Every package.json in one tree: the scan set, or the work directory.

        The scan set leaves out a link whose target is outside the tree, so a
        package whose package.json is such a link would vanish here and its in-tree
        lockfile go unaudited with nothing failing. Such a package is taken from its
        lockfile instead, when a package.json sits beside it (by lstat) that the
        list left out, once per directory; scan() then refuses it. A lockfile with no
        package.json beside it is not a package.

        The scan set is taken without the files the ignore paths ignore, matched as
        ASH matches them when it drops findings (``link_exclusions.drop_ignored``):
        npm-audit read an ignored package's lockfile, and its results held it. The
        list is ``global_ignore_paths`` when ``scan()`` is handed one (the
        orchestrator's, which honors ``--ignore-suppressions`` and leaves the
        client-supplied entries to the SARIF step); otherwise it is computed from
        the config the same way (``_scan_ignore_paths``). Recomputing it from the
        config alone discarded the list scan() was given, so the flag and the
        carve-out did not reach npm-audit's file selection.

        In a workspace scan the workspace's output directory is left out of the
        walk like the project's own (``workspace_output_dir``), as the other
        readers of the scan set leave it out.
        """
        ignore_paths = (
            self._scan_ignore_paths()
            if global_ignore_paths is None
            else list(global_ignore_paths)
        )
        workspace_output = getattr(self.context, "workspace_output_dir", None)
        orig_scannable = (
            list(self.context.work_dir.glob("**/*.*"))
            if target_type == "converted"
            else drop_ignored(
                scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    honor_ignore_files=honors_ignore_files(
                        getattr(self.context, "config", None)
                    ),
                    run_id=getattr(self.context, "run_id", None),
                    workspace_output_dir=(
                        str(workspace_output) if workspace_output else None
                    ),
                ),
                self.context.source_dir,
                ignore_paths,
            )
        )
        manifests = [Path(f) for f in orig_scannable if Path(f).name == "package.json"]
        listed = {manifest.parent for manifest in manifests}
        for f in orig_scannable:
            pf = Path(f)
            manifest = pf.parent / "package.json"
            if (
                pf.name in self.LOCKFILE_NAMES
                and pf.parent not in listed
                and (manifest.is_symlink() or manifest.exists())
            ):
                listed.add(pf.parent)
                manifests.append(manifest)
        return [manifest.as_posix() for manifest in manifests]

    @classmethod
    def _lockfile_beside(cls, package_file: str | Path) -> Path | None:
        """The lockfile npm-audit audits for *package_file*, or None."""
        for name in cls.LOCKFILE_NAMES:
            candidate = Path(package_file).parent.joinpath(name)
            if candidate.exists():
                return candidate
        return None

    def nothing_to_scan_reason(self) -> str | None:
        """None when either tree holds a package.json with a lockfile beside it.

        npm, yarn and pnpm audit a lockfile, so a package.json without one is not
        audited; that is the selection ``scan()`` makes. See the base class.
        """
        trees = ["source"]
        work_dir = Path(self.context.work_dir)
        if work_dir.is_dir() and any(work_dir.rglob("*.*")):
            trees.append("converted")
        for target_type in trees:
            for package_file in self._package_manifests(target_type):
                if self._lockfile_beside(package_file) is not None:
                    return None
        return (
            "no lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock or "
            "pnpm-lock.yaml) beside a package.json in the scanned files"
        )

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

    def _package_manager_options(
        self, results_dir: Path, target: Path
    ) -> Dict[str, Any]:
        """What utils/package_manager_child.py needs from this scan.

        ``roots`` is the scanned tree a file the tool reads has to resolve inside:
        the scanned root (the workspace root in workspace mode) and the target, which
        for the converted target is ASH's work directory.
        """
        config = getattr(self.context, "config", None)
        scan_root = Path(
            getattr(config, "_scanned_root", None) or self.context.source_dir
        )
        return {
            "parent": Path(results_dir),
            "scan_root": scan_root,
            "skip": [Path(self.context.output_dir)],
            "roots": [scan_root, Path(target)],
            "ignore_suppressions": bool(
                getattr(self.context, "ignore_suppressions", False)
            ),
        }

    def _shown_path(self, path: Path, target_type: str) -> str:
        """``path`` as recorded in the results: relative to the target, as named."""
        base = Path(
            self.context.work_dir
            if target_type == "converted"
            else self.context.source_dir
        ).absolute()
        try:
            return Path(path).absolute().relative_to(base).as_posix()
        except ValueError:
            return Path(path).as_posix()

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

    def _node_place(
        self,
        pkg_name: str,
        node_path: str,
        lock_rel: str | None,
        lock_index: NpmLockIndex | None,
    ) -> tuple[str, Dict[str, str]]:
        """The result URI's package location and the identity of one node."""
        return (
            str(node_path).replace("node_modules/", ""),
            self._node_identity(pkg_name, node_path, lock_rel, lock_index),
        )

    @staticmethod
    def _v1_report_has_evidence(document: Any) -> bool:
        """Whether *document* is an npm v1 audit document with evidence the
        lockfile was evaluated: its ``advisories`` is a dict holding findings,
        or the counting ``metadata`` dict every real clean report writes.

        One answer for every reader of the v1 shape - npm 6's report, pnpm's,
        and yarn 2/3's document - so the readers cannot drift apart. A truthy
        ``advisories`` of another type would otherwise be graded a clean
        report with zero findings, and an empty one beside a null ``metadata``
        would reach the SARIF conversion and crash there instead of reading as
        an audit without a report; both are what a truncated or broken tool
        emits, not evidence.

        ``advisories`` counts only through the records it actually yields
        (``_v1_advisory_records``): a dict of entries that are not advisory
        objects, or that name no module, is as empty as ``{}``, and grading it
        on truthiness alone read such a document as clean with zero findings."""
        if not isinstance(document, dict):
            return False
        advisories = document.get("advisories")
        if not isinstance(advisories, dict):
            return False
        if isinstance(document.get("metadata"), dict):
            return True
        return bool(NpmAuditScanner._v1_advisory_records(advisories))

    @staticmethod
    def _audit_failure(
        binary: str,
        result: Dict[str, Any],
        audit_results: Any,
        values: Sequence[str] | None = (),
    ) -> str | None:
        """Why one audit produced no report, or None when it produced one.

        ``values`` are the caller's env-read values: the stderr excerpt is
        redacted with them BEFORE it is cut, so the cut cannot split a value
        and leave a fragment the downstream whole-spelling redaction misses.
        ``None`` means the caller's values hook raised: the verdict is still
        given, but the stderr excerpt is dropped rather than shown with an
        empty value set, which would print what the values would have hidden.

        npm exits 1 both for "vulnerabilities found" and for "could not reach
        the audit endpoint", so the exit code alone cannot tell them apart. When
        the endpoint fails (connection refused, a 5xx, a 404, a body that is not
        JSON), `npm audit --json` writes a document with ``message`` and an
        ``error`` object and no ``vulnerabilities`` key. Other npm errors, such
        as ENOLOCK, write ``{"error": {"code": ..., "summary": ...}}``. pnpm
        writes nothing to stdout and its error to stderr. Each of those used to
        convert to zero findings and report PASSED.

        A timed-out audit is a failure whatever it printed: the tool was
        stopped, so the document on stdout is whatever had been written by
        then, and treating a complete-looking one as a report swallowed the
        timeout. And an exit code of 0 proves nothing by itself: a proxy that
        answers HTML with 200, or a wrapper that eats the output, leaves no
        report while the exit code alone reads as a clean run.
        """
        report_key = _REPORT_KEY.get(binary)
        if result.get("timed_out"):
            reason = str(result.get("error") or "the command was stopped")
            return f"{binary} audit timed out, so its report is incomplete: {reason}"
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
            return f"{binary} audit {_without_an_exit_code(result)}"
        # A report counts exactly when it carries evidence the tool evaluated
        # the lockfile: findings under the report key, or the metadata block
        # every real clean report writes (npm 7+ counts its dependencies there,
        # pnpm its advisory totals). A bare report key with nothing else is
        # what a truncated or broken tool emits, and grading it clean would say
        # the dependencies were checked when nothing shows they were.
        if binary == "npm" and NpmAuditScanner._v1_report_has_evidence(audit_results):
            # npm 6 and earlier write the v1 report (advisories and the
            # counting metadata block), which the SARIF converter reads; it
            # counts as a report under the same evidence rule.
            return None
        if report_key == "advisories":
            # pnpm writes the v1 shape, so its evidence answer is the one
            # every reader of that shape gives (_v1_report_has_evidence).
            if NpmAuditScanner._v1_report_has_evidence(audit_results):
                return None
        elif (
            isinstance(audit_results, dict)
            and isinstance(audit_results.get(report_key), dict)
            and (
                audit_results[report_key]
                or isinstance(audit_results.get("metadata"), dict)
            )
        ):
            # npm 7+'s own shape, held to the same bar: findings under the
            # report key as a dict, or the counting metadata dict. A truthy
            # value of another type, or a null metadata beside an empty key,
            # is a truncated or broken reply, not evidence.
            return None
        if returncode in (None, 0):
            # Exit 0 with no parseable report: nothing was checked against the
            # lockfile, and the exit code alone cannot say otherwise. A
            # response with no exit code at all is worded as that, not as a 0.
            stdout = str(result.get("stdout") or "")
            what = (
                "printing nothing"
                if not stdout.strip()
                else "with output that is not an audit report"
            )
            ended = (
                "exited 0" if returncode == 0 else "ended with no exit code recorded"
            )
            return f"{binary} audit {ended} {what}, so no advisory was checked"
        # REDACTED BEFORE the excerpt is cut: the [:300] below could split a
        # value and leave a fragment the whole-spelling redaction misses.
        # shown_tool_stderr strips every complete escape code itself before
        # matching, so a non-color escape inside a value ("EDGE\x1b[KSECRET")
        # cannot split the match. With no values (the hook raised) the
        # excerpt is dropped: the message still names the exit code.
        stderr_lines = (
            []
            if values is None
            else [
                line.strip()
                for line in shown_tool_stderr(
                    str(result.get("stderr") or ""), values
                ).splitlines()
                if line.strip() and "complete log of this run" not in line
            ]
        )
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
    def _yarn_event(raw: str) -> Any:
        """The NDJSON event on one line of yarn output, or None.

        The line is read as written first, non-strictly so a raw control
        character inside a JSON string parses: the event's data then keeps
        the spelling a value holding escape codes was read with. A line that
        does not parse as written (JSON wrapped in color codes) is read from
        its stripped form.
        """
        as_written = raw.strip()
        stripped = ESCAPE_CODES.sub("", raw).strip()
        for candidate, strict in ((as_written, False), (stripped, True)):
            if not candidate.startswith("{"):
                continue
            try:
                return json.loads(candidate, strict=strict)
            except ValueError:
                continue
        return None

    @classmethod
    def _yarn_error_detail(cls, text: Any, values: Sequence[str] | None = ()) -> str:
        """The lines of yarn output that say what went wrong, joined and capped.

        yarn 1 writes errors as NDJSON ``{"type": "error"}`` events, which are
        reduced to their message. yarn 2+ and crashes write a Node stack trace,
        often after a line of minified source; stack frames and source lines are
        dropped, and lines naming an error (``Error:``, ``[HTTPError]:``) are
        preferred over the rest.

        ``values`` are the caller's env-read values, redacted out of
        everything printed BEFORE every split and cut below -- a value can
        hold a line break (a PEM, a multi-line token), a split is a cut, and
        per-line redaction matches neither half -- and AFTER the NDJSON
        parse, because a value that is also a JSON key or event-type word
        ("error" from a log-level variable, "data") would otherwise rewrite
        the event before ``json.loads`` reads it, the event would stop
        looking like an error, and yarn 1's only error message would be
        dropped. The decoded text is redacted as ONE piece in stream order
        (each error event's data closed with its line's own terminator, each
        run of plain lines with its own separators): a value whose line
        break falls exactly at a segment boundary has no whole spelling
        inside any one segment, so per-segment redaction would print both
        halves. Each event's message is still its data's first redacted
        line, recovered by a marker line carrying a per-call nonce; when the
        marker split no longer maps back to the segments (a value redacted
        across a boundary, or text that matched the marker), attribution is
        dropped and the one redacted text is read as plain lines instead.
        ``None`` means the caller's values hook raised: no detail, rather
        than lines shown with an empty value set, which would print what the
        values would have hidden.
        """
        if values is None:
            return ""
        lines: List[str] = []
        named: List[str] = []
        # The text that is decoded and redacted keeps the raw spelling on
        # both arms: a value that itself holds codes is matched as written,
        # and shown_tool_stderr strips the redacted result, so what prints
        # holds no code. A plain line is kept as written. An error event's
        # data comes from the line as written when that line parses
        # (``_yarn_event``), and only from its stripped form when it does
        # not (a line wrapped in color codes), where the data holds no
        # codes of its own to preserve.
        raw_text = str(text or "")

        def _shown(piece: str) -> str:
            return shown_tool_stderr(piece, values)

        # The decoded stream, in order: ("event", data + its line's own
        # terminator) and ("plain", a run of raw lines with their own
        # separators). Other typed events are dropped, as before: their
        # fields are not error text and are never printed.
        segments: List[tuple[str, str | None]] = []
        plain_run: List[str] = []

        def _close_plain() -> None:
            if plain_run:
                segments.append(("plain", "".join(plain_run)))
                plain_run.clear()

        for raw in raw_text.splitlines(keepends=True):
            event = cls._yarn_event(raw)
            if isinstance(event, dict) and "type" in event:
                if event.get("type") == "error":
                    data = str(event.get("data") or "").strip()
                    if data:
                        _close_plain()
                        body = raw.splitlines()[0] if raw else ""
                        segments.append(("event", data + raw[len(body) :]))
                continue
            plain_run.append(raw)
        _close_plain()
        if not segments:
            return ""

        texts = [piece for _, piece in segments]
        # ONE redaction over the whole decoded text: the only spelling a
        # value spanning two segments has.
        spanning = _shown("".join(texts))
        # The same redaction with a marker line between segments recovers
        # each segment's own redacted text in one pass. The marker's nonce
        # is fresh per call and the values and text both pre-exist it, so
        # neither can name it; the check below catches the residue (a
        # redaction that crossed a boundary, or a planted marker-shaped
        # line) rather than trusting the mapping.
        if len(texts) == 1:
            # One segment needs no recovery: the one redacted text IS it.
            pieces = [spanning]
        else:
            marker = cls._segment_marker()
            pieces = _shown(marker.join(texts)).split(marker)
            if len(pieces) != len(segments) or "".join(pieces) != spanning:
                # Per-segment attribution would print what the one-text
                # redaction hides. Read the one redacted text as plain lines.
                segments = [("plain", None)]
                pieces = [spanning]

        # The filters (stack frames, markers, over-long lines, source
        # locations) read the SHOWN line: a dropped line costs nothing, and
        # filtering raw lines first put a split before the redaction.
        for (kind, _), shown_piece in zip(segments, pieces):
            if kind == "event":
                message = shown_piece.strip().splitlines()
                if message:
                    named.append(message[0].strip()[:200])
                continue
            for shown_raw in shown_piece.splitlines():
                shown_line = shown_raw.strip()
                if (
                    not shown_line
                    or shown_line.startswith(("at ", "^", "Node.js v"))
                    or len(shown_line) > 200
                    or _SOURCE_LOCATION.match(shown_line)
                ):
                    continue
                lines.append(shown_line)
                if _NAMED_ERROR.search(shown_line):
                    named.append(shown_line)
        return " / ".join((named or lines)[:3])[:300]

    @staticmethod
    def _segment_marker() -> str:
        """One marker line for one _yarn_error_detail call.

        The nonce is drawn after the tool text and the values both exist, so
        neither can contain it; a line that matches it anyway fails the
        split-integrity check above and costs attribution, never redaction.
        """
        return f"ash-segment-{secrets.token_hex(16)}\n"

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
        cls,
        yarn_major: int,
        result: Dict[str, Any],
        values: Sequence[str] | None = (),
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

        The timeout flag is read first, as ``_audit_failure`` reads it: a
        timed-out run was stopped (or its stop did not end it, which leaves no
        exit code), so whatever it wrote is not a report, and the no-exit-code
        wording would call it an audit that did not run.
        """
        if result.get("timed_out"):
            reason = str(result.get("error") or "the command was stopped")
            return None, f"yarn audit timed out, so its report is incomplete: {reason}"
        returncode = result.get("returncode")
        if returncode is None and "error" in result:
            return None, f"yarn audit {_without_an_exit_code(result)}"
        stdout = _ANSI_ESCAPE.sub("", str(result.get("stdout") or ""))
        detail = cls._yarn_error_detail(result.get("stderr"), values)

        records: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {}
        is_report = False
        problems: List[str] = []

        # The problems keep their ORIGINAL text, line endings included: they
        # are redacted later (in _yarn_error_detail, or the fallback below)
        # and a value can hold a line break, so a strip-and-"\n"-rejoin here
        # would rewrite a CRLF or FF value's spelling before the redaction
        # could match it, and taking an error event's first raw line would
        # cut such a value in half. EVERY non-event segment is kept, blank
        # and whitespace-only ones and lines that parse as JSON without
        # being an event or advisory included: a value can span such a line,
        # and a dropped segment breaks the value's whole spelling, so the
        # redaction over the rejoined text would match neither piece.
        # Whether a segment counts as reportable problem TEXT is a separate
        # question (saw_problem, _has_problem_text): kept whitespace and kept
        # event lines complete a spanning value's spelling but are no error
        # of yarn's on their own.
        saw_problem = False
        if yarn_major < 2:
            for raw in _ndjson_lines(stdout):
                line = raw.strip()
                if not line:
                    problems.append(raw)
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    problems.append(raw)
                    continue
                if not isinstance(event, dict):
                    problems.append(raw)
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
                    # The RAW event line: _yarn_error_detail parses it back
                    # and its event branch redacts the data whole, then takes
                    # the first shown line -- the same reduction the stderr
                    # events get, so a multi-line event is its MESSAGE, not
                    # its trailing Error line, and its continuation lines
                    # cannot crowd later events out of the detail cap. A
                    # value's line breaks ride inside the JSON string, so its
                    # spelling survives to that one redaction. An event with
                    # no data has no message; the plain marker keeps the
                    # failure reportable (_has_problem_text).
                    text = str(data or "").strip()
                    problems.append(raw if text else "error event\n")
                elif "type" not in event:
                    # A JSON object that is no event at all: kept raw, like
                    # the non-JSON segments, for the same spanning-value
                    # reason -- the detail reader keeps such objects too.
                    problems.append(raw)
            saw_problem = _has_problem_text(problems)
        else:
            document: Any = None
            try:
                document = json.loads(stdout) if stdout.strip() else None
            except ValueError:
                document = None
            if isinstance(document, dict) and "advisories" in document:
                # A document counts with the evidence every reader of the v1
                # shape requires (_v1_report_has_evidence): found advisories,
                # or the counting metadata block every real clean report
                # writes (berry3-clean.json carries both).
                if cls._v1_report_has_evidence(document):
                    meta = document.get("metadata")
                    is_report = True
                    records.extend(
                        cls._v1_advisory_records(document.get("advisories") or {})
                    )
                    if isinstance(meta, dict):
                        metadata = {
                            "vulnerabilities": meta.get("vulnerabilities") or {}
                        }
            else:
                advisory_lines = 0
                for raw in _ndjson_lines(stdout):
                    line = raw.strip()
                    if not line:
                        problems.append(raw)
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        problems.append(raw)
                        saw_problem = True
                        continue
                    if isinstance(entry, dict) and "children" in entry:
                        advisory_lines += 1
                        record = cls._berry_advisory_record(entry)
                        if record is not None:
                            records.append(record)
                    elif isinstance(entry, dict) and "type" in entry:
                        # A StreamReport event line (info, warning): the
                        # runner narrating, not a problem of the audit's --
                        # the yarn 1 loop and the detail reader both read a
                        # dict with a "type" as an event. Kept raw all the
                        # same, so a value spanning this line keeps its whole
                        # spelling for the redaction.
                        problems.append(raw)
                    else:
                        # Not an advisory and not an event: kept raw, as the
                        # yarn 1 loop keeps its non-event segments, for the
                        # same spanning-value reason -- and a problem of
                        # yarn's own.
                        problems.append(raw)
                        saw_problem = True
                # yarn 4 prints nothing when it finds nothing, and exits 0
                # (tests/test_data/scanners/npmaudit/yarn/berry-clean.json).
                # yarn 2 and 3 write an npm v1 document even when clean
                # (berry3-clean.json), so for them nothing on stdout with
                # exit 0 is no evidence any advisory was checked.
                is_report = not saw_problem and (
                    advisory_lines > 0 or (returncode == 0 and yarn_major >= 4)
                )
                counts: Dict[str, int] = {}
                for record in records:
                    severity = str(record["severity"])
                    counts[severity] = counts.get(severity, 0) + 1
                metadata = {"vulnerabilities": counts}

        if saw_problem and not is_report:
            # The fallback is REDACTED BEFORE its cut, like every excerpt
            # here. With no values (the caller's hook raised) the excerpt is
            # dropped for a value-free note rather than shown with an empty
            # value set, which would print what the values would have hidden.
            if values is None:
                return None, (
                    "yarn audit reported an error (the tool's output is not shown)"
                )
            # The segments carry their own line endings, so they concatenate
            # rather than rejoin: a "\n" join would rewrite a CRLF or FF
            # value's spelling before the redaction could match it.
            problem_text = "".join(problems)
            reason = cls._yarn_error_detail(problem_text, values)
            if not reason:
                # The fallback redacts the SAME whole text before taking and
                # cutting its first line, for the same spanning-value reason
                # -- and only when the detail answered nothing, because it is
                # a second redaction pass over the same text and nobody reads
                # it when the detail named the failure.
                fallback = shown_tool_stderr(problem_text, values).strip().splitlines()
                reason = fallback[0].strip()[:300] if fallback else ""
            if detail:
                reason = f"{reason} / {detail}"[:300]
            return None, f"yarn audit reported an error: {reason}"
        if not is_report:
            suffix = f": {detail}" if detail else ""
            # On a clean-looking exit the wording says why that is a failure:
            # with no report, nothing shows any advisory was checked.
            checked = ", so no advisory was checked" if returncode in (None, 0) else ""
            # A response with no exit code at all is worded as that, not as a
            # literal None, matching _audit_failure's wording for npm.
            ended = (
                "ended with no exit code recorded"
                if returncode is None
                else f"exited {returncode}"
            )
            no_report = f"yarn audit {ended} without an audit report"
            return None, f"{no_report}{checked}{suffix}"

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

        One result per installed version of the advisory's package, and one for
        the package by name when the record lists no version (the tool counted
        the advisory, so it is a finding, not a rule with no result). The URI is
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
            score = _usable_cvss_score(record["cvss"])
            grade = {} if score is not None else _grade_properties(severity)
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
                if score is not None:
                    rule_props["security_severity"] = score
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
            # A record with no versions map (an advisory the tool listed with
            # no finding entries) is still the tool's finding: one result for
            # the package by name, its installed version unknown.
            copies = sorted(record["versions"].items()) or [(None, [])]
            for version, paths in copies:
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
                            installed_version=(
                                version
                                if version is not None
                                else record["vulnerable_versions"]
                            ),
                            vulnerable_versions=record["vulnerable_versions"],
                            recommendation=f"Update {pkg_name} to a non-vulnerable version",
                            severity=severity,
                            cwe=record["cwe"],
                            cvss=record["cvss"],
                            **per_copy,
                            **grade,
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
        # A v1 report can carry the metadata KEY with a null value, so the
        # value's type decides, not the key's presence: .get's default fires
        # only when the key is absent, and a null here crashed the conversion
        # of a report whose advisories had already passed the evidence rule.
        metadata = merged_results.get("metadata")
        report.runs[0].properties = PropertyBag(
            metrics=metadata.get("vulnerabilities", {})
            if isinstance(metadata, dict)
            else {}
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
                    # The advisory's own severity and range where it gives
                    # them. The package entry carries the highest severity of
                    # its advisories and the union of their ranges, so grading
                    # every result of the package at the package's severity
                    # read an unscored low or moderate advisory as the
                    # package's highest.
                    via_severity = str(via.get("severity") or severity)
                    via_level = _SEVERITY_LEVEL.get(via_severity, "warning")
                    via_range = via.get("range") or vuln_info.get("range", "*")
                    cvss = via.get("cvss") if isinstance(via.get("cvss"), dict) else {}
                    score = _usable_cvss_score(cvss)
                    grade = {} if score is not None else _grade_properties(via_severity)

                    # Create a rule for this vulnerability if it doesn't exist
                    if vuln_id not in rules_dict:
                        rule_props = {
                            "tags": [
                                "security",
                                "npm-audit",
                                via_severity,
                                f"tool_name::{self.config.name}",
                                f"tool_type::{self.tool_type or 'UNKNOWN'}",
                            ],
                        }
                        # Only attach security-severity when npm reported a
                        # usable CVSS score (_usable_cvss_score). It used to
                        # default to 0, which the SARIF severity normalizer
                        # reads as CVSS 0.0 and maps to INFO, downgrading a
                        # critical/high advisory that ships no CVSS number
                        # below the severity threshold (fail-open), and npm's
                        # own 0 for an advisory with no vector reached GHAS
                        # as security-severity "0". Without a score the
                        # result declares its grade from the severity word.
                        if score is not None:
                            rule_props["security_severity"] = score
                        rule = ReportingDescriptor(
                            id=vuln_id,
                            name=f"npm-audit-{vuln_id}",
                            shortDescription=MultiformatMessageString(text=title),
                            fullDescription=MultiformatMessageString(text=description),
                            helpUri=via.get("url", ""),
                            properties=PropertyBag(**rule_props),
                        )
                        rules_dict[vuln_id] = rule

                    # Create a result for each installed copy (node). An entry
                    # with no node names no installed copy, so it stays a rule
                    # with no result.
                    for node_path in vuln_info.get("nodes") or []:
                        # The URI keeps its historical shape, which existing
                        # path-based suppressions match; package_path holds
                        # the real install path.
                        pkg_location, identity = self._node_place(
                            pkg_name, node_path, lock_rel, lock_index
                        )
                        # A copy whose installed version the lockfile gives,
                        # and which this advisory's own range excludes, is
                        # not affected by it: npm lists every installed copy
                        # under each advisory of the package, so a fixed copy
                        # carried another copy's advisory and a GHSA split
                        # into several ranges was reported once per range on
                        # every copy. An uncertain answer keeps the result.
                        if (
                            via.get("range")
                            and _version_in_range(
                                identity.get(PACKAGE_VERSION_KEY), via_range
                            )
                            is False
                        ):
                            continue
                        result = Result(
                            ruleId=vuln_id,
                            level=via_level,
                            message=Message(
                                text=f"{title} in {pkg_name} {via_range}. {via.get('url', '')}"
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
                                vulnerable_versions=via_range,
                                recommendation=f"Update {pkg_name} to a non-vulnerable version",
                                severity=via_severity,
                                cwe=via.get("cwe", []),
                                cvss=cvss,
                                fix_available=vuln_info.get("fixAvailable", False),
                                **grade,
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
                    for node_path in vuln_info.get("nodes") or []:
                        pkg_location, identity = self._node_place(
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
                                # No CVSS score here, so the grade comes from
                                # the package's severity word.
                                **_grade_properties(severity),
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

        metadata = npm_audit_results.get("metadata")

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
                            # Reached only from _convert_per_lockfile, after an
                            # audit produced a report; the flag follows the
                            # graded rule (_sarif_execution_successful), so a
                            # lost lockfile or a codeless run never says
                            # success beside an ERROR status.
                            executionSuccessful=self._sarif_execution_successful(),
                            exitCode=self.exit_code,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target_path)
                            ),
                        )
                    ],
                    # metrics reads the metadata VALUE's type, never the key's
                    # presence: a v1 report can carry "metadata": null beside
                    # real advisories, and .get's default fires only when the
                    # key is absent.
                    properties=PropertyBag(
                        metrics=metadata.get("vulnerabilities", {})
                        if isinstance(metadata, dict)
                        else {}
                    ),
                )
            ],
        )

        return sarif_report

    @classmethod
    def _merge_metadata(
        cls, into: Dict[str, Any], value: Dict[str, Any], lock_file: Path | str
    ) -> None:
        """Fold one lockfile's ``metadata`` into the merged results' ``metadata``.

        By the type of each side, never by the key alone. npm 7+ counts its
        dependencies in a dict (``"dependencies": {"prod": 1, ...}``) where
        pnpm's v1 report counts them in an integer (``"dependencies": 5``), so
        a scan with one lockfile of each raised when the second was merged:
        ``dict.update`` on an integer, or ``+=`` of an integer onto a dict.
        The raise was caught per lockfile and recorded as a failed audit, which
        failed the whole scan over two valid reports.

        Two dicts merge recursively, two numbers add, two lists join, so the
        per-severity ``vulnerabilities`` counters sum across lockfiles (a
        ``dict.update`` kept only the last lockfile's). Two values of other
        kinds, or of different kinds, cannot be combined: the first stays and
        the disagreement is logged once, since it is a count across tools and
        not a finding.
        """
        for key, incoming in value.items():
            if key not in into:
                into[key] = copy.deepcopy(incoming)
                continue
            current = into[key]
            if isinstance(current, dict) and isinstance(incoming, dict):
                cls._merge_metadata(current, incoming, lock_file)
            elif cls._is_number(current) and cls._is_number(incoming):
                into[key] = current + incoming
            elif isinstance(current, list) and isinstance(incoming, list):
                current.extend(item for item in incoming if item not in current)
            elif current != incoming:
                ASH_LOGGER.debug(
                    f"npm-audit: metadata key {key!r} of {lock_file} "
                    f"({type(incoming).__name__}) does not combine with the "
                    f"merged value ({type(current).__name__}); keeping the first",
                    extra=NO_MARKUP,
                )

    @staticmethod
    def _is_number(value: Any) -> bool:
        """An int or a float, and not a bool (a bool adds as 0 or 1)."""
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def _response_summary(
        binary: str, result: Dict[str, Any], values: Sequence[str] | None
    ) -> str:
        """One line about an audit's response for ash.log.

        The exit code, the size of each stream, the response flags that are set,
        and the first line of stderr redacted with the scan's env-read values.
        Never the raw stdout or stderr: the whole response used to be logged at
        INFO as it came back, with the stderr a registry token or proxy
        credential can land in, while every other excerpt the scanner prints is
        redacted first. ``values`` None (the values hook raised) drops the
        excerpt rather than print it against an empty value set.
        """
        stdout = str(result.get("stdout") or "")
        stderr = str(result.get("stderr") or "")
        parts = [
            f"{binary} audit responded: exit {result.get('returncode')}",
            f"stdout {len(stdout)} chars",
            f"stderr {len(stderr)} chars",
        ]
        parts.extend(
            flag
            for flag in ("timed_out", "post_run_error", "spawn_failed")
            if result.get(flag)
        )
        if values is not None and stderr.strip():
            shown = shown_tool_stderr(stderr, values).strip().splitlines()
            if shown:
                # A registry URL on stderr can carry its credentials inline
                # (``https://user:token@host/``), and the user part is not one
                # of the env-read values, so the whole userinfo is masked.
                first = _URL_USERINFO.sub(r"\1***@", shown[0].strip())
                parts.append(f"stderr starts: {first[:200]}")
        return "; ".join(parts)

    def _sarif_exit_code_accepted(self) -> bool:
        """npm audit exits 0 or 1, and yarn classic exits a bitmask of the
        severity levels its audit found (1|2|4|8|16), so any code in 0-31
        from a run whose targets were all evaluated is a completed audit; the
        base set ``{0, 1}`` graded a HIGH-only audit's 8 unsuccessful.
        The audit that produced no report is already a failed
        target in the counters, which grade first. A code past the band, a
        signal death, and ASH's spawn-failure marker (127, outside the band)
        are no audit's."""
        return self.exit_code is not None and 0 <= self.exit_code <= 31

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — NpmAudit overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    #: Why npm-audit audits nothing offline. Recorded with every lockfile it skips.
    _OFFLINE_REASON = (
        "npm, pnpm and yarn audit dependencies only against the package registry's "
        "advisory service, which offline mode does not reach, so this lockfile was "
        "not audited"
    )

    def _offline_skips(
        self, package_files: List[str], target_type: str
    ) -> List[Dict[str, str]]:
        """The not-scanned entries for every lockfile beside *package_files*.

        The one lockfile selection scan() audits by (LOCKFILE_NAMES, so
        npm-shrinkwrap.json counts): a shrinkwrap-only package used to record
        nothing here and read as a clean, empty report offline.
        """
        skipped = []
        for item in package_files:
            lock_file = self._lockfile_beside(item)
            if lock_file is not None:
                shown = self._shown_path(lock_file, target_type)
                skipped.append({"path": shown, "reason": self._OFFLINE_REASON})
        return skipped

    def _skip_offline(
        self, package_files: List[str], target: Path, target_type: str
    ) -> None:
        """Record every lockfile as not audited.

        ``npm audit`` asks the registry which dependencies are vulnerable, and
        nothing is cached for it: offline, ``npm audit --json --offline`` on a
        lockfile pinning a version with known advisories exited 0 with none
        (npm 10.9.4), ``pnpm audit --offline`` sent the dependency list to the
        registry anyway (pnpm 12.6.0), and ``yarn npm audit`` has no offline mode.
        So no audit runs, and ``inputs_not_scanned`` names each lockfile in the
        results and the summaries. ``scan`` then returns False, which records the
        scanner MISSING (see there); no target count is claimed for that, as for any
        scanner that did not run. With no lockfile there was nothing the network
        would have audited, so ``targets_attempted = 0`` grades that target SKIPPED.
        """
        skipped = self._offline_skips(package_files, target_type)
        self.inputs_not_scanned = skipped
        if not skipped:
            # None elsewhere: no claim (scanner_executor._target_count_attr).
            self.targets_attempted: int | None = 0
        else:
            self._plugin_log(
                f"Offline, npm-audit audits nothing: {self._OFFLINE_REASON}. Not "
                f"audited: {', '.join(entry['path'] for entry in skipped)}. "
                "Recorded MISSING; --exclude-scanners npm-audit leaves it out.",
                target_type=target_type,
                level=logging.WARNING,
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
        # global_ignore_paths stays None when the caller gave none: the package
        # selection then computes the list from the config as the orchestrator
        # does (_package_manifests); an empty list given is an empty list.
        # Per call, above every return, as in cfn_nag_scanner: each lockfile audited
        # counts as a target, so a tree with none to audit reads as SKIPPED rather
        # than as a clean audit. exit_code is None until an audit runs, so a scan that
        # starts no npm, yarn or pnpm audit (a lockfile whose package manager is absent)
        # reports no exit code; the version check before the scan is not an audit.
        self.targets_attempted = 0
        self.targets_failed = 0
        self.inputs_not_scanned = []
        self.exit_code = None
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
                            executionSuccessful=self._sarif_execution_successful(),
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
        # The dependency check _pre_scan runs asks npm for its version, and that answer
        # went through _process_command_response like any subprocess. It is not an
        # audit, so the exit code starts again here.
        self.exit_code = None
        if not validated or not self.dependencies_satisfied:
            if self._scanner_offline():
                # The dependency check refused offline (validate_plugin_dependencies).
                # The lockfiles it would have audited are still recorded as not
                # scanned, with the reason and the warning, so the results and the
                # summaries name them; False is what records the row MISSING.
                self._skip_offline(
                    self._package_manifests(target_type, global_ignore_paths),
                    target,
                    target_type,
                )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results.json")
            results_file.parent.mkdir(exist_ok=True, parents=True)

            # Find all files to scan from the scan set. Shared with
            # nothing_to_scan_reason, which answers from this same selection.
            scannable = self._package_manifests(target_type, global_ignore_paths)
            joined_files = "\n- ".join(scannable)
            # Logged directly with markup off rather than through _plugin_log, whose
            # prefix is markup: escaping the paths instead would write "\[" into
            # ash.log and its JSONL copy (see NO_MARKUP in utils/log.py).
            ASH_LOGGER.log(
                15,
                f"({self.config.name} @ {target_type})\tFound {len(scannable)} "
                f"package locks:\n- {joined_files}",
                extra=NO_MARKUP,
            )

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

            if self._scanner_offline():
                self._skip_offline(scannable, target, target_type)
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                # MISSING, as snyk-code is offline: what the audit depends on is
                # unavailable, so the completeness gate fails the scan rather than
                # let these dependencies read as checked. False is how scan()
                # reports that (scanner_executor records the container MISSING).
                # Per target, so the plugin's own dependencies_satisfied is left
                # alone and a target without lockfiles is graded on its own.
                if self.inputs_not_scanned:
                    return False
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
            # The ONE guarded read of the overridable values hook for this
            # scan's message paths (_values_to_redact's guarding rule): the
            # yarn probe detail, the probe excerpt and both audit-failure
            # builders reuse it. None means the hook raised: those best-effort
            # texts drop their tool excerpts -- never an empty value set,
            # which would print what the values would have hidden -- and the
            # scan itself goes on.
            # A bare string it answers is one value, not its characters (the
            # guarded read normalizes it); a hook that raised or answered no
            # value set reads as None here too.
            record_values: Sequence[str] | None = guarded_values_read(self).values
            for item in scannable:
                package_file = Path(item)
                lock_file = self._lockfile_beside(package_file)
                if lock_file is not None:
                    self.targets_attempted += 1
                    package_dir = package_file.parent

                    try:
                        # Run npm audit
                        if lock_file.name == "yarn.lock":
                            binary = "yarn"
                        elif lock_file.name == "pnpm-lock.yaml":
                            binary = "pnpm"
                        else:
                            binary = "npm"

                        # npm, pnpm and yarn follow links, so a file they read
                        # that is a link leaving the scanned tree hands them a
                        # file from elsewhere. That package is not audited; the
                        # file is recorded, and its dependencies go unchecked,
                        # which fails the scan like any unaudited lockfile.
                        child_options = self._package_manager_options(
                            target_results_dir, target
                        )
                        refused = refused_inputs(
                            binary,
                            package_dir,
                            roots=child_options["roots"],
                            skip=child_options["skip"],
                        )
                        if refused:
                            for path, reason in refused:
                                shown = self._shown_path(path, target_type)
                                self.inputs_not_scanned.append(
                                    {"path": shown, "reason": reason}
                                )
                                audit_failures.append(
                                    f"{shown}: {reason}, so its package was not audited"
                                )
                            continue

                        # Check that the binary is installed before
                        # attempting to run it (#180).  npm is already
                        # validated in validate_plugin_dependencies, but
                        # yarn and pnpm may not be present.
                        # A failed target, not a failed scan. Passing the lockfile
                        # over left its dependencies unchecked while the scan read as
                        # clean; failing the whole scan discarded the findings of
                        # every lockfile that was audited. Counted and recorded as an
                        # unevaluated target, the other lockfiles' findings are kept
                        # while the row grades ERROR naming this lockfile (the
                        # executor refuses PASSED over a recorded name), and the
                        # completeness gate's partial-coverage arm still names the
                        # shortfall and exits 1.
                        if binary != "npm" and find_executable(binary) is None:
                            message = (
                                f"{lock_file}: {binary} is not installed, so it was "
                                f"not audited. Install {binary} to audit it"
                            )
                            self.targets_failed += 1
                            self.errors.append(message)
                            # No advisory ran against this lockfile, and nothing
                            # raises for it (the other lockfiles' findings are
                            # kept), so the name is recorded and the executor
                            # refuses to grade the run PASSED over it.
                            self.record_unevaluated_target(lock_file)
                            # The lockfile path is the repository's, so it is data:
                            # a directory named "[/x]" is a closing tag to Rich.
                            ASH_LOGGER.warning(f"npm-audit: {message}", extra=NO_MARKUP)
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
                        #
                        # This and the two offline branches below are not reached by a
                        # scan: validate_plugin_dependencies refuses offline, and
                        # _pre_scan returns before this loop. They are kept for a
                        # caller that skips that check, so it gets a failure for an
                        # audit that cannot run offline rather than a clean report
                        # (test_npm_audit_absent_package_manager.py,
                        # test_npm_audit_offline_env.py).
                        offline_env = (
                            {"COREPACK_ENABLE_NETWORK": "0"}
                            if self._scanner_offline()
                            else {}
                        )

                        # yarn 2 and later dropped `yarn audit` for `yarn npm
                        # audit`, and print a different report. Which yarn runs
                        # depends on the project (corepack honours its
                        # `packageManager` field), so ask it from there. The probe
                        # runs no yarn-path and names no settings file for yarn
                        # 2+ to read (YARN_RC_FILENAME). It cannot pass yarn 1's
                        # --no-default-rc without knowing the version, so a yarn 1
                        # probe in the package directory (a sandbox, or a system
                        # temporary directory inside the scanned tree) still reads
                        # .yarnrc and .npmrc there, with its yarn-path ignored
                        # (see utils/package_manager_child.py).
                        yarn_major: int | None = None
                        cmd = [binary, "audit", "--json"]
                        if binary == "yarn":
                            with package_manager_child(
                                binary, package_dir, **child_options
                            ) as probe:
                                version_result = self._run_subprocess(
                                    command=[binary, *probe.leading_args, "--version"],
                                    stdout_preference="return",
                                    stderr_preference="return",
                                    cwd=probe.cwd,
                                    env={**probe.env, **offline_env},
                                    timeout=self._effective_scan_timeout(),
                                )
                            yarn_major = self._yarn_major(version_result.get("stdout"))
                            if yarn_major is None:
                                detail = self._yarn_error_detail(
                                    version_result.get("stderr")
                                    or version_result.get("error"),
                                    record_values,
                                )
                                # REDACTED BEFORE the excerpt is cut, like
                                # every tool-output excerpt here; the helper
                                # strips every complete escape code so a
                                # non-color escape cannot split a value's
                                # match. With no values (the hook raised)
                                # the excerpt degrades to its value-free
                                # placeholder.
                                printed = (
                                    shown_tool_stderr(
                                        str(version_result.get("stdout") or ""),
                                        record_values,
                                    ).strip()[:80]
                                    if record_values is not None
                                    else "(not shown)"
                                )
                                audit_failures.append(
                                    f"{lock_file}: could not tell which yarn "
                                    "version runs here; `yarn --version` printed "
                                    f"{printed!r}" + (f" ({detail})" if detail else "")
                                )
                                continue
                            if yarn_major >= 2:
                                # --all: every workspace in the project, as npm
                                # audits a workspace from its one lockfile.
                                # Without it yarn audits the root workspace's
                                # dependencies only, and in a monorepo the
                                # member workspaces' dependencies are never
                                # checked. --recursive: the whole tree below
                                # each; without it yarn checks direct deps only.
                                cmd = [
                                    binary,
                                    "npm",
                                    "audit",
                                    "--json",
                                    "--all",
                                    "--recursive",
                                ]

                        # npm and pnpm run from a private copy of the package's
                        # manifest and lockfile, yarn from the package directory
                        # (#99), none reading the repository's settings files.
                        with package_manager_child(
                            binary, package_dir, yarn_major=yarn_major, **child_options
                        ) as child:
                            result = self._run_subprocess(
                                command=[cmd[0], *child.leading_args, *cmd[1:]],
                                results_dir=target_results_dir,
                                stdout_preference="both",
                                stderr_preference="both",
                                cwd=child.cwd,
                                env=child.env,
                                timeout=self._effective_scan_timeout(),
                            )
                        # One redacted line about the response, never the raw
                        # streams: the runner returns them unredacted for the
                        # caller to redact, and stdout is the report itself,
                        # written beside the results. The tool's text names
                        # the project's paths: data to Rich, so a "[/x]" in it
                        # cannot raise.
                        ASH_LOGGER.debug(
                            self._response_summary(binary, result, record_values),
                            extra=NO_MARKUP,
                        )

                        # npm audit returns non-zero exit code when vulnerabilities are found
                        # but we still want to process the output
                        audit_results: Any = None
                        if yarn_major is not None:
                            audit_results, failure = self._parse_yarn_audit(
                                yarn_major, result, record_values
                            )
                        else:
                            if result.get("stdout", None):
                                try:
                                    audit_results = json.loads(
                                        result.get("stdout", None)
                                    )
                                except json.JSONDecodeError:
                                    ASH_LOGGER.warning(
                                        f"Failed to parse npm audit output for {package_dir}",
                                        extra=NO_MARKUP,
                                    )
                            failure = self._audit_failure(
                                binary, result, audit_results, record_values
                            )
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
                                # yarn's records, so results.json keeps every
                                # yarn lockfile's advisories: with no branch
                                # for this key, every yarn lockfile after the
                                # first was dropped from the merged file (the
                                # SARIF, converted per lockfile, had them).
                                yarn_records = audit_results.get(_YARN_ADVISORIES_KEY)
                                if isinstance(yarn_records, list):
                                    all_results.setdefault(
                                        _YARN_ADVISORIES_KEY, []
                                    ).extend(yarn_records)
                                # Update metadata. A v1 report can carry the
                                # key with a null value, so the value's type
                                # decides on both sides: only a dict merges,
                                # and a null already merged into is replaced,
                                # never read. .items() on the null graded this
                                # valid report as a failed audit.
                                if isinstance(audit_results.get("metadata"), dict):
                                    if not isinstance(
                                        all_results.get("metadata"), dict
                                    ):
                                        all_results["metadata"] = {}
                                    self._merge_metadata(
                                        all_results["metadata"],
                                        audit_results["metadata"],
                                        lock_file,
                                    )
                    except Exception as e:
                        ASH_LOGGER.warning(
                            f"Failed to run npm audit in {package_dir}: {str(e)}",
                            extra=NO_MARKUP,
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
                # Online and offline alike. Offline never reaches here in a scan,
                # because validate_plugin_dependencies refuses it first; a caller
                # that skips that check still gets a failure, not a clean report.
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
                                    executionSuccessful=self._sarif_execution_successful(),
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
        from automated_security_helper.utils.command_safe_stream import (
            json_commands_broken,
        )
        from automated_security_helper.utils.console import echo_raw

        # The SARIF repeats the tree's file names: no "##name[" of theirs is a
        # CI command where this prints, and the JSON is still the same document.
        echo_raw(
            json_commands_broken(
                report.model_dump_json(
                    indent=2,
                    by_alias=True,
                    exclude_unset=True,
                )
            )
        )
