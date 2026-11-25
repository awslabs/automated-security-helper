# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""License and provenance detection over the scan target using ScanCode Toolkit.

ScanCode Toolkit (https://github.com/aboutcode-org/scancode-toolkit, Apache-2.0) matches
the text of files against its bundled license index and reports which licenses a file
carries. This scanner reports each match as an INFO finding. It is license and
provenance information, not a vulnerability: a license that is not OSI-approved, or a
copyleft one, is a policy question for the project, not a security severity.

Opt-in by module listing
------------------------
ScanCode reads every file in the tree and matches it against thousands of license
rules, so it is slow on a large tree. The opt-in is listing the plugin module in
``ash_plugin_modules`` (or ``--ash-plugin-modules``): a scan that does not list it is
unchanged. Once listed the scanner is enabled like every other community scanner, so
``--scanners scancode`` runs only it. (An earlier cut set ``enabled = False``, which
made the documented one-run form a no-op: ASH runs a scanner only when it is both in
the ``--scanners`` allowlist and enabled.)

Scan flow
---------
The template flow of ``ScannerPluginBase``: ``_execute_scan`` builds the argv and the
base class runs it. ScanCode has no SARIF writer, so ``_read_results_file`` converts
the JSON ScanCode wrote (``--json=<file>``) into a SARIF document, and the base class
validates that document as it would a tool-written one.

What it runs (read from ScanCode's own documentation and source)
-----------------------------------------------------------------
``scancode --license --json=<file> --quiet [--license-score=<n>] -- <path>``

* ``--license`` (``-l``): scan for licenses.
* ``--json=FILE``: write compact JSON to FILE. The top-level keys are ``headers`` and
  ``files``; ``headers[0].tool_version`` carries the version.
* ``--license-score=<0-100>``: drop matches below the score. Default 0.
* ``--quiet`` (``-q``): no summary or progress on the console.
* ``--license-text`` is NOT passed: the matched text is a copy of the scanned file's
  content and is not needed to place a finding.
* Each ``files`` entry has ``path`` (relative to the directory ScanCode was given,
  with that directory's name as the first segment), ``type`` (``file`` or
  ``directory``), ``license_detections`` and ``scan_errors``. Each detection has
  ``matches``; each match has ``license_expression_spdx``, ``start_line``,
  ``end_line`` and ``score``.

Severity
--------
Every match is INFO: ``issue_severity`` is ``INFO`` and the SARIF level is ``none``,
the same pairing hadolint uses for its lowest tier. Level and ASH severity agree.

Exit status
-----------
ScanCode exits 0 when every stage and every file succeeded and 1 when any resource has
``scan_errors``, a timeout occurred, or a plugin raised. ``success_exit_codes`` is
``{0}``: a run that reports a scan error is not a complete license inventory, so it
fails the scan rather than reporting a partial one as clean.

Offline
-------
The license index ships inside the ``scancode-toolkit`` package, so a scan needs no
network.

Sandbox
-------
The strict default (no network, baseline environment). ScanCode reads only the target.
"""

from __future__ import annotations

import hashlib
import logging
import os
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
)

from pydantic import Field, PrivateAttr

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
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
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The ScanCode Toolkit release the converter was written against (PyPI's latest on
#: 2026-11-18). Exact on purpose: the JSON layout is versioned by the tool, not by a
#: schema ASH can pin. ``options.tool_version`` overrides it.
SCANCODE_DEFAULT_VERSION_CONSTRAINT = "==32.5.0"

#: ScanCode 32.x supports CPython 3.9 to 3.13 by its documentation and requires
#: ``>=3.10`` on PyPI. Pinned so uv does not pick an interpreter with no wheels.
SCANCODE_PYTHON_REQUEST = ">=3.10,<3.14"

#: Extra requirements installed beside the tool (uv ``--with``): see
#: ``_get_tool_with_dependencies``. Whitespace-free, as the install builder requires.
SCANCODE_WITH_DEPENDENCIES = ("pluggy<1.7",)

_COMMAND = "scancode"
_PACKAGE = "scancode-toolkit"
_INFORMATION_URI = "https://github.com/aboutcode-org/scancode-toolkit"

#: The one severity every license match gets, and the SARIF level that agrees with it.
LICENSE_SEVERITY = "INFO"
LICENSE_LEVEL = "none"

#: Rule id used when a match carries no license expression at all.
UNKNOWN_RULE = "unknown-license"


class ScanCodeScannerConfigOptions(ScannerOptionsBase):
    license_score: Annotated[
        int,
        Field(
            ge=0,
            le=100,
            description=(
                "Drop license matches whose score is lower than this, passed as "
                "ScanCode's --license-score. A number from 0 to 100; 0 keeps every "
                "match."
            ),
        ),
    ] = 0
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.scancode.options.tool_version"),
        Field(
            description=(
                "Version constraint for the scancode-toolkit installation, in pip "
                "requirement syntax. Unset uses the release the converter is tested "
                "against. A value that is not a version constraint is ignored with a "
                "warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 1200


class ScanCodeScannerConfig(ScannerPluginConfigBase):
    name: Literal["scancode"] = "scancode"
    #: Enabled once the module is listed; the module listing is the opt-in.
    enabled: bool = True
    options: Annotated[
        ScanCodeScannerConfigOptions,
        Field(description="Configure the scancode scanner"),
    ] = ScanCodeScannerConfigOptions()


def _rule_id(match: Dict[str, Any]) -> str:
    """The SPDX expression of a match, else ScanCode's own, else ``UNKNOWN_RULE``."""
    for key in ("license_expression_spdx", "license_expression"):
        value = match.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return UNKNOWN_RULE


def _is_line(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def convert_scancode_result(
    document: Any,
    *,
    uri_prefix: str = "",
    strip_first_segment: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert a ScanCode ``--json`` document into a SARIF 2.1.0 dict.

    ``strip_first_segment`` is the name of the directory ScanCode was given: its paths
    begin with it. ``uri_prefix`` (a posix path relative to the source directory, ``""``
    for the source directory itself) is prepended to place a result in the repository.

    Raises:
        ScannerError: ``document`` is not a ScanCode result (not an object, or no
            ``files`` list), so an unreadable report is never read as a clean scan.
    """
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise ScannerError(
            "the ScanCode output is not a scan result object with a 'files' list"
        )
    version: Optional[str] = None
    headers = document.get("headers")
    if isinstance(headers, list) and headers and isinstance(headers[0], dict):
        raw_version = headers[0].get("tool_version")
        if isinstance(raw_version, str) and raw_version:
            version = raw_version

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, int, int]] = set()
    for entry in document["files"]:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            continue
        path = str(entry.get("path") or "").replace("\\", "/").lstrip("/")
        if strip_first_segment and (
            path == strip_first_segment or path.startswith(strip_first_segment + "/")
        ):
            path = path[len(strip_first_segment) :].lstrip("/")
        if not path:
            continue
        uri = f"{uri_prefix.rstrip('/')}/{path}" if uri_prefix else path
        for detection in entry.get("license_detections") or []:
            if not isinstance(detection, dict):
                continue
            for match in detection.get("matches") or []:
                if not isinstance(match, dict) or not _is_line(match.get("start_line")):
                    continue
                start = int(match["start_line"])
                end = match.get("end_line")
                end = int(end) if _is_line(end) and end >= start else start
                rule = _rule_id(match)
                key = (rule, uri, start, end)
                if key in seen:
                    continue
                seen.add(key)
                rules.setdefault(
                    rule,
                    {
                        "id": rule,
                        "shortDescription": {"text": f"License detected: {rule}"},
                        "defaultConfiguration": {"level": LICENSE_LEVEL},
                    },
                )
                score = match.get("score")
                score_text = (
                    f" (match score {score:g})"
                    if isinstance(score, (int, float)) and not isinstance(score, bool)
                    else ""
                )
                digest = hashlib.sha256(
                    "\0".join((rule, uri, str(start), str(end))).encode()
                ).hexdigest()
                results.append(
                    {
                        "ruleId": rule,
                        "level": LICENSE_LEVEL,
                        "message": {
                            "text": f"ScanCode detected license {rule}{score_text}."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": start, "endLine": end},
                                }
                            }
                        ],
                        "partialFingerprints": {"scancode/v1": digest},
                        "properties": {
                            "issue_severity": LICENSE_SEVERITY,
                            "tags": ["license", "provenance"],
                        },
                    }
                )

    driver: Dict[str, Any] = {
        "name": "ScanCode Toolkit",
        "informationUri": _INFORMATION_URI,
        "rules": list(rules.values()),
    }
    if version:
        driver["version"] = version
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


@ash_scanner_plugin
class ScanCodeScanner(ScannerPluginBase[ScanCodeScannerConfig]):
    """License and provenance detection over the scan target using ScanCode."""

    #: A Python tool run through uv, but not a Python-only scan: it reads any file.
    python_only: ClassVar[bool | None] = False

    # The license index ships in the package and a scan makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # 0 only: exit 1 means a scan error or timeout, an incomplete inventory.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; ScanCode reads only the target.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # ScanCode's stderr can name paths of the scanned tree, and the scanner executor
    # copies errors into the scan's results: the base class keeps the stream out of
    # both and out of the failure text. It stays in the log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "scancode"

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. ScanCode's output is its own JSON (captured fixtures in
    #: tests/test_data/scanners/scancode/captured), converted to SARIF by
    #: ``convert_scancode_result``, so native fields name that JSON.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='match "license_expression_spdx" (else '
            '"license_expression"; else the constant unknown-license)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native severity) constant level none plus "
            'properties "issue_severity" INFO, set by the converter and '
            "_post_process_sarif",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='files[] "path", first segment (the scanned directory '
            "name) stripped by the converter",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='match "start_line" / "end_line"',
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="ScanCode matches carry line numbers only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='match "license_expression_spdx" and "score", assembled '
            "into the result text by the converter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="license matches name a file location, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="license matches name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="only --license is run; package detection (--package) is not "
            "requested, so the output carries no package data",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="only --license is run; the output carries no package data",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="only --license is run; the output carries no package data",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="license matches carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="license matches carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["scancode/v1"], a sha256 the '
            "converter computes over rule, uri, start and end line (not a native "
            "field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="license matches carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="license matches carry no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.DROPPED,
            native_field='match "matched_text" (present only with --license-text)',
            reason="--license-text is never passed: the matched text is a copy of "
            "the scanned file's content and is not needed to place a finding",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='match "rule_url"',
            reason="the converter does not carry the per-rule URL into the SARIF "
            "rules; a later unit could map it",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result PropertyBag tags license and provenance, written "
            "by the converter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the converter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="scancode",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "scancode_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): the license index ships in the "
                    "scancode-toolkit package and a scan makes no network call"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SCA,
                selection="`scancode --license` over the whole target directory; "
                "every file is read (module header)",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one scancode run per scan target (source, then "
                "the converted target)",
                python_only=False,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH publishes no per-platform "
                "download table for it and does not redistribute it (the "
                "scancode-toolkit data package is CC-BY-4.0), so an install runs "
                "uv on the host and an unsupported platform fails at install",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.CONSTANT,
                note="every license match is INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="no tool-side silencing surface is read: ASH passes "
                "no --ignore and runs scancode with only --license, --json, "
                "--quiet and an optional --license-score; ASH suppressions are the "
                "surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under scancode/v1 over rule, uri and lines",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (license_score, tool_version, "
                "install_timeout); no rules path",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 only: exit 1 means a scan error or timeout, an "
                "incomplete inventory",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=(
                    "ash_scancode_plugins in ash_plugin_modules",
                    "options.license_score",
                ),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no manifest or git repository is required; every file is read",
            ),
        )
    )

    # The target of the current run, so the report's paths can be anchored.
    _current_target: Optional[Path] = PrivateAttr(default=None)

    @property
    def _opts(self) -> ScanCodeScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, ScanCodeScannerConfigOptions):
            return options
        return ScanCodeScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ScanCodeScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SCA
        self.use_uv_tool = True
        self.uv_tool_package_name = _PACKAGE
        self._setup_uv_tool_install_commands()
        self.description = (
            "ScanCode Toolkit detects the licenses files carry, reported as INFO."
        )
        # The argv is built in _execute_scan; nothing from the base resolver may add
        # a token ScanCode would misread.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        return self._opts.tool_version or SCANCODE_DEFAULT_VERSION_CONSTRAINT

    def _get_tool_python_request(self) -> str | None:
        return SCANCODE_PYTHON_REQUEST

    def _get_tool_with_dependencies(self) -> List[str] | None:
        """``pluggy<1.7``: scancode-toolkit 32.5.0 declares ``pluggy>=1.0.0`` only, and
        with pluggy 1.7.0 every ``scancode`` command exits 1 at import
        (``ValueError: did not find any 'pre_scan' hooks``). Measured 2026-11-25 with
        a ``uv tool install``; pluggy 1.5.0 and 1.6.0 both run."""
        return list(SCANCODE_WITH_DEPENDENCIES)

    def validate_plugin_dependencies(self) -> bool:
        """uv tool, then a ``scancode`` already on PATH, then an install."""
        if self.dependency_unavailable_reason:
            return False
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
            info = self._get_tool_installation_info()
            if info.get("available"):
                return self._select_tool_execution(info)
            if self._install_uv_tool(timeout=self._opts.install_timeout):
                self.dependencies_satisfied = True
                return True
        if get_uv_tool_command(_COMMAND) is not None:
            return True
        ASH_LOGGER.warning(
            "scancode executable not found. Install it with `ash dependencies "
            "install --config-overrides 'ash_plugin_modules+=[\"automated_security_"
            "helper.plugin_modules.ash_scancode_plugins\"]' --tool scancode`."
        )
        return False

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ScanCodeScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ScanCode walks the target itself, so ASH cannot tell in advance."""
        return None

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full ScanCode argv: every option one ``--flag=value`` token, the path
        after ``--`` so it cannot be read as a flag."""
        args: List[str] = [
            self.command or _COMMAND,
            "--license",
            f"--json={results_file.as_posix()}",
            "--quiet",
        ]
        score = self._opts.license_score
        if score:
            args.append(f"--license-score={score}")
        args.extend(["--", Path(target).absolute().as_posix()])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one ScanCode run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated into ScanCode options.
        """
        if self.results_dir is None:
            raise ScannerError("ScanCodeScanner has no results directory")
        # One instance scans source then converted; start each run from a clean code.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "scancode.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        # Where this run's paths are anchored, for _read_results_file.
        self._current_target = Path(target).absolute()
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Read ScanCode's JSON and return it as a SARIF dict.

        Raised before reading when the exit code is not accepted, so a partial
        report from a run that hit a scan error or timeout is not graded as complete.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"scancode exited {self.exit_code}; it exits 0 only when every file "
                "was scanned, so this run is not a complete license inventory"
            )
        document = super()._read_results_file(results_file)
        if document is None:
            return None
        target = self._current_target
        prefix = ""
        strip: Optional[str] = None
        if target is not None:
            try:
                is_dir = target.is_dir()
            except OSError:
                is_dir = False
            if is_dir:
                strip = target.name
                try:
                    relative = target.relative_to(self._source_dir().absolute())
                    prefix = "" if relative == Path(".") else relative.as_posix()
                except ValueError:
                    prefix = ""
        return convert_scancode_result(
            document, uri_prefix=prefix, strip_first_segment=strip
        )

    def _committed_file_test(self) -> Callable[[Path], bool]:
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

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results located under ASH's own output directory inside ``target``.

        ScanCode has no exclude option used here, so when the output directory is
        inside the target it reads ASH's own files. A file the repository committed
        there is kept.
        """
        if self.context is None:
            return
        roots_rel: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            roots_rel.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in roots_rel:
                roots_rel.append(relative)
        if not roots_rel:
            return
        target_abs = Path(target).absolute()
        roots = [Path(os.path.normpath(target_abs / r)) for r in roots_rel]
        committed = self._committed_file_test()

        def under_output(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in roots) and (
                    not committed(path)
                ):
                    return True
            return False

        for run in sarif_report.runs or []:
            if run.results:
                run.results = [r for r in run.results if not under_output(r)]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files; level and ``issue_severity`` already agree."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            if result.properties is not None:
                setattr(result.properties, "issue_severity", LICENSE_SEVERITY)  # noqa: B010
        return sarif_report


__all__ = [
    "LICENSE_LEVEL",
    "LICENSE_SEVERITY",
    "SCANCODE_DEFAULT_VERSION_CONSTRAINT",
    "ScanCodeScanner",
    "ScanCodeScannerConfig",
    "ScanCodeScannerConfigOptions",
    "convert_scancode_result",
]
