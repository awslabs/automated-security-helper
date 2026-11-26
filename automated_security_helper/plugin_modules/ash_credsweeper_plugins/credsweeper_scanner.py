# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CredSweeper community scanner: ML-scored credential detection over the scan target.

CredSweeper (https://github.com/Samsung/CredSweeper, MIT) looks for credentials in
files with regular-expression rules, then scores each candidate with a small ONNX
model. This plugin runs the ``credsweeper`` command line over the source directory
and converts its JSON report to SARIF.

Not on by default in a scan that does not list the module: listing
``automated_security_helper.plugin_modules.ash_credsweeper_plugins`` in
``ash_plugin_modules`` is the opt-in. A scan that does not list it is unchanged.
It overlaps the builtin detect-secrets and gitleaks scanners; a credential more than
one of them finds is reported by each.

Scan flow
---------
The template flow: ``_execute_scan`` builds the argv and the report path, the base
``scan()`` runs the tool, and ``_read_results_file`` turns the JSON array CredSweeper
wrote into a SARIF document, which the base validates as it does a tool's own SARIF.
CredSweeper has no SARIF writer, so the conversion is the plugin's.

Invocation
----------
Read from the CredSweeper guide (docs/source/guide.rst) and ``credsweeper/main.py``
at the repository's default branch, and from PyPI for the release (1.19.6, the latest
when this was written). Each option is one ``--flag=value`` token, so no path is read
as the start of the next flag (``--path`` and ``--save-json`` take a variable number
of values):

- ``--path=<target>``: the directory to scan. ``.`` for the source directory, run with
  the source directory as the working directory, so the report's paths are
  source-relative.
- ``--save-json=<file>``: the report. Without a value the tool names its own file.
- ``--no-stdout``, ``--no-color``, ``--no-progress``: nothing is printed, so the
  subprocess log holds no finding.
- ``--hashed``: "line, variable, value will be hashed in output", so the report left
  on disk holds no credential text. The converter never reads those fields either.
- ``--no-error``: with ``--error`` the tool exits 1 when it finds credentials, the
  same code it uses for a failed scan. Off, a run exits 0 whatever it found.

Never passed, because each reads from the scanned tree or hides findings:
``--config``, ``--rules``, ``--denylist``, ``--skip_ignored`` (reads .gitignore),
``--ml_threshold``, ``--ml_model``, ``--ml_config``, ``--severity``, ``--confidence``,
``--git``, ``--diff_path``, ``--doc``, ``--depth``. The tool's defaults are kept: its
built-in rules, model and ML threshold (medium).

Exit status and output
----------------------
``main()`` returns 0 for a completed scan (findings or none) and 1 when the scan
failed or no input mode was given, from the source. ``success_exit_codes`` is
therefore ``{0}``. A report on disk next to any other code is not read. A run that
exits 0 and writes no file is a failed scan here: the tool returns before it writes
anything when it finds nothing to read, which for ASH means the target held no file
it could open.

Severity
--------
Each finding carries a rule ``severity`` (critical to info), a ``confidence``
(strong, moderate, weak) and an ``ml_probability``. ASH rates by confidence:

==========  =========  ===========  ==========
confidence  ASH         SARIF level  kind
==========  =========  ===========  ==========
strong      HIGH        error        fail
moderate    MEDIUM      warning      fail
weak        LOW         note         fail
==========  =========  ===========  ==========

A finding with no confidence, or one the table does not name, is HIGH: the more
severe choice when the tool's own rating cannot be read. HIGH and not CRITICAL: the
tool reports a candidate that its model scored, not a credential it validated (the
plugin never runs ``--validation``-style network checks). The rule's own severity and
the ML probability are kept in the result's properties.

Sandbox
-------
The strict default: no network and the baseline environment. The model and the rules
ship inside the Python package, which the uv tool directories hold.
"""

from __future__ import annotations

import hashlib
import logging
import os
import posixpath
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

from pydantic import Field

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
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    SarifReport,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

_COMMAND = "credsweeper"

#: The CredSweeper range this converter was written against. The JSON is the tool's
#: own report format, not a versioned schema, so a major release is not assumed to keep
#: it. ``options.tool_version`` overrides it.
CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT = ">=1.19.6,<2.0.0"

#: PyPI lists ``requires_python >=3.11`` for 1.19.6 and a ``zstandard`` dependency
#: marked ``python_version < "3.14"``. Capped at 3.13 so uv does not pick an
#: interpreter some dependency may publish no wheel for.
CREDSWEEPER_PYTHON_REQUEST = ">=3.11,<3.14"

#: The text written in place of a credential in a result's snippet.
REDACTED = "REDACTED"

#: Confidence -> (ASH severity, SARIF level). See "Severity" in the module docstring.
CONFIDENCE_MAP: Dict[str, Tuple[str, str]] = {
    "strong": ("HIGH", "error"),
    "moderate": ("MEDIUM", "warning"),
    "weak": ("LOW", "note"),
}

#: Used for a confidence not in ``CONFIDENCE_MAP``: the more severe choice.
UNKNOWN_CONFIDENCE: Tuple[str, str] = ("HIGH", "error")

_INFORMATION_URI = "https://github.com/Samsung/CredSweeper"


def rate_confidence(confidence: Any) -> Tuple[str, str]:
    """The (ASH severity, SARIF level) for a CredSweeper confidence value."""
    if isinstance(confidence, str):
        return CONFIDENCE_MAP.get(confidence.strip().lower(), UNKNOWN_CONFIDENCE)
    return UNKNOWN_CONFIDENCE


def _result_uri(path: str, source_dir: Path) -> str:
    """A report path as a source-relative posix URI where it lies under the source."""
    text = path.replace("\\", "/")
    if posixpath.isabs(text):
        base = Path(source_dir).absolute().as_posix().rstrip("/") + "/"
        if text.startswith(base):
            return text[len(base) :]
        return text
    normal = posixpath.normpath(text)
    return normal.removeprefix("./")


def convert_credsweeper_report(findings: Any, source_dir: Path) -> Dict[str, Any]:
    """Convert CredSweeper's JSON array to a SARIF document (as a dict).

    The finding's ``line`` and ``value`` fields are never read: the credential text
    does not enter the SARIF. The first ``line_data_list`` entry places the result.

    Raises:
        ScannerError: ``findings`` is not a list of objects.
    """
    if not isinstance(findings, list):
        raise ScannerError(
            "its report is not a JSON array of findings, so it could not be graded"
        )
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ScannerError(
                f"its report holds a non-object at position {index}, so it could "
                "not be graded"
            )
        rule_id = str(finding.get("rule") or "credsweeper")
        severity, level = rate_confidence(finding.get("confidence"))
        line_data = finding.get("line_data_list")
        first = (
            line_data[0]
            if isinstance(line_data, list)
            and line_data
            and isinstance(line_data[0], dict)
            else {}
        )
        uri = _result_uri(str(first.get("path") or ""), source_dir)
        line_num = first.get("line_num")
        line = line_num if isinstance(line_num, int) and line_num > 0 else None

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"CredSweeper rule {rule_id}"},
                "helpUri": _INFORMATION_URI,
                "properties": {"tags": ["secret", "security", "credsweeper"]},
            },
        )
        probability = finding.get("ml_probability")
        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "tags": ["secret", "security"],
            "credsweeper_confidence": finding.get("confidence"),
            "credsweeper_rule_severity": finding.get("severity"),
        }
        if isinstance(probability, (int, float)) and not isinstance(probability, bool):
            properties["credsweeper_ml_probability"] = probability
        detail = (
            f", ML probability {probability:.2f}"
            if isinstance(probability, (int, float))
            and not isinstance(probability, bool)
            else ""
        )
        physical: Dict[str, Any] = {"artifactLocation": {"uri": uri or "unknown"}}
        if line is not None:
            physical["region"] = {"startLine": line, "snippet": {"text": REDACTED}}
        digest = hashlib.sha256(f"{rule_id}\0{uri}\0{line}".encode()).hexdigest()
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail",
                "message": {
                    "text": (
                        f"CredSweeper rule {rule_id} found a possible credential "
                        f"(confidence {finding.get('confidence')}{detail}). The "
                        "value is not included in this report."
                    )
                },
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {"credsweeper/v1": digest[:32]},
                "properties": properties,
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CredSweeper",
                        "informationUri": _INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


class CredSweeperScannerConfigOptions(ScannerOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.credsweeper.options.tool_version"),
        Field(
            description=(
                "Version constraint for the credsweeper installation, in pip "
                "requirement syntax. Leave unset to use the scanner's own default "
                "constraint."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class CredSweeperScannerConfig(ScannerPluginConfigBase):
    name: Literal["credsweeper"] = "credsweeper"
    enabled: bool = True
    options: Annotated[
        CredSweeperScannerConfigOptions,
        Field(description="Configure the credsweeper scanner"),
    ] = CredSweeperScannerConfigOptions()


@ash_scanner_plugin
class CredSweeperScanner(ScannerPluginBase[CredSweeperScannerConfig]):
    """ML-scored credential detection over the scan target using CredSweeper."""

    #: A uv tool, but not Python-only: it scans any file, so a Python-only scan
    #: does not decide whether it runs.
    python_only: ClassVar[bool | None] = False

    # The rules and the model ship in the package; a scan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Native fields name
    #: CredSweeper's own JSON report (fixture
    #: tests/test_data/scanners/credsweeper/captured/positive.json).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "rule"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "confidence" (strong, moderate, weak), mapped '
            'by CONFIDENCE_MAP; the rule\'s own "severity" is kept in extras',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "line_data_list"[0]."path"',
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "line_data_list"[0]."line_num" (start line only)',
        ),
        column=FacetDecl(
            state=FacetState.DROPPED,
            native_field='finding "line_data_list"[0]."value_start" / "value_end"',
            reason="the report carries character offsets of the value in its line; "
            "the converter writes no column into the SARIF region",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "rule", "confidence" and "ml_probability", '
            "composed into the message by the converter (the value is never included)",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="credential findings name a file location, not a deployable "
            "resource; the report carries a rule and a path only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="credential findings name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="credential findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="credential findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="credential findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="credential findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native fingerprint) result partialFingerprints "
            '"credsweeper/v1", a sha256 digest of rule, path and line computed by '
            "the converter",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="credential findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text, the constant REDACTED written by the "
            'converter; the report\'s "line" and "value" are never read',
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native tags) the converter writes secret and security",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "severity" and "ml_probability", written as '
            "properties credsweeper_rule_severity and credsweeper_ml_probability, "
            'with "confidence" as credsweeper_confidence',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="credsweeper",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "credsweeper_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: the rules and the ONNX model ship in the "
                    "package and ASH never passes a validation option"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="`credsweeper --path=<target>` over the target's files; "
                "contents, not history (module header: --git and --diff_path are "
                "never passed)",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one run per scan target (source, then converted)",
                python_only=False,
                use_uv_tool=True,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH provisions no binary for it",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="HIGH, MEDIUM or LOW from the finding's confidence "
                "(strong, moderate, weak); an unreadable confidence is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes no CredSweeper config, denylist or "
                "skip_ignored option, and no tool-side silencing surface was "
                "surveyed; ASH suppressions are the surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under credsweeper/v1 of rule, path and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (tool_version, install_timeout); no "
                "rules path, because the tool's --rules and --config read the tree",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="ASH passes --no-error, so a completed scan exits 0 whatever "
                "it found; 1 means the scan failed or no input mode was given",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_credsweeper_plugins in ash_plugin_modules",),
                upstream_license=(
                    "MIT (source: the LICENSE file in the credsweeper 1.19.7 wheel, "
                    "Copyright (c) 2021 SAMSUNG; METADATA License: MIT)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository is required and no history is read",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CredSweeperScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SECRETS
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # The version probe runs once, in the dependency check; construction starts
        # nothing.
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token CredSweeper would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        options = getattr(self.config, "options", None)
        configured = getattr(options, "tool_version", None)
        return configured or CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT

    def _get_tool_python_request(self) -> str | None:
        return CREDSWEEPER_PYTHON_REQUEST

    def _install_hint(self) -> str:
        return (
            "`ash dependencies install --config-overrides "
            "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
            "ash_credsweeper_plugins\"]' --tool credsweeper`"
        )

    def _install_timeout(self) -> int:
        options = getattr(self.config, "options", None)
        return int(getattr(options, "install_timeout", 300))

    def validate_plugin_dependencies(self) -> bool:
        """uv tool first, then a copy on PATH, then an install."""
        if self.dependency_unavailable_reason:
            return False
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._record_missing_reason()
            return False

        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)
            self._plugin_log(
                "credsweeper not found via UV tool, attempting installation...",
                level=logging.INFO,
            )
            if self._install_uv_tool(timeout=self._install_timeout()):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for credsweeper",
                level=logging.WARNING,
            )

        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        requirement = f"credsweeper{self._get_tool_version_constraint() or ''}"
        install = (
            f"uv tool install --python '{CREDSWEEPER_PYTHON_REQUEST}' '{requirement}'"
        )
        if self._is_offline_mode():
            reason = (
                "credsweeper is not installed, and ASH does not install tools in "
                f"offline mode. Install it before going offline (`{install}`), or "
                "leave the credsweeper scanner disabled."
            )
        else:
            reason = (
                f"credsweeper could not be installed or found on PATH. Install it "
                f"with {self._install_hint()} or `{install}`."
            )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("CredSweeperScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before CredSweeper runs whether it reads any file."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source directory, the absolute path otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full CredSweeper argv for one target, every option one token."""
        return [
            self.command or _COMMAND,
            f"--path={self._scan_path(target)}",
            f"--save-json={results_file.as_posix()}",
            "--no-stdout",
            "--no-color",
            "--no-progress",
            "--hashed",
            "--no-error",
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one CredSweeper run.

        ``global_ignore_paths`` is not passed to the tool: ASH applies it to every
        scanner's SARIF.
        """
        if self.results_dir is None:
            raise ScannerError("CredSweeperScanner has no results directory")
        # One instance scans source and then converted; the base keeps the worst
        # exit code across runs, so a failed source run must not fail a clean one.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "credsweeper.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse a run that did not complete, then convert its JSON to SARIF."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"credsweeper exited {self.exit_code}; it exits 0 when a scan "
                "completes, so this run failed"
            )
        try:
            findings = super()._read_results_file(results_file)
        except ValueError as exc:
            raise ScannerError(
                f"its report is not valid JSON, so it could not be graded: {exc}"
            )
        if findings is None:
            return None
        return convert_credsweeper_report(findings, self._source_dir())

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep CredSweeper's stderr out of ``self.errors``.

        The log can quote paths of the scanned tree and the executor copies
        ``errors`` into the scan's results. The stream stays in the log file.
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
        """The failure and where the log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (credsweeper was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). credsweeper's log is not "
            f"quoted here; see {log_path.as_posix()}"
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

        CredSweeper is not told to skip it, so with the output directory inside the
        source it reads ASH's own files. A file the repository committed there is kept.
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
                if os.sep == "\\":
                    uri = uri.replace("\\", "/")
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
        """Drop ASH's own files and keep level, kind and severity in agreement."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            props = result.properties
            severity = getattr(props, "issue_severity", None) if props else None
            expected = {"HIGH": Level.error, "MEDIUM": Level.warning, "LOW": Level.note}
            result.level = expected.get(str(severity), Level.error)
            result.kind = Kind.fail
        return sarif_report


__all__ = [
    "CONFIDENCE_MAP",
    "CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT",
    "CREDSWEEPER_PYTHON_REQUEST",
    "CredSweeperScanner",
    "CredSweeperScannerConfig",
    "CredSweeperScannerConfigOptions",
    "REDACTED",
    "convert_credsweeper_report",
    "rate_confidence",
]
