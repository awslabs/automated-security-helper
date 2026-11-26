# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ggshield: secret detection through the GitGuardian API.

ggshield (https://github.com/GitGuardian/ggshield, MIT) is GitGuardian's command
line client. ``ggshield secret scan path`` sends the content of each file to the
GitGuardian API, which returns the secrets it detects. This plugin runs it and
reads the SARIF it writes.

This scanner sends the scanned files to a third-party service
---------------------------------------------------------------
Unlike gitleaks, detect-secrets or betterleaks, the detection runs on
GitGuardian's servers. The content of every file ggshield reads leaves the host
(GitGuardian states it stores only call metadata, not file content; that is their
statement, not something ASH checks). Because of that:

* The scanner is OFF by default (``enabled: false``). Listing the module in
  ``ash_plugin_modules`` makes it available; ``scanners.ggshield.enabled: true``
  turns it on.
* It fails closed without ``GITGUARDIAN_API_KEY``: the dependency check records a
  reason that names the variable and the scanner is reported as unavailable, so a
  scan never reads as clean because nothing was checked. Only the environment
  variable is accepted; credentials that ``ggshield auth login`` stores in the
  user's configuration are not read, so the opt-in is always explicit.
* It is skipped under ``ASH_OFFLINE`` (``OfflineStrategy.SKIP_OFFLINE``).
* It refuses a target that would upload ASH's own output directory, and a run
  that has ``global_settings.ignore_paths`` set, because ggshield has no
  exclusion ASH can rely on and an ignored file would be uploaded all the same.

What ASH runs
-------------
::

    ggshield secret scan path --recursive --yes --all-secrets
        --format=sarif --output=<results>/<target_type>/ggshield.sarif
        -- <absolute scan path>

The flags were read from ggshield's sources on its main branch
(``ggshield/cmd/secret/scan/path.py``, ``secret_scan_common_options.py``,
``cmd/utils/common_options.py``); the real CLI could not be run while this plugin
was written (no API key), see "Not measured" below.

* ``--recursive`` and ``--yes``: a directory is refused without the first, and a
  scan of more than one file asks for confirmation without the second.
* ``--all-secrets``: "Do not ignore any secret", so findings ggshield would
  discard by its own ignore reasons reach ASH, where suppressions are reported
  and counted.
* ``--format=sarif`` and ``--output``: SARIF 2.1.0 (supported since 1.30.1) is
  written to a file, so nothing is read from stdout.
* Never passed: ``--ignore-known-secrets`` (hides findings the dashboard knows),
  ``--exit-zero`` (the exit code is read), ``--show-secrets`` (secrets stay
  masked), ``--use-gitignore`` and ``--exclude`` (would hide files),
  ``--banlist-detector``, ``--source-uuid`` and ``--with-incident-details``
  (create or read dashboard incidents), ``--insecure``, ``--allow-self-signed``.

Working directory
-----------------
ggshield reads ``.gitguardian.yaml`` from the project root of its working
directory (``core/config/utils.find_local_config_path``). That file can hide
findings (``ignored-paths``, ``ignored-matches``, ``ignored-detectors``), so the
subprocess runs in a new empty directory outside the scanned tree and is given the
scan path as an absolute path; the SARIF locations ggshield writes are mapped
back to source-relative paths in ``_post_process_sarif``. ggshield offers no
``--config`` option, which is why the directory is chosen instead of a file.

Exit status
-----------
``core/errors.ExitCode``: 0 success, 1 "scan was successful, and found problems",
2 usage error, 3 authentication error, 4 server unavailable, 128 unexpected
error. 0 and 1 are the only success codes; 3 and 4 fail the scan with a message
that names the cause. ggshield's stderr is not copied into the scan's errors: it
can quote a path or a line of the scanned tree.

Severity
--------
Every result is CRITICAL with SARIF level ``error`` and kind ``fail``. The
SARIF writer (``SecretSARIFOutputHandler``) gives every result level ``error``
and ggshield's results have no severity of their own: each one says "a secret
of this detector's kind is present", the same reading ASH gives gitleaks and
betterleaks. ``issue_severity`` and ``level`` agree.

The SARIF holds no secret value: only the detector name, the match types and
positions, and a hash fingerprint (``partialFingerprints["secret/v1"]``). Any
snippet text a future release adds is overwritten with ``REDACTED``.

Measured, and what is not
-------------------------
The SARIF shape above was captured from ggshield 1.56.1's own CLI with only the
GitGuardian HTTP calls stubbed (tests/test_data/scanners/ggshield/captured/README.md):
``--output`` writes a report with an empty ``results`` list when nothing is found, the
location URI is ``file://`` plus the absolute scan path, and exits 0, 1 and 3 are as
described. Not measured: a scan against the live service, which needs an API key, so
the detector names, ``extensions[0].version`` and the service-side error cases are
unobserved. A missing report still fails the scan rather than reading as clean, and
the URI is accepted as an absolute path, a ``file://`` URI or a ``./`` path
(``_relative_uri``).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The environment variable that opts the scanner in. ggshield reads it itself.
API_KEY_ENV = "GITGUARDIAN_API_KEY"

#: The ggshield release the SARIF reader was written against (PyPI 1.56.1).
#: ``options.tool_version`` overrides it.
GGSHIELD_DEFAULT_VERSION_CONSTRAINT = "==1.56.1"

#: The upstream license of record for the register (opsf requires a source citation).
LICENSE_CITATION = (
    "MIT (source: the ggshield 1.56.1 distribution's licenses/LICENSE, sha256 "
    "c6e6d1dbc34c4a7908f1b40fb6b487e946d4db9a7cd9386550f8fc39f2ccbdc4)"
)

#: The text written in place of any snippet a report carries.
REDACTED = "REDACTED"

#: ggshield's exit codes (``ggshield/core/errors.py``, ``ExitCode``).
FOUND_PROBLEMS_EXIT_CODE = 1
AUTHENTICATION_ERROR_EXIT_CODE = 3
SERVER_UNAVAILABLE_EXIT_CODE = 4

_EXIT_CODE_MEANINGS = {
    2: "a usage error",
    AUTHENTICATION_ERROR_EXIT_CODE: (
        f"an authentication error; check that {API_KEY_ENV} holds a valid key"
    ),
    SERVER_UNAVAILABLE_EXIT_CODE: "the GitGuardian server did not respond",
    128: "an unexpected error",
}

_COMMAND = "ggshield"


class GgshieldScannerConfigOptions(ScannerOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.ggshield.options.tool_version"),
        Field(
            description=(
                "Version constraint for ggshield installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint, "
                "the ggshield release the report reader was written against. A "
                "value that is not a version constraint is ignored with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class GgshieldScannerConfig(ScannerPluginConfigBase):
    name: Literal["ggshield"] = "ggshield"
    # Off until the operator turns it on: the scan sends file content to GitGuardian.
    enabled: bool = False
    options: Annotated[
        GgshieldScannerConfigOptions,
        Field(description="Configure the ggshield scanner"),
    ] = GgshieldScannerConfigOptions()


def _relative_uri(uri: str, target: Path) -> str:
    """``uri`` as a path relative to ``target``, when it names a file below it.

    ggshield writes the path of each file as the scan saw it. The scan path is
    absolute (see "Working directory"), so the location is accepted as an absolute
    path, a ``file://`` URI or a ``./`` path, and anything else is returned
    unchanged.
    """
    text = uri
    text = text.removeprefix("file://")
    base = Path(target).absolute().as_posix().rstrip("/")
    normalized = text.replace("\\", "/") if os.sep == "\\" else text
    if normalized == base:
        return "."
    if normalized.startswith(base + "/"):
        return normalized[len(base) + 1 :]
    if normalized.startswith("./"):
        return normalized[2:]
    return uri


@ash_scanner_plugin
class GgshieldScanner(ScannerPluginBase[GgshieldScannerConfig]):
    """Secret detection through the GitGuardian API, using ggshield."""

    #: ggshield is a Python package run through uv, but the scan needs GitGuardian's
    #: servers and a key, so it is not part of a Python-only scan.
    python_only: ClassVar[bool | None] = False

    #: Every scan calls the GitGuardian API.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name ggshield's SARIF as its
    #: ``SecretSARIFOutputHandler`` writes it; the shape is generated by that
    #: writer (tests/test_data/scanners/ggshield/captured/README.md), not
    #: captured from a run against the GitGuardian API, which needs a key.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the detector display name)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native severity) constant level error plus "
            'properties "issue_severity" CRITICAL, both set by _post_process_sarif',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine / region.endLine",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startColumn / region.endColumn",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable "
            "resource; the SARIF carries a detector name and a region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="ggshield's SARIF writer emits no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "partialFingerprints" key "secret/v1" (a hash of '
            "the secret; _post_process_sarif drops empty values only)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="ggshield's SARIF writer emits no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF writer never writes the secret value; any snippet a "
            "future release adds is overwritten with REDACTED by _post_process_sarif",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="relatedLocations[].physicalLocation.artifactLocation.uri "
            "(the match locations; ASH reads their URIs as references, made "
            "source-relative by _post_process_sarif)",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="ggshield's SARIF writer emits no result properties and so no "
            "tags; the adapter adds the constant tags secret and security "
            "(_post_process_sarif), which come from ASH, not from the tool's output",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="ggshield",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.SERVICE_UPLOAD,
                fetches=(opsf.Fetched.SOURCE_UPLOAD,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "detection runs on GitGuardian's servers, so there is nothing "
                    "to run without the network"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "ggshield_scanner.py offline_strategy, sandbox_requirements "
                    "and the module header: the content of every file ggshield "
                    "reads is sent to the GitGuardian API"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="`ggshield secret scan path --recursive` over the absolute scan path; contents, not history",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=True,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; it is not installable offline and the scanner is skipped offline",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.CONSTANT,
                note="every finding is CRITICAL; ggshield's SARIF writer gives every result level error",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".gitguardian.yaml (ignored-paths, ignored-matches, ignored-detectors) in the project root of the working directory",
                        cite="ggshield_scanner.py module header (Working directory): the subprocess runs in an empty directory outside the tree, so the tree's file is never read",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_NATIVE,
                note="partialFingerprints 'secret/v1', a hash of the secret",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("GITGUARDIAN_",),
                options_surface="typed options (tool_version, install_timeout) only; detectors are the service's",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="ggshield core/errors.ExitCode: 0 clean, 1 secrets found; 2 usage, 3 authentication, 4 server unavailable and 128 unexpected fail the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=(
                    "ash_ggshield_plugins in ash_plugin_modules",
                    "scanners.ggshield.enabled (off by default)",
                    "GITGUARDIAN_API_KEY in the environment",
                ),
                upstream_license=LICENSE_CITATION,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.AUTH_TOKEN,),
                note="GITGUARDIAN_API_KEY in the environment; the scanner reports itself unavailable without it",
            ),
        )
    )

    # 0 clean, 1 secrets found; 3 (authentication) and 4 (server) must fail the scan.
    success_exit_codes: ClassVar[Set[int]] = {0, FOUND_PROBLEMS_EXIT_CODE}

    # Needs the network and the key. The key is passed by name, plus the other
    # GITGUARDIAN_ variables ggshield reads (its instance and API URL).
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        env_prefixes=("GITGUARDIAN_",),
        env_names=(API_KEY_ENV,),
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GgshieldScannerConfig()
        self.command = _COMMAND
        self.subcommands = ["secret", "scan", "path"]
        self.tool_type = ScannerToolType.SECRETS
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # Recorded here and run once by the dependency check: construction starts
        # nothing (see GuardDogScanner).
        self.tool_version = None
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        self.description = (
            "ggshield detects secrets through the GitGuardian API. It sends the "
            "scanned files to GitGuardian and needs GITGUARDIAN_API_KEY."
        )
        # The argv is assembled in _execute_scan.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> GgshieldScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, GgshieldScannerConfigOptions):
            return options
        return GgshieldScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("GgshieldScanner has no plugin context")
        return Path(self.context.source_dir)

    def _get_tool_version_constraint(self) -> str | None:
        return self._options().tool_version or GGSHIELD_DEFAULT_VERSION_CONSTRAINT

    def _environment_values(self) -> Tuple[str, ...]:
        """The config's environment values plus the API key, so no log line shows it."""
        values = tuple(super()._environment_values())
        key = snapshot_environ().get(API_KEY_ENV)
        if key and key not in values:
            values = (*values, key)
        return values

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ggshield walks the target itself and ASH cannot tell what it reads."""
        return None

    # ------------------------------------------------------------------
    # Dependencies, and the opt-in gate
    # ------------------------------------------------------------------

    def _api_key_missing_reason(self) -> Optional[str]:
        """Why the scanner cannot run for want of a key, or None when one is set."""
        if snapshot_environ().get(API_KEY_ENV, "").strip():
            return None
        return (
            f"ggshield is not run: {API_KEY_ENV} is not set. ggshield sends the "
            "scanned files to the GitGuardian API and ASH only runs it when the "
            "key is in the environment. Create an API key in the GitGuardian "
            f"dashboard and export {API_KEY_ENV}, or leave scanners.ggshield "
            "disabled."
        )

    def validate_plugin_dependencies(self) -> bool:
        """The key, then uv tool, pre-installed, install: the order guarddog uses."""
        if self.dependency_unavailable_reason:
            return False
        reason = self._api_key_missing_reason()
        if reason is not None:
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
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
                "ggshield not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )
            if self._install_uv_tool(timeout=self._options().install_timeout):
                self.dependencies_satisfied = True
                return True
        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        requirement = f"ggshield{self._get_tool_version_constraint() or ''}"
        install = f"uv tool install '{requirement}'"
        if self._is_offline_mode():
            reason = (
                "ggshield is not installed, and ASH does not install tools in "
                f"offline mode. ggshield also needs the network to scan. Install it "
                f"before going online (`{install}`) or leave the scanner disabled."
            )
        else:
            reason = (
                f"ggshield could not be installed or found on PATH. Install it with "
                f"`{install}`, or see the log above for uv's error. Run "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_ggshield_plugins\"]' --tool ggshield`."
            )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """A new empty directory, so no ``.gitguardian.yaml`` of the tree is read."""
        return empty_tool_directory("ash-ggshield-cwd", context=self.context)

    def _refuse_upload_of_output_dir(self, target: Path) -> None:
        """Refuse a target that holds ASH's own output directory.

        ggshield would upload it with the rest: an earlier run's reports and logs.
        """
        inside = self._output_dir_inside(Path(target))
        if inside is None:
            return
        raise ScannerError(
            f"Not running ggshield on {Path(target).as_posix()}: ASH's output "
            f"directory '{inside.as_posix()}' is inside it, and ggshield sends "
            "every file it reads to GitGuardian, so it would upload ASH's own "
            "output. Pass --output-dir with a directory outside the scanned tree "
            "to run ggshield on it (ggshield was not started)."
        )

    def _refuse_upload_of_ignored_paths(
        self, global_ignore_paths: List[IgnorePathWithReason]
    ) -> None:
        """Refuse a run that has ignore paths: ggshield would upload those files.

        ASH drops the findings in an ignored path after the scan, which for an
        upload is too late.
        """
        if not global_ignore_paths:
            return
        raise ScannerError(
            "Not running ggshield: global_settings.ignore_paths is set, and "
            "ggshield sends every file it reads to GitGuardian, so a file ASH "
            "was told to ignore would still be uploaded. Remove the ignore paths "
            "for this scan or leave scanners.ggshield disabled (ggshield was "
            "not started)."
        )

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full ggshield argv for one target; the scan path follows ``--``."""
        return [
            self.command or _COMMAND,
            *self.subcommands,
            "--recursive",
            "--yes",
            "--all-secrets",
            "--format=sarif",
            f"--output={results_file.as_posix()}",
            "--",
            Path(target).absolute().as_posix(),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        if self.results_dir is None:
            raise ScannerError("GgshieldScanner has no results directory")
        # One instance scans source and then converted; the base keeps the worst code.
        self.exit_code = 0
        self._refuse_upload_of_output_dir(target)
        self._refuse_upload_of_ignored_paths(global_ignore_paths)
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "ggshield.sarif")
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

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code and keep ggshield's stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure, the exit code's meaning and where the log is; no log text."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (ggshield was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        meaning = _EXIT_CODE_MEANINGS.get(self.exit_code)  # type: ignore[arg-type]
        said = f" ({meaning})" if meaning else ""
        return (
            f"{detail} (exit code {self.exit_code}{said}; accepted codes are "
            f"{sorted(self.success_exit_codes)}). ggshield's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse a run that ended with a code ggshield does not use for success."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"ggshield exited {self.exit_code}; it exits 0 when it finds nothing "
                f"and {FOUND_PROBLEMS_EXIT_CODE} when it finds secrets, so this run "
                "failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result CRITICAL, make locations source-relative, drop empties."""
        for result in sarif_report.get_all_results():
            # See "Severity" in the module docstring.
            result.level = Level.error
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("secret", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", "CRITICAL")  # noqa: B010

            # relatedLocations holds one entry per match, with the same absolute
            # file:// URI; the flat row reads their URIs as the finding's references,
            # so they are made source-relative like the primary location.
            for location in [
                *(result.locations or []),
                *(result.relatedLocations or []),
            ]:
                physical = location.physicalLocation
                if physical is None:
                    continue
                artifact = physical.root.artifactLocation
                if artifact is not None and artifact.uri:
                    artifact.uri = _relative_uri(artifact.uri, target)
                region = physical.root.region
                snippet = region.snippet if region else None
                if snippet is not None and snippet.text not in (None, REDACTED):
                    snippet.text = REDACTED

            fingerprints = result.partialFingerprints
            if fingerprints:
                kept = {k: v for k, v in fingerprints.items() if v not in ("", None)}
                result.partialFingerprints = kept or None
        return sarif_report


__all__ = [
    "API_KEY_ENV",
    "GGSHIELD_DEFAULT_VERSION_CONSTRAINT",
    "GgshieldScanner",
    "GgshieldScannerConfig",
    "GgshieldScannerConfigOptions",
]
