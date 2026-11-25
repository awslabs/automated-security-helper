# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""njsscan: a static security scanner for Node.js applications.

njsscan (https://github.com/ajinabraham/njsscan, LGPL-3.0) runs a curated
rule pack over JavaScript and Node.js template files (semantic grep rules for
the code, pattern rules for templates such as handlebars, pug and ejs) and
reports each match with an OWASP and CWE mapping.

ASH runs it as a separate process, installed through uv (the PyPI package
``njsscan``). Nothing in ASH imports it, so the wrapper itself is not a
combined work with an LGPL library.

What ASH runs
-------------
``njsscan --sarif --output=<results>/<target_type>/njsscan.sarif
--config=<empty config> -- <path>`` once per target, from the source directory.
``<path>`` is ``.`` for the source and an absolute path for the converted
target, so reported paths come out source-relative.

Every flag above is one the njsscan README documents (``--sarif``,
``-o/--output``, ``-c/--config``); ``--`` ends option parsing, as Python's
argparse, which njsscan uses, does. This is the template scan flow: the base
class runs the tool, reads the SARIF file and calls ``_post_process_sarif``.

Why ASH passes ``--config``
---------------------------
Without ``-c``, njsscan reads ``.njsscan`` from the first scan path
(``njsscan.utils.get_config``). That file can set ``ignore-rules``,
``ignore-paths``, ``ignore-extensions`` and ``severity-filter``, each of which
drops findings before ASH sees them, and ``severity-overrides``, which rewrites a
rule's severity before ASH reads it (njsscan 1.0.2, ``njsscan/utils.py``
``get_config``). The scanned tree must not decide what is reported, so ASH
always passes a config of its own that sets nothing (``ignore-rules: []``),
written outside the scanned tree. This plugin offers no option that points at a
config file. The empty config adds nothing to njsscan's built-in ignore lists
(``node_modules``, ``fixtures``, ``spec``, ``example``, ``.min.js`` and similar
paths; ``njsscan/settings.py``), which stay in force and are recorded as the
scanner's tool-default filter in its operational register row.

Inline ``// njsscan-ignore: <rule_id>`` comments are honored by njsscan
whatever ASH passes: it has no flag that turns them off. A finding a comment
suppresses is therefore not reported and not counted as suppressed. The module
docs page says so; ASH suppressions are the supported way to suppress.

Severity
--------
njsscan maps its own severity to a SARIF level (``njsscan/formatters/sarif.py``,
``level_from_severity``): ERROR -> error, WARNING -> warning, INFO -> note,
anything else -> none. ASH sets ``issue_severity`` and the SARIF level together,
as hadolint does, because every njsscan rule is a pattern match that says "this
code has the shape of a weakness", not a confirmed vulnerability:

======== ============== =====================
njsscan  SARIF level    ASH issue_severity
======== ============== =====================
ERROR    error          HIGH
WARNING  warning        MEDIUM
INFO     note           LOW
other    none           INFO
======== ============== =====================

``error`` is HIGH, not the CRITICAL that ASH's generic ``error`` level maps to,
for the reason above. A result that arrives with no level is MEDIUM (the SARIF
default is ``warning``). A level this table does not know is HIGH, so an
unrecognized value is never under-reported.

Exit status and output
----------------------
njsscan exits 0 when it found nothing it counts, and 1 when it found an ERROR
finding (or a WARNING with ``-w``, which ASH does not pass) or when semgrep
reported an error reading some file (``njsscan.__main__.handle_exit``). So 1
means "findings" or "read errors" and is accepted (``success_exit_codes``); the
two cases are told apart by the SARIF, whose invocation says
``executionSuccessful: false`` when the scan had errors. The base class carries
that flag into ASH's own invocation record, so the run is reported unsuccessful
and the incomplete-scan gate sees it. Any other code (2 is argparse's usage
error) fails the scan even when a report is on disk.

Offline
-------
The rules ship inside the package, so a scan makes no network call.
``offline_strategy`` is BUNDLED.

Platform
--------
The njsscan README says it "supports only Mac and Linux", so on Windows an
enabled scanner is skipped with a reason rather than reported missing.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
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
    cast,
)
from urllib.parse import unquote, urlparse

from pydantic import Field

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.plugin_base import CustomCommand
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
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

_COMMAND = "njsscan"

#: The njsscan release this converter was written against (PyPI, 2026-11-19).
#: Exact on purpose: the SARIF it writes is produced by its own formatter, and
#: ``options.tool_version`` overrides the pin.
NJSSCAN_DEFAULT_VERSION_CONSTRAINT = "==1.0.2"

#: The interpreter request. njsscan 1.0.2 declares ``requires_python >=3.10``
#: on PyPI; nothing here narrows it further.
NJSSCAN_PYTHON_REQUEST = ">=3.10"

#: What the empty config holds. ``njsscan.utils.validate_config`` rejects an
#: empty file (and logs "Invalid YAML"), so the file sets one key to an empty
#: list: valid, and it ignores nothing.
EMPTY_CONFIG = "ignore-rules: []\n"

#: njsscan SARIF level -> (ASH severity, SARIF level). See the module docstring.
NJSSCAN_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
    "none": ("INFO", Level.none),
}

#: Exit codes that mean njsscan ran to completion: 0 (clean) and 1 (findings or
#: read errors; the SARIF says which).
SUCCESS_EXIT_CODES: Set[int] = {0, 1}


class NjsscanScannerConfigOptions(ScannerOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.njsscan.options.tool_version"),
        Field(
            description=(
                "Version constraint for njsscan installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint, "
                "which is the njsscan release the result converter was written "
                "against. A value that is not a version constraint is ignored "
                "with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class NjsscanScannerConfig(ScannerPluginConfigBase):
    name: Literal["njsscan"] = "njsscan"
    enabled: bool = True
    options: Annotated[
        NjsscanScannerConfigOptions,
        Field(description="Configure the njsscan scanner"),
    ] = NjsscanScannerConfigOptions()


def _level_name(level: Any) -> Optional[str]:
    """A SARIF level's string value, whether it holds the enum or the string."""
    if level is None:
        return None
    return str(getattr(level, "value", level)).lower()


def source_relative_uri(uri: Optional[str], source_dir: Path) -> Optional[str]:
    """``uri`` as a source-relative POSIX path, when it names a file under the source.

    njsscan writes a relative path percent-quoted and an absolute one as a
    ``file://`` URI (``formatters/sarif.py``, ``to_uri``). A ``./`` prefix is
    dropped and a ``file://`` URI under ``source_dir`` is made relative; any
    other value is returned as it is.
    """
    if not uri:
        return uri
    if uri.startswith("file:"):
        path = Path(unquote(urlparse(uri).path))
        try:
            return path.relative_to(Path(source_dir).absolute()).as_posix()
        except ValueError:
            return uri
    return uri.removeprefix("./")


@ash_scanner_plugin
class NjsscanScanner(ScannerPluginBase[NjsscanScannerConfig]):
    """Node.js static security analysis over the scan target using njsscan."""

    #: njsscan is a Python package ASH runs through uv, but it scans JavaScript, so
    #: a Python-only scan must not skip it for being Python and must not run it
    #: for being a uv tool: it is not Python-only.
    python_only: ClassVar[bool | None] = False

    # The rules ship inside the njsscan package; a scan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name njsscan's own SARIF (fixtures
    #: tests/test_data/scanners/njsscan/captured/positive.sarif, read from a real
    #: njsscan 1.0.2 run).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (e.g. eval_nodejs)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (absent for WARNING, error for ERROR, '
            "note for INFO), rewritten with properties issue_severity by "
            "apply_severity_mapping",
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
            native_field='result "message.text" (the rule description)',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a JavaScript or template file location, not a "
            "deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a JavaScript or template file location, not a "
            "deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="njsscan is a code-pattern scanner; its findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="njsscan is a code-pattern scanner; its findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="njsscan is a code-pattern scanner; its findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="njsscan rules map to CWE and OWASP categories, not to CVEs",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field="tool.driver.rules[].properties.tags "
            "(external/cwe/cwe-<n>), which the shared flat row reads; the "
            'result property "cwe" (CWE-<n>: <title>) carries the same value',
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="njsscan writes no partialFingerprints or fingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="njsscan findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry id, name, helpUri and tags only; the "
            "result message is the rule description, not a fix",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="tool.driver.rules[].helpUri "
            "(https://ajinabraham.github.io/nodejsscan/#<rule id>)",
            reason="the shared flat row reads references from relatedLocations "
            "only, and njsscan writes none",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field="tool.driver.rules[].properties.tags (security, "
            "external/cwe/cwe-<n>)",
            reason="the tags sit on the rule, and the shared flat row reads "
            "result-level tags, which njsscan does not write (its CWE tag is "
            "read through the taxonomy_cwe facet)",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "owasp-web" and "cwe" as njsscan '
            'wrote them, plus "issue_severity" and "njsscan_level" written by '
            "apply_severity_mapping",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="njsscan",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "njsscan_scanner.py offline_strategy and sandbox_requirements; "
                    "module header (Offline): the rules ship in the njsscan package"
                ),
                unconfirmed=(
                    "the semgrep binary njsscan starts has its own metrics and "
                    "version-check settings, which ASH does not set and this "
                    "register did not read; a run with the network blocked would "
                    "settle it"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection=(
                    "njsscan walks the whole target: .js and extensionless files as "
                    "Node.js code, and template files (.html, .hbs, .ejs, .pug, "
                    ".vue and others) by pattern rules (njsscan/settings.py)"
                ),
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one run over the source and one over the converted target",
                python_only=False,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note=(
                    "a PyPI package run through uv; the njsscan README supports "
                    "only Mac and Linux, so an enabled scanner is skipped on Windows"
                ),
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="njsscan's ERROR, WARNING and INFO map to HIGH, MEDIUM and LOW",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="// njsscan-ignore: <rule_id> comments, which njsscan has no flag to turn off",
                        cite="njsscan/njsscan.py (the 'njsscan-ignore:' match, 1.0.2) and the module header (Config)",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".njsscan in the scan root (ignore-rules, ignore-paths, ignore-extensions, severity-filter, severity-overrides)",
                        cite="njsscan/utils.py get_config (1.0.2); ASH always passes --config with an empty config of its own, so the tree's file is never read",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.TOOL_DEFAULT,
                        honored=opsf.Honored.YES,
                        surface="njsscan's default ignored paths (node_modules, bower_components, fixtures, spec, example, .min.js, .git, .svn), file names (minified library copies) and extensions",
                        cite="njsscan/settings.py IGNORE_PATHS, IGNORE_FILENAMES and IGNORE_EXTENSIONS (1.0.2); the empty config does not clear them",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="njsscan writes no fingerprint; identity is rule, file and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface=(
                    "typed options (tool_version, install_timeout); no option "
                    "points at a rules path or a config file"
                ),
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics=(
                    "0 is clean; 1 is an ERROR finding or a read error, told apart "
                    "by the SARIF invocation's executionSuccessful; any other code "
                    "fails the scan"
                ),
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_njsscan_plugins in ash_plugin_modules",),
                upstream_license=(
                    "LGPL-3.0-or-later (source: njsscan 1.0.2 wheel METADATA, "
                    "classifier 'GNU Lesser General Public License v3 or later "
                    "(LGPLv3+)' and its LICENSE file, read 2026-11-25)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no manifest, lockfile or Node.js runtime is read; the rules run in semgrep",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = SUCCESS_EXIT_CODES
    # The strict default: no network, baseline environment. Nothing option- or
    # environment-derived is granted, because this plugin reads no such option.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    @property
    def _opts(self) -> NjsscanScannerConfigOptions:
        return cast(NjsscanScannerConfig, self.config).options

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = NjsscanScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # The version probe is recorded here and run once, by the dependency check
        # (resolve_deferred_tool_version): construction must start nothing.
        self.tool_version = None
        self._deferred_tool_version_probe = (
            None
            if self.unsupported_platform_reason() is not None
            else (_COMMAND, self._uv_from_spec())
        )
        self.description = (
            "njsscan finds insecure code patterns in Node.js applications and "
            "their templates."
        )
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token njsscan would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return NJSSCAN_DEFAULT_VERSION_CONSTRAINT

    def _get_tool_python_request(self) -> str | None:
        return NJSSCAN_PYTHON_REQUEST

    def unsupported_platform_reason(self) -> str | None:
        """Windows: the njsscan README says it supports only Mac and Linux."""
        if platform.system().lower() == "windows":
            return "njsscan supports only Mac and Linux, so it is skipped on Windows"
        return None

    def get_installation_commands(
        self, platform: str, arch: str
    ) -> List[List[str] | CustomCommand]:
        """No install command on Windows; see ``unsupported_platform_reason``."""
        if platform.lower() == "windows":
            return []
        return super().get_installation_commands(platform, arch)

    def validate_plugin_dependencies(self) -> bool:
        """uv tool first, then a copy on PATH, then an explicit install."""
        if self.dependency_unavailable_reason:
            return False
        if self.unsupported_platform_reason() is not None:
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
            self._plugin_log(
                "njsscan not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )
            if self._install_uv_tool(timeout=self._opts.install_timeout):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for njsscan, falling back to "
                "consolidated resolver",
                level=logging.WARNING,
            )

        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        """Say why njsscan is unavailable and how to provide it."""
        requirement = f"njsscan{self._get_tool_version_constraint() or ''}"
        install = f"uv tool install --python '{NJSSCAN_PYTHON_REQUEST}' '{requirement}'"
        if self._is_offline_mode():
            reason = (
                "njsscan is not installed, and ASH does not install tools in "
                f"offline mode. Install it before going offline (`{install}`) or "
                "leave the njsscan scanner disabled."
            )
        else:
            reason = (
                "njsscan could not be installed or found on PATH. Install it with "
                f"`{install}`, or see the log above for uv's error."
            )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)
        # Also the hint `ash dependencies install` prints for every community plugin.
        self._plugin_log(
            "Install it with `ash dependencies install --config-overrides "
            "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
            "ash_njsscan_plugins\"]' --tool njsscan`.",
            level=logging.WARNING,
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("NjsscanScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before njsscan runs whether it reads any file."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the subprocess runs there), else the absolute path."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full njsscan argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows
        ``--``, so no path or value is read as a flag.
        """
        config_file = empty_tool_config(
            "njsscan-empty.njsscan", EMPTY_CONFIG, context=self.context
        )
        return [
            self.command or _COMMAND,
            "--sarif",
            f"--output={results_file.as_posix()}",
            f"--config={Path(config_file).as_posix()}",
            "--",
            self._scan_path(target),
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
        """Resolve the argv and results path for one njsscan run.

        ``global_ignore_paths`` is not translated into an njsscan option: it is
        applied to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("NjsscanScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs;
        # without this a failed source run would fail a clean converted run.
        self.exit_code = 0
        # Absolute: njsscan runs with its working directory at the source
        # directory, and a relative output directory would have it write there.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "njsscan.sarif")
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
        return final_args, results_file, self._direct_exec_env()

    def _direct_exec_env(self) -> Optional[Dict[str, str]]:
        """The child environment for a copy of njsscan run directly, else None.

        njsscan starts ``semgrep`` by name, so it must find it on ``PATH``
        (libsast reports "semgrep not found" otherwise, and the run exits 1 with
        ``executionSuccessful`` false). ``uv tool run`` puts the tool
        environment's ``bin`` directory on ``PATH``; a pre-installed copy run
        directly does not, because the ``njsscan`` on ``PATH`` is a symlink into
        that environment and ``semgrep`` is not linked beside it. So the
        directory the executable really lives in is put first on ``PATH``. Under
        uv, and when the executable cannot be found, the environment is the
        inherited one (None).
        """
        if self.use_uv_tool:
            return None
        found = shutil.which(self.command or _COMMAND)
        if not found:
            return None
        env = snapshot_environ()
        bin_dir = Path(found).resolve().parent.as_posix()
        entries = [e for e in env.get("PATH", "").split(os.pathsep) if e]
        if bin_dir not in entries:
            env["PATH"] = os.pathsep.join([bin_dir, *entries])
        return env

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run that did not end with an accepted code.

        Raised before reading so a partial report cannot pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"njsscan exited {self.exit_code}; it exits 0 when it finds "
                "nothing and 1 when it finds ERROR findings or could not read "
                "some file, so this run failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def apply_severity_mapping(sarif_report: SarifReport) -> SarifReport:
        """Rewrite each result's severity and level from its njsscan level."""
        for result in sarif_report.get_all_results():
            # A result with no level arrives as the SARIF model's default for
            # Result.level (warning), so it is MEDIUM. A level the table lacks (or
            # one the model could not hold) is read as error: never under-reported.
            name = _level_name(result.level)
            severity, level = NJSSCAN_LEVEL_MAP.get(
                name or "error", NJSSCAN_LEVEL_MAP["error"]
            )
            result.level = level
            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
            setattr(result.properties, "njsscan_level", name or "error")  # noqa: B010
        return sarif_report

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Drop results in files under ASH's own output directory.

        njsscan walks the whole target and has no exclusion flag ASH can use, so
        a report ASH wrote into the tree earlier is read back in.
        """
        output_dirs = [
            Path(d).as_posix().strip("/")
            for d in self._ash_output_dirs_inside(target)
            if Path(d).as_posix().strip("/")
        ]
        if not output_dirs:
            return
        for run in sarif_report.runs or []:
            kept = []
            for result in run.results or []:
                uris = [
                    source_relative_uri(
                        loc.physicalLocation.root.artifactLocation.uri,
                        self._source_dir(),
                    )
                    for loc in (result.locations or [])
                    if loc.physicalLocation is not None
                    and loc.physicalLocation.root.artifactLocation is not None
                ]
                inside = any(
                    uri is not None
                    and any(uri == d or uri.startswith(d + "/") for d in output_dirs)
                    for uri in uris
                )
                if not inside:
                    kept.append(result)
            run.results = kept

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, make URIs source-relative, rate every result."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                if artifact is not None and artifact.uri:
                    artifact.uri = source_relative_uri(artifact.uri, self._source_dir())
        return self.apply_severity_mapping(sarif_report)


__all__ = [
    "EMPTY_CONFIG",
    "NJSSCAN_DEFAULT_VERSION_CONSTRAINT",
    "NJSSCAN_LEVEL_MAP",
    "NjsscanScanner",
    "NjsscanScannerConfig",
    "NjsscanScannerConfigOptions",
    "SUCCESS_EXIT_CODES",
    "source_relative_uri",
]
