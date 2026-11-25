# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ShellCheck: a shell script linter, as a community scanner plugin.

What it does
------------
Finds the shell scripts in the scan set, passes them to ``shellcheck`` by name,
reads the ``json1`` report ShellCheck prints on stdout and converts it to SARIF
results. ShellCheck is invoked as a separate process; nothing of it is imported.

ShellCheck is a community plugin: it is loaded only when ``ash_shellcheck_plugins``
is listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a
scan that does not list the module is unchanged by its existence.

Why this plugin has its own ``scan()``
--------------------------------------
ShellCheck has no SARIF formatter and no option to write a report to a file. Its
formats are ``tty``, ``gcc``, ``checkstyle``, ``diff``, ``json``, ``json1`` and
``quiet``, all on stdout, and the files to check are command-line arguments. So the
template flow (a tool that writes SARIF to a file) does not fit; this plugin
follows hadolint's own-``scan()`` shape and converts ``json1`` itself, as guarddog
converts its JSON. ``json1`` is used rather than ``json`` because ``json`` is the
legacy format with tab stops of 8 columns; ``json1`` counts a tab as one column.

Invocation (ShellCheck 0.11.0, from ``shellcheck.1.md`` and the binary)
-----------------------------------------------------------------------
``shellcheck --norc --format=json1 --severity=style -- <files>``, started in the
source directory so report paths come out source-relative.

* ``--norc``: do not look for ``.shellcheckrc``, ``shellcheckrc`` or
  ``.editorconfig`` in the script's directory and its parents, nor the user-level
  fallbacks. A repository could otherwise use an rc file to ``disable=`` rules or
  ``source-path`` outside the tree. The tool's ``--norc`` is documented to also
  cancel ``--rcfile``.
* ``--format=json1``: see above.
* ``--severity=style``: the lowest minimum severity, so every level is reported.
  It is the default; it is passed so an operator's ``SHELLCHECK_OPTS`` cannot
  change it. That variable is also removed from ShellCheck's environment, because
  ShellCheck prepends it to the command line on every run (``--exclude`` in it
  would hide findings).
* ``--``: ends option parsing, so a file whose name starts with ``-`` is a file.
* Not passed: ``--external-sources`` and ``--check-sourced`` (they follow
  ``source`` statements to files outside the scanned set), ``--source-path``,
  ``--exclude``, ``--enable``, ``--shell`` (the dialect is inferred per file from
  its ``# shellcheck shell=`` directive, shebang or extension).

Inline ``# shellcheck disable=SCxxxx`` comments inside a script are honored by
ShellCheck and cannot be switched off from the command line. They are the
script author's own suppression, the same as ``# nosec`` for bandit.

Targets
-------
A file is passed to ShellCheck when its extension is ``.sh``, ``.bash``,
``.ksh``, ``.dash`` or ``.ash``, or when it has no extension and its first line
is a shebang naming sh, bash, dash, ksh, ash or busybox (directly or through
``env``). A file whose shebang names any other interpreter (zsh, python, ...) is
skipped even when its name ends ``.sh``: ShellCheck does not support zsh and
would report the file as a syntax error. Symlinks that resolve outside the scanned
tree are skipped. A tree with no shell scripts reports SKIPPED rather than PASSED.

Severity mapping
----------------
ShellCheck has four levels and ASH five severities. The SARIF level is rewritten
to agree with the severity:

=========  ==============  ===========
ShellCheck ASH severity    SARIF level
=========  ==============  ===========
error      HIGH            error
warning    MEDIUM          warning
info       LOW             note
style      INFO            none
=========  ==============  ===========

``error`` is HIGH, not the CRITICAL ASH's generic ``error`` level maps to, because
ShellCheck is a linter: even its errors (syntax errors, ``SC2045`` iterating over
``ls``) are not by themselves exploitable vulnerabilities. A level ShellCheck did
not state, or one this table does not know, is HIGH: the more severe choice, so a
new level is never under-reported.

Exit status and output
----------------------
ShellCheck's documented statuses are 0 (no issues), 1 (issues found), 2 (some files
could not be processed), 3 (bad syntax) and 4 (bad options). ``success_exit_codes``
is ``{0, 1}``; any other status fails the scan, even if some JSON was printed. A
timeout fails the scan. Output that is not a ``json1`` document (not JSON, not an
object, no ``comments`` list) fails the scan. A file ShellCheck cannot parse is not a
special case: it is reported as ordinary ``SC1xxx`` findings, which ShellCheck
itself prints with status 1.

ShellCheck's stderr is never copied into the scan's errors beyond a short excerpt
for status 2, where it names the file that could not be read.

Install
-------
ShellCheck is GPL-3.0-or-later. ASH does not download or redistribute it: the
scanner declares no install commands and no ``utils/tool_downloads.py`` pin, and
``validate_plugin_dependencies`` reports a missing ``shellcheck`` with the way to
install it (the user's package manager or the upstream release). This is
deliberate; adding a pinned download would be a shared-file change that the
integration lane decides on (see the PR body).

Offline
-------
ShellCheck needs no network at scan time (``OfflineStrategy.BUNDLED``).

Sandbox
-------
``SandboxRequirements()``, the strict default: no network and no variables or
paths beyond the baseline.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field

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
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    MultiformatMessageString,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: ShellCheck level -> (ASH severity, SARIF level). See the module docstring.
SHELLCHECK_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "info": ("LOW", Level.note),
    "style": ("INFO", Level.none),
}

#: What a level that is missing or not in the table is rated as.
_UNKNOWN_LEVEL = "error"

#: File extensions of the shells ShellCheck supports (sh, bash, dash, ksh, busybox).
SHELL_EXTENSIONS = frozenset({".sh", ".bash", ".ksh", ".dash", ".ash"})

#: Interpreter names a shebang may carry for a file ShellCheck can check.
SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "ksh", "ash", "busybox"})

#: Bytes read from the head of a file to find its shebang.
_SHEBANG_READ_BYTES = 256

#: ShellCheck environment variables removed from its environment: it prepends
#: ``SHELLCHECK_OPTS`` to the command line of every run.
_INVOCATION_ENV_VARS = frozenset({"SHELLCHECK_OPTS"})

#: Upper bound on one command line, in characters (Windows caps it at 32,767).
_MAX_COMMAND_LINE_CHARS = 24_000

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic


def shebang_interpreter(first_line: str) -> Optional[str]:
    """The interpreter basename a shebang line names, or None.

    ``#!/bin/bash`` and ``#!/usr/bin/env bash`` give ``bash``; ``#!/usr/bin/env -S
    bash -e`` gives ``bash``. None when the line is not a shebang.
    """
    line = first_line.strip()
    if not line.startswith("#!"):
        return None
    words = line[2:].split()
    if not words:
        return None
    program = PurePosixPath(words[0]).name
    if program == "env":
        for word in words[1:]:
            if word.startswith("-") or "=" in word:
                continue
            return PurePosixPath(word).name
        return None
    return program


class ShellCheckScannerConfigOptions(ScannerOptionsBase):
    """No options beyond the base ones (``scan_timeout``, ``offline``, ...).

    ShellCheck's rule policy (``--exclude``, ``--enable``, rc files) is left out
    on purpose: each can hide findings, and ASH's own suppressions and
    ``severity_threshold`` already cover that.
    """


class ShellCheckScannerConfig(ScannerPluginConfigBase):
    name: Literal["shellcheck"] = "shellcheck"
    enabled: bool = True
    options: Annotated[
        ShellCheckScannerConfigOptions, Field(description="Configure ShellCheck")
    ] = ShellCheckScannerConfigOptions()


@ash_scanner_plugin
class ShellCheckScanner(ScannerPluginBase[ShellCheckScannerConfig]):
    """Lints shell scripts with ShellCheck."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # A native binary; no Python is needed to run it.
    python_only: ClassVar[bool | None] = False
    #: The facets register row (base/scanner_facets.py). Native fields name
    #: ShellCheck's own ``json1`` comments (fixture
    #: tests/test_data/scanners/shellcheck/captured/positive.json1), which this
    #: adapter converts to SARIF.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "code" (an integer), written as SC<code>',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "level" (error, warning, info, style) through '
            "SHELLCHECK_LEVEL_MAP; an unknown level is HIGH",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "file"',
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "line" / "endLine"',
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "column" / "endColumn"',
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='comment "message"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="shell script findings are in-file locators, not deployable "
            "resources",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="shell script findings are in-file locators, not deployable "
            "resources",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="shell lint findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="shell lint findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="shell lint findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="ShellCheck rules carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="ShellCheck rules carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="a json1 comment carries file, position, level, code and "
            "message only; no hash",
        ),
        fix_available=FacetDecl(
            state=FacetState.DROPPED,
            native_field='comment "fix" (non-null when ShellCheck can auto-fix)',
            reason="the adapter does not read the fix object",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the advice is the message text itself; the fix object holds "
            "edit replacements, not prose",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a json1 comment carries no source snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule helpUri https://www.shellcheck.net/wiki/SC<code> "
            "(adapter-written from the code, not a native field)",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="a json1 comment carries no tags",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" and '
            '"shellcheck_level" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="shellcheck",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source="shellcheck_scanner.py offline_strategy, sandbox_requirements",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="json1 on stdout, converted to SARIF by the adapter",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="its own discovery over the scan set: .sh, .bash, .ksh, "
                ".dash and .ash files, and extensionless files whose shebang names "
                "sh, bash, dash, ksh, ash or busybox",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("shellcheck",),
                invocations=opsf.Invocations.MULTI_PASS,
                invocation_note="script paths are chunked under the command-line "
                "cap, one shellcheck run per chunk",
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the user's installed ShellCheck; GPL-3.0, so ASH has no "
                "TOOL_VERSIONS pin or download for it",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="ShellCheck's four levels map to HIGH, MEDIUM, LOW and INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="# shellcheck disable=SCxxxx directives, applied "
                        "inside ShellCheck before ASH sees the report",
                        cite="shellcheck_scanner.py module header",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".shellcheckrc and .editorconfig rule policy",
                        cite="shellcheck_scanner.py _base_args (--norc)",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="identity is file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no rule options; --exclude, --enable and rc "
                "files are deliberately not exposed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 clean, 1 findings; 2 (unreadable files), 3 (bad "
                "syntax) and 4 (bad options) fail the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_shellcheck_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="shell scripts in the scan set",
            ),
        )
    )

    # 0 = clean, 1 = findings. 2, 3 and 4 mean files unreadable or bad invocation.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}
    # The strict default: no network, and no variables or paths beyond the baseline.
    # Grants derived from options or the environment wait for the sandbox's grant
    # gates; ShellCheck needs none of them.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ShellCheckScannerConfig()
        self.command = "shellcheck"
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="json1",
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: ShellCheck overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("ShellCheckScanner has no plugin context")
        return self.context

    @staticmethod
    def _looks_like_shell(path: Path) -> bool:
        """Whether *path* is a script ShellCheck should be given."""
        suffix = path.suffix
        if suffix and suffix not in SHELL_EXTENSIONS:
            return False
        try:
            with open(path, "rb") as handle:
                head = handle.read(_SHEBANG_READ_BYTES)
        except OSError:
            return False
        first_line = head.split(b"\n", 1)[0].decode("utf-8", errors="replace")
        interpreter = shebang_interpreter(first_line)
        if suffix:
            # Known extension: a shebang for another interpreter wins (zsh, python).
            return interpreter is None or interpreter in SHELL_INTERPRETERS
        return interpreter in SHELL_INTERPRETERS

    def _shell_scripts(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The scripts under *target* to pass to ShellCheck, sorted.

        The source branch reads ASH's scan set, so .gitignore, .ignore and the
        rest have already removed what they remove; ASH's own output directory is
        dropped as well. The converted branch walks ``work_dir``. A file that
        resolves outside *target* is skipped, not followed.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        absolute_output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()

        selected: List[Path] = []
        for path in candidates:
            if target_type == "source" and path.absolute().is_relative_to(
                absolute_output_dir
            ):
                continue
            suffix = path.suffix
            if suffix and suffix not in SHELL_EXTENSIONS:
                continue
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
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
            if global_ignore_paths and self._ignored(
                path, source_dir, global_ignore_paths
            ):
                continue
            if not self._looks_like_shell(path):
                continue
            selected.append(path)
        return sorted(set(selected))

    @staticmethod
    def _ignored(
        path: Path, source_dir: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> bool:
        """Whether ``global_settings.ignore_paths`` excludes *path*."""
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
        """How *path* is spelled on the command line, and so in the report."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        """The process environment minus ``_INVOCATION_ENV_VARS``."""
        return {
            k: v for k, v in snapshot_environ().items() if k not in _INVOCATION_ENV_VARS
        }

    def _base_args(self) -> List[str]:
        return [
            self.command or "shellcheck",
            "--norc",
            "--format=json1",
            "--severity=style",
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(
        self, rules: Optional[List[ReportingDescriptor]] = None
    ) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="ShellCheck",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://www.shellcheck.net/"),
                            rules=rules or [],
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
        config: ShellCheckScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Lint every shell script under *target* (one run per argv chunk)."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Reset at the top, above every early return.
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

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            scripts = self._shell_scripts(target, target_type, global_ignore_paths)
            if not scripts:
                self._plugin_log(
                    f"No shell scripts found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(scripts)
            base_args = self._base_args()
            chunks = _argv_chunks(base_args, [self._argv_path(p) for p in scripts])

            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("shellcheck.sarif")
            results_file.unlink(missing_ok=True)

            # One budget for every invocation, so scan_timeout bounds the scanner
            # and not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            responses: List[Dict[str, Any]] = []
            exit_codes: List[int | None] = []
            final_args: List[str] = []
            for chunk in chunks:
                final_args = [*base_args, "--", *chunk]
                responses.append(self._run_until(final_args, results_dir, deadline))
                exit_codes.append(self.exit_code)
                if responses[-1].get("timed_out") or (
                    self.exit_code not in self.success_exit_codes
                ):
                    break
            self._post_scan(target=target, target_type=target_type)

            comments: List[Dict[str, Any]] = []
            for response, exit_code in zip(responses, exit_codes):
                self.exit_code = exit_code
                self._check_response(response, timeout)
                comments.extend(self._parse_json1(response))

            sarif_report = convert_json1_comments(
                comments, tool_version=self.tool_version
            )
            with open_for_write(results_file) as handle:
                handle.write(
                    sarif_report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(sarif_report, final_args, target)
            return sarif_report
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    def _run_until(
        self, argv: List[str], results_dir: Path, deadline: Optional[float]
    ) -> Dict[str, Any]:
        """Run *argv* with whatever is left of the scan's time budget."""
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
            stderr_preference="both",
            env=self._subprocess_env(),
            timeout=remaining,
        )
        return response if isinstance(response, dict) else {}

    def _check_response(
        self, response: Dict[str, Any], timeout: Optional[float]
    ) -> None:
        if response.get("timed_out"):
            raise ScannerError(
                f"shellcheck timed out after {timeout}s and was killed, so it "
                "produced no complete report. Raise "
                "scanners.shellcheck.options.scan_timeout if these scripts "
                "legitimately need longer."
            )
        if self.exit_code not in self.success_exit_codes:
            stderr = (response.get("stderr") or "").strip()
            detail = f": {tool_output_excerpt(stderr, 500)}" if stderr else ""
            raise ScannerError(
                f"shellcheck exited {self.exit_code}, which is not a completed run "
                f"(0 = clean, 1 = findings){detail}"
            )

    @staticmethod
    def _parse_json1(response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The ``comments`` of a json1 document; raises when it is not one."""
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError("shellcheck exited without writing a json1 report")
        try:
            document = json.loads(stdout)
        except ValueError as e:
            raise ScannerError(f"shellcheck wrote output that is not JSON ({e})")
        if not isinstance(document, dict) or not isinstance(
            document.get("comments"), list
        ):
            raise ScannerError(
                "shellcheck wrote JSON that is not a json1 document "
                "(an object with a 'comments' list)"
            )
        return [c for c in document["comments"] if isinstance(c, dict)]

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "shellcheck")
        if not found:
            ASH_LOGGER.warning(
                "shellcheck executable not found in PATH. ASH does not install "
                "ShellCheck (GPL-3.0); install it with your package manager "
                "(for example `apt-get install shellcheck` or `brew install "
                "shellcheck`) or from https://github.com/koalaman/shellcheck/"
                "releases."
            )
        return found is not None


def convert_json1_comments(
    comments: List[Dict[str, Any]], *, tool_version: Optional[str] = None
) -> SarifReport:
    """Convert ShellCheck ``json1`` comments into a SARIF report.

    Every result gets ``properties.issue_severity`` from ``SHELLCHECK_LEVEL_MAP``
    and the SARIF level that agrees with it. A comment whose level is missing or
    unknown is rated HIGH/error.
    """
    rules: Dict[str, ReportingDescriptor] = {}
    results: List[Result] = []
    for comment in comments:
        code = comment.get("code")
        rule_id = f"SC{code}" if isinstance(code, int) else "SC0000"
        raw_level = comment.get("level")
        shellcheck_level = (
            raw_level if raw_level in SHELLCHECK_LEVEL_MAP else _UNKNOWN_LEVEL
        )
        severity, level = SHELLCHECK_LEVEL_MAP[shellcheck_level]
        message = str(comment.get("message") or rule_id)
        uri = str(comment.get("file") or "<unknown file>").replace("\\", "/")

        if rule_id not in rules:
            rules[rule_id] = ReportingDescriptor(
                id=rule_id,
                name=rule_id,
                shortDescription=MultiformatMessageString(text=message),
                helpUri=AnyUrl(f"https://www.shellcheck.net/wiki/{rule_id}"),
            )

        region: Dict[str, Any] = {}
        for src, dest in (
            ("line", "startLine"),
            ("endLine", "endLine"),
            ("column", "startColumn"),
            ("endColumn", "endColumn"),
        ):
            value = comment.get(src)
            if isinstance(value, int) and value > 0:
                region[dest] = value
        physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if region:
            physical["region"] = region
        results.append(
            Result.model_validate(
                {
                    "ruleId": rule_id,
                    "level": level.value,
                    "message": {"text": message},
                    "locations": [{"physicalLocation": physical}],
                    "properties": {
                        "issue_severity": severity,
                        "shellcheck_level": shellcheck_level,
                    },
                }
            )
        )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="ShellCheck",
                        version=tool_version,
                        informationUri=AnyUrl("https://www.shellcheck.net/"),
                        rules=[rules[k] for k in sorted(rules)],
                    )
                ),
                results=results,
            )
        ],
    )


def _argv_chunks(base_args: List[str], paths: List[str]) -> List[List[str]]:
    """Split *paths* so each command line stays under the cap.

    Every chunk has at least one path, so a single path longer than the cap is
    still attempted (and fails loudly) rather than dropped.
    """
    fixed = sum(len(a) + 3 for a in base_args) + len(" --")
    chunks: List[List[str]] = []
    current: List[str] = []
    size = fixed
    for path in paths:
        cost = len(path) + 3
        if current and size + cost > _MAX_COMMAND_LINE_CHARS:
            chunks.append(current)
            current, size = [], fixed
        current.append(path)
        size += cost
    if current:
        chunks.append(current)
    return chunks


__all__ = [
    "SHELLCHECK_LEVEL_MAP",
    "SHELL_EXTENSIONS",
    "SHELL_INTERPRETERS",
    "ShellCheckScanner",
    "ShellCheckScannerConfig",
    "ShellCheckScannerConfigOptions",
    "convert_json1_comments",
    "shebang_interpreter",
]
