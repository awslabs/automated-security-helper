# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hadolint: a Dockerfile linter, run as an opt-in builtin scanner.

What it does
------------
Finds every Dockerfile in the scan set (``Dockerfile``, ``*.Dockerfile``,
``Dockerfile.*`` and ``Containerfile``, after ASH's ignore files and
``global_settings.ignore_paths`` have had their say), passes them to one
``hadolint --format sarif`` invocation by name, and turns hadolint's report into
ASH results. hadolint runs its own DL rules and the ShellCheck (SC) rules over
each ``RUN`` instruction.

hadolint is opt-in (``OPT_IN = True``, config ``enabled: false``). A run that
has not enabled it does not construct this class at all, so a default scan's
output is unchanged by its existence. See ``core/scanner_opt_in.py``.

Severity mapping
----------------
hadolint has four levels and ASH has five severities. The mapping, and the
SARIF level each result is rewritten to so that level-reading consumers agree
with the severity:

=========  ==============  ===========
hadolint   ASH severity    SARIF level
=========  ==============  ===========
error      HIGH            error
warning    MEDIUM          warning
info       LOW             note
style      INFO            none
=========  ==============  ===========

``error`` is HIGH rather than the CRITICAL that ASH's generic ``error`` level
maps to: hadolint's errors are build-correctness and deprecation problems (a
Dockerfile that does not parse, ``MAINTAINER``, a relative ``WORKDIR``), which
are serious lint and not exploitable vulnerabilities.

Why a second, JSON-format invocation
------------------------------------
hadolint's SARIF presenter writes ``note`` for both ``info`` and ``style``, so
the SARIF report alone cannot say which of LOW and INFO a ``note`` is. Measured
on 2.15.1: with ``--style DL3003`` the DL3003 result is ``"level": "note"`` in
SARIF and ``"level": "style"`` in JSON. hadolint's level is a function of the
rule code and the configuration (``override`` in ``.hadolint.yaml``), so the
JSON pass is read only for a ``code -> level`` table, and only when the SARIF
report contains a ``note`` at all. The SARIF report stays the source of every
result; the JSON pass can only refine a ``note`` into LOW or INFO.

If that pass fails or a code maps to two levels, the ``note`` stays LOW -- the
more severe of the two possibilities -- and the scan log says why.

Targets and unparseable Dockerfiles
-----------------------------------
``targets_attempted`` is the number of Dockerfiles passed, so a tree with none
reports SKIPPED rather than PASSED. A Dockerfile hadolint cannot parse is NOT
counted as a failed target: hadolint reports it as rule DL1000 at ``error``
level (HIGH here), so the gap is in the report as a finding. Counting it as
well would turn every template named ``Dockerfile.j2`` into ASH's exit 1,
"scan incomplete", on top of the HIGH finding that already says so.

Exit status and configuration errors
------------------------------------
``--no-fail`` is passed, so 0 means hadolint ran whatever it found and any
other status means it did not. Without it hadolint exits 1 both for "found a
violation" and for "the file does not exist", which ASH cannot tell apart.

``--no-fail`` does not cover one failure: a configuration file hadolint cannot
parse is reported on stderr and then IGNORED, and the run proceeds with
defaults and exits 0. Measured on 2.15.1 with ``ignored: [`` as the whole file.
For a user who configured ignored rules or severity overrides that silently
changes the report, so ASH reads stderr for hadolint's "Error parsing your
config file" message and fails the scan instead.

Suppressions
------------
ASH's own rule, path and line suppressions apply to these results the same way
as to any scanner's, because they act on the SARIF ASH builds. hadolint's
inline ``# hadolint ignore=DL3008`` pragmas also apply, inside hadolint, before
ASH sees anything. Package-scoped suppressions do not apply: no hadolint result
identifies a package. Symbol-scoped suppressions do not apply either: a
Dockerfile has no functions or classes.

Offline
-------
hadolint reads only the files it is given and never uses the network, so it
behaves identically offline. A missing binary is reported MISSING by the scan
phase like any other builtin. ``scan_timeout`` bounds the whole scan: every
hadolint process this scanner starts, SARIF and JSON passes together, shares
one deadline.

Environment
-----------
hadolint reads ``HADOLINT_*`` environment variables and, when no ``--config``
is given, a user-level config file under ``$XDG_CONFIG_HOME`` or ``$HOME``.

The variables that decide WHAT is reported -- ``HADOLINT_IGNORE``,
``HADOLINT_OVERRIDE_*``, ``HADOLINT_TRUSTED_REGISTRIES``,
``HADOLINT_REQUIRE_LABELS``, ``HADOLINT_STRICT_LABELS`` and
``HADOLINT_DISABLE_IGNORE_PRAGMA`` -- are user policy, like the config file, and
are passed through.

The ones that decide HOW hadolint runs are removed from its environment
(``_INVOCATION_ENV_VARS``), because some of them beat the command line. Measured
on 2.15.1: ``HADOLINT_FORMAT=json hadolint --format sarif Dockerfile`` writes
JSON. Inherited from a developer's shell, that would turn every ASH run into a
parse failure.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
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
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable

#: hadolint level -> (ASH severity, SARIF level). See the module docstring.
HADOLINT_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "info": ("LOW", Level.note),
    "style": ("INFO", Level.none),
}

#: What a SARIF level means when the JSON pass cannot refine it. ``note`` is
#: ``info`` here, not ``style``: of the two levels hadolint writes as ``note``,
#: info is the more severe, so an unrefined note is never under-reported.
_SARIF_LEVEL_TO_HADOLINT: Dict[str, str] = {
    "error": "error",
    "warning": "warning",
    "note": "info",
    "none": "style",
}

#: hadolint's stderr text for a configuration file it could not parse and is
#: about to ignore. Verbatim from 2.15.1.
_CONFIG_PARSE_ERROR_MARKER = "Error parsing your config file"

#: hadolint environment variables that control the invocation rather than the
#: rules, removed from hadolint's environment. The list is every ``HADOLINT_*``
#: name in the 2.15.1 binary that is not rule policy (``strings`` on it).
_INVOCATION_ENV_VARS = frozenset(
    {
        "HADOLINT_FAILURE_THRESHOLD",
        "HADOLINT_FORMAT",
        "HADOLINT_NOFAIL",
        "HADOLINT_VERBOSE",
    }
)

#: Config files looked for, in order, relative to the source directory, when
#: ``options.config_file`` is not set. ``.hadolint.yaml`` and ``.hadolint.yml``
#: are the names hadolint itself reads from its working directory.
DEFAULT_CONFIG_CANDIDATES = (
    ".hadolint.yaml",
    ".hadolint.yml",
    ".ash/.hadolint.yaml",
    ".ash/hadolint.yaml",
)


def is_dockerfile_name(name: str) -> bool:
    """Whether a file's basename is one hadolint is pointed at.

    ``Dockerfile``, ``Containerfile``, ``<anything>.Dockerfile`` and
    ``Dockerfile.<anything>``, matched case-sensitively, which is how Docker and
    Podman spell their defaults.

    ``Dockerfile.dockerignore`` and ``<name>.Dockerfile.dockerignore`` are not
    Dockerfiles: they are BuildKit's per-Dockerfile ignore files, and
    ``Dockerfile.*`` would otherwise send them to hadolint as unparseable
    Dockerfiles.
    """
    if name.endswith(".dockerignore"):
        return False
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.endswith(".Dockerfile") and len(name) > len(".Dockerfile"):
        return True
    return name.startswith("Dockerfile.") and len(name) > len("Dockerfile.")


class HadolintScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a hadolint configuration file, relative to the source "
                "directory. When unset, ASH looks for .hadolint.yaml, "
                ".hadolint.yml, .ash/.hadolint.yaml and .ash/hadolint.yaml in the "
                "source directory and passes the first it finds. A path that is "
                "set and does not exist fails the scan rather than running with "
                "hadolint's defaults."
            ),
        ),
    ] = None


class HadolintScannerConfig(ScannerPluginConfigBase):
    name: Literal["hadolint"] = "hadolint"
    # Opt-in: see core/scanner_opt_in.py. Must stay False, and a test fails any
    # shipped opt-in scanner whose config defaults to enabled.
    enabled: bool = False
    options: Annotated[
        HadolintScannerConfigOptions, Field(description="Configure hadolint")
    ] = HadolintScannerConfigOptions()


@ash_scanner_plugin
class HadolintScanner(ScannerPluginBase[HadolintScannerConfig]):
    """Lints Dockerfiles with hadolint. Opt-in."""

    OPT_IN: ClassVar[bool] = True
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # With --no-fail, 0 is the only status hadolint gives a run that completed.
    success_exit_codes: ClassVar[Set[int]] = {0}

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = HadolintScannerConfig()
        self.command = "hadolint"
        self.tool_type = ScannerToolType.IAC
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "HadolintScanner":
        """Install hadolint from its pinned release asset (see tool_downloads)."""
        self.custom_install_commands.update(pinned_tool_install_commands("hadolint"))
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: hadolint overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        """The plugin context; the base class refuses to construct without one."""
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("HadolintScanner has no plugin context")
        return self.context

    @property
    def _options(self) -> HadolintScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, HadolintScannerConfigOptions):
            return options
        return HadolintScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _resolve_config_file(self) -> Optional[Path]:
        """The hadolint config to pass with ``--config``, or None for none.

        Resolved against the source directory rather than the process working
        directory, for the reason grype and checkov give for the same lookup.

        Raises:
            ScannerError: when ``options.config_file`` names a file that does not
                exist. Running with hadolint's defaults instead would drop the
                ignores and severity overrides the user asked for, and nothing in
                the report would say so.
        """
        source_dir = Path(self._ctx.source_dir)
        configured = self._options.config_file
        if configured is not None and str(configured).strip():
            candidate = Path(configured)
            if not candidate.is_absolute():
                candidate = source_dir / candidate
            if not candidate.is_file():
                raise ScannerError(
                    f"scanners.hadolint.options.config_file is {configured!s}, "
                    f"which does not exist (looked for {candidate.as_posix()}). "
                    "Fix the path, or unset it to use hadolint's defaults."
                )
            return candidate.resolve()
        rejected = False
        for name in DEFAULT_CONFIG_CANDIDATES:
            candidate = source_dir / name
            if not os.path.lexists(candidate):
                continue
            resolved = candidate.resolve()
            # Discovered in the scanned tree, so held to it, as Dockerfiles are:
            # a regular file inside the tree, or nothing. Anything else -- a link
            # out of the tree, or to a device or FIFO, which hadolint would read
            # from (/dev/zero exhausts its memory) -- is rejected. A config the
            # operator names explicitly (above) may live anywhere.
            if not candidate.is_file() or not resolved.is_relative_to(
                source_dir.resolve()
            ):
                self._plugin_log(
                    f"Ignoring {candidate.as_posix()}: it is not a regular file "
                    f"inside the scanned tree (resolves to {resolved.as_posix()}).",
                    level=logging.WARNING,
                )
                rejected = True
                continue
            return resolved
        if rejected:
            # Passing no --config is not enough to ignore it: hadolint runs in the
            # source directory and reads ./.hadolint.yaml there itself, following
            # the symlink. An explicit config stops that lookup. "{}" and not an
            # empty file, which hadolint reports as a parse error. Only in this
            # case, because an explicit config also stops hadolint reading the
            # user-level config under $XDG_CONFIG_HOME, which otherwise applies.
            stub = Path(self.results_dir or self._ctx.output_dir).joinpath(
                "hadolint-no-config.yaml"
            )
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text("{}\n", encoding="utf-8")
            return stub.resolve()
        return None

    def _dockerfiles(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The Dockerfiles under *target* to pass to hadolint, sorted.

        The source branch reads ASH's scan set, so .gitignore, .ashignore and the
        rest have already removed what they remove; ASH's own output directory
        is dropped as well, since it sits under the source tree by default. The
        converted branch walks ``work_dir``, as cfn-nag and detect-secrets do.

        Each file must resolve inside *target*. A symlink named ``Dockerfile``
        pointing outside the tree is skipped rather than followed: hadolint
        echoes fragments of a file it cannot parse back in its messages, so
        following such a link would copy text from outside the scanned tree into
        the report.
        """
        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [
                Path(p)
                for p in scan_set(
                    source=str(self._ctx.source_dir),
                    output=str(self._ctx.output_dir),
                )
            ]

        root = Path(target).resolve()
        absolute_output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()

        selected: List[Path] = []
        for path in candidates:
            if not is_dockerfile_name(path.name):
                continue
            if target_type == "source" and path.absolute().is_relative_to(
                absolute_output_dir
            ):
                continue
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
            except OSError:
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
            selected.append(path)
        return sorted(set(selected))

    @staticmethod
    def _ignored(
        path: Path, source_dir: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> bool:
        """Whether ``global_settings.ignore_paths`` excludes *path*.

        Matched the way detect-secrets matches it, on the path relative to the
        source directory, so one ignore entry means the same thing to both.
        """
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
        """How *path* is spelled on hadolint's command line, and so in its report.

        Relative to the source directory, which is the subprocess's working
        directory, so result URIs come out relative the way ASH reports them.
        A file outside it (the converted tree, when the output directory is
        elsewhere) keeps its absolute path.
        """
        # absolute() and not resolve(): a symlink that passed the containment
        # check in _dockerfiles is reported under its own name, not its target's.
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        """The process environment minus ``_INVOCATION_ENV_VARS``."""
        return {k: v for k, v in os.environ.items() if k not in _INVOCATION_ENV_VARS}

    def _base_args(self, config_file: Optional[Path]) -> List[str]:
        args = [self.command or "hadolint", "--no-fail", "--no-color"]
        if config_file is not None:
            args.extend(["--config", config_file.as_posix()])
        return args

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
                            name="Hadolint",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/hadolint/hadolint"
                            ),
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
        config: HadolintScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Lint every Dockerfile under *target* (one hadolint run per argv chunk)."""
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

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            dockerfiles = self._dockerfiles(target, target_type, global_ignore_paths)
            if not dockerfiles:
                self._plugin_log(
                    f"No Dockerfiles found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            config_file = self._resolve_config_file()
            if config_file is not None:
                self._plugin_log(
                    f"Using hadolint config {config_file.as_posix()}",
                    target_type=target_type,
                    level=logging.INFO,
                )

            self.targets_attempted = len(dockerfiles)
            argv_paths = [self._argv_path(p) for p in dockerfiles]
            base_args = self._base_args(config_file)
            chunks = _argv_chunks(base_args, argv_paths)

            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("hadolint.sarif")
            results_file.unlink(missing_ok=True)

            # One budget for every invocation of this scan, SARIF and JSON passes
            # alike, so scan_timeout bounds the scanner and not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            responses: List[Dict[str, Any]] = []
            exit_codes: List[int] = []
            final_args: List[str] = []
            for chunk in chunks:
                final_args = self._format_args(base_args, "sarif", chunk)
                responses.append(self._run_until(final_args, results_dir, deadline))
                exit_codes.append(self.exit_code)
                if responses[-1].get("timed_out") or self.exit_code != 0:
                    break
            # Before the checks below, so the scan's end time is recorded however
            # it ends.
            self._post_scan(target=target, target_type=target_type)

            reports: List[SarifReport] = []
            for response, exit_code in zip(responses, exit_codes):
                self.exit_code = exit_code
                self._check_sarif_response(response, timeout, config_file)
                reports.append(self._parse_sarif(response))

            sarif_report = reports[0]
            for extra in reports[1:]:
                merged = sarif_report.runs[0].results or []
                merged.extend(extra.runs[0].results or [])
                sarif_report.runs[0].results = merged
            results_file.write_text(
                sarif_report.model_dump_json(
                    exclude_none=True, exclude_unset=True, by_alias=True
                ),
                encoding="utf-8",
            )

            driver = sarif_report.runs[0].tool.driver
            if driver.version:
                self.tool_version = driver.version

            levels = None
            if any(
                _level_name(r.level) == "note" for r in sarif_report.get_all_results()
            ):
                levels = self._hadolint_levels(base_args, chunks, results_dir, deadline)
            self.apply_severity_mapping(sarif_report, levels)

            self._inject_invocation(sarif_report, final_args, target)
            return sarif_report
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    @staticmethod
    def _format_args(base_args: List[str], fmt: str, chunk: List[str]) -> List[str]:
        """``hadolint ... --format <fmt> -- <files>``.

        "--" ends option parsing, so a Dockerfile whose name starts with a dash
        is read as a file rather than as a flag. The report is read from stdout
        rather than written with --output, because --output is newer than the
        hadolint some installs carry: nixpkgs' 2.14.0 rejects it with "Invalid
        option `--output'".
        """
        return [*base_args, "--format", fmt, "--", *chunk]

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

    def _check_sarif_response(
        self,
        response: Dict[str, Any],
        timeout: Optional[float],
        config_file: Optional[Path],
    ) -> None:
        if response.get("timed_out"):
            raise ScannerError(
                f"hadolint timed out after {timeout}s and was killed, so it "
                "produced no report. Raise scanners.hadolint.options.scan_timeout "
                "if these Dockerfiles legitimately need longer."
            )
        stderr = response.get("stderr") or ""
        if _CONFIG_PARSE_ERROR_MARKER in stderr:
            raise ScannerError(
                "hadolint could not parse its configuration file "
                f"({config_file.as_posix() if config_file else 'auto-discovered'}) "
                "and would have run with its defaults instead, ignoring any rules "
                f"and severity overrides it sets. hadolint said: {stderr.strip()}"
            )
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"hadolint exited {self.exit_code}, which with --no-fail means "
                "it did not complete"
            )

    @staticmethod
    def _parse_sarif(response: Dict[str, Any]) -> SarifReport:
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError("hadolint exited 0 but wrote no report")
        report = SarifReport.model_validate(json.loads(stdout))
        if not report.runs:
            raise ScannerError("hadolint wrote a SARIF report with no runs")
        return report

    def _hadolint_levels(
        self,
        base_args: List[str],
        chunks: List[List[str]],
        results_dir: Path,
        deadline: Optional[float],
    ) -> Optional[Dict[str, str]]:
        """``rule code -> hadolint level`` from JSON-format runs, or None.

        None when any run fails or its output cannot be read, which leaves every
        ``note`` at LOW. A code that appears at two levels is left out of the
        table, with the same effect for that code.
        """
        seen: Dict[str, Set[str]] = {}
        # The SARIF runs' exit code and errors are the scanner's verdict; these
        # passes must not overwrite them.
        saved_exit, saved_errors = self.exit_code, list(self.errors)
        reason = None
        try:
            for chunk in chunks:
                response = self._run_until(
                    self._format_args(base_args, "json", chunk), results_dir, deadline
                )
                if response.get("timed_out"):
                    reason = "the JSON pass ran out of the scan's time budget"
                    break
                if self.exit_code != 0:
                    reason = f"the JSON pass exited {self.exit_code}"
                    break
                try:
                    entries = json.loads(response.get("stdout") or "[]")
                except ValueError as e:
                    reason = f"its output could not be read ({e})"
                    break
                if not isinstance(entries, list):
                    reason = "its output was not a list"
                    break
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    code, level = entry.get("code"), entry.get("level")
                    if isinstance(code, str) and isinstance(level, str):
                        seen.setdefault(code, set()).add(level)
        finally:
            self.exit_code, self.errors = saved_exit, saved_errors

        if reason is not None:
            self._plugin_log(
                "Could not tell hadolint's info findings from its style findings "
                f"because {reason}; every SARIF 'note' is reported as LOW.",
                level=logging.WARNING,
            )
            return None
        return {code: next(iter(lv)) for code, lv in seen.items() if len(lv) == 1}

    @staticmethod
    def apply_severity_mapping(
        sarif_report: SarifReport, levels: Optional[Dict[str, str]] = None
    ) -> SarifReport:
        """Rewrite each result's severity and level from its hadolint level.

        *levels* is the ``code -> hadolint level`` table from the JSON pass. It
        is consulted only for a ``note``, the one SARIF level that does not
        determine the hadolint level, and only a level that SARIF would also
        have written as ``note`` (info or style) is accepted from it.
        """
        for result in sarif_report.get_all_results():
            # A missing or unknown level is read as error, the default ASH's SARIF
            # model gives Result.level, so nothing is under-reported.
            sarif_level = _level_name(result.level) or "error"
            hadolint_level = _SARIF_LEVEL_TO_HADOLINT.get(sarif_level, "error")
            if sarif_level == "note" and levels:
                refined = levels.get(result.ruleId or "")
                if refined in ("info", "style"):
                    hadolint_level = refined
            severity, level = HADOLINT_LEVEL_MAP[hadolint_level]
            result.level = level
            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
            setattr(result.properties, "hadolint_level", hadolint_level)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "hadolint")
        if not found:
            ASH_LOGGER.warning(
                "hadolint executable not found in PATH. Install it with "
                "`ash dependencies install --tool hadolint`."
            )
        return found is not None


#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: Upper bound on one hadolint command line, in characters. Windows caps a
#: command line at 32,767 characters (CreateProcess); the margin leaves room for
#: quoting. A tree with more Dockerfiles than fit is linted in several runs whose
#: results are merged.
_MAX_COMMAND_LINE_CHARS = 24_000


def _argv_chunks(base_args: List[str], paths: List[str]) -> List[List[str]]:
    """Split *paths* so each ``hadolint`` command line stays under the cap.

    Every chunk has at least one path, so a single path longer than the cap is
    still attempted (and fails loudly) rather than dropped.
    """
    fixed = sum(len(a) + 3 for a in base_args) + len(" --format sarif --")
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


def _level_name(level: Any) -> Optional[str]:
    """A SARIF level's string value, whether it holds the enum or the string."""
    if level is None:
        return None
    return str(getattr(level, "value", level)).lower()


__all__ = [
    "DEFAULT_CONFIG_CANDIDATES",
    "HADOLINT_LEVEL_MAP",
    "HadolintScanner",
    "HadolintScannerConfig",
    "HadolintScannerConfigOptions",
    "is_dockerfile_name",
]
