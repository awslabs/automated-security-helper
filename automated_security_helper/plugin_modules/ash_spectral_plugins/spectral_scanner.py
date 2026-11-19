# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Spectral: an OpenAPI and AsyncAPI linter, as a community scanner plugin.

What it runs
------------
``spectral lint`` over the OpenAPI, Swagger and AsyncAPI descriptions in the scan
target, with Spectral's own recommended rulesets (``spectral:oas`` and
``spectral:asyncapi``). It finds API description defects: a missing ``operationId``,
an undefined path parameter, a broken ``$ref``, no ``servers``, and so on.

Spectral is a community plugin: it is loaded only when ``ash_spectral_plugins`` is
listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a scan
that does not list the module is unchanged by its existence.

Scan flow: the template flow (``_execute_scan`` returns the argv and the report path,
the base ``scan()`` runs it), the shape the betterleaks plugin uses. Spectral writes
SARIF to a file (``--output``), so nothing forces a hand-written ``scan()``. The one
override of ``scan()`` is a guard that skips a tree holding no JSON or YAML file:
Spectral exits 2 for that case (see "Exit status") and ASH reports it as a clean skip.

Invocation
----------
Measured on Spectral 6.17.1 (the pinned release, Linux x64 binary):

* ``--ruleset=<file>``: always passed. Without it Spectral reads ``.spectral.yaml``,
  ``.spectral.json`` or ``.spectral.js`` from the working directory, which is the
  scanned tree, and a ``.js`` ruleset is code. ASH writes a ruleset of its own
  (``extends: ["spectral:oas", "spectral:asyncapi"]``) next to the report, or passes
  the operator's ``options.ruleset_file``.
* ``--format=sarif --output=<file>``: the report. Spectral writes the file when there
  are no results too (an empty ``results`` array), so a missing report means the run
  failed.
* ``--fail-severity=hint``: any result, of any severity, exits 1. Spectral's default,
  ``error``, exits 0 when it only found warnings. Exit status is not the severity
  signal here; the SARIF levels are.
* ``--ignore-unknown-format``: a JSON or YAML file that is not an OpenAPI or AsyncAPI
  description is skipped silently. Without it Spectral reports an
  ``unrecognized-format`` warning for each such file.
* ``--quiet``: no logging beyond the report.
* The documents are the glob ``**/*.{json,yaml,yml}`` (an absolute path prefix for the
  converted target), passed as a plain argument. NOT after ``--``: with ``--`` Spectral
  lints nothing and reads standard input (measured: "Linting 0", and an ``EAGAIN``
  read error when stdin is not a pipe), which is the one place this plugin does not
  follow the "path after ``--``" convention of the other plugins. A glob never starts
  with ``-``, so it cannot be read as a flag. The glob skips dot-directories.

The working directory is the source directory, so report URIs are source-relative
(``api/openapi.yaml``).

Severity
--------
Spectral's SARIF formatter maps its severities to SARIF levels: error to ``error``,
warn to ``warning``, info and hint both to ``note``. ASH rates them the way it rates
hadolint's lint findings, HIGH, MEDIUM and LOW, and sets the SARIF level to agree:

* ``error`` -> HIGH / ``error``
* ``warning`` -> MEDIUM / ``warning``
* ``note`` -> LOW / ``note``

They are lint findings about an API description, not exploitable vulnerabilities, so
``error`` is HIGH and not the CRITICAL ASH's generic ``error`` level would mean. Spectral
always writes a level. A result that arrives without one is read by ASH's SARIF model
as ``warning`` (the SARIF default), so it is MEDIUM like every other scanner's. A level
this plugin does not know, or ``none``, is HIGH / ``error``: the unresolvable case errs
to the more severe rating.

Exit status
-----------
With ``--fail-severity=hint``: 0 when there are no results, 1 when there are any, 2
when Spectral itself failed (a ruleset it cannot load, no document to lint, an error
while running). 0 and 1 are success and 2, or any other code, fails the scan even if a
report is on disk.

What the tree can reach
-----------------------
Spectral resolves ``$ref`` pointers while it lints, and has no flag to turn that off.
A description in the scanned tree can point at a remote URL or at a file outside the
tree, and Spectral will fetch or read it (measured: both show up as ``invalid-ref``
errors when the target cannot be fetched or read). ASH's strict sandbox grants no
network and no read outside the tree, so under ``--sandbox`` such a reference is an
unresolved-reference finding, not a fetch.

Offline
-------
The rulesets are compiled into the binary. Only a remote ``$ref`` needs the network.

Sandbox
-------
The strict default, ``SandboxRequirements()``: no network, baseline environment only.
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

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
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
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: ``--fail-severity=hint`` makes Spectral exit 1 for a run with any result. See the
#: module docstring.
RESULTS_EXIT_CODE = 1

#: The ruleset ASH writes when the operator names none: Spectral's documented
#: recommended rulesets for OpenAPI and AsyncAPI.
DEFAULT_RULESET = 'extends: ["spectral:oas", "spectral:asyncapi"]\n'

#: The documents Spectral is asked to lint, as a glob under the target.
DOCUMENT_GLOB = "**/*.{json,yaml,yml}"

#: File name extensions the glob matches.
DOCUMENT_EXTENSIONS = (".json", ".yaml", ".yml")

#: SARIF level Spectral wrote -> (ASH severity, SARIF level ASH sets). See "Severity"
#: in the module docstring.
SPECTRAL_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}

#: Rating of a result with no level or a level not in ``SPECTRAL_LEVEL_MAP``.
UNRATED: Tuple[str, Level] = ("HIGH", Level.error)


def _has_candidate_documents(root: Path) -> bool:
    """Whether ``root`` holds a file the document glob would match.

    Walks without following links and skips dot-directories, as the glob does, and
    stops at the first match.
    """
    try:
        for _, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            if any(
                name.endswith(DOCUMENT_EXTENSIONS) and not name.startswith(".")
                for name in filenames
            ):
                return True
    except OSError:
        # Cannot tell; let Spectral say why.
        return True
    return False


class SpectralScannerConfigOptions(ScannerOptionsBase):
    ruleset_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a Spectral ruleset (YAML, JSON or JavaScript) to use in "
                "place of ASH's default, which extends Spectral's recommended "
                "`spectral:oas` and `spectral:asyncapi` rulesets. A relative path is "
                "taken from the directory of the config file that sets it, or from "
                "the working directory for --config-overrides, not from the source "
                "directory. A JavaScript ruleset runs code, and a ruleset in the "
                "scanned repository can drop every rule, so the scanned tree does "
                f"not choose it. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning. A path that does not exist fails the scan. "
                "A `.spectral.yaml` in the scanned tree is never read."
            ),
        ),
    ] = None


class SpectralScannerConfig(ScannerPluginConfigBase):
    name: Literal["spectral"] = "spectral"
    enabled: bool = True
    options: Annotated[
        SpectralScannerConfigOptions,
        Field(description="Configure the spectral scanner"),
    ] = SpectralScannerConfigOptions()


@ash_scanner_plugin
class SpectralScanner(ScannerPluginBase[SpectralScannerConfig]):
    """OpenAPI and AsyncAPI linting over the scan target using Spectral."""

    #: Not Python-only: Spectral is a native (Node.js packaged) binary, installed from
    #: its pinned release asset.
    python_only: ClassVar[bool | None] = False

    # The rulesets are compiled into the binary; only a remote $ref needs the network.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # 0 no results, 1 results, anything else (2 is Spectral's own failure) fails.
    success_exit_codes: ClassVar[Set[int]] = {0, RESULTS_EXIT_CODE}
    # The strict default (no network, baseline environment only); see "Sandbox" in the
    # module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SpectralScannerConfig()
        self.command = "spectral"
        self.subcommands = ["lint"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing from
        # the base resolver can add a token Spectral would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "SpectralScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``."""
        self.custom_install_commands.update(pinned_tool_install_commands("spectral"))
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> SpectralScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, SpectralScannerConfigOptions):
            return options
        return SpectralScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("SpectralScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """A reason when neither the source tree nor the converted tree holds a
        JSON or YAML file; None otherwise."""
        if self.context is None:
            return None
        roots = [Path(self.context.source_dir)]
        work_dir = getattr(self.context, "work_dir", None)
        if work_dir is not None:
            roots.append(Path(work_dir))
        if any(root.is_dir() and _has_candidate_documents(root) for root in roots):
            return None
        return "no JSON or YAML file for Spectral to read"

    def _operator_ruleset_path(self) -> Optional[Path]:
        """``options.ruleset_file`` when the operator set it, else None (with a
        warning).

        Raises:
            ScannerError: the operator's path is not a file, or is inside the scanned
                tree and leads out of it through a symlink.
        """
        value = self._options().ruleset_file
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        chosen = operator_path(
            config,
            "scanners.spectral.options.ruleset_file",
            value,
            self._source_dir(),
            outside_tree=False,
        )
        if chosen.refusal == LEADS_OUT_OF_THE_TREE:
            raise ScannerError(
                f"scanners.spectral.options.ruleset_file is {str(value)!r}, a path "
                "inside the scanned tree that resolves outside it through a symbolic "
                "link. The scanned repository decides what is at that path, so "
                "Spectral is not given it, and Spectral is not run."
            )
        if chosen.path is None:
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.spectral.options.ruleset_file "
                    f"({str(value)!r}): {chosen.refusal}. Spectral's recommended "
                    "rulesets are used.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
            return None
        if not chosen.path.is_file():
            raise ScannerError(
                f"scanners.spectral.options.ruleset_file is {str(value)!r}, which is "
                f"not a file (resolved to {chosen.path.as_posix()}). Fix the path or "
                "unset the option; Spectral is not run without it."
            )
        return chosen.path

    def _ruleset(self, results_file: Path) -> Path:
        """The ruleset to pass: the operator's, else ASH's, written beside the report."""
        operator = self._operator_ruleset_path()
        if operator is not None:
            return operator
        ruleset = results_file.parent / "spectral-ruleset.yaml"
        with open_for_write(ruleset, encoding="utf-8") as handle:
            handle.write(DEFAULT_RULESET)
        return ruleset

    def _documents(self, target: Path) -> List[str]:
        """What Spectral is asked to lint.

        The glob relative to the working directory for the source (the working
        directory is the source directory, so reported paths are source-relative), the
        glob under the absolute path for the converted target, and the file itself for
        a file target.
        """
        target = Path(target)
        if target.is_file():
            return [target.absolute().as_posix()]
        if target.absolute() == self._source_dir().absolute():
            return [DOCUMENT_GLOB]
        return [f"{target.absolute().as_posix()}/{DOCUMENT_GLOB}"]

    def _build_arguments(
        self, target: Path, results_file: Path, ruleset: Path
    ) -> List[str]:
        """The full Spectral argv for one target.

        Every option is one ``--flag=value`` token. The documents come last and NOT
        after ``--``; see "Invocation" in the module docstring.
        """
        return [
            self.command or "spectral",
            *self.subcommands,
            f"--ruleset={ruleset.as_posix()}",
            "--format=sarif",
            f"--output={results_file.as_posix()}",
            "--fail-severity=hint",
            "--ignore-unknown-format",
            "--quiet",
            *self._documents(target),
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(  # type: ignore[override]
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """The template scan, except for a tree with no JSON or YAML file.

        Spectral exits 2 and writes no report when its glob matches nothing, which
        would fail the scan of every tree without an API description. That tree is a
        clean skip, the same as an empty target.
        """
        if Path(target).is_dir() and not _has_candidate_documents(Path(target)):
            self.exit_code = 0
            self.start_time = None
            self.end_time = None
            self.output = []
            self._reset_errors()
            self._plugin_log(
                f"{target} holds no JSON or YAML file. Skipping scan.",
                target_type=target_type,
                level=self.empty_target_log_level,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Spectral run.

        ``global_ignore_paths`` is not translated into Spectral config: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("SpectralScanner has no results directory")
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs.
        self.exit_code = 0
        # Absolute: Spectral runs with its working directory at the source directory.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "spectral.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        ruleset = self._ruleset(results_file)
        final_args = self._build_arguments(target, results_file, ruleset)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep Spectral's stderr out of ``self.errors``.

        Its messages can quote text from the scanned documents (a ``$ref`` it cannot
        read, a parse error), and the scanner executor copies ``errors`` into the
        scan's results. The stream stays in the log file.
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
        """The failure and where Spectral's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (spectral was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        if self.scan_could_not_stop is not None:
            return (
                f"{detail} (no exit code: ASH could not stop spectral). "
                f"spectral's log is not quoted here; see {log_path.as_posix()}"
            )
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        return (
            f"{detail} (exit code {self.exit_code}: {verdict}). spectral's log is "
            f"not quoted here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result and set its SARIF level to agree. See "Severity"."""
        for result in sarif_report.get_all_results():
            raw_level = getattr(result.level, "value", result.level)
            severity, level = SPECTRAL_LEVEL_MAP.get(str(raw_level), UNRATED)
            result.level = level
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("lint", "api-description"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "spectral")
        if not found:
            ASH_LOGGER.warning(
                "spectral executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_spectral_plugins\"]' --tool spectral`."
            )
        return found is not None


__all__ = [
    "DEFAULT_RULESET",
    "DOCUMENT_GLOB",
    "RESULTS_EXIT_CODE",
    "SPECTRAL_LEVEL_MAP",
    "SpectralScanner",
    "SpectralScannerConfig",
    "SpectralScannerConfigOptions",
]
