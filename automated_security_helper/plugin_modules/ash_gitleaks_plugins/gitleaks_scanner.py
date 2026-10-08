# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks secret scanner, as a community scanner plugin.

What it runs
------------
``gitleaks dir`` over the scan target: the files as they are on disk, not git
history. History scanning (``gitleaks git``) answers a different question --
"was a secret ever committed" -- and its findings point at commits rather than
at lines a reader can open, which none of ASH's suppression or reporting paths
understand. It also needs a full clone, which most CI checkouts are not. ASH's
other secret scanner, detect-secrets, scans the working tree too, so both answer
the same question and their findings line up file for file.

Every invocation carries these flags, and none of them is configurable:

* ``--redact=100``: gitleaks writes ``REDACTED`` in place of every secret value,
  in its SARIF snippet and in its log. ASH's own ``utils/secret_masking.py``
  only knows bandit's password rules, so it does not cover gitleaks findings;
  the redaction has to happen in the tool. ``_post_process_sarif`` also
  overwrites any snippet that is not ``REDACTED``, so a future gitleaks that
  added the match to its SARIF still could not put a secret in ASH's outputs.
  Written with ``=`` because gitleaks declares ``--redact`` with an optional
  value: ``--redact 100`` would make ``100`` the scan path.
* ``--exit-code=2``: gitleaks exits 1 both when it finds leaks (its default
  ``--exit-code``) and when it fails (every fatal log line exits 1, including an
  unreadable config). Moving the leaks code to 2 is the only way to tell those
  apart, so 0 and 2 are success and 1 is a failure.
* ``--no-banner``, ``--no-color``: the log goes to a file nobody reads in a
  terminal.
* ``--gitleaks-ignore-path=<source dir>``: gitleaks reads ``.gitleaksignore``
  from its working directory by default, which is the source directory for the
  source scan and would be nothing useful for the converted one.

Config resolution
-----------------
gitleaks' own order is ``--config``, then ``GITLEAKS_CONFIG``, then
``GITLEAKS_CONFIG_TOML``, then ``<target>/.gitleaks.toml``, then its built-in
rules. ASH keeps that order with one change: it looks for ``.gitleaks.toml`` in
the SOURCE directory and passes it explicitly, so the converted target (which
lives under the output directory) is scanned with the same rules as the source.
When either environment variable is set nothing is discovered and gitleaks
resolves it, so an operator who exported one still gets it. ``config_file`` wins
over all of it, and a ``config_file`` that does not exist fails the scan rather
than falling back to the default rules, which would scan with rules the operator
did not ask for and report clean.

Paths
-----
The source target is passed as ``.`` with the working directory at the source
directory, so gitleaks reports paths like ``src/settings.py``. That is the form
``.gitleaksignore`` fingerprints are written in (``<file>:<rule>:<line>``), so a
fingerprint file written against a plain ``gitleaks dir .`` run keeps working
under ASH. The converted target is passed as an absolute path, as every other
scanner receives it.

ASH's output directory is not excluded at the tool. gitleaks has no exclude
flag, and the only route -- a generated config that extends the user's -- would
take over the config precedence above. ``apply_suppressions_to_sarif`` drops
every finding under the output directory for every scanner, which is what keeps
ASH's previous reports out of this one too.

Severity
--------
gitleaks SARIF results carry no ``level`` (measured on 8.30.1). Every gitleaks
result is set to ``level: error``, which ASH reports as CRITICAL. That is the
rating detect-secrets findings get (``detect_secrets_scanner`` sets
``Level.error`` on each), so a credential reads the same whichever of the two
found it.

It is set rather than left to ASH's SARIF model, whose ``Result.level``
defaults to "error" too. A default is not a set field, so the ``exclude_unset``
dump ASH writes its SARIF with drops it, and whoever reads that file applies the
SARIF spec's default for an absent level instead, which is "warning". gitleaks has no per-rule confidence to grade on: every rule is "a
credential of this kind is present", and an exposed credential is the same
severity whichever provider issued it.
"""

import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
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
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER

#: The text gitleaks writes in place of a secret under ``--redact``.
REDACTED = "REDACTED"

#: Exit code gitleaks is told to use when it finds leaks. See the module docstring.
LEAKS_EXIT_CODE = 2

#: Config files ASH looks for in the source directory, in order, when
#: ``config_file`` is not set. ``.gitleaks.toml`` is gitleaks' own discovery name.
DEFAULT_CONFIG_CANDIDATES = (".gitleaks.toml", ".ash/.gitleaks.toml")

#: Environment variables gitleaks reads a config from. When either is set ASH
#: discovers nothing and lets gitleaks resolve it.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")


class GitleaksScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks TOML config, relative to the source directory. "
                "Its rules and [[allowlists]] apply on top of ASH suppressions. "
                "Defaults to `.gitleaks.toml`, then `.ash/.gitleaks.toml`, in the "
                "source directory; when neither exists, or GITLEAKS_CONFIG or "
                "GITLEAKS_CONFIG_TOML is set, gitleaks resolves its own config. A "
                "path that does not exist fails the scan."
            ),
        ),
    ] = None
    baseline_path: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks JSON report, relative to the source directory, "
                "whose findings gitleaks ignores (gitleaks --baseline-path). A path "
                "that does not exist fails the scan."
            ),
        ),
    ] = None
    max_target_megabytes: Annotated[
        int | None,
        Field(
            description="Skip files larger than this many megabytes (gitleaks --max-target-megabytes). Unset scans every file.",
            ge=1,
        ),
    ] = None


class GitleaksScannerConfig(ScannerPluginConfigBase):
    name: Literal["gitleaks"] = "gitleaks"
    enabled: bool = True
    options: Annotated[
        GitleaksScannerConfigOptions,
        Field(description="Configure the gitleaks scanner"),
    ] = GitleaksScannerConfigOptions()


@ash_scanner_plugin
class GitleaksScanner(ScannerPluginBase[GitleaksScannerConfig]):
    """Secret detection over the scan target's files using gitleaks."""

    # gitleaks' rules are compiled into the binary and it makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {0, LEAKS_EXIT_CODE}

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GitleaksScannerConfig()
        self.command = "gitleaks"
        self.subcommands = ["dir"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token gitleaks would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GitleaksScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``."""
        self.custom_install_commands.update(pinned_tool_install_commands("gitleaks"))
        return self

    def _options(self) -> GitleaksScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, GitleaksScannerConfigOptions):
            return options
        return GitleaksScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("GitleaksScanner has no plugin context")
        return Path(self.context.source_dir)

    def _resolve_option_path(self, value: Path | str, option: str) -> Path:
        """An option path, anchored on the source directory, which must exist."""
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = self._source_dir() / candidate
        if not candidate.is_file():
            raise ScannerError(
                f"scanners.gitleaks.options.{option} is {str(value)!r}, which is "
                f"not a file (resolved to {candidate.as_posix()}). Fix the path or "
                f"unset the option; gitleaks is not run without it."
            )
        return candidate.resolve()

    def _resolve_config_file(self) -> Optional[Path]:
        """The config to pass as ``--config``, or None to let gitleaks decide."""
        options = self._options()
        if options.config_file:
            return self._resolve_option_path(options.config_file, "config_file")
        set_vars = [name for name in CONFIG_ENV_VARS if os.environ.get(name)]
        if set_vars:
            ASH_LOGGER.debug(
                f"{', '.join(set_vars)} set; leaving gitleaks config resolution to gitleaks"
            )
            return None
        for name in DEFAULT_CONFIG_CANDIDATES:
            candidate = self._source_dir() / name
            if candidate.is_file():
                # Said at INFO because the file comes from the tree under scan and
                # can narrow or replace gitleaks' rules; options.config_file is how
                # an operator who does not trust that tree takes the choice back.
                ASH_LOGGER.info(
                    f"gitleaks uses {name} from the scanned source directory; set "
                    "scanners.gitleaks.options.config_file to use a config you control"
                )
                return candidate.resolve()
        return None

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full gitleaks argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows
        ``--``, so no path or config value can be read as a flag.
        """
        options = self._options()
        source_dir = self._source_dir()
        args: List[str] = [
            self.command or "gitleaks",
            *self.subcommands,
            "--report-format=sarif",
            f"--report-path={results_file.as_posix()}",
            "--redact=100",
            f"--exit-code={LEAKS_EXIT_CODE}",
            "--no-banner",
            "--no-color",
            f"--gitleaks-ignore-path={source_dir.as_posix()}",
        ]
        config_file = self._resolve_config_file()
        if config_file is not None:
            args.append(f"--config={config_file.as_posix()}")
        if options.baseline_path:
            baseline = self._resolve_option_path(options.baseline_path, "baseline_path")
            args.append(f"--baseline-path={baseline.as_posix()}")
        if options.max_target_megabytes:
            args.append(f"--max-target-megabytes={int(options.max_target_megabytes)}")

        # The source target as "." from the source directory (the subprocess
        # cwd), so reported paths are source-relative; see the module docstring.
        if Path(target).absolute() == source_dir.absolute():
            scan_path = "."
        else:
            scan_path = Path(target).absolute().as_posix()
        args.extend(["--", scan_path])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one gitleaks run.

        ``global_ignore_paths`` is not translated into gitleaks config: it is
        applied to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("GitleaksScanner has no results directory")
        results_file = self.results_dir.joinpath(target_type, "gitleaks.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's: a
        # gitleaks that fails writes no report, and the template reads whatever
        # is at this path.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run gitleaks did not finish.

        Exit 1 is a gitleaks failure (see the module docstring), and any code
        outside 0 and 2 is not one gitleaks documents. Raised before reading so
        a partial report cannot pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"gitleaks exited {self.exit_code}; it exits 0 when it finds "
                f"nothing and {LEAKS_EXIT_CODE} when it finds leaks, so this run "
                "failed"
            )
        return super()._read_results_file(results_file)

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result, drop empty fingerprints, and keep snippets redacted."""
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

            for location in result.locations or []:
                physical = location.physicalLocation
                region = physical.root.region if physical else None
                snippet = region.snippet if region else None
                if snippet is not None and snippet.text not in (None, REDACTED):
                    snippet.text = REDACTED

            # gitleaks fills commitSha/author/email/date/commitMessage with empty
            # strings in dir mode. An empty fingerprint is identical across every
            # result, so it is dropped rather than passed on.
            fingerprints = result.partialFingerprints
            if fingerprints:
                kept = {k: v for k, v in fingerprints.items() if v not in ("", None)}
                result.partialFingerprints = kept or None

        run = sarif_report.runs[0] if sarif_report.runs else None
        if run is not None and run.tool and run.tool.driver:
            # gitleaks 8.30.1 writes semanticVersion "v8.0.0" whatever its real
            # version; leave it out rather than report a wrong one.
            run.tool.driver.semanticVersion = None
        return sarif_report
