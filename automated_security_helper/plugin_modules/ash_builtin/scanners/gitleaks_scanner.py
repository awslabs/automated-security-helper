# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks secret scanner, as a builtin scanner.

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
* ``--gitleaks-ignore-path=<empty directory ASH writes>``: by default gitleaks
  reads ``.gitleaksignore`` from its working directory, the source directory.

The scanned repository's own gitleaks configuration is not used
---------------------------------------------------------------
A ``.gitleaks.toml`` can replace gitleaks' rules or allowlist any path, and a
``.gitleaksignore`` or a baseline report drops findings by fingerprint. gitleaks
applies all of them before ASH sees a result, so what they hide is neither
reported nor counted as suppressed. Findings are tuned with ASH suppressions,
which are both, so the scanned tree does not configure gitleaks:

* The config is the operator's ``options.config_file`` (set by
  ``--config-overrides`` or a config file outside the scanned tree,
  ``utils/config_trust.py``), else ``GITLEAKS_CONFIG`` or ``GITLEAKS_CONFIG_TOML``
  from the operator's environment (outside the scanner sandbox, which does not
  pass them in), else a config ASH writes that extends gitleaks' default rules and
  adds nothing. It is always passed as ``--config`` except in the environment
  case, so gitleaks never falls through to ``<target>/.gitleaks.toml``. A
  ``config_file`` or ``baseline_path`` set by a config in the scanned tree is
  ignored with a warning, and a ``.gitleaks.toml`` or ``.ash/.gitleaks.toml`` in
  the tree with a note. An operator's file that does not exist fails the scan
  rather than falling back to the default rules.
* ``.gitleaksignore``: gitleaks reads ``<scan path>/.gitleaksignore`` whatever
  ``--gitleaks-ignore-path`` says, and has no flag to turn that off (measured on
  8.30.1). When the scan root has one, ASH runs gitleaks again on each file it
  names, one file per run (a single-file run reads no ``.gitleaksignore``, and
  reports the same fingerprint form), and adds back every finding the first run
  dropped. A failed re-run fails the scan rather than reporting the first run
  alone. Inline ``gitleaks:allow`` comments still apply.

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

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field, PrivateAttr, model_validator

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
from automated_security_helper.utils.config_trust import set_by_operator
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import active_scope

#: The text gitleaks writes in place of a secret under ``--redact``.
REDACTED = "REDACTED"

#: Exit code gitleaks is told to use when it finds leaks. See the module docstring.
LEAKS_EXIT_CODE = 2

#: gitleaks config names a repository commits. ASH does not read them from the
#: scanned tree; they are named only in the note logged when one is present.
TREE_CONFIG_NAMES = (".gitleaks.toml", ".ash/.gitleaks.toml")

#: Environment variables gitleaks reads a config from. When either is set, outside
#: the scanner sandbox, ASH passes no ``--config`` and gitleaks resolves it.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")

#: The ignore file gitleaks always reads at the root of its scan path.
IGNORE_FILE_NAME = ".gitleaksignore"

#: The config ASH passes when the operator chose none: gitleaks' default rules.
DEFAULT_RULES_CONFIG = (
    "# Written by ASH: gitleaks' default rules and nothing else, so no gitleaks\n"
    "# config in the scanned tree is read.\n"
    "[extend]\n"
    "useDefault = true\n"
)


class GitleaksScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks TOML config, relative to the source directory. "
                "Its rules and [[allowlists]] apply on top of ASH suppressions. "
                "Honored only when set by --config-overrides or a config file "
                "outside the scanned tree. Unset, gitleaks uses GITLEAKS_CONFIG or "
                "GITLEAKS_CONFIG_TOML from the environment if one is set, else its "
                "default rules; a .gitleaks.toml in the scanned repository is not "
                "read. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    baseline_path: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks JSON report, relative to the source directory, "
                "whose findings gitleaks ignores (gitleaks --baseline-path). Honored "
                "only when set by --config-overrides or a config file outside the "
                "scanned tree. A path that does not exist fails the scan."
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
    # The strict default: no network, and no variables or paths beyond the
    # baseline. GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML are not passed into a
    # sandbox, and neither config_file nor baseline_path outside the tree is
    # mounted: grants derived from the environment or options wait for the
    # sandbox's grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # The target and argv of the run whose report _read_results_file reads next,
    # for the .gitleaksignore re-scan. Set by _execute_scan.
    _pending_run: Optional[Tuple[Path, List[str]]] = PrivateAttr(default=None)

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

    def _set_by_operator(self, option: str, value: Any) -> bool:
        config = self.context.config if self.context is not None else None
        return set_by_operator(config, f"scanners.gitleaks.options.{option}", value)

    def _operator_option_path(self, option: str) -> Optional[Path]:
        """``option``'s path when the operator set it, else None (with a warning)."""
        value = getattr(self._options(), option)
        if not value:
            return None
        if not self._set_by_operator(option, value):
            self._plugin_log(
                f"scanners.gitleaks.options.{option} ({str(value)!r}) is set by a "
                "config in the scanned tree, so it is ignored. Set it with "
                "--config-overrides or a config file outside the scanned tree, or "
                "tune findings with ASH suppressions.",
                level=logging.WARNING,
            )
            return None
        return self._resolve_option_path(value, option)

    def _resolve_config_file(self, results_dir: Path) -> Optional[Path]:
        """The config to pass as ``--config``; None leaves it to the environment.

        See "The scanned repository's own gitleaks configuration is not used" in
        the module docstring.
        """
        operator_config = self._operator_option_path("config_file")
        if operator_config is not None:
            return operator_config
        set_vars = [name for name in CONFIG_ENV_VARS if os.environ.get(name)]
        if set_vars and active_scope() is not None:
            # The sandbox does not pass these variables in (see
            # sandbox_requirements), so gitleaks would not see them.
            self._plugin_log(
                f"{', '.join(set_vars)} is not passed into the scanner sandbox; "
                "gitleaks uses its default rules instead. Set "
                "scanners.gitleaks.options.config_file to choose a config.",
                level=logging.WARNING,
            )
        elif set_vars:
            ASH_LOGGER.debug(
                f"{', '.join(set_vars)} set; leaving gitleaks config resolution to gitleaks"
            )
            return None
        present = [n for n in TREE_CONFIG_NAMES if (self._source_dir() / n).is_file()]
        if present:
            self._plugin_log(
                f"{', '.join(present)} in the scanned tree is not read: gitleaks runs "
                "with its default rules, so its findings are reported and tuned "
                "with ASH suppressions. Set scanners.gitleaks.options.config_file "
                "with --config-overrides or a config file outside the scanned tree "
                "to use a gitleaks config.",
                level=logging.INFO,
            )
        default_rules = results_dir / "ash-gitleaks-default-rules.toml"
        with open_for_write(default_rules) as handle:
            handle.write(DEFAULT_RULES_CONFIG)
        return default_rules.resolve()

    def _empty_ignore_dir(self, results_dir: Path) -> Path:
        """A directory with no ``.gitleaksignore``, for ``--gitleaks-ignore-path``."""
        empty = results_dir / "ash-no-gitleaksignore"
        if empty.is_symlink() or empty.is_file():
            empty.unlink()
        elif empty.is_dir():
            for child in empty.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        empty.mkdir(parents=True, exist_ok=True)
        return empty.resolve()

    def _scan_path(self, target: Path) -> str:
        """The path gitleaks is given: ``.`` for the source, absolute otherwise.

        The source target as "." from the source directory (the subprocess cwd),
        so reported paths are source-relative; see the module docstring.
        """
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full gitleaks argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows
        ``--``, so no path or config value can be read as a flag.
        """
        options = self._options()
        results_dir = results_file.parent
        args: List[str] = [
            self.command or "gitleaks",
            *self.subcommands,
            "--report-format=sarif",
            f"--report-path={results_file.as_posix()}",
            "--redact=100",
            f"--exit-code={LEAKS_EXIT_CODE}",
            "--no-banner",
            "--no-color",
            f"--gitleaks-ignore-path={self._empty_ignore_dir(results_dir).as_posix()}",
        ]
        config_file = self._resolve_config_file(results_dir)
        if config_file is not None:
            args.append(f"--config={config_file.as_posix()}")
        baseline = self._operator_option_path("baseline_path")
        if baseline is not None:
            args.append(f"--baseline-path={baseline.as_posix()}")
        if options.max_target_megabytes:
            args.append(f"--max-target-megabytes={int(options.max_target_megabytes)}")
        args.extend(["--", self._scan_path(target)])
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
        self._pending_run = (Path(target), list(final_args))
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
        pending, self._pending_run = self._pending_run, None
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"gitleaks exited {self.exit_code}; it exits 0 when it finds "
                f"nothing and {LEAKS_EXIT_CODE} when it finds leaks, so this run "
                "failed"
            )
        raw = super()._read_results_file(results_file)
        if raw is not None and pending is not None:
            target, final_args = pending
            self._add_back_gitleaksignore_drops(raw, target, final_args, results_file)
        return raw

    def _gitleaksignore_files(self, target: Path) -> List[str]:
        """The files ``<target>/.gitleaksignore`` names, spelled as gitleaks reports them.

        A dir-scan fingerprint is ``<file>:<rule id>:<line>``. Entries in another
        form (a git-scan fingerprint starts with a commit), and files that are not
        inside the target, are left out: gitleaks could not have matched them.
        """
        ignore_file = Path(target) / IGNORE_FILE_NAME
        if not ignore_file.is_file():
            return []
        root = Path(target).resolve()
        names = set()
        text = ignore_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            parts = entry.rsplit(":", 2)
            if len(parts) != 3 or not parts[0]:
                continue
            name = parts[0]
            candidate = Path(name) if Path(name).is_absolute() else root / name
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved.is_file() and resolved.is_relative_to(root):
                names.add(name)
        return sorted(names)

    def _add_back_gitleaksignore_drops(
        self,
        raw: Dict[str, Any],
        target: Path,
        final_args: List[str],
        results_file: Path,
    ) -> None:
        """Re-scan each file the tree's ``.gitleaksignore`` names, one per run.

        gitleaks reads ``<scan path>/.gitleaksignore`` whatever ASH passes, so the
        run whose report is ``raw`` may have dropped findings by fingerprint. A run
        over a single file reads no ``.gitleaksignore`` and reports the same
        fingerprint form, so its findings that ``raw`` lacks are the dropped ones,
        and they are appended to ``raw``. See the module docstring.
        """
        names = self._gitleaksignore_files(target)
        if not names:
            return
        runs = raw.get("runs") or []
        if not runs:
            return
        results = runs[0].setdefault("results", None) or []
        runs[0]["results"] = results

        def key(result: Dict[str, Any]) -> Tuple[Any, ...]:
            location = ((result.get("locations") or [{}])[0]).get(
                "physicalLocation", {}
            )
            return (
                (location.get("artifactLocation") or {}).get("uri"),
                result.get("ruleId"),
                (location.get("region") or {}).get("startLine"),
            )

        seen = {key(result) for result in results}
        rescan_dir = results_file.parent / "gitleaksignore-rescan"
        if rescan_dir.is_symlink() or rescan_dir.is_file():
            rescan_dir.unlink()
        elif rescan_dir.is_dir():
            shutil.rmtree(rescan_dir)
        rescan_dir.mkdir(parents=True)
        added = 0
        for index, name in enumerate(names):
            report = rescan_dir / f"{index}.sarif"
            args = [
                f"--report-path={report.as_posix()}"
                if arg.startswith("--report-path=")
                else arg
                for arg in final_args[:-1]
            ] + [name]
            exit_code = self.exit_code
            response = self._run_subprocess(
                command=args,
                results_dir=rescan_dir,
                timeout=self._effective_scan_timeout(),
            )
            self.exit_code = exit_code
            code = response.get("returncode", 1) if isinstance(response, dict) else 1
            if (
                not isinstance(response, dict)
                or response.get("timed_out")
                or response.get("spawn_failed")
                or code not in self.success_exit_codes
                or not report.is_file()
            ):
                raise ScannerError(
                    f"gitleaks failed re-scanning {name}, which the scanned tree's "
                    f"{IGNORE_FILE_NAME} names (exit {code}); without that run the "
                    "findings the file hides would go unreported"
                )
            data = json.loads(report.read_text(encoding="utf-8") or "{}")
            for run in data.get("runs") or []:
                for result in run.get("results") or []:
                    if key(result) not in seen:
                        seen.add(key(result))
                        results.append(result)
                        added += 1
        self._plugin_log(
            f"The scanned tree's {IGNORE_FILE_NAME} names {len(names)} file(s). "
            "gitleaks applies it at the scan root whatever ASH passes, so ASH "
            f"re-scanned those files and reports the {added} finding(s) it dropped. "
            "Tune findings with ASH suppressions, which are reported and counted.",
            level=logging.INFO,
        )

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
