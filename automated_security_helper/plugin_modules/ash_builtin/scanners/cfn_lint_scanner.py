# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint: CloudFormation template validation, as a builtin ASH scanner.

What it adds next to cfn-nag and checkov
----------------------------------------
cfn-lint validates templates against the CloudFormation resource schemas and its own
best-practice rules: misspelled or invalid properties, values the service rejects,
deprecated runtimes, unused parameters. It is a correctness linter rather than a
security scanner, which is why its severities are mapped below security findings
(see ``severity_for_rule``).

Which files it reads
--------------------
Exactly the files cfn-nag reads: ``utils.cfn_template_discovery`` applies cfn-nag's
selection (JSON/YAML in the scan set that ``cfn_template_model`` models as
CloudFormation). A CloudFormation file the model rejects is counted as a failed target
with its reason, as cfn-nag counts it.

How it is invoked, and why each argument is there
-------------------------------------------------
``cfn-lint --format sarif --output-file <f> [options] -- <template>...``, run in the
source directory with templates given relative to it, so cfn-lint's SARIF URIs are
already the repository-relative paths ASH reports.

* Template paths are passed through ``glob.escape``. cfn-lint expands every filename
  argument with ``glob.glob(filename, recursive=True)`` (cfnlint/config.py at 1.57.1),
  so a template named ``a[1].yaml`` was reported as "could not be processed by
  glob.glob" (rule E0003) and never linted, and one named ``*.yaml`` would have
  expanded to every YAML file in its directory. Measured against 1.57.1: unescaped,
  ``g[1].yaml`` yields one E0003 and no lint results; escaped, it yields the three
  findings the same template produces under a plain name.
* ``--`` ends option parsing, so a template whose name starts with ``-`` is a file.
* Templates are batched under ``_ARGV_CHAR_BUDGET`` characters per invocation, so a
  repository with thousands of templates stays inside Windows' 32767-character
  command-line limit.

Network
-------
None. cfn-lint ships its resource schemas inside the package and only fetches when
asked to (``--update-specs``, ``--update-iam-policies``, ``--update-documentation``),
which ASH never passes. Measured: a run inside a network namespace with no interfaces
(``unshare -rn``) produced the same results as a run with network access. Installing
cfn-lint needs network once, like every uv-installed scanner; offline with cfn-lint
absent, the scanner reports MISSING with the uv reason (#520).

Exit codes
----------
cfn-lint's exit status is a bitmask of the levels it reported: 2 error, 4 warning,
8 informational (cfnlint/runner/cli.py). Any combination of those is a completed run.
1 is a fatal error and anything with bit 0 set, or above 15, is treated as a failed
invocation. E0003 ("Error with cfn-lint configuration", which is also what a template
path cfn-lint cannot open produces) is likewise a failed invocation rather than a
finding, because it means the named templates were not linted.
"""

from __future__ import annotations

import glob
import json
import logging
import re
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Tuple

from pydantic import AnyUrl, Field, field_validator

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Level,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_discovery import (
    discover_templates,
    display_path,
)
from automated_security_helper.config.path_trust import in_scanned_tree, resolved_path
from automated_security_helper.utils.config_trust import (
    scan_root,
    set_by_operator,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.output_excerpt import head_and_tail
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: cfn-lint's rule-id letter, mapped to an ASH severity and the SARIF level that
#: severity reads as everywhere else in ASH.
#:
#: Why below security severities: cfn-lint reports template correctness, not
#: exploitable weaknesses. An E rule means the template is invalid or will fail to
#: deploy (a misspelled property, a value the service rejects, an end-of-life Lambda
#: runtime), so it is MEDIUM: at ASH's default threshold an invalid template fails the
#: scan. A W rule is a best-practice or hygiene finding (an unused parameter, an
#: obsolete DependsOn) and is LOW, so it is reported without failing a default scan.
#: An I rule is informational and is INFO; cfn-lint emits those only when asked with
#: ``include_checks: [I]``.
#:
#: The SARIF level is set alongside ``issue_severity`` because ASH reads severity in
#: two ways that disagree for a bare level -- the scan gate maps ``error`` to CRITICAL,
#: the flat reporters map it to HIGH -- and both honor ``issue_severity``. Setting the
#: level to the one that matches keeps reporters that read only the level (the GitHub
#: code-scanning output) consistent with the rest. cfn-lint's own letter is never lost:
#: it is the first character of the rule id.
SEVERITY_BY_RULE_LETTER: Dict[str, Tuple[str, str]] = {
    "E": ("MEDIUM", "warning"),
    "W": ("LOW", "note"),
    "I": ("INFO", "none"),
}

#: Rule id cfn-lint uses for its own configuration errors, which includes a template
#: path it could not open.
_CONFIG_ERROR_RULE = "E0003"

#: The executable this scanner runs.
_COMMAND = "cfn-lint"

# Under Windows' 32767-character CreateProcess limit with room for the interpreter
# path, uv's own arguments and the options above.
_ARGV_CHAR_BUDGET = 24000

# What cfn-lint accepts for these options, checked here so a config value can never
# be read as another option.
_REGION_PATTERN = re.compile(r"^(ALL_REGIONS|[a-z]{2}(-[a-z]+)+-\d+)$")
_CHECK_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def severity_for_rule(rule_id: Optional[str]) -> Tuple[str, str]:
    """The (ASH severity, SARIF level) for a cfn-lint rule id.

    An id that does not start with E, W or I is treated as E: an unknown class is
    reported at the level that fails a default scan rather than below it.
    """
    letter = (rule_id or "E")[:1].upper()
    return SEVERITY_BY_RULE_LETTER.get(letter, SEVERITY_BY_RULE_LETTER["E"])


def _successful_exit(code: object) -> bool:
    try:
        value = int(code)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return False
    return 0 <= value <= 14 and value % 2 == 0


class CfnLintScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a cfn-lint configuration file (.cfnlintrc). When unset, ASH "
                "gives cfn-lint an empty configuration, so a .cfnlintrc in the scanned "
                "repository or the home directory is NOT read: such a file can load "
                "Python rules (append_rules) and switch checks off. Honored only when "
                "set by --config-overrides or a config file outside the scanned tree, "
                "and only for a file outside the scanned tree; otherwise "
                "it is ignored with a warning."
            ),
        ),
    ] = None
    regions: Annotated[
        List[str],
        Field(
            description=(
                "AWS regions to validate templates against, e.g. ['us-east-1', "
                "'eu-west-1'], or ['ALL_REGIONS']. Empty uses cfn-lint's default "
                "(us-east-1)."
            ),
        ),
    ] = []
    ignore_checks: Annotated[
        List[str],
        Field(
            description=(
                "cfn-lint rule ids or prefixes to skip, e.g. ['W2001', 'W3']. Prefer "
                "ASH suppressions for individual findings; this removes the rule from "
                "every template."
            ),
        ),
    ] = []
    include_checks: Annotated[
        List[str],
        Field(
            description=(
                "cfn-lint rule ids or prefixes to enable in addition to the defaults, "
                "e.g. ['I'] for informational rules."
            ),
        ),
    ] = []
    # The floor is 1.43.3, the cfn-lint the Nix flake's nixpkgs revision ships, so a
    # Nix run can use the flake's copy. Both ends were measured: 1.43.3 and 1.57.1
    # give identical SARIF on the fixture templates under
    # tests/test_data/scanners/cfn_lint_guard, and 1.57.2, the release the image
    # pins, the same results. The ceiling excludes the next major, whose rule ids
    # and output may change.
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.cfn-lint.options.tool_version"),
        Field(
            description=(
                "Version constraint for the cfn-lint installation, in pip requirement "
                "syntax. The default is the range the scanner's SARIF handling was "
                "verified against."
            )
        ),
    ] = ">=1.43.3,<2.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300

    @field_validator("regions")
    @classmethod
    def _valid_regions(cls, value: List[str]) -> List[str]:
        for item in value:
            if not _REGION_PATTERN.match(item):
                raise ValueError(f"{item!r} is not an AWS region name or ALL_REGIONS")
        return value

    @field_validator("ignore_checks", "include_checks")
    @classmethod
    def _valid_checks(cls, value: List[str]) -> List[str]:
        for item in value:
            if not _CHECK_PATTERN.match(item):
                raise ValueError(
                    f"{item!r} is not a cfn-lint rule id or prefix (letters and digits)"
                )
        return value


class CfnLintScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-lint"] = "cfn-lint"
    enabled: bool = True
    options: Annotated[
        CfnLintScannerConfigOptions,
        Field(description="Configure the cfn-lint scanner"),
    ] = CfnLintScannerConfigOptions()


@ash_scanner_plugin
class CfnLintScanner(ScannerPluginBase[CfnLintScannerConfig]):
    """Validates CloudFormation templates with cfn-lint."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # The strict default, declared so the choice is visible: cfn-lint is a uv tool,
    # whose directories and cache the baseline already exposes, and it reads the
    # templates and ASH's empty config, both mounted. Its resource specs ship in the
    # package. An operator's config_file outside the tree needs extra_read_paths.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CfnLintScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.IAC
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        self.tool_version = self._get_uv_tool_version("cfn-lint")
        super().model_post_init(context)

    def _options(self) -> CfnLintScannerConfigOptions:
        """This scanner's options, typed. The config is set in model_post_init."""
        options = getattr(self.config, "options", None)
        if not isinstance(options, CfnLintScannerConfigOptions):
            raise ScannerError(
                f"cfn-lint was configured with {type(options).__name__}, not "
                "CfnLintScannerConfigOptions"
            )
        return options

    def _get_tool_version_constraint(self) -> str | None:
        """The configured ``tool_version``; its default is the verified range."""
        return self._options().tool_version

    def _get_tool_package_extras(self) -> List[str] | None:
        """cfn-lint's SARIF formatter is behind its ``sarif`` extra."""
        return ["sarif"]

    def validate_plugin_dependencies(self) -> bool:
        """The bandit/checkov resolution: uv, then a verified binary on PATH, then install."""
        if self.dependency_unavailable_reason:
            return False
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            return False
        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)
            self._plugin_log(
                "cfn-lint not found via UV tool, attempting explicit installation..."
            )
            timeout = self._options().install_timeout
            if self._install_uv_tool(timeout=timeout):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for cfn-lint, falling back to the "
                "consolidated resolver",
                level=logging.WARNING,
            )
        return get_uv_tool_command(_COMMAND) is not None

    def _option_args(self, results_dir: Path) -> List[str]:
        """Arguments from config, each as one ``--flag=value`` token.

        The ``=`` form keeps a value from ever being parsed as a flag of its own.

        A ``--config-file`` is always passed. Without one, cfn-lint reads
        ``.cfnlintrc`` from the working directory (the scanned repository) and from
        the home directory (cfnlint/config.py, ``_find_config``), and reads neither
        once a config file is named. A repository's ``.cfnlintrc`` is not inert
        configuration: ``append_rules`` loads Python files as rules, which runs them
        in the scan's environment (measured: a ``rules/evil.py`` beside a
        ``.cfnlintrc`` naming it ran on a plain ``cfn-lint -- t.yaml``), and
        ``ignore_checks: [E, W]`` turns every finding off without anything reaching
        ASH's suppression accounting. So the default is an empty configuration ASH
        writes itself, and a ``.cfnlintrc`` is used only when the ASH config names
        it in ``config_file``.

        The ASH config usually comes from the scanned repository too, so
        ``config_file`` is honored only when the operator set it (through
        ``--config-overrides`` or a config file outside the scanned tree, see
        ``utils/config_trust.py``) and it resolves outside the scanned tree.
        Otherwise it is ignored with a warning and the empty configuration is used.
        """
        options = self._options()
        args: List[str] = []
        config_file = (
            self._operator_config_file(options.config_file)
            if options.config_file
            else None
        )
        if config_file is None:
            empty = Path(results_dir).joinpath("ash-empty.cfnlintrc")
            # Unlinked and recreated rather than overwritten, so a symlink left at
            # this path (the output directory usually sits inside the scanned tree)
            # is replaced instead of written through. open_for_write also refuses
            # to follow a link created after the unlink inside a sandbox's
            # writable directory.
            if empty.is_symlink() or empty.exists():
                empty.unlink()
            with open_for_write(empty) as handle:
                handle.write("{}\n")
            args.append(f"--config-file={empty.resolve().as_posix()}")
        else:
            args.append(f"--config-file={config_file.as_posix()}")
        if options.regions:
            args.extend(["--regions", *options.regions])
        if options.ignore_checks:
            args.extend(["--ignore-checks", *options.ignore_checks])
        if options.include_checks:
            args.extend(["--include-checks", *options.include_checks])
        return args

    def _operator_config_file(self, configured: Path | str) -> Optional[Path]:
        """The ``config_file`` to pass, or None when it must not be used.

        Raises:
            ScannerError: the operator named a file that does not exist.
        """
        source_dir = self._source_dir()
        candidate = resolved_path(configured, source_dir)
        context_config = self.context.config if self.context is not None else None
        if not set_by_operator(
            context_config, "scanners.cfn-lint.options.config_file", configured
        ):
            reason = (
                "it came from a config file in the scanned tree; set it with "
                "--config-overrides or a config file outside the tree"
            )
        elif in_scanned_tree(candidate, scan_root(context_config, source_dir)):
            reason = "it is inside the scanned tree"
        else:
            if not candidate.is_file():
                raise ScannerError(
                    f"scanners.cfn-lint.options.config_file names {candidate}, which "
                    "does not exist"
                )
            return candidate.resolve()
        # A .cfnlintrc can make cfn-lint import Python files (append_rules), so one
        # the scanned repository chose is never handed to it.
        self._plugin_log(
            f"Ignoring scanners.cfn-lint.options.config_file ({str(configured)!r}): "
            f"{reason}. A .cfnlintrc can load Python rules, so cfn-lint runs with "
            "ASH's empty configuration instead.",
            level=logging.WARNING,
        )
        return None

    @staticmethod
    def _recorded_args(option_args: List[str], source_dir: Path) -> List[str]:
        """``option_args`` as recorded in the report, without host-specific paths.

        ASH's own empty configuration is recorded by name only, and an operator's
        config file relative to the source directory, so the aggregated results do
        not carry the machine's absolute paths.
        """
        recorded = []
        for arg in option_args:
            if arg.startswith("--config-file="):
                path = Path(arg.split("=", 1)[1])
                shown = (
                    path.name
                    if path.name == "ash-empty.cfnlintrc"
                    else display_path(path, source_dir)
                )
                arg = f"--config-file={shown}"
            recorded.append(arg)
        return recorded

    @staticmethod
    def batches(paths: List[str], budget: int = _ARGV_CHAR_BUDGET) -> List[List[str]]:
        """Split ``paths`` into consecutive batches whose joined length fits ``budget``.

        A single path longer than the budget gets a batch of its own rather than
        being dropped.
        """
        out: List[List[str]] = []
        current: List[str] = []
        size = 0
        for path in paths:
            cost = len(path) + 1
            if current and size + cost > budget:
                out.append(current)
                current, size = [], 0
            current.append(path)
            size += cost
        if current:
            out.append(current)
        return out

    def normalize_report(self, report: SarifReport) -> SarifReport:
        """Apply the severity mapping and sort rules, in place.

        cfn-lint lists driver rules in a different order from run to run (a set
        iteration), so they are sorted by id to keep reports reproducible.
        """
        for run in report.runs or []:
            for result in run.results or []:
                severity, level = severity_for_rule(result.ruleId)
                result.level = Level(level)
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
            driver = run.tool.driver if run.tool else None
            if driver is not None and driver.rules:
                driver.rules = sorted(driver.rules, key=lambda r: r.id or "")
        return report

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("cfn-lint has no plugin context")
        return Path(self.context.source_dir)

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, Any]]]:
        """Abstract stub; cfn-lint overrides scan() to batch templates."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def _empty_report(self, target: Path) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="cfn-lint",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/aws-cloudformation/cfn-lint"
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
        config: ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        # Reset first, above every return, for the reason cfn_nag_scanner gives: the
        # executor reads these after scan() returns, and a return placed above the
        # reset would report the previous target's counts.
        self.targets_attempted = 0
        self.targets_failed = 0

        report = self._empty_report(target)
        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return report

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            if self.context is None:
                raise ScannerError("cfn-lint has no plugin context")
            discovery = discover_templates(self.context, target_type)
            for path, reason in discovery.unmodelable:
                self.targets_attempted += 1
                self.targets_failed += 1
                self.errors.append(f"{path.as_posix()}: {reason}")
                self._plugin_log(
                    f"cfn-lint did not evaluate {path.as_posix()}: {reason}",
                    target_type=target_type,
                    level=logging.ERROR,
                )

            if not discovery.templates:
                self._plugin_log(
                    f"No CloudFormation templates found in the {target_type} target.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return report

            source_dir = self._source_dir()
            if self.results_dir is None:
                raise ScannerError("cfn-lint has no results directory")
            results_dir = self.results_dir.joinpath(target_type)
            results_dir.mkdir(parents=True, exist_ok=True)
            option_args = self._option_args(results_dir)
            displayed = [display_path(p, source_dir) for p in discovery.templates]
            merged: List[Result] = []
            rules: Dict[str, ReportingDescriptor] = {}
            driver = report.runs[0].tool.driver

            for index, batch in enumerate(self.batches(displayed)):
                self.targets_attempted += len(batch)
                batch_file = results_dir.joinpath(f"cfn-lint.{index}.sarif")
                command = [
                    _COMMAND,
                    "--format",
                    "sarif",
                    f"--output-file={batch_file.as_posix()}",
                    *option_args,
                    "--",
                    *[glob.escape(p) for p in batch],
                ]
                response = self._run_subprocess(
                    command=command,
                    results_dir=results_dir,
                    stdout_preference="write",
                    stderr_preference="both",
                    timeout=self._effective_scan_timeout(),
                )
                failure = self._batch_failure(response, batch_file)
                batch_report = None
                if failure is None:
                    try:
                        batch_report = SarifReport.model_validate(
                            json.loads(batch_file.read_text(encoding="utf-8"))
                        )
                    except Exception as exc:  # unreadable output is a failed batch
                        failure = f"cfn-lint output was not valid SARIF ({exc})"
                if failure is None and batch_report is not None:
                    config_errors = [
                        r
                        for run in batch_report.runs or []
                        for r in run.results or []
                        if r.ruleId == _CONFIG_ERROR_RULE
                    ]
                    if config_errors:
                        texts = "; ".join(
                            (r.message.root.text or "") for r in config_errors
                        )
                        failure = f"cfn-lint reported a configuration error: {texts}"
                if failure is not None or batch_report is None:
                    failure = failure or "cfn-lint output could not be read"
                    self.targets_failed += len(batch)
                    self.errors.append(f"{', '.join(batch)}: {failure}")
                    self._plugin_log(
                        f"cfn-lint did not evaluate {len(batch)} template(s): {failure}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    continue
                for run in batch_report.runs or []:
                    merged.extend(run.results or [])
                    run_driver = run.tool.driver if run.tool else None
                    if run_driver is not None:
                        if run_driver.version:
                            driver.version = run_driver.version
                        for rule in run_driver.rules or []:
                            rules.setdefault(rule.id or "", rule)

            report.runs[0].results = merged
            driver.rules = list(rules.values()) or None
            self.normalize_report(report)
            self._post_scan(target=target, target_type=target_type)
            report.runs[0].invocations = [
                Invocation(
                    commandLine="cfn-lint",
                    arguments=[
                        "--format",
                        "sarif",
                        *self._recorded_args(option_args, source_dir),
                    ],
                    startTimeUtc=self.start_time,
                    endTimeUtc=self.end_time,
                    executionSuccessful=self.targets_failed == 0,
                    exitCode=self.exit_code,
                    exitCodeDescription="\n".join(self.errors),
                    workingDirectory=ArtifactLocation(
                        uri=get_shortest_name(input=target)
                    ),
                )
            ]
            with open_for_write(results_dir.joinpath("cfn-lint.sarif")) as handle:
                handle.write(
                    report.model_dump_json(exclude_none=True, exclude_unset=True)
                )
            return report
        except ScannerError:
            raise
        except Exception as exc:
            raise ScannerError(f"{self.__class__.__name__} failed: {exc}") from exc

    @staticmethod
    def _batch_failure(response: object, batch_file: Path) -> Optional[str]:
        """Why one cfn-lint invocation produced nothing usable, or None if it did."""
        if not isinstance(response, dict):
            return "cfn-lint did not run"
        if response.get("timed_out"):
            return "cfn-lint timed out and was killed"
        if "error" in response:
            return f"cfn-lint could not be started: {response['error']}"
        code = response.get("returncode")
        if not _successful_exit(code):
            stderr = head_and_tail((response.get("stderr") or "").strip(), 500)
            return f"cfn-lint exited {code}" + (f": {stderr}" if stderr else "")
        if not batch_file.is_file() or batch_file.stat().st_size == 0:
            return f"cfn-lint exited {code} without writing {batch_file.name}"
        return None
