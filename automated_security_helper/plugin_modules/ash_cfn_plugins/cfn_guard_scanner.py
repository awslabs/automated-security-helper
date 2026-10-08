# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-guard: policy-as-code checks on CloudFormation templates, as a community scanner.

The tool and the rules
----------------------
cfn-guard (AWS CloudFormation Guard, Apache-2.0) evaluates JSON/YAML documents against
rules written in its own DSL. It ships no rules, so ASH pins a rule source: the AWS
Guard Rules Registry release 1.0.2, Apache-2.0, installed by
``ash dependencies install`` and shipped in the container image. The binary and the
rules archive are both pinned by SHA256 in ``utils/tool_downloads.py``; the rules
install and verification are ``utils/rules_bundles.py``.

The default rule set, and why
-----------------------------
``wa-Security-Pillar``: the registry's mapping of the AWS Well-Architected Framework
Security Pillar, 44 rules. The registry's other candidate for a default,
``guard-rules-registry-all-rules`` (66 rules), is a superset that adds 22 reliability
and operations rules -- backup plans, Multi-AZ, deletion protection, S3 replication and
object lock, Lambda concurrency and DLQ, EBS optimization, detailed monitoring. Those
are not security findings, and in a security scan they would fail templates for
reasons the operator did not ask about. The remaining 48 files are compliance-framework
mappings (CIS, NIST, PCI DSS, HIPAA, ...), which are a choice an operator makes for
their own context, not a default. Any of the 50 can be selected by name with
``rule_sets``, and an operator's own ``.guard`` files with ``rules_paths``.

Which files it reads
--------------------
Exactly cfn-nag's selection, through ``utils.cfn_template_discovery``.

How it is invoked
-----------------
Once per template:
``cfn-guard validate --rules=<file>... --data=<template> --output-format=sarif
--structured --show-summary=none``. cfn-guard 3.2.1 refuses ``sarif`` without
``--structured``, and ``--structured`` refuses every ``--show-summary`` value but
``none``. Per template rather than all at once for two measured reasons: one
unparseable data file makes cfn-guard exit 255 with no output for the whole
invocation, which would cost every other template its verdict; and cfn-guard writes
each result URI as the absolute path with its leading ``/`` removed
(``local/home/.../a.yaml``), so a per-template run is what lets the URI be replaced
with the known repository-relative path. A run costs about 40ms.

Exit codes: 0 means every rule passed or skipped, 19 means at least one failed; any
other status (255 for a parse error or a missing rules path) is a failed target.

Network
-------
None. cfn-guard is a static binary with no network code path in ``validate``, and the
rules are local files. Measured under ``unshare -rn`` (no network interfaces): exit 19
with the same results.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Tuple

from pydantic import AnyUrl, Field, field_validator, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
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
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.rules_bundles import (
    RulesBundleUnavailable,
    create_rules_bundle_install_command,
    verify_installed_bundle,
)
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import get_rules_bundle

#: The registry bundle the bundled ``rule_sets`` come from.
RULES_BUNDLE_NAME = "aws-guard-rules-registry"

#: The rule set used when the operator names none. See the module docstring.
DEFAULT_RULE_SET = "wa-Security-Pillar"

#: Every cfn-guard rule violation is reported at this ASH severity and SARIF level.
#:
#: Why one severity: cfn-guard's SARIF carries ``level: error`` for every failed rule,
#: and the registry's rules declare no severity of their own, so there is nothing per
#: rule to map from. HIGH, by maintainer decision: a template that violates a rule
#: of the compliance set the operator chose is a failed control, and the default set
#: is security configuration -- public access blocks, encryption, logging, TLS. The
#: level is ``error`` to match, and ``issue_severity`` is set as well, because ASH's
#: two severity readers disagree on a bare ``error`` (the gate reads CRITICAL, the
#: flat reporters HIGH) and both honor ``issue_severity``, so every reader says HIGH.
VIOLATION_SEVERITY = "HIGH"
VIOLATION_LEVEL = "error"

_SUCCESS_EXIT_CODES = frozenset({0, 19})

#: The executable this scanner runs.
_COMMAND = "cfn-guard"
_RULE_SET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CfnGuardScannerConfigOptions(ScannerOptionsBase):
    rule_sets: Annotated[
        List[str],
        Field(
            description=(
                "Rule sets from the bundled AWS Guard Rules Registry to evaluate, by "
                "file name without the .guard extension, e.g. "
                "['wa-Security-Pillar', 'cis-aws-benchmark-level-1']. Defaults to the "
                "Well-Architected Security Pillar set. Set to [] to evaluate only "
                "rules_paths."
            ),
        ),
    ] = [DEFAULT_RULE_SET]
    rules_paths: Annotated[
        List[str],
        Field(
            description=(
                "Your own cfn-guard rules: .guard files or directories of them, "
                "relative to the source directory. Evaluated in addition to "
                "rule_sets."
            ),
        ),
    ] = []

    @field_validator("rule_sets")
    @classmethod
    def _valid_rule_set_names(cls, value: List[str]) -> List[str]:
        for item in value:
            if not _RULE_SET_NAME.match(item) or item.endswith(".guard"):
                raise ValueError(
                    f"{item!r} is not a rule set name; use the file name without "
                    "the .guard extension, e.g. 'wa-Security-Pillar'"
                )
        return value


class CfnGuardScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-guard"] = "cfn-guard"
    enabled: bool = True
    options: Annotated[
        CfnGuardScannerConfigOptions,
        Field(description="Configure the cfn-guard scanner"),
    ] = CfnGuardScannerConfigOptions()


@ash_scanner_plugin
class CfnGuardScanner(ScannerPluginBase[CfnGuardScannerConfig]):
    """Evaluates CloudFormation templates against cfn-guard rules."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CfnGuardScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.IAC
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CfnGuardScanner":
        """The pinned binary, then the pinned rules bundle, on every platform."""
        rules_command = create_rules_bundle_install_command(RULES_BUNDLE_NAME)
        for target_platform, arches in pinned_tool_install_commands(
            "cfn-guard"
        ).items():
            for arch, commands in arches.items():
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    *commands,
                    rules_command,
                ]
        return self

    def _options(self) -> CfnGuardScannerConfigOptions:
        """This scanner's options, typed. The config is set in model_post_init."""
        options = getattr(self.config, "options", None)
        if not isinstance(options, CfnGuardScannerConfigOptions):
            raise ScannerError(
                f"cfn-guard was configured with {type(options).__name__}, not "
                "CfnGuardScannerConfigOptions"
            )
        return options

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("cfn-guard has no plugin context")
        return Path(self.context.source_dir)

    def rule_files(self) -> List[Path]:
        """The rules files and directories cfn-guard will be given, in order.

        Raises:
            RulesBundleUnavailable: a named rule set is not installed or does not
                match the pinned bundle, or a ``rules_paths`` entry does not exist,
                or nothing is selected at all.
        """
        options = self._options()
        selected: List[Path] = []
        if options.rule_sets:
            bundle = get_rules_bundle(RULES_BUNDLE_NAME)
            names = [f"{name}.guard" for name in options.rule_sets]
            installed = verify_installed_bundle(bundle, files=names)
            selected.extend(installed.directory.joinpath(name) for name in names)
        source_dir = self._source_dir()
        for raw in options.rules_paths:
            path = Path(raw)
            if not path.is_absolute():
                path = source_dir / path
            if not path.exists():
                raise RulesBundleUnavailable(
                    f"scanners.cfn-guard.options.rules_paths names {path}, which does "
                    "not exist"
                )
            selected.append(path)
        if not selected:
            raise RulesBundleUnavailable(
                "no cfn-guard rules are selected: scanners.cfn-guard.options."
                "rule_sets and rules_paths are both empty"
            )
        return selected

    def validate_plugin_dependencies(self) -> bool:
        """The binary on PATH, and every selected rules file present and verified."""
        if self.dependency_unavailable_reason:
            return False
        if find_executable(_COMMAND) is None:
            self._record_unavailable(
                "cfn-guard is not on PATH. Run `ash dependencies install --tool "
                "cfn-guard`, or use the ASH container image, which ships it. "
                "nixpkgs has no cfn-guard package, so `--mode nix` does not supply "
                "it either."
            )
            return False
        try:
            self.rule_files()
        except RulesBundleUnavailable as exc:
            self._record_unavailable(str(exc))
            return False
        return True

    def _record_unavailable(self, reason: str) -> None:
        self.dependency_unavailable_reason = reason
        if reason not in self.errors:
            self.errors.append(reason)
        self._plugin_log(reason, level=logging.ERROR)

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, Any]]]:
        """Abstract stub; cfn-guard overrides scan() to run once per template."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="cfn-guard",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/aws-cloudformation/cloudformation-guard"
                            ),
                        )
                    ),
                    results=[],
                )
            ],
        )

    @staticmethod
    def normalize_results(report: SarifReport, uri: str) -> List[Result]:
        """The results of one template's run, located at ``uri`` and severity-mapped."""
        results: List[Result] = []
        for run in report.runs or []:
            for result in run.results or []:
                for location in result.locations or []:
                    physical = location.physicalLocation
                    if (
                        physical is not None
                        and physical.root.artifactLocation is not None
                    ):
                        physical.root.artifactLocation.uri = uri
                        physical.root.artifactLocation.uriBaseId = None
                result.level = Level(VIOLATION_LEVEL)
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", VIOLATION_SEVERITY)  # noqa: B010
                results.append(result)
        return results

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        # Reset above every return; see cfn_lint_scanner.
        self.targets_attempted = 0
        self.targets_failed = 0

        report = self._empty_report()
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
            rules = self.rule_files()
            rule_args = [f"--rules={path.as_posix()}" for path in rules]
            if self.context is None:
                raise ScannerError("cfn-guard has no plugin context")
            discovery = discover_templates(self.context, target_type)
            for path, reason in discovery.unmodelable:
                self.targets_attempted += 1
                self.targets_failed += 1
                self.errors.append(f"{path.as_posix()}: {reason}")
                self._plugin_log(
                    f"cfn-guard did not evaluate {path.as_posix()}: {reason}",
                    target_type=target_type,
                    level=logging.ERROR,
                )

            source_dir = self._source_dir()
            if self.results_dir is None:
                raise ScannerError("cfn-guard has no results directory")
            results_dir = self.results_dir.joinpath(target_type)
            results_dir.mkdir(parents=True, exist_ok=True)
            merged: List[Result] = []
            driver = report.runs[0].tool.driver
            for template in discovery.templates:
                self.targets_attempted += 1
                shown = display_path(template, source_dir)
                command = [
                    _COMMAND,
                    "validate",
                    *rule_args,
                    f"--data={Path(template).absolute().as_posix()}",
                    "--output-format=sarif",
                    "--structured",
                    "--show-summary=none",
                ]
                response = self._run_subprocess(
                    command=command,
                    results_dir=results_dir,
                    stdout_preference="return",
                    stderr_preference="both",
                    timeout=self._effective_scan_timeout(),
                )
                failure, template_report = self._parse_response(response)
                if failure is not None or template_report is None:
                    failure = failure or "cfn-guard output could not be read"
                    self.targets_failed += 1
                    self.errors.append(f"{shown}: {failure}")
                    self._plugin_log(
                        f"cfn-guard did not evaluate {shown}: {failure}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    continue
                for run in template_report.runs or []:
                    run_driver = run.tool.driver if run.tool else None
                    if run_driver is not None and run_driver.semanticVersion:
                        driver.version = run_driver.semanticVersion
                merged.extend(self.normalize_results(template_report, shown))

            report.runs[0].results = merged
            self._post_scan(target=target, target_type=target_type)
            report.runs[0].invocations = [
                Invocation(
                    commandLine="cfn-guard",
                    arguments=[
                        "validate",
                        *self._recorded_rule_args(rules, source_dir),
                        "--output-format=sarif",
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
            results_dir.joinpath("cfn-guard.sarif").write_text(
                report.model_dump_json(exclude_none=True, exclude_unset=True),
                encoding="utf-8",
            )
            return report
        except RulesBundleUnavailable as exc:
            raise ScannerError(str(exc)) from exc
        except ScannerError:
            raise
        except Exception as exc:
            raise ScannerError(f"{self.__class__.__name__} failed: {exc}") from exc

    @staticmethod
    def _recorded_rule_args(rules: List[Path], source_dir: Path) -> List[str]:
        """``--rules`` as recorded in the report, without host-specific paths.

        A bundled rule set is recorded relative to the rules root (its bundle
        directory and file name), an operator's rules relative to the source
        directory, so ash_aggregated_results.json carries no machine paths.
        """
        recorded = []
        for path in rules:
            parent = path.parent.name
            if parent.startswith(f"{RULES_BUNDLE_NAME}-"):
                shown = f"{parent}/{path.name}"
            else:
                shown = display_path(path, source_dir)
            recorded.append(f"--rules={shown}")
        return recorded

    @staticmethod
    def _parse_response(
        response: object,
    ) -> Tuple[Optional[str], Optional[SarifReport]]:
        """(failure reason or None, parsed report or None) for one invocation."""
        if not isinstance(response, dict):
            return "cfn-guard did not run", None
        if response.get("timed_out"):
            return "cfn-guard timed out and was killed", None
        if "error" in response:
            return f"cfn-guard could not be started: {response['error']}", None
        code = response.get("returncode")
        stderr = (response.get("stderr") or "").strip()[:500]
        if code not in _SUCCESS_EXIT_CODES:
            return (
                f"cfn-guard exited {code}" + (f": {stderr}" if stderr else ""),
                None,
            )
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            return f"cfn-guard exited {code} without writing SARIF", None
        try:
            parsed = SarifReport.model_validate(json.loads(stdout))
        except Exception as exc:
            return f"cfn-guard output was not valid SARIF ({exc})", None
        has_results = any(run.results for run in parsed.runs or [])
        if code == 19 and not has_results:
            # 19 is "a rule failed", and a failure that rendered no result is a
            # verdict the report would lose. Refused rather than read as clean.
            return (
                "cfn-guard reported a failing rule but the SARIF has no results",
                None,
            )
        return None, parsed
