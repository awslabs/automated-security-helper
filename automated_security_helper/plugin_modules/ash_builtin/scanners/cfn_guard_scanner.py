# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-guard: policy-as-code checks on CloudFormation templates, as a builtin scanner.

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

An operator's own rules
-----------------------
cfn-guard prints a rules file it cannot parse, whole, and follows a symlinked file in
a rules directory. So ``rules_paths`` is honored only from the operator
(``utils/config_trust.operator_paths``); from a config in the scanned tree it is
ignored with a warning, and an empty ``rule_sets`` then falls back to the default
set rather than leaving nothing to evaluate. ASH expands a directory itself, as
cfn-guard would (``.guard`` and ``.ruleset`` files at any depth), refuses a file that
resolves outside the directory the operator named, reads each one through
``utils/scanned_tree.open_in_scanned_tree`` and gives cfn-guard a copy in the
results directory. See ``CfnGuardScanner._operator_rules``.

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
import os
import re
from dataclasses import dataclass
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
from automated_security_helper.utils.config_trust import operator_paths
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.rules_bundles import (
    RulesBundleUnavailable,
    create_rules_bundle_install_command,
    rules_root,
    verify_installed_bundle,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
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

#: The files cfn-guard 3.2.1 reads from a ``--rules`` directory, case-sensitively
#: (measured: ``x.ruleset`` read, ``UP.GUARD`` and ``x.txt`` not).
_RULE_SUFFIXES = (".guard", ".ruleset")

#: Under the results directory, where the operator's rules are copied for cfn-guard.
_STAGED_RULES_DIR = "cfn-guard-rules"


@dataclass(frozen=True)
class _RuleFile:
    """One rules file cfn-guard is given."""

    #: Where it is: in the installed bundle, or where ``rules_paths`` led.
    path: Path
    #: The operator's rules, read through ``open_in_scanned_tree`` when selected and
    #: handed to cfn-guard as a copy. None for a bundled file, which
    #: ``verify_installed_bundle`` checked against the pin and is passed by path.
    content: Optional[str] = None


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
                "rule_sets. Honored only when set by --config-overrides or a config "
                "file outside the scanned tree: cfn-guard prints a rules file it "
                "cannot parse, so a path the scanned repository chose could put any "
                "file the scan can read into the report. Set elsewhere, it is "
                "ignored with a warning, and an empty rule_sets falls back to "
                "wa-Security-Pillar. In a directory, the .guard and .ruleset files "
                "are read, recursively; one that resolves outside the directory, "
                "through a symlink, is refused."
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

    @property
    def sandbox_requirements(self) -> SandboxRequirements:
        """Read access to the installed rules bundle, and nothing else.

        The bundle lives under ``rules_root()``: ``$ASH_CFN_GUARD_RULES_DIR``, or
        ``<ASH_BIN_PATH>/../share/cfn-guard-rules``. The baseline policy exposes ASH's
        bin directory but not that ``share`` directory beside it, so without this
        every ``--rules`` path would be missing inside the sandbox. A property
        because the location is read from the environment at scan time, as
        ``rule_files`` reads it. ``rules_paths`` needs no grant: ASH reads the
        operator's rules itself and gives cfn-guard a copy in the results directory.
        """
        return SandboxRequirements(read_paths=(rules_root().as_posix(),))

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

    def _operator_rules(self, source_dir: Path) -> Tuple[List[_RuleFile], bool]:
        """The operator's ``rules_paths``, read, and whether the list was refused.

        cfn-guard echoes a rules file it cannot parse, all of it, in its error
        (measured with 3.2.1: a credentials file given as ``--rules`` came back
        whole on stderr), and that error reaches the scan's results. So the list is
        used only when the operator set it (``config_trust.operator_paths``; the
        operator may keep rules in the tree). A list from a config in the scanned
        tree, or from an MCP client, is ignored with a warning, and the second
        value is True so ``_selected_rules`` can fall back to the default set.

        A named file is read as is. A directory is walked as cfn-guard walks one,
        for ``_RULE_SUFFIXES`` files at any depth, and each is read only when it
        resolves inside that directory: cfn-guard follows a symlinked file there
        (measured: ``creds.guard -> ../creds`` printed the target), so a link
        leaving the directory the operator named is refused with a warning. Each
        file is read through ``open_in_scanned_tree`` with the named directory as
        its root, and cfn-guard is given a copy of what was read, so a link swapped
        in after the check is never followed.

        Raises:
            RulesBundleUnavailable: an operator's path does not exist, or a file it
                names could not be read.
        """
        options = self._options()
        if not options.rules_paths:
            return [], False
        config = self.context.config if self.context is not None else None
        chosen = operator_paths(
            config,
            "scanners.cfn-guard.options.rules_paths",
            options.rules_paths,
            source_dir,
            outside_tree=False,
        )
        refused = [
            (raw, entry.refusal)
            for raw, entry in zip(options.rules_paths, chosen)
            if entry.path is None
        ]
        for raw, reason in refused:
            self._plugin_log(
                f"Ignoring scanners.cfn-guard.options.rules_paths entry {raw!r}: "
                f"{reason}.",
                level=logging.WARNING,
            )
        rules: List[_RuleFile] = []
        for entry in chosen:
            if entry.path is None:
                continue
            if not entry.path.exists():
                raise RulesBundleUnavailable(
                    f"scanners.cfn-guard.options.rules_paths names {entry.path}, "
                    "which does not exist"
                )
            if entry.path.is_dir():
                rules.extend(self._rules_in_directory(entry.path))
            else:
                rules.append(self._read_rule(entry.path, entry.path.parent))
        return rules, bool(refused)

    def _rules_in_directory(self, directory: Path) -> List[_RuleFile]:
        """The rules files under ``directory`` that stay inside it, read, sorted.

        Like cfn-guard, the walk does not enter a symlinked subdirectory. One that
        cannot be listed fails the scan rather than dropping its rules.
        """

        def unreadable(exc: OSError) -> None:
            raise RulesBundleUnavailable(
                f"cfn-guard rules directory {exc.filename} could not be read: "
                f"{exc.strerror or exc}"
            ) from exc

        rules: List[_RuleFile] = []
        for dirpath, dirnames, filenames in os.walk(directory, onerror=unreadable):
            dirnames.sort()
            for name in sorted(filenames):
                if not name.endswith(_RULE_SUFFIXES):
                    continue
                path = Path(dirpath) / name
                try:
                    rules.append(self._read_rule(path, directory))
                except TreeInputRefused as refused:
                    self._plugin_log(
                        f"Not evaluating cfn-guard rules {path.as_posix()}: "
                        f"{refused.reason.replace('scanned tree', 'rules directory')}.",
                        level=logging.WARNING,
                    )
        return rules

    @staticmethod
    def _read_rule(path: Path, root: Path) -> _RuleFile:
        """``path``'s content, read only if it is a regular file inside ``root``.

        Raises:
            TreeInputRefused: it resolves outside ``root`` or is not a regular file.
            RulesBundleUnavailable: it could not be read.
        """
        try:
            with open_in_scanned_tree(path, root, follow_links_inside=True) as handle:
                raw = handle.read()
        except OSError as exc:
            raise RulesBundleUnavailable(
                f"cfn-guard rules {path.as_posix()} could not be read: "
                f"{exc.strerror or exc}"
            ) from exc
        # surrogateescape keeps every byte, and the copy is written back the same
        # way; only line endings become the platform's.
        text = raw.decode("utf-8", errors="surrogateescape")
        return _RuleFile(path=path, content=text.replace("\r\n", "\n"))

    def _selected_rules(self) -> List[_RuleFile]:
        """The rules cfn-guard will be given, in order. See ``rule_files``."""
        options = self._options()
        source_dir = self._source_dir()
        operator_rules, refused = self._operator_rules(source_dir)
        rule_sets = list(options.rule_sets)
        if refused and not rule_sets:
            # The repository emptied rule_sets and supplied its own rules. Its
            # rules are not read, and it does not get to switch cfn-guard off.
            self._plugin_log(
                "scanners.cfn-guard.options.rule_sets is empty and rules_paths was "
                f"ignored, so cfn-guard evaluates ASH's default rule set, "
                f"{DEFAULT_RULE_SET}.",
                level=logging.WARNING,
            )
            rule_sets = [DEFAULT_RULE_SET]
        selected: List[_RuleFile] = []
        if rule_sets:
            bundle = get_rules_bundle(RULES_BUNDLE_NAME)
            names = [f"{name}.guard" for name in rule_sets]
            installed = verify_installed_bundle(bundle, files=names)
            selected.extend(
                _RuleFile(path=installed.directory.joinpath(name)) for name in names
            )
        selected.extend(operator_rules)
        if not selected:
            raise RulesBundleUnavailable(
                "no cfn-guard rules are selected: scanners.cfn-guard.options."
                "rule_sets is empty and rules_paths names no rules file"
            )
        return selected

    def rule_files(self) -> List[Path]:
        """The rules files cfn-guard will be evaluated with, in order.

        The bundled ``rule_sets`` files, then the operator's ``rules_paths`` files
        (a directory as the files in it). See ``_operator_rules``.

        Raises:
            RulesBundleUnavailable: a named rule set is not installed or does not
                match the pinned bundle, or a ``rules_paths`` entry does not exist,
                or nothing is selected at all.
        """
        return [rule.path for rule in self._selected_rules()]

    @staticmethod
    def _rules_arguments(rules: List[_RuleFile], staging: Path) -> List[str]:
        """``--rules`` for each rule: a bundled file by path, an operator's as a copy.

        The copies are named by position, so two files of the same name in
        different directories stay apart. cfn-guard's SARIF names rules by rule
        name, not by file (measured with 3.2.1), so the findings are the same.
        """
        arguments: List[str] = []
        for index, rule in enumerate(rules):
            path = rule.path
            if rule.content is not None:
                path = staging / f"{index:03d}-{rule.path.name}"
                with open_for_write(path, errors="surrogateescape") as handle:
                    handle.write(rule.content)
            arguments.append(f"--rules={path.as_posix()}")
        return arguments

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
            selected = self._selected_rules()
            rules = [rule.path for rule in selected]
            if self.context is None:
                raise ScannerError("cfn-guard has no plugin context")
            if self.results_dir is None:
                raise ScannerError("cfn-guard has no results directory")
            results_dir = self.results_dir.joinpath(target_type)
            staging = results_dir.joinpath(_STAGED_RULES_DIR)
            staging.mkdir(parents=True, exist_ok=True)
            rule_args = self._rules_arguments(selected, staging)
            discovery = discover_templates(self.context, target_type)
            for shown, reason in discovery.refused:
                # Not read, so not known to be CloudFormation: skipped and named, as
                # cfn-nag skips it.
                self._plugin_log(
                    f"Skipped {shown}: {reason}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
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
            with open_for_write(results_dir.joinpath("cfn-guard.sarif")) as handle:
                handle.write(
                    report.model_dump_json(exclude_none=True, exclude_unset=True)
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
        stderr = tool_output_excerpt((response.get("stderr") or "").strip(), 500)
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
