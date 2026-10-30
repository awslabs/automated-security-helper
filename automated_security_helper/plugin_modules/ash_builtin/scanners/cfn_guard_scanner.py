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
Security Pillar, 45 rules. The registry's other candidate for a default,
``guard-rules-registry-all-rules`` (67 rules), is a superset that adds 22 reliability
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
(``utils/config_trust.operator_paths``); from a config inside a git checkout or the
scanned directory it is ignored with a warning, and an empty ``rule_sets`` then falls back to the default
set rather than leaving nothing to evaluate. ASH expands a directory itself, as
cfn-guard would (``.guard`` and ``.ruleset`` files at any depth), refuses a file that
resolves outside the directory the operator named, reads each one through
``utils/scanned_tree.open_in_scanned_tree`` and gives cfn-guard a copy, written in
the scanner run's own directory outside the scanned tree
(``utils/tool_config_dir``). See ``CfnGuardScanner._operator_rules``.

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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import AnyUrl, Field, PrivateAttr, field_validator, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Level,
    Location,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_discovery import (
    cloudformation_templates_nothing_to_scan_reason,
    discover_templates,
    display_path,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    NOT_THE_OPERATORS,
    operator_paths,
    operator_value,
    refusal_warning,
    scan_root,
    set_by_operator,
)
from automated_security_helper.utils.error_text import text_without_values
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
    REASON_HARDLINK,
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    find_executable,
    response_could_not_stop,
)
from automated_security_helper.utils.tool_config_dir import write_tool_config
from automated_security_helper.utils.tool_downloads import get_rules_bundle

#: The registry bundle the bundled ``rule_sets`` come from.
RULES_BUNDLE_NAME = "aws-guard-rules-registry"

#: The rule set used when the operator names none. See the module docstring.
DEFAULT_RULE_SET = "wa-Security-Pillar"

#: Every cfn-guard rule violation is reported at this ASH severity and SARIF level.
#:
#: Why one severity: cfn-guard's SARIF carries ``level: error`` for every failed rule,
#: and the registry's rules declare no severity of their own, so there is nothing per
#: rule to map from. HIGH, by design: a template that violates a rule
#: of the compliance set the operator chose is a failed control, and the default set
#: is security configuration -- public access blocks, encryption, logging, TLS. The
#: level is ``error`` to match, and ``issue_severity`` is set as well, because ASH's
#: two severity readers disagree on a bare ``error`` (the gate reads CRITICAL, the
#: flat reporters HIGH) and both honor ``issue_severity``, so every reader says HIGH.
VIOLATION_SEVERITY = "HIGH"
VIOLATION_LEVEL = "error"

_SUCCESS_EXIT_CODES = frozenset({0, 19})

#: Shown in a failure message in place of the tool's stderr when the scanner's
#: redaction values could not be read (``guarded_values`` answered None): the text
#: is withheld rather than printed unredacted.
_STDERR_WITHHELD = "(stderr withheld: the scanner's redaction values could not be read)"


def _stderr_for_message(
    response: Dict[str, Any], values: Optional[Iterable[str]]
) -> str:
    """cfn-guard's stderr for a failure message, redacted before it is cut.

    The excerpt keeps the start and the end of the text and drops the middle, so a
    value that straddles a cut survives a redaction run on the excerpt (neither
    half matches it). The redaction therefore runs on the whole text first.
    ``values`` None means the scanner's redaction values could not be read; then
    the text is withheld, never shown unredacted.
    """
    raw = response.get("stderr") or ""
    if not raw.strip():
        return ""
    if values is None:
        return _STDERR_WITHHELD
    return tool_output_excerpt(text_without_values(raw, values).strip(), 500)


#: The executable this scanner runs.
_COMMAND = "cfn-guard"

#: The failure recorded for a template whose cfn-guard invocation was not started
#: because an earlier one in the same scan timed out (as cfn-lint records it).
_NOT_STARTED_AFTER_TIMEOUT = (
    "not started: an earlier cfn-guard invocation of this scan timed out, and the "
    "scan is discarded after a timeout"
)
#: ``\Z``, not ``$``: ``$`` also matches before a trailing newline, so a name
#: ending in one passed the validator and failed later as an unknown rule set.
_RULE_SET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")

#: The files cfn-guard 3.2.1 reads from a ``cfn-guard --rules`` directory, case-sensitively
#: (measured: ``x.ruleset`` read, ``UP.GUARD`` and ``x.txt`` not).
_RULE_SUFFIXES = (".guard", ".ruleset")

#: The most bytes one of the operator's rules files may hold: the cap
#: ``utils/rules_bundles.py`` applies to one member of the installed bundle. An
#: operator's file was read whole with no bound, several times per scan.
_MAX_OPERATOR_RULE_BYTES = 16 * 1024 * 1024

#: The longest file name the filesystems ASH runs on accept (NAME_MAX).
_MAX_COPY_NAME_BYTES = 255

#: The failure recorded for a template whose cfn-guard run was not started because
#: the templates before it in the same scan had spent the scanner's scan_timeout.
_NOT_STARTED_AFTER_BUDGET = (
    "not started: the templates before it in this scan spent the scanner's "
    "scan_timeout, which bounds the whole scan rather than each template"
)


def _copy_name(index: int, name: str) -> str:
    """The name of the copy of an operator's rules file: its position, then its name.

    The copy is written beside the others in one directory, so the position keeps
    two files of one name apart. The name is cut to fit ``_MAX_COPY_NAME_BYTES``
    with its suffix kept, since the four bytes the position adds pushed a name of
    252 to 255 bytes past NAME_MAX and the copy could not be written.
    """
    prefix = f"{index:03d}-"
    suffix = next((s for s in _RULE_SUFFIXES if name.endswith(s)), "")
    stem = name[: len(name) - len(suffix)]
    budget = _MAX_COPY_NAME_BYTES - len(prefix) - len(suffix)
    while stem and len(stem.encode("utf-8", "surrogateescape")) > budget:
        stem = stem[:-1]
    return f"{prefix}{stem}{suffix}"


def _run_failure(response: Dict[str, Any]) -> Optional[str]:
    """Why a run that did not complete failed, worded by the response's flags, or None.

    The flags (``subprocess_utils.RESPONSE_FLAGS``) say what happened; the ``error``
    key alone does not. Before this every response with an error key read as
    "could not be started", a tool that ran and died on a signal, or whose output
    ASH failed to record, included; and every timeout read as "was killed", one
    ASH could not end (the tool possibly left alive), included. The endings
    themselves are spelled once, in ``subprocess_utils``.
    """
    if response.get("timed_out"):
        ending = (
            COULD_NOT_STOP_ENDING
            if response_could_not_stop(response)
            else WAS_KILLED_ENDING
        )
        return f"cfn-guard timed out{ending}"
    if response.get("signaled"):
        return f"cfn-guard did not finish: {response.get('error')}"
    if response.get("post_run_error"):
        return f"cfn-guard ran, but ASH could not record its output: {response.get('error')}"
    if response.get("cancelled"):
        return f"cfn-guard was cancelled: {response.get('error')}"
    if response.get("result_rejected"):
        return f"cfn-guard's result was rejected: {response.get('error')}"
    if "error" in response:
        # spawn_failed, or a response with no flag at all: the command never ran.
        return f"cfn-guard could not be started: {response['error']}"
    return None


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
                f"rules_paths. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning and the default set is evaluated."
            ),
        ),
    ] = [DEFAULT_RULE_SET]
    rules_paths: Annotated[
        List[str],
        Field(
            description=(
                "Your own cfn-guard rules: .guard files or directories of them. A "
                "relative path is taken from the directory of the config file that "
                "sets it, or from the working directory for --config-overrides, not "
                "from the source directory. Evaluated in addition to "
                f"rule_sets. {SET_BY_THE_OPERATOR} cfn-guard prints a rules file it "
                "cannot parse, so a path the scanned repository chose could put any "
                "file the scan can read into the report. Set by such a config, it is "
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

    #: Not Python-only: cfn-guard is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The exit codes a completed cfn-guard run may end with (19 = at least one
    #: rule failed), the same set ``_parse_response`` accepts per template. Declared
    #: on the class so the base class's reading of a run's exit code sees
    #: cfn-guard's own set and not its default of {0, 1}, under which 19 read as a
    #: failed run and 1 as a clean one.
    success_exit_codes: ClassVar[Set[int]] = set(_SUCCESS_EXIT_CODES)

    # Rules warnings already logged. The rules are selected again for the dependency
    # check and for each target, and each warning is logged once per scanner.
    _warned_rules: Set[str] = PrivateAttr(default_factory=set)

    @property
    def sandbox_requirements(self) -> SandboxRequirements:
        """Read access to the installed rules bundle, and nothing else.

        The bundle lives under ``rules_root()``: ``$ASH_CFN_GUARD_RULES_DIR``, or
        ``<ASH_BIN_PATH>/../share/cfn-guard-rules``. The baseline policy exposes ASH's
        bin directory but not that ``share`` directory beside it, so without this
        every ``--rules`` path would be missing inside the sandbox. A property
        because the location is read from the environment at scan time, as
        ``rule_files`` reads it. ``rules_paths`` needs no grant: ASH reads the
        operator's rules itself and gives cfn-guard a copy in the scanner run's
        own directory, which the sandbox grants read-only to the run it belongs
        to (``utils/sandbox/scope.prepare_spawn``).

        With no rules root (``rules_root`` raises: no ``ASH_CFN_GUARD_RULES_DIR``
        and no bin directory) there is no directory to grant, so the requirements
        are empty and a warning, once per scanner, says why. The scope reads this
        with ``getattr(scanner, "sandbox_requirements", None)``, which would turn
        any AttributeError raised here into the same empty grant without a word.
        ``validate_plugin_dependencies`` gives the same reason as the scanner's
        MISSING reason when the bundle is needed.
        """
        try:
            root = rules_root()
        except RulesBundleUnavailable as unavailable:
            self._warn_rules_once(
                "The sandbox is given no read access to a cfn-guard rules directory: "
                f"{unavailable}"
            )
            return SandboxRequirements()
        shown = root.as_posix()
        if "$" in shown or shown.startswith("~"):
            # The policy expands ``~`` and ``$VAR`` in every read path
            # (utils/sandbox/policy._expand), while cfn-guard is given the
            # literal path, so such a root is granted somewhere else or not at
            # all, and every --rules path is missing inside the sandbox.
            self._warn_rules_once(
                f"The cfn-guard rules directory {shown!r} holds a '$' or starts "
                "with '~', which the sandbox reads as an expansion; its grant may "
                "not match the path cfn-guard reads, and the rules may be missing "
                "under --sandbox. Set ASH_CFN_GUARD_RULES_DIR to a path without them."
            )
        return SandboxRequirements(read_paths=(shown,))

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
        (measured with 3.2.1: a file that is not rules, given as ``--rules``, came
        back whole on stderr), and that error reaches the scan's results. So the list is
        used only when the operator set it (``config_trust.operator_paths``; the
        operator may keep rules in the tree). A list from a config inside a git
        checkout or the scanned directory, or from an MCP client, is ignored with a
        warning, and the second
        value is True so ``_selected_rules`` can fall back to the default set.

        A named file is read as is. A directory is walked as cfn-guard walks one,
        for ``_RULE_SUFFIXES`` files at any depth, and each is read only when it
        resolves inside that directory: cfn-guard follows a symlinked file there
        (measured: ``linked.guard -> ../outside.txt`` printed the target), so a link
        leaving the directory the operator named is refused with a warning. Each
        file is read through ``open_in_scanned_tree`` with the named directory as
        its root, and cfn-guard is given a copy of what was read, so a link swapped
        in after the check is never followed.

        Raises:
            RulesBundleUnavailable: an operator's path does not exist, is inside the
                scanned tree and leads out of it through a symbolic link
                (``config_trust.LEADS_OUT_OF_THE_TREE``), or names a file that
                could not be read.
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
        for raw, entry in zip(options.rules_paths, chosen):
            if entry.refusal == LEADS_OUT_OF_THE_TREE:
                raise RulesBundleUnavailable(
                    f"scanners.cfn-guard.options.rules_paths names {raw!r}, a path "
                    "inside the scanned tree that resolves outside the scanned tree "
                    "through a symbolic link. The scanned repository decides what is "
                    "at that path, so it is not read."
                )
        refused = [
            (raw, entry.refusal)
            for raw, entry in zip(options.rules_paths, chosen)
            if entry.path is None
        ]
        for raw, reason in refused:
            self._warn_rules_once(
                refusal_warning(
                    f"Ignoring scanners.cfn-guard.options.rules_paths entry {raw!r}: "
                    f"{reason}.",
                    reason,
                )
            )
        root = scan_root(config, source_dir)
        real_root = Path(os.path.realpath(root))
        rules: List[_RuleFile] = []
        for raw, entry in zip(options.rules_paths, chosen):
            if entry.path is None:
                continue
            if not entry.path.exists():
                raise RulesBundleUnavailable(
                    f"scanners.cfn-guard.options.rules_paths names {entry.path}, "
                    "which does not exist"
                )
            # Inside the tree, read under the tree's root, so a link swapped in
            # after operator_paths checked the path is refused when the file is
            # opened; for a directory, so a directory replaced by a link that
            # leads out of the tree is refused file by file (os.walk follows the
            # directory it is given). Outside the tree the operator controls the
            # path and the link it may be.
            inside = entry.path.is_relative_to(real_root)
            if entry.path.is_dir():
                found = self._rules_in_directory(
                    entry.path, real_root if inside else entry.path, in_tree=inside
                )
                if not found:
                    # Nothing from it is evaluated, and the default rule sets
                    # still run, so the operator's rules went silently unread.
                    self._warn_rules_once(
                        f"cfn-guard rules directory {entry.path.as_posix()} holds "
                        "no .guard or .ruleset file, so nothing from it is evaluated."
                    )
                rules.extend(found)
            else:
                read_root = real_root if inside else entry.path.parent
                try:
                    rules.append(self._read_rule(entry.path, read_root, in_tree=inside))
                except TreeInputRefused as unusable:
                    # Named directly, so no other rule to fall back on: the
                    # operator asked for this file and it cannot be used.
                    raise RulesBundleUnavailable(
                        f"scanners.cfn-guard.options.rules_paths names {entry.path}, "
                        f"which cannot be used: {unusable.reason}"
                    ) from unusable
        return rules, bool(refused)

    def _rules_in_directory(
        self, directory: Path, root: Path, *, in_tree: bool
    ) -> List[_RuleFile]:
        """The rules files under ``directory`` that stay inside ``root``, read, sorted.

        ``root`` is the directory itself for one outside the scanned tree, and the
        tree's root for one inside it (``in_tree``), so a link swapped in after
        the path was checked is refused as the file branch refuses it. Like
        cfn-guard, the walk does not enter a symlinked subdirectory. One that
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
                    rules.append(self._read_rule(path, root, in_tree=in_tree))
                except TreeInputRefused as refused:
                    reason = refused.reason
                    if not in_tree:
                        reason = reason.replace("scanned tree", "rules directory")
                    self._warn_rules_once(
                        f"Not evaluating cfn-guard rules {path.as_posix()}: {reason}."
                    )
        return rules

    def _warn_rules_once(self, message: str) -> None:
        if message not in self._warned_rules:
            self._warned_rules.add(message)
            self._plugin_log(message, level=logging.WARNING)

    @staticmethod
    def _read_rule(path: Path, root: Path, *, in_tree: bool = False) -> _RuleFile:
        """``path``'s content, read only if it is a regular file inside ``root``.

        A symlink inside ``root`` is followed, as cfn-guard follows one, and that
        option also admits a file with more than one hard link. Inside the
        scanned tree (``in_tree``) such a file is refused: its content is also
        reachable under another name, which may be outside the tree, and
        cfn-guard prints a rules file it cannot parse. Outside the tree the
        operator owns the file, and installers hard-link freely there.

        Raises:
            TreeInputRefused: it resolves outside ``root``, is not a regular
                file, or is a hard-linked file inside the scanned tree.
            RulesBundleUnavailable: it could not be read, or it is larger than
                ``_MAX_OPERATOR_RULE_BYTES``.
        """
        try:
            with open_in_scanned_tree(path, root, follow_links_inside=True) as handle:
                if in_tree and os.fstat(handle.fileno()).st_nlink > 1:
                    raise TreeInputRefused(
                        relative_display(path, root), REASON_HARDLINK
                    )
                raw = handle.read(_MAX_OPERATOR_RULE_BYTES + 1)
        except OSError as exc:
            raise RulesBundleUnavailable(
                f"cfn-guard rules {path.as_posix()} could not be read: "
                f"{exc.strerror or exc}"
            ) from exc
        if len(raw) > _MAX_OPERATOR_RULE_BYTES:
            raise RulesBundleUnavailable(
                f"cfn-guard rules {path.as_posix()} is larger than the "
                f"{_MAX_OPERATOR_RULE_BYTES}-byte cap for one rules file"
            )
        # surrogateescape keeps every byte, and the copy is written back the same
        # way; only a CRLF line ending becomes LF.
        text = raw.decode("utf-8", errors="surrogateescape")
        return _RuleFile(path=path, content=text.replace("\r\n", "\n"))

    def _selected_rules(self) -> List[_RuleFile]:
        """The rules cfn-guard will be given, in order. See ``rule_files``."""
        source_dir = self._source_dir()
        operator_rules, refused = self._operator_rules(source_dir)
        rule_sets = self._operator_rule_sets()
        if refused and not rule_sets:
            # The repository emptied rule_sets and supplied its own rules. Its
            # rules are not read, and it does not get to switch cfn-guard off.
            self._warn_rules_once(
                "scanners.cfn-guard.options.rule_sets is empty and rules_paths was "
                f"ignored, so cfn-guard evaluates ASH's default rule set, "
                f"{DEFAULT_RULE_SET}."
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

    def _operator_rule_sets(self) -> List[str]:
        """``rule_sets`` as the operator chose it.

        A narrower set drops findings before ASH sees them, so they are neither
        reported nor counted as suppressed: ``rule_sets: [wa-Reliability-Pillar]``
        in the scanned tree's ``.ash/.ash.yaml`` turned 24 findings on the fixture
        into 9, losing every S3 public-access, encryption and logging finding. A
        value from a config inside a git checkout or the scanned directory, or from
        an MCP client, is replaced by the operator's own choice (the trusted base
        with the operator's overrides replayed, ``config_trust.operator_value``),
        or by the default set when the operator chose none, with a warning when the
        two differ, as ``rules_paths`` is. A repository value equal to the default
        used to be taken as it stood, with no provenance check, so a repository
        could narrow an operator's wider set down to the default by writing the
        default.
        """
        value = list(self._options().rule_sets)
        config = self.context.config if self.context is not None else None
        key = "scanners.cfn-guard.options.rule_sets"
        if set_by_operator(config, key, value):
            return value
        found, trusted = operator_value(config, key)
        chosen = (
            [str(name) for name in trusted]
            if found and isinstance(trusted, list)
            else [DEFAULT_RULE_SET]
        )
        if value == chosen:
            return chosen
        if chosen == [DEFAULT_RULE_SET]:
            evaluates = f"ASH's default rule set, {DEFAULT_RULE_SET}"
        else:
            evaluates = f"the operator's rule sets, {chosen!r}"
        self._warn_rules_once(
            refusal_warning(
                f"Ignoring scanners.cfn-guard.options.rule_sets ({value!r}): "
                f"{NOT_THE_OPERATORS}. cfn-guard evaluates {evaluates}.",
                NOT_THE_OPERATORS,
            )
        )
        return chosen

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

    def _rules_arguments(self, rules: List[_RuleFile]) -> List[str]:
        """``--rules`` for each rule: a bundled file by path, an operator's as a copy.

        The copies are written in the scanner run's own directory outside the
        scanned tree, new for the run and removed when it ends
        (``utils/tool_config_dir``), not in the results directory, which is
        inside the tree with the default output directory. They are named by
        position, so two files of the same name in different directories stay
        apart. cfn-guard's SARIF names rules by rule name, not by file (measured
        with 3.2.1), so the findings are the same.

        Raises:
            OSError: a copy could not be written. ``scan`` fails the scan with it.
        """
        arguments: List[str] = []
        for index, rule in enumerate(rules):
            path = rule.path
            if rule.content is not None:
                path = write_tool_config(
                    _copy_name(index, rule.path.name),
                    rule.content,
                    context=self.context,
                    errors="surrogateescape",
                )
            arguments.append(f"--rules={path.as_posix()}")
        return arguments

    def validate_plugin_dependencies(self) -> bool:
        """The binary on PATH, and every selected rules file present and verified."""
        if self.dependency_unavailable_reason:
            return False
        if find_executable(_COMMAND) is None:
            self._record_unavailable(
                "cfn-guard is not on PATH. Run `ash dependencies install --tool "
                "cfn-guard`, or use the ASH container image or `--mode nix`, which "
                "ship it."
            )
            return False
        try:
            self.rule_files()
        except RulesBundleUnavailable as exc:
            self._record_unavailable(str(exc))
            return False
        except OSError as exc:
            # Path.exists() and Path.is_dir() raise PermissionError on a rules
            # path under a directory this user cannot search (Python 3.10-3.12).
            # Escaping here dropped the scanner with a traceback instead of
            # reporting it MISSING with the reason.
            self._record_unavailable(
                "cfn-guard rules could not be checked: "
                f"{type(exc).__name__}: {exc.strerror or exc}"
            )
            return False
        return True

    def nothing_to_scan_reason(self) -> Optional[str]:
        """Why cfn-guard has nothing to scan in this run, or None.

        From the selection ``scan()`` makes, which cfn-lint shares
        (``cloudformation_templates_nothing_to_scan_reason``). The selection
        needs neither the binary nor the rules.
        """
        if self.context is None:
            return None
        return cloudformation_templates_nothing_to_scan_reason(self.context)

    def _record_unavailable(self, reason: str) -> None:
        self.dependency_unavailable_reason = reason
        # The ERROR log puts the line in self.errors (PluginBase._plugin_log);
        # appended here as well, every reason was recorded twice.
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
        """One template's results, located at ``uri``, severity-mapped, each once.

        The registry's rule sets share rules, and cfn-guard 3.2.1 evaluates a
        rule once per selected set that holds it, reporting identical results
        each time: ``wa-Security-Pillar`` and ``cis-aws-benchmark-level-1`` on the
        fixture's insecure template give 42 results, 29 of them distinct. A
        result is dropped only when it is identical, field for field, to one
        already kept. One rule's results for different failing clauses share the
        rule and the location but not the message, so they all stay.
        """
        results: List[Result] = []
        seen: Set[str] = set()
        for run in report.runs or []:
            for result in run.results or []:
                if not result.locations:
                    # A result cfn-guard reports with no location (a rule that
                    # fails the document as a whole) reached the merged report
                    # with nothing saying which template it was found in. The
                    # template is the location it has.
                    result.locations = [
                        Location(
                            physicalLocation=PhysicalLocation(
                                root=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri)
                                )
                            )
                        )
                    ]
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
                identity = result.model_dump_json()
                if identity in seen:
                    continue
                seen.add(identity)
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
        # Reset above every return, the exit code included; see cfn_lint_scanner.
        # The exit code is None, not 0: no cfn-guard has run for this target yet,
        # and a target whose every candidate the model rejects never starts one,
        # so the executor read a 0 for a tool that never ran. self.errors too, as
        # cfn_lint_scanner resets it: one instance scans the source and then the
        # converted target, and the converted target's invocation carried the
        # source target's failures beside an executionSuccessful of its own.
        self.targets_attempted = 0
        self.targets_failed = 0
        self.exit_code = None
        self._reset_errors()

        report = self._empty_report()
        # The unevaluated targets are cleared as cfn-nag clears them, for a
        # caller that is not the executor (which clears them before each scan);
        # a dependency recorded unavailable before this call keeps its line, the
        # reason the scan below does not start.
        self.clear_unevaluated_targets()
        if self.dependency_unavailable_reason:
            self.errors.append(self.dependency_unavailable_reason)
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
            results_dir.mkdir(parents=True, exist_ok=True)
            rule_args = self._rules_arguments(selected)
            source_dir = self._source_dir()
            # Without the files the global ignore paths ignore, as cfn-nag reads them.
            discovery = discover_templates(
                self.context, target_type, global_ignore_paths
            )
            for shown, reason in [*discovery.refused, *discovery.unparseable]:
                # Not read, or read by neither parser, so not known to be
                # CloudFormation: skipped and named, as cfn-nag skips it.
                self._plugin_log(
                    f"Skipped {shown}: {reason}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
            for shown, reason in discovery.skipped:
                # Not UTF-8 and not CloudFormation by its text: skipped and named,
                # as cfn-nag skips it, counted as nothing.
                self._plugin_log(
                    f"Skipped {shown}: {reason}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
            for shown, reason in discovery.unreadable:
                # A candidate ASH could not open, or a template it could not decode:
                # not known not to be CloudFormation. The tool-absent check counts
                # it as a template (only MISSING cannot hide one), so with the tool
                # present it is a target that was not evaluated, not a skip: the
                # two runs give the same answer for the same file.
                self.targets_attempted += 1
                self.targets_failed += 1
                self.record_unevaluated_target(shown)
                self._plugin_log(
                    f"cfn-guard did not evaluate {shown}: {reason}",
                    target_type=target_type,
                    level=logging.ERROR,
                )
            for path, reason in discovery.unmodelable:
                self.targets_attempted += 1
                self.targets_failed += 1
                # The ERROR log puts the line in self.errors; appended here as
                # well, every failure was recorded twice, and with the host's
                # absolute path where the other lines carry the shown one.
                self._plugin_log(
                    f"cfn-guard did not evaluate {display_path(path, source_dir)}: "
                    f"{reason}",
                    target_type=target_type,
                    level=logging.ERROR,
                )

            merged: List[Result] = []
            driver = report.runs[0].tool.driver
            # scan_timeout bounds the whole scan: each template was given the full
            # limit, so a scan's run time was bounded only by templates x limit.
            # A template reached with no time left is named and not started.
            budget = self._effective_scan_timeout()
            deadline = time.monotonic() + budget if budget is not None else None
            # Each template's stderr, written once below as one log: the runner
            # truncates the per-run log at each start, so the log on disk kept
            # only the last template's text.
            stderr_sections: List[str] = []
            timed_out = False
            for template in discovery.templates:
                self.targets_attempted += 1
                shown = display_path(template, source_dir)
                if timed_out:
                    # An earlier invocation timed out, and the executor discards
                    # the whole scan after a recorded timeout, so starting the
                    # remaining templates, each with a fresh full scan_timeout,
                    # would only spend their time. Named, not started. The ERROR
                    # log puts the line in self.errors (PluginBase._plugin_log
                    # appends every ERROR log), so it is not appended here as
                    # well: appended twice, each template appeared twice in
                    # the invocation's exitCodeDescription.
                    self.targets_failed += 1
                    self._plugin_log(
                        f"cfn-guard did not evaluate {shown}: "
                        f"{_NOT_STARTED_AFTER_TIMEOUT}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    continue
                remaining: Optional[float] = None
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.targets_failed += 1
                        self._plugin_log(
                            f"cfn-guard did not evaluate {shown}: "
                            f"{_NOT_STARTED_AFTER_BUDGET}",
                            target_type=target_type,
                            level=logging.ERROR,
                        )
                        continue
                command = [
                    _COMMAND,
                    "validate",
                    *rule_args,
                    f"--data={Path(template).absolute().as_posix()}",
                    "--output-format=sarif",
                    "--structured",
                    "--show-summary=none",
                ]
                output_before = len(self.output)
                response = self._run_subprocess(
                    command=command,
                    results_dir=results_dir,
                    stdout_preference="return",
                    stderr_preference="return",
                    timeout=remaining,
                )
                timed_out = timed_out or (
                    isinstance(response, dict) and bool(response.get("timed_out"))
                )
                # The SARIF came back on stdout and is merged below; the base class
                # also kept every line of it in self.output, so memory grew with
                # the number of templates for text the report already holds.
                del self.output[output_before:]
                if isinstance(response, dict):
                    stderr_text = response.get("stderr") or ""
                    if str(stderr_text).strip():
                        stderr_sections.append(f"--- {shown}\n{stderr_text}")
                failure, template_report = self._parse_response(
                    response, values=guarded_values(self)
                )
                if failure is not None or template_report is None:
                    failure = failure or "cfn-guard output could not be read"
                    self.targets_failed += 1
                    # The ERROR log puts the line in self.errors; see above.
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

            if stderr_sections:
                with open_for_write(
                    results_dir.joinpath(f"{self.__class__.__name__}.stderr.log")
                ) as handle:
                    handle.write("\n".join(stderr_sections) + "\n")

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
        directory, and one outside the source directory by its file name alone
        (``display_path`` returns such a path absolute), so
        ash_aggregated_results.json carries no machine paths.
        """
        recorded = []
        for path in rules:
            parent = path.parent.name
            if parent.startswith(f"{RULES_BUNDLE_NAME}-"):
                shown = f"{parent}/{path.name}"
            else:
                shown = display_path(path, source_dir)
                if Path(shown).is_absolute():
                    shown = path.name
            recorded.append(f"--rules={shown}")
        return recorded

    @staticmethod
    def _parse_response(
        response: object,
        *,
        values: Optional[Iterable[str]],
    ) -> Tuple[Optional[str], Optional[SarifReport]]:
        """(failure reason or None, parsed report or None) for one invocation.

        ``values`` are the scanner's redaction values (``guarded_values(self)`` at
        the call site): the tool's stderr is redacted with them before it is cut
        for the message, and ``None`` (the values could not be read) shows a note in
        place of the stderr rather than the text unredacted. Required, with no
        default: a default of "redact nothing" let a caller that forgot it print
        the stderr unredacted, the gap the parameter closes.
        """
        if not isinstance(response, dict):
            return "cfn-guard did not run", None
        failure = _run_failure(response)
        if failure is not None:
            return failure, None
        code = response.get("returncode")
        stderr = _stderr_for_message(response, values)
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
        if not parsed.runs:
            # Every field of a SARIF log is optional, so ``{}`` validates. No run
            # is no evaluation, and it read as a clean template.
            return (
                (
                    f"cfn-guard exited {code} with SARIF that holds no run, so the "
                    "template was not evaluated"
                ),
                None,
            )
        has_results = any(run.results for run in parsed.runs or [])
        if code == 19 and not has_results:
            # 19 is "a rule failed", and a failure that rendered no result is a
            # verdict the report would lose. Refused rather than read as clean.
            return (
                "cfn-guard reported a failing rule but the SARIF has no results",
                None,
            )
        return None, parsed
