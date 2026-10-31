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
``cfn-lint --format sarif --output-file <f> [options] -- <template>...``, run in a
new empty directory outside the scanned tree with every path absolute, because
cfn-lint resolves a config file's relative paths against its working directory
(``CfnLintScanner._private_cwd``). cfn-lint writes each URI as the
absolute path it was given, and ``normalize_report`` maps it back to the
repository-relative path ASH reports.

* Template paths are passed through ``glob.escape``. cfn-lint expands every filename
  argument with ``glob.glob(filename, recursive=True)`` (cfnlint/config.py at 1.57.1),
  so a template named ``a[1].yaml`` was reported as "could not be processed by
  glob.glob" (rule E0003) and never linted, and one named ``*.yaml`` would have
  expanded to every YAML file in its directory. Measured against 1.57.1: unescaped,
  ``g[1].yaml`` yields one E0003 and no lint results; escaped, it yields the three
  findings the same template produces under a plain name.
* ``--`` ends option parsing, so a template whose name starts with ``-`` is a file.
* ``--mandatory-checks`` and ``--configure-rule`` keep a template's own
  ``Metadata: cfn-lint: config`` from changing what is reported, unless the operator
  sets ``honor_inline_ignores`` (``CfnLintScanner._honor_inline_ignores``).
* Templates are batched under ``_ARGV_CHAR_BUDGET`` characters per invocation, so a
  repository with thousands of templates stays inside Windows' 32767-character
  command-line limit. With ``honor_inline_ignores`` on, each template gets an
  invocation of its own instead (``CfnLintScanner._honor_inline_ignores``).
* ``AWS_REGION`` and ``AWS_DEFAULT_REGION`` are set to us-east-1 in cfn-lint's
  environment, so the region it falls back to does not depend on the host
  (``CfnLintScanner._child_env``).

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
import os
import re
import string
from pathlib import Path
import copy
from contextlib import ExitStack
from typing import (
    Annotated,
    Any,
    ClassVar,
    ContextManager,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from urllib.parse import unquote

import yaml
from pydantic import AnyUrl, Field, PrivateAttr, field_validator

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.path_trust import (
    private_cwd_outside_scanned_tree,
)
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values
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
    cloudformation_templates_nothing_to_scan_reason,
    discover_templates,
    display_path,
)
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    operator_path,
    operator_value,
    refusal_warning,
    set_by_operator,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    response_could_not_stop,
)
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: cfn-lint's rule-id letter, mapped to an ASH severity and the SARIF level that
#: severity reads as everywhere else in ASH.
#:
#: Why below security severities: cfn-lint reports template correctness, not
#: security weaknesses. An E rule means the template is invalid or will fail to
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

#: The region cfn-lint validates against when neither ``regions``, the template's
#: own metadata nor an operator's ``.cfnlintrc`` names one. See ``_child_env``.
DEFAULT_REGION = "us-east-1"

# Under Windows' 32767-character CreateProcess limit with room for the interpreter
# path, uv's own arguments and the options above.
_ARGV_CHAR_BUDGET = 24000

# What cfn-lint accepts for these options, checked here so a config value can never
# be read as another option. ``\Z``, not ``$``: ``$`` also matches before a
# trailing newline, so ``"us-east-1\n"`` passed as a region and was handed to
# cfn-lint with the newline.
_REGION_PATTERN = re.compile(r"^(ALL_REGIONS|[a-z]{2}(-[a-z]+)+-\d+)\Z")
_CHECK_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*\Z")

#: The characters a rule id prefix is built from in ``mandatory_prefixes``: the ones
#: ``_CHECK_PATTERN`` allows, which cover every built-in id (a letter and four
#: digits), plus ``_`` and ``-``, which a custom rule's id (``append_rules``) may
#: hold: without them such a rule was outside every mandatory prefix, so a
#: template's own ``ignore_checks`` could turn it off.
_RULE_ID_ALPHABET = (
    string.digits + string.ascii_uppercase + string.ascii_lowercase + "_-"
)

#: The most option text cfn-lint may be given; the rest of ``_ARGV_CHAR_BUDGET`` is
#: left for templates. A ``cfn-lint --mandatory-checks`` list longer than this comes from an
#: ignore list too long to express, and is refused rather than truncated.
_OPTION_CHAR_BUDGET = 20000

#: The ``cfn-lint --configure-rule`` value passed when the operator configures no rule, so
#: that a template's own configure_rules never apply (``_configure_rule_args``).
#: E3012's ``strict`` is false by default, so this sets it to what it already is;
#: measured with 1.43.3 and 1.57.2, it changes no finding on the fixture templates.
_NO_OP_CONFIGURE_RULE = "E3012:strict=false"

#: The ``cfn-lint --ignore-checks`` value passed when nothing is ignored, so that a
#: template's own ignore_checks never stand in for the command line's (see
#: ``_honor_inline_ignores``). It ignores nothing: every rule is mandatory then,
#: and mandatory outranks ignored. It is not a prefix of E0000, which cfn-lint
#: tests against ignore_checks alone.
_NO_OP_IGNORE_CHECK = "W0000"

#: What a configure_rules key may be when it is passed on the command line.
_CONFIG_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Characters the ``cfn-lint --configure-rule`` parser splits a value on
#: (cfnlint/config.py, ``RuleConfigurationAction``), so a value holding one cannot
#: be passed whole.
_CONFIGURE_RULE_SEPARATORS = frozenset(",:=")


def severity_for_rule(rule_id: Optional[str]) -> Tuple[str, str]:
    """The (ASH severity, SARIF level) for a cfn-lint rule id.

    An id that does not start with E, W or I is treated as E: an unknown class is
    reported at the level that fails a default scan rather than below it.
    """
    letter = (rule_id or "E")[:1].upper()
    return SEVERITY_BY_RULE_LETTER.get(letter, SEVERITY_BY_RULE_LETTER["E"])


def mandatory_prefixes(ignored: List[str]) -> List[str]:
    """Rule-id prefixes that match exactly the ids no prefix in ``ignored`` matches.

    cfn-lint matches ``--mandatory-checks`` and ``--ignore-checks`` entries as
    prefixes of a rule id, and a mandatory match wins over every ignore. So the
    complement of the ignored prefixes, over ``_RULE_ID_ALPHABET``, makes every
    other rule mandatory and leaves the ignored ones to ``--ignore-checks``. With
    nothing ignored it is each single character. For ``W2001`` it is every first
    character but ``W``, then every ``W`` and a second character but ``2``, and so
    on down to ``W200`` and a fifth character but ``1``.

    One kind of id cannot be covered: one that is a proper prefix of an ignored
    prefix (``W20`` when ``W2001`` is ignored), because every prefix of it is a
    prefix of the ignored one too. Every built-in id is a letter and four digits,
    and the ignored prefixes are validated as rule ids or prefixes, so only a
    custom rule with a shorter id is affected.
    """
    distinct = sorted(set(ignored))
    minimal = [
        p for p in distinct if not any(p != q and p.startswith(q) for q in distinct)
    ]
    result: List[str] = []

    def walk(prefix: str, below: List[str]) -> None:
        following = {entry[len(prefix)] for entry in below}
        for char in _RULE_ID_ALPHABET:
            extended = prefix + char
            if char not in following:
                result.append(extended)
            elif extended not in below:
                walk(extended, [entry for entry in below if entry.startswith(extended)])

    walk("", minimal)
    return result


def _command_line_value(value: Any) -> Optional[str]:
    """A configure_rules value as ``--configure-rule`` would read it back, or None.

    cfn-lint splits a ``--configure-rule`` value on commas, then takes the text
    between the first and second colon and after the first equals sign, and keeps
    one value per key. So a value is passed only when it survives that whole: a
    boolean, an integer, a string without ``,``, ``:`` or ``=``, or a list of
    exactly one of those (cfn-lint makes a list of a single value for a list
    option). Anything else returns None.
    """
    if isinstance(value, list):
        if len(value) != 1:
            return None
        value = value[0]
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and not _CONFIGURE_RULE_SEPARATORS & set(value):
        return value
    return None


#: The failure recorded for a template whose cfn-lint invocation was not started
#: because an earlier one in the same scan timed out.
_NOT_STARTED_AFTER_TIMEOUT = (
    "not started: an earlier cfn-lint invocation of this scan timed out, and the "
    "scan is discarded after a timeout"
)

#: How many templates one "did not evaluate" line names when a whole invocation
#: failed; the rest are counted. A batch holds up to ``_ARGV_CHAR_BUDGET``
#: characters of paths, hundreds of templates, and one line that named every one
#: of them was unreadable in the error record. No name is lost: each template is
#: recorded on its own as a target the tool never evaluated
#: (``record_unevaluated_target``), which the run's error record names one by one.
_NAMED_TEMPLATES_IN_A_LINE = 8


def _named_templates(names: List[str]) -> str:
    """``names`` for one log line: every name up to ``_NAMED_TEMPLATES_IN_A_LINE``,
    else that many and a count of the rest (``a.yaml, b.yaml and 40 more``)."""
    if len(names) <= _NAMED_TEMPLATES_IN_A_LINE:
        return ", ".join(names)
    shown = names[:_NAMED_TEMPLATES_IN_A_LINE]
    return f"{', '.join(shown)} and {len(names) - len(shown)} more"


def _invocation_failure(response: Dict[str, Any]) -> Optional[str]:
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
        return f"cfn-lint timed out{ending}"
    if response.get("signaled"):
        return f"cfn-lint did not finish: {response.get('error')}"
    if response.get("post_run_error"):
        return f"cfn-lint ran, but ASH could not record its output: {response.get('error')}"
    if response.get("cancelled"):
        return f"cfn-lint was cancelled: {response.get('error')}"
    if response.get("result_rejected"):
        return f"cfn-lint's result was rejected: {response.get('error')}"
    if "error" in response:
        # spawn_failed, or a response with no flag at all: the command never ran.
        return f"cfn-lint could not be started: {response['error']}"
    return None


def _combined_exit_code(codes: List[Any]) -> Optional[int]:
    """One exit code for a scan made of several cfn-lint invocations, or None for none.

    cfn-lint's code is a bitmask of the levels it reported (2 error, 4 warning,
    8 informational), so the codes of two completed invocations combine by OR:
    the base class kept the LARGER, which read a scan that reported an error (2)
    and a warning (4) as warnings only. An invocation that failed (a code that is
    not a completed run, or none) outranks every completed one, and the first
    such code is the scan's.
    """
    seen: List[int] = []
    for code in codes:
        if not _successful_exit(code):
            try:
                return int(code)  # type: ignore[call-overload]
            except (TypeError, ValueError):
                return 1
        seen.append(int(code))  # type: ignore[call-overload]
    if not seen:
        return None
    combined = 0
    for code in seen:
        combined |= code
    return combined


def _one_template_can_fail_the_run(response: Dict[str, Any]) -> bool:
    """Whether a failed batch invocation is worth repeating one template at a time.

    True for an invocation that started and ended on its own: cfn-lint then exited
    for the whole run on something in one template, or wrote a report ASH could not
    use. A timeout, or a tool that could not be started, would do the same again.
    """
    return bool(response) and not response.get("timed_out") and "error" not in response


#: The fewest templates left after a failed batch's first re-run for which one
#: probe lint of a synthetic template is cheaper than linting each of them alone:
#: below it the re-runs are made, each exact; from it on the probe decides whether
#: the failure is the run's (see ``_PROBE_TEMPLATE``).
_RUN_WIDE_PROBE_MIN_REMAINING = 2

#: The template a probe lint runs with the batch's own options to decide whether a
#: batch failure is the run's. Valid, one resource that takes no properties, and
#: no Metadata: a fault of one template (a region its own cfn-lint Metadata names
#: that this cfn-lint does not know) cannot reach it, while a fault of the run (an
#: operator regions value this cfn-lint does not know, a configure_rules key it
#: refuses, a broken install) fails it exactly as it failed the batch. cfn-lint's
#: message for the Metadata fault names no template, so the first and last
#: templates of a batch failing alike could not tell the two apart: a batch whose
#: first and last templates named the same unknown region folded every template
#: between them as failed without linting it.
_PROBE_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  AshProbe:\n"
    "    Type: AWS::CloudFormation::WaitConditionHandle\n"
)


def _names_a_template(text: str, names: List[str]) -> bool:
    """Whether a failure text names one of the batch's templates.

    A failure that quotes a template path is that template's (cfn-lint names the
    file it could not process), never the run's, so it is not folded over the
    others however alike the first and last re-runs read.
    """
    for name in names:
        if name and (name in text or name.rsplit("/", 1)[-1] in text):
            return True
    return False


def _successful_exit(code: object) -> bool:
    try:
        value = int(code)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return False
    return 0 <= value <= 14 and value % 2 == 0


#: Shown in a failure message in place of the tool's stderr when the scanner's
#: redaction values could not be read (``guarded_values`` answered None): the text
#: is withheld rather than printed unredacted.
_STDERR_WITHHELD = "(stderr withheld: the scanner's redaction values could not be read)"


def _stderr_for_message(
    response: Dict[str, Any], values: Optional[Iterable[str]]
) -> str:
    """cfn-lint's stderr for a failure message, redacted before it is cut.

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


class CfnLintScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a cfn-lint configuration file (.cfnlintrc). A relative path "
                "is taken from the directory of the config file that sets it, or "
                "from the working directory for --config-overrides, not from the "
                "source directory. When unset, ASH "
                "gives cfn-lint an empty configuration, so a .cfnlintrc in the scanned "
                "repository or the home directory is NOT read: such a file can load "
                "Python rules (append_rules) and switch checks off. "
                f"{SET_BY_THE_OPERATOR} The file is used only when it is outside the "
                "scanned tree; otherwise it is ignored with a warning."
            ),
        ),
    ] = None
    regions: Annotated[
        List[str],
        Field(
            description=(
                "AWS regions to validate templates against, e.g. ['us-east-1', "
                "'eu-west-1'], or ['ALL_REGIONS']. Empty validates against "
                "us-east-1, or the regions a template names in its own cfn-lint "
                "metadata or config_file names; AWS_REGION and AWS_DEFAULT_REGION "
                f"are not read. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
            ),
        ),
    ] = []
    ignore_checks: Annotated[
        List[str],
        Field(
            description=(
                "cfn-lint rule ids or prefixes to skip, e.g. ['W2001', 'W3']. Prefer "
                "ASH suppressions for individual findings; this removes the rule from "
                f"every template. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
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
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor the ignore_checks and configure_rules a template sets for "
                "itself in `Metadata: cfn-lint: config` (ignore_checks also at the "
                "resource level). Off by default: every rule outside ignore_checks "
                "and the config_file's ignore_checks is passed to cfn-lint as "
                "mandatory, and the config_file's configure_rules are passed on the "
                "command line, which cfn-lint takes instead of a template's, so a "
                "template cannot hide its own findings or the next template's "
                "parse errors, which reach ASH, where suppressions are reported "
                "and counted. A config_file setting the command line cannot carry "
                "(a list of more than one item, or a value with a comma, colon or "
                "equals sign) is then left out with a warning, and a config_file "
                "that sets merge_configs fails the scan. On, each template is "
                "linted by a cfn-lint run of its own, so its settings reach no "
                "other template; that adds a cfn-lint start-up per template. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
        ),
    ] = False
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
                f"verified against. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
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

    #: Python-only: cfn-lint is a Python package ASH runs through uv, so it needs
    #: nothing but Python. Stated here rather than read from use_uv_tool, which the
    #: dependency check sets to False when it uses a cfn-lint on PATH instead.
    python_only: ClassVar[bool | None] = True

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # The strict default, declared so the choice is visible: cfn-lint is a uv tool,
    # whose directories and cache the baseline already exposes, and it reads the
    # templates and ASH's empty config, both mounted. Its resource specs ship in the
    # package. An operator's config_file outside the tree needs extra_read_paths.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # Options already refused with a warning; each is read on every invocation and
    # warned about once per scanner.
    _refused_options: Set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CfnLintScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.IAC
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._deferred_tool_version_probe = ("cfn-lint", self._uv_from_spec())
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

    def _operator_option(self, name: str) -> Any:
        """``options.<name>`` as the operator chose it.

        For the options that decide what cfn-lint reports: ``ignore_checks`` drops
        findings before ASH sees them, so they are neither reported nor counted as
        suppressed (measured: ``ignore_checks: [E, W]`` in the scanned tree's
        ``.ash/.ash.yaml`` turned 3 findings into a PASSED scan). A value from a
        config inside a git checkout or the scanned directory, or from an MCP client,
        is replaced by the operator's own value (the trusted base with the
        operator's overrides replayed, ``config_trust.operator_value``), or by
        the option's default when the operator set none, with a warning once per
        option when the two differ, as ``config_file`` is. A repository value equal
        to the default used to be taken as it stood, with no provenance check, so a
        repository could undo an operator's ``ignore_checks`` or ``regions`` by
        writing the default. ``tool_version``, which chooses the release uv
        installs, is held to the operator's value when the config is resolved
        instead (``_get_tool_version_constraint``).
        """
        options = self._options()
        value = getattr(options, name)
        default = type(options).model_fields[name].default
        config = self.context.config if self.context is not None else None
        key = f"scanners.cfn-lint.options.{name}"
        if set_by_operator(config, key, value):
            return value
        found, trusted = operator_value(config, key)
        chosen = copy.deepcopy(trusted if found else default)
        if value == chosen:
            return chosen
        if name not in self._refused_options:
            self._refused_options.add(name)
            if found and chosen != default:
                uses = f"the operator's value, {chosen!r}"
            else:
                uses = f"the default, {default!r}"
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.cfn-lint.options.{name} ({value!r}): "
                    f"{NOT_THE_OPERATORS}. cfn-lint uses {uses}.",
                    NOT_THE_OPERATORS,
                ),
                level=logging.WARNING,
            )
        return chosen

    def _get_tool_version_constraint(self) -> str | None:
        """``tool_version``, which only the operator sets.

        ``resolve_config`` replaces a value from a config that is not the
        operator's (``config/tool_config_trust.confine_tool_versions``), so this
        reads the option as every uv-installed scanner does.
        """
        return self._options().tool_version

    def _get_tool_package_extras(self) -> List[str] | None:
        """cfn-lint's SARIF formatter is behind its ``sarif`` extra."""
        return ["sarif"]

    def validate_plugin_dependencies(self) -> bool:
        """The bandit/checkov resolution: uv, then a verified binary on PATH, then install."""
        # Gate first: a scanner already recorded MISSING has nothing to probe, and
        # the deferred version probe starts a uv run.
        if self.dependency_unavailable_reason:
            return False
        self.resolve_deferred_tool_version()
        if self.dependency_unavailable_reason:
            return False
        if not self._validate_uv_tool_availability():
            # The resolver probes under this scanner's own offline mode, as every
            # uv call of the mixin does: without it a scanner offline by its
            # options probed PyPI online while its run and install were offline.
            resolved = get_uv_tool_command(
                _COMMAND,
                from_spec=self._uv_probe_from_spec(),
                offline=self._is_offline_mode(),
            )
            if resolved is None:
                return False
            return self._accept_binary_on_path(resolved)
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
        resolved = get_uv_tool_command(
            _COMMAND,
            from_spec=self._uv_probe_from_spec(),
            offline=self._is_offline_mode(),
        )
        if resolved is None:
            return False
        # As the uv-absent branch above: a dependency declared satisfied on a
        # binary the resolver found on PATH has to run that binary. With
        # use_uv_tool left True, every scan then went through uv, whose install
        # had just failed, and refused to start.
        self.use_uv_tool = resolved[:1] == ["uv"]
        self.dependencies_satisfied = True
        return True

    def _accept_binary_on_path(self, resolved: List[str]) -> bool:
        """Whether the cfn-lint the resolver found with no uv may run the scan.

        Without uv there is no install to fall back on, so the binary on PATH
        is the scan's cfn-lint: it is verified against the scan's requirement
        (``sarif`` extra, the version constraint) as ``_select_tool_execution``
        verifies one. Before this it was declared satisfied unverified, and a
        cfn-lint without the ``sarif`` extra then failed every invocation with
        an unknown-format error. One that falls short is MISSING with the
        reason; one that cannot be verified runs, with a warning, since nothing
        better is at hand.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            verify_pre_installed_tool,
        )

        if resolved[:1] == ["uv"]:
            # Reachable only if the resolver found a uv the availability check did
            # not; run through it as the final fallback does.
            self.use_uv_tool = True
            self.dependencies_satisfied = True
            return True
        executable = resolved[0]
        checked = verify_pre_installed_tool(
            executable,
            _COMMAND,
            self._get_tool_package_extras(),
            self._get_tool_version_constraint(),
            uv_executable=None,
            values=self._values_to_redact(),
        )
        if checked.status == "unsatisfied":
            reason = (
                f"uv is not installed and the cfn-lint on PATH ({executable}) "
                f"cannot be used: {checked.detail}"
            )
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
            return False
        if checked.status != "satisfied":
            self._plugin_log(
                f"uv is not installed and the cfn-lint on PATH ({executable}) "
                f"could not be verified against the scan's requirement "
                f"({checked.detail}); running it anyway.",
                level=logging.WARNING,
            )
        self.use_uv_tool = False
        self.dependencies_satisfied = True
        return True

    def nothing_to_scan_reason(self) -> Optional[str]:
        """Why cfn-lint has nothing to scan in this run, or None.

        From the selection ``scan()`` makes, which cfn-guard shares
        (``cloudformation_templates_nothing_to_scan_reason``).
        """
        if self.context is None:
            return None
        return cloudformation_templates_nothing_to_scan_reason(self.context)

    def _option_args(self) -> List[str]:
        """Arguments from config, each as one ``--flag=value`` token.

        The ``=`` form keeps a value from ever being parsed as a flag of its own.

        A ``--config-file`` is always passed. Without one, cfn-lint reads
        ``.cfnlintrc`` from the working directory (the scanned repository) and from
        the home directory (cfnlint/config.py, ``_find_config``), and reads neither
        once a config file is named. A repository's ``.cfnlintrc`` is not inert
        configuration: ``append_rules`` loads Python files as rules, which runs them
        in the scan's environment (measured: a ``rules/extra.py`` beside a
        ``.cfnlintrc`` naming it ran on a plain ``cfn-lint -- t.yaml``), and
        ``ignore_checks: [E, W]`` turns every finding off without anything reaching
        ASH's suppression accounting. So the default is an empty configuration ASH
        writes itself, outside the scanned tree (``empty_tool_config``), and a
        ``.cfnlintrc`` is used only when the ASH config names it in ``config_file``.

        The ASH config usually comes from the scanned repository too, so
        ``config_file`` is honored only when the operator set it (through
        ``--config-overrides`` or a config file outside every git checkout and the
        scanned directory, see ``utils/config_trust.py``) and it resolves outside the
        scanned tree.
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
            # Outside the scanned tree, new for this run and removed when it ends
            # (config/tool_config_trust.empty_tool_config), so nothing the
            # repository put at a path of its choosing is written through or read.
            # It holds no relative path, so cfn-lint's private working directory
            # (_private_cwd) changes nothing about it.
            empty = empty_tool_config(
                "ash-empty.cfnlintrc", "{}\n", context=self.context
            )
            args.append(f"--config-file={empty.resolve().as_posix()}")
        else:
            args.append(
                f"--config-file={Path(os.path.abspath(config_file)).as_posix()}"
            )
        # Through the operator gate like ignore_checks: --regions overrides the
        # regions a template declares, and a region whose resource types differ
        # drops region-dependent findings, so a repository's config must not
        # choose it.
        regions = list(self._operator_option("regions"))
        if regions:
            args.extend(["--regions", *regions])
        ignore_checks = list(self._operator_option("ignore_checks"))
        honor_inline_ignores = self._honor_inline_ignores()
        if honor_inline_ignores:
            # Without this, a command-line --ignore-checks replaces a template's
            # own ignore_checks list (cfn-lint ranks the command line above the
            # template unless the configurations are merged), so the operator's
            # ignores silently defeated the option they turned on. Merged, both
            # apply: the template's lists are added to the operator's.
            args.append("--merge-configs")
        settings: Dict[str, Any] = {}
        include_checks = list(options.include_checks)
        mandatory_checks: List[str] = []
        if not honor_inline_ignores and config_file is not None:
            settings = self._config_file_settings(config_file)
            if settings.get("merge_configs"):
                raise ScannerError(
                    f"{Path(config_file).as_posix()} sets merge_configs, under which "
                    "cfn-lint merges a template's own Metadata configure_rules into "
                    "the ones ASH passes, so a template could change what is "
                    "reported. Remove merge_configs from it, or set "
                    "scanners.cfn-lint.options.honor_inline_ignores to let "
                    "templates configure rules."
                )
            for check in self._config_file_ignores(settings, config_file):
                if check not in ignore_checks:
                    ignore_checks.append(check)
            # The file's include_checks and mandatory_checks apply the same way:
            # a command-line value replaces the file's whole, so the file's were
            # silently dropped once ASH passed its own.
            for check in self._config_file_checks(
                settings, "include_checks", config_file
            ):
                if check not in include_checks:
                    include_checks.append(check)
            mandatory_checks = self._config_file_checks(
                settings, "mandatory_checks", config_file
            )
        if ignore_checks:
            args.extend(["--ignore-checks", *ignore_checks])
        elif not honor_inline_ignores:
            args.extend(["--ignore-checks", _NO_OP_IGNORE_CHECK])
        if include_checks:
            args.extend(["--include-checks", *include_checks])
        if not honor_inline_ignores:
            # See _honor_inline_ignores. One token each, so no value is read as a flag.
            prefixes = mandatory_prefixes(ignore_checks)
            for check in mandatory_checks:
                if check not in prefixes:
                    prefixes.append(check)
            # E0003 names a template cfn-lint could not open or process, which
            # ASH reads as a failed invocation (_lint_once); under an operator's
            # ``ignore_checks: [E]`` it was dropped and the templates read as
            # linted and clean. Mandatory outranks ignored, so it is always kept.
            if not any(_CONFIG_ERROR_RULE.startswith(prefix) for prefix in prefixes):
                prefixes.append(_CONFIG_ERROR_RULE)
            args.append("--mandatory-checks=" + ",".join(prefixes))
            args.extend(
                f"--configure-rule={entry}"
                for entry in self._configure_rule_args(
                    settings.get("configure_rules"), config_file
                )
            )
        option_chars = sum(len(arg) + 1 for arg in args)
        if option_chars > _OPTION_CHAR_BUDGET:
            raise ScannerError(
                f"cfn-lint's options take {option_chars} characters, more than the "
                f"{_OPTION_CHAR_BUDGET} a command line can spare: ignore_checks names "
                "too many rule ids to pass the rest as mandatory, or the config "
                "file's configure_rules are too long to pass. Use fewer, shorter "
                "prefixes, or ASH suppressions."
            )
        return args

    def _honor_inline_ignores(self) -> bool:
        """Whether a template's own ``ignore_checks`` and ``configure_rules`` may apply.

        A template can set ``Metadata: cfn-lint: config: ignore_checks`` for the
        whole template and for each resource, and cfn-lint drops what they name
        before ASH sees it, so it is neither reported nor counted as suppressed
        (measured with 1.57.2: ``[E, W]`` at the template level turned the
        fixture's three findings into none, and so did one rule per resource).
        cfn-lint applies neither to a rule ``--mandatory-checks`` names, so unless
        the operator turned this on, ``_option_args`` passes every rule outside
        the operator's own ignores as mandatory (``mandatory_prefixes``). Those
        ignores, from ``ignore_checks`` and the operator's ``config_file``, are
        passed as ``--ignore-checks``, which cfn-lint ranks above a template's.

        A template's ``configure_rules`` change what a rule reports, and
        --mandatory-checks does not stop them (measured with 1.57.2: E3031
        ``exceptions`` and E1029 ``custom_excludes`` turned a template's E3031,
        E1029 and E1161 into E1161 alone). cfn-lint takes configure_rules from the
        first of the command line, the template and the config file that sets
        any, whole, not rule by rule (cfnlint/config.py ``_get_argument_value``),
        so ``_option_args`` passes them on the command line too
        (``_configure_rule_args``).

        A template's ignore_checks also reached the next template. cfn-lint keeps
        the last decoded template's Metadata config while it reads the next one,
        and when that one cannot be decoded it drops the E0000 results if the
        kept ignore_checks name E0000 (cfnlint/runner/template/runner.py
        ``run_template_by_file_path``), without consulting --mandatory-checks.
        Measured with 1.43.3 and 1.57.2: a template with duplicate keys reported
        two E0000 alone and none after a template ignoring ``[E]`` for itself.
        A command-line --ignore-checks replaces the template's list, so one is
        always passed, ``_NO_OP_IGNORE_CHECK`` when nothing is ignored. Nothing
        else a template sets reached the next one: resource ignore_checks,
        configure_rules, regions and ignore_bad_template all left it unchanged.
        With this option on, no placeholder is passed, since it would replace
        the template-level ignore_checks the operator let in. Each template is
        linted by a cfn-lint run of its own instead (``scan``), so its ignores
        reach only itself. That costs a cfn-lint start-up per template: measured
        with 1.57.2 on the 8 CloudFormation templates under tests/test_data,
        3.4 s in one run and 12.0 s in eight.
        """
        if not self._options().honor_inline_ignores:
            return False
        if set_by_operator(
            self.context.config if self.context is not None else None,
            "scanners.cfn-lint.options.honor_inline_ignores",
            True,
        ):
            return True
        if "honor_inline_ignores" not in self._refused_options:
            self._refused_options.add("honor_inline_ignores")
            self._plugin_log(
                refusal_warning(
                    "Ignoring scanners.cfn-lint.options.honor_inline_ignores: "
                    f"{NOT_THE_OPERATORS}. A template's own ignore_checks do not "
                    "apply; suppress findings with ASH suppressions.",
                    NOT_THE_OPERATORS,
                ),
                level=logging.WARNING,
            )
        return False

    def _config_file_settings(self, config_file: Path) -> Dict[str, Any]:
        """The operator's ``.cfnlintrc`` as a mapping; a file ASH cannot read stops the scan.

        Read so that its ``ignore_checks`` can be left out of ``--mandatory-checks``
        and its ``configure_rules`` passed on the command line. A file that cannot
        be opened, decoded or parsed raises ``ScannerError``: cfn-lint would read
        it whole, so handing it over unchecked would apply a ``merge_configs`` ASH
        could not see.

        It is read with ``load_config_yaml``, which refuses YAML aliases as every
        YAML config ASH reads does. cfn-lint reads aliases, so a file that uses
        one would still apply in full, ``merge_configs`` included, with ASH unable
        to check what it sets: such a file stops the scan instead.
        """
        # Imported here: config/ash_config.py imports this module.
        from automated_security_helper.config.ash_config import load_config_yaml

        try:
            parsed = load_config_yaml(Path(config_file).read_text(encoding="utf-8"))
        except yaml.composer.ComposerError as exc:
            line = exc.problem_mark.line + 1 if exc.problem_mark else "?"
            raise ScannerError(
                f"ASH could not read {Path(config_file).as_posix()}: {exc.problem} "
                f"(line {line}). ASH checks that file for merge_configs and passes "
                "its ignore_checks and configure_rules itself, and cfn-lint would "
                "read the rest of it, so cfn-lint is not run with a file ASH could "
                "not check."
            ) from exc
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            # Closed, not open: the file is still handed to cfn-lint whole, so a
            # merge_configs it sets would apply with ASH unable to check it, and
            # cfn-lint would read what ASH could not. UnicodeDecodeError is a
            # ValueError, not an OSError: a file that is not UTF-8 lands here too.
            raise ScannerError(
                f"ASH could not read {Path(config_file).as_posix()} "
                f"({type(exc).__name__}). ASH checks that file for merge_configs "
                "and passes its ignore_checks and configure_rules itself, and "
                "cfn-lint would read the rest of it, so cfn-lint is not run with a "
                "file ASH could not check."
            ) from exc
        return parsed if isinstance(parsed, dict) else {}

    def _configure_rule_args(
        self, configured: Any, config_file: Optional[Path]
    ) -> List[str]:
        """The ``--configure-rule`` values to pass while template config is off.

        The operator's own configure_rules, from the ``config_file`` they named,
        as ``RULE:key=value``, one per key. A command-line value replaces both
        the template's and the file's, so the file's must be passed here to apply
        at all. With none, ``_NO_OP_CONFIGURE_RULE`` keeps the template's out.

        An entry that ``--configure-rule`` cannot carry (``_command_line_value``),
        or whose rule id or key could be read as something else, is left out with
        a warning, once per scanner. Its rule then uses the default, which for
        every built-in rule reports at least as much as any setting.
        """
        entries: List[str] = []
        shown = Path(config_file).as_posix() if config_file is not None else ""

        def refuse(what: str, value: Any) -> None:
            if f"configure_rules {what}" in self._refused_options:
                return
            self._refused_options.add(f"configure_rules {what}")
            self._plugin_log(
                f"Not passing configure_rules {what} ({value!r}) from {shown}: "
                "cfn-lint's --configure-rule takes one value per key, without "
                "commas, colons or equals signs, under a rule id and key of "
                "letters, digits and underscores. The rule uses its default. To "
                "have cfn-lint read the file as written, set "
                "scanners.cfn-lint.options.honor_inline_ignores, which also lets "
                "templates configure their own rules.",
                level=logging.WARNING,
            )

        if configured is not None and not isinstance(configured, dict):
            refuse("as a whole", configured)
            configured = None
        for rule_id, keys in (configured or {}).items():
            if not isinstance(keys, dict):
                refuse(repr(rule_id), keys)
                continue
            for key, value in keys.items():
                text = _command_line_value(value)
                if (
                    isinstance(rule_id, str)
                    and _CHECK_PATTERN.match(rule_id)
                    and isinstance(key, str)
                    and _CONFIG_KEY_PATTERN.match(key)
                    and text is not None
                ):
                    entries.append(f"{rule_id}:{key}={text}")
                else:
                    refuse(f"{rule_id!r} {key!r}", value)
        return entries or [_NO_OP_CONFIGURE_RULE]

    def _config_file_ignores(
        self, settings: Dict[str, Any], config_file: Path
    ) -> List[str]:
        """The ``ignore_checks`` the operator's ``.cfnlintrc`` sets, if any.

        Read here so they can be left out of ``--mandatory-checks``. An entry that
        is not a rule id or prefix is left out with a warning, so it can never be
        read as an option, and that check then runs.
        """
        return self._config_file_checks(settings, "ignore_checks", config_file)

    def _config_file_checks(
        self, settings: Dict[str, Any], key: str, config_file: Path
    ) -> List[str]:
        """The rule ids or prefixes the operator's ``.cfnlintrc`` lists under ``key``.

        ``ignore_checks``, ``include_checks`` and ``mandatory_checks`` share one
        shape: a list, or a comma-separated string. An entry that is not a rule
        id or prefix is left out with a warning, so it can never be read as an
        option.
        """
        raw = settings.get(key)
        if isinstance(raw, str):
            raw = raw.split(",")
        checks: List[str] = []
        for item in raw if isinstance(raw, list) else []:
            if isinstance(item, str) and _CHECK_PATTERN.match(item):
                checks.append(item)
            else:
                self._plugin_log(
                    f"Ignoring {key} entry {item!r} in "
                    f"{Path(config_file).as_posix()}: not a cfn-lint rule id or "
                    "prefix (letters and digits).",
                    level=logging.WARNING,
                )
        return checks

    @staticmethod
    def _child_env() -> Dict[str, str]:
        """ASH's environment for cfn-lint, with its last-resort region pinned.

        cfn-lint takes its regions from ``--regions``, then from the template's
        ``Metadata: cfn-lint: config: regions``, then from the config file, and
        only then from ``AWS_REGION``, ``AWS_DEFAULT_REGION`` and finally
        us-east-1 (cfnlint/config.py, ``regions``, at 1.57.2). Inherited as is,
        that last step made a scan's findings depend on the host. Measured with
        1.57.2: ``AWS_REGION=``, which CI gets from an unset variable, makes
        cfn-lint exit 32 ("Regions [''] are unsupported") on every template, and
        ``AWS_REGION=af-south-1`` reports an ``AWS::Bedrock::Agent`` as E3006, a
        resource type that region lacks.

        Both variables are pinned rather than passing ``--regions us-east-1``,
        because ``--regions`` also overrides the regions a template declares in
        its own metadata and the ones an operator's config file names (measured:
        a template declaring af-south-1 lost its E3006 under ``--regions``).
        ASH's own environment is not changed. Under ``--sandbox`` the variables
        are not passed at all, which leaves cfn-lint at the same us-east-1.

        The copy is ``snapshot_environ``'s, taken under ``ENVIRON_LOCK``: other
        scanner threads change the environment while this one runs
        (utils/process_env.py).
        """
        return {
            **snapshot_environ(),
            "AWS_REGION": DEFAULT_REGION,
            "AWS_DEFAULT_REGION": DEFAULT_REGION,
        }

    def _operator_config_file(self, configured: Path | str) -> Optional[Path]:
        """The ``config_file`` to pass, or None when it must not be used.

        Raises:
            ScannerError: the operator named a path that is not a file: nothing
                there, or a directory.
        """
        chosen = operator_path(
            self.context.config if self.context is not None else None,
            "scanners.cfn-lint.options.config_file",
            configured,
            self._source_dir(),
        )
        if chosen.path is not None:
            if not chosen.path.is_file():
                # Say what was found: a directory at the path is not "missing".
                found = "is not a file" if chosen.path.exists() else "does not exist"
                raise ScannerError(
                    f"scanners.cfn-lint.options.config_file names {chosen.path}, "
                    f"which {found}"
                )
            return chosen.path
        reason = chosen.refusal
        # A .cfnlintrc can make cfn-lint import Python files (append_rules), so one
        # the scanned repository chose is never handed to it. Warned once per
        # scanner, as the other refused options are: this is read on every
        # invocation, and the line repeated per batch and per target.
        if "config_file" not in self._refused_options:
            self._refused_options.add("config_file")
            self._plugin_log(
                refusal_warning(
                    "Ignoring scanners.cfn-lint.options.config_file "
                    f"({str(configured)!r}): {reason}. A .cfnlintrc can load Python "
                    "rules, so cfn-lint runs with ASH's empty configuration instead.",
                    reason,
                ),
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

        Each path costs what it takes on the command line: its ``glob.escape``-d
        form (``_lint_once`` passes that) and a separator. A path holding
        ``[``, ``]``, ``*`` or ``?`` grows under the escape, so costing the raw
        path let a batch overrun the budget. A single path longer than the budget
        gets a batch of its own rather than being dropped.
        """
        out: List[List[str]] = []
        current: List[str] = []
        size = 0
        for path in paths:
            cost = len(glob.escape(path)) + 1
            if current and size + cost > budget:
                out.append(current)
                current, size = [], 0
            current.append(path)
            size += cost
        if current:
            out.append(current)
        return out

    def normalize_report(
        self, report: SarifReport, shown_by_argument: Optional[Dict[str, str]] = None
    ) -> SarifReport:
        """Locate results as ASH reports them, map severities, sort rules, in place.

        cfn-lint writes each URI as the template path it was given, which is
        absolute (see ``_private_cwd``); ``shown_by_argument`` maps each such
        path to the repository-relative one ASH reports, as cfn-guard's
        ``normalize_results`` replaces its URIs. cfn-lint also tags every
        location with ``uriBaseId: EXECUTIONROOT``, a base its own run declares
        with a description and no uri. ASH builds its own run and the merged
        SARIF never defines that base, so the reference is dropped: an ASH
        location without a base is relative to the source directory.

        cfn-lint lists driver rules in a different order from run to run (a set
        iteration), so they are sorted by id to keep reports reproducible.
        """
        shown_by_argument = shown_by_argument or {}
        for run in report.runs or []:
            for result in run.results or []:
                for location in [
                    *(result.locations or []),
                    *(result.relatedLocations or []),
                ]:
                    physical = location.physicalLocation
                    artifact = physical.root.artifactLocation if physical else None
                    if artifact is None:
                        continue
                    artifact.uriBaseId = None
                    if artifact.uri:
                        # As written first: a path that holds a backslash on
                        # POSIX is a name, and replacing it matched nothing. Then
                        # with Windows separators made ``/``, then percent-decoded,
                        # since cfn-lint writes a URI and a path holding a space
                        # or ``#`` came back encoded and matched nothing.
                        written = artifact.uri
                        slashed = written.replace("\\", "/")
                        shown = (
                            shown_by_argument.get(written)
                            or shown_by_argument.get(slashed)
                            or shown_by_argument.get(unquote(slashed))
                        )
                        artifact.uri = shown or written
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

    def _private_cwd(self, results_dir: Path) -> ContextManager[Path]:
        """A new, empty directory of this scan's own to run cfn-lint in.

        cfn-lint resolves every relative path in a config file (``append_rules``,
        ``custom_rules``, ``override_spec`` and the rest) against its working
        directory, not against the file (cfnlint/helpers.py ``load_plugins``
        walks the directory as written). Run in the source directory, an
        operator's ``.cfnlintrc`` outside the tree with ``append_rules: [rules]``
        imported the scanned tree's ``rules/*.py`` (measured with 1.57.2). Run
        from the filesystem root, ``append_rules: [tmp/x]`` read ``/tmp/x``,
        which any local user can write to. From a new empty directory outside
        the tree that only this user can enter, removed after the scan, a
        relative path names nothing (``private_cwd_outside_scanned_tree``), so
        templates, the output file and the config file are all passed as
        absolute paths. The ``.cfnlintrc`` lookup in the working directory is
        already off: ASH always names a config file.
        """
        return private_cwd_outside_scanned_tree(
            results_dir=results_dir,
            source_dir=self._source_dir(),
            config=getattr(self.context, "config", None),
        )

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
        # reset would report the previous target's counts. The exit code too:
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst code across subprocess calls,
        # so the converted target's invocation recorded the source's exit code.
        self.targets_attempted = 0
        self.targets_failed = 0
        # None, not 0: no cfn-lint has run for this target yet, and a target with
        # no template never starts one, so the executor read a 0 for a tool that
        # never ran. A run's code is folded in by _combined_exit_code below.
        self.exit_code = None
        # self.errors too, as cdk_nag_scanner resets it: the converted target's
        # invocation record carried the source target's error lines. The
        # unevaluated targets as cfn-nag clears them, for a caller that is not
        # the executor (which clears them before each scan).
        self._reset_errors()
        self.clear_unevaluated_targets()

        report = self._empty_report(target)
        try:
            empty = not target.exists() or not any(target.iterdir())
        except OSError as exc:
            # A target that exists but cannot be listed (its mode, a mount that
            # went away) raised out of scan() as a bare OSError the executor
            # reported with no scanner name; named here instead.
            raise ScannerError(
                f"cfn-lint cannot list the {target_type} target {target}: "
                f"{exc.strerror or exc}"
            ) from exc
        if empty:
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

        # Removes cfn-lint's working directory however the scan ends.
        cleanup = ExitStack()
        try:
            if self.context is None:
                raise ScannerError("cfn-lint has no plugin context")
            # Without the files the global ignore paths ignore, as cfn-nag reads them.
            discovery = discover_templates(
                self.context, target_type, global_ignore_paths
            )
            source_dir = self._source_dir()
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
                    f"cfn-lint did not evaluate {shown}: {reason}",
                    target_type=target_type,
                    level=logging.ERROR,
                )
            for path, reason in discovery.unmodelable:
                self.targets_attempted += 1
                self.targets_failed += 1
                shown = display_path(path, source_dir)
                # A target the tool never evaluated, recorded by name as the
                # unreadable ones are and as cfn-nag records it. The ERROR log
                # puts the line in self.errors (PluginBase._plugin_log); appended
                # here as well, every failure was recorded twice, and with the
                # host's absolute path where the other lines carry the shown one.
                self.record_unevaluated_target(shown)
                self._plugin_log(
                    f"cfn-lint did not evaluate {shown}: {reason}",
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

            if self.results_dir is None:
                raise ScannerError("cfn-lint has no results directory")
            results_dir = Path(os.path.abspath(self.results_dir.joinpath(target_type)))
            results_dir.mkdir(parents=True, exist_ok=True)
            # A previous run of this scanner into the same output directory left
            # its per-invocation files behind; with fewer batches this run, the
            # stale ones sat beside the new report as if they were its own.
            for stale in results_dir.glob("cfn-lint.*.sarif"):
                try:
                    stale.unlink()
                except OSError:
                    pass
            option_args = self._option_args()
            # Absolute, because cfn-lint does not run in the source directory (see
            # _private_cwd). Each maps back to the path ASH reports.
            shown_by_argument = {
                Path(template).absolute().as_posix(): display_path(template, source_dir)
                for template in discovery.templates
            }
            merged: List[Result] = []
            rules: Dict[str, ReportingDescriptor] = {}
            driver = report.runs[0].tool.driver
            child_env = self._child_env()
            cwd = cleanup.enter_context(self._private_cwd(results_dir))

            # _option_args keeps the options under _OPTION_CHAR_BUDGET. The fixed
            # arguments of every invocation (_lint_once) count too: the command,
            # the format, the output file at its longest name, and ``--``; left
            # out, a full batch overran the budget by their length.
            fixed = [
                _COMMAND,
                "--format",
                "sarif",
                f"--output-file={results_dir.joinpath('cfn-lint.999-999.sarif').as_posix()}",
                *option_args,
                "--",
            ]
            budget = _ARGV_CHAR_BUDGET - sum(len(arg) + 1 for arg in fixed)
            # With template ignores honored, each template runs alone, so its
            # ignores reach no other template (see _honor_inline_ignores).
            groups = (
                [[argument] for argument in shown_by_argument]
                if self._honor_inline_ignores()
                else self.batches(list(shown_by_argument), budget)
            )

            def fold(
                names: List[str], failure: Optional[str], found: Optional[SarifReport]
            ) -> None:
                """Record one invocation: its templates failed, or its results."""
                if failure is not None or found is None:
                    failure = failure or "cfn-lint output could not be read"
                    self.targets_failed += len(names)
                    # Each template is a target the tool never evaluated, recorded
                    # by name as the unreadable and unmodelable ones are, so the
                    # run's error record names every one. Then ONE line for the
                    # invocation: the ERROR log puts it in self.errors, so the
                    # separate append recorded each failure twice, once with the
                    # names and once with only their count; and a line naming
                    # every template of a 24,000-character batch was unreadable,
                    # so it names the first few and counts the rest.
                    for name in names:
                        self.record_unevaluated_target(name)
                    self._plugin_log(
                        f"cfn-lint did not evaluate {_named_templates(names)}: "
                        f"{failure}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    return
                for run in found.runs or []:
                    merged.extend(run.results or [])
                    run_driver = run.tool.driver if run.tool else None
                    if run_driver is not None:
                        if run_driver.version:
                            driver.version = run_driver.version
                        for rule in run_driver.rules or []:
                            rules.setdefault(rule.id or "", rule)

            timed_out = False
            # Every invocation's exit code, combined below (_combined_exit_code):
            # the base class keeps the largest, which loses the error bit.
            exit_codes: List[Any] = []
            for index, arguments in enumerate(groups):
                batch = [shown_by_argument[argument] for argument in arguments]
                self.targets_attempted += len(batch)
                if timed_out:
                    # An earlier invocation timed out, and the executor discards
                    # the whole scan after a recorded timeout, so starting the
                    # remaining batches, each with a fresh full scan_timeout,
                    # would only spend their time. Named, not started.
                    fold(batch, _NOT_STARTED_AFTER_TIMEOUT, None)
                    continue
                batch_file = results_dir.joinpath(f"cfn-lint.{index}.sarif")
                failure, batch_report, response = self._lint_once(
                    arguments, batch_file, option_args, results_dir, cwd, child_env
                )
                exit_codes.append(response.get("returncode"))
                timed_out = timed_out or bool(response.get("timed_out"))
                if (
                    failure is not None
                    and len(arguments) > 1
                    and _one_template_can_fail_the_run(response)
                ):
                    # cfn-lint exits for the whole invocation on one template's
                    # fault (a region its Metadata names that this cfn-lint does
                    # not know exits 32), so every other template in the batch
                    # read as not evaluated and its findings were discarded. The
                    # same exit also comes from a fault of the run, not of one
                    # template (an operator regions value this cfn-lint does not
                    # know, a configure_rules key it refuses, a broken install),
                    # and re-running every template alone would then repeat one
                    # failure once per template, each a cfn-lint start-up with a
                    # fresh scan_timeout. So the first template is re-run alone:
                    # when it fails exactly as the batch did, the failure names
                    # no template, and _RUN_WIDE_PROBE_MIN_REMAINING or more
                    # templates remain, one probe lint of _PROBE_TEMPLATE with
                    # the same options decides: failing alike, the failure is
                    # the run's and the remaining templates are recorded with
                    # it, not re-run; otherwise each is linted on its own and
                    # only the faulty ones fail. No template is ever recorded
                    # as failed without a run that fails it or a probe that
                    # shows the run itself fails.
                    self._plugin_log(
                        f"cfn-lint did not evaluate {len(batch)} template(s) in one "
                        f"invocation ({failure}); re-running the first on its own "
                        "to tell one template's fault from the run's.",
                        target_type=target_type,
                        level=logging.WARNING,
                    )
                    batch_failure = failure

                    # The batch index is bound as a default at definition time,
                    # not read from the loop variable when the closure runs
                    # (flake8-bugbear B023), so the closure carries its own batch.
                    def lint_alone(
                        position: int, argument: str, batch_index: int = index
                    ) -> Tuple[Optional[str], Optional[SarifReport], Dict[str, Any]]:
                        return self._lint_once(
                            [argument],
                            results_dir.joinpath(
                                f"cfn-lint.{batch_index}-{position}.sarif"
                            ),
                            option_args,
                            results_dir,
                            cwd,
                            child_env,
                        )

                    remaining = list(enumerate(arguments))
                    first_position, first_argument = remaining.pop(0)
                    failure, batch_report, response = lint_alone(
                        first_position, first_argument
                    )
                    exit_codes.append(response.get("returncode"))
                    timed_out = timed_out or bool(response.get("timed_out"))
                    fold([shown_by_argument[first_argument]], failure, batch_report)
                    if (
                        failure == batch_failure
                        and not timed_out
                        and len(remaining) >= _RUN_WIDE_PROBE_MIN_REMAINING
                        and not _names_a_template(
                            batch_failure,
                            [*arguments, *(shown_by_argument[a] for a in arguments)],
                        )
                    ):
                        probe_failure, response = self._probe_run_wide_failure(
                            index, option_args, results_dir, cwd, child_env
                        )
                        exit_codes.append(response.get("returncode"))
                        timed_out = timed_out or bool(response.get("timed_out"))
                        if probe_failure == batch_failure:
                            fold(
                                [shown_by_argument[a] for _, a in remaining],
                                f"{batch_failure} (read as a failure of the run, "
                                "not of one template: a probe template with no "
                                "Metadata failed alike under the same options, "
                                f"so the {len(remaining)} remaining were not "
                                "re-run)",
                                None,
                            )
                            continue
                    for position, argument in remaining:
                        if timed_out:
                            fold(
                                [shown_by_argument[argument]],
                                _NOT_STARTED_AFTER_TIMEOUT,
                                None,
                            )
                            continue
                        failure, batch_report, response = lint_alone(position, argument)
                        exit_codes.append(response.get("returncode"))
                        timed_out = timed_out or bool(response.get("timed_out"))
                        fold([shown_by_argument[argument]], failure, batch_report)
                    continue
                fold(batch, failure, batch_report)

            report.runs[0].results = merged
            driver.rules = list(rules.values()) or None
            self.normalize_report(report, shown_by_argument)
            if exit_codes:
                self.exit_code = _combined_exit_code(exit_codes)
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
        finally:
            cleanup.close()

    def _lint_once(
        self,
        arguments: List[str],
        batch_file: Path,
        option_args: List[str],
        results_dir: Path,
        cwd: Path,
        child_env: Dict[str, str],
    ) -> Tuple[Optional[str], Optional[SarifReport], Dict[str, Any]]:
        """One cfn-lint invocation over ``arguments``, written to ``batch_file``.

        Returns the failure reason or None, the parsed report or None, and the
        subprocess response (``{}`` when the runner returned none).
        """
        command = [
            _COMMAND,
            "--format",
            "sarif",
            f"--output-file={batch_file.as_posix()}",
            *option_args,
            "--",
            *[glob.escape(argument) for argument in arguments],
        ]
        response = self._run_subprocess(
            command=command,
            results_dir=results_dir,
            stdout_preference="write",
            stderr_preference="both",
            cwd=cwd,
            env=child_env,
            timeout=self._effective_scan_timeout(),
        )
        failure = self._batch_failure(response, batch_file, values=guarded_values(self))
        batch_report = None
        if failure is None:
            try:
                batch_report = SarifReport.model_validate(
                    json.loads(batch_file.read_text(encoding="utf-8"))
                )
            except Exception as exc:  # unreadable output is a failed batch
                failure = f"cfn-lint output was not valid SARIF ({exc})"
            else:
                # Read into the merged report, so the file has served its purpose;
                # kept, it sat beside cfn-lint.sarif as a second copy of the
                # findings, and a later run with fewer batches left stale ones.
                # One that could not be read stays for a look.
                try:
                    batch_file.unlink()
                except OSError:
                    pass
        if failure is None and batch_report is not None:
            config_errors = [
                r
                for run in batch_report.runs or []
                for r in run.results or []
                if r.ruleId == _CONFIG_ERROR_RULE
            ]
            if config_errors:
                texts = "; ".join((r.message.root.text or "") for r in config_errors)
                failure = f"cfn-lint reported a configuration error: {texts}"
        return failure, batch_report, response if isinstance(response, dict) else {}

    def _probe_run_wide_failure(
        self,
        index: int,
        option_args: List[str],
        results_dir: Path,
        cwd: Path,
        child_env: Dict[str, str],
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Lint ``_PROBE_TEMPLATE`` once with the batch's options.

        Returns the probe's failure reason (None when it linted) and the subprocess
        response, so a timeout of the probe counts as the scan's. The probe is
        written beside the batch's SARIF files, never into the scanned tree, and
        its results are not merged: it is a question about the run, not a target.
        """
        probe = results_dir.joinpath(f"cfn-lint.{index}.probe.yaml")
        with open_for_write(probe) as handle:
            handle.write(_PROBE_TEMPLATE)
        failure, _report, response = self._lint_once(
            [probe.as_posix()],
            results_dir.joinpath(f"cfn-lint.{index}.probe.sarif"),
            option_args,
            results_dir,
            cwd,
            child_env,
        )
        return failure, response

    @staticmethod
    def _batch_failure(
        response: object,
        batch_file: Path,
        *,
        values: Optional[Iterable[str]],
    ) -> Optional[str]:
        """Why one cfn-lint invocation produced nothing usable, or None if it did.

        ``values`` are the scanner's redaction values (``guarded_values(self)`` at
        the call site): the tool's stderr is redacted with them before it is cut
        for the message, and ``None`` (the values could not be read) shows a note in
        place of the stderr rather than the text unredacted. Required, with no
        default: a default of "redact nothing" let a caller that forgot it print
        the stderr unredacted, the gap the parameter closes.
        """
        if not isinstance(response, dict):
            return "cfn-lint did not run"
        failure = _invocation_failure(response)
        if failure is not None:
            return failure
        code = response.get("returncode")
        if not _successful_exit(code):
            stderr = _stderr_for_message(response, values)
            return f"cfn-lint exited {code}" + (f": {stderr}" if stderr else "")
        if not batch_file.is_file() or batch_file.stat().st_size == 0:
            return f"cfn-lint exited {code} without writing {batch_file.name}"
        return None
