# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import uuid
from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from automated_security_helper.base.forward_refs import OnceOnlyResolver
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import ExportFormat, ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.core import IgnoreFileExclusions
from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    assign_identity_ids,
)
from automated_security_helper.models.workspace import WorkspaceResults
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from typing import (
    TYPE_CHECKING,
    Annotated,
    Dict,
    Any,
    Iterator,
    Literal,
    Optional,
    Union,
    List,
)
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.undecodable_text import (
    RecordModel,
    StrippedRecordModel,
    names_as_recorded,
    recorded,
    undecodables_of_texts,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.secret_masking import (
    SecretValueShape,
    mask_secrets_in_results,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

__all__ = ["AshAggregatedResults"]


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_VALID_INCREMENT_FIELDS = _SEVERITY_ORDER + ("suppressed",)
_SUMMARY_SEVERITY_FIELDS = frozenset(
    ("critical", "high", "medium", "low", "info", "suppressed")
)


class ScannerSeverityCount(StrippedRecordModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )
    suppressed: int = (
        0  # Suppressed findings take precedence over other severity levels
    )
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        """Sum of all non-suppressed severity counts."""
        return self.critical + self.high + self.medium + self.low + self.info

    def actionable_count(self, threshold: str) -> int:
        """Count findings at or above the given severity threshold.

        threshold is case-insensitive. Valid values: critical, high, medium, low,
        info, and all, the configuration's "ALL" threshold, which counts every
        severity.
        """
        if not isinstance(threshold, str):
            raise ValueError(f"Invalid severity threshold: {threshold!r}")
        key = threshold.lower()
        if key == "all":
            key = _SEVERITY_ORDER[-1]
        if key not in _SEVERITY_ORDER:
            raise ValueError(f"Invalid severity threshold: {threshold!r}")
        idx = _SEVERITY_ORDER.index(key)
        return sum(getattr(self, name) for name in _SEVERITY_ORDER[: idx + 1])

    def increment(self, severity: str) -> None:
        """Increment the named severity field by 1.

        severity is case-insensitive. Valid values: critical, high, medium, low, info, suppressed.
        """
        if not isinstance(severity, str):
            raise ValueError(f"Invalid severity: {severity!r}")
        key = severity.lower()
        if key not in _VALID_INCREMENT_FIELDS:
            raise ValueError(f"Invalid severity: {severity!r}")
        setattr(self, key, getattr(self, key) + 1)

    def max_severity(self) -> str:
        """Return the name of the highest non-zero severity, or "none" if all zero.

        suppressed is not considered.
        """
        for name in _SEVERITY_ORDER:
            if getattr(self, name) > 0:
                return name
        return "none"


class SummaryStats(StrippedRecordModel):
    """Summary statistics for the final report.

    Composes a ScannerSeverityCount for per-severity tallies. Flat severity
    kwargs (e.g. critical=2) are accepted for backward compatibility and routed
    into severity_counts. Forwarding properties expose severity fields at the
    top level so all existing call sites continue to work unchanged.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )

    severity_counts: ScannerSeverityCount = Field(default_factory=ScannerSeverityCount)

    start: str | datetime | None = None
    end: str | datetime | None = None
    duration: float = 0.0
    total: int = 0
    actionable: int = 0

    # Scanner-outcome counters. Every scanner lands in exactly one of these, so
    # passed + failed + missing + skipped + error is the number of scanners in the
    # run and a consumer can tell a complete scan from a partial one by arithmetic.
    #
    # `error` is here because it was the one status with no counter. A scanner that
    # ran and failed outright appeared in none of the other four, so on a run with
    # two ERROR scanners the counters summed to 8 of 10 and every one of them read
    # clean. Anything deriving a verdict from these -- a dashboard, a CI gate, a
    # reviewer skimming ash.flat.json -- was reading a total that silently excluded
    # the scanners with the worst outcome. The exit code does not read these fields
    # (it reads per-scanner status through incomplete_scanners), which is why the
    # gap survived: nothing that failed loudly depended on it.
    passed: int = 0
    failed: int = 0
    missing: int = 0
    skipped: int = 0
    error: int = 0

    @model_validator(mode="before")
    @classmethod
    def _coerce_flat_severity_kwargs(cls, data: Any) -> Any:
        """Accept flat severity kwargs and route them into severity_counts."""
        if not isinstance(data, dict):
            return data
        flat = {k: v for k, v in data.items() if k in _SUMMARY_SEVERITY_FIELDS}
        if not flat:
            return data
        # Routed into a copy: the caller's dict, and the severity_counts it holds,
        # stay as they were given.
        routed = {k: v for k, v in data.items() if k not in _SUMMARY_SEVERITY_FIELDS}
        existing = routed.get("severity_counts")
        if existing is None:
            routed["severity_counts"] = flat
        elif isinstance(existing, dict):
            routed["severity_counts"] = {**existing, **flat}
        elif isinstance(existing, ScannerSeverityCount):
            routed["severity_counts"] = {**existing.model_dump(), **flat}
        # Any other severity_counts is left as given for the field's own
        # validation to refuse.
        return routed

    @model_validator(mode="after")
    def _derive_total_from_severity_counts(self) -> "SummaryStats":
        """When total was not explicitly provided, compute it from severity_counts."""
        if "total" not in self.model_fields_set:
            computed = self.severity_counts.total
            if computed != 0:
                self.total = computed
        return self

    @property
    def critical(self) -> int:
        return self.severity_counts.critical

    @critical.setter
    def critical(self, value: int) -> None:
        self.severity_counts.critical = value

    @property
    def high(self) -> int:
        return self.severity_counts.high

    @high.setter
    def high(self, value: int) -> None:
        self.severity_counts.high = value

    @property
    def medium(self) -> int:
        return self.severity_counts.medium

    @medium.setter
    def medium(self, value: int) -> None:
        self.severity_counts.medium = value

    @property
    def low(self) -> int:
        return self.severity_counts.low

    @low.setter
    def low(self, value: int) -> None:
        self.severity_counts.low = value

    @property
    def info(self) -> int:
        return self.severity_counts.info

    @info.setter
    def info(self, value: int) -> None:
        self.severity_counts.info = value

    @property
    def suppressed(self) -> int:
        return self.severity_counts.suppressed

    @suppressed.setter
    def suppressed(self, value: int) -> None:
        self.severity_counts.suppressed = value

    def bump(self, key: str, amount: int = 1) -> int:
        setattr(self, key, getattr(self, key) + amount)
        return getattr(self, key)

    def set_timing(
        self,
        start: str | datetime | None,
        end: str | datetime | None,
        duration: float,
    ) -> None:
        """Set start, end, and duration in a single call."""
        self.start = start
        self.end = end
        self.duration = duration


class ScannerTargetStatusInfo(StrippedRecordModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )

    status: ScannerStatus = ScannerStatus.PASSED
    dependencies_satisfied: Annotated[
        bool,
        Field(
            description=(
                "False on a MISSING row: the scanner's tool or another dependency "
                "was not available. True on every other row, including a SKIPPED "
                "one, which did not need its tool, and a MISSING row for a scanner "
                "whose filtering raised before any dependency was checked (its "
                "missing_reason says so)."
            ),
        ),
    ] = True
    excluded: Annotated[
        bool,
        Field(
            description=(
                "True when the run left the scanner out: --exclude-scanners or the "
                "shard split, --scanners, the configuration's enabled flag, "
                "--python-only, or a platform the scanner does not support."
            ),
        ),
    ] = False
    severity_counts: ScannerSeverityCount = ScannerSeverityCount()
    finding_count: int | None = 0
    actionable_finding_count: int | None = 0
    suppressed_finding_count: int | None = 0
    exit_code: Annotated[
        int | None,
        Field(
            description=(
                "The exit code of the scanner's tool, the highest over the targets "
                "it ran on. None when no tool ran (a MISSING or excluded row, a "
                "scanner that had nothing to scan or started no tool for its "
                "targets, or one that could not be built) or when no target recorded "
                "one."
            ),
        ),
    ] = 0
    duration: float | None = 0.0
    # The two reasons are set by core.unified_metrics when it rebuilds the row, from
    # what the scan phase and the executor recorded, so a SKIPPED or MISSING row
    # always says why and every other row carries None.
    missing_reason: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Why the scanner is MISSING: its tool was not found (or was found "
                "only inside the scanned tree, which ASH does not run tools from "
                "by default), a dependency check failed with the reason the scanner "
                "gave, or the scanner could not be sandboxed. Set on every MISSING "
                "row and None on every other."
            ),
        ),
    ] = None
    skipped_reason: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Why the scanner is SKIPPED: excluded with --exclude-scanners (the "
                "excluded_scanners parameter over MCP) or by the shard split, not "
                "named by --scanners (the scanners parameter over MCP), disabled in the "
                "configuration, left out by --python-only, not supported on this "
                "platform, or nothing to scan in the project (no CloudFormation "
                "template for cdk-nag and cfn-nag, no lockfile for npm-audit), "
                "whether or not its tool is installed. Set on every SKIPPED row and "
                "None on every other."
            ),
        ),
    ] = None

    @property
    def total_duration(self) -> float:
        """Alias for duration; returns 0.0 when duration is None."""
        return self.duration or 0.0


class ScannerStatusInfo(StrippedRecordModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )

    severity_threshold: str | None = None
    status: ScannerStatus | None = None
    dependencies_satisfied: bool = True
    excluded: bool = False

    source: ScannerTargetStatusInfo = ScannerTargetStatusInfo()
    converted: ScannerTargetStatusInfo = ScannerTargetStatusInfo()

    @property
    def is_dual_layer(self) -> bool:
        """True when both source and converted targets show non-default state.

        A target is "non-default" if its status is not PASSED, or if any of its
        severity counts (including suppressed) are non-zero.
        """

        def _non_default(t: ScannerTargetStatusInfo) -> bool:
            if t.status != ScannerStatus.PASSED:
                return True
            sc = t.severity_counts
            return (
                sc.critical + sc.high + sc.medium + sc.low + sc.info + sc.suppressed
            ) > 0

        return _non_default(self.source) and _non_default(self.converted)


class InputNotScanned(RecordModel):
    """One input that was found and not scanned, and why.

    A scanner records its own in its report (``ScanResultsContainer.
    inputs_not_scanned``); ASH records the ones it left out of the scan set, which
    every reader of the scan set therefore did not scan, in
    ``ReportMetadata.inputs_not_scanned``.
    """

    # Read from a scanner's report or a results file, whose values an error does
    # not quote.
    model_config = ConfigDict(hide_input_in_errors=True)

    path: Annotated[
        str,
        Field(
            description=(
                "The input's path relative to the scanned tree, with '/' separators."
            )
        ),
    ]
    reason: Annotated[str, Field(description="Why it was not scanned.")]


#: The validation-context key under which the records that keep only their own keys
#: (RefusedInputInfo, FailedInputInfo) count the keys they drop, for the one warning
#: ``warning_of_dropped_keys`` logs per results file.
_DROPPED_RECORD_KEYS = "dropped_record_keys"


def _count_dropped_record_keys(
    model: type[BaseModel], data: Any, info: ValidationInfo
) -> None:
    """Add the keys *data* holds that *model* does not define to the count the
    validation context carries, when the read asked for one."""
    context = info.context
    if (
        isinstance(data, dict)
        and isinstance(context, dict)
        and _DROPPED_RECORD_KEYS in context
    ):
        context[_DROPPED_RECORD_KEYS] += sum(
            1 for key in data if key not in model.model_fields
        )


class RefusedInputInfo(StrippedRecordModel):
    """One input a converter declined to read, and why."""

    # Only these fields are kept. A results file ASH reads back can hold any other
    # key in a record, and every record and report written from it carried that
    # key; no ASH writer sets one. Such a key is dropped, not refused, so a record
    # an earlier ASH wrote still loads.
    # No whitespace is stripped: the path, member and reason are the names and
    # words of the tree, kept as the converter gave them.
    # Read from a results file, whose values an error does not quote.
    model_config = ConfigDict(extra="ignore", hide_input_in_errors=True)

    @model_validator(mode="before")
    @classmethod
    def _count_the_keys_it_drops(cls, data: Any, info: ValidationInfo) -> Any:
        _count_dropped_record_keys(cls, data, info)
        return data

    path: Annotated[
        str,
        Field(
            description=(
                "The input's path relative to the scanned tree, with '/' separators. "
                "For an archive member, the archive's path."
            )
        ),
    ]
    member: Annotated[
        str | None,
        Field(
            default=None,
            description="The archive member's name, when the refusal was of a member.",
        ),
    ] = None
    reason: Annotated[str, Field(description="Why the input was not read.")]
    # Left out of a dump when None, so every other refusal's record reads as it did
    # before the field existed.
    limit: Annotated[
        str | None,
        Field(
            default=None,
            exclude_if=lambda value: value is None,
            description=(
                "The extraction-limit option the input exceeded, such as "
                "max_total_bytes, when that is why it was refused. None for every "
                "other refusal. A refusal with a limit leaves the whole input "
                "unscanned, so the completeness gate counts it as incomplete "
                "conversion."
            ),
        ),
    ] = None
    unlisted_members: Annotated[
        int | None,
        Field(
            default=None,
            exclude_if=lambda value: value is None,
            description=(
                "Set on a record that stands for several members: how many more "
                "members of the archive were refused for the same reason without "
                "a record of their own. An archive lists the first 20 refusals of "
                "each reason one by one and counts the rest here."
            ),
        ),
    ] = None


def known_failed_input_kind(value: Any) -> str:
    """*value* read as a failed-input record's kind: itself when it is "input" or
    "tool", and "tool" for anything else.

    The one reading of the kind. FailedInputInfo's validator applies it to every
    record built through the model; a reader of a record that skipped validation
    (one built with model_construct, a kind assigned after the record was made, a
    row ``ash merge`` assembled) applies it itself. "tool" is the fail-closed
    reading: a tool failure is never accepted, so an unknown kind can never waive
    the completeness gate.
    """
    return value if value in ("input", "tool") else "tool"


class FailedInputInfo(StrippedRecordModel):
    """One input a converter set out to convert and could not."""

    # Only these fields are kept, as for RefusedInputInfo: a results file ASH reads
    # back can hold any other key in a record, and no ASH writer sets one. Values
    # come from a results file, so an error does not quote them. Whitespace is
    # kept, as there.
    model_config = ConfigDict(extra="ignore", hide_input_in_errors=True)

    @model_validator(mode="before")
    @classmethod
    def _count_the_keys_it_drops(cls, data: Any, info: ValidationInfo) -> Any:
        _count_dropped_record_keys(cls, data, info)
        return data

    path: Annotated[
        str,
        Field(
            description=(
                "The input's path relative to the scanned tree, with '/' separators."
            )
        ),
    ]
    reason: Annotated[str, Field(description="Why it was not converted.")]
    kind: Annotated[
        Literal["input", "tool"],
        Field(
            description=(
                "What failed: 'input' when the file is not one the converter "
                "could hand to its tool (for the jupyter converter, not a "
                "notebook), 'tool' when the tool could not convert it. The "
                "completeness gate's trust in 'accepted' rides on the kind, "
                "so any other value is read as 'tool', which is never "
                "accepted, rather than as 'input' or as a refusal to load "
                "the record."
            ),
        ),
    ] = "tool"

    @field_validator("kind", mode="before")
    @classmethod
    def _an_unknown_kind_reads_as_tool(cls, value: Any) -> Any:
        """A kind this version does not know is read as "tool".

        Recording a failure must not itself fail (a converter plugin outside
        this repository can pass its own kind, after the failure was already
        logged), and a results file ASH reads back can carry a record it did
        not write; refusing the value would turn one unknown record into a
        failed load of the whole results. The reading is
        known_failed_input_kind's.
        """
        return known_failed_input_kind(value)

    accepted: Annotated[
        bool,
        Field(
            description=(
                "True when a suppression with rule_id 'ash-unconverted-input' "
                "accepts this input error, so it does not count against the "
                "completeness gate. The record stays, with the suppression's "
                "reason. A tool failure is never accepted."
            ),
        ),
    ] = False
    accepted_reason: Annotated[
        str | None,
        Field(description="The accepting suppression's reason."),
    ] = None
    accepted_by: Annotated[
        str | None,
        Field(
            description=(
                "The written-form id of the suppression that accepted this "
                "input error, recorded when the acceptance was granted. The "
                "convert phase registers exactly this id in "
                "used_suppressions, so no other entry that happens to match "
                "the path reads used. None when the id write failed, for a "
                "record a third-party converter built, and in a results file "
                "written before the field existed; the phase re-derives those "
                "records' entries from their paths instead."
            ),
        ),
    ] = None


def waives_gate(record: Any) -> bool:
    """Whether a failed-input record does not count against the completeness gate.

    The one trust rule, read by the gate (``incomplete_converters``) and the
    convert phase's reporting alike: accepted, and of kind "input". Only the
    writer promises a tool failure is never accepted, and a shard file can come
    from any producer, so an accepted record of any other kind still counts.
    Read with ``getattr`` because a shard row assembled by ``ash merge`` can
    carry records that never passed this model's validation.
    """
    return bool(getattr(record, "accepted", False)) and (
        getattr(record, "kind", None) == "input"
    )


class ConverterStatusInfo(StrippedRecordModel):
    """Information about converter status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )

    dependencies_satisfied: bool = True
    excluded: bool = False

    # Declared for the same reason as the fields below, and the converter's
    # counterpart of a MISSING scanner's missing_reason: without it the reason was
    # in the console's warning and ash.log only, where a merge of shards or an MCP
    # client reading the results never sees it.
    dependency_unavailable_reason: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Why the converter's dependencies were unavailable: the reason its "
                "dependency check recorded, with the home directory written as ~, "
                "or a message naming the converter when the check recorded none or "
                "raised. Set on every row whose dependencies_satisfied is False and "
                "None on every other."
            ),
        ),
    ] = None

    # Declared rather than left to ride on extra="allow", so model_json_schema()
    # carries it and the committed AshAggregatedResults.json documents the shape a
    # consumer reads.
    #
    # Without it, three outcomes shared one representation -- an empty
    # converted_paths. A converter that raised, one that was turned off, and one
    # that legitimately found nothing all produced the same row, and the convert
    # phase emitted the same "No files were converted" warning for all three.
    failure: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Why this converter produced nothing, when the reason was that "
                "something went wrong. For an exception out of convert() this is "
                "'<type>: <message>'. None when nothing went wrong, which "
                "includes a converter that ran and found nothing to convert. "
                "Distinct from excluded, which means the run never intended to "
                "use it, and from dependencies_satisfied, which reports an "
                "absent external tool."
            ),
        ),
    ] = None

    # Declared for the same reason failure is: a consumer reads the committed schema,
    # and this field is what makes an unavailable converter's row interpretable.
    #
    # The number of files the converter WOULD have converted, established without its
    # tool. None means the converter does not report one, and the completeness gate
    # treats None exactly as strictly as it treated every row before this field existed
    # -- an unavailable converter with no count is still incomplete conversion. 0 is the
    # only value that exempts a row, and it is a positive claim that there was nothing
    # to convert rather than an absence of information.
    #
    # Separate from converted_paths, which cannot answer this. An empty converted_paths
    # is produced both by "no notebooks here" and by "notebooks here, tool missing", and
    # collapsing those is what made every nix-mode run report lost conversion coverage on
    # trees containing no notebooks.
    candidate_inputs: Annotated[
        int | None,
        Field(
            default=None,
            description=(
                "How many files this converter would have converted, counted without "
                "its external tool. 0 means there was nothing for it to do, so its "
                "absence cost no coverage. None means the converter does not report a "
                "count, which the completeness gate treats as strictly as it treats a "
                "converter that lost inputs."
            ),
        ),
    ] = None

    # Declared for the same reason as the two fields above. A converter input that ASH
    # declined to read used to have no representation at all, so a skipped notebook
    # left the same row as one that was never there. ConvertPhase leaves it unset when
    # nothing was refused: a full dump then carries an empty list, and an
    # ``exclude_unset`` dump (``to_simple_dict``) carries nothing, as before.
    refused_inputs: List[RefusedInputInfo] = Field(
        default_factory=list,
        description=(
            "Inputs this converter did not read because they failed the "
            "scanned-tree check: a symlink, a path outside the scanned tree, a "
            "file that is not a regular file or has more than one hard link, or "
            "an archive member that is a link, would be extracted outside its "
            "destination, or is itself an archive. An archive over an extraction "
            "limit is recorded here too, with the limit named in limit, and so is a "
            "Git LFS pointer named like an archive. An archive that could not be "
            "read is in failed_inputs instead."
        ),
    )

    # A converter that raised has failure; one that could not convert some of its
    # inputs carries on, and the completeness gate reads this, so a notebook
    # nbconvert could not convert is lost coverage in the exit code as well as in
    # the log. Omitted from the row when empty, as refused_inputs is.
    failed_inputs: List[FailedInputInfo] = Field(
        default_factory=list,
        description=(
            "Inputs this converter tried to convert and could not, so the scanners "
            "never saw what conversion would have produced from them. The "
            "completeness gate counts a converter with any such record as "
            "incomplete, except records a suppression accepted (kind 'input' "
            "with accepted true), which stay here for the reader."
        ),
    )

    converted_paths: List[str] = []


def _unreadable_expirations(stored: Any) -> List[str]:
    """Where a stored config holds an expiration that is not a YYYY-MM-DD date.

    The config is validated again without the tolerance, and each such date is
    one of its errors, located by pydantic: ``global_settings.ignore_paths[0]
    .expiration``. A mapping key that is not a name of the config schema is
    shown as ``<key>``, since it is the file's data too. Called only when the
    tolerant validation kept such a date.

    A date is told by where and how it failed, a ``value_error`` at an
    ``expiration``, never by the refusal's words, which are the date check's
    own (models/core.expiration_date_problem) and change with it. A count that
    still disagrees falls back to unlocated warnings (validate_ash_config).
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.config_validator import (
        _schema_names,
        location_text,
    )

    try:
        AshConfig.model_validate(stored)
    except ValidationError as error:
        names = _schema_names()
        return [
            location_text(item["loc"], names)
            for item in error.errors(include_url=False)
            if item.get("loc")
            and item["loc"][-1] == "expiration"
            and item.get("type") == "value_error"
        ]
    return []


def _kept_unknown_keys(config: BaseModel) -> List[str]:
    """Where a tolerantly loaded config kept a key its model does not declare.

    One location per kept key, of the entry or options section that holds it
    (``global_settings.suppressions[0]``, ``scanners.bandit.options``): the
    models that refuse unknown keys keep them as extras under the tolerance.
    The generic options bases record nothing there (base/options.py), so their
    extras are not counted either. Names that are not in the config schema
    are shown as ``<key>``.
    """
    from automated_security_helper.base.options import (
        _GENERIC_OPTION_BASES,
        PluginOptionsBase,
    )
    from automated_security_helper.config.config_validator import (
        _schema_names,
        location_text,
    )
    from automated_security_helper.models.core import IgnorePathWithReason

    names = _schema_names()
    found: List[str] = []

    def walk(node: Any, loc: tuple) -> None:
        if isinstance(node, BaseModel):
            extra = node.model_extra or {}
            # The bases exactly, as base/options.py tests them: every plugin's
            # own options model subclasses one.
            refuses = (
                isinstance(node, (IgnorePathWithReason, PluginOptionsBase))
                and type(node) not in _GENERIC_OPTION_BASES
            )
            if refuses and extra:
                found.extend([location_text(loc, names)] * len(extra))
            for name, field in type(node).model_fields.items():
                walk(getattr(node, name, None), loc + (field.alias or name,))
            for key, value in extra.items():
                walk(value, loc + (key,))
        elif isinstance(node, (list, tuple)):
            for index, item in enumerate(node):
                walk(item, loc + (index,))
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(value, loc + (key,))

    walk(config, ())
    return found


_ISO_FRACTION = re.compile(r"\.(\d+)")


def _instant_of(text: str) -> datetime:
    """*text*, an ISO 8601 date and time, as a datetime on every supported Python.

    ``datetime.fromisoformat`` before 3.11 refuses a trailing ``Z`` and a
    fraction of seconds that is not 3 or 6 digits; 3.11 and later take both.
    The two are written the way 3.10 takes them first, so a results file reads
    the same on each. Raises ValueError for text that is not a date and time.
    """
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = _ISO_FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, 1)
    return datetime.fromisoformat(text)


def new_report_id(
    now: Optional[datetime] = None,
    token: Optional[str] = None,
    prefix: str = "ASH",
) -> str:
    """A report id for one scan: ``<prefix>-<UTC YYYYMMDDHHMMSS>-<12 hex digits>``.

    The time comes first, so ids sort by when the scan started and begin with
    the ``ASH-YYYYMMDD`` a reader may match on; the random ``token`` separates
    scans started in the same second, including the
    shards of one sharded scan, which run at the same time on different hosts.

    Args:
        now: The scan's start. Defaults to the current UTC time.
        token: Twelve lowercase hex digits. Defaults to the last twelve of a fresh
            ``uuid4``, which are all random bits. ``ash merge`` passes a digest of
            the shard ids instead, so the union's id is reproducible.
        prefix: ``ASH`` for a scan; the workspace aggregate adds its own marker.
    """
    instant = now if now is not None else datetime.now(timezone.utc)
    if instant.tzinfo is not None:
        instant = instant.astimezone(timezone.utc)
    if token is None:
        token = uuid.uuid4().hex[-12:]
    return f"{prefix}-{instant.strftime('%Y%m%d%H%M%S')}-{token}"


class ReportMetadata(StrippedRecordModel):
    """Metadata for security reports."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
            ExportFormat: lambda v: str(v),
        },
        # Read from a results file, whose values an error does not quote.
        hide_input_in_errors=True,
    )

    report_id: Annotated[
        str | None,
        Field(
            min_length=1,
            pattern=r"^[A-Za-z][\/\.\w-]+$",
            description="Unique identifier for the report",
        ),
    ] = None
    generated_at: Annotated[str | None, Field()] = None
    project_name: Annotated[
        str | None, Field(min_length=1, description="Name of the project being scanned")
    ] = None
    tool_version: Annotated[
        str | None, Field(min_length=1, description="Version of the security tool")
    ] = None
    description: Annotated[
        str | None, Field(min_length=1, description="Description of the tool/scan")
    ] = None
    summary_stats: Annotated[
        SummaryStats,
        Field(description="Summary statistics (e.g., count by severity)"),
    ] = SummaryStats()
    validation_summary: Annotated[
        Dict[str, Any],
        Field(
            default_factory=dict,
            description="Summary of ASH component validation results for the report",
        ),
    ]
    execution_discrepancy_report: Annotated[
        Dict[str, Any],
        Field(default_factory=dict, description="Discrepancy report for ASH execution"),
    ]
    # Declared, rather than left to ride on this model's extra="allow". Three
    # things follow from declaring it that an extra key does not give:
    # model_json_schema() carries it, so the committed AshAggregatedResults.json
    # documents the shape `ash merge` reads; a malformed shard block is refused at
    # model_validate_json time instead of surfacing as an AttributeError inside
    # merge; and it round-trips as a ShardAssignment rather than as a bare dict,
    # so verify_shard_coverage can be handed it directly.
    shard: Annotated[
        ShardAssignment | None,
        Field(
            default=None,
            description=(
                "Which shard of a split scan produced these results, and which "
                "scanners it was responsible for. Absent when the scan was not "
                "sharded, which is how a whole-repository scan is told apart from "
                "one shard of several."
            ),
        ),
    ] = None

    # The completeness denominator, recorded so it is not re-derived from the
    # numerator.
    #
    # `expected_scanners` used to have no existence outside the scan phase, where it
    # was derived from `self._scanner_tasks` -- built from the resolved plugin set,
    # which is also where the completed set comes from. Both sides of the comparison
    # came from one resolve, so a scanner that never joined that resolve was absent
    # from both and produced no discrepancy: the five status counters summed
    # correctly over the scanners that remained and `_validate_result_completeness`
    # reported 100% for a run that had lost scanners.
    #
    # Declared rather than left to this model's extra="allow", for the reasons the
    # `shard` field above states: model_json_schema() carries it so the committed
    # AshAggregatedResults.json documents what
    # .github/scripts/assert_scanners_completed.py reads, and a malformed block is
    # refused at validate time instead of surfacing as a TypeError inside the gate.
    expected_scanners: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "Scanner names this run was supposed to account for, taken from the "
                "configuration's declared scanner roster rather than from the "
                "plugins that resolved. A name here with no scanner_results entry is "
                "a scanner that never joined the run. Empty when the run did not "
                "resolve ASH's built-in plugin set -- a caller supplying its own "
                "plugin classes is not measured against the built-in roster."
            ),
        ),
    ]
    plugin_load_errors: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Plugin modules that failed to import during this run, mapped to the "
                "error text. Non-empty means the run is missing plugins it ships "
                "with, whatever the per-scanner statuses say."
            ),
        ),
    ]
    # Declared for the reasons the `shard` field above states. The scan set decides
    # what detect-secrets, cfn-nag, cdk-nag, cfn-lint, cfn-guard, actionlint, zizmor,
    # npm-audit and the converters read, and nothing in their own results says a
    # file was left out of it.
    ignore_file_exclusions: Annotated[
        IgnoreFileExclusions | None,
        Field(
            default=None,
            description=(
                "Whether the scanned repository's .gitignore and .ignore files were "
                "honored when ASH built its scan set, and how many files they "
                "removed from it, in total and per ignore file. Written by every "
                "scan that runs the convert or scan phase. Absent from results "
                "that did not build a scan set, and from results older ASH "
                "versions wrote."
            ),
        ),
    ] = None
    # Beside ignore_file_exclusions for the same reason: nothing in the scan-set
    # readers' own results says a file was left out of it. Set only when there is
    # something to record, as each scanner's inputs_not_scanned is.
    inputs_not_scanned: Annotated[
        List[InputNotScanned] | None,
        Field(
            default=None,
            description=(
                "Files ASH left out of its scan set, so that no reader of the scan "
                "set scanned them, each with the reason: a link to a file whose "
                "target, every link resolved, is outside the scanned tree ('link "
                "leaves the scanned tree'). The summaries list them under 'Inputs "
                "not scanned' as ASH's. Null when there were none."
            ),
        ),
    ] = None
    # Declared for the reasons the `shard` field above states. The engine writes
    # True for a run under --ignore-suppressions, so a results file re-rendered
    # later by `ash report` (whose context carries no such flag) still says the
    # suppressions were not evaluated. It never writes False, and the field is
    # left out of what is written while unset, so a normal run's record is
    # written as before and a saved True survives a later report-only run.
    suppressions_ignored: Annotated[
        bool | None,
        Field(
            default=None,
            exclude_if=lambda value: value is None,
            description=(
                "True when this run was made under --ignore-suppressions, so no "
                "suppression was matched in any phase and the unused-suppressions "
                "report is not evaluated. Absent otherwise: a normal run records "
                "nothing here."
            ),
        ),
    ] = None

    @field_validator("project_name")
    @classmethod
    def validate_non_empty_str(cls, v: str | None, info) -> str | None:
        """Validate string fields are not empty.

        The field is optional, so a results file whose metadata records it as
        null reaches this with None: that is the field's default, not an empty
        name, and stripping it raised a bare AttributeError out of load_model.
        """
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError(f"{info.field_name} cannot be empty")
        return v

    @field_validator("generated_at")
    @classmethod
    def validate_datetime(cls, v: Union[str, datetime, None] = None) -> str:
        """Validate that value is timestamp or, if empty, set to current datetime.

        A string that is not one is refused with the rule, from None: the
        parser's own error quotes the string.
        """
        if not v:
            v = datetime.now(timezone.utc)
        if isinstance(v, str):
            try:
                v = _instant_of(v)
            except ValueError:
                # fromisoformat's own message quotes the value, which is read
                # from a results file; the rule is named instead.
                raise ValueError(
                    "generated_at must be an ISO 8601 date and time"
                ) from None
        return v.isoformat(timespec="seconds")

    def model_post_init(self, context):
        super().model_post_init(context)
        default_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.generated_at:
            self.generated_at = default_timestamp
        if not self.report_id:
            self.report_id = new_report_id()


class AshAggregatedResults(RecordModel):
    """Main model class for parsing security scan reports from ASH tooling."""

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        # The stored config's values can be secrets, and the rest is read from a
        # results file: an error does not quote them.
        hide_input_in_errors=True,
    )

    name: str = Field(default="ASH Scan Report", description="Name of the report")
    description: str = Field(
        default="Automated Security Helper - Aggregated Report",
        description="The description of the generated report.",
    )

    # Its own str fields, not "*" (StrippedRecordModel): a before-validator on sarif
    # would hand the whole report's JSON to Python on every read-back.
    @field_validator("name", "description", mode="before")
    @classmethod
    def _names_as_recorded_before(cls, value: Any, info: ValidationInfo) -> Any:
        return names_as_recorded(value, info)

    metadata: ReportMetadata = Field(
        default_factory=lambda: ReportMetadata(
            report_id=new_report_id(),
            project_name="ASH",
            # tool_name="ASH",
            tool_version=get_ash_version(),
            description="Automated Security Helper Aggregated Report Post-processor",
            summary_stats=SummaryStats(),
        )
    )
    ash_config: Annotated[
        Optional["AshConfig"],
        Field(description="The full ASH configuration used during this scan."),
    ] = None
    scanner_results: Dict[str, ScannerTargetStatusInfo] = Field(default_factory=dict)
    converter_results: Dict[str, ConverterStatusInfo] = Field(default_factory=dict)
    sarif: Annotated[
        SarifReport | None,
        Field(description="The SARIF formatted vulnerability report"),
    ] = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="AWS Labs - Automated Security Helper",
                        fullName="awslabs/automated-security-helper",
                        version=get_ash_version(),
                        organization="Amazon Web Services",
                        downloadUri=AnyUrl(ASH_REPO_URL),
                        informationUri=AnyUrl(ASH_DOCS_URL),
                    ),
                    extensions=[],
                ),
                results=[],
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )
    cyclonedx: Annotated[
        CycloneDXReport | None,
        Field(description="The CycloneDXReport formatted SBOM report"),
    ] = CycloneDXReport()
    additional_reports: Annotated[
        Dict[str, Any],
        Field(
            description="Dictionary of additional reports where the keys are the scanner name and the values are the outputs of the scanner."
        ),
    ] = {}
    validation_checkpoints: Annotated[
        List[Dict[str, Any]],
        Field(
            description="List of validation checkpoints captured during the scan process for debugging and monitoring.",
            default_factory=list,
        ),
    ]
    used_suppressions: Annotated[
        set[str],
        Field(
            description=(
                "Set of suppression IDs that were applied to findings or "
                "accepted an unconverted input during the scan."
            ),
            default_factory=set,
        ),
    ]
    workspace: Annotated[
        Optional[WorkspaceResults],
        Field(
            None,
            description=(
                "Per-project attribution for a workspace-mode scan: one entry "
                "per project, the skipped-project payload, and the exit code the "
                "run produced. Null for a single-directory scan, which is how a "
                "consumer tells the two shapes apart."
            ),
        ),
    ] = None

    secret_value_shapes: Annotated[
        List[SecretValueShape],
        Field(
            default_factory=list,
            # Left out of a file with no secret findings, so its shape is
            # unchanged.
            exclude_if=lambda shapes: not shapes,
            description=(
                "The shape of each value a secret finding exposed, as its masked "
                "form shows it: visible prefix, visible suffix and length, never "
                "the value. Every token of these shapes is masked whenever the "
                "results are masked, which is how `ash merge` masks, in one shard's "
                "findings, a value another shard exposed."
            ),
        ),
    ]

    # Private cache for to_flat_vulnerabilities() — the method mutates
    # summary_stats.suppressed and scanner_results as a side effect, so
    # we memoize the result to keep the method idempotent when reporters
    # call it multiple times during rendering. It holds for as long as the
    # findings it was made from stand: _flat_cache_source says which (see
    # _flat_source), so a copy made with another sarif, or a sarif or
    # additional_reports replaced or appended to since, is flattened again. An
    # edit in place that keeps both objects and their counts (a suppression set
    # on a result, a result replaced by index, masking) is not seen: code that
    # makes one calls _invalidate_flat_cache().
    _flat_cache: Optional[List[FlatVulnerability]] = PrivateAttr(default=None)
    _flat_cache_source: Optional[tuple] = PrivateAttr(default=None)

    # The raw values the masking of these results found (utils/secret_masking.py),
    # never serialized. A workspace masks each project's outputs with the values
    # every project exposed.
    _secret_values: set = PrivateAttr(default_factory=set)

    # How many findings in converted files the --changed-files-only filter has
    # already said it kept for this model (utils/changed_files.py). The scan
    # execution engine narrows the one model at the end of the scan phase and
    # again at the report phase, and the kept findings survive both passes, so
    # without this the count was said twice. Never serialized.
    _changed_files_kept_said: int = PrivateAttr(default=0)

    # Each of the three entry points below resolves the AshConfig forward reference
    # before doing anything else. This module does not resolve it when it is
    # imported, so unless config.ash_config's last line already has, the first of
    # them to run is what does. The comment above _resolve_forward_refs explains
    # why, and why they cannot be dropped in favour of Pydantic's own
    # rebuild-on-first-access.
    #
    # These three are the entry points production reaches: six call sites
    # deserialize through model_validate / model_validate_json, and
    # base/engine_phase.py constructs. model_construct is deliberately not hooked,
    # but note the cost of that: while the reference is unresolved Pydantic mocks
    # __pydantic_serializer__ as well as the validator, so model_dump and
    # model_dump_json are safe only because every instance today arrives through
    # one of these three. One model_construct call, in a process where none of
    # them has run yet, yields an instance whose model_dump_json raises.

    def __init__(self, /, **data: Any) -> None:
        _resolve_forward_refs()
        super().__init__(**data)

    # Keep __pydantic_custom_init__ False. _model_construction sets it from
    # `not getattr(cls.__init__, '__pydantic_base_init__', False)`, so defining
    # __init__ at all would otherwise flip it to True and bake custom_init=True
    # into the core schema. pydantic-core then stops validating a mapping in place
    # and instead materializes one and calls cls(**data), which turns every
    # model_validate_json into parse, build objects, re-enter __init__, validate.
    # That cost is invisible from the __init__ above, which is why this line is
    # here rather than in a commit message. The claim it makes is true: the
    # override adds a _resolve_forward_refs() call and delegates, so it is
    # BaseModel.__init__ for every purpose Pydantic reads this flag for. Pydantic
    # marks its own two pass-through inits the same way (main.py, root_model.py).
    # Private attribute, so a Pydantic release could change what it means; the
    # guard test's positive control is what would catch that.
    __init__.__pydantic_base_init__ = True  # type: ignore[attr-defined]

    @classmethod
    def model_validate(cls, *args: Any, **kwargs: Any) -> "AshAggregatedResults":
        _resolve_forward_refs()
        return super().model_validate(*args, **kwargs)

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> "AshAggregatedResults":
        _resolve_forward_refs()
        return super().model_validate_json(*args, **kwargs)

    # These two need the reference resolved as well: in a process that imported only
    # this module, model_json_schema() raised PydanticUserError and model_rebuild()
    # PydanticUndefinedAnnotation for AshConfig. _resolve_forward_refs rebuilds through
    # BaseModel.model_rebuild, not this override, so it does not call itself.
    @classmethod
    def model_rebuild(cls, *args: Any, **kwargs: Any) -> bool | None:
        _resolve_forward_refs()
        return super().model_rebuild(*args, **kwargs)

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        _resolve_forward_refs()
        return super().model_json_schema(*args, **kwargs)

    @field_validator("ash_config", mode="before")
    @classmethod
    def validate_ash_config(cls, v: Any):
        """Read the stored config, keeping expiration dates today's check refuses.

        A results file records the config its scan ran with. One written before
        ``expiration`` was checked on ignore paths can hold a value such as
        ``TBD`` there, and every reader of results files (``ash report``,
        ``--existing-results``, ``ash merge``, workspace reporting, the MCP
        tools) would otherwise refuse the whole file. The value is kept as
        written and a warning names it; the matcher never applies such an
        entry. Any other refusal fails the load.

        A "before" validator, so it sees the stored data before the field's own
        validation: an "after" validator's fallback to the default config could
        never run, since the field would already have failed.

        A kept date is named by where it is (``global_settings.ignore_paths[0]
        .expiration``), never by what it says, and a kept key by the section
        that holds it (``an unknown key <key> in 'scanners.bandit.options'``),
        never by its name: both are the results file's data, and the warning
        reaches the CI log.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.models.core import UNREADABLE_EXPIRATION_NOTE
        from automated_security_helper.utils.unknown_keys import (
            TOLERATE_STORED_CONFIG,
            UNKNOWN_KEY_NOTE,
        )

        if v is None or isinstance(v, AshConfig):
            return v
        # A name the record holds in its record form, a surrogate's escape such as
        # \udcNN, is read back as the name (utils/undecodable_text
        # .undecodables_of_texts), so ash report, --existing-results and ash merge
        # apply the ignore paths and suppressions the scan applied.
        if isinstance(v, dict):
            v = undecodables_of_texts(v)
        from automated_security_helper.config.recorded_config import (
            without_unreadable_references,
        )

        notes: List[str] = []
        unreadable: List[Any] = []
        try:
            config = AshConfig.model_validate(
                v, context={TOLERATE_STORED_CONFIG: notes}
            )
        except ValidationError as error:
            # A results file keeps an environment reference as the file wrote
            # it, and a fixed-choice field (severity_threshold) cannot hold one.
            # Read with that field's default; any other refusal still fails.
            kept, unreadable = without_unreadable_references(v, error)
            if not unreadable:
                raise
            notes = []
            config = AshConfig.model_validate(
                kept, context={TOLERATE_STORED_CONFIG: notes}
            )
        unreadable_dates = notes.count(UNREADABLE_EXPIRATION_NOTE)
        unknown = notes.count(UNKNOWN_KEY_NOTE)
        described = [
            note
            for note in notes
            if note not in (UNREADABLE_EXPIRATION_NOTE, UNKNOWN_KEY_NOTE)
        ]
        if unknown:
            kept = _kept_unknown_keys(config)
            # Located only when the walk finds exactly the keys the load
            # recorded; otherwise each still warns, without a location.
            described = (
                [f"{UNKNOWN_KEY_NOTE} in '{where}'" for where in kept]
                if len(kept) == unknown
                else [UNKNOWN_KEY_NOTE] * unknown
            ) + described
        if unreadable_dates:
            located = [
                f"{UNREADABLE_EXPIRATION_NOTE} at '{where}'"
                for where in _unreadable_expirations(v)
            ]
            # Located only when the strict pass finds every kept date: it stops
            # at a section that also holds an unknown key, so it can miss one.
            # Otherwise each still warns, without a location.
            described = (
                located
                if len(located) == unreadable_dates
                else [UNREADABLE_EXPIRATION_NOTE] * unreadable_dates
            ) + described
        for note in described:
            ASH_LOGGER.warning(
                f"The configuration stored in these results has {note}. It is "
                "kept as written; an entry with it does not apply, and a "
                "configuration file with it is refused."
            )
        for field, reference in unreadable:
            ASH_LOGGER.warning(
                f"The configuration stored in these results records {field} as "
                f"{reference}, a reference read from the environment where the "
                "scan ran, which that field cannot hold. It is read with the "
                "field's default; a command that acts on it takes the value from "
                "its own configuration.",
                extra={"markup": False},
            )
        config._unreadable_references = unreadable
        return config

    @field_serializer("used_suppressions", when_used="json")
    def _used_suppressions_in_order(self, value: set) -> Any:
        """The ids in order, so identical scans and merges write one file: a set
        iterates in the order of the process's string hashes.

        The return type is ``Any`` on purpose: a serializer with a concrete
        return type replaces the field's own schema in the serialization-mode
        JSON schema, which would drop the ``uniqueItems`` the committed schema
        file records for this set."""
        return sorted(value)

    @field_serializer("ash_config", mode="wrap")
    def _record_ash_config(self, value: Any, handler: Any) -> Any:
        """The configuration as its record: each value and key its files read
        from the environment as the file wrote it (config_validator
        record_of_config), never the value.

        On the dump, not the model: during the scan this is the run's own
        configuration object, which the scan reads its values from. A results
        file, the merged results, and anything else dumped from these results
        keep the reference. Read back, the record holds the reference text where
        the file wrote one, and ``ash report`` renders that text, as the scan's
        own reports do for the project name (ScanExecutionEngine).
        """
        from automated_security_helper.config.config_validator import (
            record_of_config,
        )

        return record_of_config(value, handler(value))

    @field_serializer("metadata", mode="wrap")
    def _record_metadata(self, value: Any, handler: Any) -> Any:
        """The metadata, with the project name and the scanner names as the
        configuration's record has them (config_validator record_of_metadata,
        through record_of_config): the run's reports take the project name from
        here, and a name read from the environment is recorded as the reference
        the file wrote, as the configuration's own record keeps it (above)."""
        from automated_security_helper.config.config_validator import (
            record_of_metadata,
        )

        return record_of_metadata(self.ash_config, handler(value))

    def model_post_init(self, context):
        """Initialize aggregator and trend analyzer with current findings."""
        if self.scanner_results is None:
            self.scanner_results = {}
        # Results read back from a file (ash report, ash merge, --use-existing, the
        # MCP tools, a workspace's per-project files) may have been written without
        # masking, by an older ASH or another producer, so every model is masked as
        # it is built; see utils/secret_masking.py.
        mask_secrets_in_results(self)
        return super().model_post_init(context)

    def _recorded_metadata(self, mode: str = "python") -> Any:
        """The metadata as the results' off-host sends carry it: the fields that
        were set, with the project name and the scanner names as the
        configuration's record has them (config_validator record_of_metadata).

        ``validation_summary`` is filled by mutating the dict the metadata
        started with, which never marks the field as set, so a dump of the set
        fields alone left it out of a live scan's send while the same results
        read back from a file carried it. It is added whenever it holds
        something.
        """
        from automated_security_helper.config.config_validator import (
            record_of_metadata,
        )

        dumped = self.metadata.model_dump(by_alias=True, exclude_unset=True, mode=mode)
        if self.metadata.validation_summary and "validation_summary" not in dumped:
            dumped["validation_summary"] = self.metadata.model_dump(
                by_alias=True, include={"validation_summary"}, mode=mode
            )["validation_summary"]
        return record_of_metadata(self.ash_config, dumped)

    def metadata_only(self) -> dict:
        """Produces a simplified version of the aggregated results without the
            sarif or cyclonedx properties.

        Returns:
            dict: A simple dictionary representation of the AshAggregatedResults
        """
        return self._recorded_metadata(mode="json")

    def to_simple_dict(self) -> dict:
        """Convert the AshAggregatedResults to a simple dictionary representation.

        ``ash_config`` is the configuration the results record, as the fields that
        were set, and None when they record none. ASH's defaults never stand in
        for it: they are not the configuration the scan ran with.

        Returns:
            dict: A simple dictionary representation of the AshAggregatedResults
        """
        from automated_security_helper.config.config_validator import (
            record_of_config,
        )

        conf: dict | None = None
        if self.ash_config is not None:
            # The record, as a results file keeps it (_record_ash_config): this
            # dict is what the CloudWatch Logs and S3 reporters send off the
            # host, so no value read from the environment is in it.
            conf = record_of_config(
                self.ash_config,
                self.ash_config.model_dump(by_alias=True, exclude_unset=True),
            )
        # Results that record no configuration send None, as the results file
        # keeps them; a stored configuration that sets nothing sends {}. ASH's
        # default configuration stands in for neither: it is not the one the
        # scan ran with, and it is loaded from the ASH_CONFIG file of the
        # process sending it.
        simple_dict = {
            "name": self.name,
            "description": self.description,
            "metadata": self._recorded_metadata(),
            "converter_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.converter_results.items())
            },
            "scanner_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.scanner_results.items())
            },
            "ash_config": conf,
        }
        return simple_dict

    def to_flat_vulnerabilities(self) -> List[FlatVulnerability]:
        """Convert the AshAggregatedResults to a list of flattened vulnerability objects.

        The first call materializes the list and applies legacy side effects
        (setting summary_stats.suppressed and the scanner rows' suppressed
        counts from the flattened findings and the suppressed findings the
        scanners' dict results recorded, so a second pass sets the same
        counts again). Subsequent
        calls return the memoized list so the method is safe to call from
        reporters multiple times per run, for as long as the sarif and the
        additional_reports it was made from stand: not replaced, and not
        appended to (see _flat_source). Code that edits the findings in place
        calls _invalidate_flat_cache() after.

        Returns:
            List[FlatVulnerability]: A list of flattened vulnerability objects
        """
        source = self._flat_source()
        if self._flat_cache is not None and self._flat_cache_source is not None:
            held = self._flat_cache_source
            if held[0] is source[0] and held[1] is source[1] and held[2:] == source[2:]:
                return self._flat_cache

        flat_vulns: List[FlatVulnerability] = []

        # The results are read field by field below, so a name set on one after it
        # was validated is read from a copy in the record form (the same report
        # when there is none).
        sarif = recorded(self.sarif) if self.sarif else self.sarif
        if sarif and sarif.runs:
            for run in sarif.runs:
                if not run.results:
                    continue

                tool_name = "Unknown"
                tool_type = "UNKNOWN"
                if run.tool and run.tool.driver:
                    tool_name = run.tool.driver.name
                    driver_props = getattr(run.tool.driver, "properties", None)
                    driver_tags = (
                        getattr(driver_props, "tags", None) if driver_props else None
                    )
                    if driver_tags:
                        for tag in driver_tags:
                            if tag.upper() in {
                                "SAST",
                                "DAST",
                                "SCA",
                                "IAC",
                                "SECRETS",
                                "CONTAINER",
                                "SBOM",
                            }:
                                tool_type = tag.upper()
                                break

                for result in run.results:
                    flat_vuln = FlatVulnerability.from_sarif_result(
                        result, tool_name, tool_type
                    )
                    flat_vulns.append(flat_vuln)

        # The suppressed counts are SET from the flattened findings, never
        # bumped per finding: the unified metrics (core.unified_metrics, run at
        # the end of the scan and by `ash merge`) already count every suppressed
        # SARIF result into summary_stats and the scanner rows, so a bump here
        # counted each one a second time in the saved results. Setting the same
        # count twice is idempotent, and a model no metrics pass has visited
        # still gets its counts from here. A scanner's count is the one those
        # metrics give it: its suppressed SARIF results plus the suppressed
        # findings its dict result recorded (_suppressed_by_scanner).
        suppressed_by_scanner = self._suppressed_by_scanner(flat_vulns)
        self.metadata.summary_stats.suppressed = sum(suppressed_by_scanner.values())
        for scanner_key, count in suppressed_by_scanner.items():
            self._apply_suppression_side_effects(scanner_key, count)

        for scanner_name, results in self.additional_reports.items():
            if results is None:
                continue
            if isinstance(results, dict) and "severity_counts" in results:
                continue
            if isinstance(results, list):
                for finding in results:
                    if not isinstance(finding, dict):
                        continue
                    flat_vulns.append(
                        FlatVulnerability.from_additional_report(finding, scanner_name)
                    )

        project = getattr(self.metadata, "workspace_project", None)
        assign_identity_ids(
            flat_vulns,
            default_project=project
            if isinstance(project, str) and project.strip()
            else None,
        )
        self._flat_cache = flat_vulns
        self._flat_cache_source = source
        return flat_vulns

    def _suppressed_by_scanner(
        self, flat_vulns: List[FlatVulnerability]
    ) -> Dict[str, int]:
        """Each scanner's suppressed count, keyed by its lowercased name.

        The suppressed flattened SARIF findings of the scanner, plus the suppressed
        count a dict result of the scanner recorded on its per-target report: a
        scanner that returned a dict instead of SARIF has findings the merged SARIF
        never holds, and the unified metrics count them. Counted from the SARIF
        alone, the flatten lowered what a metrics pass had written for such a
        scanner. A scanner with neither has no entry.
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        counts: Dict[str, int] = {}
        for flat_vuln in flat_vulns:
            if flat_vuln.is_suppressed:
                scanner_key = (flat_vuln.scanner or "").lower()
                counts[scanner_key] = counts.get(scanner_key, 0) + 1

        seen: set[str] = set()
        for name in [*self.scanner_results, *self.additional_reports]:
            if not isinstance(name, str) or name.lower() in seen:
                continue
            seen.add(name.lower())
            recorded_by_dict = ScannerStatisticsCalculator._dict_result_counts(
                self, name
            ).suppressed
            if recorded_by_dict:
                counts[name.lower()] = counts.get(name.lower(), 0) + recorded_by_dict
        return counts

    def _flat_source(self) -> tuple:
        """What to_flat_vulnerabilities flattens, as it stands now: the sarif and
        the additional_reports objects themselves (held, so that one replaced by
        another is told by identity and never by a reused id), and how many
        results and report entries they hold, which an append changes. An edit
        that keeps both objects and both counts is not told: see
        _invalidate_flat_cache."""
        sarif = self.sarif
        results = (
            sum(len(run.results or []) for run in sarif.runs)
            if sarif is not None and sarif.runs
            else 0
        )
        entries = sum(
            len(value)
            for value in self.additional_reports.values()
            if isinstance(value, list)
        )
        return (sarif, self.additional_reports, results, entries)

    def _invalidate_flat_cache(self) -> None:
        """Forget the flattened findings, so the next to_flat_vulnerabilities
        flattens again.

        For code that edits the findings in place without changing which sarif
        and additional_reports the model holds or how many results and entries
        they hold: setting or clearing a result's suppressions, replacing a
        result by index, masking a value. Replacing and appending need no call.
        """
        self._flat_cache = None
        self._flat_cache_source = None

    def _apply_suppression_side_effects(
        self, scanner: Optional[str], count: Optional[int] = None
    ) -> None:
        """Record suppressed findings on the matching scanner_results entry.

        Extracted from the inline SARIF processing in to_flat_vulnerabilities()
        so the conversion factory can stay side-effect free. With ``count`` the
        entry's suppressed count is SET to it, not added to: the unified metrics
        already count every suppressed finding into the row, so an increment per
        finding doubled it in the saved results; to_flat_vulnerabilities passes
        the whole count once and sets the summary's own count itself. Without
        ``count`` (the original one-argument call) the entry is bumped by one,
        for a caller that records findings one at a time.
        """
        if not scanner:
            return
        key = scanner.lower()
        if key not in self.scanner_results:
            # The rows are keyed by the scanner's recorded name, in the case the
            # configuration spells it; the caller lowercased the finding's.
            key = next(
                (
                    name
                    for name in self.scanner_results
                    if isinstance(name, str) and name.lower() == key
                ),
                None,
            )
            if key is None:
                return

        target_info = self.scanner_results[key]
        if target_info is None:
            return
        if not isinstance(target_info, ScannerTargetStatusInfo):
            # Normalise to the declared element type before reading, rather than
            # guarding each read. Six fields -- finding_count,
            # actionable_finding_count, suppressed_finding_count, severity_counts,
            # exit_code, duration -- are declared on ScannerTargetStatusInfo and not
            # on ScannerStatusInfo, so reading any of them off the wrong shape
            # raises. A hasattr guard would be worse than a raise: both classes set
            # extra="allow", so the assignment below would then succeed by creating
            # an undeclared attribute, and the suppression count would be written to
            # an object nothing reads.
            #
            # dicts arrive from JSON and are expected. Anything else is a writer that
            # did not honour the annotation, so it is logged rather than absorbed.
            if not isinstance(target_info, dict):
                ASH_LOGGER.warning(
                    f"scanner_results[{key!r}] holds {type(target_info).__name__}, "
                    f"not ScannerTargetStatusInfo; normalising. This is a writer "
                    f"that did not honour the declared type."
                )
                # Drop keys the source left unset so the target's own defaults
                # apply. The shapes disagree on optionality as well as on which
                # fields exist: ScannerStatusInfo declares
                # `status: ScannerStatus | None = None`, while
                # ScannerTargetStatusInfo declares `status: ScannerStatus`, so
                # forwarding an explicit None fails validation on a field the
                # source simply never filled in.
                target_info = {
                    field_name: value
                    for field_name, value in target_info.model_dump().items()
                    if value is not None
                }
            target_info = ScannerTargetStatusInfo.model_validate(target_info)
            self.scanner_results[key] = target_info

        # ScannerSeverityCount declares `suppressed: int = 0`, so the attribute
        # always exists and moves with the count above.
        if count is None:
            target_info.suppressed_finding_count += 1
            target_info.severity_counts.suppressed += 1
        else:
            target_info.suppressed_finding_count = count
            target_info.severity_counts.suppressed = count

    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> "AshAggregatedResults":
        """Parse JSON data into an AshAggregatedResults instance.

        Args:
            json_data: Either a JSON string or dictionary containing the report data.
                Must include metadata and findings fields.

        Returns:
            AshAggregatedResults instance populated with the report data.

        Raises:
            ValidationError: If the JSON data is missing required fields or has invalid values.
        """
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)
        return cls.model_validate(json_data)

    def save_model(self, output_dir: Path) -> None:
        """Save AshAggregatedResults as JSON alongside aggregated results.

        This method populates the final metrics right before saving to ensure
        all metrics are aligned and based on the final processed SARIF data.
        """
        # Populate the final metrics right before saving, from the SARIF this
        # model holds now. Done only when scanner_results was empty, the
        # scan-phase file (the scan-complete marker) carried all-zero
        # summary_stats whenever any scanner was skipped, missing, excluded or
        # errored: those scanners have rows before the rebuild, so the summary
        # was never filled while the SARIF held findings. Recomputing is
        # idempotent, so a model whose metrics were already populated is saved
        # with the same counts.
        self._populate_final_metrics()

        # No secret value a finding exposes is written to the file; see
        # utils/secret_masking.py. In place, so what is reported next is masked too.
        mask_secrets_in_results(self)
        # The masking edited the findings in place, which the cache does not
        # see: what is flattened next is flattened from the masked ones.
        self._invalidate_flat_cache()

        # Refused rather than created through when it is a link, which it can have
        # become since the run set it up (utils/report_path_links.py).
        from automated_security_helper.utils.report_path_links import (
            ensure_reports_dir,
        )

        ensure_reports_dir(output_dir.joinpath("reports"))

        # Save aggregated results as JSON. Atomically, because this file's existence is
        # what marks the scan complete and get_scan_progress parses it while the scan is
        # still running; see utils/atomic_write.py.
        #
        # The full model, not exclude_unset. The scan builds this model by mutating
        # it in place -- scanner_results[name] = ..., appending SARIF results -- and
        # pydantic records a field as set only when it is assigned or passed to the
        # constructor. exclude_unset therefore dropped scanner_results and sarif from
        # a model that had both, and the file said the scan had no scanners. Dumped
        # the same way as the rewrite in _run_local_mode and a workspace's
        # per-project file, so every writer of this file produces one shape.
        json_path = output_dir.joinpath("ash_aggregated_results.json")
        write_text_atomically(
            json_path,
            self.model_dump_json(indent=2, by_alias=True),
        )

    def _populate_final_metrics(self) -> None:
        """Populate scanner_results and summary_stats from final SARIF data.

        This ensures all metrics are aligned and based on the final processed
        SARIF data after all suppressions have been applied.
        """
        from automated_security_helper.core.unified_metrics import (
            _populate_summary_stats_from_unified_metrics,
            get_unified_scanner_metrics,
        )

        ASH_LOGGER.debug("Populating final metrics from unified scanner metrics")

        try:
            # Get unified metrics from the final SARIF data
            unified_metrics = get_unified_scanner_metrics(self)
            ASH_LOGGER.debug(f"Got {len(unified_metrics)} unified metrics")

            # Note: scanner_results should remain as ScannerStatusInfo objects
            # The unified metrics are computed separately when needed
            ASH_LOGGER.debug(
                f"Unified metrics computed for {len(unified_metrics)} scanners"
            )

            # Populate summary_stats from unified metrics using the canonical
            # module-level helper in core.unified_metrics.
            _populate_summary_stats_from_unified_metrics(self, unified_metrics)

            ASH_LOGGER.debug(
                f"Populated final metrics for {len(unified_metrics)} scanners"
            )

        except Exception as e:
            # Reporting the failure must not be a second one: this runs in
            # save_model, and an error raised from here would keep the results
            # file, the scan-complete marker, from being written.
            try:
                from automated_security_helper.utils.error_text import (
                    config_environment_values,
                    error_text,
                    traceback_text,
                )

                # Shown as every unexpected error is: with no input a
                # ValidationError quotes and no value the stored configuration read
                # from the environment.
                values = config_environment_values(self.ash_config)
                ASH_LOGGER.error(
                    f"Error populating final metrics: {error_text(e, values)}",
                    extra=NO_MARKUP,
                )
                ASH_LOGGER.error(
                    f"Stack trace: {traceback_text(e, values)}", extra=NO_MARKUP
                )
            except Exception as describing:
                # The type alone: it names no input and no value. The error that
                # stopped the description is named the same way, one line before,
                # so a broken formatter is not lost behind the first failure.
                ASH_LOGGER.debug(
                    "Describing the final-metrics error raised "
                    f"{type(describing).__name__}",
                    extra=NO_MARKUP,
                )
                ASH_LOGGER.error(
                    f"Error populating final metrics: {type(e).__name__}",
                    extra=NO_MARKUP,
                )
            # Don't raise to avoid breaking the save operation

    @classmethod
    def load_model(cls, json_path: Path) -> Optional["AshAggregatedResults"]:
        """Load AshAggregatedResults from JSON file."""
        if not json_path.exists():
            return None

        # UTF-8, as every writer of this file writes it: the platform's locale
        # encoding read it wrong, or refused it, on Windows.
        with open(json_path, encoding="utf-8") as f:
            json_data = json.load(f)

        # As ash report, ash merge and --use-existing read a results file: one
        # warning says how many keys the records dropped, and from which file.
        with warning_of_dropped_keys(json_path) as context:
            if isinstance(json_data, str):
                return cls.model_validate_json(json_data, context=context)
            return cls.model_validate(json_data, context=context)


# Resolve the AshConfig forward reference so deserialization works regardless of
# import order.
#
# ash_config is annotated Optional["AshConfig"] as a string, because AshConfig is
# imported at the top of this module only under TYPE_CHECKING. Until a rebuild
# resolves that string the model has no validator and no serializer at all, and
# model_validate and model_validate_json raise PydanticUserError instead of
# returning a model.
#
# It is called on first use, and the last line of config/ash_config.py rebuilds the
# model too when that module is imported. It is not called at import time at the
# bottom of this module, because that call would do harm: importing
# config.ash_config from inside this module's import loads every built-in plugin
# group, while the module that started the chain (core.unified_metrics,
# utils.sarif_utils, ...) is still partially initialized, and a plugin module
# importing back from it would take its whole group down with it. The half-imported
# config.ash_config would then be evicted too, so the model would stay unresolved
# until first use anyway.
#
# First use means __init__, model_validate and model_validate_json. The cycle only
# exists while the package is being imported, so by the time anything constructs
# or deserializes the model the import succeeds. That is why those three overrides
# cannot be dropped in favour of the rebuild Pydantic attempts by itself when a
# mocked validator, serializer or core schema is first touched: when nothing has
# imported config.ash_config yet, it is not in sys.modules at all, so Pydantic's
# attempt has nothing to resolve the reference against. Removing the overrides
# leaves a model that cannot validate in that process -- measured, not assumed.
#
# Resolving on first use is not a new idea here, it is the older one. Before
# 9babca5f, interactions/run_ash_scan.py and cli/report.py each ran this rebuild
# themselves, at call time, right before deserializing. That commit consolidated
# both into a single call at import time, the one moment the cycle can block it,
# and that call is gone. Resolving on first use restores call-time resolution, in
# one place instead of two.
#
# The import binds AshConfig into this module's globals before rebuilding.
# model_rebuild() resolves the reference against the model's own module namespace
# (pydantic._internal._namespace_utils.get_module_ns_of), so once the name is
# there every later rebuild succeeds on its own, wherever it is called from.
# Without the assignment AshConfig is reachable only as a local of this
# function's frame, which is a namespace only a model_rebuild() called directly
# from inside this function can see.

# model_rebuild() is not thread-safe, and says so in its own source: it clears
# __pydantic_complete__ and deletes the validator, serializer and core schema
# before regenerating them. Two threads that both get past the flag can have the
# second delete the validator the first just published, leaving a third -- which
# saw the flag as True and skipped the rebuild -- to fail against the inherited
# BaseModel validator with a misleading error, mid-scan and non-deterministically.
# Scans are genuinely multi-threaded: workspace/execution.py submits one
# orchestrator per project to a ThreadPoolExecutor, and core/orchestrator.py
# deserializes while base/engine_phase.py constructs. Reentrant because importing
# config.ash_config executes module bodies this module does not control, and one
# of them constructing an AshAggregatedResults would re-enter on this thread.
#: The one once-only resolver both models share (base/forward_refs.py): the lock,
#: the flag set only after the rebuild, and the import outside the lock. This
#: module and base/plugin_context.py each carried a copy before.
_forward_refs: OnceOnlyResolver[type] = OnceOnlyResolver()


def _import_ash_config() -> type:
    # Raises ImportError mid-cycle, when the model was used while the package
    # was still being imported; the resolver then does nothing, and the next
    # use, once the import has finished, resolves it.
    from automated_security_helper.config.ash_config import AshConfig

    return AshConfig


def _bind_ash_config(ash_config: type) -> None:
    globals()["AshConfig"] = ash_config
    # The base class's rebuild: AshAggregatedResults.model_rebuild would call
    # the resolver again.
    super(AshAggregatedResults, AshAggregatedResults).model_rebuild()


def _resolve_forward_refs() -> None:
    """Bind AshConfig into this module and rebuild AshAggregatedResults on it, once.

    Cheap to call repeatedly, and a no-op while AshConfig is still unimportable.
    """
    _forward_refs.resolve(_import_ash_config, _bind_ash_config)


# Not called at import time. Importing config.ash_config from here imported the
# built-in converter and reporter modules, and with them the ash_builtin package,
# which loads every plugin group -- while whichever module started this import was
# still partially initialized. A plugin module importing back from it (sarif_utils,
# suppression_matcher, unified_metrics, scanner_statistics_calculator) then failed,
# and its whole group was lost for the process. Resolution happens instead on first
# use (__init__, model_validate, model_validate_json above), and on the last line
# of config/ash_config.py when that module is imported. See
# tests/unit/plugins/test_entry_module_import_order.py.


@contextmanager
def warning_of_dropped_keys(source: str | Path) -> Iterator[Dict[str, int]]:
    """The validation context for reading a results file, as ash report, ash merge
    and --use-existing do:
    ``AshAggregatedResults.model_validate_json(text, context=context)``.

    A refused-input record and a failed-input record keep only the keys they
    define. When the file's records held others, one warning after the read says
    how many were dropped and from which file. It names neither a key nor its
    value, which come from the file.
    """
    context: Dict[str, int] = {_DROPPED_RECORD_KEYS: 0}
    yield context
    dropped = context[_DROPPED_RECORD_KEYS]
    if dropped:
        noun = "key" if dropped == 1 else "keys"
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Dropped {dropped} {noun} that a refused-input record or a "
                f"failed-input record does not define from '{source}'"
            )
        )


if __name__ == "__main__":
    from automated_security_helper.utils.console import echo_raw

    model = AshAggregatedResults()
    echo_raw(model.model_dump_json(indent=2))
