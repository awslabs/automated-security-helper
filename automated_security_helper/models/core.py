# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from __future__ import annotations

import fnmatch
from typing import (
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Annotated,
    Optional,
    Tuple,
    TYPE_CHECKING,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from datetime import datetime, date

from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
    ignore_path_pattern,
)
from automated_security_helper.utils.redacted_model import RedactedSection
from automated_security_helper.utils.symbol_spans import is_valid_symbol
from automated_security_helper.utils.unknown_keys import (
    refuse_unknown_keys,
    tolerated_notes,
)

if TYPE_CHECKING:
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability
    from automated_security_helper.utils.symbol_spans import SymbolResolver


#: What an entry's expiration that is not a YYYY-MM-DD date records under
#: TOLERATE_STORED_CONFIG. No value: the reader of a results file names where the
#: entry is (models/asharp_model.py), since the value is the file's data.
UNREADABLE_EXPIRATION_NOTE = "an expiration that is not a YYYY-MM-DD date"
#: The note a results file's kept suppression gets when its ``symbol`` is the
#: environment reference the config wrote (``${VAR}``), which the scan read and the
#: record stores as written. The entry is kept, and never applied.
UNREADABLE_SYMBOL_NOTE = "a symbol that is a reference to the environment"
#: The note a results file's kept suppression gets when its ``rule_id`` is blank,
#: which a scan of an earlier version accepted and recorded. The entry is kept, and
#: never applied: a blank rule id once covered every rule in the entry's path.
BLANK_RULE_ID_NOTE = "a rule_id that is blank"


def _is_environment_reference(value: Any) -> bool:
    """Whether ``value`` is the text of an environment reference as a config
    writes it (``${VAR}``, with or without the ``!ENV`` tag), the form a results
    file records for a value the scan read from the environment."""
    # Lazy: config.ash_config imports this module.
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

    if not isinstance(value, str):
        return False
    return ENV_REFERENCE_PATTERN.match(value.removeprefix("!ENV ")) is not None


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


def current_date() -> date:
    """Today on this host's local clock, the date every ``expiration`` is read against.

    Ignore paths and suppressions both compare with this one function, so the
    places that decide whether an entry still applies cannot disagree about which
    day it is.
    """
    return date.today()


def expiration_has_passed(expiration: str) -> bool:
    """Whether an entry with this ``expiration`` no longer applies today.

    The one rule for suppressions and ignore paths, wherever they are applied
    (``utils/suppression_matcher.py``), in ``is_expired`` and in
    ``ash config lint``: ``expiration`` is a YYYY-MM-DD date, and the entry stops
    applying at the start of that day on ``current_date()``, so on the expiration
    date itself it has already expired.

    Raises:
        ValueError: ``expiration`` is not a YYYY-MM-DD date.
    """
    return datetime.strptime(expiration, "%Y-%m-%d").date() <= current_date()


# The one wording for a refused ``expiration`` and ``symbol``. The models raise
# them, and a scan, ``ash config validate`` and ``ash config lint`` all print
# the model's message.
SYMBOL_RULE = (
    "symbol must be a dotted qualified name such as 'MyClass.my_method' "
    "(identifiers joined by '.', no spaces, wildcards or call syntax)"
)
EXPIRATION_RULE = "Invalid expiration date format. Use YYYY-MM-DD"


def _named_by_type(value: Any) -> str:
    """How a message names a value that is not text, without showing it."""
    if isinstance(value, bool):
        return "true or false"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    return f"a {type(value).__name__}"


def refuse_an_expiration_that_is_not_text(value: Any) -> Any:
    """``value``, unless it is an ``expiration`` that is not a string.

    For a ``mode="before"`` validator: YAML and TOML read an unquoted
    2099-01-31 as a date, which a strict ``str`` field refused with pydantic's
    own string error, before any check that could say what to write. A date or
    a number can only be the file's own text, never a value read from the
    environment (that is always a string), so a date is shown; anything else is
    named by its type, since a list or a mapping can hold strings that are.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, date):
        raise ValueError(
            "expiration must be a quoted YYYY-MM-DD string: an unquoted "
            f"{value.isoformat()} is read as a date, not text, so put it in quotes"
        )
    raise ValueError(
        f"expiration must be a quoted YYYY-MM-DD string, not {_named_by_type(value)}"
    )


def expiration_date_problem(value: str) -> Optional[str]:
    """EXPIRATION_RULE when the string ``value`` is not a YYYY-MM-DD date, or None.

    The rule, not the value: a redaction replaces only a value it can recognize,
    and the value may have been read from the environment.
    """
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return EXPIRATION_RULE
    return None


# Where ignore-path entries sit in a configuration, by key, and how a message
# names an entry of each list. ``ash config lint`` walks the file's mapping with
# it and the scan-start expiry warnings walk the loaded config, so the two
# cannot cover different lists. Every list holds ``IgnorePathWithReason``
# entries, which expire by the rule below.
IGNORE_PATH_LISTS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("global_settings", "ignore_paths"), "Ignore path"),
    (("scanners", "bandit", "options", "excluded_paths"), "Bandit excluded path"),
    (("scanners", "checkov", "options", "skip_path"), "Checkov skip path"),
    (("scanners", "syft", "options", "exclude"), "Syft exclude entry"),
)


def value_at(container: Any, keys: Tuple[str, ...]) -> Any:
    """The value at ``keys`` in a config mapping or a loaded config, or None."""
    value = container
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, BaseModel):
            value = getattr(value, key, None)
        else:
            return None
    return value


# ``expiration`` means the same here and on ``AshSuppression``, which inherits
# it: a YYYY-MM-DD date compared with ``current_date()``. The entry stops applying
# at the start of that day, so on the expiration date itself it no longer applies.
# ``utils/suppression_matcher.py`` enforces it for both. (A comment rather than
# the docstring, which pydantic publishes as the JSON schema's description.)
class IgnorePathWithReason(RedactedSection):
    """Represents a path exclusion entry."""

    # Validated on its own from a config or a results file: a refused value can
    # be a secret, and an error's text goes wherever the error is shown.
    # Unknown keys are refused by _refuse_unknown_keys below. Extras are allowed
    # only so that a results file holding one (utils/unknown_keys.py) keeps it,
    # and the schema says what a config file may contain.
    model_config = ConfigDict(
        extra="allow",
        hide_input_in_errors=True,
        json_schema_extra={"additionalProperties": False},
    )

    # How errors and warnings name an entry of this kind.
    ENTRY_KIND: ClassVar[str] = "an ignore path"

    path: Annotated[str, Field(..., description="Path or pattern to exclude")]
    reason: Annotated[str, Field(..., description="Reason for exclusion")]
    expiration: Annotated[
        str | None,
        Field(
            None,
            description=(
                "(Optional) Expiration date (YYYY-MM-DD). The entry stops applying "
                "on this date, by the local clock of the host running the scan."
            ),
        ),
    ] = None
    client_supplied: Annotated[
        bool,
        Field(
            description=(
                "Set by ASH: True when a config or workspace policy file an MCP "
                "client delivered supplied this entry, so results show which "
                "suppressions and ignored paths came from the client. A value "
                "written in a config file is ignored."
            ),
        ),
    ] = False

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown_keys(cls, data: Any, info: ValidationInfo) -> Any:
        """Refuse a key the entry does not declare, rather than drop it.

        Dropped, a misspelled ``rule_id`` left a suppression with no rule, and a
        suppression with no rule covers every rule in its path; a misspelled
        ``expiration`` made an entry permanent. See utils/unknown_keys.py for the
        message and for the results-file exception.
        """
        return refuse_unknown_keys(cls, data, info, cls.ENTRY_KIND)

    @field_validator("expiration", mode="before")
    @classmethod
    def _expiration_is_text(cls, v: Any, info: ValidationInfo) -> Any:
        """An unquoted date, refused with what to write (``refuse_an_expiration_that_is_not_text``).

        Under the TOLERATE_STORED_CONFIG context a stored value that is not text
        is kept as its text, which ``validate_expiration_date`` then records as an
        unreadable date like a malformed string, instead of refusing the whole
        results file.
        """
        if (
            v is not None
            and not isinstance(v, str)
            and tolerated_notes(info) is not None
        ):
            return str(v)
        return refuse_an_expiration_that_is_not_text(v)

    @field_validator("expiration")
    @classmethod
    def validate_expiration_date(cls, v, info: ValidationInfo):
        """Validate that expiration date is in YYYY-MM-DD format.

        Past dates are accepted; use is_expired to check whether the
        entry has expired at runtime. Under the TOLERATE_STORED_CONFIG context
        (utils/unknown_keys.py) a malformed date is kept and recorded rather than
        refused; the matcher never applies such an entry. The note records no
        value: the reader that collects it names the entry's location instead.
        """
        problem = None if v is None else expiration_date_problem(v)
        if problem is not None:
            notes = tolerated_notes(info)
            if notes is not None:
                notes.append(UNREADABLE_EXPIRATION_NOTE)
                return v
            raise ValueError(problem)
        return v

    @property
    def has_unknown_keys(self) -> bool:
        """True for an entry kept from a results file with a key it does not declare.

        Such an entry is never applied: what the unknown key was meant to say
        cannot be known, and a suppression that lost its ``rule_id`` that way
        would cover every rule in its path.
        """
        return bool(self.model_extra)

    @property
    def is_expired(self) -> bool:
        """Return True if this entry's expiration date has been reached.

        An expiration that is not a YYYY-MM-DD date counts as expired. A config
        refuses one, so only an entry kept from a results file can hold it, and
        ``active_ignore_paths`` and ``should_suppress_finding`` already leave
        such an entry out: an unreadable date gives no assurance the entry still
        applies. Returning False here made ``AshSuppression.matches`` apply it.

        Only None is "no expiration". An empty string is kept from a results
        file as an unreadable date (``validate_expiration_date`` records it so),
        and reading it as no expiration applied the entry permanently while the
        load warning said it did not apply.
        """
        if self.expiration is None:
            return False
        try:
            return expiration_has_passed(self.expiration)
        except ValueError:
            return True

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Days from today until expiration; None if no expiration is set.

        A negative value indicates the entry has already expired.
        """
        if not self.expiration:
            return None
        try:
            expiration_date = datetime.strptime(self.expiration, "%Y-%m-%d").date()
        except ValueError:
            return None
        return (expiration_date - current_date()).days

    def matches_path(self, file_path: str) -> bool:
        """Return True if ``file_path`` matches this entry's path pattern.

        Supports exact matches, simple globs (``*.py``), and recursive globs
        (``tests/**/*.py``). Matching is case-sensitive and the same on every
        platform: on a case-sensitive filesystem ``TESTS/`` is not ``tests/``. A
        path ending in ``/`` names a directory and matches everything below it
        (``path_matching.ignore_path_pattern``); ``AshSuppression`` keeps the
        literal meaning.
        """
        return _path_pattern_matches(file_path, ignore_path_pattern(self.path))


class IgnoreFileExclusions(BaseModel):
    """What the scanned repository's ignore files took out of one scan set.

    ASH leaves out every file a ``.gitignore`` or ``.ignore`` in the scanned tree
    matches, unless the operator turned that off with ``honor_ignore_files: false``
    or ``--no-honor-ignore-files``. A scanner that read fewer files cannot say so in
    its own results, so the scan records it here and the summaries print it.
    """

    # Read from a results file, whose values an error does not quote.
    model_config = ConfigDict(hide_input_in_errors=True)

    honored: Annotated[
        bool,
        Field(
            description=(
                "Whether the scanned repository's .gitignore and .ignore files "
                "decided which files were scanned. False when the operator set "
                "honor_ignore_files: false or passed --no-honor-ignore-files. In "
                "merged results (a workspace scan's, or ash merge's), True only "
                "when every merged scan honored them; see honored_scan_count."
            )
        ),
    ]
    excluded_file_count: Annotated[
        int,
        Field(
            ge=0,
            description=(
                "How many files the ignore files removed from the scan set: the sum "
                "of by_ignore_file. Files ASH leaves out on its own (.git, CDK "
                "assets, the bundled aws-cdk tree, its own output directory) are "
                "not counted. When the scanned repository's ignore files were not "
                "honored, only ignore files the caller named are counted, which is "
                "none for ash scan."
            ),
        ),
    ] = 0
    by_ignore_file: Annotated[
        Dict[str, int],
        Field(
            default_factory=dict,
            description=(
                "Each ignore file whose rules were applied, by its path relative to "
                "the scan root (relative to the workspace root in a workspace "
                "scan's merged results), mapped to the number of files it removed. "
                "An ignore file that removed nothing is listed with 0. Files under "
                "a directory the root .gitignore excluded count for the root "
                ".gitignore, and ignore files inside that directory are not read."
            ),
        ),
    ]

    output_dir_file_count: Annotated[
        int,
        Field(
            ge=0,
            description=(
                "How many files were already in ASH's own output directory when "
                "the scan set was built, when that directory is inside the scanned "
                "tree. ASH leaves its output directory out of the scan set whatever "
                "honor_ignore_files says, so these files were not scanned either; "
                "they are files from an earlier run, or repository files that sit "
                "where ASH writes. This run's own log files are not counted."
            ),
        ),
    ] = 0

    # Both counts are left out of what is written while unset, so a single scan's
    # record, and a merged one whose scans agreed, are written as before.
    honored_scan_count: Annotated[
        Optional[int],
        Field(
            default=None,
            ge=0,
            exclude_if=lambda value: value is None,
            description=(
                "In merged results (a workspace scan's, or ash merge's) whose "
                "scans did not agree, how many of the scan_count merged scans "
                "honored the ignore files; honored is then False. Absent for a "
                "single scan, and when every merged scan agreed."
            ),
        ),
    ] = None
    scan_count: Annotated[
        Optional[int],
        Field(
            default=None,
            ge=0,
            exclude_if=lambda value: value is None,
            description=(
                "With honored_scan_count: how many scans the merged record covers "
                "(the projects or shards that recorded one; one that recorded none "
                "is not counted)."
            ),
        ),
    ] = None

    @model_validator(mode="after")
    def _drop_counts_that_agree_with_honored(self) -> "IgnoreFileExclusions":
        """Leave out a pair of counts that only repeats what ``honored`` says.

        Every scan honoring (with ``honored``) or none (without it) is not a
        disagreement, so the record reads as one that never had the counts. Any
        other pair that does not describe a disagreement is kept as stored, and
        ``summary_text`` says the record is inconsistent.
        """
        h, n = self.honored_scan_count, self.scan_count
        if h is not None and n is not None and n > 0:
            if (h == n and self.honored) or (h == 0 and not self.honored):
                self.honored_scan_count = None
                self.scan_count = None
        return self

    def _disagreement(self) -> Optional[Tuple[int, int]]:
        """(honoring, total) scans when the record says its merged scans disagreed."""
        h, n = self.honored_scan_count, self.scan_count
        if h is not None and n is not None and 0 < h < n and not self.honored:
            return h, n
        return None

    def _inconsistent(self) -> bool:
        has_counts = self.honored_scan_count is not None or self.scan_count is not None
        return has_counts and self._disagreement() is None

    def scan_counts(self) -> Tuple[int, int]:
        """(honoring, total) scans this record stands for, to merge it with others.

        A record that is itself merged from scans that disagreed stands for its
        counts; any other stands for one scan, honoring or not as ``honored``
        says.
        """
        return self._disagreement() or (1 if self.honored else 0, 1)

    def summary_text(self) -> str:
        """The sentence the text and markdown summaries print for this record."""
        files = "file" if self.excluded_file_count == 1 else "files"
        if self._inconsistent():
            # Counts that contradict each other or honored, as only a hand-edited
            # or partly lost record has: neither which scans honored the ignore
            # files nor "excluded no files" can be taken from it.
            text = (
                "recorded inconsistently, so which merged scans honored them is "
                f"not known; the ignore files that were applied excluded "
                f"{self.excluded_file_count} {files} from ASH's scan sets"
            )
        elif self.scan_count is not None and self.honored_scan_count is not None:
            # Merged scans that disagreed. Neither one-scan sentence is true of
            # them: some scan sets were cut by the repository's ignore files and
            # some were not, and the count cannot be split between the two.
            honored, total = self.honored_scan_count, self.scan_count
            text = (
                f"honored by {honored} of {total} merged scans and not by the other "
                f"{total - honored} (honor_ignore_files: false); the ignore files "
                f"that were applied excluded {self.excluded_file_count} {files} "
                "from ASH's scan sets"
            )
        elif self.honored:
            text = (
                "the scanned repository's .gitignore and .ignore files excluded "
                f"{self.excluded_file_count} {files} from ASH's scan set"
            )
        else:
            # "ASH's scan set" and not more: semgrep and opengrep walk the tree
            # themselves and still skip what git ignores in a checkout.
            text = (
                "not honored for this scan (honor_ignore_files: false), so the scanned "
                "repository's .gitignore and .ignore files excluded no files from "
                "ASH's scan set"
            )
            if self.excluded_file_count:
                text += (
                    f"; ignore files named by the caller excluded "
                    f"{self.excluded_file_count} {files}"
                )
        if self.output_dir_file_count:
            found = self.output_dir_file_count
            text += (
                f"; {found} {'file' if found == 1 else 'files'} already in ASH's "
                f"output directory {'was' if found == 1 else 'were'} left out as well"
            )
        return text


def merged_honoring(records: Iterable[IgnoreFileExclusions]) -> Dict[str, Any]:
    """``honored`` for the records of several scans merged into one record.

    With ``honored_scan_count`` and ``scan_count`` as well when the scans
    disagree. A record that is itself merged counts as the scans it stands for
    (``IgnoreFileExclusions.scan_counts``), so merging merged records keeps their
    counts. ``ash merge`` and a workspace scan's merged results both use this.

    A merged record whose scans all agreed carries no counts
    (``_drop_counts_that_agree_with_honored``), so merging it with others counts
    it as one scan, however many it covered. "honored by H of N" can then read H
    or N smaller than the number of scans merged; ``honored`` itself stays right.
    """
    honoring = total = 0
    for record in records:
        record_honoring, record_total = record.scan_counts()
        honoring += record_honoring
        total += record_total
    merged: Dict[str, Any] = {"honored": honoring == total}
    if 0 < honoring < total:
        merged["honored_scan_count"] = honoring
        merged["scan_count"] = total
    return merged


def ignore_paths_that_skip_scanning(
    ignore_paths: "List[IgnorePathWithReason] | None",
    *,
    ignore_suppressions: bool,
) -> "List[IgnorePathWithReason]":
    """The ignore paths that keep a file from being converted or scanned at all.

    Those the operator supplied. A path a delivered tree's own config supplied
    (``client_supplied``) is left to the SARIF step instead, which keeps a finding
    under it as a marked, suppressed result, so the results show what the
    client's config hid. Applying it before the scan as well would mean no
    finding to keep. The cost is that those files are scanned.

    None under ``--ignore-suppressions``. An ignore path is a suppression, and the
    flag lifts every suppression for every scanner: the files under one are
    converted and scanned, and their findings are reported. Without this the
    flag's effect would depend on the scanner, since a scanner that reads the
    whole directory reports those findings anyway and one that is handed only the
    files left after this filter never sees them. The cost is a slower scan.
    Keyword-only and required, so every caller states the flag.
    """
    if ignore_suppressions:
        return []
    return [path for path in ignore_paths or [] if path.client_supplied is not True]


class ToolArgs(BaseModel):
    """Base class for tool argument dictionaries."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    output_arg: str | None = None
    scan_path_arg: str | None = None
    format_arg: str | None = None
    format_arg_value: str | None = None
    extra_args: List[ToolExtraArg] = []


PACKAGE_SUPPRESSION_FIELDS = ("package_name", "package_version", "package_path")


def suppression_id(suppression: Dict[str, Any]) -> str:
    """Identifier for a suppression given as a dict of its fields.

    Shared by ``AshSuppression.id`` and the config linter, which reads raw YAML
    dicts, so the unused-suppressions report and the linter's fixer agree.
    """
    # Every part is text. The linter reads raw YAML dicts, where a rule id or a
    # package version can arrive as a number (``rule_id: 1234``,
    # ``package_version: 2.0``), and joining a number raised TypeError out of
    # ``ash config lint --fix-unused``. ``str()`` of a value is what the config's
    # own text form would have been.

    def _text(value: Any, absent: str) -> str:
        if value is None or value == "":
            return absent
        return value if isinstance(value, str) else str(value)

    line_start = suppression.get("line_start")
    line_end = suppression.get("line_end")
    line_end_val = line_end if line_end is not None else line_start
    parts = [
        _text(suppression.get("path"), ""),
        _text(suppression.get("rule_id"), "*"),
        str(line_start) if line_start is not None else "*",
        str(line_end_val) if line_end_val is not None else "*",
    ]
    symbol = suppression.get("symbol")
    if symbol or any(suppression.get(f) for f in PACKAGE_SUPPRESSION_FIELDS):
        parts.append(
            "@".join(_text(suppression.get(f), "*") for f in PACKAGE_SUPPRESSION_FIELDS)
        )
    # A symbol is a sixth part, and its presence always brings the fifth, so an
    # id's part count says which fields it carries and a symbol can never be
    # read as a package.
    if symbol:
        parts.append(_text(symbol, "*"))
    return "|".join(parts)


class AshSuppression(IgnorePathWithReason):
    """Represents a finding suppression rule."""

    ENTRY_KIND: ClassVar[str] = "a suppression"

    # The unused-suppressions report and the expiry warning show each field
    # the config read from the environment by its reference, never the value.
    # An int cannot carry the reference text, so a line number read from the
    # environment would print as the value. The section base's default
    # already refuses a reference at a typed field
    # (RedactedSection._env_scalar_typed_fields is empty unless a section
    # opts a measured field in), so this section declares nothing.

    rule_id: Annotated[str | None, Field(None, description="Rule ID to suppress")] = (
        None
    )
    line_start: Annotated[
        int | None, Field(None, description="(Optional) Starting line number")
    ] = None
    line_end: Annotated[
        int | None, Field(None, description="(Optional) Ending line number")
    ] = None
    package_name: Annotated[
        str | None,
        Field(
            None,
            description=(
                "(Optional) Only suppress findings about this package (glob, "
                "case-insensitive). Findings that do not report a package name "
                "never match."
            ),
        ),
    ] = None
    package_version: Annotated[
        str | None,
        Field(
            None,
            description=(
                "(Optional) Only suppress findings about this installed package "
                "version (glob, case-insensitive). Findings that do not report an "
                "installed version never match."
            ),
        ),
    ] = None
    package_path: Annotated[
        str | None,
        Field(
            None,
            description=(
                "(Optional) Only suppress findings about the package copy installed "
                "at this path, relative to the scan root (glob, supports **), e.g. "
                "'deploy/cdk/node_modules/aws-cdk-lib/node_modules/brace-expansion'. "
                "Separates two copies with the same name and version. Findings that "
                "do not report an install path never match."
            ),
        ),
    ] = None
    symbol: Annotated[
        str | None,
        Field(
            None,
            description=(
                "(Optional) Only suppress findings whose lines lie inside the "
                "definition with this qualified name, e.g. 'MyClass.my_method', "
                "in the finding's file. Names are dotted from the top of the "
                "file, exact and case-sensitive. Resolved by parsing the file "
                "with tree-sitter (Python, JavaScript, TypeScript, Java), which "
                "needs the 'symbols' extra; a finding whose file cannot be "
                "parsed never matches."
            ),
        ),
    ] = None

    @field_validator("line_end")
    @classmethod
    def validate_line_range(cls, v, values):
        """Validate that line_end is greater than or equal to line_start if both are provided."""
        if (
            v is not None
            and hasattr(values, "data")
            and values.data is not None
            and values.data.get("line_start") is not None
            and v < values.data["line_start"]
        ):
            raise ValueError("line_end must be greater than or equal to line_start")
        return v

    @field_validator("package_name", "package_version", "package_path")
    @classmethod
    def validate_package_field_not_blank(cls, v):
        """Reject a blank package field: it reads as "any" but would match nothing."""
        if v is not None and not v.strip():
            raise ValueError(
                "package_name, package_version and package_path must be omitted "
                "rather than left blank"
            )
        return v

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id_not_blank(cls, v, info: ValidationInfo):
        """Reject a blank rule_id.

        An omitted ``rule_id`` matches every rule in the suppression's path, as the
        suppressions guide says. A blank one was accepted and read the same way
        by ``matches`` (an empty string is false there), so a suppression whose
        rule id was left empty by mistake silently covered every rule in its
        path; a whitespace-only one matched nothing at all. Both are refused
        with what to write, as the package fields are.

        Under the TOLERATE_STORED_CONFIG context (utils/unknown_keys.py) a blank
        rule id a results file recorded, written before this check, is kept and
        noted rather than refused: refusing it made the whole results file
        unreadable to ``ash report``, ``ash merge`` and ``--existing-results``.
        ``matches`` never applies such an entry.
        """
        if v is not None and not v.strip():
            notes = tolerated_notes(info)
            if notes is not None:
                notes.append(BLANK_RULE_ID_NOTE)
                return v
            raise ValueError(
                "rule_id must be omitted rather than left blank: a suppression "
                "with no rule_id covers every rule in its path"
            )
        return v

    @field_validator("symbol", mode="before")
    @classmethod
    def validate_symbol(cls, v, info: ValidationInfo):
        """Reject a symbol that is not a dotted qualified name.

        A malformed name could never equal a parsed definition's name, so the
        entry would silently match nothing. Before the field's own ``str`` check,
        so a number gets this message too, not pydantic's string error. The rule
        alone, for text and for anything else: the value is not quoted.

        Under the TOLERATE_STORED_CONFIG context (utils/unknown_keys.py) a
        symbol a results file recorded as the environment reference its config
        wrote (``${VAR}``) is kept and noted rather than refused: the scan read
        the reference, the record stores it, and refusing it made the scan's
        own results file unreadable. ``matches`` never applies such an entry.
        """
        if v is None:
            return v
        if isinstance(v, str) and not is_valid_symbol(v):
            notes = tolerated_notes(info)
            if notes is not None and _is_environment_reference(v):
                notes.append(UNREADABLE_SYMBOL_NOTE)
                return v
        if not isinstance(v, str) or not is_valid_symbol(v):
            raise ValueError(SYMBOL_RULE)
        return v

    @property
    def id(self) -> str:
        """Stable identifier derived from ``path|rule_id|line_start|line_end``.

        Unspecified rule_id is rendered as ``*``. When ``line_end`` is None,
        ``line_start`` is reused to match how suppressions are indexed elsewhere
        in the codebase.

        A suppression that sets any package field gets a fifth part,
        ``name@version@path`` with ``*`` for each unset piece, so two entries
        that differ only by package do not share an id. Entries without
        package fields keep the four-part id they always had.

        A suppression that sets ``symbol`` gets that fifth part (``*@*@*``
        when no package field is set) and the symbol as a sixth. Entries
        without a symbol keep the id they had before the field existed.
        """
        return suppression_id(self.model_dump())

    def matches_path(self, file_path: str) -> bool:
        """Return True if ``file_path`` matches this suppression's path pattern.

        As ``matches`` reads the path: unlike an ignore path's, one ending in ``/``
        is not read as its directory, so it matches no file.
        """
        return _path_pattern_matches(file_path, self.path)

    def matches(
        self,
        finding: "FlatVulnerability",
        symbol_resolver: "SymbolResolver | None" = None,
    ) -> bool:
        """Return True if ``finding`` is covered by this suppression rule.

        Checks rule_id (exact or glob), path (supports ``**``), optional line
        range overlap, the optional package fields, and the optional symbol.
        Expired suppressions never match.

        Each package field that is set must match the finding's corresponding
        field. A finding that does not carry that field does not match: the
        scanner could not say which package it is about, so a package-scoped
        suppression must not assume it is the one intended.

        A symbol is checked last, so a file is parsed only for a finding that
        every other field already matches. It needs ``symbol_resolver``, which
        reads the scanned source; without one a symbol-scoped suppression
        matches nothing, and so does a finding with no line number or in a
        file the resolver cannot parse.
        """
        if self.is_expired or self.has_unknown_keys:
            return False
        # A symbol kept from a results file as the environment reference its
        # config wrote (validate_symbol under the tolerance) names no definition,
        # so the entry does not apply, as the load warning says.
        if self.symbol is not None and not is_valid_symbol(self.symbol):
            return False
        # A blank rule id kept from a results file (validate_rule_id_not_blank
        # under the tolerance) names no rule and is not "any rule" either: the
        # entry does not apply, as the load warning says.
        if self.rule_id is not None and not self.rule_id.strip():
            return False

        if self.rule_id:
            if finding.rule_id is None:
                return False
            # The finding's exact rule id first, then the case-insensitive glob.
            # fnmatch reads '[' as a character class, so a suppression saved
            # for a rule id that holds glob characters (cdk-nag's granular
            # 'Rule[Resource::*]' ids, as the TUI saves them) never matched the
            # finding it was saved for through the glob alone.
            if finding.rule_id.lower() != self.rule_id.lower() and not fnmatch.fnmatch(
                finding.rule_id.lower(), self.rule_id.lower()
            ):
                return False

        if not _path_pattern_matches(finding.file_path, self.path):
            return False

        if not self._line_range_matches(finding):
            return False

        if not self._package_matches(finding):
            return False

        if self.symbol is not None:
            if symbol_resolver is None:
                return False
            return symbol_resolver.contains(
                finding.file_path, finding.line_start, finding.line_end, self.symbol
            )

        return True

    def _package_matches(self, finding: "FlatVulnerability") -> bool:
        """Return True if every package field set here matches ``finding``."""
        for pattern, value in (
            (self.package_name, finding.package_name),
            (self.package_version, finding.package_version),
        ):
            if pattern is None:
                continue
            if value is None or not fnmatch.fnmatch(value.lower(), pattern.lower()):
                return False
        if self.package_path is not None:
            if finding.package_path is None:
                return False
            if not _path_pattern_matches(finding.package_path, self.package_path):
                return False
        return True

    def _line_range_matches(self, finding: "FlatVulnerability") -> bool:
        """Return True if ``finding``'s line range overlaps with this suppression."""
        if self.line_start is None and self.line_end is None:
            return True

        if finding.line_start is None:
            return False

        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )

        if self.line_start is not None and self.line_end is None:
            return finding_end >= self.line_start

        if self.line_start is None and self.line_end is not None:
            return finding_end <= self.line_end

        finding_start = finding.line_start
        return (finding_start <= (self.line_end or 0)) and (
            finding_end >= (self.line_start or 0)
        )
