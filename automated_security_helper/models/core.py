# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from __future__ import annotations

import fnmatch
from typing import (
    Any,
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
    field_validator,
    model_validator,
)
from datetime import datetime, date

from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
    ignore_path_pattern,
)
from automated_security_helper.utils.symbol_spans import is_valid_symbol

if TYPE_CHECKING:
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability
    from automated_security_helper.utils.symbol_spans import SymbolResolver


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


class IgnorePathWithReason(BaseModel):
    """Represents a path exclusion entry."""

    # Validated on its own from a config or a results file: a refused value can
    # be a secret, and an error's text goes wherever the error is shown.
    model_config = ConfigDict(hide_input_in_errors=True)

    path: Annotated[str, Field(..., description="Path or pattern to exclude")]
    reason: Annotated[str, Field(..., description="Reason for exclusion")]
    expiration: Annotated[
        str | None, Field(None, description="(Optional) Expiration date (YYYY-MM-DD)")
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

    def matches_path(self, file_path: str) -> bool:
        """Return True if ``file_path`` matches this entry's path pattern.

        Supports exact matches, simple globs (``*.py``), and recursive globs
        (``tests/**/*.py``). Matching is case-insensitive for OS portability. A
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
    line_start = suppression.get("line_start")
    line_end = suppression.get("line_end")
    line_end_val = line_end if line_end is not None else line_start
    parts = [
        suppression.get("path") or "",
        suppression.get("rule_id") or "*",
        str(line_start) if line_start is not None else "*",
        str(line_end_val) if line_end_val is not None else "*",
    ]
    symbol = suppression.get("symbol")
    if symbol or any(suppression.get(f) for f in PACKAGE_SUPPRESSION_FIELDS):
        parts.append(
            "@".join(suppression.get(f) or "*" for f in PACKAGE_SUPPRESSION_FIELDS)
        )
    # A symbol is a sixth part, and its presence always brings the fifth, so an
    # id's part count says which fields it carries and a symbol can never be
    # read as a package.
    if symbol:
        parts.append(symbol)
    return "|".join(parts)


class AshSuppression(IgnorePathWithReason):
    """Represents a finding suppression rule."""

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

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, v):
        """Reject a symbol that is not a dotted qualified name.

        A malformed name could never equal a parsed definition's name, so the
        entry would silently match nothing.
        """
        if v is not None and not is_valid_symbol(v):
            # The rule, not the value: a value can be one read from the
            # environment, and the message goes wherever the error is shown.
            raise ValueError(
                "symbol must be a dotted qualified name such as "
                "'MyClass.my_method' (identifiers joined by '.', no spaces, "
                "wildcards or call syntax)"
            )
        return v

    @field_validator("expiration")
    @classmethod
    def validate_expiration_date(cls, v):
        """Validate that expiration date is in YYYY-MM-DD format.

        Past dates are accepted; use is_expired to check whether the
        suppression has expired at runtime.
        """
        if v is not None:
            try:
                datetime.strptime(v, "%Y-%m-%d")
            except ValueError:
                # Not the value, as for symbol; from None so strptime's message,
                # which quotes it, is not the context either.
                raise ValueError(
                    "Invalid expiration date format. Use YYYY-MM-DD"
                ) from None
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

    @property
    def is_expired(self) -> bool:
        """Return True if this suppression has a past expiration date."""
        if not self.expiration:
            return False
        try:
            expiration_date = datetime.strptime(self.expiration, "%Y-%m-%d").date()
        except ValueError:
            return False
        return expiration_date <= date.today()

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Days from today until expiration; None if no expiration is set.

        A negative value indicates the suppression has already expired.
        """
        if not self.expiration:
            return None
        try:
            expiration_date = datetime.strptime(self.expiration, "%Y-%m-%d").date()
        except ValueError:
            return None
        return (expiration_date - date.today()).days

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
        if self.is_expired:
            return False

        if self.rule_id:
            if finding.rule_id is None:
                return False
            # Case-insensitive glob match for OS portability
            if not fnmatch.fnmatch(finding.rule_id.lower(), self.rule_id.lower()):
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
