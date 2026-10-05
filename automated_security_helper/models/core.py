# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Annotated, Optional, TYPE_CHECKING
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime, date

from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
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

    path: Annotated[str, Field(..., description="Path or pattern to exclude")]
    reason: Annotated[str, Field(..., description="Reason for exclusion")]
    expiration: Annotated[
        str | None, Field(None, description="(Optional) Expiration date (YYYY-MM-DD)")
    ] = None

    def matches_path(self, file_path: str) -> bool:
        """Return True if ``file_path`` matches this entry's path pattern.

        Supports exact matches, simple globs (``*.py``), and recursive globs
        (``tests/**/*.py``). Matching is case-insensitive for OS portability.
        """
        return _path_pattern_matches(file_path, self.path)


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
            raise ValueError(
                f"symbol must be a dotted qualified name such as "
                f"'MyClass.my_method' (identifiers joined by '.', no spaces, "
                f"wildcards or call syntax): {v!r}"
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
                raise ValueError(f"Invalid expiration date format. Use YYYY-MM-DD: {v}")
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
