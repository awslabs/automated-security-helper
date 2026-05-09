# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from __future__ import annotations

import fnmatch
import re
from typing import List, Annotated, Optional, TYPE_CHECKING
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime, date

if TYPE_CHECKING:
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


def _recursive_glob_match(path: str, pattern: str) -> bool:
    """Match ``path`` against ``pattern`` treating ``**`` as zero-or-more directories."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")

    segments = re.split(r"/?\*\*/?", pattern)
    has_trailing_star = pattern.rstrip("/").endswith("**")
    has_leading_star = pattern.lstrip("/").startswith("**")
    segments = [s for s in segments if s]

    if not segments:
        return True

    if len(segments) == 1 and has_leading_star and has_trailing_star:
        middle = segments[0]
        parts = path.split("/")
        seg_parts = middle.split("/")
        seg_len = len(seg_parts)
        for j in range(len(parts) - seg_len + 1):
            candidate = "/".join(parts[j : j + seg_len])
            if fnmatch.fnmatch(candidate, middle):
                return True
        return False

    if len(segments) == 1 and has_trailing_star and not has_leading_star:
        prefix = segments[0]
        parts = path.split("/")
        seg_parts = prefix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return False
        candidate = "/".join(parts[:seg_len])
        return fnmatch.fnmatch(candidate, prefix)

    if len(segments) == 1 and has_leading_star and not has_trailing_star:
        suffix = segments[0]
        parts = path.split("/")
        seg_parts = suffix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return fnmatch.fnmatch(path, suffix)
        candidate = "/".join(parts[-seg_len:])
        return fnmatch.fnmatch(candidate, suffix)

    remaining = path
    for i, segment in enumerate(segments):
        if not segment:
            continue

        is_first = i == 0
        is_last = i == len(segments) - 1

        if is_first and is_last:
            return fnmatch.fnmatch(remaining, segment)

        if is_first:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            prefix = "/".join(parts[:seg_len])
            if not fnmatch.fnmatch(prefix, segment):
                return False
            remaining = "/".join(parts[seg_len:])
        elif is_last:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            suffix = "/".join(parts[-seg_len:]) if seg_len <= len(parts) else remaining
            return fnmatch.fnmatch(suffix, segment)
        else:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            found = False
            for j in range(len(parts) - seg_len + 1):
                candidate = "/".join(parts[j : j + seg_len])
                if fnmatch.fnmatch(candidate, segment):
                    remaining = "/".join(parts[j + seg_len :])
                    found = True
                    break
            if not found:
                return False

    return True


def _path_pattern_matches(file_path: Optional[str], pattern: str) -> bool:
    """Case-insensitive path match supporting ``**`` recursive globs."""
    if file_path is None:
        return False

    finding_lower = file_path.lower()
    pattern_lower = pattern.lower()

    if finding_lower == pattern_lower:
        return True

    if "**" in pattern_lower:
        return _recursive_glob_match(finding_lower, pattern_lower)

    return fnmatch.fnmatch(finding_lower, pattern_lower)


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
                raise ValueError(
                    f"Invalid expiration date format. Use YYYY-MM-DD: {v}"
                )
        return v

    @property
    def id(self) -> str:
        """Stable identifier derived from ``path|rule_id|line_start|line_end``.

        Unspecified rule_id is rendered as ``*``. When ``line_end`` is None,
        ``line_start`` is reused to match how suppressions are indexed elsewhere
        in the codebase.
        """
        line_end_val = (
            self.line_end if self.line_end is not None else self.line_start
        )
        parts = [
            self.path,
            self.rule_id or "*",
            str(self.line_start) if self.line_start is not None else "*",
            str(line_end_val) if line_end_val is not None else "*",
        ]
        return "|".join(parts)

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

    def matches(self, finding: "FlatVulnerability") -> bool:
        """Return True if ``finding`` is covered by this suppression rule.

        Checks rule_id (exact or glob), path (supports ``**``), and optional
        line range overlap. Expired suppressions never match.
        """
        if self.is_expired:
            return False

        if self.rule_id:
            if finding.rule_id is None:
                return False
            # Case-insensitive glob match for OS portability
            if not fnmatch.fnmatch(
                finding.rule_id.lower(), self.rule_id.lower()
            ):
                return False

        if not _path_pattern_matches(finding.file_path, self.path):
            return False

        if not self._line_range_matches(finding):
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
