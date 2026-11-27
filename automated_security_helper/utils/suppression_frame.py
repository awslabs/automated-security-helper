# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The frame layer under suppression predicate matching.

``AshSuppression.matches`` and ``suppression_matcher.should_suppress_finding``
are thin entry points over :func:`first_match`. A finding is checked against a
list of suppressions as a frame with one row per suppression and one column per
predicate; the first row whose columns all hold is the match.

What is a frame expression and what is not, and why:

* The line-range overlap and the conjunction of the predicate columns are
  polars expressions. Line numbers are rank-encoded first (see
  :func:`~automated_security_helper.utils.frame_text.ranks`), because they are
  unbounded Python ints and a frame column is 64-bit; every comparison the
  overlap makes is on order alone. That policy lives on the model:
  ``AshSuppression.line_start``/``line_end`` carry ``RankEncoded("lines")``
  markers, and the ``line_start``/``line_end`` columns here derive from
  :func:`line_span_spec`, so the frames and the model cannot disagree about
  the columns' names, dtypes or carrying rule. The rank collection of one
  build is the entries' lines plus the finding's, and is relative to that
  build alone.
* Every string predicate (rule id, path, package, resource glob) is a Python
  callable per row, not a frame expression. They are ``fnmatch`` and
  ``path_matching`` semantics (``[`` classes, ``**`` components, a backslash
  that is a separator) that Rust regex cannot reproduce byte for byte, and a
  path can hold an unpaired surrogate, which a frame's UTF-8 string column
  refuses. So no string enters a frame: the callables return booleans and the
  frame carries those.
* The three predicates with a side effect (the engine plugin's rule-id split
  and its scope-block hook, and the symbol resolver) are Python and run in list
  order, only for a row whose cheaper columns already hold, and stop at the
  first match. A plugin hook is called, and a symbol file parsed, for exactly
  the entries the one-pair-at-a-time check reached, and for no entry after the
  match.
* Entries are read in chunks that grow (16, then 64, ...), not all at once, so
  a finding that the first entry covers does not evaluate a thousand globs.
"""

from __future__ import annotations

import fnmatch
from functools import lru_cache
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from automated_security_helper.utils import frame_text
from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
    has_glob_syntax,
)
from automated_security_helper.utils.suppression_scope_registry import (
    engine_hooks_for,
    split_rule_qualifier_for,
    warn_once_unmatched_engine,
)
from automated_security_helper.utils.symbol_spans import is_valid_symbol

if TYPE_CHECKING:
    import polars as pl

    from automated_security_helper.models.core import AshSuppression
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability
    from automated_security_helper.models.frame_model import FrameSpec
    from automated_security_helper.utils.symbol_spans import SymbolResolver

_FIRST_CHUNK = 16
_CHUNK_GROWTH = 4


@lru_cache(maxsize=None)
def line_span_spec() -> "FrameSpec":
    """The spec the ``line_start``/``line_end`` columns derive from.

    Built lazily: ``models/core.py`` imports this module, so the model and the
    spec machinery cannot be imported here at module level. Every other name
    ``AshSuppression`` holds is waived with its reason, so the drift gate
    (``tests/unit/models/test_frame_schemas.py``) fails on a field added to the
    model until someone decides its frame fate.
    """
    from automated_security_helper.models.core import AshSuppression
    from automated_security_helper.models.frame_model import FrameSpec

    host_predicate = (
        "a Python predicate per row (fnmatch and path semantics the module "
        "docstring names), carried only as a boolean result column"
    )
    return FrameSpec(
        AshSuppression,
        ("line_start", "line_end"),
        waived={
            "path": host_predicate,
            "rule_id": host_predicate + " (the rule column)",
            "package_name": host_predicate + " (part of the rest column)",
            "package_version": host_predicate + " (part of the rest column)",
            "package_path": host_predicate + " (part of the rest column)",
            "image": "gated on the host (_image_holds), a glob over the finding's "
            "image reference and digest; never a column",
            "scope": "gated on the host (_scope_gate), carried as the rest "
            "and engine columns",
            "resource_id": "sugar folded into scope at validation; gated with it",
            "symbol": "resolved by the symbol resolver after the frame; never a column",
            "reason": "display text for the unused-suppressions report, not a "
            "matcher input",
            "client_supplied": "provenance bookkeeping read on the host (which "
            "entries an MCP client delivered), not a matcher input",
            "expires": "read on the host by is_expired, which the live column carries",
            "is_expired": "an input of the live column's predicate (_inert)",
            "has_unknown_keys": "an input of the live column's predicate (_inert)",
            "expiration": "the deprecated spelling of expires, same fate",
            "days_until_expiry": "an expiry display helper over expires",
            "id": "the suppression's stable identifier for reports, not a "
            "matcher column",
            "_scope_conflict": "an input of the scope gate on the host",
            "_environment_record": "config-redaction bookkeeping "
            "(RedactedSection), not frame data",
        },
    )


def _span_schema() -> Dict[str, Any]:
    """``line_start``/``line_end`` as polars dtypes, derived from the spec."""
    from automated_security_helper.models.frame_model import frame_schema

    return frame_schema(line_span_spec())


def _span_frame(
    starts: Sequence[Optional[int]], ends: Sequence[Optional[int]]
) -> "pl.DataFrame":
    """One row per entry: its line span, already rank-encoded by the caller."""
    import polars as pl

    return pl.DataFrame(
        {"line_start": list(starts), "line_end": list(ends)}, schema=_span_schema()
    )


def _inert(entry: "AshSuppression") -> bool:
    """An entry that applies to no finding whatever the finding says."""
    if entry.is_expired or entry.has_unknown_keys:
        return True
    # A symbol kept from a results file as the environment reference its config
    # wrote names no definition; a blank rule id names no rule and is not "any
    # rule" either. Neither applies, as the load warning says.
    if entry.symbol is not None and not is_valid_symbol(entry.symbol):
        return True
    return entry.rule_id is not None and not entry.rule_id.strip()


def _rule_columns(
    entry: "AshSuppression", finding: "FlatVulnerability"
) -> Tuple[bool, bool]:
    """``(rule holds, engine base id still to be read)`` for a live entry.

    The finding's id is compared with the entry's lowercased, equal or as a
    glob. A scoped entry that fails that may still cover a finding through the
    engine's BASE rule id; reading it calls the engine plugin, so it is left to
    the ordered walk (``_base_rule_matches``).
    """
    wanted = entry.rule_id
    if not wanted:
        return True, False
    if finding.rule_id is None:
        return False, False
    found, wanted = finding.rule_id.lower(), wanted.lower()
    if found == wanted or fnmatch.fnmatch(found, wanted):
        return True, False
    return False, entry.scope is not None


def _base_rule_matches(entry: "AshSuppression", finding: "FlatVulnerability") -> bool:
    """Whether the entry's rule id names the base of a qualified engine id."""
    # Both ids are set here: _rule_columns only offers the base split for a
    # finding that has a rule id and an entry that names one.
    base, qualifier = split_rule_qualifier_for(finding.scanner, finding.rule_id or "")
    wanted = (entry.rule_id or "").lower()
    return qualifier is not None and (
        base.lower() == wanted or fnmatch.fnmatch(base.lower(), wanted)
    )


def _package_holds(entry: "AshSuppression", finding: "FlatVulnerability") -> bool:
    """Every package field set on the entry matches the finding's; a finding that
    does not carry the field never matches."""
    for pattern, value in (
        (entry.package_name, finding.package_name),
        (entry.package_version, finding.package_version),
    ):
        if pattern is None:
            continue
        if value is None or not fnmatch.fnmatch(value.lower(), pattern.lower()):
            return False
    if entry.package_path is not None:
        if finding.package_path is None:
            return False
        # package_path separates two installed copies, so it is an identity,
        # not a scope: the bare-directory rule (issue #894) must not make a
        # glob-free entry cover packages nested below the copy it names.
        if _path_pattern_matches(
            finding.package_path, entry.package_path, bare_directory=False
        ):
            return True
        return _names_the_copy_with_a_trailing_slash(
            finding.package_path, entry.package_path
        )
    return True


def _names_the_copy_with_a_trailing_slash(finding_path: str, pattern: str) -> bool:
    """A glob-free ``package_path`` also names the copy when the finding spells
    that same copy's path with trailing slashes (``node_modules/a/`` for
    ``node_modules/a``). Only the slashes: a path below the copy, or another name
    that starts the same (``node_modules/ab/``), is not the copy."""
    stripped = finding_path.rstrip("/")
    directory = pattern.rstrip("/\\")
    if stripped == finding_path or not directory or has_glob_syntax(pattern):
        return False
    return _path_pattern_matches(stripped, directory, bare_directory=False)


def _image_holds(entry: "AshSuppression", finding: "FlatVulnerability") -> bool:
    """An entry with no ``image`` holds for any finding. One that names an image
    holds only for a finding inside an image whose submitted reference or
    resolved digest matches the pattern (case-insensitive glob); a finding that
    carries no image never matches it, as a finding without a package never
    matches a package field."""
    pattern = getattr(entry, "image", None)
    if pattern is None:
        return True
    wanted = pattern.lower()
    return any(
        value is not None and fnmatch.fnmatch(value.lower(), wanted)
        for value in (finding.image_ref, finding.image_digest)
    )


def _scope_gate(
    entry: "AshSuppression", finding: "FlatVulnerability"
) -> Tuple[bool, bool]:
    """``(the scope holds so far, an engine block must still be asked)``.

    A scope fails closed on every gap: one that selects nothing or kept unknown
    keys matches nothing, and a resource key never matches a finding that
    carries no such value. ``engines`` enumerates the covered scanners.
    """
    from automated_security_helper.models.core import scope_value_matches

    if entry._scope_conflict:
        return False, False
    scope = entry.scope
    if scope is None:
        return True, False
    if scope.selects_nothing or scope.has_unknown_keys:
        return False, False
    if scope.resource_id is not None:
        if finding.resource_id is None or not scope_value_matches(
            finding.resource_id, scope.resource_id, case_sensitive=True
        ):
            return False, False
    if scope.resource_type is not None:
        if finding.resource_type is None or not scope_value_matches(
            finding.resource_type, scope.resource_type, case_sensitive=False
        ):
            return False, False
    if scope.engines is not None:
        if finding.scanner is None or finding.scanner not in scope.engines:
            return False, False
        return True, True
    return True, False


def _engine_block_matches(
    entry: "AshSuppression",
    finding: "FlatVulnerability",
    warned_engines: Optional[Set[str]],
) -> bool:
    """Whether the finding's scanner plugin accepts the entry's block for it.

    Fails closed, with a warn-once note naming the engine, when no plugin is
    registered for the scanner.
    """
    # _scope_gate asks for a block only when the scope lists the scanner.
    engines = entry.scope.engines if entry.scope is not None else None
    scanner = finding.scanner
    if engines is None or scanner is None:
        return False
    hooks = engine_hooks_for(scanner)
    if hooks is None:
        warn_once_unmatched_engine(scanner, warned_engines)
        return False
    return hooks.suppression_scope_matches(engines[scanner], finding)


def _line_ok(finding: "FlatVulnerability", ranks: Dict[int, int]) -> "pl.Expr":
    """The overlap as an expression over the ``line_start``/``line_end`` columns.

    The columns hold dense ranks (the ``RankEncoded`` markers on the model), so
    every comparison is on order alone. No entry range: any line. An entry
    range and a finding without a line: never. A start alone is open-ended
    (the finding's end reaches it), an end alone bounds the finding's end, both
    mean overlap. A finding with no end is a one-line finding.
    """
    import polars as pl

    s, e = pl.col("line_start"), pl.col("line_end")
    unbounded = s.is_null() & e.is_null()
    if finding.line_start is None:
        return unbounded
    start = pl.lit(ranks[finding.line_start], dtype=pl.Int64)
    end_value = finding.line_end if finding.line_end is not None else finding.line_start
    end = pl.lit(ranks[end_value], dtype=pl.Int64)
    return (
        pl.when(unbounded)
        .then(pl.lit(True))
        .when(e.is_null())
        .then(end >= s)
        .when(s.is_null())
        .then(end <= e)
        .otherwise((start <= e) & (end >= s))
    )


def line_range_overlaps(
    finding: "FlatVulnerability", entries: Sequence["AshSuppression"]
) -> List[bool]:
    """Per entry, whether the finding's line range overlaps the entry's."""
    ranks = frame_text.ranks(
        [finding.line_start, finding.line_end]
        + [v for e in entries for v in (e.line_start, e.line_end)]
    )
    frame = _span_frame(
        [None if e.line_start is None else ranks[e.line_start] for e in entries],
        [None if e.line_end is None else ranks[e.line_end] for e in entries],
    )
    return frame.select(_line_ok(finding, ranks).alias("ok"))["ok"].to_list()


def _chunk_frame(
    finding: "FlatVulnerability", chunk: Sequence["AshSuppression"]
) -> "pl.DataFrame":
    """One row per entry: the predicate columns that have no side effect."""
    import polars as pl

    live, rule, base, rest, engine = [], [], [], [], []
    for entry in chunk:
        is_live = not _inert(entry)
        holds, base_pending, gate_ok, needs_engine = is_live, False, False, False
        if is_live:
            holds, base_pending = _rule_columns(entry, finding)
            # Short-circuits in the order the checks have always run in, so a
            # glob is not read for an entry the rule id already rules out.
            if holds or base_pending:
                gate_ok = _path_pattern_matches(finding.file_path, entry.path)
                gate_ok = gate_ok and _package_holds(entry, finding)
                gate_ok = gate_ok and _image_holds(entry, finding)
                if gate_ok:
                    gate_ok, needs_engine = _scope_gate(entry, finding)
        live.append(is_live)
        rule.append(holds)
        base.append(base_pending)
        rest.append(gate_ok)
        engine.append(needs_engine)
    # Lines are read only for an entry every earlier column already holds for, as
    # the one-pair check read them: a finding that is never asked about its lines
    # (every entry inert, or ruled out by rule id, path, package or scope) need
    # not carry any.
    reached = rest
    ranks = frame_text.ranks(
        ([finding.line_start, finding.line_end] if any(reached) else [])
        + [v for e, r in zip(chunk, reached) if r for v in (e.line_start, e.line_end)]
    )
    # The predicate columns are results of host predicates, not model fields,
    # so they stay hand-declared; the line columns derive from the spec.
    frame = pl.DataFrame(
        {
            "live": live,
            "rule": rule,
            "base": base,
            "rest": rest,
            "engine": engine,
            "line_start": [
                ranks[e.line_start] if r and e.line_start is not None else None
                for e, r in zip(chunk, reached)
            ],
            "line_end": [
                ranks[e.line_end] if r and e.line_end is not None else None
                for e, r in zip(chunk, reached)
            ],
        },
        schema={
            "live": pl.Boolean,
            "rule": pl.Boolean,
            "base": pl.Boolean,
            "rest": pl.Boolean,
            "engine": pl.Boolean,
            **_span_schema(),
        },
    )
    lines_hold = _line_ok(finding, ranks) if any(reached) else pl.lit(False)
    return frame.with_columns(
        (pl.col("live") & pl.col("rest") & lines_hold).alias("static_ok")
    )


def first_match(
    finding: "FlatVulnerability",
    entries: Sequence["AshSuppression"],
    *,
    symbol_resolver: "Optional[SymbolResolver]" = None,
    warned_engines: Optional[Set[str]] = None,
    skip: Optional[Callable[[int, "AshSuppression"], bool]] = None,
) -> Optional[int]:
    """The index of the first entry that covers ``finding``, or None.

    ``skip`` is asked about every entry in order, up to the match, before the
    entry is read (``should_suppress_finding`` warns about an expired or
    unreadable entry there); an entry it skips is never matched.

    A symbol is asked last, so a file is parsed only for a finding that every
    other column already holds for; without a resolver a symbol-scoped entry
    matches nothing.

    Once a match is found nothing after it is read, called or warned about.
    """
    start, size = 0, _FIRST_CHUNK
    while start < len(entries):
        chunk = entries[start : start + size]
        frame = _chunk_frame(finding, chunk)
        columns = frame.to_dict(as_series=False)
        for offset, entry in enumerate(chunk):
            index = start + offset
            if skip is not None and skip(index, entry):
                continue
            if not columns["live"][offset]:
                continue
            if not columns["rule"][offset]:
                if not (columns["base"][offset] and _base_rule_matches(entry, finding)):
                    continue
            if not columns["static_ok"][offset]:
                continue
            if columns["engine"][offset] and not _engine_block_matches(
                entry, finding, warned_engines
            ):
                continue
            if entry.symbol is None:
                return index
            if symbol_resolver is not None and symbol_resolver.contains(
                finding.file_path, finding.line_start, finding.line_end, entry.symbol
            ):
                return index
        start += size
        size *= _CHUNK_GROWTH
    return None


def matches(
    entry: "AshSuppression",
    finding: "FlatVulnerability",
    symbol_resolver: "Optional[SymbolResolver]" = None,
    warned_engines: Optional[Set[str]] = None,
) -> bool:
    """Whether ``entry`` covers ``finding``: ``first_match`` over one entry."""
    return (
        first_match(
            finding,
            [entry],
            symbol_resolver=symbol_resolver,
            warned_engines=warned_engines,
        )
        is not None
    )


def _first_true(flags: Sequence[bool]) -> Optional[int]:
    """The index of the first True of ``flags``, decided by a frame."""
    import polars as pl

    frame = pl.DataFrame({"hit": list(flags)}, schema={"hit": pl.Boolean})
    first = frame.with_row_index("i").filter(pl.col("hit"))["i"].head(1).to_list()
    return first[0] if first else None


def first_ignore_path(
    path: Optional[str],
    ignore_paths: Sequence[Any],
    matches: Callable[[Optional[str], str], bool],
) -> Optional[int]:
    """The index of the first ignore path ``path`` is under, or None.

    ``matches`` is the string predicate (``ignore_path_matches``): glob and path
    semantics that stay Python, as for a suppression, and it is asked in list
    order only up to the entry that holds, so an entry after the match is never
    read. The frame carries the booleans it returned and picks the first.
    """
    flags: List[bool] = []
    for ignore_path in ignore_paths:
        held = bool(matches(path, ignore_path.path))
        flags.append(held)
        if held:
            break
    return _first_true(flags)


def ignore_verdict(
    client_flags: Sequence[bool], located: int
) -> Tuple[bool, Optional[int]]:
    """``(drop the result, index of the client-supplied match to mark it by)``.

    ``located`` is how many of a result's locations name a file;
    ``client_flags`` holds one entry per location an ignore path matched, in
    location order, True for a client-supplied path. A result is dropped when
    every located location is under an ignore path and none of those paths is
    the client's; when every one is under an ignore path and some is the
    client's, the result is kept and marked by the LAST such path; otherwise
    (some location is outside every ignore path) it is left as it is.
    """
    import polars as pl

    frame = pl.DataFrame({"client": list(client_flags)}, schema={"client": pl.Boolean})
    under = frame.height
    all_under = located > 0 and under == located
    clients = frame.with_row_index("i").filter(pl.col("client"))["i"].to_list()
    drop = all_under and not clients
    return drop, (clients[-1] if (all_under and clients) else None)


__all__: List[str] = [
    "first_ignore_path",
    "ignore_verdict",
    "first_match",
    "line_range_overlaps",
    "line_span_spec",
    "matches",
]
