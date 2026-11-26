# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Polars frame schemas derived from the pydantic models they project.

Internal to the package: no plugin or documentation surface consumes it.

A frame layer projects rows out of a model we author into a polars schema. Written
by hand, the schema, its docstring table and the test that pins it are three
copies of one fact, and the per-field carrying rules (text goes through
:func:`~automated_security_helper.utils.frame_text.wire`, an unbounded line number
is a rank or a null plus a flag) live in each builder's head. Here they live on
the field, as ``Annotated`` markers pydantic ignores:

* :class:`WireText` / :class:`RawText`: a String column is wired by default, and
  ``RawText`` opts a column that is proven ASCII-constant out of it.
* :class:`OverflowNullable`: an Int64 column where a value outside 64 bits is null
  and sets a companion Boolean column.
* :class:`RankEncoded`: an Int64 column holding the dense rank of the value among
  the group's values over the collection given to :func:`to_frame`. A rank is
  relative to that one build: it joins and sorts only against columns of the same
  build, never across frames.
* :class:`EnumColumn`: the field's closed vocabulary. The column is a polars
  ``Enum`` of it, so a value outside the vocabulary raises
  :class:`FrameSpecError` at frame build.
* :class:`NotInFrame`: the field never becomes a column.

A frame is never wholly derivable (a private attribute, a property, a position
and a lower-cased key are not fields), so the unit of derivation is a
:class:`FrameSpec`: the ordered columns, each a model field named by string or a
declared :class:`Computed` / :class:`Position` / :class:`Ranked` entry.
Properties and private attributes are declared, never derived: a ``Computed``
names what it ``reads``. A :class:`Ranked` entry projects an int field under
THIS frame's rank policy when the field's own marker carries another site's
(one unbounded-int shape, two encodings, chosen per site: the flat frame nulls
an overflowing line and flags it, the diff side compares order alone).

The boundary rule: pydantic validates at ingest and egress only. :func:`to_frame`
reads attributes of instances the boundary already validated, never
``model_validate`` or ``model_dump`` per row, and no helper rebuilds a model from
a row. A consumer that needs the rich object reads it from its own list by the
position column.

:func:`unaccounted` is the drift gate's rule: every model field must be projected,
marked :class:`NotInFrame` or waived with a note, and every private attribute and
public property must be read by a ``Computed`` or waived with a note, so a field
added to a model fails the gate until someone decides its frame fate.

Polars is imported when a schema or a frame is built, not when a spec is declared,
so declaring one costs an import of nothing but pydantic.
"""

from __future__ import annotations

import types
import typing
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.utils.frame_text import ranks, wire

if TYPE_CHECKING:
    import polars as pl
    from pydantic import BaseModel

DTypeName = Literal["Int64", "String", "Boolean"]

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class FrameSpecError(ValueError):
    """A spec that cannot derive a frame, or a model the drift gate refuses."""


@dataclass(frozen=True)
class WireText:
    """The String column's cells go through ``wire`` (the default for a ``str``)."""


@dataclass(frozen=True)
class RawText:
    """The String column's cells are written as they are.

    Only for a column proven ASCII-constant (severity labels, outcome words):
    ``wire`` is the identity on ASCII, so the opt-out saves nothing it could break.
    """


@dataclass(frozen=True)
class OverflowNullable:
    """An Int64 column where a value outside 64 bits is null, with ``flag`` set.

    The companion Boolean column is named by ``flag``, shared by every field that
    names it, true on a row when any of them overflowed, and placed right after the
    last of those fields.
    """

    flag: str = "line_overflow"


@dataclass(frozen=True)
class RankEncoded:
    """An Int64 column of the dense rank of the value within ``group``.

    Ranks are taken over every value of every field of the group across the whole
    collection given to :func:`to_frame`; a null stays null. Collection-relative:
    never join or sort a rank column against another build's.
    """

    group: str = "lines"


@dataclass(frozen=True)
class EnumColumn:
    """The field's closed vocabulary, in order. The dtype is a polars ``Enum`` of it.

    The field is a ``str`` or a ``str``-mixin enum (the cell is the member's value).
    A cell outside the vocabulary raises :class:`FrameSpecError` at frame build.
    """

    values: Tuple[str, ...]


@dataclass(frozen=True)
class NotInFrame:
    """The field never becomes a column."""


@dataclass(frozen=True)
class Position:
    """The row's position in the collection given to :func:`to_frame` (Int64)."""

    name: str = "i"


@dataclass(frozen=True)
class Ranked:
    """A model int field projected as the dense rank of its value within ``group``.

    The per-site override of the field's own int policy: a field whose marker
    carries another frame's encoding (``line_start`` is overflow-nullable on the
    flat frame) is still projected here, as order alone, when this frame only
    ever compares and sorts it. Ranks are collection-relative exactly as
    :class:`RankEncoded` says; a null value stays a null rank, and no overflow
    flag column is appended.
    """

    name: str
    group: str = "lines"


@dataclass(frozen=True)
class Computed:
    """A column the model's fields cannot supply, declared.

    ``fn`` reads one model instance. A String result goes through ``wire`` unless
    ``raw``. ``reads`` names the model attributes, properties and private
    attributes ``fn`` depends on, which is what the drift gate accounts them by.
    """

    name: str
    dtype: DTypeName
    fn: Callable[[Any], Any]
    reads: Tuple[str, ...] = ()
    nullable: bool = True
    raw: bool = False
    note: str = ""


Entry = Union[str, Computed, Position, Ranked]


@dataclass(frozen=True, eq=False)
class FrameSpec:
    """One frame layer: a model and the ordered columns projected from it.

    ``columns`` is the frame's column order. A string is a model field, whose
    dtype and policy come from its annotation and markers; an
    :class:`OverflowNullable` flag column is appended right after the last field
    that names it and is not listed. ``waived`` maps a model field, private
    attribute or property name that the frame does not carry to the reason.
    """

    model: type[BaseModel]
    columns: Tuple[Entry, ...]
    waived: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _resolve(self)


@dataclass(frozen=True)
class ColumnInfo:
    """One derived column: where it comes from and the contract it carries."""

    name: str
    dtype: DTypeName
    nullable: bool
    source: str  # "field", "flag", "computed" or "position"
    raw: bool = False
    rank_group: Optional[str] = None
    overflow_flag: Optional[str] = None
    vocabulary: Optional[Tuple[str, ...]] = None


def _unwrap(annotation: Any) -> Tuple[Any, bool]:
    """*annotation* without ``Optional``, and whether it admitted ``None``."""
    origin = typing.get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        members = [m for m in typing.get_args(annotation) if m is not type(None)]
        nullable = len(members) != len(typing.get_args(annotation))
        if len(members) == 1:
            return members[0], nullable
        return annotation, nullable
    return annotation, False


def _marker(metadata: Iterable[Any], kind: type) -> Optional[Any]:
    found = [item for item in metadata if isinstance(item, kind)]
    return found[0] if found else None


def _is_str_enum(annotation: Any) -> bool:
    return (
        isinstance(annotation, type)
        and issubclass(annotation, str)
        and issubclass(annotation, Enum)
    )


def _field_column(model: type[BaseModel], name: str) -> ColumnInfo:
    info = model.model_fields.get(name)
    if info is None:
        raise FrameSpecError(f"{model.__name__}.{name} is not a model field")
    metadata = list(info.metadata)
    if _marker(metadata, NotInFrame) is not None:
        raise FrameSpecError(f"{model.__name__}.{name} is marked NotInFrame")
    base, optional = _unwrap(info.annotation)
    overflow = _marker(metadata, OverflowNullable)
    rank = _marker(metadata, RankEncoded)
    raw = _marker(metadata, RawText) is not None
    if raw and _marker(metadata, WireText) is not None:
        raise FrameSpecError(f"{model.__name__}.{name} is both RawText and WireText")
    vocabulary = _marker(metadata, EnumColumn)
    nullable = optional or info.default is None
    where = f"{model.__name__}.{name}"
    if base is bool:
        dtype: DTypeName = "Boolean"
    elif base is int:
        if overflow is None and rank is None:
            raise FrameSpecError(
                f"{where} is an unbounded int with no RankEncoded or "
                "OverflowNullable marker; a 64-bit column cannot hold it"
            )
        if overflow is not None and rank is not None:
            raise FrameSpecError(f"{where} is both OverflowNullable and RankEncoded")
        dtype = "Int64"
    elif base is str or _is_str_enum(base):
        dtype = "String"
    else:
        raise FrameSpecError(
            f"{where} has type {info.annotation!r}, which has no column; mark it "
            "NotInFrame or declare a Computed column"
        )
    if dtype != "Int64" and (overflow is not None or rank is not None):
        raise FrameSpecError(f"{where} carries an int marker on a {dtype} field")
    if dtype != "String" and (raw or vocabulary is not None):
        raise FrameSpecError(f"{where} carries a text marker on a {dtype} field")
    return ColumnInfo(
        name=name,
        dtype=dtype,
        nullable=nullable or overflow is not None,
        source="field",
        raw=raw,
        rank_group=None if rank is None else rank.group,
        overflow_flag=None if overflow is None else overflow.flag,
        vocabulary=None if vocabulary is None else tuple(vocabulary.values),
    )


def _ranked_column(model: type[BaseModel], entry: Ranked) -> ColumnInfo:
    info = model.model_fields.get(entry.name)
    if info is None:
        raise FrameSpecError(f"{model.__name__}.{entry.name} is not a model field")
    if _marker(info.metadata, NotInFrame) is not None:
        raise FrameSpecError(f"{model.__name__}.{entry.name} is marked NotInFrame")
    base, optional = _unwrap(info.annotation)
    if base is not int:
        raise FrameSpecError(
            f"Ranked({entry.name!r}) projects {model.__name__}.{entry.name} of "
            f"type {info.annotation!r}; only an int field has a rank"
        )
    return ColumnInfo(
        name=entry.name,
        dtype="Int64",
        nullable=optional or info.default is None,
        source="field",
        rank_group=entry.group,
    )


def _resolve(spec: FrameSpec) -> Tuple[ColumnInfo, ...]:
    cached = _RESOLVED.get(id(spec))
    if cached is not None and cached[0] is spec:
        return cached[1]
    model = spec.model
    entries: List[Tuple[ColumnInfo, Entry]] = []
    seen: Dict[str, None] = {}
    last_for_flag: Dict[str, int] = {}
    for entry in spec.columns:
        if isinstance(entry, str):
            info = _field_column(model, entry)
        elif isinstance(entry, Ranked):
            info = _ranked_column(model, entry)
        elif isinstance(entry, Position):
            info = ColumnInfo(entry.name, "Int64", False, "position")
        elif isinstance(entry, Computed):
            info = ColumnInfo(
                entry.name, entry.dtype, entry.nullable, "computed", raw=entry.raw
            )
            for read in entry.reads:
                if not _knows(model, read):
                    raise FrameSpecError(
                        f"column {entry.name!r} reads {read!r}, which "
                        f"{model.__name__} does not have"
                    )
        else:
            raise FrameSpecError(f"column entry {entry!r} is not a field name")
        if info.name in seen:
            raise FrameSpecError(f"column {info.name!r} is declared twice")
        seen[info.name] = None
        entries.append((info, entry))
        if info.overflow_flag is not None:
            last_for_flag[info.overflow_flag] = len(entries) - 1
    columns: List[ColumnInfo] = []
    for index, (info, _entry) in enumerate(entries):
        columns.append(info)
        for flag, last in last_for_flag.items():
            if last == index:
                if flag in seen:
                    raise FrameSpecError(
                        f"overflow flag column {flag!r} collides with a column"
                    )
                columns.append(ColumnInfo(flag, "Boolean", False, "flag"))
    for name in spec.waived:
        if not _knows(model, name):
            raise FrameSpecError(
                f"waiver for {name!r}, which {model.__name__} does not have"
            )
    resolved = tuple(columns)
    _RESOLVED[id(spec)] = (spec, resolved)
    return resolved


_RESOLVED: Dict[int, Tuple[FrameSpec, Tuple[ColumnInfo, ...]]] = {}


def _knows(model: type[BaseModel], name: str) -> bool:
    return (
        name in model.model_fields
        or name in model.__private_attributes__
        or hasattr(model, name)
    )


def frame_columns(spec: FrameSpec) -> Tuple[ColumnInfo, ...]:
    """The frame's columns in order, each with its dtype name and contract."""
    return _resolve(spec)


@lru_cache(maxsize=None)
def _dtypes() -> Dict[str, Any]:
    import polars as pl

    return {"Int64": pl.Int64, "String": pl.String, "Boolean": pl.Boolean}


def frame_schema(spec: FrameSpec) -> Dict[str, "pl.DataType"]:
    """The frame's polars schema, names and dtypes in column order."""
    import polars as pl

    dtypes = _dtypes()
    return {
        info.name: (
            pl.Enum(list(info.vocabulary))
            if info.vocabulary is not None
            else dtypes[info.dtype]
        )
        for info in _resolve(spec)
    }


def column_vocabularies(spec: FrameSpec) -> Dict[str, Tuple[str, ...]]:
    """Each :class:`EnumColumn` column's vocabulary, by column name."""
    return {
        info.name: info.vocabulary
        for info in _resolve(spec)
        if info.vocabulary is not None
    }


def _text(value: Any, raw: bool) -> Optional[str]:
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text if raw else wire(text)


def _vocabulary_cell(value: Any, info: ColumnInfo) -> Optional[str]:
    """The cell of an :class:`EnumColumn` column: a vocabulary word, or an error.

    A member of a ``str`` enum is read as its value. Nothing is wired: the cell is
    one of the vocabulary's own ASCII words or the build stops, and the refused
    value is shown by ``repr`` cut to 40 characters, never as a cell. ``None`` is
    a cell only in a nullable column.
    """
    if value is None and info.nullable:
        return None
    word = value.value if isinstance(value, Enum) else value
    if isinstance(word, str) and word in (info.vocabulary or ()):
        return word
    shown = repr(word)
    if len(shown) > 40:
        shown = shown[:37] + "..."
    raise FrameSpecError(
        f"column {info.name!r} holds {shown}, which is not in its vocabulary "
        f"{info.vocabulary!r}"
    )


def _int64(value: Optional[int]) -> Tuple[Optional[int], bool]:
    if value is None:
        return None, False
    if _INT64_MIN <= value <= _INT64_MAX:
        return value, False
    return None, True


def to_frame(models: Sequence[Any], spec: FrameSpec) -> "pl.DataFrame":
    """*models* as a frame of *spec*: one row each, in the order given.

    One pass of attribute reads over instances already validated; nothing is
    validated, dumped or rebuilt per row.
    """
    import polars as pl

    items = list(models)
    resolved = _resolve(spec)
    entries = {(e.name if not isinstance(e, str) else e): e for e in spec.columns}
    rank_maps: Dict[str, Dict[int, int]] = {}
    for group in {c.rank_group for c in resolved if c.rank_group is not None}:
        rank_maps[group] = ranks(
            getattr(item, c.name)
            for c in resolved
            if c.rank_group == group
            for item in items
        )
    flags: Dict[str, List[bool]] = {
        c.name: [False] * len(items) for c in resolved if c.source == "flag"
    }
    data: Dict[str, List[Any]] = {}
    for info in resolved:
        if info.source == "flag":
            data[info.name] = flags[info.name]
            continue
        if info.source == "position":
            data[info.name] = list(range(len(items)))
            continue
        if info.source == "computed":
            entry = entries[info.name]
            if not isinstance(entry, Computed):
                raise FrameSpecError(
                    f"{spec.model.__name__}.{info.name} is a computed column "
                    "without a Computed entry"
                )
            fn = entry.fn
            values = [fn(item) for item in items]
        else:
            values = [getattr(item, info.name) for item in items]
        if info.vocabulary is not None:
            data[info.name] = [_vocabulary_cell(v, info) for v in values]
        elif info.dtype == "String":
            data[info.name] = [_text(v, info.raw) for v in values]
        elif info.dtype == "Boolean":
            if info.nullable:
                data[info.name] = [None if v is None else bool(v) for v in values]
            else:
                # a nullable=False flag is never null: an instance built around
                # validation that holds None reads as False, as bool() did in the
                # builders this replaced
                data[info.name] = [bool(v) for v in values]
        elif info.rank_group is not None:
            mapping = rank_maps[info.rank_group]
            data[info.name] = [None if v is None else mapping[v] for v in values]
        elif info.overflow_flag is not None:
            cells = [_int64(v) for v in values]
            data[info.name] = [cell for cell, _over in cells]
            flag = flags[info.overflow_flag]
            for row, (_cell, over) in enumerate(cells):
                if over:
                    flag[row] = True
        else:
            data[info.name] = values
    return pl.DataFrame(data, schema=frame_schema(spec))


def _public_properties(model: type) -> List[str]:
    names: List[str] = []
    for klass in model.__mro__:
        if klass.__module__.startswith(("pydantic", "builtins")):
            continue
        for name, member in vars(klass).items():
            if isinstance(member, property) and not name.startswith("_"):
                if name not in names:
                    names.append(name)
    return names


def unaccounted(spec: FrameSpec) -> List[str]:
    """The model's names whose frame fate nobody decided, in a stable order.

    A field is accounted for when the spec projects it, it is marked
    :class:`NotInFrame`, or it is waived. A private attribute or public property
    is accounted for when a ``Computed`` reads it or it is waived.
    """
    model = spec.model
    projected = {c for c in spec.columns if isinstance(c, str)} | {
        c.name for c in spec.columns if isinstance(c, Ranked)
    }
    read = {r for c in spec.columns if isinstance(c, Computed) for r in c.reads}
    missing: List[str] = []
    for name, info in model.model_fields.items():
        if name in projected or name in spec.waived:
            continue
        if _marker(info.metadata, NotInFrame) is not None:
            continue
        missing.append(name)
    for name in list(model.__private_attributes__) + _public_properties(model):
        if name not in read and name not in spec.waived and name not in missing:
            missing.append(name)
    return missing


def assert_accounted(spec: FrameSpec) -> None:
    """Raise :class:`FrameSpecError` naming every unaccounted name of *spec*."""
    missing = unaccounted(spec)
    if missing:
        raise FrameSpecError(
            f"{spec.model.__name__} has names with no decided frame fate: "
            f"{', '.join(missing)}; project them, mark fields NotInFrame, read "
            "them from a Computed column, or waive them with a note"
        )
