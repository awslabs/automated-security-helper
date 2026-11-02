# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name read from the filesystem or an archive, made into text a record can hold.

On POSIX a file or member name is bytes. os.listdir, os.walk, Path iteration and
tarfile decode them as UTF-8 with surrogateescape, so each byte that is not UTF-8
becomes a lone surrogate: latin-1 ``b\\xe9.tar`` is read as "b\\udce9.tar". That
string is not valid text. pydantic refuses it in a str field of a model that strips
whitespace and cannot write it as JSON, a UTF-8 log or JSON writer cannot encode it,
and pytest-xdist cannot send a report whose captured log holds one.

A record holds such a name in its record form: each lone surrogate written as its
escape, the six characters ``\\udcNN`` (:func:`text_of_undecodable`). That is text,
so UTF-8 JSON holds it and ``model_validate_json`` reads it back.

The result models apply the form themselves (:class:`RecordModel`), so a scanner,
converter or plugin that puts a name it listed into a SARIF result, an invocation or
a status row needs to do nothing. Held as is, one such name in one record would stop
the record's JSON dump, and with it that scanner's results for every file, or the
run's results file for every scanner.

Code that compares a recorded name with one it reads from the filesystem or git
compares the two in the record form (:func:`text_of_undecodable`,
:func:`path_in_record_form`). Code that opens or resolves the file a record names
reads the name back first (:func:`undecodable_of_text`), since the file is named on
disk by its own bytes.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path, PurePath
from typing import Any, List, Optional, TypeVar

from pydantic import BaseModel, ValidationInfo, field_validator, model_validator
from pydantic_core import PydanticSerializationError

#: Any surrogate code point. A str decoded with surrogateescape holds only lone ones.
_SURROGATE = re.compile("[\ud800-\udfff]")


def text_of_undecodable(name: str) -> str:
    """*name* with each lone surrogate written as its escape, ``\\udcNN``.

    For a field of a record (a model or a JSON row) built from such a name. Every
    other character stays as it is, so a name that is already text comes back
    unchanged; a record is data, and whatever prints it shows it for its own sink.

    Known limit: the result does not tell such a name from one that holds the
    escape's own text. "b\\udce9.tar" read from latin-1 bytes and a UTF-8 name
    spelled with a backslash, "u", "d", "c", "e", "9" give the same text, so in a
    tree holding both the two read as one name: both are scanned and both files'
    findings are reported under it, ``--changed-files-only`` keeps both when either
    changed, and an ignore path or suppression that names either applies to both.
    No text form can keep them apart: a record is validated again from its own
    text (an aggregated results file read back is built from a dict), so the form
    has to leave text that is already in it unchanged, and the escape's text is
    also a name. Only a POSIX tree can hold both; a Windows name cannot hold a
    backslash.
    """
    if name.isascii():
        return name
    return name.encode("utf-8", "backslashreplace").decode("utf-8")


_PathT = TypeVar("_PathT", bound=PurePath)


def path_in_record_form(path: _PathT) -> _PathT:
    """*path* with its text in the record form (:func:`text_of_undecodable`), as a
    path of the same kind, or *path* itself when it is already text.

    For comparing a path ASH lists or resolves, which holds each lone surrogate
    itself, with a path read from a record. Both sides go through this, so the
    path's own comparison (case-insensitive on Windows) decides as it does for any
    other name.
    """
    text = str(path)
    recorded_text = text_of_undecodable(text)
    return path if recorded_text == text else type(path)(recorded_text)


#: A lone surrogate's record form, ``\\uXXXX`` for U+D800 to U+DFFF as
#: :func:`text_of_undecodable` writes it: ``\\udcNN`` for the bytes 0x80 to 0xFF that
#: surrogateescape turns into U+DC80 to U+DCFF on POSIX, and any other surrogate a
#: Windows file name can hold (a lone leading one, or a pair held as two code points).
_RECORDED_ESCAPE = re.compile(r"\\u(d[89a-f][0-9a-f]{2})")


def undecodable_of_text(text: str) -> str:
    """*text* with each record-form escape, ``\\udcNN`` or any other surrogate's
    ``\\uXXXX``, read back as its lone surrogate: the inverse of
    :func:`text_of_undecodable` for a name that is not UTF-8. For text a record
    wrote that code applies as a name, such as the recorded configuration's ignore
    paths, so a run that reads the record back applies the name the scan read, not
    its six-character spelling."""
    if "\\ud" not in text:
        return text
    return _RECORDED_ESCAPE.sub(lambda match: chr(int(match[1], 16)), text)


#: What resolving a name can raise when its text cannot be a file's name:
#: ``ValueError`` for an embedded NUL (the percent-decoded reading of a uri that
#: carries ``%00``), ``OSError`` where the platform refuses the name outright,
#: and ``RuntimeError`` for a symlink loop under CPython 3.10-3.12, whose
#: non-strict ``Path.resolve`` stats its result (``check_eloop``; 3.13 stopped
#: doing that).
_UNRESOLVABLE = (ValueError, OSError, RuntimeError)


def resolve_uri_reading(text: str, base: Optional[Path] = None) -> Optional[Path]:
    """The file that one reading of a location uri resolves to, or ``None``.

    *text* is one reading of a SARIF ``artifactLocation.uri`` (literal or
    percent-decoded), in the record form; it is read back
    (:func:`undecodable_of_text`) and resolved, below *base* when one is given
    and the text is relative. A text that cannot be resolved names no file
    (``_UNRESOLVABLE`` above), so the caller treats ``None`` as "not this
    reading" and decides from the reading's alternatives, rather than one bad
    reading raising out of a loop over results. The one guard for every place
    that resolves such a text, so the sites cannot drift apart.
    """
    candidate = Path(undecodable_of_text(text))
    if base is not None:
        candidate = Path(base) / candidate
    try:
        return candidate.resolve()
    except _UNRESOLVABLE:
        return None


def undecodables_of_texts(value: Any) -> Any:
    """*value*, a JSON-compatible record, with each str read back as by
    :func:`undecodable_of_text`: a dict's keys and values and a list's items, into
    new containers. *value* itself is returned when nothing changed."""
    if isinstance(value, str):
        return undecodable_of_text(value)
    if isinstance(value, dict):
        decoded = {
            undecodables_of_texts(key): undecodables_of_texts(item)
            for key, item in value.items()
        }
        unchanged = all(
            new_key is key and new_item is item
            for (key, item), (new_key, new_item) in zip(value.items(), decoded.items())
        )
        return value if unchanged and len(decoded) == len(value) else decoded
    if isinstance(value, list):
        items = [undecodables_of_texts(item) for item in value]
        return value if all(new is old for new, old in zip(items, value)) else items
    return value


def texts_of_undecodable(value: Any) -> Any:
    """*value* with every str in it in the record form (:func:`text_of_undecodable`).

    A dict's keys and values, a list's, tuple's or set's items, and a path's text
    (:func:`path_in_record_form`, staying a path) are walked, into
    new containers; nothing passed in is changed. A pydantic model inside *value*
    is left as it is: a :class:`RecordModel` applied the form when it was built, and
    any other model (the live configuration, a plugin's own model in a property bag,
    a CycloneDX component) is code's own object, which a scan goes on reading, so
    its text is put in the form only where it is written (:meth:`RecordModel.
    model_dump_json`). *value* itself is returned when nothing in it needed a
    change, so a record without such a name costs a walk and no copy.
    """
    if value is None:
        return value
    if isinstance(value, str):
        if value.isascii() or _SURROGATE.search(value) is None:
            return value
        return text_of_undecodable(value)
    if isinstance(value, PurePath):
        return path_in_record_form(value)
    if isinstance(value, dict):
        changed = None
        for index, (key, item) in enumerate(value.items()):
            new_key = texts_of_undecodable(key)
            new_item = texts_of_undecodable(item)
            if changed is None and (new_key is not key or new_item is not item):
                changed = dict(list(value.items())[:index])
            if changed is not None:
                changed[new_key] = new_item
        return value if changed is None else changed
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [texts_of_undecodable(item) for item in value]
        if all(new is old for new, old in zip(items, value)):
            return value
        if isinstance(value, list):
            return items
        return _rebuilt(value, items)
    return value


def _rebuilt(value: Any, items: List[Any]) -> Any:
    """A container of ``value``'s type holding ``items``.

    A tuple subclass with named fields (a NamedTuple, which the result models
    keep in a few property bags) takes its items as positional arguments, one
    per field, where every other container takes one iterable; ``type(value)
    (items)`` handed a NamedTuple one list where it wanted its fields and raised
    TypeError out of a dump.
    """
    if isinstance(value, tuple) and hasattr(type(value), "_fields"):
        return type(value)(*items)
    return type(value)(items)


def _record_fields(model: BaseModel) -> None:
    """Put each of *model*'s own fields and extra fields in the record form.

    *model* is a :class:`RecordModel` being built. Each changed value is a new
    object, written to the instance dict as pydantic's own validators do, so neither
    validate_assignment nor the set of fields given at construction changes, and an
    object passed in to build the model is not changed.

    A value that cannot need the form is skipped before the walk: None, which most
    optional fields of a result are, a number, an ASCII str, and a nested model,
    which is a RecordModel that applies the form itself as it is built or a model
    that is not walked (:func:`texts_of_undecodable`).
    """
    # The checks are written out here rather than in a helper: this runs once per
    # field of every model a scan builds, and a call per field is most of its cost.
    fields = model.__dict__
    for key, value in fields.items():
        if value is None or isinstance(value, _HOLDS_NO_NAME):
            continue
        if isinstance(value, str) and value.isascii():
            continue
        new = texts_of_undecodable(value)
        if new is not value:
            fields[key] = new
    extra = model.__pydantic_extra__
    if extra:
        for key, value in extra.items():
            if value is None or isinstance(value, _HOLDS_NO_NAME):
                continue
            if isinstance(value, str) and value.isascii():
                continue
            new = texts_of_undecodable(value)
            if new is not value:
                extra[key] = new
        # The extra fields' NAMES too: a property bag's key is a name a tool or a
        # repository chose, and a dump in JSON mode UTF-8-encodes the keys, so a
        # lone surrogate in one stops the dump as one in a value would. Renamed in
        # place, in the same order, only when a name changed. Two names with one
        # record form collapse to one key (the later value stays), which leaves
        # ``renamed`` shorter than ``extra``; zip stops at the shorter, so a
        # collision whose first key was already the record form compared equal and
        # the raw name stayed in the bag.
        renamed = {texts_of_undecodable(key): value for key, value in extra.items()}
        if len(renamed) != len(extra) or any(
            new_key is not key for new_key, key in zip(renamed, extra)
        ):
            extra.clear()
            extra.update(renamed)


#: Field values :func:`_record_fields` skips: they hold no str of their own.
#: ``bool`` is an ``int``.
_HOLDS_NO_NAME = (int, float, BaseModel)


class RecordModel(BaseModel):
    """A model whose text holds each name in the record form once it is built.

    The base of the SARIF models, the aggregated results' models and
    FlatVulnerability. After a model is validated from Python, each str in its own
    fields and extra fields is put in the record form; a nested RecordModel did the
    same for itself when it was built, so each str is looked at once. A model
    validated from JSON is left alone: JSON cannot hold a lone surrogate (pydantic
    refuses the escape), so there is nothing to change, and the read-back pays for
    one call per model.

    A model that strips whitespace (``str_strip_whitespace``) refuses a lone
    surrogate in a str field before any after-validator runs, so its fields that
    can hold a name also take :func:`names_as_recorded` as a before-validator.

    pydantic validates neither a value assigned to a field after the model is
    built nor a model made with ``model_construct``, and the scan fills the
    aggregated results in after they are built (additional_reports,
    validation_checkpoints). A model inside a record that is not a RecordModel (the
    live configuration, a plugin's own model in a property bag, a CycloneDX
    component) is not walked either (:func:`texts_of_undecodable`). So a JSON dump
    that meets a lone surrogate anywhere in the tree is written again from a dump in
    JSON mode with every such name in the form, and a dump in JSON mode puts its
    output in the form; neither changes the model, and a JSON dump with no such
    name costs no second dump. A dump in Python mode is checked the same way: the
    reporters that write JSON themselves (flat JSON, OCSF, GitLab, GHAS) write from
    one, so a set or a path it keeps as an object is put in the form where it sits.
    Code that reads a model's fields instead of dumping it reads
    :func:`recorded` of it.
    """

    @model_validator(mode="after")
    def _names_as_recorded(self, info: ValidationInfo) -> "RecordModel":
        if info.mode == "json":
            return self
        _record_fields(self)
        return self

    def model_dump(self, *, mode: str = "python", **kwargs: Any) -> dict[str, Any]:
        try:
            dumped = super().model_dump(mode=mode, **kwargs)
        except UnicodeEncodeError:
            # A lone surrogate in a dict KEY: a dump in JSON mode UTF-8-encodes
            # the keys (a str value passes through), so the serializer raises
            # before there is a dump to put in the form. Dump a copy with every
            # name in the form instead; the model is left as it is. When nothing
            # in the model holds one, the failure is not a name's: raised as is.
            copy = recorded(self)
            if copy is self:
                raise
            return copy.model_dump(mode=mode, **kwargs)
        if _holds_a_lone_surrogate(dumped):
            # No dump mode raises on a lone surrogate, so the output itself is put
            # in the form; the model is left as it is. A dump to Python is covered
            # too: the reporters that write JSON themselves (flat JSON, OCSF,
            # GitLab, GHAS) write from one, and json.dump of a lone surrogate
            # writes a document no strict UTF-8 reader can take back.
            return texts_of_undecodable(dumped)
        return dumped

    def model_dump_json(self, *, indent: int | None = None, **kwargs: Any) -> str:
        try:
            return super().model_dump_json(indent=indent, **kwargs)
        except PydanticSerializationError:
            # Told by what the dump holds, not by the error's words, which are the
            # codec's: a failure with no lone surrogate in the tree is raised as is.
            try:
                dumped = super().model_dump(mode="json", **_dump_options(kwargs))
            except UnicodeEncodeError:
                # A lone surrogate in a dict KEY: the JSON-mode dump UTF-8-encodes
                # the keys too, so no dump of this model can succeed. Dump a copy
                # with every name in the form (model_dump above does the same).
                copy = recorded(self)
                if copy is self:
                    raise
                dumped = copy.model_dump(mode="json", **_dump_options(kwargs))
            else:
                if not _holds_a_lone_surrogate(dumped):
                    raise
        # A field, perhaps of a nested model, was given such a name after it was
        # validated. Write the same document from a dump in JSON mode with the
        # name in the form; the model is left as it is.
        return _json_text(
            texts_of_undecodable(dumped), indent, bool(kwargs.get("ensure_ascii"))
        )


#: What ``BaseModel.model_dump`` takes. ``model_dump_json`` takes these and the
#: JSON-only ones (``indent``, ``ensure_ascii``), which a dump to Python refuses.
_MODEL_DUMP_OPTIONS = frozenset(inspect.signature(BaseModel.model_dump).parameters) - {
    "self",
    "mode",
}


def _dump_options(kwargs: dict[str, Any]) -> dict[str, Any]:
    """The ``model_dump_json`` keyword arguments ``model_dump`` takes too."""
    return {key: value for key, value in kwargs.items() if key in _MODEL_DUMP_OPTIONS}


def _json_text(data: Any, indent: int | None, ensure_ascii: bool = False) -> str:
    """*data* as JSON laid out as pydantic lays out a model dump."""
    if indent is None:
        return json.dumps(data, ensure_ascii=ensure_ascii, separators=(",", ":"))
    return json.dumps(data, ensure_ascii=ensure_ascii, indent=indent)


def recorded(model: Any) -> Any:
    """*model*, or when a field anywhere in it holds a lone surrogate, a deep copy
    of it whose text is all in the record form.

    For code that reads a model's fields rather than dumping it: the report phase
    hands its reporters, and the flattening every finding report starts from
    reads, this, so a nested field given a name after validation does not reach
    them as is. The copy keeps which fields were set and the private attributes,
    so it dumps as the model would; *model* itself is never changed. A caller
    that goes on with the run re-binds the model to what this returns, so that
    nothing after it reads the other object.

    The check reads the model's own objects (:func:`_tree_holds_a_lone_surrogate`),
    not a dump: dumping a large report once per reader made one report serialize
    the same model several times, and the serializer is left for the one dump the
    report writes.
    """
    if not _tree_holds_a_lone_surrogate(model, set()):
        return model
    copy = model.model_copy(deep=True)
    _record_tree(copy, set())
    return copy


def _tree_holds_a_lone_surrogate(value: Any, seen: set[int]) -> bool:
    """Whether any text reachable from *value*, a model, a field's value or a
    container, holds a surrogate code point. Read from the objects themselves,
    with no serializer call. A model already walked is not walked again. A leaf
    that is not text cannot hold one; a path's text is read as the str it
    renders to."""
    if isinstance(value, str):
        return not value.isascii() and _SURROGATE.search(value) is not None
    if isinstance(value, PurePath):
        return _tree_holds_a_lone_surrogate(str(value), seen)
    if isinstance(value, BaseModel):
        if id(value) in seen:
            return False
        seen.add(id(value))
        # The extra fields' names are read as a dict's keys are: a dump encodes
        # them, so one holding a lone surrogate fails the dump as a value would.
        extra = value.__pydantic_extra__ or {}
        return any(
            _tree_holds_a_lone_surrogate(item, seen)
            for item in [*value.__dict__.values(), *extra.keys(), *extra.values()]
        )
    if isinstance(value, dict):
        return any(
            _tree_holds_a_lone_surrogate(key, seen)
            or _tree_holds_a_lone_surrogate(item, seen)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_tree_holds_a_lone_surrogate(item, seen) for item in value)
    return False


def _holds_a_lone_surrogate(value: Any) -> bool:
    """Whether any str in *value*, a model dump, holds a surrogate code point
    (U+D800 to U+DFFF), which no UTF-8 writer can encode. A name that is not UTF-8
    is listed with one per byte it cannot decode (U+DC80 to U+DCFF), and a config
    file can spell any of them as an escape. Read from the text itself, so it does
    not depend on how a codec words its error. A dump in Python mode keeps a set as
    a set and a path as a path, so both are read too; a path's text is read as the
    str it renders to."""
    if isinstance(value, str):
        return not value.isascii() and _SURROGATE.search(value) is not None
    if isinstance(value, PurePath):
        return _holds_a_lone_surrogate(str(value))
    if isinstance(value, dict):
        return any(
            _holds_a_lone_surrogate(key) or _holds_a_lone_surrogate(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_holds_a_lone_surrogate(item) for item in value)
    return False


def _record_tree(value: Any, seen: set[int]) -> None:
    """Every pydantic model reachable from *value*, nested RecordModels included,
    with its fields put in the record form in place. Only ever given a copy."""
    if isinstance(value, BaseModel):
        if id(value) in seen:
            return
        seen.add(id(value))
        _record_fields(value)
        for item in [
            *value.__dict__.values(),
            *(value.__pydantic_extra__ or {}).values(),
        ]:
            _record_tree(item, seen)
    elif isinstance(value, dict):
        for item in value.values():
            _record_tree(item, seen)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _record_tree(item, seen)


def names_as_recorded(value: Any, info: ValidationInfo) -> Any:
    """A before-validator for a field of a model that strips whitespace: *value* in
    the record form, so pydantic does not refuse a name that is not UTF-8."""
    if info.mode == "json":
        return value
    return texts_of_undecodable(value)


class StrippedRecordModel(RecordModel):
    """A :class:`RecordModel` for a model that strips whitespace: every field takes
    :func:`names_as_recorded` before pydantic validates it.

    For small models only. A before-validator on a field makes pydantic hand that
    field's JSON to Python when the model is read from JSON, so a field that holds a
    whole report (AshAggregatedResults.sarif) names its own str fields instead.
    """

    @field_validator("*", mode="before")
    @classmethod
    def _names_as_recorded_before(cls, value: Any, info: ValidationInfo) -> Any:
        return names_as_recorded(value, info)
