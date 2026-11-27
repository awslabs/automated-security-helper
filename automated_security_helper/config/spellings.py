"""One table of renamed configuration spellings, and the readers that use it.

A configuration key is renamed in a release, and the old spelling keeps loading,
with a deprecation line, until the release that removes it. Before this module
each reader that touched a renamed key paired the field with its old spelling in
its own way: the loader's merge saw two keys where there was one setting, no
owner held the rule for a file that wrote both, a runtime-patch denial written in
one spelling let a write in the other through, and the linter derived its own
direction. Every reader now reads the rows below instead:

* the models declare a renamed field through :func:`renamed_field`, which takes
  the old spellings from the table, and apply the both-spellings rule through
  :func:`check_spellings` when they are built without the loader;
* the loader folds each file of an ``extends`` chain through
  :func:`fold_spellings` before it layers one file over another, so a base and
  its child agree on one spelling, the deprecation is said once per file and
  spelling, and the file is refused at the release that removes the old one;
* a ``patch`` operation is part of its file: its pointers and its values are
  folded with the keys;
* a reader that builds a configuration from a document it does not fold (a
  runtime patch, a profile's ``override_yaml``, a config override) checks it with
  :func:`refuse_removed_spellings`;
* a runtime-patch denial matches both spellings of a renamed key
  (:func:`canonical_segments`);
* lint reads the rows and the places that hold their model
  (:func:`entry_places`), and every reader that pairs a top-level field with the
  keys it is written under reads :func:`field_spellings`.

A row's old spellings are read until ``removed_in`` and refused from that release
on (:func:`is_removed`), by the loader's fold of a file and by
:func:`refuse_removed_spellings` in the readers above. The models read them at
every release and refuse none: an entry built in code keeps loading, and so does
a stored results file, a record of the run that wrote it.

No message here carries a value. A value can be read from the environment, so
every message names files, places in the document, and keys.
"""

from __future__ import annotations

import importlib
import types
import warnings
from collections import abc as collections_abc
from dataclasses import dataclass
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    get_args,
    get_origin,
)

from packaging.version import InvalidVersion, Version
from pydantic import AliasChoices, AliasPath, BaseModel, Field, ValidationInfo
from pydantic_core import PydanticUndefined

from automated_security_helper.config import command_names
from automated_security_helper.utils.unknown_keys import tolerated_notes, warned_notes

#: The key a config file holds its ``patch`` operations under
#: (``config_sources.PATCH_KEY``, which imports this module and so cannot be read
#: from here).
_PATCH_KEY = "patch"

#: The operations that carry a ``value`` the file's own models read.
_VALUE_OPS = ("add", "replace", "test")

_GLOB_CHARS = frozenset("*?[")


@dataclass(frozen=True)
class SpellingRow:
    """One renamed key: the model that holds the field and the spellings it had."""

    #: Only key renames exist so far; a later kind adds a value to this literal.
    kind: Literal["key"]
    #: The dotted path of the model whose field was renamed. A subclass of the
    #: model holds the row too. A path rather than the class: the models import
    #: this module to declare their fields, so the class cannot be named here.
    model: str
    #: The spelling now written: the field's name, and the first of its choices.
    canonical: str
    #: The spellings read, with a deprecation line, until ``removed_in``.
    old: Tuple[str, ...]
    #: The release that introduced the canonical spelling.
    introduced: str
    #: The release that stops reading the old spellings in a config, or None for
    #: a spelling that is never removed.
    removed_in: Optional[str]
    #: One line saying what changed, for the changelog and for an upgrade.
    note: str

    def status(self, version: Optional[str] = None) -> Literal["live", "removed"]:
        """``"removed"`` when the old spellings are refused at ``version`` (the
        running release when None), else ``"live"``: read, with a line."""
        return "removed" if is_removed(self, version) else "live"


#: The table. A row added here reaches the loader, the merge, the patch
#: pointers, the denials and lint with no other edit, once its field is declared
#: through :func:`renamed_field`.
ROWS: Tuple[SpellingRow, ...] = (
    SpellingRow(
        kind="key",
        model="automated_security_helper.models.core.IgnorePathWithReason",
        canonical="expires",
        old=("expiration",),
        introduced="3.8.0",
        removed_in="4.0",
        note=(
            "An ignore path, a suppression and an exclusion write 'expires' where "
            "they wrote 'expiration'."
        ),
    ),
)


# ---------------------------------------------------------------------------
# The release gate
# ---------------------------------------------------------------------------


def running_version() -> str:
    """The release this process is, read when called.

    ``__version__`` is a lazy attribute of the package, so a test that sets it
    changes what every gate below reads.
    """
    import automated_security_helper

    return str(automated_security_helper.__version__)


def is_removed(row: SpellingRow, version: Optional[str] = None) -> bool:
    """Whether ``row``'s old spellings are refused at ``version``.

    The release numbers are compared, so a pre-release of the removing release
    (``4.0.0rc1``) already refuses them. A version that does not parse is not
    removed, and a row with no ``removed_in`` never is: an unreadable version
    must not stop a configuration from loading.
    """
    if row.removed_in is None:
        return False
    removal = Version(row.removed_in)
    try:
        running = Version(version if version is not None else running_version())
    except InvalidVersion:
        return False
    return running.release >= removal.release


def release_label(release: str) -> str:
    """``v4`` for ``4.0``, ``v4.2`` for ``4.2``: how the changelog names it."""
    parts = release.split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return "v" + ".".join(parts)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def deprecation_message(row: SpellingRow, old: str) -> str:
    """What a config says when it writes ``old`` while the row is live."""
    if row.removed_in is None:
        return (
            f"The '{old}' key is a deprecated spelling of '{row.canonical}'; "
            f"write '{row.canonical}'."
        )
    return (
        f"The '{old}' key is a deprecated spelling of '{row.canonical}' and will "
        f"be removed in ASH {release_label(row.removed_in)}; write "
        f"'{row.canonical}'."
    )


def disagreement_message(row: SpellingRow, old: str) -> str:
    """What a config says when it writes both spellings with different values."""
    return (
        f"{row.canonical} and {old} are two spellings of one field and disagree; "
        "keep one"
    )


def removal_message(row: SpellingRow, old: str, *, by_hand: bool = False) -> str:
    """What a config says when it writes ``old`` at or after ``removed_in``.

    It ends with the sentence the command registry gives for the command that
    rewrites a config file (``command_names.rewrite_sentence``), which is empty
    while the registry holds none. ``by_hand`` is for a file that command does not
    rewrite in place, a TOML one: the sentence then says to edit the key.
    """
    release = row.removed_in
    if release is None:
        message = f"The '{old}' key is no longer read; write '{row.canonical}'."
    else:
        message = (
            f"The '{old}' key is no longer read as of ASH {release}; write "
            f"'{row.canonical}'."
        )
    return message + command_names.rewrite_sentence(by_hand=by_hand)


def disagreement_note(row: SpellingRow, old: str) -> str:
    """What a stored config records when it holds both spellings with different
    values. No value: the reader that collects it names where the entry is."""
    return f"both {old} spellings, disagreeing"


class SpellingRefused(ValueError):
    """A file's old spelling was refused: it is past its removal release, or the
    file writes both spellings with different values.

    The text names the file, the place in it and the keys, and no value, in the
    form every refusal of a config file uses (``Config <file>: ...``). The file is
    named as it was given: the sink that shows the whole text (the CLI's refusal,
    the log handlers) shows it once, and a name escaped here first would be shown
    twice, each escape's backslash doubled
    (``config_sources.describe_config_path`` says the same of every path it names).

    A reader whose document is no file (a runtime patch, an override) words its
    own refusal from ``place`` and ``detail``, or from ``located``.
    """

    def __init__(self, source: str, place: str, detail: str) -> None:
        self.source = source
        self.place = place
        self.detail = detail
        super().__init__(f"Config {source}: {self.located}")

    @property
    def located(self) -> str:
        """The refusal without the file: the place in the document, then the
        detail."""
        return f"{self.place}: {self.detail}" if self.place else self.detail


# ---------------------------------------------------------------------------
# The rows' models and fields
# ---------------------------------------------------------------------------


@lru_cache(maxsize=None)
def _import_model(path: str) -> type[BaseModel]:
    module_name, _, attribute = path.rpartition(".")
    model = getattr(importlib.import_module(module_name), attribute)
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        raise TypeError(f"{path} is not a pydantic model")
    return model


def row_model(row: SpellingRow) -> type[BaseModel]:
    """The class ``row.model`` names, imported when asked for."""
    return _import_model(row.model)


#: How a field holds the model a row names: one value, a list of them, or a dict
#: of them whose keys are free.
PlaceKind = Literal["model", "list", "dict"]


class Shape(NamedTuple):
    """What a value at a key is read as: one model, a list of one model, or a
    dict (keys free) of one model."""

    kind: PlaceKind
    model: type[BaseModel]


@dataclass(frozen=True)
class _Field:
    name: str
    #: The key a file writes the field under: its alias, else its name.
    written: str
    #: Every spelling the field is read under, table rows included.
    spellings: Tuple[str, ...]
    shape: Optional[Shape]


_LIST_ORIGINS = (list, collections_abc.Sequence, collections_abc.MutableSequence)
_DICT_ORIGINS = (dict, collections_abc.Mapping, collections_abc.MutableMapping)


def _shape_of(annotation: Any) -> Optional[Shape]:
    """The shape of a field's annotation, through ``Annotated``, ``Optional`` and
    unions that hold one such shape. None for anything else: a scalar, a mix of
    models, a list of anything but one model."""
    origin = get_origin(annotation)
    if origin is Annotated:
        return _shape_of(get_args(annotation)[0])
    if origin is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return Shape("model", annotation)
        return None
    if origin is Union or origin is types.UnionType:
        found = {
            shape for shape in map(_shape_of, get_args(annotation)) if shape is not None
        }
        return found.pop() if len(found) == 1 else None
    args = get_args(annotation)
    if origin in _LIST_ORIGINS and len(args) == 1:
        inner = _shape_of(args[0])
        return Shape("list", inner.model) if inner and inner.kind == "model" else None
    if origin in _DICT_ORIGINS and len(args) == 2:
        inner = _shape_of(args[1])
        return Shape("dict", inner.model) if inner and inner.kind == "model" else None
    return None


def _alias_strings(alias: Any) -> Tuple[str, ...]:
    """The keys a validation alias reads: a name, every name of an
    ``AliasChoices`` and the first key of an ``AliasPath``."""
    if isinstance(alias, str):
        return (alias,)
    if isinstance(alias, AliasChoices):
        return tuple(key for choice in alias.choices for key in _alias_strings(choice))
    if isinstance(alias, AliasPath):
        first = alias.path[0] if alias.path else None
        return (first,) if isinstance(first, str) else ()
    return ()


class _Index:
    """The table read once: each model's rows and fields, built when first asked.

    Held for one value of ``ROWS``. A test (or a later release) that replaces
    ``ROWS`` gets a new index, so no lookup answers from rows it was not given.
    """

    def __init__(self, rows: Tuple[SpellingRow, ...]) -> None:
        self.rows = rows
        self.rows_by_model: Dict[type[BaseModel], Tuple[SpellingRow, ...]] = {}
        self.fields_by_model: Dict[type[BaseModel], Dict[str, _Field]] = {}
        self.places_by_model: Dict[
            type[BaseModel], Tuple[Tuple[Tuple[str, ...], PlaceKind], ...]
        ] = {}
        #: The canonical spelling of each old one, for a model that is not known.
        self.canonical_of: Dict[str, str] = {}
        for row in rows:
            for old in row.old:
                self.canonical_of.setdefault(old, row.canonical)


_INDEX: Optional[_Index] = None


def _index() -> _Index:
    """The index of the current ``ROWS``."""
    global _INDEX
    rows = ROWS
    index = _INDEX
    if index is None or index.rows is not rows:
        index = _INDEX = _Index(rows)
    return index


def rows_for(model: type[BaseModel]) -> Tuple[SpellingRow, ...]:
    """The rows whose model is ``model`` or one of its base classes."""
    index = _index()
    found = index.rows_by_model.get(model)
    if found is None:
        found = tuple(row for row in index.rows if issubclass(model, row_model(row)))
        index.rows_by_model[model] = found
    return found


def field_spellings(model: type[BaseModel], name: str) -> Tuple[str, ...]:
    """Every spelling the field ``name`` of ``model`` is read under: its name,
    its alias, each name of its ``AliasChoices``, then the old spellings the
    table gives it, each once and in that order."""
    spellings: List[str] = [name]
    info = model.model_fields.get(name)
    if info is not None:
        if info.alias:
            spellings.append(info.alias)
        spellings.extend(_alias_strings(info.validation_alias))
    for row in rows_for(model):
        if row.canonical == name:
            spellings.extend(row.old)
    return tuple(dict.fromkeys(spellings))


def _field_map(model: type[BaseModel]) -> Dict[str, _Field]:
    """Each field of ``model`` under every spelling it is read as."""
    index = _index()
    found = index.fields_by_model.get(model)
    if found is None:
        found = {}
        for name, info in model.model_fields.items():
            field = _Field(
                name=name,
                written=info.alias or name,
                spellings=field_spellings(model, name),
                shape=_shape_of(info.annotation),
            )
            for spelling in field.spellings:
                found.setdefault(spelling, field)
        index.fields_by_model[model] = found
    return found


def _row_with_old(model: type[BaseModel], key: str) -> Optional[SpellingRow]:
    """The row of ``model`` that ``key`` is an old spelling of, or None."""
    for row in rows_for(model):
        if key in row.old:
            return row
    return None


def _root_model() -> type[BaseModel]:
    # Imported here: ash_config imports this module's readers through the models.
    from automated_security_helper.config.ash_config import AshConfig

    return AshConfig


def child_model(model: type[BaseModel], key: str) -> Optional[Shape]:
    """What the value at ``key`` of a ``model`` mapping is read as, or None.

    ``key`` matches a field when it is the field's name, its alias, a name of its
    ``AliasChoices`` or an old spelling the table gives it. A key the model does
    not declare (an extra, a typo) names no shape and is not walked.
    """
    field = _field_map(model).get(key)
    return None if field is None else field.shape


def _names_an_element(shape: Shape, segment: str) -> bool:
    """Whether ``segment`` names one element of a list or one value of a dict."""
    if shape.kind == "dict":
        return True
    return segment == "-" or (segment.isascii() and segment.isdigit())


def entry_places(
    model: type[BaseModel],
) -> Tuple[Tuple[Tuple[str, ...], PlaceKind], ...]:
    """Every static place from the root configuration to a field that holds
    ``model`` or a subclass of it: the keys a file writes to get there, and
    whether the field holds one such model, a list of them or a dict of them.

    A key is the one a file writes (the alias where the field has one). The root
    itself is the place ``()`` when it is ``model`` or a subclass.
    """
    index = _index()
    found = index.places_by_model.get(model)
    if found is not None:
        return found
    places: List[Tuple[Tuple[str, ...], PlaceKind]] = []
    root = _root_model()
    if issubclass(root, model):
        places.append(((), "model"))

    def visit(
        current: type[BaseModel], path: Tuple[str, ...], above: Tuple[Any, ...]
    ) -> None:
        if current in above:
            return
        seen: Set[str] = set()
        for field in _field_map(current).values():
            if field.name in seen:
                continue
            seen.add(field.name)
            if field.shape is None:
                continue
            here = (*path, field.written)
            if issubclass(field.shape.model, model):
                places.append((here, field.shape.kind))
            visit(field.shape.model, here, (*above, current))

    visit(root, (), ())
    found = tuple(dict.fromkeys(places))
    index.places_by_model[model] = found
    return found


def entry_paths(model: type[BaseModel]) -> Tuple[Tuple[str, ...], ...]:
    """The keys of every place :func:`entry_places` finds, in the same order."""
    return tuple(dict.fromkeys(keys for keys, _ in entry_places(model)))


def renamed_field(
    name: str,
    *,
    model: str,
    default: Any = PydanticUndefined,
    **field_kwargs: Any,
) -> Any:
    """``Field(default, validation_alias=AliasChoices(name, *old), **field_kwargs)``,
    with the old spellings the table gives ``name`` on the model ``model`` (a
    dotted path).

    The canonical name comes first, so a dump and the schema write it, and no
    ``alias`` is set. A field declared this way with no row would be read under
    spellings no other reader knows, so it is refused here.
    """
    old: List[str] = []
    for row in _index().rows:
        if row.model == model and row.canonical == name:
            old.extend(spelling for spelling in row.old if spelling not in old)
    if not old:
        raise ValueError(
            f"{model}.{name} is declared with renamed_field but the spelling "
            "table has no row for it"
        )
    return Field(default, validation_alias=AliasChoices(name, *old), **field_kwargs)


# ---------------------------------------------------------------------------
# The fold of one document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FoldedDocument:
    """A document with its old spellings renamed, and what to say about them."""

    document: Any
    #: One line per file and old spelling met, each ``Config <file>: <message>``.
    warnings: Tuple[str, ...]


def _decode(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def _encode(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _join(place: str, key: str) -> str:
    return f"{place}.{key}" if place else key


class _Fold:
    """One walk of one document.

    Checked (``source`` given), it says each old spelling it renames, refuses one
    past its removal release and a file that writes both spellings with different
    values. Checked with ``removal_only``, it refuses an old spelling past its
    removal release and does nothing else: no warning, no line, no refusal of
    both spellings, so a reader that goes on to use the document as it is can
    check it. Unchecked, it renames and nothing else, keeping the canonical key
    where both are written: the view of a file as it was written (its
    environment references) pairs with the folded data key for key.
    """

    def __init__(
        self,
        root: type[BaseModel],
        source: Optional[str] = None,
        version: Optional[str] = None,
        removal_only: bool = False,
        by_hand: bool = False,
    ) -> None:
        self.root = root
        self.source = source
        self.version = version
        self.removal_only = removal_only
        self.by_hand = by_hand
        self.lines: Dict[Tuple[str, str, str], str] = {}

    # -- the document ------------------------------------------------------

    def document(self, document: Any) -> Any:
        if not isinstance(document, dict):
            return document
        folded = self.mapping(document, self.root, "")
        operations = folded.get(_PATCH_KEY)
        if isinstance(operations, list):
            respelled = self.operations(operations)
            if respelled is not operations:
                folded = {**folded, _PATCH_KEY: respelled}
        return folded

    def mapping(
        self, mapping: Dict[Any, Any], model: type[BaseModel], place: str
    ) -> Any:
        """``mapping`` read as ``model``: its own old keys renamed, then the
        values of the fields it holds. The same object when nothing changes."""
        folded = mapping
        for row in rows_for(model):
            for old in row.old:
                if old in folded:
                    folded = self._respell(folded, row, old, place)
        fields = _field_map(model)
        updated: Optional[Dict[Any, Any]] = None
        for key, value in folded.items():
            field = fields.get(key) if isinstance(key, str) else None
            if field is None or field.shape is None:
                continue
            respelled = self.value(value, field.shape, _join(place, key))
            if respelled is not value:
                if updated is None:
                    updated = dict(folded)
                updated[key] = respelled
        return folded if updated is None else updated

    def value(self, value: Any, shape: Shape, place: str) -> Any:
        """``value`` read as ``shape``; the same object when nothing changes."""
        if shape.kind == "model":
            if not isinstance(value, dict):
                return value
            return self.mapping(value, shape.model, place)
        if shape.kind == "list":
            if not isinstance(value, list):
                return value
            items = [
                self.mapping(item, shape.model, f"{place}[{index}]")
                if isinstance(item, dict)
                else item
                for index, item in enumerate(value)
            ]
            same = all(new is old for new, old in zip(items, value))
            return value if same else items
        if not isinstance(value, dict):
            return value
        # A dict's keys are the file's own names, which can be read from the
        # environment: a message names none of them.
        entries = {
            key: self.mapping(item, shape.model, f"{place}.<key>")
            if isinstance(item, dict)
            else item
            for key, item in value.items()
        }
        same = all(entries[key] is value[key] for key in value)
        return value if same else entries

    # -- one old key ---------------------------------------------------------

    def _met(self, row: SpellingRow, old: str, place: str) -> None:
        """An old spelling read: past its removal release it is refused, and
        otherwise it is said (once per file and spelling)."""
        if self.source is None:
            return
        if row.status(self.version) == "removed":
            raise SpellingRefused(
                self.source, place, removal_message(row, old, by_hand=self.by_hand)
            )
        if self.removal_only:
            return
        message = deprecation_message(row, old)
        warnings.warn(message, DeprecationWarning)
        self.lines.setdefault(
            (row.model, row.canonical, old), f"Config {self.source}: {message}"
        )

    def _respell(
        self, mapping: Dict[Any, Any], row: SpellingRow, old: str, place: str
    ) -> Dict[Any, Any]:
        canonical = row.canonical
        self._met(row, old, place)
        if canonical not in mapping:
            return {
                (canonical if key == old else key): value
                for key, value in mapping.items()
            }
        if (
            self.source is not None
            and not self.removal_only
            and mapping[old] != mapping[canonical]
        ):
            raise SpellingRefused(self.source, place, disagreement_message(row, old))
        return {key: value for key, value in mapping.items() if key != old}

    # -- patch operations ------------------------------------------------------

    def operations(self, operations: List[Any]) -> List[Any]:
        folded = list(operations)
        changed = False
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                continue
            respelled = self.operation(operation, f"{_PATCH_KEY}[{index}]")
            if respelled is not operation:
                folded[index] = respelled
                changed = True
        return folded if changed else operations

    def operation(self, operation: Dict[Any, Any], place: str) -> Dict[Any, Any]:
        updated: Dict[str, Any] = {}
        end: Optional[Shape] = None
        for key in ("path", "from"):
            pointer = operation.get(key)
            respelled, shape = self.pointer(pointer, f"{place}.{key}")
            if respelled is not pointer:
                updated[key] = respelled
            if key == "path":
                end = shape
        if operation.get("op") in _VALUE_OPS and "value" in operation and end:
            value = operation["value"]
            folded = self.value(value, end, f"{place}.value")
            if folded is not value:
                updated["value"] = folded
        return {**operation, **updated} if updated else operation

    def pointer(self, pointer: Any, place: str) -> Tuple[Any, Optional[Shape]]:
        """``pointer`` with each segment that is an old spelling along the model
        spelled as the canonical one, and the shape the pointer ends at (None
        once it leaves the model). A pointer that names no old spelling is the
        same object. The root pointer, the empty string, names the whole
        document and ends at the root model."""
        if pointer == "":
            return pointer, Shape("model", self.root)
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            return pointer, None
        shape: Optional[Shape] = Shape("model", self.root)
        segments: List[str] = []
        changed = False
        for raw in pointer[1:].split("/"):
            segment = _decode(raw)
            if shape is not None:
                spelled, shape = self._step(shape, segment, place)
                if spelled != segment:
                    segment, raw, changed = spelled, _encode(spelled), True
            segments.append(raw)
        return ("/" + "/".join(segments) if changed else pointer), shape

    def _step(
        self, shape: Shape, segment: str, place: str
    ) -> Tuple[str, Optional[Shape]]:
        if shape.kind == "model":
            field = _field_map(shape.model).get(segment)
            if field is None:
                return segment, None
            row = _row_with_old(shape.model, segment)
            if row is None:
                return segment, field.shape
            self._met(row, segment, place)
            return row.canonical, field.shape
        if _names_an_element(shape, segment):
            return segment, Shape("model", shape.model)
        return segment, None


def fold_spellings(
    document: Any,
    source: str,
    *,
    model: Optional[type[BaseModel]] = None,
    version: Optional[str] = None,
    by_hand: bool = False,
) -> FoldedDocument:
    """``document``, one config file's parsed mapping, with each old spelling a
    row of the table names written as the canonical one, keys in place.

    Walks from ``AshConfig`` (or ``model``) through the fields it reads, so a key
    another model declares under the same name (a content database staleness
    override's own ``expiration``) is left alone, as is anything the walk does not
    know. The file's ``patch`` operations are part of it: each ``path`` and
    ``from`` pointer is respelled along the model, and a value an operation adds,
    replaces or tests is read as the model its path names (the whole
    configuration, for the root pointer). Never changes ``document``.

    Raises SpellingRefused, naming ``source``, the place and the keys, when an old
    spelling is read at or after the row's ``removed_in`` (``version`` is the
    release, the running one when None) and when a mapping writes both spellings
    with different values. Each old spelling met also emits the row's
    ``DeprecationWarning``, and the returned ``warnings`` hold one line for each
    spelling the file uses, however many places use it. A refusal at the removal
    release ends with the registry's sentence about the command that rewrites the
    file; ``by_hand`` is for a file that command does not rewrite in place (a TOML
    one), whose sentence says to edit the key (``removal_message``).
    """
    fold = _Fold(
        model if model is not None else _root_model(),
        source,
        version,
        by_hand=by_hand,
    )
    folded = fold.document(document)
    return FoldedDocument(folded, tuple(fold.lines.values()))


def fold_written_spellings(
    document: Any, *, model: Optional[type[BaseModel]] = None
) -> Any:
    """``document`` with the same renames :func:`fold_spellings` makes, and
    nothing else: no gate, no refusal, no warning, no line.

    For a view of a file that must pair with the folded data key for key (the
    file as written, with its environment references). Where both spellings are
    written the canonical key stays, as in the folded data.
    """
    return _Fold(model if model is not None else _root_model()).document(document)


def refuse_removed_spellings(
    document: Any,
    source: str,
    *,
    model: Optional[type[BaseModel]] = None,
    version: Optional[str] = None,
) -> None:
    """Raise :class:`SpellingRefused` when ``document`` writes the old spelling of
    a row removed at ``version`` (the running release when None): as a key, in a
    ``patch`` pointer or in an operation's value. Return None otherwise.

    For a reader that builds a configuration from a document it does not fold: a
    runtime patch, a profile's ``override_yaml``, a config override. The models
    read an old spelling at every release and refuse none, so such a reader
    refuses a removed one here, naming the place and the keys and no value. It
    only checks. ``document`` is not changed and the reader goes on with it as it
    is, so nothing is said for a spelling that is still live, and a document that
    writes both spellings is left to the models, which refuse it.
    """
    _Fold(
        model if model is not None else _root_model(),
        source,
        version,
        removal_only=True,
    ).document(document)


# ---------------------------------------------------------------------------
# The rule of a model built without the loader
# ---------------------------------------------------------------------------


def _without(data: Dict[Any, Any], old: str) -> Dict[Any, Any]:
    return {key: value for key, value in data.items() if key != old}


def check_spellings(model: type[BaseModel], data: Any, info: ValidationInfo) -> Any:
    """The body of a ``mode="before"`` validator: one spelling per field.

    A stored config (a results file, ``TOLERATE_STORED_CONFIG``) is a record: an
    equal duplicate drops the old key, different values record a note and keep the
    data, and nothing is said or gated, so a results file loads at every release.

    A config built from a mapping says the deprecation while the row is live (a
    ``DeprecationWarning`` and, where the load collects them, a line), drops an
    old key equal to the canonical one, refuses different values, and otherwise
    renames the old key where it stood. From the row's removal release it does
    the same and says nothing: the model reads an old spelling at every release
    and refuses none, so an entry built in code keeps loading, and what refuses a
    removed spelling is a reader of a document (the loader's fold, and
    :func:`refuse_removed_spellings`). A file the loader read has been folded
    already, so this meets only what was built from a mapping directly: a model
    validated in code, an override.

    The deprecation is a Python warning and not an ``ASH_LOGGER`` line because
    entries are validated wherever a config or an override is read, so a logger
    line would land in every command's output for a spelling that still works.
    The default filters drop the warning outside ``__main__``, so an operator
    sees the deprecation through the lines a load collects: one per file, from
    the fold, and, for an entry built some other way, the ``In <entry kind>``
    line this adds to the validation context's warn list when one is bound.
    """
    if not isinstance(data, dict):
        return data
    rows = rows_for(model)
    if not rows:
        return data
    notes = tolerated_notes(info)
    for row in rows:
        for old in row.old:
            if old not in data:
                continue
            if notes is not None:
                if row.canonical not in data:
                    continue
                if data[old] == data[row.canonical]:
                    data = _without(data, old)
                else:
                    notes.append(disagreement_note(row, old))
                continue
            # A removed row's old spelling is no deprecation any more: it is
            # renamed below and nothing is said.
            if row.status() != "removed":
                message = deprecation_message(row, old)
                warnings.warn(message, DeprecationWarning)
                warned = warned_notes(info)
                if warned is not None:
                    kind = getattr(model, "ENTRY_KIND", None) or model.__name__
                    warned.append(f"In {kind}: {message}")
            if row.canonical not in data:
                data = {
                    (row.canonical if key == old else key): value
                    for key, value in data.items()
                }
            elif data[old] == data[row.canonical]:
                data = _without(data, old)
            else:
                raise ValueError(disagreement_message(row, old))
    return data


# ---------------------------------------------------------------------------
# What a denial and lint read
# ---------------------------------------------------------------------------


def _is_glob(segment: str) -> bool:
    return not _GLOB_CHARS.isdisjoint(segment)


def canonical_segments(segments: Sequence[str]) -> List[str]:
    """``segments``, the parts of a pointer or of a denial's pattern, with each
    old spelling along the model written as the canonical one.

    A ``*`` where the shape is a list or a dict of one model names the element
    and is kept; an index or ``-`` names it too. Any other glob (``**``, or a glob
    where a field is named) and any key the walk does not know make the model
    unknown, and from then on every row's old spelling is mapped to its canonical
    one: a denial then covers more, never less. A segment that is not exactly an
    old spelling is kept. Whether a row's old spelling is still read is not asked:
    an operator's denial written under the old spelling keeps denying both.
    """
    index = _index()
    shape: Optional[Shape] = Shape("model", _root_model())
    result: List[str] = []
    for segment in segments:
        if shape is not None and segment != "**":
            if shape.kind == "model":
                field = (
                    None if _is_glob(segment) else _field_map(shape.model).get(segment)
                )
                if field is not None:
                    row = _row_with_old(shape.model, segment)
                    result.append(segment if row is None else row.canonical)
                    shape = field.shape
                    continue
            elif segment == "*" or _names_an_element(shape, segment):
                result.append(segment)
                shape = Shape("model", shape.model)
                continue
        shape = None
        result.append(index.canonical_of.get(segment, segment))
    return result


def section_variant(key: str) -> Optional[str]:
    """``key`` with ``-`` written as ``_``, or ``_`` as ``-`` when it has none:
    the other spelling of a plugin's section name, or None for a key with no
    separator.

    It folds the spellings of a plugin's NAME (``cdk-nag`` and ``cdk_nag``) in a
    section key, not the names of an option. Lint's legacy-name check and its
    fixer both read it, so they cannot disagree about the other spelling.
    """
    if "-" in key:
        return key.replace("-", "_")
    if "_" in key:
        return key.replace("_", "-")
    return None
