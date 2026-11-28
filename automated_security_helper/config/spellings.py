"""One table of renamed configuration spellings, and the readers that use it.

A configuration key is renamed in a release, and the old spelling keeps loading,
with a deprecation line, until the release that removes it. Every reader reads
the rows of ``models/spelling_table.py``, so they agree on what one setting is:
the loader's merge sees one key for it, one owner holds the rule for a file that
writes both spellings, a runtime-patch denial written in either spelling of a
renamed key covers both, and lint reads from the table which spelling replaces
which. The readers:

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

The walk reads a key as the field it names the way the loader reads it
(:func:`field_at`): under the field's name or another spelling of it, under the
``-``/``_`` twin of one (a file that extends a base writing ``global_settings``
can write ``global-settings``, which the merge reads as the same key), and, in a
plugin's segment, under another spelling of a section's name. A message names the
key as the file wrote it. A plugin's section that the configuration does not
declare is walked only for a scanner ASH ships whose manifest gives it no typed
section, read as that scanner's own config class (:func:`field_at`,
:func:`entry_places`). Any other (no shipped manifest, an off-host package, classes
that do not import or disagree, a key with a type word or other punctuation) is not
walked: an old spelling in it is not respelled, said or refused here, the plugin's
model renames it (silently from the removal release), and lint does not report it.

No message here carries a value. A value can be read from the environment, so
every message names files, places in the document, and keys.
"""

from __future__ import annotations

import types
import warnings
from collections import abc as collections_abc
from dataclasses import dataclass, replace
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

from pydantic import BaseModel

from automated_security_helper.config import command_names
from automated_security_helper.models import spelling_table

# The table, and the rules a model reads from it, are in the models package, which
# this one imports and not the other way round. Re-exported: this module is where
# callers have always imported them from.
from automated_security_helper.models.spelling_table import (
    ROWS as ROWS,
    SpellingRow as SpellingRow,
    _alias_strings as _alias_strings,
    _import_model as _import_model,
    _without as _without,
    check_spellings as check_spellings,
    deprecation_message as deprecation_message,
    disagreement_message as disagreement_message,
    disagreement_note as disagreement_note,
    is_removed as is_removed,
    release_label as release_label,
    renamed_field as renamed_field,
    row_model as row_model,
    rows_for as rows_for,
    running_version as running_version,
)

#: The key a config file holds its ``patch`` operations under
#: (``config_sources.PATCH_KEY``, which imports this module and so cannot be read
#: from here).
_PATCH_KEY = "patch"

#: The operations that carry a ``value`` the file's own models read.
_VALUE_OPS = ("add", "replace", "test")

_GLOB_CHARS = frozenset("*?[")


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


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


class _Index:
    """The table read once: each model's fields and places, built when first asked.

    Held for one value of ``spelling_table.ROWS``. A test (or a later release)
    that replaces ``ROWS`` gets a new index, so no lookup answers from rows it was
    not given.
    """

    def __init__(self, rows: Tuple[SpellingRow, ...]) -> None:
        self.rows = rows
        self.fields_by_model: Dict[type[BaseModel], Dict[str, _Field]] = {}
        self.places_by_model: Dict[
            type[BaseModel], Tuple[Tuple[Tuple[str, ...], PlaceKind], ...]
        ] = {}
        #: The section of each shipped scanner that has no typed one, by the
        #: scanner's name, or None for one that cannot be read: found once for each
        #: name (``_known_plugin_field``).
        self.known_plugin_fields: Dict[str, Optional[_Field]] = {}
        #: The canonical spelling of each old one, for a model that is not known.
        self.canonical_of: Dict[str, str] = {}
        for row in rows:
            for old in row.old:
                self.canonical_of.setdefault(old, row.canonical)


_INDEX: Optional[_Index] = None


def _index() -> _Index:
    """The index of the current ``spelling_table.ROWS``."""
    global _INDEX
    rows = spelling_table.ROWS
    index = _INDEX
    if index is None or index.rows is not rows:
        index = _INDEX = _Index(rows)
    return index


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


def _classes_in(annotation: Any) -> List[type[BaseModel]]:
    """Every model class an annotation names, through ``Annotated``, ``Optional``
    and unions."""
    if get_origin(annotation) is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return [annotation]
        return []
    return [model for arg in get_args(annotation) for model in _classes_in(arg)]


# An undeclared plugin section is walked only for a scanner ASH ships whose manifest
# gives no typed section, read as that scanner's own config class. Any other (no
# shipped manifest, an off-host package, classes that do not import or disagree, a key
# with a type word or other punctuation) is not walked: an old spelling in it is not
# respelled, said or refused here, the plugin's model renames it (silently from the
# removal release), and lint does not report it.
def _known_plugin_field(name: str) -> Optional[_Field]:
    """The section of the shipped scanner ``name``, as a field of the scanners
    segment, or None when the scanner has a typed section already, is off-host, or
    has classes that cannot be read.

    The section is read as the scanner's own config class: the one model its
    ``config`` names whose ``options`` are the manifest's options model. Found once
    for each name, a failure too. Reading it imports the scanner's plugin module,
    which registers the scanner there; a scan still takes only the plugins its own
    ``ash_plugin_modules`` name (``plugins.loader.scan_plugin_filter``).
    """
    index = _index()
    if name not in index.known_plugin_fields:
        index.known_plugin_fields[name] = _read_known_plugin_field(name)
    return index.known_plugin_fields[name]


def _read_known_plugin_field(name: str) -> Optional[_Field]:
    # Imported here: a manifest names its plugin by data, and ``resolve_ref`` is the
    # one place that imports it.
    from automated_security_helper.base.plugin_manifest import resolve_ref
    from automated_security_helper.config.plugin_module_trust import off_host_package
    from automated_security_helper.plugin_manifests import manifest_for

    manifest = manifest_for(name)
    if manifest is None or manifest.config_section is not None:
        return None
    if off_host_package(manifest.plugin_module) is not None:
        return None
    try:
        options = resolve_ref(manifest.options_model)
        scanner = resolve_ref(manifest.entry_points.scanner)
    except (ValueError, ImportError, AttributeError):
        return None
    scanner_fields = getattr(scanner, "model_fields", None)
    config = scanner_fields.get("config") if isinstance(scanner_fields, dict) else None
    if config is None:
        return None
    wanted = Shape("model", options)
    configs = {
        model
        for model in _classes_in(config.annotation)
        if "options" in model.model_fields
        and _shape_of(model.model_fields["options"].annotation) == wanted
    }
    if len(configs) != 1:
        return None
    return _Field(
        name=manifest.name,
        written=manifest.name,
        spellings=(manifest.name,),
        shape=Shape("model", configs.pop()),
    )


def _known_plugin_sections(model: type[BaseModel]) -> Tuple[_Field, ...]:
    """The sections ``_known_plugin_field`` reads, as fields of ``model`` when it is
    the scanners segment: none for any other model."""
    # Imported here: ash_config imports this module as it loads.
    from automated_security_helper.config.ash_config import _ScannerConfigSegmentBase
    from automated_security_helper.plugin_manifests import scanner_manifests

    if not issubclass(model, _ScannerConfigSegmentBase):
        return ()
    sections = (_known_plugin_field(manifest.name) for manifest in scanner_manifests())
    return tuple(section for section in sections if section is not None)


def _twins(segment: str) -> Tuple[str, ...]:
    """``segment`` with every ``-`` written as ``_``, and with every ``_`` written
    as ``-``, each one that differs from ``segment``."""
    return tuple(
        twin
        for twin in (segment.replace("-", "_"), segment.replace("_", "-"))
        if twin != segment
    )


def field_at(
    model: type[BaseModel], segment: str, *, known_plugins: bool = False
) -> Optional[Tuple[_Field, str]]:
    """The field of ``model`` that a key or a pointer segment names the way the
    loader reads it, with the spelling of the field that matched; None when it
    names no field.

    In order: ``segment`` itself, as a spelling of a field (``_field_map``: its
    name, its alias, a name of its ``AliasChoices``, an old spelling the table
    gives it); its ``-``/``_`` twins, which the merge and a ``patch`` pointer read
    as the same key (``config_sources._resolve_dict_key``); and, in a plugin's
    segment (scanners, reporters and converters), the one section whose name folds
    to the same name (``ash_config.section_fold_key``), which a pointer reads as
    that section (``config_sources._normalize_pointer``). Two sections that fold
    alike name none.

    With ``known_plugins``, the scanners segment has one more: when none of those
    names a field, the one shipped scanner whose manifest gives it no typed section
    and whose name folds to the same name (``_known_plugin_field``). Reading that
    section imports the scanner's plugin module, so a reader that must import no
    plugin, a denial, leaves the flag off.
    """
    fields = _field_map(model)
    field = fields.get(segment)
    if field is not None:
        return field, segment
    for twin in _twins(segment):
        field = fields.get(twin)
        if field is not None:
            return field, twin
    # Imported here: ash_config imports this module as it loads.
    from automated_security_helper.config.ash_config import (
        _PluginConfigSegment,
        _ScannerConfigSegmentBase,
        section_fold_key,
    )

    if not issubclass(model, _PluginConfigSegment):
        return None
    wanted = section_fold_key(segment)
    folding: Dict[str, Tuple[_Field, str]] = {}
    for spelling, candidate in fields.items():
        if section_fold_key(spelling) == wanted:
            folding.setdefault(candidate.name, (candidate, spelling))
    if folding:
        return next(iter(folding.values())) if len(folding) == 1 else None
    if known_plugins and issubclass(model, _ScannerConfigSegmentBase):
        return _known_plugin_at(wanted)
    return None


def _known_plugin_at(wanted: Tuple[str, str]) -> Optional[Tuple[_Field, str]]:
    """The section of the one shipped scanner with no typed section whose name folds
    to ``wanted`` (``ash_config.section_fold_key``), with the scanner's name; None
    for none or for two."""
    # Imported here: ash_config imports this module as it loads.
    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.plugin_manifests import scanner_manifests

    names = [
        manifest.name
        for manifest in scanner_manifests()
        if manifest.config_section is None and section_fold_key(manifest.name) == wanted
    ]
    if len(names) != 1:
        return None
    field = _known_plugin_field(names[0])
    return None if field is None else (field, names[0])


def key_in(model: type[BaseModel], mapping: Dict[Any, Any], key: str) -> Optional[str]:
    """The key of ``mapping``, a mapping read as ``model``, that is the field
    ``key`` names: ``key`` itself when ``mapping`` holds it, else the one other key
    that reads as the same field (``field_at``, the section of a shipped scanner
    with no typed one included). None when ``mapping`` holds no such key, and when
    it holds more than one."""
    if key in mapping:
        return key
    field = field_at(model, key, known_plugins=True)
    if field is None:
        return None
    readers: List[str] = []
    for name in mapping:
        found = (
            field_at(model, name, known_plugins=True) if isinstance(name, str) else None
        )
        if found is not None and found[0] is field[0]:
            readers.append(name)
    return readers[0] if len(readers) == 1 else None


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

    ``key`` matches a field as ``field_at`` reads it: it is the field's name, its
    alias, a name of its ``AliasChoices`` or an old spelling the table gives it,
    or the ``-``/``_`` twin of one, or another spelling of a plugin's section, or
    the section of a shipped scanner whose manifest gives it no typed one (read as
    that scanner's own config class). A key the model does not declare (an extra, a
    typo) names no shape and is not walked.
    """
    found = field_at(model, key, known_plugins=True)
    return None if found is None else found[0].shape


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
    itself is the place ``()`` when it is ``model`` or a subclass. Under the scanners
    segment, the section of a shipped scanner whose manifest gives it no typed one is
    a field too, written under the scanner's name (``_known_plugin_field``).
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
        for field in (*_field_map(current).values(), *_known_plugin_sections(current)):
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


# ---------------------------------------------------------------------------
# The fold of one document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeySpelling:
    """A key a file wrote under an old spelling, and the key the fold put in its
    place.

    ``path`` is the mapping that holds the key: the keys and list indices from the
    document's root to it, with a ``patch`` operation's value starting at
    ``("patch", index, "value")``. The merged document and the model's errors say
    ``canonical``; a message that names the place in the file says ``written``,
    the key as the file wrote it. The fields after ``written`` are what a record of
    a mapping key the file read from the environment has, so the loader follows
    this one through a ``patch`` the way it follows that one.
    """

    path: Tuple[Any, ...]
    canonical: str
    written: str
    #: Always true: the record is about a mapping key, as a reference is when the
    #: file read the key from the environment.
    key: bool = True

    @property
    def resolved(self) -> str:
        """The key the merged document holds at ``path``."""
        return self.canonical

    def moved_to_unknown_list(self, path: Sequence[Any]) -> "KeySpelling":
        """This record for the mapping a ``patch`` moved to ``path``."""
        return replace(self, path=tuple(path))


@dataclass(frozen=True)
class FoldedDocument:
    """A document with its old spellings renamed, and what to say about them."""

    document: Any
    #: One line per file and old spelling met, each ``Config <file>: <message>``.
    warnings: Tuple[str, ...]
    #: Each lone old key the fold renamed, in the order the walk met them. A key
    #: written beside its canonical spelling is dropped and has no record.
    renamed: Tuple[KeySpelling, ...] = ()


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
        #: Each lone old key renamed, with the mapping that holds it.
        self.renamed: List[KeySpelling] = []

    # -- the document ------------------------------------------------------

    def document(self, document: Any) -> Any:
        if not isinstance(document, dict):
            return document
        folded = self.mapping(document, self.root, "", ())
        operations = folded.get(_PATCH_KEY)
        if isinstance(operations, list):
            respelled = self.operations(operations)
            if respelled is not operations:
                folded = {**folded, _PATCH_KEY: respelled}
        return folded

    def mapping(
        self,
        mapping: Dict[Any, Any],
        model: type[BaseModel],
        place: str,
        path: Tuple[Any, ...],
    ) -> Any:
        """``mapping`` read as ``model``: its own old keys renamed, then the
        values of the fields it holds. ``place`` names the mapping in a message
        and ``path`` is where it stands in the document, under which a rename is
        recorded. A key is read as the field it names the way the loader reads it
        (``field_at``): under the field's name or another spelling of it, under the
        ``-``/``_`` twin of one, which the merge reads as the same key, and, in a
        plugin's segment, as the section it names under another spelling or as the
        section of a shipped scanner that has no typed one. ``place`` and ``path``
        keep the key as the file wrote it. The same object when nothing changes."""
        folded = mapping
        for row in rows_for(model):
            for old in row.old:
                if old in folded:
                    folded = self._respell(folded, row, old, place, path)
        updated: Optional[Dict[Any, Any]] = None
        for key, value in folded.items():
            found = (
                field_at(model, key, known_plugins=True)
                if isinstance(key, str)
                else None
            )
            field = None if found is None else found[0]
            if field is None or field.shape is None:
                continue
            respelled = self.value(value, field.shape, _join(place, key), (*path, key))
            if respelled is not value:
                if updated is None:
                    updated = dict(folded)
                updated[key] = respelled
        return folded if updated is None else updated

    def value(self, value: Any, shape: Shape, place: str, path: Tuple[Any, ...]) -> Any:
        """``value`` read as ``shape``; the same object when nothing changes."""
        if shape.kind == "model":
            if not isinstance(value, dict):
                return value
            return self.mapping(value, shape.model, place, path)
        if shape.kind == "list":
            if not isinstance(value, list):
                return value
            items = [
                self.mapping(item, shape.model, f"{place}[{index}]", (*path, index))
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
            key: self.mapping(item, shape.model, f"{place}.<key>", (*path, key))
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
        self,
        mapping: Dict[Any, Any],
        row: SpellingRow,
        old: str,
        place: str,
        path: Tuple[Any, ...],
    ) -> Dict[Any, Any]:
        canonical = row.canonical
        self._met(row, old, place)
        if canonical not in mapping:
            self.renamed.append(KeySpelling(path, canonical, old))
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
            respelled = self.operation(
                operation, f"{_PATCH_KEY}[{index}]", (_PATCH_KEY, index)
            )
            if respelled is not operation:
                folded[index] = respelled
                changed = True
        return folded if changed else operations

    def operation(
        self, operation: Dict[Any, Any], place: str, path: Tuple[Any, ...]
    ) -> Dict[Any, Any]:
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
            folded = self.value(value, end, f"{place}.value", (*path, "value"))
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
            found = field_at(shape.model, segment, known_plugins=True)
            if found is None:
                return segment, None
            field, matched = found
            row = _row_with_old(shape.model, matched)
            if row is None:
                # Not an old spelling: the segment stays as written, a twin or a
                # variant of a section included, which the loader resolves by its
                # own rule, and the walk goes on through the field.
                return segment, field.shape
            self._met(row, matched, place)
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
    know: the module docstring says which plugin sections it does not walk. The
    file's ``patch`` operations are part of it: each ``path`` and ``from`` pointer
    is respelled along the model, and a value an operation adds, replaces or tests
    is read as the model its path names (the whole configuration, for the root
    pointer). Never changes ``document``.

    Raises SpellingRefused, naming ``source``, the place and the keys, when an old
    spelling is read at or after the row's ``removed_in`` (``version`` is the
    release, the running one when None) and when a mapping writes both spellings
    with different values. Each old spelling met also emits the row's
    ``DeprecationWarning``, and the returned ``warnings`` hold one line for each
    spelling the file uses, however many places use it. ``renamed`` holds one
    :class:`KeySpelling` for each old key renamed in a mapping that had no
    canonical key, so a message that names a place in the file can say the key as
    the file wrote it. A refusal at the removal release ends with the registry's
    sentence about the command that rewrites the file; ``by_hand`` is for a file
    that command does not rewrite in place (a TOML one), whose sentence says to
    edit the key (``removal_message``).
    """
    fold = _Fold(
        model if model is not None else _root_model(),
        source,
        version,
        by_hand=by_hand,
    )
    folded = fold.document(document)
    return FoldedDocument(folded, tuple(fold.lines.values()), tuple(fold.renamed))


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
    one: a denial then covers more, never less. A segment that is not an old
    spelling is kept as written, the ``-``/``_`` twin of a key and another
    spelling of a plugin's section included: ``field_at`` reads each as the field,
    so the model stays known past it. The section of a shipped scanner that has no
    typed one is a key the walk does not know here, since a denial imports no
    plugin. Whether a row's old spelling is still read is not asked: an operator's
    denial written under the old spelling keeps denying both.
    """
    index = _index()
    shape: Optional[Shape] = Shape("model", _root_model())
    result: List[str] = []
    for segment in segments:
        if shape is not None and segment != "**":
            if shape.kind == "model":
                found = None if _is_glob(segment) else field_at(shape.model, segment)
                if found is not None:
                    field, matched = found
                    row = _row_with_old(shape.model, matched)
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
