"""The table of renamed configuration spellings, and the rules a model reads from it.

A configuration key is renamed in a release, and the old spelling keeps loading,
with a deprecation line, until the release that removes it. :data:`ROWS` lists each
rename. This module holds that table, the release gate over it
(:func:`is_removed`), the text a row gives (:func:`deprecation_message`,
:func:`disagreement_message`, :func:`disagreement_note`) and the two things a
model does with a row:

* :func:`renamed_field` declares a renamed field, taking its old spellings from
  the table;
* :func:`check_spellings` is the body of the ``mode="before"`` validator that
  applies the rule of one spelling per field to a model built from a mapping.

It sits with the models so that a model reads the table without importing the
config package. The readers that walk a document (the loader's fold, the
runtime-patch denials, lint) are in ``config/spellings.py``, which re-exports the
names here.

No message here carries a value. A value can be read from the environment, so
every message names keys.
"""

from __future__ import annotations

import importlib
import warnings
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional, Tuple

from packaging.version import InvalidVersion, Version
from pydantic import AliasChoices, AliasPath, BaseModel, Field, ValidationInfo
from pydantic_core import PydanticUndefined

from automated_security_helper.utils.unknown_keys import tolerated_notes, warned_notes


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


def disagreement_note(row: SpellingRow, old: str) -> str:
    """What a stored config records when it holds both spellings with different
    values. No value: the reader that collects it names where the entry is."""
    return f"both {old} spellings, disagreeing"


# ---------------------------------------------------------------------------
# The rows' models
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


class _RowIndex:
    """The table read once: each model's rows, built when first asked.

    Held for one value of ``ROWS``. A test (or a later release) that replaces
    ``ROWS`` gets a new index, so no lookup answers from rows it was not given.
    """

    def __init__(self, rows: Tuple[SpellingRow, ...]) -> None:
        self.rows = rows
        self.rows_by_model: Dict[type[BaseModel], Tuple[SpellingRow, ...]] = {}


_ROW_INDEX: Optional[_RowIndex] = None


def _row_index() -> _RowIndex:
    """The index of the current ``ROWS``."""
    global _ROW_INDEX
    rows = ROWS
    index = _ROW_INDEX
    if index is None or index.rows is not rows:
        index = _ROW_INDEX = _RowIndex(rows)
    return index


def rows_for(model: type[BaseModel]) -> Tuple[SpellingRow, ...]:
    """The rows whose model is ``model`` or one of its base classes."""
    index = _row_index()
    found = index.rows_by_model.get(model)
    if found is None:
        found = tuple(row for row in index.rows if issubclass(model, row_model(row)))
        index.rows_by_model[model] = found
    return found


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
    for row in _row_index().rows:
        if row.model == model and row.canonical == name:
            old.extend(spelling for spelling in row.old if spelling not in old)
    if not old:
        raise ValueError(
            f"{model}.{name} is declared with renamed_field but the spelling "
            "table has no row for it"
        )
    return Field(default, validation_alias=AliasChoices(name, *old), **field_kwargs)


# ---------------------------------------------------------------------------
# The rule of a model built without the loader
# ---------------------------------------------------------------------------


def _without(data: Dict[Any, Any], old: str) -> Dict[Any, Any]:
    return {key: value for key, value in data.items() if key != old}


def _field_reads(model: type[BaseModel], name: str, key: str) -> bool:
    """Whether the field ``name`` of ``model`` reads ``key`` itself, as a key of
    its alias or of its validation alias."""
    field = model.model_fields.get(name)
    if field is None:
        return False
    return key in (
        *_alias_strings(field.alias),
        *_alias_strings(field.validation_alias),
    )


def check_spellings(model: type[BaseModel], data: Any, info: ValidationInfo) -> Any:
    """The body of a ``mode="before"`` validator: one spelling per field.

    A stored config (a results file, ``TOLERATE_STORED_CONFIG``) is a record: an
    equal duplicate drops the old key, different values record a note and keep the
    data, and nothing is said or gated, so a results file loads at every release.

    A config built from a mapping says the deprecation while the row is live (a
    ``DeprecationWarning`` and, where the load collects them, a line), drops an
    old key equal to the canonical one, refuses different values, and otherwise
    leaves a lone old key the field reads itself under its aliases (so the
    location pydantic prints for an error names the key as the data wrote it) and
    renames any other old key where it stood. From the row's removal release it
    does the same and says nothing: the model reads an old spelling at every release
    and refuses none, so an entry built in code keeps loading, and what refuses a
    removed spelling is a reader of a document (the loader's fold, and
    ``config.spellings.refuse_removed_spellings``). A file the loader read has
    been folded already, so this meets only what was built from a mapping
    directly: a model validated in code, an override.

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
                if not _field_reads(model, row.canonical, old):
                    data = {
                        (row.canonical if key == old else key): value
                        for key, value in data.items()
                    }
            elif data[old] == data[row.canonical]:
                data = _without(data, old)
            else:
                raise ValueError(disagreement_message(row, old))
    return data
