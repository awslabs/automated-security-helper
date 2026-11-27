"""What an override that lands on a list does to the records of that list.

A configuration records each value and key its files read from the environment
at the place the file wrote it, a list entry by its index:
``_environment_references`` and ``_displayed_environment_references`` (where a
view or a message shows the reference or ``<value>``, never the value) and
``_written_references`` (where the record of the configuration writes the
reference back, ``record_of_config``). The load attaches them after
``--config-overrides`` were applied to the model, so what each override did to a
list is carried over to them here:

- ``KEY=VALUE`` replaces the value at KEY. No record at KEY or under it describes
  what KEY holds now, so every one is dropped, whatever the value is.
- ``KEY-=VALUE`` takes items out of the list at KEY. Each kept entry moves to a
  lower index and its records move with it; a removed entry's records are
  dropped. Dropping the kept entries' records too would show their values in
  clear.
- ``KEY+=VALUE`` adds to the end of the list, so no entry moves: nothing to do.

A ``ListChange`` is one replacement or one removal, and changes apply in the
order of the overrides. ``apply_config_overrides`` collects them, reconciles the
records of the model it rebuilt, and stamps them on that model
(``AshConfig._override_list_changes``); ``load_config_file_for_run`` reconciles
the records it attaches from the stamp, before it places a patch append
(``placed_at_appends``). Each change applies to a record once: a removal's map
read twice would take a moved record's new index for an old one. A change's path
is compared with a record's path one whole segment at a time, keys in the
spelling ``environment_record`` matches them in (``-`` and ``_`` alike, any
case), so a change at ``exclude`` leaves ``exclude_more`` alone.
"""

from __future__ import annotations

from dataclasses import dataclass, is_dataclass, replace
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Sequence, Tuple

from automated_security_helper.utils.override_key import REMOVE, REPLACE, OverrideOp

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: The attributes of a configuration that hold its records by place.
LIST_REFERENCE_ATTRIBUTES: Tuple[str, ...] = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@dataclass(frozen=True)
class ListChange:
    """What one override did to the value at ``path``.

    ``path`` is the keys the override landed on, as the apply resolved them (the
    first item ``_apply_config_override`` returns). ``op`` is ``REPLACE`` for an
    override that set the value, or ``REMOVE`` for a removal from a list the
    configuration held. For a removal, ``old_length`` is how many entries the
    list had before it, and ``kept`` the old index of each entry it kept, in
    order: the entry that was at ``kept[n]`` is at index ``n`` after it.
    """

    path: Tuple[str, ...]
    op: OverrideOp
    old_length: int = 0
    kept: Tuple[int, ...] = ()


def _spelled(segment: Any) -> Any:
    """A key as ``environment_record`` compares keys, ``-`` and ``_`` alike and
    in any case; an index or the any-index marker as it is."""
    if isinstance(segment, str):
        return segment.replace("-", "_").lower()
    return segment


def _at_or_under(path: Sequence[Any], prefix: Tuple[Any, ...]) -> bool:
    """Whether ``path`` is ``prefix`` or a place under it, segment by segment."""
    return len(path) >= len(prefix) and all(
        _spelled(segment) == wanted for segment, wanted in zip(path, prefix)
    )


def _placed_at(item: Any, path: Tuple[Any, ...], width: int, length: int) -> Any:
    """``item`` at ``path``. An ``EnvironmentReference`` written as an entry of
    the list that moved (its ``index_at`` is that list's index position,
    ``width``) also gets the list's new ``length``, so a view that compares the
    two (``environment_record._Index._moved``) reads it as in place; one written
    in a list inside the entry keeps its own. An ``EnvironmentRewrite`` has no
    length."""
    if is_dataclass(item):
        if getattr(item, "index_at", None) == width:
            return replace(item, path=path, length=length)
        return replace(item, path=path)
    return item._replace(path=path)


def reconciled_list_references(
    items: Iterable[Any], changes: Sequence[ListChange]
) -> List[Any]:
    """``items``, records of a configuration by place (``EnvironmentReference``
    or ``EnvironmentRewrite``), as they read after ``changes``, in order.

    A replacement drops every record at its path or under it. A removal moves a
    record under one of the list's entries to the entry's new index, and drops
    one under an entry it removed. A record that names no entry the removal saw
    is left as it is: one at the list itself, one at the any-index marker
    (``environment_record.UNKNOWN_INDEX``, found later by its value), a patch
    append not yet placed (``-``, which ``placed_at_appends`` places against the
    list as the overrides left it), and one at an index past the list's old
    length. The order of the records is kept.
    """
    result = list(items)
    for change in changes:
        prefix = tuple(_spelled(segment) for segment in change.path)
        width = len(prefix)
        new_index: Dict[int, int] = {old: new for new, old in enumerate(change.kept)}
        following: List[Any] = []
        for item in result:
            path = tuple(item.path)
            if not _at_or_under(path, prefix):
                following.append(item)
                continue
            if change.op == REPLACE:
                continue
            if change.op != REMOVE or len(path) == width:
                following.append(item)
                continue
            old = path[width]
            if not isinstance(old, int) or not 0 <= old < change.old_length:
                following.append(item)
                continue
            if old in new_index:
                moved = (*path[:width], new_index[old], *path[width + 1 :])
                following.append(_placed_at(item, moved, width, len(change.kept)))
        result = following
    return result


def reconcile_list_references(
    config: "AshConfig", changes: Sequence[ListChange]
) -> None:
    """Apply ``changes`` to each list of ``config``'s records
    (``LIST_REFERENCE_ATTRIBUTES``), keeping each list's type: a tuple stays a
    tuple."""
    if not changes:
        return
    for attribute in LIST_REFERENCE_ATTRIBUTES:
        held = getattr(config, attribute, None)
        if not held:
            continue
        reconciled = reconciled_list_references(held, changes)
        setattr(
            config,
            attribute,
            tuple(reconciled) if isinstance(held, tuple) else reconciled,
        )
