# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refusing keys a config model does not declare, and when not to.

These models refuse an unknown key: the entries of ``suppressions`` and
``ignore_paths`` (``models/core.py``), where a dropped key such as a misspelled
``rule_id`` would leave a suppression covering every rule in its path, and plugin
options (``base/options.py``), where a kept key would never be read.
:func:`refuse_unknown_keys` is the check they share, and
:func:`unknown_keys_message` the wording, so a key is named the same way and
gets the same "did you mean" wherever it was written.

Results files are the exception. ``ash_aggregated_results.json`` records the
config a scan ran with, and every reader of one (``ash report``,
``--existing-results``, ``ash merge``, workspace reporting, the MCP tools)
validates that record again. One written by another ASH version can carry a
key this version does not declare, or a value its validators refuse, and
refusing the whole file would lose the results for a config nobody is about to
apply. The results loader therefore validates the stored config with
``TOLERATE_STORED_CONFIG`` in the validation context, bound to a list: the
checks here, and the ones in ``models/core.py`` that honor it, record a note in
that list and keep the data instead of raising, and the loader logs each note.
The models keep such a key as an extra, which is what marks an entry as one
never to apply (``IgnorePathWithReason.has_unknown_keys``).
"""

from __future__ import annotations

import difflib
import os
import re
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from pydantic import AliasChoices, AliasPath, BaseModel, ValidationInfo

#: Validation-context key. Bound to a list, it makes the checks that honor it
#: record a note there and keep the data rather than refuse it. Passed only by
#: ``AshAggregatedResults.validate_ash_config``.
TOLERATE_STORED_CONFIG = "tolerate_stored_config"

#: What a kept unknown key records under TOLERATE_STORED_CONFIG, once per key.
#: Not the key: a stored key is the results file's data, so the results loader
#: names the section that holds it instead (models/asharp_model.py). A config
#: file's refusal still names the key, since its author needs the typo.
UNKNOWN_KEY_NOTE = "an unknown key <key>"

#: The fields older ``ash config init`` versions wrote into each plugin section,
#: by segment: ASH's own bookkeeping, never a setting the operator chose. A
#: section declares ``name`` (and a reporter's ``extension``), so a scan accepts
#: those and the config checks warn about them; it refuses the others.
INTERNAL_SECTION_FIELDS: Dict[str, FrozenSet[str]] = {
    "scanners": frozenset({"name", "extension", "tool_version", "install_timeout"}),
    "reporters": frozenset({"name", "extension"}),
    "converters": frozenset({"name", "tool_version", "install_timeout"}),
}

_SECTION_KINDS = {"scanners": "Scanner", "reporters": "Reporter"}

#: What an internal-only field may have been meant as, when the plugin also
#: declares an option of that name (bandit's tool_version, for example).
OPTION_MEANINGS = {
    "tool_version": "a version constraint",
    "install_timeout": "an install timeout",
}

#: internal_field_message's text, read back: the kind, the section and the field.
INTERNAL_FIELD_MESSAGE = re.compile(
    r"(Scanner|Reporter|Converter) '([^']+)' contains internal-only field '([^']+)'"
    r" - this should not be in user configs"
)


def internal_field_message(segment: str, section: str, field: str) -> str:
    """``Scanner 'bandit' contains internal-only field 'tool_version' - ...``

    The one wording for such a field: the model's refusal, the config checks'
    warning for one a scan accepts, and what ``ash config lint --fix`` reads to
    remove it (INTERNAL_FIELD_MESSAGE).
    """
    kind = _SECTION_KINDS.get(segment, "Converter")
    return (
        f"{kind} '{section}' contains internal-only field '{field}' - "
        "this should not be in user configs"
    )


def internal_fields_named(message: str) -> List[Tuple[str, str, str]]:
    """``(kind, section, field)`` for each internal_field_message in ``message``."""
    return [
        (match.group(1), match.group(2), match.group(3))
        for match in INTERNAL_FIELD_MESSAGE.finditer(message)
    ]


def tolerated_notes(info: Optional[ValidationInfo]) -> Optional[List[str]]:
    """The list to record a note in, when validation is under the tolerance."""
    if info is None or not info.context:
        return None
    notes = info.context.get(TOLERATE_STORED_CONFIG)
    return notes if isinstance(notes, list) else None


def known_keys(model_cls: type[BaseModel]) -> Set[str]:
    """Every key ``model_cls`` accepts: field names and their aliases.

    A validation alias can be one name, an ``AliasChoices`` of several, or an
    ``AliasPath`` into a nested value; pydantic accepts a key by each choice and
    by a path's first segment, so each of those is a key here too, and
    ``refuse_unknown_keys`` does not refuse a key the model would take.

    A field's own name is a key only when pydantic reads it: always for a field
    with no alias, and for an aliased field only when the model validates by
    name too (``populate_by_name`` or ``validate_by_name``) or not by alias at
    all. Counted whatever the model did, a key written by field name for an
    alias-only field passed this check and was kept as an extra the model never
    read, where a misspelled alias is refused with its "did you mean".
    """
    config = model_cls.model_config
    by_name = bool(
        config.get("validate_by_name", config.get("populate_by_name", False))
    )
    by_alias = config.get("validate_by_alias", True)
    keys: Set[str] = set()
    for name, field in model_cls.model_fields.items():
        aliased = field.alias is not None or field.validation_alias is not None
        if not aliased or by_name or not by_alias:
            keys.add(name)
        if field.alias:
            keys.add(field.alias)
        keys.update(_alias_keys(field.validation_alias))
    return keys


def _alias_keys(alias: Any) -> Set[str]:
    """The top-level keys a field's validation alias accepts."""
    if isinstance(alias, str):
        return {alias}
    if isinstance(alias, AliasChoices):
        keys: Set[str] = set()
        for choice in alias.choices:
            keys.update(_alias_keys(choice))
        return keys
    if isinstance(alias, AliasPath):
        first = alias.path[0] if alias.path else None
        return {first} if isinstance(first, str) else set()
    return set()


def _folded(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")


def closest_key(key: str, known: Iterable[str]) -> Optional[str]:
    """The declared key ``key`` was probably meant to be, or None.

    Case, ``_`` and ``-`` are ignored first, so ``ruleId`` and ``rule-id`` are
    ``rule_id``; then the closest spelling by ``difflib``, if it is close; then
    the key sharing the longest stem of at least four characters and half the
    key (``expires`` for ``expiration``).
    """
    known = sorted(known)
    for candidate in known:
        if _folded(candidate) == _folded(key):
            return candidate
    matches = difflib.get_close_matches(key.lower(), known, n=1, cutoff=0.6)
    if matches:
        return matches[0]
    # A shared stem difflib scores low: "expires" for "expiration".
    prefix_lengths = {
        candidate: len(os.path.commonprefix([key.lower(), candidate.lower()]))
        for candidate in known
    }
    best = max(prefix_lengths, key=lambda c: prefix_lengths[c], default=None)
    if best is not None and prefix_lengths[best] >= max(4, len(key) // 2):
        return best
    return None


def unknown_keys_message(
    unknown: Iterable[str], known: Iterable[str], where: str
) -> str:
    """``Unknown key 'ruleId' (did you mean 'rule_id'?) in a suppression. ...``"""
    known = sorted(known)
    named = []
    for key in unknown:
        suggestion = closest_key(key, known)
        named.append(
            f"'{key}'" + (f" (did you mean '{suggestion}'?)" if suggestion else "")
        )
    noun = "key" if len(named) == 1 else "keys"
    # Only a plugin's options can declare nothing: every entry kind has keys.
    accepted = (
        f"Accepted keys: {', '.join(known)}."
        if known
        else "No key is accepted: the plugin declares no options."
    )
    return f"Unknown {noun} {', '.join(named)} in {where}. {accepted}"


def misplaced_key_problems(
    unknown: Iterable[str], known: Iterable[str], option_keys: Set[str], where: str
) -> List[str]:
    """What to say about keys at a plugin section's level that it does not declare.

    ``where`` is the section's place, ``scanners.bandit``. A field older ``ash
    config init`` versions wrote there (INTERNAL_SECTION_FIELDS) is named as an
    internal-only field, even when the plugin has an option of that name:
    moving a leaked ``tool_version`` under ``options`` would make it a version
    constraint. A key that is one of the plugin's options belongs under
    ``options``, and the message says so: ``scanners.bandit.severity_threshold
    is not a section-level key; move severity_threshold under options``. Any
    other key is named as unknown, with a suggestion when one is close.
    """
    known = sorted(known)
    segment, _, section = where.partition(".")
    internal = INTERNAL_SECTION_FIELDS.get(segment, frozenset())
    problems = []
    other = []
    for key in unknown:
        if key in internal:
            message = internal_field_message(segment, section, key)
            if key in option_keys:
                # The plugin has an option of that name: the field may be a
                # pin the operator meant, written a level too high.
                meant = OPTION_MEANINGS.get(key, f"its {key} option")
                message += f"; if you meant {meant}, put it under options"
            problems.append(f"{message}.")
        elif key in option_keys:
            problems.append(
                f"{where}.{key} is not a section-level key; move {key} under options."
            )
        else:
            other.append(key)
    if other:
        problems.append(unknown_keys_message(other, known, where))
    return problems


#: The words :func:`unknown_keys_message` and :func:`misplaced_key_problems`
#: give a key a model does not declare, read back: ``Unknown key 'x' ...``,
#: ``Unknown keys 'a', 'b' ...`` and ``scanners.bandit.severity_threshold is
#: not a section-level key; move severity_threshold under options.`` An
#: internal-only field is read back by INTERNAL_FIELD_MESSAGE. A cell compares
#: this with what those functions write, so the wording cannot drift from it.
UNDECLARED_KEY_MESSAGE = re.compile(
    r"Unknown keys? '| is not a section-level key; move "
)


def error_names_an_undeclared_key(error: Mapping[str, Any]) -> bool:
    """Whether *error*, one entry of a pydantic ``ValidationError.errors()``,
    refuses a key the model does not declare and nothing else.

    Two shapes carry such a refusal: a section that forbids extras
    (``extra_forbidden``), and a validator of ours that words the key itself
    (``value_error`` whose message is one of the above, raised by
    :func:`refuse_unknown_keys` and the plugin section check). Every other
    error is about a value, or about the shape of the document, and is not
    this: a later schema that declares the key accepts the document, while a
    value of the wrong kind for a field both schemas declare stays refused.
    Reads the error's type and message, never its input.
    """
    kind = error.get("type")
    if kind == "extra_forbidden":
        return True
    if kind != "value_error":
        return False
    message = str(error.get("msg", ""))
    return bool(
        UNDECLARED_KEY_MESSAGE.search(message) or INTERNAL_FIELD_MESSAGE.search(message)
    )


def refuse_unknown_keys(
    model_cls: type[BaseModel], data: Any, info: Optional[ValidationInfo], where: str
) -> Any:
    """The body of a ``mode="before"`` model validator that refuses unknown keys.

    Raises ``ValueError``, which pydantic reports at the location of the model
    in the config (``global_settings.suppressions.0``,
    ``scanners.bandit.options``), so the error says where as well as what.
    Under ``TOLERATE_STORED_CONFIG`` the keys are recorded and ``data`` is
    returned unchanged; the model, which must allow extras for this, keeps them.
    """
    if not isinstance(data, dict):
        return data
    known = known_keys(model_cls)
    unknown = [key for key in data if isinstance(key, str) and key not in known]
    if not unknown:
        return data
    notes = tolerated_notes(info)
    if notes is not None:
        notes.extend(UNKNOWN_KEY_NOTE for _ in unknown)
        return data
    raise ValueError(unknown_keys_message(unknown, known, where))
