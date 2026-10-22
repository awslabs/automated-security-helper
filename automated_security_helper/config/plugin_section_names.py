# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One rule for when two spellings of a known plugin's section are one name.

The model reads any spelling of a declared plugin's section (case and the
``-``/``_`` separators dropped) as that plugin's section
(ash_config._PluginConfigSegment). The record of what a file read from the
environment keys each reference and rewrite by the section's place, and
``extends`` merges sections by key, so they all have to agree on the spelling.
The fold happens once, in the document (config_sources._resolve and the
views paired with it), before references and rewrites are recorded and before
``extends`` merges; the model folds with the same functions, for a
configuration built from a dict directly (a results file's record, a
``--config-overrides`` round-trip). The config linter deliberately reads each
file unfolded, so its warnings can name the spelling the file wrote.

Where both the declared spelling and a variant appear in one mapping, the
declared spelling wins key by key. Two non-declared spellings of one plugin
name no winner, so they are refused as ambiguous.
"""

import string
from typing import Any, Dict, Tuple

from pydantic import BaseModel

#: The AshConfig sections whose children are known plugins' sections.
PLUGIN_SEGMENT_KEYS: Tuple[str, ...] = ("converters", "scanners", "reporters")

#: ASCII-only lowering. Declared plugin names are ASCII, so only ASCII case can
#: be a respelling of one. Unicode case rules read more as equal -- casefold
#: turns the long s (U+017F) into "s" -- and the runtime-patch deny policy's
#: lowering does not, so a Unicode fold here read a spelling as a plugin's
#: section that no denial covered. Non-ASCII characters stay themselves.
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


class AmbiguousPluginSpellings(ValueError):
    """Two non-declared spellings of one known plugin in one mapping.

    Carries the parts, so the document loader can rebuild the message with an
    env-read key named by its written form instead of its value
    (config_sources). The default message names the keys as the mapping holds
    them, which is safe for a configuration built from a dict directly: no
    environment read mediates those keys.
    """

    def __init__(self, segment_key: str, first: str, second: str, target: str):
        self.segment_key = segment_key
        self.first = first
        self.second = second
        self.target = target
        super().__init__(
            f"{segment_key}.{first} and {segment_key}.{second} are two "
            f"spellings of the {target} section: ambiguous, keep one"
        )


def folded_section_name(name: str) -> str:
    """``name`` with ASCII case and the ``-``/``_`` separators dropped: the form
    on which two spellings of one plugin's section name are the same name. ASCII
    only, so the fold and the runtime-patch deny policy agree on what is a
    spelling of a plugin (see ``_ASCII_LOWER``)."""
    return name.replace("-", "").replace("_", "").translate(_ASCII_LOWER)


def declared_section_names(segment_key: str) -> Dict[str, str]:
    """The declared plugin section names under ``segment_key``, by their folded
    form. Read from the segment model's fields (the alias where one is
    declared), so a plugin added later is covered without being listed."""
    # Imported here: ash_config imports this module.
    from automated_security_helper.config import ash_config

    segments: Dict[str, type[BaseModel]] = {
        "converters": ash_config.ConverterConfigSegment,
        "scanners": ash_config.ScannerConfigSegment,
        "reporters": ash_config.ReporterConfigSegment,
    }
    segment_cls = segments[segment_key]
    declared = {info.alias or name for name, info in segment_cls.model_fields.items()}
    return {folded_section_name(name): name for name in declared}


def plugin_key_in(container: Any, parent_key: Any, key: str) -> "str | None":
    """The spelling of ``key`` an override should use inside ``container``, a
    mapping directly under ``parent_key``, when ``key`` is a spelling of a
    declared plugin's section; ``None`` otherwise. An existing variant spelling
    in ``container`` wins over the declared one, so the override lands on the
    section the document holds. Unknown sections and extras never fold."""
    if parent_key not in PLUGIN_SEGMENT_KEYS or not isinstance(key, str):
        return None
    declared_by_fold = declared_section_names(parent_key)
    folded = folded_section_name(key)
    if folded not in declared_by_fold:
        return None
    if isinstance(container, dict):
        for existing in container:
            if isinstance(existing, str) and folded_section_name(existing) == folded:
                return existing
    return declared_by_fold[folded]


def _merged_raw(variant: Any, declared: Any) -> Any:
    """``variant`` and ``declared`` merged key by key, ``declared`` winning.
    Anything that is not a mapping on both sides is ``declared`` whole."""
    if not (isinstance(variant, dict) and isinstance(declared, dict)):
        return declared
    merged = dict(variant)
    for key, value in declared.items():
        merged[key] = _merged_raw(merged[key], value) if key in merged else value
    return merged


def fold_known_plugin_sections(data: Any) -> Any:
    """``data``, a config file's parsed mapping, with each known plugin's
    section keyed by its declared spelling. A copy; ``data`` is not changed.

    Raises ValueError when one mapping holds two non-declared spellings of one
    plugin, naming both spellings and no value.
    """
    if not isinstance(data, dict):
        return data
    folded = data
    for segment_key in PLUGIN_SEGMENT_KEYS:
        section = folded.get(segment_key)
        if not isinstance(section, dict):
            continue
        declared_by_fold = declared_section_names(segment_key)
        seen_variant: Dict[str, str] = {}
        result = dict(section)
        for key in list(result):
            if not isinstance(key, str) or key in declared_by_fold.values():
                continue
            target = declared_by_fold.get(folded_section_name(key))
            if target is None:
                continue
            earlier = seen_variant.get(target)
            if earlier is not None:
                raise AmbiguousPluginSpellings(segment_key, earlier, key, target)
            seen_variant[target] = key
            value = result.pop(key)
            result[target] = (
                _merged_raw(value, result[target]) if target in result else value
            )
        if result != section:
            if folded is data:
                folded = dict(data)
            folded[segment_key] = result
    return folded
