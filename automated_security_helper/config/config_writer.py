# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ASH writes a whole config file from an AshConfig.

One writer for every command that does: `ash config init`, `wizard` and
`update`, and ``AshConfig.save`` (the MCP server's session configs), so none of
them writes the internal fields ConfigValidator warns about, and a ``.json`` file
gets JSON, which the loader can parse.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    AshConfig,
    ConverterConfigSegment,
    MCPResourceManagementConfig,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
from automated_security_helper.config.config_sources import is_json_file
from automated_security_helper.utils.report_yaml import NoCommandLineDumper

SCHEMA_COMMENT = "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json"


class IndentableYamlDumper(NoCommandLineDumper, yaml.Dumper):
    """The dumper of each config file and config view ASH writes, with no line a
    CI workflow command (utils/report_yaml.py)."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super(IndentableYamlDumper, self).increase_indent(flow, indentless)


class _EnvTagged(str):
    """A reference a file wrote with an explicit ``!ENV`` tag, without the tag."""

    __slots__ = ()


class _Reference(str):
    """A reference a file wrote untagged (``${VAR}``), written plain so that the
    loader's implicit resolver reads it as one again, or with the ``!ENV`` tag
    where the emitter cannot write it plain (_represent_reference)."""

    __slots__ = ()


_ENV_TAG = "!ENV "


def _as_reference(written: str) -> Any:
    """The record's string for a location its file read from the environment
    (record_of_config's ``mark``), typed by how the file wrote it."""
    if written.startswith(_ENV_TAG):
        return _EnvTagged(written[len(_ENV_TAG) :])
    return _Reference(written)


def _represent_text(dumper: yaml.Dumper, value: str) -> yaml.ScalarNode:
    """A string that is no reference, quoted when written plain it would read
    as one: a ``${VAR...}`` start (ENV_REFERENCE_PATTERN, the implicit
    resolver's), or a leading ``!``, a tag."""
    if ENV_REFERENCE_PATTERN.match(value) or value.startswith("!"):
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="'")
    return dumper.represent_str(value)


def _represent_reference(dumper: yaml.Dumper, value: str) -> yaml.ScalarNode:
    """A reference the file wrote untagged, plain where the emitter writes it so.

    The loader's implicit resolver reads only a plain scalar as a reference. Text
    the emitter would quote (a non-ASCII character, ``' #'``, ``': '``, a line
    break, or a ``'::'`` after a blank, which NoCommandLineDumper quotes) would
    read back as a literal, so it is written with the explicit ``!ENV`` tag,
    which the loader resolves however the scalar is quoted.
    """
    text = str(value)
    node = dumper.represent_str(text)
    if node.style is None and dumper.analyze_scalar(text).allow_block_plain:
        return node
    return dumper.represent_scalar("!ENV", text)


# Every writer dumping with this class (config update's render_config_file,
# the linter's --fix) keeps a reference-shaped literal quoted, as the save
# path does; a plain dump would turn it into a reference the next load reads.
IndentableYamlDumper.add_representer(str, _represent_text)


class _AsWrittenYamlDumper(IndentableYamlDumper):
    """IndentableYamlDumper for a record with references marked: an _EnvTagged
    string with its tag, a _Reference plain, and any other string as text."""


_AsWrittenYamlDumper.add_representer(
    _EnvTagged, lambda dumper, value: dumper.represent_scalar("!ENV", str(value))
)
_AsWrittenYamlDumper.add_representer(_Reference, _represent_reference)
_AsWrittenYamlDumper.add_representer(str, _represent_text)


def _paths_in_record(
    rewrites: List[Any], path: Tuple[Any, ...]
) -> List[Tuple[Any, ...]]:
    """The places the record can hold the value a rewrite names at ``path``.

    A value's path names a key its files read from the environment by the value
    it resolved to, and record_of_config renames that key to the reference its
    file wrote after it has recorded the values. Each such segment is looked up
    as the key written: as the text the file wrote (the record of a JSON file),
    and as the typed key a marked record holds (_as_reference, which leaves an
    explicit tag off).
    """
    renamed = {
        (tuple(rewrite.path), rewrite.resolved): rewrite.written
        for rewrite in rewrites
        if rewrite.kind == "key"
    }
    as_written: List[Any] = []
    as_typed: List[Any] = []
    for index, segment in enumerate(path):
        written = renamed.get((tuple(path[:index]), segment))
        as_written.append(segment if written is None else written)
        as_typed.append(segment if written is None else _as_reference(written))
    places = [tuple(as_written)]
    if as_typed != as_written:
        places.append(tuple(as_typed))
    return places


def _without_references(text: str, rewrite: Any) -> str:
    """``text`` without the reference ``rewrite`` records, as the file wrote it
    and as the part of it a variable stands for.

    A reference can hold its variable's value itself, as its default
    (``${VAR:value}``), and the record of a JSON file holds each reference as a
    plain string, which no type marks. What remains is text the record kept.
    """
    for reference in (rewrite.written, rewrite.reference):
        if reference:
            text = text.replace(reference, "")
    return text


def _refuse_a_value_left_as_text(data: Any, ash_config: AshConfig) -> None:
    """Raise RuntimeError when ``data``, the record of ``ash_config``, holds a
    value its files read from the environment as text where they wrote its
    reference.

    record_of_config writes each such value as its reference, at the location
    its rewrite names. One left there as text (a string the record could not
    write as the reference) would be a literal the scan reads and no redaction
    knows: not written, then, rather than written so. Only those locations are
    looked at, and the reference itself is taken out of a string before it is
    compared with the value, since its default can be the value. A location
    under a key read from the environment is looked up under the key as
    written. A runtime patch keeps the rewrites whose value is still where
    they were followed to, drops those an op wrote over, and is refused when a
    value moved anywhere else (runtime_patch._ReferencesThroughPatch), so a
    default, or a client's string, equal to a value is not one: comparing every
    string refused valid profiles, and told a client its guess was right. The
    message names no value or location, since a location can hold a key read
    from the environment. A value at such a location that is not a string (a
    list the model made of one reference's string) is one when the reference's
    text loads as it (reads_back_as), whatever its length.
    """
    from automated_security_helper.config.config_validator import (
        reads_back_as,
        recorded_value_at,
    )

    rewrites = getattr(ash_config, "_written_references", None) or []
    dumped = None
    for rewrite in rewrites:
        if rewrite.kind != "value" or not rewrite.path:
            continue
        leaf = None
        for place in _paths_in_record(rewrites, rewrite.path):
            leaf = recorded_value_at(ash_config, data, place)
            if leaf is not None:
                break
        if isinstance(leaf, (_EnvTagged, _Reference)) or leaf is None:
            continue
        if not isinstance(leaf, str):
            if dumped is None:
                dumped = user_config_data(ash_config)
            left = reads_back_as(
                ash_config, dumped, rewrite.path, rewrite.resolved, leaf
            )
        else:
            left = leaf == rewrite.resolved or bool(
                rewrite.environment_part
                and rewrite.environment_part in _without_references(leaf, rewrite)
            )
        if left:
            raise RuntimeError(
                "the configuration was not written: it would hold a value its "
                "files read from the environment as text, where they wrote a "
                "reference to the variable"
            )


def render_config_file_as_written(
    config_path: Path, ash_config: AshConfig, comments: List[str]
) -> str:
    """render_config_file, with each value and key ``ash_config``'s files read
    from the environment written as the reference they wrote, not the value.

    For a file ASH writes so that a scan loads it again, the MCP server's
    session config: loading it resolves each reference again and knows the
    value came from the environment, so every message and log of that scan
    redacts it. A config that knows no references (one not loaded with
    resolve_config.load_config_file_for_run) is written as render_config_file
    writes it.
    """
    from automated_security_helper.config.config_validator import record_of_config

    if is_json_file(config_path):
        data = record_of_config(ash_config, user_config_data(ash_config))
        _refuse_a_value_left_as_text(data, ash_config)
        # A JSON config is read with no interpolation (config_sources), so each
        # reference is written as the text the file wrote; the value is never
        # written in its place.
        return json.dumps(data, indent=2) + "\n"
    # Marked where record_of_config writes a reference, by location: matching
    # the text instead tagged a literal that read like a reference elsewhere.
    data = record_of_config(ash_config, user_config_data(ash_config), _as_reference)
    _refuse_a_value_left_as_text(data, ash_config)
    return "\n".join(
        [
            *comments,
            yaml.dump(
                data,
                Dumper=_AsWrittenYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            ),
        ]
    )


def user_config_data(ash_config: AshConfig) -> Dict[str, Any]:
    """The settings a config file written by ASH holds.

    Every setting, defaults included, except what only ASH itself should write:
    the `build` section and the per-plugin fields ConfigValidator warns about
    (`name`, `extension`, ...), and `client_supplied` on a suppression or an
    ignore path, which ASH sets and a config file cannot set.
    `mcp-resource-management` is left out while it
    holds the defaults, and kept once a user has changed it. Dumped in JSON
    mode, so an enum or a date is written as its value and the YAML carries no
    Python tags.
    """
    from automated_security_helper.config.config_validator import ConfigValidator

    exclude: Dict[str, Any] = {
        "build": True,
        "scanners": dict.fromkeys(
            ScannerConfigSegment.model_fields, ConfigValidator.INTERNAL_SCANNER_FIELDS
        ),
        "reporters": dict.fromkeys(
            ReporterConfigSegment.model_fields,
            ConfigValidator.INTERNAL_REPORTER_FIELDS,
        ),
        "converters": dict.fromkeys(
            ConverterConfigSegment.model_fields,
            ConfigValidator.INTERNAL_CONVERTER_FIELDS,
        ),
        "global_settings": {
            "ignore_paths": {"__all__": {"client_supplied"}},
            "suppressions": {"__all__": {"client_supplied"}},
        },
    }
    if ash_config.mcp_resource_management == MCPResourceManagementConfig():
        exclude["mcp_resource_management"] = True
    return _without_unset_item_fields(
        ash_config.model_dump(
            mode="json",
            by_alias=True,
            exclude_defaults=False,
            exclude_none=False,
            exclude=exclude,
        )
    )


def _without_unset_item_fields(value: Any, in_list: bool = False) -> Any:
    """``value`` with the null fields of every mapping inside a list left out.

    A suppression or an ignore path is a list item, and dumping it with every
    field wrote about ten `key: null` lines per entry (package_name, line_start,
    ...). A field left out of an item reads back as the same default. Null
    settings outside lists stay, so a written file still shows every setting.
    """
    if isinstance(value, list):
        return [_without_unset_item_fields(item, in_list=True) for item in value]
    if isinstance(value, dict):
        return {
            key: _without_unset_item_fields(item, in_list=in_list)
            for key, item in value.items()
            if not (in_list and item is None)
        }
    return value


def render_config_file(
    config_path: Path,
    ash_config: AshConfig,
    comments: List[str],
    keep_from: Any = None,
) -> str:
    """The text of `config_path` holding `ash_config`, in the file's own format.

    A `.json` file gets JSON, which has no comments: writing the YAML (and its
    schema comment) into it left a file the loader could not parse, so a scan
    fell back to the default configuration.

    `keep_from` is the file's previous contents. Its top-level keys that are no
    AshConfig field (a JSON `$schema`, a key for another ASH version) are kept:
    the model drops them on load, and a rewrite must not delete what the user
    wrote.
    """
    data = user_config_data(ash_config)
    if isinstance(keep_from, dict):
        known = {
            spelling
            for name, info in AshConfig.model_fields.items()
            for spelling in (name, info.alias)
            if spelling
        }
        for key, value in keep_from.items():
            if key not in known and key not in data:
                data[key] = value
    if is_json_file(config_path):
        return json.dumps(data, indent=2) + "\n"
    return "\n".join(
        [
            *comments,
            yaml.dump(
                data,
                Dumper=IndentableYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            ),
        ]
    )
