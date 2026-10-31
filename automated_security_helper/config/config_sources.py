# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where an ASH configuration comes from, and how one config extends another.

Discovery (#313)
----------------
When no config path is given, ``discover_config_source`` picks exactly one
source from the scan root. Sources are never merged with each other. In order:

1. The dedicated file names in ``ASH_CONFIG_FILE_NAMES``, in that list's order,
   each checked at the scan root and then in ``.ash/``. This is the order ASH
   has always used, kept unchanged.
2. ``ASH_RC_FILE_NAMES`` (``.ashrc.toml`` ... ``ashrc.json``) at the scan root.
3. ``pyproject.toml`` at the scan root, only if it has a ``[tool.ash]`` table.
   A ``pyproject.toml`` without one is not a config source at all.

An explicit path (``--config`` or ``ASH_CONFIG``) skips discovery.

The dedicated names win over the newer sources because #313 asks for
``[tool.ash]`` to be read "when no .ash/.ash.yaml exists" and for an existing
``.ash/.ash.yaml`` to keep working. Letting a newer source win would change the
config of every repository that has ``.ash/.ash.yaml`` and then gains an
unrelated ``[tool.ash]`` table. The source used is logged, every other source
found is logged as ignored, and when a dedicated file shadows a newer source the
warning says the dedicated names are deprecated.

Rejected: merging the sources found (two files each holding half a config is the
confusion this is meant to remove, and pytest does not merge either), and
failing when more than one exists (that breaks every repository with both on
upgrade, for a situation a warning already explains).

Extends (#289)
--------------
A config may name one or more base configs, plus RFC 6902 JSON-Patch ops::

    extends: ../shared/ash-base.yaml        # or a list of paths
    patch:
      - op: add
        path: /global_settings/suppressions/-
        value: {rule_id: B101, path: "tests/**", reason: "asserts in tests"}

One file resolves as follows:

1. Each base is resolved the same way (recursively), and the bases are merged
   left to right, so a later base wins over an earlier one.
2. The file's own keys are merged over the result. The file always wins.
3. The file's ``patch`` ops are applied, in order, to that result.

Merge rules: two mappings merge key by key, recursively. Anything else -- a
list, a scalar, ``null`` -- replaces what was there. Lists are replaced, never
concatenated, so a child that writes ``suppressions`` drops its base's
suppressions; to keep them and add more, use a ``patch`` ``add`` at
``/global_settings/suppressions/-``. To delete a key a base set, use a ``patch``
``remove``. JSON-Patch pointers are matched to the document's own spelling,
where a key differs only in ``-`` versus ``_`` (``_resolve_dict_key``).

Spellings: a setting is merged as the config model reads it (``deep_merge``
with the model). Where the model reads a field under two spellings, its name
and its alias (``cdk_nag`` and ``cdk-nag``), both are one setting: each
document's spellings are folded as the model folds them, the child's result is
merged over the base's, and the result is written once, under the alias. A
spelling the model does not read (``global-settings`` for ``global_settings``)
in the base is left as it is, so it cannot take the child's value away from the
setting. One in the child still reaches the base's spelling of the setting, as
keys differing only in ``-`` versus ``_`` always did, unless the child also
sets the setting under a spelling the model reads, which wins. Two
spellings of a plugin's section in ``scanners``, ``reporters`` or
``converters`` that ``get_plugin_config`` reads for the same plugin
(``plugin_key_lookup_names``: ``BedrockSummary`` and
``bedrock-summary-reporter``) are one section, written under the child's
spelling. Keys inside a section whose model is not known (a plugin's own
section) keep the older rule: keys that differ only in ``-`` versus ``_`` are
one key. Workspace mode merges the operator's ``--config`` over a project's
config by the same rules (``resolve_config``'s ``overlay_config_path``).

``move`` and ``copy`` are refused, as in ``runtime_patch.py``; #289 asks for
``add``, ``remove`` and ``replace``, and ``test`` is allowed because it reads
only. A file an MCP client chose (one the "Environment variables" rule refuses
by its own names, not only as a base of a refused file) may not use ``test``:
whether such a file loads would say whether a value it may not read equals the
one it guessed.

Base paths
----------
A base path is relative to the directory of the file that names it, after that
file's own symlinks are resolved; an absolute path is also accepted. Nothing is
fetched: a reference that looks like a URL is refused with an error, not
downloaded.

Every base must resolve, after following symlinks, to a location inside the
confinement root. ``Path.resolve`` alone normalizes a path and confines nothing,
so the check is ``is_relative_to`` between two resolved paths. A ``..`` that
stays inside the root is fine. One that leaves it is refused, and so is a
symlink inside the root whose target is outside. The root is the scan's source
directory when the root config is inside it, otherwise the root config's own
directory (the parent of ``.ash/`` for a file in ``.ash/``); see
``default_confinement_root``. A root config reached through a link an MCP
client delivered is placed where that link sits for this, not where it leads,
so a named link in a delivered tree cannot extend a file beside its target.

A file is judged by every path it was reached by
(``ResolvedConfigDocument.names``), and a base also by the paths of the files
above it, since the file that names a base chose it: a base of a file a client
delivered, or of a file a client's link reaches, is the client's wherever it
is.

A caller can narrow that further with ``permit_base``, a predicate every base
must also pass after its symlinks are resolved. The MCP server passes one built
from the calling session's allowed config roots
(``cli/mcp/sandbox.config_base_gate``), so a grant naming a ``.ash/`` directory
confines the chain to that directory rather than to its parent. The predicate is
consulted before the confinement root, and its refusal,
``ASHConfigInputNotPermittedError``, names the ``extends`` entry as written and
not the path it resolved to. Without a predicate the rules above are unchanged.

Discovery takes the same predicate (``discover_config_source(..., permit=)``).
A source found in the scanned directory can be a symbolic link to any file, and
discovery reads ``pyproject.toml`` to look for its table, so every source that
exists is checked by the path it resolves to before anything opens it. A refused
one raises ``ASHConfigInputNotPermittedError`` naming the source as found, so the
refusal reads the same whether its target is missing, unreadable or readable.

The same predicate is applied to the file discovery selects, when a caller
passes one (``check_discovered_source``). The directory searched is one the
caller may read, but a file found there may be a symlink to a file elsewhere,
and reading that file would let the caller choose a file on the host. The
MCP server's ``get_config`` already checks a file it finds this way. The refusal
names the file as found, not the file it resolves to. Discovery looks only at
whether each candidate exists before the predicate is applied to it; a
``pyproject.toml`` is read for its ``[tool.ash]`` table only after it passed.

Bounds
------
Every config file is opened without blocking and read only when the opened file
is a regular file, and at most ``ASH_CONFIG_MAX_FILE_BYTES`` of it
(``read_config_bytes``). A FIFO or a device at a config name, including one
swapped in after a caller checked the name, is refused rather than blocking the
scan or being read until memory runs out.

A file that appears twice on its own chain is a cycle and fails with the chain
printed. The same file reached on two branches (a diamond) is not a cycle. A
chain deeper than ``ASH_CONFIG_EXTENDS_MAX_DEPTH`` fails, and so does reading
more than ``ASH_CONFIG_EXTENDS_MAX_FILES`` files in total, which bounds a chain
that fans out where depth alone would not.

Environment variables
---------------------
Each file is read by the same parser the single-file loader always used: YAML
through ``load_yaml_config``, TOML by passing each string value that starts with
``${`` through ``resolve_env_references`` (the same function the YAML ``!ENV``
constructor calls), and JSON with no interpolation, as before. The
``ASH_CONFIG_ENV_VAR_PREFIX`` / ``ASH_CONFIG_ENV_VAR_ALLOWLIST`` bound therefore
holds for every value in the merged result, whichever file it came from.

Some files resolve no environment variable at all, and one of them that uses
``!ENV`` (tagged, a plain ``${VAR:default}`` scalar, or a TOML string starting
with one) is refused with ``ASHConfigEnvNotResolvedError`` naming the file and
the line or key. Which files is a ``RefuseEnv`` predicate the caller passes to
``read_config_file`` and ``resolve_config_document``; ``env_refused_for`` gives
the MCP server's two:

* For a remote caller (``cli/mcp/sandbox.caller_is_remote``), every file the
  operator did not set aside: anything outside ``ASH_MCP_ALLOWED_CONFIG_ROOTS``
  except the profile files the server writes in the calling session's
  ``config/`` directory (``cli/mcp/sandbox.client_named_config_is_untrusted``).
  That covers a path the
  client names, a file discovered in a directory it names, and a scan target's
  own config, as well as anything it delivered.
* For any other caller, the CLI included, and the default when none is passed:
  a file an MCP client delivered (``cli/mcp/sandbox.config_is_client_supplied``),
  that is anything under the MCP workspace root except the profile files the
  server writes in the sessions' ``config/`` directories, judged on the path as
  named and on the file it resolves to. A local stdio caller launched the server and holds its
  environment already, so its own repository config keeps ``!ENV``.

``validate_config``'s ``config_content`` from a remote caller is refused
wherever it is written (``refuse_env_everywhere``). Each base is judged by the
same predicate, on the path its ``extends`` entry spells and on the file that
resolves to, and every base of a refused file is refused with it: the file that
names a base is what chose it.

A refused file is refused before any of its references is resolved, so the
refusal is the same whether or not a variable it reads is set, and a file the
rule does not refuse reports an unset variable as it always has.

The bound above cannot cover this case. There the variables are the operator's
own, set wherever ASH runs; here they are the MCP server's, and a remote client
reads the result back (``get_config`` returns the resolved config, and a scan's
results carry it). Refused rather than left as written, because a value that
silently stays a literal is a config that is not what either side meant, and
the other refusals for delivered configs work the same way. A config the CLI
reads keeps ``!ENV`` exactly as before.

Failure
-------
Every failure here raises ``ASHConfigSourceError``, which ``resolve_config``
re-raises instead of falling back to the default config. A root YAML or JSON
file that cannot be read or parsed raises what the reader raised;
``resolve_config.read_config_document`` turns that into an
``ASHConfigSourceError`` too, so a root file that does not load refuses the
scan just as a base that does not load does. Neither is replaced by the
defaults, which would scan with the file's suppressions and settings off.

Discovery selects a config name that exists, not only one that is a regular
file: a dangling symbolic link or a directory at ``.ash/.ash.yaml`` is selected
and then refused when it is read, rather than skipped as though the repository
had no config. A ``pyproject.toml`` that cannot be read refuses the same way
when it would be the selected source, because whether it holds a ``[tool.ash]``
table cannot be told. Discovery opens ``pyproject.toml`` to look for that table
only when it is a regular file; one that is not is told by its type and never
opened (``_pyproject_is_a_source``).
"""

from __future__ import annotations

import copy
import errno
import functools
import inspect
import io
import json
import os
import re
import secrets
import stat
import sys
import threading
import types
import typing
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePath
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

# jsonpatch ships no type information (no py.typed, no stubs package).
import jsonpatch  # type: ignore[import-untyped]
import yaml

from pydantic import BaseModel

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    AshConfig,
    EnvReferenceNotResolved,
    _PluginConfigSegment,
    load_yaml_config,
    plugin_key_lookup_names,
    resolve_env_references,
    sandbox_mode_in_document,
)
from automated_security_helper.config.plugin_section_names import (
    PLUGIN_SEGMENT_KEYS,
    AmbiguousPluginSpellings,
    fold_known_plugin_sections,
    folded_section_name,
    plugin_key_in,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    UNKNOWN_INDEX,
    EnvironmentReference,
    environment_references,
    referenced_name,
    with_environment_values_shown,
    written_without_tag,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_EXTENDS_MAX_DEPTH,
    ASH_CONFIG_EXTENDS_MAX_FILES,
    ASH_CONFIG_FILE_NAMES,
    ASH_CONFIG_MAX_FILE_BYTES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigFileNotFoundError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
    ASHConfigUnparsedError,
    ASHConfigUnsetVariableError,
)
from automated_security_helper.utils.error_text import os_error_without_named_file
from automated_security_helper.utils.link_chain import (
    LINK_HOPS,
    first_unsafe_link,
    names_a_windows_share,
)
from automated_security_helper.utils.link_locations import link_locations
from automated_security_helper.utils.log import ASH_LOGGER

# tomllib is stdlib only from Python 3.11; requires-python starts at 3.10. There
# it is tomli, the parser tomllib was taken from, which pyproject.toml declares
# for Python below 3.11. It was `toml` 0.10, which implements TOML 0.5 and
# refuses valid TOML 1.0 such as an array of mixed types, so a config a scan on
# 3.11 accepted was "not valid TOML" on 3.10. Chosen by version, not by
# ImportError, so mypy checks only the branch of the Python it checks for and
# does not look for tomli where it is not installed.
if sys.version_info >= (3, 11):  # pragma: no cover - depends on interpreter version
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

_TOMLDecodeError: Any = tomllib.TOMLDecodeError


def _parse_toml(text: str) -> Dict[str, Any]:
    return tomllib.loads(text)


EXTENDS_KEY = "extends"
PATCH_KEY = "patch"

#: Decides whether one resolved base path may be read. True permits it. See
#: "Base paths" in the module docstring.
PermitBase = Callable[[Path], bool]

#: Decides whether one config file may not resolve ``!ENV``. True refuses it. See
#: "Environment variables" in the module docstring.
RefuseEnv = Callable[[Path], bool]

#: Decides whether one config file is the operator's, so its relative paths are
#: taken from its directory (``config/operator_paths.py``). True anchors them.
AnchorPaths = Callable[[Path], bool]

SOURCE_KIND_EXPLICIT = "explicit"
SOURCE_KIND_DEDICATED = "dedicated"
SOURCE_KIND_ASHRC = "ashrc"
SOURCE_KIND_PYPROJECT = "pyproject"

_PATCH_OPS = {"add", "remove", "replace", "test"}
_URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# The `tool` and `ash` keys as TOML lets them be written: bare, or as a basic or
# a literal string (`"tool"`, `'ash'`), which name the same key.
_TOOL_KEY = r"""(?:tool|"tool"|'tool')"""
_ASH_KEY = r"""(?:ash|"ash"|'ash')"""
# A [tool.ash] or [tool.ash.*] header, a [[tool.ash.*]] array-of-tables header,
# a top-level dotted `tool.ash...` key, or a top-level `tool = { ... }` inline
# table that holds an `ash` key. Only consulted for a pyproject.toml that
# failed to parse, to decide whether it was meant to configure ASH, and to
# report the table's line (_tool_ash_declared, which also reads the other
# spelling: an `ash` key under a [tool] table).
_TOOL_ASH_PATTERN = re.compile(
    rf"^[ \t]*(\[\[?[ \t]*{_TOOL_KEY}[ \t]*\.[ \t]*{_ASH_KEY}[ \t]*[\].]"
    rf"|{_TOOL_KEY}[ \t]*\.[ \t]*{_ASH_KEY}[ \t]*[.=]"
    rf"|{_TOOL_KEY}[ \t]*=[ \t]*\{{(?:[^\n]*?[{{,])?[ \t]*{_ASH_KEY}[ \t]*[.=])",
    re.MULTILINE,
)
# A bare `[tool]` table header, and an `ash` key (`ash = {...}` or `ash.x = ...`)
# on a line of its own; the key counts only between a [tool] header and the next
# header, where TOML puts it under tool. The text is decoded with no newline
# translation, so a CRLF file's header line ends in a carriage return before
# the `$`; the trailing class admits it, where the other two patterns need no
# such care because they do not anchor at the line's end.
_TOOL_TABLE_HEADER = re.compile(
    rf"^[ \t]*\[[ \t]*{_TOOL_KEY}[ \t]*\][ \t]*(?:#.*)?[ \t\r]*$", re.MULTILINE
)
# A table header: a dotted key path between one pair of brackets or two, never
# one of each (`[a]]` and `[[a]` are no header), with a comment after it at most.
# Any line starting with `[` used to count, so a row of a multi-line array value
# (`  ["a", "b"],`, `[3]`) ended the table early, the `ash` key under it was
# missed, and an unparsable pyproject written that way was skipped as holding no
# ASH settings. A row such as `[3]` or `[true]` has a header's exact shape, so a
# line is tested as a header only outside a multi-line value (`_table_end`).
_TOML_KEY = r"""(?:[A-Za-z0-9_-]+|"(?:[^"\\\n]|\\.)*"|'[^'\n]*')"""
_KEY_PATH = rf"{_TOML_KEY}(?:[ \t]*\.[ \t]*{_TOML_KEY})*"
_ANY_TABLE_HEADER = re.compile(
    rf"^[ \t]*(?:\[[ \t]*{_KEY_PATH}[ \t]*\]|\[\[[ \t]*{_KEY_PATH}[ \t]*\]\])"
    r"[ \t]*(?:#.*)?[ \t\r]*$",
    re.MULTILINE,
)
_ASH_KEY_LINE = re.compile(rf"^[ \t]*{_ASH_KEY}[ \t]*[.=]", re.MULTILINE)


def _tool_ash_declared(text: str) -> Optional[int]:
    """The offset in ``text``, a pyproject.toml's text, where it declares ASH
    settings, or None when it declares none.

    Read by the lines alone, for a text that did not parse: a ``[tool.ash]`` or
    ``[tool.ash.*]`` table header, a ``[[tool.ash.*]]`` array-of-tables header, a
    top-level dotted ``tool.ash...`` key, a top-level ``tool = { ash = ... }``
    inline table, or an ``ash`` key under a bare ``[tool]`` table, with either key
    bare or quoted (``[tool."ash"]``). A spelling that went unread made an
    unparsable pyproject written that way be skipped as holding no ASH settings,
    and the scan ran with the defaults while its configuration sat unread.
    """
    match = _TOOL_ASH_PATTERN.search(text)
    if match is not None:
        return match.start()
    for header in _TOOL_TABLE_HEADER.finditer(text):
        table_end = _table_end(text, header.end())
        key = _ASH_KEY_LINE.search(text, header.end(), table_end)
        if key is not None:
            return key.start()
    return None


def _table_end(text: str, start: int) -> int:
    """The offset of the first table header at or after ``start`` that is not
    inside a multi-line value, or the end of ``text``.

    ``start`` is the end of a header's line. The lines after it are read in
    order, tracking the brackets a value leaves open (an array written over
    several lines) and a multi-line string, and a line is tested as a header
    only outside both. The text did not parse, so this is a reading by lines and
    not a parser: a bracket inside a quoted string or after a ``#`` is not
    counted, and a value left unclosed hides every header after it, which keeps
    scanning the table the key might be in rather than ending it early.
    """
    depth = 0
    multiline: Optional[str] = None
    position = start
    while position < len(text):
        newline = text.find("\n", position)
        line_end = len(text) if newline < 0 else newline
        line = text[position:line_end]
        if depth == 0 and multiline is None and _ANY_TABLE_HEADER.match(line):
            return position
        depth, multiline = _brackets_left_open(line, depth, multiline)
        position = line_end + 1
    return len(text)


def _brackets_left_open(
    line: str, depth: int, multiline: Optional[str]
) -> Tuple[int, Optional[str]]:
    """The array depth and the open multi-line string delimiter after ``line``,
    given those before it. Quoted strings and comments hold no brackets."""
    index = 0
    while index < len(line):
        if multiline is not None:
            closing = line.find(multiline, index)
            if closing < 0:
                return depth, multiline
            index = closing + len(multiline)
            multiline = None
            continue
        char = line[index]
        if char == "#":
            break
        if char in "\"'":
            if line.startswith(char * 3, index):
                multiline = char * 3
                index += 3
            else:
                index = _end_of_string(line, index)
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        index += 1
    return depth, multiline


def _end_of_string(line: str, start: int) -> int:
    """The index just past the single-line string that opens at ``start``, or the
    end of ``line`` when it does not close there. A basic string reads a
    backslash as escaping the next character; a literal one does not."""
    quote = line[start]
    index = start + 1
    while index < len(line):
        if quote == '"' and line[index] == "\\":
            index += 2
        elif line[index] == quote:
            return index + 1
        else:
            index += 1
    return len(line)


def _resolve_dict_key(container: Dict[str, Any], key: str) -> str:
    """Return the key `container` already uses for `key`, if it differs only in '-' vs '_'.

    The dict an override is applied to comes from `model_dump()` without
    `by_alias=True`, so a section with an alias is keyed by its Python field name
    -- `cdk_nag`, not `cdk-nag`. Operators type the spelling in their own config
    file, which for those sections is the alias; this option's own documented
    example is a kebab-case key. Writing the typed spelling verbatim added a
    second section beside the dumped one, and since pydantic resolves an alias
    ahead of a field name the new one won revalidation -- so the override applied
    and every other field under that section came back as a default.

    Only a key that already exists is ever followed. A name absent under both
    spellings is created exactly as typed, which is what keeps a plugin-supplied
    section (an extra key, present under one spelling only) reachable.

    Comparing the two spellings is equivalent to consulting the alias map here
    because every alias declared anywhere under `AshConfig` is its field name
    with '_' replaced by '-'; that held for 9 of 9 aliases across 75 models when
    this was written, walking `model_fields` from `AshConfig` down.

    `extends` merging and `patch` pointers use the same rule, for the same
    reason: a base and a child are as likely to spell a section differently as a
    file and an override are.

    A key that is not a string (a YAML number or boolean key) has no
    ``-``/``_`` twin and is matched only as itself; read as text, it made the
    merge of any file holding one fail with an AttributeError. A null key is
    refused before this point (``deep_merge``).
    """
    if key in container or not isinstance(key, str):
        return key
    for variant in (key.replace("-", "_"), key.replace("_", "-")):
        if variant != key and variant in container:
            return variant
    return key


_TOP_LEVEL_FIELDS_BY_FOLD: "Dict[str, Tuple[str, FrozenSet[str]]] | None" = None


def _declared_top_level_fields() -> Dict[str, Tuple[str, FrozenSet[str]]]:
    """The configuration's own top-level fields by their folded name: the
    field's name and the spellings an override may use for it (the name and
    its declared alias; their ``-``/``_`` twins resolve as twins). Built once;
    read from the model's fields, so a field added later is covered without
    being listed."""
    global _TOP_LEVEL_FIELDS_BY_FOLD
    if _TOP_LEVEL_FIELDS_BY_FOLD is None:
        # Imported here: this module is imported while ash_config loads.
        from automated_security_helper.config.ash_config import AshConfig

        by_fold: Dict[str, Tuple[str, FrozenSet[str]]] = {}
        for name, info in AshConfig.model_fields.items():
            accepted = frozenset(
                spelling for spelling in (name, info.alias) if spelling
            )
            by_fold[folded_section_name(name)] = (name, accepted)
        _TOP_LEVEL_FIELDS_BY_FOLD = by_fold
    return _TOP_LEVEL_FIELDS_BY_FOLD


def resolve_override_segment(
    current: Any,
    parent_key: "str | None",
    key: str,
    environment_values: Collection[str] = (),
) -> str:
    """The key an override's path segment lands on inside ``current``.

    One resolver for every override walker (``--config-overrides`` apply, the
    operator-only gate, and the MCP workspace gate), so what the apply writes is
    what the gates checked. An exact or ``-``/``_`` twin key that already exists
    wins (``_resolve_dict_key``); otherwise a spelling of a declared plugin's
    section directly under a plugin segment folds to that section's key
    (``plugin_key_in``). A non-exact spelling of an EXISTING undeclared section
    is refused with the real key: landing it as a new extra would be a silent
    no-op against the section the plugin reads -- an operator disabling an
    off-host reporter under a respelling would see success while findings keep
    going off the host. Only a spelling that matches no existing section lands
    as written.

    Raises ASHRespelledOverrideError (an ASHConfigValidationError) for the
    refused spelling, which the apply and both gates surface as the override
    refusals they already raise; a caller that tolerates overrides that do not
    apply to its base re-raises this one by its class.

    ``environment_values`` are the values and keys the configuration read from
    the environment, which a refusal is redacted with. They must be a
    re-iterable collection: each walker calls this once per segment and per
    override, and a single-use iterator is empty after its first use, so a
    later refusal would name an env-read key unredacted. Such an iterator is a
    TypeError here, at the one resolver every walker shares.
    """
    if iter(environment_values) is environment_values:
        raise TypeError(
            "resolve_override_segment: environment_values must be a re-iterable "
            "collection (a tuple, list or set), not a single-use iterator; an "
            "exhausted iterator leaves a later refusal unredacted"
        )
    resolved = _resolve_dict_key(current, key) if isinstance(current, dict) else key
    if isinstance(current, dict) and resolved in current:
        return resolved
    folded = plugin_key_in(current, parent_key, key)
    if folded is not None:
        return folded
    if parent_key is None and isinstance(current, dict) and isinstance(key, str):
        # The same hazard one level up: a respelling of one of the
        # configuration's own top-level fields lands as a new extra key the
        # model ignores, a silent no-op against every setting under the real
        # one. The exact name and the -/_ twin resolve above (a dump holds
        # every declared field); any other spelling of a declared field is
        # refused. A key that is no spelling of a declared field still lands
        # as written, the documented leniency for unknown top-level keys.
        entry = _declared_top_level_fields().get(folded_section_name(key))
        if entry is not None:
            field, accepted = entry
            if (
                key not in accepted
                and key.replace("-", "_") not in accepted
                and key.replace("_", "-") not in accepted
            ):
                from automated_security_helper.core.exceptions import (
                    ASHRespelledOverrideError,
                )
                from automated_security_helper.utils.error_text import (
                    text_without_values,
                )

                raise ASHRespelledOverrideError(
                    text_without_values(
                        f"Config override names '{key}', a spelling of the "
                        f"configuration's '{field}' section: use that key, so "
                        "the override reaches the settings the scan reads",
                        environment_values,
                    )
                )
    if (
        parent_key in PLUGIN_SEGMENT_KEYS
        and isinstance(current, dict)
        and isinstance(key, str)
    ):
        fold = folded_section_name(key)
        for existing in current:
            if (
                isinstance(existing, str)
                and existing != key
                and folded_section_name(existing) == fold
            ):
                from automated_security_helper.core.exceptions import (
                    ASHRespelledOverrideError,
                )
                from automated_security_helper.utils.error_text import (
                    text_without_values,
                )

                # A section key the file read from the environment resolves to
                # the variable's value, and this text reaches the client and
                # ash.log, so the caller's environment values are redacted.
                raise ASHRespelledOverrideError(
                    text_without_values(
                        f"Config override names '{parent_key}.{key}', a spelling "
                        f"of the existing section '{parent_key}.{existing}': use "
                        "that key, so the override reaches the section the "
                        "plugin reads",
                        environment_values,
                    )
                )
    return resolved


# A config's format comes from its suffix in any case. A file system that
# ignores case (the default on macOS and Windows) opens the project's
# pyproject.toml for `PYPROJECT.TOML`; a check that matched lower case only read
# it as YAML, and the commands that rewrite a config wrote YAML over it.


def is_pyproject(path: Path) -> bool:
    return Path(path).name.lower() == ASH_PYPROJECT_FILE_NAME


def is_toml_file(path: Path) -> bool:
    """Whether a config at `path` is read, and so must be written, as TOML."""
    return Path(path).name.lower().endswith(".toml")


def is_json_file(path: Path) -> bool:
    """Whether a config at `path` is read, and so must be written, as JSON."""
    return Path(path).name.lower().endswith(".json")


#: Windows' ERROR_CANT_RESOLVE_FILENAME: what a symbolic link that leads back to
#: itself raises there, in place of the ELOOP a POSIX kernel gives.
_WINERROR_CANT_RESOLVE_FILENAME = 1921


def is_symlink_loop(exc: OSError) -> bool:
    """Whether ``exc`` says a symbolic link leads back to itself."""
    return (
        exc.errno == errno.ELOOP
        or getattr(exc, "winerror", None) == _WINERROR_CANT_RESOLVE_FILENAME
    )


def is_regular_file(path: Path) -> bool:
    """Whether `path` leads to a regular file; False for any error.

    os.stat rather than Path.is_file: before Python 3.14, is_file raises for an
    error other than "not found" (a directory above that cannot be searched),
    which let a bare OSError out of a check that only meant to ask.
    """
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        # ValueError: a path with a NUL in it.
        return False


FileIdentity = Tuple[int, int]


def file_identity(path: Path) -> Optional[FileIdentity]:
    """(device, inode) of the file `path` leads to now, or None when it leads nowhere.

    A caller that checks a config path takes ``identity_to_hold`` instead, which
    never gives None, and hands it to ``read_config_bytes`` as ``expect``, so the
    file read is the file that was checked.
    """
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return None
    return info.st_dev, info.st_ino


#: The ``expect`` of a path that led nowhere when it was checked. No file has
#: this device and inode, so a read held to it refuses whatever file has come
#: to be at the name since (a link created after the name was judged, say).
ABSENT_FILE: FileIdentity = (-1, -1)


def identity_to_hold(path: Path) -> FileIdentity:
    """What a read of `path` is held to: ``file_identity``, or ``ABSENT_FILE``
    when the path leads nowhere now.

    A caller that judges a path takes this, never ``file_identity`` itself. A
    ``None`` handed on as ``expect`` means "no identity was taken", so the read
    would not be held to anything, and a path that was absent when it was judged
    is exactly the one that can be made to lead anywhere before it is opened.
    ``expect=None`` is for a caller that judged no path.
    """
    identity = file_identity(path)
    return ABSENT_FILE if identity is None else identity


class OpenedConfig:
    """A config file opened once, so the file judged and the file read are one.

    A grant is a decision about a path, and a name can lead to another file between
    the decision and the read. The file is opened first; ``real`` is the path the
    descriptor leads to, as the operating system reports it for the descriptor and
    not as the name resolves later, and that is the path to ask the grant about.
    ``identity`` is the descriptor's (device, inode), which a later read is held to
    (``read_config_bytes(expect=)``), or which ``read_opened_config_bytes`` reads
    from the descriptor itself.

    ``real`` is None when the path cannot be told (a file unlinked since it was
    opened, a platform without ``/proc`` whose resolved name does not lead to the
    held file); a caller then takes the file for one that changed.

    The descriptor stays open until ``close``. A freed inode number can be given to
    a file made afterwards, so an identity compared after the descriptor was closed
    could not tell a replacement from the original; an open descriptor keeps the
    inode in use.
    """

    __slots__ = ("fd", "identity", "real")

    def __init__(self, fd: int, identity: FileIdentity, real: Optional[Path]) -> None:
        self.fd = fd
        self.identity = identity
        self.real = real

    def close(self) -> None:
        fd, self.fd = self.fd, -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _descriptor_path(fd: int, named: Path, identity: FileIdentity) -> Optional[Path]:
    """The path the open descriptor ``fd`` leads to, or None when it cannot be told.

    On Linux the kernel's own answer for the descriptor (``/proc/self/fd``). Where
    that is missing, or the file has been unlinked, the resolved ``named``, taken
    only when its last component is not a link and is the very file the
    descriptor holds: the floor, which refuses what it cannot vouch for.
    """
    if sys.platform.startswith("linux"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        if os.path.isabs(target) and not target.endswith(" (deleted)"):
            return Path(target)
    try:
        resolved = Path(os.path.realpath(named))
        leaf = os.lstat(resolved)
    except (OSError, ValueError):
        return None
    if stat.S_ISLNK(leaf.st_mode) or (leaf.st_dev, leaf.st_ino) != identity:
        return None
    return resolved


def open_config_for_judgment(path: Path) -> Optional[OpenedConfig]:
    """``path`` opened for a grant check, or None when it leads to no regular file.

    Only a path that leads to a regular file now is opened, and the opened
    descriptor is checked to be one: a FIFO or a device is never opened here (an
    open can act on a device even when nothing is read), and the caller then
    judges the name as before. The open does not wait on a FIFO that was swapped in
    since and does not make a terminal the process's controlling one. A name that
    cannot be opened (absent, unreadable) gives None as well.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOCTTY", 0)
            | getattr(os, "O_BINARY", 0),
        )
    except (OSError, ValueError):
        return None
    try:
        held = os.fstat(fd)
    except OSError:
        os.close(fd)
        return None
    if not stat.S_ISREG(held.st_mode):
        os.close(fd)
        return None
    identity = (held.st_dev, held.st_ino)
    return OpenedConfig(fd, identity, _descriptor_path(fd, Path(path), identity))


def read_opened_config_bytes(opened: OpenedConfig, path: Path) -> bytes:
    """The bytes of the file ``opened`` holds, read from its descriptor.

    Bounded by ``ASH_CONFIG_MAX_FILE_BYTES`` as ``read_config_bytes`` is. ``path``
    is the name a refusal uses.
    """
    limit = ASH_CONFIG_MAX_FILE_BYTES
    os.lseek(opened.fd, 0, os.SEEK_SET)
    if getattr(os, "O_NONBLOCK", 0):
        # O_NONBLOCK was for the open. A regular file is then read normally.
        os.set_blocking(opened.fd, True)
    chunks: List[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(opened.fd, min(remaining, 1 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining <= 0:
        raise ASHConfigSourceError(
            f"{Path(path).as_posix()} is larger than {limit} bytes, the most ASH "
            "reads from one config file."
        )
    return b"".join(chunks)


class ConfigFileChangedError(OSError):
    """A read refused because the file it opened is not the one that was checked.

    ``read_config_bytes`` raises it for an ``expect`` the opened file does not
    match: a file swapped in since the check, or one that appeared where the path
    led nowhere. It keeps ``errno.ESTALE``, so a caller that tests the errno is
    unaffected, but the errno is not what says a file changed: a stale handle
    reported by the file system is a plain ``OSError`` with the same errno, and
    must not be taken for a swap. A caller that needs to tell "the file changed
    since it was checked" from "the read failed" asks ``config_file_changed``.
    """


#: Set to True on an error raised in place of a ``ConfigFileChangedError`` whose
#: cause was dropped on purpose (a base the environment chose is reworded with no
#: cause, because the original's text can name the path). The mark carries only
#: the fact that the file changed, never the path. The shape of
#: ``_UNHELD_TEXT_MARK``.
_FILE_CHANGED_MARK = "_ash_config_file_changed"


def config_file_changed(error: Optional[BaseException]) -> bool:
    """Whether ``error`` is a read refused because the file is no longer the one
    that was checked, or was raised from one (its ``__cause__`` chain) or in
    place of one that was reworded without its cause (``_FILE_CHANGED_MARK``).

    Decided by the type and the mark and never by an errno: ``ESTALE`` also comes
    from a file system. Only ``__cause__`` is followed (``raise ... from``), never
    ``__context__``, so a wrapper that raises inside its handler without ``from``
    loses the refusal unless it carries the mark.
    """
    seen: Set[int] = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, ConfigFileChangedError):
            return True
        if getattr(error, _FILE_CHANGED_MARK, False) is True:
            return True
        error = error.__cause__
    return False


def read_config_bytes(path: Path, expect: Optional[FileIdentity] = None) -> bytes:
    """A config file's bytes; see "Bounds" in the module docstring.

    Opened with ``O_NONBLOCK``, so opening a FIFO does not wait for a writer, and
    ``O_NOCTTY``, so a tty swapped in at the name cannot become the controlling
    terminal of a process that has none (a daemonized MCP server). Checked with
    ``fstat`` on the open descriptor, so what is read is the regular file that was
    opened and not whatever the name pointed at when a caller checked it. With
    ``expect`` (from ``identity_to_hold`` at the caller's check), the opened file's
    device and inode must be those, so a file replaced between a check and this
    read is refused rather than read (``ConfigFileChangedError``), and so is one
    that was not there at the check (``ABSENT_FILE``). Raises ``OSError`` for
    anything else, and ``ASHConfigSourceError`` for a file longer than
    ``ASH_CONFIG_MAX_FILE_BYTES``.
    """
    nonblock = getattr(os, "O_NONBLOCK", 0)
    flags = (
        os.O_RDONLY | nonblock | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
        if expect is not None and (opened.st_dev, opened.st_ino) != expect:
            raise ConfigFileChangedError(
                errno.ESTALE,
                "changed after it was checked, so it is not read",
                os.fspath(path),
            )
        if nonblock:
            # O_NONBLOCK was for the open. A regular file is then read normally:
            # on some filesystems a non-blocking read of one can return early.
            os.set_blocking(fd, True)
        limit = ASH_CONFIG_MAX_FILE_BYTES
        chunks: List[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    if remaining <= 0:
        raise ASHConfigSourceError(
            f"{Path(path).as_posix()} is larger than {limit} bytes, the most ASH "
            "reads from one config file."
        )
    return b"".join(chunks)


def _read_toml_text(path: Path, expect: Optional[FileIdentity] = None) -> str:
    """A TOML file's text. A leading UTF-8 byte order mark is dropped, since
    tomllib rejects it and editors on some platforms write one."""
    text = read_config_bytes(path, expect=expect).decode("utf-8")
    return text.removeprefix("\ufeff")


def _tool_ash_line(path: Path) -> Optional[int]:
    # Only a regular file is read: this names a file in messages, including the
    # one that says a path is not a regular file.
    if not is_regular_file(path):
        return None
    try:
        text = _read_toml_text(path)
    except (OSError, UnicodeDecodeError, ASHConfigSourceError):
        return None
    declared = _tool_ash_declared(text)
    if declared is None:
        return None
    return text.count("\n", 0, declared) + 1


#: The name prefix of a scan's server-written copy of a session profile. The
#: MCP server copies the profile beside itself for one scan's duration, as
#: ``.ash-scan-<scan id>.<the profile's name>``, and removes the copy when
#: the run ends, so a message that named the copy would point at a file the
#: operator never wrote and cannot find afterwards. Spelled here, where
#: messages name config files, and imported by the writer so the two cannot
#: drift.
SCAN_COPY_PREFIX = ".ash-scan-"

#: Marks the writer's process id after the scan id in a scan copy's name:
#: ``.ash-scan-<scan id>-p<pid>.<the profile's name>``. Two servers on the
#: default session share one config directory, but each keeps its own scan
#: registry, so the registry cannot say whether a copy it does not know
#: belongs to a sibling's live scan; the writer's pid can. A name without the
#: segment is a copy an older writer made and still parses. The pid is 1 to 9
#: digits without a leading zero, so it is a positive number os.kill takes.
SCAN_COPY_PID_MARK = "-p"

#: Marks the identity of the place the writer ran in, after its pid:
#: ``.ash-scan-<scan id>-p<pid>-h<token>.<the profile's name>``. A pid means
#: something only in the pid view of the host that wrote it, and a config
#: directory on a shared filesystem is seen from several: the sweep asks whether
#: a pid runs only for a copy whose token is its own, and judges every other
#: copy by age. The token is 16 lowercase hex digits (the writer takes it from
#: ``cli.mcp_tools._this_host_token``);
#: a name without one, an older writer's, has no identity and is judged by age.
SCAN_COPY_HOST_MARK = "-h"

#: A scan id as the scan writer spells it: ``str(uuid.uuid4())``, lowercase
#: hyphenated 8-4-4-4-12 hex, optionally followed by the writer's pid
#: (``SCAN_COPY_PID_MARK``). Nothing else is treated as a scan copy's id,
#: because the prefix and a dot alone also match names an operator could
#: write; the id's format is what proves the name is one of ours.
_SCAN_COPY_ID = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    rf"(?:{SCAN_COPY_PID_MARK}([1-9][0-9]{{0,8}})"
    rf"(?:{SCAN_COPY_HOST_MARK}([0-9a-f]{{16}}))?)?\Z"
)

#: The concrete path flavor given, kept: a caller's Path stays a Path.
_AnyPurePath = TypeVar("_AnyPurePath", bound=PurePath)


def parse_scan_copy_name(name: str) -> tuple[str, str] | None:
    """``(scan id, copied file's own name)`` for a scan copy's name, else None.

    A scan copy's name is ``SCAN_COPY_PREFIX``, the scan id -- a UUID in the
    scan writer's own spelling, which never holds a dot, optionally the
    writer's pid (``scan_copy_writer_pid``) and, after a pid, the identity token
    of the place it wrote in (``scan_copy_writer_host``; the tuple returned here
    is the same with or without either) -- a dot, then the copied file's own
    name. A name whose id segment is not such a UUID is
    some file of the operator's own, whatever else it looks like: both the
    naming of config sources and the sweep of leftover copies key on this
    parse, and neither may treat a file as ours on the prefix alone.
    """
    split = _split_scan_copy_name(name)
    if split is None:
        return None
    return split[0], split[3]


def scan_copy_writer_pid(name: str) -> int | None:
    """The process id a scan copy's name records, or None.

    None for a name that is not a scan copy's, and for a copy an older writer
    made, whose name carries no pid. The sweep of leftover copies uses it to
    leave a copy alone while the process that wrote it is still running.
    """
    split = _split_scan_copy_name(name)
    return None if split is None else split[1]


def scan_copy_writer_host(name: str) -> str | None:
    """The identity token a scan copy's name records, or None.

    None for a name that is not a scan copy's, for a copy whose writer could not
    read its own identity, and for one an older writer made. A copy with no
    token has no identity, which matches no host: the sweep judges it by age.
    """
    split = _split_scan_copy_name(name)
    return None if split is None else split[2]


def _split_scan_copy_name(name: str) -> tuple[str, int | None, str | None, str] | None:
    """``(scan id, writer pid or None, host token or None, copied file's name)``,
    else None."""
    if not name.startswith(SCAN_COPY_PREFIX):
        return None
    id_segment, sep, original = name[len(SCAN_COPY_PREFIX) :].partition(".")
    matched = _SCAN_COPY_ID.match(id_segment)
    if not sep or not original or matched is None:
        return None
    pid = matched.group(2)
    return (
        matched.group(1),
        None if pid is None else int(pid),
        matched.group(3),
        original,
    )


#: The copies a running server holds right now, by real path. The scan writer
#: registers a copy when it creates the file and discards it when it removes
#: it. A name alone proves nothing about who wrote the file: an operator's
#: own file, or a leftover from a run that died, can wear a scan copy's name,
#: and describing it as its sibling would name a different file. Only a path
#: a live scan registered is mapped. Scans copy and load on worker threads,
#: so this is a lock-guarded module-level set, not a context variable.
_LIVE_SCAN_COPIES: set[str] = set()
_LIVE_SCAN_COPIES_LOCK = threading.Lock()


def _scan_copy_key(path: PurePath | str) -> str:
    return os.path.realpath(os.fspath(path))


def register_scan_copy(path: PurePath | str) -> None:
    """Record *path* as a copy a live scan has written."""
    with _LIVE_SCAN_COPIES_LOCK:
        _LIVE_SCAN_COPIES.add(_scan_copy_key(path))


def discard_scan_copy(path: PurePath | str) -> None:
    """Forget *path*; a no-op for a path that was never registered."""
    with _LIVE_SCAN_COPIES_LOCK:
        _LIVE_SCAN_COPIES.discard(_scan_copy_key(path))


def is_registered_scan_copy(path: PurePath | str) -> bool:
    """Whether *path* is a copy a live scan registered and has not discarded."""
    with _LIVE_SCAN_COPIES_LOCK:
        return _scan_copy_key(path) in _LIVE_SCAN_COPIES


def original_of_scan_copy(path: _AnyPurePath) -> _AnyPurePath:
    """The file a scan copy's name copies, or *path* itself.

    The copy is written beside the file it copies, so the original is the
    sibling under the copied name (``parse_scan_copy_name``). Only a path a
    live scan registered (``register_scan_copy``) maps, and only when its
    name also parses: anything else is some file of the operator's own, or a
    leftover from a run that is gone, and is returned unchanged, so a
    message about it names the file as written.
    """
    parsed = parse_scan_copy_name(path.name)
    if parsed is None:
        return path
    with _LIVE_SCAN_COPIES_LOCK:
        registered = _scan_copy_key(path) in _LIVE_SCAN_COPIES
    if not registered:
        return path
    return path.with_name(parsed[1])


def describe_config_path(path: Path) -> str:
    """Name a config source for a message: the path, plus the table for pyproject.

    The path is written as it is: the message it goes into is shown once by
    its sink (utils/terminal_text.py's shown_on_one_line or shown_not_obeyed,
    through the console's echo and secho, escape_markup and the log handlers),
    which writes a newline in it ``\\x0a`` and a terminal escape ``\\x1b``. A
    path escaped here first was shown twice: the sink doubled the backslash of
    each escape (``\\\\x1b``), and a newline escaped here as ``\\n`` never read
    as the ``\\x0a`` every other shown path reads as. The raw form is also what
    utils/parser_text.py's own_lines finds inside a parser's message, to keep
    the name's newline inside its line.

    A path object keeps its own flavor: before Python 3.12, ``Path()`` rebuilds
    a foreign-flavored path (a Windows-form path on this platform) from its
    parsed parts, and the drive anchor's backslash lands in the name, where
    3.12 reuses the written text. The path's own ``as_posix`` answers the same
    on every version, and the frame and its duplicate-check both read this one
    form. A scan's copy of a session profile is named as the profile itself
    (``original_of_scan_copy``): the copy holds the profile's content and is
    removed when the run ends, so its own name points a reader at nothing.
    """
    path = path if isinstance(path, PurePath) else Path(path)
    path = original_of_scan_copy(path)
    shown = path.as_posix()
    if is_pyproject(path):
        line = _tool_ash_line(path)
        where = f" (line {line})" if line else ""
        return f"{shown} [tool.ash]{where}"
    return shown


def is_config_parse_error(error: BaseException) -> bool:
    """Whether ``error`` is a parser's refusal of a config file's text: YAML,
    JSON or TOML that does not parse, bytes that are not UTF-8, or any other
    ValueError raised while the file's values were constructed (``!!int`` and
    ``!!float`` call ``int()`` and ``float()``, and ``int()`` also enforces its
    digit limit), whose message quotes the file.

    Not a parse error, although each is a ValueError by inheritance: ASH's own
    refusals (ASHConfigValidationError and its subclasses), whose messages are
    built, and redacted, to be shown, and pydantic's ValidationError, whose raw
    str quotes each input_value -- ASH's loaders wrap and redact it
    (ConfigFileRefused), and a raw one is re-raised, never formatted here.
    """
    from pydantic import ValidationError

    from automated_security_helper.core.exceptions import ASHConfigValidationError

    if isinstance(error, (ASHConfigValidationError, ValidationError)):
        return False
    return isinstance(error, (yaml.YAMLError, ValueError))


def unparsed_config_reason(path: Path, error: BaseException) -> str:
    """Why the config file at ``path`` could not be parsed, quoting none of it.

    Every refusal of a config file that does not parse says this, and nothing
    the parser said: a parser's message can quote the file. PyYAML's
    "found undefined alias %r" and "could not determine a constructor for the
    tag %r" give a token of the line even from a stream, a load from a str adds
    a snippet of the line, and tomllib's "Cannot declare %r twice" gives a table
    name. A value such as ``api_key: *Abc123`` would reach the refusal, ash.log
    and an MCP client's reply. So the refusal gives the error's type and where
    the parser stopped:

        <path> could not be parsed (ComposerError at line 1, column 15)

    The place is YAML's problem mark (or, without one, its context mark), or the
    line and column a JSON or TOML error carries; where tomllib sets no
    attributes (before Python 3.14), the place is read from the fixed suffix a
    mid-document message ends with, and an error at the end of the document,
    whose message ends "(at end of document)" with no suffix to read, gives
    the error's type alone (parse_error_kind). An undecodable byte gives the
    byte's offset, ``(not UTF-8 at byte offset N)``, and never its value.

    Raise the refusal outside the ``except`` block that caught ``error``, so no
    reader of the exception can reach the parser's words at all: one raised
    inside it keeps ``error`` as its ``__context__``. ``from None`` inside the
    handler is also safe with every renderer shipped today (they honor
    ``__suppress_context__``, and error_text and traceback_text read the chain
    to redact: of a chained error's own words they print only input-free parts,
    a ValidationError's titles and field descriptions -- utils/error_text.py's
    ``_chain``); the outside raise is the form that cannot regress with a
    future reader.
    """
    return f"{describe_config_path(path)} could not be parsed {parse_error_kind(error)}"


#: The fixed suffix a tomllib (and tomli) message ends with mid-document; one
#: for an error at the end ends "(at end of document)" instead, and carries no
#: place before Python 3.14. Anchored at the end and matching digits alone, so
#: nothing of the message's own words, which can name a duplicated table, is
#: taken.
_TOML_PLACE_SUFFIX = re.compile(r"\(at line (\d+), column (\d+)\)\Z")

#: json messages that quote fixed template punctuation, not document text.
#: Any other message holding a quote character is treated as carrying a
#: character of the document: json's pure-Python string scanner formats the
#: refused character into two of its templates (an invalid control character,
#: an invalid escape), where the C scanner's equivalents are fixed. Matching
#: exact strings fails closed if a template this module has not seen also
#: quotes something.
_JSON_FIXED_QUOTED_REASONS = frozenset(
    {
        "Expecting ',' delimiter",
        "Expecting ':' delimiter",
    }
)


def parse_error_kind(error: BaseException) -> str:
    """``(<type> at line L, column C)`` for ``error``, a parser's refusal: the
    words unparsed_config_reason gives after "could not be parsed", for a
    message that names the file its own way (an ``extends`` base).

    A decode error has no line: it gives the byte offset instead, which is
    where to look for the bad byte, and never the byte's value, in the words
    the merge and validator surfaces use for one.

    A YAML refusal whose problem and context marks differ names both places:
    where the parser stopped, and where the construct it was reading started
    ("; started at line C, column D"). An unclosed flow sequence stops the
    parser at the end of the stream, a line not in the editor, while its own
    bracket is. Both places are digits alone. Equal marks, or no context
    mark, keep the single place.

    tomllib sets ``lineno`` and ``colno`` on Python 3.14 and later only; on
    earlier interpreters the place is read from the fixed ``(at line N,
    column M)`` suffix a tomllib message ends with mid-document. An error at
    the end of the document ends ``(at end of document)`` instead, so before
    3.14 its refusal carries no place. The suffix regex takes
    digits alone, so the message's own words, which can name a duplicated
    table, stay out of the refusal. A JSON refusal carries the parser's
    reason with the place when the message is one of json's fixed templates;
    a message holding a quote character outside the two fixed delimiter
    templates is dropped, because json's pure-Python string scanner formats
    the refused character, a character of the document, into two of its
    templates. A template that ends " at" ("Unterminated string starting
    at") meets " at line" with that suffix removed, so the place is said
    once.
    """
    if isinstance(error, UnicodeDecodeError):
        return f"(not UTF-8 at byte offset {error.start})"
    kind = type(error).__name__
    if isinstance(error, json.JSONDecodeError):
        reason = error.msg
        if ("'" in reason or '"' in reason) and (
            reason not in _JSON_FIXED_QUOTED_REASONS
        ):
            reason = ""
        if reason:
            kind = f"{kind}: {reason.removesuffix(' at')}"
    line: Any = getattr(error, "lineno", None)
    column: Any = getattr(error, "colno", None)
    started = ""
    if isinstance(error, yaml.error.MarkedYAMLError):
        mark = error.problem_mark or error.context_mark
        line, column = (
            (mark.line + 1, mark.column + 1) if mark is not None else (None, None)
        )
        context = error.context_mark
        if (
            error.problem_mark is not None
            and context is not None
            and (context.line, context.column)
            != (error.problem_mark.line, error.problem_mark.column)
        ):
            started = (
                f"; started at line {context.line + 1}, column {context.column + 1}"
            )
    if isinstance(error, _TOMLDecodeError) and not (
        isinstance(line, int) and isinstance(column, int)
    ):
        place = _TOML_PLACE_SUFFIX.search(str(error))
        if place is not None:
            line, column = int(place.group(1)), int(place.group(2))
    if not (isinstance(line, int) and isinstance(column, int)):
        return f"({kind})"
    return f"({kind} at line {line}, column {column}{started})"


@dataclass(frozen=True)
class ConfigSource:
    """A config source discovery found: its path, its kind, and, under a
    caller's ``permit``, the identity of the file the path led to when the permit
    checked it (the opened descriptor's, taken after the permit admitted the name;
    ``ABSENT_FILE`` when the name led to no file, or to another than the one
    judged), None when no permit checked it.

    The identity is what the caller's read is held to (``resolve_config`` hands
    it to the load as ``expect``, which ``read_config_bytes`` compares with the
    opened file): a source that passed the check and was swapped for a link out
    of the grant before the open is refused at the open, instead of read.
    """

    path: Path
    kind: str
    identity: Optional[FileIdentity] = None

    @property
    def label(self) -> str:
        return describe_config_path(self.path)


@dataclass
class ConfigDiscovery:
    """The source discovery selected, and every other source it found.

    ``notes`` are what discovery could not use behind the selected source, such
    as a pyproject.toml it could not read. They are reported with the ignored
    sources (``discovery_warnings``), so they are logged once per scan and
    recorded with its results, rather than logged by each of the several readers
    that run discovery.
    """

    selected: Optional[ConfigSource] = None
    ignored: List[ConfigSource] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def pyproject_has_ash_table(path: Path, expect: Optional[FileIdentity] = None) -> bool:
    """Whether `path` is a pyproject.toml that configures ASH.

    A pyproject.toml that does not parse (including one that is not UTF-8,
    which TOML requires) is skipped unless its text declares a ``tool.ash``
    table, in which case it is an error: skipping it would scan with the default
    config while the repository's own config sat unread. Read errors propagate.

    ``expect`` is the identity a caller took when it checked the path
    (``ConfigSource.identity``, taken by discovery's permit check): every read
    here is held to it, so a name made to lead to another file after the check
    is refused (``ConfigFileChangedError``) and not read. Without it the
    identity is the file the name leads to now.
    """
    undecoded: Optional[str] = None
    # The file the name leads to now, or the one the caller checked: the first
    # read decides that it is not UTF-8, and the read of its bytes below must be
    # of that same file, so one swapped in between is refused (OSError, ESTALE)
    # and not scanned for the pattern in its place.
    seen = expect if expect is not None else identity_to_hold(path)
    try:
        text = _read_toml_text(path, expect=seen)
    except UnicodeDecodeError as exc:
        # Latin-1 decodes any byte string, which is all the pattern needs. A
        # leading UTF-8 byte order mark is dropped first, as _read_toml_text
        # drops it from a file that is UTF-8: decoded as Latin-1 it is three
        # characters in front of the first line, and a [tool.ash] header there
        # no longer started its line.
        raw = read_config_bytes(path, expect=seen).removeprefix(b"\xef\xbb\xbf")
        if _tool_ash_declared(raw.decode("latin-1")) is None:
            return False
        # The decoder's message is not repeated (unparsed_config_reason);
        # parse_error_kind gives the error's type, because this message names
        # the file its own way.
        undecoded = (
            f"{describe_config_path(path)} declares an ASH configuration but "
            f"could not be parsed {parse_error_kind(exc)}"
        )
    if undecoded is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(undecoded)
    unparsed: Optional[str] = None
    try:
        document = _parse_toml(text)
    except (ValueError, RecursionError) as exc:
        # TOMLDecodeError is a ValueError; so is the one int() raises for a
        # number longer than the interpreter's digit limit, which tomllib lets
        # through undressed. Either is this file not parsing.
        if _tool_ash_declared(text) is None:
            ASH_LOGGER.debug(
                f"Skipping {Path(path).as_posix()} as a config source: it has no "
                f"[tool.ash] table, and it does not parse {parse_error_kind(exc)}"
            )
            return False
        # The file is named with its tool.ash table, which says it is meant
        # to configure ASH.
        unparsed = unparsed_config_reason(path, exc)
    if unparsed is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(unparsed)
    tool = document.get("tool")
    table = tool.get("ash") if isinstance(tool, dict) else None
    if table is None:
        return False
    if not isinstance(table, dict):
        raise ASHConfigSourceError(
            f"tool.ash in {Path(path).as_posix()} must be a table, got "
            f"{type(table).__name__}"
        )
    return True


def _unreadable_pyproject(
    path: Path, found_before: List[ConfigSource], exc: OSError, notes: List[str]
) -> bool:
    """Refuse a pyproject.toml that could not be read, or note it behind a source."""
    if not found_before:
        refusal = (
            ASHConfigFileNotFoundError
            if isinstance(exc, FileNotFoundError)
            else ASHConfigSourceError
        )
        raise refusal(
            f"Could not read {path.as_posix()} ({exc}), so ASH cannot tell "
            "whether it holds a [tool.ash] table. Make it readable, remove "
            "it, or name a config file with --config."
        ) from exc
    notes.append(
        f"Could not read {path.as_posix()} ({exc}); it is not used as an ASH "
        "config source."
    )
    return False


def _pyproject_is_a_source(
    path: Path,
    found_before: List[ConfigSource],
    notes: List[str],
    expect: Optional[FileIdentity] = None,
) -> bool:
    """Probe pyproject.toml without letting it break an unrelated config.

    When a higher-precedence source already exists, pyproject.toml is probed
    only to report it as ignored, so nothing about it may fail the load: before
    #313 a repository with .ash/.ash.yaml was unaffected by whatever its
    pyproject.toml held. When it would be the selected source, a pyproject that
    declares [tool.ash] but cannot be parsed fails closed, and so does one that
    cannot be read at all (a dangling link, a directory, no permission): there
    is no way to tell whether it configures ASH, and skipping it would scan with
    the defaults while its [tool.ash] table, if it has one, sat unread.

    Only a regular file is opened. Discovery runs on whatever a cloned
    repository holds, and opening a device can act on it even when nothing is
    read: a watchdog arms, a tape rewinds. So a FIFO, a device or a directory at
    this name is told by its type, from ``stat``, and refused or ignored unopened.

    What cannot be used behind a higher-precedence source is appended to
    ``notes`` rather than logged; see ``ConfigDiscovery``.

    ``expect`` is the identity discovery's permit check took for the name
    (``ConfigSource.identity``); the read for the table is held to it
    (``pyproject_has_ash_table``), so a file swapped in after the check is
    refused as one that cannot be read, not read outside the grant.
    """
    # Classified from os.stat and its errno, so each name that cannot be followed
    # is reported for what it is.
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except FileNotFoundError:
        # The name exists (discovery found it) but leads nowhere.
        missing = FileNotFoundError(
            errno.ENOENT, "a symbolic link to nothing", os.fspath(path)
        )
        return _unreadable_pyproject(path, found_before, missing, notes)
    except OSError as exc:
        if is_symlink_loop(exc):
            exc = OSError(
                errno.ELOOP,
                "a symbolic link that leads back to itself",
                os.fspath(path),
            )
        return _unreadable_pyproject(path, found_before, exc, notes)
    if not regular:
        return _unreadable_pyproject(
            path,
            found_before,
            OSError(errno.EINVAL, "not a regular file", os.fspath(path)),
            notes,
        )
    try:
        return pyproject_has_ash_table(path, expect=expect)
    except OSError as exc:
        return _unreadable_pyproject(path, found_before, exc, notes)
    except ASHConfigSourceError as exc:
        if not found_before:
            raise
        notes.append(
            f"Ignoring {path.as_posix()}: {found_before[0].label} takes precedence, "
            f"and the [tool.ash] table there could not be read ({exc})."
        )
        return False


def _name_exists(path: Path) -> bool:
    """Whether a config name exists, as ``os.path.lexists`` says, but never guessed.

    ``lexists`` answers False for any error, so a ``.ash/`` directory that cannot
    be searched hid the config inside it and the scan ran with the defaults.
    Only "no such file" and "a path component is not a directory" mean absent;
    any other error refuses, since whether the repository has a config there
    cannot be told.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as exc:
        raise ASHConfigSourceError(
            f"Could not look for a config file at {Path(path).as_posix()} "
            f"({exc.strerror}), so ASH cannot tell whether one is there. Make the "
            "directory readable, or name a config file with --config."
        ) from exc
    return True


def _not_permitted(found: Path) -> ASHConfigInputNotPermittedError:
    # Names the source as found, never what it resolves to, so the refusal reads
    # the same whether that target is missing, unreadable or readable.
    return ASHConfigInputNotPermittedError(
        f"{found.as_posix()}, a config source found in the scanned directory, "
        "reaches a file outside the directories this caller may read config from."
    )


def _search_dir_not_permitted(search_dir: Path) -> ASHConfigInputNotPermittedError:
    # Names the directory as given, never what it leads to.
    return ASHConfigInputNotPermittedError(
        f"{search_dir.as_posix()}, the directory to look for a config source in, "
        "leads through a network share, a device path or a link ASH cannot "
        "read, so ASH does not look inside it."
    )


def _on_windows() -> bool:
    return os.name == "nt"


def _is_a_link_by(path: Path, is_link_stat: Callable[[os.stat_result], bool]) -> bool:
    """Whether *is_link_stat* reads the lstat of `path` as a link.

    False only when `path` provably is not one: it is absent or sits under a
    non-directory. When it cannot be examined at all (a parent directory the
    process cannot search), it may be a link nobody here can see, so the answer
    is True. Every caller is a refusal or permission gate, for which reading an
    unjudgeable component as a link is the safe side. The callers differ only in
    which stat they read as a link, so that is the parameter.
    """
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return is_link_stat(info)


def _is_a_symlink_or_reparse_point(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(getattr(info, "st_file_attributes", 0) & reparse)


def _is_a_link(path: Path) -> bool:
    """Whether `path` is a symbolic link or, on Windows, any reparse point.

    See :func:`_is_a_link_by` for the answer when `path` cannot be examined.
    """
    return _is_a_link_by(path, _is_a_symlink_or_reparse_point)


def discovery_candidates(search_dir: Path) -> Iterator[Path]:
    """Every name discovery looks at in `search_dir` that is there, as an entry.

    In discovery's order, and whatever the entry is: a link counts whether or
    not its target exists. For a caller that checks each candidate before
    discovery reads any: checking only those that are files skips a link to a
    missing target, which then gives a different answer from a link to a present
    one, and so says whether the target exists.

    A ``.ash`` that is a link is itself a candidate, given before any name in
    it is looked at, and the caller stops at the first one it refuses. Asking
    whether ``.ash/<name>`` is there follows the link, so for a ``.ash`` linked
    out of what the caller may read, an answer that depended on the names in it
    would say whether the directory it leads to holds them. A ``.ash`` that is
    a directory of the search directory's own is not one: its names are checked
    one by one, and it holds a scan's output too.
    """
    search_dir = Path(search_dir)
    ash_dir = search_dir / ".ash"
    ash_dir_given = False
    for name in ASH_CONFIG_FILE_NAMES:
        for candidate in (search_dir / name, ash_dir / name):
            if candidate.parent == ash_dir and not ash_dir_given:
                ash_dir_given = True
                # Not Path.is_symlink(), which is False for a Windows junction.
                if _is_a_link(ash_dir):
                    yield ash_dir
            if os.path.lexists(candidate):
                yield candidate
    for name in ASH_RC_FILE_NAMES:
        if os.path.lexists(search_dir / name):
            yield search_dir / name
    if os.path.lexists(search_dir / ASH_PYPROJECT_FILE_NAME):
        yield search_dir / ASH_PYPROJECT_FILE_NAME


#: Links followed before a chain is given up on as unjudgeable: the bound
#: ``os.path.realpath`` applies to a chain of links before it stops following.
#: The reading itself is ``utils/link_chain`` (the one copy, shared with the MCP
#: sandbox gates); the bound is a module attribute so a test can shorten it, and
#: it is passed to the walk at call time.
_LINK_HOPS = LINK_HOPS


def _refused_before_resolving(path: Path) -> bool:
    """Whether resolving `path` on Windows could connect to a host, or cannot be ruled out.

    Resolving a path there opens what it names, so this reads the path from text
    and from ``os.lstat`` / ``os.readlink`` alone (``utils/link_chain``), which
    open a link's own entry and never what it names. True when:

    - the spelling names a share or a device (a UNC path, or a device-prefixed
      path whose device is not a drive letter, or a drive path with a ``..``
      step behind a device prefix);
    - a link on the way, ANY component from the anchor down and not only the
      last, or a link that link leads to, names a share or a device, or its
      target cannot be read, or its chain is longer than ``_LINK_HOPS``;
    - a component that is there cannot be examined, so whether it is a link
      cannot be told.

    A link that leads only to local names is followed and the components under it
    are judged where it leads, as resolving would read them; a component that is
    not there ends the walk with nothing judged, and the permit judges the path
    as it does on every other platform. A relative link target is walked name by
    name from the directory the link is in: ``os.lstat`` of the whole collapsed
    spelling would follow a link among its parents, and open the share at the
    check meant to prevent it.
    """
    text = os.fspath(path)
    if names_a_windows_share(text):
        return True
    return first_unsafe_link(text, hops=_LINK_HOPS) is not None


def _resolved_if_permitted(path: Path, permit: PermitBase) -> Optional[Path]:
    """The path ``path`` resolves to when ``permit`` admits it, else None.

    Nothing is opened. The caller that reads the file takes its identity from a
    descriptor opened after this judgment (``_identity_held_after_the_judgment``),
    never from the name.
    """
    if _on_windows() and _refused_before_resolving(path):
        # Resolving a path on Windows can open a connection to the host a UNC
        # spelling or a link target names, so a path that leads to a share, or
        # one a link on the way makes unreadable, is refused unresolved, as an
        # extends base whose spelling leaves the root is (_resolve_base_path).
        # Every component is read, not the last alone: a link in a parent
        # directory is followed by the lstat of the whole spelling. A link that
        # leads only to local names is resolved below and judged as the file it
        # names.
        return None
    # realpath reads links and opens nothing, and does not raise on a loop.
    resolved = Path(os.path.realpath(path))
    return resolved if permit(resolved) else None


def _permitted(path: Path, permit: PermitBase) -> bool:
    return _resolved_if_permitted(path, permit) is not None


def _identity_held_after_the_judgment(
    path: Path, resolved: Path, held: Optional[List[OpenedConfig]]
) -> FileIdentity:
    """What a read of ``path`` is held to, once the permit admitted ``resolved``.

    ``path`` is opened now, after the judgment (a name the permit refused is never
    opened), and the identity is the descriptor's, when the descriptor leads to
    the very path that was judged (``OpenedConfig.real``). The identity is never
    looked up from the name again: that was a second lookup beside the one the
    judgment made, so a link re-pointed between the two had its new target held as
    the file judged. It is ``ABSENT_FILE`` when the name leads to no regular file
    (a directory, a dangling link, an unreadable name), when it was made to lead
    elsewhere before the open (the descriptor's path is not the judged one), and
    when the descriptor's path cannot be told: no identity vouches for a file the
    permit did not see, and a read held to ``ABSENT_FILE`` refuses whatever file
    is at the name by then.

    With ``held`` the descriptor is appended to it and stays open for the caller to
    close, so the inode stays in use until a read has compared the identity: a
    freed inode number can be given to a file made afterwards, which would pass a
    compare made on a closed descriptor.
    """
    opened = open_config_for_judgment(path)
    if opened is None:
        return ABSENT_FILE
    identity = opened.identity if opened.real == resolved else ABSENT_FILE
    if held is not None:
        held.append(opened)
    else:
        opened.close()
    return identity


def check_search_directory(
    search_dir: Path, permit: Optional[PermitBase] = None
) -> None:
    """Refuse a directory to look for a config source in that leads to a share.

    Under ``permit`` on Windows only. Every lookup of a name under `search_dir`
    (``discovery_candidates``, ``_existing_candidates``) is an ``os.lstat`` of a
    spelling that passes through it, which follows a link among its components;
    so a caller that looks under a directory it was handed judges the directory
    first, whether or not any config name is there, and calls this before the
    first lookup.

    Raises:
        ASHConfigInputNotPermittedError: when the directory names a share or a
            device, or a link on the way leads to one or cannot be read. The
            message names the directory as given.
    """
    if permit is not None and _on_windows() and _refused_before_resolving(search_dir):
        raise _search_dir_not_permitted(search_dir)


def _existing_candidates(
    search_dir: Path, permit: Optional[PermitBase] = None
) -> List[ConfigSource]:
    """Every config name in `search_dir` that exists, in precedence order, unopened.

    Under ``permit`` a ``.ash`` that is a link out of the grant is refused before
    anything looks inside it: whether a name exists there would otherwise answer
    whether a file exists in a directory the caller may not read.
    """
    check_search_directory(search_dir, permit)
    dot_ash = search_dir / ".ash"
    if permit is not None and _name_exists(dot_ash) and not _permitted(dot_ash, permit):
        raise _not_permitted(dot_ash)
    candidates: List[ConfigSource] = []
    for name in ASH_CONFIG_FILE_NAMES:
        for candidate in (search_dir / name, dot_ash / name):
            if _name_exists(candidate):
                candidates.append(ConfigSource(candidate, SOURCE_KIND_DEDICATED))
    for name in ASH_RC_FILE_NAMES:
        candidate = search_dir / name
        if _name_exists(candidate):
            candidates.append(ConfigSource(candidate, SOURCE_KIND_ASHRC))
    pyproject = search_dir / ASH_PYPROJECT_FILE_NAME
    if _name_exists(pyproject):
        candidates.append(ConfigSource(pyproject, SOURCE_KIND_PYPROJECT))
    return candidates


def _check_candidates(
    candidates: List[ConfigSource],
    permit: Optional[PermitBase],
    held: Optional[List[OpenedConfig]] = None,
) -> List[ConfigSource]:
    """``candidates``, each checked against ``permit`` and, when one checked,
    carrying the identity of the file its path led to at the check.

    The identity binds the caller's read to the file that was judged: the permit
    alone left the milliseconds between its check and the open, in which the name
    could be made to lead to a file outside the grant. It is the opened
    descriptor's (``_identity_held_after_the_judgment``), taken after the permit
    admitted the name and never looked up from the name afterwards, so the judged
    file and the held file are one. A candidate the permit refuses is not opened.
    ``held`` collects the descriptors, left open for the caller to close once its
    reads have compared the identities. Without a permit nothing is checked and
    no identity is taken, as before.
    """
    if permit is None:
        return list(candidates)
    checked: List[ConfigSource] = []
    for candidate in candidates:
        resolved = _resolved_if_permitted(candidate.path, permit)
        if resolved is None:
            raise _not_permitted(candidate.path)
        identity = _identity_held_after_the_judgment(candidate.path, resolved, held)
        checked.append(replace(candidate, identity=identity))
    return checked


def check_discovery_candidates(search_dir: Path, permit: Optional[PermitBase]) -> None:
    """Refuse `search_dir` when a config source in it resolves outside `permit`.

    The check ``discover_config_source(search_dir, permit=permit)`` makes before
    it opens anything, for a caller that refuses before a scan starts (MCP
    ``scan_directory``). Opens nothing itself: each candidate is judged by the
    path it resolves to and no identity is taken, since the caller reads none.
    """
    search_dir = Path(search_dir)
    candidates = _existing_candidates(search_dir, permit)
    if permit is None:
        return
    for candidate in candidates:
        if not _permitted(candidate.path, permit):
            raise _not_permitted(candidate.path)


def discover_config_source(
    search_dir: Path, permit: Optional[PermitBase] = None
) -> ConfigDiscovery:
    """Find every config source in `search_dir` and select one by precedence.

    A name counts when it exists, whatever it is; see "Failure" in the module
    docstring for why a dangling link is selected rather than skipped.

    ``permit`` is the caller's predicate for the files it may read config from,
    as for an ``extends`` base. Every source that exists -- the one selected and
    the ones ignored, which are reported and, for ``pyproject.toml``, read -- is
    checked by the path it resolves to before anything opens it, and one the
    predicate refuses raises ``ASHConfigInputNotPermittedError`` naming the
    source as found. Without it nothing is checked.
    """
    search_dir = Path(search_dir)
    # The descriptors each admitted source was held by stay open until this
    # function returns, so the pyproject read below compares its identity while
    # the inode is still in use.
    held: List[OpenedConfig] = []
    found: List[ConfigSource] = []
    notes: List[str] = []
    try:
        candidates = _check_candidates(
            _existing_candidates(search_dir, permit), permit, held
        )
        for candidate in candidates:
            if candidate.kind != SOURCE_KIND_PYPROJECT or _pyproject_is_a_source(
                candidate.path, found, notes, expect=candidate.identity
            ):
                found.append(candidate)
    finally:
        for opened in held:
            opened.close()
    if not found:
        return ConfigDiscovery()
    return ConfigDiscovery(selected=found[0], ignored=found[1:], notes=notes)


def check_discovered_source(path: Path, permit_base: Optional[PermitBase]) -> None:
    """Refuse a discovered config file that resolves to one ``permit_base`` does not permit.

    See "Base paths". Nothing is checked without ``permit_base``. Raises
    ``ASHConfigInputNotPermittedError`` naming ``path`` as it was found, never the
    file it resolves to.

    Resolved with ``os.path.realpath``, as ``_permitted`` resolves a candidate:
    it reads links, opens nothing and does not raise on a symlink loop, where
    ``Path.resolve`` raised a bare RuntimeError on one on Python 3.10 to 3.12
    in place of a config refusal. A loop resolves to itself and is judged as
    the path it was found at. Judged by ``_permitted``, the check discovery
    makes of each candidate, so on Windows a found file that is a link is
    refused unresolved: resolving it can open a connection to the host a UNC
    target names, which discovery's own check never does.
    """
    if permit_base is None or _permitted(Path(path), permit_base):
        return
    raise ASHConfigInputNotPermittedError(
        f"{Path(path).as_posix()}, the config file found in the scanned directory, "
        "reaches a file outside the directories this caller may read config from."
    )


def discovery_warnings(discovery: ConfigDiscovery) -> List[str]:
    """One warning per source discovery found and did not select, then its notes.

    The settings in an ignored source are not applied, so a scan reports these
    with its results as well as in the log; see ``log_config_discovery`` and
    ``resolve_config``. A note says what discovery could not use behind the
    selected source (``ConfigDiscovery.notes``).
    """
    selected = discovery.selected
    if selected is None:
        return []
    warnings: List[str] = []
    for other in discovery.ignored:
        message = (
            f"Ignoring ASH configuration at {other.label}: {selected.label} takes "
            "precedence, and configuration sources are never merged."
        )
        if selected.kind == SOURCE_KIND_DEDICATED and other.kind in (
            SOURCE_KIND_ASHRC,
            SOURCE_KIND_PYPROJECT,
        ):
            message += (
                f" The config file names {', '.join(ASH_CONFIG_FILE_NAMES)} (at the "
                "repository root or in .ash/) are deprecated in favor of "
                f"{', '.join(ASH_RC_FILE_NAMES)} or a [tool.ash] table in "
                f"{ASH_PYPROJECT_FILE_NAME}. Move the settings into one source "
                "and delete the other."
            )
        warnings.append(message)
    warnings.extend(discovery.notes)
    return warnings


def log_config_discovery(
    discovery: ConfigDiscovery, announce_selected: bool = True
) -> List[str]:
    """Say which source is used and which were found but ignored.

    ``announce_selected`` is False for a caller that reports the selected file
    through its own logger; the ignored sources are always reported here.
    Returns the warnings logged, ``discovery_warnings(discovery)``.
    """
    selected = discovery.selected
    if selected is None:
        return []
    if announce_selected:
        ASH_LOGGER.info(f"Using ASH configuration from {selected.label}")
    warnings = discovery_warnings(discovery)
    for message in warnings:
        ASH_LOGGER.warning(message)
    return warnings


def _resolve_toml_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_toml_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_toml_env(v) for v in value]
    if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
        return resolve_env_references(value)
    return value


def _toml_env_reference(value: Any, key: str = "") -> Optional[str]:
    """The key of the first value `_resolve_toml_env` would resolve, or None."""
    if isinstance(value, dict):
        items = ((f"{key}.{k}" if key else str(k), v) for k, v in value.items())
    elif isinstance(value, list):
        items = ((f"{key}[{i}]", v) for i, v in enumerate(value))
    else:
        if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
            return key
        return None
    for child_key, child in items:
        found = _toml_env_reference(child, child_key)
        if found is not None:
            return found
    return None


def config_is_client_delivered(path: Path) -> bool:
    """Whether an MCP client delivered `path`; see "Environment variables".

    ``cli.mcp.sandbox.config_is_client_supplied``, imported when called. The
    ``RefuseEnv`` every caller gets unless it passes another.
    """
    # Imported here, as config/path_trust.py does: importing cli.mcp runs its
    # __init__, which imports profile_registry and through it ash_config.
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    return config_is_client_supplied(path)


def env_refused_for(remote_client: bool, session_id: Optional[str] = None) -> RefuseEnv:
    """The files that resolve no ``!ENV`` for a caller; see "Environment variables".

    ``remote_client`` is ``cli.mcp.sandbox.caller_is_remote`` for the MCP call
    the config is read for, and False for everything else. ``session_id`` is
    that call's session: of the profile files the server writes in the sessions'
    ``config/`` directories, only its own are set aside for a remote caller.
    """
    if not remote_client:
        return config_is_client_delivered
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )

    def refused(path: Path) -> bool:
        return client_named_config_is_untrusted(path, session_id=session_id)

    return refused


def refuse_env_everywhere(path: Path) -> bool:
    """A ``RefuseEnv`` that refuses every file: content a remote client sent."""
    return True


def _refuse_env_nowhere(path: Path) -> bool:
    return False


def _env_rule(refused: bool) -> RefuseEnv:
    """The ``RefuseEnv`` for one file of a chain, once its refusal is decided."""
    return refuse_env_everywhere if refused else _refuse_env_nowhere


def _env_not_resolved(path: Path, where: str) -> ASHConfigEnvNotResolvedError:
    return ASHConfigEnvNotResolvedError(
        f"{describe_config_path(path)} uses !ENV ({where}). !ENV is not resolved "
        "in a config an MCP client delivered, so the file is refused. Write the "
        "value itself in the file (in YAML, quote a value that only looks like a "
        "${VAR} reference), or leave the setting to the server's config."
    )


def _environment_read_refusal(shown: str) -> ASHConfigEnvNotResolvedError:
    """The refusal of a file of a chain whose text reads the environment, when the
    chain's rule keeps that file from it; ``shown`` is how the file is named.

    The one refusal of that kind: the chain walk gives it before a reference is
    resolved (``parse_config_text``) and after a read that did not parse through
    it (``_resolve``), and a caller that judges the texts of a chain it already
    read gives it from ``environment_read_refusals``. It quotes no value, and it
    is the same whether or not the variable it reads is set. It is marked
    (``_REFUSED_BY_THE_WALK_MARK``), so a base whose path came from the
    environment keeps it where another failure of that base is given without the
    path."""
    error = ASHConfigEnvNotResolvedError(
        f"{shown} reads a value from the environment (an !ENV tag or a ${{VAR}} "
        "reference), which a config an MCP client delivered may not, so the file "
        "is refused. Write the value itself in the file (in YAML, quote a value "
        "that only looks like a ${VAR} reference), or leave the setting to the "
        "server's config."
    )
    setattr(error, _REFUSED_BY_THE_WALK_MARK, True)
    return error


def environment_read_refusals(
    texts: Mapping[Path, str],
    names: Mapping[Path, Sequence[Path]],
    refuse_env: RefuseEnv,
    shown: Callable[[Path], str] = describe_config_path,
) -> Dict[Path, ASHConfigEnvNotResolvedError]:
    """The refusals a chain walk with ``refuse_env`` makes of files whose text
    reads the environment, by resolved path, decided on the texts of a chain
    already read.

    ``texts`` is the text of each file of the chain by resolved path and
    ``names`` the paths each was reached by (``ResolvedConfigDocument.names``;
    ``ConfigCheck.texts`` and ``document_names``). A file is refused when
    ``refuse_env`` refuses it or any name that reached it, which includes the
    names of every file above it: the file that names a base chose it, so every
    base of a refused file is refused too, as ``resolve_config_document``
    refuses them. Nothing is read: a caller that judged a chain from the files it
    read once gets the verdict of a second walk without a second read, and a
    file changed since cannot change it. ``shown`` names a file in a message.
    """
    refusals: Dict[Path, ASHConfigEnvNotResolvedError] = {}
    for real, text in texts.items():
        reached_by = (real, *names.get(real, ()))
        if any(refuse_env(name) for name in reached_by) and text_reads_the_environment(
            real, text
        ):
            refusals[real] = _environment_read_refusal(shown(real))
    return refusals


def refuse_unless_a_file(path: Path) -> None:
    """Raise ASHConfigSourceError when ``path`` exists and is not a regular file.

    Decided with stat, before anything opens it: opening a FIFO for reading waits
    for a writer, so a FIFO named as the config (``--config``, or ``ASH_CONFIG``,
    which is ``--config``'s environment variable) left the reader waiting for
    ever; a device such as ``/dev/null`` read as an empty config and
    ``/dev/zero`` without end; a directory raised IsADirectoryError. The one
    check for every reader of this module and the root of every chain
    (``_resolve``), so each caller refuses such a path the same way: the
    commands exit 3, as they do for a config a scan refuses. A path that does
    not exist, or that stat cannot read, is left to the open, which reports it
    as it always has.
    """
    try:
        mode = os.stat(path).st_mode
    except (OSError, ValueError):
        return
    if not stat.S_ISREG(mode):
        raise not_a_regular_file_refusal(Path(path))


def not_a_regular_file_refusal(path: Path) -> ASHConfigSourceError:
    """The refusal for a ``path`` that exists and is not a regular file, in the
    words :func:`refuse_unless_a_file` uses; for a caller that has already made
    its one stat of the path and must not make a second."""
    # The path is raw here: each place that prints the refusal shows the whole
    # line once, on one line (a message built from shown text would be shown a
    # second time by a log sink).
    return ASHConfigSourceError(
        f"{describe_config_path(path)} is not a regular file, so it is not read as "
        "a config"
    )


def read_config_file(
    path: Path,
    expect: Optional[FileIdentity] = None,
    refuse_env: Optional[RefuseEnv] = None,
    references: Optional[List[EnvironmentReference]] = None,
) -> Any:
    """Parse one config file, without resolving its `extends`.

    A ``pyproject.toml`` yields its ``[tool.ash]`` table; any other ``.toml``
    file is a config at its top level. YAML and JSON are read exactly as
    ``AshConfig.from_file`` always read them, except that a YAML or TOML file
    ``refuse_env`` refuses (by default, one an MCP client delivered) is refused
    if it uses ``!ENV``; see "Environment variables". JSON has no ``!ENV``.
    ``expect`` is passed to ``read_config_bytes``.

    ``references``, when given, is extended with what the file read from the
    environment, at paths in the file's own document. They are found by parsing
    the text the file was read as a second time, with each reference left as
    the file wrote it (``config/environment_record.py``); a YAML text that can
    hold no reference is parsed once.
    """
    data, found = _read_config_file(Path(path), expect, refuse_env)
    if references is not None:
        references.extend(found)
    return data


def read_config_file_and_references(
    path: Path,
    expect: Optional[FileIdentity] = None,
    refuse_env: Optional[RefuseEnv] = None,
) -> Tuple[Any, List[EnvironmentReference]]:
    """``read_config_file``, and what the file read from the environment."""
    found: List[EnvironmentReference] = []
    data = read_config_file(
        path, expect=expect, refuse_env=refuse_env, references=found
    )
    return data, found


def toml_text_of(path: Path, data: bytes) -> str:
    """The text of the TOML config file ``path`` whose bytes are ``data``, as
    ``read_config_file`` decodes it: a leading UTF-8 byte order mark is dropped
    (tomllib rejects it), and bytes that are not UTF-8 are refused as every
    unparsed config is (``unparsed_config_reason``: the byte's offset, never
    its value). Nothing is read: the answer is made of ``data`` alone, so a
    caller that already holds the bytes of the file it checked (the raw
    ``get_config`` answer) decodes and judges them without a second read.
    """
    undecoded: Optional[str] = None
    try:
        return data.removeprefix(b"\xef\xbb\xbf").decode("utf-8")
    except UnicodeDecodeError as exc:
        undecoded = unparsed_config_reason(path, exc)
    # Outside the handler (unparsed_config_reason): the decoder's message,
    # which names the byte, is neither the cause nor the context of this one.
    raise ASHConfigUnparsedError(undecoded)


def toml_config_text(path: Path, expect: Optional[FileIdentity] = None) -> str:
    """The text of the TOML config file ``path``, as ``read_config_file`` reads it:
    one read of the name, held to ``expect`` when one is given, decoded by
    :func:`toml_text_of`.

    Together with :func:`toml_config_table` this is the whole of that reader's
    TOML handling short of the environment.
    """
    return toml_text_of(path, read_config_bytes(path, expect=expect))


def toml_config_table(path: Path, text: str) -> Any:
    """The settings of the TOML config file ``path`` whose text is ``text``, before
    any ``${VAR}`` value is resolved: the file's top level, or a
    ``pyproject.toml``'s ``[tool.ash]`` table.

    Text that is not TOML is refused as every unparsed config is
    (``unparsed_config_reason``: the error's type and where the parser stopped,
    nothing the parser said, which can name a table of the file); a
    ``pyproject.toml`` with no such table and one whose ``tool.ash`` is not a
    table are refused in the words ``read_config_file`` uses. Nothing is read:
    the answer is made of ``text`` alone.
    """
    unparsed: Optional[str] = None
    try:
        document = _parse_toml(text)
    except (ValueError, RecursionError) as exc:
        # TOMLDecodeError, the ValueError int() raises for a number past the
        # interpreter's digit limit, which tomllib lets through undressed, and
        # the RecursionError of a text nested past the interpreter's recursion
        # limit, which left read_config_file raw (parse_config_text and
        # pyproject_has_ash_table word it the same way).
        unparsed = unparsed_config_reason(path, exc)
    if unparsed is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(unparsed)
    if is_pyproject(path):
        tool = document.get("tool")
        table = tool.get("ash") if isinstance(tool, dict) else None
        if table is None:
            raise ASHConfigSourceError(
                f"{path.as_posix()} has no [tool.ash] table, so it holds no "
                "ASH configuration"
            )
        if not isinstance(table, dict):
            raise ASHConfigSourceError(
                f"tool.ash in {path.as_posix()} must be a table, got "
                f"{type(table).__name__}"
            )
        document = table
    return document


def _read_config_file(
    path: Path,
    expect: Optional[FileIdentity],
    refuse_env: Optional[RefuseEnv],
) -> Tuple[Any, List[EnvironmentReference]]:
    if is_json_file(path):
        # utf-8-sig: a leading byte order mark is dropped, as YAML and TOML drop
        # it; Windows PowerShell 5 writes one.
        return (
            json.loads(read_config_bytes(path, expect=expect).decode("utf-8-sig")),
            [],
        )
    delivered = (refuse_env or config_is_client_delivered)(path)
    if is_toml_file(path):
        document = toml_config_table(path, toml_config_text(path, expect=expect))
        if delivered:
            key = _toml_env_reference(document)
            if key is not None:
                raise _env_not_resolved(path, f"key {key}")
            return document, []
        try:
            resolved = _resolve_toml_env(document)
        except ASHConfigUnsetVariableError as exc:
            raise _unset_variable_in(path, exc) from None
        return resolved, environment_references(document, resolved)
    text = read_config_bytes(path, expect=expect).decode("utf-8")
    try:
        resolved = load_yaml_config(
            named_text_stream(text, path),
            env="refuse" if delivered else "resolve",
        )
    except EnvReferenceNotResolved as exc:
        raise _env_not_resolved(path, f"line {exc.line}") from exc
    except ASHConfigUnsetVariableError as exc:
        raise _unset_variable_in(path, exc) from None
    if delivered or ("$" not in text and "\\" not in text):
        # No reference: one holds a "$", written as itself or, in a
        # double-quoted scalar a file tags !ENV, as an escape.
        return resolved, []
    written = load_yaml_config(named_text_stream(text, path), env="written")
    return resolved, environment_references(written, resolved)


def _unset_variable_in(
    path: Path, exc: ASHConfigUnsetVariableError
) -> ASHConfigUnsetVariableError:
    """``exc``, naming ``path`` as the file that references the unset variable."""
    return ASHConfigUnsetVariableError(
        f"{describe_config_path(path)}: {exc.detail}",
        variable=exc.variable,
        config_file=path,
        detail=exc.detail,
    )


def named_text_stream(text: str, path: Path) -> io.StringIO:
    """`text` as a stream named `path`, for a YAML parser.

    A parse error then names the file and gives its line and column, as it did
    when the parser read the open file, rather than "<unicode string>" followed
    by a copy of the offending line.
    """
    stream = io.StringIO(text)
    stream.name = os.fspath(path)
    return stream


def read_config_text(path: Path, expect: Optional[FileIdentity] = None) -> str:
    """The text of one config file, for parse_config_text and
    parse_config_text_literally: a caller that needs both of its views parses
    them from this one read, so a file changed in between cannot give two
    different ones. A path that is not a regular file is refused before it is
    opened (``refuse_unless_a_file``); a TOML or JSON file loses a leading byte
    order mark (as ``read_config_file`` drops it: tomllib and json refuse one),
    and a TOML file that is not UTF-8 is refused as read_config_file refuses it.

    Every read goes through ``read_config_bytes``: a non-blocking open of a
    regular file, held to ``expect`` when the caller took an identity, and
    bounded by ``ASH_CONFIG_MAX_FILE_BYTES``. Without an identity this used to
    fall back to a plain blocking ``open()`` and an unbounded read, so the
    config validator, the linter, MCP profile loading and the literal
    re-resolution read whole files with no bound.
    """
    path = Path(path)
    refuse_unless_a_file(path)
    if is_toml_file(path):
        undecoded: Optional[str] = None
        try:
            return _read_toml_text(path, expect=expect)
        except UnicodeDecodeError as exc:
            # The decoder's message prints the byte (unparsed_config_reason).
            undecoded = unparsed_config_reason(path, exc)
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(undecoded)
    text = read_config_bytes(path, expect=expect).decode("utf-8")
    if is_json_file(path):
        # json.loads refuses a leading byte order mark; read_config_file
        # decodes a JSON file as utf-8-sig, so the scan's own parse of this
        # text (parse_config_text) must see the same text.
        return text.removeprefix(chr(0xFEFF))
    return text


#: The name a chain walk refuses a file by while it reads a file its rule
#: (``_ChainState.refuse_env``) keeps from reading the environment, and None
#: while it reads any other. Set around each read of the chain
#: (``_read_into_state``) and consulted by ``parse_config_text``, where every
#: reader of the chain, a caller's own included, parses a file's text: the
#: refusal is then decided before a ``${VAR}`` reference is resolved, so it does
#: not depend on whether the variable is set.
_ENV_REFUSED_READ_OF: ContextVar[Optional[str]] = ContextVar(
    "ash_config_env_refused_read_of", default=None
)

#: Set on the refusal the chain's rule gives (``_environment_read_refusal``). It
#: names its file as the walk shows it, so a base whose path came from the
#: environment keeps it where another failure of that base is given without it.
_REFUSED_BY_THE_WALK_MARK = "_ash_env_refused_by_the_walk"


class _NamedText(io.StringIO):
    """``text`` as a stream named ``name``, so a YAML error names the file it
    was read from, as one parsed from the open file does."""

    def __init__(self, text: str, name: str) -> None:
        super().__init__(text)
        self.name = name


def parse_config_text(
    path: Path, text: str, refuse_env: Optional[RefuseEnv] = None
) -> Any:
    """read_config_file for ``text``, the text read_config_text read from
    ``path`` (whose name says the format and, for a pyproject.toml, the
    table).

    A file an MCP client delivered that reads from the environment is refused
    first (refuse_environment_in_a_delivered_file): every load and every check
    of a config parses its files here, so each refuses it. So is a file the
    chain walk reading it keeps from the environment by its own rule
    (``_ENV_REFUSED_READ_OF``), which can be stricter than "delivered".

    ``refuse_env`` is the same rule for a caller that parses a file outside a
    chain walk, the root a check reads first: when it refuses ``path``, a text
    that reads the environment is refused here too, before a reference is
    resolved, in the words the walk uses. A walk's own decision for the file
    takes precedence.

    A file nested past the interpreter's recursion limit makes a parser raise
    RecursionError. That is this file's text failing to parse, and this is the
    one place that knows which file it is, so it is refused here as an
    unparsed config (unparsed_config_reason) and every caller words it as it
    words any other file that does not parse.
    """
    path = Path(path)
    refuse_environment_in_a_delivered_file(path, text)
    refused_as = _ENV_REFUSED_READ_OF.get()
    if refused_as is None and refuse_env is not None and refuse_env(path):
        refused_as = describe_config_path(path)
    if refused_as is not None and text_reads_the_environment(path, text):
        raise _environment_read_refusal(refused_as)
    unparsed: Optional[str] = None
    try:
        return _parse_text_by_format(path, text)
    except RecursionError as exc:
        unparsed = unparsed_config_reason(path, exc)
    # Outside the handler (unparsed_config_reason).
    raise ASHConfigUnparsedError(unparsed)


def _parse_text_by_format(path: Path, text: str) -> Any:
    """The document ``text`` parses to, in the format ``path``'s name says."""
    if is_json_file(path):
        return json.loads(text)
    if is_toml_file(path):
        document = _toml_document(path, text)
        try:
            return _resolve_toml_env(document)
        except ASHConfigSourceError as exc:
            raise _with_its_file(path, exc) from exc
    try:
        return load_yaml_config(_NamedText(text, str(path)))
    except ASHConfigSourceError as exc:
        # An ${VAR} reference to an unset variable. Named with its file,
        # since the reference itself does not say where it was written.
        raise _with_its_file(path, exc) from exc


def refuse_environment_in_a_delivered_file(path: Path, text: str) -> None:
    """Raise ASHConfigEnvNotResolvedError when ``path`` is a config file an MCP
    client delivered (``cli.mcp.sandbox.config_is_client_supplied``) and
    ``text``, the text read from it, reads from the environment.

    A value such a file read from the environment is the server's: the client
    wrote the file and reads back what ASH makes of it (get_config, a scan's
    results), and a ``patch`` can put the value anywhere in the configuration.
    So the file reads nothing from it. Decided on the text the load is about to
    parse, before it is parsed with the environment, so no value is read for
    the file and a file changed between two reads cannot get past it.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if not config_is_client_supplied(path) or not text_reads_the_environment(
        path, text
    ):
        return
    raise ASHConfigEnvNotResolvedError(
        f"{describe_config_path(path)} reads a value from the environment (an "
        "!ENV tag or a ${VAR} reference), which a config an MCP client delivered "
        "may not, so the file is refused. Write the value itself in the file (in "
        "YAML, quote a value that only looks like a ${VAR} reference), or leave "
        "the setting to the server's config."
    )


def text_reads_the_environment(path: Path, text: str) -> bool:
    """Whether ``text``, a config file's text, reads anything from the
    environment when ``path`` is loaded: an ``!ENV`` scalar or a plain YAML
    scalar the loader resolves as one (a key included), or a TOML string
    value starting with a reference (``_resolve_toml_env``). JSON reads
    nothing. A text that does not parse reads nothing; its load says why. A
    text nested past the interpreter's recursion limit is NOT answered that
    way: this check's parse and the load's parse run at different depths of
    the stack, so a text at the edge of the limit could pass here and then
    parse, with its references read. A check that cannot judge the text
    refuses it as an unparsed config (ASHConfigUnparsedError, in the words
    ``parse_config_text`` uses for the same file), where the RecursionError
    used to escape this check raw."""
    path = Path(path)
    if is_json_file(path):
        return False
    if is_toml_file(path):
        unparsed: Optional[str] = None
        try:
            document = _toml_document(path, text)
        except ASHConfigSourceError:
            return False
        except RecursionError as exc:
            unparsed = unparsed_config_reason(path, exc)
        if unparsed is not None:
            # Outside the handler (unparsed_config_reason).
            raise ASHConfigUnparsedError(unparsed)
        pending: List[Any] = [document]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
                return True
        return False
    return _yaml_reads_the_environment(_NamedText(text, str(path)), path)


def _yaml_reads_the_environment(stream: Any, path: Optional[Path] = None) -> bool:
    """Whether the YAML in ``stream`` holds a scalar the loader reads from the
    environment: one tagged ``!ENV``, or a plain scalar the loader tags so
    (``load_yaml_config`` registers ENV_REFERENCE_PATTERN as an implicit
    resolver). False for a stream that does not parse. A stream nested past
    the interpreter's recursion limit is refused as an unparsed config when
    ``path`` names the file (``text_reads_the_environment``, a check that may
    not answer "reads nothing" for a text it could not judge), and answers
    False without one (``uses_env_references``, a lint convenience whose load
    words the depth itself)."""

    class _Loader(yaml.SafeLoader):
        pass

    _Loader.add_implicit_resolver("!ENV", ENV_REFERENCE_PATTERN, None)
    unparsed: Optional[str] = None
    try:
        root = yaml.compose(stream, Loader=_Loader)
    except (UnicodeDecodeError, yaml.YAMLError):
        return False
    except RecursionError as exc:
        if path is None:
            return False
        unparsed = unparsed_config_reason(path, exc)
    if unparsed is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(unparsed)
    pending = [root] if root is not None else []
    # An alias is the node it names, so a node can be reached twice, and a
    # recursive alias reaches itself.
    seen: Set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if node.tag == "!ENV":
            return True
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                pending.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)
    return False


def _with_its_file(path: Path, exc: ASHConfigSourceError) -> ASHConfigSourceError:
    """``exc`` again, named with the file it was raised for, and of the same kind.

    An unset-variable error keeps its class and its variable and gains its file, so
    that the scan and the checks can tell it from an ``extends`` failure
    (_environment_blind_error).
    """
    message = f"{describe_config_path(path)}: {exc}"
    if isinstance(exc, ASHConfigUnsetVariableError):
        return ASHConfigUnsetVariableError(
            message, variable=exc.variable, config_file=path
        )
    return ASHConfigSourceError(message)


def _toml_document(path: Path, text: str) -> Any:
    """The settings of a TOML config file, parsed from ``text``, the text of
    ``path``, before ``${...}`` values resolve.

    A ``pyproject.toml`` yields its ``[tool.ash]`` table; any other ``.toml``
    file is a config at its top level.
    """
    unparsed: Optional[str] = None
    try:
        document = _parse_toml(text)
    except ValueError as exc:
        # TOMLDecodeError, and int()'s digit-limit ValueError (toml_config_table).
        unparsed = unparsed_config_reason(path, exc)
    if unparsed is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(unparsed)
    if is_pyproject(path):
        tool = document.get("tool")
        table = tool.get("ash") if isinstance(tool, dict) else None
        if table is None:
            raise ASHConfigSourceError(
                f"{path.as_posix()} has no [tool.ash] table, so it holds no "
                "ASH configuration"
            )
        if not isinstance(table, dict):
            raise ASHConfigSourceError(
                f"tool.ash in {path.as_posix()} must be a table, got "
                f"{type(table).__name__}"
            )
        document = table
    return document


#: The tag read_config_file_as_written gives a scalar the file tags ``!ENV``
#: itself, so its constructor can keep the tag. Not a tag a file can write.
_WRITTEN_ENV_TAG = "tag:ash.internal,2026:explicit-env"


def read_config_file_as_written(path: Path) -> Any:
    """``read_config_file_literally``, with an explicit ``!ENV`` tag kept.

    A scalar the file tags ``!ENV`` itself comes back as ``"!ENV "`` followed
    by the scalar, and a plain scalar the loader tags ``!ENV`` implicitly (a
    ``${VAR}`` or ``${VAR:default}``) as the file writes it. So each value
    read from the environment comes back exactly as the file wrote it, for a
    record of the configuration that keeps the reference and not the value
    (config_validator.environment_record_read).
    """
    return read_config_file_literally(path, keep_env_tags=True)


def read_config_file_literally(path: Path, keep_env_tags: bool = False) -> Any:
    """``read_config_file`` without reading the environment.

    Every value that would be read from the environment (an ``!ENV`` scalar, a
    plain YAML scalar or a TOML string starting with ``${``) is returned as the
    file writes it, without the tag (``keep_env_tags`` keeps an explicit one:
    read_config_file_as_written). Used to tell which values of a loaded config
    came from the environment, and to report an ``extends`` failure without
    them. A path that is not a regular file is refused before it is opened
    (``refuse_unless_a_file``).
    """
    return parse_config_text_literally(path, read_config_text(path), keep_env_tags)


class TagWrittenReference(str):
    """A scalar whose leading ``!ENV `` the tag-keeping loader added itself.

    ``parse_config_text_literally(keep_env_tags=True)`` writes an explicitly
    tagged entry as ``"!ENV " + scalar`` so a reader sees the file's own
    spelling. Literal text that merely starts with those bytes (a JSON string,
    a quoted YAML scalar) is a plain ``str``: a reader strips the prefix only
    on this type, so a file's own text is never misquoted as a tag.

    Only a reader that asks for the mark gets this type
    (``mark_written_tags``); every other tag-keeping reader gets a plain
    ``str``, because ``yaml.safe_dump`` refuses a ``str`` subclass and the
    as-written records those readers feed are dumped.
    """

    __slots__ = ()


def parse_config_text_literally(
    path: Path,
    text: str,
    keep_env_tags: bool = False,
    mark_written_tags: bool = False,
) -> Any:
    """read_config_file_literally for ``text``, the text read_config_text read
    from ``path``.

    With ``keep_env_tags`` an explicit ``!ENV`` scalar comes back as
    ``"!ENV "`` plus the scalar. With ``mark_written_tags`` as well, that
    string is a :class:`TagWrittenReference`, so a reader can tell the prefix
    the loader added from the same bytes in a JSON or quoted-YAML string; the
    mark is for the one reader that needs the difference, and is off for the
    rest."""
    path = Path(path)
    if is_json_file(path):
        return json.loads(text)
    if is_toml_file(path):
        return _toml_document(path, text)

    from automated_security_helper.config.ash_config import _NoAliasSafeLoader

    # Every alias is refused, as parse_config_text's loader (load_yaml_config)
    # refuses it: a literal reading that admitted one read a document the load
    # never reads.
    class _LiteralLoader(_NoAliasSafeLoader):
        pass

    def as_written(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
        # An !ENV tag on a list or a mapping fails here with the YAML error
        # load_yaml_config's constructor raises for it.
        return loader.construct_scalar(node)

    _LiteralLoader.add_implicit_resolver("!ENV", ENV_REFERENCE_PATTERN, None)
    _LiteralLoader.add_constructor("!ENV", as_written)

    class _TagKeepingLoader(_LiteralLoader):
        def compose_scalar_node(self, anchor: Any) -> Any:
            # The event's own tag is the one the file wrote; the implicit
            # resolver gives a plain scalar the same "!ENV" afterwards.
            explicit = self.peek_event().tag == "!ENV"
            node = super().compose_scalar_node(anchor)
            if explicit:
                node.tag = _WRITTEN_ENV_TAG
            return node

    def tagged_as_written(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
        written = "!ENV " + loader.construct_scalar(node)
        return TagWrittenReference(written) if mark_written_tags else written

    _TagKeepingLoader.add_constructor(_WRITTEN_ENV_TAG, tagged_as_written)
    loader_class = _TagKeepingLoader if keep_env_tags else _LiteralLoader
    loader = loader_class(_NamedText(text, str(path)))
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def default_confinement_root(
    config_path: Path, source_dir: Optional[Path] = None
) -> Path:
    """The directory every base in `config_path`'s chain must stay inside.

    The scan's source directory when `config_path` is inside it, so a project
    config may extend a file anywhere in the repository being scanned.
    Otherwise -- no source directory, or a config kept outside it -- the root
    config's own directory, or the parent of ``.ash/`` for a file in ``.ash/``.

    A root config reached through a link an MCP client delivered is placed
    where that link sits, not where it leads (``_client_link``): the client
    chose the file by placing the link, so its bases stay in the tree the client
    delivered, as the bases of a file written there do.
    """
    config_real = _client_link(Path(config_path))
    if config_real is None:
        try:
            config_real = Path(config_path).resolve()
        except RuntimeError:
            # Before Python 3.13, resolve() raises RuntimeError on a symbolic
            # link loop, and that error's text names the path. Refused as the
            # path problem it is, with a fresh filename-less ELOOP cause for
            # the category mapping; the raise site that would name the file
            # does so by its shown form, and this one names it not at all.
            # Raised below, outside the handler, so neither the RuntimeError
            # nor resolve()'s own error stays on the chain a walker could
            # print.
            pass
    if config_real is None:
        raise ASHConfigSourceError("Config path is a symbolic link loop") from OSError(
            errno.ELOOP, os.strerror(errno.ELOOP)
        )
    if source_dir is not None:
        # realpath, as check_discovered_source resolves: it reads links and does
        # not raise on a symbolic link loop, where Path.resolve raised a bare
        # RuntimeError on Python 3.10 to 3.12. A source directory that loops
        # holds no config, and the root falls back to the config's own
        # directory, as it does from 3.13 on.
        source_real = Path(os.path.realpath(source_dir))
        if config_real.is_relative_to(source_real):
            return source_real
    parent = config_real.parent
    if parent.name == ".ash":
        parent = parent.parent
    return parent


def _client_link(path: Path) -> Optional[Path]:
    """Where the first link on the way to ``path`` that sits in a client's tree is, or None.

    A link sits in a client's tree when the directory holding it is one an MCP
    client delivered (``config_is_client_delivered``); a link elsewhere that
    leads into such a tree was not placed by the client. Each location is under
    its parent with that parent's links resolved (``link_locations``), so it
    compares with resolved paths.
    """
    for location in link_locations(path):
        if config_is_client_delivered(location.parent):
            return location
    return None


@dataclass
class ResolvedConfigDocument:
    """A config's merged data, and the files it was built from.

    ``chain`` lists every file read, in merge order: bases before the files that
    extend them, the root config last. A file reached on two branches appears
    twice, because it was merged twice. ``named`` lists the same files, in the same
    order, by the path that named them before any symlink was followed: the root
    as the caller gave it, and each base as its ``extends`` entry spells it from
    the file that extends it (``_base_named``). A base that is a symlink is judged
    by that name too (``config/sandbox_grants.py``, ``files_inside``), since
    whoever can write the link chooses the file it reaches. ``documents`` holds
    each file's document
    as it was parsed, before its ``extends`` and ``patch`` were applied, so a
    caller checking what a file sets checks what was read rather than reading the
    file again.

    ``chain`` and ``documents`` name each file by its resolved path. ``names``
    gives, for each of them, the paths it was reached by before any symlink was
    followed: the root config as it was passed or discovered, and a base as its
    ``extends`` entry spells it, relative to the resolved directory of the file
    that names it. After those, a base's names include the resolved path and the
    names of every file above it in the chain, since the file that names a base
    chose it. A check of who wrote a file judges it by each of these and by
    every symlink on the way (``by_every_name``), since a link's location says who
    chose the file it reaches.
    """

    data: Any
    chain: List[Path] = field(default_factory=list)
    root: Optional[Path] = None
    named: List[Path] = field(default_factory=list)
    documents: Dict[Path, Any] = field(default_factory=dict)
    names: Dict[Path, Tuple[Path, ...]] = field(default_factory=dict)
    #: What the files of ``chain`` read from the environment, each at the place
    #: its file wrote it, in ``data``'s terms: a ``patch`` operation's value at
    #: the place the operation puts it (``config/environment_record.py``). One
    #: under ``extends`` names a base, not a value of ``data``, and is not here.
    #: Every read is here, one a later file of the chain wrote a literal over
    #: included: a consumer that masks what was read (redaction, the record)
    #: masks a value the chain read wherever it appears.
    environment_references: List[EnvironmentReference] = field(default_factory=list)
    #: The references of ``environment_references`` the merged ``data`` still
    #: shows at their places (``_still_describes``): the ones a view of the
    #: merged configuration writes back as the file wrote them (`ash config
    #: get`, the MCP get_config tool). A base's reference under an overlay's
    #: literal describes a file of the chain, not the configuration, and is
    #: left out here; every other consumer reads ``environment_references``.
    displayed_environment_references: List[EnvironmentReference] = field(
        default_factory=list
    )
    #: The files of ``chain`` reached through a value read from the environment:
    #: a base an ``extends`` entry named with one, and every base below it.
    environment_paths: FrozenSet[Path] = frozenset()
    #: Every string the files of ``chain`` read from the environment, those of
    #: ``extends`` and ``patch`` included: each reference's resolved string and
    #: the part the variable gave. Only for a free-text message that names no
    #: field (``config_validator.redact_values``); a message about a field
    #: quotes it by its place (``environment_record.with_environment_values_shown``).
    environment_values: List[str] = field(default_factory=list)
    #: Where each reference a file of ``chain`` wrote ended up in ``data``, by
    #: ``EnvironmentReference.place_key`` (the file, the path it holds in the
    #: file's own document, value or key, its text): the places of
    #: ``environment_references`` it is now at, none for one a ``patch`` wrote
    #: over or that sets no value. For the record of the configuration
    #: (config_validator.environment_record_read), which reads each file's
    #: references in the file's own terms.
    reference_places: Dict[Tuple[Any, ...], List[Tuple[Any, ...]]] = field(
        default_factory=dict
    )

    def shown_path(self, path: Path) -> str:
        """How a message names ``path``, a file of ``chain``: as
        ``describe_config_path`` does, or as ``<value>`` when its path came from
        the environment (``environment_paths``)."""
        return _shown_chain_path(path, self.environment_paths)


def _shown_chain_path(path: Path, environment_paths: Collection[Path]) -> str:
    if Path(path) in environment_paths:
        return ENVIRONMENT_VALUE_SHOWN
    return describe_config_path(Path(path))


def _values_of(references: List[EnvironmentReference]) -> List[str]:
    """``ResolvedConfigDocument.environment_values`` for ``references``."""
    values: List[str] = []
    for reference in references:
        for text in (reference.resolved, reference.value):
            if text and text not in values:
                values.append(text)
    return values


#: The paths each file of a chain was reached by; see ``ResolvedConfigDocument``.
ChainNames = Mapping[Path, Sequence[Path]]


def by_every_name(
    judge: Callable[[Path], bool], names: Optional[ChainNames] = None
) -> Callable[[Path], bool]:
    """``judge`` for a chain file, true when it holds for any name the file has.

    The names are the file's resolved path and each path in ``names`` it was
    reached by. ``judge`` takes one path, as named; the checks it is used with
    (``cli/mcp/sandbox.config_is_client_supplied`` and
    ``client_named_config_is_untrusted``) also judge each symlink on the way.
    """
    known = names or {}

    def judged(path: Path) -> bool:
        return any(judge(name) for name in (path, *known.get(path, ())))

    return judged


@dataclass
class _ChainState:
    root: Path
    permit_base: Optional[PermitBase] = None
    refuse_env: RefuseEnv = config_is_client_delivered
    anchor_relative_paths: Optional[AnchorPaths] = None
    files_read: int = 0
    order: List[Path] = field(default_factory=list)
    named: List[Path] = field(default_factory=list)
    documents: Dict[Path, Any] = field(default_factory=dict)
    names: Dict[Path, List[Path]] = field(default_factory=dict)
    #: For each base, the paths of the files above it in the chain.
    above: Dict[Path, List[Path]] = field(default_factory=dict)
    reader: Callable[[Path], Any] = read_config_file
    #: Each file's text as the resolution read it, by resolved path: filled by
    #: the stock reader (_read_into_state) or handed in by a caller whose own
    #: reader keeps text (load_config_file_for_run, the config checks). The
    #: as-written reference view is parsed from it (_file_references), so no
    #: file is read from disk twice and a file changed between two reads
    #: cannot give the record a document the resolution never saw.
    texts: Dict[Path, str] = field(default_factory=dict)
    #: ``ResolvedConfigDocument.environment_references``.
    references: List[EnvironmentReference] = field(default_factory=list)
    #: Every reference a file of the chain read, ``extends`` and ``patch``
    #: included, where it was written: ``ResolvedConfigDocument.environment_values``.
    read: List[EnvironmentReference] = field(default_factory=list)
    #: ``ResolvedConfigDocument.environment_paths``.
    environment_paths: Set[Path] = field(default_factory=set)
    #: ``resolve_config_document``'s ``confine``: given each file's resolved
    #: path, the name that reached it, and the document the file resolved to
    #: (its own data merged over its bases', its ``patch`` applied), it returns
    #: the document the chain merges in its place.
    confine: Optional[Callable[[Path, Path, Any], Any]] = None
    #: ``resolve_config_document``'s ``repository_file``: given a chain file's
    #: resolved path and the name that reached it, whether the file is the
    #: repository's. None tracks no ownership, and every patch pointer then
    #: resolves against the whole merged document, as without the hook.
    repository_file: Optional[Callable[[Path, Path], bool]] = None
    #: The bases the walk holds open (``_resolve_base_path``), closed when the
    #: walk ends: a base is judged on the file it opened, and an open descriptor
    #: keeps that inode in use until the read has been held to it.
    held: List["OpenedConfig"] = field(default_factory=list)

    def shown(self, path: Path) -> str:
        """``ResolvedConfigDocument.shown_path`` for a file of this chain."""
        return _shown_chain_path(path, self.environment_paths)

    def confined(self, real: Path, named: Path, data: Any) -> Any:
        """``data``, the document the file at ``real`` resolved to, as
        ``confine`` gives it back; as it is without one."""
        return data if self.confine is None else self.confine(real, named, data)

    def reached(self, real: Path, named: Path) -> None:
        spellings = self.names.setdefault(real, [])
        if named != real and named not in spellings:
            spellings.append(named)

    def chosen_by(self, real: Path, paths: Sequence[Path]) -> None:
        recorded = self.above.setdefault(real, [])
        for path in paths:
            if path != real and path not in recorded:
                recorded.append(path)

    def all_names(self) -> Dict[Path, Tuple[Path, ...]]:
        """``ResolvedConfigDocument.names``: own spellings first, then the files above.

        A file with no spelling of its own but files above it is listed under
        its own path first, so a message that names a file by the first of
        these (``client_config_policy._as_reached``) names the file itself.
        """
        result: Dict[Path, Tuple[Path, ...]] = {}
        for real in dict.fromkeys([*self.names, *self.above]):
            own = list(self.names.get(real, ()))
            inherited = [p for p in self.above.get(real, ()) if p not in own]
            if inherited:
                own = (own or [real]) + inherited
            if own:
                result[real] = tuple(own)
        return result


#: Set to True on a chain error whose text quotes what a file holds (a ``patch``
#: operation, or an error raised while merging), which can be a value read from
#: the environment. resolve_config_document gives the reason without the
#: environment (_environment_blind_error) when the chain read anything from it.
#: A mark on a plain ASHConfigSourceError, not a private subclass: when the
#: refusal is kept (nothing was read from the environment), it is the error an
#: operator's traceback shows, and every printer (a repr, traceback_text, a
#: formatted traceback) then names the public class, where a subclass showed
#: the private one.
_QUOTES_THE_DOCUMENT_MARK = "_ash_quotes_the_document"


def _quotes_the_document(message: str) -> ASHConfigSourceError:
    """An ASHConfigSourceError carrying the document-quoting mark above."""
    error = ASHConfigSourceError(message)
    setattr(error, _QUOTES_THE_DOCUMENT_MARK, True)
    return error


#: Set on the extends/patch catch-all's error: the variables named by mapping
#: keys the failing file writes as references that resolved to no key (set,
#: but to text that spells none). Threaded from the raising frame, which still
#: holds the file's held text, to _environment_blind_error, whose own literal
#: re-resolution cannot see this shape (the literal reading keeps the key as
#: written and resolves). Names only, never values.
_EMPTY_KEY_REFERENCE_NAMES_MARK = "_ash_empty_key_reference_names"


def _empty_key_reference_names(text: Optional[str], path: Path) -> Tuple[str, ...]:
    """The variables named by mapping keys the file at ``path`` writes as
    references that resolve to no key: each is set, but to text that spells
    none (empty or whitespace), so the loader's resolution gives None and the
    entry lands under a None key, which no later step expects.

    ``text`` is the held text of the read that failed (``_ChainState.texts``),
    so the file is never read from disk again; the references are resolved by
    the loader's own rule (``resolve_env_references``), in the raising frame,
    right after the read that failed. Empty when the text is missing or does
    not parse: nothing can be said then without reading the file again.
    """
    if text is None:
        return ()
    try:
        written = parse_config_text_literally(path, text, keep_env_tags=True)
    except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
        return ()
    names: Set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                name = referenced_name(key) if isinstance(key, str) else None
                if name is not None:
                    try:
                        resolved = resolve_env_references(written_without_tag(key))
                    except ASHConfigSourceError:
                        # Unset without a default: refused elsewhere, by name
                        # (ASHConfigUnsetVariableError), never a None key.
                        resolved = key
                    if resolved is None and os.environ.get(name) is not None:
                        names.add(name)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(written)
    return tuple(sorted(names))


def _format_chain(paths: Tuple[Path, ...], state: Optional[_ChainState] = None) -> str:
    if state is None:
        return " -> ".join(describe_config_path(p) for p in paths)
    return " -> ".join(state.shown(p) for p in paths)


def _what_was_got(value: Any) -> str:
    """How a refusal names ``value``, an ``extends`` that is not a path or a
    list of paths: a number, a boolean or null as it is, text as written in
    quotes, anything else by its kind. Never a repr: the sink that prints the
    message shows each control character as its escape, and a repr's own escape
    was shown with a doubled backslash."""
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)
    if isinstance(value, str):
        return f"'{value}'"
    return f"a {type(value).__name__}"


def _extends_refs(
    value: Any,
    path: Path,
    shown_file: Optional[str] = None,
    from_environment: bool = False,
) -> List[str]:
    """The base paths ``value``, the ``extends`` of the file at ``path``, names.

    The refusal of a value that is not a path or a list of paths names the file
    as ``shown_file`` (``describe_config_path`` when None), and does not quote
    the value when part of it came from the environment (``from_environment``).
    """
    if value is None:
        return []
    refs = [value] if isinstance(value, str) else value
    if not isinstance(refs, list) or not all(
        isinstance(r, str) and r.strip() for r in refs
    ):
        got = ENVIRONMENT_VALUE_SHOWN if from_environment else _what_was_got(value)
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}' in "
            f"{describe_config_path(path) if shown_file is None else shown_file} "
            f"must be a path or a list of paths, got {got}"
        )
    return [r.strip() for r in refs]


def _base_not_permitted(ref: str, extending: str) -> ASHConfigInputNotPermittedError:
    # Names the ref as written, never what it resolves to; see "Base paths".
    # ``extending`` is the extending file as the message names it.
    return ASHConfigInputNotPermittedError(
        f"'{EXTENDS_KEY}: {ref}' in {extending} names a "
        "file outside the directories this caller may read config from."
    )


def _base_named(ref: str, extending: Path) -> Path:
    """The path an ``extends`` ref names, before any link in it is followed.

    Relative to the directory of *extending*, the file that holds the ref, as
    that file resolves.
    """
    candidate = Path(ref)
    if candidate.is_absolute():
        return candidate
    return extending.parent / candidate


def _base_permitted(permit_base: PermitBase, path: Path) -> bool:
    """``permit_base(path)``, for ``path`` the path an open base leads to.

    A gate that takes ``resolved`` is given the path as the one to judge, so it
    does not resolve the name a second time: resolved later, a directory of the
    path can lead elsewhere, and the verdict would be about another file than the
    one that is open. A gate with the one-argument shape is called as before.
    """
    try:
        takes_resolved = "resolved" in inspect.signature(permit_base).parameters
    except (TypeError, ValueError):
        takes_resolved = False
    if takes_resolved:
        return permit_base(path, resolved=path)  # type: ignore[call-arg]
    return permit_base(path)


def _resolve_base_path(
    ref: str,
    extending: Path,
    root: Path,
    permit_base: Optional[PermitBase] = None,
    shown: Optional[Tuple[str, str]] = None,
    held: Optional[List[OpenedConfig]] = None,
) -> Tuple[Path, FileIdentity]:
    """The base `ref` names, resolved and checked, and the identity checked.

    The base is opened before it is judged. The gate and the root check are asked
    about the path the descriptor leads to, and the identity is the descriptor's;
    the read of the base must open that same file
    (``read_config_bytes(expect=)``). The descriptor is appended to ``held`` and
    stays open until the caller closes it, which keeps the inode in use; without
    ``held`` it is closed on return. A base that cannot be opened as a regular
    file (absent, a directory) is judged by its resolved path, as it always was,
    and the identity is the file that path led to when the checks ran. A path
    that led nowhere then gives ``ABSENT_FILE``, never None, so a file that
    appears there before the read is refused and not read unchecked.

    ``shown`` is how a message names `ref` and `extending` when a value read
    from the environment chose either (``_ChainState.environment_paths``). A
    path built from them is then named ``<value>`` too.
    """
    ref_text, extending_text = (
        shown if shown is not None else (ref, describe_config_path(extending))
    )

    def built(path: Path) -> str:
        return ENVIRONMENT_VALUE_SHOWN if shown is not None else path.as_posix()

    if _URL_PATTERN.match(ref):
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref_text}' in {extending_text} looks like "
            "a URL. ASH does not fetch remote configs; copy the file into the "
            "repository and extend it by path."
        )
    if "\x00" in ref:
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}' in {extending_text} contains a NUL character"
        )
    candidate = _base_named(ref, extending)
    relative = not Path(ref).is_absolute()
    lexical = Path(os.path.normpath(candidate))
    # Refused before resolve() touches the filesystem when the spelling alone
    # leaves the root. For a relative ref that is a `..` escape. On Windows it
    # also covers an absolute ref, because resolving a UNC path opens a
    # connection to the host it names. A POSIX absolute ref is resolved first,
    # since it may name a location inside the root through a symlinked prefix.
    if not lexical.is_relative_to(root) and (relative or os.name == "nt"):
        if permit_base is not None:
            # Under a caller's gate every refused base is reported one way, so
            # the refusal does not depend on which check caught it -- or on the
            # platform, since on Windows this check runs before resolve() for
            # an absolute ref too.
            raise _base_not_permitted(ref_text, extending_text)
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref_text}' in {extending_text} names "
            f"{built(lexical)}, which is outside the directory config bases "
            f"must stay inside ({root.as_posix()})."
        )
    resolved = None
    try:
        resolved = candidate.resolve()
    except RuntimeError:
        # Before Python 3.13, resolve() raises RuntimeError on a symbolic link
        # loop, and that error's text names the looped path, which can be one
        # read from the environment. Refused with a fresh filename-less ELOOP
        # cause (never the RuntimeError, whose text a chain walker could
        # print; raised below, outside the handler, so it is on neither
        # __cause__ nor __context__), so the MCP category mapping answers
        # invalid_path on every interpreter and the message names the base
        # only as ref_text, the shown form the other refusals here use.
        pass
    if resolved is None:
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref_text}' in {extending_text} is a symbolic link loop"
        ) from OSError(errno.ELOOP, os.strerror(errno.ELOOP))
    opened = open_config_for_judgment(resolved)

    def changed() -> ASHConfigSourceError:
        return ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref_text}' in {extending_text} names "
            f"{built(resolved)}, which changed after it was checked, so it is "
            "not read"
        )

    try:
        if opened is None:
            judged, checked = resolved, identity_to_hold(resolved)
        else:
            if opened.real is None:
                raise changed() from ConfigFileChangedError(
                    errno.ESTALE, "changed after it was checked, so it is not read"
                )
            judged, checked = opened.real, opened.identity
        # Ahead of the root check, whose message names the resolved target: this
        # refusal must read the same whether or not that target exists.
        if permit_base is not None and not _base_permitted(permit_base, judged):
            raise _base_not_permitted(ref_text, extending_text)
        if not judged.is_relative_to(root):
            # `extending` is already resolved, so a lexically normalized candidate
            # that is inside the root got out only by following a symlink.
            how = " through a symlink" if lexical.is_relative_to(root) else ""
            raise ASHConfigSourceError(
                f"'{EXTENDS_KEY}: {ref_text}' in {extending_text} resolves"
                f"{how} to {built(judged)}, which is outside the directory "
                f"config bases must stay inside ({root.as_posix()})."
            )
        if opened is not None and file_identity(judged) != checked:
            # The path the descriptor led to no longer leads to the open file.
            raise changed() from ConfigFileChangedError(
                errno.ESTALE, "changed after it was checked, so it is not read"
            )
    except BaseException:
        if opened is not None:
            opened.close()
        raise
    if opened is not None:
        if held is not None:
            held.append(opened)
        else:
            opened.close()
    return judged, checked


@dataclass(frozen=True)
class _Setting:
    """One field of a config model, as the model reads it from a document."""

    #: The spelling a merged value is written under: the alias, else the name.
    written: str
    #: Every spelling the model reads, lowest precedence first.
    spellings: Tuple[str, ...]
    #: The model the value is validated as, when it is one.
    model: Optional[type[BaseModel]]
    #: Where a document holds several spellings, whether the model takes the
    #: last one whole (pydantic's alias over name) rather than merging them key
    #: by key (``_PluginConfigSegment``'s validator).
    whole: bool


def _value_model(annotation: Any) -> Optional[type[BaseModel]]:
    """The pydantic model a field's mapping is validated as, or None.

    Only through ``Optional`` and other unions: a list is replaced whole, and the
    keys of a ``Dict`` field are names, not settings.
    """
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        models = {_value_model(arg) for arg in typing.get_args(annotation)}
        models.discard(None)
        return models.pop() if len(models) == 1 else None
    return None


@functools.lru_cache(maxsize=None)
def _settings_of(model: type[BaseModel]) -> Dict[str, _Setting]:
    """Each field of ``model``, keyed by every spelling the model reads it under."""
    segment = issubclass(model, _PluginConfigSegment)
    by_name = segment or bool(
        model.model_config.get("populate_by_name")
        or model.model_config.get("validate_by_name")
    )
    settings: Dict[str, _Setting] = {}
    for name, info in model.model_fields.items():
        alias = info.alias if info.alias and info.alias != name else None
        if alias is None:
            spellings: Tuple[str, ...] = (name,)
        elif by_name:
            spellings = (name, alias)
        else:
            spellings = (alias,)
        setting = _Setting(
            written=alias or name,
            spellings=spellings,
            model=_value_model(info.annotation),
            whole=not segment,
        )
        for spelling in spellings:
            settings[spelling] = setting
    return settings


def _fold(values: List[Any], setting: _Setting) -> Any:
    """One document's spellings of ``setting``, read as the model reads them."""
    if setting.whole:
        return values[-1]
    folded = values[0]
    for value in values[1:]:
        folded = deep_merge(folded, value, setting.model)
    return folded


def deep_merge(base: Any, overlay: Any, model: Optional[type[BaseModel]] = None) -> Any:
    """Merge `overlay` over `base` under the rules in the module docstring.

    ``model`` is the config model both mappings are read as (``AshConfig`` for
    a whole config document). With it, a setting is merged under the spellings
    the model reads (see "Spellings"); without it, keys that differ only in
    ``-`` versus ``_`` are one key.
    """
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return copy.deepcopy(overlay)
    if None in overlay:
        # A null key is what a key written as a reference to a set but empty
        # variable resolves to (_empty_key_reference_names): it spells no key,
        # and no later step reads it. It is refused here, as this merge has
        # always refused it, so the chain's catch-all words the refusal and
        # names the variable, and no scan runs on a file whose key the host
        # and a container would read differently. Not an
        # ASHConfigSourceError, which the catch-all passes through unworded.
        raise ValueError("a mapping key is null")
    merged = copy.deepcopy(base)
    rest = dict(overlay)
    settings = _settings_of(model) if model is not None else {}
    # The spellings of the fields the overlay sets under a spelling the model
    # reads: settled here, so no other key of the overlay reaches them below.
    settled: set[str] = set()
    for setting in dict.fromkeys(settings.values()):
        upper = [rest.pop(key) for key in setting.spellings if key in rest]
        if not upper:
            continue
        settled.update(setting.spellings)
        lower = [merged.pop(key) for key in setting.spellings if key in merged]
        value = _fold(upper, setting)
        merged[setting.written] = (
            deep_merge(_fold(lower, setting), value, setting.model)
            if lower
            else copy.deepcopy(value)
        )
    if model is not None and issubclass(model, _PluginConfigSegment):
        # A plugin's section: every spelling get_plugin_config reads for the
        # same plugin is one section, under the overlay's spelling. A key that
        # is not a string (a YAML number, boolean or null) names no plugin, so
        # it joins nothing here and is merged below by itself.
        for key in list(rest):
            if not isinstance(key, str):
                continue
            names = plugin_key_lookup_names(key)
            same = [
                other
                for other in merged
                if isinstance(other, str)
                and other not in settings
                and plugin_key_lookup_names(other) & names
            ]
            if not same:
                continue
            lower_value: Any = merged.pop(same[0])
            for other in same[1:]:
                lower_value = deep_merge(lower_value, merged.pop(other))
            merged[key] = deep_merge(lower_value, rest.pop(key))
    # The rest: a key the model does not read as a field. Keys that differ
    # only in '-' versus '_' are one key here, as they always were, so an
    # overlay's unread spelling of a field still reaches the base's spelling of
    # it -- but not a field the overlay set above under a spelling the model
    # reads, which wins. Those the overlay spells exactly as the base does (or
    # that are new) are applied last, so where the overlay carries both
    # spellings of one key, its exact spelling wins.
    base_keys = dict.fromkeys(
        key for key in base if key in merged and key not in settled
    )
    items = sorted(
        rest.items(),
        key=lambda kv: _resolve_dict_key(base_keys, kv[0]) == kv[0],
    )
    for key, value in items:
        target = _resolve_dict_key(base_keys, key)
        if target in merged:
            field = settings.get(target)
            merged[target] = deep_merge(
                merged[target], value, field.model if field else None
            )
        else:
            merged[target] = copy.deepcopy(value)
    return merged


def _unescape(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def _escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _normalize_pointer(
    document: Any, pointer: str, owned: Optional[Dict[str, Set[str]]] = None
) -> str:
    """Respell a JSON pointer's keys the way `document` spells them.

    A segment directly under a TOP-LEVEL plugin segment key also folds onto
    the key the document already holds with the same fold identity
    (``section_fold_key``: the folded section name paired with the reduced
    plugin name), the identity the owned view's settle step reads, so the
    two patch walks reach one canonical path and a spelling whose type word
    a separator splits -- which folds by name alone but names no plugin the
    lookup reads -- stays as typed on both. Only when EXACTLY ONE existing
    key matches: a merged document can hold two case-variant keys of an
    undeclared section (deep_merge joins only "-"/"_" twins), and picking
    one by insertion order would land the op on a key the plugin does not
    read while the override resolver refuses the same spelling as ambiguous
    -- so an ambiguous segment stays as typed. A deeper key that happens to
    be named ``reporters`` is a value's own mapping, not the plugin segment,
    and never folds. A key that matches no existing fold stays as typed,
    like the view's settle anchoring a new spelling.

    ``owned``, when given, is the ownership the operator view already holds
    (``_resolve``): by plugin segment key, the section keys the patching
    file's own chain wrote, as written -- the operator's files for an
    operator file's patch. The segment then matches only document keys
    those files wrote (_spelled_by_an_owned_write), the exact and "-"/"_"
    match as well as the fold: a key only a repository file wrote neither
    blocks the exactly-one match nor captures the operator's spelling,
    under any spelling of its own -- the operator view never holds the
    repository's keys, and matching them here made the two walks disagree.
    When the matched spelling is not the operator's, the fold runs over the
    owned keys, so the patch lands where the view walk's settle lands it.
    The restriction holds only while the owned keys hold a spelling of the
    POINTER's section (the fold identity): a pointer at a section the
    operator's files never spelled has no owned key a twin could capture
    it from, and resolves as it does without ownership.
    """
    from automated_security_helper.config.ash_config import section_fold_key

    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return pointer
    current = document
    parent: "str | None" = None
    segments = []
    for position, raw in enumerate(pointer[1:].split("/")):
        segment = _unescape(raw)
        if isinstance(current, dict):
            resolved = _resolve_dict_key(current, segment)
            if position == 1 and parent in PLUGIN_SEGMENT_KEYS:
                held = None if owned is None else owned.get(parent) or set()
                fold = section_fold_key(segment)
                if held is not None and not any(
                    section_fold_key(key) == fold for key in held
                ):
                    # The patching file's own chain wrote no spelling of this
                    # section, so there is no owned key a repository twin
                    # could capture the pointer from: the segment resolves as
                    # it does without ownership. Restricting here made the
                    # load refuse a variant pointer at a section only the
                    # repository's files wrote, while the exact spelling
                    # landed on the same key.
                    held = None
                if resolved in current and (
                    held is None or _spelled_by_an_owned_write(resolved, held, current)
                ):
                    segment = resolved
                else:
                    # No exact or "-"/"_" match the patching file's own chain
                    # wrote: fold onto the one key it did write with this
                    # identity. Without ownership, over every key, as before.
                    matches = [
                        existing
                        for existing in current
                        if isinstance(existing, str)
                        and section_fold_key(existing) == fold
                        and (
                            held is None
                            or _spelled_by_an_owned_write(existing, held, current)
                        )
                    ]
                    if len(matches) == 1:
                        segment = matches[0]
            else:
                segment = resolved
            parent = segment
            current = current.get(segment)
        elif isinstance(current, list) and segment.isascii() and segment.isdigit():
            index = int(segment)
            parent = None
            current = current[index] if index < len(current) else None
        else:
            parent = None
            current = None
        segments.append(_escape(segment))
    return "/" + "/".join(segments)


def _owned_plugin_keys(data: Any, owned: Dict[str, Set[str]]) -> None:
    """Add *data*'s own top-level plugin-section keys to *owned*, as written.

    The ownership compare (_spelled_by_an_owned_write) applies deep_merge's
    own join rule to these spellings, so the set holds what the files wrote,
    never a normalized form.
    """
    if not isinstance(data, dict):
        return
    for segment_key in PLUGIN_SEGMENT_KEYS:
        sections = data.get(segment_key)
        if isinstance(sections, dict):
            owned.setdefault(segment_key, set()).update(
                key for key in sections if isinstance(key, str)
            )


def _spelled_by_an_owned_write(
    key: str, held: Set[str], present: Collection[str]
) -> bool:
    """Whether the document key *key* carries a write from the owned set.

    By deep_merge's own join rule (_resolve_dict_key): the key is an owned
    spelling itself, or an owned spelling joined it under a uniform "-"/"_"
    swap when the chain merged. Deliberately not separator-blind: a
    mixed-separator spelling is one deep_merge keeps apart, so an owned
    write never sits under it, and reading it as owned made the operator's
    own key ambiguous beside such a repository twin.

    ``present`` is the container's own keys. A swap counts only while the
    owned spelling is not itself one of them, and only when it is the key
    deep_merge would join that spelling onto (_resolve_dict_key over the
    present keys, the join's own lookup): deep_merge joins an incoming key
    onto ONE existing key, trying the dash-to-underscore swap first, so
    when the document holds both uniform swaps of an absent owned
    spelling, the owned write sits under that one key and the other swap
    is another file's. Reading any swap of an absent owned spelling as
    owned landed an operator's patch on a repository section the operator
    never spelled, and split a third spelling over two keys that cannot
    both be the operator's.
    """
    if key in held:
        return True
    taken = dict.fromkeys(present)
    return any(
        owned_key not in taken and key == _resolve_dict_key(taken, owned_key)
        for owned_key in held
    )


def _owned_patched_key(
    owned: Dict[str, Set[str]], how: Tuple[str, str], value: Any = None
) -> None:
    """Record the section key an owned file's own operation wrote, as written.

    ``how`` is the op and path the document took (_patch_step with ownership),
    and ``value`` is the operation's value. An op whose path is exactly a
    plugin segment's key wrote that section, so a later operation of the same
    file can fold onto it, as the view walk's settle anchors a patched-in
    spelling. An op at the plugin segment itself wrote every section its
    value holds, so those keys anchor the same way: recording only the
    two-segment shape left a later variant pointer with no owned key to
    fold onto, and the load refused spellings that were all this file's
    own. A rewrite of the whole document wrote every section its value's
    plugin segments hold, recorded the same way for the same reason. A
    remove changes no ownership (the match intersects this set with
    the document's keys, so a removed key cannot match anyway), and a test
    asserts without writing, so recording it would let a later patch land
    on a key only the repository wrote.
    """
    name, path = how
    if name in ("remove", "test"):
        return
    if path == "":
        # A rewrite of the whole document wrote every section its value's
        # plugin segments hold, so those keys anchor later ops exactly as a
        # whole-segment write's do.
        if isinstance(value, dict):
            for segment in PLUGIN_SEGMENT_KEYS:
                sections = value.get(segment)
                if isinstance(sections, dict):
                    owned.setdefault(segment, set()).update(
                        key for key in sections if isinstance(key, str)
                    )
        return
    if not path.startswith("/"):
        return
    segments = path[1:].split("/")
    if len(segments) == 2 and segments[0] in PLUGIN_SEGMENT_KEYS:
        owned.setdefault(segments[0], set()).add(_unescape(segments[1]))
    elif (
        len(segments) == 1
        and segments[0] in PLUGIN_SEGMENT_KEYS
        and isinstance(value, dict)
    ):
        owned.setdefault(segments[0], set()).update(
            key for key in value if isinstance(key, str)
        )


#: How the document took a patch operation that does not fit it as written
#: (_patch_step): not at all (None), or as this op at this path.
_Rewritten = Optional[Tuple[str, str]]


@dataclass
class _Patched:
    """``_apply_patch``'s result."""

    #: The document with the operations applied.
    document: Any
    #: The unconfined view with them applied; None when it was not followed.
    unconfined: Any
    #: By entry index, how the document took each operation it did not take
    #: as written (_patch_step), so the values it moves are followed the same
    #: way. With ownership on (an operator file's patch), every operation the
    #: document takes except a ``test`` is recorded, as its op and the
    #: pointer the ownership fold resolved, and an op the document dropped to
    #: the unconfined view records None: a replay then lands each one where
    #: this walk landed it instead of re-normalizing against keys the
    #: operator never wrote.
    rewritten: Dict[int, _Rewritten]


_AS_WRITTEN = object()


def _patch_step(
    document: Any,
    unconfined: Any,
    op: Dict[str, Any],
    owned: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[Any, Any, Any]:
    """One ``patch`` operation applied to ``document`` and to ``unconfined``.

    ``unconfined`` is the same document as the chain's files wrote it, before
    the chain's confine hook left anything out of the bases (an operator-only
    option a repository's file set). An operation at such a place does not fit
    ``document``: the file still loads, as it would have without the trust
    rules, and the document takes what the operation means for it. A remove
    of the place leaves nothing to remove; a replace sets the value, as an add
    at the place does; an operation below the place (inside the value left
    out) leaves the place out still. A test is of ``unconfined``, so whether
    the file loads never depends on what was left out. Whatever an operation
    sets is then the extending file's own: its confine hook sees it.

    Returns the two documents and how the document took the operation:
    ``_AS_WRITTEN``, or a ``_Rewritten``. With ``unconfined`` None, the
    operation applies to ``document`` alone, as written. jsonpatch's errors
    are raised for the caller to word: an operation that fits neither view.

    ``owned`` is the ownership the pointer fold resolves against
    (_normalize_pointer). With it, an operation the document takes is
    reported as a ``_Rewritten`` at the path chosen here, never as
    ``_AS_WRITTEN``: the reference replay (_placed_through_patch) then
    reapplies the op at that path instead of re-normalizing without the
    ownership this step had. A ``test`` operation's pointer takes the same
    ownership respell as a write's: the two ops of one guard, a test and
    the write under the same pointer, then aim at one key, the operator's
    own. Resolving the test as typed aimed them at different keys beside a
    repository twin, so the twin's value decided whether the operator's
    guarded write applied. A test still reports ``_AS_WRITTEN``: it writes
    nothing, so the reference replay, which skips tests, has nothing to
    reapply for it.
    """
    normalized = dict(op, path=_normalize_pointer(document, op["path"], owned))
    taken = (
        _AS_WRITTEN
        if owned is None or op["op"] == "test"
        else (op["op"], normalized["path"])
    )
    if unconfined is None:
        return (
            jsonpatch.apply_patch(document, [normalized], in_place=False),
            None,
            taken,
        )
    whole = dict(op, path=_normalize_pointer(unconfined, op["path"], owned))
    if op["op"] == "test":
        jsonpatch.apply_patch(unconfined, [whole], in_place=False)
        return document, unconfined, _AS_WRITTEN
    try:
        patched = jsonpatch.apply_patch(document, [normalized], in_place=False)
    except (
        jsonpatch.JsonPatchConflict,
        jsonpatch.JsonPointerException,
        # jsonpatch's bare shape for an op indexing into a value the document
        # holds as a scalar (a remove's `del text[0]`): the same misfit as a
        # conflict, so a remove falls to the unconfined view exactly as an
        # add does, instead of refusing the whole load.
        TypeError,
    ) as exc:
        unfit = exc
    else:
        try:
            unconfined = jsonpatch.apply_patch(unconfined, [whole], in_place=False)
        except (
            jsonpatch.JsonPatchException,
            jsonpatch.JsonPointerException,
            TypeError,
        ):
            # The document took it, so the unconfined view, which differs
            # only by what was left out, should have: no longer followed.
            unconfined = None
        return patched, unconfined, taken
    try:
        unconfined = jsonpatch.apply_patch(unconfined, [whole], in_place=False)
    except (jsonpatch.JsonPatchException, jsonpatch.JsonPointerException, TypeError):
        # It fits neither: the file's own error, as the document gave it.
        raise unfit from None
    if whole["op"] == "replace":
        try:
            parent, _part = jsonpatch.JsonPointer(whole["path"]).to_last(document)
        except jsonpatch.JsonPointerException:
            parent = None
        if isinstance(parent, dict):
            added = dict(whole, op="add")
            return (
                jsonpatch.apply_patch(document, [added], in_place=False),
                unconfined,
                ("add", whole["path"]),
            )
    return document, unconfined, None


def _tested_path_shown(
    document: Any,
    path: Any,
    shown_path: Any,
    owned: Optional[Dict[str, Set[str]]],
    hidden: Collection[str],
) -> str:
    """How a failed ``test`` op's refusal names the pointer it checked.

    With ownership on, the pointer's plugin-section segment folds onto the
    key the file's own writes landed on (_normalize_pointer), so the value
    checked can sit at a spelling the operator did not type: naming the
    typed path pointed a reader at a key holding exactly the value the
    message says was not found. The refusal names the respelled path when
    every respelled segment is the typed one, its uniform "-"/"_" swap, or
    a key the file's own chain wrote, and none of it holds a string the
    chain read from the environment (``hidden``). Where the fold respelled
    the path but a segment may not be shown, the typed, already-shown path
    stands with a clause saying where the check landed, so no document key
    a message may not quote is shown. A pointer that was itself read from
    the environment -- the whole scalar is a reference, the only pointer
    shape that reads one -- arrives already shown as its hidden form, and
    stands with the clause too, since the raw path's segments may hold the
    read value. Where the fold leaves the typed form unchanged -- a
    reference inside a longer pointer is literal text, never a read -- the
    typed form stands alone, with no clause, since the check landed exactly
    where the pointer says.
    """
    typed_shown = f"'{shown_path}'"
    if owned is None or not isinstance(path, str) or not path.startswith("/"):
        return typed_shown
    respelled = _normalize_pointer(document, path, owned)
    if respelled == path or not isinstance(respelled, str):
        return typed_shown
    typed = path[1:].split("/")
    folded = respelled[1:].split("/")
    landed = f"{typed_shown}, checked at the key this file's own writes landed on,"
    if shown_path != path:
        # The typed path read something from the environment, so the raw
        # path's segments may hold the read values: only the already-shown
        # form is printed, whatever the fold did to the rest.
        return landed
    if len(typed) != len(folded):
        return landed
    for position, (was, now) in enumerate(zip(typed, folded)):
        if was == now:
            continue
        own_spelling = position == 1 and now in (
            owned.get(_unescape(typed[0])) or set()
        )
        swap = now in (was.replace("-", "_"), was.replace("_", "-"))
        if not (swap or own_spelling):
            return landed
        if any(value and value in now for value in hidden):
            return landed
    return f"'{respelled}'"


def _refuse_a_clients_test_op(ops: Any, where: str) -> None:
    """Refuse a ``test`` operation in the ``patch`` of a file an MCP client chose.

    A test op compares a place of the configuration with the value it gives,
    and the file loads only when the two are equal. A client's file that
    extends the operator's config could so learn, from whether it loaded,
    whether a value it may not read was the one it guessed: a wrong guess was
    refused as a failed test and a right one loaded. Every test op of such a
    file is refused before any operation applies, in one text whatever the
    configuration holds at its path, so no outcome depends on that value.
    ``where`` is how the message names the file.
    """
    if not isinstance(ops, list):
        return
    for index, op in enumerate(ops):
        if isinstance(op, dict) and op.get("op") == "test":
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} is a test op, which a "
                "config file chosen by this caller may not use: it compares "
                "values of the configuration the file is given, which the "
                "caller may not read. Remove the test op."
            )


def _apply_patch(
    document: Dict[str, Any],
    ops: Any,
    path: Path,
    where: Optional[str] = None,
    shown_ops: Any = None,
    unconfined: Any = None,
    owned: Optional[Dict[str, Set[str]]] = None,
    hidden: Collection[str] = (),
) -> _Patched:
    """``document`` with the JSON-Patch ``ops`` of the file at ``path`` applied.

    ``where`` is how a message names that file (``describe_config_path`` when
    None). ``shown_ops`` is ``ops`` with each value the file read from the
    environment shown as ``<value>`` (environment_record), for the one part of
    an operation a message quotes, its path; None quotes ``ops``.
    ``unconfined``, when given, is ``document`` without the chain's confine
    hook (_patch_step): an operation at a place the hook left out of a base
    is then taken as _patch_step says, not refused. ``owned`` is the
    ownership each operation's pointer fold resolves against
    (_normalize_pointer); a section key an operation itself writes joins it
    (_owned_patched_key), so a later operation of the same file folds onto
    that key as the view walk's settle does.
    """
    where = describe_config_path(path) if where is None else where
    if not isinstance(ops, list):
        raise ASHConfigSourceError(
            f"'{PATCH_KEY}' in {where} must be a list of JSON-Patch operations, "
            f"got {type(ops).__name__}"
        )
    if not (isinstance(shown_ops, list) and len(shown_ops) == len(ops)):
        shown_ops = ops
    result: Any = document
    rewritten: Dict[int, _Rewritten] = {}
    # The messages below name an entry's position, its op and its path, never a
    # value the entry or the document holds: either can be one a file read from
    # the environment, and jsonpatch's own messages quote the document.
    for index, op in enumerate(ops):
        if not isinstance(op, dict) or not isinstance(op.get("path"), str):
            # The keys are named as shown_ops shows them: a key the file read
            # from the environment is the value it read, and is <value> there.
            shown_keys = shown_ops[index] if isinstance(shown_ops[index], dict) else op
            got = (
                f"a mapping with keys {', '.join(sorted(map(str, shown_keys)))}"
                if isinstance(op, dict)
                else f"a {type(op).__name__}"
            )
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} must be a mapping with "
                f"'op' and 'path', got {got}"
            )
        op_name = op.get("op")
        if not isinstance(op_name, str) or op_name not in _PATCH_OPS:
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} uses an op that is not "
                f"one of the allowed ops, {', '.join(sorted(_PATCH_OPS))}"
            )
        shown_op = shown_ops[index] if isinstance(shown_ops[index], dict) else op
        shown_path = shown_op.get("path", op["path"])
        try:
            result, unconfined, how = _patch_step(result, unconfined, op, owned)
        except jsonpatch.JsonPatchTestFailed:
            # jsonpatch's own message quotes the value it found, which may come
            # from a base the author of this file did not write. The path is
            # the one the check landed on (_tested_path_shown): the ownership
            # fold can respell it onto the key this file's own writes land on.
            tested = _tested_path_shown(
                result if unconfined is None else unconfined,
                op["path"],
                shown_path,
                owned,
                hidden,
            )
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where}: the value at "
                f"{tested} does not equal the value the test op gives"
            ) from None
        except (
            jsonpatch.JsonPatchException,
            jsonpatch.JsonPointerException,
            TypeError,
        ) as exc:
            # jsonpatch's message quotes the document it patches. The path is
            # quoted as written, not as a repr: the sink shows its controls.
            # A TypeError is jsonpatch indexing into a value that is not a
            # container (a remove at an index of a string): the same misfit,
            # named as the entry's rather than by an implementation detail.
            kind = "" if isinstance(exc, TypeError) else f"{type(exc).__name__}, "
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} ({op_name} at "
                f"'{shown_path}') failed: {kind}the path does not "
                "fit the document it patches"
            ) from None
        if how is not _AS_WRITTEN:
            rewritten[index] = how
            if owned is not None and how is not None:
                _owned_patched_key(owned, how, op.get("value"))
    return _Patched(result, unconfined, rewritten)


#: Set to True on the TypeError _file_references raises for a file of the
#: chain a caller's reader read without holding its text. Its message is a
#: constant, so it holds no value read from the environment and no path:
#: resolve_config_document keeps the refusal it causes as it is, rather than
#: replacing it with the environment-blind reason. A TypeError the reader
#: raises itself carries no mark, and its text, the reader's own, still takes
#: the blind path. A mark on a plain TypeError, not a private subclass: every
#: printer (a repr, traceback_text, a formatted traceback) names the builtin,
#: where a subclass needed each one to translate its name.
_UNHELD_TEXT_MARK = "_ash_unheld_text"


def _file_references(
    path: Path,
    data: Any,
    reader: Callable[[Path], Any],
    text: Optional[str] = None,
    parsed_as: Optional[Path] = None,
) -> List[EnvironmentReference]:
    """What the file at ``path``, which ``reader`` read as ``data``, read from the
    environment, each at the place the file wrote it (environment_record).

    The as-written view is parsed from ``text``, the text the resolution read
    (``_ChainState.texts``), so both views are of one read, in the format of
    ``parsed_as`` (``path`` by default): the name whose suffix the resolution
    parsed the text under. The root is parsed as the path the caller named,
    so for a root that is a link to a file with another suffix the as-written
    view parsed in the target's format read nothing while the data held the
    values, and none of its reads was recorded. The file is never
    read from disk again, including for a text that does not parse (nothing is
    recorded then): a file swapped after the read would pair the swapped text
    against data the swap never produced, missing a reference the read made
    (its value then prints where its ``${VAR}`` belongs) or claiming one it
    did not. Every reader holds its text (``_read_into_state`` for the stock
    reader, the caller's ``texts`` for its own), so a missing text is a read
    the caller's reader made without filling its cache: recording nothing
    there would leave the file's environment reads resolved into the data
    with no reference recorded anywhere, so it is a TypeError instead.
    Nothing for the literal reader, which reads nothing from the environment.
    """
    if reader is read_config_file_literally:
        return []
    if text is None:
        # Fail closed, with a constant text: naming the file could name a
        # path the chain read from the environment.
        unheld = TypeError(
            "config_sources._file_references: a file of the chain was read "
            "with no held text, so what it read from the environment cannot "
            "be recorded; a caller's own reader (and a run load's `reads` "
            "cache) must fill the `texts` mapping for every file it reads"
        )
        setattr(unheld, _UNHELD_TEXT_MARK, True)
        raise unheld
    try:
        written = parse_config_text_literally(
            parsed_as if parsed_as is not None else path, text, keep_env_tags=True
        )
        # Folded as ``data`` was folded, so the two views pair up at a
        # respelled known-plugin section (plugin_section_names).
        written = fold_known_plugin_sections(written)
    except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
        return []
    return [
        reference.read_in(path) for reference in environment_references(written, data)
    ]


#: The most places one file's document may expand to when every aliased
#: place is written out on its own (refuse_past_expansion_bound). Mappings,
#: sequences and scalars all count: a stack of anchored mappings demands a
#: number of places exponential in its depth from a file a few hundred
#: bytes long, and an anchored scalar aliased from many places is written
#: once per place just the same. The bound caps what a hostile file can
#: cost; a configuration a scan can use sits orders of magnitude below it.
_UNALIASED_CONTAINER_BOUND = 100_000

#: The most characters of string content the same expansion may write. A
#: short file whose anchors alias long scalars expands to little structure
#: but much text, which the place bound alone would admit; each string's
#: length is charged against this budget beside the place charge
#: (refuse_past_expansion_bound), so the bound tracks the text written too.
_UNALIASED_BYTE_BOUND = 10_000_000


def _unaliased(value: Any, path: Path) -> Any:
    """``value`` with every mapping and sequence given its own container.

    A YAML anchor makes two places in a loaded document ONE object, and both
    ``copy.deepcopy`` and jsonpatch's ``in_place=False`` application keep that
    sharing in their copies, so a patch landing through one place would land
    in every place the alias shares -- and where a strict section model
    refuses the added key, the whole load was refused while the alias-free
    spelling of the same document loaded. Rebuilding the containers gives
    each place its own mapping, exactly as the alias-free spelling reads.
    Scalars stay as read: the loader gives immutable ones, and keeping them
    keeps the environment-reference values the chain's bookkeeping compares.

    The expansion budgets are charged before the rebuild
    (``refuse_past_expansion_bound``, the one owner of the budget
    arithmetic), so a document whose anchors multiply is refused at the
    bound's cost, not its own product's, and the rebuild keeps no count of
    its own.

    A document nested past the interpreter's recursion limit can parse (a
    parser that runs out of recursion on one is refused in ``parse_config_text``,
    but not every parser does on every interpreter) and then run the rebuild
    out of recursion. That is this file's document being too deep to read, so
    it is refused here as an unparsed config (``unparsed_config_reason``), the
    way ``parse_config_text`` words the parser's own RecursionError.
    """
    refuse_past_expansion_bound(value, describe_config_path(path))

    def rebuilt(item: Any) -> Any:
        if not isinstance(item, (dict, list)):
            return item
        if isinstance(item, dict):
            return {key: rebuilt(entry) for key, entry in item.items()}
        return [rebuilt(entry) for entry in item]

    unparsed: Optional[str] = None
    try:
        return rebuilt(value)
    except RecursionError as exc:
        unparsed = unparsed_config_reason(path, exc)
    # Outside the handler (unparsed_config_reason).
    raise ASHConfigUnparsedError(unparsed)


def _expansion_refusal(subject: str, lead_in: str = "") -> ASHConfigSourceError:
    """The refusal both budgets raise. ``subject`` opens the sentence, so a
    caller whose frame also names the file can start the message with the
    file's name and the frame then leaves its own copy out
    (mcp_tools._config_load_failure); ``lead_in`` carries a surface's
    error-prefix convention in front of it."""
    return ASHConfigSourceError(
        f"{lead_in}{subject} expands to more than "
        f"{_UNALIASED_CONTAINER_BOUND} places or {_UNALIASED_BYTE_BOUND} "
        "characters through YAML anchors"
    )


def refuse_past_expansion_bound(value: Any, subject: str, lead_in: str = "") -> None:
    """Refuse ``value`` as a source error when its expansion passes a budget.

    Writing a document out costs one place per node written -- mappings,
    sequences and scalars alike -- plus each string's characters, so both
    are charged: every place against ``_UNALIASED_CONTAINER_BOUND`` and
    every string's length against ``_UNALIASED_BYTE_BOUND``. The budget is
    spent child by child as a container's children are yielded, so the
    refusal can land partway through one container and the walk itself
    costs at most the bound, whatever the document expands to.

    This is the one owner of the budget arithmetic: the chain's rebuild
    (``_unaliased``), raw ``get_config``'s transport and ``select_profile``'s
    ``override_yaml`` all charge through it. ``subject`` and ``lead_in``
    name the document in the refusal (``_expansion_refusal``).
    """
    place_budget = _UNALIASED_CONTAINER_BOUND
    byte_budget = _UNALIASED_BYTE_BOUND

    def charged(item: Any) -> None:
        nonlocal place_budget, byte_budget
        place_budget -= 1
        if isinstance(item, str):
            byte_budget -= len(item)
        if place_budget < 0 or byte_budget < 0:
            raise _expansion_refusal(subject, lead_in)

    charged(value)
    pending = [value] if isinstance(value, (dict, list)) else []
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            # A mapping's keys are written out too, once per place the
            # mapping is aliased from: charged like its values, so an aliased
            # long key repeated across many aliased mappings cannot pass the
            # text budget on its values alone.
            for key in item:
                charged(key)
        children = item.values() if isinstance(item, dict) else item
        for child in children:
            charged(child)
            if isinstance(child, (dict, list)):
                pending.append(child)


def _a_callers_read(
    reader: Callable[..., Any], path: Path, expect: Optional[FileIdentity]
) -> Any:
    """``reader(path)``, with the identity the chain walk vetted when the
    reader takes it.

    A caller's reader that accepts ``expect`` (``read_once`` in
    ``resolve_config``, the reader every scan's load uses, and the config
    validator's) is handed the vetted ``FileIdentity``, so its read refuses a
    file swapped in between the walk's check and the open, as the stock
    reader's does. A reader with the plain one-argument shape (a test's) is
    called as before.
    """
    try:
        parameters = inspect.signature(reader).parameters.values()
    except (TypeError, ValueError):
        return reader(path)
    if any(
        parameter.name == "expect" or parameter.kind is parameter.VAR_KEYWORD
        for parameter in parameters
    ):
        return reader(path, expect=expect)
    return reader(path)


def _read_into_state(
    path: Path,
    state: "_ChainState",
    key: Path,
    note_failure: bool = False,
    expect: Optional[FileIdentity] = None,
    env_refused: bool = False,
) -> Any:
    """``state.reader(path)``, through ``_a_callers_read``, which hands a
    reader that takes ``expect`` the identity the walk vetted. With the stock
    reader the text is read once and
    kept (``state.texts``), so the as-written reference view is parsed from
    the same read (_file_references) instead of reading the disk again; a
    caller's own reader keeps its text itself and hands the mapping in
    (resolve_config_document's ``texts``).

    ``key`` is the path the resolution resolved ``path`` to, the key the text
    is looked up by. The stock reader holds its text under it rather than
    resolving again at read time: a symbolic link retargeted in between would
    put the text under one path and the lookup under another, and the read
    would be refused as a reader that did not hold its text.

    Both branches un-alias the document (_unaliased): every file enters the
    chain here, so this is the one place that gives each of its mappings its
    own container before any merge or patch touches it. It is also where a
    boolean ``sandbox.mode`` is read as the mode it stands for
    (``sandbox_mode_in_document``): an unquoted ``off`` loads as "off" and an
    unquoted ``on`` is refused with the quoting hint. The mapping is scoped to
    the files read here, so the mode's own type still refuses a boolean that
    arrives by a patch value or an override. A caller's reader keeps the
    document it returned; the mapping is made on the un-aliased copy.

    ``note_failure`` is set for the root read only: a failure of that read is
    marked with the file (_note_the_file_being_read). A base's read is not
    marked: the chain walk words a base's failure itself, so the mark had no
    reader for a base, and a base the environment chose must not carry its path
    on an exception.

    ``env_refused`` is the walk's decision that the chain's rule keeps this file
    from reading the environment. The read then refuses it, in
    ``parse_config_text`` (``_ENV_REFUSED_READ_OF``), when its text reads from
    the environment, before a ``${VAR}`` reference is resolved: a reader that
    parsed the file first would answer "not set" for a variable the server has
    not set and the refusal for one it has. A caller's own reader parses the
    text through ``parse_config_text`` too (``read_once`` in ``resolve_config``,
    the config validator's), so it is covered; one that parses some other way is
    still refused by ``_resolve`` after its read."""
    refused_read = _ENV_REFUSED_READ_OF.set(state.shown(key) if env_refused else None)
    try:
        try:
            if state.reader is not read_config_file:
                return _with_a_spelled_sandbox_mode(
                    _unaliased(_a_callers_read(state.reader, path, expect), path),
                    state.shown(key),
                )
            text = read_config_text(path, expect=expect)
            state.texts[key] = text
            return _with_a_spelled_sandbox_mode(
                _unaliased(parse_config_text(path, text), path), state.shown(key)
            )
        except Exception as exc:
            if note_failure:
                _note_the_file_being_read(exc, path)
            raise
    finally:
        _ENV_REFUSED_READ_OF.reset(refused_read)


#: The attribute a failure of a chain file's read carries, naming that file.
_FILE_BEING_READ = "ash_config_file_being_read"


def _note_the_file_being_read(error: BaseException, path: Path) -> None:
    """Record on *error* the config file whose read raised it, unless it
    already names one. A RecursionError from a deeply nested file carries no
    name. Only the root read is noted: a file the stock reader reads is refused
    by parse_config_text, which words its RecursionError by the file it parsed,
    and a base's failures are worded at the base read."""
    if getattr(error, _FILE_BEING_READ, None) is not None:
        return
    try:
        setattr(error, _FILE_BEING_READ, Path(path))
    except AttributeError:  # an exception type that takes no attributes
        pass


def config_file_being_read(error: BaseException) -> Optional[Path]:
    """The config file whose read raised *error* in a chain walk
    (:func:`resolve_config_document`), or None when the error did not come from
    reading one: the walk noted it where the root read failed
    (``_read_into_state``). A base's failure carries no note."""
    path = getattr(error, _FILE_BEING_READ, None)
    return path if isinstance(path, Path) else None


def _with_a_spelled_sandbox_mode(document: Any, shown: str) -> Any:
    """``sandbox_mode_in_document`` for the file named *shown*, its refusal
    raised as a source error that names the file and never a value."""
    try:
        return sandbox_mode_in_document(document)
    except ValueError as exc:
        raise ASHConfigSourceError(f"{shown}: sandbox.mode: {exc}") from None


def _shown_fold_key(key: str, path: Path, data: Any, text: Optional[str]) -> str:
    """``key``, a section key the fold refuses, as the refusal may print it:
    the written reference (``${VAR}``) when the file read the key from the
    environment, the key itself otherwise, and ``<value>`` when no as-written
    view of the same read exists to tell.

    The as-written view is parsed from ``text``, the text the resolution read
    (``_ChainState.texts``), the same way ``_file_references`` builds its view,
    so both views are of one read. With no held text the key is shown as
    ``<value>``, never read from disk again: a file swapped after the read
    would print the swapped text's value, and a removed file would decide the
    display from a read the load never made. Unlike ``_file_references`` the
    view stays unfolded: the fold of ``data`` is what raised, so folding here
    would raise the same refusal.
    """
    if text is None:
        return ENVIRONMENT_VALUE_SHOWN
    try:
        written = parse_config_text_literally(path, text, keep_env_tags=True)
    except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
        return ENVIRONMENT_VALUE_SHOWN
    for reference in environment_references(written, data):
        if reference.key and reference.resolved == key:
            return written_without_tag(reference.written)
    return key


#: A reference in a ``patch`` operation's value: the operation's index, the
#: path inside the value, and the reference.
_OpReference = Tuple[int, Tuple[Any, ...], EnvironmentReference]


def _still_describes(document: Any, reference: EnvironmentReference) -> bool:
    """Whether the merged ``document`` still holds ``reference`` at its place.

    A later source of an ``extends`` chain can write a literal over a place an
    earlier one read from the environment; the earlier reference then
    describes its own file, not the merged document, and a view writing it
    back as "this place's value came from the environment" would be wrong
    there. A reference whose place is gone, or whose place no longer holds
    its value, is left out of the displayed view
    (``ResolvedConfigDocument.displayed_environment_references``); it stays an
    environment read (``environment_references``), so redaction still masks
    its value. A value that still contains the environment's part is kept,
    erring toward keeping.
    """
    node = document
    for segment in reference.path:
        if not isinstance(node, (dict, list)):
            # The place is gone: a later file wrote a scalar where the
            # reference's mapping or list was. Indexing a string with the
            # reference's list index would read one character of it, and a
            # character equal to the value read would keep the reference.
            return False
        try:
            node = typing.cast(Any, node)[segment]
        except (TypeError, KeyError, IndexError):
            # The merge folds a section spelled with "-" into one spelled
            # with "_" and the other way around, so the reference's spelling
            # can differ from the merged document's.
            twins = (
                (segment.replace("-", "_"), segment.replace("_", "-"))
                if isinstance(segment, str) and isinstance(node, dict)
                else ()
            )
            for twin in twins:
                if twin != segment and twin in node:
                    node = node[twin]
                    break
            else:
                return False
    if reference.key:
        return isinstance(node, dict) and reference.resolved in node
    text = node if isinstance(node, str) else str(node)
    return text == reference.resolved or (
        bool(reference.value) and reference.value in text
    )


def _split_references(
    references: List[EnvironmentReference], data: Any
) -> Tuple[List[EnvironmentReference], List[_OpReference]]:
    """``references``, one file's: those at their places in the file's own
    settings, and those in the value of a ``patch`` operation that sets one
    (``add`` or ``replace``), which _placed_through_patch places.

    One under ``extends`` names a base, which is not part of the merged
    configuration, and is left out. So is any other one under ``patch``: an
    operation's path, or a ``test`` operation's value, sets no value.
    """
    own: List[EnvironmentReference] = []
    from_ops: List[_OpReference] = []
    ops = data.get(PATCH_KEY) if isinstance(data, dict) else None
    for reference in references:
        head = reference.path[:1]
        if head == (EXTENDS_KEY,):
            continue
        if head != (PATCH_KEY,):
            own.append(reference)
            continue
        index = reference.path[1] if len(reference.path) > 2 else None
        if (
            isinstance(ops, list)
            and isinstance(index, int)
            and 0 <= index < len(ops)
            and reference.path[2] == "value"
            and isinstance(ops[index], dict)
            and ops[index].get("op") in ("add", "replace")
        ):
            from_ops.append((index, tuple(reference.path[3:]), reference))
    return own, from_ops


def _node_at(root: Any, path: Tuple[Any, ...]) -> Any:
    """The node at ``path`` in ``root``, a mapping key matched as the merge
    matches it (_resolve_dict_key), or None."""
    node = root
    for segment in path:
        if isinstance(node, dict):
            key = _resolve_dict_key(node, segment) if isinstance(segment, str) else None
            if key not in node:
                return None
            node = node[key]
        elif isinstance(node, list) and isinstance(segment, int):
            if not 0 <= segment < len(node):
                return None
            node = node[segment]
        else:
            return None
    return node


def _plant(
    root: Any,
    path: Tuple[Any, ...],
    reference: EnvironmentReference,
    planted: Set[str],
) -> Optional[str]:
    """Put a token at ``reference``'s place under ``root`` (path ``path``) and
    return it, or None when that place does not hold what the reference read.

    A value's token replaces the value; a second reference at a place that
    already holds one (``planted``) shares it. A key's is a key added to the
    key's mapping, so an operation that writes the mapping over drops it with
    the key.
    """
    token = f"ash-reference-{secrets.token_hex(16)}"
    if reference.key:
        holder = _node_at(root, path)
        if not isinstance(holder, dict) or reference.resolved not in holder:
            return None
        holder[token] = None
        planted.add(token)
        return token
    if not path:
        return None
    container = _node_at(root, path[:-1])
    last = path[-1]
    if isinstance(container, dict) and isinstance(last, str):
        last = _resolve_dict_key(container, last)
        if last not in container:
            return None
    elif not (
        isinstance(container, list)
        and isinstance(last, int)
        and 0 <= last < len(container)
    ):
        return None
    held = container[last]
    if isinstance(held, str) and held in planted:
        return held
    if held != reference.resolved:
        return None
    container[last] = token
    planted.add(token)
    return token


def _placed_through_patch(
    document: Any,
    ops: List[Any],
    tracked: List[EnvironmentReference],
    from_ops: List[_OpReference],
    where: str,
    rewritten: Optional[Dict[int, _Rewritten]] = None,
) -> List[EnvironmentReference]:
    """The references of a file and of its bases, each at the place its value
    has once the file's ``patch`` (``ops``, which applied to ``document``) has.
    ``rewritten`` is how ``document`` took the operations that did not fit it
    as written (``_Patched.rewritten``); the copy takes each of those the same
    way.

    ``tracked`` are at their places in ``document``, the file merged over its
    bases; ``from_ops`` are in the operations' values. Each value is followed,
    not computed: a copy of ``document`` holds a token in place of each, the
    operations' values hold theirs, and the same operations apply to the copy
    (a test operation changes nothing). Where a token is then is where its value
    is: an insert in front of it or a remove before it moves it, and an append
    puts it at the end, whatever its index; one an operation writes over is
    gone, and so is its reference. Placing an operation's reference at the
    operation's path instead put an append at index 0, so the value the append
    added was shown where the entry at 0 should have been marked.

    A reference whose place does not hold what it read (a value the extending
    file wrote over) is kept as it was.
    """
    shadow = copy.deepcopy(document)
    shadow_ops = copy.deepcopy(ops)
    tokens: Set[str] = set()
    planted: List[Tuple[EnvironmentReference, Optional[str]]] = []
    for reference in tracked:
        token = _plant(shadow, tuple(reference.path), reference, tokens)
        planted.append((reference, token))
    for index, inside, reference in from_ops:
        token = _plant(shadow_ops[index], ("value", *inside), reference, tokens)
        if token is not None:
            planted.append((reference, token))
    if not tokens:
        return list(tracked)
    result: Any = shadow
    rewritten = rewritten or {}
    try:
        for index, op in enumerate(shadow_ops):
            if op.get("op") == "test":
                continue
            if index in rewritten:
                how = rewritten[index]
                if how is None:
                    continue
                normalized = dict(op, op=how[0], path=how[1])
            else:
                normalized = dict(op, path=_normalize_pointer(result, op["path"]))
            result = jsonpatch.apply_patch(result, [normalized], in_place=False)
    except (
        jsonpatch.JsonPatchException,
        jsonpatch.JsonPointerException,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ):
        # The copy differs from the configuration only at the tokens, so the
        # operations apply to it as they did to the configuration. Should one
        # not, the values cannot be located, and the file is refused rather
        # than shown with one where its reference does not say.
        raise ASHConfigSourceError(
            f"'{PATCH_KEY}' in {where}: the values the file reads from the "
            "environment could not be followed through its operations"
        ) from None
    found: Dict[str, List[Tuple[Any, ...]]] = {}

    def walk(node: Any, path: Tuple[Any, ...]) -> None:
        if isinstance(node, str):
            if node in tokens:
                found.setdefault(node, []).append(path)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key in tokens:
                    found.setdefault(key, []).append(path)
                else:
                    walk(value, (*path, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, (*path, index))

    walk(result, ())
    placed: List[EnvironmentReference] = []
    for reference, token in planted:
        if token is None:
            placed.append(reference)
        else:
            placed.extend(
                reference.moved_to_unknown_list(path) for path in found.get(token, ())
            )
    return placed


def _placed_references(
    references: List[EnvironmentReference], data: Any
) -> List[EnvironmentReference]:
    """``references``, one file's, each at the path it holds once the file merges.

    One under ``extends`` names a base, which is not part of the merged
    configuration, and is left out. One in a ``patch`` operation's ``value`` is
    moved to the operation's ``path``. A digit in the pointer is that list index;
    ``-`` (append) is an index the file cannot name, which the record reads as an
    unknown index (``UNKNOWN_INDEX``). A list inside the operation's value keeps
    the length it had there. Any other reference under ``patch`` sets no value,
    and is left out too.
    """
    placed: List[EnvironmentReference] = []
    for reference in references:
        head = reference.path[:1]
        if head == (EXTENDS_KEY,):
            continue
        if head != (PATCH_KEY,):
            placed.append(reference)
            continue
        ops = data.get(PATCH_KEY) if isinstance(data, dict) else None
        index = reference.path[1] if len(reference.path) > 2 else None
        if (
            not isinstance(ops, list)
            or not isinstance(index, int)
            or not 0 <= index < len(ops)
            or reference.path[2] != "value"
            or not isinstance(ops[index], dict)
            or not isinstance(ops[index].get("path"), str)
        ):
            continue
        pointer = ops[index]["path"]
        segments: List[Any] = [
            UNKNOWN_INDEX
            if segment == "-"
            else int(segment)
            if segment.isdigit()
            else _unescape(segment)
            for segment in pointer.split("/")[1:]
        ]
        placed.append(reference.rebase(3, tuple(segments)))
    return placed


def _measured_in(
    references: List["EnvironmentReference"], data: Any
) -> List["EnvironmentReference"]:
    """Each reference whose path ends at a digit index of a list the post-patch
    document holds, with that list's length recorded, so the index is used; a
    path the document does not hold stays as it is."""
    measured: List[Any] = []
    for reference in references:
        place = None
        if reference.length is None:
            for position, segment in enumerate(reference.path):
                if isinstance(segment, int):
                    place = position
        if place is None:
            measured.append(reference)
            continue
        container: Any = data
        for segment in reference.path[:place]:
            if isinstance(container, dict) and segment in container:
                container = container[segment]
            else:
                container = None
                break
        # ``place`` was found with isinstance(segment, int) above, so the
        # segment is an int; the isinstance here is the narrowing mypy needs
        # to admit the comparison, not a new condition.
        index = reference.path[place]
        if (
            isinstance(index, int)
            and isinstance(container, list)
            and 0 <= index < len(container)
        ):
            measured.append(replace(reference, length=len(container), index_at=place))
        else:
            measured.append(reference)
    return measured


def _resolve(
    path: Path,
    stack: Tuple[Path, ...],
    state: _ChainState,
    ref: Optional[str] = None,
    env_refused_above: bool = False,
    named: Optional[Path] = None,
    above: Tuple[Path, ...] = (),
    expect: Optional[FileIdentity] = None,
    operator_context: bool = True,
) -> Tuple[Any, Any, Optional[Dict[str, Set[str]]]]:
    """The document ``path`` resolves to, the same document as its files
    wrote it, without the chain's confine hook (what a patch operation of an
    extending file is followed through, _patch_step), and the plugin-section
    keys the operator's own files among them wrote (the ownership an owned
    file's patch pointers resolve against, _normalize_pointer; None when the
    chain tracks none). ``named`` is the name that reached it, for a base
    (``_base_named``); the root config's is ``path`` itself.

    Ownership follows the rule the operator view reads the chain by
    (resolve_config's _with_operator_chain_reporters): a file is the
    operator's own when ``state.repository_file`` says it is not the
    repository's AND it was not reached through a repository file
    (``operator_context``: False for every base below one). A repository
    file's own patch resolves against its whole subtree, which that rule
    makes the repository's throughout, so it is passed no ownership and
    keeps the unrestricted fold."""
    real = None
    try:
        real = path.resolve()
    except RuntimeError:
        # Before Python 3.13, resolve() raises RuntimeError on a symbolic link
        # loop, and that error's text names the path, which can be one read
        # from the environment. Refused as the path problem it is, with a
        # fresh filename-less ELOOP cause (never the RuntimeError, whose text
        # a chain walker could print; raised below, outside the handler, so
        # it is on neither __cause__ nor __context__), so the MCP category
        # mapping answers invalid_path on every interpreter. The path is
        # named as shown: a loop cannot be resolved, so both its spellings
        # are checked against the environment-chosen set.
        pass
    if real is None:
        hidden = (
            Path(path) in state.environment_paths
            or Path(os.path.realpath(path)) in state.environment_paths
        )
        raise ASHConfigSourceError(
            f"Config "
            f"{ENVIRONMENT_VALUE_SHOWN if hidden else describe_config_path(path)}"
            f": the path is a symbolic link loop"
        ) from OSError(errno.ELOOP, os.strerror(errno.ELOOP))
    if named is None:
        named = path
    if real in stack:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' cycle: {_format_chain(stack + (real,), state)}"
        )
    if len(stack) > ASH_CONFIG_EXTENDS_MAX_DEPTH:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' chain is deeper than "
            f"{ASH_CONFIG_EXTENDS_MAX_DEPTH} levels: "
            f"{_format_chain(stack + (real,), state)}"
        )
    state.files_read += 1
    if state.files_read > ASH_CONFIG_EXTENDS_MAX_FILES:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' chain reads more than "
            f"{ASH_CONFIG_EXTENDS_MAX_FILES} files; stopped at "
            f"{_format_chain(stack + (real,), state)}"
        )

    if not stack:
        # The root config: parse errors behave exactly as they always have. Any
        # reader, the caller's own included, is spared a path it would wait on.
        # Read and judged as named rather than as `real`, so a refusal names the
        # path the caller gave and not the target of a symlink.
        refuse_unless_a_file(path)
        env_refused = state.refuse_env(path)
        # Whether the rule refuses this file for itself, not only as a base of
        # a file it refuses: the file's own patch is then the client's.
        refused_for_itself = env_refused
        data = _read_into_state(
            path,
            state,
            key=real,
            note_failure=True,
            expect=expect,
            env_refused=env_refused,
        )
    else:
        extending = stack[-1]
        # A base whose path came from the environment is named `<value>`, and
        # so is everything its own path was built from.
        hidden = real in state.environment_paths
        # is_regular_file, not Path.is_file: before Python 3.14 is_file raised
        # PermissionError for a base under a directory that cannot be searched,
        # and the base then failed as an unforeseen error of the file that
        # extends it instead of with the refusal below.
        if not is_regular_file(real):
            # The cause says which path problem it is (missing, a directory, a
            # link loop), so the MCP category mapping answers it as a path
            # problem, never with format advice (config_load_category reads
            # the chain). Rebuilt without the OSError's filename: the message
            # names the file once, as shown, and a hidden path stays hidden
            # whatever a printer does with the chain.
            try:
                mode = os.stat(real).st_mode
            except OSError as os_exc:
                cause = OSError(os_exc.errno, os_exc.strerror or "")
            else:
                cause = (
                    IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR))
                    if stat.S_ISDIR(mode)
                    else OSError(errno.EINVAL, "Not a regular file")
                )
            raise ASHConfigSourceError(
                f"'{EXTENDS_KEY}: {ref}' in {state.shown(extending)} names "
                f"{state.shown(real) if hidden else real.as_posix()}, which does "
                "not exist or is not a file"
            ) from cause
        # Judged by the name the entry spells as well as the file it reaches, as
        # the root is: a base reached through a client's link is the client's.
        refused_for_itself = state.refuse_env(named) or state.refuse_env(real)
        env_refused = env_refused_above or refused_for_itself
        unquoted: Optional[str] = None
        # Whether the read was refused because the file is no longer the one that
        # was checked. A reworded error below drops its cause, so the fact rides
        # on a mark (_FILE_CHANGED_MARK) instead.
        changed = False
        try:
            data = _read_into_state(
                real, state, key=real, expect=expect, env_refused=env_refused
            )
        except ASHConfigUnsetVariableError:
            # Named by resolve_config_document, which names no base's path
            # (_environment_blind_error).
            raise
        except ASHConfigSourceError as exc:
            # The chain's own refusal names the base as the walk shows it.
            if not hidden or getattr(exc, _REFUSED_BY_THE_WALK_MARK, False):
                raise
            changed = config_file_changed(exc)
            # Its text names the file: given without it.
            unquoted = (
                f"Base config {state.shown(real)}, extended by "
                f"{state.shown(extending)}, could not be read ({type(exc).__name__})"
            )
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
            changed = config_file_changed(exc)
            # json.JSONDecodeError is a ValueError.
            if not hidden and is_config_parse_error(exc):
                # The parser's own words can quote the base's text
                # (unparsed_config_reason).
                unquoted = (
                    f"Base config {describe_config_path(real)}, extended by "
                    f"{describe_config_path(extending)}, could not be parsed "
                    f"{parse_error_kind(exc)}"
                )
            elif not hidden:
                # An OSError's own text names the file the message already
                # names, so it is given without that copy.
                why = (
                    os_error_without_named_file(exc, real)
                    if isinstance(exc, OSError)
                    else str(exc)
                )
                raise ASHConfigSourceError(
                    f"Base config {describe_config_path(real)}, extended by "
                    f"{describe_config_path(extending)}, could not be read: {why}"
                ) from exc
            else:
                # The error's own text can name the file: it is given without.
                why = (
                    exc.strerror
                    if isinstance(exc, OSError) and exc.strerror
                    else type(exc).__name__
                )
                unquoted = (
                    f"Base config {state.shown(real)}, extended by "
                    f"{state.shown(extending)}, could not be read ({why})"
                )
        if unquoted is not None:
            # Raised outside the handler, so the error's text is not its context.
            reworded = ASHConfigSourceError(unquoted)
            if changed:
                # The cause is dropped on purpose, so the fact that the file
                # changed rides on the error itself (config_file_changed).
                setattr(reworded, _FILE_CHANGED_MARK, True)
            raise reworded
        if not isinstance(data, dict):
            raise ASHConfigSourceError(
                f"Base config {state.shown(real)}, extended by "
                f"{state.shown(extending)}, must be a mapping, got "
                f"{type(data).__name__}"
            )

    # A file the chain's rule keeps from reading the environment (state.refuse_env,
    # judged by the name that reached it and the file it resolves to, and inherited
    # by every base below a refused file) is refused when its held text reads one
    # (text_reads_the_environment): the parse layer refuses only the files an MCP
    # client delivered, and this rule can be stricter (env_refused_for a remote
    # caller). Decided on the text of the same read, so a file changed in between
    # cannot get past it; the message quotes no value. The read itself refuses
    # such a file before it resolves a reference (_read_into_state); this stays
    # for a caller's reader that does not parse through parse_config_text.
    # The name whose suffix the text was parsed under: the root is read as the
    # caller named it (above), a base as the path it resolved to. The checks
    # of the held text below read it in that same format, so a root that is a
    # link to a file with another suffix is judged as it was parsed and not as
    # its target would be.
    parsed_as = path if not stack else real
    if env_refused:
        held_text = state.texts.get(real)
        if held_text is not None and text_reads_the_environment(parsed_as, held_text):
            raise _environment_read_refusal(state.shown(real))

    # Each known plugin's section keyed by its declared spelling, before this
    # file's references are recorded and before the merge below: the record,
    # the display and `extends` all see one spelling
    # (plugin_section_names). The linter reads the file unfolded itself.
    try:
        data = fold_known_plugin_sections(data)
    except AmbiguousPluginSpellings as exc:
        # A colliding key can itself be read from the environment; the refusal
        # names such a key by its written form, never by the value it gave.
        # The as-written view comes from the held text of this same read.
        held_text = state.texts.get(real)
        shown_first = _shown_fold_key(exc.first, real, data, held_text)
        shown_second = _shown_fold_key(exc.second, real, data, held_text)
        raise ASHConfigSourceError(
            f"Config {state.shown(real)}: {exc.segment_key}.{shown_first} and "
            f"{exc.segment_key}.{shown_second} are two spellings of the "
            f"{exc.target} section: ambiguous, keep one"
        ) from None
    except ValueError as exc:
        raise ASHConfigSourceError(f"Config {state.shown(real)}: {exc}") from None

    state.documents.setdefault(real, copy.deepcopy(data))
    # In read order, so a file's own come before those of the bases it extends,
    # which are read below. The order decides only which of two references at
    # one position that resolved to the same text is recorded: the extending
    # file's, whose value the merge keeps.
    read = _file_references(
        real, data, state.reader, state.texts.get(real), parsed_as=parsed_as
    )
    state.read.extend(read)
    own_references, from_ops = _split_references(read, data)
    # This file's references and, after the loop below, its bases': the ones
    # its patch can move.
    first = len(state.references)
    state.references.extend(own_references)

    state.reached(real, named)
    # The file that names a base chose it, so a base is judged by the paths of
    # the files above it too, as env_refused_above carries a refusal down.
    state.chosen_by(real, above)
    anchor = state.anchor_relative_paths is not None and (
        state.anchor_relative_paths(real) and state.anchor_relative_paths(named)
    )
    if anchor:
        # Each operator file's own relative paths are taken from its directory,
        # before the merge loses which file set them (config/operator_paths.py).
        # ``documents`` keeps what the file holds, for the checks of who set what.
        from automated_security_helper.config.operator_paths import (
            anchor_relative_paths,
        )

        data = anchor_relative_paths(data, real.parent)

    repository_file = state.repository_file
    operator_file = (
        repository_file is not None
        and operator_context
        and not repository_file(real, named)
    )
    owned: Optional[Dict[str, Set[str]]] = {} if repository_file is not None else None

    if not isinstance(data, dict) or (
        EXTENDS_KEY not in data and PATCH_KEY not in data
    ):
        state.order.append(real)
        state.named.append(named)
        if owned is not None and operator_file:
            _owned_plugin_keys(data, owned)
        return state.confined(real, named, data), data, owned

    # The `extends` entries this file read from the environment, as resolved.
    read_bases = {
        reference.resolved.strip()
        for reference in read
        if not reference.key and reference.path[:1] == (EXTENDS_KEY,)
    }
    try:
        own = dict(data)
        refs = _extends_refs(
            own.pop(EXTENDS_KEY, None),
            real,
            shown_file=state.shown(real),
            from_environment=bool(read_bases),
        )
        ops = own.pop(PATCH_KEY, None)
        # The operations as the file wrote them, whose values the references
        # read from the environment were taken from: anchoring below rewrites
        # an operator path in a value, and a token planted for a reference
        # matches the value as read, so the anchored copy would drop the
        # reference of every value it rewrote (_placed_through_patch).
        written_ops = ops
        if anchor:
            from automated_security_helper.config.operator_paths import (
                anchor_patch_operations,
            )

            ops = anchor_patch_operations(ops, real.parent)
        merged: Any = {}
        # Followed only where a confine hook can leave something out.
        unconfined: Any = None if state.confine is None else {}
        for base_ref in refs:
            # A base the environment chose, by this entry or by the path of the
            # file that names it, is named `<value>` in every message about it.
            entry_read = base_ref in read_bases
            chosen_by_environment = entry_read or real in state.environment_paths
            shown_ref = ENVIRONMENT_VALUE_SHOWN if entry_read else base_ref
            base_path, checked = _resolve_base_path(
                base_ref,
                real,
                state.root,
                state.permit_base,
                shown=(shown_ref, state.shown(real)) if chosen_by_environment else None,
                held=state.held,
            )
            if chosen_by_environment:
                state.environment_paths.add(base_path)
            # The base as its entry spells it, before any symlink is followed:
            # relative to the resolved file that extends it, as base_path is.
            base_named = _base_named(base_ref, real)
            base_document, base_unconfined, base_owned = _resolve(
                base_path,
                stack + (real,),
                state,
                shown_ref,
                env_refused,
                base_named,
                (real, named, *above),
                expect=checked,
                operator_context=operator_file,
            )
            if not isinstance(base_document, dict):
                # A base's own patch can replace its whole document (the root
                # pointer). Merged, a non-mapping replaced everything the bases
                # before it set, and this file's own keys then replaced it in
                # turn, so the base and each earlier one were dropped silently.
                raise ASHConfigSourceError(
                    f"Base config {state.shown(base_path)}, extended by "
                    f"{state.shown(real)}, must be a mapping once its own "
                    f"'{PATCH_KEY}' is applied, got {type(base_document).__name__}"
                )
            merged = deep_merge(merged, base_document, AshConfig)
            if unconfined is not None:
                unconfined = deep_merge(unconfined, base_unconfined, AshConfig)
            if owned is not None and base_owned:
                for segment_key, keys in base_owned.items():
                    owned.setdefault(segment_key, set()).update(keys)
        merged = deep_merge(merged, own, AshConfig)
        if unconfined is not None:
            unconfined = deep_merge(unconfined, own, AshConfig)
        if owned is not None and operator_file:
            _owned_plugin_keys(own, owned)
        if ops is not None:
            if refused_for_itself:
                # A file the chain's rule refuses for itself is one an MCP
                # client chose (see "Environment variables"), so its patch is
                # the client's. A base it extends is refused with it for the
                # environment, but that base's own patch is not the client's.
                _refuse_a_clients_test_op(ops, state.shown(real))
            shown_data = with_environment_values_shown(data, read)
            patched = _apply_patch(
                merged,
                ops,
                real,
                where=state.shown(real),
                shown_ops=(
                    shown_data.get(PATCH_KEY) if isinstance(shown_data, dict) else None
                ),
                unconfined=unconfined,
                # A repository file's patch keeps the unrestricted fold over
                # its own subtree; only an operator file's pointers resolve
                # against the operator-written keys.
                owned=owned if operator_file else None,
                # A failed test op's refusal never names a key holding a
                # string the chain read from the environment. The values the
                # operations' own values read ride beside the chain's: they
                # are placed into the references only after the patch
                # applies, and a key one of them wrote can be the very key a
                # later operation's pointer folds onto.
                hidden=_values_of(
                    state.references + [reference for _, _, reference in from_ops]
                ),
            )
            # Each reference at the place its value has once the patch has
            # applied, which only the patch says. Followed through the
            # operations as written: anchoring changes values only, so they
            # move each value where the anchored ones moved it.
            state.references[first:] = _placed_through_patch(
                merged,
                written_ops,
                state.references[first:],
                from_ops,
                where=state.shown(real),
                rewritten=patched.rewritten,
            )
            merged = patched.document
            unconfined = patched.unconfined
    except ASHConfigSourceError:
        raise
    except Exception as exc:  # noqa: BLE001 -- see below
        # Anything unforeseen while following `extends` or applying `patch`
        # (an OSError from resolve(), a malformed value no check above caught)
        # must not reach resolve_config's catch-all, which returns the default
        # config. The file was not loaded as written, so it is an error.
        blind = _quotes_the_document(
            f"Could not resolve '{EXTENDS_KEY}'/'{PATCH_KEY}' in "
            f"{state.shown(real)}: {type(exc).__name__}: {exc}"
        )
        # This frame still holds the file's text and the environment the read
        # just resolved against, so the variables whose written keys resolved
        # to no key are threaded here, by name, for the env-blind rewrite
        # (_environment_blind_error), which cannot see this shape itself.
        empty_key_names = _empty_key_reference_names(state.texts.get(real), real)
        if empty_key_names:
            setattr(blind, _EMPTY_KEY_REFERENCE_NAMES_MARK, empty_key_names)
        raise blind from exc
    state.order.append(real)
    state.named.append(named)
    return (
        state.confined(real, named, merged),
        merged if unconfined is None else unconfined,
        owned,
    )


def resolve_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
    reader: Optional[Callable[[Path], Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    expect: Optional[FileIdentity] = None,
) -> ResolvedConfigDocument:
    """Read `config_path` and every base it extends into one merged document.

    `expect` is ``identity_to_hold(config_path)`` as its caller took it when it
    checked the path: the root is then read only if it is still that file, and
    one swapped in after the check is refused (``ConfigFileChangedError``), one
    that was not there at the check included (``ABSENT_FILE``). Without it the
    identity is taken when the root is read.

    `confine`, when given, is called once for each file of the chain with the
    file's resolved path, the name that reached it, and the document the file
    resolved to (its own data merged over its bases', its `patch` applied); the
    document it returns is merged in that file's place. resolve_config passes
    one that leaves out of a file inside the scanned tree, or inside any other
    checkout, what only the operator may set (config/operator_only_options.py),
    before anything is validated. It must not change the document it is given.

    `repository_file`, when given, answers for each chain file (resolved path,
    the name that reached it) whether it is the repository's -- a caller that
    passes a RepositorySettings confine passes its ``is_repository_file``
    beside it. An operator file's patch pointers then fold only onto section
    keys the operator's own files wrote (_normalize_pointer), the ownership
    the operator reporter view reads the chain by, so a case-variant twin a
    repository file wrote can neither make the operator's patch ambiguous
    nor capture it. Without it every pointer resolves against the whole
    merged document.

    `permit_base` is checked for every base, in addition to `confine_to`; see
    "Base paths" in the module docstring. A base is opened first and the gate is
    asked about the path the descriptor leads to (a gate that takes a `resolved`
    argument is given that path to judge as it is), and the read is held to the
    descriptor's identity. It is not checked for `config_path`
    itself, which the caller chose and is responsible for having checked.
    `refuse_env` decides which files of the chain resolve no ``!ENV``; None
    refuses the files an MCP client delivered. See "Environment variables".
    `anchor_relative_paths` judges each file of the chain by its resolved path
    and by the path it was reached by; for a file it accepts under both, the
    relative paths the file sets for the options in ``config/operator_paths.py``
    are taken from its directory. ``resolve_config`` passes one that accepts the
    operator's files. ``documents`` holds each file as written either way.

    `reader` reads each file of the chain. A config check passes a reader that
    returns what it already read, so no file is parsed (and no `!ENV` warning
    logged) twice. The data it returns is not modified. ``texts`` is such a
    reader's cache of each file's text, by resolved path (the reader fills it
    as it reads): the as-written reference view is parsed from it
    (_file_references), so no file is read from disk twice. With the stock
    reader the resolution keeps its own text the same way (_read_into_state).
    A caller's own reader without ``texts`` is a TypeError: such a reader
    returns parsed data, not text, so the resolution would have no as-written
    view to record environment references from, and every surface that redacts
    what the chain read (``environment_values``) would silently hold nothing.
    The literal reader needs no cache, as it reads nothing from the
    environment.

    A chain that does not resolve raises an ASHConfigSourceError whose message
    holds no value read from the environment. Every caller prints it: the scan,
    the config checks, `get_default_config` for ASH_CONFIG, the MCP session
    profiles. A base an `extends` entry names through the environment, and every
    base below it, is named `<value>` in it (``ResolvedConfigDocument.shown_path``),
    and so is the entry. An error whose text quotes what a file holds (a `patch`
    operation) and an unset variable in a base are given without the
    environment instead (_environment_blind_error), when the chain read anything
    from it. With ``read_config_file_literally`` as the reader, nothing is read
    from the environment and the error is raised as it is.
    """
    # The None sentinel exists so the check below measures CALLER INTENT,
    # not a rebinding of the module global: a test idiom patches
    # read_config_file to record which files a resolution reads, and a
    # default call under that patch is still a default call. None resolves
    # to the call-time global, so such a recording wrapper is picked up
    # and records, which is its purpose.
    caller_supplied = reader is not None
    if reader is None:
        reader = read_config_file
    if (
        caller_supplied
        and reader is not read_config_file
        and reader is not read_config_file_literally
        and texts is None
    ):
        # Fail closed: with no text cache the resolution records no
        # environment reference the chain read (_file_references has no
        # as-written view), so the values would be resolved into the data and
        # never redacted anywhere.
        raise TypeError(
            "resolve_config_document: a caller's own reader needs the `texts` "
            "mapping it fills with each file's text; without it no "
            "environment reference the chain reads is recorded"
        )
    config_path = Path(config_path)
    root = (
        Path(confine_to).resolve()
        if confine_to is not None
        else default_confinement_root(config_path)
    )
    state = _ChainState(
        root=root,
        permit_base=permit_base,
        refuse_env=refuse_env or config_is_client_delivered,
        anchor_relative_paths=anchor_relative_paths,
        reader=reader,
        texts=texts if texts is not None else {},
        confine=confine,
        repository_file=repository_file,
    )
    data: Any = None
    blind_for: Optional[ASHConfigSourceError] = None
    try:
        # The root is read as the file its caller checked (`expect`), or as the
        # file the name leads to now when the caller handed no identity; one
        # swapped in before the open is refused.
        data, _unconfined, _owned = _resolve(
            config_path,
            (),
            state,
            expect=expect if expect is not None else identity_to_hold(config_path),
        )
    except ASHConfigSourceError as error:
        if reader is read_config_file_literally:
            raise
        if getattr(error.__cause__, _UNHELD_TEXT_MARK, False) is True:
            # A base the caller's reader read without holding its text: the
            # cause is the reader, and the refusal names the file whose
            # `extends` failed, by its shown form (an env-chosen one as
            # <value>), and the constant reason, so it is kept. The blind
            # reason would point at the file system instead.
            raise
        read_any = bool(state.read or state.environment_paths)
        if isinstance(error, ASHConfigUnsetVariableError) or (
            getattr(error, _QUOTES_THE_DOCUMENT_MARK, False) is True and read_any
        ):
            # `error` can quote a value read from the environment, and a chain
            # walker prints __context__ even under `from None`, so the blind
            # error is built and raised below, outside the handler, where
            # `error` is on neither chain. Building it here would chain it
            # too: the literal resolution inside _environment_blind_error
            # raises while `error` is the active exception.
            blind_for = error
        else:
            raise
    finally:
        # The bases the walk held open (_resolve_base_path).
        for opened in state.held:
            opened.close()
    if blind_for is not None:
        blind = _environment_blind_error(config_path, root, permit_base, blind_for)
        # The fresh error's traceback carries this frame, and a walker that
        # prints frame locals (a debugger, a verbose traceback renderer) would
        # print what the chain read from the environment: `state` holds every
        # reference read with its value, and `blind_for` is the refused error,
        # whose text can quote one. Both are dropped from the frame before the
        # raise, so the error leaves with a frame that holds no value.
        del state, blind_for
        raise blind from None
    places: Dict[Tuple[Any, ...], List[Tuple[Any, ...]]] = {
        reference.place_key: [] for reference in state.read
    }
    for reference in state.references:
        places.setdefault(reference.place_key, []).append(tuple(reference.path))
    return ResolvedConfigDocument(
        data=data,
        chain=state.order,
        root=root,
        named=state.named,
        documents=state.documents,
        names=state.all_names(),
        environment_references=state.references,
        # The merge decided each place; a reference the merged document no
        # longer shows (a base's, under an overlay's literal or an overlay's
        # own reference) describes a file of the chain, not the configuration,
        # and is left out of the displayed view (_still_describes).
        displayed_environment_references=[
            reference
            for reference in state.references
            if _still_describes(data, reference)
        ],
        environment_paths=frozenset(state.environment_paths),
        environment_values=_values_of(state.read),
        reference_places=places,
    )


def _environment_blind_error(
    config_path: Path,
    root: Path,
    permit_base: Optional[PermitBase],
    error: ASHConfigSourceError,
) -> ASHConfigSourceError:
    """Why `config_path`'s chain does not resolve, without environment values.

    The chain is resolved again with nothing read from the environment, and
    that failure is the reason when it names no reference: it names files as
    they are written, and it is where the resolution with the environment
    fails too. When it does name a reference (a `${` in its text), the literal
    resolution failed at the reference itself, which the real one resolves, so
    its reason would differ and suggest the reference was never resolved.
    Then, and when the chain resolves without the environment, the reason is
    given without quoting anything: the failure depended on a value read from
    the environment. When the raising site threaded the names of mapping keys
    that resolved to no key (_EMPTY_KEY_REFERENCE_NAMES_MARK), the reason
    names those variables, which the literal reading cannot see (it keeps each
    key as written); otherwise it is the generic base-file reason. A refusal
    by `permit_base` is returned as it is (ASHConfigInputNotPermittedError),
    so callers report it as a refusal.
    """
    if isinstance(error, ASHConfigUnsetVariableError):
        # The literal reading below would find nothing wrong: the reference fails
        # only once the environment is read, because the variable is unset. So
        # its text quotes no environment value; it names the variable as written
        # and the file holding it. That file is named only when it is the config
        # itself, since a base's path can be one read from the environment.
        if error.config_file is not None and _is_same_file(
            error.config_file, config_path
        ):
            return ASHConfigSourceError(str(error))
        return ASHConfigSourceError(
            f"a file in the extends chain of {describe_config_path(config_path)} "
            f"references ${{{error.variable}}}, which has no default, and "
            f"{error.variable} is not set. Set {error.variable}, or write "
            f"${{{error.variable}:None}} (or another default after the colon) to "
            "allow it to be unset."
        )
    try:
        resolve_config_document(
            config_path,
            confine_to=root,
            permit_base=permit_base,
            reader=read_config_file_literally,
        )
    except ASHConfigSourceError as literal_error:
        if "${" not in str(literal_error):
            # Without its traceback: that traceback runs through this frame,
            # whose local `error` is the refused error (its text can quote a
            # value read from the environment) and whose own traceback keeps
            # the real resolution's frames, and their state, alive. The
            # caller raises the returned error with the chain cut (`from
            # None`), but a traceback is carried on the error itself, so it
            # is cut here, where it would otherwise leave with the frame.
            if config_file_changed(literal_error):
                # The caller raises this error `from None`, which drops the
                # ConfigFileChangedError it was raised from, and with it the
                # fact that a file changed after it was checked. The fact rides
                # on the error itself, as it does on a reworded base error; the
                # mark carries no path.
                setattr(literal_error, _FILE_CHANGED_MARK, True)
            return literal_error.with_traceback(None)
    except (yaml.YAMLError, OSError, ValueError):
        # The file reads with the environment but not without it; nothing more
        # can be said without quoting what the environment supplied.
        pass
    # Not "the base named through a variable is missing": that base may exist,
    # and a file it extends be the one missing.
    names = tuple(getattr(error, _EMPTY_KEY_REFERENCE_NAMES_MARK, ()))
    if len(names) == 1:
        # The raising site threaded the name (the mark): a mapping key spelled
        # from the environment resolved to no key. The name is no secret; what
        # the variable holds is never shown.
        reason = (
            f"the extends chain of {describe_config_path(config_path)} does not "
            f"resolve with the values its environment references hold: a "
            f"mapping key is written as a reference to {names[0]}, which is "
            "set to text that spells no key (empty or whitespace), so the "
            f"entry resolves to no key. Set {names[0]} to a key name, or "
            "write the key as text"
        )
    elif names:
        listed = ", ".join(names)
        reason = (
            f"the extends chain of {describe_config_path(config_path)} does not "
            f"resolve with the values its environment references hold: mapping "
            f"keys are written as references to {listed}, each set to text "
            "that spells no key (empty or whitespace), so those entries "
            "resolve to no key. Set each to a key name, or write the keys "
            "as text"
        )
    else:
        reason = (
            f"the extends chain of {describe_config_path(config_path)} does not "
            "resolve with the values its environment references hold: a file reached "
            "through a base named by an environment variable (that base, or one it "
            "extends) is missing, cannot be read, or is outside the directory bases "
            "must stay inside"
        )
    if isinstance(error, ASHConfigInputNotPermittedError):
        return ASHConfigInputNotPermittedError(reason)
    return ASHConfigSourceError(reason)


def _is_same_file(a: Path, b: Path) -> bool:
    try:
        return Path(a).resolve() == Path(b).resolve()
    except (OSError, RuntimeError):
        return Path(a) == Path(b)


def load_config_with_references(
    config_path: Path,
    anchor_relative_paths: Optional[AnchorPaths] = None,
) -> AshConfig:
    """``AshConfig.from_file``, keeping what the file and its bases read from the
    environment (``AshConfig._environment_references``), for a caller that
    writes the config out again (``config/environment_record.py``)."""
    document = resolve_config_document(
        Path(config_path), anchor_relative_paths=anchor_relative_paths
    )
    # The strict_file_load context, as build_config and validate_config_document
    # validate a document: it selects the named refusal of a typed field's
    # environment reference rather than pydantic's message about the resolved
    # text.
    config = AshConfig.model_validate(
        document.data, strict=True, context={"strict_file_load": True}
    )
    config._environment_references = tuple(document.environment_references)
    return config


def load_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
) -> Any:
    return resolve_config_document(
        config_path,
        confine_to=confine_to,
        permit_base=permit_base,
        refuse_env=refuse_env,
        anchor_relative_paths=anchor_relative_paths,
    ).data


def uses_env_references(path: Path) -> bool:
    """Whether a YAML config file reads any value from the environment.

    True when a scalar carries the ``!ENV`` tag, or is a plain scalar the YAML
    loader resolves as one (``load_yaml_config`` registers ENV_REFERENCE_PATTERN
    as an implicit resolver). A command that rewrites the file from its parsed
    values would replace each such reference with the value it resolves to now,
    so those commands refuse the file. TOML and JSON files return False: the
    rewriting commands refuse TOML already, and JSON is not interpolated. A file
    that does not parse returns False, and the caller's own load reports why.

    The file is read as every config file is (``read_config_bytes``): opened
    without blocking, read only when the opened file is a regular file, and at
    most ``ASH_CONFIG_MAX_FILE_BYTES`` of it. A plain ``open`` here waited on a
    FIFO swapped in after the check below and read a file of any size. A file
    that cannot be read within those bounds returns False, and the caller's own
    load refuses it the same way.
    """
    path = Path(path)
    if is_toml_file(path) or is_json_file(path):
        return False
    try:
        refuse_unless_a_file(path)
    except ASHConfigSourceError:
        # The caller's load refuses it; opening a FIFO here would wait for ever.
        return False
    try:
        text = read_config_bytes(path).decode("utf-8")
    except (OSError, UnicodeDecodeError, ASHConfigSourceError):
        return False
    return _yaml_reads_the_environment(_NamedText(text, str(path)))
