# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mkdocs hook: the data and the page policy of the configuration editor.

The editor is one page of the docs site, how-to/config-editor.md. It builds an ASH
config file in the reader's browser and sends nothing anywhere. This hook gives
that page two things and does nothing on any other page.

The data block. A JSON block, written into the built page as
``<script type="application/json" id="ash-config-editor-data">``, that holds what the
editor needs to know about ASH's configuration, computed from the commit being
built so that no second copy exists to go stale:

* the published schema, automated_security_helper/schemas/AshConfig.json, with the
  ``build`` property (a subtree ASH refuses in a config file) and the definitions
  only it reaches cut out, and the annotation keywords removed, with the sha256 of
  the file as read;
* a folded view of every setting for the form: its kind, default, bounds, enum
  values, whether it may be null, whether the schema admits an environment
  reference, and what ASH does with it (hidden, deprecated, host-dependent);
* what ASH does with each setting in a repository's own file, which it does not
  trust the way it trusts an operator's: measured by loading planted files through
  ASH's own config loader, with a pinned table for the rules a load cannot show;
* whether ASH accepts a ``${VAR}`` reference per kind of setting on the route
  that loads a config file, measured the same way;
* ASH's own constants the editor must agree with (the environment-variable rule,
  the section spelling fold, the warning texts), read from ASH's code.

The contract of the block is BLOCK_SCHEMA below. The generator tripwires stop the
build, naming the JSON pointer or path, when the schema grows something the editor
cannot handle: a keyword it does not know, a pattern it has no translation for, a
node its kinds cannot hold, a setting an annotation names that the schema lacks, or
a block over the size ceiling. They run in the unit tests on every pull request, so
a schema change that would break the editor fails there, not on the site.

The page policy. For the editor page, a Content-Security-Policy meta placed
directly after ``<meta charset>``, with a sha256 for each executable inline script
of the final page, so that the page can load only this site's own files and cannot
connect anywhere else. The build fails when that page holds an inline event
handler, a ``javascript:`` URL, an external script, a second policy meta or no
charset meta. The one exception is the search-share anchor Material for MkDocs
writes on every page while ``search.share`` is on, which is exempt by its exact
markup.

Both parts run in on_post_page at the lowest event priority, after every other
plugin, so the hashes are taken over the final bytes.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import hashlib
import html
import importlib.util
import inspect
import json
import os
import platform
import re
import sys
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, NamedTuple

from mkdocs.exceptions import PluginError
from mkdocs.plugins import event_priority

#: The editor page, as its source path relative to docs_dir.
EDITOR_PAGE = "how-to/config-editor.md"
#: Relative to the directory mkdocs.yml is in.
SCHEMA_PATH = "automated_security_helper/schemas/AshConfig.json"
GENERATOR = "docs/hooks/config_editor.py"
CONTRACT = "ash-config-editor-data/1"
BLOCK_ID = "ash-config-editor-data"
#: The serialized block may not be larger than this many bytes. The projection of
#: the schema measured 333,407 bytes when the ceiling was set, so this is 20% above
#: it: room for the schema to grow, and a stop, naming the largest parts, before it
#: grows past that.
SIZE_CEILING = 400_000

#: The three plugin kinds, by the key of their segment in a config file.
SEGMENTS = ("scanners", "reporters", "converters")

#: The keywords of ASH's schema that assert something. Every other keyword the
#: schema uses must be one of ANNOTATIONS, or the tripwire names it.
ASSERTIONS = frozenset(
    {
        "$ref",
        "additionalProperties",
        "anyOf",
        "const",
        "enum",
        "exclusiveMinimum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "type",
    }
)
#: Keywords that describe and never decide. The validation schema leaves them out.
ANNOTATIONS = ("title", "description", "default", "examples", "format")
#: The keywords the root of the schema may carry besides its definitions.
ROOT_KEYWORDS = frozenset({"$defs", "$ref", "$schema", "$id"})

#: The pattern ASH's schema puts on the string branch that admits an environment
#: reference, ``${NAME}``, ``${NAME:default}`` or either behind ``!ENV ``.
REFERENCE_PATTERN = r"^(!ENV )?\$\{\w+(:.*)?\}$"
#: The one definition the build subtree hangs from. ASH's validator calls the
#: property invalid and its writer leaves it out.
CUT_PROPERTY = "build"
ROOT_DEFINITION = "AshConfig"

#: The JavaScript translation of every ``pattern`` the schema holds, keyed by the
#: Python source. ``\w`` is letters, numbers and the underscore, ``.`` stops at a
#: newline, and ``$`` also matches before one trailing newline, which is what
#: Python's ``re.search`` does and a JavaScript ``$`` does not. A pattern the schema
#: gains that is not here stops the build with its pointer: it needs a translation
#: and hazard tests first.
PATTERN_TRANSLATIONS: dict[str, dict[str, str]] = {
    REFERENCE_PATTERN: {
        "js": r"^(!ENV )?\$\{[\p{L}\p{N}_]+(:[^\n]*)?\}(?=\n?$)",
        "flags": "u",
    },
    r"^[a-zA-Z][\w-]+$": {
        "js": r"^[a-zA-Z][\p{L}\p{N}_-]+(?=\n?$)",
        "flags": "u",
    },
    r"^[0-9a-fA-F]{64}$": {
        "js": r"^[0-9a-fA-F]{64}(?=\n?$)",
        "flags": "u",
    },
}
#: ASH's own reference recognizer. It matches a prefix: no end anchor.
REFERENCE_RECOGNIZER_PYTHON = r"^\${(\w+)(:?)([^}\r\n]*)}"
REFERENCE_RECOGNIZER_TRANSLATION = {
    "js": r"^\$\{([\p{L}\p{N}_]+)(:?)([^}\r\n]*)\}",
    "flags": "u",
}

#: Settings the vocabulary of kinds cannot hold, or that the editor keeps as YAML
#: text on purpose: free-form objects and lists, and a baseline file's own
#: structure. A node that no kind can hold and that is not named here stops the
#: build; a name here that matches no setting of the schema stops it too.
RAW_PATHS = frozenset(
    {
        "patch",
        "global_settings.suppressions[].scope.engines",
        "scanners.detect-secrets.options.scan_settings",
    }
)

#: The left pane's groups, in order. Every top-level path except ``build`` and
#: ``global_settings``, and every child of ``global_settings``, is in exactly one.
GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "project",
        "Project and gate",
        (
            "project_name",
            "fail_on_findings",
            "fail_on_incomplete_scanners",
            "fail_on_unknown_keys",
            "global_settings.severity_threshold",
            "content_db_staleness",
            "content_db_staleness_overrides",
            "content_db_staleness_offline_image_default",
        ),
    ),
    ("scanners", "Scanners", ("scanners",)),
    ("reporters", "Reporters", ("reporters", "output_formats")),
    ("converters", "Converters", ("converters",)),
    (
        "scope",
        "Scope and exceptions",
        (
            "global_settings.ignore_paths",
            "global_settings.exclusions",
            "global_settings.suppressions",
            "honor_ignore_files",
            "default_scanners",
            "precommit",
        ),
    ),
    (
        "runtime",
        "Runtime",
        (
            "sandbox",
            "workspace",
            "global_settings.deduplication",
            "global_settings.history",
            "global_settings.mcp",
            "mcp-resource-management",
            "external_reports_to_include",
        ),
    ),
    (
        "plugins",
        "Plugins and composition",
        ("ash_plugin_modules", "extends", "patch"),
    ),
)

#: What moves a default ASH computes when it is imported: the schema carries the
#: shipped value. Each entry is checked against ASH's code by the unit tests.
HOST_DEFAULTS: dict[str, dict[str, str]] = {
    "project_name": {"dependsOn": "environment", "name": "ASH_PROJECT_NAME"},
    "global_settings.severity_threshold": {
        "dependsOn": "environment",
        "name": "ASH_DEFAULT_SEVERITY_LEVEL",
    },
    "scanners.opengrep.enabled": {"dependsOn": "platform", "name": "windows"},
    "scanners.semgrep.enabled": {"dependsOn": "platform", "name": "windows"},
}
#: Where a scanner's null severity threshold takes its value from.
INHERITED_SEVERITY = "global_settings.severity_threshold"

#: The reference pages the editor links settings to, and the page each anchors.
REFERENCE_PAGES = {
    "configuration": "docs/content/reference/configuration.md",
    "scanners": "docs/content/reference/scanners.md",
    "reporters": "docs/content/reference/reporters.md",
    "converters": "docs/content/reference/converters.md",
}


#: Two texts ASH builds with f-strings, with ``{field}`` and ``{anchor}`` where its
#: code puts the name. The unit tests hold each equal to what ASH writes for a
#: planted file.
INVALID_TOP_LEVEL_FIELD_WARNING = (
    "Top-level field '{field}' is an internal field and should not be in user configs"
)
ALIAS_REFUSAL = (
    "found the alias *{anchor}; ASH configuration does not accept YAML aliases, "
    "so write the value out where it is used"
)


class ProjectionError(PluginError):
    """A generator tripwire: the schema, ASH or an annotation is not what the
    editor's projection can handle. The message names the JSON pointer or path."""


# --- The shape of the block --------------------------------------------------------

_PATH = r"^[A-Za-z0-9_-]+(\[\]|\{\})?(\.[A-Za-z0-9_-]+(\[\]|\{\})?)*$"
_PATH_PATTERN = r"^([A-Za-z0-9_-]+|\*)(\[\]|\{\})?(\.([A-Za-z0-9_-]+|\*)(\[\]|\{\})?)*$"
_NON_EMPTY = {"type": "string", "minLength": 1}
_KIND_LISTS = {
    "type": "object",
    "additionalProperties": False,
    "required": ["scanners", "reporters", "converters"],
    "properties": {
        "scanners": {"type": "array", "items": _NON_EMPTY},
        "reporters": {"type": "array", "items": _NON_EMPTY},
        "converters": {"type": "array", "items": _NON_EMPTY},
    },
}
_PROBE_CELL = {
    "type": "object",
    "additionalProperties": False,
    "required": ["topLevel", "section"],
    "properties": {"topLevel": {"type": "boolean"}, "section": {"type": "boolean"}},
}

#: The JSON Schema every block validates against (Draft 2020-12). The block's
#: consumers build against this document: they may rely on what it requires and
#: on nothing else. A change to it is a new contract.
BLOCK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:ash:config-editor-data:1",
    "title": "ASH configuration editor data block, contract 1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "contract",
        "source",
        "validationSchema",
        "fields",
        "groups",
        "sections",
        "optIn",
        "trust",
        "env",
        "envProbe",
        "constants",
        "patterns",
        "spelling",
    ],
    "properties": {
        "contract": {"const": CONTRACT},
        "source": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schemaPath",
                "schemaSha256",
                "ashVersion",
                "docsVersion",
                "generator",
            ],
            "properties": {
                "schemaPath": {"const": SCHEMA_PATH},
                "schemaSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "ashVersion": _NON_EMPTY,
                "docsVersion": _NON_EMPTY,
                "generator": {"const": GENERATOR},
            },
        },
        "validationSchema": {
            "type": "object",
            "required": ["$defs", "$ref"],
            "properties": {
                "$ref": {"const": "#/$defs/" + ROOT_DEFINITION},
                "$defs": {"type": "object", "required": [ROOT_DEFINITION]},
            },
        },
        "fields": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"$ref": "#/$defs/path"},
            "additionalProperties": {"$ref": "#/$defs/field"},
        },
        "groups": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/group"}},
        "sections": {
            "type": "object",
            "additionalProperties": False,
            "required": list(SEGMENTS),
            "properties": {
                kind: {"type": "array", "items": {"$ref": "#/$defs/section"}}
                for kind in SEGMENTS
            },
        },
        "optIn": {"type": "array", "items": {"$ref": "#/$defs/optIn"}},
        "trust": {"type": "array", "items": {"$ref": "#/$defs/trustRule"}},
        "env": {"$ref": "#/$defs/env"},
        "envProbe": {"$ref": "#/$defs/envProbe"},
        "constants": {"$ref": "#/$defs/constants"},
        "patterns": {
            "type": "object",
            "additionalProperties": {"$ref": "#/$defs/pattern"},
        },
        "spelling": {"$ref": "#/$defs/spelling"},
    },
    "$defs": {
        "path": {"type": "string", "pattern": _PATH},
        "pathPattern": {"type": "string", "pattern": _PATH_PATTERN},
        "field": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "path",
                "key",
                "parent",
                "kind",
                "schemaPointer",
                "nullable",
                "required",
                "envRef",
                "envAccepted",
                "hidden",
                "order",
            ],
            "properties": {
                "path": {"$ref": "#/$defs/path"},
                "key": _NON_EMPTY,
                "parent": {"anyOf": [{"$ref": "#/$defs/path"}, {"type": "null"}]},
                "kind": {
                    "enum": [
                        "section",
                        "object",
                        "boolean",
                        "integer",
                        "number",
                        "string",
                        "enum",
                        "enumList",
                        "stringList",
                        "stringOrList",
                        "objectList",
                        "map",
                        "raw",
                    ]
                },
                "schemaPointer": {"type": "string", "pattern": "^#/\\$defs/"},
                "description": {"type": ["string", "null"]},
                "default": True,
                "nullable": {"type": "boolean"},
                "required": {"type": "boolean"},
                "enum": {"type": "array", "minItems": 1},
                "bounds": {
                    "type": "object",
                    "additionalProperties": False,
                    "minProperties": 1,
                    "properties": {
                        "minimum": {"type": "number"},
                        "maximum": {"type": "number"},
                        "exclusiveMinimum": {"type": "number"},
                        "minLength": {"type": "integer", "minimum": 0},
                        "maxLength": {"type": "integer", "minimum": 0},
                        "minItems": {"type": "integer", "minimum": 0},
                        "maxItems": {"type": "integer", "minimum": 0},
                    },
                },
                "patternRef": _NON_EMPTY,
                "envRef": {"type": "boolean"},
                "envAccepted": {"type": "boolean"},
                "hidden": {"type": "boolean"},
                "deprecated": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["renameTo"],
                    "properties": {"renameTo": _NON_EMPTY},
                },
                "hostDefault": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["dependsOn", "name"],
                    "properties": {
                        "dependsOn": {"enum": ["environment", "platform"]},
                        "name": _NON_EMPTY,
                    },
                },
                "inherits": {"$ref": "#/$defs/path"},
                "trust": _NON_EMPTY,
                "order": {"type": "integer", "minimum": 0},
                "anchor": _NON_EMPTY,
                "mapKeys": {
                    "type": "object",
                    "additionalProperties": False,
                    "minProperties": 1,
                    "properties": {
                        "enum": {"type": "array", "minItems": 1},
                        "patternRef": _NON_EMPTY,
                        "envRef": {"type": "boolean"},
                    },
                },
            },
            "allOf": [
                {
                    "if": {"properties": {"kind": {"enum": ["enum", "enumList"]}}},
                    "then": {"required": ["enum"]},
                },
                {
                    "if": {"properties": {"kind": {"const": "map"}}},
                    "then": {"required": ["mapKeys"]},
                },
            ],
        },
        "group": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "title", "paths"],
            "properties": {
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
                "title": _NON_EMPTY,
                "paths": {"type": "array", "items": {"$ref": "#/$defs/path"}},
            },
        },
        "section": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "category"],
            "properties": {
                "name": _NON_EMPTY,
                "category": {"type": ["string", "null"]},
            },
        },
        "optIn": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "kind", "module"],
            "properties": {
                "name": _NON_EMPTY,
                "kind": {"enum": ["scanner", "reporter", "converter"]},
                "module": {
                    "type": "string",
                    "pattern": "^automated_security_helper\\.plugin_modules\\.[a-z0-9_]+$",
                },
                "anchor": _NON_EMPTY,
            },
        },
        "trustRule": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "id",
                "paths",
                "rule",
                "keep",
                "instead",
                "appliesAt",
                "via",
                "source",
            ],
            "properties": {
                "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]*$"},
                "paths": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/$defs/pathPattern"},
                },
                "rule": {"enum": ["ignored", "limited", "operatorSection"]},
                "keep": {"type": "array", "items": _NON_EMPTY},
                "instead": _NON_EMPTY,
                "appliesAt": {"enum": ["load", "report", "plugin", "scanner"]},
                "via": {"enum": ["probe", "table"]},
                "source": {"type": "string", "pattern": "^[^:\\s]+:[0-9]+(-[0-9]+)?$"},
            },
        },
        "pattern": {
            "type": "object",
            "additionalProperties": False,
            "required": ["python", "js", "flags"],
            "properties": {
                "python": _NON_EMPTY,
                "js": _NON_EMPTY,
                "flags": {"type": "string", "pattern": "^[dgimsuy]*$"},
            },
        },
        "env": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "prefix",
                "allowlist",
                "refusedNames",
                "readableNames",
                "secretSuffixes",
                "vectors",
                "referencePattern",
                "explicitTag",
            ],
            "properties": {
                "prefix": _NON_EMPTY,
                "allowlist": {"type": "array", "items": _NON_EMPTY},
                "refusedNames": {"type": "array", "items": _NON_EMPTY},
                "readableNames": {"type": "array", "items": _NON_EMPTY},
                "secretSuffixes": {"type": "array", "items": _NON_EMPTY},
                "vectors": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "array",
                        "prefixItems": [_NON_EMPTY, {"type": "boolean"}],
                        "minItems": 2,
                        "maxItems": 2,
                    },
                },
                "referencePattern": {"$ref": "#/$defs/pattern"},
                "explicitTag": {"const": "!ENV "},
            },
        },
        "probeCell": _PROBE_CELL,
        "envProbe": {
            "type": "object",
            "additionalProperties": False,
            "required": ["route", "classes"],
            "properties": {
                "route": {"const": "file-load"},
                "classes": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "boolean",
                        "integer",
                        "number",
                        "enum",
                        "string",
                        "constrainedString",
                    ],
                    "properties": {
                        name: {"$ref": "#/$defs/probeCell"}
                        for name in (
                            "boolean",
                            "integer",
                            "number",
                            "enum",
                            "string",
                            "constrainedString",
                        )
                    },
                },
            },
        },
        "kindLists": _KIND_LISTS,
        "constants": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schemaComment",
                "missingProjectNameMessage",
                "invalidTopLevelFields",
                "invalidTopLevelFieldWarning",
                "requiredTopLevelFields",
                "deprecatedKeys",
                "internalSectionFields",
                "aliasRefusal",
            ],
            "properties": {
                "schemaComment": {
                    "type": "string",
                    "pattern": "^# yaml-language-server: \\$schema=",
                },
                "missingProjectNameMessage": _NON_EMPTY,
                "invalidTopLevelFields": {"type": "array", "items": _NON_EMPTY},
                "invalidTopLevelFieldWarning": {
                    "type": "string",
                    "pattern": "\\{field\\}",
                },
                "requiredTopLevelFields": {"type": "array", "items": _NON_EMPTY},
                "deprecatedKeys": {
                    "type": "object",
                    "additionalProperties": _NON_EMPTY,
                },
                "internalSectionFields": {"$ref": "#/$defs/kindLists"},
                "aliasRefusal": {"type": "string", "pattern": "\\{anchor\\}"},
            },
        },
        "spelling": {
            "type": "object",
            "additionalProperties": False,
            "required": ["canonical", "vectors"],
            "properties": {
                "canonical": {"$ref": "#/$defs/kindLists"},
                "vectors": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "array",
                        "prefixItems": [
                            {"enum": list(SEGMENTS)},
                            _NON_EMPTY,
                            {"type": ["string", "null"]},
                        ],
                        "minItems": 3,
                        "maxItems": 3,
                    },
                },
            },
        },
    },
}


# --- The schema: reading it, cutting it, checking its keywords ---------------------


def read_schema(root: Path) -> tuple[dict[str, Any], str]:
    """The committed schema, and the sha256 of its bytes exactly as read."""
    data = (Path(root) / SCHEMA_PATH).read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def pointer_escape(name: str) -> str:
    return name.replace("~", "~0").replace("/", "~1")


def definition_name(ref: str) -> str:
    """The name in a ``#/$defs/Name`` reference; anything else stops the build."""
    prefix = "#/$defs/"
    if not ref.startswith(prefix) or "/" in ref[len(prefix) :]:
        raise ProjectionError(f"{ref}: only references to a #/$defs/ name are handled")
    return ref[len(prefix) :]


def subschemas(node: Mapping[str, Any]) -> Iterator[tuple[str, Any]]:
    """Each schema nested directly in ``node``, with its pointer relative to it.

    Only the keywords that hold schemas are followed. ``default``, ``enum`` and the
    like hold data, and a property named ``description`` is a name, not a keyword.
    A boolean is a schema too (``additionalProperties: false``), so it is yielded.
    """
    for keyword in ("properties", "$defs"):
        children = node.get(keyword)
        if isinstance(children, dict):
            for name, child in children.items():
                yield f"/{keyword}/{pointer_escape(name)}", child
    for keyword in ("additionalProperties", "items", "propertyNames"):
        child = node.get(keyword)
        if isinstance(child, (dict, bool)):
            yield f"/{keyword}", child
    branches = node.get("anyOf")
    if isinstance(branches, list):
        for index, child in enumerate(branches):
            yield f"/anyOf/{index}", child


def walk_schema(node: Any, pointer: str = "#") -> Iterator[tuple[str, Any]]:
    """Every schema under ``node`` (itself first), with its JSON pointer."""
    yield pointer, node
    if isinstance(node, dict):
        for relative, child in subschemas(node):
            yield from walk_schema(child, pointer + relative)


def references(node: Any) -> Iterator[str]:
    """The definition names every schema under ``node`` refers to."""
    for _, schema in walk_schema(node):
        if isinstance(schema, dict) and "$ref" in schema:
            yield definition_name(schema["$ref"])


def live_definitions(schema: Mapping[str, Any]) -> set[str]:
    """The definitions reachable from the root definition without the cut property."""
    definitions = schema["$defs"]
    if ROOT_DEFINITION not in definitions:
        raise ProjectionError(
            f"#/$defs/{ROOT_DEFINITION}: the root definition is missing"
        )
    seen: set[str] = set()
    todo = [ROOT_DEFINITION]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        node = definitions[name]
        if name == ROOT_DEFINITION:
            node = {
                **node,
                "properties": {
                    key: value
                    for key, value in node.get("properties", {}).items()
                    if key != CUT_PROPERTY
                },
            }
        todo.extend(ref for ref in references(node) if ref not in seen)
    return seen


def strip_annotations(node: Any) -> Any:
    """``node`` without the annotation keywords of any schema under it.

    A property that is named ``description`` or ``default`` keeps its name and its
    subschema: only keywords are removed, never names or data.
    """
    if isinstance(node, bool) or not isinstance(node, dict):
        return copy.deepcopy(node)
    result: dict[str, Any] = {}
    for key, value in node.items():
        if key in ANNOTATIONS:
            continue
        if key in ("properties", "$defs") and isinstance(value, dict):
            result[key] = {name: strip_annotations(sub) for name, sub in value.items()}
        elif key in ("additionalProperties", "items", "propertyNames"):
            result[key] = strip_annotations(value)
        elif key == "anyOf" and isinstance(value, list):
            result[key] = [strip_annotations(branch) for branch in value]
        else:
            result[key] = copy.deepcopy(value)
    return result


def build_validation_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """The schema the editor validates against: ``build`` and what only it reaches
    cut out, annotations removed, every other keyword kept as it is."""
    root = schema["$defs"].get(ROOT_DEFINITION, {})
    if CUT_PROPERTY not in root.get("properties", {}):
        raise ProjectionError(
            f"#/$defs/{ROOT_DEFINITION}/properties/{CUT_PROPERTY}: the schema no "
            "longer has this property, so cutting it is a step to drop"
        )
    extra_root = sorted(set(schema) - ROOT_KEYWORDS)
    if extra_root:
        raise ProjectionError(
            f"#/{extra_root[0]}: a root keyword the editor does not know"
        )
    live = live_definitions(schema)
    definitions: dict[str, Any] = {}
    for name, node in schema["$defs"].items():
        if name not in live:
            continue
        if name == ROOT_DEFINITION:
            node = {
                **node,
                "properties": {
                    key: value
                    for key, value in node["properties"].items()
                    if key != CUT_PROPERTY
                },
            }
        definitions[name] = strip_annotations(node)
    result: dict[str, Any] = {
        key: copy.deepcopy(schema[key]) for key in ROOT_KEYWORDS if key in schema
    }
    result["$defs"] = definitions
    if result.get("$ref") != "#/$defs/" + ROOT_DEFINITION:
        raise ProjectionError(f"#/$ref: expected #/$defs/{ROOT_DEFINITION}")
    check_keywords(result)
    return result


def check_keywords(validation_schema: Mapping[str, Any]) -> None:
    """Stop the build, naming its pointer, at the first keyword the editor's
    validator does not handle, or a ``type`` that is not a single string."""
    for pointer, node in walk_schema(validation_schema):
        if pointer == "#" or not isinstance(node, dict):
            continue
        for keyword, value in node.items():
            if keyword not in ASSERTIONS:
                raise ProjectionError(
                    f"{pointer}/{pointer_escape(keyword)}: the keyword {keyword!r} "
                    "is not one the editor's validator handles"
                )
            if keyword == "type" and not isinstance(value, str):
                raise ProjectionError(
                    f"{pointer}/type: a type that is not a single string is not handled"
                )


def collect_patterns(validation_schema: Mapping[str, Any]) -> dict[str, str]:
    """Every distinct ``pattern`` value, with the pointer of its first use."""
    found: dict[str, str] = {}
    for pointer, node in walk_schema(validation_schema):
        if isinstance(node, dict) and isinstance(node.get("pattern"), str):
            found.setdefault(node["pattern"], f"{pointer}/pattern")
    return found


def pattern_table(validation_schema: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """The ``patterns`` of the block. A pattern with no recorded translation stops
    the build, naming where the schema uses it."""
    table: dict[str, dict[str, str]] = {}
    for source, pointer in collect_patterns(validation_schema).items():
        translation = PATTERN_TRANSLATIONS.get(source)
        if translation is None:
            raise ProjectionError(
                f"{pointer}: the pattern {source!r} has no recorded JavaScript "
                "translation; add one, with its hazard tests"
            )
        table[source] = {"python": source, **translation}
    return table


# --- The fields: folding the schema into the form's view ---------------------------

_BOUNDS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
)
_SCALARS = ("boolean", "integer", "number", "string")
_MISSING = object()


class Unclassified(Exception):
    """A node no kind of the editor can hold. Carries its JSON pointer."""

    def __init__(self, pointer: str, why: str):
        super().__init__(f"{pointer}: {why}")
        self.pointer = pointer
        self.why = why


class Shape:
    """What a property folds to: its kind and the facts its field is built from."""

    def __init__(
        self,
        kind: str,
        pointer: str,
        *,
        nullable: bool = False,
        env_ref: bool = False,
        enum: list[Any] | None = None,
        bounds: dict[str, Any] | None = None,
        pattern: str | None = None,
        node: Mapping[str, Any] | None = None,
        definition: str | None = None,
        item: Shape | None = None,
        value: Shape | None = None,
        value_pointer: str | None = None,
        keys: Shape | None = None,
    ):
        self.kind = kind
        self.pointer = pointer
        self.nullable = nullable
        self.env_ref = env_ref
        self.enum = enum
        self.bounds = bounds or {}
        self.pattern = pattern
        self.node = node
        self.definition = definition
        self.item = item
        self.value = value
        self.value_pointer = value_pointer
        self.keys = keys

    def flagged(self, nullable: bool, env_ref: bool) -> Shape:
        """This shape with the flags of the unions it was reached through added."""
        self.nullable = self.nullable or nullable
        self.env_ref = self.env_ref or env_ref
        return self


def is_reference_branch(branch: Any) -> bool:
    return branch == {"pattern": REFERENCE_PATTERN, "type": "string"}


def is_null_branch(branch: Any) -> bool:
    return branch == {"type": "null"}


def pointer_get(root: Any, pointer: str) -> Any:
    """The node ``pointer`` (``#/a/b``) names in ``root``, or ``_MISSING``."""
    node = root
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        else:
            return _MISSING
    return node


class Folder:
    """Folds a subschema of the validation schema into a Shape."""

    def __init__(self, definitions: Mapping[str, Any]):
        self.definitions = definitions

    def fold(self, node: Any, pointer: str) -> Shape:
        nullable = env_ref = False
        while isinstance(node, dict) and "anyOf" in node:
            rest: list[tuple[int, Any]] = []
            for index, branch in enumerate(node["anyOf"]):
                if is_reference_branch(branch):
                    env_ref = True
                elif is_null_branch(branch):
                    nullable = True
                elif all(branch != seen for _, seen in rest):
                    rest.append((index, branch))
            if len(rest) == 1:
                index, node = rest[0]
                pointer = f"{pointer}/anyOf/{index}"
                continue
            return self.union(rest, pointer).flagged(nullable, env_ref)
        return self.single(node, pointer).flagged(nullable, env_ref)

    def union(self, rest: list[tuple[int, Any]], pointer: str) -> Shape:
        if not rest:
            raise Unclassified(pointer, "a union with no branch to fold")
        shapes = [self.fold(branch, f"{pointer}/anyOf/{i}") for i, branch in rest]
        kinds = sorted(shape.kind for shape in shapes)
        nullable = any(shape.nullable for shape in shapes)
        env_ref = any(shape.env_ref for shape in shapes)
        if kinds == ["string", "stringList"]:
            return Shape("stringOrList", pointer).flagged(nullable, env_ref)
        if kinds == ["enum", "enumList"]:
            enums = [shape.enum for shape in shapes]
            if enums[0] == enums[1]:
                return Shape("enumList", pointer, enum=enums[0]).flagged(
                    nullable, env_ref
                )
        raise Unclassified(pointer, "a union of " + " and ".join(kinds))

    def single(self, node: Any, pointer: str) -> Shape:
        if not isinstance(node, dict) or not node:
            raise Unclassified(pointer, "a schema that says nothing about its value")
        if "$ref" in node:
            name = definition_name(node["$ref"])
            target = self.definitions.get(name)
            if target is None:
                raise Unclassified(pointer, f"a reference to the missing {name}")
            shape = self.fold(target, f"#/$defs/{name}")
            if shape.kind == "object" and shape.definition is None:
                shape.definition = name
            return shape
        if "const" in node:
            return Shape("enum", pointer, enum=[node["const"]])
        kind = node.get("type")
        bounds = {key: node[key] for key in _BOUNDS if key in node}
        if "enum" in node:
            return Shape("enum", pointer, enum=list(node["enum"]), bounds=bounds)
        if kind in _SCALARS:
            return Shape(kind, pointer, bounds=bounds, pattern=node.get("pattern"))
        if kind == "array":
            return self.array(node, pointer, bounds)
        if kind == "object":
            return self.mapping(node, pointer)
        raise Unclassified(pointer, f"a node of type {kind!r}")

    def array(
        self, node: Mapping[str, Any], pointer: str, bounds: dict[str, Any]
    ) -> Shape:
        if "items" not in node:
            raise Unclassified(pointer, "an array with no items schema")
        item = self.fold(node["items"], f"{pointer}/items")
        if item.kind == "string":
            return Shape("stringList", pointer, bounds=bounds, item=item)
        if item.kind == "enum":
            return Shape("enumList", pointer, bounds=bounds, enum=item.enum, item=item)
        if item.kind == "object" and item.node is not None:
            return Shape("objectList", pointer, bounds=bounds, item=item)
        raise Unclassified(pointer, f"a list of {item.kind}")

    def mapping(self, node: Mapping[str, Any], pointer: str) -> Shape:
        if "properties" in node:
            return Shape("object", pointer, node=node)
        values = node.get("additionalProperties")
        if isinstance(values, dict) and values:
            value_pointer = f"{pointer}/additionalProperties"
            value = self.fold(values, value_pointer)
            keys = None
            if isinstance(node.get("propertyNames"), dict):
                keys = self.fold(node["propertyNames"], f"{pointer}/propertyNames")
            return Shape(
                "map", pointer, value=value, value_pointer=value_pointer, keys=keys
            )
        raise Unclassified(pointer, "an object with no properties and no typed values")


def clean_description(text: Any) -> str | None:
    """A description with the reST double backticks written as inline code."""
    if not isinstance(text, str) or not text.strip():
        return None
    return text.replace("``", "`").strip()


def class_of(kind: str, pattern: str | None) -> str | None:
    """The environment-probe class of a field, or None where none applies."""
    if kind in ("boolean", "integer", "number", "enum"):
        return kind
    if kind == "string":
        return "constrainedString" if pattern else "string"
    return None


def location_of(path: str) -> str:
    """``section`` inside a plugin section, ``topLevel`` anywhere else."""
    parts = path.split(".")
    return "section" if len(parts) >= 3 and parts[0] in SEGMENTS else "topLevel"


class Projection:
    """Builds ``fields`` from the schema, one field per setting."""

    def __init__(
        self,
        schema: Mapping[str, Any],
        validation_schema: Mapping[str, Any],
        *,
        internal_fields: Mapping[str, Iterable[str]],
        deprecated: Mapping[str, str],
        env_classes: Mapping[str, Mapping[str, bool]],
        anchors: Mapping[str, str] | None = None,
        raw_paths: Iterable[str] = RAW_PATHS,
        host_defaults: Mapping[str, Mapping[str, str]] = HOST_DEFAULTS,
    ):
        self.schema = schema
        self.definitions = validation_schema["$defs"]
        self.folder = Folder(self.definitions)
        self.internal = {
            kind: frozenset(names) for kind, names in internal_fields.items()
        }
        self.deprecated = dict(deprecated)
        self.env_classes = env_classes
        self.anchors = anchors or {}
        self.raw_paths = frozenset(raw_paths)
        self.host_defaults = dict(host_defaults)
        self.fields: dict[str, dict[str, Any]] = {}
        self.used_raw: set[str] = set()
        self.used_deprecated: set[str] = set()
        self.used_host: set[str] = set()

    def run(self) -> dict[str, dict[str, Any]]:
        root = self.definitions[ROOT_DEFINITION]
        self.properties(root, f"#/$defs/{ROOT_DEFINITION}", "", None, None)
        self.check_annotations()
        return self.fields

    # -- the walk --

    def properties(
        self,
        node: Mapping[str, Any],
        pointer: str,
        prefix: str,
        parent: str | None,
        section_kind: str | None,
    ) -> None:
        names = set(node.get("properties", {}))
        required = set(node.get("required", []))
        for order, (name, sub) in enumerate(node.get("properties", {}).items()):
            path = f"{prefix}.{name}" if prefix else name
            self.field(
                path,
                name,
                parent,
                f"{pointer}/properties/{pointer_escape(name)}",
                sub,
                order,
                name in required,
                section_kind,
                names,
            )

    def field(
        self,
        path: str,
        key: str,
        parent: str | None,
        pointer: str,
        sub: Any,
        order: int,
        required: bool,
        section_kind: str | None,
        siblings: set[str],
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise ProjectionError(
                f"{pointer}: the key {key!r} holds a character the path grammar "
                "does not allow (only letters, digits, - and _), because a path "
                "would no longer name one setting"
            )
        if path in self.raw_paths:
            self.used_raw.add(path)
            shape = Shape("raw", pointer, nullable=self.nullable_of(sub))
        else:
            try:
                shape = self.folder.fold(sub, pointer)
            except Unclassified as error:
                raise ProjectionError(
                    f"{error.pointer}: {error.why}, which no kind of the editor can "
                    f"hold; name {path!r} in RAW_PATHS to keep it as YAML text"
                ) from None
        kind = shape.kind
        if kind == "object" and parent in SEGMENTS:
            kind = "section"
        field: dict[str, Any] = {
            "path": path,
            "key": key,
            "parent": parent,
            "kind": kind,
            "schemaPointer": pointer,
            "nullable": shape.nullable,
            "required": required,
            "envRef": shape.env_ref,
            "envAccepted": self.accepts_reference(kind, shape.pattern, path),
            "hidden": self.hidden(key, section_kind),
            "order": order,
        }
        original = pointer_get(self.schema, pointer)
        description = None
        if isinstance(original, dict):
            description = clean_description(original.get("description"))
        if description is None and shape.definition:
            target = self.schema["$defs"].get(shape.definition, {})
            description = clean_description(target.get("description"))
        if description is not None:
            field["description"] = description
        if (
            kind not in ("object", "section", "raw")
            and isinstance(original, dict)
            and "default" in original
        ):
            field["default"] = copy.deepcopy(original["default"])
        if kind in ("enum", "enumList"):
            field["enum"] = list(shape.enum or [])
        if shape.bounds:
            field["bounds"] = dict(shape.bounds)
        if shape.pattern:
            field["patternRef"] = shape.pattern
        self.annotate(field, siblings)
        self.fields[path] = field
        self.descend(field, shape)

    def descend(self, field: dict[str, Any], shape: Shape) -> None:
        path, kind = field["path"], field["kind"]
        if kind in ("object", "section") and shape.node is not None:
            segment = path.split(".")[0] if kind == "section" else None
            self.properties(shape.node, shape.pointer, path, path, segment)
        elif kind == "objectList" and shape.item is not None and shape.item.node:
            self.properties(
                shape.item.node, shape.item.pointer, f"{path}[]", path, None
            )
        elif kind == "map" and shape.value is not None:
            self.map_value(field, shape)

    def map_value(self, field: dict[str, Any], shape: Shape) -> None:
        path = field["path"]
        value = shape.value
        keys: dict[str, Any] = {"envRef": False}
        if shape.keys is not None:
            if shape.keys.enum:
                keys["enum"] = list(shape.keys.enum)
            if shape.keys.pattern:
                keys["patternRef"] = shape.keys.pattern
            keys["envRef"] = shape.keys.env_ref
        field["mapKeys"] = keys
        value_path = f"{path}{{}}"
        item: dict[str, Any] = {
            "path": value_path,
            "key": field["key"],
            "parent": path,
            "kind": value.kind,
            "schemaPointer": shape.value_pointer,
            "nullable": value.nullable,
            "required": False,
            "envRef": value.env_ref,
            "envAccepted": self.accepts_reference(
                value.kind, value.pattern, value_path
            ),
            "hidden": False,
            "order": 0,
        }
        if value.kind in ("enum", "enumList"):
            item["enum"] = list(value.enum or [])
        if value.bounds:
            item["bounds"] = dict(value.bounds)
        if value.pattern:
            item["patternRef"] = value.pattern
        self.annotate(item, set())
        self.fields[value_path] = item
        if value.kind == "object" and value.node:
            self.properties(value.node, value.pointer, value_path, value_path, None)

    # -- the facts a field carries besides its shape --

    @staticmethod
    def nullable_of(sub: Any) -> bool:
        return isinstance(sub, dict) and any(
            is_null_branch(branch) for branch in sub.get("anyOf", [])
        )

    def accepts_reference(self, kind: str, pattern: str | None, path: str) -> bool:
        name = class_of(kind, pattern)
        if name is None:
            return False
        return bool(self.env_classes[name][location_of(path)])

    def hidden(self, key: str, section_kind: str | None) -> bool:
        if key == "client_supplied":
            return True
        return section_kind is not None and key in self.internal.get(section_kind, ())

    def annotate(self, field: dict[str, Any], siblings: set[str]) -> None:
        path, key = field["path"], field["key"]
        renamed = self.deprecated.get(key)
        if renamed is not None and renamed in siblings:
            self.used_deprecated.add(key)
            field["deprecated"] = {"renameTo": renamed}
        host = self.host_defaults.get(path)
        if host is not None:
            self.used_host.add(path)
            field["hostDefault"] = dict(host)
        parts = path.split(".")
        if (
            key == "severity_threshold"
            and field["nullable"]
            and len(parts) == 4
            and parts[0] == "scanners"
            and parts[2] == "options"
        ):
            field["inherits"] = INHERITED_SEVERITY
        anchor = self.anchors.get(re.sub(r"\[\]|\{\}", "", path))
        if anchor:
            field["anchor"] = anchor

    def check_annotations(self) -> None:
        """An annotation that names something the schema lacks stops the build."""
        for path in sorted(self.raw_paths - self.used_raw):
            raise ProjectionError(
                f"RAW_PATHS names {path!r}, which is no setting of the schema"
            )
        for path in sorted(set(self.host_defaults) - self.used_host):
            raise ProjectionError(
                f"HOST_DEFAULTS names {path!r}, which is no setting of the schema"
            )
        for key in sorted(set(self.deprecated) - self.used_deprecated):
            raise ProjectionError(
                f"the deprecated key {key!r} matches no setting of the schema"
            )
        if INHERITED_SEVERITY not in self.fields:
            raise ProjectionError(f"{INHERITED_SEVERITY!r} is no setting of the schema")


def project_fields(
    schema: Mapping[str, Any],
    validation_schema: Mapping[str, Any],
    **facts: Any,
) -> dict[str, dict[str, Any]]:
    """``fields`` of the block: one entry per setting, keyed by path."""
    return Projection(schema, validation_schema, **facts).run()


# --- ASH's own facts, read from its code -------------------------------------------

#: The deprecated keys ASH accepts, with the key each is the old name of. ASH names
#: the old keys and not what replaced them, so the replacement is recorded here, and
#: the unit tests hold the two sets equal.
DEPRECATED_RENAMES = {"expiration": "expires"}

#: Environment variable names the block's vectors cover, besides the names ASH's own
#: constants give. Each is a case the rule has to answer the same way in the browser:
#: a name ending in a secret word, a qualified or glued one, a word that only looks
#: like one, a limit named after the word, other case, and names outside ASH_.
ENV_VECTOR_NAMES = (
    "ASH_PROJECT_NAME",
    "ASH_DEFAULT_SEVERITY_LEVEL",
    "ASH_OUTPUT_DIR",
    "ASH_API_KEY_PROD",
    "ASH_API_KEY2",
    "ASH_APIKEY",
    "ASH_X_PASSPHRASE",
    "ASH_DB_PASS",
    "ASH_GITHUB_PAT",
    "ASH_GITHUBTOKENPROD",
    "ASH_MYPASSWORDV2",
    "ASH_TOKEN_V2",
    "ASH_AUTH_ENABLED",
    "ASH_PASS_THRESHOLD",
    "ASH_COMPAT",
    "ASH_BYPASS",
    "ASH_COMPASS",
    "ASH_OLDPWD",
    "ASH_BYPASS_TOKEN",
    "ASH_MYCOMPASS_TOKEN",
    "ASH_BYPASSES",
    "ASH_BYPASS2",
    "ASH_KEYBOARD",
    "ASH_MONKEY",
    "ASH_PASSPORT",
    "ASH_MAX_TOKEN",
    "ASH_X_MAX_TOKENS",
    "ASH_API_KEY_MAX_TOKENS",
    "ASH_API_TOKENS",
    "ash_api_key",
    "Ash_Project_Name",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "HOME",
    "PATH",
    "aws_region",
)
#: Section-name spellings the spelling vectors try for a few names of each kind:
#: ASH reads case, ``-`` and ``_`` as nothing and one trailing type word as nothing.
SPELLING_NAMES_PER_KIND = 3
SPELLING_NEGATIVES = ("no-such-section", "scanner", "reporter", "converter")


def package_parent() -> Path:
    """The directory ASH's package is in: its source's paths are relative to it."""
    import automated_security_helper

    return Path(automated_security_helper.__file__).resolve().parent.parent


def source_range(function: Any) -> str:
    """``path:first-last`` for a function of ASH, as ``source`` of a trust rule."""
    lines, first = inspect.getsourcelines(function)
    where = Path(inspect.getsourcefile(function) or "").resolve()
    return f"{where.relative_to(package_parent()).as_posix()}:{first}-{first + len(lines) - 1}"


def environment_rule() -> dict[str, Any]:
    """ASH's rule for the variables a config file may read, and vectors that pin it."""
    from automated_security_helper.config import ash_config
    from automated_security_helper.core import constants

    if ash_config.ENV_REFERENCE_PATTERN.pattern != REFERENCE_RECOGNIZER_PYTHON:
        raise ProjectionError(
            "ASH's reference recognizer is no longer "
            f"{REFERENCE_RECOGNIZER_PYTHON!r}; add its JavaScript translation"
        )
    names: list[str] = []
    candidates = [
        *constants.ASH_CONFIG_ENV_VAR_ALLOWLIST,
        *constants.ASH_CONFIG_ENV_VAR_SECRET_NAMES,
        *constants.ASH_CONFIG_ENV_VAR_READABLE_NAMES,
        *(f"ASH_X{suffix}" for suffix in constants.ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES),
        *ENV_VECTOR_NAMES,
    ]
    for name in candidates:
        if name not in names:
            names.append(name)
    return {
        "prefix": constants.ASH_CONFIG_ENV_VAR_PREFIX,
        "allowlist": list(constants.ASH_CONFIG_ENV_VAR_ALLOWLIST),
        "refusedNames": list(constants.ASH_CONFIG_ENV_VAR_SECRET_NAMES),
        "readableNames": list(constants.ASH_CONFIG_ENV_VAR_READABLE_NAMES),
        "secretSuffixes": list(constants.ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES),
        "vectors": [
            [name, bool(constants.is_refused_config_environment_name(name))]
            for name in names
        ],
        "referencePattern": {
            "python": ash_config.ENV_REFERENCE_PATTERN.pattern,
            **REFERENCE_RECOGNIZER_TRANSLATION,
        },
        "explicitTag": ash_config.EXPLICIT_ENV_TAG,
    }


def ash_constants() -> dict[str, Any]:
    """The texts and tables of ASH's the editor repeats, read from its code."""
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.config.config_writer import SCHEMA_COMMENT
    from automated_security_helper.utils import unknown_keys

    if set(unknown_keys.DEPRECATED_KEYS) != set(DEPRECATED_RENAMES):
        raise ProjectionError(
            f"ASH's deprecated keys are {sorted(unknown_keys.DEPRECATED_KEYS)}; "
            "DEPRECATED_RENAMES must name the key each is the old name of"
        )
    internal = {
        kind: sorted(unknown_keys.INTERNAL_SECTION_FIELDS[kind]) for kind in SEGMENTS
    }
    return {
        "schemaComment": SCHEMA_COMMENT,
        "missingProjectNameMessage": ConfigValidator.MISSING_PROJECT_NAME_MESSAGE,
        "invalidTopLevelFields": sorted(ConfigValidator.INVALID_TOP_LEVEL_FIELDS),
        "invalidTopLevelFieldWarning": INVALID_TOP_LEVEL_FIELD_WARNING,
        "requiredTopLevelFields": sorted(ConfigValidator.REQUIRED_TOP_LEVEL_FIELDS),
        "deprecatedKeys": dict(DEPRECATED_RENAMES),
        "internalSectionFields": internal,
        "aliasRefusal": ALIAS_REFUSAL,
    }


def spelling_variants(name: str, kind: str) -> list[str]:
    """Spellings of a section name ASH folds into it, and one it does not."""
    joined = name.replace("-", "").replace("_", "")
    camel = "".join(part.capitalize() for part in re.split(r"[-_]", name))
    word = {"scanners": "Scanner", "reporters": "Reporter", "converters": "Converter"}[
        kind
    ]
    variants = [
        name,
        name.upper(),
        name.replace("-", "_"),
        joined,
        camel,
        camel + word,
        name + "-" + word.lower(),
        name[: len(name) // 2] + "-" + name[len(name) // 2 :],
    ]
    return list(dict.fromkeys(variants))


def spelling_data(published: Mapping[str, list[str]]) -> dict[str, Any]:
    """The published section names, and ASH's own spelling fold applied to a sample
    of spellings, so the browser's port can be held to it."""
    from automated_security_helper.config.plugin_section_names import (
        declared_section_names,
        declared_target,
    )

    vectors: list[list[Any]] = []
    for kind in SEGMENTS:
        declared = declared_section_names(kind)
        if sorted(declared.values()) != sorted(published[kind]):
            raise ProjectionError(
                f"ASH declares the {kind} sections {sorted(declared.values())} but the "
                f"schema publishes {sorted(published[kind])}"
            )
        names = published[kind]
        sample = [*names[:SPELLING_NAMES_PER_KIND], *[n for n in names if "-" in n][:2]]
        for name in dict.fromkeys(sample):
            for variant in spelling_variants(name, kind):
                vectors.append([kind, variant, declared_target(declared, variant)])
        for negative in SPELLING_NEGATIVES:
            vectors.append([kind, negative, declared_target(declared, negative)])
    return {
        "canonical": {kind: list(published[kind]) for kind in SEGMENTS},
        "vectors": vectors,
    }


def reference_anchors(root: Path) -> dict[str, str]:
    """The settings the reference pages anchor, by path without ``[]``: an explicit
    ``<a id>`` for each option and a heading for each plugin section."""
    anchors: dict[str, str] = {}
    for page, relative in REFERENCE_PAGES.items():
        text = (Path(root) / relative).read_text(encoding="utf-8")
        for found in re.finditer(r'<a id="([^"]+)"></a>', text):
            anchors.setdefault(found.group(1), f"reference/{page}/#{found.group(1)}")
        if page in SEGMENTS:
            for found in re.finditer(r"^## `([^`]+)`\s*$", text, re.MULTILINE):
                name = found.group(1)
                anchors.setdefault(f"{page}.{name}", f"reference/{page}/#{name}")
    return anchors


@contextlib.contextmanager
def scripts_on_path(root: Path) -> Iterator[None]:
    """The repository's scripts directory on ``sys.path`` while its generators are
    imported: they import one another by name."""
    entry = str(Path(root) / "scripts")
    sys.path.insert(0, entry)
    try:
        yield
    finally:
        if entry in sys.path:
            sys.path.remove(entry)


def plugin_data(root: Path) -> dict[str, Any]:
    """What ASH's registry knows about every plugin: the category of each scanner
    from its tool type, as the plugin data page of the docs derives it, and each
    plugin that no published section covers, with the module that loads it."""
    with scripts_on_path(root):
        import _plugin_reference as registry

        spec = importlib.util.spec_from_file_location(
            "_ash_docs_generate_plugin_data_partial",
            Path(root) / "scripts" / "generate_plugin_data_partial.py",
        )
        if spec is None or spec.loader is None:
            raise ProjectionError("cannot load scripts/generate_plugin_data_partial.py")
        generator = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = generator
        spec.loader.exec_module(generator)
        found = {
            kind: registry.discover(kind)
            for kind in ("scanner", "reporter", "converter")
        }
        registry.instantiate(found["scanner"])
    labels = dict(generator.CATEGORY_LABELS)
    categories: dict[str, str | None] = {}
    for plugin in found["scanner"]:
        tool_type = getattr(plugin.instance, "tool_type", None)
        tool_type = getattr(tool_type, "value", tool_type)
        slug = generator.TOOL_TYPE_CATEGORY.get(str(tool_type)) if tool_type else None
        categories[plugin.name] = labels.get(slug) if slug else None
    catalog = [
        {"name": plugin.name, "kind": kind, "module": plugin.package}
        for kind, plugins in found.items()
        for plugin in plugins
        if not plugin.builtin
    ]
    return {"categories": categories, "catalog": catalog}


def published_sections(fields: Mapping[str, Mapping[str, Any]]) -> dict[str, list[str]]:
    """The plugin sections the schema publishes, per kind, in the schema's order."""
    names: dict[str, list[str]] = {kind: [] for kind in SEGMENTS}
    for field in fields.values():
        if field["kind"] == "section":
            names[field["parent"]].append(field["key"])
    return names


def build_sections_and_opt_in(
    fields: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, Any],
    anchors: Mapping[str, str],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    published = published_sections(fields)
    sections = {
        kind: [
            {
                "name": name,
                "category": data["categories"].get(name)
                if kind == "scanners"
                else None,
            }
            for name in published[kind]
        ]
        for kind in SEGMENTS
    }
    singular = {
        "scanner": "scanners",
        "reporter": "reporters",
        "converter": "converters",
    }
    opt_in = []
    for entry in sorted(data["catalog"], key=lambda e: (e["kind"], e["name"])):
        kind = singular[entry["kind"]]
        if entry["name"] in published[kind]:
            continue
        item = dict(entry)
        anchor = anchors.get(f"{kind}.{entry['name']}")
        if anchor:
            item["anchor"] = anchor
        opt_in.append(item)
    return sections, opt_in


def group_list() -> list[dict[str, Any]]:
    return [
        {"id": group, "title": title, "paths": list(paths)}
        for group, title, paths in GROUPS
    ]


# --- Probes: asking ASH's own loader what it does ----------------------------------

#: Variables that decide what ASH's defaults are or where it looks. They are unset
#: while a probe runs, so that the answers are ASH's and not the build host's.
ENV_PROBE_VARIABLE = "ASH_PROBE_VALUE"
PINNED_ENVIRONMENT = (
    "ASH_CONFIG",
    "ASH_PLUGIN_MODULES",
    "ASH_MCP_WORKSPACE_ROOT",
    "ASH_PROJECT_NAME",
    "ASH_DEFAULT_SEVERITY_LEVEL",
    ENV_PROBE_VARIABLE,
)
ENV_CLASSES = ("boolean", "integer", "number", "enum", "string", "constrainedString")
LOCATIONS = ("topLevel", "section")
#: A value for each pattern the schema holds, for the probes that need one that
#: matches.
PATTERN_SAMPLES = {r"^[0-9a-fA-F]{64}$": "0" * 64, r"^[a-zA-Z][\w-]+$": "probe-name"}
#: Settings the trust probe leaves alone. ASH would import a module, open a base file
#: or apply a patch for ``ash_plugin_modules``, ``extends`` and ``patch`` while loading.
#: A load reads ``sandbox.network_scanners`` as replaced by the operator's list,
#: although ASH also keeps the repository's list as a limit that a load does not show.
#: The table has a row for ``ash_plugin_modules`` and for ``sandbox.network_scanners``.
PROBE_EXCLUDED = ("ash_plugin_modules", "extends", "patch", "sandbox.network_scanners")
#: Settings whose value a generic planting cannot make, because ASH checks it against
#: a vocabulary of its own, with values it accepts to plant instead.
PROBE_VALUES: dict[str, list[Any]] = {
    "sandbox.environment": [["PROBE_VARIABLE"]],
    "scanners.cfn-lint.options.regions": [["us-east-1"]],
    "scanners.cfn-lint.options.ignore_checks": [["W1001"]],
    "scanners.cfn-lint.options.include_checks": [["W1001"]],
    "global_settings.mcp.runtime_overrides.denied_paths": [["/probe"]],
    "reporters.unused-suppressions.options.output_format": ["markdown"],
    "scanners.opengrep.options.version": ["v1.9.0"],
}
#: The same for a setting of one name in every section that has it. A plugin's
#: ``tool_version`` is a PEP 440 specifier set, and ASH resets any other value to the
#: default from every source, an operator's file included. Planting a plain name would
#: read as a rule a repository's file is held to, which it is not.
PROBE_VALUES_BY_KEY: dict[str, list[Any]] = {"tool_version": [">=0.1.0"]}
MAX_ROUNDS = 6


def special_leaves() -> dict[str, list[Any]]:
    """The settings the generic planting cannot make a value for, with the values to
    plant. A staleness entry names a database ASH declares and its own expiry, which
    ASH judges against the clock, so the date is far in the future."""
    from automated_security_helper.utils.content_databases import CONTENT_DATABASES

    database = CONTENT_DATABASES[0].name
    overrides = [
        [
            {
                "database": database,
                "policy": policy,
                "expiration": "2099-01-01",
                "reason": "probe",
            }
        ]
        for policy in ("warn", "fail")
    ]
    return {**PROBE_VALUES, "content_db_staleness_overrides": overrides}


class ControlRefused(ProjectionError):
    """The plain value of a probe's control document was refused, so what the
    document with a reference in its place says proves nothing."""


class Reference(str):
    """A scalar written as it is, unquoted: an environment reference."""

    __slots__ = ()


def yaml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)


def yaml_scalar(value: Any) -> str:
    if isinstance(value, Reference):
        return str(value)
    return json.dumps(value)


def yaml_text(document: Mapping[str, Any], indent: int = 0) -> str:
    """A document as YAML: mappings as blocks, every other value as JSON, which YAML
    reads. Only a Reference is written as a plain scalar, as ASH resolves one only
    there."""
    lines = []
    for key, value in document.items():
        pad = "  " * indent
        if isinstance(value, Mapping) and value:
            lines.append(f"{pad}{yaml_key(key)}:")
            lines.append(yaml_text(value, indent + 1).rstrip("\n"))
        else:
            lines.append(f"{pad}{yaml_key(key)}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def plant(
    fields: Mapping[str, Mapping[str, Any]], path: str, value: Any
) -> dict[str, Any] | None:
    """The document that sets ``path`` to ``value``, or None when the path runs
    through a list."""
    document: dict[str, Any] = {}
    node = document
    segments = path.split(".")
    for index, segment in enumerate(segments):
        if segment.endswith("[]"):
            return None
        name = segment.removesuffix("{}")
        last = index == len(segments) - 1
        if segment.endswith("{}"):
            owner = ".".join([*segments[:index], name])
            enum = fields[owner].get("mapKeys", {}).get("enum")
            holder = node.setdefault(name, {})
            key = enum[0] if enum else "probe-key"
            if last:
                holder[key] = value
            else:
                node = holder.setdefault(key, {})
        elif last:
            node[name] = value
        else:
            node = node.setdefault(name, {})
    return document


def merge_documents(into: dict[str, Any], other: Mapping[str, Any]) -> dict[str, Any]:
    for key, value in other.items():
        if isinstance(value, dict) and isinstance(into.get(key), dict):
            merge_documents(into[key], value)
        else:
            into[key] = copy.deepcopy(value)
    return into


def normal(value: Any) -> Any:
    """A value as JSON would hold it, so that a loaded value can be compared with a
    planted one."""
    value = getattr(value, "value", value)
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, (list, tuple)):
        return [normal(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): normal(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        return normal(value.model_dump())
    return value


def check_host(workdir: Path, fields: Mapping[str, Mapping[str, Any]]) -> None:
    """Stop, saying why, when this host would put its own answers in a probe: it is
    Windows, the probe's directory is where ASH keeps an MCP client's files or sits
    in a git checkout (so ASH would not read it as a repository's own file), or ASH
    was imported with an environment that moved its defaults."""
    if platform.system() == "Windows":
        raise ProjectionError(
            "the trust probe measures ASH on the build host and needs Linux or macOS"
        )
    resolved = Path(workdir).resolve()
    cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    mcp_root = (Path(cache) / "ash-mcp").resolve()
    if resolved == mcp_root or mcp_root in resolved.parents:
        raise ProjectionError(f"{resolved} is inside ASH's MCP workspace root")
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            raise ProjectionError(
                f"{resolved} is inside the git checkout at {parent}: point TMPDIR "
                "outside every checkout, or ASH reads the probe's files as the operator's"
            )
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.config_trust import value_at

    config = AshConfig()
    for path, host in HOST_DEFAULTS.items():
        shipped = fields[path].get("default")
        if normal(value_at(config, path)) != shipped:
            raise ProjectionError(
                f"ASH's default for {path} is {normal(value_at(config, path))!r} on this "
                f"host and the schema's is {shipped!r}: it depends on {host['name']}, "
                "which was set when ASH was imported, or on the platform"
            )


@contextlib.contextmanager
def pinned_host(
    workdir: Path, fields: Mapping[str, Mapping[str, Any]]
) -> Iterator[None]:
    saved = {
        name: os.environ.pop(name) for name in PINNED_ENVIRONMENT if name in os.environ
    }
    try:
        check_host(workdir, fields)
        yield
    finally:
        os.environ.update(saved)


def valid_value(field: Mapping[str, Any]) -> Any:
    """A value the field takes as a plain value."""
    kind, bounds = field["kind"], field.get("bounds", {})
    if kind == "boolean":
        return True
    if kind in ("integer", "number"):
        if "minimum" in bounds:
            return bounds["minimum"]
        if "exclusiveMinimum" in bounds:
            return bounds["exclusiveMinimum"] + 1
        return 1
    if kind == "enum":
        return field["enum"][0]
    pattern = field.get("patternRef")
    if pattern:
        if pattern not in PATTERN_SAMPLES:
            raise ProjectionError(
                f"{field['path']}: no sample value matches {pattern!r}"
            )
        return PATTERN_SAMPLES[pattern]
    return "probe-name"


def representative(field: Mapping[str, Any], name: str, location: str) -> bool:
    path = field["path"]
    return (
        not field["hidden"]
        and "[]" not in path
        and class_of(field["kind"], field.get("patternRef")) == name
        and location_of(path) == location
    )


def load_config_file(path: Path) -> Any:
    """Load a config file the way a scan does: ASH's file-load route."""
    from automated_security_helper.config.config_sources import (
        load_config_with_references,
    )

    return load_config_with_references(Path(path))


def reference_accepted(
    fields: Mapping[str, Mapping[str, Any]],
    path: str,
    workdir: Path,
    load: Any = load_config_file,
) -> bool:
    """Whether ``load`` takes ``${VAR:default}`` written as the value of ``path``.

    The default is a value the field takes, with the variable unset, so a refusal
    is the field's and not the variable's. A control document with the plain value
    must load, or the answer proves nothing and the build stops.
    """
    field = fields[path]
    value = valid_value(field)
    text = str(value).lower() if isinstance(value, bool) else str(value)
    reference = Reference("${" + ENV_PROBE_VARIABLE + ":" + text + "}")
    where = Path(workdir) / "probe-reference.yaml"
    where.write_text(yaml_text(plant(fields, path, value) or {}), encoding="utf-8")
    try:
        load(where)
    except Exception as error:
        raise ControlRefused(
            f"{path}: the control document was refused: {type(error).__name__}: "
            f"{str(error)[:200]}"
        ) from None
    where.write_text(yaml_text(plant(fields, path, reference) or {}), encoding="utf-8")
    try:
        load(where)
    except Exception:
        return False
    return True


def probe_env(
    fields: Mapping[str, Mapping[str, Any]], workdir: Path, load: Any = load_config_file
) -> dict[str, dict[str, bool]]:
    """Whether ASH accepts a reference, per class of setting, at the top level and in
    a section, on the route that loads a config file. A setting whose control
    document is refused is passed over for the next of its class; a cell with no
    setting left takes the other location's answer."""
    found: dict[tuple[str, str], bool] = {}
    passed_over: list[str] = []
    for name in ENV_CLASSES:
        for location in LOCATIONS:
            for path, field in fields.items():
                if not representative(field, name, location):
                    continue
                try:
                    found[(name, location)] = reference_accepted(
                        fields, path, workdir, load
                    )
                except ControlRefused as error:
                    passed_over.append(str(error))
                    continue
                break
    classes: dict[str, dict[str, bool]] = {}
    for name in ENV_CLASSES:
        row = {}
        for location, other in (("topLevel", "section"), ("section", "topLevel")):
            answer = found.get((name, location), found.get((name, other)))
            if answer is None:
                raise ProjectionError(
                    f"no {name} setting of the schema loads as a plain value, so a "
                    "reference to it cannot be probed; passed over: "
                    + "; ".join(passed_over[:5])
                )
            row[location] = answer
        classes[name] = row
    return classes


# --- The trust probe ---------------------------------------------------------------


def candidate_values(field: Mapping[str, Any]) -> list[Any]:
    """Values to plant for a setting, each of a class a rule may treat differently."""
    kind, default = field["kind"], field.get("default")
    bounds = field.get("bounds", {})
    if kind == "boolean":
        return [not bool(default)]
    if kind in ("integer", "number"):
        base = (
            default
            if isinstance(default, (int, float)) and not isinstance(default, bool)
            else bounds.get("minimum", 1)
        )
        low = bounds.get(
            "minimum",
            bounds.get("exclusiveMinimum", base - 1)
            + (0 if "minimum" in bounds else 1),
        )
        values = [base + 1]
        if base - 1 >= low:
            values.append(base - 1)
        return [value for value in values if bounds.get("maximum", value) >= value]
    if kind == "enum":
        return [value for value in field["enum"] if value != default][:3]
    if kind == "string":
        if field["key"] in PROBE_VALUES_BY_KEY:
            return list(PROBE_VALUES_BY_KEY[field["key"]])
        return [] if field.get("patternRef") else ["probe-name", "/probe/path"]
    if kind == "stringList":
        return [["probe-name"]]
    if kind == "enumList":
        return [[value] for value in field["enum"][:1] if [value] != default]
    return []


def probe_excluded(path: str) -> bool:
    """Whether the probe leaves a setting, or a setting inside it, to the table."""
    return any(path == name or path.startswith(name + ".") for name in PROBE_EXCLUDED)


def probe_leaves(fields: Mapping[str, Mapping[str, Any]]) -> dict[str, list[Any]]:
    """Every setting the probe plants, with the values it plants."""
    leaves: dict[str, list[Any]] = {}
    for path, field in fields.items():
        if "[]" in path or "{}" in path or field["hidden"]:
            continue
        if probe_excluded(path):
            continue
        values = candidate_values(field)
        if values:
            leaves[path] = values[:MAX_ROUNDS]
    for path, values in special_leaves().items():
        if path in fields:
            leaves[path] = values
    return leaves


def unplanted_settings(
    fields: Mapping[str, Mapping[str, Any]],
    planted: Mapping[str, Any] | None = None,
) -> list[str]:
    """The published settings the probe plants no value for and does not leave to the
    table: a list of objects, a raw mapping, a list that holds its own default, a string
    that ASH checks against a vocabulary the probe does not know. The probe cannot say
    what a load does with them, so the report lists them, and a setting that joins the
    list is a setting someone decides about."""
    planted = probe_leaves(fields) if planted is None else planted
    return sorted(
        path
        for path, field in fields.items()
        if "[]" not in path
        and "{}" not in path
        and not field["hidden"]
        and field["kind"] not in ("object", "section")
        and path not in planted
        and not probe_excluded(path)
    )


def load_repository_file(
    workdir: Path, document: Mapping[str, Any]
) -> tuple[Any, list[Any]]:
    """Load a planted ``.ash.yaml`` as a scan loads a repository's own file: the file
    is in a directory that is the scanned root, and ASH reads where it is."""
    from automated_security_helper.config.resolve_config import resolve_config

    repository = Path(workdir) / "repository"
    repository.mkdir(exist_ok=True)
    path = repository / ".ash.yaml"
    path.write_text(yaml_text(document), encoding="utf-8")
    out: list[Any] = []
    config = resolve_config(
        config_path=path,
        source_dir=repository,
        scanned_root=repository,
        fallback_to_default=False,
        repository_out=out,
    )
    return config, out


def ignored_paths(out: list[Any]) -> set[str]:
    """The settings the operator-only strip left out of the planted file."""
    paths: set[str] = set()
    for settings in out:
        for kind, _plugin, key, option, _value in getattr(settings, "found", []):
            paths.add(f"{kind}.{key}.options.{option}")
        for name in getattr(settings, "selection_written", {}):
            paths.add(f"default_scanners.{name}")
    return paths


def holds(planted: Any, loaded: Any) -> bool:
    """Whether the loaded value holds what was planted. A model comes back with its
    defaults filled in, and a list can come back with other entries beside the
    planted one, so a mapping needs the planted keys and a list the planted items."""
    if isinstance(planted, dict):
        return isinstance(loaded, dict) and all(
            key in loaded and holds(value, loaded[key])
            for key, value in planted.items()
        )
    if isinstance(planted, list):
        return isinstance(loaded, list) and all(
            any(holds(item, other) for other in loaded) for item in planted
        )
    return bool(planted == loaded)


def read_back(
    config: Any,
    out: list[Any],
    planted: Mapping[str, Any],
    defaults: Any,
) -> dict[str, str]:
    """Per planted setting, what the load did: kept, replaced (by the trusted value),
    ignored (left out of the file) or other (neither value: the probe cannot say)."""
    from automated_security_helper.utils.config_trust import value_at

    stripped = ignored_paths(out)
    result = {}
    for path, value in planted.items():
        if path in stripped:
            result[path] = "ignored"
            continue
        loaded = normal(value_at(config, path))
        trusted = normal(value_at(defaults, path))
        if holds(normal(value), loaded):
            result[path] = "kept"
        elif loaded == trusted:
            result[path] = "replaced"
        else:
            result[path] = "other"
    return result


#: A run of separators between the parts of a path, written either way.
_PATH_SEPARATORS = r"[\\/]+"


def failure_text(error: Exception, workdir: Path) -> str:
    """What a refused load said, without the directory of the planted file: that
    directory belongs to this build, and the reason is what a reader needs.

    The directory is found whichever separator the message writes between its
    parts. A path printed on Windows can hold backslashes and slashes together,
    for example when a message joins a file name to a directory with a slash.
    """
    parts = re.split(_PATH_SEPARATORS, str(Path(workdir) / "repository"))
    directory = re.compile(_PATH_SEPARATORS.join(re.escape(part) for part in parts))
    text = directory.sub("<repository>", str(error))
    return f"{type(error).__name__}: {text}"[:300]


def probe_round(
    fields: Mapping[str, Mapping[str, Any]],
    workdir: Path,
    planted: Mapping[str, Any],
    defaults: Any,
    unprobed: dict[str, str],
) -> dict[str, str]:
    """One load of a document holding every planted setting. When ASH refuses the
    whole document, each section's settings are loaded alone, then each setting."""

    def attempt(batch: Mapping[str, Any]) -> dict[str, str] | None:
        document: dict[str, Any] = {}
        for path, value in batch.items():
            merge_documents(document, plant(fields, path, value) or {})
        try:
            config, out = load_repository_file(workdir, document)
        except Exception as error:
            if len(batch) == 1:
                unprobed[next(iter(batch))] = failure_text(error, workdir)
            return None
        return read_back(config, out, batch, defaults)

    result = attempt(planted)
    if result is not None:
        return result
    result = {}
    sections: dict[str, dict[str, Any]] = {}
    for path, value in planted.items():
        sections.setdefault(".".join(path.split(".")[:2]), {})[path] = value
    for batch in sections.values():
        got = attempt(batch)
        if got is None:
            for path, value in batch.items():
                got = attempt({path: value})
                result.update(got or {})
        else:
            result.update(got)
    return result


def describe_kept(
    field: Mapping[str, Any], value: Any, replaced: Iterable[Any] = ()
) -> str:
    """What kind of value a repository's file may keep, in words for the badge.
    ``replaced`` are the values planted for the same setting that ASH did not keep:
    a list of entries is described by what its kept entry has that those lack."""
    kind, default = field["kind"], field.get("default")
    if kind in ("boolean", "enum"):
        return json.dumps(value) if kind == "boolean" else str(value)
    if kind in ("integer", "number"):
        below = default is not None and value < default
        return (
            "a value at or below the operator's"
            if below
            else "a value at or above the operator's"
        )
    if isinstance(value, list) and value and isinstance(value[0], dict):
        others = [item[0] for item in replaced if item and isinstance(item[0], dict)]
        different = [
            f"{name} {setting}"
            for name, setting in value[0].items()
            if all(other.get(name) != setting for other in others)
        ]
        return "an entry with " + " and ".join(different or ["these values"])
    if isinstance(value, list):
        return "a list of plain names"
    return "a path" if str(value).startswith("/") else "a plain name"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def matches(pattern: str, path: str) -> bool:
    """Whether a rule's path pattern names the field's path: ``*`` is one segment."""
    shape, real = pattern.split("."), path.split(".")
    return len(shape) == len(real) and all(a in ("*", b) for a, b in zip(shape, real))


def rules_from_outcomes(
    fields: Mapping[str, Mapping[str, Any]],
    outcomes: Mapping[str, list[tuple[Any, str]]],
    source: str,
) -> list[dict[str, Any]]:
    """Trust rules from what the probe saw, one per setting-name and behavior."""
    groups: dict[tuple[str, str, tuple[str, ...], str], list[str]] = {}
    for path, seen in outcomes.items():
        if all(outcome == "kept" for _, outcome in seen):
            continue
        field = fields[path]
        replaced = [value for value, outcome in seen if outcome != "kept"]
        kept = [
            describe_kept(field, value, replaced)
            for value, outcome in seen
            if outcome == "kept"
        ]
        kept = list(dict.fromkeys(kept))
        stripped = any(outcome == "ignored" for _, outcome in seen)
        if stripped:
            instead = "the key is left out of the file before it is read; the operator's value, or ASH's default, applies"
        else:
            instead = (
                "the operator's value, or ASH's default where the operator sets none"
            )
        parts = path.split(".")
        name = field["key"] if len(parts) >= 4 and parts[2] == "options" else path
        rule = "limited" if kept and not stripped else "ignored"
        groups.setdefault((name, rule, tuple(kept), instead), []).append(path)
    rules: list[dict[str, Any]] = []
    used: set[str] = set()
    for (name, rule, kept, instead), paths in sorted(groups.items()):
        # A rule about one section's option says which section; one about the same
        # option in many sections is named by the option alone.
        sections = {".".join(path.split(".")[:2]) for path in paths}
        ident = slug(name)
        if (
            "." not in name
            and len(sections) == 1
            and all(p.split(".")[0] in SEGMENTS for p in paths)
        ):
            ident = slug(f"{next(iter(sections)).split('.')[1]}-{name}")
        while ident in used:
            ident += "-2"
        used.add(ident)
        rules.append(
            {
                "id": ident,
                "paths": wildcard_paths(fields, paths),
                "rule": rule,
                "keep": list(kept),
                "instead": instead,
                "appliesAt": "load",
                "via": "probe",
                "source": source,
            }
        )
    return rules


def wildcard_paths(
    fields: Mapping[str, Mapping[str, Any]], paths: list[str]
) -> list[str]:
    """The paths of a rule, written ``<kind>.*.options.<key>`` when the rule covers
    every setting of that name in every section of the kind."""
    covered: set[str] = set(paths)
    result: list[str] = []
    done: set[str] = set()
    for path in sorted(paths):
        parts = path.split(".")
        if len(parts) == 4 and parts[0] in SEGMENTS and parts[2] == "options":
            pattern = f"{parts[0]}.*.options.{parts[3]}"
            every = {p for p in fields if matches(pattern, p)}
            if every <= covered and len(every) > 1:
                if pattern not in done:
                    done.add(pattern)
                    result.append(pattern)
                continue
        result.append(path)
    return result


def probe_trust(
    fields: Mapping[str, Mapping[str, Any]], workdir: Path
) -> dict[str, Any]:
    """Load planted repository files through ``resolve_config`` and read back what
    ASH kept, replaced or ignored, setting by setting."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import resolve_config

    started = time.monotonic()
    defaults = AshConfig()
    leaves = probe_leaves(fields)
    unprobed: dict[str, str] = {}
    outcomes: dict[str, list[tuple[Any, str]]] = {path: [] for path in leaves}
    loads = 0
    for step in range(max(len(values) for values in leaves.values())):
        planted = {
            path: values[step] for path, values in leaves.items() if step < len(values)
        }
        for path, outcome in probe_round(
            fields, workdir, planted, defaults, unprobed
        ).items():
            outcomes[path].append((planted[path], outcome))
        loads += 1
    unsure = {
        path
        for path, seen in outcomes.items()
        if any(outcome == "other" for _, outcome in seen)
    }
    for path in sorted(unsure):
        unprobed[path] = (
            "the loaded value is neither the planted one nor the trusted one"
        )
    seen = {
        path: seen for path, seen in outcomes.items() if seen and path not in unsure
    }
    return {
        "rules": rules_from_outcomes(fields, seen, source_range(resolve_config)),
        "outcomes": {
            path: [outcome for _, outcome in seen] for path, seen in seen.items()
        },
        "unprobed": unprobed,
        "unplanted": unplanted_settings(fields, leaves),
        "rounds": loads,
        "seconds": time.monotonic() - started,
    }


# --- The pinned table of the rules a load cannot show ------------------------------


class Row(NamedTuple):
    """One rule ASH applies somewhere a load of a repository's file does not show,
    kept here by hand and pinned to ASH's code by the unit tests.

    ``function`` is the qualified name of the function in ``file`` that applies the
    rule, and ``needle`` a literal that must be inside it: a rename or a move stops
    the build, naming the row, and so does a literal that is gone.

    ``paths`` is empty for a rule about something no published setting names, such as
    the content of a baseline file or what a plugin module declares. The data block
    carries no rule for such a row, since the editor has no field to show it on, but
    the tests pin its function and its literal like any other row's.
    """

    ident: str
    paths: tuple[str, ...]
    rule: str
    keep: tuple[str, ...]
    instead: str
    applies_at: str
    file: str
    function: str
    needle: str


_SCANNERS = "automated_security_helper/plugin_modules/ash_builtin/scanners/"
_PLUGINS = "automated_security_helper/plugin_modules/"
_OPERATOR = ("a value equal to the operator's",)
_OFF = ("false",)


def trust_table() -> list[Row]:
    """The rules that a load of a repository's file does not show, one row each."""
    from automated_security_helper.config.plugin_module_trust import (
        OFF_HOST_PLUGIN_PACKAGES,
    )
    from automated_security_helper.config.reporter_trust import (
        REPORTER_ENABLED_DEFAULTS,
    )

    off_host = ", ".join(sorted(OFF_HOST_PLUGIN_PACKAGES))
    return [
        Row(
            "plugin-modules",
            ("ash_plugin_modules",),
            "limited",
            (
                "ASH's own package",
                "a module installed outside the scanned tree and every checkout",
                (
                    f"a package that sends data off the host ({off_host}) only when "
                    "the operator's list names it"
                ),
            ),
            "the entry is dropped",
            "load",
            "automated_security_helper/config/plugin_module_trust.py",
            "confine_plugin_modules",
            "refusal_reason(",
        ),
        Row(
            "sandbox-mode",
            ("sandbox.mode",),
            "limited",
            ("a sandbox mode, when no setting of the operator turns the sandbox on",),
            "the operator's mode, when the operator's settings turn the sandbox on",
            "load",
            "automated_security_helper/config/sandbox_grants.py",
            "confine_sandbox_grants",
            "sandbox.mode = trusted.mode",
        ),
        Row(
            "sandbox-network-scanners",
            ("sandbox.network_scanners",),
            "limited",
            ("a list, which takes the network from each scanner it does not name",),
            (
                "the operator's list gives a scanner its network; a repository's "
                "list only takes it away"
            ),
            "load",
            "automated_security_helper/config/sandbox_grants.py",
            "confine_sandbox_grants",
            "sandbox.network_limit = ",
        ),
        Row(
            "detect-secrets-scan-settings",
            ("scanners.detect-secrets.options.scan_settings",),
            "limited",
            ("plugins and filters named by a module, not the verification filter",),
            (
                "the verification filter and each plugin or filter that names a file "
                "are left out, unless the operator's own settings name them"
            ),
            "load",
            "automated_security_helper/config/secret_verification_trust.py",
            "confine_detect_secrets_settings",
            "drop_untrusted_entries(",
        ),
        Row(
            "detect-secrets-baseline-settings",
            (),
            "limited",
            ("plugins and filters named by a module, not the verification filter",),
            (
                "a baseline file that is not the operator's loses its verification "
                "filter and each plugin or filter that names a file"
            ),
            "scanner",
            _SCANNERS + "detect_secrets_scanner.py",
            "DetectSecretsScanner._apply_settings_trust",
            "keep_verification=False",
        ),
        Row(
            "off-host-reporters",
            tuple(f"reporters.{name}" for name in sorted(REPORTER_ENABLED_DEFAULTS)),
            "operatorSection",
            (),
            "the operator's whole section is used, enabled and every option",
            "report",
            "automated_security_helper/config/operator_only_options.py",
            "reporter_section",
            "_operator_reporters",
        ),
        Row(
            "plugin-reporter-destinations",
            (),
            "ignored",
            (),
            (
                "a reporter that a plugin module adds has the options it declares as "
                "destinations, and its enabled switch, set from the operator's settings"
            ),
            "plugin",
            "automated_security_helper/config/reporter_trust.py",
            "confine_declared_reporter_destinations",
            "declared_destination_options(",
        ),
        Row(
            "zizmor-online-audits",
            ("scanners.zizmor.options.online_audits",),
            "limited",
            _OFF,
            "zizmor runs offline, without the GitHub token",
            "scanner",
            _SCANNERS + "zizmor_scanner.py",
            "ZizmorScanner._online",
            "scanners.zizmor.options.online_audits",
        ),
        Row(
            "zizmor-honor-inline-ignores",
            ("scanners.zizmor.options.honor_inline_ignores",),
            "limited",
            _OFF,
            "zizmor ignores a workflow's own ignore comments",
            "scanner",
            _SCANNERS + "zizmor_scanner.py",
            "ZizmorScanner._honor_inline_ignores",
            "scanners.zizmor.options.honor_inline_ignores",
        ),
        Row(
            "gitleaks-honor-inline-ignores",
            ("scanners.gitleaks.options.honor_inline_ignores",),
            "limited",
            _OFF,
            "gitleaks ignores inline allow comments",
            "scanner",
            _SCANNERS + "gitleaks_scanner.py",
            "GitleaksScanner._honor_inline_ignores",
            "scanners.gitleaks.options.honor_inline_ignores",
        ),
        Row(
            "gitleaks-max-target-megabytes",
            ("scanners.gitleaks.options.max_target_megabytes",),
            "limited",
            ("unset",),
            "gitleaks scans files of every size",
            "scanner",
            _SCANNERS + "gitleaks_scanner.py",
            "GitleaksScanner._max_target_megabytes",
            "scanners.gitleaks.options.max_target_megabytes",
        ),
        Row(
            "cfn-lint-honor-inline-ignores",
            ("scanners.cfn-lint.options.honor_inline_ignores",),
            "limited",
            _OFF,
            "a template's own ignore comments do not apply",
            "scanner",
            _SCANNERS + "cfn_lint_scanner.py",
            "CfnLintScanner._honor_inline_ignores",
            "scanners.cfn-lint.options.honor_inline_ignores",
        ),
        Row(
            "cfn-lint-operator-choices",
            (
                "scanners.cfn-lint.options.ignore_checks",
                "scanners.cfn-lint.options.regions",
            ),
            "limited",
            _OPERATOR,
            "the operator's value, or the option's default",
            "scanner",
            _SCANNERS + "cfn_lint_scanner.py",
            "CfnLintScanner._operator_option",
            "scanners.cfn-lint.options.{name}",
        ),
        Row(
            "cfn-guard-rule-sets",
            ("scanners.cfn-guard.options.rule_sets",),
            "limited",
            _OPERATOR,
            "the operator's rule sets, or ASH's default rule set",
            "scanner",
            _SCANNERS + "cfn_guard_scanner.py",
            "CfnGuardScanner._operator_rule_sets",
            "scanners.cfn-guard.options.rule_sets",
        ),
        Row(
            "trivy-scanners",
            ("scanners.trivy.options.scanners",),
            "limited",
            ("the default set",),
            "the default set of scanners",
            "scanner",
            _SCANNERS + "trivy_scanner.py",
            "TrivyScanner._honor_scanner_set",
            "scanners.trivy.options.scanners",
        ),
        Row(
            "actionlint-integrations",
            (
                "scanners.actionlint.options.shellcheck",
                "scanners.actionlint.options.pyflakes",
            ),
            "limited",
            ("the program's own name", "an empty value"),
            "that integration is off",
            "scanner",
            _SCANNERS + "actionlint_scanner.py",
            "ActionlintScanner._integration_executable",
            "scanners.actionlint.options.{flag}",
        ),
        Row(
            "betterleaks-honor-inline-ignores",
            ("scanners.betterleaks.options.honor_inline_ignores",),
            "limited",
            _OFF,
            "betterleaks keeps its safe default, false",
            "scanner",
            _PLUGINS + "ash_betterleaks_plugins/betterleaks_scanner.py",
            "BetterleaksScanner._honor_inline_ignores",
            "scanners.betterleaks.options.honor_inline_ignores",
        ),
        Row(
            "betterleaks-honor-tree-ignore-files",
            ("scanners.betterleaks.options.honor_tree_ignore_files",),
            "limited",
            _OFF,
            "betterleaks keeps its safe default, false",
            "scanner",
            _PLUGINS + "ash_betterleaks_plugins/betterleaks_scanner.py",
            "BetterleaksScanner._honor_tree_ignore_files",
            "scanners.betterleaks.options.honor_tree_ignore_files",
        ),
        Row(
            "guarddog-max-hits",
            ("scanners.guarddog.options.max_hits",),
            "limited",
            ("a limit that only raises a rule's own limit",),
            "each rule keeps the larger of its own limit and the value",
            "scanner",
            _PLUGINS + "ash_guarddog_plugins/guarddog_scanner.py",
            "GuardDogScanner._hit_limit",
            "set_by_operator(",
        ),
        Row(
            "tool-config-paths",
            (
                "scanners.actionlint.options.config_file",
                "scanners.cfn-guard.options.rules_paths",
                "scanners.cfn-lint.options.config_file",
                "scanners.gitleaks.options.config_file",
                "scanners.gitleaks.options.baseline_path",
                "scanners.zizmor.options.config_file",
                "scanners.hadolint.options.config_file",
                "scanners.betterleaks.options.config_file",
                "scanners.trivy.options.config_file",
                "scanners.trivy.options.ignore_file",
                "scanners.trivy.options.secret_config_file",
                "scanners.trivy-repo.options.config_file",
                "scanners.trivy-repo.options.ignore_file",
                "scanners.trivy-repo.options.secret_config_file",
                "scanners.trivy-repo.options.module_dir",
            ),
            "ignored",
            (),
            "the scanner runs without it, with ASH's own empty file, or with the operator's",
            "scanner",
            "automated_security_helper/utils/config_trust.py",
            "operator_path",
            "set_by_operator(config, key, value)",
        ),
        Row(
            "tool-path-location",
            (
                "scanners.checkov.options.config_file",
                "scanners.syft.options.config_file",
                "scanners.ferret-scan.options.config_file",
                "scanners.syft.options.sdist_harvest.cache_dir",
                "scanners.opengrep.options.config",
                "scanners.semgrep.options.config",
            ),
            "limited",
            ("a path outside every git checkout and the scanned directory",),
            "the tool runs without it, or with ASH's own default",
            "scanner",
            "automated_security_helper/config/path_trust.py",
            "honored_path",
            "from outside every git checkout",
        ),
    ]


def find_function(
    tree: ast.Module, qualified: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The function ``Class.method`` or ``name`` names in a module, or None."""
    body: list[ast.stmt] = tree.body
    parts = qualified.split(".")
    for index, name in enumerate(parts):
        last = index == len(parts) - 1
        kinds = (ast.FunctionDef, ast.AsyncFunctionDef) if last else (ast.ClassDef,)
        node = next(
            (item for item in body if isinstance(item, kinds) and item.name == name),
            None,
        )
        if node is None:
            return None
        if last:
            return node  # type: ignore[return-value]
        body = node.body
    return None


def locate(row: Row) -> str:
    """``path:first-last`` of the function in ASH that applies the row's rule. A
    function that is gone, or one that no longer holds the row's literal, stops the
    build and names the row."""
    text = (package_parent() / row.file).read_text(encoding="utf-8")
    node = find_function(ast.parse(text), row.function)
    if node is None:
        raise ProjectionError(f"{row.ident}: {row.file} has no function {row.function}")
    first, last = node.lineno, node.end_lineno or node.lineno
    source = "\n".join(text.splitlines()[first - 1 : last])
    if row.needle not in source:
        raise ProjectionError(
            f"{row.ident}: {row.function} in {row.file} no longer holds {row.needle!r}"
        )
    return f"{row.file}:{first}-{last}"


def table_rules(
    fields: Mapping[str, Mapping[str, Any]], rows: list[Row], claimed: set[str]
) -> list[dict[str, Any]]:
    """The table's rows that name a setting of the schema no probe rule covers. A
    row for a plugin the schema does not publish has no field to attach to, and
    stays in the table."""
    rules = []
    for row in rows:
        paths = [
            path
            for path in row.paths
            if any(matches(path, other) and other not in claimed for other in fields)
        ]
        if not paths:
            continue
        rules.append(
            {
                "id": row.ident,
                "paths": paths,
                "rule": row.rule,
                "keep": list(row.keep),
                "instead": row.instead,
                "appliesAt": row.applies_at,
                "via": "table",
                "source": locate(row),
            }
        )
        claimed.update(
            other for path in paths for other in fields if matches(path, other)
        )
    return rules


def attach_trust(
    fields: dict[str, dict[str, Any]], rules: list[dict[str, Any]]
) -> None:
    """Name each field's rule on the field: the first rule that covers it."""
    for rule in rules:
        for path, field in fields.items():
            if "trust" not in field and any(matches(p, path) for p in rule["paths"]):
                field["trust"] = rule["id"]


# --- Assembling and checking the block ---------------------------------------------


def internal_section_fields() -> dict[str, list[str]]:
    from automated_security_helper.utils.unknown_keys import INTERNAL_SECTION_FIELDS

    return {kind: sorted(INTERNAL_SECTION_FIELDS[kind]) for kind in SEGMENTS}


def build_block(
    root: Path,
    version: str,
    workdir: Path | None = None,
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The editor's data block for the checkout at ``root``. ``report`` collects what
    the probes measured (the unit tests and the build log read it)."""
    root = Path(root)
    schema, digest = read_schema(root)
    validation = build_validation_schema(schema)
    anchors = reference_anchors(root)
    constants = ash_constants()
    common: dict[str, Any] = {
        "internal_fields": internal_section_fields(),
        "deprecated": DEPRECATED_RENAMES,
        "anchors": anchors,
    }
    unknown = {name: {"topLevel": False, "section": False} for name in ENV_CLASSES}
    first = project_fields(schema, validation, env_classes=unknown, **common)
    with contextlib.ExitStack() as stack:
        if workdir is None:
            workdir = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="ash-config-editor-")
                )
            )
        stack.enter_context(pinned_host(workdir, first))
        classes = probe_env(first, workdir)
        probe = probe_trust(first, workdir)
    fields = project_fields(schema, validation, env_classes=classes, **common)
    rows = trust_table()
    claimed: set[str] = set()
    rules = probe["rules"]
    for rule in rules:
        claimed.update(
            path for path in fields if any(matches(p, path) for p in rule["paths"])
        )
    rules = [*rules, *table_rules(fields, rows, claimed)]
    attach_trust(fields, rules)
    data = plugin_data(root)
    sections, opt_in = build_sections_and_opt_in(fields, data, anchors)
    block = {
        "contract": CONTRACT,
        "source": {
            "schemaPath": SCHEMA_PATH,
            "schemaSha256": digest,
            "ashVersion": ash_version(),
            "docsVersion": version,
            "generator": GENERATOR,
        },
        "validationSchema": validation,
        "fields": fields,
        "groups": group_list(),
        "sections": sections,
        "optIn": opt_in,
        "trust": rules,
        "env": environment_rule(),
        "envProbe": {"route": "file-load", "classes": classes},
        "constants": constants,
        "patterns": pattern_table(validation),
        "spelling": spelling_data(published_sections(fields)),
    }
    problems = check_block(block, digest)
    if problems:
        raise ProjectionError(
            "the editor's data block is not sound:\n  " + "\n  ".join(problems)
        )
    if report is not None:
        report.update(probe=probe, classes=classes, rows=[row.ident for row in rows])
    return block


def ash_version() -> str:
    from automated_security_helper.utils.get_ash_version import get_ash_version

    return str(get_ash_version())


def check_block(block: Mapping[str, Any], digest: str | None = None) -> list[str]:
    """What is wrong with a block, as sentences: it does not fit the contract's
    schema, its sha256 is not the file's, a pointer does not resolve, a group rule,
    a trust rule or the pattern set does not hold, or it is over the size ceiling."""
    import jsonschema

    problems: list[str] = []
    validator = jsonschema.Draft202012Validator(BLOCK_SCHEMA)
    for error in sorted(
        validator.iter_errors(block), key=lambda e: list(map(str, e.path))
    )[:10]:
        where = "/".join(str(part) for part in error.path) or "the block"
        problems.append(
            f"the block does not fit its schema at {where}: {error.message[:160]}"
        )
    if problems:
        return problems
    if digest is not None and block["source"]["schemaSha256"] != digest:
        problems.append("source.schemaSha256 is not the sha256 of the schema file")
    fields = block["fields"]
    for path, field in fields.items():
        if pointer_get(block["validationSchema"], field["schemaPointer"]) is _MISSING:
            problems.append(
                f"{path}: schemaPointer {field['schemaPointer']} does not resolve"
            )
    problems.extend(group_problems(block))
    problems.extend(trust_problems(block))
    patterns = set(collect_patterns(block["validationSchema"]))
    if patterns != set(block["patterns"]):
        problems.append(
            f"patterns {sorted(patterns ^ set(block['patterns']))} are in the schema or the table but not both"
        )
    size = len(serialize_block(block).encode("utf-8"))
    if size > SIZE_CEILING:
        parts = sorted(
            (len(serialize_block({name: value}).encode("utf-8")), name)
            for name, value in block.items()
        )[-4:]
        largest = ", ".join(f"{name} {count}" for count, name in reversed(parts))
        problems.append(
            f"the block is {size} bytes, over the ceiling of {SIZE_CEILING} "
            f"(largest parts: {largest})"
        )
    return problems


def group_problems(block: Mapping[str, Any]) -> list[str]:
    fields = block["fields"]
    expected = {
        path
        for path in fields
        if re.fullmatch(r"[^.\[\]{}]+", path) and path != "global_settings"
    } | {
        path
        for path in fields
        if path.startswith("global_settings.")
        and re.fullmatch(r"[^.\[\]{}]+\.[^.\[\]{}]+", path)
    }
    placed: dict[str, int] = {}
    for group in block["groups"]:
        for path in group["paths"]:
            placed[path] = placed.get(path, 0) + 1
    problems = [f"{path} is in no group" for path in sorted(expected - set(placed))]
    problems += [
        f"{path} is in {n} groups" for path, n in sorted(placed.items()) if n != 1
    ]
    problems += [
        f"group path {path} is no setting" for path in sorted(set(placed) - set(fields))
    ]
    return problems


def trust_problems(block: Mapping[str, Any]) -> list[str]:
    ids = [rule["id"] for rule in block["trust"]]
    problems = [
        f"trust id {ident} is used twice"
        for ident in sorted(set(ids))
        if ids.count(ident) > 1
    ]
    for path, field in block["fields"].items():
        if "trust" in field and field["trust"] not in ids:
            problems.append(
                f"{path} names the trust rule {field['trust']}, which does not exist"
            )
    for rule in block["trust"]:
        for pattern in rule["paths"]:
            if not any(matches(pattern, path) for path in block["fields"]):
                problems.append(
                    f"trust rule {rule['id']}: {pattern} matches no setting"
                )
    return problems


# --- Writing the block into the page -----------------------------------------------

#: What each character is written as inside the block, so that the block can hold
#: neither ``</script>`` nor a Jinja opener and no line terminator a script cannot
#: contain. Built by concatenation so that no escape sequence is spelled out in
#: this file.
_ESCAPES = (
    ("<", "\\" + "u003c"),
    (">", "\\" + "u003e"),
    ("&", "\\" + "u0026"),
    (chr(0x2028), "\\" + "u2028"),
    (chr(0x2029), "\\" + "u2029"),
)


def serialize_block(block: Mapping[str, Any]) -> str:
    """The block as the page carries it. Building twice gives identical bytes."""
    text = json.dumps(
        block,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    for char, escape in _ESCAPES:
        text = text.replace(char, escape)
    return text


def data_block_element(text: str) -> str:
    return f'<script type="application/json" id="{BLOCK_ID}">{text}</script>\n'


def insert_data_block(page_html: str, text: str) -> str:
    """The page with the data block before its closing body tag."""
    matches = list(re.finditer(r"</body\s*>", page_html, re.IGNORECASE))
    if not matches:
        raise ProjectionError(
            "the editor page has no closing body tag to place the data in"
        )
    at = matches[-1].start()
    return page_html[:at] + data_block_element(text) + page_html[at:]


# --- The page policy ---------------------------------------------------------------

#: The directives of the policy, in order. ``script-src`` gets the hash of every
#: executable inline script of the page. There is no ``report-uri``: a report
#: endpoint would itself be a connection.
POLICY_DIRECTIVES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("default-src", ("'none'",)),
    ("script-src", ("'self'",)),
    ("style-src", ("'self'", "'unsafe-inline'")),
    ("img-src", ("'self'", "data:")),
    ("font-src", ("'self'",)),
    ("connect-src", ("'self'",)),
    ("worker-src", ("'self'",)),
    ("form-action", ("'none'",)),
    ("base-uri", ("'none'",)),
    ("object-src", ("'none'",)),
    ("frame-src", ("'none'",)),
)

#: Script types a browser runs. A script of any other type is a data block.
_JAVASCRIPT_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
        "module",
        "importmap",
    }
)

#: The one element exempt from the ``javascript:`` rule: the search-share anchor that
#: Material for MkDocs writes on every page while ``search.share`` is on. Its
#: script replaces the address and cancels every click, and the policy blocks the
#: URL if it is ever followed. Exempt by its exact markup: these attributes and no
#: others, the fixed ones with these values. ``title`` and ``aria-label`` carry the
#: word "Share" in the site's language.
SEARCH_SHARE_FIXED = {
    "href": "javascript:void(0)",
    "class": "md-search__icon md-icon",
    "data-clipboard": "",
    "data-clipboard-text": "",
    "data-md-component": "search-share",
    "tabindex": "-1",
}
SEARCH_SHARE_TRANSLATED = ("title", "aria-label")


def script_hash(text: str) -> str:
    """The CSP source for a script's exact text: ``sha256-`` and the base64 digest.

    The text is the script element's content as the parser reads it: with each
    newline written as a line feed, and nothing trimmed.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def build_policy(hashes: Iterable[str]) -> str:
    sources = [f"'{value}'" for value in hashes]
    parts = []
    for name, fixed in POLICY_DIRECTIVES:
        extra = tuple(sources) if name == "script-src" else ()
        parts.append(" ".join((name, *fixed, *extra)))
    return "; ".join(parts)


def policy_meta(policy: str) -> str:
    # The attribute is double-quoted, so the single quotes of the sources stay.
    escaped = html.escape(policy, quote=False).replace('"', "&quot;")
    return f'<meta http-equiv="Content-Security-Policy" content="{escaped}">'


def is_search_share_anchor(tag: str, attrs: list[tuple[str, str | None]]) -> bool:
    """Whether this start tag is Material's search-share anchor, in its exact markup."""
    if tag != "a":
        return False
    found = {name: ("" if value is None else value) for name, value in attrs}
    if len(found) != len(attrs):
        return False
    if set(found) != set(SEARCH_SHARE_FIXED) | set(SEARCH_SHARE_TRANSLATED):
        return False
    return all(found[name] == value for name, value in SEARCH_SHARE_FIXED.items())


#: What a URL parser strips from both ends of a value: the C0 controls and the space.
_URL_ENDS = "".join(chr(code) for code in range(0x21))


def url_as_parsed(value: str) -> str:
    """A URL attribute value as a browser's URL parser reads it before it looks for a
    scheme or a host: tabs and line breaks are dropped wherever they are, controls
    and spaces are stripped from the ends, and a backslash is a slash, because the
    page's own scheme is one of the special ones."""
    text = "".join(char for char in value if char not in "\t\n\r")
    return text.strip(_URL_ENDS).replace("\\", "/")


def is_external(src: str) -> bool:
    """Whether a script URL leaves the site: read as a browser reads it, it names a
    scheme or a host."""
    value = url_as_parsed(src)
    return (
        value.startswith("//")
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value) is not None
    )


def is_javascript_url(value: str) -> bool:
    """Whether a browser would read ``value`` as a ``javascript:`` URL."""
    return url_as_parsed(value).lower().startswith("javascript:")


def first_attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str | None]:
    """A start tag's attributes as a browser reads them: the first of a repeated name
    is the one it keeps."""
    found: dict[str, str | None] = {}
    for name, value in attrs:
        found.setdefault(name, value)
    return found


class PageScanner(HTMLParser):
    """Reads a built page for what the policy needs: the charset meta's end, each
    executable inline script, and everything a build must refuse."""

    def __init__(self, source: str, foreign: int = 0):
        super().__init__(convert_charrefs=True)
        self.source = source
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", source)]
        self.scripts: list[str] = []
        self.problems: list[str] = []
        self.charset_end: int | None = None
        self.policy_metas = 0
        self._text: list[str] | None = None
        self._executable = False
        # The svg and math elements open at this point, and the text of a style
        # inside one: a browser parses the content of those as markup.
        self._foreign = foreign
        self._style: list[str] | None = None

    def where(self) -> tuple[int, int]:
        line, offset = self.getpos()
        return line, self.line_starts[line - 1] + offset

    def problem(self, text: str) -> None:
        self.problems.append(f"line {self.getpos()[0]}: {text}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        exempt = is_search_share_anchor(tag, attrs)
        for name, value in attrs:
            if name.startswith("on"):
                self.problem(f"the {tag} element has the inline event handler {name!r}")
            elif value and not exempt and is_javascript_url(value):
                self.problem(f"the {tag} element has a javascript: URL in {name!r}")
        if tag in ("script", "meta"):
            names = [name for name, _ in attrs]
            for name in dict.fromkeys(n for n in names if names.count(n) > 1):
                self.problem(f"the {tag} element repeats the attribute {name!r}")
        attributes = first_attributes(attrs)
        if tag in ("svg", "math"):
            self._foreign += 1
        elif tag == "style" and self._foreign:
            self._style = []
        elif tag == "meta":
            self.meta(attributes)
        elif tag == "script":
            self.script(attributes)

    def meta(self, attributes: dict[str, str | None]) -> None:
        equiv = (attributes.get("http-equiv") or "").strip().lower()
        if equiv == "content-security-policy":
            self.policy_metas += 1
        if "charset" in attributes and self.charset_end is None:
            text = self.get_starttag_text() or ""
            start = self.where()[1]
            if self.source[start : start + len(text)] != text:
                raise ProjectionError("the page's charset meta could not be located")
            self.charset_end = start + len(text)

    def script(self, attributes: dict[str, str | None]) -> None:
        # An HTML script loads from src and an SVG script from href or xlink:href.
        # A script with any of them takes its code from there, so it has no inline
        # text to hash, and each address is held to the same rule.
        loaded = False
        for name in ("src", "href", "xlink:href"):
            source = attributes.get(name)
            if source is None:
                continue
            loaded = True
            if is_external(source):
                self.problem(f"the page loads the external script {source!r}")
        if loaded:
            self._text = None
            return
        kind = (attributes.get("type") or "").strip().lower()
        self._executable = kind == "" or kind in _JAVASCRIPT_TYPES
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._text is not None:
            self._text.append(data)
        if self._style is not None:
            self._style.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._text is not None:
            text = "".join(self._text)
            if self._executable:
                self.scripts.append(text)
            if self._foreign:
                self.rescan(tag, text)
            self._text = None
        elif tag == "style" and self._style is not None:
            self.rescan(tag, "".join(self._style))
            self._style = None
        elif tag in ("svg", "math") and self._foreign:
            self._foreign -= 1

    def close(self) -> None:
        super().close()
        # An element left open runs to the end of the page.
        if self._style is not None:
            self.rescan("style", "".join(self._style))
            self._style = None
        if self._text is not None and self._foreign:
            self.rescan("script", "".join(self._text))
            self._text = None

    def rescan(self, tag: str, text: str) -> None:
        """Read the text of an SVG or MathML ``style`` or ``script`` as markup.

        The parser here reads that text as text, as it does for an HTML element of
        those names. A browser parses it as markup inside SVG and MathML, so an
        ``img`` in it is an HTML element with its handlers, and a link in it keeps
        its ``javascript:`` URL. The same refusals apply to what the text holds. The
        element itself is not refused: the site's own logo is an SVG with a style.
        """
        inner = PageScanner(text, foreign=1)
        inner.feed(text)
        inner.close()
        line = self.getpos()[0]
        for problem in inner.problems:
            reason = problem.split(": ", 1)[1]
            self.problems.append(
                f"line {line}: in the markup a browser reads inside the {tag} "
                f"element, {reason}"
            )


def apply_page_policy(page_html: str, name: str = EDITOR_PAGE) -> str:
    """The page with its Content-Security-Policy meta, or a build error naming
    everything the page holds that the policy cannot be made true for."""
    scanner = PageScanner(page_html)
    scanner.feed(page_html)
    scanner.close()
    problems = list(scanner.problems)
    if scanner.policy_metas:
        problems.append(
            "the page already holds a Content-Security-Policy meta, and this hook "
            "writes the only one"
        )
    if scanner.charset_end is None:
        problems.append("the page has no <meta charset>, which the policy goes after")
    if problems:
        raise ProjectionError(f"{name}: " + "; ".join(problems))
    hashes: list[str] = []
    for text in scanner.scripts:
        value = script_hash(text)
        if value not in hashes:
            hashes.append(value)
    at = scanner.charset_end or 0
    return page_html[:at] + policy_meta(build_policy(hashes)) + page_html[at:]


# --- The mkdocs events -------------------------------------------------------------

_blocks: dict[tuple[str, str, str], dict[str, Any]] = {}


def docs_version(config: Any) -> str:
    return str(config.extra.get("docs_version") or "") or "main"


def editor_block(config: Any) -> dict[str, Any]:
    """The block for this build. Built once per process for a given schema file
    and version: the trust probe is the slow part, and ``mkdocs serve`` rebuilds."""
    root = Path(config.config_file_path).parent
    _, digest = read_schema(root)
    key = (str(root), digest, docs_version(config))
    if key not in _blocks:
        _blocks[key] = build_block(root, docs_version(config))
    return _blocks[key]


@event_priority(-100)
def on_post_page(output: str, page: Any, config: Any) -> str:
    """Give the editor page its data block and its policy, after every plugin."""
    if page.file.src_uri != EDITOR_PAGE:
        return output
    text = serialize_block(editor_block(config))
    return apply_page_policy(insert_data_block(output, text))
