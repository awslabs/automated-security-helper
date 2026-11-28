# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The data block the docs build hook writes into the configuration editor page.

The block is computed from the commit being built and never committed, so these
tests are what keeps it honest. They build the real block once, from the checked-out
schema and ASH's own code, and hold it to what the page's consumers may rely on:

* the block fits its JSON Schema, carries the schema file's sha256, resolves every
  pointer, places every setting in one group and names only trust rules that exist;
* every property the validation schema reaches has a field, whatever it takes to
  cut the ``build`` subtree and what only it reaches;
* what the block says about ASH (hidden fields, deprecated keys, host-dependent
  defaults, the environment rule, the text of two messages) equals ASH's own code;
* the repository-file trust rules come from loading planted files through ASH's own
  loader, and the pinned table of the rules a load cannot show is held to ASH's code
  three ways;
* a reference such as ``${ASH_X:60}`` is judged on the route that loads a config
  file, never on the lax route that keeps one where every real file refuses it;
* each generator tripwire stops the build, naming the pointer or path it found.

Every check is paired with the planted input that makes it fail, run in the same
file: a planted schema, a planted block, a planted pointer, a planted vector.
"""

import ast
import copy
import gzip
import hashlib
import importlib.util
import itertools
import json
import os
import platform
import re
import time
import types
from pathlib import Path

import jsonschema
import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK_PATH = REPO_ROOT / "docs" / "hooks" / "config_editor.py"
PACKAGE = REPO_ROOT / "automated_security_helper"
SCHEMA_PATH = PACKAGE / "schemas" / "AshConfig.json"
PLUGIN_MODULES = PACKAGE / "plugin_modules"

PROBE_SECONDS_LIMIT = 30
SIZE_CEILING = 400_000

#: The settings the table holds that no static read of the scanners' call sites can
#: name, each with why. The scan follows string literals and f-strings through
#: assignments and call arguments; these keys are built where it cannot look.
NOT_FOUND_BY_THE_SCAN = {
    "scanners.checkov.options.config_file": "named in a conditional expression",
    "scanners.syft.options.config_file": "named in a conditional expression",
    "scanners.opengrep.options.config": "named by a method the base class calls",
    "scanners.semgrep.options.config": "named by a method the base class calls",
    "scanners.trivy.options.config_file": "a bare option name, the section added later",
    "scanners.trivy.options.ignore_file": "a bare option name, the section added later",
    "scanners.trivy.options.secret_config_file": "a bare option name, the section added later",
    "scanners.trivy-repo.options.config_file": "a bare option name, the section added later",
    "scanners.trivy-repo.options.ignore_file": "a bare option name, the section added later",
    "scanners.trivy-repo.options.secret_config_file": "a bare option name, the section added later",
    "scanners.trivy-repo.options.module_dir": "a bare option name, the section added later",
}

#: Settings whose description does not say "Used only when the operator sets it"
#: although a scan keeps only what the operator set, each with why.
NOT_DESCRIBED_THAT_WAY = {
    "scanners.checkov.options.config_file": "the description names the path rule",
    "scanners.opengrep.options.config": "the description names the path rule",
    "scanners.semgrep.options.config": "the description names the path rule",
}

#: The published settings the probe plants no value for: a list of objects, a map, a
#: raw mapping, or a list whose first value is its default. The probe's report lists
#: them, and a new one fails the test that compares the two, so that someone decides
#: whether ASH confines it. Two have a row of the table (the detect-secrets scan
#: settings and trivy's scanners); the others have no rule.
UNPLANTED = [
    "global_settings.exclusions",
    "global_settings.ignore_paths",
    "global_settings.mcp.runtime_overrides.denied_value_patterns",
    "global_settings.suppressions",
    "scanners.bandit.options.excluded_paths",
    "scanners.checkov.options.frameworks",
    "scanners.checkov.options.skip_path",
    "scanners.detect-secrets.options.scan_settings",
    "scanners.opengrep.options.sha256",
    "scanners.syft.options.exclude",
    "scanners.syft.options.sdist_harvest.lockfiles",
    "scanners.trivy.options.scanners",
]


# -- Loading the hook and building the real block ------------------------------------


@pytest.fixture(scope="module")
def hook():
    spec = importlib.util.spec_from_file_location("ash_config_editor_hook", HOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_bytes())


@pytest.fixture(scope="module")
def built(hook, tmp_path_factory):
    if platform.system() == "Windows":
        # The hook refuses a Windows host by design: its trust probe measures ASH on
        # the build host. Every test that needs a build is skipped there, with the
        # hook's own words as the reason, and the refusal is held on every system by
        # test_a_windows_host_is_refused_before_anything_is_measured.
        with pytest.raises(hook.ProjectionError) as refusal:
            hook.check_host(tmp_path_factory.getbasetemp(), {})
        pytest.skip(str(refusal.value))
    report: dict = {}
    workdir = tmp_path_factory.mktemp("editor-probe")
    started = time.monotonic()
    block = hook.build_block(REPO_ROOT, "main", workdir=workdir, report=report)
    return types.SimpleNamespace(
        block=block,
        report=report,
        seconds=time.monotonic() - started,
        workdir=workdir,
    )


@pytest.fixture(scope="module")
def fields(built):
    return built.block["fields"]


def _project(hook, schema_copy, **overrides):
    validation = hook.build_validation_schema(schema_copy)
    facts = {
        "internal_fields": hook.internal_section_fields(),
        "deprecated": hook.DEPRECATED_RENAMES,
        "env_classes": {
            name: {"topLevel": False, "section": False} for name in hook.ENV_CLASSES
        },
    }
    facts.update(overrides)
    return hook.project_fields(schema_copy, validation, **facts)


# -- The block and its contract ------------------------------------------------------


def test_the_block_fits_the_contract_schema(hook, built):
    jsonschema.Draft202012Validator.check_schema(hook.BLOCK_SCHEMA)
    errors = list(
        jsonschema.Draft202012Validator(hook.BLOCK_SCHEMA).iter_errors(built.block)
    )
    assert errors == [], errors[:3]


@pytest.mark.parametrize(
    "plant",
    [
        lambda block: block.pop("trust"),
        lambda block: block.update(contract="ash-config-editor-data/2"),
        lambda block: block["fields"]["project_name"].update(kind="tuple"),
        lambda block: block["source"].update(schemaSha256="not-a-sha"),
        lambda block: block["fields"].update({"bad path": {}}),
    ],
    ids=[
        "a part missing",
        "another contract",
        "an unknown kind",
        "a bad sha",
        "a bad path",
    ],
)
def test_a_block_that_does_not_fit_the_contract_is_reported(hook, built, plant):
    planted = copy.deepcopy(built.block)
    plant(planted)
    assert hook.check_block(planted), (
        "check_block passed a block that breaks the contract"
    )


def test_the_block_carries_the_sha256_of_the_schema_file(hook, built):
    digest = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    assert built.block["source"]["schemaSha256"] == digest
    planted = copy.deepcopy(built.block)
    planted["source"]["schemaSha256"] = "0" * 64
    assert any("sha256" in p for p in hook.check_block(planted, digest))


def test_every_schema_pointer_resolves(hook, built):
    validation = built.block["validationSchema"]
    missing = [
        path
        for path, field in built.block["fields"].items()
        if _resolve(validation, field["schemaPointer"]) is _ABSENT
    ]
    assert missing == []
    planted = copy.deepcopy(built.block)
    planted["fields"]["project_name"]["schemaPointer"] = (
        "#/$defs/AshConfig/properties/nope"
    )
    assert any("does not resolve" in p for p in hook.check_block(planted))


_ABSENT = object()


def _resolve(root, pointer):
    node = root
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        else:
            return _ABSENT
    return node


# -- Closure: what the validation schema keeps, and a field for everything it reaches --


def _refs(node):
    """Every definition name any ``$ref`` under ``node`` names, found without
    reading the schema's structure at all."""
    found = set()
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            ref = item.get("$ref")
            if isinstance(ref, str):
                found.add(ref.rsplit("/", 1)[-1])
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _reach(definitions, start):
    seen = set()
    todo = list(start)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo.extend(_refs(definitions[name]))
    return seen


def _closure_problems(schema_data, kept):
    """What is wrong with the definitions kept: one the root reaches without the
    ``build`` property is missing, or one is cut that ``build`` does not reach."""
    definitions = schema_data["$defs"]
    root = copy.deepcopy(definitions["AshConfig"])
    cut = root["properties"].pop("build")
    live = _reach({**definitions, "AshConfig": root}, {"AshConfig"})
    only_build = _reach(definitions, _refs(cut)) - live
    problems = []
    if set(kept) != live:
        problems.append(f"kept {sorted(set(kept) ^ live)} wrongly")
    stray = set(definitions) - live - only_build
    if stray:
        problems.append(f"definitions nothing reaches: {sorted(stray)}")
    return problems


def test_the_cut_keeps_what_the_root_reaches_and_only_that(built, schema):
    kept = built.block["validationSchema"]["$defs"]
    assert _closure_problems(schema, kept) == []
    assert "BuildConfig" not in kept and len(schema["$defs"]) - len(kept) >= 1
    assert _closure_problems(
        schema, {k: v for k, v in kept.items() if k != "ScannerConfigSegment"}
    )
    planted = copy.deepcopy(schema)
    planted["$defs"]["Orphan"] = {"type": "string"}
    assert _closure_problems(planted, kept), (
        "a definition nothing reaches went unnoticed"
    )


def _small_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/AshConfig",
        "$defs": {
            "AshConfig": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "build": {"$ref": "#/$defs/Build"},
                    "flag": {"type": "boolean", "default": False, "title": "Flag"},
                    "free": {},
                    "anything": True,
                    "box": {"$ref": "#/$defs/Box"},
                },
            },
            "Build": {
                "type": "object",
                "properties": {"deep": {"$ref": "#/$defs/Deep"}},
            },
            "Deep": {"type": "string"},
            "Box": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "rows": {"type": "array", "items": {"$ref": "#/$defs/Leaf"}},
                    "open": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/Leaf"}]},
                },
            },
            "Leaf": {"type": "object", "additionalProperties": True},
        },
    }


def test_the_closure_follows_references_through_boolean_and_empty_schemas(hook):
    small = _small_schema()
    assert hook.live_definitions(small) == {"AshConfig", "Box", "Leaf"}
    validation = hook.build_validation_schema(small)
    assert set(validation["$defs"]) == {"AshConfig", "Box", "Leaf"}
    assert "build" not in validation["$defs"]["AshConfig"]["properties"]
    assert "title" not in validation["$defs"]["AshConfig"]["properties"]["flag"]
    assert validation["$defs"]["AshConfig"]["properties"]["anything"] is True
    assert validation["$defs"]["AshConfig"]["properties"]["free"] == {}


def test_a_definition_reached_only_through_build_is_cut_and_one_reached_elsewhere_is_kept(
    hook,
):
    small = _small_schema()
    small["$defs"]["AshConfig"]["properties"]["flag"] = {"$ref": "#/$defs/Deep"}
    assert hook.live_definitions(small) == {"AshConfig", "Box", "Leaf", "Deep"}


def _reachable_paths(definitions, raw_paths):
    """Every setting path the schema reaches, by the contract's grammar, found
    separately from the hook's projection."""
    found = set()

    def visit(node, path, chain):
        if not isinstance(node, dict):
            return
        ref = node.get("$ref")
        if isinstance(ref, str):
            name = ref.rsplit("/", 1)[-1]
            if name not in chain:
                visit(definitions[name], path, chain + (name,))
            return
        for branch in node.get("anyOf", []):
            visit(branch, path, chain)
        for name, sub in node.get("properties", {}).items():
            child = f"{path}.{name}" if path else name
            found.add(child)
            if child not in raw_paths:
                visit(sub, child, chain)
        if isinstance(node.get("items"), dict):
            visit(node["items"], path + "[]", chain)
        values = node.get("additionalProperties")
        if isinstance(values, dict) and values and "properties" not in node:
            found.add(path + "{}")
            visit(values, path + "{}", chain)

    visit(definitions["AshConfig"], "", ("AshConfig",))
    return found


def test_every_property_the_schema_reaches_has_a_field_and_no_field_is_invented(
    hook, built
):
    reachable = _reachable_paths(
        built.block["validationSchema"]["$defs"], hook.RAW_PATHS
    )
    fields = set(built.block["fields"])
    assert sorted(reachable - fields) == []
    assert sorted(fields - reachable) == []
    assert "build" not in fields and not any(p.startswith("build.") for p in fields)


def test_a_field_is_missing_when_the_projection_drops_a_property(hook, built):
    reachable = _reachable_paths(
        built.block["validationSchema"]["$defs"], hook.RAW_PATHS
    )
    dropped = set(built.block["fields"]) - {"fail_on_findings"}
    assert reachable - dropped == {"fail_on_findings"}


# -- The group map ------------------------------------------------------------------


def _group_problems(block):
    top = {p for p, f in block["fields"].items() if f["parent"] is None}
    children = {
        p for p, f in block["fields"].items() if f["parent"] == "global_settings"
    }
    expected = (top - {"global_settings"}) | children
    seen = list(itertools.chain.from_iterable(g["paths"] for g in block["groups"]))
    problems = [f"{p} is in no group" for p in sorted(expected - set(seen))]
    problems += [
        f"{p} is in more than one group"
        for p in sorted({p for p in seen if seen.count(p) > 1})
    ]
    problems += [f"{p} is no field" for p in sorted(set(seen) - set(block["fields"]))]
    deeper = (set(seen) & set(block["fields"])) - expected
    problems += [f"{p} should not be in a group" for p in sorted(deeper)]
    return problems


def test_every_top_level_setting_and_every_global_setting_is_in_exactly_one_group(
    built,
):
    assert _group_problems(built.block) == []


@pytest.mark.parametrize(
    "plant",
    [
        lambda block: block["groups"][0]["paths"].remove("project_name"),
        lambda block: block["groups"][1]["paths"].append("project_name"),
        lambda block: block["groups"][0]["paths"].append("no_such_setting"),
        lambda block: block["groups"][0]["paths"].append("build"),
    ],
    ids=[
        "one left out",
        "one in two groups",
        "a group names no field",
        "the cut property",
    ],
)
def test_a_group_map_that_breaks_the_rule_is_reported(hook, built, plant):
    planted = copy.deepcopy(built.block)
    plant(planted)
    assert _group_problems(planted)
    assert hook.group_problems(planted)


# -- The raw paths, the pattern set, the size ceiling --------------------------------

PINNED_RAW_PATHS = {
    "patch",
    "global_settings.suppressions[].scope.engines",
    "scanners.detect-secrets.options.scan_settings",
}


def test_the_raw_path_set_is_the_recorded_one_and_each_is_a_raw_leaf(hook, built):
    assert set(hook.RAW_PATHS) == PINNED_RAW_PATHS
    raw = {p for p, f in built.block["fields"].items() if f["kind"] == "raw"}
    assert raw == PINNED_RAW_PATHS
    assert not any(p.startswith(r + ".") for p in built.block["fields"] for r in raw)


@pytest.mark.parametrize("path", sorted(PINNED_RAW_PATHS))
def test_without_its_entry_a_raw_path_is_no_longer_raw_or_stops_the_build(
    hook, schema, path
):
    remaining = set(hook.RAW_PATHS) - {path}
    try:
        projected = _project(hook, copy.deepcopy(schema), raw_paths=remaining)
    except hook.ProjectionError as error:
        assert "RAW_PATHS" in str(error), str(error)
        return
    assert projected[path]["kind"] != "raw"


def test_every_pattern_of_the_schema_has_an_entry_and_nothing_else_does(hook, built):
    found = set()
    stack = [built.block["validationSchema"]]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if isinstance(item.get("pattern"), str):
                found.add(item["pattern"])
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    table = built.block["patterns"]
    assert found == set(table) and len(found) >= 3
    for source, entry in table.items():
        assert entry["python"] == source and entry["js"] and entry["flags"] == "u"
    planted = copy.deepcopy(built.block)
    planted["patterns"].pop(next(iter(planted["patterns"])))
    assert any("patterns" in p for p in hook.check_block(planted))


def test_the_serialized_block_is_within_the_size_ceiling(hook, built, record_property):
    text = hook.serialize_block(built.block).encode("utf-8")
    probe = built.report["probe"]
    record_property("block_bytes", len(text))
    record_property("block_gzip_bytes", len(gzip.compress(text, 9)))
    record_property("probe_seconds", f"{probe['seconds']:.2f}")
    record_property("probe_loads", probe["rounds"])
    record_property("build_seconds", f"{built.seconds:.2f}")
    record_property("fields", len(built.block["fields"]))
    record_property("trust_rules", ",".join(r["id"] for r in built.block["trust"]))
    record_property("trust_json", json.dumps(built.block["trust"], sort_keys=True))
    record_property(
        "unprobed",
        "; ".join(f"{k}: {v}" for k, v in sorted(probe["unprobed"].items()))[:6000],
    )
    assert hook.SIZE_CEILING == SIZE_CEILING
    assert len(text) <= SIZE_CEILING, f"the block is {len(text)} bytes"


def test_a_block_over_the_ceiling_is_reported(hook, built):
    planted = copy.deepcopy(built.block)
    planted["fields"]["project_name"]["description"] = "x" * (SIZE_CEILING + 1)
    assert any("ceiling" in p for p in hook.check_block(planted))


def test_two_builds_of_one_commit_give_identical_bytes(hook, built, tmp_path_factory):
    again = hook.build_block(
        REPO_ROOT, "main", workdir=tmp_path_factory.mktemp("second")
    )
    assert hook.serialize_block(again) == hook.serialize_block(built.block)


def test_the_embedded_text_holds_no_raw_character_that_can_end_or_open_markup(hook):
    block = {
        "a": "</script><!--",
        "b": "&amp;",
        "c": "line" + chr(0x2028) + chr(0x2029),
    }
    text = hook.serialize_block(block)
    assert not any(char in text for char in ("<", ">", "&", chr(0x2028), chr(0x2029)))
    assert json.loads(text) == block
    unescaped = json.dumps(
        block, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert "</script>" in unescaped, (
        "the plain serialization would have ended the script"
    )


# -- The tripwires, each naming its pointer or path -----------------------------------


def _mutated(schema, change):
    planted = copy.deepcopy(schema)
    change(planted["$defs"]["AshConfig"]["properties"]["project_name"])
    return planted


UNKNOWN_KEYWORDS = [
    ("oneOf", []),
    ("allOf", []),
    ("if", {}),
    ("patternProperties", {}),
    ("discriminator", {}),
    ("$comment", "new"),
]


@pytest.mark.parametrize(("keyword", "value"), UNKNOWN_KEYWORDS)
def test_a_keyword_the_validator_does_not_handle_stops_the_build_at_its_pointer(
    hook, schema, keyword, value
):
    planted = _mutated(schema, lambda node: node.update({keyword: value}))
    pointer = f"#/$defs/AshConfig/properties/project_name/{keyword}"
    with pytest.raises(hook.ProjectionError, match=re.escape(pointer)):
        hook.build_validation_schema(planted)


def test_a_type_that_is_not_one_string_stops_the_build_at_its_pointer(hook, schema):
    planted = _mutated(schema, lambda node: node.update(type=["string", "null"]))
    with pytest.raises(hook.ProjectionError, match=re.escape("project_name/type")):
        hook.build_validation_schema(planted)


def test_a_root_keyword_the_hook_does_not_know_stops_the_build(hook, schema):
    planted = copy.deepcopy(schema)
    planted["x-new"] = 1
    with pytest.raises(hook.ProjectionError, match=re.escape("#/x-new")):
        hook.build_validation_schema(planted)


def test_a_schema_that_no_longer_has_the_cut_property_stops_the_build(hook, schema):
    planted = copy.deepcopy(schema)
    del planted["$defs"]["AshConfig"]["properties"]["build"]
    with pytest.raises(hook.ProjectionError, match="properties/build"):
        hook.build_validation_schema(planted)


def test_a_pattern_with_no_recorded_translation_stops_the_build_at_its_pointer(
    hook, schema
):
    planted = _mutated(schema, lambda node: node.update(pattern="^new-pattern$"))
    validation = hook.build_validation_schema(planted)
    with pytest.raises(
        hook.ProjectionError, match=r"project_name/pattern.*translation"
    ):
        hook.pattern_table(validation)


def test_a_node_no_kind_can_hold_stops_the_build_unless_it_is_a_raw_path(hook, schema):
    objects = [
        {"type": "object", "properties": {"a": {"type": "string"}}},
        {"type": "object", "properties": {"b": {"type": "string"}}},
    ]
    planted = _mutated(schema, lambda node: (node.clear(), node.update(anyOf=objects)))
    with pytest.raises(hook.ProjectionError, match=r"project_name.*RAW_PATHS"):
        _project(hook, planted)
    raw = set(hook.RAW_PATHS) | {"project_name"}
    assert _project(hook, planted, raw_paths=raw)["project_name"]["kind"] == "raw"


def test_a_key_the_path_grammar_cannot_hold_stops_the_build_at_its_pointer(
    hook, schema
):
    planted = copy.deepcopy(schema)
    planted["$defs"]["AshConfig"]["properties"]["bad.key"] = {"type": "string"}
    with pytest.raises(hook.ProjectionError, match=re.escape("properties/bad.key")):
        _project(hook, planted)


def test_an_annotation_that_names_a_setting_the_schema_lacks_stops_the_build(
    hook, schema
):
    with pytest.raises(hook.ProjectionError, match="RAW_PATHS names 'no.such.path'"):
        _project(
            hook,
            copy.deepcopy(schema),
            raw_paths=set(hook.RAW_PATHS) | {"no.such.path"},
        )
    hosts = {
        **hook.HOST_DEFAULTS,
        "no.such.path": {"dependsOn": "platform", "name": "x"},
    }
    with pytest.raises(
        hook.ProjectionError, match="HOST_DEFAULTS names 'no.such.path'"
    ):
        _project(hook, copy.deepcopy(schema), host_defaults=hosts)
    renames = {**hook.DEPRECATED_RENAMES, "gone": "new"}
    with pytest.raises(hook.ProjectionError, match="deprecated key 'gone'"):
        _project(hook, copy.deepcopy(schema), deprecated=renames)


# -- Annotations read from ASH's code --------------------------------------------------


def test_the_hidden_deprecated_and_inherited_annotations_equal_ashs_code(
    hook, built, fields
):
    from automated_security_helper.utils import unknown_keys

    internal = {
        kind: set(names) for kind, names in unknown_keys.INTERNAL_SECTION_FIELDS.items()
    }
    assert {
        k: set(v) for k, v in built.block["constants"]["internalSectionFields"].items()
    } == {kind: internal[kind] for kind in hook.SEGMENTS}
    hidden = {p for p, f in fields.items() if f["hidden"]}

    def internal_in_a_section(path):
        # <kind>.<section>.<name>: the fields of the section itself, not its options
        parts = path.split(".")
        return (
            len(parts) == 3
            and parts[0] in hook.SEGMENTS
            and parts[2] in internal[parts[0]]
        )

    expected = {
        p
        for p, f in fields.items()
        if f["key"] == "client_supplied" or internal_in_a_section(p)
    }
    assert hidden == expected, sorted(hidden ^ expected)
    assert hidden
    assert not any(
        f["hidden"]
        for p, f in fields.items()
        if ".options." in p and f["key"] == "tool_version"
    )
    assert set(unknown_keys.DEPRECATED_KEYS) == set(hook.DEPRECATED_RENAMES)
    marked = {p for p, f in fields.items() if "deprecated" in f}
    assert marked and all(
        fields[p]["key"] in unknown_keys.DEPRECATED_KEYS for p in marked
    )
    for path in marked:
        sibling = path.rsplit(".", 1)[0] + "." + fields[path]["deprecated"]["renameTo"]
        assert sibling in fields, (
            f"{path} is marked deprecated with no {sibling} beside it"
        )
    inherits = {p for p, f in fields.items() if "inherits" in f}
    assert inherits and all(p.endswith(".options.severity_threshold") for p in inherits)


def test_a_deprecated_key_ash_names_and_the_hook_does_not_stops_the_build(
    hook, monkeypatch
):
    from automated_security_helper.utils import unknown_keys

    monkeypatch.setattr(
        unknown_keys,
        "DEPRECATED_KEYS",
        frozenset({*unknown_keys.DEPRECATED_KEYS, "newly"}),
    )
    with pytest.raises(hook.ProjectionError, match="newly"):
        hook.ash_constants()


def _source(relative):
    return (REPO_ROOT / "automated_security_helper" / relative).read_text(
        encoding="utf-8"
    )


HOST_SOURCES = {
    "project_name": ("config/ash_config.py", 'os.environ.get("ASH_PROJECT_NAME"'),
    "global_settings.severity_threshold": (
        "core/constants.py",
        'os.environ.get("ASH_DEFAULT_SEVERITY_LEVEL")',
    ),
    "scanners.opengrep.enabled": (
        "plugin_modules/ash_builtin/scanners/opengrep_scanner.py",
        'platform.system().lower() != "windows"',
    ),
    "scanners.semgrep.enabled": (
        "plugin_modules/ash_builtin/scanners/semgrep_scanner.py",
        'platform.system().lower() != "windows"',
    ),
}


def test_each_host_dependent_default_is_read_where_the_hook_says_and_carries_the_shipped_value(
    hook, fields
):
    assert set(hook.HOST_DEFAULTS) == set(HOST_SOURCES)
    for path, (relative, needle) in HOST_SOURCES.items():
        assert needle in _source(relative), f"{relative} no longer reads {needle}"
        assert fields[path]["hostDefault"] == hook.HOST_DEFAULTS[path]
    assert fields["project_name"]["default"] == "ash-scan"
    assert fields["global_settings.severity_threshold"]["default"] == "MEDIUM"
    assert fields["scanners.opengrep.enabled"]["default"] is True
    assert fields["scanners.semgrep.enabled"]["default"] is True


def test_the_two_message_templates_equal_the_text_ash_writes(built, tmp_path):
    from automated_security_helper.config.ash_config import load_config_yaml
    from automated_security_helper.config.config_validator import ConfigValidator

    constants = built.block["constants"]
    with pytest.raises(
        Exception, match=re.escape(constants["aliasRefusal"].format(anchor="x"))
    ):
        load_config_yaml("a: &x 1\nb: *x\n")
    planted = tmp_path / "planted.yaml"
    planted.write_text("project_name: x\nbuild: {}\n", encoding="utf-8")
    warnings = ConfigValidator._structure_warnings(
        planted,
        {"project_name": "x", "build": {}},
        {"project_name": "x", "build": {}},
        True,
        False,
        None,
    )
    assert constants["invalidTopLevelFieldWarning"].format(field="build") in warnings


# -- The environment rule ---------------------------------------------------------------


def _env_problems(env):
    from automated_security_helper.core import constants

    problems = []
    if env["prefix"] != constants.ASH_CONFIG_ENV_VAR_PREFIX:
        problems.append("the prefix differs")
    if env["allowlist"] != list(constants.ASH_CONFIG_ENV_VAR_ALLOWLIST):
        problems.append("the allowlist differs")
    if env["refusedNames"] != list(constants.ASH_CONFIG_ENV_VAR_SECRET_NAMES):
        problems.append("the refused names differ")
    if env["secretSuffixes"] != list(constants.ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES):
        problems.append("the secret suffixes differ")
    if env["readableNames"] != list(constants.ASH_CONFIG_ENV_VAR_READABLE_NAMES):
        problems.append("the readable names differ")
    names = {name for name, _ in env["vectors"]}
    exported = [
        *constants.ASH_CONFIG_ENV_VAR_ALLOWLIST,
        *constants.ASH_CONFIG_ENV_VAR_SECRET_NAMES,
        *constants.ASH_CONFIG_ENV_VAR_READABLE_NAMES,
    ]
    problems += [f"{n} has no vector" for n in exported if n not in names]
    for suffix in constants.ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES:
        if [f"ASH_X{suffix}", True] not in env["vectors"]:
            problems.append(f"no refused vector for the suffix {suffix}")
    for name, refused in env["vectors"]:
        if refused != bool(constants.is_refused_config_environment_name(name)):
            problems.append(f"{name} is {refused} in the block")
    if not any(r for _, r in env["vectors"]) or all(r for _, r in env["vectors"]):
        problems.append("the vectors hold only one answer")
    return problems


def test_the_environment_rule_and_its_vectors_equal_ashs_own(built):
    assert _env_problems(built.block["env"]) == []


@pytest.mark.parametrize(
    "plant",
    [
        lambda env: env["vectors"].__setitem__(
            0, [env["vectors"][0][0], not env["vectors"][0][1]]
        ),
        lambda env: env["secretSuffixes"].pop(),
        lambda env: env["allowlist"].append("EXTRA_NAME"),
        lambda env: env.update(prefix="XASH_"),
        lambda env: env.update(
            vectors=[v for v in env["vectors"] if v[0] != "ASH_BEDROCK_MAX_TOKENS"]
        ),
        lambda env: env["readableNames"].append("ASH_X_MAX_TOKENS"),
        lambda env: env["readableNames"].clear(),
    ],
    ids=[
        "a flipped vector",
        "a suffix lost",
        "an extra name",
        "another prefix",
        "a vector lost",
        "an extra readable name",
        "the readable names lost",
    ],
)
def test_an_environment_rule_that_differs_from_ash_is_reported(built, plant):
    planted = copy.deepcopy(built.block["env"])
    plant(planted)
    assert _env_problems(planted)


def test_the_readable_names_are_admitted_before_a_suffix_refuses_them(built):
    env = built.block["env"]
    assert env["readableNames"], "ASH lists no readable name"
    refused_by_suffix = [
        name
        for name in env["readableNames"]
        if name.endswith(tuple(env["secretSuffixes"]))
    ]
    assert refused_by_suffix, (
        "no readable name ends in a refused suffix, so it needs no list"
    )
    vectors = dict(env["vectors"])
    for name in env["readableNames"]:
        assert vectors[name] is False, f"{name} is readable and its vector says refused"


# -- A reference is judged on the route that loads a config file ----------------------------

SCAN_TIMEOUT = "scanners.actionlint.options.scan_timeout"


def _lax_load(path):
    """The lax route: ASH resolves the file's references as it does for any load, and
    the model is then validated without the context that makes a config file refuse a
    reference in a typed field. ``scan_timeout`` opted in to keeping one there and
    types its text (``ScannerOptionsBase._env_scalar_typed_fields``)."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.config_sources import resolve_config_document

    return AshConfig.model_validate(resolve_config_document(Path(path)).data)


def _takes_everything(path):
    return None


def _refuses_a_reference(path):
    if "${" in Path(path).read_text(encoding="utf-8"):
        raise ValueError("a reference is refused")


def _route_check(hook, fields, workdir, load=None):
    """The check the brief names: a reference in ``scan_timeout`` is refused on the
    route that loads a config file. ``load`` plants another route in the probe."""
    assert fields[SCAN_TIMEOUT]["kind"] == "integer"
    extra = {} if load is None else {"load": load}
    assert hook.reference_accepted(fields, SCAN_TIMEOUT, workdir, **extra) is False, (
        "the probe's route accepts a reference in scan_timeout"
    )


def test_a_reference_in_scan_timeout_is_reported_refused(hook, fields, tmp_path):
    _route_check(hook, fields, tmp_path)


def test_the_lax_route_reports_a_reference_in_scan_timeout_accepted(
    hook, fields, tmp_path
):
    assert (
        hook.reference_accepted(fields, SCAN_TIMEOUT, tmp_path, load=_lax_load) is True
    )


def test_the_route_check_fails_when_the_probe_loads_on_the_lax_route(
    hook, fields, tmp_path
):
    with pytest.raises(AssertionError, match="accepts a reference in scan_timeout"):
        _route_check(hook, fields, tmp_path, load=_lax_load)


def test_a_load_that_takes_a_reference_reads_as_accepted(hook, fields, tmp_path):
    assert (
        hook.reference_accepted(fields, SCAN_TIMEOUT, tmp_path, load=_takes_everything)
        is True
    )


def test_a_load_that_refuses_only_the_reference_reads_as_refused(
    hook, fields, tmp_path
):
    assert (
        hook.reference_accepted(
            fields, SCAN_TIMEOUT, tmp_path, load=_refuses_a_reference
        )
        is False
    )


def test_the_probe_reports_each_class_on_the_file_load_route(built):
    classes = built.block["envProbe"]["classes"]
    assert built.block["envProbe"]["route"] == "file-load"
    assert classes["integer"] == {"topLevel": False, "section": False}
    assert classes["boolean"] == {"topLevel": False, "section": False}
    assert classes["string"]["section"] is True


def test_a_field_takes_its_environment_answer_from_its_class(hook, built):
    for path, field in built.block["fields"].items():
        name = hook.class_of(field["kind"], field.get("patternRef"))
        expected = (
            False
            if name is None
            else built.block["envProbe"]["classes"][name][hook.location_of(path)]
        )
        assert field["envAccepted"] == expected, path


def test_a_probe_whose_plain_control_is_refused_does_not_answer(hook, fields, tmp_path):
    def refuse_everything(path):
        raise ValueError("refused")

    with pytest.raises(hook.ControlRefused):
        hook.reference_accepted(fields, SCAN_TIMEOUT, tmp_path, load=refuse_everything)


# -- The opt-in catalog ----------------------------------------------------------------------


def _enum_values(node):
    """Every value of every ``enum`` under ``node``."""
    values = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if isinstance(item.get("enum"), list):
                values.extend(item["enum"])
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return values


def test_the_catalog_lists_the_shipped_plugins_the_schema_does_not_publish(hook, built):
    sections = {
        kind: {s["name"] for s in built.block["sections"][kind]}
        for kind in hook.SEGMENTS
    }
    singular = {
        "scanner": "scanners",
        "reporter": "reporters",
        "converter": "converters",
    }
    catalog = built.block["optIn"]
    assert catalog
    for entry in catalog:
        assert entry["name"] not in sections[singular[entry["kind"]]], entry
        assert entry["module"].startswith("automated_security_helper.plugin_modules.")
    reporters = {e["name"] for e in catalog if e["kind"] == "reporter"}
    assert {
        "aws-security-hub",
        "bedrock-summary-reporter",
        "cloudwatch-logs",
        "s3",
    } <= reporters
    export_values = set(
        _enum_values(built.block["validationSchema"]["$defs"]["ExportFormat"])
    )
    assert {"aws-security-hub", "s3"} <= export_values, (
        "the four reporter names are also output_formats values, so a section is "
        "recognized by its key and never by one of those values"
    )


def test_a_plugin_the_schema_publishes_is_not_listed_as_opt_in(hook, fields):
    data = {
        "categories": {},
        "catalog": [{"name": "bandit", "kind": "scanner", "module": "m"}],
    }
    sections, opt_in = hook.build_sections_and_opt_in(fields, data, {})
    assert opt_in == []
    assert "bandit" in {s["name"] for s in sections["scanners"]}
    data["catalog"].append({"name": "not-published", "kind": "scanner", "module": "m"})
    assert [e["name"] for e in hook.build_sections_and_opt_in(fields, data, {})[1]] == [
        "not-published"
    ]


# -- Trust rules: the probe, the rules it cannot reach, and the three parity checks ----


def test_the_probe_stays_within_the_build_budget(built):
    probe = built.report["probe"]
    assert probe["seconds"] < PROBE_SECONDS_LIMIT, f"{probe['seconds']:.1f} s"
    assert probe["rules"], "the probe found no rule at all"


def test_every_trust_id_exists_and_every_trust_path_matches_a_field(hook, built):
    assert hook.trust_problems(built.block) == []
    ids = [r["id"] for r in built.block["trust"]]
    assert len(ids) == len(set(ids))
    for rule in built.block["trust"]:
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]*", rule["id"]), rule["id"]
        assert (
            rule["source"].count(":") == 1
            and (REPO_ROOT / rule["source"].split(":")[0]).is_file()
        )


@pytest.mark.parametrize(
    "plant",
    [
        lambda block: block["fields"]["project_name"].update(trust="no-such-rule"),
        lambda block: block["trust"].append(copy.deepcopy(block["trust"][0])),
        lambda block: block["trust"][0].update(paths=["no.such.path"]),
    ],
    ids=["an unknown id", "a repeated id", "a path matching no field"],
)
def test_a_trust_rule_that_breaks_the_rules_is_reported(hook, built, plant):
    planted = copy.deepcopy(built.block)
    plant(planted)
    assert hook.trust_problems(planted)


def _rows(hook):
    """The rows that name a scanner's option: a row with no path is about settings no
    published key names (a baseline file's own content, a plugin's declarations)."""
    return [
        row for row in hook.trust_table() if row.applies_at == "scanner" and row.paths
    ]


def _row(hook, ident):
    return next(row for row in hook.trust_table() if row.ident == ident)


def _call_site_keys(root):
    """The ``scanners.<name>.options.<option>`` keys the scanners pass to the
    operator checks, found by reading their source: string literals and f-strings,
    followed through assignments and through the arguments of the functions they
    are passed to."""
    positions = {
        "_operator_gated": 0,
        "set_by_operator": 1,
        "operator_path": 1,
        "operator_paths": 1,
        "operator_value": 1,
    }
    key = re.compile(r"^scanners\.[a-z0-9-]+\.options\.[A-Za-z0-9_.]+$")
    found: dict[str, list[str]] = {}

    def name_of(call):
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        return func.attr if isinstance(func, ast.Attribute) else None

    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        functions: dict[str, list] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(node.name, []).append(node)

        def enclosing(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node
            return None

        def values(node, func, depth=0):
            if depth > 6:
                return None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return {node.value}
            if isinstance(node, ast.JoinedStr):
                parts = []
                for piece in node.values:
                    if isinstance(piece, ast.Constant):
                        parts.append({piece.value})
                    elif isinstance(piece, ast.FormattedValue):
                        inner = values(piece.value, func, depth + 1)
                        if inner is None:
                            return None
                        parts.append(inner)
                return {"".join(c) for c in itertools.product(*parts)}
            if isinstance(node, ast.Name) and func is not None:
                return named(node.id, func, depth + 1)
            return None

        def named(name, func, depth):
            out: set[str] = set()
            seen = False
            for node in ast.walk(func):
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == name for t in node.targets
                ):
                    inner = values(node.value, func, depth)
                    if inner is None:
                        return None
                    out |= inner
                    seen = True
                elif (
                    isinstance(node, ast.For)
                    and isinstance(node.target, ast.Name)
                    and node.target.id == name
                ):
                    if not isinstance(node.iter, (ast.Tuple, ast.List)):
                        return None
                    items = [values(e, func, depth) for e in node.iter.elts]
                    if any(i is None for i in items):
                        return None
                    for item in items:
                        out |= item
                    seen = True
            if seen:
                return out
            arguments = func.args
            if name in [
                a.arg
                for a in arguments.posonlyargs + arguments.args + arguments.kwonlyargs
            ]:
                return from_callers(func, name, depth)
            return None

        def from_callers(func, name, depth):
            params = [a.arg for a in func.args.posonlyargs + func.args.args]
            offset = 1 if params and params[0] in ("self", "cls") else 0
            out: set[str] = set()
            callers = 0
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and name_of(node) == func.name):
                    continue
                argument = None
                if name in params and 0 <= params.index(name) - offset < len(node.args):
                    argument = node.args[params.index(name) - offset]
                for keyword in node.keywords:
                    if keyword.arg == name:
                        argument = keyword.value
                if argument is None:
                    continue
                callers += 1
                inner = values(argument, enclosing(node), depth + 1)
                if inner is None:
                    return None
                out |= inner
            return out if callers else None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called = name_of(node)
            if called in positions:
                index = positions[called]
                target = node.args[index] if index < len(node.args) else None
                for keyword in node.keywords:
                    if keyword.arg == "key":
                        target = keyword.value
            elif called == "honored_path":
                target = next((k.value for k in node.keywords if k.arg == "key"), None)
            else:
                continue
            if target is None:
                continue
            for text in values(target, enclosing(node)) or ():
                if key.match(text):
                    found.setdefault(text, []).append(f"{path.name}:{node.lineno}")
    return found


def test_the_table_equals_a_static_read_of_the_scanners_call_sites(hook, tmp_path):
    table = {path for row in _rows(hook) for path in row.paths}
    scanned = set(_call_site_keys(PLUGIN_MODULES))
    assert scanned, "the static read found no call site at all"
    assert table - scanned == set(NOT_FOUND_BY_THE_SCAN), sorted(table - scanned)
    assert scanned - table == set(), sorted(scanned - table)
    assert not (set(NOT_FOUND_BY_THE_SCAN) & scanned), "an exception the scan now finds"


def test_a_scanner_that_gates_an_option_the_table_lacks_is_found_by_the_read(tmp_path):
    scanners = tmp_path / "scanners"
    scanners.mkdir()
    (scanners / "planted.py").write_text(
        "class Planted:\n"
        "    def run(self):\n"
        "        return self._operator_gated(\n"
        '            "scanners.planted.options.new_switch", True, False, "x"\n'
        "        )\n"
        "    def other(self, config, name):\n"
        '        key = f"scanners.planted.options.{name}"\n'
        "        return set_by_operator(config, key, 1)\n"
        "    def caller(self, config):\n"
        '        self.other(config, "second")\n',
        encoding="utf-8",
    )
    assert set(_call_site_keys(tmp_path)) == {
        "scanners.planted.options.new_switch",
        "scanners.planted.options.second",
    }


def _published(hook, fields, row):
    return sorted(
        p for pattern in row.paths for p in fields if hook.matches(pattern, p)
    )


def test_the_table_equals_the_published_descriptions_that_say_the_operator_sets_them(
    hook, built, fields
):
    described = {
        p
        for p, f in fields.items()
        if "Used only when the operator sets it" in (f.get("description") or "")
    }
    assert len(described) >= 20
    covered = {p for p, f in fields.items() if "trust" in f}
    assert described - covered == set(), (
        "a description names a rule no trust rule covers"
    )
    table = {p for row in _rows(hook) for p in _published(hook, fields, row)}
    assert table - described == set(NOT_DESCRIBED_THAT_WAY), sorted(table - described)
    assert not (set(NOT_DESCRIBED_THAT_WAY) & described), (
        "an exception that is described after all"
    )


def test_a_description_without_a_rule_is_found_by_the_check(fields):
    described = {"scanners.bandit.options.config_file", "scanners.invented.options.x"}
    covered = {p for p, f in fields.items() if "trust" in f}
    assert described - covered == {"scanners.invented.options.x"}


def test_the_table_equals_the_constants_of_ash_it_restates(hook):
    from automated_security_helper.config import plugin_module_trust, reporter_trust

    rows = {row.ident: row for row in hook.trust_table()}
    reporters = {p.split(".", 1)[1] for p in rows["off-host-reporters"].paths}
    assert reporters == set(reporter_trust.REPORTER_ENABLED_DEFAULTS)
    packages = plugin_module_trust.OFF_HOST_PLUGIN_PACKAGES
    assert packages, "ASH names no off-host package"
    text = " ".join(rows["plugin-modules"].keep)
    assert all(package in text for package in packages)
    for row in hook.trust_table():
        assert hook.locate(row).split(":")[0] == row.file


def test_a_table_row_whose_function_or_literal_moved_stops_the_build(hook):
    row = next(r for r in hook.trust_table() if r.ident == "zizmor-online-audits")
    assert hook.locate(row).startswith(row.file + ":")
    with pytest.raises(hook.ProjectionError, match="has no function"):
        hook.locate(row._replace(function="ZizmorScanner._renamed"))
    with pytest.raises(hook.ProjectionError, match="no longer holds"):
        hook.locate(row._replace(needle="scanners.zizmor.options.other"))


def test_each_table_row_reads_as_set_by_the_operator_only_in_an_operator_file(
    hook, built, fields, record_property
):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.config_trust import set_by_operator

    leaves = hook.probe_leaves(fields)
    wanted = {}
    for row in _rows(hook):
        for path in _published(hook, fields, row):
            if path in leaves and path not in wanted:
                wanted[path] = leaves[path][0]

    def document_of(batch):
        document: dict = {}
        for path, value in batch.items():
            hook.merge_documents(document, hook.plant(fields, path, value) or {})
        return document

    def loads(batch):
        try:
            hook.load_repository_file(built.workdir, document_of(batch))
        except Exception:
            return False
        return True

    planted = (
        wanted
        if loads(wanted)
        else {path: value for path, value in wanted.items() if loads({path: value})}
    )
    refused = sorted(set(wanted) - set(planted))
    record_property("table_paths_refused_when_planted", ", ".join(refused) or "none")
    assert len(planted) >= 15, refused
    document = document_of(planted)
    with_repository, _ = hook.load_repository_file(built.workdir, document)
    operator = built.workdir / "operator"
    operator.mkdir(exist_ok=True)
    (operator / "ash.yaml").write_text(hook.yaml_text(document), encoding="utf-8")
    with_operator = resolve_config(
        config_path=operator / "ash.yaml",
        source_dir=operator,
        scanned_root=built.workdir / "repository",
        fallback_to_default=False,
    )
    for path, value in planted.items():
        assert set_by_operator(with_operator, path, value) is True, (
            f"{path} in an operator's file"
        )
        assert set_by_operator(with_repository, path, value) is False, (
            f"{path} in a repository's file"
        )


def test_the_probe_reads_a_planted_operator_only_option_as_ignored(built, fields):
    rules = {r["id"]: r for r in built.block["trust"]}
    path = "scanners.detect-secrets.options.max_worker_output_mib"
    assert "trust" in fields[path], f"no rule covers {path}"
    rule = rules[fields[path]["trust"]]
    assert (rule["rule"], rule["via"], rule["appliesAt"]) == (
        "ignored",
        "probe",
        "load",
    )


def test_a_planted_file_is_read_back_as_kept_replaced_or_ignored(hook, built, fields):
    from automated_security_helper.config.ash_config import AshConfig

    defaults = AshConfig()
    cases = {
        "converters.archive.options.max_members": 1_000_000,
        "scanners.detect-secrets.options.max_worker_output_mib": 7,
        "fail_on_findings": not fields["fail_on_findings"]["default"],
    }
    document: dict = {}
    for path, value in cases.items():
        hook.merge_documents(document, hook.plant(fields, path, value) or {})
    config, out = hook.load_repository_file(built.workdir, document)
    result = hook.read_back(config, out, cases, defaults)
    assert result["converters.archive.options.max_members"] == "replaced"
    assert result["scanners.detect-secrets.options.max_worker_output_mib"] == "ignored"
    assert result["fail_on_findings"] == "kept"


# -- Rules a load shows in a way no planted value can: scan settings, a baseline, plugins ---

SCAN_SETTINGS = "scanners.detect-secrets.options.scan_settings"
VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
SEQUENTIAL_FILTER = "detect_secrets.filters.heuristic.is_sequential_string"
FILE_PLUGIN = "file:///probe/plugin.py"
FILE_FILTER = "file:///probe/filter.py::is_planted"


def _load_as_operator(hook, built, document):
    """Load a planted document as an operator's own file: outside the scanned root and
    every checkout, so none of the repository-file rules is applied to it."""
    from automated_security_helper.config.resolve_config import resolve_config

    operator = built.workdir / "operator"
    operator.mkdir(exist_ok=True)
    (built.workdir / "repository").mkdir(exist_ok=True)
    (operator / "ash.yaml").write_text(hook.yaml_text(document), encoding="utf-8")
    return resolve_config(
        config_path=operator / "ash.yaml",
        source_dir=operator,
        scanned_root=built.workdir / "repository",
        fallback_to_default=False,
    )


def _scan_settings_document():
    settings = {
        "plugins_used": [
            {"name": "KeywordDetector"},
            {"name": "PlantedPlugin", "path": FILE_PLUGIN},
        ],
        "filters_used": [
            {"path": SEQUENTIAL_FILTER},
            {"path": VERIFICATION_FILTER},
            {"path": FILE_FILTER},
        ],
    }
    return {"scanners": {"detect-secrets": {"options": {"scan_settings": settings}}}}


def test_the_scan_settings_of_detect_secrets_carry_the_rule_a_load_applies(
    hook, built, fields
):
    row = _row(hook, "detect-secrets-scan-settings")
    assert fields[SCAN_SETTINGS]["kind"] == "raw"
    rule = {r["id"]: r for r in built.block["trust"]}[fields[SCAN_SETTINGS]["trust"]]
    assert (rule["id"], rule["rule"], rule["via"], rule["appliesAt"]) == (
        row.ident,
        "limited",
        "table",
        "load",
    )
    assert rule["source"].startswith(
        "automated_security_helper/config/secret_verification_trust.py:"
    )


def test_a_repository_file_loses_the_verification_filter_and_the_file_entries(
    hook, built
):
    document = _scan_settings_document()
    config, _ = hook.load_repository_file(built.workdir, document)
    kept = config.scanners.detect_secrets.options.scan_settings
    assert [p.name for p in kept.plugins_used] == ["KeywordDetector"]
    assert [f.path for f in kept.filters_used] == [SEQUENTIAL_FILTER]


def test_an_operators_file_keeps_every_entry_a_repository_file_loses(hook, built):
    config = _load_as_operator(hook, built, _scan_settings_document())
    kept = config.scanners.detect_secrets.options.scan_settings
    assert [p.name for p in kept.plugins_used] == ["KeywordDetector", "PlantedPlugin"]
    assert [f.path for f in kept.filters_used] == [
        SEQUENTIAL_FILTER,
        VERIFICATION_FILTER,
        FILE_FILTER,
    ]


def _baseline_settings():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanSettings,
    )

    return DetectSecretsScanSettings(
        plugins_used=[
            {"name": "KeywordDetector"},
            {"name": "PlantedPlugin", "path": FILE_PLUGIN},
        ],
        filters_used=[
            {"path": SEQUENTIAL_FILTER},
            {"path": VERIFICATION_FILTER},
            {"path": FILE_FILTER},
        ],
    )


def test_a_baseline_files_own_settings_are_held_to_the_same_rule(hook):
    from automated_security_helper.config.secret_verification_trust import (
        UntrustedDetectSecretsSettings,
        drop_untrusted_entries,
    )

    row = _row(hook, "detect-secrets-baseline-settings")
    assert (row.applies_at, row.paths) == ("scanner", ())
    other = UntrustedDetectSecretsSettings(
        reason="a baseline that is not the operator's"
    )
    settings = _baseline_settings()
    removed = drop_untrusted_entries(settings, other, keep_verification=False)
    assert removed == [FILE_PLUGIN, VERIFICATION_FILTER, FILE_FILTER]
    assert [f.path for f in settings.filters_used] == [SEQUENTIAL_FILTER]
    named = UntrustedDetectSecretsSettings(
        reason="a baseline the operator names",
        operator_verifies=True,
        operator_paths=frozenset({FILE_PLUGIN, FILE_FILTER}),
    )
    kept = _baseline_settings()
    assert drop_untrusted_entries(kept, named) == []
    assert len(kept.plugins_used) == 2 and len(kept.filters_used) == 3


def test_a_reporter_a_plugin_module_adds_is_read_by_what_it_declares(hook):
    from automated_security_helper.config import reporter_trust

    row = _row(hook, "plugin-reporter-destinations")
    assert (row.applies_at, row.paths) == ("plugin", ())

    class Planted:
        destination_options = ("endpoint",)
        sends_off_host = True

    class Local:
        pass

    assert reporter_trust.declared_destination_options([Planted, Local]) == {
        "planted": ("endpoint",)
    }
    assert reporter_trust.declared_off_host_reporters([Planted, Local]) == ("planted",)
    assert reporter_trust.declared_enabled_defaults([Planted, Local]) == {
        "planted": True
    }


# -- A setting is a repository-file rule only if an operator's file keeps its value ---------

OPENGREP_VERSION = "scanners.opengrep.options.version"


def test_a_release_tag_for_the_opengrep_version_is_kept_in_a_repository_file(
    hook, built, fields
):
    assert "trust" not in fields[OPENGREP_VERSION], (
        "the editor would badge a setting a repository's file keeps"
    )
    document = hook.plant(fields, OPENGREP_VERSION, "v1.9.0")
    config, _ = hook.load_repository_file(built.workdir, document)
    assert config.scanners.opengrep.options.version == "v1.9.0"


def test_a_value_that_is_no_release_tag_is_replaced_whoever_wrote_it(
    hook, built, fields
):
    document = hook.plant(fields, OPENGREP_VERSION, "probe-name")
    default = fields[OPENGREP_VERSION]["default"]
    repository, _ = hook.load_repository_file(built.workdir, document)
    operator = _load_as_operator(hook, built, document)
    assert repository.scanners.opengrep.options.version == default
    assert operator.scanners.opengrep.options.version == default


def test_no_setting_is_a_rule_only_because_its_validator_resets_the_value(
    hook, built, fields
):
    """A value a repository's file loses is a trust rule only when an operator's file
    keeps it: a validator that resets what it does not accept does that for any file."""
    from automated_security_helper.config.ash_config import AshConfig

    leaves = hook.probe_leaves(fields)
    rounds: dict[int, dict] = {}
    for path, seen in built.report["probe"]["outcomes"].items():
        for step, outcome in enumerate(seen):
            if outcome != "kept":
                rounds.setdefault(step, {})[path] = leaves[path][step]
    assert rounds, "the probe found no rule at all"
    defaults = AshConfig()

    def outcomes_of(batch):
        document: dict = {}
        for path, value in batch.items():
            hook.merge_documents(document, hook.plant(fields, path, value) or {})
        config = _load_as_operator(hook, built, document)
        return hook.read_back(config, [], batch, defaults)

    lost = {}
    for batch in rounds.values():
        try:
            found = outcomes_of(batch)
        except Exception:
            found = {}
            for path, value in batch.items():
                try:
                    found.update(outcomes_of({path: value}))
                except Exception:
                    found[path] = "inconclusive"
        lost.update({p: o for p, o in found.items() if o in ("replaced", "ignored")})
    assert lost == {}, lost


# -- What the probe does not plant -------------------------------------------------------------


def test_the_settings_the_probe_plants_no_value_for_are_listed(hook, built, fields):
    unplanted = built.report["probe"]["unplanted"]
    assert unplanted == UNPLANTED
    assert "trust" in fields[SCAN_SETTINGS], (
        "an unplanted setting ASH confines has no rule"
    )
    planted = set(hook.probe_leaves(fields))
    assert not planted & set(unplanted)


def test_every_setting_ash_checks_against_a_vocabulary_of_its_own_is_probed(
    hook, built
):
    unprobed = built.report["probe"]["unprobed"]
    refused = {
        path: unprobed[path] for path in hook.special_leaves() if path in unprobed
    }
    assert refused == {}, refused


def test_each_setting_the_probe_leaves_to_the_table_has_a_table_rule(
    hook, built, fields
):
    rules = {rule["id"]: rule for rule in built.block["trust"]}
    for path in hook.PROBE_EXCLUDED:
        if path in ("extends", "patch"):
            continue
        assert "trust" in fields[path], (
            f"{path} is left out of the probe and of the table"
        )
        assert rules[fields[path]["trust"]]["via"] == "table", path


def test_a_list_of_network_scanners_in_a_repository_file_is_kept_only_as_a_limit(
    hook, built
):
    config, _ = hook.load_repository_file(
        built.workdir, {"sandbox": {"network_scanners": ["bandit"]}}
    )
    assert config.sandbox.network_scanners is None
    assert config.sandbox.network_limit == ["bandit"]
    rule = next(
        r for r in built.block["trust"] if r["id"] == "sandbox-network-scanners"
    )
    assert (rule["rule"], rule["via"], rule["appliesAt"]) == (
        "limited",
        "table",
        "load",
    )


def test_a_refused_load_is_reported_without_the_build_directory(hook, tmp_path):
    # The message names the planted file as the loader prints a path: with the
    # separators of the system the build runs on.
    planted = tmp_path / "repository" / ".ash.yaml"
    refused = ValueError(f"refused '{planted}': Invalid value at 'x'")
    text = hook.failure_text(refused, tmp_path)
    assert text.startswith("ValueError: refused '<repository>")
    assert text.endswith(".ash.yaml': Invalid value at 'x'")
    assert str(tmp_path) not in text
    assert len(hook.failure_text(ValueError("x" * 1000), tmp_path)) <= 300


#: A Windows temporary directory, and the same one written with slashes. The marker
#: is the part of it that would show if a message kept the directory.
WINDOWS_DIRECTORY = (
    r"C:\Users\runner\AppData\Local\Temp\pytest-of-runner\pytest-0\build-dir-marker0"
)
SLASHED_DIRECTORY = WINDOWS_DIRECTORY.replace("\\", "/")
POSIX_DIRECTORY = "/tmp/pytest-of-runner/pytest-0/build-dir-marker0"


@pytest.mark.parametrize(
    ("directory", "planted"),
    [
        (WINDOWS_DIRECTORY, WINDOWS_DIRECTORY + "\\repository\\.ash.yaml"),
        (WINDOWS_DIRECTORY, WINDOWS_DIRECTORY + "/repository/.ash.yaml"),
        (WINDOWS_DIRECTORY, SLASHED_DIRECTORY + "/repository/.ash.yaml"),
        (WINDOWS_DIRECTORY, SLASHED_DIRECTORY + "\\repository\\.ash.yaml"),
        (SLASHED_DIRECTORY, WINDOWS_DIRECTORY + "\\repository\\.ash.yaml"),
        (POSIX_DIRECTORY, POSIX_DIRECTORY + "/repository/.ash.yaml"),
    ],
    ids=[
        "backslashes only",
        "a slash after the temporary directory",
        "slashes only",
        "slashes, then backslashes",
        "a directory written with slashes, a message with backslashes",
        "a POSIX directory",
    ],
)
def test_the_build_directory_is_left_out_whichever_separator_the_message_uses(
    hook, directory, planted
):
    refused = ValueError(f"refused '{planted}': Invalid value at 'x'")
    text = hook.failure_text(refused, directory)
    assert "build-dir-marker" not in text, text
    assert text.startswith("ValueError: refused '<repository>"), text
    assert text.endswith(".ash.yaml': Invalid value at 'x'"), text


def test_a_windows_host_is_refused_before_anything_is_measured(
    hook, tmp_path, monkeypatch
):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(
        hook.ProjectionError,
        match=re.escape(
            "the trust probe measures ASH on the build host and needs Linux or macOS"
        ),
    ):
        hook.check_host(tmp_path, {})


def test_the_probe_runs_on_the_pinned_host_and_restores_the_environment(
    hook, fields, tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_CONFIG", "/nonexistent/config.yaml")
    with hook.pinned_host(tmp_path, fields):
        inside = os.environ.get("ASH_CONFIG")
    assert inside is None
    assert os.environ["ASH_CONFIG"] == "/nonexistent/config.yaml"


def test_a_host_whose_defaults_moved_when_ash_was_imported_stops_the_probe(
    hook, fields, tmp_path, monkeypatch
):
    shifted = copy.deepcopy(dict(fields))
    shifted["project_name"] = {
        **fields["project_name"],
        "default": "not-the-shipped-default",
    }
    with pytest.raises(hook.ProjectionError, match="project_name"):
        hook.check_host(tmp_path, shifted)
