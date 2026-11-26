# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The drift gate for ``PluginKind`` and the RFC 6902 patch-op constants (E3).

Two modes, per vocabulary (the unit that cures a vocabulary says which):

* The STRONG mode scans the vocabulary's cured files with ``ast`` and fails on a
  string constant equal to a member value (or a derived spelling). It is used
  where the files carry no legitimate use of the word. Docstrings and comments
  are not constants in code position, so prose stays prose.
* The POSITIVE mode is for words common enough that a scan would drown in false
  hits: it pins that each table is derived from the enum, and that each
  previously inventoried copy site is gone, by an exact ``(path, fragment)`` pair.

Each mode has a planted-positive control, so a scan that has gone silent cannot
read as clean.
"""

import json
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.models.vocab import PluginKind

from tests.unit.vocab.vocab_scan import scan_scope, stray_spellings

pytestmark = pytest.mark.unit

ROOT = Path(automated_security_helper.__file__).resolve().parent


# --------------------------------------------------------------------------
# The registry: one entry per vocabulary the gate covers.
# --------------------------------------------------------------------------

#: PluginKind, STRONG mode. The scope is the files the unit cured completely: no
#: string constant in them equals a kind or a section spelling. A file that still
#: spells the words for a legitimate reason (a path segment of a config
#: override, a key walked by name) is not in the scope; it is pinned in the
#: positive mode below.
PLUGIN_KIND_SPELLINGS = (*PluginKind.values(), *PluginKind.sections())
PLUGIN_KIND_SCOPE = (
    "plugins/decorators.py",
    "plugins/plugin_manager.py",
    "plugins/loader.py",
    "config/ash_config.py",
    "config/plugin_section_names.py",
    "cli/plugin.py",
    "cli/dependencies.py",
    "utils/config_trust.py",
)
#: ``{path: reason}``: a constant kept on purpose inside the scope. Empty today.
PLUGIN_KIND_ALLOWLIST: dict = {}

#: PluginKind, POSITIVE mode: ``(path, fragment)`` pairs that must NOT occur,
#: each a copy site the catalog named and the unit removed.
PLUGIN_KIND_GONE = (
    ("plugins/decorators.py", 'Literal["converter", "scanner", "reporter"]'),
    ("plugins/plugin_manager.py", 'Literal["converter", "scanner", "reporter"]'),
    ("plugins/plugin_manager.py", 'if plugin_type == "converter"'),
    ("plugins/loader.py", '"converter",\n    "scanner",\n    "reporter",'),
    ("plugins/loader.py", 'Literal["converter", "scanner", "reporter"]'),
    ("config/ash_config.py", 'Literal["converter", "scanner", "reporter"]'),
    ("config/ash_config.py", 'case "scanner":'),
    ("config/operator_only_options.py", 'Literal["converter", "scanner", "reporter"]'),
    ("config/tool_config_trust.py", '("scanners", "scanner")'),
    ("cli/dependencies.py", 'PLUGIN_KINDS = ("converter", "scanner", "reporter")'),
    ("cli/plugin.py", '("scanner", "scanners")'),
    ("cli/plugin.py", 'rstrip("s")'),
    ("config/plugin_section_names.py", '("converters", "scanners", "reporters")'),
    ("config/runtime_patch.py", 'frozenset({"scanners", "reporters", "converters"})'),
    ("config/runtime_patch.py", '"scanners": "scanner"'),
    ("utils/config_trust.py", 'frozenset({"scanners", "converters", "reporters"})'),
)

#: RFC 6902, POSITIVE mode: the subset spellings the unit consolidated into
#: ``config/patch_ops.py``. The values are the RFC's, so these stay constants.
PATCH_OPS_GONE = (
    ("config/runtime_patch.py", '{"add", "replace"}'),
    ("config/runtime_patch.py", '{"move", "copy"}'),
    ("config/runtime_patch.py", '("add", "replace", "remove", "move", "copy")'),
    ("config/runtime_patch.py", '("add", "remove")'),
    ("config/runtime_patch.py", '("add", "replace", "remove")'),
    ("config/runtime_patch.py", 'frozenset({"add", "remove", "replace"'),
    ("config/config_sources.py", '{"add", "remove", "replace", "test"}'),
    ("config/config_sources.py", '("add", "replace")'),
    ("config/resolve_config.py", '("add", "replace", "remove")'),
    ("config/resolve_config.py", 'name in ("add", "replace")'),
    ("config/client_scanner_exclusions.py", '("add", "replace")'),
)


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Strong mode
# --------------------------------------------------------------------------


def test_plugin_kind_spellings_are_gone_from_the_cured_files():
    hits = scan_scope(ROOT, PLUGIN_KIND_SCOPE, PLUGIN_KIND_SPELLINGS)
    stray = {
        path: [h for h in found if (path, h[2]) not in PLUGIN_KIND_ALLOWLIST]
        for path, found in hits.items()
    }
    stray = {path: found for path, found in stray.items() if found}
    assert not stray, (
        "a plugin kind or section spelled as a string constant outside "
        f"models/vocab.py; use PluginKind: {stray}"
    )


def test_the_plugin_kind_allowlist_has_no_stale_entry():
    for (path, spelling), reason in PLUGIN_KIND_ALLOWLIST.items():
        assert reason, f"allowlist entry {path} {spelling!r} needs a reason"
        found = stray_spellings(ROOT / path, [spelling])
        assert found, f"allowlist entry {path} {spelling!r} no longer matches"


def test_the_scanner_flags_a_planted_stray_spelling(tmp_path):
    """The control: a dead scan would read this file as clean."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        '"""A docstring that says scanner is skipped."""\n'
        "# a comment that says reporter never reaches the AST\n"
        'KIND = "scanner"\n'
        'SECTION = ("converters", "reporters")\n',
        encoding="utf-8",
    )
    found = stray_spellings(planted, PLUGIN_KIND_SPELLINGS)
    assert [h[2] for h in found] == ["scanner", "converters", "reporters"]
    assert [h[1] for h in found] == [3, 4, 4]


def test_the_scanner_reads_the_real_scope_not_an_empty_one():
    """A control on the other side: the scope files exist and are parsed."""
    for relative in PLUGIN_KIND_SCOPE:
        assert (ROOT / relative).is_file(), relative
    # models/vocab.py is the enum's own module, deliberately outside the scope,
    # and it must read as full of the spellings: the scan sees them there.
    assert stray_spellings(ROOT / "models/vocab.py", PLUGIN_KIND_SPELLINGS)


# --------------------------------------------------------------------------
# Positive mode
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "fragment"), PLUGIN_KIND_GONE + PATCH_OPS_GONE)
def test_an_inventoried_copy_site_is_gone(path, fragment):
    assert fragment not in _source(path), f"{path} still spells {fragment!r}"


def test_the_positive_mode_flags_a_planted_copy_site():
    """The control: the fragment check finds a fragment that is there."""
    assert 'Literal["converter", "scanner", "reporter"]' in (
        'plugin_type: Literal["converter", "scanner", "reporter"],'
    )


def test_every_plugin_kind_table_is_derived_from_the_enum():
    from automated_security_helper.cli import dependencies, plugin as cli_plugin
    from automated_security_helper.config import (
        plugin_section_names,
        runtime_patch,
        tool_config_trust,
    )
    from automated_security_helper.utils import config_trust

    assert plugin_section_names.PLUGIN_SEGMENT_KEYS == PluginKind.sections()
    assert plugin_section_names._TYPE_WORDS == PluginKind.values()
    assert dependencies.PLUGIN_KINDS == PluginKind.values()
    assert config_trust._PLUGIN_SEGMENTS == frozenset(PluginKind.sections())
    assert runtime_patch._PLUGIN_SECTIONS == frozenset(PluginKind.sections())
    assert runtime_patch._PLUGIN_TYPES == {k.section: k for k in PluginKind}
    assert set(runtime_patch._SHIPPED_PLUGIN_KEYS) == set(PluginKind.sections())
    assert {kind for kind, _ in cli_plugin._PLUGIN_TYPES} == set(PluginKind)
    assert all(kind.section == section for kind, section in cli_plugin._PLUGIN_TYPES)
    assert dict(tool_config_trust._PLUGIN_SEGMENTS) == {
        PluginKind.SCANNER.section: PluginKind.SCANNER,
        PluginKind.CONVERTER.section: PluginKind.CONVERTER,
    }


def test_the_config_sections_the_validator_accepts_include_every_kind_section():
    from automated_security_helper.config.config_validator import ConfigValidator

    assert set(PluginKind.sections()) <= set(ConfigValidator.VALID_TOP_LEVEL_FIELDS)


def test_the_exit_meaning_prose_names_the_kinds_in_member_order():
    """Prose stays prose; this pins that it still says what the enum says."""
    from automated_security_helper.core.constants import (
        ASH_EXIT_BAD_SELECTION_MEANING,
    )

    values = PluginKind.values()
    spelled = ", ".join(values[:-1]) + " and " + values[-1]
    assert ASH_EXIT_BAD_SELECTION_MEANING.replace("\n", " ").endswith(spelled)


def test_the_exit_meaning_pin_is_not_vacuous():
    """The control: a different order of the kinds would not satisfy the pin."""
    values = tuple(reversed(PluginKind.values()))
    reordered = ", ".join(values[:-1]) + " and " + values[-1]
    from automated_security_helper.core.constants import (
        ASH_EXIT_BAD_SELECTION_MEANING,
    )

    assert not ASH_EXIT_BAD_SELECTION_MEANING.endswith(reordered)


# --------------------------------------------------------------------------
# RFC 6902: constants aligned with the library that applies the patches
# --------------------------------------------------------------------------


def test_the_patch_op_constants_are_the_rfc_set_and_its_subsets():
    import jsonpatch

    from automated_security_helper.config import (
        client_scanner_exclusions,
        config_sources,
        patch_ops,
        runtime_patch,
    )

    # The extracted set: the operations the patch library itself applies.
    library = frozenset(jsonpatch.JsonPatch([]).operations)
    assert patch_ops.JSON_PATCH_OPS == library
    assert patch_ops.JSON_PATCH_OPS == frozenset(
        {"add", "remove", "replace", "move", "copy", "test"}
    )
    for subset in (
        patch_ops.VALUE_WRITING_OPS,
        patch_ops.DOCUMENT_CHANGING_OPS,
        patch_ops.NODE_EDITING_OPS,
        patch_ops.INSERT_OR_DELETE_OPS,
        patch_ops.FORBIDDEN_RUNTIME_OPS,
        patch_ops.CONFIG_SOURCE_OPS,
    ):
        assert subset <= patch_ops.JSON_PATCH_OPS
    assert "test" not in patch_ops.DOCUMENT_CHANGING_OPS
    assert patch_ops.NODE_EDITING_OPS == patch_ops.VALUE_WRITING_OPS | {"remove"}
    assert runtime_patch._JSON_PATCH_OPS is patch_ops.JSON_PATCH_OPS
    assert runtime_patch._FORBIDDEN_OPS is patch_ops.FORBIDDEN_RUNTIME_OPS
    assert config_sources._PATCH_OPS is patch_ops.CONFIG_SOURCE_OPS
    assert client_scanner_exclusions.VALUE_WRITING_OPS is patch_ops.VALUE_WRITING_OPS


# --------------------------------------------------------------------------
# PluginKind itself
# --------------------------------------------------------------------------


def test_plugin_kind_members_and_sections():
    assert [m.value for m in PluginKind] == ["converter", "scanner", "reporter"]
    assert PluginKind.sections() == ("converters", "scanners", "reporters")
    assert PluginKind.values() == ("converter", "scanner", "reporter")
    for kind in PluginKind:
        assert kind.section == kind.value + "s"


def test_plugin_kind_is_a_string_on_every_boundary():
    kind = PluginKind.SCANNER
    assert kind == "scanner"
    assert hash(kind) == hash("scanner")
    assert {"scanner": 1}[kind] == 1
    assert str(kind) == "scanner"
    assert f"{kind}s" == "scanners"
    assert "%s" % kind == "scanner"
    assert json.dumps({"kind": kind}) == '{"kind": "scanner"}'
    assert f"{kind:>9}" == "  scanner"


def test_plugin_kind_ingest_helpers():
    assert PluginKind.coerce("reporter") is PluginKind.REPORTER
    assert PluginKind.coerce(PluginKind.REPORTER) is PluginKind.REPORTER
    assert PluginKind.coerce("reporters") is None
    assert PluginKind.coerce("Scanner") is None
    assert PluginKind.coerce(None) is None
    assert PluginKind.coerce(3) is None
    assert PluginKind.from_section("converters") is PluginKind.CONVERTER
    assert PluginKind.from_section("converter") is None
    assert PluginKind.from_section(None) is None
    with pytest.raises(ValueError):
        PluginKind("plugin")


def test_the_decorator_stores_a_member_and_still_takes_the_spelling():
    from automated_security_helper.plugins.decorators import ash_plugin

    class ByMember:
        pass

    class BySpelling:
        pass

    ash_plugin(ByMember, plugin_type=PluginKind.SCANNER, auto_register=False)
    ash_plugin(BySpelling, plugin_type="scanner", auto_register=False)
    assert ByMember.ash_plugin_type is PluginKind.SCANNER
    assert BySpelling.ash_plugin_type is PluginKind.SCANNER
    assert BySpelling.ash_plugin_type == "scanner"


def test_the_manager_reads_a_member_and_a_spelling_alike_and_refuses_an_unknown_kind():
    from automated_security_helper.plugins import ash_plugin_manager

    for kind in PluginKind:
        by_member = ash_plugin_manager._registry(kind)
        # A real registration dict, so the identity chain below is not three
        # Nones agreeing with each other. WHICH dict it is (the library's own
        # live section, keyed by kind.section) is plugin_manager.py's
        # implementation: the registry-isolation sweep
        # (tests/unit/workspace/test_project_isolation.py) keeps raw
        # plugin_library reads out of every file but the manager's own, this
        # one included, so the member-vs-spelling pin stays on the manager's
        # API alone.
        assert isinstance(by_member, dict)
        assert by_member is ash_plugin_manager._registry(kind.value)
        assert by_member is ash_plugin_manager._registrations(kind.value)
    assert ash_plugin_manager._registry("plugin") is None
    assert ash_plugin_manager._registry("scanners") is None
    assert ash_plugin_manager.plugin_modules("plugin") == []
