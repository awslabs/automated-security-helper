# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drift gate for the scanner facets vocabularies.

The facets registers (``base/scanner_facets.py`` and
``base/scanner_operational_facets.py``) define every closed vocabulary they
use as a ``(str, Enum)`` in their own module, and every consumer compares by
member identity. This gate fails when a stray literal spelling of one of those
vocabularies reappears in the package, in two modes:

* NEGATIVE (an AST scan): every string constant in the package's Python files
  -- docstrings skipped, comments never reach the AST -- that equals a
  DISTINCTIVE member value of a registered vocabulary is flagged, unless the
  file is the vocabulary's own module. A spelling such as
  ``"mappable-dropped"`` or ``"content_fetch"`` has no business anywhere
  else.
* POSITIVE (pinned sites): short common words (``"none"``, ``"yes"``,
  ``"native"``, ``"n/a"``) cannot be scanned for without drowning in false
  positives, so for those the gate pins the known former copy sites
  explicitly (a path and a forbidden fragment) and checks the one function
  that used to hand back a state's text now hands back the member.

Scanner and converter names are deliberately NOT a vocabulary here: the set of
scanners is open (third parties register their own), and the register keys
them by configuration name.

A planted-positive control proves the scanner is alive: a deliberately stray
spelling in a fixture source must be flagged, and a clean one must not.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base import scanner_facets as mapping_register
from automated_security_helper.base import scanner_operational_facets as ops_register
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.plugin_modules import ash_builtin
from automated_security_helper.utils.scanner_tool_types import (
    _class_config_name,
    scanner_resource_id_state,
)

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE = _REPO_ROOT / "automated_security_helper"

_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()


@dataclass(frozen=True)
class Vocabulary:
    """One registered vocabulary: its enum, its home module, its scan rules."""

    enum: type[Enum]
    #: Path (relative to the repo root) of the module that defines the enum.
    #: It is the one place the spellings legitimately live.
    home: str
    #: Member values too common to scan for; covered by POSITIVE pins instead.
    ambiguous: frozenset[str] = frozenset()
    #: ``path -> reason`` for files that may spell a distinctive value.
    allowlist: dict[str, str] = field(default_factory=dict)


_MAPPING_HOME = "automated_security_helper/base/scanner_facets.py"
_OPS_HOME = "automated_security_helper/base/scanner_operational_facets.py"

VOCABULARIES: tuple[Vocabulary, ...] = (
    Vocabulary(
        FacetState,
        _MAPPING_HOME,
        # "unconfirmed" is also a member of Honored and FingerprintClass, so a
        # stray spelling of it cannot be told from theirs by value.
        ambiguous=frozenset({"mapped", "n/a", "unconfirmed"}),
    ),
    Vocabulary(ops_register.FetchKind, _OPS_HOME, ambiguous=frozenset({"none"})),
    Vocabulary(
        ops_register.Fetched,
        _OPS_HOME,
        allowlist={
            "automated_security_helper/models/flat_vulnerability.py": (
                "IMAGE_ATTRIBUTION_FIELDS names the flat row's own "
                "'image_digest' COLUMN, that column's wire name on the CSV "
                "and flat-JSON reports; Fetched.IMAGE_DIGEST names a "
                "scanner's registry read of a digest"
            ),
        },
    ),
    Vocabulary(ops_register.Prefetch, _OPS_HOME),
    Vocabulary(
        ops_register.OfflineOutcome,
        _OPS_HOME,
        ambiguous=frozenset({"unchanged", "degraded"}),
    ),
    Vocabulary(
        ops_register.SandboxNetwork,
        _OPS_HOME,
        ambiguous=frozenset({"none", "online", "verifying"}),
    ),
    Vocabulary(
        ops_register.OutputFormat,
        _OPS_HOME,
        ambiguous=frozenset({"sarif", "cyclonedx", "tool_json", "synthesized"}),
    ),
    Vocabulary(
        ops_register.TargetKind,
        _OPS_HOME,
        ambiguous=frozenset({"source_code", "dockerfiles"}),
        allowlist={
            "automated_security_helper/core/asset.py": (
                "AssetKind is the subject kind of a scan and owns the spelling "
                "'container_image' on its own wire; TargetKind names what a "
                "scanner serves"
            ),
        },
    ),
    Vocabulary(ops_register.RuntimeKind, _OPS_HOME),
    Vocabulary(
        ops_register.Invocations,
        _OPS_HOME,
        ambiguous=frozenset({"one", "per_target", "multi_pass"}),
    ),
    Vocabulary(
        ops_register.SeverityClass,
        _OPS_HOME,
        ambiguous=frozenset(
            {"native", "constant", "derived", "degraded", "not_applicable"}
        ),
    ),
    Vocabulary(
        ops_register.SilencingLayerKind,
        _OPS_HOME,
        # "ignore_file" names the ignore-file concept all over the config
        # layer (a path-class label there), so it cannot be scanned for.
        ambiguous=frozenset({"ignore_file"}),
    ),
    Vocabulary(
        ops_register.SilencingWriter,
        _OPS_HOME,
        ambiguous=frozenset({"repository", "operator", "tool_default"}),
    ),
    Vocabulary(
        ops_register.Honored,
        _OPS_HOME,
        ambiguous=frozenset({"yes", "no", "unconfirmed"}),
    ),
    Vocabulary(
        ops_register.FingerprintClass,
        _OPS_HOME,
        ambiguous=frozenset({"unconfirmed", "not_applicable"}),
    ),
    Vocabulary(
        ops_register.CustomRules,
        _OPS_HOME,
        ambiguous=frozenset({"none", "both"}),
    ),
    Vocabulary(ops_register.ProvenanceSource, _OPS_HOME),
    Vocabulary(
        ops_register.Prerequisite,
        _OPS_HOME,
        ambiguous=frozenset(
            {"none", "lockfile", "manifest", "template", "git_checkout"}
        ),
    ),
    Vocabulary(
        ops_register.RuntimeName,
        _OPS_HOME,
        # "python" and "node" name the runtimes all over the package (uv
        # --python arguments, node on PATH checks), so neither can be scanned
        # for.
        ambiguous=frozenset({"python", "node"}),
    ),
    Vocabulary(
        ops_register.CompatResolution,
        _OPS_HOME,
        # "pin" is an ordinary word (pinned versions, pinned releases); the
        # scan would drown.
        ambiguous=frozenset({"pin"}),
    ),
)


def _distinctive(vocab: Vocabulary) -> dict[str, str]:
    """``value -> member name`` for the values the AST scan may flag."""
    return {
        str(member.value): member.name
        for member in vocab.enum
        if str(member.value) not in vocab.ambiguous
    }


# --------------------------------------------------------------------------
# The scanner
# --------------------------------------------------------------------------


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Ids of the ``ast.Constant`` nodes that sit in docstring position."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def stray_spellings(source: str, values: dict[str, str]) -> list[tuple[int, str]]:
    """``(line, value)`` for every non-docstring string constant in ``values``."""
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skip
            and node.value in values
        ):
            found.append((node.lineno, node.value))
    return sorted(found)


def _package_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for path in sorted(_PACKAGE.rglob("*.py")):
        sources[path.relative_to(_REPO_ROOT).as_posix()] = path.read_text(
            encoding="utf-8"
        )
    return sources


_SOURCES = _package_sources()


# --------------------------------------------------------------------------
# NEGATIVE mode
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vocab", VOCABULARIES, ids=lambda v: v.enum.__name__)
def test_no_stray_spelling_of_a_distinctive_member_value(vocab: Vocabulary) -> None:
    values = _distinctive(vocab)
    hits: list[str] = []
    for relative, source in _SOURCES.items():
        if relative == vocab.home or relative in vocab.allowlist:
            continue
        for line, value in stray_spellings(source, values):
            hits.append(
                f"{relative}:{line}: {value!r} spells "
                f"{vocab.enum.__name__}.{values[value]}; use the member"
            )
    assert not hits, "\n".join(hits)


def test_every_vocabulary_is_its_own_module_s_enum() -> None:
    """The home path names the module that actually defines the enum."""
    for vocab in VOCABULARIES:
        module = importlib.import_module(vocab.enum.__module__)
        home = Path(module.__file__).resolve().relative_to(_REPO_ROOT).as_posix()
        assert home == vocab.home, (
            f"{vocab.enum.__name__} is defined in {home}, registered under {vocab.home}"
        )
        assert issubclass(vocab.enum, str), (
            f"{vocab.enum.__name__} must be a (str, Enum): its values are the wire "
            "spelling, and the project floor (3.10) has no StrEnum"
        )


def test_the_registry_covers_every_enum_the_two_register_modules_define() -> None:
    """A new enum in a register module cannot skip the gate."""
    defined: set[type] = set()
    for module in (mapping_register, ops_register):
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, Enum)
                and value.__module__ == module.__name__
            ):
                defined.add(value)
    registered = {v.enum for v in VOCABULARIES}
    assert defined == registered, (
        f"unregistered: {sorted(c.__name__ for c in defined - registered)}; "
        f"stale: {sorted(c.__name__ for c in registered - defined)}"
    )


def test_ambiguous_values_are_real_members() -> None:
    """An ``ambiguous`` entry that names no member is a typo that hides a scan."""
    for vocab in VOCABULARIES:
        values = {str(m.value) for m in vocab.enum}
        assert vocab.ambiguous <= values, (
            f"{vocab.enum.__name__}: {sorted(vocab.ambiguous - values)} are not "
            "member values"
        )


# --------------------------------------------------------------------------
# POSITIVE mode: the pinned former copy sites
# --------------------------------------------------------------------------

#: ``(path, forbidden string constant)``: spellings consumers used to carry
#: instead of the member. Each is an ambiguous or distinctive value taken from
#: the pre-conversion tree.
FORMER_COPY_SITES: tuple[tuple[str, str], ...] = (
    ("automated_security_helper/models/flat_vulnerability.py", "n/a"),
    ("automated_security_helper/models/flat_vulnerability.py", "mappable-dropped"),
    ("automated_security_helper/utils/scanner_tool_types.py", "mappable-dropped"),
)


@pytest.mark.parametrize(
    ("relative", "forbidden"), FORMER_COPY_SITES, ids=lambda x: str(x)[-40:]
)
def test_a_former_copy_site_no_longer_spells_the_value(
    relative: str, forbidden: str
) -> None:
    assert stray_spellings(_SOURCES[relative], {forbidden: "x"}) == []


def _registered_scanner_classes() -> list[type]:
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


@pytest.mark.parametrize(
    "scanner_cls", _registered_scanner_classes(), ids=lambda c: c.__name__
)
def test_the_resource_id_state_lookup_answers_with_the_member(
    scanner_cls: type,
) -> None:
    name = _class_config_name(scanner_cls)
    assert name, f"{scanner_cls.__name__}: no config name to look up"
    declared = vars(scanner_cls)[SCANNER_FACETS_ATTR].resource_id.state
    answered = scanner_resource_id_state(name)
    assert answered is declared, (
        f"{scanner_cls.__name__}: declared {declared!r}, looked up as {answered!r}"
    )
    assert isinstance(answered, FacetState)


@pytest.mark.parametrize("unknown", [None, "", "no-such-scanner", 7])
def test_the_resource_id_state_lookup_cannot_decide_for_an_unknown_scanner(
    unknown: object,
) -> None:
    assert scanner_resource_id_state(unknown) is None


# --------------------------------------------------------------------------
# The planted-positive control
# --------------------------------------------------------------------------

_PLANTED_STRAY = '''
"""A docstring that mentions "mappable-dropped" is not a spelling."""

STATE = "mappable-dropped"
'''

_PLANTED_CLEAN = '''
"""A docstring that mentions "mappable-dropped" is not a spelling."""

from enum import Enum


class State(Enum):
    DROPPED = 1
'''


def test_the_scanner_flags_a_planted_stray_spelling() -> None:
    values = _distinctive(VOCABULARIES[0])
    assert "mappable-dropped" in values, "the control needs a distinctive value"
    assert stray_spellings(_PLANTED_STRAY, values) == [(4, "mappable-dropped")]


def test_the_scanner_passes_a_clean_source_and_skips_docstrings() -> None:
    assert stray_spellings(_PLANTED_CLEAN, _distinctive(VOCABULARIES[0])) == []


def test_the_scan_walked_a_real_tree() -> None:
    """A scan over zero files reads clean; the denominator must be real."""
    assert len(_SOURCES) > 200
    assert _MAPPING_HOME in _SOURCES and _OPS_HOME in _SOURCES
