# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fail-closed gate on externality-consulting sites.

A plugin's maturity tier is registry membership
(``automated_security_helper/plugins/registries.py``), and the maintainer's
budget is that consulting it -- reading one registry's members and not the
other's, branching on a tier token, or spelling the tier's name in product
identifiers or messages -- happens in at most five places. Before the
registries landed the same fact lived in four parallel carriers and was
consulted at nine product sites; this gate is what stops that regrowth, the
way ``tests/unit/test_no_core_to_cli_imports.py`` stops layering regrowth.

Two passes over ``automated_security_helper/**/*.py``:

* an AST pass that flags (a) a module referencing one registry (``CORE`` or
  ``ALPHA``) without the other -- a uniform iteration over both, or over
  ``SHIPPED_REGISTRIES``/``registry_of``, is not a consultation -- and (b) any
  reference to the deprecated tier tokens (``Tier.ALPHA_OPTIN``,
  ``Tier.BUILTIN_DEFAULT``); bindings are followed, so an aliased import
  (``from ...registries import ALPHA as A``) is caught by binding, not
  spelling;
* a token pass that flags the word "alpha" in identifiers and string literals
  (docstrings included). Comments are prose, not consultation, and are
  skipped; so are URLs, the repo's own opt-in file name, spellings where
  "alpha" is part of a longer word (``isalpha``, ``alphabet``,
  ``alphanumeric``), the per-plugin self-descriptions under
  ``plugin_modules/`` (a plugin may say what it is; the AST pass still covers
  those files), and the vendored CycloneDX schema module (upstream text).

Fail-closed in both directions: a hit outside the allowlist fails naming the
file and line; an allowlisted file with zero hits fails too (a stale allowlist
is also drift); an allowlist outside the ordered 3-5 window fails; and the
scanner itself is proven live by planted controls -- a smuggled consultation
that must flag and a clean source that must pass -- so a dead scanner reads
red, never green.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"

#: The admitted files: every externality consultation in the package lives in
#: one of these, each named with why it is admitted. The two definition sites
#: (A-1 core, A-2 alpha) share the first file; the enable-default policy and
#: the unloaded-name hint are the second (A-3); the last two are the
#: compatibility window's carriers and retire with it (3.9.0), folding into
#: A-3 and into registry membership respectively. The docs/inventory grouping
#: generator (A-4, ``scripts/``) and the CI conformance gate (A-5,
#: ``.github/`` and this file) live outside the scanned package tree.
ADMITTED_FILES = {
    "automated_security_helper/plugins/registries.py": (
        "A-1 + A-2: the two registry definitions; something has to say which "
        "members load unnamed and which need naming"
    ),
    "automated_security_helper/plugins/enablement.py": (
        "A-3: the enable-default policy and the shipped-but-unloaded hint; the "
        "one behavioral meaning membership has"
    ),
    "automated_security_helper/core/alpha_scanners.py": (
        "transitional: the one-release import shim onto plugins.enablement "
        "plus the community-tier alias warning; retires in 3.9.0"
    ),
    "automated_security_helper/base/scanner_operational_facets.py": (
        "transitional: the deprecated per-scanner Tier vocabulary, accepted "
        "and ignored until 3.9.0"
    ),
}

#: The window the maintainer ordered: "there should only be 3-5 places".
SITE_WINDOW = range(3, 6)

#: Registry names whose asymmetric use is a consultation.
_REGISTRY_NAMES = {"CORE", "ALPHA"}
#: The deprecated tier tokens; any attribute reference to them is flagged.
_TIER_TOKENS = {"ALPHA_OPTIN", "BUILTIN_DEFAULT"}
_REGISTRIES_MODULE = "automated_security_helper.plugins.registries"

#: The word, in identifiers and strings: "alpha" not embedded in a longer
#: word, so ``alpha_optin`` and ``alpha-tier`` hit while ``isalpha``,
#: ``alphabet`` and ``alphanumeric`` do not.
_ALPHA_WORD = re.compile(r"(?i)(?<![a-z0-9])alpha(?![a-z0-9])")

#: String content carrying one of these around the match is prose that names a
#: thing, not a consultation: URLs, and the repo's own opt-in file.
_STRING_EXCLUSIONS = ("://", ".ash_alpha_plugins.yaml")

#: Directories whose files the TOKEN pass skips (the AST pass still runs):
#: plugins may describe themselves, and vendored upstream text is not ours.
_TOKEN_PASS_SKIPS = (
    "automated_security_helper/plugin_modules/",
    "automated_security_helper/schemas/cyclonedx_bom_1_6_schema/",
)


def token_hits(source: str, rel_path: str) -> list[tuple[int, str]]:
    """``(line, reason)`` for every tier word in identifiers and strings."""
    if any(rel_path.startswith(skip) for skip in _TOKEN_PASS_SKIPS):
        return []
    hits: list[tuple[int, str]] = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for tok in tokens:
        if tok.type == tokenize.NAME and _ALPHA_WORD.search(tok.string):
            hits.append((tok.start[0], f"identifier {tok.string!r}"))
        elif tok.type == tokenize.STRING and _ALPHA_WORD.search(tok.string):
            if any(marker in tok.string for marker in _STRING_EXCLUSIONS):
                continue
            hits.append((tok.start[0], "string literal carrying the tier word"))
    return hits


class _RegistryUse(ast.NodeVisitor):
    """Which registry names a module binds or references, followed by binding."""

    def __init__(self) -> None:
        self.referenced: dict[str, int] = {}  # registry name -> first line
        self.tier_tokens: list[tuple[int, str]] = []
        self._aliases: dict[str, str] = {}  # local name -> registry name
        self._module_aliases: set[str] = set()  # local names of the module

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports resolve inside the package; match on the suffix so
        # ``from ..plugins.registries import ALPHA`` and the absolute spelling
        # are one case.
        module = node.module or ""
        if module.endswith("registries"):
            for alias in node.names:
                if alias.name in _REGISTRY_NAMES:
                    local = alias.asname or alias.name
                    self._aliases[local] = alias.name
                    self.referenced.setdefault(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == _REGISTRIES_MODULE or alias.name.endswith(".registries"):
                self._module_aliases.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        registry = self._aliases.get(node.id)
        if registry is not None and isinstance(node.ctx, ast.Load):
            self.referenced.setdefault(registry, node.lineno)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _TIER_TOKENS:
            self.tier_tokens.append((node.lineno, f"tier token .{node.attr}"))
        if node.attr in _REGISTRY_NAMES and isinstance(node.value, ast.Name):
            if node.value.id in self._module_aliases or node.value.id == "registries":
                self.referenced.setdefault(node.attr, node.lineno)
        self.generic_visit(node)


def ast_hits(source: str, rel_path: str) -> list[tuple[int, str]]:
    """``(line, reason)`` for asymmetric registry reads and tier tokens."""
    visitor = _RegistryUse()
    visitor.visit(ast.parse(source))
    hits = list(visitor.tier_tokens)
    if len(visitor.referenced) == 1:
        ((registry, line),) = visitor.referenced.items()
        reason = (
            f"references registry {registry} without the other: a uniform "
            "iteration touches both"
        )
        hits.append((line, reason))
    return hits


def scan_file(path: Path, rel_path: str) -> list[tuple[int, str]]:
    source = path.read_text(encoding="utf-8")
    return sorted(token_hits(source, rel_path) + ast_hits(source, rel_path))


def _package_files() -> list[Path]:
    files = sorted(PACKAGE_ROOT.rglob("*.py"))
    assert len(files) > 100, "the package tree went missing from the scan"
    return files


def test_externality_is_consulted_only_at_the_admitted_sites() -> None:
    offenders: list[str] = []
    hit_files: set[str] = set()
    for path in _package_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        hits = scan_file(path, rel)
        if not hits:
            continue
        hit_files.add(rel)
        if rel in ADMITTED_FILES:
            continue
        for line, reason in hits:
            offenders.append(f"{rel}:{line}: {reason}")
    assert not offenders, (
        "externality consulted outside the admitted sites; either convert the "
        "site (membership is read only through plugins.enablement's policy "
        "queries, messages stay tier-neutral, grouping comes from the docs "
        "generator) or, if it is genuinely a new admitted site, add it to "
        "ADMITTED_FILES with its justification and keep the count in the 3-5 "
        "window:\n" + "\n".join(offenders)
    )
    stale = set(ADMITTED_FILES) - hit_files
    assert not stale, (
        "allowlisted files with no externality hit; a stale allowlist is also "
        f"drift -- remove them: {sorted(stale)}"
    )


def test_the_admitted_site_count_stays_inside_the_ordered_window() -> None:
    assert len(ADMITTED_FILES) in SITE_WINDOW, (
        f"{len(ADMITTED_FILES)} admitted files: the maintainer's budget is "
        "3-5 places; merging or splitting sites changes this list only with "
        "that budget re-argued"
    )
    missing = [rel for rel in ADMITTED_FILES if not (REPO_ROOT / rel).is_file()]
    assert not missing, f"allowlisted files that do not exist: {missing}"


# ---------------------------------------------------------------------------
# Planted controls: the scanner itself is proven live in both directions, so
# a zero from a dead scanner cannot read as a pass.
# ---------------------------------------------------------------------------

_SMUGGLED_ASYMMETRIC = """
from automated_security_helper.plugins.registries import ALPHA as A

def is_optin(module: str) -> bool:
    return any(module.startswith(m) for m in A.members)
"""

_SMUGGLED_TIER_TOKEN = """
from automated_security_helper.base import scanner_operational_facets as opsf

def label(facet) -> str:
    return "x" if facet.tier is opsf.Tier.ALPHA_OPTIN else "y"
"""

_SMUGGLED_IDENTIFIER = """
alpha_modules = ["a"]
"""

_CLEAN_UNIFORM = """
from automated_security_helper.plugins.registries import SHIPPED_REGISTRIES

def shipped() -> list[str]:
    return [m for r in SHIPPED_REGISTRIES for m in r.members]
"""

_CLEAN_PLAIN = """
import math

def isalpha_count(text: str) -> int:
    # the alphabet is prose here, and this comment may say alpha freely
    return sum(1 for c in text if c.isalpha()) + int(math.e)
"""


def test_planted_asymmetric_registry_read_is_flagged() -> None:
    hits = ast_hits(_SMUGGLED_ASYMMETRIC, "automated_security_helper/x.py")
    assert any("without the other" in reason for _, reason in hits), (
        "the AST pass went dead: an aliased single-registry read was not flagged"
    )


def test_planted_tier_token_is_flagged() -> None:
    hits = ast_hits(_SMUGGLED_TIER_TOKEN, "automated_security_helper/x.py")
    assert any("tier token" in reason for _, reason in hits)


def test_planted_identifier_is_flagged() -> None:
    hits = token_hits(_SMUGGLED_IDENTIFIER, "automated_security_helper/x.py")
    assert any("identifier" in reason for _, reason in hits)


def test_planted_clean_sources_pass() -> None:
    for source in (_CLEAN_UNIFORM, _CLEAN_PLAIN):
        rel = "automated_security_helper/x.py"
        assert token_hits(source, rel) + ast_hits(source, rel) == []


def test_the_token_pass_skips_are_narrow() -> None:
    # The plugin self-description skip applies to the token pass only: the
    # same smuggled identifier under plugin_modules/ is still caught by the
    # AST pass when it reads a registry asymmetrically.
    rel = "automated_security_helper/plugin_modules/x/scanner.py"
    assert token_hits(_SMUGGLED_IDENTIFIER, rel) == []
    assert ast_hits(_SMUGGLED_ASYMMETRIC, rel) != []
