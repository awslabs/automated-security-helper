"""Every path a validate.py hint names must actually exist, checked mechanically.

Seven references in validate.py named configs.yaml, a file deleted in the
class-per-backend refactor. They went stale because nothing checked them: a hint
is a string, no test reaches the branches that print them, and a human rereading
prose does not notice that one of thirteen fragments no longer resolves. So this
resolves them against the git tree instead of trusting the text.

The subtler failure this also guards is the one an interim repair introduced. The
JSON and YAML hints were briefly rewritten to read "Edit transpiler/_base/ or the
backend's class vars under transpiler/backends/", and those two fragments cannot
both resolve from any one working directory:

    fragment              from agentic-coding/   from the transpiler project root
    transpiler/_base/     exists                 absent
    transpiler/backends/  absent                 exists

because the project root and the package inside it share the name "transpiler".
Whichever directory a reader started from, one half of the sentence pointed
somewhere that is not there. A check that only resolved each fragment
independently would have passed that text, since each fragment does exist from
*some* root. So the per-hint test below is the load-bearing one: it requires a
single root to satisfy every fragment in the same hint.

Deliberately not asserted: that hints name no path at all. They legitimately do
-- transpiler/_base/, transpiler/templates/, and the two `uv run --project`
commands -- and the fix was to drop one unresolvable fragment, not paths in
general.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# tests/ sits directly under the transpiler project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VALIDATE = PROJECT_ROOT / "validate.py"

# Every directory a reader might plausibly have their shell in when they read a
# hint. Ordered outermost-first only for legibility; the checks below try all of
# them.
CANDIDATE_ROOTS = {
    "ash-agent-plugins/": PROJECT_ROOT.parent.parent,
    "agentic-coding/": PROJECT_ROOT.parent,
    "transpiler project root": PROJECT_ROOT,
}

# A path-shaped run of characters: at least one slash, made of path-safe
# characters. Intentionally greedy about what it collects; the filter below
# removes what is not a path.
_FRAGMENT = re.compile(r"[A-Za-z0-9_.\-*]+(?:/[A-Za-z0-9_.\-*]*)+")

# Trailing sentence punctuation gets swept up by the regex ("...extension.yaml.j2.").
_TRAILING = ".,;:)]}"


def _looks_like_a_path(fragment: str) -> bool:
    """Exclude the two non-path shapes that share the slash character.

    SKILL/COMMANDS/AGENTS enumerates three class var names; *.yaml/*.yml is a
    glob pair naming file types. Neither is a location, and treating either as
    one would make this test fail on correct text -- which is worse than not
    checking, because the fix would be to weaken the test.
    """
    if "*" in fragment:
        return False
    return not fragment.replace("/", "").replace("_", "").isupper()


def _fragments(text: str) -> list[str]:
    out = []
    for raw in _FRAGMENT.findall(text):
        fragment = raw.rstrip(_TRAILING)
        if fragment and _looks_like_a_path(fragment):
            out.append(fragment)
    return out


def _hints() -> list[tuple[str, str]]:
    """(where, text) for every hint string validate.py can print, plus the docstring.

    The module docstring is included because it carried one of the seven stale
    references -- the Tier 2 summary line -- so excluding it would leave the
    original defect partly unguarded.
    """
    tree = ast.parse(VALIDATE.read_text(encoding="utf-8"))
    found: list[tuple[str, str]] = []

    doc = ast.get_docstring(tree)
    if doc:
        found.append(("module docstring", doc))

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "err"):
            continue
        hint = None
        if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
            hint = node.args[2].value
        for kw in node.keywords:
            if kw.arg == "hint" and isinstance(kw.value, ast.Constant):
                hint = kw.value.value
        if isinstance(hint, str) and hint:
            found.append((f"validate.py:{node.lineno}", hint))
    return found


HINTS = _hints()


def _roots_satisfying(fragment: str) -> set[str]:
    return {
        name for name, root in CANDIDATE_ROOTS.items() if (root / fragment).exists()
    }


def test_the_extractor_actually_found_the_hints():
    """Guard the guard: an extractor returning nothing would pass every test below.

    If `err()` is renamed or the hints move to a constant, this fails loudly
    instead of the suite reporting a clean bill of health over zero strings.
    """
    assert len(HINTS) >= 20, f"only found {len(HINTS)} hints; the extractor is stale"
    with_paths = [h for h in HINTS if _fragments(h[1])]
    assert len(with_paths) >= 8, (
        f"only {len(with_paths)} hints yielded a path fragment; the fragment "
        f"regex or the path filter has stopped matching"
    )


@pytest.mark.parametrize("where,text", HINTS, ids=[h[0] for h in HINTS])
def test_every_path_a_hint_names_exists(where, text):
    for fragment in _fragments(text):
        assert _roots_satisfying(fragment), (
            f"{where} names '{fragment}', which does not exist under any of "
            f"{sorted(CANDIDATE_ROOTS)}. This is the configs.yaml defect: a hint "
            f"printed next to a validation failure, sending the reader to a path "
            f"that is not in the tree."
        )


@pytest.mark.parametrize("where,text", HINTS, ids=[h[0] for h in HINTS])
def test_one_hint_never_mixes_fragments_needing_different_roots(where, text):
    """The invariant an independent per-fragment check cannot see.

    Each fragment resolving from *somewhere* is not enough; a reader stands in
    one directory at a time.
    """
    fragments = _fragments(text)
    if len(fragments) < 2:
        return

    shared = set(CANDIDATE_ROOTS)
    for fragment in fragments:
        shared &= _roots_satisfying(fragment)

    assert shared, (
        f"{where} names {fragments}, and no single working directory resolves all "
        f"of them:\n"
        + "\n".join(
            f"    {frag}: resolves from {sorted(_roots_satisfying(frag)) or 'nowhere'}"
            for frag in fragments
        )
        + "\nA reader following this hint finds one half of it missing whichever "
        "directory they picked."
    )


def test_no_hint_names_a_file_the_refactor_deleted():
    """configs.yaml, transpile.py and schema.py went away with the refactor.

    A name check as well as a path check, because `configs.yaml` on its own has no
    slash and so is invisible to the fragment tests above -- which is exactly the
    form six of the seven original references took.
    """
    body = "\n".join(text for _, text in HINTS)
    for dead in ("configs.yaml", "transpile.py", "schema.py"):
        assert dead not in body, (
            f"a hint still names '{dead}', which the class-per-backend refactor deleted"
        )


def test_the_unresolvable_backends_path_is_not_reintroduced():
    """Names the specific fragment, so a reviewer sees why it is banned.

    transpiler/backends/ does resolve -- from the project root -- so the per-hint
    test only catches it when paired with a transpiler/_base/ fragment, which is
    how it was written. This states the rule directly for the case where someone
    adds it on its own.
    """
    body = "\n".join(text for _, text in HINTS)
    assert "transpiler/backends" not in body, (
        "backends live at transpiler/transpiler/backends because the project root "
        "and the package share a name, so 'transpiler/backends/' is wrong from "
        "agentic-coding/ -- where every other transpiler/ fragment in these hints "
        "resolves. Name the class var without a directory instead."
    )
