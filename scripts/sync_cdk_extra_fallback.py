"""Keep ``_CDK_EXTRA_FALLBACK_REQUIREMENTS`` equal to pyproject's ``cdk`` extra.

Why this exists
---------------
``automated_security_helper/plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py``
carries a hardcoded copy of ``[project.optional-dependencies] cdk``. The copy is
reached only when reading the installed distribution's metadata fails outright,
which happens in editable and source layouts, so it cannot simply be deleted.

Being a copy, it drifts. 200a6565 (#547) bumped ``aws-cdk-lib`` in pyproject.toml
and touched nothing else, and every dependabot bump since has done the same:
`dependabot/uv/scanner-minor` broke ``test_fallback_matches_installed_metadata``
on every unit-test leg -- 18 of them at the time, 25 since ash-unified-ci.yml
gained Python 3.14 and dropped its macos-14 exclusions -- and
`dependabot/uv/engine-minor` broke it twice before that. The figure is given as
"every leg" first because the bare 18 that used to stand here kept reading as a
current fact after the matrix grew, and the sentence is about blast radius rather
than arithmetic. The test is correct and worth keeping -- it fails on a bumped floor, a
dropped ceiling, a removed requirement, an added requirement and a renamed
package -- but it only ever reports the drift. Nothing repaired it, so a human
edited the constant by hand on every bump.

This script is the repair. ``--fix`` rewrites the constant from pyproject, so a
bump fixes itself in the commit that causes it; ``--check`` fails when they
disagree, so CI and the merge queue cannot land a drifted pair.

Why codegen rather than reading pyproject at runtime
----------------------------------------------------
Reading pyproject.toml inside the scanner would remove the duplication outright,
and it would work: in the layouts where metadata is unreadable, pyproject.toml is
on disk beside the package. It was rejected on dependency grounds. ``tomllib``
entered the standard library in 3.11 while ``requires-python`` starts at 3.10, so
the scanner would need ``tomli`` as a *runtime* dependency purely to serve the
oldest supported interpreter. A security scanner's runtime dependency surface is
part of its risk profile, and that is the wrong currency to pay in.

This script escapes the dependency half of that constraint -- it runs in
pre-commit and CI, never inside ASH, so a wrong parse here breaks a gate loudly
instead of a scan quietly -- but not the interpreter half. An earlier version
exited on anything below 3.11 and let the hook's and the drift workflow's pinned
``--python 3.13`` satisfy that, which held exactly until the unit-test matrix ran
on 3.10: "needs only the standard library" is a property relative to the
interpreter actually running the script, the repository floor is 3.10, and a
contributor may run the script directly with that floor. So ``tomllib`` is the
parser of record where it exists, and on 3.10 ``_parse_cdk_extra`` below reads
the one table and key this script owns, strictly.

Failure modes and limitations
-----------------------------
* The rewrite is anchored on the assignment's exact opening line. If that line is
  reformatted -- a type annotation change, or ruff-format collapsing the list --
  the anchor stops matching and the script exits non-zero saying so, rather than
  writing to a place it no longer understands. It never edits a file it cannot
  locate the block in.
* The explanatory comment above the constant is left alone. Only the list
  elements between the anchor and its closing bracket are rewritten.
* ``--check`` reads past comments inside the list, whole-line or trailing an
  element. ``--fix`` replaces every line of the list with the rendered
  requirements, so it refuses, writing nothing, when the list holds a comment:
  move the comment above the assignment, where it is left alone. Blank lines
  inside the list carry no content and are normalized away.
* It does not validate that the requirements are installable, only that the two
  spellings agree. ``test_fallback_matches_installed_metadata`` is what checks
  the constant against reality; this only stops the two declarations diverging.
* Requirement strings are copied verbatim from pyproject, so specifier order is
  whatever pyproject says. That is deliberate: a normalizing rewrite would make
  the committed constant differ from its source for no reason, and the test
  already compares order-insensitively.
* On 3.10 the extra is read by ``_parse_cdk_extra``, which accepts only the
  committed shape: the table header and ``cdk = [`` each on a line of their own,
  one double-quoted requirement per line, blank and comment lines, and a closing
  ``]``. Anything else exits non-zero naming the line, rather than guessing what
  a TOML parser would have read. ``tomllib`` stays the parser of record on
  3.11+, and ``test_cdk_extra_fallback_sync_gate.py`` holds the two equal on the
  real pyproject.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sys
import tokenize
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, the bottom of requires-python.
    # tomllib entered the standard library in 3.11, and under `uv run
    # --no-project` a tomli backport is unreachable even where the project
    # environment carries one. _parse_cdk_extra below is the 3.10 path.
    tomllib = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
SCANNER = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_builtin"
    / "scanners"
    / "cdk_nag_scanner.py"
)

#: The assignment this script owns. Matched literally rather than by regex so a
#: near-miss is a loud failure instead of a partial match somewhere unintended.
ANCHOR = "_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = ["
CLOSER = "]"
EXTRA_NAME = "cdk"

#: The table the extra lives in, as the line _parse_cdk_extra anchors on.
_OPTIONAL_DEPENDENCIES = "[project.optional-dependencies]"

#: One array element in the committed shape: a double-quoted string with no
#: escapes and no quotes inside, an optional trailing comma, nothing else on the
#: line. For a string this regex accepts, the raw characters ARE the TOML value,
#: which is what makes the fallback's answer equal to tomllib's.
_ELEMENT = re.compile(r'^"([^"\\]+)",?$')


def _parse_cdk_extra(text: str) -> list[str]:
    """``[project.optional-dependencies] cdk`` without a TOML parser, for 3.10.

    Accepts exactly the committed shape of the extra and refuses anything else,
    naming the first line it does not understand. The refusals are the point: a
    narrow parser that guessed would hand ``--fix`` a wrong list to write into
    the scanner. ``test_cdk_extra_fallback_sync_gate.py`` holds this function
    equal to ``tomllib`` on the real pyproject, and the 3.10 unit leg runs the
    whole gate suite through it.
    """
    lines = text.splitlines()
    opener = f"{EXTRA_NAME} = ["

    def _refusal(reason: str) -> SystemExit:
        return SystemExit(
            f"{PYPROJECT}: {reason}. This fallback parser runs only on Python "
            f"3.10, where tomllib is not yet in the standard library, and it "
            f"reads only the committed shape of the {EXTRA_NAME} extra: either "
            f"run the script on 3.11+ or keep the extra in that shape."
        )

    try:
        header = next(
            index
            for index, line in enumerate(lines)
            if line.strip() == _OPTIONAL_DEPENDENCIES
        )
    except StopIteration:
        raise _refusal(
            f"no {_OPTIONAL_DEPENDENCIES} table found; the extra was renamed or "
            f"removed, so this script's premise is gone and the fallback "
            f"constant needs a human decision"
        ) from None

    opener_index = None
    for index in range(header + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            break  # the next table; the key was not in this one
        if stripped == opener:
            opener_index = index
            break
    if opener_index is None:
        raise _refusal(
            f"no `{opener}` line inside {_OPTIONAL_DEPENDENCIES}; the extra was "
            f"renamed or removed, so this script's premise is gone and the "
            f"fallback constant needs a human decision"
        )

    found: list[str] = []
    for index in range(opener_index + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped == CLOSER:
            return found
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            break  # a table header before the closer: the array never closed
        element = _ELEMENT.match(stripped)
        if element is None:
            raise _refusal(
                f"line {index + 1} ({lines[index].strip()!r}) is not one "
                f"double-quoted requirement, a comment, or a blank line"
            )
        found.append(element.group(1))
    raise _refusal(f"the `{opener}` array never closes with {CLOSER!r}")


def declared_requirements() -> list[str]:
    """The ``cdk`` extra, verbatim, from pyproject.toml."""
    if tomllib is None:
        return _parse_cdk_extra(PYPROJECT.read_text(encoding="utf-8"))
    with PYPROJECT.open("rb") as handle:
        data = tomllib.load(handle)
    try:
        return list(data["project"]["optional-dependencies"][EXTRA_NAME])
    except KeyError as exc:
        raise SystemExit(
            f"{PYPROJECT} has no [project.optional-dependencies] {EXTRA_NAME}; "
            f"the extra was renamed or removed, so this script's premise is gone "
            f"and the fallback constant needs a human decision (missing: {exc})"
        ) from exc


def locate_block(lines: list[str]) -> tuple[int, int]:
    """The half-open line range of the list literal's elements.

    Returns ``(first_element, closing_bracket)`` as 0-based indices.
    """
    starts = [index for index, line in enumerate(lines) if line.rstrip() == ANCHOR]
    if len(starts) != 1:
        raise SystemExit(
            f"expected exactly one line equal to {ANCHOR!r} in {SCANNER}, found "
            f"{len(starts)}. The assignment was reformatted or renamed; fix this "
            f"script's ANCHOR rather than letting it write to a block it no "
            f"longer recognizes."
        )
    start = starts[0]
    for index in range(start + 1, len(lines)):
        if lines[index].rstrip() == CLOSER:
            return start + 1, index
    raise SystemExit(
        f"no closing {CLOSER!r} found after {ANCHOR!r} in {SCANNER}; refusing to "
        f"rewrite a block whose end is unknown"
    )


def _split_comment(text: str) -> tuple[str, str | None]:
    """``text`` without a trailing ``#`` comment, and that comment (or None).

    Found with the tokenizer, so a ``#`` inside a string literal is not one.
    """
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                return text[: token.start[1]].rstrip(), token.string
    except (tokenize.TokenError, SyntaxError):
        pass  # not tokenizable; the caller's literal parse refuses it by name
    return text, None


def committed_requirements(lines: list[str]) -> list[str]:
    """The constant's elements, read as the Python string literals they are.

    Read with the parser rather than by stripping quote characters: stripping
    took the closing ``'`` off a requirement whose environment marker ends in
    one (``...; python_version < '3.11'``), so the committed value never
    equaled the declared one and ``--fix`` rewrote the same list on every run.
    A comment after an element is not part of the requirement.
    """
    first, closer = locate_block(lines)
    found = []
    for line in lines[first:closer]:
        stripped = _split_comment(line.strip())[0].rstrip(",")
        if not stripped or stripped.startswith("#"):
            continue
        try:
            value = ast.literal_eval(stripped)
        except (SyntaxError, ValueError) as exc:
            raise SystemExit(
                f"{SCANNER}: {stripped!r} inside _CDK_EXTRA_FALLBACK_REQUIREMENTS is "
                f"not one string literal ({exc}); refusing to read a block this "
                "script does not understand"
            ) from exc
        if not isinstance(value, str):
            raise SystemExit(
                f"{SCANNER}: {stripped!r} inside _CDK_EXTRA_FALLBACK_REQUIREMENTS is "
                "not a string"
            )
        found.append(value)
    return found


def render(requirements: list[str]) -> list[str]:
    """One double-quoted Python string literal per requirement.

    Through json.dumps, whose escapes are Python's, so a requirement holding a
    double quote or a backslash is written as a literal that reads back as
    itself instead of as a syntax error in the scanner module.
    """
    return [
        f"    {json.dumps(requirement, ensure_ascii=False)},"
        for requirement in requirements
    ]


def commented_lines(lines: list[str], first: int, closer: int) -> list[int]:
    """1-based numbers of the block's lines that hold a comment.

    A whole-line comment or one after an element; ``render`` writes neither, so
    a rewrite would delete them.
    """
    return [
        index + 1
        for index in range(first, closer)
        if _split_comment(lines[index].strip())[1] is not None
    ]


def main() -> int:
    # __doc__ is None under `python -OO`, which strips docstrings.
    summary = __doc__.splitlines()[0] if __doc__ else None
    parser = argparse.ArgumentParser(description=summary)
    parser.add_argument(
        "--fix",
        action="store_true",
        help="rewrite the constant from pyproject instead of only reporting drift",
    )
    args = parser.parse_args()

    declared = declared_requirements()
    lines = SCANNER.read_text(encoding="utf-8").splitlines()
    committed = committed_requirements(lines)

    if committed == declared:
        print(
            f"ok: _CDK_EXTRA_FALLBACK_REQUIREMENTS matches "
            f"[project.optional-dependencies] {EXTRA_NAME} ({len(declared)} "
            f"requirements)"
        )
        return 0

    if not args.fix:
        print(
            "drift: _CDK_EXTRA_FALLBACK_REQUIREMENTS disagrees with "
            f"[project.optional-dependencies] {EXTRA_NAME} in pyproject.toml\n"
            f"  pyproject: {declared}\n"
            f"  constant : {committed}\n"
            "Run `uv run --no-project --python 3.13 python "
            "scripts/sync_cdk_extra_fallback.py --fix` and commit the result.",
            file=sys.stderr,
        )
        return 1

    first, closer = locate_block(lines)
    with_comment = commented_lines(lines, first, closer)
    if with_comment:
        raise SystemExit(
            f"{SCANNER}: line(s) {with_comment} inside "
            "_CDK_EXTRA_FALLBACK_REQUIREMENTS hold a comment, and --fix replaces "
            "every line of the list, which would delete it. Refusing to write. "
            "Move the comment above the assignment, which --fix leaves alone, "
            "then run --fix again."
        )
    rewritten = lines[:first] + render(declared) + lines[closer:]
    SCANNER.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(
        f"fixed: rewrote _CDK_EXTRA_FALLBACK_REQUIREMENTS in {SCANNER.name} from "
        f"{committed} to {declared}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
