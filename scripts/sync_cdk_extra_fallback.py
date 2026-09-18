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
on all 18 unit-test legs, and `dependabot/uv/engine-minor` broke it twice before
that. The test is correct and worth keeping -- it fails on a bumped floor, a
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

This script has no such constraint: it runs in pre-commit and CI, never inside
ASH, so it may require 3.11+ and use ``tomllib`` from the standard library. That
asymmetry is the whole argument for generating rather than reading.

Failure modes and limitations
-----------------------------
* The rewrite is anchored on the assignment's exact opening line. If that line is
  reformatted -- a type annotation change, or ruff-format collapsing the list --
  the anchor stops matching and the script exits non-zero saying so, rather than
  writing to a place it no longer understands. It never edits a file it cannot
  locate the block in.
* The explanatory comment above the constant is left alone. Only the list
  elements between the anchor and its closing bracket are rewritten.
* It does not validate that the requirements are installable, only that the two
  spellings agree. ``test_fallback_matches_installed_metadata`` is what checks
  the constant against reality; this only stops the two declarations diverging.
* Requirement strings are copied verbatim from pyproject, so specifier order is
  whatever pyproject says. That is deliberate: a normalizing rewrite would make
  the committed constant differ from its source for no reason, and the test
  already compares order-insensitively.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 11):  # pragma: no cover - guarded by the message itself
    sys.exit(
        "sync_cdk_extra_fallback.py needs Python 3.11+ for tomllib. It runs in "
        "pre-commit and CI, never inside ASH, so this does not constrain "
        "requires-python. Run it with `uv run --python 3.13`."
    )

import tomllib

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


def declared_requirements() -> list[str]:
    """The ``cdk`` extra, verbatim, from pyproject.toml."""
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


def committed_requirements(lines: list[str]) -> list[str]:
    first, closer = locate_block(lines)
    found = []
    for line in lines[first:closer]:
        stripped = line.strip().rstrip(",")
        if not stripped or stripped.startswith("#"):
            continue
        found.append(stripped.strip('"').strip("'"))
    return found


def render(requirements: list[str]) -> list[str]:
    return [f'    "{requirement}",' for requirement in requirements]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
            "Run `uv run --python 3.13 python scripts/sync_cdk_extra_fallback.py "
            "--fix` and commit the result.",
            file=sys.stderr,
        )
        return 1

    first, closer = locate_block(lines)
    rewritten = lines[:first] + render(declared) + lines[closer:]
    SCANNER.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(
        f"fixed: rewrote _CDK_EXTRA_FALLBACK_REQUIREMENTS in {SCANNER.name} from "
        f"{committed} to {declared}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
