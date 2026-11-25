#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/scanner-facets.md from the facets register.

Usage:
    uv run python scripts/generate_facets_reference.py           # rewrite the page
    uv run python scripts/generate_facets_reference.py --check   # exit 1 with a diff if stale

Every scanner class declares a ``ScannerFacets`` register row
(``automated_security_helper/base/scanner_facets.py``) classifying each facet of
the vocabulary as mapped (lands where the shared pipeline reads it),
mappable-dropped (the native output carries it; ASH discards it today), n/a
(this scanner class cannot have it, with the reason) or unconfirmed (no real
run of the tool has been read for it, with the run that would settle it). The
page renders that
register as written: a per-scanner summary, then one table per scanner with the
declared state, the native field and the reason of every facet. The register is
the source; the page invents nothing and so can say nothing the register does
not.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_prose,
    prepare_environment,
    reference_dir,
    refuse_check_to_stdout,
    write_or_check,
)

GENERATOR = "scripts/generate_facets_reference.py"
PAGE = "scanner-facets.md"

#: What each state means, rendered once above the tables, worded the way the
#: register's own docstrings word it.
STATE_MEANINGS = (
    (
        "mapped",
        (
            "the facet lands where the shared pipeline reads it, and the cell "
            "names the native field it comes from. The corpus-consistency gate "
            "(`tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`) "
            "holds these cells against the committed fixtures."
        ),
    ),
    (
        "mappable-dropped",
        (
            "the native output carries the value and ASH discards it today: a "
            "roadmap record, not a promise. The cell names the native field and "
            "why it is dropped."
        ),
    ),
    (
        "n/a",
        (
            "this scanner class cannot have the facet, with the reason. The "
            "corpus gate treats a populated column here as contamination."
        ),
    ),
    (
        "unconfirmed",
        (
            "no real run of the tool has been read for the facet, so the "
            "register claims neither that it maps nor that it cannot exist. The "
            "cell says what was read instead and the run that would settle it. "
            "The corpus gate lists it as a fixture owed and fails nothing."
        ),
    ),
)


def runtime_compat_section(rows: list) -> list[str]:
    """The runtime-compatibility family of the operational register, as written.

    Each scanner's rows say which range of the tool's versions needs which range
    of its language runtime's versions, how that is resolved (an interpreter
    pin, or a launch-time shim), and, for an unsolved upstream issue, the issue
    and the open end of the row. The rows are read exactly as the installer
    reads them (``declared_runtime_compat``, which walks the MRO), so a
    subclass that inherits a declaring base is listed with the rows it installs
    under -- the page never says "no incompatibility known" of a scanner the
    installer pins. A scanner whose MRO declares no operational row, or an
    empty one, is counted and not listed: no known incompatibility.
    """
    from automated_security_helper.base.scanner_operational_facets import (
        declared_runtime_compat,
    )
    from automated_security_helper.utils.runtime_compat_ranges import RANGE_GRAMMARS

    declared = []
    for p, _facets in rows:
        compat = declared_runtime_compat(p.cls)
        compat_rows = compat.rows if compat else ()
        declared.append((p, compat_rows))
    with_rows = [(p, compat_rows) for p, compat_rows in declared if compat_rows]

    lines = [
        "## Runtime compatibility",
        "",
        (
            "Some tool versions do not run on some versions of the language runtime "
            "they are installed into. The operational register "
            "(`automated_security_helper/base/scanner_operational_facets.py`) records "
            "each known case as a row on the scanner's `runtime_compat` facet: a "
            "range of tool versions, the range of runtime versions it needs, and the "
            "reason, measured. The installer derives the interpreter it asks uv for "
            "from these rows, so there is one place a range is declared."
        ),
        "",
        (
            "Ranges are written in the grammar native to the runtime: "
            + "; ".join(
                f"{code(runtime)} uses {md_prose(grammar)}"
                for runtime, grammar in RANGE_GRAMMARS.items()
            )
            + ". An empty tool range means every version of the tool."
        ),
        "",
        "- `pin`: the interpreter request is constrained to the runtime range. The preferred resolution.",
        (
            "- `polyfill`: a shim is applied over the runtime range at tool launch. "
            "A polyfill row states why a pin cannot serve."
        ),
        (
            "- open-ended: the incompatibility is unsolved upstream. The row declares "
            "only the bounds that are proved, links the upstream issue (or says what "
            "was searched when none exists to cite), and is re-read whenever the "
            "tool's version constraint moves."
        ),
        "",
    ]
    if with_rows:
        lines += [
            "| Scanner | Runtime | Tool versions | Runtime request | Resolution | Open-ended | Reason |",
            "|---------|---------|---------------|-----------------|------------|------------|--------|",
        ]
        for p, compat_rows in with_rows:
            for row in compat_rows:
                reason = md_prose(row.reason)
                if row.polyfill:
                    reason += (
                        f" Shim: {code(row.polyfill)}. Why not a pin: "
                        f"{md_prose(row.pin_insufficient)}"
                    )
                tool_versions = code(row.tool_versions) if row.tool_versions else "all"
                # A row carrying both fields renders the URL alone: the
                # recheck_note is the URL's stand-in, not a second link (the
                # model refuses a blank-but-non-None upstream_issue, so a
                # truthy value here is a real URL).
                if row.open_ended and row.upstream_issue:
                    open_ended = (
                        f"yes, [{md_prose(row.upstream_issue)}]({row.upstream_issue})"
                    )
                elif row.open_ended:
                    # No upstream issue exists to cite; the row's recheck_note
                    # says what was searched in the URL's place.
                    open_ended = f"yes, {md_prose(row.recheck_note)}"
                elif row.upstream_issue:
                    open_ended = (
                        f"no, [{md_prose(row.upstream_issue)}]({row.upstream_issue})"
                    )
                else:
                    open_ended = "no"
                lines.append(
                    f"| [{code(p.name)}](#{p.name}) | {code(row.runtime.value)} | "
                    f"{tool_versions} | {code(row.runtime_request)} | "
                    f"{code(row.resolution.value)} | {open_ended} | {reason} |"
                )
        lines.append("")
    without = len(declared) - len(with_rows)
    lines += [
        (
            f"{len(with_rows)} of {len(declared)} scanners declare a row. The other "
            f"{without} declare none: no incompatibility between their tool "
            "versions and their runtime versions is known."
        ),
        "",
    ]
    return lines


def generate() -> tuple[str, dict]:
    from _plugin_reference import discover

    from automated_security_helper.base.scanner_facets import (
        FACET_NAMES,
        SCANNER_FACETS_ATTR,
        FacetState,
    )

    plugins = discover("scanner")
    rows = []
    for p in plugins:
        declaration = vars(p.cls).get(SCANNER_FACETS_ATTR)
        if declaration is None:
            raise SystemExit(
                f"ERROR: {p.cls.__module__}.{p.cls.__name__} declares no "
                f"'{SCANNER_FACETS_ATTR}' register row; the registry totality "
                "test refuses such a scanner, so the page does too."
            )
        rows.append((p, declaration))

    lines = banner(
        GENERATOR,
        "the scanner facets register (the `facets` class attribute of every "
        "scanner, automated_security_helper/base/scanner_facets.py) and the "
        "runtime_compat rows of the operational register "
        "(automated_security_helper/base/scanner_operational_facets.py)",
        extra=[
            "",
            "Anchors: each scanner's heading id is its config name (#bandit).",
        ],
    )
    lines += [
        "# Scanner facets reference",
        "",
        generated_note(GENERATOR, "the scanner facets register in the ASH source code"),
        "",
        (
            f"ASH ships {len(rows)} scanners, and every one declares, per facet of "
            "the shared vocabulary, whether its native output maps into the shared "
            "pipeline. The register is production code "
            "(`automated_security_helper/base/scanner_facets.py`): the declaration "
            "has runtime consumers, and a scanner without one is refused by the "
            "registry totality test. The four states:"
        ),
        "",
    ]
    for state, meaning in STATE_MEANINGS:
        lines.append(f"- {code(state)}: {meaning}")
    lines += [
        "",
        (
            f"The facet vocabulary, in declaration order: "
            f"{', '.join(code(name) for name in FACET_NAMES)}."
        ),
        "",
        "## Summary",
        "",
        "| Scanner | Mapped | Mappable, dropped | Not applicable | Unconfirmed |",
        "|---------|--------|-------------------|----------------|-------------|",
    ]

    def states(declaration) -> list[FacetState]:
        return [getattr(declaration, facet).state for facet in FACET_NAMES]

    for p, declaration in rows:
        declared = states(declaration)
        lines.append(
            f"| [{code(p.name)}](#{p.name}) | "
            f"{declared.count(FacetState.MAPPED)} | "
            f"{declared.count(FacetState.DROPPED)} | "
            f"{declared.count(FacetState.NA)} | "
            f"{declared.count(FacetState.UNCONFIRMED)} |"
        )
    lines.append("")
    lines += runtime_compat_section(rows)

    for p, declaration in rows:
        lines += [
            f"## {code(p.name)}",
            "",
            f"- Class: {code(f'{p.cls.__module__}.{p.cls.__name__}')}",
            "",
            "| Facet | State | Native field | Reason |",
            "|-------|-------|--------------|--------|",
        ]
        for facet in FACET_NAMES:
            cell = getattr(declaration, facet)
            notes = md_prose(cell.reason) if cell.reason else ""
            # Every facet's example, as the register wrote it: a value from a
            # real read is the evidence the cell stands on, wherever it sits.
            if cell.example:
                example = f"Example: {code(cell.example)}"
                notes = f"{notes} {example}".strip() if notes else example
            # An n/a cell whose reason says UNCONFIRMED is the documented form
            # for "the tool might carry it and no read says" (base/
            # scanner_facets.py declaration rules); render it as such, so a
            # reader does not take it for a confident "cannot exist".
            state_text = cell.state.value
            if cell.state is FacetState.NA and "UNCONFIRMED" in (cell.reason or ""):
                state_text = f"{state_text}, unconfirmed"
            lines.append(
                f"| {code(facet)} | {code(state_text)} | "
                f"{md_prose(cell.native_field) if cell.native_field else ''} | "
                f"{notes} |"
            )
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n", {"scanners": len(rows)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="Exit 1 with a diff if stale."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/docs/content/reference/{PAGE}",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    prepare_environment(Path(args.docs_root))
    output = Path(args.output) if args.output else reference_dir(args.docs_root) / PAGE
    content, stats = generate()
    summary = f"{stats['scanners']} scanners' register rows."
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
