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
mappable-dropped (the native output carries it; ASH discards it today) or n/a
(this scanner class cannot have it, with the reason). The page renders that
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
            "this scanner class cannot have the facet (or its output was not "
            "read), with the reason."
        ),
    ),
)


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
        "scanner, automated_security_helper/base/scanner_facets.py)",
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
            "registry totality test. The three states:"
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
        "| Scanner | Mapped | Mappable, dropped | Not applicable |",
        "|---------|--------|-------------------|----------------|",
    ]

    def states(declaration) -> list[FacetState]:
        return [getattr(declaration, facet).state for facet in FACET_NAMES]

    for p, declaration in rows:
        declared = states(declaration)
        lines.append(
            f"| [{code(p.name)}](#{p.name}) | "
            f"{declared.count(FacetState.MAPPED)} | "
            f"{declared.count(FacetState.DROPPED)} | "
            f"{declared.count(FacetState.NA)} |"
        )
    lines.append("")

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
            if facet == "resource_id" and cell.example:
                example = f"Example: {code(cell.example)}"
                notes = f"{notes} {example}".strip() if notes else example
            lines.append(
                f"| {code(facet)} | {code(cell.state.value)} | "
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
