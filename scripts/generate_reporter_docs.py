#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/reporters.md from the reporter plugins ASH ships.

Why this exists
---------------
The set of built-in reporters was stated in seven places -- the reporters package
``__all__``, ``ASH_REPORTERS`` in ``plugin_modules/ash_builtin/__init__.py``,
``ReporterConfigSegment`` in ``config/ash_config.py``, and four documentation
pages -- and no two of them agreed. Measured at the commit that introduced this
script: the registry had 15 reporters, ``ASH_REPORTERS`` listed 13,
``ReporterConfigSegment`` declared 14 fields, ``output-formats.md`` showed 14
rows, ``plugins/builtin/reporters.md`` claimed 14 in prose while tabulating 13,
``plugins/builtin/index.md`` said 13 and ``plugins/index.md`` said 12.

Reconciling six numbers by hand produces a seventh number that is correct for one
commit. Instead, the row set, the file extensions and the enabled-by-default
column are derived here from the registered reporter classes, which is the set a
scan actually runs. They are written to one page, the reporter reference, and other
pages link to it rather than restate the set.

What stays hand-written
-----------------------
The "primary use case" and "standard" columns are editorial and live in
``REPORTER_DOCS`` below, keyed by reporter name. They are deliberately NOT
derived: no attribute on a reporter class carries "what a reader would use this
for". The check is instead a completeness one -- a reporter registered with no
``REPORTER_DOCS`` entry, or an entry naming no registered reporter, is an error.
That way a newly added reporter cannot reach the docs as a blank row, and cannot
be silently omitted either.

The page
--------
docs/content/reference/reporters.md, written whole: the built-in reporters, every
reporter in a plugin module (the AWS reporters), and each reporter's options from
its options model. This script used to rewrite marker-delimited regions in four
older pages as well (output-formats.md and three plugin pages); the docs rewrite
replaces those pages, so the reference page is the only output.

Usage
-----
    uv run python scripts/generate_reporter_docs.py           # rewrite the page
    uv run python scripts/generate_reporter_docs.py --check   # fail if stale

``--check`` is the freshness gate. It re-renders the page and compares it with
what is on disk, exiting non-zero with a diff when they differ, so a reporter
added, removed, renamed, re-extensioned, or flipped between enabled and disabled
cannot land while the page still describes the previous set.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

#: The reference page, relative to the docs tree (``--docs-root``).
REFERENCE_PAGE = Path("docs/content/reference/reporters.md")
GENERATOR = "scripts/generate_reporter_docs.py"

# Editorial metadata per reporter name: the title, what a reader would use the
# format for, and the standard it follows. See "What stays hand-written" above.
REPORTER_DOCS: dict[str, dict] = {
    "csv": {
        "title": "CSV",
        "use_case": "Spreadsheet analysis, filtering",
        "standard": "RFC 4180",
    },
    "cyclonedx": {
        "title": "CycloneDX",
        "use_case": "Software bill of materials (SBOM)",
        "standard": "[CycloneDX 1.6](https://cyclonedx.org/specification/overview/)",
    },
    "flat-json": {
        "title": "Flat JSON",
        "use_case": "Programmatic consumption, dashboards",
        "standard": "ASH-native",
    },
    "github-ghas": {
        "title": "GitHub GHAS",
        "use_case": "GitHub Advanced Security code scanning upload",
        "standard": "[OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)",
    },
    "gitlab-cyclonedx": {
        "title": "GitLab CycloneDX",
        "use_case": "GitLab dependency scanning",
        "standard": "[GitLab dependency scanning report](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdependency_scanning)",
    },
    "gitlab-sast": {
        "title": "GitLab SAST",
        "use_case": "GitLab Security Dashboard",
        "standard": "[GitLab SAST report](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportssast)",
    },
    "html": {
        "title": "HTML",
        "use_case": "Interactive browser-based reports",
        "standard": "--",
    },
    "junitxml": {
        "title": "JUnit XML",
        "use_case": "CI/CD test result reporting",
        "standard": "[JUnit XML](https://llg.cubic.org/docs/junit/)",
    },
    "markdown": {
        "title": "Markdown",
        "use_case": "Pull request comments, documentation",
        "standard": "CommonMark",
    },
    "ocsf": {
        "title": "OCSF",
        "use_case": "Security data lakes, SIEM ingestion",
        "standard": "[OCSF 1.0](https://schema.ocsf.io/)",
    },
    "sarif": {
        "title": "SARIF",
        "use_case": "IDE integration, GitHub/GitLab code scanning",
        "standard": "[OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)",
    },
    "spdx": {
        "title": "SPDX",
        "use_case": "License compliance, SBOM",
        "standard": "[SPDX 2.3](https://spdx.dev/specifications/)",
    },
    "text": {
        "title": "Text",
        "use_case": "Console output, logs",
        "standard": "--",
    },
    "unused-suppressions": {
        "title": "Unused suppressions",
        "use_case": "Suppression hygiene: rules that matched nothing this scan",
        "standard": "ASH-native",
    },
    "yaml": {
        "title": "YAML",
        "use_case": "Human-readable structured data",
        "standard": "--",
    },
}


def registered_reporters() -> list[dict]:
    """Return {name, extension, enabled, class_name} for every registered reporter.

    Importing the reporters package fires the ``@ash_reporter_plugin``
    decorators, so the plugin manager's reporter inventory after this import is
    the set a scan would run. Each reporter's defaults come from instantiating
    its config class with no arguments, which is exactly what ASH does when a
    user names no reporter options.
    """
    import automated_security_helper.plugin_modules.ash_builtin.reporters  # noqa: F401
    from automated_security_helper.plugins import ash_plugin_manager

    import typing

    rows = []
    for cls in ash_plugin_manager.plugin_modules("reporter"):
        field = getattr(cls, "model_fields", {}).get("config")
        if field is None:
            raise RuntimeError(f"{cls.__name__} has no `config` model field")
        annotation = field.annotation
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        config_cls = args[0] if args else annotation
        config = config_cls()
        rows.append(
            {
                "name": config.name,
                "extension": getattr(config, "extension", None),
                "enabled": bool(config.enabled),
                "class_name": cls.__name__,
            }
        )
    rows.sort(key=lambda r: r["name"])
    return rows


def _check_editorial_coverage(rows: list[dict]) -> None:
    registered = {r["name"] for r in rows}
    documented = set(REPORTER_DOCS)
    missing = sorted(registered - documented)
    extra = sorted(documented - registered)
    problems = []
    if missing:
        problems.append(
            f"registered reporters with no REPORTER_DOCS entry: {missing}. "
            f"Add a use case and standard for each in scripts/generate_reporter_docs.py."
        )
    if extra:
        problems.append(
            f"REPORTER_DOCS entries naming no registered reporter: {extra}. "
            f"Remove them, or fix the reporter's registration."
        )
    if problems:
        raise SystemExit("ERROR: " + "\n       ".join(problems))


def _prose_list(names: list[str]) -> str:
    """Render names as `a`, `b`, and `c`."""
    ticked = [f"`{n}`" for n in names]
    if len(ticked) == 1:
        return ticked[0]
    if len(ticked) == 2:
        return f"{ticked[0]} and {ticked[1]}"
    return ", ".join(ticked[:-1]) + f", and {ticked[-1]}"


def defaults_sentence(rows: list[dict]) -> str:
    """Which built-in reporters run by default, as one sentence."""
    on = [r["name"] for r in rows if r["enabled"]]
    off = [r["name"] for r in rows if not r["enabled"]]
    sentence = (
        f"Of the {len(rows)} built-in reporters, {len(on)} are enabled by default: "
        f"{_prose_list(on)}."
    )
    if off:
        sentence += (
            f" {_prose_list(off)} "
            f"{'is' if len(off) == 1 else 'are'} available but disabled by default."
        )
    return sentence


def _reference_table(rows: list[dict]) -> list[str]:
    """The built-in table, each row linked to the reporter's own section."""
    lines = [
        "| Reporter | File extension | Enabled by default | Primary use case | Standard |",
        "|----------|----------------|--------------------|------------------|----------|",
    ]
    for r in rows:
        doc = REPORTER_DOCS[r["name"]]
        lines.append(
            f"| [{doc['title']}](#{r['name']}) (`{r['name']}`) | `.{r['extension']}` | "
            f"{'yes' if r['enabled'] else 'no'} | {doc['use_case']} | {doc['standard']} |"
        )
    return lines


def render_reference_page(rows: list[dict]) -> tuple[str, list[str]]:
    """The whole of docs/content/reference/reporters.md, and the options with no description.

    ``rows`` is :func:`registered_reporters`, computed before anything here imports
    the other plugin packages: the plugin registry is process-global, and
    importing ``ash_aws_plugins`` adds its reporters to it.
    """
    import inspect

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _plugin_reference import (
        ENV_NOTE_SLOT,
        discover,
        instantiate,
        options_table,
        package_note,
        package_short,
        place_env_note,
        yes_no,
    )
    from _reference_docs import banner, code, generated_note, md_prose

    plugins = discover("reporter")
    builtin = sorted(p.name for p in plugins if p.builtin)
    registered = sorted(r["name"] for r in rows)
    if builtin != registered:
        raise SystemExit(
            "ERROR: the built-in reporters ash_builtin declares "
            f"({builtin}) differ from the registered reporter set ({registered})."
        )
    instantiate(plugins)
    missing: list[str] = []

    lines = banner(
        GENERATOR,
        "the reporter plugins declared under automated_security_helper/plugin_modules",
        extra=[
            "",
            "Anchors: each reporter's heading id is its config name (#sarif, #flat-json);",
            "each option has <a id> reporters.<name>.options.<option>.",
            "The use-case and standard columns are editorial, from REPORTER_DOCS in the generator.",
        ],
    )
    lines += [
        "# Reporters reference",
        "",
        generated_note(GENERATOR, "the reporter plugins in the ASH source code"),
        "",
        "## Built-in reporters",
        "",
        *_reference_table(rows),
        "",
        defaults_sentence(rows),
        "",
        ENV_NOTE_SLOT,
        "",
    ]
    others = [p for p in plugins if not p.builtin]
    if others:
        lines += [
            "## Reporters in plugin modules",
            "",
            (
                "These are loaded only when the configuration's `ash_plugin_modules` names "
                "their module."
            ),
            "",
            "| Reporter | File extension | Enabled by default | Provided by |",
            "|----------|----------------|--------------------|-------------|",
        ]
        for p in others:
            extension = None
            if p.config_cls is not None:
                try:
                    extension = getattr(p.config_cls(), "extension", None)
                except Exception:
                    extension = None
            lines.append(
                f"| [{code(p.name)}](#{p.name}) | "
                f"{code('.' + extension) if extension else 'none'} | "
                f"{yes_no(p.enabled)} | {package_short(p)} |"
            )
        lines.append("")

    for p in plugins:
        lines += [f"## {code(p.name)}", ""]
        doc = p.cls.__dict__.get("__doc__")
        if doc:
            lines += [md_prose(inspect.cleandoc(doc).split("\n\n")[0]), ""]
        extension = None
        if p.config_cls is not None:
            try:
                extension = getattr(p.config_cls(), "extension", None)
            except Exception:
                extension = None
        python_only = None
        if p.instance is not None:
            try:
                python_only = bool(p.instance.is_python_only())
            except Exception:
                python_only = None
        facts = [
            ("Class", code(f"{p.cls.__module__}.{p.cls.__name__}")),
            ("Provided by", package_note(p)),
            ("Enabled by default", yes_no(p.enabled)),
            ("File extension", code("." + extension) if extension else "none"),
            ("Runs with `--python-only`", yes_no(python_only)),
        ]
        if p.instance_error:
            facts.append(
                ("Could not be built for inspection", md_prose(p.instance_error))
            )
        lines += [f"- {label}: {value}" for label, value in facts]
        lines.append("")
        lines += options_table(p, "reporters", missing)

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(place_env_note(lines)) + "\n", missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="Exit 1 with a diff if stale."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/{REFERENCE_PAGE.as_posix()}",
    )
    parser.add_argument(
        "--missing-descriptions",
        default=None,
        help="Also write the reporter options that have no description to this path.",
    )
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _reference_docs import (
        add_docs_root_argument,
        prepare_environment,
        write_or_check,
    )

    add_docs_root_argument(parser)
    args = parser.parse_args()
    docs_root = Path(args.docs_root).resolve()
    prepare_environment(docs_root)
    rows = registered_reporters()
    _check_editorial_coverage(rows)
    page, missing = render_reference_page(rows)
    summary = (
        f"{len(rows)} built-in reporters, {sum(1 for r in rows if r['enabled'])} "
        f"enabled by default; {len(missing)} reporter options with no description in "
        "the model."
    )
    if args.missing_descriptions:
        Path(args.missing_descriptions).write_text(
            "\n".join(missing) + "\n", encoding="utf-8"
        )
    if args.output == "-":
        sys.stdout.write(page)
        print(summary, file=sys.stderr)
        return 0
    output = Path(args.output) if args.output else docs_root / REFERENCE_PAGE
    return write_or_check(output, page, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
