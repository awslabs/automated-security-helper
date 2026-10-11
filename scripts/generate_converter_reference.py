#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/converters.md from the converter plugins ASH ships.

Usage:
    uv run python scripts/generate_converter_reference.py           # rewrite the page
    uv run python scripts/generate_converter_reference.py --check   # exit 1 with a diff if stale

Converters run before the scanners and turn files the scanners cannot read (an
archive, a notebook) into files they can. The page lists every converter class a
package under ``plugin_modules/`` declares, with its config name, default, the
package that provides it, the command it runs and how that is installed, and
every key of its ``options`` model. The description is the first paragraph of
the converter class's docstring, quoted as written.
"""

from __future__ import annotations

import argparse
import inspect
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

GENERATOR = "scripts/generate_converter_reference.py"
PAGE = "converters.md"


def generate() -> tuple[str, dict]:
    from _plugin_reference import (
        ENV_NOTE_SLOT,
        discover,
        install_text,
        instantiate,
        options_table,
        package_note,
        package_short,
        place_env_note,
        yes_no,
    )

    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

    plugins = discover("converter")
    instantiate(plugins)
    missing: list[str] = []

    lines = banner(
        GENERATOR,
        "the converter plugins declared under automated_security_helper/plugin_modules",
        extra=[
            "",
            "Anchors: each converter's heading id is its config name (#archive);",
            "each option has <a id> converters.<name>.options.<option>.",
        ],
    )
    lines += [
        "# Converters reference",
        "",
        generated_note(GENERATOR, "the converter plugins in the ASH source code"),
        "",
        (
            f"ASH ships {len(plugins)} converters. Converters run in the `convert` phase, "
            "before the `scan` phase, and write what they produce under "
            f"`<output directory>/{ASH_WORK_DIR_NAME}/<converter name>/`."
        ),
        "",
        "| Converter | Enabled by default | Provided by | Command | Runs with `--python-only` |",
        "|-----------|--------------------|-------------|---------|---------------------------|",
    ]
    for p in plugins:
        inst = p.instance
        python_only = None
        if inst is not None:
            try:
                python_only = bool(inst.is_python_only())
            except Exception:
                python_only = None
        command = getattr(inst, "command", None)
        lines.append(
            f"| [{code(p.name)}](#{p.name}) | {yes_no(p.enabled)} | {package_short(p)} | "
            f"{code(command) if command else 'none (runs in the ASH process)'} | "
            f"{yes_no(python_only)} |"
        )
    lines += ["", ENV_NOTE_SLOT, ""]

    for p in plugins:
        inst = p.instance
        lines += [f"## {code(p.name)}", ""]
        doc = p.cls.__dict__.get("__doc__")
        if doc:
            lines += [md_prose(inspect.cleandoc(doc).split("\n\n")[0]), ""]
        command = getattr(inst, "command", None)
        facts = [
            ("Class", code(f"{p.cls.__module__}.{p.cls.__name__}")),
            ("Provided by", package_note(p)),
            ("Enabled by default", yes_no(p.enabled)),
            ("Command", code(command) if command else "none (runs in the ASH process)"),
            ("Install", install_text(inst)),
        ]
        if p.instance_error:
            facts.append(
                ("Could not be built for inspection", md_prose(p.instance_error))
            )
        lines += [f"- {label}: {value}" for label, value in facts]
        lines.append("")
        lines += options_table(p, "converters", missing)

    while lines and lines[-1] == "":
        lines.pop()
    lines = place_env_note(lines)
    return "\n".join(lines) + "\n", {"plugins": len(plugins), "missing": missing}


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
    parser.add_argument(
        "--missing-descriptions",
        default=None,
        help="Also write the options that have no description to this path.",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    prepare_environment(Path(args.docs_root))
    output = Path(args.output) if args.output else reference_dir(args.docs_root) / PAGE
    content, stats = generate()
    summary = (
        f"{stats['plugins']} converters, {len(stats['missing'])} options with no "
        "description in the model."
    )
    if args.missing_descriptions:
        Path(args.missing_descriptions).write_text(
            "\n".join(stats["missing"]) + "\n", encoding="utf-8"
        )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
