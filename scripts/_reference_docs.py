# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers shared by the generators that write docs/content/reference/.

Why a shared module
-------------------
Each reference page (CLI, configuration, environment variables, scanners,
converters, reporters, MCP tools) is written whole by one generator, and every
generator needs the same four things: a banner naming itself, a ``--check`` mode
that prints a diff instead of writing, markdown-cell escaping, and an environment
that cannot leak into the output. Written five times, those drift apart, and a
generator whose ``--check`` compares differently from its writer is the failure
this whole set of scripts exists to remove.

Why the environment is scrubbed before ASH is imported
------------------------------------------------------
Several defaults are read from the environment at import time:
``AshConfig.project_name`` is ``os.environ.get("ASH_PROJECT_NAME", "ash-scan")``,
``ASH_DEFAULT_SEVERITY_LEVEL`` sets the default severity threshold and is
interpolated into a scanner option's description, and ``ASH_BIN_PATH`` sets the
directory install commands name. A generator run in a shell that had any of them
set would publish that shell's values as ASH's defaults, and ``--check`` would
then fail on every other machine. :func:`scrub_import_time_environment` removes
every ``ASH_``-prefixed variable before the package is imported, so the pages
document the defaults a user gets with nothing set. Values derived from the home
directory or the checkout path are replaced by :func:`normalize_paths`.

This module never imports ASH itself, so importing it is cheap and safe from any
test.
"""

from __future__ import annotations

import difflib
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = REPO_ROOT / "docs" / "content" / "reference"

#: Marker rendered wherever the code carries no description for something the page
#: documents. Kept visible, and counted by each generator's ``--check``, because a
#: blank cell reads as "nothing to say" and an invented one is worse.
NO_DESCRIPTION = "No description in the code."


def scrub_import_time_environment() -> list[str]:
    """Remove ``ASH_*`` variables from this process, before ASH is imported.

    Returns the names removed so a caller can say what it ignored. Has no effect on
    a module that was already imported, which is why every generator calls it from
    ``main()`` before its first ASH import.
    """
    removed = sorted(name for name in os.environ if name.startswith("ASH_"))
    for name in removed:
        del os.environ[name]
    return removed


def normalize_paths(text: str) -> str:
    """Replace machine-specific absolute paths with stable placeholders.

    The checkout path is replaced before the home directory because the checkout
    is usually inside it.
    """
    repo = str(REPO_ROOT)
    home = str(Path.home())
    text = text.replace(repo, "<repository>")
    if home and home != "/":
        text = text.replace(home, "~")
    return text


def md_cell(text: object) -> str:
    """Render ``text`` so it stays inside one markdown table cell.

    Pipes would end the cell, newlines would end the row, and a bare ``<`` can be
    read as the start of an HTML tag, which python-markdown then swallows.
    """
    if text is None:
        return ""
    value = " ".join(str(text).split())
    return value.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


_CODE_SPAN = re.compile(r"(``.+?``|`[^`]+`)")


def md_prose(text: object) -> str:
    """Render prose taken from code (help text, docstrings, comments) for a table cell.

    Code spans are kept as code, with reStructuredText's double backticks turned
    into markdown's single ones. Outside code spans, characters markdown would act
    on are escaped: ``|`` ends a cell, ``<`` opens an HTML tag, ``*`` and a
    word-boundary ``_`` start emphasis. Inside a span nothing is escaped, because
    python-markdown shows an escape there literally (a pipe inside backticks does
    not end a cell for it).
    """
    if text is None:
        return ""
    value = " ".join(str(text).split())
    out = []
    for i, part in enumerate(_CODE_SPAN.split(value)):
        if i % 2:
            inner = part[2:-2] if part.startswith("``") else part[1:-1]
            out.append(code(inner))
            continue
        part = part.replace("\\", "\\\\").replace("|", "\\|")
        part = part.replace("<", "&lt;").replace(">", "&gt;").replace("*", "\\*")
        part = re.sub(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", r"\\_", part)
        out.append(part)
    return "".join(out)


def code(text: object) -> str:
    """Render ``text`` as inline code, choosing a fence the text does not contain."""
    value = str(text)
    fence = "``" if "`" in value else "`"
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def banner(generator: str, source: str, extra: list[str] | None = None) -> list[str]:
    """The comment block and visible note every generated reference page opens with.

    ``generator`` is the script's repository-relative path and ``source`` names what
    it reads, in a phrase that completes "generated from".
    """
    command = f"uv run python {generator}"
    lines = [
        "<!--",
        f"  Generated by {generator} from {source}.",
        "  Do not edit this file by hand: change the code or the generator, then run",
        f"    {command}",
        f"  CI runs `{command} --check` and fails when this file is stale.",
    ]
    for line in extra or []:
        lines.append(f"  {line}" if line else "")
    lines += [
        "-->",
        "",
    ]
    return lines


def generated_note(generator: str, source: str) -> str:
    """One visible sentence saying the page is generated, and from what."""
    return (
        f"This page is generated from {source} by `{generator}`. "
        "Edits made to this file by hand are overwritten the next time it is generated."
    )


def write_or_check(
    path: Path, content: str, check: bool, generator: str, summary: str = ""
) -> int:
    """Write ``content`` to ``path``, or with ``check`` report whether it is current.

    Returns a process exit code: 0 when written or current, 1 when ``check`` found a
    difference (the diff is printed to stderr). ``summary`` is printed on success so
    a CI log shows what was compared, not only that something passed.
    """
    try:
        rel = path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel = str(path)
    actual = path.read_text(encoding="utf-8") if path.exists() else None

    if check:
        if actual == content:
            print(f"{rel} is up to date. {summary}".rstrip(), file=sys.stderr)
            return 0
        print(
            f"{rel} is stale relative to the code it documents.\n"
            f"Regenerate with: uv run python {generator}\n",
            file=sys.stderr,
        )
        sys.stderr.writelines(
            difflib.unified_diff(
                (actual or "").splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"{rel} (on disk)",
                tofile=f"{rel} (regenerated)",
                n=2,
            )
        )
        return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    if actual != content:
        path.write_text(content, encoding="utf-8")
        print(f"Wrote {rel}. {summary}".rstrip(), file=sys.stderr)
    else:
        print(f"{rel} unchanged. {summary}".rstrip(), file=sys.stderr)
    return 0
