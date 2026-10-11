# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers shared by the generators that write docs/content/reference/.

Why a shared module
-------------------
Each reference page (CLI, configuration, environment variables, scanners,
converters, reporters, MCP tools) is written whole by one generator, and every
generator needs the same things: a banner naming itself, a ``--check`` mode that
prints a diff instead of writing, markdown-cell escaping, the two trees it works
between, and an environment that cannot leak into the output. Written seven
times, those drift apart, and a generator whose ``--check`` compares differently
from its writer is the failure this whole set of scripts exists to remove.

Two trees: the code and the docs
--------------------------------
A generator documents the ``automated_security_helper`` its interpreter imports,
and writes (or checks) pages under ``--docs-root``, which defaults to the
checkout the script is in. The two are usually one tree. They differ when one
tree's docs are generated from another tree's code::

    <code-tree>/.venv/bin/python <docs-tree>/scripts/generate_cli_docs.py \\
        --docs-root <docs-tree> --check

:func:`prepare_environment` finds the code tree from the import system without
importing ASH (``importlib.util.find_spec``) and prints which package it
documents, so a log always says which code a page was compared against. The code
tree must be a source checkout (a ``pyproject.toml`` beside the package), because
the environment-variable page also reads the shipped ``ash`` and ``utils/``
scripts, which a wheel does not carry.

Why the environment is scrubbed before ASH is imported
------------------------------------------------------
Several defaults are read from the environment at import time:
``AshConfig.project_name`` is ``os.environ.get("ASH_PROJECT_NAME", "ash-scan")``,
``ASH_DEFAULT_SEVERITY_LEVEL`` sets the default severity threshold, and the AWS
reporters' ``region`` options are ``os.environ.get("AWS_REGION", ...)``. A
generator run in a shell that had any of them set would publish that shell's
values as ASH's defaults (a host's ``AWS_REGION`` once reached the AWS reporter
defaults this way), and ``--check`` would then fail on every other machine.

:func:`prepare_environment` removes, before the package is imported:

* every ``ASH_*`` and ``AWS_*`` variable;
* every other name the code tree reads, from
  ``generate_env_var_reference.read_env_names`` over that tree (``CI``,
  ``XDG_CACHE_HOME``, ``UV_TOOL_DIR``, ...);
* ``COLUMNS`` and ``LINES``, which click reads to size the usage lines.

It keeps the few names a process cannot run without (:data:`KEEP_ENVIRONMENT`),
whose values reach a page only as paths that :func:`normalize_paths` replaces.
The pages document the defaults a user gets with nothing set; where a default
comes from a variable, the page says so ("from ``ASH_PROJECT_NAME``, else
``ash-scan``"), which the generators find in the model source, not in the
environment.

This module never imports ASH at module level, so importing it is cheap and safe
from any test.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "automated_security_helper"
#: The reference pages' directory, relative to a docs tree.
REFERENCE_SUBDIR = Path("docs") / "content" / "reference"

#: Marker rendered wherever the code carries no description for something the page
#: documents. Kept visible, and counted by each generator's ``--check``, because a
#: blank cell reads as "nothing to say" and an invented one is worse.
NO_DESCRIPTION = "No description in the code."

#: Prefixes removed from the environment whether or not the code reads them.
SCRUB_PREFIXES = ("ASH_", "AWS_")
#: Names that libraries the generators use read to shape their output.
DEPENDENCY_ENVIRONMENT = frozenset({"COLUMNS", "LINES"})
#: Names kept even when the code reads them: without them a process cannot find
#: programs (PATH), a home or temp directory, or on Windows run at all (SystemRoot).
KEEP_ENVIRONMENT = frozenset(
    {"PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR"}
)

#: Trees whose absolute paths :func:`normalize_paths` replaces, longest first.
_ROOTS: list[Path] = [REPO_ROOT]


def add_docs_root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--docs-root",
        default=str(REPO_ROOT),
        help=(
            "Tree whose pages are written or checked (default: the checkout this "
            "script is in). The code documented is the automated_security_helper "
            "this interpreter imports."
        ),
    )


def refuse_check_to_stdout(parser: argparse.ArgumentParser, args) -> None:
    """Stop with a usage error when ``--check`` is combined with ``--output -``.

    ``--check`` compares a page on disk with the regenerated one, and ``--output -``
    sends the page to stdout instead of to any file, so together they compared
    nothing and exited 0: a CI step written that way could never fail.
    """
    if getattr(args, "check", False) and getattr(args, "output", None) == "-":
        parser.error(
            "--check compares a page on disk with the regenerated one and cannot be "
            "combined with --output -; name a file with --output, or drop it"
        )


def reference_dir(docs_root: Path) -> Path:
    return Path(docs_root) / REFERENCE_SUBDIR


def find_code_root() -> Path:
    """The source tree of the ``automated_security_helper`` this interpreter imports.

    Found without importing it, so nothing in the package has read the
    environment yet.
    """
    spec = importlib.util.find_spec(PACKAGE)
    if spec is None or not spec.origin:
        raise SystemExit(
            f"ERROR: this interpreter ({sys.executable}) cannot import {PACKAGE}. "
            "Run the generator with the Python of the tree whose code it documents."
        )
    package_dir = Path(spec.origin).resolve().parent
    root = package_dir.parent
    if not (root / "pyproject.toml").is_file():
        raise SystemExit(
            f"ERROR: {PACKAGE} is imported from {package_dir}, which is not in a "
            "source checkout (no pyproject.toml beside it). The reference pages also "
            "read the checkout's shipped scripts; use the Python of a checkout's "
            "environment (uv sync), or put the checkout first on PYTHONPATH."
        )
    return root


def scrub_environment(code_root: Path) -> list[str]:
    """Remove every variable that could reach a page from this process; return the names."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from generate_env_var_reference import read_env_names

    read, _dynamic = read_env_names(code_root)
    removed = sorted(
        name
        for name in os.environ
        if name not in KEEP_ENVIRONMENT
        and (
            name.startswith(SCRUB_PREFIXES)
            or name in read
            or name in DEPENDENCY_ENVIRONMENT
        )
    )
    for name in removed:
        del os.environ[name]
    return removed


def prepare_environment(docs_root: Path | None = None) -> Path:
    """Find the code tree, scrub the environment, import ASH; return the code tree.

    Call it from ``main()`` before anything imports ASH: a module that was already
    imported has already read its defaults. Prints the package documented and the
    names removed (never their values) to stderr.
    """
    code_root = find_code_root()
    removed = scrub_environment(code_root)
    docs = Path(docs_root or REPO_ROOT).resolve()
    roots = {code_root, docs, REPO_ROOT}
    _ROOTS[:] = sorted(roots, key=lambda p: len(str(p)), reverse=True)

    import automated_security_helper

    imported = Path(automated_security_helper.__file__).resolve().parent
    if imported != code_root / PACKAGE:
        raise SystemExit(
            f"ERROR: {PACKAGE} was expected from {code_root / PACKAGE} but imported "
            f"from {imported}."
        )
    print(
        f"Documenting {PACKAGE} from {imported}; pages under {docs}. "
        f"Removed {len(removed)} environment variables before importing it"
        + (f": {', '.join(removed)}." if removed else "."),
        file=sys.stderr,
    )
    return code_root


def normalize_paths(text: str) -> str:
    """Replace machine-specific absolute paths with stable placeholders.

    The code and docs trees are replaced before the home directory because a
    checkout is usually inside it.
    """
    for root in _ROOTS:
        for spelling in (str(root), root.as_posix()):
            text = text.replace(spelling, "<repository>")
    home = Path.home()
    # Both spellings: on Windows a default rendered with as_posix() carries
    # C:/Users/x while str() is C:\\Users\\x.
    for spelling in (str(home), home.as_posix()):
        if spelling and spelling != "/":
            text = text.replace(spelling, "~")
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


def yaml_value(value: Any) -> str:
    """``value`` as the code-span content of a Default cell (see "Default cells" in
    ``generate_config_reference.py``).

    ``yaml.safe_load`` of the result gives ``value`` back: a string that YAML would
    read as something else (``true``, ``5``, ``~``, ``""``) is JSON-quoted.
    """
    import yaml

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        try:
            plain = yaml.safe_load(value) == value and value == value.strip()
        except yaml.YAMLError:
            plain = False
        return value if plain and value else json.dumps(value)
    return json.dumps(value, sort_keys=isinstance(value, dict))


def code(text: object) -> str:
    """Render ``text`` as inline code, choosing a fence the text does not contain."""
    value = str(text)
    fence = "``" if "`" in value else "`"
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def options_marker(of: str) -> str:
    """The docs-check marker on the line directly above a table of options or keys.

    ``of`` names what the table documents, as the docs checks resolve it:
    ``scanners.bandit`` (a plugin's options), ``global_settings`` or ``config`` (a
    config section, or the top level), ``workspace-policy.<path>``, or
    ``cli.<command words>`` (``cli.config.init``; ``cli`` for ``ash`` itself). The
    checks compare every row and Default cell with the code, and treat a table that
    looks like one of these without a marker as an error.
    """
    return f"<!-- doctest: options of={of} -->"


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


def display_path(path: Path) -> str:
    """``path`` relative to whichever known tree holds it, else as given."""
    resolved = Path(path).resolve()
    for root in _ROOTS:
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            continue
    return str(path)


def write_or_check(
    path: Path, content: str, check: bool, generator: str, summary: str = ""
) -> int:
    """Write ``content`` to ``path``, or with ``check`` report whether it is current.

    Returns a process exit code: 0 when written or current, 1 when ``check`` found a
    difference (the diff is printed to stderr). ``summary`` is printed on success so
    a CI log shows what was compared, not only that something passed.
    """
    rel = display_path(path)
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
        # newline="\n" so a page written on Windows is byte-identical to one written
        # anywhere else; read_text() above already folds CRLF for the comparison.
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        print(f"Wrote {rel}. {summary}".rstrip(), file=sys.stderr)
    else:
        print(f"{rel} unchanged. {summary}".rstrip(), file=sys.stderr)
    return 0
