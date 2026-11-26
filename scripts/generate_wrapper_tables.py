#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render the wrapper contract into the marked blocks of ``utils/ash_helpers.ps1``.

Usage:
    uv run python scripts/generate_wrapper_tables.py           # rewrite the blocks
    uv run python scripts/generate_wrapper_tables.py --check   # exit 1 with a diff if stale

The PowerShell host wrapper exists for hosts with no Python, so it carries written-out
copies of the ``ashx`` CLI's own surface: the subcommand names, the root options that
take a value, which subcommands take the options the wrapper adds, the runner discovery
order. This script computes those from the real typer app and container mode's
constants (``automated_security_helper/interactions/wrapper_contract.py``) and writes
them between marker comments inside the wrapper, in its own syntax (v4 removed the
``./ash`` bash wrapper, which had blocks of its own, and its renderers with it)::

    # BEGIN generated: <name> (scripts/generate_wrapper_tables.py)
    ...
    # END generated: <name>

Everything outside a pair of markers is hand-written and never touched. The generated
output is committed, as the environment variable reference is; ``--check`` fails when a
block differs from what the CLI says today, naming the file and the block, so a CLI
change that adds a subcommand or an option fails CI until the wrappers are regenerated.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = "scripts/generate_wrapper_tables.py"

POWERSHELL = "utils/ash_helpers.ps1"


class MarkerError(Exception):
    """A block's markers are missing, repeated, or out of order."""


@dataclass(frozen=True)
class Drift:
    """One block whose text differs from what the contract renders."""

    file: str
    block: str
    diff: str


def _begin(name: str) -> str:
    return f"# BEGIN generated: {name} ({GENERATOR})"


def _end(name: str) -> str:
    return f"# END generated: {name}"


# ---------------------------------------------------------------------------
# PowerShell renderers: each returns the lines between the markers, relative to
# the markers' own indentation.
# ---------------------------------------------------------------------------


def _ps_list(values) -> str:
    return "@(" + ", ".join(f"'{value}'" for value in values) + ")"


def ps_subcommands(contract) -> list[str]:
    return [
        f"$ashSubcommands = {_ps_list(contract.subcommands)}",
        f"$ashTakesSandbox = {_ps_list(contract.sandbox_subcommands)}",
    ]


def ps_root_value_options(contract) -> list[str]:
    return [f"$ashRootValueOptions = {_ps_list(contract.root_value_options)}"]


def ps_option_subcommands(contract) -> list[str]:
    width = max(len(f"'{option}'") for option, _ in contract.option_subcommands) + 2
    lines = ["$ashOptionSubcommands = @{"]
    for option, takers in contract.option_subcommands:
        key = f"'{option}'"
        lines.append(f"    {key:<{width}}= '{' '.join(takers)}'")
    lines.append("}")
    return lines


def ps_runner_discovery(contract) -> list[str]:
    return [
        "$runners = if (-not [string]::IsNullOrEmpty($OCIRunner)) {",
        "    @($OCIRunner)",
        "}",
        "else {",
        f"    {_ps_list(contract.runner_order)}",
        "}",
    ]


def ps_build_target_completer(contract) -> list[str]:
    return [
        f'{_ps_list(contract.build_targets)} | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{'
    ]


def ps_exit_codes(contract) -> list[str]:
    return [
        f"$refusalExitCode = {contract.refusal_exit}",
        f"$usageErrorExitCode = {contract.usage_error_exit}",
    ]


def ps_image_reference_pattern(contract) -> list[str]:
    return [f"$imageReferencePattern = '\\A{contract.image_name_pattern}\\z'"]


def ps_ci_runner_markers(contract) -> list[str]:
    # Each marker is read as ``$env:<name>`` by name, not through a lookup by a variable,
    # so the environment-variable reference still finds Invoke-ASH reading it.
    width = max(len(name) for name in contract.ci_runner_markers)
    lines = ["$ciRunnerMarkers = [ordered]@{"]
    for name in contract.ci_runner_markers:
        lines.append(f"    {name:<{width}} = $env:{name}")
    lines.append("}")
    return lines


Renderer = Callable[..., list[str]]

#: file -> [(block name, renderer)]. The names are the ones written in the markers.
BLOCKS: dict[str, list[tuple[str, Renderer]]] = {
    POWERSHELL: [
        ("ps1-subcommands", ps_subcommands),
        ("ps1-root-value-options", ps_root_value_options),
        ("ps1-option-subcommands", ps_option_subcommands),
        ("ps1-runner-discovery", ps_runner_discovery),
        ("ps1-build-target-completer", ps_build_target_completer),
        ("ps1-exit-codes", ps_exit_codes),
        ("ps1-image-reference-pattern", ps_image_reference_pattern),
        ("ps1-ci-runner-markers", ps_ci_runner_markers),
    ],
    # The root bash entrypoint (./ash) was absorbed into the ash CLI, so the
    # PowerShell helper is the one wrapper left carrying generated tables.
}


def _find_block(lines: list[str], name: str, file: str) -> tuple[int, int, str]:
    begin, end = _begin(name), _end(name)
    begins = [i for i, line in enumerate(lines) if line.strip() == begin]
    ends = [i for i, line in enumerate(lines) if line.strip() == end]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise MarkerError(
            f"{file}: expected exactly one `{begin}` followed by one `{end}`; "
            f"found {len(begins)} begin and {len(ends)} end markers"
        )
    indent = lines[begins[0]][: len(lines[begins[0]]) - len(lines[begins[0]].lstrip())]
    return begins[0], ends[0], indent


def render_file(text: str, file: str, contract) -> str:
    """The file's text with every generated block rewritten from the contract."""
    lines = text.split("\n")
    for name, renderer in BLOCKS[file]:
        begin, end, indent = _find_block(lines, name, file)
        body = [f"{indent}{line}" if line else line for line in renderer(contract)]
        lines[begin + 1 : end] = body
    return "\n".join(lines)


def check_file(text: str, file: str, contract) -> list[Drift]:
    """Each block of ``text`` that differs from its rendering, with a diff."""
    drifts = []
    current = text.split("\n")
    for name, renderer in BLOCKS[file]:
        begin, end, indent = _find_block(current, name, file)
        have = current[begin + 1 : end]
        want = [f"{indent}{line}" if line else line for line in renderer(contract)]
        if have != want:
            diff = "\n".join(
                difflib.unified_diff(
                    have,
                    want,
                    fromfile=f"{file} ({name}, committed)",
                    tofile=f"{file} ({name}, generated)",
                    lineterm="",
                )
            )
            drifts.append(Drift(file=file, block=name, diff=diff))
    return drifts


def check(root: Path = REPO_ROOT, contract=None) -> list[Drift]:
    contract = contract or _contract()
    drifts: list[Drift] = []
    for file in BLOCKS:
        if BLOCKS[file]:
            drifts += check_file(
                (root / file).read_text(encoding="utf-8"), file, contract
            )
    return drifts


def write(root: Path = REPO_ROOT, contract=None) -> list[str]:
    """Rewrite every file whose blocks moved; returns the files written."""
    contract = contract or _contract()
    written = []
    for file in BLOCKS:
        if not BLOCKS[file]:
            continue
        path = root / file
        # Read with newline="" so the file's own line endings are seen, not translated:
        # a work tree checked out with CRLF (autocrlf on Windows) is written back with
        # CRLF, and one with LF with LF. The blocks are rendered on LF text, as
        # check_file reads it, and each line ending is restored on the way out.
        with path.open("r", encoding="utf-8", newline="") as handle:
            raw = handle.read()
        ending = "\r\n" if "\r\n" in raw else "\n"
        text = raw.replace("\r\n", "\n")
        new = render_file(text, file, contract)
        if new != text:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(new.replace("\n", ending))
            written.append(file)
    return written


def _contract():
    sys.path.insert(0, str(REPO_ROOT))
    from automated_security_helper.interactions.wrapper_contract import contract

    return contract()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 with a diff if a generated block is stale; write nothing",
    )
    args = parser.parse_args(argv)
    try:
        if args.check:
            drifts = check()
            for drift in drifts:
                print(f"STALE  {drift.file}: block {drift.block}")
                print(drift.diff)
            if drifts:
                print(
                    f"\n{len(drifts)} generated block(s) differ from the ash CLI. "
                    f"Run `uv run python {GENERATOR}` and commit the result."
                )
                return 1
            print("The generated wrapper blocks match the ash CLI.")
            return 0
        written = write()
    except MarkerError as error:
        print(f"ERROR  {error}", file=sys.stderr)
        return 2
    print("Wrote: " + (", ".join(written) if written else "nothing (already current)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
