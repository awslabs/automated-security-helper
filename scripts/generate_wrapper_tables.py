#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render the wrapper contract into the marked blocks of ``./ash`` and ``utils/ash_helpers.ps1``.

Usage:
    uv run python scripts/generate_wrapper_tables.py           # rewrite the blocks
    uv run python scripts/generate_wrapper_tables.py --check   # exit 1 with a diff if stale

The two host wrappers exist for hosts with no Python, so they carry written-out copies of
the ``ash`` CLI's own surface: the subcommand names, the root options that take a value,
which subcommands take the options a wrapper adds, the subjects of ``scan``, the runner
discovery order, and the shell completion each wrapper offers (``./ash --show-completion``
for bash, an argument completer for ``Invoke-ASH`` in PowerShell). This
script computes those from the real typer app and container mode's constants
(``automated_security_helper/interactions/wrapper_contract.py``) and writes them between
marker comments inside each wrapper, in that wrapper's own syntax::

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

ASH = "ash"
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


def ps_scan_subjects(contract) -> list[str]:
    return [
        f"$ashScanSubjects = {_ps_list(contract.scan_subjects)}",
        f"$ashScanValueOptions = {_ps_list(contract.scan_subject_value_options)}",
    ]


def ps_completion(contract) -> list[str]:
    """The argument completer for Invoke-ASH's -AshArgs and its remaining arguments.

    Built from the same tables as the wrapper's parser: the subcommands, the subjects
    of ``scan``, the options and the options that take a value. Written for the
    PowerShell 5.1 the wrapper supports.
    """
    return [
        "$ashArgumentCompleter = {",
        "    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)",
        f"    $subcommands = {_ps_list(contract.subcommands)}",
        f"    $subjects = {_ps_list(contract.scan_subjects)}",
        f"    $options = {_ps_list(contract.root_options)}",
        "    $valueOptions = "
        + _ps_list(
            (*contract.root_value_options, *contract.scan_subject_value_options)
        ),
        "    if ($parameterName -eq 'AshArgs') {",
        "        # -AshArgs is one string: complete its last word and keep the rest.",
        '        $line = "$wordToComplete".Trim([char]39, [char]34)',
        "        $words = @($line -split '\\s+' | Where-Object { $_ -ne '' })",
        "        if ($line -match '\\s$' -or $words.Count -eq 0) {",
        "            $typed = ''",
        "            $before = $words",
        "        }",
        "        else {",
        "            $typed = $words[$words.Count - 1]",
        "            $before = @($words | Select-Object -First ($words.Count - 1))",
        "        }",
        "        $lead = if ($before.Count -gt 0) { ($before -join ' ') + ' ' } else { '' }",
        "    }",
        "    else {",
        '        $typed = "$wordToComplete"',
        '        $all = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { "$_" })',
        "        if ($all.Count -gt 0 -and $all[$all.Count - 1] -eq $typed) {",
        "            $before = @($all | Select-Object -First ($all.Count - 1))",
        "        }",
        "        else {",
        "            $before = $all",
        "        }",
        "        $lead = ''",
        "    }",
        "    if ($before.Count -gt 0 -and $before[$before.Count - 1] -cin $valueOptions) {",
        "        return",
        "    }",
        "    $subcommand = ''",
        "    $subject = ''",
        "    $skip = $false",
        "    foreach ($word in $before) {",
        "        if ($skip) {",
        "            $skip = $false",
        "            continue",
        "        }",
        "        if ($word -cin $valueOptions) {",
        "            $skip = $true",
        "            continue",
        "        }",
        "        if ($subcommand -eq '' -and $word -cin $subcommands) {",
        "            $subcommand = $word",
        "            continue",
        "        }",
        "        if ($subcommand -eq 'scan' -and $subject -eq '' -and $word -cin $subjects) {",
        "            $subject = $word",
        "        }",
        "    }",
        "    $candidates = if ($typed -like '-*') { if ($subcommand -eq '' -or $subcommand -eq 'scan') { $options } else { @() } }",
        "    elseif ($subcommand -eq '') { $subcommands }",
        "    elseif ($subcommand -eq 'scan' -and $subject -eq '') { $subjects }",
        "    else { @() }",
        '    $candidates | Where-Object { $_ -like "$typed*" } | ForEach-Object {',
        "        [System.Management.Automation.CompletionResult]::new($lead + $_, $_, 'ParameterValue', $_)",
        "    }",
        "}",
        "Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'AshArgs' -ScriptBlock $ashArgumentCompleter",
        "Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'RemainingAshArgs' -ScriptBlock $ashArgumentCompleter",
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


# ---------------------------------------------------------------------------
# Bash renderers
# ---------------------------------------------------------------------------


def _sh_words(values) -> str:
    return " ".join(values)


def sh_subcommands(contract) -> list[str]:
    return [f'ASH_SUBCOMMANDS="{_sh_words(contract.subcommands)}"']


def sh_scan_subjects(contract) -> list[str]:
    return [
        f'ASH_SCAN_SUBJECTS="{_sh_words(contract.scan_subjects)}"',
        f'ASH_SCAN_VALUE_OPTIONS="{_sh_words(contract.scan_subject_value_options)}"',
        f'ASH_ROOT_OPTIONS="{_sh_words(contract.root_options)}"',
    ]


def sh_completion(contract) -> list[str]:
    """``print_bash_completion``: the bash completion function, printed by
    ``./ash --show-completion`` for hosts that have no Python to run the CLI's own.

    Built from the same tables as the wrapper's parser, so it cannot name a
    subcommand, a subject or an option the CLI does not have.
    """
    return [
        "print_bash_completion() {",
        "  cat <<'ASH_BASH_COMPLETION'",
        "_ash_completion() {",
        '  local cur="${COMP_WORDS[COMP_CWORD]}" prev="" subcommand="" subject="" word i skip="NO"',
        "ASH_BASH_COMPLETION",
        # The word lists are the wrapper's own tables, read when the function is
        # printed, so the text here holds no second copy of them.
        '  printf \'  local subcommands="%s"\\n\' "${ASH_SUBCOMMANDS}"',
        '  printf \'  local subjects="%s"\\n\' "${ASH_SCAN_SUBJECTS}"',
        '  printf \'  local options="%s"\\n\' "${ASH_ROOT_OPTIONS}"',
        '  printf \'  local value_options="%s %s"\\n\' "${ASH_ROOT_VALUE_OPTIONS}" "${ASH_SCAN_VALUE_OPTIONS}"',
        "  cat <<'ASH_BASH_COMPLETION'",
        "  if ((COMP_CWORD > 1)); then",
        '    prev="${COMP_WORDS[COMP_CWORD - 1]}"',
        "  fi",
        '  if [[ " ${value_options} " == *" ${prev} "* ]]; then',
        "    COMPREPLY=()",
        "    return 0",
        "  fi",
        "  for ((i = 1; i < COMP_CWORD; i++)); do",
        '    word="${COMP_WORDS[i]}"',
        '    if [[ "${skip}" = "YES" ]]; then',
        '      skip="NO"',
        "      continue",
        "    fi",
        '    if [[ " ${value_options} " == *" ${word} "* ]]; then',
        '      skip="YES"',
        "      continue",
        "    fi",
        '    if [[ -z "${subcommand}" && " ${subcommands} " == *" ${word} "* ]]; then',
        '      subcommand="${word}"',
        '    elif [[ "${subcommand}" = "scan" && -z "${subject}" && " ${subjects} " == *" ${word} "* ]]; then',
        '      subject="${word}"',
        "    fi",
        "  done",
        # No mapfile: bash 3.2, the macOS default, has none.
        "  COMPREPLY=()",
        '  if [[ "${cur}" == -* ]]; then',
        # Options are the wrapper's own and scan's; the other subcommands' are not
        # in these tables, so they are not offered.
        '    if [[ -z "${subcommand}" || "${subcommand}" = "scan" ]]; then',
        '      COMPREPLY=($(compgen -W "${options}" -- "${cur}"))',
        "    fi",
        '  elif [[ -z "${subcommand}" ]]; then',
        '    COMPREPLY=($(compgen -W "${subcommands}" -- "${cur}"))',
        '  elif [[ "${subcommand}" = "scan" && -z "${subject}" ]]; then',
        '    COMPREPLY=($(compgen -W "${subjects}" -- "${cur}"))',
        "  else",
        "    local IFS=$'\\n'",
        '    COMPREPLY=($(compgen -d -- "${cur}"))',
        "  fi",
        "}",
        "complete -o default -F _ash_completion ash ./ash",
        "ASH_BASH_COMPLETION",
        "}",
    ]


def sh_dash_o_subcommands(contract) -> list[str]:
    return [f'ASH_DASH_O_IS_THE_SUBCOMMANDS="{_sh_words(contract.dash_o_subcommands)}"']


def sh_root_value_options(contract) -> list[str]:
    return [f'ASH_ROOT_VALUE_OPTIONS="{_sh_words(contract.root_value_options)}"']


def sh_takes_quiet_and_color(contract) -> list[str]:
    return [
        f'ASH_TAKES_QUIET="{_sh_words(contract.takers("--quiet"))}"',
        f'ASH_TAKES_COLOR="{_sh_words(contract.takers("--no-color"))}"',
    ]


def sh_takes_sandbox(contract) -> list[str]:
    return [f'ASH_TAKES_SANDBOX="{_sh_words(contract.sandbox_subcommands)}"']


def sh_exit_codes(contract) -> list[str]:
    return [
        f"WRAPPER_REFUSAL_EXIT={contract.refusal_exit}",
        f"USAGE_ERROR_EXIT={contract.usage_error_exit}",
    ]


def sh_runner_order(contract) -> list[str]:
    return [f'ASH_RUNNER_ORDER="{_sh_words(contract.runner_order)}"']


def sh_ci_runner_markers(contract) -> list[str]:
    return [f'ASH_CI_RUNNER_MARKERS="{_sh_words(contract.ci_runner_markers)}"']


def sh_option_groups(contract) -> list[str]:
    return [
        f'ASH_OPTION_GROUPS="{_sh_words(contract.option_groups)}"',
        f'ASH_GROUP_LEAF_TAKERS="{_sh_words(contract.group_leaf_takers)}"',
    ]


def ps_option_groups(contract) -> list[str]:
    return [
        f"$ashOptionGroups = {_ps_list(contract.option_groups)}",
        f"$ashGroupLeafTakers = {_ps_list(contract.group_leaf_takers)}",
    ]


Renderer = Callable[..., list[str]]

#: file -> [(block name, renderer)]. The names are the ones written in the markers.
BLOCKS: dict[str, list[tuple[str, Renderer]]] = {
    POWERSHELL: [
        ("ps1-subcommands", ps_subcommands),
        ("ps1-scan-subjects", ps_scan_subjects),
        ("ps1-option-groups", ps_option_groups),
        ("ps1-root-value-options", ps_root_value_options),
        ("ps1-option-subcommands", ps_option_subcommands),
        ("ps1-runner-discovery", ps_runner_discovery),
        ("ps1-build-target-completer", ps_build_target_completer),
        ("ps1-completion", ps_completion),
        ("ps1-exit-codes", ps_exit_codes),
        ("ps1-image-reference-pattern", ps_image_reference_pattern),
        ("ps1-ci-runner-markers", ps_ci_runner_markers),
    ],
    ASH: [
        ("sh-subcommands", sh_subcommands),
        ("sh-scan-subjects", sh_scan_subjects),
        ("sh-option-groups", sh_option_groups),
        ("sh-completion", sh_completion),
        ("sh-dash-o-subcommands", sh_dash_o_subcommands),
        ("sh-root-value-options", sh_root_value_options),
        ("sh-takes-quiet-and-color", sh_takes_quiet_and_color),
        ("sh-takes-sandbox", sh_takes_sandbox),
        ("sh-exit-codes", sh_exit_codes),
        ("sh-runner-order", sh_runner_order),
        ("sh-ci-runner-markers", sh_ci_runner_markers),
    ],
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
