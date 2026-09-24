#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asserts no `type: boolean` workflow input is consumed as if it were a string.

WHY THIS EXISTS
---------------
`.github/workflows/run-ash-security-scan.yml` declared `fail-on-findings` as
`type: boolean` with `default: true`, then selected the CLI flag with
`inputs.fail-on-findings == 'true'`. That comparison is false for every value the
input can hold, so the workflow passed `--no-fail-on-findings` on every run it
ever made -- including ASH's own pull request and merge queue gate, and every
external consumer of the reusable workflow. There was no input value a caller
could supply to switch findings enforcement back on.

The mechanism is GitHub's loose equality. When the operand types differ, GitHub
casts both to a number: Boolean `true` becomes 1 and `false` becomes 0, while a
String is parsed as a JSON number or else becomes `NaN`. Neither `'true'` nor
`'false'` is a legal JSON number, so both comparisons are made against `NaN` and
neither can hold.

The published casting table documents that much. The always-false rule GitHub
states in so many words covers the relational operators rather than `==`, so the
last step is stated here as measured rather than inferred: the workflow
demonstrably passed `--no-fail-on-findings` while the input held its default of
`true`, and only the `||` branch of that expression produces that string.

That is the whole defect, and it is invisible in review: the expression reads
like a string comparison in any other language, the workflow runs green, and the
scan still produces a report. Only the exit code changes, and a caller reading
only the exit code cannot tell an enforced gate from an unenforced one.

The same file carried a second instance in a different disguise. `verbose` is
also `type: boolean`, was assigned bare into an env var, and was consumed as
`${VERBOSE:+--verbose}`. Rendering a Boolean into an env var produces the
STRING, so `false` arrived as `"false"` -- set and non-empty -- and `:+` fired
anyway. Two instances of one root cause in one file is what makes this a class
worth a gate rather than two lines worth a commit.

WHAT THIS CHECKS, AND WHAT IT CANNOT SEE
----------------------------------------
Two rules, both keyed on inputs this script has read a `type: boolean`
declaration for in the same file.

  1. A quoted string on either side of `==` or `!=` from that input. This is the
     unambiguous form: for a Boolean operand, a quoted string comparison is
     either always false (the string is not a legal JSON number) or accidentally
     right for an unreadable reason (`'1'` casts to 1, so `true == '1'` holds).
     Both are refused. Compare against the bare literal -- `inputs.foo == true`,
     or just `inputs.foo` -- which needs no cast at all.

  2. A shell truthiness test on an env var assigned bare from that input:
     `${VAR:+...}`, `${VAR:-...}`, `${VAR:=...}`, `${VAR:?...}`, and `-n`/`-z`
     tests. All of these ask whether the variable is set and non-empty, and a
     Boolean rendered into the environment is never empty for either value.
     Resolve the choice in the `env:` block instead, where the expression engine
     still sees a Boolean: `VAR: ${{ inputs.foo && '--foo' || '' }}`.

What it deliberately does NOT flag, because each of these is correct code and a
gate that reddens on correct configuration gets switched off:

  * `.github/actions/**/action.yml`. Composite action inputs have no `type:`
     field -- they are always strings -- so `inputs.offline == 'true'` there is
     the right idiom, and this repository has 40-odd of them. Only workflow
     files are censused for that reason.
  * `[ "$VAR" = "true" ]`. A literal string comparison in the shell is exact,
     because the shell genuinely received the string `"true"`. Only the
     truthiness constructs in rule 2 are wrong.
  * `${{ inputs.foo }}` interpolated bare into a command line. Whether
     `--flag=false` is meaningful depends on the CLI being invoked, which this
     script cannot know.
  * A boolean input passed through `with:` to another workflow, then compared
     there. The declaration and the use are in different files; this script
     reasons within one file only.

A green run therefore means "no instance of these two forms", not "every boolean
input is consumed correctly". Say so, rather than letting the next reader take
green as a proof of the wider property.

ENV VAR SCOPING IS DELIBERATELY IGNORED
---------------------------------------
Rule 2 treats a workflow file as one env namespace: an assignment anywhere in
the file is matched against a truthiness test anywhere in it. GitHub scopes
`env:` per workflow, job and step, so this over-approximates. That direction is
chosen on purpose -- it errs toward reporting -- and a file that defines one env
name twice from different sources is worth a human look regardless.

NO VACUOUS PASSES
-----------------
The realistic failure of a check like this is matching nothing and exiting 0.
Every route to an empty examination fails instead:

  * `git ls-files` returning no workflow YAML (wrong directory, not a
    repository) leaves nothing to iterate. Fails.
  * finding no `workflow_call` or `workflow_dispatch` input anywhere means the
    declaration scanner is broken, not that the repository declares none. Fails.
  * finding inputs but zero declared `type: boolean` means the type reader is
    broken, and both rules would then apply to the empty set. Fails.
  * a `workflow_call` input with no readable `type:` is a declaration this
    script cannot classify, so it is reported rather than skipped. GitHub
    requires `type:` on every `workflow_call` input; `workflow_dispatch` does
    not, and an untyped input there is a string by definition and is accepted.

`--self-test` closes the last gap, which is the detectors themselves silently
stopping. It builds fixtures for each rule and asserts each one is rejected AND
that the clean and string-typed fixtures are accepted, so a regression that
makes this script blind fails the self-test instead of quietly passing every
workflow in the tree. CI runs it before the real census for that reason.

USAGE
-----
    python3 assert-workflow-boolean-inputs.py
    python3 assert-workflow-boolean-inputs.py --self-test

Exit codes: 0 clean, 1 findings, 2 this script could not do its job.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Only workflow files. Composite action inputs are untyped strings, so the rules
# here do not apply to them -- see WHAT THIS CHECKS above.
SCANNED_DIRS = (".github/workflows",)

# The two `on:` sections that can declare typed inputs. `workflow_call` requires
# `type:`; `workflow_dispatch` defaults it to string.
INPUT_SECTIONS = ("workflow_call", "workflow_dispatch")

# A mapping key with a simple scalar name, optionally quoted. `on` is quoted in
# some workflows because YAML 1.1 reads the bare word as a Boolean.
KEY_LINE = re.compile(r"""^(\s*)("[^"]*"|'[^']*'|[A-Za-z0-9_.\-]+)\s*:(\s.*|)$""")

# `|`, `>`, `|-`, `>+`, `|2` and friends: the value is a block scalar whose body
# follows on more-indented lines.
BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*$")

# `inputs.name == 'literal'` in either operand order. Both operators, because
# `!=` inverts the same broken cast rather than avoiding it.
COMPARISON = re.compile(
    r"""
    (?:
        inputs\.(?P<lname>[A-Za-z0-9_-]+)
        \s*(?P<lop>==|!=)\s*
        (?P<lval>'[^']*'|"[^"]*")
      |
        (?P<rval>'[^']*'|"[^"]*")
        \s*(?P<rop>==|!=)\s*
        inputs\.(?P<rname>[A-Za-z0-9_-]+)
    )
    """,
    re.VERBOSE,
)

# `VAR: ${{ inputs.name }}` and nothing else on the line. A selection expression
# such as `${{ inputs.name && '--flag' || '' }}` does not match, and must not:
# that is the correct form, because the engine evaluates the Boolean before the
# shell ever sees a string.
ENV_FROM_INPUT = re.compile(
    r"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"\$\{\{\s*inputs\.(?P<name>[A-Za-z0-9_-]+)\s*\}\}\s*$"
)


class CheckError(Exception):
    """This script could not do its job. Distinct from finding a violation."""


def strip_comment(line: str) -> str:
    """Drops a trailing YAML comment, leaving a `#` inside quotes alone.

    Needed in both directions. Without it a commented-out example carrying the
    bad pattern is reported as a live violation; with a naive `line.find('#')`
    a real violation sitting after a quoted `#` is truncated away.
    """
    quote: str | None = None
    for index, char in enumerate(line):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def unquote(value: str) -> str:
    """Strips one layer of matching quotes, so `"on":` reads as `on`."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def iter_block_children(lines: list[str], start: int, parent_indent: int):
    """Yields `(index, indent, key, value)` for the direct children of a block.

    `key` is None when a non-blank line at the child indentation is not a
    mapping key, which the caller reports rather than skips. Lines indented
    deeper belong to a grandchild block and are left to a recursive call; a line
    at or under `parent_indent` ends this block.
    """
    child_indent: int | None = None
    index = start
    while index < len(lines):
        code = strip_comment(lines[index])
        if not code.strip():
            index += 1
            continue
        indent = len(code) - len(code.lstrip(" "))
        if indent <= parent_indent:
            return
        if child_indent is None:
            child_indent = indent
        if indent > child_indent:
            # A nested block, or the body of a block scalar. Both are reached by
            # recursing from the key that owns them, never from here.
            index += 1
            continue
        match = KEY_LINE.match(code)
        if match is None:
            yield (index, indent, None, code.strip())
        else:
            yield (index, indent, unquote(match.group(2)), match.group(3).strip())
        index += 1


def parse_typed_inputs(path: str, lines: list[str]) -> tuple[dict[str, str], list[str]]:
    """Reads the `workflow_call` / `workflow_dispatch` input declarations.

    Returns `{input name: declared type}` plus problems for declarations this
    script cannot classify. An input whose type it cannot read is a hole in both
    rules below, so it is named rather than dropped.
    """
    declared: dict[str, str] = {}
    problems: list[str] = []

    for on_index, on_indent, on_key, on_value in iter_block_children(lines, 0, -1):
        if on_key != "on":
            continue
        if on_value and not BLOCK_SCALAR.match(on_value):
            # `on: push` or `on: [push]`. No inputs are reachable.
            continue
        for sec_index, sec_indent, section, _ in iter_block_children(
            lines, on_index + 1, on_indent
        ):
            if section not in INPUT_SECTIONS:
                continue
            for in_index, in_indent, in_key, in_value in iter_block_children(
                lines, sec_index + 1, sec_indent
            ):
                if in_key != "inputs":
                    continue
                if in_value:
                    problems.append(
                        f"{path}:{in_index + 1} `inputs:` under `{section}` has an "
                        f"inline value {in_value!r}, so this check cannot read the "
                        f"input declarations. Refusing to skip a block it cannot "
                        f"parse."
                    )
                    continue
                problems.extend(
                    _read_input_block(
                        path, lines, in_index, in_indent, section, declared
                    )
                )
    return declared, problems


def _read_input_block(
    path: str,
    lines: list[str],
    inputs_index: int,
    inputs_indent: int,
    section: str,
    declared: dict[str, str],
) -> list[str]:
    """Records one `inputs:` mapping into `declared`, returning any problems."""
    problems: list[str] = []
    for name_index, name_indent, name, name_value in iter_block_children(
        lines, inputs_index + 1, inputs_indent
    ):
        if name is None:
            problems.append(
                f"{path}:{name_index + 1} is inside `{section}.inputs` but is not a "
                f"mapping key: {name_value!r}. Refusing to skip a declaration it "
                f"cannot read."
            )
            continue

        input_type: str | None = None
        if not name_value:
            for _, _, field, field_value in iter_block_children(
                lines, name_index + 1, name_indent
            ):
                if field == "type":
                    input_type = unquote(field_value)

        if input_type is None:
            if section == "workflow_call":
                problems.append(
                    f"{path}:{name_index + 1} `workflow_call` input {name!r} has no "
                    f"readable `type:`. GitHub requires one, and without it this "
                    f"check cannot tell a Boolean input from a string input, so it "
                    f"would silently stop covering this input."
                )
            # A `workflow_dispatch` input with no `type:` is a string by
            # definition, so it is correctly outside both rules.
            continue

        declared[name] = input_type
    return problems


def find_violations(path: str, lines: list[str], boolean_inputs: set[str]) -> list[str]:
    """Applies both rules to one file's lines."""
    problems: list[str] = []
    env_from_boolean: dict[str, tuple[str, int]] = {}

    for index, raw in enumerate(lines):
        code = strip_comment(raw)
        line_number = index + 1

        for match in COMPARISON.finditer(code):
            name = match.group("lname") or match.group("rname")
            if name not in boolean_inputs:
                continue
            literal = match.group("lval") or match.group("rval")
            operator = match.group("lop") or match.group("rop")
            problems.append(
                f"{path}:{line_number} compares `type: boolean` input {name!r} "
                f"against the quoted string {literal} using `{operator}`. GitHub "
                f"casts mismatched operands to a number: a Boolean becomes 1 or 0, "
                f"and a string is parsed as a JSON number or else becomes NaN. So "
                f"the result does not depend on the input at all -- `==` is false "
                f"for both values and `!=` is true for both. Compare against the "
                f"bare literal instead: `inputs.{name} == true`, or just "
                f"`inputs.{name}`."
            )

        env_match = ENV_FROM_INPUT.match(code)
        if env_match and env_match.group("name") in boolean_inputs:
            env_from_boolean[env_match.group("var")] = (
                env_match.group("name"),
                line_number,
            )

    for var, (name, assigned_at) in sorted(env_from_boolean.items()):
        colon_test = re.compile(r"\$\{" + re.escape(var) + r":[-+=?]")
        flag_test = re.compile(
            r"(?<![A-Za-z0-9_])-[nz]\s+\"?\$\{?" + re.escape(var) + r"\b"
        )
        for index, raw in enumerate(lines):
            code = strip_comment(raw)
            if not (colon_test.search(code) or flag_test.search(code)):
                continue
            problems.append(
                f"{path}:{index + 1} applies a shell set-and-non-empty test to "
                f"${var}, which {path}:{assigned_at} assigns bare from the "
                f"`type: boolean` input {name!r}. A Boolean renders into the "
                f"environment as the STRING `true` or `false`, and `false` is set "
                f"and non-empty, so the test fires for both values. Resolve the "
                f"choice where the engine still sees a Boolean: "
                f"`{var}: ${{{{ inputs.{name} && '--flag' || '' }}}}`, then use "
                f"${{{var}}} directly."
            )
    return problems


def check_text(path: str, text: str) -> tuple[list[str], int, int]:
    """Checks one workflow's text. Returns (problems, inputs, boolean inputs)."""
    lines = text.split("\n")
    declared, problems = parse_typed_inputs(path, lines)
    boolean_inputs = {name for name, kind in declared.items() if kind == "boolean"}
    problems.extend(find_violations(path, lines, boolean_inputs))
    return problems, len(declared), len(boolean_inputs)


def vacuous_reason(files: int, inputs: int, boolean_inputs: int) -> str | None:
    """Names the reason an examination measured nothing, or None if it measured."""
    if files == 0:
        return (
            f"git ls-files found no YAML under {' or '.join(SCANNED_DIRS)} -- there "
            f"is nothing to check, and this gate must not pass by finding nothing"
        )
    if inputs == 0:
        return (
            f"no `workflow_call` or `workflow_dispatch` input was found in any of "
            f"the {files} workflow file(s) scanned. This repository publishes a "
            f"reusable workflow, so that is the declaration scanner failing rather "
            f"than the truth"
        )
    if boolean_inputs == 0:
        return (
            f"{inputs} workflow input(s) were read but none declared "
            f"`type: boolean`, so both rules were applied to the empty set. A pass "
            f"here would measure the type reader, not the repository"
        )
    return None


def git(repo_root: str, args: list[str]) -> str:
    return subprocess.run(
        ["git", "-C", repo_root, *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def census(repo_root: str) -> list[str]:
    """Tracked workflow YAML, so an untracked stray cannot change the verdict."""
    out = git(repo_root, ["ls-files", "-z", "--", *SCANNED_DIRS])
    return [
        entry
        for entry in out.split("\0")
        if entry and entry.endswith((".yml", ".yaml"))
    ]


def run_census(repo_root: str, files: list[str], out, err) -> int:
    problems: list[str] = []
    total_inputs = 0
    total_boolean = 0

    for relative in files:
        text = Path(repo_root, relative).read_text(encoding="utf-8")
        file_problems, inputs, boolean_inputs = check_text(relative, text)
        problems.extend(file_problems)
        total_inputs += inputs
        total_boolean += boolean_inputs

    reason = vacuous_reason(len(files), total_inputs, total_boolean)
    if reason is not None:
        raise CheckError(reason)

    if problems:
        err.write("Workflow boolean input check failed:\n")
        for problem in problems:
            err.write(f"  - {problem}\n")
        return 1

    out.write(
        f"workflow boolean inputs OK: {total_boolean} of {total_inputs} declared "
        f"input(s) across {len(files)} workflow file(s) are `type: boolean`, and "
        f"none is compared against a quoted string or tested for emptiness in a "
        f"shell\n"
    )
    return 0


# --- self-test ---------------------------------------------------------------
#
# Each fixture is a whole workflow rather than a snippet, so the declaration
# parser is exercised on the same shape it sees in the tree. The two ACCEPTED
# fixtures matter as much as the rejected ones: they are what stops this gate
# from becoming a false-alarm generator over the 40-odd correct
# `inputs.x == 'true'` comparisons in .github/actions.

_HEADER = """name: Fixture
on:
  workflow_call:
    inputs:
"""


def _fixture(inputs: str, steps: str) -> str:
    return f"""{_HEADER}{inputs}
jobs:
  job:
    runs-on: ubuntu-latest
    steps:
{steps}
"""


_BOOLEAN_INPUT = """      flag:
        description: "A boolean"
        required: false
        default: true
        type: boolean
"""

_STRING_INPUT = """      flag:
        description: "A string"
        required: false
        default: "true"
        type: string
"""

FIXTURES: tuple[tuple[str, str, str | None], ...] = (
    (
        "boolean-compared-to-quoted-string",
        _fixture(
            _BOOLEAN_INPUT,
            """      - name: Run
        env:
          PARAM: ${{ inputs.flag == 'true' && '--flag' || '--no-flag' }}
        run: echo "${PARAM}"
""",
        ),
        "against the quoted string 'true'",
    ),
    (
        "boolean-compared-in-an-if",
        _fixture(
            _BOOLEAN_INPUT,
            """      - name: Run
        if: inputs.flag != 'false'
        run: echo hi
""",
        ),
        "against the quoted string 'false'",
    ),
    (
        "boolean-env-var-tested-with-colon-plus",
        _fixture(
            _BOOLEAN_INPUT,
            """      - name: Run
        env:
          FLAG: ${{ inputs.flag }}
        run: echo "${FLAG:+--flag}"
""",
        ),
        "set-and-non-empty test to $FLAG",
    ),
    (
        "boolean-env-var-tested-with-dash-n",
        _fixture(
            _BOOLEAN_INPUT,
            """      - name: Run
        env:
          FLAG: ${{ inputs.flag }}
        run: |
          if [ -n "$FLAG" ]; then echo on; fi
""",
        ),
        "set-and-non-empty test to $FLAG",
    ),
    (
        "workflow-call-input-with-no-type",
        _fixture(
            """      flag:
        description: "Untyped"
        required: false
"""
            + _BOOLEAN_INPUT.replace("      flag:", "      other:"),
            """      - name: Run
        run: echo hi
""",
        ),
        "has no readable `type:`",
    ),
    # Accepted: the bare-literal comparison, and a selection expression resolved
    # in `env:` and then consumed with `:+`. The second is the exact shape the
    # fix uses, so a regression that flagged it would redden the tree it fixed.
    (
        "clean-bare-literal-and-resolved-env",
        _fixture(
            _BOOLEAN_INPUT,
            """      - name: Run
        if: inputs.flag == true
        env:
          FLAG: ${{ inputs.flag && '--flag' || '' }}
        run: echo "${FLAG:+resolved}" ${FLAG}
""",
        ),
        None,
    ),
    # Accepted: a string-typed input genuinely is a string, so comparing it to a
    # quoted string is correct. This is why composite actions are out of scope.
    (
        "clean-string-input-compared-to-quoted-string",
        _fixture(
            _STRING_INPUT,
            """      - name: Run
        if: inputs.flag == 'true'
        env:
          FLAG: ${{ inputs.flag }}
        run: echo "${FLAG:+--flag}"
""",
        ),
        None,
    ),
)


def run_self_test(stream) -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        for name, text, expected in FIXTURES:
            path = Path(tmp, f"{name}.yml")
            path.write_text(text, encoding="utf-8")
            problems, _, _ = check_text(f"{name}.yml", path.read_text(encoding="utf-8"))

            if expected is None:
                if problems:
                    failures.append(f"clean fixture {name} was REJECTED: {problems}")
                else:
                    stream.write(f"  self-test: {name} accepted\n")
                continue

            if not problems:
                failures.append(
                    f"fixture {name} was NOT rejected -- the detector for "
                    f"{expected!r} has stopped firing"
                )
            elif not any(expected in problem for problem in problems):
                failures.append(
                    f"fixture {name} was rejected but for the wrong reason; "
                    f"expected a message containing {expected!r}, got {problems}"
                )
            else:
                stream.write(f"  self-test: {name} rejected, naming {expected!r}\n")

    # The no-vacuous-pass guards are part of the contract, so they are tested
    # rather than trusted. Each argument triple is a way the census can measure
    # nothing; all three must be refused, and a real measurement must not be.
    for label, args in (
        ("no workflow files", (0, 0, 0)),
        ("no inputs declared", (3, 0, 0)),
        ("no boolean inputs", (3, 7, 0)),
    ):
        if vacuous_reason(*args) is None:
            failures.append(f"vacuous-pass guard did not fire for: {label}")
        else:
            stream.write(f"  self-test: vacuous-pass guard fires for {label}\n")
    if vacuous_reason(3, 7, 2) is not None:
        failures.append(
            "vacuous-pass guard fired on a real measurement (3 files, 7 inputs, "
            "2 boolean), which would fail the gate on correct input"
        )

    if failures:
        stream.write("\nself-test FAILED:\n")
        for failure in failures:
            stream.write(f"  - {failure}\n")
        return 1

    stream.write(
        f"\nself-test OK: all {len(FIXTURES)} fixture(s) classified as expected and "
        f"every no-vacuous-pass guard fires\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fails when a `type: boolean` workflow input is compared against a "
            "quoted string or tested for emptiness in a shell."
        )
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Run the detectors against built-in fixtures instead of the "
            "repository, so a detector that stops firing fails here rather than "
            "passing every workflow silently."
        ),
    )
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return run_self_test(sys.stdout)

    repo_root = git(str(Path.cwd()), ["rev-parse", "--show-toplevel"]).strip()
    return run_census(repo_root, census(repo_root), sys.stdout, sys.stderr)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except CheckError as error:
        sys.stderr.write(f"workflow boolean inputs: {error}\n")
        sys.exit(2)
    except subprocess.CalledProcessError as error:
        sys.stderr.write(
            f"workflow boolean inputs: git failed: {error.stderr.strip()}\n"
        )
        sys.exit(2)
