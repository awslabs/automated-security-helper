# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Find the values the steps under .github/ print in a workflow command.

The runner reads each line of a step's stdout and stderr, and treats a line as a
workflow command when it starts with `::` or holds `##[` anywhere; it ends a line at
a carriage return as well as at a line feed. So a value that a step prints inside
`::error::...` (or any other command) and that holds a line break followed by
`::warning::...`, or `##[`, adds a command of its own. The workflows pass such
values through one_line, written to `${RUNNER_TEMP}/ash-one-line.sh` by the step
named DEFINER_NAME, or through the Python copy PY_ONE_LINE in a Python step.

``printed_values`` lists every value a command line prints, by workflow file, job
and step; tests/unit/test_workflow_commands_print_no_unchecked_value.py holds each
one to the rule. It reads shell, PowerShell and inline Python (``<<'PY'`` heredocs
and ``python -c``). A value is any expansion: ``$VAR``, ``${...}``, ``$(...)``,
``$((...))``, ``${{ ... }}`` in shell and PowerShell, and each ``{...}`` of an
f-string whose text holds a command, found with ``ast`` so an f-string split over
several lines is read whole.
"""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFINER_NAME = "Write the one_line helper"
#: The function the definer writes. In the C locale [[:cntrl:]] is C0 and DEL; the
#: UTF-8 bytes of C1 (U+0080 to U+009F), U+2028 and U+2029 are named.
HELPER_TEXT = (
    "one_line() {\n"
    "  local LC_ALL=C\n"
    '  local text="${1//[[:cntrl:]]/ }"\n'
    "  text=\"${text//$'\\xc2'[$'\\x80'-$'\\x9f']/ }\"\n"
    "  text=\"${text//$'\\xe2\\x80'[$'\\xa8\\xa9']/ }\"\n"
    '  while [[ "${text}" == *::* ]]; do text="${text//::/: :}"; done\n'
    "  while [[ \"${text}\" == *'##['* ]]; do text=\"${text//'##['/# #[}\"; done\n"
    "  printf '%s' \"${text}\"\n"
    "}\n"
)
#: How the definer's `run:` opens: the heredoc starts with one_line as HELPER_TEXT
#: writes it, and with_commands_stopped and its helpers follow in the same file.
DEFINER_OPENING = "cat > \"${RUNNER_TEMP}/ash-one-line.sh\" <<'EOF'\n" + HELPER_TEXT


def _scan_definer_run() -> str:
    """The definer's whole `run:` as the scan workflow writes it.

    The scan job's definer is the one copy of the text (with_commands_stopped is too
    long to pin here); every other job's definer must equal it, and the tests hold
    its opening to HELPER_TEXT.
    """
    path = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for step in (data.get("jobs") or {}).get("ash", {}).get("steps") or []:
        if isinstance(step, dict) and step.get("name") == DEFINER_NAME:
            run = str(step.get("run") or "")
            if not run.startswith(DEFINER_OPENING):
                raise AssertionError(
                    f"{path.name}: the {DEFINER_NAME!r} step does not open with "
                    "HELPER_TEXT"
                )
            return run
    raise AssertionError(f"{path.name}: no step named {DEFINER_NAME!r} in job ash")


#: The definer's whole `run:`, the same in every job that has one.
DEFINER_RUN = _scan_definer_run()
#: The file the definer writes under RUNNER_TEMP.
HELPER_FILE = "ash-one-line.sh"
#: How a step loads the helper the definer wrote.
HELPER_SOURCE = '. "${RUNNER_TEMP}/' + HELPER_FILE + '"'

#: The Python form of one_line, for a Python step: the same three rules, with
#: Unicode categories Cc, Zl and Zp standing for bash's [[:cntrl:]] in a UTF-8
#: locale. Every Python copy is this text, indented.
PY_ONE_LINE = (
    "def one_line(text):\n"
    '    text = "".join(\n'
    '        " " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c\n'
    "        for c in str(text)\n"
    "    )\n"
    '    while "::" in text:\n'
    '        text = text.replace("::", ": :")\n'
    '    while "##[" in text:\n'
    '        text = text.replace("##[", "# #[")\n'
    "    return text\n"
)

#: Values that would add a workflow command if a step printed them as they are: a
#: command after a carriage return, after a line feed, at the start of the value,
#: and the legacy marker, which the runner finds anywhere in a line.
COMMAND_TEXT_VALUES = {
    "carriage return": "x\r::warning::from the value",
    "line feed": "x\n::warning::from the value",
    "command": "::warning::from the value",
    "legacy marker": "x ##[warning]from the value",
}


def command_text(value: str) -> str:
    """The part of a COMMAND_TEXT_VALUES value that the runner would act on."""
    start = value.find("##[")
    return value[start:] if start >= 0 else value[value.index("::") :]


def runner_locales() -> list[str]:
    """C and C.UTF-8, in every glibc image, and en_US.UTF-8 where it is installed."""
    listing = subprocess.run(
        ["locale", "-a"], capture_output=True, text=True, check=False
    ).stdout
    installed = {n.strip().lower().replace("-", "") for n in listing.splitlines()}
    return ["C", "C.UTF-8", *(["en_US.UTF-8"] if "en_us.utf8" in installed else [])]


#: A workflow command as a print writes it: `::name::` or `::name props::`.
COMMAND = re.compile(r"::[a-z][a-z-]*(?:\s[^:\n]*)?::")
#: One shell or PowerShell expansion. Alternatives are tried in this order at each
#: position, and a match consumes its text, so the inner `${x}` of `$(one_line
#: "${x}")` is not read again.
EXPANSION = re.compile(
    r"\$\(\((?P<arith>.*?)\)\)"
    r"|\$\((?P<sub>(?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)"
    r"|\$\{\{(?P<expr>.*?)\}\}"
    r"|\$\{(?P<brace>[^}]+)\}"
    r"|\$(?P<bare>[A-Za-z_][A-Za-z0-9_]*|[*@#?0-9])"
)
PY_HEREDOC = re.compile(
    r"<<-?\s*'(?P<tag>[A-Z_]+)'\s*\n(?P<body>.*?)\n\s*(?P=tag)\s*$",
    re.DOTALL | re.MULTILINE,
)
PY_DASH_C = re.compile(r"python3?\s+(?:-[A-Za-z]+\s+)*-c\s+'(?P<body>[^']*)'")


@dataclass(frozen=True)
class Printed:
    """One value a workflow-command line prints."""

    file: str
    job: str
    step: str
    value: str
    line: str

    @property
    def neutralized(self) -> bool:
        return (
            self.value.startswith(("one_line ", "one_line("))
            or self.value == "one_line"
        )


def workflow_files(root: Path = REPO_ROOT) -> list[Path]:
    return sorted(
        [
            *(root / ".github" / "workflows").glob("*.yml"),
            *(root / ".github" / "workflows").glob("*.yaml"),
            *(root / ".github" / "actions").glob("*/action.yml"),
        ]
    )


def jobs_and_steps(data: dict[str, Any]) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    """(job id, steps) for a workflow, or ("(composite action)", steps) for an action."""
    for job_id, job in (data.get("jobs") or {}).items():
        yield (
            str(job_id),
            [s for s in (job or {}).get("steps") or [] if isinstance(s, dict)],
        )
    runs = data.get("runs") or {}
    if runs.get("steps"):
        yield "(composite action)", [s for s in runs["steps"] if isinstance(s, dict)]


def _logical_lines(script: str) -> Iterator[str]:
    """Lines with backslash continuations joined, comment lines dropped."""
    pending = ""
    for raw in script.splitlines():
        if not pending and raw.lstrip().startswith("#"):
            continue
        if raw.endswith("\\"):
            pending += raw[:-1]
            continue
        yield pending + raw
        pending = ""
    if pending:
        yield pending


def _shell_values(script: str) -> Iterator[tuple[str, str]]:
    """(value, line) for each expansion after a workflow command on a shell line."""
    for line in _logical_lines(script):
        found = COMMAND.search(line)
        if not found:
            continue
        for match in EXPANSION.finditer(line, found.start()):
            # `\$NAME` prints the text `$NAME`; it expands nothing.
            before = line[: match.start()]
            if (len(before) - len(before.rstrip("\\"))) % 2:
                continue
            value = next(v for v in match.groupdict().values() if v is not None)
            yield value.strip(), line.strip()


def _python_sources(script: str) -> Iterator[str]:
    for match in PY_HEREDOC.finditer(script):
        yield match.group("body")
    for match in PY_DASH_C.finditer(script):
        yield match.group("body")


def _python_values(source: str) -> Iterator[tuple[str, str]]:
    """(value, f-string) for each {...} of an f-string whose text holds a command."""
    try:
        tree = ast.parse(_dedent(source))
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        text = "".join(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
        if "::" not in text:
            continue
        rendered = ast.unparse(node)
        if not COMMAND.search(text.replace("{", "").replace("}", "")) and not re.search(
            r"::[a-z][a-z-]*", text
        ):
            continue
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                yield ast.unparse(part.value), rendered


def _dedent(source: str) -> str:
    lines = source.splitlines()
    indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
    cut = min(indents) if indents else 0
    return "\n".join(line[cut:] for line in lines)


def _is_shell_line_in_python(script: str) -> set[str]:
    """The lines of `script` that belong to an inline Python program."""
    inside: set[str] = set()
    for source in _python_sources(script):
        inside.update(source.splitlines())
    return inside


def printed_values(root: Path = REPO_ROOT) -> list[Printed]:
    found: list[Printed] = []
    for path in workflow_files(root):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        where = path.relative_to(root).as_posix()
        for job, steps in jobs_and_steps(data):
            for step in steps:
                script = str(step.get("run") or "")
                if not script:
                    continue
                name = str(step.get("name") or step.get("id") or "")
                python_lines = _is_shell_line_in_python(script)
                shell_part = "\n".join(
                    line for line in script.splitlines() if line not in python_lines
                )
                for value, line in _shell_values(shell_part):
                    found.append(Printed(where, job, name, value, line))
                for source in _python_sources(script):
                    for value, line in _python_values(source):
                        found.append(Printed(where, job, name, value, line))
    return found


def definer_steps(root: Path = REPO_ROOT) -> list[tuple[str, str, int, dict[str, Any]]]:
    """(file, job, index, step) for every step that writes ash-one-line.sh."""
    found = []
    for path in workflow_files(root):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        where = path.relative_to(root).as_posix()
        for job, steps in jobs_and_steps(data):
            for index, step in enumerate(steps):
                if "ash-one-line.sh" in str(
                    step.get("run") or ""
                ) and HELPER_SOURCE not in str(step.get("run") or ""):
                    found.append((where, job, index, step))
    return found


def helper_without_definer(data: dict[str, Any]) -> list[tuple[str, str]]:
    """(job, step) for each step that loads the helper with no definer before it."""
    missing = []
    for job, steps in jobs_and_steps(data):
        defined = False
        for step in steps:
            script = str(step.get("run") or "")
            if step.get("name") == DEFINER_NAME and script == DEFINER_RUN:
                defined = True
            elif HELPER_SOURCE in script and not defined:
                missing.append((job, str(step.get("name"))))
    return missing


def python_one_line_copies(root: Path = REPO_ROOT) -> list[tuple[str, str, str]]:
    """(file, step, text) of every `def one_line` in an inline Python program."""
    found = []
    for path in workflow_files(root):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        where = path.relative_to(root).as_posix()
        for _, steps in jobs_and_steps(data):
            for step in steps:
                for source in _python_sources(str(step.get("run") or "")):
                    body = _dedent(source)
                    start = body.find("def one_line(")
                    if start < 0:
                        continue
                    end = body.find("\n\n", start)
                    found.append(
                        (
                            where,
                            str(step.get("name")),
                            body[start : end + 1 if end >= 0 else None],
                        )
                    )
    return found
