#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Terraform gate's docs tell an operator to pass must be what the gate accepts.

Why this file exists
--------------------
`ash_pr_gate.py` refuses `--changed-files-only` and `--base-ref` in
`ASH_SCAN_EXTRA_ARGS`, on purpose: they filter the findings down to a diff before the
exit code is computed, so findings elsewhere in the tree stop counting, and this gate
can APPROVE. The refusal is read as outcome "error", which comments that the pull
request was not assessed and revokes any approval.

The module's example set `ash_scan_extra_args = "--changed-files-only --base-ref
origin/main"`, and three READMEs and the variable's description recommended the same
pair. Deployed as documented, the gate refused every pull request.

The handler is the side with the stated intent, so the docs were wrong. These tests
hold the docs to the handler: the example module call, run through the real
`run_scan`, must reach `ash scan`, and every `ash_scan_extra_args = "..."` written
anywhere under deploy/terraform must pass the handler's own refusal check.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from types import ModuleType, SimpleNamespace

import pytest

from tests.utils.helpers import iter_repo_files

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
TERRAFORM = REPO_ROOT / "deploy" / "terraform"
GATE_MODULE = TERRAFORM / "modules" / "codecommit-gate"
GATE_PATH = GATE_MODULE / "files" / "ash_pr_gate.py"
EXAMPLE = GATE_MODULE / "examples" / "basic" / "main.tf"
VARIABLES = GATE_MODULE / "variables.tf"

# `ash_scan_extra_args = "..."`, in HCL or in a Markdown snippet of HCL.
_ASSIGNMENT = re.compile(r'ash_scan_extra_args\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"')
# The variable's declared default, from `variable "ash_scan_extra_args" { ... }`.
_VARIABLE_BLOCK = re.compile(
    r'variable\s+"ash_scan_extra_args"\s*\{(?P<body>.*?)\n\}', re.DOTALL
)
_DEFAULT = re.compile(r'^\s*default\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"', re.MULTILINE)


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ash_pr_gate_docs", GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _example_extra_args() -> str:
    """What the example's gate module call ends up with: its own value or the default."""
    text = EXAMPLE.read_text(encoding="utf-8")
    start = text.index('module "ash_pr_gate"')
    block = text[start : text.index("\n}\n", start)]
    assigned = _ASSIGNMENT.search(block)
    if assigned:
        return assigned.group("value")
    variable = _VARIABLE_BLOCK.search(VARIABLES.read_text(encoding="utf-8"))
    assert variable, f"no ash_scan_extra_args variable block in {VARIABLES}"
    default = _DEFAULT.search(variable.group("body"))
    assert default, "ash_scan_extra_args has no string default"
    return default.group("value")


def test_the_example_gate_reaches_ash_scan(monkeypatch, tmp_path):
    """The example, deployed unchanged, must scan rather than refuse every pull request."""
    import typer.main

    from automated_security_helper.cli.main import app

    gate = _load_gate()
    captured: list[list[str]] = []
    monkeypatch.setattr(
        gate,
        "_run",
        lambda argv, cwd=None, env=None: (
            SimpleNamespace(
                returncode=0,
                stdout=f"Usage: ash scan [OPTIONS]\n  {gate.COMPLETENESS_FLAG}\n",
                stderr="",
            )
            if argv == ["ash", "scan", "--help"]
            else (
                captured.append(list(argv))
                or SimpleNamespace(returncode=0, stdout="", stderr="")
            )
        ),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    extra = _example_extra_args()
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", extra)

    try:
        gate.run_scan(tmp_path / "src", "low", True)
    except RuntimeError as exc:
        pytest.fail(
            f"{EXAMPLE.relative_to(REPO_ROOT)} configures ash_scan_extra_args={extra!r}, "
            f"which the gate refuses, so every pull request reports an error:\n{exc}"
        )

    assert captured and captured[0][:2] == ["ash", "scan"], captured
    scan = typer.main.get_command(app).commands["scan"]
    context = scan.make_context("scan", captured[0][2:], resilient_parsing=False)
    assert not context.args, (
        f"`ash scan` collected unknown options from the example's argv: {context.args}"
    )


def _documented_assignments(
    root: pathlib.Path = TERRAFORM, base: pathlib.Path = REPO_ROOT
) -> tuple[set[str], list[tuple[str, int, str]]]:
    """The files read, and every `ash_scan_extra_args = "..."` in them.

    A file counts as read only once its text is in hand, so a walk that listed files
    and read none cannot report them.
    """
    read, found = set(), []
    for path in iter_repo_files(root, skip_dirs=frozenset({".terraform"})):
        if path.suffix not in {".tf", ".md"}:
            continue
        relative = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8")
        if text:
            read.add(relative)
        for number, line in enumerate(text.splitlines(), 1):
            for match in _ASSIGNMENT.finditer(line):
                found.append((relative, number, match.group("value")))
    return read, found


def _refused(found: list[tuple[str, int, str]]) -> list[str]:
    gate = _load_gate()
    refused = []
    for path, number, value in found:
        try:
            gate._reject_gate_owned_options(value.split())
        except RuntimeError:
            refused.append(f"  {path}:{number}: ash_scan_extra_args = {value!r}")
    return refused


def test_the_walk_finds_and_refuses_a_planted_assignment(tmp_path):
    """Control for the walk itself, on a tree that does carry assignments.

    Nothing under deploy/terraform assigns the variable today, so the real walk finds
    nothing and the check below passes over an empty list; this gives it something
    to find, in both file types it reads, and one value the gate refuses.
    """
    module = tmp_path / "modules" / "codecommit-gate"
    (module / "examples" / "basic").mkdir(parents=True)
    (module / "README.md").write_text(
        "Set it like this:\n\n```hcl\n"
        '  ash_scan_extra_args = "--changed-files-only --base-ref origin/main"\n'
        "```\n",
        encoding="utf-8",
    )
    (module / "examples" / "basic" / "main.tf").write_text(
        'module "ash_pr_gate" {\n  ash_scan_extra_args = "--log-level DEBUG"\n}\n',
        encoding="utf-8",
    )
    (module / "variables.tf").write_text("", encoding="utf-8")

    read, found = _documented_assignments(tmp_path, tmp_path)

    assert read == {
        "modules/codecommit-gate/README.md",
        "modules/codecommit-gate/examples/basic/main.tf",
    }, read
    assert sorted(found) == [
        (
            "modules/codecommit-gate/README.md",
            4,
            "--changed-files-only --base-ref origin/main",
        ),
        ("modules/codecommit-gate/examples/basic/main.tf", 2, "--log-level DEBUG"),
    ], found
    assert _refused(found) == [
        (
            "  modules/codecommit-gate/README.md:4: ash_scan_extra_args = "
            "'--changed-files-only --base-ref origin/main'"
        )
    ]


def test_the_walk_reads_where_the_value_is_documented():
    """Positive control for the walk: no assignment ships today, so it finds nothing.

    An empty result passes the check below whether or not the walk read anything,
    so the files that document the variable must be among the ones it read.
    """
    read, _ = _documented_assignments()
    documenting = {
        "deploy/terraform/modules/codecommit-gate/README.md",
        "deploy/terraform/modules/codecommit-gate/examples/basic/main.tf",
        "deploy/terraform/modules/codecommit-gate/variables.tf",
    }
    assert documenting <= read, sorted(documenting - read)
    for relative in documenting:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "ash_scan_extra_args" in text, f"{relative} no longer mentions it"


def test_every_documented_extra_args_value_is_accepted():
    _, found = _documented_assignments()
    refused = _refused(found)

    assert not refused, (
        "These documented values set options the gate reserves, so a gate configured "
        "from them refuses every pull request:\n" + "\n".join(refused)
    )


def test_the_assignment_pattern_reads_the_shape_that_shipped():
    """Positive control for the pattern the walk above depends on.

    The walk passes on an empty result, so the pattern is exercised on the line the
    example shipped, and the refusal on its value.
    """
    shipped = '  ash_scan_extra_args = "--changed-files-only --base-ref origin/main"'
    match = _ASSIGNMENT.search(shipped)
    assert (
        match and match.group("value") == "--changed-files-only --base-ref origin/main"
    )
    with pytest.raises(RuntimeError):
        _load_gate()._reject_gate_owned_options(match.group("value").split())
