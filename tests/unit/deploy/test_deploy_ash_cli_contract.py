#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deploy targets must default to an ASH that accepts every option they pass it.

Why this file exists
--------------------
The deploy targets build ASH from a git ref (`AshVersion`, `ash_version`,
`DEFAULT_ASH_REF`) and then run it with options that older releases such as v3.7.0
and v3.6.0 do not have (`ash mcp --stateless-http` and `--allowed-host`, `ash scan
--shard-index/--shard-count` and `--fail-on-incomplete-scanners`, and the whole
`ash merge` command). So those defaults move at every release: a target defaulted
to an ASH older than itself would run it with options it does not know.
v3.7.0's `ash scan` ignores options it does not know, so several of those
combinations would not even fail: a shard would run a full scan, and the Terraform gate would lose the flag that
makes an incomplete scan an error rather than a pass.

What is asserted
----------------
1. Every default ASH pin in deploy/ names the packaged release (`v` plus
   `[tool.commitizen] version`), and a simulated `cz bump` rewrites every one of
   them. So at the commit a release is tagged on, each target defaults to that
   release.
2. Every option every target passes to ASH is declared by this tree's CLI, on the
   command it is passed to. At a release commit this tree IS the pinned release,
   so (1) and (2) together say the default configuration of every target works at
   every release. Between releases the pins still name the previous release; that
   is inherent in pinning a tag, and deploy/README.md tells anyone deploying from
   main to pin the commit instead.
3. No file in deploy/ invokes ASH without being one of the sources (2) reads, so a
   new target cannot pass options nobody checks.

How the invocations are read
----------------------------
From what ships, not from the TypeScript that renders it: the committed CDK
templates (held equal to a fresh synth by the IaC drift gate), the generated
cdk-constructs buildspecs (held equal to their renderer by its own check), the
Terraform buildspec templates as committed, and the two Python entrypoints of the
Terraform targets by running the code that builds their argv. The CDK gate handler
is Python inside a template, so its argv list is read with `ast`.
"""

from __future__ import annotations

import ast
import contextlib
import fnmatch
import importlib.machinery
import importlib.util
import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Callable, Iterator
from unittest import mock

import pytest
import yaml

from tests.unit.deploy.buildspec_extraction import (
    CODEBUILD_PROJECT,
    all_template_paths,
    codebuild_buildspecs,
    load_template,
)
from tests.utils.helpers import iter_repo_files

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY = REPO_ROOT / "deploy"
TERRAFORM_MODULES = DEPLOY / "terraform" / "modules"
TF_GATE = TERRAFORM_MODULES / "codecommit-gate" / "files" / "ash_pr_gate.py"
TF_MCP_SERVE = TERRAFORM_MODULES / "ash-image-pipeline" / "files" / "ash-mcp-serve"
CDK_CONSTRUCTS = DEPLOY / "cdk-constructs"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _packaged_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


# ---------------------------------------------------------------------------
# The CLI, and the check an invocation has to pass against it
# ---------------------------------------------------------------------------


def _cli():
    import typer.main

    from automated_security_helper.cli.main import app

    return typer.main.get_command(app)


@dataclass(frozen=True)
class Invocation:
    """One ASH command line: where it was found, and its words after `ash`."""

    where: str
    words: tuple[str, ...]

    def command_path(self, root) -> str:
        """The subcommand path this invocation reaches, '' for the root command."""
        return " ".join(_walk(self, root)[0])


def _option(command, spelling: str):
    for param in command.params:
        if spelling in getattr(param, "opts", ()) or spelling in getattr(
            param, "secondary_opts", ()
        ):
            return param
    return None


def _takes_value(param) -> bool:
    return not getattr(param, "is_flag", False) and not getattr(param, "count", False)


def _walk(invocation: Invocation, root) -> tuple[list[str], list[str]]:
    """Resolve subcommands and options the way click would, collecting what it lacks.

    Returns the subcommand path and the problems. A word is a subcommand when the
    current command is a group with a command of that name; an option is looked up
    on the command it follows, which is where click resolves it. Shell expansions
    (`$VAR`, `${...}`) are values, never options.
    """
    command, path, problems = root, [], []
    words = list(invocation.words)
    index = 0
    while index < len(words):
        word = words[index]
        if word.startswith("-") and len(word) > 1:
            spelling = word.split("=", 1)[0]
            param = _option(command, spelling)
            if param is None and spelling not in ("--help", "-h"):
                name = " ".join(["ash", *path])
                problems.append(
                    f"{invocation.where}: `{name}` has no option {spelling}"
                )
            elif param is not None and _takes_value(param) and "=" not in word:
                index += 1
        # Duck-typed rather than isinstance(click.Group): typer can carry its own
        # copy of click, whose Group is not the importable one.
        elif hasattr(command, "commands") and not word.startswith("$"):
            if word in command.commands:
                command = command.commands[word]
                path.append(word)
            elif not path:
                # click stops here too: nothing after an unknown command is parsed.
                problems.append(f"{invocation.where}: ash has no command {word!r}")
                break
        index += 1
    return path, problems


def unknown_to_cli(invocation: Invocation, root=None) -> list[str]:
    return _walk(invocation, root or _cli())[1]


# ---------------------------------------------------------------------------
# Reading ASH command lines out of shell text
# ---------------------------------------------------------------------------

# Words that can precede a command in a compound statement without being one.
_PREFIXES = {
    "do",
    "then",
    "else",
    "elif",
    "if",
    "while",
    "until",
    "!",
    "{",
    "exec",
    "time",
}


def _segments(line: str) -> list[list[str]]:
    """Split one logical shell line into simple commands, or [] if it does not lex."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        words = list(lexer)
    except ValueError:
        return []
    segments, current = [], []
    for word in [*words, ";"]:
        if set(word) <= set(";&|()<>"):
            while current and current[0] in _PREFIXES:
                current = current[1:]
            if current:
                segments.append(current)
            current = []
        else:
            current.append(word)
    return segments


def shell_invocations(text: str, where: str) -> list[Invocation]:
    """Every `ash ...` command in a block of shell text.

    Handles the two shapes the targets use to build an argv in pieces: a command
    started with `set -- ... ash ...` and extended by later `set -- "$@" ...` lines,
    and an `ash ... "$@"` that consumes such a list. Either way the appended words
    belong to the ASH command line.

    Appended words are attributed to every such command in the text, not tracked per
    list. Two unrelated lists in one script would therefore share their words, which
    can only add options to a command line and so errs toward reporting a problem,
    never toward hiding one.
    """
    logical = text.replace("\\\n", " ")
    found: list[tuple[list[str], bool]] = []
    appended: list[str] = []
    for line in logical.splitlines():
        for words in _segments(line):
            if words[:3] == ["set", "--", "$@"]:
                appended.extend(words[3:])
                continue
            if "ash" not in words:
                continue
            after = words[words.index("ash") + 1 :]
            # A command line, not prose that happens to contain the word: the next
            # word is an option or one of ASH's commands.
            if not after or not (after[0].startswith("-") or after[0] in _COMMANDS):
                continue
            built_with_set = words[:2] == ["set", "--"]
            found.append((after, built_with_set or "$@" in after))
    return [
        Invocation(where, tuple(after + (appended if takes_appended else [])))
        for after, takes_appended in found
    ]


# ---------------------------------------------------------------------------
# The sources
# ---------------------------------------------------------------------------


#: ASH's top-level commands, so `ash merge` reads as a command line and `ash scan's`
#: in a sentence does not. Written out rather than read from the CLI on purpose: a
#: reader that took its vocabulary from the CLI under test would stop seeing
#: `ash merge` lines the day `merge` disappeared, and pass over them.
#: test_the_reader_knows_every_ash_command keeps it equal to the CLI's own list.
_COMMANDS = frozenset(
    {
        "build-image",
        "config",
        "dependencies",
        "get-genai-guide",
        "inspect",
        "mcp",
        "merge",
        "plugin",
        "report",
        "scan",
    }
)


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _heredocs(command: str) -> Iterator[tuple[str, str]]:
    """(file name, body) for each `cat > NAME <<'DELIM' ... DELIM` in a command."""
    for match in re.finditer(
        r"cat > (\S+) <<'(\w+)'\n(.*?)\n\2(?:\n|$)", command, re.DOTALL
    ):
        yield match.group(1), match.group(3)


def _python_argv_invocations(source: str, where: str) -> list[Invocation]:
    """The `argv = ["ash", ...]` list in a Python handler, plus every `argv += [...]`.

    Non-constant elements become a `$VALUE` placeholder, which the check treats as a
    value. Both branches of a conditional `+=` are included, since either can run.
    """
    base: list[str] | None = None
    extra: list[str] = []
    for node in ast.walk(ast.parse(source)):
        value = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "argv"
            for target in node.targets
        ):
            value, is_base = node.value, True
        elif (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "argv"
        ):
            value, is_base = node.value, False
        if not isinstance(value, ast.List):
            continue
        words = [
            element.value
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
            else "$VALUE"
            for element in value.elts
        ]
        if is_base:
            if words[:1] == ["ash"]:
                base = words[1:]
        else:
            extra.extend(words)
    return [Invocation(where, tuple(base + extra))] if base is not None else []


def _joined_buildspecs(template: dict) -> list[str]:
    """The image-build buildspecs, which CDK emits as `Fn::Join`, as decodable JSON.

    Each `Ref` part becomes a placeholder string, as in buildspec_extraction.
    """
    texts = []
    for resource in template.get("Resources", {}).values():
        spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
        if resource.get("Type") != CODEBUILD_PROJECT or not isinstance(spec, dict):
            continue
        if "Fn::Join" in spec:
            delimiter, parts = spec["Fn::Join"]
            texts.append(
                delimiter.join(p if isinstance(p, str) else "CFN_REF" for p in parts)
            )
    return texts


def cdk_template_invocations() -> list[Invocation]:
    found: list[Invocation] = []
    for path in all_template_paths():
        template = load_template(path)
        name = path.name
        for logical_id, spec in codebuild_buildspecs(template).items():
            for phase, body in spec.get("phases", {}).items():
                for command in body.get("commands", []):
                    found += shell_invocations(command, f"{name} {logical_id} {phase}")
        for text in _joined_buildspecs(template):
            for phase, body in json.loads(text).get("phases", {}).items():
                for command in body.get("commands", []):
                    for filename, script in _heredocs(command):
                        where = f"{name} image build, {filename}"
                        if filename.endswith(".py"):
                            found += _python_argv_invocations(script, where)
                        elif filename.endswith(".sh"):
                            found += shell_invocations(script, where)
    return found


def cdk_constructs_invocations() -> list[Invocation]:
    found: list[Invocation] = []
    for path in sorted(CDK_CONSTRUCTS.glob("buildspec*.yml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        for phase, body in spec.get("phases", {}).items():
            for command in body.get("commands", []):
                found += shell_invocations(command, f"{_relative(path)} {phase}")
    return found


def terraform_buildspec_invocations() -> list[Invocation]:
    found: list[Invocation] = []
    for path in sorted(TERRAFORM_MODULES.glob("*/*.tftpl")):
        found += shell_invocations(path.read_text(encoding="utf-8"), _relative(path))
    return found


def _load_by_path(name: str, path: Path) -> ModuleType:
    """Import a deployed script that is not on any import path.

    Without writing bytecode beside it: these directories are what the Terraform
    modules read their files from.
    """
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    with mock.patch.object(sys, "dont_write_bytecode", True):
        loader.exec_module(module)
    return module


@contextlib.contextmanager
def _environment(values: dict[str, str], clear_prefixes: tuple[str, ...]):
    """os.environ without the variables a code path reads, plus `values`."""
    kept = {k: v for k, v in os.environ.items() if not k.startswith(clear_prefixes)}
    with mock.patch.dict(os.environ, {**kept, **values}, clear=True):
        yield


def _gate_runner(captured: list[list[str]]):
    """A stand-in for the gate's subprocess runner that records what it would run.

    The gate first asks ``ash scan --help`` whether the image's ASH has
    ``--fail-on-incomplete-scanners`` and refuses to scan when it does not; the probe
    is answered as an ASH that has it, and is not a scan, so it is not recorded.
    """

    def run(argv, cwd=None, env=None):
        argv = list(argv)
        if argv == ["ash", "scan", "--help"]:
            return SimpleNamespace(
                returncode=0, stdout="  --fail-on-incomplete-scanners\n", stderr=""
            )
        captured.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return run


def terraform_gate_invocations() -> list[Invocation]:
    """Run the Terraform gate's own run_scan and capture the argv it would execute."""
    gate = _load_by_path("_ash_pr_gate_cli_contract", TF_GATE)
    found: list[Invocation] = []
    with tempfile.TemporaryDirectory() as work:
        for fail_on_findings in (True, False):
            captured: list[list[str]] = []
            with (
                mock.patch.object(gate, "_run", _gate_runner(captured)),
                mock.patch.object(gate, "WORK_ROOT", Path(work) / "ash-gate"),
            ):
                with _environment(
                    {},
                    (
                        "ASH_SCAN_EXTRA_ARGS",
                        "ASH_OFFLINE",
                        "ASH_BAKED_",
                        "ASH_IMAGE_PATH",
                    ),
                ):
                    gate.run_scan(Path(work) / "src", "low", fail_on_findings)
            for argv in captured:
                assert argv[0] == "ash", argv
                found.append(
                    Invocation(
                        f"{_relative(TF_GATE)} run_scan(fail_on_findings={fail_on_findings})",
                        tuple(argv[1:]),
                    )
                )
    return found


#: The environments ash-mcp-serve is documented to read, one per branch of build_argv.
MCP_SERVE_ENVIRONMENTS = (
    {},
    {"ASH_MCP_STATELESS_HTTP": "false"},
    {
        "ASH_MCP_ALLOWED_HOSTS": "a.example, b.example",
        "ASH_MCP_AUTH_HEADER_NAME": "X-Ash-Auth",
        "ASH_MCP_AUTH_HEADER_VALUE": "value",
    },
    {"ASH_MCP_TRANSPORT": "sse"},
)


def terraform_mcp_serve_invocations() -> list[Invocation]:
    serve = _load_by_path("_ash_mcp_serve_cli_contract", TF_MCP_SERVE)
    found: list[Invocation] = []
    for environment in MCP_SERVE_ENVIRONMENTS:
        with _environment(environment, ("ASH_MCP_",)):
            argv = serve.build_argv()
        assert argv[0] == "ash", argv
        found.append(
            Invocation(f"{_relative(TF_MCP_SERVE)} {environment}", tuple(argv[1:]))
        )
    return found


def workflow_invocations() -> list[Invocation]:
    """The reusable workflow's `ash` commands, with the flags its env blocks supply.

    The Run ASH step selects several flags in its `env:` block, as quoted literals in
    `${{ ... }}` expressions, and splices them in through shell variables. Every
    literal a referenced variable can hold is added to that command line.
    """
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    found: list[Invocation] = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            script = step.get("run")
            if not script:
                continue
            where = f"{_relative(WORKFLOW)} step {step.get('name')!r}"
            flags_by_variable = {
                name: re.findall(r"'(--[a-z][a-z0-9-]*)'", str(value))
                for name, value in (step.get("env") or {}).items()
            }
            for invocation in shell_invocations(script, where):
                referenced = {
                    name
                    for word in invocation.words
                    for name in re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)", word)
                }
                spliced = [
                    flag
                    for name in sorted(referenced)
                    for flag in flags_by_variable.get(name, [])
                ]
                found.append(Invocation(where, invocation.words + tuple(spliced)))
    return found


#: source -> (reader, the command paths it must yield). The second half is the
#: positive control: a reader that silently stopped matching would otherwise pass.
SOURCES: dict[str, tuple[Callable[[], list[Invocation]], set[str]]] = {
    "reusable workflow": (workflow_invocations, {"", "dependencies install", "report"}),
    "CDK templates": (cdk_template_invocations, {"scan", "merge", "mcp"}),
    "cdk-constructs buildspecs": (cdk_constructs_invocations, {"scan", "merge"}),
    "Terraform buildspecs": (terraform_buildspec_invocations, {"scan", "merge"}),
    "Terraform gate": (terraform_gate_invocations, {"scan"}),
    "Terraform ash-mcp-serve": (terraform_mcp_serve_invocations, {"mcp"}),
}


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_every_option_a_target_passes_exists_in_the_cli(source):
    reader, expected_paths = SOURCES[source]
    root = _cli()
    invocations = reader()

    reached = {invocation.command_path(root) for invocation in invocations}
    assert expected_paths <= reached, (
        f"the {source} reader found ASH command lines for {sorted(reached)}, but these "
        f"targets run {sorted(expected_paths)}; the reader has stopped seeing some of "
        f"them, so the check below would pass over nothing"
    )

    problems = [
        problem
        for invocation in invocations
        for problem in unknown_to_cli(invocation, root)
    ]
    assert not problems, (
        "These targets pass ASH options or commands that this tree's CLI does not "
        "declare. At a release commit the tree is the release every target defaults "
        "to, so each of these would fail as a usage error in a default deployment "
        "(an ASH that predates exit 5 ignores an unknown `ash scan` option "
        "instead):\n  " + "\n  ".join(problems)
    )


def test_the_reader_knows_every_ash_command():
    assert set(_COMMANDS) == set(_cli().commands), (
        "_COMMANDS must list ASH's top-level commands exactly, or the shell reader "
        "skips lines that invoke the ones it does not know"
    )


def test_the_check_reports_what_the_cli_lacks():
    """Controls for the checker itself, on lines the CLI does and does not accept."""
    root = _cli()
    accepted = [
        Invocation("control", ("scan", "--source-dir", "$X", "--shard-index", "0")),
        Invocation("control", ("--output-dir", "out", "report")),
        Invocation("control", ("mcp", "--stateless-http", "--allowed-host", "h")),
    ]
    for invocation in accepted:
        assert not unknown_to_cli(invocation, root), invocation

    rejected = {
        Invocation("control", ("scan", "--shard-indx", "0")): "--shard-indx",
        Invocation("control", ("merge-results", "--results", "a")): "merge-results",
        Invocation("control", ("mcp", "--fail-on-findings")): "--fail-on-findings",
    }
    for invocation, name in rejected.items():
        problems = unknown_to_cli(invocation, root)
        assert problems and name in problems[0], (invocation, problems)


def test_the_shell_reader_follows_continuations_and_appended_arguments():
    text = (
        "set -- /usr/local/bin/ash-container-init ash merge \\\n"
        "  --output-dir merged\n"
        'set -- "$@" --fail-on-findings\n'
        "# ash scan --not-this-one\n"
        'set --; for d in $X; do set -- "$@" --results "$d"; done; ash merge "$@"\n'
        'echo "ash scan is quoted, so not a command"\n'
    )
    invocations = shell_invocations(text, "control")
    assert [invocation.words for invocation in invocations] == [
        ("merge", "--output-dir", "merged", "--fail-on-findings", "--results", "$d"),
        ("merge", "$@", "--fail-on-findings", "--results", "$d"),
    ]


#: Files whose ASH command lines are read by SOURCES, or that render into files that
#: are. The TypeScript under deploy/cdk/lib and deploy/cdk-constructs/src is not read
#: directly: what ships is its rendered output, which the drift gates hold equal to it.
COVERED = (
    "deploy/cdk/templates/*.template.json",
    "deploy/cdk/lib/*.ts",
    "deploy/cdk-constructs/src/*.ts",
    "deploy/cdk-constructs/src/private/*.ts",
    "deploy/cdk-constructs/buildspec*.yml",
    "deploy/terraform/modules/*/*.tftpl",
    "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py",
    "deploy/terraform/modules/ash-image-pipeline/files/ash-mcp-serve",
)

#: Not deployed: documentation and tests describe or exercise the targets, and
#: jsii's build output (gitignored) is a compiled copy of src/.
_NOT_SHIPPED = (
    "*.md",
    "*/test/*",
    "*/tests/*",
    "*package-lock.json",
    "*.lock.hcl",
    "deploy/cdk-constructs/lib/*",
    "deploy/cdk-constructs/.jsii",
)


def test_no_file_in_deploy_runs_ash_unchecked():
    skip = frozenset({"node_modules", ".terraform", "cdk.out", "dist"})
    unchecked = []
    for path in iter_repo_files(DEPLOY, skip_dirs=skip):
        relative = _relative(path)
        if any(fnmatch.fnmatch(relative, pattern) for pattern in _NOT_SHIPPED):
            continue
        if any(fnmatch.fnmatch(relative, pattern) for pattern in COVERED):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        invocations = shell_invocations(text, relative)
        if path.suffix == ".py":
            invocations += _python_argv_invocations(text, relative)
        if invocations:
            unchecked.append(f"{relative}: {' '.join(invocations[0].words)[:80]}")

    assert not unchecked, (
        "These files run ASH but no reader in this module checks their options "
        "against the CLI. Add a reader to SOURCES and the file to COVERED:\n  "
        + "\n  ".join(unchecked)
    )


# ---------------------------------------------------------------------------
# The default pins
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PinShape:
    glob: str
    pattern: str


#: Every place a deploy target names the ASH release it builds or installs by default.
#: Globs are relative to deploy/, which holds no test scratch to race.
PIN_SHAPES = (
    PinShape("cdk/lib/ash-config.ts", r"DEFAULT_ASH_VERSION = '(?P<ref>[^']*)'"),
    PinShape("cdk/templates/*.template.json", r'"Default": "(?P<ref>v[0-9][^"]*)"'),
    PinShape("cdk/README.md", r"\| `AshVersion` \| `(?P<ref>[^`]*)` \|"),
    PinShape(
        "cdk-constructs/src/private/commands.ts",
        r"DEFAULT_ASH_REF = '(?P<ref>[^']*)'",
    ),
    PinShape("cdk-constructs/buildspec*.yml", r"ASH_VERSION: (?P<ref>\S+)"),
    PinShape(
        "terraform/modules/*/examples/*/main.tf",
        r'^\s*ash_version\s*=\s*"(?P<ref>[^"]*)"',
    ),
)


def _pins() -> list[tuple[str, int, str]]:
    found = []
    for shape in PIN_SHAPES:
        paths = sorted(DEPLOY.glob(shape.glob))
        assert paths, f"no file matches {shape.glob}"
        for path in paths:
            hits = [
                (number, match.group("ref"))
                for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1
                )
                for match in [re.search(shape.pattern, line)]
                if match
            ]
            assert hits, (
                f"{_relative(path)} no longer carries a pin of shape {shape.pattern!r}"
            )
            found += [(_relative(path), number, ref) for number, ref in hits]
    return found


def test_every_default_pin_names_the_packaged_release():
    expected = f"v{_packaged_version()}"
    stale = [
        f"  {path}:{number} defaults to {ref}"
        for path, number, ref in _pins()
        if ref != expected
    ]
    assert not stale, (
        f"These deploy defaults do not name {expected}, the release this tree is:\n"
        + "\n".join(stale)
    )


def test_the_cdk_templates_default_ash_version_to_the_packaged_release():
    """The same property read as CloudFormation reads it, not as a line of text."""
    expected = f"v{_packaged_version()}"
    for path in all_template_paths():
        parameters = load_template(path).get("Parameters", {})
        assert parameters["AshVersion"]["Default"] == expected, path.name


def test_cz_bump_rewrites_every_default_pin(monkeypatch):
    """Every pin line must be one `cz bump` rewrites, or it goes stale at the release.

    Uses commitizen's own file and pattern resolution, which globs relative to the
    working directory, as `cz bump` does from the repository root. The import stays
    inside the test for the logging reason tests/unit/test_agent_plugin_ash_version.py
    gives.
    """
    from commitizen.bump import _resolve_files_and_regexes

    monkeypatch.chdir(REPO_ROOT)

    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        settings = tomllib.load(handle)["tool"]["commitizen"]
    current = settings["version"]

    rewritten = set()
    for path, regex in _resolve_files_and_regexes(settings["version_files"], current):
        relative = Path(path).resolve().relative_to(REPO_ROOT).as_posix()
        for number, line in enumerate(
            Path(path).read_text(encoding="utf-8").splitlines(), 1
        ):
            if regex.search(line) and current in line:
                rewritten.add((relative, number))

    missed = [
        f"  {path}:{number}"
        for path, number, _ in _pins()
        if (path, number) not in rewritten
    ]
    assert not missed, (
        "`cz bump` would leave these deploy defaults on the old release; add them to "
        "[tool.commitizen] version_files with a pattern that matches the line:\n"
        + "\n".join(missed)
    )


def test_terraform_hands_ash_the_min_severity_it_validated():
    """Both Terraform modules validate `lower(var.min_severity)`, so `HIGH` passes.

    The value ASH receives has to be that same lowered spelling. Passing the raw value
    makes what reaches `ash scan` or `ash merge` depend on how each ASH release treats
    case, which a plan-time check that already accepted the value cannot see. Every use
    of `var.min_severity` outside its own validation must therefore be lowered.
    """
    raw = []
    for path in sorted(TERRAFORM_MODULES.glob("*/*.tf")):
        if path.name == "variables.tf":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "var.min_severity" in line and "lower(var.min_severity)" not in line:
                raw.append(f"  {_relative(path)}:{number}: {line.strip()}")

    assert not raw, (
        "These hand ASH min_severity as the operator typed it, though the validation "
        "only checked its lowered form:\n" + "\n".join(raw)
    )
