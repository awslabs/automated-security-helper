#!/usr/bin/env python3
"""Fail when any workflow, composite action or script they run can deploy infrastructure.

WHY THIS EXISTS

The deployment stacks under deploy/ are tested offline only: cdk synth, the
template drift check, cdk-nag, cfn-lint, cfn-guard, terraform validate and the
CloudFormation/Terraform equivalence census. Deploying a stack needs an AWS
account and the operator's authorization, and no CI job on this public
repository has either. The workflows say so in comments. A comment is not a
check, so this script makes the absence of every deploy path a gate: a step that
runs `cdk deploy`, `aws cloudformation create-stack`, `terraform apply` or one of
their relatives turns the run red before it can reach a credential.

WHAT IT LOOKS FOR

Every `*.yml` / `*.yaml` under .github/workflows and .github/actions, and every
repository script those files run, followed transitively. Each file is read as
text, comment lines are dropped, backslash-continued lines are joined, and each
line is split into commands at `&&`, `||`, `;`, `|` and `&`. Redirections
(`2>&1`, `>log`, `&>/dev/null`) are removed from each command, including one glued
to the verb, so `cdk deploy&>log` still ends in `deploy`. Brackets, braces,
backticks and commas become spaces, so `out=$(cdk deploy)` and
`execSync("cdk deploy")` split into the same tokens as `cdk deploy`. Each
whitespace-separated token is normalized to the tool it names before matching:
the part after the last `/` (so `./node_modules/.bin/cdk` is `cdk`), without an
`@version` or `@tag` suffix (so `aws-cdk@2.150.0` and `cdk@latest` are `aws-cdk`
and `cdk`), with the npm package `aws-cdk` read as `cdk` and OpenTofu's `tofu`
read as `terraform`. A command is a deploy when it contains, as whole tokens:

  * `cdk` followed later by `deploy`, `destroy` or `bootstrap`
    (bootstrap creates a stack too);
  * `cloudformation` followed later by a stack- or change-set-mutating
    subcommand (`deploy`, `create-stack`, `update-stack`, `delete-stack`,
    `create-change-set`, `execute-change-set`, and the stack-set forms);
  * `terraform` followed later by `apply`, `destroy` or `import`;
  * `sam` followed later by `deploy` or `delete`;
  * `eks` followed later by a cluster-, node-group- or add-on-mutating
    subcommand, or `update-kubeconfig` (which points kubectl at a real
    cluster), and `eksctl` followed later by `create`, `delete`, `upgrade`
    or `scale`.

It also refuses `uses:` of the CloudFormation deploy action
(aws-actions/aws-cloudformation-github-deploy).

Whole tokens, not substrings, because this repository is full of paths that
contain the words: `deploy/cdk-constructs`, `terraform-hygiene`. A substring
match would fire on all of them and train people to ignore it. The basename rule
does read a directory such as `deploy/cdk` as `cdk`, so a command that names that
directory and later has a bare `deploy` argument is flagged; that errs toward a
red run, and no workflow here has that shape.

FOLLOWING SCRIPTS

A deploy is as easy to hide in `run: bash scripts/release.sh` as in the run
block itself, so the scan follows what a command executes:

  * Any token that names an existing file in the repository with a script
    suffix (.sh, .bash, .zsh, .ps1, .py, .js, .mjs, .cjs), or a path to an
    extensionless file that starts with `#!`, is scanned too. The interpreter
    does not matter, so `bash x.sh`, `./x.sh`, `python3 x.py` and
    `uv run python x.py` are all followed. A path is tried against the
    repository root, the directory of the file that names it, every
    `working-directory:` value and every `cd <dir>` target in that file.
    `${{ github.action_path }}` and `$GITHUB_ACTION_PATH` are read as the
    composite action's own directory, and `$GITHUB_WORKSPACE` as the root.
  * `npm run <name>` (also `npm run-script`, `pnpm run`, `yarn run`, with any
    flags such as `--prefix`) is mapped through the `scripts` table of every
    package.json that defines `<name>`, with its `pre<name>` and `post<name>`
    hooks. `npm test` and `npm start` map to `test` and `start`, and `npm ci` and
    a bare `npm install` to the install lifecycle (`preinstall`, `install`,
    `postinstall`, `prepare`). A script value is a command line, so it is
    scanned and followed the same way, relative to its package.
  * A Python script is parsed rather than read as shell, because its docstrings
    and messages name the forbidden commands in prose (this file does). What
    it runs is an argv list or tuple of plain strings (`["npx", "cdk",
    "deploy"]`; non-string elements are skipped) or the string passed to
    `subprocess.run`/`call`/`check_call`/`check_output`/`Popen`/`getoutput`
    or `os.system`/`os.popen`. Both are scanned as commands and followed. A
    Python file that does not parse is a failure.

Every file is followed once. A hit in a followed file names the file and line
and the chain of references that reached it.

KNOWN LIMITS

A deploy assembled from variables at run time is not seen, and neither is a
script named only through a variable (`npm run "$script"`, `bash "$HELPER"` when
the env value is set elsewhere). An env value written as a literal path in the
same file (`HELPER: ${{ github.action_path }}/x.py`) is followed, because the path
is a token on that line. Python commands built from f-strings or concatenation
are not seen. `kubectl` and `helm` are not refused: the operator e2e applies to
a local kind cluster with them, and which cluster a context names is decided at
run time; `aws eks update-kubeconfig` and `eksctl`, which reach a real cluster,
are refused. The workflows that touch deploy/ call `npx cdk synth`,
`terraform init -backend=false` / `validate` and Python scripts under
deploy/tests, all of which are read-only.

Run with --self-test to feed it planted deploy commands and planted look-alikes,
and planted repositories whose deploy sits in a script a workflow calls.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = (".github/workflows", ".github/actions")

# (tool token, verbs that make it a deploy)
DEPLOY_VERBS: dict[str, frozenset[str]] = {
    "cdk": frozenset({"deploy", "destroy", "bootstrap"}),
    "cloudformation": frozenset(
        {
            "deploy",
            "create-stack",
            "update-stack",
            "delete-stack",
            "create-change-set",
            "execute-change-set",
            "create-stack-set",
            "update-stack-set",
            "delete-stack-set",
            "create-stack-instances",
            "update-stack-instances",
            "delete-stack-instances",
        }
    ),
    "terraform": frozenset({"apply", "destroy", "import"}),
    "sam": frozenset({"deploy", "delete"}),
    "eks": frozenset(
        {
            "create-cluster",
            "delete-cluster",
            "update-cluster-config",
            "update-cluster-version",
            "create-nodegroup",
            "delete-nodegroup",
            "update-nodegroup-config",
            "update-nodegroup-version",
            "create-fargate-profile",
            "delete-fargate-profile",
            "create-addon",
            "delete-addon",
            "update-addon",
            "associate-access-policy",
            "create-access-entry",
            "update-kubeconfig",
        }
    ),
    "eksctl": frozenset({"create", "delete", "upgrade", "scale"}),
}

DEPLOY_ACTIONS = ("aws-actions/aws-cloudformation-github-deploy",)

# `&&` and `||` before their single-character forms; a lone `&` backgrounds a job,
# which still runs it, so it ends a command the same way `;` does. An `&` inside a
# redirection (`2>&1`, `>&2`, `&>file`) is not a separator, so the command goes on.
SEPARATORS = re.compile(r"&&|\|\||;|\||(?<![<>])&(?!>)")

# A redirection with its target, removed from each command before it is split into
# tokens. Without this, a redirection glued to the verb (`cdk deploy&>log`,
# `cdk deploy>&2`, `terraform apply>out`) makes the verb token `deploy&>log`, which
# matches no verb. Covers `>`, `>>`, `<`, `<<`, `>&`, `<&`, `&>`, `&>>`, each with an
# optional file-descriptor number and the target that follows without a space.
REDIRECTION = re.compile(r"\d*(?:&>>?|[<>]{1,2}&?)\S*")

# Other names the same tool runs under, after normalize_tool().
TOOL_ALIASES = {
    "aws-cdk": "cdk",  # the npm package: `npx aws-cdk deploy`
    "tofu": "terraform",  # OpenTofu takes terraform's subcommands
}
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s@]+)")

# The reason recorded for a followed Python file that does not parse.
PARSE_FAILURE = "does not parse"

# Grouping characters that glue a command to its surroundings: `$(cdk deploy)`,
# `` `cdk deploy` ``, `execSync("cdk deploy")`, `["cdk", "deploy"]`. They become
# spaces before a command is split into tokens.
GROUPING = re.compile(r"[`(){}\[\],]")

# A GitHub expression is one value at run time, so it stays one token.
EXPRESSION = re.compile(r"\$\{\{.*?\}\}")

# Files a token may name and the scan will follow.
SCRIPT_SUFFIXES = frozenset(
    {".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs"}
)
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})

# Directory names never followed into: dependencies and VCS metadata.
SKIP_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "__pycache__"})

# Path variables a workflow or action uses for a script next to it.
ACTION_PATH = re.compile(
    r"\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?"
)
WORKSPACE = re.compile(r"\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?")

WORKING_DIRECTORY = re.compile(r"^\s*-?\s*working-directory:\s*['\"]?([^'\"\s#]+)")
# A YAML list item that is one bare scalar, as in a `paths:` filter. It names a file
# without running it, so it is not followed.
YAML_SCALAR_ITEM = re.compile(r"^\s*-\s*['\"]?[^\s'\":]+['\"]?\s*$")
CD = re.compile(r"(?:^|[\s;&|(])(?:cd|pushd)\s+['\"]?([^'\"\s;&|)]+)")

# npm-family subcommands that run package.json scripts, and the scripts they run.
NPM_TOOLS = frozenset({"npm", "pnpm", "yarn"})
NPM_LIFECYCLE = {
    "ci": ("preinstall", "install", "postinstall", "prepare"),
    "install": ("preinstall", "install", "postinstall", "prepare"),
    "i": ("preinstall", "install", "postinstall", "prepare"),
    "test": ("pretest", "test", "posttest"),
    "t": ("pretest", "test", "posttest"),
    "start": ("prestart", "start", "poststart"),
}
# npm flags that take a separate value, so the value is not read as the subcommand.
NPM_VALUE_FLAGS = frozenset({"--prefix", "-C", "--workspace", "-w", "--cwd"})

# Python calls whose first argument is a command line.
PY_SHELL_CALLS = frozenset(
    {
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "getoutput",
        "getstatusoutput",
    }
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    text: str
    reason: str
    # The chain of `file:line` references that reached a followed file; empty for
    # a workflow or action file, which is scanned on its own.
    via: tuple[str, ...] = field(default=())


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Comment-free lines with backslash continuations joined, keyed by first line number."""
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        if not pending:
            start = number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        pending.append(stripped)
        out.append((start, " ".join(pending)))
        pending = []
    if pending:
        out.append((start, " ".join(pending)))
    return out


def normalize_tool(token: str) -> str:
    """The tool a token names: `./node_modules/.bin/cdk`, `aws-cdk@2.150.0` and `cdk@latest` are all `cdk`."""
    # An npm scope (`@aws-cdk/...`) sits before the last `/`, so any `@` left after
    # the basename starts a version or dist-tag.
    name = token.rsplit("/", 1)[-1].split("@", 1)[0]
    return TOOL_ALIASES.get(name, name)


def command_tokens(command: str) -> list[str]:
    """`command` split into words, without redirections, grouping characters or quotes."""
    bare = GROUPING.sub(" ", REDIRECTION.sub(" ", EXPRESSION.sub("$EXPR", command)))
    return [t for t in (t.strip("'\"") for t in bare.split()) if t]


def deploy_reason(command: str) -> str | None:
    """Why `command` is a deploy, or None."""
    tokens = command_tokens(command)
    for index, token in enumerate(tokens):
        verbs = DEPLOY_VERBS.get(normalize_tool(token))
        if verbs is None:
            continue
        for later in tokens[index + 1 :]:
            if later in verbs:
                return f"`{token} ... {later}`"
    return None


def scan_text(path: str, text: str) -> list[Hit]:
    hits: list[Hit] = []
    for number, line in logical_lines(text):
        match = USES.match(line)
        if match and match.group(1).lower() in DEPLOY_ACTIONS:
            hits.append(Hit(path, number, line.strip(), f"uses {match.group(1)}"))
            continue
        for command in SEPARATORS.split(line):
            reason = deploy_reason(command)
            if reason:
                hits.append(Hit(path, number, line.strip(), reason))
                break
    return hits


# ---------------------------------------------------------------------------
# Following what a command runs.


@dataclass(frozen=True)
class Command:
    line: int
    text: str


def shell_commands(text: str, js: bool = False) -> list[Command]:
    """Every command in shell-like `text`. For JavaScript, `//` comment lines are dropped too."""
    if js:
        text = "\n".join(
            "" if raw.lstrip().startswith(("//", "/*", "*")) else raw
            for raw in text.splitlines()
        )
    return [
        Command(number, command)
        for number, line in logical_lines(text)
        for command in SEPARATORS.split(line)
        if command.strip()
    ]


def python_commands(text: str) -> list[Command]:
    """What a Python script runs: argv lists of plain strings, and command-line strings passed to a runner.

    Raises SyntaxError when the file does not parse.
    """
    commands: list[Command] = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.List, ast.Tuple)):
            words = [
                e.value
                for e in node.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
            # An argv is words, none with whitespace; a tuple of prose strings is data.
            if len(words) >= 2 and not any(re.search(r"\s", w) for w in words):
                commands.append(Command(node.lineno, " ".join(words)))
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            first = node.args[0]
            if (
                name in PY_SHELL_CALLS
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                commands.extend(
                    Command(node.lineno, part)
                    for part in SEPARATORS.split(first.value)
                    if part.strip()
                )
    return commands


def walk_files(root: Path, name: str) -> list[Path]:
    """Every file called `name` under `root`, outside dependency and VCS directories."""
    found: list[Path] = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
        if name in files:
            found.append(Path(directory) / name)
    return sorted(found)


class Follower:
    """Scans workflow and action files, then every repository script they run."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.hits: list[Hit] = []
        self.followed: list[str] = []
        self.unresolved_npm: list[str] = []
        self._seen: set[str] = set()
        self._packages: dict[Path, dict[str, str]] | None = None

    # -- package.json scripts ------------------------------------------------

    def packages(self) -> dict[Path, dict[str, str]]:
        if self._packages is None:
            self._packages = {}
            for path in walk_files(self.root, "package.json"):
                try:
                    scripts = json.loads(path.read_text(encoding="utf-8")).get(
                        "scripts"
                    )
                except (OSError, ValueError, AttributeError):
                    continue
                if isinstance(scripts, dict):
                    self._packages[path.parent] = {
                        k: v for k, v in scripts.items() if isinstance(v, str)
                    }
        return self._packages

    def npm_scripts(self, tokens: list[str]) -> list[str] | None:
        """The package.json script names an npm-family command runs, or None if it is not one."""
        for index, token in enumerate(tokens):
            if normalize_tool(token) not in NPM_TOOLS:
                continue
            rest = tokens[index + 1 :]
            position = 0
            while position < len(rest) and rest[position].startswith("-"):
                position += 2 if rest[position] in NPM_VALUE_FLAGS else 1
            if position >= len(rest):
                return []
            sub = rest[position]
            if sub in ("run", "run-script", "run-scripts"):
                names = [t for t in rest[position + 1 :] if not t.startswith("-")]
                if not names:
                    return []
                name = names[0]
                if "$" in name:
                    return [name]
                return [f"pre{name}", name, f"post{name}"]
            if sub in ("install", "i"):
                # `npm install <package>` adds a dependency; only a bare install
                # runs this package's install lifecycle.
                extra = [t for t in rest[position + 1 :] if not t.startswith("-")]
                return list(NPM_LIFECYCLE[sub]) if not extra else []
            if sub in NPM_LIFECYCLE:
                return list(NPM_LIFECYCLE[sub])
            # yarn and pnpm run a script named as the subcommand (`yarn deploy`).
            if normalize_tool(token) in ("yarn", "pnpm"):
                return [sub]
            return []
        return None

    # -- path resolution -----------------------------------------------------

    def bases(self, text: str, own_dir: Path) -> list[Path]:
        bases = [self.root, own_dir]
        for raw in text.splitlines():
            match = WORKING_DIRECTORY.match(raw)
            if match:
                bases.append(self.root / match.group(1))
            for target in CD.findall(raw):
                bases.append(self.root / target)
                bases.append(own_dir / target)
        unique: list[Path] = []
        for base in bases:
            if base not in unique:
                unique.append(base)
        return unique

    def resolve(self, word: str, bases: list[Path]) -> list[Path]:
        if not word or "$" in word or "*" in word or "://" in word:
            return []
        candidate = Path(word)
        if candidate.is_absolute():
            return []
        # Only a script suffix, or a path that may be an extensionless script, can
        # name something to follow; most words are neither, and resolving every
        # one against every base is most of the run time.
        if candidate.suffix not in SCRIPT_SUFFIXES and (
            candidate.suffix or "/" not in word
        ):
            return []
        found: list[Path] = []
        for base in bases:
            path = (base / candidate).resolve()
            try:
                relative = path.relative_to(self.root)
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in relative.parts):
                continue
            if not path.is_file() or path in found:
                continue
            if path.suffix in SCRIPT_SUFFIXES or (
                not path.suffix and "/" in word and self._has_shebang(path)
            ):
                found.append(path)
        return found

    @staticmethod
    def _has_shebang(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                return handle.read(2) == b"#!"
        except OSError:
            return False

    def referenced_scripts(self, tokens: list[str], bases: list[Path]) -> list[Path]:
        found: list[Path] = []
        for token in tokens:
            # `HELPER=x.py`, `-v x.sh:/tmp/x.sh:ro`: each piece may be a path.
            for word in {token, *re.split(r"[=:]", token)}:
                for path in self.resolve(word, bases):
                    if path not in found:
                        found.append(path)
        return found

    # -- scanning ------------------------------------------------------------

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def scan_workflow(self, path: Path) -> None:
        relative = self.rel(path)
        text = path.read_text(encoding="utf-8")
        self.hits.extend(scan_text(relative, text))
        action_dir = self.rel(path.parent) or "."
        text = WORKSPACE.sub(".", ACTION_PATH.sub(action_dir, text))
        runnable = "\n".join(
            "" if YAML_SCALAR_ITEM.match(raw) else raw for raw in text.splitlines()
        )
        self.follow_commands(
            relative, shell_commands(runnable), self.bases(text, path.parent), (), None
        )

    def follow_commands(
        self,
        relative: str,
        commands: list[Command],
        bases: list[Path],
        via: tuple[str, ...],
        package: Path | None,
    ) -> None:
        for command in commands:
            tokens = command_tokens(command.text)
            here = (*via, f"{relative}:{command.line}")
            for script in self.referenced_scripts(tokens, bases):
                self.follow_file(script, here)
            names = self.npm_scripts(tokens)
            if names is None:
                continue
            for name in names:
                self.follow_npm(name, here, package)

    def follow_npm(self, name: str, via: tuple[str, ...], package: Path | None) -> None:
        packages = self.packages()
        if "$" in name:
            self.unresolved_npm.append(via[-1])
            return
        if package is not None and name in packages.get(package, {}):
            targets = [package]
        else:
            targets = [p for p, scripts in packages.items() if name in scripts]
        for directory in targets:
            key = f"npm:{directory}:{name}"
            if key in self._seen:
                continue
            self._seen.add(key)
            manifest = f"{self.rel(directory / 'package.json')}#scripts.{name}"
            self.followed.append(manifest)
            value = packages[directory][name]
            for hit in scan_text(manifest, value):
                self.hits.append(Hit(manifest, 1, value, hit.reason, via))
            self.follow_commands(
                manifest,
                shell_commands(value),
                self.bases(value, directory)[1:] + [self.root],
                via,
                directory,
            )

    def follow_file(self, path: Path, via: tuple[str, ...]) -> None:
        relative = self.rel(path)
        if relative in self._seen:
            return
        self._seen.add(relative)
        self.followed.append(relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            try:
                commands = python_commands(text)
            except SyntaxError as error:
                self.hits.append(
                    Hit(relative, error.lineno or 1, str(error.msg), PARSE_FAILURE, via)
                )
                return
        else:
            commands = shell_commands(text, js=path.suffix in JS_SUFFIXES)
        for command in commands:
            reason = deploy_reason(command.text)
            if reason:
                self.hits.append(
                    Hit(relative, command.line, command.text.strip(), reason, via)
                )
        self.follow_commands(
            relative, commands, self.bases(text, path.parent), via, None
        )


def scan_repo_detailed(root: Path) -> tuple[Follower, int]:
    """Scan every workflow and action file under `root`, and every script they run."""
    follower = Follower(root)
    scanned = 0
    for directory in SCAN_DIRS:
        base = follower.root / directory
        if not base.is_dir():
            continue
        for path in sorted(
            p for p in base.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file()
        ):
            scanned += 1
            follower.scan_workflow(path)
    return follower, scanned


def scan_repo(root: Path) -> tuple[list[Hit], int]:
    follower, scanned = scan_repo_detailed(root)
    return follower.hits, scanned


# Each planted case must be caught; each look-alike must not be.
PLANTED_DEPLOYS = (
    "run: npx cdk deploy --all --require-approval never",
    "run: cd deploy/cdk && npx cdk deploy AshEksOperator",
    "run: npm run cdk -- destroy --force",
    "run: npx cdk bootstrap --toolkit-stack-name CDKToolkit",
    "run: aws cloudformation deploy --template-file t.json --stack-name s",
    "run: aws cloudformation create-stack --stack-name s --template-body file://t.json",
    "run: aws cloudformation update-stack --stack-name s",
    "run: aws cloudformation execute-change-set --change-set-name c",
    "run: terraform -chdir=deploy/terraform/examples/agentcore apply -auto-approve",
    "run: terraform destroy -auto-approve",
    "run: sam deploy --guided",
    "run: |\n  aws cloudformation \\\n    create-stack --stack-name s",
    # The tool spelled as a package name, a pinned package, or a path.
    "run: npx aws-cdk deploy --all",
    "run: npx aws-cdk@2.150.0 deploy",
    "run: npx cdk@latest deploy",
    "run: ./node_modules/.bin/cdk deploy",
    "run: npx --yes aws-cdk@latest destroy --force",
    "run: /usr/local/bin/terraform apply -auto-approve",
    # A background job is its own command, as `;` is.
    "run: cdk deploy&",
    "run: cdk deploy & wait",
    # A redirection's `&` is not a separator; the command keeps going.
    "run: cdk 2>&1 deploy",
    "run: terraform 2>&1 apply -auto-approve",
    "run: cdk >&2 deploy",
    # A redirection glued to the verb is not part of the verb.
    "run: cdk deploy&>log",
    "run: cdk deploy&>>log",
    "run: terraform apply&>/dev/null",
    "run: cdk deploy>log",
    "run: cdk deploy>&2",
    "run: cdk deploy<&3",
    # OpenTofu is a drop-in for terraform.
    "run: tofu apply",
    "run: tofu -chdir=deploy/terraform destroy -auto-approve",
    "- uses: aws-actions/aws-cloudformation-github-deploy@0123456789abcdef0123456789abcdef01234567",
    # A command inside a substitution, backticks or a call is still a command.
    "run: out=$(npx cdk deploy --all)",
    "run: echo `cdk deploy`",
    "run: node -e 'execSync(\"npx cdk deploy\")'",
    # EKS: a cluster change, or pointing kubectl at a real cluster.
    "run: aws eks update-kubeconfig --name c --region us-east-1",
    "run: aws eks create-cluster --name c",
    "run: eksctl create cluster -f cluster.yaml",
    "run: eksctl delete cluster --name c",
)

LOOK_ALIKES = (
    "run: npx cdk synth --all --no-lookups --quiet",
    "run: npm ci --prefix deploy/cdk",
    "working-directory: deploy/cdk",
    "run: cdk ls && ls deploy/cdk-constructs",
    "# this job never runs cdk deploy",
    "    # aws cloudformation create-stack is forbidden here",
    "run: terraform init -backend=false && terraform validate",
    "run: terraform plan -destroy -out=plan.bin",
    "run: aws cloudformation validate-template --template-body file://t.json",
    "name: terraform-hygiene apply checks",
    "run: python3 deploy/tests/cfn-lint-guard.py check",
    "run: npx aws-cdk@2.150.0 synth --quiet",
    "run: ./node_modules/.bin/cdk synth",
    "run: tofu init -backend=false && tofu validate",
    "run: ls deploy/cdk/ & echo deploy",
    "run: npm install aws-cdk-lib@2.150.0",
    "run: echo foo@deploy",
    "run: aws eks describe-cluster --name c",
    "run: eksctl get clusters",
    "run: kubectl --context kind-ash apply -f crd.yaml && helm upgrade --install ash chart/",
    "run: echo ${{ inputs.deploy }}",
)


# Planted repositories: files by path, and the hits the scan must report, as
# (path, reason) pairs. Each is the deploy hidden one step or more away from the
# workflow, where reading the workflow text alone would pass it.
WORKFLOW_HEAD = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
PLANTED_REPOS: tuple[tuple[str, dict[str, str], tuple[tuple[str, str], ...]], ...] = (
    (
        "a workflow runs a shell script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: bash scripts/release.sh\n",
            "scripts/release.sh": "#!/usr/bin/env bash\nset -e\nnpx cdk deploy --all --require-approval never\n",
        },
        (("scripts/release.sh", "`cdk ... deploy`"),),
    ),
    (
        "npm run deploy maps to a package.json script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - working-directory: deploy/app\n        run: npm ci && npm run deploy\n",
            "deploy/app/package.json": json.dumps(
                {"scripts": {"deploy": "cdk deploy"}}
            ),
        },
        (("deploy/app/package.json#scripts.deploy", "`cdk ... deploy`"),),
    ),
    (
        "a script runs a second script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: ./scripts/a.sh\n",
            "scripts/a.sh": "#!/bin/sh\necho start\nsh ./b.sh\n",
            "scripts/b.sh": "#!/bin/sh\nterraform -chdir=deploy/terraform apply -auto-approve\n",
        },
        (("scripts/b.sh", "`terraform ... apply`"),),
    ),
    (
        "a Python script runs an argv that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: uv run --extra cdk python scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nsubprocess.run(\n    ["npx", "aws-cdk@2.150.0", "deploy", "--all"], check=True\n)\n',
        },
        (("scripts/ship.py", "`aws-cdk@2.150.0 ... deploy`"),),
    ),
    (
        "a Python script runs a command line that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import os\n\nos.system("aws cloudformation deploy --template-file t.json --stack-name s")\n',
        },
        (("scripts/ship.py", "`cloudformation ... deploy`"),),
    ),
    (
        "an npm script runs a package-relative shell script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npm --prefix deploy/app run synth\n",
            "deploy/app/package.json": json.dumps(
                {"scripts": {"synth": "./scripts/synth.sh"}}
            ),
            "deploy/app/scripts/synth.sh": "#!/bin/sh\nout=$(npx cdk deploy --all)\n",
        },
        (("deploy/app/scripts/synth.sh", "`cdk ... deploy`"),),
    ),
    (
        "npm ci runs a prepare script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: cd deploy/app && npm ci\n",
            "deploy/app/package.json": json.dumps(
                {"scripts": {"prepare": "sam deploy --guided"}}
            ),
        },
        (("deploy/app/package.json#scripts.prepare", "`sam ... deploy`"),),
    ),
    (
        "a composite action runs a script next to it that deploys",
        {
            ".github/actions/x/action.yml": "runs:\n  using: composite\n  steps:\n"
            '    - shell: bash\n      run: bash "${{ github.action_path }}/run.sh"\n',
            ".github/actions/x/run.sh": "#!/bin/bash\naws eks update-kubeconfig --name prod\n",
        },
        (("/run.sh", "`eks ... update-kubeconfig`"),),
    ),
    (
        "a Node script runs a command line that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node .github/scripts/go.mjs\n",
            ".github/scripts/go.mjs": "import { execSync } from 'node:child_process';\nexecSync('npx cdk destroy --force');\n",
        },
        (("/go.mjs", "`cdk ... destroy`"),),
    ),
    (
        "a followed Python file that does not parse",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/broken.py\n",
            "scripts/broken.py": "def f(:\n",
        },
        (("scripts/broken.py", PARSE_FAILURE),),
    ),
)

# Planted repositories that must scan clean, and a file each must have followed, to
# prove the clean result came from reading it.
LOOK_ALIKE_REPOS: tuple[tuple[str, dict[str, str], str], ...] = (
    (
        "a followed script that only synthesizes",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: bash scripts/synth.sh\n",
            "scripts/synth.sh": "#!/bin/sh\n# never cdk deploy here\nnpx cdk synth --quiet\necho 'no deploy'\n",
        },
        "scripts/synth.sh",
    ),
    (
        "a Python script that names deploy commands only in prose and data",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/guard.py\n",
            "scripts/guard.py": '"""Refuses `cdk deploy` and `terraform apply`."""\n'
            'PLANTS = ("run: cdk deploy --all", "run: terraform apply")\n'
            'VERBS = frozenset({"deploy", "destroy"})\n'
            'print("never run cdk deploy here")\n'
            'ARGV = ["npx", "cdk", "synth"]\n',
        },
        "scripts/guard.py",
    ),
    (
        "an npm script that builds, next to an unused deploy script",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npm --prefix deploy/app run build\n",
            "deploy/app/package.json": json.dumps(
                {"scripts": {"build": "tsc", "deploy": "cdk deploy"}}
            ),
        },
        "deploy/app/package.json#scripts.build",
    ),
    (
        "a paths filter that names a deploying script without running it",
        {
            ".github/workflows/w.yml": "on:\n  push:\n    paths:\n      - scripts/release.sh\n"
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash scripts/ok.sh\n",
            "scripts/release.sh": "#!/bin/sh\ncdk deploy\n",
            "scripts/ok.sh": "#!/bin/sh\necho ok\n",
        },
        "scripts/ok.sh",
    ),
)


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def self_test() -> int:
    failures = []
    for planted in PLANTED_DEPLOYS:
        if not scan_text("planted.yml", planted):
            failures.append(f"not caught: {planted!r}")
    for look_alike in LOOK_ALIKES:
        hits = scan_text("look-alike.yml", look_alike)
        if hits:
            failures.append(f"false positive: {look_alike!r} -> {hits[0].reason}")
    for name, files, expected in PLANTED_REPOS:
        with tempfile.TemporaryDirectory() as scratch:
            write_tree(Path(scratch), files)
            follower, _ = scan_repo_detailed(Path(scratch))
        got = {(hit.path, hit.reason) for hit in follower.hits}
        for path, reason in expected:
            if not any(p.endswith(path) and r == reason for p, r in got):
                failures.append(
                    f"not caught: {name}: expected {reason} in {path}, got {sorted(got)}"
                )
        if len(follower.hits) != len(expected):
            failures.append(
                f"{name}: expected {len(expected)} hit(s), got {sorted(got)}"
            )
    for name, files, must_follow in LOOK_ALIKE_REPOS:
        with tempfile.TemporaryDirectory() as scratch:
            write_tree(Path(scratch), files)
            follower, _ = scan_repo_detailed(Path(scratch))
        if follower.hits:
            hit = follower.hits[0]
            failures.append(
                f"false positive: {name}: {hit.path}:{hit.line} {hit.reason}"
            )
        if must_follow not in follower.followed:
            failures.append(
                f"{name}: {must_follow} was never followed, so the clean result proves nothing"
            )
    for failure in failures:
        print(f"SELF-TEST FAIL: {failure}")
    if failures:
        return 1
    print(
        f"self-test passed: {len(PLANTED_DEPLOYS)} planted deploys caught, {len(LOOK_ALIKES)} look-alikes passed, "
        f"{len(PLANTED_REPOS)} planted script deploys caught, {len(LOOK_ALIKE_REPOS)} look-alike repositories passed"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test", action="store_true", help="run against planted inputs and exit"
    )
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="repository root to scan"
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    follower, scanned = scan_repo_detailed(args.root)
    hits = follower.hits
    if scanned == 0:
        print(
            f"::error::no workflow or action files found under {', '.join(SCAN_DIRS)} in {args.root}; nothing was checked"
        )
        return 1
    for hit in hits:
        chain = f" (reached from {' -> '.join(hit.via)})" if hit.via else ""
        # A package.json script is reported as `package.json#scripts.<name>`; the
        # annotation needs the file alone, and the message keeps the name.
        file = hit.path.split("#", 1)[0]
        where = f"{hit.path}: " if file != hit.path else ""
        if hit.reason == PARSE_FAILURE:
            print(
                f"::error file={file},line={hit.line}::{hit.path}: a script CI runs does not parse ({hit.text}), so what it runs was not checked{chain}"
            )
        else:
            print(
                f"::error file={file},line={hit.line}::{where}{hit.reason} deploys infrastructure; CI here must stay offline: {hit.text}{chain}"
            )
    for where in follower.unresolved_npm:
        print(
            f"note: {where} runs an npm script named by a variable, which was not followed"
        )
    if hits:
        print(
            f"{len(hits)} deploy command(s) found in {scanned} workflow/action file(s) and {len(follower.followed)} script(s) they run"
        )
        return 1
    print(
        f"no deploy command in {scanned} workflow/action file(s) or the {len(follower.followed)} script(s) they run"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
