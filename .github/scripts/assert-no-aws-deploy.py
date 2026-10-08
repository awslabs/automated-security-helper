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
    suffix (.sh, .bash, .zsh, .ps1, .py, .js, .mjs, .cjs, .ts, .mts, .cts), or a
    path to an extensionless file that starts with `#!`, is scanned too, and so
    is the module `python -m pkg.mod` names (pkg/mod.py or pkg/mod/__main__.py).
    The interpreter does not matter, so `bash x.sh`, `./x.sh`, `python3 x.py`,
    `npx tsx x.ts` and `uv run python x.py` are all followed. A path is tried
    against the repository root, the directory of the file that names it, every
    `working-directory:` value and every `cd <dir>` target in that file.
    `${{ github.action_path }}` and `$GITHUB_ACTION_PATH` are read as the
    composite action's own directory, and `$GITHUB_WORKSPACE` as the root.
  * `npm run <name>` (also its aliases `run-script`, `rum`, `urn`, and `pnpm
    run`, `yarn run`, `yarn <name>`, `pnpm <name>`, `yarn workspace <ws>
    <name>`, `yarn workspaces run|foreach`, `pnpm recursive`) is mapped through
    the `scripts` table of every package.json that defines `<name>`, with its
    `pre<name>` and `post<name>` hooks. Flags are taken out first, each with the
    value it takes: npm's from @npmcli/config's option definitions (`-w app`,
    `--workspace app`, `--prefix x`, `-C x`, `--loglevel warn`, ...), pnpm's and
    yarn's from their `--help`. A flag whose arity is not known (a pnpm or yarn
    flag not in those lists, an npm abbreviation such as `--pref`) is read both
    with and without a value, and both readings are followed. `--` ends the
    flags. The lifecycle commands map to the scripts npm's scripts.md lists for
    them: `npm ci` and a bare `npm install` (and their aliases) to `preinstall`,
    `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`,
    `postprepare`; `npm test`, `start`, `stop`, `restart`, `install-test`,
    `install-ci-test`, `rebuild`, `pack`, `publish`, `version` and `diff` to
    theirs; a bare `yarn` installs. A script value is a command line, so it is
    scanned and followed the same way, relative to its package.
  * A JavaScript or TypeScript file is read as shell text with its comment lines
    dropped and each multi-line array literal joined onto one line, so a
    `spawn("npx", [...])` argv written one word per line is one command.
  * A Python script is parsed rather than read as shell, because its docstrings
    and messages name the forbidden commands in prose (this file does). What it
    runs is the argv list or tuple, or the string, given to a runner:
    `subprocess.run`/`call`/`check_call`/`check_output`/`Popen`/`getoutput`,
    `os.system`/`os.popen`, the `os.exec*`/`os.spawn*` families,
    `posix_spawn`, `pty.spawn` and asyncio's `create_subprocess_exec`/`_shell`.
    An argv may be a literal or a name bound to one (`cmd = [...]`), of any
    length, so `subprocess.run(["scripts/d.sh"])` and `subprocess.run(
    [sys.executable, "scripts/d.py"])` follow the script. Its string words
    without whitespace are joined into one command; each element with whitespace
    is one argument, and is also read as a command line of its own, because the
    program may run it (`["bash", "-c", "npx cdk deploy"]`). A list or tuple
    that is not given to a runner may be data, so it counts as an argv only when
    it has two or more string words and the first has no whitespace, and an
    element with whitespace in it counts as a command line only after a command
    flag (`-c`, `-lc`, `-e`, `--eval`, `-Command`, `/c`). A Python file that does
    not parse is a failure.

Every file is followed once. A hit in a followed file names the file and line
and the chain of references that reached it.

KNOWN LIMITS

A deploy assembled from variables at run time is not seen, and neither is a
script named only through a variable (`npm run "$script"`, `bash "$HELPER"` when
the env value is set elsewhere). An env value written as a literal path in the
same file (`HELPER: ${{ github.action_path }}/x.py`) is followed, because the path
is a token on that line. Python commands built from f-strings or concatenation
are not seen, and neither is an argv bound to a name that is reassigned or
built up after it is bound. An abbreviated npm subcommand (`npm ru`, which npm
expands) is not followed. `make <target>` is not followed into the Makefile, and
nothing in this repository's CI runs make. A script given by an absolute path,
such as one a `docker run` names inside the container (`/w/x.sh`), is not
mapped back to the repository file it was mounted from. A JavaScript argv
assembled across lines other than as one array literal (an argument per line
of the call itself) is read line by line. `kubectl` and `helm` are not refused:
the operator e2e applies to a local kind cluster with them, and which cluster a
context names is decided at run time; `aws eks update-kubeconfig` and `eksctl`,
which reach a real cluster, are refused. The workflows that touch deploy/ call
`npx cdk synth`, `terraform init -backend=false` / `validate` and Python scripts
under deploy/tests, all of which are read-only.

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
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"})
SCRIPT_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ps1", ".py", *JS_SUFFIXES})
# A JavaScript array literal left open for more lines than this is not joined: an
# unbalanced bracket in a regular expression or a string the scan misreads would
# otherwise glue the rest of the file into one command.
MAX_JOINED_LINES = 50
# `python -m pkg.mod`: the module a `-m` names.
PY_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")

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

# npm-family tools, how each reads its flags, and the package.json scripts each
# subcommand runs.
NPM_TOOLS = frozenset({"npm", "pnpm", "yarn"})


@dataclass(frozen=True)
class FlagSyntax:
    """Which flags of one npm-family CLI take the next word as their value.

    Reading a value as the subcommand or script name (`npm run -w app deploy` read
    as script `app`) would follow the wrong script and miss the one that runs, so a
    flag whose arity is not known is read both ways and both readings are followed.
    """

    long_values: frozenset[str]
    short_values: frozenset[str]
    # npm's option parser (nopt) reads an unknown flag as a boolean, so for npm a
    # flag outside `long_values` takes no value unless it abbreviates one that does.
    unknown_is_boolean: bool = False
    # Single-dash shorthands longer than one letter that expand to a value flag.
    long_shorthand_values: frozenset[str] = frozenset()
    # Single-dash shorthands known to take no value.
    short_booleans: frozenset[str] = frozenset()

    def takes_value(self, flag: str, following: str) -> bool | None:
        """Whether `flag` consumes `following`; None when it may or may not."""
        if "=" in flag:
            return False
        if following.startswith("-") and len(following) > 1:
            # A string option given no value leaves the next flag alone, but a path
            # or number option takes it; either can happen.
            return None if self._may_take(flag) else False
        return self._takes(flag, following)

    def _may_take(self, flag: str) -> bool:
        return self._takes(flag, "x") is not False

    def _takes(self, flag: str, following: str) -> bool | None:
        if flag.startswith("--"):
            name = flag[2:]
            if name in self.long_values:
                return True
            if not self.unknown_is_boolean:
                return None
            if name.startswith("no-"):
                return False  # `--no-x` is always the boolean false
            if any(value.startswith(name) for value in self.long_values):
                return None  # an abbreviation nopt may expand to a value flag
            # A boolean also takes a following `true`/`false` (`--color always`).
            return None if following in ("true", "false", "null", "always") else False
        body = flag[1:]
        if body in self.long_shorthand_values:
            return True
        if body in self.short_booleans:
            return False
        letters = self.short_values | self.short_booleans
        if body and all(letter in letters for letter in body):
            # `-C dir`, and combined letters (`-gC dir`): the last one decides.
            return body[-1] in self.short_values
        if not self.unknown_is_boolean:
            return True if body[-1:] in self.short_values else None
        if any(value.startswith(body) for value in self.long_values):
            return None
        return None if following in ("true", "false", "null") else False


# npm 10: every option in @npmcli/config's definitions whose type does not include
# Boolean, the one-letter shorthands that expand to one (-C --prefix, -w
# --workspace, -L --location, -m --message, -c --call), and --browser, whose type is
# Boolean or String and so takes a word that is not a flag.
NPM_SYNTAX = FlagSyntax(
    long_values=frozenset(
        """
        _auth access also audit-level auth-type before browser ca cache cache-max
        cache-min cafile call cert cidr cpu depth diff
        diff-dst-prefix diff-src-prefix diff-unified editor expect-result-count
        fetch-retries fetch-retry-factor fetch-retry-maxtimeout fetch-retry-mintimeout
        fetch-timeout git globalconfig heading https-proxy include init-author-email
        init-author-name init-author-url init-license init-module init-version
        init.author.email init.author.name init.author.url init.license init.module
        init.version install-strategy key libc local-address location lockfile-version
        loglevel logs-dir logs-max maxsockets message node-options noproxy omit only os
        otp pack-destination package prefix preid provenance-file proxy registry
        replace-registry-host save-prefix sbom-format sbom-type scope script-shell
        searchexclude searchlimit searchopts searchstaleness shell tag
        tag-version-prefix umask user-agent userconfig viewer which workspace
        """.split()
    ),
    short_values=frozenset({"C", "w", "L", "m", "c"}),
    unknown_is_boolean=True,
    long_shorthand_values=frozenset({"reg", "enjoy-by"}),
    # The other shorthands in @npmcli/config's definitions.
    short_booleans=frozenset(
        """
        d dd ddd quiet q s silent verbose desc help local n no porcelain readonly iwr a
        f g l p S B D E O P ? H h v ws y
        """.split()
    ),
)
# pnpm (`pnpm help`, `pnpm help run`, `pnpm help install`). Its `-w` is
# --workspace-root, a boolean, unlike npm's.
PNPM_SYNTAX = FlagSyntax(
    long_values=frozenset(
        """
        dir filter filter-prod store-dir state-dir npmrc-auth-file userconfig
        workspace-packages registry https-proxy http-proxy no-proxy reporter loglevel
        test-pattern changed-files-ignore-pattern cpu os libc node-linker user-agent
        pnpr-server merge-git-branch-lockfiles-branch-pattern
        """.split()
    ),
    short_values=frozenset({"C", "F"}),
)
# yarn 1 (`yarn --help`).
YARN_SYNTAX = FlagSyntax(
    long_values=frozenset(
        """
        cwd cache-folder global-folder link-folder modules-folder preferred-cache-folder
        mutex network-concurrency network-timeout otp proxy https-proxy registry
        use-yarnrc
        """.split()
    ),
    short_values=frozenset(),
)
NPM_FLAG_SYNTAX = {"npm": NPM_SYNTAX, "pnpm": PNPM_SYNTAX, "yarn": YARN_SYNTAX}

# Lifecycle scripts, from npm's docs/content/using-npm/scripts.md.
_INSTALL = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
)
_TEST = ("pretest", "test", "posttest")
_START = ("prestart", "start", "poststart")
_STOP = ("prestop", "stop", "poststop")
# Subcommand -> scripts it runs. Aliases are npm's lib/utils/cmd-list.js.
_INSTALL_ALIASES = tuple(
    "install i add in ins inst insta instal isnt isnta isntal isntall".split()
)
NPM_LIFECYCLE: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(_INSTALL_ALIASES, _INSTALL),
    **dict.fromkeys(
        ("ci", "clean-install", "ic", "install-clean", "isntall-clean"), _INSTALL
    ),
    **dict.fromkeys(("test", "t", "tst"), _TEST),
    "start": _START,
    "stop": _STOP,
    "restart": ("prerestart", "restart", "postrestart", *_STOP, *_START),
    **dict.fromkeys(("install-test", "it"), _INSTALL + _TEST),
    **dict.fromkeys(
        ("install-ci-test", "cit", "clean-install-test", "sit"), _INSTALL + _TEST
    ),
    **dict.fromkeys(
        ("rebuild", "rb"), ("preinstall", "install", "postinstall", "prepare")
    ),
    "pack": ("prepack", "prepare", "postpack"),
    "publish": (
        "prepublishOnly",
        "prepack",
        "prepare",
        "postpack",
        "publish",
        "postpublish",
    ),
    "version": ("preversion", "version", "postversion"),
    "diff": ("prepare",),
}
# `install <package>` adds a dependency; only a bare install runs this package's
# install lifecycle.
NPM_BARE_ONLY = frozenset({*_INSTALL_ALIASES, "install-test", "it"})
NPM_RUN = frozenset({"run", "run-script", "rum", "urn", "run-scripts"})

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
        "create_subprocess_shell",
    }
)
# Python calls that take the program and its arguments as separate strings or as an
# argv list: the os.exec*/os.spawn* families, posix_spawn, asyncio's
# create_subprocess_exec and pty.spawn.
PY_ARGV_CALLS = frozenset(
    {
        *(f"exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
        *(f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
        "posix_spawn",
        "posix_spawnp",
        "create_subprocess_exec",
        "spawn",
    }
)
# The flag before an argv element that a shell or interpreter runs as a command
# line: `sh -c`, `bash -lc`, `node -e`, `pwsh -Command`, `cmd /c`.
PY_COMMAND_FLAG = re.compile(r"-[A-Za-z]*c|-e|--eval|-Command|/[cC]")


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


def command_word(tokens: list[str]) -> str:
    """The program a command runs: its first token after a YAML `- run:` and `VAR=value`s."""
    for token in tokens:
        if token != "-" and not re.fullmatch(r"[\w-]+:|\w+=.*", token):
            return token
    return ""


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


def _bracket_depth(line: str, depth: int, quote: str) -> tuple[int, str]:
    """`depth` of open `[` after `line`, skipping strings; `quote` is an open string's quote."""
    escaped = False
    for char in line:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth = max(depth - 1, 0)
    # Only a template literal spans lines.
    return depth, quote if quote == "`" else ""


def join_js_arrays(text: str) -> str:
    """JavaScript with each multi-line array literal on one line, its first, so
    `spawn("npx", [\n "cdk",\n "deploy"\n])` reads as one command. Other lines keep
    their numbers."""
    out: list[str] = []
    pending: list[str] = []
    depth, quote = 0, ""
    for line in text.splitlines():
        depth, quote = _bracket_depth(line, depth, quote)
        pending.append(line)
        if depth == 0 or len(pending) > MAX_JOINED_LINES:
            if len(pending) > MAX_JOINED_LINES:
                out.extend(pending)
                depth = 0
            else:
                out.append(" ".join(pending))
                out.extend("" for _ in pending[1:])
            pending = []
    if pending:
        out.extend(pending)
    return "\n".join(out)


def shell_commands(text: str, js: bool = False) -> list[Command]:
    """Every command in shell-like `text`. For JavaScript, `//` comment lines are dropped too."""
    if js:
        text = join_js_arrays(
            "\n".join(
                "" if raw.lstrip().startswith(("//", "/*", "*")) else raw
                for raw in text.splitlines()
            )
        )
    return [
        Command(number, command)
        for number, line in logical_lines(text)
        for command in SEPARATORS.split(line)
        if command.strip()
    ]


def _string_elements(node: ast.List | ast.Tuple) -> list[str]:
    return [
        e.value
        for e in node.elts
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]


def _command_lines(line: int, text: str) -> list[Command]:
    return [Command(line, part) for part in SEPARATORS.split(text) if part.strip()]


def _argv_commands(line: int, words: list[str], run: bool) -> list[Command]:
    """The commands an argv runs.

    The words without whitespace are the command, joined. An element with whitespace
    is one argument, so it is not joined in; it is a command line of its own when a
    shell or interpreter runs it (`bash -c "..."`). When the argv is passed to a
    runner (`run` is true) every such element is read as a command line, because
    which program interprets its arguments as commands is not known here. A bare
    list or tuple may be data, so there only the element after a command flag is.
    """
    if not words:
        return []
    commands: list[Command] = []
    plain = [w for w in words if not re.search(r"\s", w)]
    if plain:
        commands.append(Command(line, " ".join(plain)))
    for previous, word in zip(["", *words], words):
        if re.search(r"\s", word) and (run or PY_COMMAND_FLAG.fullmatch(previous)):
            commands.extend(_command_lines(line, word))
    return commands


def python_commands(text: str) -> list[Command]:
    """What a Python script runs: argv lists of strings, and command-line strings passed to a runner.

    Raises SyntaxError when the file does not parse.
    """
    tree = ast.parse(text)
    # `cmd = [...]` then `subprocess.run(cmd)`: the list a name is bound to.
    bound: dict[str, ast.List | ast.Tuple] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, (ast.List, ast.Tuple))
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            bound[node.targets[0].id] = node.value

    commands: list[Command] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)):
            words = _string_elements(node)
            # A tuple of prose strings is data: an argv starts with a program.
            if len(words) >= 2 and not re.search(r"\s", words[0]):
                commands.extend(_argv_commands(node.lineno, words, run=False))
            continue
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in PY_SHELL_CALLS and name not in PY_ARGV_CALLS:
            continue
        args = list(node.args) + [
            k.value for k in node.keywords if k.arg in ("args", "cmd", "argv")
        ]
        positional_words: list[str] = []
        for index, arg in enumerate(args):
            if isinstance(arg, ast.Name) and arg.id in bound:
                arg = bound[arg.id]
            if isinstance(arg, (ast.List, ast.Tuple)):
                commands.extend(
                    _argv_commands(arg.lineno, _string_elements(arg), run=True)
                )
            elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if name in PY_ARGV_CALLS:
                    # `os.execlp("npx", "npx", "cdk", "deploy")`: one word each.
                    positional_words.append(arg.value)
                elif index == 0:
                    commands.extend(_command_lines(node.lineno, arg.value))
        commands.extend(_argv_commands(node.lineno, positional_words, run=True))
    return list(dict.fromkeys(commands))


def walk_files(root: Path, name: str) -> list[Path]:
    """Every file called `name` under `root`, outside dependency and VCS directories."""
    found: list[Path] = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
        if name in files:
            found.append(Path(directory) / name)
    return sorted(found)


# A command whose flags could be read more ways than this is read only this many ways.
MAX_FLAG_READINGS = 64


def flag_readings(words: list[str], syntax: FlagSyntax) -> list[list[str]]:
    """Every way to read `words` as positional words once the flags are taken out.

    A flag whose arity `syntax` cannot settle is read both with and without a value.
    `--` ends the flags; every word after it is positional.
    """
    readings: list[list[str]] = []

    def walk(index: int, positional: list[str]) -> None:
        while index < len(words) and len(readings) < MAX_FLAG_READINGS:
            word = words[index]
            if re.fullmatch(r"-{2,}", word):
                positional = positional + words[index + 1 :]
                break
            if len(word) > 1 and word.startswith("-"):
                following = words[index + 1] if index + 1 < len(words) else None
                takes = (
                    syntax.takes_value(word, following)
                    if following is not None
                    else False
                )
                if takes is None:
                    walk(index + 2, positional)
                index += 2 if takes else 1
                continue
            positional = positional + [word]
            index += 1
        readings.append(positional)

    walk(0, [])
    return readings


def _run_names(args: list[str]) -> list[str]:
    if not args:
        return []
    name = args[0]
    if "$" in name:
        return [name]
    return [f"pre{name}", name, f"post{name}"]


def scripts_run(tool: str, words: list[str]) -> list[str]:
    """The package.json scripts `<tool> <words...>` runs, `words` being its positional words."""
    if not words:
        # A bare `yarn` installs; a bare `npm` or `pnpm` prints help.
        return list(_INSTALL) if tool == "yarn" else []
    sub, args = words[0], words[1:]
    if tool == "yarn" and sub == "workspace":
        # `yarn workspace <name> <command...>` runs `yarn <command...>` in it.
        return scripts_run(tool, args[1:])
    if tool == "yarn" and sub == "workspaces":
        # yarn 1 `workspaces run <script>`; yarn 2+ `workspaces foreach ... <command>`.
        if args[:1] == ["run"]:
            return _run_names(args[1:])
        if args[:1] == ["foreach"]:
            return scripts_run(tool, args[1:])
        return []
    if tool == "pnpm" and sub in ("recursive", "multi", "m"):
        return scripts_run(tool, args)
    if sub in NPM_RUN:
        return _run_names(args)
    if sub in NPM_LIFECYCLE:
        if sub in NPM_BARE_ONLY and args:
            return []
        return list(NPM_LIFECYCLE[sub])
    # yarn and pnpm run a script named as the subcommand (`yarn deploy`).
    if tool in ("yarn", "pnpm"):
        return _run_names([sub])
    return []


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
            tool = normalize_tool(token)
            if tool not in NPM_TOOLS:
                continue
            names: list[str] = []
            for words in flag_readings(tokens[index + 1 :], NPM_FLAG_SYNTAX[tool]):
                for name in scripts_run(tool, words):
                    if name not in names:
                        names.append(name)
            return names
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
        for previous, token in zip(["", *tokens], tokens):
            # `HELPER=x.py`, `-v x.sh:/tmp/x.sh:ro`: each piece may be a path.
            words = {token, *re.split(r"[=:]", token)}
            if previous == "-m" and PY_MODULE.fullmatch(token):
                # `python -m pkg.mod` runs pkg/mod.py, or pkg/mod/__main__.py.
                module = token.replace(".", "/")
                words |= {f"{module}.py", f"{module}/__main__.py"}
            for word in words:
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
                if "$" in name and command_word(tokens) in ("echo", "printf"):
                    continue  # a message that names a command; nothing runs
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
        "a Python script runs bash -c with a command line that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nsubprocess.run(["bash", "-c", "npx cdk deploy --all"], check=True)\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python argv with an argument that has a space still deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nsubprocess.run(["npx", "cdk", "deploy", "--context", "a b"])\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python script runs a one-word argv, bound to a name, naming a script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nCMD = ["scripts/d.sh"]\nsubprocess.run(CMD, check=True)\n',
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy --all\n",
        },
        (("scripts/d.sh", "`cdk ... deploy`"),),
    ),
    (
        "a Python script runs sys.executable on a Python script that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess, sys\n\nsubprocess.check_call([sys.executable, "scripts/d.py"])\n',
            "scripts/d.py": 'import os\n\nos.execlp("terraform", "terraform", "apply", "-auto-approve")\n',
        },
        (("scripts/d.py", "`terraform ... apply`"),),
    ),
    (
        "npm run with a workspace flag before the script name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npm run -w app deploy\n",
            "package.json": json.dumps(
                {"workspaces": ["app"], "scripts": {"app": "echo app"}}
            ),
            "app/package.json": json.dumps({"scripts": {"deploy": "cdk deploy"}}),
        },
        (("app/package.json#scripts.deploy", "`cdk ... deploy`"),),
    ),
    (
        "yarn workspace runs a script in a workspace that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: yarn --cwd . workspace app ship\n",
            "app/package.json": json.dumps({"scripts": {"ship": "sam deploy"}}),
        },
        (("app/package.json#scripts.ship", "`sam ... deploy`"),),
    ),
    (
        "an extensionless script with a shebang that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: ./scripts/release --all\n",
            "scripts/release": '#!/bin/sh\nnpx cdk deploy "$@"\n',
        },
        (("scripts/release", "`cdk ... deploy`"),),
    ),
    (
        "a script named relative to the directory a cd moved into",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: cd tools && ./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nterraform destroy -auto-approve\n",
        },
        (("tools/ship.sh", "`terraform ... destroy`"),),
    ),
    (
        "a Node script spawns a multi-line argv that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node .github/scripts/go.js\n",
            ".github/scripts/go.js": "const { spawnSync } = require('node:child_process');\n"
            "spawnSync('npx', [\n  'cdk',\n  'deploy',\n  '--all',\n], { stdio: 'inherit' });\n",
        },
        (("/go.js", "`cdk ... deploy`"),),
    ),
    (
        "a TypeScript script runs a command line that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npx tsx scripts/ship.ts\n",
            "scripts/ship.ts": "import { execSync } from 'node:child_process';\nexecSync('npx cdk deploy --all');\n",
        },
        (("scripts/ship.ts", "`cdk ... deploy`"),),
    ),
    (
        "python -m runs a module in the repository that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 -m tools.ship\n",
            "tools/__init__.py": "",
            "tools/ship.py": 'import os\n\nos.system("aws cloudformation delete-stack --stack-name s")\n',
        },
        (("tools/ship.py", "`cloudformation ... delete-stack`"),),
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
            'ARGV = ["npx", "cdk", "synth"]\n'
            'NOTES = ["cdk", "never run cdk deploy here"]\n',
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
    (
        "an extensionless file without a shebang is not a script",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: cat ./scripts/notes && bash scripts/ok.sh\n",
            "scripts/notes": "To ship by hand: npx cdk deploy --all\n",
            "scripts/ok.sh": "#!/bin/sh\necho ok\n",
        },
        "scripts/ok.sh",
    ),
    (
        "a cd target resolves the script there, not one of the same name elsewhere",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: cd tools && ./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nnpx cdk synth\n",
            "elsewhere/ship.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        "tools/ship.sh",
    ),
    (
        "a dependency's package.json under node_modules is not a script CI runs",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: npm run deploy\n",
            "package.json": json.dumps({"scripts": {"deploy": "tsc"}}),
            "node_modules/dep/package.json": json.dumps(
                {"scripts": {"deploy": "cdk deploy"}}
            ),
        },
        "package.json#scripts.deploy",
    ),
    (
        "a Node script that names deploy commands only in comments",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node .github/scripts/go.mjs\n",
            ".github/scripts/go.mjs": "// never npx cdk deploy here\n"
            "/*\n * terraform apply is forbidden\n */\n"
            "import { execSync } from 'node:child_process';\nexecSync('npx cdk synth');\n",
        },
        ".github/scripts/go.mjs",
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
