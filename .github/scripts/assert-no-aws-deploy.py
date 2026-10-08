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
    is the module `python -m pkg.mod` (or `-mpkg.mod`) names (pkg/mod.py or
    pkg/mod/__main__.py). The interpreter does not matter, so `bash x.sh`,
    `./x.sh`, `python3 x.py`, `npx tsx x.ts` and `uv run python x.py` are all
    followed. When the interpreter is explicit (`bash`, `sh`, `source`, `.`,
    `pwsh`, `python*`, `node`, `tsx`, ...), the first word after it that is not a
    flag is followed whatever its suffix (`bash tools/ship`, `source ./env`,
    `bash x.txt`) and read the interpreter's way. A path is tried against the
    repository root, the directory of the file that names it, every
    `working-directory:` value and every `cd [-P|-L] <dir>` target in that file.
    `${{ github.action_path }}` and `$GITHUB_ACTION_PATH` are read as the
    composite action's own directory, and `$GITHUB_WORKSPACE` as the root. A
    block-list item under a `matrix:` key is a value a step runs through
    `${{ matrix.x }}`, so it is read as a token too; other bare list items (a
    `paths:` filter) are not.
  * A followed Python file's imports of repository modules (`import a.b`, `from
    a import b`, relative imports), resolved against its directory and the
    root, are followed, and so are a JavaScript or TypeScript file's relative
    imports and requires (`./lib/d` tried with each script suffix and as a
    directory index).
  * `npm run <name>` (also its aliases `run-script`, `rum`, `urn`, and `pnpm
    run`, `yarn run`, `yarn <name>`, `pnpm <name>`, `yarn workspace <ws>
    <name>`, `yarn workspaces run|foreach`, `pnpm recursive`, `bun run <name>`,
    `bun <name>`, `lerna run <name>`, `deno task <name>`) is mapped through the
    `scripts` table of every package.json that defines `<name>`, and the `tasks`
    of every deno.json / deno.jsonc, with its `pre<name>` and `post<name>`
    hooks. Every npm-family word in a command is read, not only the first
    (`npm explore app -- npm run ship`). Flags are taken out first, each with the
    value it takes: npm's from @npmcli/config's option definitions (`-w app`,
    `--workspace app`, `--prefix x`, `-C x`, `--loglevel warn`, ...), pnpm's and
    yarn's value and boolean flags from their `--help`. A flag whose arity is not
    known (a pnpm or yarn flag not in those lists, an npm abbreviation such as
    `--pref`) is read both with and without a value, and every reading is
    followed. The search over readings is complete: parser states are
    deduplicated and a reading stops walking once it holds READING_DEPTH
    words, so the work grows with the command, not exponentially; a command that
    would walk more than MAX_FLAG_STATES states, or whose subcommands run past
    the READING_DEPTH words a reading keeps, is a finding ("could not be read
    completely"), never a pass. `--` ends the
    flags. The words after the script name are appended to the script's value
    before it is scanned, as npm, yarn and pnpm pass them to it, so
    `"tool": "npx cdk"` with `npm run tool -- deploy` is a deploy. A script
    followed from one workflow file with more than MAX_SCRIPT_ARGUMENT_SETS
    different argument lists (each ambiguous flag in a script that runs another
    can double them) is a finding too. The lifecycle
    commands map to the scripts npm's scripts.md lists for them: `npm ci` and a
    bare `npm install` (and their aliases) to `preinstall`, `install`,
    `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`; `npm
    test`, `start`, `stop`, `restart`, `install-test`, `install-ci-test`,
    `rebuild`, `pack`, `publish`, `version` and `diff` to theirs; a bare `yarn`
    installs. The task runners `npm-run-all`, `run-s`, `run-p`, `turbo`, `nx` and
    `concurrently` map every word after them that is not a flag (split at `:` and
    `,`, with npm-run-all's `*` and `**` globs, and concurrently's `npm:<name>`,
    `yarn:`, `pnpm:` and `bun:` prefixes) to the scripts of that name. A script value
    is a command line, so it is scanned and followed the same way, relative to
    its package.
  * A JavaScript or TypeScript file is read as shell text after its `//` and
    `/* */` comments are blanked, in one pass that tracks strings (with
    backslash-newline continuations), template literals and the `${...}` code
    nested in them (a stack), and regular-expression literals, so neither a `//`
    in a URL nor a quote in a regex is misread. A `/` is a regex after an
    operator, an opening bracket, a keyword such as `return`, or the `)` that
    closes an `if`/`while`/`for`/`with` head, and a division otherwise. Every
    multi-line array literal or call is joined onto its first line, so a
    `spawn("npx", [...])` argv written one word per line is one command. Joining
    has no length cap, because it can only add words to a command. Telling a
    regex from a division is a guess, so a line where a comment starts after a
    regex-or-division decision, or a line that starts inside a template literal,
    is also read whole, with its comment, which can only add a hit. A comment
    after strings or plain code is a comment and is not read. A file whose strings, templates or
    brackets do not balance at its end is a finding, and the finding says to
    restructure that JavaScript rather than change this check.
  * In a workflow, a folded block scalar (`run: >`) is read as the one line
    Actions makes of it, and the `script:` block of an actions/github-script
    step is read as JavaScript, with its multi-line arrays and calls joined;
    another action's `script:` (an SSH action's shell, say) is read as written. A shell command
    that calls a function or alias the same file defines (`c() { npx cdk "$@";
    }`, `alias c='npx cdk'`) is also read with the definition in its place, and
    a pipe into `xargs` is also read with the producer's words as its arguments
    (`echo deploy | xargs npx cdk`).
  * A Python script is parsed rather than read as shell, because its docstrings
    and messages name the forbidden commands in prose (this file does). What it
    runs is the argv list or tuple, or the string, given to a runner:
    `subprocess.run`/`call`/`check_call`/`check_output`/`Popen`/`getoutput`,
    `os.system`/`os.popen`, the `os.exec*`/`os.spawn*` families,
    `posix_spawn`, `pty.spawn` and asyncio's `create_subprocess_exec`/`_shell`,
    also when imported under another name (`from subprocess import run as sh`).
    A runner is also anything bound to one (`sh = subprocess.check_call`,
    `sh = functools.partial(subprocess.run, shell=True)`), reached through
    `getattr(subprocess, "run")`, or a function or lambda that hands a parameter
    (positional, keyword-only or `*args`) to a runner's input. Wrappers are found
    to a fixpoint; each keeps the runner inputs it builds, and a call site is
    read with its arguments in the parameters' places, through any number of
    wrapper levels, so `def cdk(a): subprocess.run(["npx", "cdk", a, "--all"])`
    makes `cdk("deploy")` read as `npx cdk deploy --all`, and every string of a
    wrapper call is also read joined in order. Parameters are kept in a fixed
    order, so the reading does not depend on string hashing. A wrapper is seen
    in the file that defines it and in the followed files that import that file
    (`from helpers import run_command`, `import helpers`), matched by name; a
    bare call to a wrapper named like a runner (`def run(*argv): ...`, then
    `run("cdk", a)`) reaches the wrapper, while `subprocess.run(...)` stays the
    runner. The sh library's `sh.<program>(...)` runs
    `<program>`. `runpy.run_path`, `runpy.run_module`, `importlib.import_module`
    and `exec(open(path).read())` follow the file they name. The runner's input
    (including an `executable=` keyword) may be a literal, a name bound to one by
    a plain, chained or annotated assignment (`cmd = [...]`, `a = b = "..."`,
    `cmd: list[str] = [...]`), a list grown after it is bound (`cmd.append(x)`,
    `cmd.extend(xs)`, `cmd.insert(i, x)`, `cmd += [...]`, read in source order),
    an f-string (each `{name}` read as what the name holds, else `$EXPR`), or any
    other expression, whose strings are all read in source order, through the
    names they are bound from (`shlex.split("...")`, `"...".split()`, `["npx",
    "cdk"] + ["deploy"]`, `C["go"]` with `C = {"go": "..."}`); all of an
    argument's strings are also joined into one command line, so string building
    (`"npx cdk " + "deploy"`, `"npx cdk %s" % x`, `"npx cdk {}".format(x)`) is
    read as the command it builds. An
    argv may have any length, so `subprocess.run(["scripts/d.sh"])` and
    `subprocess.run([sys.executable, "scripts/d.py"])` follow the script. Its
    string words without whitespace are joined into one command; each element
    with whitespace is one argument, and is also read as a command line of its
    own, because the program may run it (`["bash", "-c", "npx cdk deploy"]`,
    `["ssh", "host", "npx cdk deploy"]`). This errs toward a hit: a prose
    argument such as a commit message that names a deploy command is one. A list
    or tuple that is not given to a runner may be data, so it counts as an argv
    only when it has two or more string words and the first has no whitespace,
    and an element with whitespace in it counts as a command line only after a
    command flag (`-c`, `-lc`, `-e`, `--eval`, `-Command`, `/c`). A Python file
    that does not parse is a failure.
  * A word is read the way the shell joins it: quotes inside it are dropped, so
    `dep'loy'` is `deploy`.

Every file is followed once. A hit in a followed file names the file and line
and the chain of references that reached it.

KNOWN LIMITS

A deploy assembled from variables at run time is not seen: a script named only
through a variable (`npm run "$script"`, `bash "$HELPER"` when the env value is
set elsewhere), a Python name reassigned after it is bound (only the last
binding of a name in the file is used, grown by the appends after it), a list
grown through a different name or inside a loop over values from elsewhere, a
Python value read from a file or the environment, or a JavaScript argv pushed
onto a variable (`args.push("deploy")`). A Python wrapper is matched by name in
its own file and in the files that import it directly, so one reached through a
re-export (a package `__init__` that imports it from a submodule), passed around
as a value, or renamed by assignment in another file is not; a wrapper keeps at
most MAX_WRAPPER_INPUTS runner inputs, past which its calls are read only by
their own joined strings. A JavaScript function that wraps child_process is not
followed to its callers. An env value written as a literal path in the
same file (`HELPER: ${{ github.action_path }}/x.py`) is followed, because the path
is a token on that line. A Python import is resolved only against the importing
file's directory and the repository root, so a module found through another
`sys.path` entry, or imported dynamically (`importlib.import_module(name)`), is
not followed; a JavaScript import by package name or a non-relative path is not
followed either. An abbreviated npm subcommand (`npm ru`, which npm expands) is
not followed. `make <target>` is not followed into the Makefile, and nothing in
this repository's CI runs make. A script given by an absolute path, such as one
a `docker run` names inside the container (`/w/x.sh`), is not mapped back to the
repository file it was mounted from. Other script runners (wireit, nps, gulp,
grunt, a Makefile-like task file) are not mapped to the scripts they run.
A regular-expression literal is told from a division by the code before its
`/`. A misjudgment that hides or invents a backtick can carry a wrong template
state onto later lines; a line that then starts with `//` inside what is really
a template literal is blanked. Such a file usually ends unbalanced, which is
reported, and the text lost is template text that only matters if it is then
run as a command. `kubectl` and `helm` are not refused: the operator
e2e applies to a local kind cluster with them, and which cluster a context names
is decided at run time; `aws eks update-kubeconfig` and `eksctl`, which reach a
real cluster, are refused. The workflows that touch deploy/ call `npx cdk synth`,
`terraform init -backend=false` / `validate` and Python scripts under
deploy/tests, all of which are read-only.

Run with --self-test to feed it planted deploy commands and planted look-alikes,
and planted repositories whose deploy sits in a script a workflow calls.
"""

from __future__ import annotations

import argparse
import ast
import functools
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

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
CD = re.compile(
    r"(?:^|[\s;&|(])(?:cd|pushd)\s+(?:-[A-Za-z@]+\s+)*['\"]?([^'\"\s;&|)]+)"
)
# A YAML mapping key, for finding the keys a list item sits under.
YAML_KEY = re.compile(r"^(\s*)(?:-\s+)?([\w.-]+):(?:\s|$)")
# Programs that run the file named after them whatever its suffix, and how that
# file is read: as Python, as JavaScript, or as shell.
INTERPRETERS = {
    **dict.fromkeys(
        ("bash", "sh", "zsh", "dash", "ksh", "source", ".", "pwsh"), "shell"
    ),
    **dict.fromkeys(("node", "tsx", "ts-node", "bun", "deno"), "js"),
}
PYTHON = re.compile(r"python[0-9.]*")
# JavaScript and TypeScript relative imports: `import x from './a'`, `import './a'`,
# `import('./a')`, `require('./a')`, `export * from './a'`.
JS_IMPORT = re.compile(
    r"""(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"](\.{1,2}/[^'"]+)['"]"""
)
JS_RESOLVE_SUFFIXES = (
    "", ".ts", ".mts", ".cts", ".js", ".mjs", ".cjs",
    "/index.ts", "/index.js", "/index.mjs",
)  # fmt: skip

# npm-family tools, how each reads its flags, and the package.json scripts each
# subcommand runs.
NPM_TOOLS = frozenset({"npm", "pnpm", "yarn", "bun", "lerna", "deno"})


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
    # Long flags known to take no value.
    long_booleans: frozenset[str] = frozenset()

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
            if name in self.long_booleans:
                return False
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
# pnpm (`pnpm help`, `pnpm help run`, `pnpm help test`, `pnpm help install`,
# `pnpm help exec`, `pnpm help start`), plus --silent and --bail/--no-bail, which
# earlier pnpm releases document. Its `-w` is --workspace-root, a boolean, unlike
# npm's.
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
    long_booleans=frozenset(
        """
        aggregate-output auto-dedupe color dry-run fail-if-no-match fix-lockfile force
        frozen-lockfile frozen-store if-present ignore-manifest-check ignore-pnpmfile
        ignore-scripts ignore-workspace include-workspace-root json lockfile-only
        merge-git-branch-lockfiles no-auto-dedupe no-frozen-lockfile no-frozen-store
        no-ignore-scripts no-include-workspace-root no-offline no-optional
        no-prefer-frozen-lockfile no-prefer-offline no-progress no-runtime no-sort
        no-trust-lockfile offline optional parallel prefer-frozen-lockfile
        prefer-offline reverse sort stream trust-lockfile update-checksums use-stderr
        dev prod shell-mode help recursive sequential version workspace-root yes
        silent bail no-bail
        """.split()
    ),
    short_booleans=frozenset({"D", "P", "c", "h", "r", "s", "v", "w", "y"}),
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
    long_booleans=frozenset(
        """
        check-files disable-pnp enable-pnp pnp flat focus force frozen-lockfile har
        ignore-engines ignore-optional ignore-platform ignore-scripts json
        link-duplicates no-bin-links no-default-rc no-lockfile non-interactive
        no-node-version-check no-progress offline prefer-offline pure-lockfile silent
        skip-integrity-check strict-semver update-checksums version verbose help
        """.split()
    ),
    short_booleans=frozenset({"s", "v", "h"}),
)
# bun, lerna and deno: no flag is known, so every flag is read both ways.
UNKNOWN_SYNTAX = FlagSyntax(long_values=frozenset(), short_values=frozenset())
NPM_FLAG_SYNTAX = {
    "npm": NPM_SYNTAX,
    "pnpm": PNPM_SYNTAX,
    "yarn": YARN_SYNTAX,
    "bun": UNKNOWN_SYNTAX,
    "lerna": UNKNOWN_SYNTAX,
    "deno": UNKNOWN_SYNTAX,
}

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


def logical_lines(text: str, hash_comments: bool = True) -> list[tuple[int, str]]:
    """Comment-free lines with backslash continuations joined, keyed by first line number.

    `#` starts a comment line unless `hash_comments` is false (JavaScript, whose
    comments are removed beforehand and where `#x = [...]` is code).
    """
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if hash_comments and raw.lstrip().startswith("#"):
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
    # The shell joins quoted and bare pieces into one word (`dep'loy'`), so quotes
    # inside a word go too.
    return [t for t in (t.replace("'", "").replace('"', "") for t in bare.split()) if t]


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


def line_commands(line: str) -> list[str]:
    """The commands on one logical line: split at the separators, plus, for a pipe
    into `xargs`, the xargs command with the producer's words as its arguments
    (`echo deploy | xargs npx cdk` runs `npx cdk deploy`)."""
    commands = [c for c in SEPARATORS.split(line) if c.strip()]
    for match in re.finditer(r"\|\s*xargs\b", line):
        consumer = SEPARATORS.split(line[match.end() :])[0]
        commands.append(f"{consumer} {line[: match.start()]}")
    return commands


def scan_text(path: str, text: str) -> list[Hit]:
    hits: list[Hit] = []
    for number, line in logical_lines(text):
        match = USES.match(line)
        if match and match.group(1).lower() in DEPLOY_ACTIONS:
            hits.append(Hit(path, number, line.strip(), f"uses {match.group(1)}"))
            continue
        for command in line_commands(line):
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


# Where a `/` starts a regular-expression literal rather than a division: after
# one of these characters, or one of these keywords, or at the start of the text,
# or after the `)` that closes an `if (...)`, `while (...)`, `for (...)` or
# `with (...)` head.
JS_REGEX_AFTER = frozenset("(,=:[!&|?{};+-*%<>~^")
JS_REGEX_KEYWORD = re.compile(
    r"(?:^|[^\w$.])(?:return|typeof|case|do|else|in|of|void|yield|await|delete|new|throw)$"
)
JS_CONTROL_HEAD = re.compile(r"(?:^|[^\w$.])(?:if|while|for|with)$")


def _js_regex_end(text: str, index: int, before: str, after_control: bool) -> int:
    """The index after the regular-expression literal starting at `text[index]`, or -1.

    `before` is the code before it, ignoring whitespace; `after_control` says the
    `)` before it closes a control-statement head. A literal ends at an unescaped
    `/` outside a `[...]` class, on the same line.
    """
    previous = before[-1:] if before else ""
    if previous == ")":
        if not after_control:
            return -1
    elif previous and previous not in JS_REGEX_AFTER:
        if not JS_REGEX_KEYWORD.search(before):
            return -1
    in_class = False
    position = index + 1
    while position < len(text):
        char = text[position]
        if char == "\n":
            return -1
        if char == "\\":
            position += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return position + 1
        position += 1
    return -1


@dataclass(frozen=True)
class JsScan:
    """What one pass over a JavaScript file found."""

    # The text with `//` and `/* */` comments blanked; newlines and every other
    # character keep their places.
    blanked: str
    # The `(`/`[` depth after each line, counted outside strings, templates,
    # comments and regular-expression literals.
    depths: tuple[int, ...]
    # The file ends inside a template literal, a `${...}` or an open bracket.
    unbalanced: bool
    # Lines where a comment starts after a regex-or-division decision on the same
    # line, or on a line that started inside a template literal. Those decisions
    # may be wrong, so these lines are also scanned with their comments in place
    # (which can only add hits).
    suspect: frozenset[int]


def _js_walk(text: str) -> JsScan:
    """Read JavaScript `text` once, tracking strings, template literals with their
    nested `${...}` code (a stack), comments, regex literals and brackets."""
    out: list[str] = []
    depths: list[int] = []
    suspect: set[int] = set()
    # Each level is a template literal (None) or code with its open `{` count.
    stack: list[list[int] | None] = [[0]]
    parens: list[bool] = []  # per open `(`: is it a control-statement head
    depth = 0
    after_control = False
    code = ""  # recent code, for the regex test
    line = 1
    # A regex-or-division decision was made on this line, or the line started
    # inside a template literal: the two places the walker can be wrong.
    guessed = False
    index = 0
    length = len(text)

    def newlines(segment: str, in_template: bool = False) -> None:
        nonlocal line, guessed
        for _ in range(segment.count("\n")):
            depths.append(depth)
            line += 1
            guessed = in_template

    while index < length:
        char = text[index]
        top = stack[-1]
        if char == "\n":
            depths.append(depth)
            line += 1
            guessed = top is None
            out.append(char)
            index += 1
            continue
        if top is None:  # inside a template literal
            if char == "\\" and index + 1 < length:
                pair = text[index : index + 2]
                out.append(pair)
                newlines(pair, in_template=True)
                index += 2
                continue
            if char == "`":
                stack.pop()
                code += "x"
                out.append(char)
                index += 1
                continue
            if text.startswith("${", index):
                stack.append([0])
                out.append("${")
                index += 2
                continue
            out.append(char)
            index += 1
            continue
        if char in "'\"":
            end = index + 1
            while end < length:
                if text[end] == "\\" and end + 1 < length:
                    end += 2  # an escape, or a backslash-newline continuation
                    continue
                if text[end] == char:
                    end += 1
                    break
                if text[end] == "\n":
                    break  # unterminated: the string ends with its line
                end += 1
            segment = text[index:end]
            out.append(segment)
            newlines(segment)
            code += "x"
            after_control = False
            index = end
            continue
        if char == "`":
            stack.append(None)
            after_control = False
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index) or text.startswith("/*", index):
            if guessed:
                suspect.add(line)
            if text[index + 1] == "/":
                end = text.find("\n", index)
                end = length if end < 0 else end
            else:
                end = text.find("*/", index + 2)
                end = length if end < 0 else end + 2
            segment = text[index:end]
            out.append(re.sub(r"[^\n]", " ", segment))
            newlines(segment)
            index = end
            continue
        if char == "/":
            end = _js_regex_end(text, index, code.rstrip(), after_control)
            guessed = True  # a regex or a division: either way, a decision
            if end > 0:
                out.append(text[index:end])
                code += "x"  # a regex is a value; a `/` after it divides
                after_control = False
                index = end
                continue
        if char == "{":
            top[0] += 1
        elif char == "}":
            if top[0] == 0 and len(stack) > 1:
                stack.pop()  # the end of a `${...}`
                out.append(char)
                index += 1
                continue
            top[0] = max(top[0] - 1, 0)
        closing_control = False
        if char in "([":
            if char == "(":
                parens.append(bool(JS_CONTROL_HEAD.search(code.rstrip())))
            depth += 1
        elif char in ")]":
            if char == ")":
                closing_control = parens.pop() if parens else False
            depth = max(depth - 1, 0)
        if not char.isspace():
            code = (code + char)[-64:]
            after_control = closing_control
        out.append(char)
        index += 1
    depths.append(depth)
    return JsScan(
        "".join(out), tuple(depths), len(stack) > 1 or depth != 0, frozenset(suspect)
    )


def strip_js_comments(text: str) -> str:
    """`text` with JavaScript `//` and `/* */` comments blanked, outside strings,
    template literals and regular-expression literals."""
    return _js_walk(text).blanked


# The reason for a JavaScript file whose strings or brackets do not balance.
JS_MISREAD = (
    "its strings, template literals, regular expressions or brackets do not balance"
    " as this scan reads them, so a multi-line command in it may not have been read"
    " whole. Restructure the JavaScript (close each string and bracket on its line;"
    " build a regex the scan misreads with new RegExp(...)) instead of changing"
    " this check"
)


def js_misread(text: str) -> bool:
    """Whether JavaScript `text` ends inside a template literal, a `${...}` or a bracket."""
    return _js_walk(text).unbalanced


def _join_by_depth(lines: list[str], depths: tuple[int, ...]) -> list[str]:
    out: list[str] = []
    pending: list[str] = []
    for line, depth in zip(lines, depths):
        pending.append(line)
        if depth == 0:
            out.append(" ".join(pending))
            out.extend("" for _ in pending[1:])
            pending = []
    if pending:
        out.append(" ".join(pending))
        out.extend("" for _ in pending[1:])
    return out


def join_js_arrays(text: str) -> str:
    """JavaScript with each multi-line array literal or call joined onto its first
    line, so `spawn("npx", [\n "cdk",\n "deploy"\n])` reads as one command. Other
    lines keep their numbers. Comments are left as they are; the bracket depths
    come from a scan that skips them.

    There is no length cap: joining lines only puts more words into a command, so it
    can add a hit and never remove one. A file that ends unbalanced is also reported
    (js_misread), because what was joined there is a guess.
    """
    return "\n".join(_join_by_depth(text.split("\n"), _js_walk(text).depths))


def js_commands(text: str) -> list[Command]:
    """Every command in JavaScript `text`: the comment-blanked text with multi-line
    arrays and calls joined, plus every suspect line read with its comment."""
    scan = _js_walk(text)
    joined = "\n".join(_join_by_depth(scan.blanked.split("\n"), scan.depths))
    commands = [
        Command(number, command)
        for number, line in logical_lines(joined, hash_comments=False)
        for command in SEPARATORS.split(line)
        if command.strip()
    ]
    raw = text.split("\n")
    for number in sorted(scan.suspect):
        commands.extend(_command_lines(number, raw[number - 1]))
    return commands


SHELL_FUNCTION = re.compile(r"^\s*(?:function\s+)?([\w.-]+)\s*(?:\(\s*\))?\s*\{(.*)$")
SHELL_ALIAS = re.compile(r"\balias\s+([\w.-]+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))")


def shell_definitions(text: str) -> dict[str, str]:
    """Shell functions and aliases `text` defines, each with the command text it
    stands for: `c() { npx cdk "$@"; }` and `alias c='npx cdk'` are `npx cdk`."""
    definitions: dict[str, str] = {}
    lines = [line for _, line in logical_lines(text)]
    index = 0
    while index < len(lines):
        line = lines[index]
        for match in SHELL_ALIAS.finditer(line):
            definitions[match.group(1)] = next(
                g for g in match.groups()[1:] if g is not None
            )
        function = SHELL_FUNCTION.match(line)
        if (
            function
            and "(" in line
            or (function and line.lstrip().startswith("function"))
        ):
            body = [function.group(2)]
            depth = line.count("{") - line.count("}")
            while depth > 0 and index + 1 < len(lines):
                index += 1
                body.append(lines[index])
                depth += lines[index].count("{") - lines[index].count("}")
            definitions[function.group(1)] = " ; ".join(body).rstrip("} ;")
        index += 1
    return definitions


def shell_commands(text: str, js: bool = False) -> list[Command]:
    """Every command in shell-like `text`; JavaScript goes through js_commands().

    A command that calls a shell function or alias the text defines is also read
    with the definition in its place and the arguments substituted for `$@`/`$*`
    (`c deploy` after `c() { npx cdk "$@"; }`), and a pipe into `xargs` is also
    read with the producer's words as the arguments (`echo deploy | xargs npx
    cdk`). Both only add commands.
    """
    if js:
        return js_commands(text)
    commands: list[Command] = []
    for number, line in logical_lines(text):
        commands.extend(Command(number, command) for command in line_commands(line))
    definitions = shell_definitions(text)
    if definitions:
        for command in list(commands):
            tokens = command_tokens(command.text)
            word = command_word(tokens)
            if word not in definitions:
                continue
            rest = " ".join(tokens[tokens.index(word) + 1 :])
            body = definitions[word]
            expanded = re.sub(r'"?\$[@*]"?|"?\$\{[@*]\}"?', lambda _: rest, body)
            if expanded == body:
                expanded = f"{body} {rest}"
            commands.extend(_command_lines(command.line, expanded))
    return commands


# A YAML key whose value is a block scalar: `run: >`, `script: |-`.
YAML_BLOCK_SCALAR = re.compile(
    r"^(\s*)(?:-\s+)?([\w.-]+):\s*([|>])[-+0-9]*\s*(?:#.*)?$"
)


def yaml_block_scalars(text: str) -> str:
    """Workflow text with block scalars read the way Actions reads them.

    A folded scalar (`run: >`) is one line: its lines are joined onto the first,
    so `npx cdk` and `deploy` on two lines are one command, as the runner sees
    them. The `script:` block of an actions/github-script step is JavaScript, so
    each multi-line array or call in it is joined as in a followed .js file;
    another action's `script:` is left as written. Other lines become empty and
    keep their numbers.
    """
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        match = YAML_BLOCK_SCALAR.match(lines[index])
        if not match:
            index += 1
            continue
        key_indent = len(match.group(1))
        end = index + 1
        while end < len(lines) and (
            not lines[end].strip()
            or len(lines[end]) - len(lines[end].lstrip()) > key_indent
        ):
            end += 1
        block = lines[index + 1 : end]
        if match.group(3) == ">":
            content = [line.strip() for line in block if line.strip()]
            first = next((i for i, line in enumerate(block) if line.strip()), None)
            if first is not None:
                indent = block[first][: len(block[first]) - len(block[first].lstrip())]
                block = [""] * len(block)
                block[first] = indent + " ".join(content)
        elif match.group(2) == "script" and _in_github_script_step(lines, index):
            block = _join_by_depth(block, _js_walk("\n".join(block)).depths)
        lines[index + 1 : end] = block
        index = end
    return "\n".join(lines)


def _in_github_script_step(lines: list[str], index: int) -> bool:
    """Whether the `script:` key on line `index` belongs to a step that uses
    actions/github-script, whose script is JavaScript. Another action's `script:`
    (an SSH action's, say) is shell, and is left as it is."""
    key_indent = len(lines[index]) - len(lines[index].lstrip())
    for back in range(index - 1, -1, -1):
        raw = lines[back]
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        match = USES.match(raw)
        if match and indent < key_indent:
            return match.group(1).lower() == "actions/github-script"
        if raw.lstrip().startswith("- ") and indent < key_indent - 2:
            return False  # the start of the step, with no uses: above the key
    return False


def matrix_item_lines(text: str) -> set[int]:
    """Line numbers of YAML block-list items under a `matrix:` key.

    A bare list item elsewhere (a `paths:` filter) names a file without running it,
    but a matrix value is run through `${{ matrix.x }}`, so it is followed.
    """
    items: set[int] = set()
    keys: list[tuple[int, str]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        match = YAML_KEY.match(raw)
        if match:
            key_indent = len(match.group(1))
            while keys and keys[-1][0] >= key_indent:
                keys.pop()
            keys.append((key_indent, match.group(2)))
        elif YAML_SCALAR_ITEM.match(raw):
            if any(k == "matrix" for i, k in keys if i <= indent):
                items.add(number)
    return items


def _string_value(node: ast.AST) -> str | None:
    """A string constant's value, or an f-string with each `{...}` read as `$EXPR`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            str(part.value) if isinstance(part, ast.Constant) else "$EXPR"
            for part in node.values
        )
    return None


def _string_elements(node: ast.List | ast.Tuple) -> list[str]:
    return [v for v in (_string_value(e) for e in node.elts) if v is not None]


# What a wrapper's parameters stand for at one call site: each name maps to the
# call's argument expressions (several for `*args`). A chain is read innermost
# first; an argument found in env i is read with the envs after it, which hold
# the names of the scope the call was made in.
Env = dict[str, tuple[ast.expr, ...]]
Chain = tuple[Env, ...]


def _lookup(name: str, chain: Chain) -> tuple[tuple[ast.expr, ...], Chain] | None:
    for index, env in enumerate(chain):
        if name in env:
            return env[name], chain[index + 1 :]
    return None


def _strings_in(
    node: ast.AST,
    bound: dict[str, ast.expr] | None = None,
    chain: Chain = (),
    depth: int = 0,
) -> list[str]:
    """Every string in an expression, in source order (`shlex.split("...")`, `a + b`,
    `"%s" % x`, `"{}".format(x)`). A name a wrapper's call site gives a value, or
    one bound in the file, is read as that value (a binding inside a wrapper is
    read with the call site's arguments); an f-string's `{name}` too."""
    bound = bound or {}
    if depth > MAX_BINDING_DEPTH:
        return []
    if isinstance(node, ast.Constant):
        return [node.value] if isinstance(node.value, str) else []
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(str(part.value))
            else:
                value = part.value if isinstance(part, ast.FormattedValue) else part
                inner = _strings_in(value, bound, chain, depth + 1)
                parts.append(" ".join(inner) if inner else "$EXPR")
        return ["".join(parts)]
    if isinstance(node, ast.Name):
        found = _lookup(node.id, chain)
        if found is not None:
            values, rest = found
            return [s for v in values for s in _strings_in(v, bound, rest, depth + 1)]
        if node.id in bound:
            return _strings_in(bound[node.id], bound, chain, depth + 1)
        return []
    out: list[str] = []
    for child in ast.iter_child_nodes(node):
        out.extend(_strings_in(child, bound, chain, depth))
    return out


def _expr_words(
    node: ast.expr, bound: dict[str, ast.expr], chain: Chain = (), depth: int = 0
) -> list[str]:
    """The argv words an expression gives a runner: a list's elements one word each
    (`*xs` spread), a name through its value, anything else its strings as one."""
    if depth > MAX_BINDING_DEPTH:
        return []
    if isinstance(node, ast.Starred):
        return _expr_words(node.value, bound, chain, depth)
    if isinstance(node, ast.Name):
        found = _lookup(node.id, chain)
        if found is not None:
            values, rest = found
            return [w for v in values for w in _expr_words(v, bound, rest, depth + 1)]
        if node.id in bound:
            return _expr_words(bound[node.id], bound, chain, depth + 1)
        return []
    if isinstance(node, (ast.List, ast.Tuple)):
        words: list[str] = []
        for element in node.elts:
            if isinstance(element, ast.Starred) or isinstance(element, ast.Name):
                words.extend(_expr_words(element, bound, chain, depth + 1))
            else:
                text = " ".join(_strings_in(element, bound, chain, depth + 1))
                if text:
                    words.append(text)
        return words
    if (
        isinstance(node, ast.Call)
        and getattr(node.func, "id", "") in ("list", "tuple")
        and len(node.args) == 1
    ):
        return _expr_words(node.args[0], bound, chain, depth + 1)
    text = " ".join(_strings_in(node, bound, chain, depth))
    return [text] if text else []


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


# How far a name bound to an expression naming other names is followed.
MAX_BINDING_DEPTH = 8
# The most runner inputs one wrapper keeps; a wrapper of wrappers of wrappers can
# multiply them, and past this the rest are read only by name, as before.
MAX_WRAPPER_INPUTS = 64
# Keyword arguments that carry a runner's command.
PY_COMMAND_KEYWORDS = frozenset({"args", "cmd", "argv", "executable", "command"})
# Modules whose functions are the runners themselves.
PY_RUNNER_MODULES = frozenset({"subprocess", "os", "asyncio", "pty", "sp"})
# Calls whose string argument names a Python file or module that is then run.
PY_RUN_PATH_CALLS = frozenset({"run_path", "run_module", "import_module"})


@dataclass(frozen=True)
class WrapperParam:
    """A parameter of a function that reaches a runner's input."""

    position: int | None  # its position at a call site; None when keyword-only
    name: str
    vararg: bool = False


def _param_order(param: WrapperParam) -> tuple[bool, int, str]:
    # A fixed order, so nothing depends on how a set of parameters hashes.
    return (param.position is None, param.position or 0, param.name)


@dataclass(frozen=True)
class RunnerInput:
    """An expression a runner reads its command from, inside a wrapper, with what
    the names of inner wrappers it went through stand for."""

    expression: ast.expr
    kind: str  # "shell" (a command line or an argv) or "argv" (one word each)
    chain: Chain
    line: int


@dataclass(frozen=True)
class Wrapper:
    params: tuple[WrapperParam, ...]  # sorted by _param_order
    inputs: tuple[RunnerInput, ...]


Wrappers = dict[str, Wrapper]


def _call_name(func: ast.expr, aliases: dict[str, str]) -> str:
    """The name a call is made through: `x.run` is `run`, an alias is what it aliases,
    and `getattr(subprocess, "run")` is `run`."""
    if isinstance(func, ast.Attribute):
        return aliases.get(func.attr, func.attr)
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if (
        isinstance(func, ast.Call)
        and getattr(func.func, "id", "") == "getattr"
        and len(func.args) >= 2
    ):
        return _string_value(func.args[1]) or ""
    return ""


def _call_env(call: ast.Call, params: tuple[WrapperParam, ...]) -> Env:
    """What each parameter of a wrapper stands for at `call`."""
    env: Env = {}
    for param in params:
        values: list[ast.expr] = []
        if param.position is not None:
            if param.vararg:
                values.extend(call.args[param.position :])
            elif param.position < len(call.args):
                values.append(call.args[param.position])
            else:
                # A positional parameter after a `*xs` argument at the call.
                values.extend(a for a in call.args if isinstance(a, ast.Starred))
        values.extend(k.value for k in call.keywords if k.arg == param.name)
        if values:
            env[param.name] = tuple(values)
    return env


def _runner_inputs(
    call: ast.Call, name: str, wrappers: Wrappers
) -> list[RunnerInput] | None:
    """The inputs a call hands a runner, read in its own scope, or None if the call
    is not to a runner or a wrapper."""
    keywords = [k.value for k in call.keywords if k.arg in PY_COMMAND_KEYWORDS]
    # A function under a runner's name (`def run(*argv): ...`) is what a bare
    # call to that name, `self.run(...)` or `helpers.run(...)` reaches;
    # `subprocess.run(...)` and `os.system(...)` keep meaning the runner.
    wrapper = wrappers.get(name)
    if wrapper is not None and (
        isinstance(call.func, ast.Name)
        or (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id not in PY_RUNNER_MODULES
        )
        or (name not in PY_ARGV_CALLS and name not in PY_SHELL_CALLS)
    ):
        return _wrapper_inputs(call, wrapper)
    if name in PY_ARGV_CALLS:
        return [
            RunnerInput(a, "argv", (), getattr(a, "lineno", call.lineno))
            for a in list(call.args) + keywords
        ]
    if name in PY_SHELL_CALLS:
        return [
            RunnerInput(a, "shell", (), getattr(a, "lineno", call.lineno))
            for a in list(call.args[:1]) + keywords
        ]
    return None


def _wrapper_inputs(call: ast.Call, wrapper: Wrapper) -> list[RunnerInput]:
    """A wrapper's runner inputs with its parameters standing for `call`'s arguments."""
    env = _call_env(call, wrapper.params)
    inputs = [
        RunnerInput(i.expression, i.kind, (*i.chain, env), call.lineno)
        for i in wrapper.inputs
    ]
    # Every string of the call is also read, joined in order: a wrapper whose own
    # input could not be kept still shows its call's words.
    inputs.append(RunnerInput(_call_arguments(call), "shell", (), call.lineno))
    return inputs


def _call_arguments(call: ast.Call) -> ast.expr:
    """A call's positional arguments as one tuple expression, made once per call so
    that reading the call again yields an equal input."""
    made = getattr(call, "_guard_arguments", None)
    if not isinstance(made, ast.expr):
        made = ast.copy_location(ast.Tuple(elts=list(call.args), ctx=ast.Load()), call)
        setattr(call, "_guard_arguments", made)
    return made


def _bindings(tree: ast.AST) -> tuple[dict[str, ast.expr], dict[str, str]]:
    """What each name is bound to, and which names are other names for a callable
    (`from subprocess import run as sh`, `sh = subprocess.check_call`).

    A list a name is bound to is extended, in source order, by what is appended to
    it later (`cmd.append(x)`, `cmd.extend(xs)`, `cmd.insert(i, x)`, `cmd +=
    [...]`), so an argv built up step by step is read whole.
    """
    bound: dict[str, ast.expr] = {}
    aliases: dict[str, str] = {}
    events: list[tuple[int, int, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.ImportFrom)):
            events.append((node.lineno, node.col_offset, node))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("append", "extend", "insert")
            and isinstance(node.func.value, ast.Name)
        ):
            events.append((node.lineno, node.col_offset, node))
    for _, _, node in sorted(events, key=lambda e: (e[0], e[1])):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if name in bound:
                bound[name] = _extended(bound[name], [ast.Starred(node.value)], node)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        ):
            name = node.func.value.id
            if name in bound and node.args:
                added = node.args[-1]
                base = bound[name]
                position = node.args[0] if node.func.attr == "insert" else None
                if (
                    isinstance(position, ast.Constant)
                    and isinstance(position.value, int)
                    and isinstance(base, (ast.List, ast.Tuple))
                ):
                    elements = list(base.elts)
                    elements.insert(position.value, added)
                    bound[name] = ast.copy_location(
                        ast.List(elts=elements, ctx=ast.Load()), node
                    )
                else:
                    extra = (
                        [ast.Starred(added)] if node.func.attr == "extend" else [added]
                    )
                    bound[name] = _extended(base, extra, node)
        if value is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(value, (ast.Attribute, ast.Name)):
                aliases[target.id] = _call_name(value, {})
            elif _partial_runner(value) is not None:
                aliases[target.id] = _partial_runner(value) or ""
            else:
                bound[target.id] = value
    return bound, aliases


def _partial_runner(value: ast.expr) -> str | None:
    """The callable `functools.partial(<callable>, ...)` wraps, by name."""
    if (
        isinstance(value, ast.Call)
        and _call_name(value.func, {}) == "partial"
        and value.args
        and isinstance(value.args[0], (ast.Name, ast.Attribute))
    ):
        return _call_name(value.args[0], {})
    return None


def _extended(base: ast.expr, extra: Sequence[ast.expr], at: ast.AST) -> ast.expr:
    elements: list[ast.expr] = (
        list(base.elts)
        if isinstance(base, (ast.List, ast.Tuple))
        else [ast.Starred(base)]
    )
    return ast.copy_location(ast.List(elts=[*elements, *extra], ctx=ast.Load()), at)


@functools.lru_cache(maxsize=4096)
def _parse(text: str) -> ast.Module:
    """`text` parsed once however often it is read; raises SyntaxError."""
    return ast.parse(text)


@dataclass(frozen=True)
class _PyFunction:
    name: str
    params: dict[str, WrapperParam]
    calls: tuple[ast.Call, ...]


@dataclass(frozen=True)
class _PyFacts:
    """What one Python file holds, computed once per text."""

    tree: ast.Module
    bound: dict[str, ast.expr]
    aliases: dict[str, str]
    functions: tuple[_PyFunction, ...]
    nodes: tuple[ast.AST, ...]
    # The name of every call in the file, for knowing when a wrapper found in
    # another file can change what this one runs.
    called: frozenset[str]


def _function_params(arguments: ast.arguments) -> dict[str, WrapperParam]:
    positional = [a.arg for a in arguments.posonlyargs + arguments.args]
    offset = 1 if positional[:1] in (["self"], ["cls"]) else 0
    params = {
        name: WrapperParam(index - offset, name)
        for index, name in enumerate(positional)
        if index >= offset
    }
    params.update({a.arg: WrapperParam(None, a.arg) for a in arguments.kwonlyargs})
    if arguments.vararg:
        params[arguments.vararg.arg] = WrapperParam(
            len(positional) - offset, arguments.vararg.arg, vararg=True
        )
    return params


@functools.lru_cache(maxsize=4096)
def _facts(text: str) -> _PyFacts:
    tree = _parse(text)
    bound, aliases = _bindings(tree)
    nodes = tuple(ast.walk(tree))
    functions: list[_PyFunction] = []
    for node in nodes:
        body: ast.AST
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name, arguments, body = node.name, node.args, node
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Lambda)
        ):
            # `sh = lambda c: subprocess.run(c, shell=True)` is a function.
            name, arguments, body = node.targets[0].id, node.value.args, node.value
        else:
            continue
        params = _function_params(arguments)
        calls = tuple(c for c in ast.walk(body) if isinstance(c, ast.Call))
        if params and calls:
            functions.append(_PyFunction(name, params, calls))
    called = frozenset(
        _call_name(n.func, aliases) for n in nodes if isinstance(n, ast.Call)
    )
    return _PyFacts(tree, bound, aliases, tuple(functions), nodes, called)


def _free_names(
    node: ast.AST, bound: dict[str, ast.expr], chain: Chain, depth: int = 0
) -> set[str]:
    """The names an expression reads that its chain does not give a value, through
    the names they are bound from."""
    names: set[str] = set()
    if depth > MAX_BINDING_DEPTH:
        return names
    for child in ast.walk(node):
        if not isinstance(child, ast.Name):
            continue
        found = _lookup(child.id, chain)
        if found is not None:
            values, rest = found
            for value in values:
                names |= _free_names(value, bound, rest, depth + 1)
            continue
        names.add(child.id)
        if child.id in bound and bound[child.id] is not node:
            names |= _free_names(bound[child.id], bound, chain, depth + 1)
    return names


def _input_key(runner_input: RunnerInput) -> tuple[object, ...]:
    """An identity for a runner input: its expression and what each name in its
    chain stands for, by node."""
    return (
        id(runner_input.expression),
        runner_input.kind,
        tuple(
            (name, tuple(id(v) for v in values))
            for env in runner_input.chain
            for name, values in env.items()
        ),
    )


def _merge_inputs(
    old: Sequence[RunnerInput], new: Sequence[RunnerInput]
) -> tuple[RunnerInput, ...]:
    merged = list(old)
    keys = {_input_key(i) for i in merged}
    for runner_input in new:
        key = _input_key(runner_input)
        if key not in keys and len(merged) < MAX_WRAPPER_INPUTS:
            keys.add(key)
            merged.append(runner_input)
    return tuple(merged)


def python_wrappers(text: str, known: Wrappers | None = None) -> Wrappers:
    """Functions in `text` that hand a parameter to a runner, to a fixpoint.

    A function whose parameter reaches the input of a runner, or of a function
    already found to do so, is itself one. Each keeps the runner inputs it builds,
    so a call site is read with its arguments in the parameters' places
    (`def cdk(a): run(["npx", "cdk", a])` then `cdk("deploy")` is `npx cdk
    deploy`). `known` holds wrappers found in other files, matched by name.
    """
    facts = _facts(text)
    wrappers: Wrappers = dict(known or {})
    changed = True
    while changed:
        changed = False
        for function in facts.functions:
            names_called = [_call_name(c.func, facts.aliases) for c in function.calls]
            if not any(
                n in PY_SHELL_CALLS or n in PY_ARGV_CALLS or n in wrappers
                for n in names_called
            ):
                continue
            reached: dict[str, WrapperParam] = {}
            inputs: list[RunnerInput] = []
            for call, call_name in zip(function.calls, names_called):
                found = _runner_inputs(call, call_name, wrappers)
                if not found:
                    continue
                for runner_input in found:
                    names = _free_names(
                        runner_input.expression, facts.bound, runner_input.chain
                    )
                    hit = [
                        function.params[n]
                        for n in sorted(names)
                        if n in function.params
                    ]
                    if hit:
                        reached.update((p.name, p) for p in hit)
                        inputs.append(runner_input)
            if not reached:
                continue
            old = wrappers.get(function.name)
            params = tuple(
                sorted(
                    {*(old.params if old else ()), *reached.values()}, key=_param_order
                )
            )
            merged = _merge_inputs(old.inputs if old else (), inputs)
            new = Wrapper(params, merged)
            if (
                old is None
                or new.params != old.params
                or len(new.inputs) != len(old.inputs)
            ):
                wrappers[function.name] = new
                changed = True
    return wrappers


def _input_commands(
    runner_input: RunnerInput, bound: dict[str, ast.expr]
) -> list[Command]:
    """The commands one runner input gives: its words as an argv (a spaced word also
    a command line), and all its strings joined as one command line."""
    expression, chain, line = (
        runner_input.expression,
        runner_input.chain,
        runner_input.line,
    )
    if isinstance(expression, (ast.List, ast.Tuple)) and not chain:
        line = expression.lineno  # the list's own line, where it is also read alone
    words = _expr_words(expression, bound, chain)
    commands = _argv_commands(line, words, run=True)
    joined = " ".join(_strings_in(expression, bound, chain))
    if joined.strip():
        commands.extend(_command_lines(line, joined))
    return commands


def python_commands(
    text: str, wrappers: Wrappers | None = None, resolved: bool = False
) -> list[Command]:
    """What a Python script runs: argv lists of strings, and command-line strings
    passed to a runner or to a function that hands them to one.

    Raises SyntaxError when the file does not parse.
    """
    facts = _facts(text)
    bound, aliases = facts.bound, facts.aliases
    # `resolved`: `wrappers` already holds this file's own wrappers.
    wrappers = (
        wrappers
        if resolved and wrappers is not None
        else python_wrappers(text, wrappers)
    )
    uses_sh = any(
        isinstance(node, ast.Import) and any(a.name == "sh" for a in node.names)
        for node in facts.nodes
    )

    commands: list[Command] = []
    for node in facts.nodes:
        if isinstance(node, (ast.List, ast.Tuple)):
            words = _string_elements(node)
            # A tuple of prose strings is data: an argv starts with a program.
            if len(words) >= 2 and not re.search(r"\s", words[0]):
                commands.extend(_argv_commands(node.lineno, words, run=False))
            continue
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func, aliases)
        if name in PY_RUN_PATH_CALLS and node.args:
            # `runpy.run_path("x.py")`, `runpy.run_module("pkg.mod")`.
            target = _string_value(node.args[0])
            if target:
                prefix = "" if target.endswith(".py") or "/" in target else "-m "
                commands.append(Command(node.lineno, prefix + target))
            continue
        if name == "exec" and node.args:
            # `exec(open("x.py").read())`: the file read is run.
            for child in ast.walk(node.args[0]):
                if isinstance(child, ast.Call) and _call_name(child.func, {}) == "open":
                    target = _string_value(child.args[0]) if child.args else None
                    if target:
                        commands.append(Command(node.lineno, target))
            continue
        func = node.func
        if (
            uses_sh
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "sh"
        ):
            # The sh library runs the program its attribute names: `sh.npx("cdk")`.
            flat = [func.attr] + [" ".join(_strings_in(a, bound)) for a in node.args]
            commands.extend(_argv_commands(node.lineno, flat, run=True))
            continue
        found = _runner_inputs(node, name, wrappers)
        if found is None:
            continue
        positional_words: list[str] = []
        for runner_input in found:
            if runner_input.kind == "argv":
                # `os.execlp("npx", "npx", "cdk", "deploy")`: one word each.
                positional_words.extend(
                    _expr_words(runner_input.expression, bound, runner_input.chain)
                )
            commands.extend(_input_commands(runner_input, bound))
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


# A reading keeps this many positional words, more than any subcommand chain
# scripts_run() looks through; a command that needs more is a finding.
READING_DEPTH = 8
# A hard stop on distinct parser states. The states are deduplicated, so their
# number grows with the command's length, not exponentially with its ambiguous
# flags; reaching the stop is a finding, never a silent pass.
MAX_FLAG_STATES = 20_000
# The most distinct argument lists one package.json script is followed with. Each
# ambiguous flag in a script that runs another script can double them, so the
# count is bounded, and reaching the bound is a finding, not a pass.
MAX_SCRIPT_ARGUMENT_SETS = 32
# The reason recorded for a command the scan could not read completely.
UNREADABLE = "could not be read completely"


class UnreadableCommand(Exception):
    """A command whose readings exceed a bound; reported as a finding."""


@dataclass(frozen=True)
class Reading:
    """One way to read a command's words with its flags taken out."""

    # The first READING_DEPTH positional words, and where each sits in the input.
    words: tuple[str, ...]
    indices: tuple[int, ...]
    # Positional words past READING_DEPTH exist.
    more: bool


def flag_readings(words: list[str], syntax: FlagSyntax) -> list[Reading]:
    """Every way to read `words` as positional words once the flags are taken out.

    A flag whose arity `syntax` cannot settle is read both with and without a value.
    `--` ends the flags; every word after it is positional. The search is complete:
    parser states are deduplicated, and a command that would pass MAX_FLAG_STATES
    raises UnreadableCommand rather than drop a reading.
    """
    readings: dict[Reading, None] = {}
    seen: set[tuple[int, tuple[int, ...], bool]] = set()
    stack: list[tuple[int, tuple[int, ...], bool]] = [(0, (), False)]
    walked = 0
    while stack:
        state = stack.pop()
        if state in seen:
            continue
        seen.add(state)
        # The bound counts states walked, so it bounds the work as well as the
        # readings: without the deduplication above, flags whose following words
        # are flags would be walked exponentially many times.
        walked += 1
        if walked > MAX_FLAG_STATES:
            raise UnreadableCommand(
                f"its flags can be read more than {MAX_FLAG_STATES} ways"
            )
        index, indices, more = state
        while index < len(words):
            word = words[index]
            if re.fullmatch(r"-{2,}", word):
                rest = tuple(range(index + 1, len(words)))
                room = READING_DEPTH - len(indices)
                more = more or len(rest) > room
                indices = indices + rest[: max(room, 0)]
                index = len(words)
                break
            if len(word) > 1 and word.startswith("-"):
                following = words[index + 1] if index + 1 < len(words) else None
                takes = (
                    syntax.takes_value(word, following)
                    if following is not None
                    else False
                )
                if takes is None:
                    stack.append((index + 2, indices, more))
                index += 2 if takes else 1
                continue
            indices = indices + (index,)
            index += 1
            if len(indices) == READING_DEPTH:
                # Words past the depth cannot change the ones kept, so the rest
                # of a long tail is not walked; whatever follows counts as more.
                more = more or index < len(words)
                break
        readings[Reading(tuple(words[i] for i in indices), indices, more)] = None
    return list(readings)


# A script name, and the position in the words it was read from of the word whose
# followers are passed to the script as arguments (None: no arguments reach it).
Invocation = tuple[str, "int | None"]


def _run_names(args: list[str], position: int) -> list[Invocation]:
    if not args:
        return []
    name = args[0]
    if "$" in name:
        return [(name, position)]
    return [(f"pre{name}", position), (name, position), (f"post{name}", position)]


def scripts_run(tool: str, words: list[str], offset: int = 0) -> list[Invocation]:
    """The package.json scripts `<tool> <words...>` runs, `words` being its positional words.

    Each comes with the position (counted from `offset`) of the word after which the
    command's remaining words are passed to the script.
    """
    if not words:
        # A bare `yarn` installs; a bare `npm` or `pnpm` prints help.
        return [(name, None) for name in _INSTALL] if tool == "yarn" else []
    sub, args = words[0], words[1:]
    if tool == "lerna":
        # `lerna run <script>` runs it in every package; `lerna exec -- <cmd>`
        # is a command line the scan already reads.
        return _run_names(args, offset + 1) if sub == "run" else []
    if tool == "deno":
        # `deno task <name>` runs a deno.json task or a package.json script.
        return _run_names(args, offset + 1) if sub == "task" else []
    if tool == "yarn" and sub == "workspace":
        # `yarn workspace <name> <command...>` runs `yarn <command...>` in it.
        return scripts_run(tool, args[1:], offset + 2)
    if tool == "yarn" and sub == "workspaces":
        # yarn 1 `workspaces run <script>`; yarn 2+ `workspaces foreach ... <command>`.
        if args[:1] == ["run"]:
            return _run_names(args[1:], offset + 2)
        if args[:1] == ["foreach"]:
            return scripts_run(tool, args[1:], offset + 2)
        return []
    if tool == "pnpm" and sub in ("recursive", "multi", "m"):
        return scripts_run(tool, args, offset + 1)
    if sub in NPM_RUN:
        return _run_names(args, offset + 1)
    if sub in NPM_LIFECYCLE:
        if sub in NPM_BARE_ONLY:
            return [] if args else [(n, None) for n in NPM_LIFECYCLE[sub]]
        return [(n, offset) for n in NPM_LIFECYCLE[sub]]
    # yarn, pnpm and bun run a script named as the subcommand (`yarn deploy`).
    if tool in ("yarn", "pnpm", "bun"):
        return _run_names([sub], offset)
    return []


# Task runners that run package.json scripts by name: npm-run-all and its run-s and
# run-p, turbo and nx. Every word after the runner that is not a flag may name a
# script or task, so each is followed (a superset of what runs). npm-run-all reads
# `*` as any characters but `:` and `**` as any.
TASK_RUNNERS = frozenset(
    {"npm-run-all", "npm-run-all2", "run-s", "run-p", "turbo", "nx", "concurrently"}
)
# concurrently (and npm-run-all, which accepts them) names a script as
# `npm:<name>`, `yarn:<name>`, `pnpm:<name>` or `bun:<name>`.
RUNNER_PREFIX = re.compile(r"(?:npm|yarn|pnpm|bun):(.+)")


def task_runner_names(tokens: list[str]) -> list[str]:
    for index, token in enumerate(tokens):
        if normalize_tool(token) not in TASK_RUNNERS:
            continue
        names: list[str] = []
        for word in tokens[index + 1 :]:
            if word == "--":
                break
            if word.startswith("-"):
                word = word.split("=", 1)[1] if "=" in word else ""
            prefixed = RUNNER_PREFIX.fullmatch(word)
            # nx: `run project:target`, `-t build,test`.
            pieces = re.split(r"[:,]", word) + [word]
            if prefixed:
                pieces.append(prefixed.group(1))
            for name in pieces:
                if name and name not in names:
                    names.append(name)
        return names
    return []


def _glob_names(pattern: str, scripts: dict[str, str]) -> list[str]:
    if "*" not in pattern:
        return [pattern] if pattern in scripts else []
    expression = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^:]*")
    return [name for name in scripts if re.fullmatch(expression, name)]


class Follower:
    """Scans workflow and action files, then every repository script they run."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.hits: list[Hit] = []
        self.followed: list[str] = []
        self.unresolved_npm: list[str] = []
        self._seen: set[str] = set()
        self._packages: dict[Path, dict[str, str]] | None = None
        # Python functions, in any followed file, that hand a parameter to a
        # runner; a call to one by name in any followed file is a runner call.
        # By followed file: the wrappers it defines, and the followed files it
        # imports. A file sees its own wrappers and those of the files it imports.
        self._defined: dict[str, Wrappers] = {}
        self._imports_of: dict[str, list[str]] = {}
        # Followed Python files with what each was scanned for so far, so a
        # wrapper found later re-reads them (rescan_python()).
        self._python: dict[str, tuple[Path, tuple[str, ...], str, set[Command]]] = {}
        self._hit_lines: dict[str, set[int]] = {}
        # Bumped whenever a file's wrappers grow; a file is re-read only after one
        # of the files it imports changed.
        self._wrapper_version = 0
        self._read_at: dict[str, int] = {}
        # The version at which each file's wrappers last changed.
        self._changed_at: dict[str, int] = {}
        # Distinct pass-through word sets followed per script.
        self._extras: dict[str, set[str]] = {}
        # Where a script that is not a package.json script is defined
        # (`deno.json#tasks`), by directory and name.
        self._manifests: dict[tuple[Path, str], str] = {}

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
            # deno.json / deno.jsonc `tasks`, which `deno task <name>` runs too; a
            # task is a command string or an object with a `command`.
            for name in ("deno.json", "deno.jsonc"):
                for path in walk_files(self.root, name):
                    try:
                        tasks = json.loads(
                            strip_js_comments(path.read_text(encoding="utf-8"))
                        ).get("tasks")
                    except (OSError, ValueError, AttributeError):
                        continue
                    if not isinstance(tasks, dict):
                        continue
                    table = self._packages.setdefault(path.parent, {})
                    for key, task in tasks.items():
                        command = (
                            task.get("command") if isinstance(task, dict) else task
                        )
                        if isinstance(command, str) and key not in table:
                            table[key] = command
                            self._manifests[(path.parent, key)] = f"{name}#tasks"
        return self._packages

    def manifest(self, directory: Path, script: str) -> str:
        """`package.json#scripts.<name>`, or `deno.json#tasks.<name>`, under `directory`."""
        where = self._manifests.get((directory, script), "package.json#scripts")
        file, table = where.split("#")
        return f"{self.rel(directory / file)}#{table}.{script}"

    def npm_invocations(self, tokens: list[str]) -> list[tuple[str, str]] | None:
        """The package.json scripts an npm-family command runs, each with the words
        passed through to it, or None if the command is not one.

        The pass-through words are every word after the script name, flags and all:
        a superset of what npm, yarn or pnpm hand the script, so a deploy assembled
        from the script and its arguments (`"tool": "npx cdk"`, then
        `npm run tool -- deploy`) is seen. Raises UnreadableCommand at a bound.
        """
        found: list[tuple[str, str]] | None = None
        # Every npm-family word in the command, not only the first: `npm explore
        # app -- npm run ship`, `concurrently "npm run a" "yarn b"`.
        for index, token in enumerate(tokens):
            tool = normalize_tool(token)
            if tool not in NPM_TOOLS:
                continue
            words = tokens[index + 1 :]
            found = found if found is not None else []
            for reading in flag_readings(words, NPM_FLAG_SYNTAX[tool]):
                invocations = scripts_run(tool, list(reading.words))
                if reading.more and invocations != scripts_run(
                    tool, [*reading.words, "\0"]
                ):
                    raise UnreadableCommand(
                        f"its subcommands run past the {READING_DEPTH} words read"
                    )
                for name, position in invocations:
                    extra = (
                        " ".join(words[reading.indices[position] + 1 :])
                        if position is not None
                        else ""
                    )
                    if (name, extra) not in found:
                        found.append((name, extra))
        return found

    def npm_scripts(self, tokens: list[str]) -> list[str] | None:
        """The package.json script names an npm-family command runs, or None if it is not one."""
        invocations = self.npm_invocations(tokens)
        if invocations is None:
            return None
        return list(dict.fromkeys(name for name, _ in invocations))

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

    def resolve_any(self, word: str, bases: list[Path]) -> list[Path]:
        """Existing repository files `word` names, whatever their suffix."""
        if (
            not word
            or "$" in word
            or "*" in word
            or "://" in word
            or word.startswith("-")
        ):
            return []
        if Path(word).is_absolute():
            return []
        found: list[Path] = []
        for base in bases:
            path = (base / word).resolve()
            try:
                relative = path.relative_to(self.root)
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in relative.parts):
                continue
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def referenced_scripts(
        self, tokens: list[str], bases: list[Path]
    ) -> list[tuple[Path, str | None]]:
        """Scripts a command names, each with how it must be read (None: by suffix)."""
        found: list[tuple[Path, str | None]] = []

        def add(path: Path, mode: str | None) -> None:
            if (path, mode) not in found:
                found.append((path, mode))

        for index, (previous, token) in enumerate(zip(["", *tokens], tokens)):
            # `HELPER=x.py`, `-v x.sh:/tmp/x.sh:ro`: each piece may be a path.
            # A dict, not a set: the order things are followed in must not depend
            # on string hashing.
            words = dict.fromkeys([token, *re.split(r"[=:]", token)])
            module = None
            if previous == "-m" and PY_MODULE.fullmatch(token):
                module = token
            elif token.startswith("-m") and PY_MODULE.fullmatch(token[2:]):
                module = token[2:]  # `python -mpkg.mod`
            if module:
                # `python -m pkg.mod` runs pkg/mod.py, or pkg/mod/__main__.py.
                stem = module.replace(".", "/")
                for word in (f"{stem}.py", f"{stem}/__main__.py"):
                    for path in self.resolve(word, bases):
                        add(path, "python")
            for word in words:
                for path in self.resolve(word, bases):
                    add(path, None)
            # `bash tools/ship`, `source ./env`, `python3 tools/x`: the interpreter
            # is explicit, so the file is read its way whatever its suffix.
            tool = normalize_tool(token)
            mode = "python" if PYTHON.fullmatch(tool) else INTERPRETERS.get(tool)
            if mode is None:
                continue
            target = next((t for t in tokens[index + 1 :] if not t.startswith("-")), "")
            for path in self.resolve_any(target, bases):
                if path.suffix not in SCRIPT_SUFFIXES:
                    add(path, mode)
        return found

    # -- scanning ------------------------------------------------------------

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def scan_workflow(self, path: Path) -> None:
        relative = self.rel(path)
        text = yaml_block_scalars(path.read_text(encoding="utf-8"))
        self.hits.extend(scan_text(relative, text))
        action_dir = self.rel(path.parent) or "."
        text = WORKSPACE.sub(".", ACTION_PATH.sub(action_dir, text))
        matrix_items = matrix_item_lines(text)
        runnable = "\n".join(
            "" if YAML_SCALAR_ITEM.match(raw) and number not in matrix_items else raw
            for number, raw in enumerate(text.splitlines(), start=1)
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
            for script, mode in self.referenced_scripts(tokens, bases):
                self.follow_file(script, here, mode)
            for name in task_runner_names(tokens):
                self.follow_npm(name, "", here, package, glob=True)
            try:
                invocations = self.npm_invocations(tokens)
            except UnreadableCommand as error:
                self.hits.append(
                    Hit(
                        relative,
                        command.line,
                        command.text.strip(),
                        f"{UNREADABLE}: {error}",
                        via,
                    )
                )
                continue
            if invocations is None:
                continue
            for name, extra in invocations:
                if "$" in name and command_word(tokens) in ("echo", "printf"):
                    continue  # a message that names a command; nothing runs
                self.follow_npm(name, extra, here, package)

    def follow_npm(
        self,
        name: str,
        extra: str,
        via: tuple[str, ...],
        package: Path | None,
        glob: bool = False,
    ) -> None:
        """Scan and follow the script `name` with the words `extra` passed to it."""
        packages = self.packages()
        if "$" in name:
            if not glob:
                self.unresolved_npm.append(via[-1])
            return
        if glob:
            targets = [
                (p, n)
                for p, scripts in packages.items()
                for n in _glob_names(name, scripts)
            ]
        elif package is not None and name in packages.get(package, {}):
            targets = [(package, name)]
        else:
            targets = [(p, name) for p, scripts in packages.items() if name in scripts]
        for directory, script in targets:
            key = f"npm:{directory}:{script}:{extra}"
            if key in self._seen:
                continue
            self._seen.add(key)
            # Counted per workflow file that started the chain, so many workflows
            # each running a script with their own arguments do not add up.
            origin = via[0].rsplit(":", 1)[0] if via else ""
            extras = self._extras.setdefault(f"{origin}:{directory}:{script}", set())
            extras.add(extra)
            if len(extras) > MAX_SCRIPT_ARGUMENT_SETS:
                if len(extras) == MAX_SCRIPT_ARGUMENT_SETS + 1:
                    manifest = self.manifest(directory, script)
                    self.hits.append(
                        Hit(
                            manifest,
                            1,
                            packages[directory][script],
                            f"{UNREADABLE}: it is run with more than"
                            f" {MAX_SCRIPT_ARGUMENT_SETS} different argument lists",
                            via,
                        )
                    )
                continue
            manifest = self.manifest(directory, script)
            if manifest not in self.followed:
                self.followed.append(manifest)
            value = packages[directory][script]
            # npm, yarn and pnpm append the pass-through words to the script.
            line = f"{value} {extra}" if extra else value
            for hit in scan_text(manifest, line):
                self.hits.append(Hit(manifest, 1, line, hit.reason, via))
            self.follow_commands(
                manifest,
                shell_commands(line),
                self.bases(value, directory)[1:] + [self.root],
                via,
                directory,
            )

    def follow_file(
        self, path: Path, via: tuple[str, ...], mode: str | None = None
    ) -> None:
        """Scan `path` and follow what it runs; `mode` overrides how its suffix reads it."""
        relative = self.rel(path)
        if mode is None:
            mode = (
                "python"
                if path.suffix == ".py"
                else "js"
                if path.suffix in JS_SUFFIXES
                else "shell"
            )
        if relative in self._seen:
            return
        self._seen.add(relative)
        self.followed.append(relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        imports: list[Path] = []
        if mode == "python":
            try:
                imports = self.python_imports(text, path)
                self._imports_of[relative] = [self.rel(m) for m in imports]
                self._learn_wrappers(relative, text)
                commands = python_commands(text, self.view(relative), resolved=True)
            except SyntaxError as error:
                self.hits.append(
                    Hit(relative, error.lineno or 1, str(error.msg), PARSE_FAILURE, via)
                )
                return
            self._python[relative] = (path, via, text, set(commands))
            self._read_at[relative] = self._wrapper_version
        else:
            commands = shell_commands(text, js=mode == "js")
            if mode == "js":
                imports = self.js_imports(text, path)
        if mode == "js" and js_misread(text):
            self.hits.append(Hit(relative, 1, "", f"{UNREADABLE}: {JS_MISREAD}", via))
        self._scan_commands(relative, path, text, commands, via)
        for module in imports:
            self.follow_file(module, (*via, f"{relative} imports"), None)

    def _scan_commands(
        self,
        relative: str,
        path: Path,
        text: str,
        commands: list[Command],
        via: tuple[str, ...],
    ) -> None:
        hit_lines = self._hit_lines.setdefault(relative, set())
        for command in commands:
            reason = deploy_reason(command.text)
            # One hit per line, as for a workflow line: several readings of one
            # line (an argv, its spaced element, its joined strings) are one deploy.
            if reason and command.line not in hit_lines:
                hit_lines.add(command.line)
                self.hits.append(
                    Hit(relative, command.line, command.text.strip(), reason, via)
                )
        self.follow_commands(
            relative, commands, self.bases(text, path.parent), via, None
        )

    def view(self, relative: str) -> Wrappers:
        """The wrappers a followed file can call: its own and those of the followed
        files it imports, matched by name."""
        seen: Wrappers = {}
        for source in [*self._imports_of.get(relative, []), relative]:
            for name, wrapper in self._defined.get(source, {}).items():
                known = seen.get(name)
                seen[name] = (
                    wrapper
                    if known is None
                    else Wrapper(
                        tuple(
                            sorted({*known.params, *wrapper.params}, key=_param_order)
                        ),
                        _merge_inputs(known.inputs, wrapper.inputs),
                    )
                )
        return seen

    def _learn_wrappers(self, relative: str, text: str) -> bool:
        """Record the wrappers `text` defines; True if they changed."""
        own = {f.name for f in _facts(text).functions}
        found = python_wrappers(text, self.view(relative))
        defined = {name: found[name] for name in found if name in own}
        old = self._defined.get(relative, {})
        changed = set(defined) != set(old) or any(
            defined[n].params != old[n].params
            or len(defined[n].inputs) != len(old[n].inputs)
            for n in defined
        )
        if changed:
            self._defined[relative] = defined
            self._wrapper_version += 1
            self._changed_at[relative] = self._wrapper_version
        return changed

    def rescan_python(self) -> None:
        """Re-read followed Python files whose imports learned new wrappers, until
        none do (a fixpoint across files)."""
        changed = True
        while changed:
            changed = False
            for relative, (path, via, text, done) in list(self._python.items()):
                read_at = self._read_at.get(relative, -1)
                if not any(
                    self._changed_at.get(source, -1) > read_at
                    for source in self._imports_of.get(relative, [])
                ):
                    continue
                self._read_at[relative] = self._wrapper_version
                self._learn_wrappers(relative, text)
                new = [
                    c
                    for c in python_commands(text, self.view(relative), resolved=True)
                    if c not in done
                ]
                if new:
                    done.update(new)
                    self._scan_commands(relative, path, text, new, via)
                changed = True

    def python_imports(self, text: str, path: Path) -> list[Path]:
        """Repository modules a Python file imports, resolved against its directory and the root."""
        found: list[Path] = []
        for node in ast.walk(_parse(text)):
            names: list[str] = []
            base_dirs = [path.parent, self.root]
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                if node.level:
                    anchor = path.parent
                    for _ in range(node.level - 1):
                        anchor = anchor.parent
                    base_dirs = [anchor]
                names = [prefix] if prefix else []
                names += [
                    f"{prefix}.{alias.name}" if prefix else alias.name
                    for alias in node.names
                ]
            for name in names:
                stem = name.replace(".", "/")
                for word in (f"{stem}.py", f"{stem}/__init__.py"):
                    for module in self.resolve(word, base_dirs):
                        if module not in found and module != path:
                            found.append(module)
        return found

    def js_imports(self, text: str, path: Path) -> list[Path]:
        """Repository files a JavaScript or TypeScript file imports by a relative path."""
        found: list[Path] = []
        for spec in JS_IMPORT.findall(strip_js_comments(text)):
            for suffix in JS_RESOLVE_SUFFIXES:
                for module in self.resolve_any(spec + suffix, [path.parent]):
                    if module.suffix in JS_SUFFIXES and module not in found:
                        found.append(module)
                        break
                else:
                    continue
                break
        return found


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
    follower.rescan_python()
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
    # The shell joins quoted and bare pieces of a word.
    "run: cdk dep'loy'",
    'run: "c"dk de"ploy"',
    # xargs runs its command with the producer's words.
    "run: echo deploy | xargs npx cdk",
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
        "pnpm booleans and --filter values, seven pairs, before the script name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: pnpm --silent --filter p0 --stream --filter p1 --parallel --filter p2 --reverse --filter p3 --if-present --filter p4 --aggregate-output --filter p5 --no-bail --filter p6 ship\n",
            "package.json": json.dumps({"scripts": {"ship": "cdk deploy"}}),
        },
        (("package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "seven unknown pnpm flags, each read with and without a value",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: pnpm --u0 --filter p0 --u1 --filter p1 --u2 --filter p2 --u3 --filter p3 --u4 --filter p4 --u5 --filter p5 --u6 --filter p6 ship\n",
            "package.json": json.dumps({"scripts": {"ship": "cdk deploy"}}),
        },
        (("package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "seven unknown pnpm flags whose words are their values",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: pnpm --u0 v0 --u1 v1 --u2 v2 --u3 v3 --u4 v4 --u5 v5 --u6 v6 ship\n",
            "package.json": json.dumps({"scripts": {"ship": "cdk deploy"}}),
        },
        (("package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "npm run passes the words after -- to a script that names the tool",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npm run tool -- deploy --all\n",
            "package.json": json.dumps({"scripts": {"tool": "npx cdk"}}),
        },
        (("package.json#scripts.tool", "`cdk ... deploy`"),),
    ),
    (
        "yarn passes the words after the script name to it",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: yarn tool deploy\n",
            "package.json": json.dumps({"scripts": {"tool": "npx cdk"}}),
        },
        (("package.json#scripts.tool", "`cdk ... deploy`"),),
    ),
    (
        "a script runs other scripts through npm-run-all",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: npm run ci\n",
            "package.json": json.dumps(
                {
                    "scripts": {
                        "ci": "run-s build ship:*",
                        "build": "tsc",
                        "ship:prod": "cdk deploy",
                    }
                }
            ),
        },
        (("package.json#scripts.ship:prod", "`cdk ... deploy`"),),
    ),
    (
        "a Python command line bound to a name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import os\n\nCMD = "npx cdk deploy --all"\nos.system(CMD)\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python argv bound by an annotated, chained assignment",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nA = B = ["scripts/d.sh"]\nC: list[str] = A\nsubprocess.run(B)\n',
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        (("scripts/d.sh", "`cdk ... deploy`"),),
    ),
    (
        "a Python argv split from a string by shlex",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import shlex, subprocess\n\nsubprocess.run(shlex.split("npx cdk deploy --all"))\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python argv split from a string by str.split",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nsubprocess.run("terraform apply -auto-approve".split())\n',
        },
        (("scripts/ship.py", "`terraform ... apply`"),),
    ),
    (
        "a Python runner imported under another name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'from subprocess import run as sh\n\nsh(["scripts/d.sh"])\n',
            "scripts/d.sh": "#!/bin/sh\nsam deploy\n",
        },
        (("scripts/d.sh", "`sam ... deploy`"),),
    ),
    (
        "a Python argv whose spaced element a remote program runs",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import subprocess\n\nsubprocess.run(["ssh", "host", "npx cdk deploy --all"])\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python f-string command line",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": 'import os\n\nstack = "s"\nos.system(f"npx cdk {stack} deploy")\n',
        },
        (("scripts/ship.py", "`cdk ... deploy`"),),
    ),
    (
        "a followed Python script imports a local module that deploys",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": "from helper import go\n\ngo()\n",
            "scripts/helper.py": 'import subprocess\n\n\ndef go():\n    subprocess.run(["npx", "cdk", "deploy"])\n',
        },
        (("scripts/helper.py", "`cdk ... deploy`"),),
    ),
    (
        "python -m with the module glued to the flag",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 -mtools.ship\n",
            "tools/__init__.py": "",
            "tools/ship.py": 'import os\n\nos.system("cdk destroy --force")\n',
        },
        (("tools/ship.py", "`cdk ... destroy`"),),
    ),
    (
        "bash runs a file with no suffix and no shebang",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: bash tools/ship && source ./tools/env && sh tools/ship.txt\n",
            "tools/ship": "npx cdk deploy\n",
            "tools/env": "terraform apply\n",
            "tools/ship.txt": "sam deploy\n",
        },
        (
            ("tools/ship", "`cdk ... deploy`"),
            ("tools/env", "`terraform ... apply`"),
            ("tools/ship.txt", "`sam ... deploy`"),
        ),
    ),
    (
        "a matrix block list names the script a step runs",
        {
            ".github/workflows/w.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      matrix:\n        script:\n          - scripts/ok.sh\n"
            "          - scripts/d.sh\n    steps:\n      - run: bash ${{ matrix.script }}\n",
            "scripts/ok.sh": "#!/bin/sh\necho ok\n",
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        (("scripts/d.sh", "`cdk ... deploy`"),),
    ),
    (
        "cd with an option before its directory",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: cd -P tools && ./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        (("tools/ship.sh", "`cdk ... deploy`"),),
    ),
    (
        "a Node argv longer than fifty lines, after a backtick in a comment and a regex with a quote",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node scripts/go.js\n",
            "scripts/go.js": "// the ` character\nconst q = /^(['\"])(.*)\\1$/;\n"
            "/* note */ const { spawnSync } = require('node:child_process');\n"
            "spawnSync('npx', [\n  'cdk',\n"
            + "".join(f"  '--context', 'k{i}=v',\n" for i in range(30))
            + "  'deploy',\n]);\n",
        },
        (("scripts/go.js", "`cdk ... deploy`"),),
    ),
    (
        "a Node call with one argument per line",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node scripts/go.js\n",
            "scripts/go.js": "require('node:child_process').execFileSync(\n  'npx',\n  'cdk',\n  'deploy',\n);\n",
        },
        (("scripts/go.js", "`cdk ... deploy`"),),
    ),
    (
        "a TypeScript script imports a module by a path without a suffix",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npx tsx scripts/main.ts\n",
            "scripts/main.ts": "import { go } from './lib/d';\ngo();\n",
            "scripts/lib/d.ts": "import { execSync } from 'node:child_process';\nexport const go = () => execSync('npx cdk deploy');\n",
        },
        (("scripts/lib/d.ts", "`cdk ... deploy`"),),
    ),
    (
        "a Node script whose template literal never closes is not passed",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node scripts/go.js\n",
            "scripts/go.js": "const t = `open\nspawnSync('npx', [\n 'cdk',\n 'deploy'\n]);\n",
        },
        (("scripts/go.js", f"{UNREADABLE}: {JS_MISREAD}"),),
    ),
    (
        "a template literal holding a backtick and // before real code",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: node go.js\n",
            "go.js": 'const s = `${"`"}${"//"}`; require(\'child_process\').execSync("npx cdk deploy --all");\n',
        },
        (("go.js", "`cdk ... deploy`"),),
    ),
    (
        "a regex after a control-statement head, then a string with //",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: node go.js\n",
            "go.js": "if (1) /'/.test('x'); const u = '//'; require('child_process').execSync('npx cdk deploy');\n",
        },
        (("go.js", "`cdk ... deploy`"),),
    ),
    (
        "a regex holding a backtick inside a template's ${...}",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: node go.js\n",
            "go.js": "const s = `${'a'.replace(/`/g, '')}//`; require('child_process').execSync('npx cdk deploy');\n",
        },
        (("go.js", "`cdk ... deploy`"),),
    ),
    (
        "a string continued past a backslash-newline",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: node go.js\n",
            "go.js": "const s = 'a\\\n// '; require('child_process').execSync('npx cdk deploy');\n",
        },
        (("go.js", "`cdk ... deploy`"),),
    ),
    (
        "a Python command line built with +",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import os\n\nos.system("npx cdk " + "deploy --all")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python command line built with % and bound to a name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\nC = "npx cdk %s" % "deploy"\nsubprocess.run(C, shell=True)\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python command line built with str.format",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import os\n\nos.system("npx cdk {}".format("deploy"))\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python helper hands its parameter to a runner",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef sh(c):\n    subprocess.run(c, shell=True, check=True)\n\n\nsh("npx cdk deploy --all")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python helper's varargs become an argv naming a script",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef sh(*a):\n    subprocess.run(list(a))\n\n\nsh("scripts/d.sh")\n',
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        (("scripts/d.sh", "`cdk ... deploy`"),),
    ),
    (
        "a Python helper through a helper, in another module",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: python3 scripts/s.py\n",
            "scripts/s.py": 'from util import go\n\ngo("npx cdk destroy --force")\n',
            "scripts/util.py": "import subprocess\n\n\ndef run(cmd):\n    return _run(cmd)\n\n\ndef _run(cmd, cwd=None):\n    subprocess.check_call(cmd, shell=True, cwd=cwd)\n\n\ndef go(cmd):\n    run(cmd)\n",
        },
        (("scripts/s.py", "`cdk ... destroy`"),),
    ),
    (
        "a Python runner bound to a name",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\nsh = subprocess.check_call\nsh("npx cdk deploy", shell=True)\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python runner reached through getattr",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\ngetattr(subprocess, "run")("terraform apply", shell=True)\n',
        },
        (("s.py", "`terraform ... apply`"),),
    ),
    (
        "a Python command read from a dict",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\nC = {"go": "npx cdk deploy"}\nsubprocess.run(C["go"], shell=True)\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "the sh library runs the program its attribute names",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import sh\n\nsh.npx("cdk", "deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python executable= keyword names a script",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\nsubprocess.Popen(executable="scripts/d.sh", args=[])\n',
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
        (("scripts/d.sh", "`cdk ... deploy`"),),
    ),
    (
        "runpy and exec(open()) run another Python file",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import runpy\n\nrunpy.run_path("scripts/x.py")\nexec(open("scripts/y.py").read())\n',
            "scripts/x.py": 'import os\n\nos.system("cdk deploy")\n',
            "scripts/y.py": 'import os\n\nos.system("sam deploy")\n',
        },
        (
            ("scripts/x.py", "`cdk ... deploy`"),
            ("scripts/y.py", "`sam ... deploy`"),
        ),
    ),
    (
        "bun runs a script, with the words after it",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: bun run ship && bun tool deploy\n",
            "package.json": '{"scripts": {"ship": "cdk destroy", "tool": "npx cdk"}}',
        },
        (
            ("package.json#scripts.ship", "`cdk ... destroy`"),
            ("package.json#scripts.tool", "`cdk ... deploy`"),
        ),
    ),
    (
        "lerna run runs a script in every package",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npx lerna run ship --stream\n",
            "app/package.json": '{"scripts": {"ship": "cdk deploy"}}',
        },
        (("app/package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "deno task runs a deno.json task",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: deno task ship\n",
            "deno.json": '{"tasks": {"ship": {"command": "npx cdk deploy"}}}',
        },
        (("deno.json#tasks.ship", "`cdk ... deploy`"),),
    ),
    (
        "concurrently runs an npm:<script>",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npx concurrently -k npm:ship 'npm:lint'\n",
            "package.json": '{"scripts": {"ship": "cdk deploy", "lint": "eslint ."}}',
        },
        (("package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "npm explore runs a second npm command",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: npm explore app -- npm run ship\n",
            "package.json": '{"scripts": {"ship": "cdk deploy"}}',
        },
        (("package.json#scripts.ship", "`cdk ... deploy`"),),
    ),
    (
        "a shell function and an alias stand for the deploy tool",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: bash scripts/a.sh\n",
            "scripts/a.sh": "#!/bin/bash\nshopt -s expand_aliases\nc() { npx cdk \"$@\"; }\nalias t='terraform'\nc deploy\nt apply\n",
        },
        (
            ("scripts/a.sh", "`cdk ... deploy`"),
            ("scripts/a.sh", "`terraform ... apply`"),
        ),
    ),
    (
        "a folded YAML run scalar is one command",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: >\n          npx cdk\n          deploy --all\n",
        },
        ((".github/workflows/w.yml", "`cdk ... deploy`"),),
    ),
    (
        "actions/github-script runs a multi-line exec.exec argv",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - uses: actions/github-script@0123456789abcdef0123456789abcdef01234567\n        with:\n          script: |\n            await exec.exec('npx', [\n              'cdk',\n              'deploy'])\n",
        },
        ((".github/workflows/w.yml", "`cdk ... deploy`"),),
    ),
    (
        "a two-parameter Python wrapper puts its words in parameter order",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef tool(name, *args):\n    subprocess.run([name, *args])\n\n\ntool("terraform", "apply")\n',
        },
        (("s.py", "`terraform ... apply`"),),
    ),
    (
        "an os.execlp wrapper with a program and its arguments",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import os\n\n\ndef tool(prog, *args):\n    os.execlp(prog, prog, *args)\n\n\ntool("terraform", "apply", "-auto-approve")\n',
        },
        (("s.py", "`terraform ... apply`"),),
    ),
    (
        "a Python wrapper adds fixed words around its parameter",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef cdk(action):\n    subprocess.run(["npx", "cdk", action, "--all"], check=True)\n\n\ncdk("deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python wrapper spreads its *args after fixed words",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef cdk(*args):\n    subprocess.run(["npx", "cdk", *args], check=True)\n\n\ncdk("deploy", "--all")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python wrapper builds an f-string around its parameter",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef cdk(action):\n    subprocess.run(f"npx cdk {action} --all", shell=True)\n\n\ncdk("deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a Python wrapper takes the program and its argument",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef run2(prog, arg):\n    subprocess.run([prog, arg])\n\n\nrun2("terraform", "apply")\n',
        },
        (("s.py", "`terraform ... apply`"),),
    ),
    (
        "functools.partial of a runner",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import functools\nimport subprocess\n\nsh = functools.partial(subprocess.run, shell=True)\nsh("npx cdk deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a lambda that hands its parameter to a runner",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\nsh = lambda c: subprocess.run(c, shell=True)  # noqa: E731\nsh("npx cdk deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a wrapper through a keyword-only parameter",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef sh(*, command):\n    subprocess.run(["npx", "cdk", command])\n\n\nsh(command="deploy")\n',
        },
        (("s.py", "`cdk ... deploy`"),),
    ),
    (
        "a wrapper of a wrapper with fixed words at each level",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\n\ndef run(*argv):\n    subprocess.run(["npx", *argv])\n\n\ndef cdk(action):\n    run("cdk", action)\n\n\ncdk("destroy")\n',
        },
        (("s.py", "`cdk ... destroy`"),),
    ),
    (
        "an argv built up with append and +=",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD + "      - run: python3 s.py\n",
            "s.py": 'import subprocess\n\ncmd = ["npx", "cdk"]\ncmd.append("deploy")\nargs = ["terraform"]\nargs += ["apply"]\nsubprocess.run(cmd)\nsubprocess.run(args)\n',
        },
        (
            ("s.py", "`cdk ... deploy`"),
            ("s.py", "`terraform ... apply`"),
        ),
    ),
    (
        "another action's script: block is shell, not JavaScript",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - uses: appleboy/ssh-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          script: |\n            # restart (prod\n            npx cdk deploy\n",
        },
        ((".github/workflows/w.yml", "`cdk ... deploy`"),),
    ),
    (
        "one word that names two scripts, each followed in a fixed order",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: docker run -v scripts/a.sh:scripts/b.sh:ro img\n",
            "scripts/a.sh": "#!/bin/sh\nnpx cdk deploy\n",
            "scripts/b.sh": "#!/bin/sh\nterraform apply\n",
        },
        (
            ("scripts/a.sh", "`cdk ... deploy`"),
            ("scripts/b.sh", "`terraform ... apply`"),
        ),
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
        "nested template literals and a regex after if (...) read as balanced",
        {
            ".github/workflows/w.yml": WORKFLOW_HEAD
            + "      - run: node scripts/ok.js\n",
            "scripts/ok.js": "const a = `${[1, 2].map((v) => `(${v}`)}`;\nif (a) /\\(/.test(a);\nconst b = 4 / 2 / 1;\nconsole.log(a, b);\n",
        },
        "scripts/ok.js",
    ),
    (
        "a list outside a matrix is not run",
        {
            ".github/workflows/w.yml": "on:\n  push:\n    paths:\n      - scripts/d.sh\n"
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n"
            "        os: [ubuntu-latest]\n    steps:\n      - run: bash scripts/ok.sh\n",
            "scripts/d.sh": "#!/bin/sh\ncdk deploy\n",
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
