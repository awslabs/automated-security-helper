#!/usr/bin/env python3
"""Fail when any workflow or composite action can deploy infrastructure.

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

Every `*.yml` / `*.yaml` under .github/workflows and .github/actions. Each file is
read as text, comment lines are dropped, backslash-continued lines are joined,
and each line is split into commands at `&&`, `||`, `;`, `|` and `&`. Each
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
  * `sam` followed later by `deploy` or `delete`.

It also refuses `uses:` of the CloudFormation deploy action
(aws-actions/aws-cloudformation-github-deploy).

Whole tokens, not substrings, because this repository is full of paths that
contain the words: `deploy/cdk-constructs`, `terraform-hygiene`. A substring
match would fire on all of them and train people to ignore it. The basename rule
does read a directory such as `deploy/cdk` as `cdk`, so a command that names that
directory and later has a bare `deploy` argument is flagged; that errs toward a
red run, and no workflow here has that shape.

KNOWN LIMITS

It reads the workflow text. A deploy hidden behind a script the workflow calls,
or assembled from variables at run time, is not seen. The workflows that touch
deploy/ call `npx cdk synth`, `terraform init -backend=false` / `validate` and
Python scripts under deploy/tests, all of which are read-only.

Run with --self-test to feed it planted deploy commands and planted look-alikes.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
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
}

DEPLOY_ACTIONS = ("aws-actions/aws-cloudformation-github-deploy",)

# `&&` and `||` before their single-character forms; a lone `&` backgrounds a job,
# which still runs it, so it ends a command the same way `;` does.
SEPARATORS = re.compile(r"&&|\|\||;|\||&")

# Other names the same tool runs under, after normalize_tool().
TOOL_ALIASES = {
    "aws-cdk": "cdk",  # the npm package: `npx aws-cdk deploy`
    "tofu": "terraform",  # OpenTofu takes terraform's subcommands
}
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s@]+)")


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    text: str
    reason: str


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


def deploy_reason(command: str) -> str | None:
    """Why `command` is a deploy, or None."""
    tokens = [t.strip("'\"") for t in command.split()]
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


def scan_repo(root: Path) -> tuple[list[Hit], int]:
    hits: list[Hit] = []
    scanned = 0
    for directory in SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(
            p for p in base.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file()
        ):
            scanned += 1
            hits.extend(
                scan_text(str(path.relative_to(root)), path.read_text(encoding="utf-8"))
            )
    return hits, scanned


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
    # OpenTofu is a drop-in for terraform.
    "run: tofu apply",
    "run: tofu -chdir=deploy/terraform destroy -auto-approve",
    "- uses: aws-actions/aws-cloudformation-github-deploy@0123456789abcdef0123456789abcdef01234567",
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
)


def self_test() -> int:
    failures = []
    for planted in PLANTED_DEPLOYS:
        if not scan_text("planted.yml", planted):
            failures.append(f"not caught: {planted!r}")
    for look_alike in LOOK_ALIKES:
        hits = scan_text("look-alike.yml", look_alike)
        if hits:
            failures.append(f"false positive: {look_alike!r} -> {hits[0].reason}")
    for failure in failures:
        print(f"SELF-TEST FAIL: {failure}")
    if failures:
        return 1
    print(
        f"self-test passed: {len(PLANTED_DEPLOYS)} planted deploys caught, {len(LOOK_ALIKES)} look-alikes passed"
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

    hits, scanned = scan_repo(args.root)
    if scanned == 0:
        print(
            f"::error::no workflow or action files found under {', '.join(SCAN_DIRS)} in {args.root}; nothing was checked"
        )
        return 1
    for hit in hits:
        print(
            f"::error file={hit.path},line={hit.line}::{hit.reason} deploys infrastructure; CI here must stay offline: {hit.text}"
        )
    if hits:
        print(f"{len(hits)} deploy command(s) found in {scanned} file(s)")
        return 1
    print(f"no deploy command in {scanned} workflow/action file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
