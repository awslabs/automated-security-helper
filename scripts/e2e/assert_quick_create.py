#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Judge a rendered quick-create document against the hosting file it was rendered from.

    assert_quick_create.py --doc DOC --hosting HOSTING --addressing {path,virtual}
                           [--templates DIR] [--lint-cmd CMD]

This is the e2e verdict for the quick-create channel. It does not import
scripts/render_quick_create_links.py on purpose: the renderer's own `check` already
validates links with the renderer's code, and a second opinion built from the same
functions would agree with it whatever they both got wrong. Everything here is derived
from the hosting file, the committed templates and the URL specification.

What it asserts, for every console link in DOC:

* there is exactly one link per (committed template, launch region) pair, and nothing
  else, so a render that dropped a stack or a region fails;
* the console host and the ``?region=`` query name the same launch region, and the
  fragment opens the quick-create review page;
* ``templateURL`` is exactly the URL the requested addressing implies.
  ``path`` is ``https://s3.<bucket_region>.amazonaws.com/<bucket>/<key>``, which is the
  only form S3's TLS certificate covers for a bucket name containing a period.
  ``virtual`` is ``https://<bucket>.s3.<bucket_region>.amazonaws.com/<key>``;
* ``stackName`` is the stack the key names;
* every ``param_<Name>`` is a parameter that template declares, is not NoEcho, and
  carries the template's declared Default. CloudFormation ignores an undeclared or
  NoEcho name without saying so, which is why this is checked from the template.

With ``--lint-cmd`` it then runs that command once per distinct template the links
name, as ``<cmd> <template> --regions <launch regions>``, and fails if any run exits
non-zero. The caller chooses the linter and its strictness; see scripts/e2e/quick_create.sh.
CMD is split with POSIX shell rules (``shlex.split``) on every platform, so a caller
builds it with ``shlex.join``; an unquoted Windows path would lose its backslashes. A
linter that cannot be started is a usage error.

Exit status: 0 when every assertion holds, 1 when one does not, 2 for a usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEMPLATES = REPO_ROOT / "deploy" / "cdk" / "templates"
TEMPLATE_SUFFIX = ".template.json"
REVIEW_MARKER = "/stacks/create/review?"

# Loose on purpose, so a malformed link is still found and reported instead of reading
# as absent.
CONSOLE_URL_RE = re.compile(
    r"https://[^\s)\]/]*console\.aws\.amazon\.com/cloudformation/home\?[^\s)\]]+"
)


class UsageError(Exception):
    """The inputs cannot be judged at all."""


def load_hosting(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hosting = {
        "bucket": str(data.get("bucket") or ""),
        "bucket_region": str(data.get("bucket_region") or ""),
        "key_prefix": str(data.get("key_prefix") or ""),
        "launch_regions": [str(r) for r in (data.get("launch_regions") or [])],
    }
    if not hosting["bucket"] or not hosting["bucket_region"]:
        raise UsageError(
            f"{path} configures no bucket or no bucket_region, so there are no links "
            "to judge."
        )
    if not hosting["launch_regions"]:
        raise UsageError(f"{path} lists no launch_regions.")
    return hosting


def load_templates(directory: Path) -> dict[str, dict[str, Any]]:
    stacks = {
        path.name[: -len(TEMPLATE_SUFFIX)]: json.loads(
            path.read_text(encoding="utf-8")
        ).get("Parameters")
        or {}
        for path in sorted(directory.glob(f"*{TEMPLATE_SUFFIX}"))
    }
    if not stacks:
        raise UsageError(f"no *{TEMPLATE_SUFFIX} under {directory}.")
    return stacks


def expected_template_url(hosting: dict[str, Any], stack: str, addressing: str) -> str:
    key = urllib.parse.quote(
        f"{hosting['key_prefix']}{stack}{TEMPLATE_SUFFIX}", safe="/"
    )
    bucket = hosting["bucket"]
    region = hosting["bucket_region"]
    if addressing == "path":
        return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def _noecho(spec: dict[str, Any]) -> bool:
    return str(spec.get("NoEcho", "")).strip().lower() == "true"


def judge_link(
    url: str,
    hosting: dict[str, Any],
    stacks: dict[str, dict[str, Any]],
    addressing: str,
) -> tuple[tuple[str, str] | None, int, list[str]]:
    """Judge one link. Returns ((stack, region) or None, params checked, problems)."""
    problems: list[str] = []
    prefix, sep, fragment = url.partition("#")
    if not sep or not fragment.startswith(REVIEW_MARKER):
        return None, 0, [f"{url}: fragment does not start with {REVIEW_MARKER!r}."]

    split = urllib.parse.urlsplit(prefix)
    host = split.hostname or ""
    host_region = (
        host[: -len(".console.aws.amazon.com")]
        if host.endswith(".console.aws.amazon.com")
        else ""
    )
    query_region = dict(urllib.parse.parse_qsl(split.query)).get("region", "")
    if not host_region or host_region != query_region:
        problems.append(
            f"{url}: console host {host!r} and ?region={query_region!r} do not name "
            "the same region."
        )
    if host_region not in hosting["launch_regions"]:
        problems.append(
            f"{url}: launch region {host_region!r} is not in launch_regions "
            f"{hosting['launch_regions']}."
        )

    try:
        fields = urllib.parse.parse_qsl(
            fragment[len(REVIEW_MARKER) :], keep_blank_values=True, strict_parsing=True
        )
    except ValueError as exc:
        return None, 0, problems + [f"{url}: query does not parse: {exc}."]
    names = [name for name, _ in fields]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        problems.append(f"{url}: repeats {', '.join(duplicated)}.")
    seen = dict(fields)

    template = seen.get("templateURL", "")
    key_name = urllib.parse.unquote(template.rsplit("/", 1)[-1])
    if not key_name.endswith(TEMPLATE_SUFFIX):
        return (
            None,
            0,
            problems + [f"{url}: templateURL {template!r} names no template."],
        )
    stack = key_name[: -len(TEMPLATE_SUFFIX)]
    if stack not in stacks:
        return (
            None,
            0,
            problems
            + [
                f"{url}: templateURL names {stack!r}, which is not a committed template."
            ],
        )

    want = expected_template_url(hosting, stack, addressing)
    if template != want:
        problems.append(
            f"{url}: templateURL is {template!r}; {addressing} addressing of "
            f"{hosting['bucket']!r} requires {want!r}."
        )
    if seen.get("stackName") != stack:
        problems.append(
            f"{url}: stackName is {seen.get('stackName')!r} but the template is {stack!r}."
        )

    params = stacks[stack]
    checked = 0
    for name, value in fields:
        if not name.startswith("param_"):
            if name not in ("templateURL", "stackName"):
                problems.append(f"{url}: unexpected query field {name!r}.")
            continue
        param = name[len("param_") :]
        spec = params.get(param)
        if spec is None:
            problems.append(f"{url}: {name} is not declared by {stack}.")
        elif _noecho(spec):
            problems.append(f"{url}: {name} is NoEcho on {stack}.")
        elif "Default" not in spec or str(spec["Default"]) != value:
            problems.append(
                f"{url}: {name}={value!r} but {stack} declares Default "
                f"{spec.get('Default')!r}."
            )
        else:
            checked += 1
    return (stack, host_region), checked, problems


def judge(
    text: str,
    hosting: dict[str, Any],
    stacks: dict[str, dict[str, Any]],
    addressing: str,
) -> tuple[dict[str, list[str]], int, list[str]]:
    """Judge a whole document. Returns (regions per stack, params checked, problems)."""
    urls = CONSOLE_URL_RE.findall(text)
    problems: list[str] = []
    pairs: list[tuple[str, str]] = []
    params = 0
    for url in urls:
        pair, checked, found = judge_link(url, hosting, stacks, addressing)
        problems.extend(found)
        params += checked
        if pair:
            pairs.append(pair)

    expected = {(s, r) for s in stacks for r in hosting["launch_regions"]}
    if len(urls) != len(expected):
        problems.append(
            f"found {len(urls)} console link(s); {len(stacks)} template(s) x "
            f"{len(hosting['launch_regions'])} region(s) requires {len(expected)}."
        )
    for stack, region in sorted(expected - set(pairs)):
        problems.append(f"no link launches {stack} in {region}.")
    for pair in sorted({p for p in pairs if pairs.count(p) > 1}):
        problems.append(f"more than one link launches {pair[0]} in {pair[1]}.")
    if params == 0:
        problems.append(
            "no param_ value was checked, so the parameter check is vacuous."
        )

    regions: dict[str, list[str]] = {}
    for stack, region in pairs:
        regions.setdefault(stack, [])
        if region not in regions[stack]:
            regions[stack].append(region)
    return regions, params, problems


def lint(
    lint_cmd: list[str], templates: Path, regions: dict[str, list[str]]
) -> list[str]:
    problems: list[str] = []
    for stack in sorted(regions):
        path = templates / f"{stack}{TEMPLATE_SUFFIX}"
        argv = [*lint_cmd, str(path), "--regions", *regions[stack]]
        try:
            result = subprocess.run(argv, check=False)
        except OSError as exc:
            raise UsageError(f"cannot run the linter {lint_cmd[0]!r}: {exc}") from exc
        print(f"lint {stack} in {' '.join(regions[stack])}: exit {result.returncode}")
        if result.returncode != 0:
            problems.append(
                f"{shlex.join(argv)} exited {result.returncode} for the template the "
                f"{stack} link launches."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--doc", type=Path, required=True)
    parser.add_argument("--hosting", type=Path, required=True)
    parser.add_argument("--addressing", choices=["path", "virtual"], required=True)
    parser.add_argument("--templates", type=Path, default=DEFAULT_TEMPLATES)
    parser.add_argument(
        "--lint-cmd",
        default="",
        help=(
            "linter command line, run once per template the links name; quoted the "
            "way a POSIX shell quotes on every platform (shlex), so a Windows path "
            "with backslashes must be quoted"
        ),
    )
    args = parser.parse_args(argv)

    try:
        hosting = load_hosting(args.hosting)
        stacks = load_templates(args.templates)
        text = args.doc.read_text(encoding="utf-8")
    except (OSError, ValueError, UsageError) as exc:
        print(f"USAGE: {exc}", file=sys.stderr)
        return 2

    regions, params, problems = judge(text, hosting, stacks, args.addressing)
    links = sum(len(r) for r in regions.values())
    print(
        f"bucket {hosting['bucket']!r}, {args.addressing} addressing: {links} link(s) "
        f"over {len(regions)} template(s), {params} param_ value(s) checked"
    )
    if args.lint_cmd and not problems:
        try:
            problems.extend(lint(shlex.split(args.lint_cmd), args.templates, regions))
        except UsageError as exc:
            print(f"USAGE: {exc}", file=sys.stderr)
            return 2

    if problems:
        print("quick-create e2e assertion FAILED:", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print("quick-create e2e assertion passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
