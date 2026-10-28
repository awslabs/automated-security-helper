# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which CI blocks each runner leg of the Docs CI Runners workflow runs.

WHY THIS EXISTS
---------------
The Docs CI Runners workflow runs the CI pages' pipelines with their CI systems' own
runners, one matrix leg per runner and page. A block can stop running without anything
failing: a marker edit that turns it into a fragment of nothing, a kind that loses its
runner, a page that moves. So ``ci_runner_census`` in scripts/docs_checks.py says, for a
set of pages, every leg's blocks, and the blocks no runner runs (``runner=none``, with
its reason) and the ones only the static checks read (a kind with no local runner).
This file compares that census with an exact list for the real corpus, so a block that
stops running fails the unit suite, and with a second count made here without the
parser, so every CI block is in exactly one class.

The legs: ``act`` once per page with GitHub Actions blocks, ``gitlab-ci-local``,
``jenkinsfile-runner-lts`` and ``jenkinsfile-runner-bundled`` (both run each
Jenkinsfile, on two Jenkins cores), ``codebuild-agent`` and ``circleci``.

A block's census entry also carries the event its runner emulates (the marker's
``event=``, else ``pull_request`` for a workflow that triggers on it, else ``push``; a
GitLab pipeline is a ``push`` pipeline unless marked ``merge_request``; the other kinds
have none), and whether its scan is limited to changed files. That is read from the
pipeline, never from a marker key, so it cannot drift from the page: an ``ash`` command
with ``--changed-files-only``, one taking ``"$@"`` after the script's own ``set --``
put that option in the positional parameters (followed in script order: a set --
behind ``then`` or a case pattern counts, a later plain ``set --`` resets only
outside every if and case, an ash before any set -- never had them), or a call to
the reusable scan workflow with its ``changed-files-only`` input true.

The exact list below is the corpus once the CI pages carry their runner markers:
save-as and extends on the fragments and the pipelines they extend, ``event=`` on the
GitLab merge request fragment, ``runner=none`` on the two blocks that are part of a
larger file, the Jenkinsfile marked as one, and the CircleCI section.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FENCE = "```"

CI_KINDS = frozenset(
    {
        "github-actions",
        "gitlab-ci",
        "buildspec",
        "azure-pipelines",
        "jenkins",
        "jenkinsfile",
        "circleci",
    }
)
LEG_RUNNERS = frozenset(
    {
        "act",
        "gitlab-ci-local",
        "jenkinsfile-runner-lts",
        "jenkinsfile-runner-bundled",
        "codebuild-agent",
        "circleci",
    }
)


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _checks():
    return _load("_ash_docs_checks", REPO_ROOT / "scripts" / "docs_checks.py")


def _census(pages):
    checks = _checks()
    if not hasattr(checks, "ci_runner_census"):
        pytest.fail(
            "scripts/docs_checks.py defines no ci_runner_census, the list of the CI "
            "blocks each runner leg runs"
        )
    return checks.ci_runner_census(pages)


def _row(entry) -> tuple:
    return (
        entry.page,
        entry.line,
        entry.kind,
        entry.composed_from,
        entry.event,
        entry.changed_files,
    )


def _legs(census) -> dict[tuple[str, str], list[tuple]]:
    return {
        leg: [_row(entry) for entry in entries] for leg, entries in census.legs.items()
    }


# ---------------------------------------------------------------------------
# A synthetic corpus: every class and every rule, on pages written here
# ---------------------------------------------------------------------------


def _page(blocks: list[tuple[str, str, str]]) -> tuple[str, list[int]]:
    """The text of a page of (marker, body, language) blocks, and each fence's line."""
    lines: list[str] = ["# Page", ""]
    fences = []
    for marker, body, lang in blocks:
        if marker:
            lines.append(f"<!-- doctest: {marker} -->")
        fences.append(len(lines) + 1)
        lines += [f"{FENCE}{lang}", *body.rstrip("\n").split("\n"), FENCE, ""]
    return "\n".join(lines), fences


WORKFLOW = """\
name: ASH
on:
  pull_request:
  push:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - name: Run ASH
        run: ash scan --mode local --no-progress
"""
CHANGED_FILES_STEPS = """\
- name: Run ASH
  run: ash scan --mode local --no-progress --changed-files-only --base-ref origin/main
"""
CONDITIONAL_CHANGED_STEPS = """\
- name: Run ASH
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    set --
    if [ -n "${BASE_REF}" ]; then
      set -- --changed-files-only --base-ref "origin/${BASE_REF}"
    fi
    ash scan --mode local --no-progress "$@"
"""
POSITIONALS_WITHOUT_THE_FLAG = """\
- name: Run ASH
  run: |
    set -- --no-progress
    ash scan --mode local "$@"
"""
CONDITIONAL_ON_ONE_LINE_STEPS = """\
- name: Run ASH
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    if [ -n "${BASE_REF}" ]; then set -- --changed-files-only --base-ref "origin/${BASE_REF}"; fi
    ash scan --mode local --no-progress "$@"
"""
RESET_POSITIONALS_STEPS = """\
- name: Run ASH
  run: |
    set -- --changed-files-only
    set --
    ash scan --mode local --no-progress "$@"
"""
ASH_BEFORE_THE_SET_STEPS = """\
- name: Run ASH
  run: |
    ash scan --mode local --no-progress "$@"
    set -- --changed-files-only
"""
IF_ELIF_ELSE_RESET_STEPS = """\
- name: Run ASH
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    if [ -n "${BASE_REF}" ]; then
      set -- --changed-files-only --base-ref "origin/${BASE_REF}"
    elif [ -n "${FALLBACK_REF}" ]; then
      set -- --changed-files-only --base-ref "${FALLBACK_REF}"
    else
      set --
    fi
    ash scan --mode local --no-progress "$@"
"""
CASE_ARM_RESET_STEPS = """\
- name: Run ASH
  run: |
    set -- --changed-files-only
    case "${EVENT}" in
      push) set -- ;;
      *) : ;;
    esac
    ash scan --mode local --no-progress "$@"
"""
CASE_ARM_SETS_THE_FLAG_STEPS = """\
- name: Run ASH
  run: |
    set --
    case "${EVENT}" in
      pull_request) set -- --changed-files-only --base-ref "origin/${BASE_REF}" ;;
    esac
    ash scan --mode local --no-progress "$@"
"""
ACCUMULATED_POSITIONALS_STEPS = """\
- name: Run ASH
  run: |
    set -- --changed-files-only
    set -- "$@" --base-ref origin/main
    ash scan --mode local --no-progress "$@"
"""
REPLACED_AFTER_THE_FLAG_STEPS = """\
- name: Run ASH
  run: |
    set -- --changed-files-only
    set -- --base-ref origin/main
    ash scan --mode local --no-progress "$@"
"""
PUSH_ONLY_REUSABLE = """\
on:
  push:
jobs:
  ash:
    uses: awslabs/automated-security-helper/.github/workflows/run-ash-security-scan.yml@main
    with:
      changed-files-only: true
"""
REUSABLE_FULL = """\
on:
  pull_request:
jobs:
  ash:
    uses: awslabs/automated-security-helper/.github/workflows/run-ash-security-scan.yml@main
    with:
      changed-files-only: false
"""
ECHOES_THE_FLAG = """\
on:
  pull_request:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - run: echo "--changed-files-only is not passed here"
      - run: ash scan --mode local --no-progress
"""
AZURE = "steps:\n  - script: ash scan --mode local --no-progress\n"
GITLAB = "ash-scan:\n  image: python:3.12\n  script:\n    - ash scan --mode local\n"
GITLAB_MR = """\
ash-scan:
  script:
    - ash scan --mode local --changed-files-only --base-ref "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
"""
JENKINS_YAML = "pipeline:\n  steps:\n    - sh: ash scan --mode local\n"
JENKINSFILE = "pipeline {\n  agent any\n  stages { stage('ASH') { steps { sh 'ash scan --mode local' } } }\n}\n"
BUILDSPEC = (
    "version: 0.2\nphases:\n  build:\n    commands:\n      - ash scan --mode local\n"
)
CIRCLECI = "version: 2.1\njobs:\n  ash:\n    docker:\n      - image: cimg/python:3.12-node\n    steps:\n      - run: ash scan --mode local\n"

A_PAGE = [
    ("config kind=github-actions save-as=.github/workflows/ash.yml", WORKFLOW, "yaml"),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        CHANGED_FILES_STEPS,
        "yaml",
    ),
    (
        (
            "config kind=github-actions runner=none reason=\"needs the repository's "
            'code scanning"'
        ),
        WORKFLOW,
        "yaml",
    ),
    ("config kind=azure-pipelines", AZURE, "yaml"),
    ("config kind=github-actions", PUSH_ONLY_REUSABLE, "yaml"),
    ("config kind=github-actions", REUSABLE_FULL, "yaml"),
    ("config kind=github-actions", ECHOES_THE_FLAG, "yaml"),
    ("config kind=github-actions event=push", WORKFLOW, "yaml"),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        CONDITIONAL_CHANGED_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        POSITIONALS_WITHOUT_THE_FLAG,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        CONDITIONAL_ON_ONE_LINE_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        RESET_POSITIONALS_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        ASH_BEFORE_THE_SET_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        IF_ELIF_ELSE_RESET_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        CASE_ARM_RESET_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        CASE_ARM_SETS_THE_FLAG_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        ACCUMULATED_POSITIONALS_STEPS,
        "yaml",
    ),
    (
        "config kind=github-actions extends=.github/workflows/ash.yml",
        REPLACED_AFTER_THE_FLAG_STEPS,
        "yaml",
    ),
    ("", "global_settings:\n  severity_threshold: HIGH\n", "yaml"),
]
B_PAGE = [
    ("config kind=gitlab-ci save-as=.gitlab-ci.yml", GITLAB, "yaml"),
    (
        "config kind=gitlab-ci extends=.gitlab-ci.yml event=merge_request",
        GITLAB_MR,
        "yaml",
    ),
    ("config kind=jenkins", JENKINS_YAML, "yaml"),
]
C_PAGE = [
    ("config kind=jenkinsfile", JENKINSFILE, "groovy"),
    ("config kind=buildspec", BUILDSPEC, "yaml"),
    ("config kind=circleci", CIRCLECI, "yaml"),
    ('config kind=circleci runner=none reason="uses a private orb"', CIRCLECI, "yaml"),
    ("", JENKINSFILE, "groovy"),  # unmarked: not a CI block
]


def test_the_census_of_a_synthetic_corpus(tmp_path):
    texts = {}
    lines = {}
    for rel, blocks in (
        ("docs/a.md", A_PAGE),
        ("docs/b.md", B_PAGE),
        ("docs/c.md", C_PAGE),
        ("docs/c.md.template", C_PAGE),
    ):
        texts[rel], lines[rel] = _page(blocks)
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(texts[rel], encoding="utf-8")
    checks = _checks()
    pages = checks.load_pages(sorted(tmp_path.rglob("*.md*")), tmp_path)
    census = _census(pages)
    a, b, c = lines["docs/a.md"], lines["docs/b.md"], lines["docs/c.md"]
    assert _legs(census) == {
        ("act", "docs/a.md"): [
            ("docs/a.md", a[0], "github-actions", None, "pull_request", False),
            ("docs/a.md", a[1], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[4], "github-actions", None, "push", True),
            ("docs/a.md", a[5], "github-actions", None, "pull_request", False),
            ("docs/a.md", a[6], "github-actions", None, "pull_request", False),
            ("docs/a.md", a[7], "github-actions", None, "push", False),
            ("docs/a.md", a[8], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[9], "github-actions", a[0], "pull_request", False),
            ("docs/a.md", a[10], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[11], "github-actions", a[0], "pull_request", False),
            ("docs/a.md", a[12], "github-actions", a[0], "pull_request", False),
            ("docs/a.md", a[13], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[14], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[15], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[16], "github-actions", a[0], "pull_request", True),
            ("docs/a.md", a[17], "github-actions", a[0], "pull_request", False),
        ],
        ("gitlab-ci-local", "docs/b.md"): [
            ("docs/b.md", b[0], "gitlab-ci", None, "push", False),
            ("docs/b.md", b[1], "gitlab-ci", b[0], "merge_request", True),
        ],
        ("jenkinsfile-runner-lts", "docs/c.md"): [
            ("docs/c.md", c[0], "jenkinsfile", None, None, False),
        ],
        ("jenkinsfile-runner-bundled", "docs/c.md"): [
            ("docs/c.md", c[0], "jenkinsfile", None, None, False),
        ],
        ("codebuild-agent", "docs/c.md"): [
            ("docs/c.md", c[1], "buildspec", None, None, False),
        ],
        ("circleci", "docs/c.md"): [("docs/c.md", c[2], "circleci", None, None, False)],
    }, "a .md.template is run through its rendered page, so it has no leg of its own"
    assert [(e.page, e.line, e.kind, e.reason) for e in census.runner_none] == [
        ("docs/a.md", a[2], "github-actions", "needs the repository's code scanning"),
        ("docs/c.md", c[3], "circleci", "uses a private orb"),
    ]
    assert [(e.page, e.line, e.kind) for e in census.static_only] == [
        ("docs/a.md", a[3], "azure-pipelines"),
        ("docs/b.md", b[2], "jenkins"),
    ]


# ---------------------------------------------------------------------------
# The real corpus
# ---------------------------------------------------------------------------


def _corpus_pages():
    gate = _load(
        "_ash_docs_gate_for_runner", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
    )
    return _checks().load_pages(gate.collect_md_files(), gate.REPO_ROOT)


_MARKER = re.compile(r"^\s*<!--\s*doctest:(.*?)-->\s*$")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def _counted_ci_blocks() -> dict[str, list[tuple[int, str]]]:
    """Each tracked .md page -> (fence line, kind) of its CI blocks, counted without the
    docs parser: a well-formed config marker naming a CI kind, on the line directly
    above an opening fence. Templates are left to their rendered pages."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found: dict[str, list[tuple[int, str]]] = {}
    for rel in sorted(filter(None, listed.split("\0"))):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        in_fence: tuple[str, int] | None = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            if in_fence is not None:
                char, length = in_fence
                if stripped and set(stripped) == {char} and len(stripped) >= length:
                    in_fence = None
                continue
            opened = _FENCE.match(line)
            if opened is None:
                continue
            fence = opened.group(1)
            if fence[0] == "`" and "`" in line.lstrip()[len(fence) :]:
                continue  # inline code, not a fence
            in_fence = (fence[0], len(fence))
            marker = _MARKER.match(lines[index - 1]) if index else None
            if marker is None:
                continue
            try:
                words = shlex.split(marker.group(1))
            except ValueError:
                continue
            keys = dict(word.split("=", 1) for word in words if "=" in word)
            if words and words[0] == "config" and keys.get("kind") in CI_KINDS:
                found.setdefault(rel, []).append((index + 1, keys["kind"]))
    return found


@pytest.fixture(scope="module")
def counted():
    found = _counted_ci_blocks()
    assert sum(len(v) for v in found.values()) >= 14, found
    return found


def _line(counted, page: str, ordinal: int, kind: str) -> int:
    """The fence line of the ordinal-th CI block (counting from 1) on a page."""
    blocks = counted.get(page, [])
    assert len(blocks) >= ordinal, f"{page} has {len(blocks)} CI blocks: {blocks}"
    line, counted_kind = blocks[ordinal - 1]
    assert counted_kind == kind, (
        f"{page} CI block {ordinal} is {counted_kind}, not {kind}"
    )
    return line


CI_PAGE = "docs/content/getting-started/ci.md"
GHA_PAGE = "docs/content/how-to/ci/github-actions.md"
SHARDS_PAGE = "docs/content/how-to/scale-large-repos.md"
GITLAB_PAGE = "docs/content/how-to/ci/gitlab-ci.md"
OTHER_PAGE = "docs/content/how-to/ci/other-ci.md"
EXPORT_PAGE = "docs/content/how-to/export-reports.md"
CODEBUILD_EXAMPLE = "examples/AWSCodeBuild/README.md"

#: Leg -> its blocks, as (ordinal of the block among the page's CI blocks, kind,
#: ordinal of the block it extends, event, scans changed files only).
EXPECTED_LEGS = {
    ("act", CI_PAGE): [
        (1, "github-actions", None, "pull_request", False),
        (2, "github-actions", 1, "pull_request", False),
    ],
    ("act", GHA_PAGE): [
        (1, "github-actions", None, "pull_request", False),
        (2, "github-actions", None, "pull_request", False),
        (3, "github-actions", 2, "pull_request", False),
        (4, "github-actions", 2, "pull_request", True),
    ],
    ("act", SHARDS_PAGE): [(1, "github-actions", None, "pull_request", False)],
    ("gitlab-ci-local", GITLAB_PAGE): [
        (1, "gitlab-ci", None, "push", False),
        (2, "gitlab-ci", None, "push", False),
        (3, "gitlab-ci", 1, "merge_request", True),
    ],
    ("jenkinsfile-runner-lts", OTHER_PAGE): [(1, "jenkinsfile", None, None, False)],
    ("jenkinsfile-runner-bundled", OTHER_PAGE): [(1, "jenkinsfile", None, None, False)],
    ("codebuild-agent", OTHER_PAGE): [(2, "buildspec", None, None, False)],
    ("circleci", OTHER_PAGE): [(4, "circleci", None, None, False)],
}
#: (page, ordinal, kind) of the blocks marked runner=none, and of the static-only ones.
EXPECTED_RUNNER_NONE = [
    (EXPORT_PAGE, 1, "github-actions"),
    (CODEBUILD_EXAMPLE, 1, "buildspec"),
]
EXPECTED_STATIC_ONLY = [(OTHER_PAGE, 3, "azure-pipelines")]


def test_the_census_of_the_corpus_is_exactly_the_blocks_each_leg_runs(counted):
    """Red until the CI pages carry their runner markers (the Jenkinsfile marker, the
    CircleCI section, save-as/extends/event and runner=none); exact after that, so a
    block that stops running, or a new one, changes this list in the same commit."""
    census = _census(_corpus_pages())
    expected = {
        leg: [
            (
                leg[1],
                _line(counted, leg[1], ordinal, kind),
                kind,
                None if base is None else _line(counted, leg[1], base, kind),
                event,
                changed,
            )
            for ordinal, kind, base, event, changed in rows
        ]
        for leg, rows in EXPECTED_LEGS.items()
    }
    assert _legs(census) == expected
    assert [(e.page, e.line, e.kind) for e in census.runner_none] == [
        (page, _line(counted, page, ordinal, kind), kind)
        for page, ordinal, kind in EXPECTED_RUNNER_NONE
    ]
    for entry in census.runner_none:
        assert _checks()._reason_problem(entry.reason) is None, (
            entry.page,
            entry.reason,
        )
    assert [(e.page, e.line, e.kind) for e in census.static_only] == [
        (page, _line(counted, page, ordinal, kind), kind)
        for page, ordinal, kind in EXPECTED_STATIC_ONLY
    ]


def test_every_ci_block_of_the_corpus_is_in_exactly_one_class(counted):
    """Whatever the pages hold: each CI block the count here finds is run by some leg,
    marked runner=none, or static-only, and in only one of those."""
    census = _census(_corpus_pages())
    ran = {(e.page, e.line) for entries in census.legs.values() for e in entries}
    none = [(e.page, e.line) for e in census.runner_none]
    static = [(e.page, e.line) for e in census.static_only]
    assert len(none) == len(set(none)) and len(static) == len(set(static))
    assert (
        not (ran & set(none))
        and not (ran & set(static))
        and not (set(none) & set(static))
    )
    every = {(page, line) for page, blocks in counted.items() for line, _ in blocks}
    classified = ran | set(none) | set(static)
    assert classified == every, (
        f"CI blocks in no class: {sorted(every - classified)}; "
        f"entries that are not CI blocks: {sorted(classified - every)}"
    )
    assert {runner for runner, _page in census.legs} <= LEG_RUNNERS
    for (runner, page), entries in census.legs.items():
        assert entries, f"leg {runner} on {page} runs nothing"
        assert all(e.page == page for e in entries), (runner, page)
