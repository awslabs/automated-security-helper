# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every command that gates a CI page's pipeline keeps its gate flags.

WHY THIS EXISTS
---------------
A pull request scan reads the configuration in the branch it scans. The CI pages say
that ``--fail-on-findings``, ``--fail-on-incomplete-scanners`` and
``--no-allow-stale-content-db`` on the command line keep that branch from turning the
gate off for findings, incomplete scans and stale content databases. A pipeline that
drops one of them still parses, still passes the docs checks, and still passes its
runner leg, whose fixture's configuration turns none of them off. So nothing else
fails when one goes missing.

WHAT IT READS
-------------
Every github-actions and gitlab-ci block of the docs, fragments and ``runner=none``
blocks included, and a .md.template twin as well as its page. Each block is read as
written, so a fragment is checked on the fragment. In each block:

- Each ``ash scan``, which needs all three flags.
- Each ``ash merge``, which needs the ones ``ash merge`` takes, read from its CLI:
  ``--fail-on-findings`` and ``--fail-on-incomplete-scanners``.
- Each job that calls run-ash-security-scan.yml. The workflow's scan step passes
  ``--fail-on-findings``, or ``--no-fail-on-findings`` when the job sets
  ``fail-on-findings: false``, and then the job's ``ash-args`` split on spaces, last.
  Together they need all three flags. A ``fail-on-findings`` value that is neither
  true nor false, such as an expression, passes neither flag here, so the call then
  needs ``--fail-on-findings`` in ``ash-args``.

When a command line holds both ``--fail-on-findings`` and ``--no-fail-on-findings``,
the last one applies, as click reads them. A command whose choice is
``--no-fail-on-findings`` does not gate and is not checked, except a shard (an
``ash scan`` with ``--shard-index``): the sharded example's merge job gives the
verdict, and a shard needs the gate flags ``ash merge`` does not take
(``--no-allow-stale-content-db``), because the shards' scanners read the content
databases.

The calls on getting-started/ci.md and its twin are not held to the flags:
MINIMAL_CALL_PAGES gives the reason.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

GATE_FLAGS = (
    "--fail-on-findings",
    "--fail-on-incomplete-scanners",
    "--no-allow-stale-content-db",
)
GATES_ON_FINDINGS = "--fail-on-findings"
NOT_GATING = "--no-fail-on-findings"
SHARD_INDEX = "--shard-index"
GATED_KINDS = frozenset({"github-actions", "gitlab-ci"})

GHA_PAGE = "docs/content/how-to/ci/github-actions.md"
GITLAB_PAGE = "docs/content/how-to/ci/gitlab-ci.md"
SHARDS_PAGE = "docs/content/how-to/scale-large-repos.md"

# What each entry of gating_scans is.
SCAN = "an ash scan"
SHARD_SCAN = "a shard's ash scan"
MERGE = "an ash merge"
CALL = "a call of run-ash-security-scan.yml"

#: Pages whose call of run-ash-security-scan.yml is not held to the gate flags. The
#: tutorial's workflow is the minimal call and passes no ash-args on purpose; the page
#: says that a pull request can change the rules it is judged by, and links to the
#: pages that hold the gate (platform-teams.md and how-to/set-the-gate.md).
MINIMAL_CALL_PAGES = frozenset(
    {
        "docs/content/getting-started/ci.md",
        "docs/content/getting-started/ci.md.template",
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


def _corpus_pages():
    gate = _load(
        "_ash_docs_gate_for_runner", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
    )
    return _checks().load_pages(gate.collect_md_files(), gate.REPO_ROOT)


def _page(rel: str, text: str):
    """The page ``rel`` parsed from ``text``, a scratch copy that is never written."""
    return _checks().parse_page(REPO_ROOT / rel, REPO_ROOT, text=text)


def _merge_flags() -> tuple[str, ...]:
    """The gate flags ``ash merge`` takes, read from the CLI (cli/merge.py)."""
    merge = _checks().load_cli().subcommands["merge"]
    return tuple(flag for flag in GATE_FLAGS if flag in merge.options)


def _workflow_calls(block) -> list[list[str]]:
    """The gate-flag part of the ``ash scan`` command line of each job in a
    github-actions block that calls run-ash-security-scan.yml: the fail-on-findings
    choice its scan step passes, then ``ash-args`` split on spaces, which it passes
    last."""
    checks = _checks()
    document, error = checks.parse_config_text(block.body, block.lang)
    if error is not None:
        return []
    calls = []
    for job in checks._dicts_with_key(document, "uses"):
        if not checks._calls_scan_workflow(str(job.get("uses"))):
            continue
        given = job.get("with") if isinstance(job.get("with"), dict) else {}
        choice = given.get("fail-on-findings", True)
        args = ["scan"]
        if choice is True:
            args.append(GATES_ON_FINDINGS)
        elif choice is False:
            args.append(NOT_GATING)
        calls.append(args + str(given.get("ash-args") or "").split())
    return calls


def _gate(args: list[str]) -> tuple[str, tuple[str, ...]] | None:
    """What an ash command line is and the gate flags it needs, or None if it needs
    none."""
    chosen = [arg for arg in args if arg in (GATES_ON_FINDINGS, NOT_GATING)]
    gates = not chosen or chosen[-1] == GATES_ON_FINDINGS
    if args[:1] == ["merge"]:
        return (MERGE, _merge_flags()) if gates else None
    if args[:1] != ["scan"]:
        return None
    if gates:
        return SCAN, GATE_FLAGS
    if any(arg == SHARD_INDEX or arg.startswith(f"{SHARD_INDEX}=") for arg in args):
        merge_flags = _merge_flags()
        return SHARD_SCAN, tuple(flag for flag in GATE_FLAGS if flag not in merge_flags)
    return None


def gating_scans(pages) -> list[tuple[str, int, str, list[str]]]:
    """(page, fence line of the block, what it is, the gate flags it lacks) of every
    command in the github-actions and gitlab-ci blocks of ``pages`` that the gate rests
    on: each ash scan and ash merge that gates, each shard's scan, and each call of
    run-ash-security-scan.yml that gates (see the module docstring).

    The ash commands are the ones the docs' CLI check reads (block_invocations): the
    ``run:`` scripts of a workflow, and the ``script:``, ``before_script:`` and
    ``after_script:`` lines of a GitLab job.
    """
    checks = _checks()
    found = []
    for page in pages:
        for block in page.blocks:
            marker = checks.ci_marker(block)
            if marker is None or marker.kind not in GATED_KINDS:
                continue
            invocations, _problems = checks.block_invocations(block, REPO_ROOT)
            commands = [(None, invocation.args) for invocation in invocations]
            if marker.kind == "github-actions":
                commands += [(CALL, args) for args in _workflow_calls(block)]
            for what, args in commands:
                gate = _gate(args)
                if gate is None:
                    continue
                missing = [flag for flag in gate[1] if flag not in args]
                found.append((page.rel, block.fence_line, what or gate[0], missing))
    return found


def _lacking(scans) -> list[tuple[str, int, list[str]]]:
    return [(page, line, missing) for page, line, _, missing in scans if missing]


@pytest.mark.integration
def test_every_gating_scan_on_the_ci_pages_keeps_the_gate_flags():
    scans = gating_scans(_corpus_pages())
    read = {(page, what) for page, _, what, _ in scans}
    expected = {
        (GHA_PAGE, CALL),
        (GHA_PAGE, SCAN),
        (GITLAB_PAGE, SCAN),
        (SHARDS_PAGE, SHARD_SCAN),
        (SHARDS_PAGE, MERGE),
    } | {(rel, CALL) for rel in MINIMAL_CALL_PAGES}
    assert expected <= read, f"none of these was read: {sorted(expected - read)}"
    on_pages = [scan for scan in scans if scan[0] in (GHA_PAGE, GITLAB_PAGE)]
    assert len(on_pages) >= 7, (
        "the GitHub Actions page holds a call of the scan workflow and three gating "
        "scans, and the GitLab CI page three gating scans; only these were read: "
        f"{on_pages}"
    )
    lacking = [
        (page, line, what, missing)
        for page, line, what, missing in scans
        if missing and not (page in MINIMAL_CALL_PAGES and what == CALL)
    ]
    assert not lacking, "\n".join(
        f"{page}: the block at line {line} holds {what} without {', '.join(missing)}, "
        "so a pull request's own config can turn that part of the gate off"
        for page, line, what, missing in lacking
    )


@pytest.mark.unit
@pytest.mark.parametrize("flag", GATE_FLAGS)
@pytest.mark.parametrize("rel", [GHA_PAGE, GITLAB_PAGE])
def test_a_gating_scan_that_drops_a_gate_flag_is_reported(rel, flag):
    """A scratch copy of the page whose last gating scan, the changed-files fragment's,
    lacks one flag is reported at that block, for that flag only."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    as_written = gating_scans([_page(rel, text)])
    assert len(as_written) >= 3 and not _lacking(as_written), as_written
    at = text.rindex(f" {flag}")
    dropped = text[:at] + text[at + len(flag) + 1 :]
    scans = gating_scans([_page(rel, dropped)])
    last = max(line for _, line, _, _ in scans)
    assert _lacking(scans) == [(rel, last, [flag])]


@pytest.mark.unit
def test_a_shard_scan_does_not_gate_until_it_drops_no_fail_on_findings():
    """The sharded example's shard scan, the page's last command with
    --no-fail-on-findings, is not held to the flags its merge job passes; without that
    flag it gates, and lacks the two flags it does not pass."""
    text = (REPO_ROOT / SHARDS_PAGE).read_text(encoding="utf-8")
    assert not _lacking(gating_scans([_page(SHARDS_PAGE, text)]))
    at = text.rindex(f" {NOT_GATING}")
    gated = text[:at] + text[at + len(NOT_GATING) + 1 :]
    lacking = _lacking(gating_scans([_page(SHARDS_PAGE, gated)]))
    assert [missing for _, _, missing in lacking] == [
        ["--fail-on-findings", "--fail-on-incomplete-scanners"]
    ]


# The lines the cells below change, each found once on its page.
CALL_ARGS_LINE = (
    "      ash-args: --fail-on-incomplete-scanners --no-allow-stale-content-db\n"
)
SHARD_LINE = (
    "          ash scan --mode local --no-progress --no-fail-on-findings "
    "--no-allow-stale-content-db \\\n"
)
MERGE_LINE = (
    "          ash merge --fail-on-findings --fail-on-incomplete-scanners "
    "--output-dir .ash/ash_output \\\n"
)


def _text_with(rel: str, line: str) -> str:
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert text.count(line) == 1, f"{rel} no longer holds this line once: {line!r}"
    return text


def _fence_of(rel: str, text: str, line: str) -> int:
    """The fence line of the block of ``rel``, parsed from ``text``, that holds ``line``."""
    (fence,) = [b.fence_line for b in _page(rel, text).blocks if line in b.body + "\n"]
    return fence


def _at(scans, fence: int) -> list[tuple[str, list[str]]]:
    return [(page, missing) for page, line, _, missing in scans if line == fence]


@pytest.mark.unit
def test_the_call_of_the_scan_workflow_is_read_with_the_flags_it_passes():
    """github-actions.md's call of run-ash-security-scan.yml: the workflow passes
    --fail-on-findings, since the call leaves fail-on-findings at its default, and
    ash-args passes the other two."""
    text = _text_with(GHA_PAGE, CALL_ARGS_LINE)
    fence = _fence_of(GHA_PAGE, text, CALL_ARGS_LINE)
    assert _at(gating_scans([_page(GHA_PAGE, text)]), fence) == [(GHA_PAGE, [])]


@pytest.mark.unit
@pytest.mark.parametrize("flag", GATE_FLAGS[1:])
def test_a_call_of_the_scan_workflow_that_drops_a_gate_flag_is_reported(flag):
    """A scratch copy whose ash-args line lacks one of its two flags is reported at that
    block, for that flag only."""
    text = _text_with(GHA_PAGE, CALL_ARGS_LINE)
    fence = _fence_of(GHA_PAGE, text, CALL_ARGS_LINE)
    dropped = text.replace(CALL_ARGS_LINE, CALL_ARGS_LINE.replace(f" {flag}", ""))
    assert _lacking(gating_scans([_page(GHA_PAGE, dropped)])) == [
        (GHA_PAGE, fence, [flag])
    ]


@pytest.mark.unit
def test_a_call_of_the_scan_workflow_without_its_ash_args_line_is_reported():
    text = _text_with(GHA_PAGE, CALL_ARGS_LINE)
    fence = _fence_of(GHA_PAGE, text, CALL_ARGS_LINE)
    deleted = text.replace(CALL_ARGS_LINE, "")
    assert _lacking(gating_scans([_page(GHA_PAGE, deleted)])) == [
        (GHA_PAGE, fence, list(GATE_FLAGS[1:]))
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("given", "read"),
    [
        ("      fail-on-findings: true\n" + CALL_ARGS_LINE, [(GHA_PAGE, [])]),
        ("      fail-on-findings: false\n" + CALL_ARGS_LINE, []),
        (
            "      fail-on-findings: false\n"
            + CALL_ARGS_LINE.replace("ash-args: ", "ash-args: --fail-on-findings "),
            [(GHA_PAGE, [])],
        ),
    ],
    ids=["true", "false", "false-then-ash-args"],
)
def test_the_fail_on_findings_input_is_read_as_the_workflow_passes_it(given, read):
    """true is the default, so the workflow passes --fail-on-findings. false makes it
    pass --no-fail-on-findings, and the call no longer gates, so the corpus test, which
    expects a gating call on the page, fails. ash-args comes last on the command line,
    so a --fail-on-findings there wins over false."""
    text = _text_with(GHA_PAGE, CALL_ARGS_LINE)
    fence = _fence_of(GHA_PAGE, text, CALL_ARGS_LINE)
    changed = text.replace(CALL_ARGS_LINE, given)
    assert _at(gating_scans([_page(GHA_PAGE, changed)]), fence) == read


@pytest.mark.unit
def test_ash_merge_takes_the_findings_and_incomplete_scan_flags():
    """ash merge runs no scanner, so it has no content database to check, and takes two
    of the three."""
    assert _merge_flags() == ("--fail-on-findings", "--fail-on-incomplete-scanners")


@pytest.mark.unit
def test_the_sharded_example_is_read_with_its_shard_and_merge():
    text = _text_with(SHARDS_PAGE, MERGE_LINE)
    fence = _fence_of(SHARDS_PAGE, text, MERGE_LINE)
    assert _fence_of(SHARDS_PAGE, _text_with(SHARDS_PAGE, SHARD_LINE), SHARD_LINE) == (
        fence
    )
    assert _at(gating_scans([_page(SHARDS_PAGE, text)]), fence) == [
        (SHARDS_PAGE, []),
        (SHARDS_PAGE, []),
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "flag", ["--fail-on-findings", "--fail-on-incomplete-scanners"]
)
def test_a_merge_that_drops_a_gate_flag_is_reported(flag):
    """The sharded example's merge job gives the verdict; a scratch copy whose ash merge
    lacks one of the flags ash merge takes is reported at that block, for that flag."""
    text = _text_with(SHARDS_PAGE, MERGE_LINE)
    fence = _fence_of(SHARDS_PAGE, text, MERGE_LINE)
    dropped = text.replace(MERGE_LINE, MERGE_LINE.replace(f" {flag}", ""))
    assert _lacking(gating_scans([_page(SHARDS_PAGE, dropped)])) == [
        (SHARDS_PAGE, fence, [flag])
    ]


@pytest.mark.unit
def test_a_shard_that_drops_no_allow_stale_content_db_is_reported():
    """ash merge cannot pass --no-allow-stale-content-db, so the shards that read the
    content databases have to."""
    text = _text_with(SHARDS_PAGE, SHARD_LINE)
    fence = _fence_of(SHARDS_PAGE, text, SHARD_LINE)
    dropped = text.replace(
        SHARD_LINE, SHARD_LINE.replace(" --no-allow-stale-content-db", "")
    )
    assert _lacking(gating_scans([_page(SHARDS_PAGE, dropped)])) == [
        (SHARDS_PAGE, fence, ["--no-allow-stale-content-db"])
    ]
