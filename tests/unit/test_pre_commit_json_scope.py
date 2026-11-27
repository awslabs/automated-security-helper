# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""pretty-format-json formats the JSON people write, and leaves alone the JSON tools write.

The hook runs with ``--autofix``, sorts keys and reindents. On a file another tool
generates, or one a gate compares byte for byte, that rewrite is a defect: the generator
undoes it, or the gate fails on it. ``pre-commit run --all-files`` on a clean checkout used
to rewrite 24 tracked files, every one of them data-identical, and to fail on one file it
could not parse. Measured by formatting each group and running the gate that owns it:

* ``ash-agent-plugins/agentic-coding/plugins/`` is the transpiler's output, and
  ``agentic-plugins check`` byte-compares it with a rebuild ("generated outputs differ
  from _base/ source." after the hook ran).
* ``transpiler/_base/mcp.json`` is copied byte for byte into five of those outputs, so it
  fails the same check once formatted.
* ``transpiler/schemas/*.schema.json`` are upstream schemas ``refresh-schemas`` writes as
  fetched.
* ``deploy/cdk/tsconfig.json`` has comments, so the hook cannot parse it.

The hand-written files among the 24 (``_base/manifest.json``, ``schemas/schemas.json``, two
deploy/ configs, a CI exclusion list and two test fixtures) were formatted once instead,
and stay in the hook's scope.

Four more files joined the exclusions later, each JSON a tool writes. Three are recordings
of scanner output under ``tests/test_data/scanners/*/captured/`` (the M0 runs of bandit and
cfn-lint, and trivy's terraform misconfig run) that are not in the hook's format, and whose
bytes the ``transcripts.json`` beside them pins by sha256: the hook would rewrite them and
fail the transcript gate. The fourth is the GitLab SAST projection golden under
``tests/unit/reporters/golden/``, which its test writes from the reporter and compares in
the writer's key order. They are listed one by one: the other recordings, and the golden
under ``tests/unit/utils/golden/`` (which its test compares as data), are in the hook's
format and stay in its scope.

Files are listed with ``git ls-files``, never by walking the tree.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.tool_transcript import (
    TRANSCRIPT_FILE_NAME,
    load_transcript_file,
)

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS = "ash-agent-plugins/agentic-coding/plugins/"
BASE_MCP = "ash-agent-plugins/agentic-coding/transpiler/_base/mcp.json"
SCANNER_FIXTURES = "tests/test_data/scanners"

#: The recordings of scanner output the hook must leave alone: not in its format, and
#: pinned by sha256 in the transcripts.json of their scanner's fixture directory, so a
#: rewrite fails tests/unit/plugin_conformance/
#: test_the_committed_transcripts_are_sound_and_fresh.py.
EXCLUDED_CAPTURES = (
    f"{SCANNER_FIXTURES}/bandit/captured/bandit-1.9.4-m0.json",
    f"{SCANNER_FIXTURES}/cfn_lint_guard/captured/cfn-lint-1.61.0-m0-bad-property.json",
    f"{SCANNER_FIXTURES}/trivy/captured/trivy-0.76.2-misconfig-terraform.json",
)

#: The GitLab SAST projection golden: its test writes it from the reporter and compares
#: ``json.dumps`` of it and of the reporter's output, so the key order is part of it.
GITLAB_SAST_GOLDEN = "tests/unit/reporters/golden/gitlab_sast_projection.json"

#: Generated, vendored, compared byte for byte, or not JSON at all.
MUST_BE_EXCLUDED = (
    BASE_MCP,
    "ash-agent-plugins/agentic-coding/transpiler/schemas/amazonq-agent.schema.json",
    "ash-agent-plugins/agentic-coding/transpiler/schemas/continue-config.schema.json",
    "ash-agent-plugins/agentic-coding/transpiler/schemas/mcpb-manifest.schema.json",
    "ash-agent-plugins/agentic-coding/transpiler/schemas/opencode-config.schema.json",
    "deploy/cdk/tsconfig.json",
    "deploy/cdk/package.json",
    "deploy/cdk/package-lock.json",
    *EXCLUDED_CAPTURES,
    GITLAB_SAST_GOLDEN,
)

#: JSON the hook must keep formatting: hand-written files, and the recordings and goldens
#: that are in its format or that their tests read as data.
MUST_BE_FORMATTED = (
    ".github/typescript-coverage-exclusions.json",
    "ash-agent-plugins/agentic-coding/transpiler/_base/manifest.json",
    "ash-agent-plugins/agentic-coding/transpiler/_base/cli_versions.json",
    "ash-agent-plugins/agentic-coding/transpiler/schemas/schemas.json",
    "deploy/cdk-constructs/tsconfig.dev.json",
    "deploy/cdk/cdk.json",
    "tests/integration/codecommit_gate_regression/expected.json",
    "tests/integration/codecommit_gate_regression/cases/observed-2026-08-28/observed.json",
    # A recording that is already in the hook's format, beside the three that are not.
    f"{SCANNER_FIXTURES}/cfn_lint_guard/captured/cfn-lint-1.57.2-m0-two-bad-properties.json",
    # A golden its test compares as data: ``json.loads`` of it must equal the observed output.
    "tests/unit/utils/golden/finding_diff_characterization.json",
)


#: Every family the hook may skip, and why. A tracked file it skips outside these is a
#: hand-written or generated-but-formatted file the exclude has swallowed, as a pattern
#: such as ``automated_security_helper/.*`` would.
EXCLUDED_FAMILIES = {
    r"(.*/)?\.vscode/.*": "editor settings, which allow comments",
    r"deploy/cdk/templates/.*\.template\.json": "cdk synth output, byte-compared",
    r"deploy/[^/]+/package(-lock)?\.json": "npm manifests",
    r"deploy/cdk/tsconfig\.json": "tsc config with comments",
    r"tests/snapshot/.*/__snapshots__/.*": "snapshot bytes",
    **{
        re.escape(path): (
            "recorded tool output, pinned by sha256 in the scanner's transcripts.json"
        )
        for path in EXCLUDED_CAPTURES
    },
    re.escape(GITLAB_SAST_GOLDEN): (
        "recorded from the reporter, and compared in the reporter's key order"
    ),
    r"ash-agent-plugins/agentic-coding/plugins/.*": "transpiler output, byte-compared",
    BASE_MCP.replace(".", r"\."): "copied byte for byte into transpiler output",
    r"ash-agent-plugins/agentic-coding/transpiler/schemas/.*\.schema\.json": "vendored",
}


def _tracked(*pathspecs: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", *pathspecs],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return [name for name in out.split("\0") if name]


@pytest.fixture(scope="module")
def excluded():
    config = yaml.safe_load(
        (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    hooks = [
        hook
        for repo in config["repos"]
        for hook in repo["hooks"]
        if hook["id"] == "pretty-format-json"
    ]
    assert len(hooks) == 1, hooks
    # pre-commit applies `exclude` with re.search against the repository-relative path.
    pattern = re.compile(hooks[0]["exclude"])
    return lambda path: pattern.search(path) is not None


@pytest.fixture(scope="module")
def tracked_json():
    """Every tracked file pre-commit would hand the hook, before its exclude.

    pre-commit selects a hook's files by identify's tags (pretty-format-json declares
    ``types: [json]``), which include Jupyter notebooks and leave out symlinks, so this
    asks identify rather than matching ``*.json``.
    """
    from identify.identify import tags_from_path

    names = [
        name
        for name in _tracked()
        if os.path.lexists(REPO_ROOT / name)
        and "json" in tags_from_path(str(REPO_ROOT / name))
    ]
    assert len(names) > 50, f"identify tagged only {len(names)} tracked files json"
    return names


#: Tracked files identify tags json without a .json name; the hook is given these too.
JSON_WITHOUT_A_JSON_NAME = (
    "tests/test_data/finding_samples/ipynb.ipynb",
    "tests/test_data/jupyter/test.ipynb",
)


@pytest.mark.parametrize("path", JSON_WITHOUT_A_JSON_NAME)
def test_the_files_in_scope_are_the_ones_pre_commit_selects(tracked_json, path):
    """pre-commit picks the hook's files by identify's ``json`` tag, not by name.

    The tag covers Jupyter notebooks, so these tests have to as well, or a notebook the
    hook would rewrite passes them.
    """
    assert path in tracked_json, f"{path} is json to pre-commit but not to this test"


@pytest.mark.parametrize("path", MUST_BE_EXCLUDED)
def test_generated_and_compared_files_are_left_alone(excluded, tracked_json, path):
    assert path in tracked_json, f"{path} is no longer tracked; update this list"
    assert excluded(path), f"pretty-format-json would rewrite {path}"


@pytest.mark.parametrize("path", MUST_BE_FORMATTED)
def test_hand_written_files_are_formatted(excluded, tracked_json, path):
    assert path in tracked_json, f"{path} is no longer tracked; update this list"
    assert not excluded(path), (
        f"{path} is JSON the hook has to keep formatting, and it no longer does"
    )


def test_the_hook_skips_nothing_outside_the_known_families(excluded, tracked_json):
    skipped = [p for p in tracked_json if excluded(p)]
    assert skipped, "the exclude matches nothing; read the wrong hook?"
    unexplained = [
        p
        for p in skipped
        if not any(re.fullmatch(family, p) for family in EXCLUDED_FAMILIES)
    ]
    assert not unexplained, (
        f"pretty-format-json skips {unexplained[:10]}"
        f"{' ...' if len(unexplained) > 10 else ''}, which belong to no generated, "
        "vendored or byte-compared family. Narrow the exclude, or add the family here "
        "with its reason."
    )


def _why_no_transcript_pins(root: Path, path: str) -> str | None:
    """Why no ``transcripts.json`` pins the recording at ``path``, or None when one does.

    ``path`` is relative to ``root`` and has the shape the scanners' fixtures have,
    ``tests/test_data/scanners/<scanner>/captured/<file>``. A recording is pinned when the
    transcripts.json of its scanner's directory names it, as a result or a side report;
    every such entry carries the sha256 of the file, and the plugin_conformance gate
    refuses a file whose bytes differ from it.
    """
    scanner = root.joinpath(*Path(path).parts[:4])
    relative = "/".join(Path(path).parts[4:])
    transcript_file = scanner / TRANSCRIPT_FILE_NAME
    if not transcript_file.is_file():
        return f"{scanner.name} has no {TRANSCRIPT_FILE_NAME}"
    pinned = {
        entry.path
        for transcript in load_transcript_file(transcript_file).transcripts
        for entry in (*transcript.results, *transcript.side_reports)
    }
    if relative not in pinned:
        return f"{scanner.name}/{TRANSCRIPT_FILE_NAME} names no recording {relative}"
    return None


def test_every_recording_the_hook_skips_is_pinned_by_its_transcripts(
    excluded, tracked_json
):
    """The reason for skipping a recording is that a transcript pins its bytes.

    Without that reason a recording is just JSON in the wrong format, and the hook should
    format it. This reads every tracked recording the exclude skips, whatever pattern
    skips it, so a recording added to the exclude without a transcript fails here.
    """
    skipped = [
        p
        for p in tracked_json
        if excluded(p) and re.fullmatch(rf"{SCANNER_FIXTURES}/[^/]+/captured/.+", p)
    ]
    assert skipped, "the exclude skips no recording; this test checks nothing"
    unpinned = {}
    for path in skipped:
        why = _why_no_transcript_pins(REPO_ROOT, path)
        if why:
            unpinned[path] = why
    assert not unpinned, unpinned


def test_the_pin_check_refuses_a_recording_no_transcript_names(tmp_path):
    """Must-flag and must-not-flag through the real transcripts file.

    A copy of bandit's fixture directory holds the transcripts.json as committed. The
    recording it names passes, whatever its bytes; one it does not name, and one in a
    directory with no transcripts.json, are each refused.
    """
    scanner = tmp_path.joinpath(*SCANNER_FIXTURES.split("/"), "bandit")
    (scanner / "captured").mkdir(parents=True)
    shutil.copyfile(
        REPO_ROOT / SCANNER_FIXTURES / "bandit" / TRANSCRIPT_FILE_NAME,
        scanner / TRANSCRIPT_FILE_NAME,
    )
    named = f"{SCANNER_FIXTURES}/bandit/captured/bandit-1.9.4-m0.json"
    unnamed = f"{SCANNER_FIXTURES}/bandit/captured/recorded-by-nobody.json"
    bare = f"{SCANNER_FIXTURES}/unrecorded/captured/recorded-by-nobody.json"
    for path in (named, unnamed, bare):
        planted = tmp_path / path
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text("{}\n", encoding="utf-8")

    assert _why_no_transcript_pins(tmp_path, named) is None
    assert "names no recording" in (_why_no_transcript_pins(tmp_path, unnamed) or "")
    assert "has no transcripts.json" in (_why_no_transcript_pins(tmp_path, bare) or "")


def test_every_generated_plugin_file_is_left_alone(excluded, tracked_json):
    generated = [p for p in tracked_json if p.startswith(PLUGINS)]
    assert len(generated) >= 10, f"found only {generated} under {PLUGINS}"
    formatted = [p for p in generated if not excluded(p)]
    assert not formatted, (
        f"the transpiler writes {formatted} and agentic-plugins check compares them "
        "byte for byte with a rebuild, so the hook must not rewrite them"
    )


def test_base_mcp_json_is_copied_verbatim_into_generated_files():
    """The reason _base/mcp.json is excluded although a person writes it.

    If the transpiler stops copying it byte for byte, the exclusion has no reason left
    and this test says so.
    """
    source = (REPO_ROOT / BASE_MCP).read_bytes()
    copies = [
        p
        for p in _tracked(f"{PLUGINS}*.json")
        if (REPO_ROOT / p).read_bytes() == source
    ]
    assert copies, f"no generated plugin file is a byte copy of {BASE_MCP}"


def test_every_file_in_scope_is_json_the_hook_can_parse(excluded, tracked_json):
    """A file the hook cannot parse fails it on every run, whatever else changed."""
    unparseable = []
    for path in tracked_json:
        if excluded(path):
            continue
        try:
            json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))
        except ValueError as exc:
            unparseable.append(f"{path}: {exc}")
    assert not unparseable, unparseable


def _as_the_hook_writes_it(text: str) -> str:
    """What ``pretty-format-json --autofix --indent=2`` (pre-commit-hooks v5.0.0) writes.

    Keys sorted (the hook is not given --no-sort-keys), non-ASCII escaped (nor
    --no-ensure-ascii), two-space indent and one trailing newline. The hook reads the
    file as text, as read_text does, so line endings compare the same way.
    """
    return json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=True) + (
        "\n"
    )


def test_every_file_in_scope_is_already_in_the_hooks_format(excluded, tracked_json):
    """CI does not run pre-commit, so nothing else keeps these files formatted.

    A file the hook would rewrite passes CI, and then the next contributor whose commit
    touches it gets an unrelated reformat in their diff, or a hook failure. The base of
    this branch had one: deploy/cdk/cdk.json.
    """
    checked, unformatted = [], []
    for path in tracked_json:
        if excluded(path):
            continue
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        try:
            expected = _as_the_hook_writes_it(text)
        except ValueError:
            continue  # test_every_file_in_scope_is_json_the_hook_can_parse reports it
        checked.append(path)
        if text != expected:
            unformatted.append(path)
    assert checked, "no JSON file is in the hook's scope; this test checks nothing"
    assert not unformatted, (
        f"pretty-format-json would rewrite {unformatted}; run `pre-commit run "
        "pretty-format-json --all-files` and commit the result"
    )
