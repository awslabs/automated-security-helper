# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a fragment block is merged into the pipeline it extends.

WHY THIS EXISTS
---------------
Several blocks on the CI pages are not whole pipelines: a second job to add under
``jobs:``, steps that "replace the install and scan steps of the job above", the
``rules:`` a merge request pipeline adds. A block marked ``extends=<path>`` runs merged
into the block an earlier marker saved at ``<path>``, and the lint performs the same
merge, so a fragment that no longer fits the pipeline it changes fails before any
runner starts. The merge rules are written down here, as exact results:

* gitlab-ci: as GitLab merges an included file into the including one, with the
  fragment as the including file. Hashes merge at any depth, the fragment's value
  wins, and anything that is not a hash on both sides (arrays such as script and rules,
  scalars) is the fragment's.
* github-actions, a mapping of job ids: its jobs are added, and a job with the same id
  is replaced whole.
* github-actions, a list of steps: a named step replaces the saved job's step with the
  same name; an unnamed one replaces the step that uses the same action, whatever its
  ref. A step with no counterpart goes right before the next step of the fragment that
  replaces one, or right after the last replaced step.

Results are compared after parsing, so key order and quoting do not matter. The real
pages' fragments are merged too, from the pages as they are. The values the merge
cannot carry as the page shows them are pinned here as well: the config check holds
every gitlab-ci block, merged or not, to GitLab's reading of its values, and the checks
that read a workflow's triggers read them from its on: key alone, as the merge does.

WHAT THIS DOES NOT CHECK
------------------------
The marker grammar (test_docs_ci_runner_markers.py) and which runner runs the result
(test_docs_ci_runner_census.py).
"""

from __future__ import annotations

import copy
import importlib.util
import re
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
FENCE = "```"


def _checks():
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, CHECKS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _api(name: str):
    module = _checks()
    if not hasattr(module, name):
        pytest.fail(
            f"scripts/docs_checks.py defines no {name}, which merging a CI fragment "
            "into the pipeline it extends needs"
        )
    return getattr(module, name)


def _load(text: str):
    """YAML as a runner reads it. PyYAML reads a bare ``on:`` key as True; a quoted
    'on' is the same trigger key to GitHub, so both are compared as "on"."""
    document = yaml.safe_load(text)
    if isinstance(document, dict) and True in document:
        document["on"] = document.pop(True)
    return document


def _compose(kind: str, saved: str, fragment: str):
    """The merged pipeline, parsed, and its text."""
    text = _api("compose_ci_pipeline")(kind, saved, fragment)
    assert isinstance(text, str), "compose_ci_pipeline returns the pipeline file's text"
    if kind == "github-actions":
        assert not re.search(r"^true:", text, re.MULTILINE), (
            "the merged workflow must keep its `on:` key; GitHub reads a `true:` key "
            f"as no trigger at all:\n{text}"
        )
    return _load(text), text


def _compose_error(kind: str, saved: str, fragment: str) -> str:
    compose = _api("compose_ci_pipeline")
    error = _api("CiComposeError")
    assert issubclass(error, ValueError)
    with pytest.raises(error) as raised:
        compose(kind, saved, fragment)
    return str(raised.value)


def _dump(document) -> str:
    return yaml.safe_dump(document, sort_keys=False)


# ---------------------------------------------------------------------------
# gitlab-ci
# ---------------------------------------------------------------------------

GITLAB_SAVED = {
    "variables": {"A": "1", "B": "2"},
    "ash-scan": {
        "stage": "test",
        "image": "python:3.12",
        "variables": {"X": "1", "Y": {"value": "a", "description": "kept"}},
        "before_script": ["install"],
        "script": ["one", "two"],
        "rules": [{"if": "$A"}],
        "artifacts": {"when": "always", "paths": ["a"], "reports": {"junit": "j.xml"}},
        "cache": {"key": "k", "paths": ["c"]},
    },
    "ash-gate": {"needs": ["ash-scan"], "script": ["exit 0"]},
}

GITLAB_FRAGMENT = {
    "ash-scan": {
        "variables": {"Y": {"value": "z"}, "Z": "3"},
        "script": ["three"],
        "artifacts": {"paths": ["b"]},
        "cache": False,
        "image": {"name": "python:3.13", "entrypoint": [""]},
        "tags": ["docker"],
    },
    "ash-report": {"script": ["report"]},
}

GITLAB_MERGED = {
    "variables": {"A": "1", "B": "2"},
    "ash-scan": {
        "stage": "test",
        # a scalar replaced by a hash: the fragment's
        "image": {"name": "python:3.13", "entrypoint": [""]},
        # hashes merged at any depth, the fragment's values winning
        "variables": {"X": "1", "Y": {"value": "z", "description": "kept"}, "Z": "3"},
        "before_script": ["install"],
        # arrays replaced, not appended
        "script": ["three"],
        "rules": [{"if": "$A"}],
        "artifacts": {"when": "always", "paths": ["b"], "reports": {"junit": "j.xml"}},
        # a hash replaced by a scalar: the fragment's
        "cache": False,
        "tags": ["docker"],
    },
    "ash-gate": {"needs": ["ash-scan"], "script": ["exit 0"]},
    "ash-report": {"script": ["report"]},
}


def test_gitlab_fragment_merges_like_an_including_file():
    merged, _ = _compose("gitlab-ci", _dump(GITLAB_SAVED), _dump(GITLAB_FRAGMENT))
    assert merged == GITLAB_MERGED


def test_gitlab_fragment_must_be_a_mapping():
    message = _compose_error("gitlab-ci", _dump(GITLAB_SAVED), "- one\n- two\n")
    assert "mapping" in message, message


# ---------------------------------------------------------------------------
# github-actions: a mapping of jobs
# ---------------------------------------------------------------------------

#: Written as text, as a page holds it, so its trigger key is the bare `on:`.
GHA_SAVED_TEXT = """\
name: ASH
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make
  ash:
    runs-on: ubuntu-latest
    env:
      INSTALL_SPEC: x
    steps:
      - name: Check out
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Install
        run: install
      - name: Scan
        run: scan
      - name: Upload
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
"""
GHA_SAVED = _load(GHA_SAVED_TEXT)


def _saved_text() -> str:
    return GHA_SAVED_TEXT


def test_github_jobs_fragment_adds_jobs_and_replaces_a_job_with_the_same_id():
    fragment = {
        "ash": {"needs": "build", "uses": "./.github/workflows/scan.yml"},
        "sarif": {"needs": "ash", "if": "${{ !cancelled() }}", "uses": "./x.yml"},
    }
    merged, text = _compose("github-actions", _saved_text(), _dump(fragment))
    expected = copy.deepcopy(GHA_SAVED)
    expected["jobs"]["ash"] = fragment["ash"]  # whole, not merged into the old job
    expected["jobs"]["sarif"] = fragment["sarif"]
    assert merged == expected
    assert re.search(r"""^(on|'on'|"on"):""", text, re.MULTILINE), text


def test_github_jobs_fragment_whose_job_is_not_a_mapping_no_longer_parses():
    message = _compose_error("github-actions", _saved_text(), "sarif: upload it\n")
    assert "no longer parses" in message, message


def test_github_fragment_is_a_mapping_of_jobs_or_a_list_of_steps():
    message = _compose_error("github-actions", _saved_text(), "just a string\n")
    assert "a mapping of jobs or a list of steps" in message, message


# ---------------------------------------------------------------------------
# github-actions: a list of steps
# ---------------------------------------------------------------------------

STEPS = GHA_SAVED["jobs"]["ash"]["steps"]


def _merged_steps(fragment_steps: list) -> list:
    merged, _ = _compose("github-actions", _saved_text(), _dump(fragment_steps))
    jobs = merged["jobs"]
    assert jobs["build"] == GHA_SAVED["jobs"]["build"], "only the matching job changes"
    assert {k: v for k, v in jobs["ash"].items() if k != "steps"} == {
        k: v for k, v in GHA_SAVED["jobs"]["ash"].items() if k != "steps"
    }
    return jobs["ash"]["steps"]


def test_github_steps_fragment_replaces_by_name_and_places_new_steps():
    restore = {"name": "Restore", "uses": "actions/cache/restore@aaaa"}
    install = {"name": "Install", "run": "install again"}
    save = {"name": "Save", "uses": "actions/cache/save@aaaa"}
    scan = {"name": "Scan", "run": "scan again"}
    after = {"name": "After", "run": "after"}
    got = _merged_steps([restore, install, save, scan, after])
    assert got == [
        STEPS[0],
        restore,  # before the next replaced step (Install)
        install,
        save,  # before the next replaced step (Scan)
        scan,
        after,  # right after the last replaced step, not at the end of the job
        STEPS[3],
    ]


def test_github_unnamed_step_replaces_the_step_using_the_same_action_at_any_ref():
    checkout = {
        "uses": "actions/checkout@0123456789012345678901234567890123456789",
        "with": {"fetch-depth": 0, "persist-credentials": False},
    }
    got = _merged_steps([checkout])
    assert got == [checkout, *STEPS[1:]]


def test_github_named_step_is_matched_by_name_only():
    """A named step whose name matches nothing is new, even when it uses an action a
    saved step uses."""
    get_code = {
        "name": "Get the code",
        "uses": "actions/checkout@0123456789012345678901234567890123456789",
    }
    scan = {"name": "Scan", "run": "scan again"}
    got = _merged_steps([get_code, scan])
    assert got == [STEPS[0], STEPS[1], get_code, scan, STEPS[3]]


def test_github_steps_fragment_that_replaces_nothing_is_refused():
    message = _compose_error(
        "github-actions", _saved_text(), _dump([{"name": "New", "run": "x"}])
    )
    assert "no step of the fragment replaces" in message, message


def test_github_steps_fragment_matching_more_than_one_job_is_refused():
    saved = copy.deepcopy(GHA_SAVED)
    saved["jobs"]["build"]["steps"].append({"name": "Scan", "run": "scan too"})
    message = _compose_error(
        "github-actions", _dump(saved), _dump([{"name": "Scan", "run": "s"}])
    )
    assert "more than one job" in message, message


# ---------------------------------------------------------------------------
# The real pages' fragments
# ---------------------------------------------------------------------------


def _page_blocks(rel: str, kind: str) -> list:
    """The blocks of one CI kind on a real page, in page order."""
    page = _checks().parse_page(REPO_ROOT / rel, REPO_ROOT)
    blocks = [
        block
        for block in page.blocks
        if block.marker is not None and block.marker.keys.get("kind") == kind
    ]
    assert blocks, f"{rel} has no config kind={kind} block"
    return blocks


def test_getting_started_sarif_job_merges_into_the_workflow():
    first, second = _page_blocks("docs/content/getting-started/ci.md", "github-actions")
    merged, _ = _compose("github-actions", first.body, second.body)
    expected = _load(first.body)
    expected["jobs"].update(yaml.safe_load(second.body))
    assert merged == expected
    assert list(merged["jobs"]) == ["ash", "sarif"]


def test_github_actions_caching_steps_merge_into_the_plain_steps_job():
    blocks = _page_blocks("docs/content/how-to/ci/github-actions.md", "github-actions")
    plain, caching = blocks[1], blocks[2]
    saved = _load(plain.body)
    fragment = yaml.safe_load(caching.body)
    merged, _ = _compose("github-actions", plain.body, caching.body)
    steps = saved["jobs"]["ash"]["steps"]
    names = [step.get("name") for step in steps]
    assert names[3:6] == ["Install ASH", "Install scanner tools", "Run ASH"], (
        f"the plain-steps job changed shape ({names}); update this expectation with it"
    )
    expected = copy.deepcopy(saved)
    expected["jobs"]["ash"]["steps"] = [*steps[:4], *fragment, *steps[6:]]
    assert merged == expected
    assert [step.get("name") for step in merged["jobs"]["ash"]["steps"]] == [
        None,
        None,
        None,
        "Install ASH",
        "Restore ASH's scanner tools",
        "Install scanner tools",
        "Save ASH's scanner tools",
        "Today's date, for the grype database cache key",
        "Restore grype's database",
        "Run ASH",
        "Save grype's database",
        "Upload the output directory",
        "Upload SARIF to code scanning",
    ]


def test_github_actions_changed_files_steps_replace_the_checkout():
    """True of the page as it is: the fragment's unnamed checkout replaces the job's,
    so the merged job has one checkout, with the full history."""
    blocks = _page_blocks("docs/content/how-to/ci/github-actions.md", "github-actions")
    plain, changed = blocks[1], blocks[3]
    merged, _ = _compose("github-actions", plain.body, changed.body)
    steps = merged["jobs"]["ash"]["steps"]
    checkouts = [
        s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts == [yaml.safe_load(changed.body)[0]]
    assert checkouts[0]["with"]["fetch-depth"] == 0
    assert steps[0] == checkouts[0], "the replacement keeps the checkout's place"
    scans = [s for s in steps if "--changed-files-only" in str(s.get("run", ""))]
    assert len(scans) == 1


def test_github_actions_changed_files_scan_replaces_the_run_ash_step():
    """Holds once the page names its changed-files step Run ASH, as the job's scan step
    is named: the scan then takes the place of the job's scan, after the installs. Until
    then the step matches nothing and lands right after the checkout, before ASH is
    installed."""
    blocks = _page_blocks("docs/content/how-to/ci/github-actions.md", "github-actions")
    plain, changed = blocks[1], blocks[3]
    saved_steps = _load(plain.body)["jobs"]["ash"]["steps"]
    fragment = yaml.safe_load(changed.body)
    merged, _ = _compose("github-actions", plain.body, changed.body)
    assert merged["jobs"]["ash"]["steps"] == [
        fragment[0],
        *saved_steps[1:5],
        fragment[1],
        *saved_steps[6:],
    ], (
        "the changed-files scan must replace the job's Run ASH step; the page's "
        f"step is named {fragment[1].get('name')!r}"
    )


def test_gitlab_merge_request_fragment_merges_into_the_first_pipeline():
    first, _own_image, merge_request = _page_blocks(
        "docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci"
    )
    saved = yaml.safe_load(first.body)
    fragment = yaml.safe_load(merge_request.body)
    merged, _ = _compose("gitlab-ci", first.body, merge_request.body)
    expected = copy.deepcopy(saved)
    expected["ash-scan"]["rules"] = fragment["ash-scan"]["rules"]
    expected["ash-scan"]["variables"]["GIT_DEPTH"] = "0"
    expected["ash-scan"]["script"] = fragment["ash-scan"]["script"]
    expected["ash-gate"]["rules"] = fragment["ash-gate"]["rules"]
    assert merged == expected
    assert set(merged) == {"ash-scan", "ash-gate"}
    assert merged["ash-scan"]["before_script"] == saved["ash-scan"]["before_script"]


# ---------------------------------------------------------------------------
# A page's pipeline for a block, and the lint's merge
# ---------------------------------------------------------------------------

SAVED_BLOCK = (
    "<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->\n"
    f"{FENCE}yaml\n{GHA_SAVED_TEXT}{FENCE}\n"
)


def _fragment_block(steps: list) -> str:
    return (
        "<!-- doctest: config kind=github-actions extends=.github/workflows/ash.yml -->\n"
        f"{FENCE}yaml\n{_dump(steps)}{FENCE}\n"
    )


def test_ci_pipeline_text_is_a_block_s_own_body_or_its_merged_pipeline(tmp_path):
    scan = {"name": "Scan", "run": "scan again"}
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    path.write_text(SAVED_BLOCK + "\n" + _fragment_block([scan]), encoding="utf-8")
    checks = _checks()
    page = checks.parse_page(path, tmp_path)
    saved_block, fragment_block = page.blocks
    pipeline_text = _api("ci_pipeline_text")
    assert _load(pipeline_text(page, saved_block)) == _load(saved_block.body)
    merged = _load(pipeline_text(page, fragment_block))
    assert merged["jobs"]["ash"]["steps"] == [STEPS[0], STEPS[1], scan, STEPS[3]]


LINT_DEFECTS = [
    (
        "replaces nothing",
        [{"name": "Not a step of the job", "run": "x"}],
        "no step of the fragment replaces",
    ),
    (
        "jobs fragment whose job is not a job",
        {"sarif": "upload it"},
        "no longer parses",
    ),
]


@pytest.mark.parametrize(
    "case,fragment,expected", LINT_DEFECTS, ids=[c[0] for c in LINT_DEFECTS]
)
def test_the_config_check_reports_a_fragment_that_does_not_merge(
    tmp_path, case, fragment, expected
):
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    text = SAVED_BLOCK + "\n" + _fragment_block(fragment)
    path.write_text(text, encoding="utf-8")
    # SAVED_BLOCK, a blank line, the fragment's marker, then its fence.
    fence_line = len(SAVED_BLOCK.split("\n")) + 2
    findings = _checks().check_config_blocks([path], tmp_path)
    assert any(f.line == fence_line and expected in f.message for f in findings), (
        f"{case}: expected {expected!r} at line {fence_line}, got {[str(f) for f in findings]}"
    )


def _saved_block(text: str) -> str:
    return (
        "<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->\n"
        f"{FENCE}yaml\n{text}{FENCE}\n"
    )


def test_a_fragment_extends_the_nearest_block_above_it_saved_at_its_path(tmp_path):
    """Two blocks save the path; the runner's file holds the second when the fragment
    runs, so that is the one it merges into, and the one the census names."""
    second_text = GHA_SAVED_TEXT.replace("run: scan\n", "run: scan, as saved second\n")
    assert second_text != GHA_SAVED_TEXT
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    install = {"name": "Install", "run": "install again"}
    path.write_text(
        "\n".join([SAVED_BLOCK, _saved_block(second_text), _fragment_block([install])]),
        encoding="utf-8",
    )
    checks = _checks()
    page = checks.parse_page(path, tmp_path)
    _first, second, fragment = page.blocks
    merged = _load(_api("ci_pipeline_text")(page, fragment))
    assert merged["jobs"]["ash"]["steps"][2] == {
        "name": "Scan",
        "run": "scan, as saved second",
    }
    census = checks.ci_runner_census([page])
    (entry,) = [
        e for e in census.legs[("act", "docs/page.md")] if e.line == fragment.fence_line
    ]
    assert entry.composed_from == second.fence_line


def test_the_config_check_leaves_a_fragment_of_an_unparsable_block_to_that_block(
    tmp_path,
):
    """A saved block that does not parse is reported at its own fence. The fragment
    that extends it gets no second finding for the same problem."""
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    saved = _saved_block("name: ASH\njobs: [unclosed\n")
    fragment = _fragment_block([{"name": "Scan", "run": "scan again"}])
    path.write_text(saved + "\n" + fragment, encoding="utf-8")
    findings = _checks().check_config_blocks([path], tmp_path)
    fragment_fence = len(saved.split("\n")) + 2
    assert any(f.line == 2 and "does not parse" in f.message for f in findings), [
        str(f) for f in findings
    ]
    assert [f for f in findings if f.line == fragment_fence] == [], [
        str(f) for f in findings
    ]


# ---------------------------------------------------------------------------
# Steps fragments the merge cannot place as the page shows them
# ---------------------------------------------------------------------------


def test_github_unnamed_step_matching_two_steps_of_one_job_is_refused():
    saved = copy.deepcopy(GHA_SAVED)
    saved["jobs"]["ash"]["steps"].insert(
        1,
        {
            "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "with": {},
        },
    )
    message = _compose_error(
        "github-actions",
        _dump(saved),
        _dump([{"uses": "actions/checkout@0123456789012345678901234567890123456789"}]),
    )
    assert "matches 2 steps of job ash" in message, message


def test_github_two_fragment_steps_replacing_one_step_are_refused():
    message = _compose_error(
        "github-actions",
        _saved_text(),
        _dump([{"name": "Scan", "run": "a"}, {"name": "Scan", "run": "b"}]),
    )
    assert "two steps of the fragment replace step 3 of job ash" in message, message


def test_github_steps_fragment_out_of_the_job_s_order_is_refused():
    """The fragment replaces Scan, then Install, the reverse of the job's order. No
    merged order has its new steps where the page shows them, so it is refused."""
    fragment = [
        {"name": "X", "run": "x"},
        {"name": "Scan", "run": "scan again"},
        {"name": "Y", "run": "y"},
        {"name": "Install", "run": "install again"},
        {"name": "Z", "run": "z"},
    ]
    message = _compose_error("github-actions", _saved_text(), _dump(fragment))
    assert "in the job's order" in message, message
    assert "Install" in message and "Scan" in message, message


def test_github_job_with_neither_runs_on_nor_uses_no_longer_parses():
    """A jobs fragment written as a whole workflow puts its jobs under a job named jobs."""
    message = _compose_error(
        "github-actions",
        _saved_text(),
        _dump({"jobs": {"sarif": {"uses": "./x.yml"}}}),
    )
    assert "neither runs-on: nor uses:" in message, message
    assert "no longer parses" in message, message


# ---------------------------------------------------------------------------
# Job ids YAML does not read as strings
# ---------------------------------------------------------------------------

NUMBERED_JOB = """\
on: push
jobs:
  123:
    runs-on: ubuntu-latest
    steps:
      - name: Scan
        run: scan
"""


def test_a_steps_fragment_merges_into_a_job_whose_id_reads_as_a_number():
    merged, _ = _compose(
        "github-actions", NUMBERED_JOB, _dump([{"name": "Scan", "run": "scan again"}])
    )
    assert merged["jobs"][123]["steps"] == [{"name": "Scan", "run": "scan again"}]


def test_steps_matching_a_numbered_job_and_a_named_one_are_ambiguous():
    saved = NUMBERED_JOB + (
        "  ash:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Scan\n"
        "        run: scan too\n"
    )
    message = _compose_error(
        "github-actions", saved, _dump([{"name": "Scan", "run": "s"}])
    )
    assert "more than one job" in message and "123" in message, message


# ---------------------------------------------------------------------------
# Plain values that YAML 1.1 and YAML 1.2 read differently
# ---------------------------------------------------------------------------
#
# PyYAML reads YAML 1.1, so a merged pipeline written back from what it read carries
# its reading: `no` becomes false, `0755` becomes 493, `1:30` becomes 90. A runner that
# reads YAML 1.2 read the page's `no` as the string "no", so the merged pipeline would
# not be the page's. The merge refuses such a value, naming it and its line. A string
# is written back in the page's form: plain where the page writes it plain, so every
# reader reads it in the merged pipeline as it reads it on the page, and quoted where
# the page quotes it.

GITLAB_TEXT = (
    "ash-scan:\n  image: python:3.12\n  script:\n    - ash scan --mode local\n"
)
GITLAB_SCRIPT = "ash-scan:\n  script:\n    - ash scan --mode local --no-progress\n"

#: (case id, a plain value YAML 1.1 reads as something other than a string, and YAML
#: 1.2 reads differently)
VERSION_DIVERGENT = [
    ("yes", "yes"),
    ("No", "No"),
    ("ON", "ON"),
    ("off", "off"),
    ("zero-led integer", "0755"),
    ("sexagesimal", "1:30"),
    ("underscored integer", "1_000"),
    ("underscored float", "1_0.5"),
    ("binary integer", "0b101"),
    ("date", "2026-10-12"),
]

#: Plain values PyYAML, YAML 1.2 and GitLab (Psych) all read as strings: written back
#: unchanged in a gitlab-ci pipeline. yEs, 0o17 and 1e3, which some of them read as
#: something else, are in GITLAB_DIVERGENT below.
WRITTEN_AS_WRITTEN = ["y", "N", "Y", "n"]


@pytest.mark.parametrize("value", WRITTEN_AS_WRITTEN)
def test_a_value_pyyaml_reads_as_a_string_is_written_back_as_written(value):
    fragment = f"ash-scan:\n  variables:\n    FLAG: {value}\n"
    merged, text = _compose("gitlab-ci", GITLAB_TEXT, fragment)
    assert merged["ash-scan"]["variables"]["FLAG"] == value
    assert re.search(rf"^\s*FLAG: {re.escape(value)}$", text, re.MULTILINE), text


@pytest.mark.parametrize(
    "case,value", VERSION_DIVERGENT, ids=[c[0] for c in VERSION_DIVERGENT]
)
def test_a_value_the_two_yaml_versions_read_differently_is_refused_in_the_fragment(
    case, value
):
    fragment = f"ash-scan:\n  variables:\n    FLAG: {value}\n"
    message = _compose_error("gitlab-ci", GITLAB_TEXT, fragment)
    assert repr(value) in message and "line 3" in message, message


@pytest.mark.parametrize(
    "case,value", VERSION_DIVERGENT, ids=[c[0] for c in VERSION_DIVERGENT]
)
def test_a_value_the_two_yaml_versions_read_differently_is_refused_in_the_saved_block(
    case, value
):
    saved = GITLAB_TEXT + f"  variables:\n    FLAG: {value}\n"
    message = _compose_error("gitlab-ci", saved, GITLAB_SCRIPT)
    assert repr(value) in message and "line 6" in message, message


@pytest.mark.parametrize(
    "case,value", VERSION_DIVERGENT, ids=[c[0] for c in VERSION_DIVERGENT]
)
def test_the_same_value_quoted_merges(case, value):
    fragment = f"ash-scan:\n  variables:\n    FLAG: '{value}'\n"
    merged, _ = _compose("gitlab-ci", GITLAB_TEXT, fragment)
    assert merged["ash-scan"]["variables"]["FLAG"] == value


@pytest.mark.parametrize(
    "value", ["true", "False", "0", "12", "-3", "0x1F", "1.5", "~", "null", "plain"]
)
def test_a_value_both_yaml_versions_read_alike_merges(value):
    fragment = f"ash-scan:\n  variables:\n    FLAG: {value}\n"
    merged, _ = _compose("gitlab-ci", GITLAB_TEXT, fragment)
    assert merged["ash-scan"]["variables"]["FLAG"] == yaml.safe_load(value)


def test_the_workflow_s_own_on_key_is_exempt_and_any_other_on_is_not():
    """The bare on: at the top of a workflow is the trigger key, written back as on:.
    An on key anywhere else would be written back as true:."""
    merged, text = _compose(
        "github-actions", _saved_text(), _dump([{"name": "Scan", "run": "scan again"}])
    )
    assert "on" in merged and re.search(r"^on:", text, re.MULTILINE), text
    message = _compose_error(
        "github-actions", _saved_text(), "- name: Scan\n  env:\n    on: x\n"
    )
    assert "'on'" in message and "line 3" in message, message
    message = _compose_error(
        "gitlab-ci", GITLAB_TEXT, "on:\n  script:\n    - ash scan --mode local\n"
    )
    assert "'on'" in message and "line 1" in message, message


def test_the_page_lines_of_a_value_are_named_through_ci_pipeline_text(tmp_path):
    """Through a page, the line named is the page's line."""
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    saved = (
        "<!-- doctest: config kind=gitlab-ci save-as=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\n{GITLAB_TEXT}{FENCE}\n"
    )
    fragment = (
        "<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\nash-scan:\n  variables:\n    FLAG: no\n{FENCE}\n"
    )
    path.write_text(saved + "\n" + fragment, encoding="utf-8")
    page = _checks().parse_page(path, tmp_path)
    flag_line = len(saved.split("\n")) + 5
    assert page.text.split("\n")[flag_line - 1] == "    FLAG: no"
    with pytest.raises(_api("CiComposeError")) as raised:
        _api("ci_pipeline_text")(page, page.blocks[1])
    assert f"line {flag_line}" in str(raised.value), str(raised.value)


@pytest.mark.parametrize("kind", ["gitlab-ci", "github-actions"])
@pytest.mark.parametrize("value", ["0x_", "0b_"])
def test_a_plain_value_pyyaml_cannot_load_is_refused_by_name(kind, value):
    """PyYAML resolves 0x_ as an integer and then fails to build it. The merge names the
    value and its line, as for any other value it cannot carry, rather than failing
    with PyYAML's own error."""
    if kind == "gitlab-ci":
        saved, fragment = GITLAB_TEXT, f"ash-scan:\n  variables:\n    FLAG: {value}\n"
    else:
        saved, fragment = _saved_text(), f"- name: Scan\n  env:\n    FLAG: {value}\n"
    message = _compose_error(kind, saved, fragment)
    assert repr(value) in message and "line 3" in message, message


# ---------------------------------------------------------------------------
# Plain values GitLab reads otherwise than the runner does
# ---------------------------------------------------------------------------
#
# GitLab loads a pipeline with Ruby's Psych, which reads yEs as true, nUll as null,
# 1,000 as 1000, :sym as a symbol and leaves 0o17 and 1e3 strings. gitlab-ci-local, the
# runner that runs the page's pipeline, is not a Psych reader, so a run would test a
# value GitLab never sees. In a gitlab-ci block the merge refuses a plain value Psych
# reads otherwise than YAML 1.2 or PyYAML. The other kinds keep the rule above.

#: (a plain value, GitLab's reading of it). The values Psych's own tests give its scalar
#: scanner (test/psych/test_scalar_scanner.rb at v5.3.1), as GitLab reads them: its
#: loader permits no Time or Date class, so it refuses a timestamp or a date, even one
#: Psych alone would read as a string for its bad day; and the port keeps Psych
#: 5.0.1's legacy integers, which read 0x_,_ and +0__,, as numbers where 5.3.1 reads
#: strings. Then the readings that set the rule below, a value split over lines, and a
#: float with no digit, which Ruby's Float() refuses.
PSYCH_READINGS = [
    ("2001-12-15T02:59:43.1Z", ("timestamp", "2001-12-15T02:59:43.1Z")),
    ("2001-12-14 21:59:43.10 -5", ("timestamp", "2001-12-14 21:59:43.10 -5")),
    ("2001-12-15T02:59:73.1Z", ("timestamp", "2001-12-15T02:59:73.1Z")),
    ("2000-15-01", ("str", "2000-15-01")),
    ("2000-10-32", ("str", "2000-10-32")),
    ("2000-1-31", ("date", "2000-1-31")),
    ("2000-11-31", ("date", "2000-11-31")),
    (".inf", ("float", ".inf")),
    ("+.inf", ("float", ".inf")),
    ("-.inf", ("float", "-.inf")),
    (".nan", ("float", ".nan")),
    ("0.E+0", ("float", 0.0)),
    ("null", ("null", None)),
    ("~", ("null", None)),
    ("", ("null", None)),
    (":foo", ("symbol", "foo")),
    ("00:00:00:00:0f", ("str", "00:00:00:00:0f")),
    ("00:00:00:00:00.0", ("str", "00:00:00:00:00.0")),
    ("190:20:30.15", ("float", 685230.15)),
    ("190:20:30", ("int", 685230)),
    ("1.2", ("float", 1.2)),
    ("true", ("bool", True)),
    ("_100", ("str", "_100")),
    ("450D", ("str", "450D")),
    ("100_", ("str", "100_")),
    ("0x_,_", ("error", "0x_,_")),
    ("+0__,,", ("int", 0)),
    ("123,456,789", ("int", 123456789)),
    ("1_2,3,4_5,6_789", ("int", 123456789)),
    ("-1", ("int", -1)),
    ("0b0,1_0,1_,0,1_01,0", ("int", 0b010101010)),
    ("0_,,,1_2,_34567", ("int", 0o1234567)),
    ("0x_12_,34,_56,_789abcdef", ("int", 0x123456789ABCDEF)),
    (".", ("str", ".")),
    ("+.", ("str", "+.")),
    ("abcdefghijklmnopqrstuvwxyz", ("str", "abcdefghijklmnopqrstuvwxyz")),
    ("y", ("str", "y")),
    ("N", ("str", "N")),
    ("yEs", ("bool", True)),
    ("oFf", ("bool", False)),
    ("nUll", ("null", None)),
    (".iNf", ("float", ".inf")),
    ("-.InF", ("float", "-.inf")),
    (".nAn", ("float", ".nan")),
    ("1,000", ("int", 1000)),
    ("1,000.5", ("float", 1000.5)),
    (":sym", ("symbol", "sym")),
    ("0o17", ("str", "0o17")),
    ("1e3", ("str", "1e3")),
    ("0.1e3", ("str", "0.1e3")),
    ("1__0", ("str", "1__0")),
    ("1:20", ("int", 4800)),
    ("0755", ("int", 493)),
    ("y\nyes", ("bool", True)),
    (".e+5", ("error", ".e+5")),
]


@pytest.mark.parametrize(
    "text,expected", PSYCH_READINGS, ids=[repr(c[0]) for c in PSYCH_READINGS]
)
def test_the_gitlab_reading_is_psych_s(text, expected):
    assert _api("_psych_reading")(text) == expected


#: (case id, a plain value GitLab (Psych) reads otherwise than YAML 1.2 or PyYAML)
GITLAB_DIVERGENT = [
    ("mixed-case yes", "yEs"),
    ("mixed-case no", "nO"),
    ("mixed-case on", "oN"),
    ("mixed-case off", "oFf"),
    ("mixed-case true", "tRue"),
    ("mixed-case false", "fAlse"),
    ("mixed-case null", "nUll"),
    ("mixed-case infinity", ".iNf"),
    ("mixed-case negative infinity", "-.InF"),
    ("mixed-case not-a-number", ".nAn"),
    ("integer with a comma", "1,000"),
    ("float with a comma", "1,000.5"),
    ("symbol", ":sym"),
    ("0o octal", "0o17"),
    ("exponent with no point", "1e3"),
    ("exponent with no sign", "0.1e3"),
]


@pytest.mark.parametrize(
    "case,value", GITLAB_DIVERGENT, ids=[c[0] for c in GITLAB_DIVERGENT]
)
def test_a_value_gitlab_reads_otherwise_is_refused_in_a_gitlab_fragment(case, value):
    fragment = f"ash-scan:\n  variables:\n    FLAG: {value}\n"
    message = _compose_error("gitlab-ci", GITLAB_TEXT, fragment)
    assert repr(value) in message and "line 3" in message, message
    assert "GitLab" in message, message


@pytest.mark.parametrize(
    "case,value", GITLAB_DIVERGENT, ids=[c[0] for c in GITLAB_DIVERGENT]
)
def test_a_value_gitlab_reads_otherwise_is_refused_in_a_saved_gitlab_pipeline(
    case, value
):
    saved = GITLAB_TEXT + f"  variables:\n    FLAG: {value}\n"
    message = _compose_error("gitlab-ci", saved, GITLAB_SCRIPT)
    assert repr(value) in message and "line 6" in message, message
    assert "GitLab" in message, message


@pytest.mark.parametrize(
    "value", ["y", "N", "08"] + [value for _case, value in GITLAB_DIVERGENT]
)
def test_a_plain_value_pyyaml_reads_as_a_string_stays_plain_in_a_github_fragment(
    value,
):
    """The control for the other kinds: a GitHub fragment's plain value that PyYAML
    reads as a string merges, and is written back plain, as the page writes it, so a
    YAML 1.2 reader reads 0o17 in the merged workflow as the 15 it reads on the page."""
    fragment = f"- name: Scan\n  run: scan again\n  env:\n    FLAG: {value}\n"
    merged, text = _compose("github-actions", _saved_text(), fragment)
    assert merged["jobs"]["ash"]["steps"][2]["env"]["FLAG"] == value
    assert re.search(rf"^\s*FLAG: {re.escape(value)}$", text, re.MULTILINE), text


# ---------------------------------------------------------------------------
# GitLab's reading in every gitlab-ci block, merged or not
# ---------------------------------------------------------------------------
#
# gitlab-ci-local reads a pipeline with js-yaml, not Psych, so a gitlab-ci block run as
# the page writes it tests such a value as GitLab never reads it, as a merged one does.
# The config check refuses the value in every gitlab-ci block, at the block's fence,
# naming the value's page line. A github-actions block is not held to GitLab's reading.
# The message names the reader that differs: a local run where GitLab's reading is not
# YAML 1.2's, by whose core schema js-yaml reads plain values (plus timestamps and merge
# keys), and PyYAML where it is (1__0); a block no runner runs (runner=none) gets no
# word about a run. A fragment, which the merge writes back, gets the merge's message
# instead.

#: (case id, a plain value GitLab reads otherwise than YAML 1.2 or PyYAML): one or two
#: of each reading in the rule above, and two the rule for merges refused already
#: (PyYAML reads 1__0 as 10 and 1:20 as 80, GitLab as a string and as 4800).
GITLAB_BLOCK_DIVERGENT = [
    ("mixed-case yes", "yEs"),
    ("mixed-case off", "oFf"),
    ("mixed-case null", "nUll"),
    ("mixed-case infinity", ".iNf"),
    ("mixed-case not-a-number", ".nAn"),
    ("integer with a comma", "1,000"),
    ("float with a comma", "1,000.5"),
    ("symbol", ":sym"),
    ("0o octal", "0o17"),
    ("exponent with no point", "1e3"),
    ("exponent with no sign", "0.1e3"),
    ("doubled underscore", "1__0"),
    ("sexagesimal", "1:20"),
]


def _gitlab_block(value: str, keys: str = "", lang: str = "yaml") -> str:
    """A gitlab-ci block whose FLAG variable is ``value``, on line 8 of a page that
    starts with it."""
    return (
        f"<!-- doctest: config kind=gitlab-ci{keys} -->\n"
        f"{FENCE}{lang}\n{GITLAB_TEXT}  variables:\n    FLAG: {value}\n{FENCE}\n"
    )


def _config_findings(tmp_path, text: str) -> list:
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return _checks().check_config_blocks([path], tmp_path)


@pytest.mark.parametrize(
    "case,value", GITLAB_BLOCK_DIVERGENT, ids=[c[0] for c in GITLAB_BLOCK_DIVERGENT]
)
def test_a_value_gitlab_reads_otherwise_is_refused_in_an_unmerged_gitlab_block(
    tmp_path, case, value
):
    findings = _config_findings(tmp_path, _gitlab_block(value))
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    (message,) = [f.message for f in findings]
    assert repr(value) in message and "line 8" in message, message
    assert "GitLab" in message, message


@pytest.mark.parametrize("value", WRITTEN_AS_WRITTEN)
def test_a_value_every_reader_reads_as_a_string_passes_in_a_gitlab_block(
    tmp_path, value
):
    assert _config_findings(tmp_path, _gitlab_block(value)) == []


@pytest.mark.parametrize(
    "value", WRITTEN_AS_WRITTEN + [value for _case, value in GITLAB_BLOCK_DIVERGENT]
)
def test_a_github_block_is_not_held_to_gitlab_s_reading(tmp_path, value):
    workflow = GHA_SAVED_TEXT.replace(
        "      INSTALL_SPEC: x\n", f"      INSTALL_SPEC: x\n      FLAG: {value}\n"
    )
    assert workflow != GHA_SAVED_TEXT
    block = f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\n{workflow}{FENCE}\n"
    assert _config_findings(tmp_path, block) == []


def test_a_value_gitlab_reads_otherwise_in_a_later_document_is_refused(tmp_path):
    """A pipeline with a spec: header is two YAML documents, and GitLab reads both."""
    block = (
        "<!-- doctest: config kind=gitlab-ci -->\n"
        f"{FENCE}yaml\nspec:\n  inputs:\n    flag:\n      default: x\n---\n"
        f"{GITLAB_TEXT}  variables:\n    FLAG: yEs\n{FENCE}\n"
    )
    findings = _config_findings(tmp_path, block)
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    assert "'yEs'" in findings[0].message and "line 13" in findings[0].message, str(
        findings[0]
    )


def test_a_saved_gitlab_block_s_value_is_reported_at_its_own_fence(tmp_path):
    """The saved block runs on its own as well, so its value is reported at its fence.
    The fragment that extends it gets no second finding for the same value."""
    saved = _gitlab_block("yEs", " save-as=.gitlab-ci.yml")
    fragment = (
        "<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\n{GITLAB_SCRIPT}{FENCE}\n"
    )
    findings = _config_findings(tmp_path, saved + "\n" + fragment)
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    assert "'yEs'" in findings[0].message and "line 8" in findings[0].message, str(
        findings[0]
    )


def test_a_fragment_s_value_is_reported_once_at_its_fence(tmp_path):
    saved = _gitlab_block("x", " save-as=.gitlab-ci.yml")
    fragment = (
        "<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\nash-scan:\n  variables:\n    FLAG: yEs\n{FENCE}\n"
    )
    findings = _config_findings(tmp_path, saved + "\n" + fragment)
    fragment_fence = len(saved.split("\n")) + 2
    assert [f.line for f in findings] == [fragment_fence], [str(f) for f in findings]
    message = findings[0].message
    assert "the fragment" in message and "'yEs'" in message, message
    assert f"line {fragment_fence + 3}" in message, message


def test_a_saved_github_workflow_s_value_is_reported_at_its_own_fence(tmp_path):
    """A plain value only the merge refuses (no: false to YAML 1.1, a string to
    YAML 1.2) belongs to the saved workflow that holds it: it is reported once,
    at the saved block's fence, not repeated at every fragment that extends it."""
    workflow = GHA_SAVED_TEXT.replace(
        "      INSTALL_SPEC: x\n", "      INSTALL_SPEC: x\n      FLAG: no\n"
    )
    assert workflow != GHA_SAVED_TEXT
    saved = (
        "<!-- doctest: config kind=github-actions save-as=.github/workflows/a.yml -->\n"
        f"{FENCE}yaml\n{workflow}{FENCE}\n"
    )
    fragment = (
        "<!-- doctest: config kind=github-actions extends=.github/workflows/a.yml -->\n"
        f"{FENCE}yaml\n- name: Scan\n  run: scan again\n{FENCE}\n"
    )
    findings = _config_findings(tmp_path, saved + "\n" + fragment + "\n" + fragment)
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    message = findings[0].message
    assert "'no'" in message and "YAML 1.1" in message, message
    value_line = 2 + workflow.splitlines().index("      FLAG: no") + 1
    assert f"line {value_line}" in message, message


def test_a_saved_workflow_s_trigger_key_is_not_a_value_to_refuse(tmp_path):
    """The top-level plain on: key is the workflow's trigger key, exempt as the
    merge exempts it; a saved workflow with no other plain divergent value has
    no finding."""
    saved = (
        "<!-- doctest: config kind=github-actions save-as=.github/workflows/a.yml -->\n"
        f"{FENCE}yaml\n{GHA_SAVED_TEXT}{FENCE}\n"
    )
    assert _config_findings(tmp_path, saved) == []


def test_a_fragment_that_extends_nothing_is_still_held_to_gitlab_s_reading(tmp_path):
    """The markers check reports the extends= that names nothing above the fragment;
    the config check still reports the fragment's own value."""
    fragment = (
        "<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\nash-scan:\n  variables:\n    FLAG: yEs\n{FENCE}\n"
    )
    findings = _config_findings(tmp_path, fragment)
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    assert "'yEs'" in findings[0].message and "line 5" in findings[0].message, str(
        findings[0]
    )


def test_a_yml_block_is_held_to_gitlab_s_reading(tmp_path):
    findings = _config_findings(tmp_path, _gitlab_block("yEs", lang="yml"))
    assert [f.line for f in findings] == [2], [str(f) for f in findings]
    (message,) = [f.message for f in findings]
    assert "'yEs'" in message and "line 8" in message and "GitLab" in message, message


@pytest.mark.parametrize("fragment", [True, False], ids=["fragment", "unmerged"])
def test_a_fragment_s_value_gets_the_merge_s_message(tmp_path, fragment):
    """The merge writes a fragment back as PyYAML read it, so the config check names a
    fragment's plain no as the merge does: YAML 1.1 reads it as false and YAML 1.2 as a
    string. A block run as the page writes it gets GitLab's reading of the same no."""
    if fragment:
        saved = _gitlab_block("x", " save-as=.gitlab-ci.yml")
        text = saved + (
            "\n<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
            f"{FENCE}yaml\nash-scan:\n  variables:\n    FLAG: no\n{FENCE}\n"
        )
        fence = len(saved.split("\n")) + 2
    else:
        text, fence = _gitlab_block("no"), 2
    findings = _config_findings(tmp_path, text)
    assert [f.line for f in findings] == [fence], [str(f) for f in findings]
    (message,) = [f.message for f in findings]
    merge_message = "YAML 1.1 reads as the boolean false and YAML 1.2 as a string"
    gitlab_message = "GitLab (Psych) reads as the boolean false"
    assert (merge_message in message, gitlab_message in message) == (
        fragment,
        not fragment,
    ), message


def test_a_value_only_pyyaml_reads_otherwise_names_pyyaml(tmp_path):
    """GitLab and YAML 1.2 read a plain 1__0 as the string it is, and PyYAML as 10.
    js-yaml, which gitlab-ci-local reads the pipeline with, reads it by YAML 1.2, so a
    local run tests GitLab's value; the reader that differs is PyYAML."""
    findings = _config_findings(tmp_path, _gitlab_block("1__0"))
    (message,) = [f.message for f in findings]
    assert "GitLab (Psych) and YAML 1.2 read as a string" in message, message
    assert "PyYAML" in message and "as the number 10" in message, message
    assert "local run" not in message, message


#: A runner=none marker, on a block that is part of a pipeline the page does not show.
NO_RUNNER = ' runner=none reason="part of a larger pipeline"'


@pytest.mark.parametrize("keys", ["", NO_RUNNER], ids=["run", "runner=none"])
@pytest.mark.parametrize("fragment", [False, True], ids=["unmerged", "fragment"])
def test_only_a_block_a_runner_runs_is_refused_for_a_local_run(
    tmp_path, keys, fragment
):
    """A local run tests yEs as the string YAML 1.2 reads, and GitLab reads true. The
    message says so for a block a runner runs, and leaves the run out for one no runner
    runs, whose readings it still names."""
    if fragment:
        saved = _gitlab_block("x", " save-as=.gitlab-ci.yml")
        text = saved + (
            f"\n<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml{keys} -->\n"
            f"{FENCE}yaml\nash-scan:\n  variables:\n    FLAG: yEs\n{FENCE}\n"
        )
    else:
        text = _gitlab_block("yEs", keys)
    findings = _config_findings(tmp_path, text)
    (message,) = [f.message for f in findings]
    assert "GitLab (Psych) reads as the boolean true" in message, message
    assert "YAML 1.2 as a string and PyYAML as a string" in message, message
    runs = keys == ""
    run = "a local run would not test the value GitLab reads"
    assert (run in message) is runs, message
    assert ("local run" in message) is runs, message


# ---------------------------------------------------------------------------
# Quoted values keep their quotes through the merge
# ---------------------------------------------------------------------------

#: Quoted on the page, so a string to every reader; written plain, each would read as
#: something else: yEs is true and nUll null to Psych, 0o17 is 15 and 1e3 is 1000.0 to
#: YAML 1.2.
QUOTED = {
    "A": "yEs",
    "B": "0o17",
    "C": "1e3",
    "E": "nUll",
    "F": ".iNf",
    "G": "1,000",
    "H": ":sym",
    "I": "08",
}
QUOTED_LINES = (
    "A: 'yEs'\nB: '0o17'\nC: \"1e3\"\nE: 'nUll'\nF: '.iNf'\nG: '1,000'\nH: \":sym\"\n"
    "I: '08'\n"
)
QUOTED_CASES = [
    (
        "gitlab-ci",
        GITLAB_TEXT,
        "ash-scan:\n  variables:\n" + textwrap.indent(QUOTED_LINES, "    "),
        ["ash-scan", "variables"],
    ),
    (
        "github-actions",
        GHA_SAVED_TEXT,
        "- name: Scan\n  run: scan again\n  env:\n"
        + textwrap.indent(QUOTED_LINES, "    "),
        ["jobs", "ash", "steps", 2, "env"],
    ),
]


def _scalars_at(text: str, path: list) -> dict:
    """The scalar nodes of the mapping at ``path`` of a YAML text, by key."""
    node = yaml.compose(text)
    for step in path:
        if isinstance(step, int):
            node = node.value[step]
        else:
            node = next(value for key, value in node.value if key.value == step)
    return {key.value: value for key, value in node.value}


def _read_back(node, reading) -> tuple:
    """A scalar of the merged text as a reader reads it: a quoted or block scalar is a
    string to every reader, a plain one is what ``reading`` makes of it."""
    return ("str", node.value) if node.style is not None else reading(node.value)


@pytest.mark.parametrize(
    "kind,saved,fragment,path", QUOTED_CASES, ids=[c[0] for c in QUOTED_CASES]
)
def test_a_quoted_value_stays_a_string_to_every_reader_through_the_merge(
    kind, saved, fragment, path
):
    _merged, text = _compose(kind, saved, fragment)
    scalars = _scalars_at(text, path)
    yaml12 = _api("_yaml12_reading")
    assert {key: _read_back(scalars[key], yaml12) for key in QUOTED} == {
        key: ("str", value) for key, value in QUOTED.items()
    }, text
    psych = _api("_psych_reading")
    assert {key: _read_back(scalars[key], psych) for key in QUOTED} == {
        key: ("str", value) for key, value in QUOTED.items()
    }, text


#: Quoted on the page. YAML 1.2, PyYAML and Psych read each written plain as a string
#: too, but go-yaml (gopkg.in/yaml.v3 v3.0.1, which act reads a workflow with) drops a
#: plain number's underscores and resolves 0o1_7 as 15, +0o17 as 15, -0o17 as -15,
#: 1_0e3 as 10000.0, 1_0.5e3 as 10500.0 and 0_8 as 8.0. act gets that number where it
#: decodes a value untyped, as in a reusable-workflow job's with:. It decodes env: and
#: a step's with: into strings, where go-yaml keeps the text as written, so act reads
#: the text there either way. Readers differ in which plain forms they read as strings,
#: so a value the page quotes is written back quoted, wherever it is.
GO_YAML_NUMBERS = {
    "J": "0o1_7",
    "K": "+0o17",
    "L": "-0o17",
    "M": "1_0e3",
    "N": "1_0.5e3",
    "O": "0_8",
}
GO_YAML_LINES = "".join(f"{key}: '{value}'\n" for key, value in GO_YAML_NUMBERS.items())
#: The body of a job that calls a reusable workflow, whose with: act decodes untyped.
REUSABLE_CALL = "  needs: build\n  uses: ./.github/workflows/scan.yml\n"
GO_YAML_CASES = [
    (
        "github-actions fragment",
        "github-actions",
        GHA_SAVED_TEXT,
        "- name: Scan\n  run: scan again\n  env:\n"
        + textwrap.indent(GO_YAML_LINES, "    "),
        ["jobs", "ash", "steps", 2, "env"],
    ),
    (
        "github-actions reusable-workflow call",
        "github-actions",
        GHA_SAVED_TEXT,
        f"scan:\n{REUSABLE_CALL}  with:\n" + textwrap.indent(GO_YAML_LINES, "    "),
        ["jobs", "scan", "with"],
    ),
    (
        "github-actions saved workflow",
        "github-actions",
        GHA_SAVED_TEXT.replace(
            "      INSTALL_SPEC: x\n",
            "      INSTALL_SPEC: x\n" + textwrap.indent(GO_YAML_LINES, "      "),
        ),
        "- name: Scan\n  run: scan again\n",
        ["jobs", "ash", "env"],
    ),
    (
        "gitlab-ci fragment",
        "gitlab-ci",
        GITLAB_TEXT,
        "ash-scan:\n  variables:\n" + textwrap.indent(GO_YAML_LINES, "    "),
        ["ash-scan", "variables"],
    ),
]


@pytest.mark.parametrize(
    "case,kind,saved,fragment,path", GO_YAML_CASES, ids=[c[0] for c in GO_YAML_CASES]
)
def test_a_value_the_page_quotes_is_written_back_quoted(
    case, kind, saved, fragment, path
):
    _merged, text = _compose(kind, saved, fragment)
    scalars = _scalars_at(text, path)
    assert {
        key: (scalars[key].style is not None, scalars[key].value)
        for key in GO_YAML_NUMBERS
    } == {key: (True, value) for key, value in GO_YAML_NUMBERS.items()}, text


#: (case id, a fragment holding FLAG, the path of FLAG's mapping in the merged workflow)
PLAIN_PLACES = [
    (
        "step env",
        "- name: Scan\n  run: scan again\n  env:\n    FLAG: {value}\n",
        ["jobs", "ash", "steps", 2, "env"],
    ),
    (
        "reusable-workflow with",
        "scan:\n" + REUSABLE_CALL + "  with:\n    FLAG: {value}\n",
        ["jobs", "scan", "with"],
    ),
]


@pytest.mark.parametrize(
    "place,fragment,path", PLAIN_PLACES, ids=[c[0] for c in PLAIN_PLACES]
)
@pytest.mark.parametrize("value", list(GO_YAML_NUMBERS.values()))
def test_the_same_value_written_plain_is_written_back_plain(
    value, place, fragment, path
):
    """The control: written plain on the page, the value is written back plain, so
    every reader reads it in the merged workflow as it reads it on the page. For act
    that is the text in a step's env:, which it decodes into strings, and go-yaml's
    number in a reusable-workflow job's with:, which it decodes untyped."""
    merged, text = _compose(
        "github-actions", _saved_text(), fragment.format(value=value)
    )
    mapping = merged
    for step in path:
        mapping = mapping[step]
    assert mapping["FLAG"] == value
    assert re.search(rf"^\s*FLAG: {re.escape(value)}$", text, re.MULTILINE), text


#: (case id, kind, saved, fragment, the start of the refusal): a plain string where a
#: mapping or a list goes, which the messages name as a string.
STRING_WHERE_A_MAPPING_GOES = [
    (
        "github fragment",
        "github-actions",
        GHA_SAVED_TEXT,
        "just a string\n",
        "this one is a string",
    ),
    ("gitlab fragment", "gitlab-ci", GITLAB_TEXT, "text\n", "this one is a string"),
    (
        "saved gitlab pipeline",
        "gitlab-ci",
        "just text\n",
        GITLAB_SCRIPT,
        "pipeline is a string, not a mapping",
    ),
    (
        "github step",
        "github-actions",
        GHA_SAVED_TEXT,
        "- name: Scan\n  run: x\n- plain\n",
        "step 2 of the fragment is a string",
    ),
    (
        "github job",
        "github-actions",
        GHA_SAVED_TEXT,
        "ash: plain\n",
        "job ash is a string",
    ),
]


@pytest.mark.parametrize(
    "case,kind,saved,fragment,expected",
    STRING_WHERE_A_MAPPING_GOES,
    ids=[c[0] for c in STRING_WHERE_A_MAPPING_GOES],
)
def test_a_string_where_a_mapping_goes_is_named_a_string(
    case, kind, saved, fragment, expected
):
    message = _compose_error(kind, saved, fragment)
    assert expected in message, message


# ---------------------------------------------------------------------------
# Only the plain on: key is the trigger key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["true", "True"])
def test_a_true_key_of_the_saved_workflow_is_not_written_back_as_on(key):
    """PyYAML reads a plain on: and a true: key alike, as true. Only the page's on: is
    the trigger key; a true: key is a boolean key to GitHub as well, and the merged
    workflow keeps it as one."""
    saved = GHA_SAVED_TEXT.replace("\non:\n", f"\n{key}:\n")
    assert saved != GHA_SAVED_TEXT
    text = _api("compose_ci_pipeline")(
        "github-actions", saved, _dump([{"name": "Scan", "run": "scan again"}])
    )
    assert not re.search(r"^on:", text, re.MULTILINE), text
    assert re.search(r"^true:", text, re.MULTILINE), text


def test_a_true_key_beside_the_on_key_keeps_both():
    saved = GHA_SAVED_TEXT.replace("\non:\n", "\ntrue: x\non:\n")
    text = _api("compose_ci_pipeline")(
        "github-actions", saved, _dump([{"name": "Scan", "run": "scan again"}])
    )
    assert re.search(r"^on:$", text, re.MULTILINE), text
    assert re.search(r"^true: x$", text, re.MULTILINE), text


def test_the_census_reads_the_event_from_the_on_key_only(tmp_path):
    """A workflow whose top-level key is true:, not on:, has no trigger, so the census
    gives it push; with on: it gives the pull_request its on: has."""
    blocks = []
    for key in ("on", "true", "On"):
        workflow = GHA_SAVED_TEXT.replace("\non:\n", f"\n{key}:\n")
        blocks.append(
            f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\n{workflow}{FENCE}\n"
        )
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    path.write_text("\n".join(blocks), encoding="utf-8")
    checks = _checks()
    census = checks.ci_runner_census([checks.parse_page(path, tmp_path)])
    events = [entry.event for entry in census.legs[("act", "docs/page.md")]]
    assert events == ["pull_request", "push", "push"], events


#: Top-level keys PyYAML reads as true, as it reads a plain on:, and GitHub does not
#: read as on:; and the forms of on: GitHub reads as the trigger key.
NOT_THE_ON_KEY = ["true", "True", "On"]
THE_ON_KEY = ["on", "'on'", '"on"']


def _repository_workflow(root, key: str) -> str:
    """This repository's reusable scan workflow, with its triggers under ``key``, in
    the tree at ``root``; returns its path in the tree."""
    rel = ".github/workflows/scan.yml"
    path = root / rel
    path.parent.mkdir(parents=True)
    path.write_text(
        f"name: scan\n{key}:\n  workflow_call:\n    inputs:\n"
        "      ash-version: {type: string, default: main}\n"
        "      token-name: {type: string, required: true}\njobs: {}\n",
        encoding="utf-8",
    )
    return rel


def _workflow_call_problems(root, rel: str) -> list:
    uses = f"awslabs/automated-security-helper/{rel}@v3.7.0"
    job = {"uses": uses, "with": {"token-name": "x"}}
    return _api("_reusable_workflow_call_problems")(job, uses, rel, root)


@pytest.mark.parametrize("key", NOT_THE_ON_KEY)
def test_a_called_workflow_s_true_key_is_not_its_trigger_key(tmp_path, key):
    """The reusable-workflow call check reads the called workflow's on: key only. With
    its triggers under a true: key, GitHub reads no workflow_call, so the workflow
    cannot be called."""
    problems = _workflow_call_problems(tmp_path, _repository_workflow(tmp_path, key))
    assert any("declares no on.workflow_call" in p for p in problems), problems


@pytest.mark.parametrize("key", THE_ON_KEY)
def test_a_called_workflow_s_on_key_is_its_trigger_key(tmp_path, key):
    assert _workflow_call_problems(tmp_path, _repository_workflow(tmp_path, key)) == []


@pytest.mark.parametrize("key", NOT_THE_ON_KEY)
def test_a_workflow_s_true_key_declares_no_inputs_for_an_options_table(tmp_path, key):
    """An options table of=github-inputs:<workflow> reads the workflow_call and
    workflow_dispatch inputs under the workflow's on: key only."""
    rel = _repository_workflow(tmp_path, key)
    section, problem = _api("github_inputs_section")(f"github-inputs:{rel}", tmp_path)
    assert section is None, section
    assert problem is not None and "declares no inputs" in problem, problem


@pytest.mark.parametrize("key", THE_ON_KEY)
def test_a_workflow_s_on_key_declares_its_inputs_for_an_options_table(tmp_path, key):
    rel = _repository_workflow(tmp_path, key)
    section, problem = _api("github_inputs_section")(f"github-inputs:{rel}", tmp_path)
    assert problem is None, problem
    assert sorted(section.keys) == ["ash-version", "token-name"], section


# ---------------------------------------------------------------------------
# A pipeline of more than one YAML document
# ---------------------------------------------------------------------------


def test_a_saved_pipeline_of_two_documents_is_named_as_such():
    saved = GITLAB_TEXT + "---\n" + GITLAB_TEXT
    message = _compose_error("gitlab-ci", saved, GITLAB_SCRIPT)
    assert "2 YAML documents" in message, message
    assert "expected a single document" not in message, message


def test_a_fragment_of_two_documents_is_named_as_such():
    message = _compose_error(
        "gitlab-ci", GITLAB_TEXT, GITLAB_SCRIPT + "---\n" + GITLAB_SCRIPT
    )
    assert "2 YAML documents" in message, message


def test_the_config_check_names_a_saved_pipeline_of_two_documents(tmp_path):
    path = tmp_path / "docs" / "page.md"
    path.parent.mkdir(parents=True)
    saved = (
        "<!-- doctest: config kind=gitlab-ci save-as=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\n{GITLAB_TEXT}---\n{GITLAB_TEXT}{FENCE}\n"
    )
    fragment = (
        "<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml -->\n"
        f"{FENCE}yaml\n{GITLAB_SCRIPT}{FENCE}\n"
    )
    path.write_text(saved + "\n" + fragment, encoding="utf-8")
    fragment_fence = len(saved.split("\n")) + 2
    findings = _checks().check_config_blocks([path], tmp_path)
    assert any(
        f.line == fragment_fence and "2 YAML documents" in f.message for f in findings
    ), [str(f) for f in findings]
