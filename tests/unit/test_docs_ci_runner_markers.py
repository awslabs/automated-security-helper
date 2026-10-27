# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The marker grammar for CI pipelines that run under their CI system's own runner.

WHY THIS EXISTS
---------------
The CI pages hold complete pipelines and fragments of pipelines. The Docs CI Runners
workflow runs them with nektos/act, gitlab-ci-local, Jenkinsfile Runner, the AWS
CodeBuild local agent and the CircleCI CLI. Which block runs, merged into what, under
which event, is said by the block's marker, and scripts/docs_checks.py is the one
parser for it: the static checks and the runners read the same markers, so they cannot
disagree about what a block is.

What the grammar adds:

* two kinds: ``config kind=circleci`` on a yaml block, and ``config kind=jenkinsfile``
  on a groovy block (a declarative Jenkinsfile; the YAML ``jenkins`` kind is
  unchanged), which every groovy block must carry, so none drops out of the census
  (and a block fenced jenkinsfile is told to fence it as groovy);
* three keys on the kinds that have a runner (github-actions, gitlab-ci, buildspec,
  jenkinsfile, circleci): ``extends=<path>`` (a fragment, merged into the pipeline an
  earlier block on the page saved at that path; only github-actions and gitlab-ci have
  a merge rule, so the other three refuse it), ``event=<event>`` (the event the
  runner emulates), and ``runner=none reason="..."`` (not run; the static checks still
  apply).

Every way to get one of these wrong has its own message, so the contributor who wrote
the marker reads what to change.

WHAT THIS DOES NOT CHECK
------------------------
How a fragment is merged (test_docs_ci_runner_compose.py), which blocks each runner
runs (test_docs_ci_runner_census.py), or anything a runner does.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
FENCE = "```"

#: The kinds that are a CI system's pipeline file, before and after this grammar.
CI_KINDS = (
    "github-actions",
    "gitlab-ci",
    "buildspec",
    "azure-pipelines",
    "jenkins",
    "jenkinsfile",
    "circleci",
)


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
    """A name the CI-runner grammar adds to scripts/docs_checks.py, or a failure that
    says it is missing."""
    module = _checks()
    if not hasattr(module, name):
        pytest.fail(
            f"scripts/docs_checks.py defines no {name}, which the CI-runner marker "
            "grammar needs"
        )
    return getattr(module, name)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _marker_findings(root: Path, text: str) -> list:
    path = _write(root, "docs/page.md", text)
    return _checks().check_markers([path], root)


def _messages(findings) -> list[str]:
    return [str(finding) for finding in findings]


# ---------------------------------------------------------------------------
# Blocks used below
# ---------------------------------------------------------------------------

GHA_WORKFLOW = """\
name: ASH
on:
  pull_request:
  push:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Run ASH
        run: ash scan --mode local --no-progress
"""

GHA_STEPS = """\
- name: Run ASH
  run: ash scan --mode local --no-progress --fail-on-findings
"""

GITLAB_PIPELINE = """\
ash-scan:
  image: python:3.12
  script:
    - ash scan --mode local --no-progress
"""

GITLAB_FRAGMENT = """\
ash-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"""

BUILDSPEC = """\
version: 0.2
phases:
  build:
    commands:
      - ash scan --mode local --no-progress
"""

AZURE = """\
pool:
  vmImage: ubuntu-latest
steps:
  - script: ash scan --mode local --no-progress
"""

JENKINS_YAML = """\
pipeline:
  stages:
    - stage: ASH
      steps:
        - sh: ash scan --mode local --no-progress
"""

JENKINSFILE = """\
pipeline {
  agent any
  stages {
    stage('ASH') {
      steps {
        sh '''
          ash scan --mode local --no-progress
        '''
      }
    }
  }
}
"""

CIRCLECI = """\
version: 2.1
jobs:
  ash:
    docker:
      - image: cimg/python:3.12-node
    steps:
      - checkout
      - run: ash scan --mode local --no-progress
workflows:
  ash:
    jobs:
      - ash
"""


def _block(marker: str, body: str, lang: str = "yaml") -> str:
    return f"<!-- doctest: {marker} -->\n{FENCE}{lang}\n{body}{FENCE}\n"


# ---------------------------------------------------------------------------
# The two new kinds
# ---------------------------------------------------------------------------


def test_circleci_is_a_kind_whose_run_steps_get_the_cli_check(tmp_path):
    """A run step is a string or a mapping with command:. A bad ash flag in either is
    reported, and the marker itself is accepted."""
    body = """\
version: 2.1
jobs:
  ash:
    docker:
      - image: cimg/python:3.12-node
    steps:
      - checkout
      - run: ash scan --mode local --bogus-short-form
      - run:
          name: Run ASH
          command: |
            export PATH="$HOME/ash-venv/bin:$PATH"
            ash scan --mode local --bogus-long-form
"""
    page = _write(tmp_path, "docs/page.md", _block("config kind=circleci", body))
    checks = _checks()
    marker_findings = checks.check_markers([page], tmp_path)
    assert marker_findings == [], (
        "config kind=circleci must be a known kind: "
        + "; ".join(_messages(marker_findings))
    )
    cli = _messages(checks.check_cli([page], tmp_path))
    for flag in ("--bogus-short-form", "--bogus-long-form"):
        assert any(f"{flag} is not an option of 'ash scan'" in m for m in cli), (
            f"the CLI check did not read the ash line with {flag} in a CircleCI "
            f"run step; it reported: {cli}"
        )
    assert checks.check_config_blocks([page], tmp_path) == []


def test_jenkinsfile_is_a_kind_of_groovy_block_whose_sh_steps_get_the_cli_check(
    tmp_path,
):
    body = JENKINSFILE.replace("--no-progress", "--no-progress --bogus-in-sh")
    page = _write(
        tmp_path, "docs/page.md", _block("config kind=jenkinsfile", body, "groovy")
    )
    checks = _checks()
    marker_findings = checks.check_markers([page], tmp_path)
    assert marker_findings == [], (
        "config kind=jenkinsfile must be accepted on a groovy block: "
        + "; ".join(_messages(marker_findings))
    )
    cli = _messages(checks.check_cli([page], tmp_path))
    assert any("--bogus-in-sh is not an option of 'ash scan'" in m for m in cli), cli


def test_jenkinsfile_on_a_yaml_block_is_refused_and_the_yaml_jenkins_kind_is_unchanged(
    tmp_path,
):
    findings = _marker_findings(
        tmp_path,
        _block("config kind=jenkinsfile", BUILDSPEC)
        + "\n"
        + _block("config kind=jenkins", JENKINS_YAML),
    )
    on_yaml = [f for f in findings if f.line == 1]
    assert any(
        "config kind=jenkinsfile is a groovy block" in f.message for f in on_yaml
    ), (
        "a jenkinsfile marker on a yaml block must say the kind is for groovy "
        f"blocks; got {_messages(on_yaml)}"
    )
    assert [f for f in findings if f.line != 1] == [], (
        "the YAML jenkins kind takes the marker it always took"
    )


#: Groovy blocks the census would not count: unmarked, marked only save-as=, and marked
#: with a mode that does nothing on groovy.
GROOVY_MISTAKES = [
    ("unmarked", f"{FENCE}groovy\n{JENKINSFILE}{FENCE}\n"),
    ("save-as only", _block("save-as=Jenkinsfile", JENKINSFILE, "groovy")),
    (
        "another mode",
        _block("run", JENKINSFILE, "groovy"),
    ),
]


def test_every_groovy_block_is_marked_as_a_jenkinsfile(tmp_path):
    """The census counts a groovy block only when its marker names it a Jenkinsfile, so
    an unmarked one, or one marked only save-as=, would drop out of what the runners
    run with nothing failing. Each is one markers finding at line 1, with a message of
    its own that names config kind=jenkinsfile, and runner=none for a block no runner
    can run; the message for another mode no longer offers a bare save-as=. The
    control: the same block marked config kind=jenkinsfile, with save-as= or with
    runner=none and a reason, gives no finding."""
    messages = {}
    for case, text in GROOVY_MISTAKES:
        findings = _marker_findings(tmp_path / case.replace(" ", "-"), text)
        assert [f.line for f in findings] == [1], (case, _messages(findings))
        messages[case] = findings[0].message
    for case in ("unmarked", "save-as only"):
        assert "config kind=jenkinsfile" in messages[case], (case, messages[case])
        assert "runner=none" in messages[case], (case, messages[case])
    assert "bare save-as" not in messages["another mode"], messages["another mode"]
    assert len(set(messages.values())) == len(GROOVY_MISTAKES), messages
    for index, marker in enumerate(
        (
            "config kind=jenkinsfile save-as=Jenkinsfile",
            'config kind=jenkinsfile runner=none reason="needs a Docker agent"',
        )
    ):
        findings = _marker_findings(
            tmp_path / f"control-{index}", _block(marker, JENKINSFILE, "groovy")
        )
        assert findings == [], (marker, _messages(findings))


#: Groovy that is not a Jenkinsfile: a Gradle build file a page shows.
GRADLE_GROOVY = """\
plugins {
    id 'java'
}
"""


def test_an_illustrative_groovy_block_is_accepted_with_a_reason(tmp_path):
    """Groovy that is not a Jenkinsfile (a Gradle build file, a test class) has no
    truthful config kind: kind=jenkinsfile would mislabel it and put its sh steps
    through the Jenkinsfile rules. illustrative reason="..." marks it shown-only,
    the reason recording why it is outside the runner census. The reason is still
    required, and the unmarked message names the option."""
    accepted = _marker_findings(
        tmp_path / "ok",
        _block(
            'illustrative reason="a Gradle build file, not a Jenkinsfile"',
            GRADLE_GROOVY,
            "groovy",
        ),
    )
    assert accepted == [], _messages(accepted)
    missing = _marker_findings(
        tmp_path / "bare", _block("illustrative", GRADLE_GROOVY, "groovy")
    )
    assert [f.line for f in missing] == [1], _messages(missing)
    assert 'illustrative needs reason="..."' in missing[0].message
    extra = _marker_findings(
        tmp_path / "extra",
        _block(
            'illustrative reason="a Gradle build file" fixture=x',
            GRADLE_GROOVY,
            "groovy",
        ),
    )
    assert [f.line for f in extra] == [1], _messages(extra)
    assert "illustrative takes only reason=" in extra[0].message
    unmarked = _marker_findings(
        tmp_path / "unmarked", f"{FENCE}groovy\n{GRADLE_GROOVY}{FENCE}\n"
    )
    assert [f.line for f in unmarked] == [1], _messages(unmarked)
    assert "illustrative" in unmarked[0].message, unmarked[0].message


#: A Jenkinsfile fenced with its file name instead of groovy, in each state its marker
#: can be in: unmarked, marked only save-as=, and marked as a Jenkinsfile.
JENKINSFILE_FENCE_MISTAKES = [
    (f"{fence} {case}", text)
    for fence in ("jenkinsfile", "Jenkinsfile")
    for case, text in (
        ("unmarked", f"{FENCE}{fence}\n{JENKINSFILE}{FENCE}\n"),
        ("save-as only", _block("save-as=Jenkinsfile", JENKINSFILE, fence)),
        ("marked", _block("config kind=jenkinsfile", JENKINSFILE, fence)),
    )
]


@pytest.mark.parametrize(
    "text",
    [text for _, text in JENKINSFILE_FENCE_MISTAKES],
    ids=[case for case, _ in JENKINSFILE_FENCE_MISTAKES],
)
def test_a_block_fenced_jenkinsfile_is_told_to_fence_it_as_groovy(tmp_path, text):
    """The marker rules for config kind=jenkinsfile and the sh-step checks apply only
    to a groovy block, so one fenced jenkinsfile or Jenkinsfile gets no check, and
    unmarked it drops out of what the runners run. Each is one markers finding at line
    1 that says to fence it as groovy and mark it config kind=jenkinsfile, with
    runner=none for a block no runner can run. The control: the same text in a text
    block gives no finding."""
    findings = _marker_findings(tmp_path / "page", text)
    assert [f.line for f in findings] == [1], _messages(findings)
    message = findings[0].message
    for part in ("as groovy", "config kind=jenkinsfile", "runner=none"):
        assert part in message, (part, message)
    control = _marker_findings(
        tmp_path / "control", f"{FENCE}text\n{JENKINSFILE}{FENCE}\n"
    )
    assert control == [], _messages(control)


# ---------------------------------------------------------------------------
# The three new keys, where they are accepted
# ---------------------------------------------------------------------------

ACCEPTED = "\n".join(
    [
        _block(
            "config kind=github-actions save-as=.github/workflows/ash.yml",
            GHA_WORKFLOW,
        ),
        _block(
            "config kind=github-actions extends=.github/workflows/ash.yml event=push",
            GHA_STEPS,
        ),
        _block("config kind=github-actions event=pull_request", GHA_WORKFLOW),
        _block(
            'config kind=github-actions runner=none reason="uploads to code scanning '
            'of a repository the runner cannot reach"',
            GHA_WORKFLOW,
        ),
        _block("config kind=gitlab-ci save-as=.gitlab-ci.yml", GITLAB_PIPELINE),
        _block(
            "config kind=gitlab-ci extends=.gitlab-ci.yml event=merge_request",
            GITLAB_FRAGMENT,
        ),
        _block("config kind=gitlab-ci event=push", GITLAB_PIPELINE),
        _block(
            'config kind=buildspec runner=none reason="part of a larger buildspec '
            'that scans in container mode"',
            BUILDSPEC,
        ),
        _block("config kind=buildspec", BUILDSPEC),
        _block("config kind=jenkinsfile", JENKINSFILE, "groovy"),
        _block(
            'config kind=jenkinsfile runner=none reason="needs a Docker agent '
            'with a label"',
            JENKINSFILE,
            "groovy",
        ),
        _block("config kind=circleci", CIRCLECI),
        _block(
            'config kind=circleci runner=none reason="uses a private orb"', CIRCLECI
        ),
    ]
)


def test_every_new_key_is_accepted_on_the_kinds_that_have_a_runner(tmp_path):
    findings = _marker_findings(tmp_path, ACCEPTED)
    assert findings == [], (
        "extends=, event= and runner=none reason=... must be accepted on "
        "github-actions, gitlab-ci, buildspec, jenkinsfile and circleci blocks: "
        + "; ".join(_messages(findings))
    )


def test_a_fragment_that_extends_a_saved_block_passes_the_config_check(tmp_path):
    """The lint merges each fragment into the block it extends; these two merge."""
    page = _write(tmp_path, "docs/page.md", ACCEPTED)
    findings = _checks().check_config_blocks([page], tmp_path)
    assert findings == [], _messages(findings)
    # The check above had two fragments to merge: the page's two extends= blocks.
    ci_marker = _api("ci_marker")
    markers = [ci_marker(b) for b in _checks().parse_page(page, tmp_path).blocks]
    assert sum(1 for m in markers if m is not None and m.extends) == 2


# ---------------------------------------------------------------------------
# Every way to get the new keys wrong, each with its own message
# ---------------------------------------------------------------------------

SAVED_GHA = _block(
    "config kind=github-actions save-as=.github/workflows/ash.yml", GHA_WORKFLOW
)
SAVED_GITLAB = _block("config kind=gitlab-ci save-as=.ci/pipeline.yml", GITLAB_PIPELINE)

#: (case id, error id, page text, line of the marker at fault, text the message holds)
#: Cases that share an error id are the same mistake on different kinds or keys, and
#: share a message; different error ids must have different messages.
MARKER_DEFECTS = [
    (
        "azure extends",
        "azure has no runner",
        _block("config kind=azure-pipelines extends=x.yml", AZURE),
        1,
        "config kind=azure-pipelines has no runner",
    ),
    (
        "azure event",
        "azure has no runner",
        _block("config kind=azure-pipelines event=push", AZURE),
        1,
        "config kind=azure-pipelines has no runner",
    ),
    (
        "azure runner none",
        "azure has no runner",
        _block(
            'config kind=azure-pipelines runner=none reason="needs an Azure DevOps '
            'organization"',
            AZURE,
        ),
        1,
        "config kind=azure-pipelines has no runner",
    ),
    (
        "runner other than none",
        "runner value",
        _block("config kind=github-actions runner=act", GHA_WORKFLOW),
        1,
        "runner= takes only none",
    ),
    (
        "runner none without reason",
        "runner needs reason",
        _block("config kind=gitlab-ci runner=none", GITLAB_PIPELINE),
        1,
        'runner=none needs reason="..."',
    ),
    (
        "placeholder reason",
        "placeholder reason",
        _block('config kind=buildspec runner=none reason="example"', BUILDSPEC),
        1,
        "is a placeholder and names no cause",
    ),
    (
        "vague reason",
        "vague reason",
        _block(
            'config kind=circleci runner=none reason="illustrative example only"',
            CIRCLECI,
        ),
        1,
        "names no cause",
    ),
    (
        "reason without runner none",
        "reason alone",
        _block(
            'config kind=github-actions reason="needs a GitHub App token"',
            GHA_WORKFLOW,
        ),
        1,
        "reason= goes with runner=none",
    ),
    (
        "github event not in its set",
        "event not of kind",
        _block("config kind=github-actions event=merge_request", GHA_WORKFLOW),
        1,
        "event=merge_request is not an event of config kind=github-actions",
    ),
    (
        "gitlab event not in its set",
        "event not of kind",
        _block("config kind=gitlab-ci event=pull_request", GITLAB_PIPELINE),
        1,
        "event=pull_request is not an event of config kind=gitlab-ci",
    ),
    (
        "buildspec event",
        "kind has no events",
        _block("config kind=buildspec event=push", BUILDSPEC),
        1,
        "config kind=buildspec takes no event=",
    ),
    (
        "jenkinsfile event",
        "kind has no events",
        _block("config kind=jenkinsfile event=push", JENKINSFILE, "groovy"),
        1,
        "config kind=jenkinsfile takes no event=",
    ),
    (
        "circleci event",
        "kind has no events",
        _block("config kind=circleci event=push", CIRCLECI),
        1,
        "config kind=circleci takes no event=",
    ),
    (
        "extends a path nothing saves",
        "extends names no saved block",
        _block(
            "config kind=github-actions extends=.github/workflows/ash.yml", GHA_STEPS
        ),
        1,
        (
            "extends=.github/workflows/ash.yml names no earlier block on this page "
            "saved with save-as=.github/workflows/ash.yml"
        ),
    ),
    (
        "extends a block saved later on the page",
        "extends names no saved block",
        _block(
            "config kind=github-actions extends=.github/workflows/ash.yml", GHA_STEPS
        )
        + "\n"
        + SAVED_GHA,
        1,
        "names no earlier block on this page saved with",
    ),
    (
        "extends a block of another kind",
        "extends another kind",
        SAVED_GITLAB
        + "\n"
        + _block("config kind=github-actions extends=.ci/pipeline.yml", GHA_STEPS),
        len(SAVED_GITLAB.split("\n")) + 1,
        "can extend only a block of its own kind",
    ),
    (
        "extends and save-as together",
        "fragment saved",
        SAVED_GHA
        + "\n"
        + _block(
            "config kind=github-actions extends=.github/workflows/ash.yml "
            "save-as=.github/workflows/other.yml",
            GHA_STEPS,
        ),
        len(SAVED_GHA.split("\n")) + 1,
        "cannot also be saved",
    ),
]


@pytest.mark.parametrize(
    "case,error,text,line,expected",
    MARKER_DEFECTS,
    ids=[case[0] for case in MARKER_DEFECTS],
)
def test_each_wrong_use_of_the_new_keys_is_reported(
    tmp_path, case, error, text, line, expected
):
    findings = _marker_findings(tmp_path, text)
    at_marker = [f for f in findings if f.line == line]
    assert any(expected in f.message for f in at_marker), (
        f"{case}: expected a finding at line {line} containing {expected!r}, "
        f"got {_messages(findings)}"
    )
    generic = [f for f in at_marker if "does not take" in f.message]
    assert not generic, (
        f"{case}: the new keys are part of the CI kinds' grammar, so the generic "
        f"'does not take' message must not be what reports them: {_messages(generic)}"
    )


def test_the_messages_of_different_mistakes_differ(tmp_path):
    seen: dict[str, set[str]] = {}
    for case, error, text, line, expected in MARKER_DEFECTS:
        root = tmp_path / re.sub(r"\W+", "-", case)
        findings = _marker_findings(root, text)
        messages = {
            f.message for f in findings if f.line == line and expected in f.message
        }
        assert messages, f"{case}: no finding containing {expected!r}"
        seen.setdefault(error, set()).update(messages)
    errors = sorted(seen)
    for index, first in enumerate(errors):
        for second in errors[index + 1 :]:
            shared = seen[first] & seen[second]
            assert not shared, (
                f"'{first}' and '{second}' are different mistakes reported with the "
                f"same message: {sorted(shared)}"
            )


def test_an_unknown_key_is_reported_alone(tmp_path):
    """The one unknown key is named; the valid key beside it is not."""
    findings = _marker_findings(
        tmp_path, _block("config kind=gitlab-ci event=push bogus=1", GITLAB_PIPELINE)
    )
    at_marker = [f for f in findings if f.line == 1]
    assert len(at_marker) == 1, _messages(findings)
    assert "bogus" in at_marker[0].message
    assert "event" not in at_marker[0].message, (
        "event= is a key of config kind=gitlab-ci, so only bogus= may be reported: "
        + at_marker[0].message
    )


# ---------------------------------------------------------------------------
# extends= on a kind that has a runner but no merge rule
# ---------------------------------------------------------------------------

#: (kind, a block of that kind, its fence language, the path a page saves it at). Each
#: has a runner, and no rule says how a fragment of it merges into a saved one.
NO_MERGE_RULE_KINDS = [
    ("buildspec", BUILDSPEC, "yaml", "buildspec.yml"),
    ("jenkinsfile", JENKINSFILE, "groovy", "Jenkinsfile"),
    ("circleci", CIRCLECI, "yaml", ".circleci/config.yml"),
]

RUNNER_NONE_REASON = 'reason="part of a larger file that the page does not show"'


def _saves_then_extends(kind: str, body: str, lang: str, path: str) -> tuple[str, int]:
    """A page that saves a block of the kind at the path, then extends it: the text, and
    the line of the second block's marker."""
    saved = _block(f"config kind={kind} save-as={path}", body, lang)
    fragment = _block(f"config kind={kind} extends={path}", body, lang)
    return saved + "\n" + fragment, len(saved.split("\n")) + 1


@pytest.mark.parametrize(
    "kind,body,lang,path",
    NO_MERGE_RULE_KINDS,
    ids=[case[0] for case in NO_MERGE_RULE_KINDS],
)
def test_extends_on_a_kind_with_no_merge_rule_is_refused(
    tmp_path, kind, body, lang, path
):
    """A fragment of a buildspec, a Jenkinsfile or a CircleCI config could only run as a
    pipeline the page does not show, so extends= is refused on them, even when an
    earlier block of the kind is saved at the path. The finding is the only one on the
    page, and its message is this mistake's own: not the generic one, not the one for a
    kind with no runner, and not any other wrong use's."""
    text, line = _saves_then_extends(kind, body, lang, path)
    findings = _marker_findings(tmp_path / "page", text)
    expected = f"config kind={kind} has no merge rule, so it takes no extends="
    assert [f for f in findings if f.line != line] == [], _messages(findings)
    at_marker = [f for f in findings if f.line == line]
    assert len(at_marker) == 1 and expected in at_marker[0].message, (
        f"expected one finding at line {line} containing {expected!r}, got "
        f"{_messages(findings)}"
    )
    message = at_marker[0].message
    assert "does not take" not in message, message
    assert "has no runner" not in message, message
    others = set()
    for case, _error, defect_text, defect_line, _expected in MARKER_DEFECTS:
        root = tmp_path / re.sub(r"\W+", "-", case)
        others |= {
            f.message
            for f in _marker_findings(root, defect_text)
            if f.line == defect_line
        }
    assert message not in others, (
        f"extends= on config kind={kind} is reported with another mistake's message: "
        f"{message}"
    )


def test_the_no_merge_rule_message_says_to_drop_extends_on_a_runner_none_block(
    tmp_path,
):
    """A block that is already runner=none is told to drop extends=, not only to mark
    itself runner=none."""
    text, line = _saves_then_extends(*NO_MERGE_RULE_KINDS[0])
    text = text.replace(
        "config kind=buildspec extends=buildspec.yml",
        f"config kind=buildspec runner=none {RUNNER_NONE_REASON} extends=buildspec.yml",
    )
    findings = _marker_findings(tmp_path, text)
    assert [f.line for f in findings] == [line], _messages(findings)
    message = findings[0].message
    assert message.startswith(
        "config kind=buildspec has no merge rule, so it takes no extends="
    ), message
    assert "drop extends=" in message, message


@pytest.mark.parametrize(
    "kind,body,lang,path",
    NO_MERGE_RULE_KINDS,
    ids=[case[0] for case in NO_MERGE_RULE_KINDS],
)
def test_the_same_blocks_without_extends_are_accepted(tmp_path, kind, body, lang, path):
    """The control: the page above with the second marker's extends= dropped, plus a
    runner=none block, has no finding. save-as= and runner=none reason="..." stay keys
    of these kinds (none of them takes event=)."""
    text = "\n".join(
        [
            _block(f"config kind={kind} save-as={path}", body, lang),
            _block(f"config kind={kind}", body, lang),
            _block(f"config kind={kind} runner=none {RUNNER_NONE_REASON}", body, lang),
        ]
    )
    findings = _marker_findings(tmp_path, text)
    assert findings == [], _messages(findings)


# ---------------------------------------------------------------------------
# event= naming an event the workflow does not run on
# ---------------------------------------------------------------------------

PUSH_ONLY_WORKFLOW = GHA_WORKFLOW.replace("  pull_request:\n", "")
PULL_REQUEST_ONLY_WORKFLOW = GHA_WORKFLOW.replace("  push:\n", "")

#: (case id, page text, line of the marker at fault, the event)
EVENT_NOT_TRIGGERED = [
    (
        "pull_request on a push-only workflow",
        _block("config kind=github-actions event=pull_request", PUSH_ONLY_WORKFLOW),
        1,
        "pull_request",
    ),
    (
        "push on a pull_request-only workflow",
        _block("config kind=github-actions event=push", PULL_REQUEST_ONLY_WORKFLOW),
        1,
        "push",
    ),
    (
        "push on a fragment whose merged workflow has no push",
        _block(
            "config kind=github-actions save-as=.github/workflows/ash.yml",
            PULL_REQUEST_ONLY_WORKFLOW,
        )
        + "\n"
        + _block(
            "config kind=github-actions extends=.github/workflows/ash.yml event=push",
            GHA_STEPS,
        ),
        len(
            _block(
                "config kind=github-actions save-as=.github/workflows/ash.yml",
                PULL_REQUEST_ONLY_WORKFLOW,
            ).split("\n")
        )
        + 1,
        "push",
    ),
    # PyYAML reads these keys as true, as it reads a plain on:. Only on: is the
    # trigger key to GitHub, so these workflows have no event.
    (
        "pull_request on a workflow whose top-level key is true:, not on:",
        _block(
            "config kind=github-actions event=pull_request",
            GHA_WORKFLOW.replace("\non:\n", "\ntrue:\n"),
        ),
        1,
        "pull_request",
    ),
    (
        "pull_request on a workflow whose top-level key is On:, not on:",
        _block(
            "config kind=github-actions event=pull_request",
            GHA_WORKFLOW.replace("\non:\n", "\nOn:\n"),
        ),
        1,
        "pull_request",
    ),
]


@pytest.mark.parametrize(
    "case,text,line,event",
    EVENT_NOT_TRIGGERED,
    ids=[c[0] for c in EVENT_NOT_TRIGGERED],
)
def test_an_event_the_workflow_does_not_run_on_is_reported(
    tmp_path, case, text, line, event
):
    """A runner emulating an event the workflow's on: lacks starts none of its jobs,
    so the block would pass without running anything. The marker check says so, with a
    message no other mistake has."""
    findings = _marker_findings(tmp_path / "page", text)
    assert [f.line for f in findings] == [line], _messages(findings)
    message = findings[0].message
    assert f"on: has no {event}" in message, message
    assert "does not take" not in message, message
    others = set()
    for defect_case, _error, defect_text, defect_line, _expected in MARKER_DEFECTS:
        root = tmp_path / re.sub(r"\W+", "-", defect_case)
        others |= {
            f.message
            for f in _marker_findings(root, defect_text)
            if f.line == defect_line
        }
    assert message not in others, message


def test_an_event_the_workflow_runs_on_is_accepted(tmp_path):
    """The control: the same blocks with the event their on: has."""
    text = "\n".join(
        [
            _block("config kind=github-actions event=push", PUSH_ONLY_WORKFLOW),
            _block(
                "config kind=github-actions event=pull_request",
                PULL_REQUEST_ONLY_WORKFLOW,
            ),
            _block(
                "config kind=github-actions save-as=.github/workflows/ash.yml",
                PULL_REQUEST_ONLY_WORKFLOW,
            ),
            _block(
                "config kind=github-actions extends=.github/workflows/ash.yml "
                "event=pull_request",
                GHA_STEPS,
            ),
        ]
    )
    findings = _marker_findings(tmp_path, text)
    assert findings == [], _messages(findings)


# ---------------------------------------------------------------------------
# What a CI marker says, read once
# ---------------------------------------------------------------------------


def test_ci_marker_reads_every_key_of_a_ci_block(tmp_path):
    page_text = "\n".join(
        [
            SAVED_GHA,
            _block(
                "config kind=github-actions extends=.github/workflows/ash.yml event=push",
                GHA_STEPS,
            ),
            _block(
                'config kind=circleci runner=none reason="uses a private orb"', CIRCLECI
            ),
            _block("config kind=jenkinsfile", JENKINSFILE, "groovy"),
            _block("config kind=ash", "global_settings:\n  severity_threshold: HIGH\n"),
            f"{FENCE}groovy\n{JENKINSFILE}{FENCE}\n",
        ]
    )
    path = _write(tmp_path, "docs/page.md", page_text)
    blocks = _checks().parse_page(path, tmp_path).blocks
    ci_marker = _api("ci_marker")
    got = [ci_marker(block) for block in blocks]
    fields = [
        None
        if marker is None
        else (
            marker.kind,
            marker.save_as,
            marker.extends,
            marker.event,
            marker.runner,
            marker.reason,
        )
        for marker in got
    ]
    assert fields == [
        ("github-actions", ".github/workflows/ash.yml", None, None, None, None),
        ("github-actions", None, ".github/workflows/ash.yml", "push", None, None),
        ("circleci", None, None, None, "none", "uses a private orb"),
        ("jenkinsfile", None, None, None, None, None),
        None,  # an ASH config is not a CI pipeline
        None,  # an unmarked groovy block is not one either
    ]


# ---------------------------------------------------------------------------
# The markers already on the pages still parse, and read the same
# ---------------------------------------------------------------------------

#: The CI markers the pages carried before this grammar, each on a block of its kind.
EXISTING_MARKERS = [
    ("github-actions", GHA_WORKFLOW),
    ("gitlab-ci", GITLAB_PIPELINE),
    ("buildspec", BUILDSPEC),
    ("azure-pipelines", AZURE),
    ("jenkins", JENKINS_YAML),
]


@pytest.mark.parametrize(
    "kind,body", EXISTING_MARKERS, ids=[k for k, _ in EXISTING_MARKERS]
)
def test_an_existing_ci_marker_still_parses_and_reads_as_a_complete_pipeline(
    tmp_path, kind, body
):
    path = _write(tmp_path, "docs/page.md", _block(f"config kind={kind}", body))
    checks = _checks()
    assert checks.check_markers([path], tmp_path) == []
    (block,) = checks.parse_page(path, tmp_path).blocks
    marker = _api("ci_marker")(block)
    assert marker is not None, f"config kind={kind} is a CI pipeline"
    assert (
        marker.kind,
        marker.save_as,
        marker.extends,
        marker.event,
        marker.runner,
    ) == (
        kind,
        None,
        None,
        None,
        None,
    )


def _ci_pages() -> list[Path]:
    """Every tracked page and template with a CI marker, found without the parser."""
    marker = re.compile(
        r"^\s*<!--\s*doctest:\s*config\b[^>]*\bkind=(" + "|".join(CI_KINDS) + r")\b"
    )
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md", "*.md.template"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    pages = []
    for rel in sorted(filter(None, listed.split("\0"))):
        path = REPO_ROOT / rel
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(marker.match(line) for line in text.split("\n")):
            pages.append(path)
    return pages


def test_every_ci_marker_on_the_real_pages_parses_and_reads_as_written():
    """The regression row over the corpus: whatever CI markers the pages carry, the
    marker check accepts them, and ci_marker reads back exactly the keys they hold."""
    checks = _checks()
    ci_marker = _api("ci_marker")
    pages = _ci_pages()
    assert len(pages) >= 8, (
        f"found {len(pages)} pages with a CI marker; expected the CI pages"
    )
    findings = checks.check_markers(pages, REPO_ROOT)
    assert findings == [], _messages(findings)
    read = 0
    for page in checks.load_pages(pages, REPO_ROOT):
        for block in page.blocks:
            if block.marker is None or block.marker.keys.get("kind") not in CI_KINDS:
                continue
            marker = ci_marker(block)
            keys = block.marker.keys
            assert marker is not None, f"{page.rel}:{block.fence_line}"
            assert (
                marker.kind,
                marker.save_as,
                marker.extends,
                marker.event,
                marker.runner,
                marker.reason,
            ) == (
                keys["kind"],
                keys.get("save-as"),
                keys.get("extends"),
                keys.get("event"),
                keys.get("runner"),
                keys.get("reason"),
            ), f"{page.rel}:{block.fence_line}"
            read += 1
    assert read >= 15, f"read {read} CI markers; the CI pages hold more"
