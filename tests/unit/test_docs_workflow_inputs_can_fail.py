# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A docs example passes run-ash-security-scan.yml only values its input check accepts.

WHY THIS EXISTS
---------------
The reusable scan workflow's first step refuses any string input that holds a control
character or the legacy command marker ``##[``: the runner reads such a value as the
start of a workflow command on any line that prints it. It drops one line feed at the
end first, so a one-line ``|`` block passes, and refuses a value that is only a line
feed. The CI checks of a docs example read only the
names in ``with:`` (declared, required, secrets), so an example whose ``ash-args`` is a
two-line block, or holds ``##[group]``, passed every check and failed in the reader's
first run.

check_workflow_inputs reads every ``with:`` value that a ``config kind=github-actions``
block passes to run-ash-security-scan.yml and reports one the workflow would refuse. The
inputs it checks are the workflow's own: the step that loops over "${!INPUT_@}", whose
env maps each INPUT_<NAME> to ${{ inputs.<name> }}. A workflow with no such step fails
the check closed, since it cannot tell which inputs are refused.

Like test_docs_checks_can_fail.py, every page and workflow lives in tmp_path, and
nothing runs a workflow.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
FENCE = "```"
SCAN = ".github/workflows/run-ash-security-scan.yml"


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


dc = _load("_ash_docs_checks", CHECKS_PATH)

#: The scan workflow, cut down to what the check reads: its inputs, and the first
#: step's INPUT_ list. artifact-id is a string input the step does not list.
WORKFLOW = """name: scan
on:
  workflow_call:
    inputs:
      ash-version: {type: string, default: main}
      ash-args: {type: string, default: ''}
      artifact-id: {type: string, default: ash}
      fail-on-findings: {type: boolean, default: true}
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Refuse an input that could start a workflow command
        env:
          INPUT_ASH_VERSION: ${{ inputs.ash-version }}
          INPUT_ASH_ARGS: ${{ inputs.ash-args }}
        run: |
          export LC_ALL=C
          for var in "${!INPUT_@}"; do
            given="${!var}"
            value="${given%$'\\n'}"
            case "${value}" in
              *[[:cntrl:]]* | *$'\\xc2'[$'\\x80'-$'\\x9f']* | *$'\\xe2\\x80'[$'\\xa8\\xa9']* | *'##['*)
                exit 1 ;;
            esac
            if [ -z "${value}" ] && [ -n "${given}" ]; then exit 1; fi
          done
"""


def _code(tmp_path: Path, workflow: str = WORKFLOW) -> Path:
    code = tmp_path / "code"
    path = code / ".github" / "workflows" / "run-ash-security-scan.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    return code


def _page(tmp_path: Path, with_block: str, workflow: str = "run-ash-security-scan.yml"):
    text = (
        "# CI\n\n<!-- doctest: config kind=github-actions -->\n"
        f"{FENCE}yaml\njobs:\n  ash:\n"
        f"    uses: awslabs/automated-security-helper/.github/workflows/{workflow}@v3.7.0\n"
        f"    with:\n{with_block}{FENCE}\n"
    )
    page = tmp_path / "docs" / "ci.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(text, encoding="utf-8")
    return page, text


def _check(tmp_path: Path, with_block: str, **kwargs):
    page, text = _page(tmp_path, with_block, **kwargs)
    notes: list[str] = []
    findings = dc.check_workflow_inputs(
        [page], tmp_path, code=_code(tmp_path), notes=notes
    )
    return findings, text, notes


def _line_of(text: str, needle: str) -> int:
    return next(n for n, line in enumerate(text.split("\n"), 1) if needle in line)


def test_a_multi_line_ash_args_is_reported(tmp_path):
    findings, text, _notes = _check(
        tmp_path, "      ash-args: |\n        --scanners bandit\n        --verbose\n"
    )
    (finding,) = findings
    assert finding.check == "workflow-inputs"
    assert finding.line == _line_of(text, "ash-args:")
    assert "ash-args" in finding.message
    assert "line break" in finding.message
    assert "run-ash-security-scan.yml" in finding.message


def test_the_legacy_command_marker_is_reported(tmp_path):
    """Quoted: unquoted, YAML reads " ##[group]x" as a comment, as the runner does."""
    findings, _text, _notes = _check(
        tmp_path, '      ash-args: "--scanners bandit ##[group]x"\n'
    )
    (finding,) = findings
    assert "ash-args" in finding.message
    assert "##[" in finding.message


def test_a_one_line_block_passes(tmp_path):
    """Control: a `|` block of one line ends in one line feed, which the check allows."""
    findings, _text, notes = _check(
        tmp_path,
        "      ash-version: v3.7.0\n      ash-args: |\n        --scanners bandit\n",
    )
    assert findings == []
    assert notes == [f"examined 2 input values in 1 block that calls {SCAN}"]


def test_every_other_control_character_is_reported(tmp_path):
    """The step refuses C0 and DEL through [[:cntrl:]] under LC_ALL=C, and C1 and the
    line and paragraph separators (YAML's \\L and \\P) by their UTF-8 bytes, so the
    answer is the same whatever locale the runner has."""
    for value, why in (
        ('"--scanners\\tbandit"', "control character 0x09"),
        ('"--scanners bandit\\r"', "line break"),
        ('"a\\n\\n"', "line break"),
        ('"x\\x85y"', "control character 0x85"),
        ('"x\\Ly"', "control character 0x2028"),
        ('"x\\Py"', "control character 0x2029"),
    ):
        findings, _text, _notes = _check(tmp_path, f"      ash-version: {value}\n")
        assert [why in f.message for f in findings] == [True], (value, findings)


def test_a_value_that_is_only_a_line_feed_is_reported(tmp_path):
    """Dropping the one trailing line feed leaves nothing, which the workflow refuses
    so that a later step reading the input as given agrees it is not empty. An empty
    value is the control: it passes."""
    findings, _text, _notes = _check(tmp_path, '      ash-version: "\\n"\n')
    (finding,) = findings
    assert "ash-version" in finding.message
    assert "only a line feed" in finding.message
    assert "Leave it empty" in finding.message
    findings, _text, notes = _check(tmp_path, '      ash-version: ""\n')
    assert findings == []
    assert notes == [f"examined 1 input value in 1 block that calls {SCAN}"]


def test_only_the_inputs_the_workflow_checks_are_read(tmp_path):
    """artifact-id is not in the step's INPUT_ list, and fail-on-findings is a
    boolean, so the workflow refuses neither value and neither is reported."""
    findings, _text, notes = _check(
        tmp_path,
        "      artifact-id: |\n        a\n        b\n      fail-on-findings: false\n",
    )
    assert findings == []
    assert notes == [f"examined 0 input values in 1 block that calls {SCAN}"]


def test_the_list_of_checked_inputs_is_the_workflows(tmp_path):
    """Adding artifact-id to the step's env makes the same page a finding."""
    workflow = WORKFLOW.replace(
        "          INPUT_ASH_ARGS: ${{ inputs.ash-args }}\n",
        "          INPUT_ASH_ARGS: ${{ inputs.ash-args }}\n"
        "          INPUT_ARTIFACT_ID: ${{ inputs.artifact-id }}\n",
    )
    assert workflow != WORKFLOW
    assert dc.checked_workflow_inputs(WORKFLOW) == {"ash-version", "ash-args"}
    assert dc.checked_workflow_inputs(workflow) == {
        "ash-version",
        "ash-args",
        "artifact-id",
    }
    page, _text = _page(tmp_path, "      artifact-id: |\n        a\n        b\n")
    (finding,) = dc.check_workflow_inputs(
        [page], tmp_path, code=_code(tmp_path, workflow)
    )
    assert "artifact-id" in finding.message


def test_a_workflow_with_no_input_check_fails_closed(tmp_path):
    workflow = WORKFLOW.split("    steps:")[0] + "    steps:\n      - run: echo hi\n"
    page, _text = _page(tmp_path, "      ash-args: --scanners bandit\n")
    (finding,) = dc.check_workflow_inputs(
        [page], tmp_path, code=_code(tmp_path, workflow)
    )
    assert "cannot tell which inputs" in finding.message


def test_a_call_to_another_workflow_is_not_read(tmp_path):
    findings, _text, notes = _check(
        tmp_path, "      ash-args: |\n        a\n        b\n", workflow="other.yml"
    )
    assert findings == []
    assert notes == [f"examined 0 input values in 0 blocks that call {SCAN}"]
