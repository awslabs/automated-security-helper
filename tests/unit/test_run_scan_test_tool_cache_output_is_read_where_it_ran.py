"""A step of run-scan-test reads the tool-cache restore's output where it can have run.

Why this file exists
--------------------
.github/actions/run-scan-test/action.yml restores the tool download cache in the step
with the id `tool-cache`, and each step that runs ASH maps ASH_TOOL_DOWNLOAD_CACHE from
that step's `dir` output (tests/unit/test_build_handoffs_reach_every_consumer.py holds
every step that runs ASH after a restore to it). The outputs of a step the runner
skips are empty strings. So a step that never runs in a context where the restore ran
gets an empty ASH_TOOL_DOWNLOAD_CACHE: a mapping that reads as a wired cache and is
none. ASH reads an empty value as "no cache", so nothing fails and nothing is saved.

That was the state of the two python-container steps that map it. The restore ran for
`inputs.method == 'python-local'` only, and those steps run for `python-container`
only, so the value they got was always the empty string. The restore now runs for both
methods, as the tool-download-cache action says it is meant to ("Restored everywhere,
saved from a push to main only"), and the save stays python-local only.

What is asserted
----------------
The `if:` of the restore and of each step that names `steps.tool-cache.outputs.` is
evaluated over every method the action knows (the ones the `method` input lists and the
ones a condition names), on Linux, macOS and Windows, with the default config file and
the alpha one. A step that runs in some of those contexts and in none where the restore
ran is a failure, and the message names the methods it runs under.

What it does not cover
----------------------
A step that runs under several methods and reads the output is accepted when the restore
ran under one of them: "Validate ASH config files" runs for both python methods, and
"Install Alpha Plugin Tools" runs for the alpha config under any method, so its value is
empty under a method without the restore. The repository's own convention, in
tests/unit/test_build_handoffs_reach_every_consumer.py, asks every step that runs ASH
to map the variable, and the cost of an empty one is nothing, so this file asks only
that the value is not empty in every context a step runs in.

The conditions are evaluated by the model in tests/utils/github_actions.py, which
raises on syntax it does not read. A step whose own condition names another step's
output is refused here, since its context is not modeled.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils.github_actions import base_context, condition_holds

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"
#: The id of the restore step, and so the name its outputs are read by.
RESTORE_ID = "tool-cache"
RUNNER_OSES = ("Linux", "macOS", "Windows")
CONFIG_FILES = ("default", "alpha")
#: The steps of the action that map the variable and run for python-container only.
PYTHON_CONTAINER_STEPS = (
    "Validate ASH using Python + Container",
    "Validate No Plugin Errors (Python Container)",
)


def _load() -> dict[str, Any]:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def _steps(action: dict[str, Any]) -> list[dict[str, Any]]:
    return action["runs"]["steps"]


def _label(step: dict[str, Any]) -> str:
    return str(step.get("name") or step.get("id") or step.get("uses"))


def _methods(action: dict[str, Any]) -> list[str]:
    """Every value of the `method` input: the ones its description lists, and each one a
    step condition names, so a method that a condition has and the description lacks is
    still a context."""
    described = action["inputs"]["method"]["description"].split(":", 1)[1]
    names = {name.strip() for name in described.split(",") if name.strip()}
    for step in _steps(action):
        names.update(
            re.findall(r"inputs\.method\s*[!=]=\s*'([^']+)'", str(step.get("if", "")))
        )
    return sorted(names)


def _contexts(action: dict[str, Any]) -> list[dict[str, Any]]:
    """One expression context for each method, runner OS and config file."""
    defaults = {
        name: spec.get("default", "") for name, spec in action["inputs"].items()
    }
    contexts = []
    for method, runner_os, config_file in itertools.product(
        _methods(action), RUNNER_OSES, CONFIG_FILES
    ):
        context = base_context()
        context["inputs"] = {**defaults, "method": method, "config-file": config_file}
        context["runner"] = {**context["runner"], "os": runner_os}
        contexts.append(context)
    return contexts


def _restore(action: dict[str, Any]) -> dict[str, Any]:
    found = [step for step in _steps(action) if step.get("id") == RESTORE_ID]
    assert len(found) == 1, (
        f"expected one step with id {RESTORE_ID}, found {len(found)}"
    )
    return found[0]


def _reads_the_restore(step: dict[str, Any]) -> bool:
    text = json.dumps(step, default=str)
    return re.search(rf"steps\.{re.escape(RESTORE_ID)}\.outputs\.", text) is not None


def readers(action: dict[str, Any]) -> list[dict[str, Any]]:
    """The steps, other than the restore, that read one of its outputs."""
    restore = _restore(action)
    return [
        step
        for step in _steps(action)
        if step is not restore and _reads_the_restore(step)
    ]


def reads_where_the_restore_never_ran(action: dict[str, Any]) -> list[str]:
    """One line for each step that reads the restore's output and runs in no context
    where the restore ran."""
    restore = _restore(action)
    contexts = _contexts(action)
    problems = []
    for step in readers(action):
        label = _label(step)
        assert "steps." not in str(step.get("if", "")), (
            f"{label!r} has a condition that reads another step's output, which this "
            "check does not model"
        )
        runs = [c for c in contexts if condition_holds(step.get("if"), c)]
        assert runs, (
            f"{label!r} runs in none of the {len(contexts)} contexts this check models "
            f"({step.get('if')!r}), so what it reads cannot be judged"
        )
        if not any(condition_holds(restore.get("if"), c) for c in runs):
            methods = sorted({c["inputs"]["method"] for c in runs})
            problems.append(
                f"{label!r} runs only under {methods}, and the {RESTORE_ID} restore "
                f"({restore.get('if')!r}) runs under none of them: its mapping of the "
                "restore's output is always the empty string"
            )
    return problems


def test_every_step_that_reads_the_restore_runs_where_the_restore_ran() -> None:
    assert reads_where_the_restore_never_ran(_load()) == []


def test_the_check_sees_the_steps_and_contexts_it_is_about() -> None:
    """Fails if the action stops matching, so the test above cannot pass on nothing."""
    action = _load()
    methods = _methods(action)
    assert {"python-local", "python-container", "bash", "sh-helper", "powershell"} <= (
        set(methods)
    ), methods
    assert len(_contexts(action)) == len(methods) * len(RUNNER_OSES) * len(CONFIG_FILES)
    named = {_label(step) for step in readers(action)}
    for expected in (
        *PYTHON_CONTAINER_STEPS,
        "Validate ASH using Python Local (Unix)",
        "Validate ASH config files",
        "Save the tool download cache",
    ):
        assert expected in named, (expected, sorted(named))
    # The restore itself runs for the method that downloads, or the check judges nothing.
    restore = _restore(action)
    python_local = [
        c for c in _contexts(action) if c["inputs"]["method"] == "python-local"
    ]
    assert all(condition_holds(restore.get("if"), c) for c in python_local)


def _document(restore_if: str | None, *conditions: str | None) -> dict[str, Any]:
    """A small action: a restore with the condition *restore_if* (none when None), and
    one step for each of *conditions*, each mapping the restore's output."""
    restore: dict[str, Any] = {
        "id": RESTORE_ID,
        "uses": "./.github/actions/tool-download-cache",
        "with": {"mode": "restore"},
    }
    if restore_if is not None:
        restore["if"] = restore_if
    steps = [restore]
    for index, condition in enumerate(conditions):
        step: dict[str, Any] = {
            "name": f"reader {index}",
            "env": {"ASH_TOOL_DOWNLOAD_CACHE": "${{ steps.tool-cache.outputs.dir }}"},
            "run": "ash --version",
        }
        if condition is not None:
            step["if"] = condition
        steps.append(step)
    return {
        "inputs": {
            "method": {
                "description": "Scan method: python-local, python-container, bash"
            },
            "config-file": {"default": "default"},
        },
        "runs": {"steps": steps},
    }


PYTHON_LOCAL = "inputs.method == 'python-local'"
PYTHON_CONTAINER = "inputs.method == 'python-container'"


@pytest.mark.parametrize(
    ("restore_if", "condition", "named_method"),
    [
        pytest.param(PYTHON_LOCAL, PYTHON_CONTAINER, "python-container", id="other"),
        pytest.param(
            PYTHON_LOCAL, "inputs.method != 'python-local'", "bash", id="every-other"
        ),
        pytest.param(
            PYTHON_LOCAL,
            f"{PYTHON_CONTAINER} && runner.os == 'Windows'",
            "python-container",
            id="other-on-windows",
        ),
        pytest.param(
            PYTHON_LOCAL,
            "contains(inputs.method, 'container')",
            "python-container",
            id="contains",
        ),
        pytest.param(PYTHON_LOCAL, "inputs.method == 'bash'", "bash", id="bash"),
        pytest.param(PYTHON_CONTAINER, PYTHON_LOCAL, "python-local", id="reversed"),
        pytest.param(
            f"{PYTHON_LOCAL} && runner.os != 'Windows'",
            f"{PYTHON_LOCAL} && runner.os == 'Windows'",
            "python-local",
            id="restore-on-the-other-os",
        ),
        pytest.param(
            PYTHON_LOCAL,
            "inputs.config-file == 'alpha' && inputs.method == 'bash'",
            "bash",
            id="and-the-config",
        ),
    ],
)
def test_a_reader_that_never_runs_with_the_restore_is_flagged(
    restore_if: str, condition: str, named_method: str
) -> None:
    """The must-flag controls, through the check the real action goes through."""
    problems = reads_where_the_restore_never_ran(_document(restore_if, condition))

    assert len(problems) == 1, problems
    assert "'reader 0'" in problems[0] and named_method in problems[0], problems


@pytest.mark.parametrize(
    ("restore_if", "condition"),
    [
        pytest.param(PYTHON_LOCAL, PYTHON_LOCAL, id="same"),
        pytest.param(
            PYTHON_LOCAL, f"{PYTHON_LOCAL} && runner.os == 'Windows'", id="narrower"
        ),
        pytest.param(
            PYTHON_LOCAL,
            f"{PYTHON_LOCAL} && inputs.config-file == 'alpha'",
            id="narrower-by-config",
        ),
        pytest.param(
            f"{PYTHON_LOCAL} || {PYTHON_CONTAINER}", PYTHON_CONTAINER, id="or"
        ),
        pytest.param(
            "contains(inputs.method, 'python')", PYTHON_CONTAINER, id="contains"
        ),
        pytest.param(
            f"{PYTHON_LOCAL} || {PYTHON_CONTAINER}", PYTHON_LOCAL, id="or-other-side"
        ),
        # The two named limits: a reader that also runs where the restore ran.
        pytest.param(PYTHON_LOCAL, None, id="no-condition"),
        pytest.param(PYTHON_LOCAL, "contains(inputs.method, 'python')", id="shared"),
        pytest.param(None, "inputs.method == 'bash'", id="restore-with-no-condition"),
    ],
)
def test_a_reader_that_can_run_with_the_restore_is_not_flagged(
    restore_if: str | None, condition: str | None
) -> None:
    """The must-not-flag controls."""
    assert reads_where_the_restore_never_ran(_document(restore_if, condition)) == []


def test_a_step_that_does_not_read_the_restore_is_not_judged() -> None:
    document = _document(PYTHON_LOCAL, PYTHON_CONTAINER)
    document["runs"]["steps"][1].pop("env")

    assert readers(document) == []
    assert reads_where_the_restore_never_ran(document) == []


def test_a_reader_that_runs_in_none_of_the_modeled_contexts_fails_loudly() -> None:
    """A condition the contexts never satisfy would otherwise read as a step that never
    runs, and never be judged. (A method a condition names is itself a context, so the
    condition here is on a runner OS the contexts do not have.)"""
    document = _document(PYTHON_LOCAL, "runner.os == 'Plan9'")

    with pytest.raises(AssertionError, match="runs in none of the"):
        reads_where_the_restore_never_ran(document)


def test_a_reader_whose_condition_reads_a_step_output_is_refused() -> None:
    document = _document(PYTHON_LOCAL, "steps.prepull.outputs.base-image-override")

    with pytest.raises(AssertionError, match="does not model"):
        reads_where_the_restore_never_ran(document)


def test_the_check_is_red_on_the_real_action_with_the_old_restore() -> None:
    """Revert what the restore's condition guards, and the check goes red on the steps
    it is about: the restore as it was before it ran for python-container."""
    action = _load()
    _restore(action)["if"] = PYTHON_LOCAL

    problems = reads_where_the_restore_never_ran(action)

    assert len(problems) == len(PYTHON_CONTAINER_STEPS), problems
    for name in PYTHON_CONTAINER_STEPS:
        assert any(repr(name) in problem for problem in problems), (name, problems)
    assert all("python-container" in problem for problem in problems), problems
