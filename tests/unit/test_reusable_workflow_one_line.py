# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value the scan workflow prints in a workflow command stays on its line.

Why this file exists
--------------------
The runner reads a line of a step's output as a workflow command when it starts with
`::` after leading whitespace, or holds `##[` anywhere, and it ends a line at a
carriage return as well as a line feed. So `echo "::error::... ${value} ..."` with a
value holding `\\r::warning::x` prints two commands, and the second is the value's.
Steps of run-ash-security-scan.yml print values they have not checked: the commit
and repository read from the job context, and ASH_UVX_SOURCE, which an earlier step
wrote. Each passes them through one_line, which turns every control character into
a space, `::` into `: :` and `##[` into `# #[`. Each step runs in its own shell, so
the job's "Write the one_line helper" step writes the function to RUNNER_TEMP once,
and a step that calls it loads that file first.

What is asserted
----------------
* The job has one definer, every step that loads or calls one_line comes after it,
  and every step that calls one_line loads the helper before the first call. A call
  with no load does not fail the step: bash prints "command not found", the value
  comes out empty, and the step goes on.
* Every step of the scan workflow, the upload workflow and this repository's caller
  prints each value on a workflow-command line through one_line, and so does each
  plain line of the steps the functional changes own. BASE_BRANCH_KEEPS lists, by
  line, the values that the base branch's copy of a line already prints safely; the
  merge keeps the base branch's text there, and a second test fails when an entry
  goes stale.
* The definer writes the function from the workflow's own text: a quoted heredoc
  with no expression in it, so nothing from the caller or the checkout reaches it.
* one_line replaces C0, DEL, C1, U+2028 and U+2029 with a space and breaks `::` and
  `##[` until none is left, leaves other text as it is, and gives the same bytes in
  the C and C.UTF-8 locales. The runner's locale does not change what it replaces.

The steps that print through it are run with such values in
test_reusable_workflow_defaults.py and test_reusable_workflow_tool_install_preflight.py.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest
import yaml

from tests.utils.workflow_one_line import (
    DEFINER_NAME,
    HELPER_SOURCE,
    calls_one_line,
    definers,
    honored_commands,
    write_helper,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]


@pytest.mark.unit
def test_the_job_has_one_definer_before_every_step_that_uses_it():
    steps = _steps()
    (definer,) = definers(steps)
    first = steps.index(definer)
    users = [
        index
        for index, step in enumerate(steps)
        if calls_one_line(step) or HELPER_SOURCE in str(step.get("run") or "")
    ]

    assert users, "no step prints through one_line"
    assert first < min(users), [steps[i].get("name") for i in users if i < first]


@pytest.mark.unit
def test_every_step_that_calls_one_line_loads_it_first():
    unloaded = []
    for step in _steps():
        if not calls_one_line(step):
            continue
        run = step["run"]
        load = run.find(HELPER_SOURCE)
        first_call = min(
            i
            for i in (run.find("one_line "), run.find("with_commands_stopped "))
            if i >= 0
        )
        if load < 0 or load > first_call:
            unloaded.append(step.get("name"))

    assert not unloaded, f"these steps call the helper without loading it: {unloaded}"


@pytest.mark.unit
def test_only_the_definer_prints_a_stop_commands_line():
    """Output the runner must not act on goes through with_commands_stopped.

    Its token comes from /dev/urandom for each call, and it closes the region and
    passes the command's status on. A step that opened a region of its own would
    have to get all of that right again.
    """
    own = [
        step.get("name")
        for step in _steps()
        if step.get("name") != DEFINER_NAME
        and "::stop-commands::" in str(step.get("run") or "")
    ]

    assert not own, f"these steps open a stop-commands region of their own: {own}"


WORKFLOWS = REPO_ROOT / ".github" / "workflows"
#: The workflows whose steps are read: the scan workflow, the upload workflow that
#: callers chain after it, and this repository's own caller of both.
READ = ("run-ash-security-scan.yml", "upload-ash-sarif.yml", "ash-repo-scan.yml")
COMMAND = re.compile(r"::(?:error|warning|notice|debug)\b[^:]*::|##\[")
PLAIN = re.compile(r"^\s*(?:echo|printf)\b")
#: A print whose standard output goes to a file, such as GITHUB_OUTPUT, not to the
#: log. `2>>` moves only standard error, so it does not count.
TO_FILE = re.compile(r"(?<![0-9&>])>>?\s*\"?\$\{?[A-Z_]+")
#: The closing line of a `{ ... } >> "${GITHUB_OUTPUT}"` group.
GROUP_TO_FILE = re.compile(r"^\s*\}\s*>>?\s*\"?\$\{?[A-Z_]+")
THROUGH_ONE_LINE = re.compile(r'\$\(one_line "[^"]*"\)')
EXPANSION = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)|\$\(\s*([A-Za-z_]+)|\$([A-Za-z_]\w*)"
)
#: The steps the functional changes add or edit and that keep their own text in the
#: merged workflow. Their plain prints, not only their workflow commands, put every
#: value through one_line, as the base branch does for the steps it owns.
OWN_STEPS = {
    ("run-ash-security-scan.yml", "Resolve the ASH to install"),
    ("run-ash-security-scan.yml", "Resolve the base for changed-files-only"),
    ("run-ash-security-scan.yml", "Check that this ASH can install the scanner tools"),
    ("run-ash-security-scan.yml", "Run ASH"),
}
#: Values a workflow command prints without one_line because the step itself sets
#: them: the input check names the refused input by its own INPUT_<NAME> variable's
#: name, and runs before the definer so that nothing prints an input unchecked.
LITERAL_VALUES = {
    (
        "run-ash-security-scan.yml",
        "Refuse an input that could start a workflow command",
        "name",
    ),
}
SCAN, REPO_SCAN = "run-ash-security-scan.yml", "ash-repo-scan.yml"
#: Workflow-command lines that the base branch prints through one_line, or without
#: the value, on its side; the merge keeps the base branch's text for them. Each
#: entry is one message line, named by its step and the opening of the line, with
#: the values it prints; a new line in the same step that prints the same value is
#: not covered. Each entry must still be printed here, so the table names exactly
#: what the base branch replaces. Empty since the merge: every line the base branch
#: owned prints through one_line now, and the report job's notices print no value.
BASE_BRANCH_KEEPS: dict[tuple[str, str, str], set[str]] = {}
#: A keep as the two control tests below exercise `_kept` with, so the controls
#: still measure the matching when BASE_BRANCH_KEEPS itself is empty.
_CONTROL_KEEPS = {
    (
        SCAN,
        "Install cfn-nag",
        'echo "::error::Ruby is not on PATH for the runner user (',
    ): {"BUNDLE_BIN", "GEM_CMD", "RUBY_CMD"},
}


def _every_step():
    for name in READ:
        data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
        for job in (data.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                yield name, step


def _bare_values(line: str) -> set[str]:
    rest = THROUGH_ONE_LINE.sub("", line)
    return {next(g for g in m.groups() if g) for m in EXPANSION.finditer(rest)}


def _log_lines(run: str) -> list[str]:
    """The lines of a script whose output can reach the log.

    Leaves out a line that sends its output to a file, and every line of a
    `{ ... } >> file` group.
    """
    kept: list[str] = []
    group: list[str] = []
    for line in run.splitlines():
        if group:
            group.append(line)
            if line.strip().startswith("}"):
                if not GROUP_TO_FILE.match(line):
                    kept.extend(group)
                group = []
        elif line.strip() == "{":
            group = [line]
        elif not TO_FILE.search(line):
            kept.append(line)
    return kept + group


@pytest.mark.unit
def test_log_lines_leaves_out_what_goes_to_a_file():
    run = """\
echo "a=${a}" >> "${GITHUB_OUTPUT}"
{
  echo "b=${b}"
} >> "${GITHUB_OUTPUT}"
{
  echo "c ${c}"
} 2>&1
echo "d ${d}" 2>> "${LOG}"
"""

    assert [line.strip() for line in _log_lines(run)] == [
        "{",
        'echo "c ${c}"',
        "} 2>&1",
        'echo "d ${d}" 2>> "${LOG}"',
    ]


def _printed_bare():
    """(file, step, kind, value, line) for each value printed outside one_line."""
    for name, step in _every_step():
        if step.get("name") == DEFINER_NAME:
            continue
        for line in _log_lines(str(step.get("run") or "")):
            if COMMAND.search(line):
                kind = "command"
            elif (name, step.get("name")) in OWN_STEPS and PLAIN.match(line):
                kind = "plain"
            else:
                continue
            for value in sorted(_bare_values(line)):
                yield name, step.get("name"), kind, value, line.strip()


def _kept(
    file: str,
    step: str,
    value: str,
    line: str,
    keeps: dict[tuple[str, str, str], set[str]] | None = None,
) -> bool:
    """Whether the base branch's text replaces this printed value at the merge: a
    keep for this step whose line opening this line starts with names the value."""
    table = BASE_BRANCH_KEEPS if keeps is None else keeps
    return any(
        value in values
        for (kept_file, kept_step, opening), values in table.items()
        if (kept_file, kept_step) == (file, step) and line.startswith(opening)
    )


@pytest.mark.unit
def test_a_keep_covers_its_own_line():
    """Control for the test below: the line a keep names is kept."""
    step = "Install cfn-nag"
    line = "echo \"::error::Ruby is not on PATH for the runner user (bundle='${BUNDLE_BIN}'"

    assert _kept(SCAN, step, "BUNDLE_BIN", line, keeps=_CONTROL_KEEPS)


@pytest.mark.unit
def test_a_kept_value_on_a_new_line_is_not_kept():
    """A keep names the line the base branch replaces, not every line of its step
    that prints the same value."""
    step = "Install cfn-nag"
    new_line = 'echo "::error::a new message with ${BUNDLE_BIN} in it"'

    assert not _kept(SCAN, step, "BUNDLE_BIN", new_line, keeps=_CONTROL_KEEPS)


@pytest.mark.unit
def test_every_value_a_step_prints_goes_through_one_line():
    """Every step of the three workflows, not only the steps that were changed.

    A line break in a value printed bare starts a line of its own, on a plain line as
    well as in a workflow command. The values the base branch replaces are listed by
    line.
    """
    bare = [
        f"{file} | {step} | {kind} | {value}: {line[:90]}"
        for file, step, kind, value, line in _printed_bare()
        if not _kept(file, step, value, line)
        and (file, step, value) not in LITERAL_VALUES
    ]

    assert not bare, "values printed outside one_line:\n" + "\n".join(bare)


@pytest.mark.unit
def test_every_value_the_base_branch_replaces_is_still_printed():
    printed = [
        (file, step, value, line) for file, step, _, value, line in _printed_bare()
    ]
    stale = [
        f"{file} | {step} | {opening} | {value}"
        for (file, step, opening), values in BASE_BRANCH_KEEPS.items()
        for value in values
        if not any(
            (p_file, p_step, p_value) == (file, step, value)
            and p_line.startswith(opening)
            for p_file, p_step, p_value, p_line in printed
        )
    ]

    listing = "\n".join(stale)
    assert not stale, f"BASE_BRANCH_KEEPS names values no longer printed:\n{listing}"


@pytest.mark.unit
def test_each_own_step_that_prints_a_value_loads_the_helper():
    steps = {(file, step.get("name")): step for file, step in _every_step()}
    unloaded = [
        name
        for key in sorted(OWN_STEPS)
        for name in [key[1]]
        if HELPER_SOURCE not in str(steps[key].get("run") or "")
    ]

    assert not unloaded, f"these steps do not load the helper: {unloaded}"


@pytest.mark.unit
def test_the_definer_writes_the_function_from_the_workflows_own_text():
    (definer,) = definers(_steps())
    run = definer["run"]

    assert "${{" not in run, "an expression in the definer puts outside text in it"
    assert "<<'EOF'" in run, "an unquoted heredoc would expand the function's $ text"
    assert WORKFLOW.read_text(encoding="utf-8").count("one_line() {") == 1


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)

LINE_SEPARATOR, PARAGRAPH_SEPARATOR = chr(0x2028), chr(0x2029)
NEL, CSI, PAD = chr(0x85), chr(0x9B), chr(0x80)
#: Kept as they are: an accented letter, a currency sign and a no-break space, whose
#: UTF-8 bytes share a lead or trail byte with the characters one_line replaces.
KEPT = chr(0xE9) + chr(0x20AC) + chr(0xA0)

#: (value, what one_line prints for it)
CASES = [
    ("a\rb", "a b"),
    ("a\nb", "a b"),
    ("a\r\nb", "a  b"),
    ("a\tb\x1bc\x7fd", "a b c d"),
    (f"a{NEL}b{CSI}c{PAD}d", "a b c d"),
    (f"a{LINE_SEPARATOR}b{PARAGRAPH_SEPARATOR}c", "a b c"),
    ("::warning::x", ": :warning: :x"),
    (":::", ": : :"),
    ("::::", ": : : :"),
    ("##[warning]x", "# #[warning]x"),
    ("###[", "## #["),
    ("##[##[", "# #[# #["),
    (f"kept {KEPT} #[ and : alone", f"kept {KEPT} #[ and : alone"),
]


def _one_line(helper: Path, value: str, locale_name: str) -> bytes:
    bash = shutil.which("bash")
    assert bash, "bash is required to run the helper"
    script = '. "$1"; one_line "$2"'
    result = subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", script, "bash", str(helper), value],
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": locale_name},
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("locale_name", ["C", "C.UTF-8"])
@pytest.mark.parametrize("value, shown", CASES, ids=[ascii(v) for v, _ in CASES])
def test_one_line_keeps_a_value_on_its_line(tmp_path, locale_name, value, shown):
    helper = write_helper(_steps(), tmp_path / "runner_temp")

    assert _one_line(helper, value, locale_name) == shown.encode("utf-8")


@pytest.mark.integration
@posix_only
def test_the_stop_window_closes_after_output_with_no_final_line_feed(tmp_path):
    """The resume line must start a line of its own, or the window stays open."""
    runner_temp = tmp_path / "runner_temp"
    helper = write_helper(_steps(), runner_temp)
    script = (
        '. "$1"\n'
        "with_commands_stopped printf 'no line feed at the end'\n"
        'echo "::warning::after the window"\n'
    )
    result = subprocess.run(
        [
            shutil.which("bash") or "bash",
            "-eo",
            "pipefail",
            "-c",
            script,
            "bash",
            helper,
        ],
        env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": str(runner_temp)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert honored_commands(result.stdout) == ["::warning::after the window"], (
        result.stdout
    )


#: The runner's own waits, 7.5 s after SIGINT and 2.5 s after SIGTERM. Once the
#: command has exited, the helper may take up to 5.5 s after SIGINT to end the rest
#: of its group (5 s, then SIGKILL and 0.5 s more), and up to 1.5 s after SIGTERM,
#: so a shorter wait would be shorter than the bound it checks. The stand-in
#: outlives both.
SIGINT_WAIT, SIGTERM_WAIT, POST_EXIT_READ = 7.5, 2.5, 1.0


#: Stand-ins for the command, by what they do with SIGINT, and the signal that
#: must end the step: SIGINT when the command stops on it, and the runner's
#: SIGTERM when it does not, which is the only run of the SIGTERM trap.
CANCELED_TOOLS = {
    "stops on SIGINT": ("", "SIGINT"),
    "ignores SIGINT": ("trap '' INT\n", "SIGTERM"),
}


@contextlib.contextmanager
def _with_sigint_at_its_default() -> Iterator[None]:
    """Start a child with SIGINT at its default, as the runner starts a step.

    A child inherits an ignored SIGINT across exec, and a test run started as
    ``cmd &`` has SIGINT ignored: the step's command then ignored the runner's
    SIGINT too, so "stops on SIGINT" ended on SIGTERM there, and only there.
    Python's own handler is set for the start, which exec resets to the default
    in the child; this process's disposition is put back afterwards. The same
    hold starts the hosts of test_an_interrupted_scan_exits_130.py.
    """
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _cancel_like_the_runner(
    tmp_path, prologue: str, slow_sleep: bool = False
) -> tuple[str, str, int]:
    """Runs `with_commands_stopped uvx scan` as the step does and cancels it as the
    runner does. Returns how the shell ended, what the runner read, and the exit
    status. With slow_sleep, every `sleep 0.1` on the step's PATH takes 0.3 s."""
    runner_temp = tmp_path / "runner_temp"
    helper = write_helper(_steps(), runner_temp)
    record = tmp_path / "tool.pid"
    tool = tmp_path / "bin" / "uvx"
    tool.parent.mkdir()
    tool.write_text(
        f'#!/bin/sh\necho "$$" > "{record}"\n{prologue}exec sleep 20\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    if slow_sleep:
        real_sleep = shutil.which("sleep")
        assert real_sleep, "sleep is not on PATH"
        stand_in = tool.parent / "sleep"
        stand_in.write_text(
            "#!/bin/sh\n"
            f'case "$1" in 0.1) exec "{real_sleep}" 0.3 ;; '
            f'*) exec "{real_sleep}" "$@" ;; esac\n',
            encoding="utf-8",
        )
        stand_in.chmod(0o755)
    step = tmp_path / "step.sh"
    step.write_text(f'. "{helper}"\nwith_commands_stopped uvx scan\n', encoding="utf-8")
    with _with_sigint_at_its_default():
        proc = subprocess.Popen(
            [
                shutil.which("bash") or "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                str(step),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={
                "PATH": f"{tool.parent}{os.pathsep}{os.environ.get('PATH', '')}",
                "RUNNER_TEMP": str(runner_temp),
            },
        )
    chunks: list[bytes] = []
    reader = threading.Thread(
        target=lambda: chunks.extend(iter(lambda: proc.stdout.read1(4096), b"")),
        daemon=True,
    )
    reader.start()
    deadline = time.monotonic() + 10
    while not record.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert record.exists(), "the stand-in did not start"
    time.sleep(0.2)

    ended_by = "SIGKILL"
    for sig, wait in ((signal.SIGINT, SIGINT_WAIT), (signal.SIGTERM, SIGTERM_WAIT)):
        os.kill(proc.pid, sig)
        try:
            proc.wait(wait)
            ended_by = sig.name
            break
        except subprocess.TimeoutExpired:
            continue
    else:
        proc.kill()
        proc.wait()
    # The runner reads on for a while after the shell exits; what comes after that
    # does not count, so take the output before the stand-in is ended.
    reader.join(POST_EXIT_READ)
    seen = b"".join(chunks).decode("utf-8", "replace")
    try:
        os.kill(int(record.read_text().strip()), signal.SIGKILL)
    except (ProcessLookupError, ValueError):
        pass
    reader.join(5)
    return ended_by, seen, proc.returncode


def _closes(seen: str) -> list[str]:
    (token,) = re.findall(r"^::stop-commands::([0-9a-f]{32})$", seen, re.MULTILINE)
    return [line for line in seen.splitlines() if line == f"::{token}::"]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("tool_kind", sorted(CANCELED_TOOLS))
def test_a_canceled_command_closes_its_stop_window(tmp_path, tool_kind):
    """A cancel or a timeout signals the step's shell alone.

    actions/runner's ProcessInvoker sends SIGINT to the shell's pid, then SIGTERM
    7.5 s later, then kills the shell 2.5 s after that. Its ActionCommandManager
    keeps the stop-commands state for the rest of the job, so a window the step
    left open would stop command processing in every later step. The window has to
    close before the kill, once.
    """
    prologue, expected_end = CANCELED_TOOLS[tool_kind]
    ended_by, seen, _ = _cancel_like_the_runner(tmp_path, prologue)

    assert len(_closes(seen)) == 1 and ended_by == expected_end, (
        f"ended by {ended_by}\n{seen}"
    )


LEFT_RUNNING = (
    "::error::processes the command started did not end in time, so they were sent"
    " SIGKILL and the step fails"
)


@pytest.mark.integration
@posix_only
def test_the_window_closes_within_the_runners_wait_on_a_slow_host(tmp_path):
    """The helper's waits are measured by the clock, not by how many 0.1 s sleeps
    it took: a loaded host stretches each sleep, and on SIGTERM the runner sends
    SIGKILL 2.5 s later whether the window has closed or not. Here every 0.1 s
    sleep takes 0.3 s, and the command ignores SIGINT and SIGTERM."""
    ended_by, seen, status = _cancel_like_the_runner(
        tmp_path, "trap '' INT TERM\n", slow_sleep=True
    )

    assert len(_closes(seen)) == 1 and ended_by == "SIGTERM", (
        f"ended by {ended_by}\n{seen}"
    )
    assert status == 143, seen
    assert honored_commands(seen) == [LEFT_RUNNING], seen
