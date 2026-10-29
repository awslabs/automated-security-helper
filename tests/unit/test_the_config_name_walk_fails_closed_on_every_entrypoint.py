# ONE file: the config-name walk's undecidable shapes must fail closed on
# every entrypoint. The failing shapes are a link loop as the final
# component, a link loop as a directory component, a link that cannot be
# read, and a link inside a directory the process cannot search (the
# lstat arm's shape). Every shape is probed on BOTH entrypoints:
#   py-gate  : rac._named_in_a_scanned_tree, rac._refuse_config_linked_out_of_the_tree, rac._assemble_run_command
#   bash-fn  : the shipped `ash` file's named_in_a_scanned_tree function, extracted from the tree and run alone
#              with the script functions it reaches (the extraction carries them; a cell pins the list)
#   bash-run : ./ash --config <name> against the fake OCI runner (a fake runner that records its argv)
# The must-not controls (a plain outside file, a name that IS a tree link)
# are accepted and refused respectively on every entrypoint.
# The steered-layout cells run the NAMES_STEERED_BY_THE_SCANNED_CHECKOUT layouts through both entrypoints,
# and measure the argv for a MARKED ASH_CONFIG file that is not the scan's config
# (a discoverable source config is present).
# Each cell prints GATE|<cell>|k=v lines (run with -s), then ends in one position-anchored assert.

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404 - runs the repository's own wrapper script and one extracted function
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from tests.utils.config_link_layouts import (
    NAMES_STEERED_BY_THE_SCANNED_CHECKOUT,
    config_through_links,
)
from tests.utils.helpers import mark_git_checkout

FLAG = rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG
FILE_FLAG = rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG
IMAGE = "automated-security-helper:non-root"
REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _fact(cell: str, **facts: Any) -> None:
    print("GATE|%s|%s" % (cell, "|".join("%s=%r" % (k, v) for k, v in facts.items())))


def _fact_realpath(name) -> str:
    # Diagnostic only: realpath follows links itself and raises on one it
    # cannot read, which must not abort the cell that provoked that state.
    try:
        return os.path.realpath(name)
    except OSError:
        return "<unresolvable>"


# --------------------------------------------------------------------------- python entrypoint helpers


def _assemble(source_dir: Path, output_dir: Path, config: Optional[str]) -> List[str]:
    return rac._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name=IMAGE,
        source_dir=source_dir,
        output_dir=output_dir,
        offline=False,
        debug=False,
        color=False,
        quiet=True,
        progress=False,
        verbose=False,
        simple=True,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[ExecutionPhase.SCAN],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=config,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
    )


def _inner_args(cmd: List[str]) -> List[str]:
    return cmd[cmd.index(IMAGE) + 1 :]


def _mount_sources(cmd: List[str]) -> List[str]:
    sources = []
    for index, item in enumerate(cmd[:-1]):
        if item == "--mount":
            fields = dict(
                field.split("=", 1)
                for field in cmd[index + 1].split(",")
                if "=" in field
            )
            sources.append(fields.get("source", ""))
    return sources


def _py_probe(named: Path, source: Path, out: Path) -> Dict[str, Any]:
    """What the three python-side calls do for one name."""
    trees = rac._scanned_tree_roots(source)
    result: Dict[str, Any] = {"name": str(named)}
    result["trees"] = [str(t) for t in trees]
    try:
        result["gate_returns"] = rac._named_in_a_scanned_tree(Path(named), trees)
        result["gate_raised"] = None
        result["gate_unresolvable"] = False
    except rac.ContainerInputError as error:
        result["gate_returns"] = "RAISED"
        result["gate_raised"] = str(error)[-70:]
        result["gate_unresolvable"] = "cannot be resolved" in str(error)
    try:
        rac._refuse_config_linked_out_of_the_tree(str(named), source)
        result["refusal_raised"] = None
        result["refusal_unresolvable"] = False
    except rac.ContainerInputError as error:
        result["refusal_raised"] = str(error)[-70:]
        result["refusal_unresolvable"] = "cannot be resolved" in str(error)
    try:
        cmd = _assemble(source, out, str(named))
        result["assembled"] = True
        result["assemble_raised"] = None
        result["assemble_unresolvable"] = False
        result["argv_mount_sources"] = _mount_sources(cmd)
        result["mark_flag_in_inner"] = FLAG in _inner_args(cmd)
    except rac.ContainerInputError as error:
        result["assembled"] = False
        result["assemble_raised"] = str(error)[-70:]
        result["assemble_unresolvable"] = "cannot be resolved" in str(error)
        result["argv_mount_sources"] = []
        result["mark_flag_in_inner"] = None
    return result


def _py_closed(result: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    """(the gate raises the unresolvable-name refusal, the launcher's link refusal raises it, assembly raises it)."""
    return (
        result["gate_unresolvable"],
        result["refusal_unresolvable"],
        result["assemble_unresolvable"],
    )


# --------------------------------------------------------------------------- bash entrypoint helpers

_TOOLS = (
    "dirname",
    "basename",
    "mkdir",
    "id",
    "date",
    "cat",
    "tr",
    "rm",
    "grep",
    "readlink",
)

_FAKE_RUNNER = """#!/bin/bash
n=$(cat "$FAKE_RUNNER_COUNT" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$FAKE_RUNNER_COUNT"
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$n")"
exit 0
"""


@pytest.fixture
def fake_runner(tmp_path):
    bin_dir = tmp_path / "wrapper-bin"
    bin_dir.mkdir()
    for tool in _TOOLS:
        found = shutil.which(tool)
        assert found, f"{tool} is not installed; ./ash needs it"
        (bin_dir / tool).symlink_to(found)
    runner = bin_dir / "fake-oci-runner"
    runner.write_text(_FAKE_RUNNER, encoding="utf-8")
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return bin_dir, runner, log_dir


def _run_ash(
    fake_runner, cwd: Path, args: List[str], extra_env: Optional[Dict[str, str]] = None
) -> Tuple[int, str, List[List[str]]]:
    bin_dir, runner, log_dir = fake_runner
    env = {
        "PATH": str(bin_dir),
        "HOME": str(log_dir.parent),
        "OCI_RUNNER": str(runner),
        "FAKE_RUNNER_LOG_DIR": str(log_dir),
        "FAKE_RUNNER_COUNT": str(log_dir.parent / "runner-count"),
    }
    env.update(extra_env or {})
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        [shutil.which("bash"), str(ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
        timeout=180,
        check=False,
    )
    calls = [
        record.read_bytes().decode().split("\0")[:-1]
        for record in sorted(log_dir.iterdir())
    ]
    return result.returncode, result.stdout + result.stderr, calls


_WALK_FUNCTION = "named_in_a_scanned_tree"
# The walk runs alone in bash, so every script function it reaches, directly or
# through another, is carried with it. A function missing here is "command not
# found" when the walk calls it, which the walk's fail-closed arms read as an
# undecidable link. test_the_extracted_walk_carries_every_function_it_reaches
# checks this list against the shipped script.
_WALK_CARRIED_FUNCTIONS = ("resolve_dir", "kept_output", "resolve_file")
_FUNCTION_HEADER = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) [{(]$", re.MULTILINE)


def _ash_function_source(name: str) -> str:
    """One function as the tree's `ash` file defines it (from its first line to the closing line)."""
    lines = ASH_SCRIPT.read_text(encoding="utf-8").splitlines()
    for opener, closer in (("{", "}"), ("(", ")")):
        header = f"{name}() {opener}"
        if header in lines:
            start = lines.index(header)
            end = start + 1
            while lines[end] != closer:
                end += 1
            return "\n".join(lines[start : end + 1])
    raise AssertionError(f"{name}() is not defined in ./ash")


def _ash_function_text() -> str:
    """named_in_a_scanned_tree with the script functions it needs, as the tree's `ash` file defines them."""
    return "\n".join(
        _ash_function_source(name)
        for name in (*_WALK_CARRIED_FUNCTIONS, _WALK_FUNCTION)
    )


def _functions_reached_from(root: str) -> set:
    """Every other function of ./ash that *root* names in its code, and that those name in theirs."""
    defined = set(_FUNCTION_HEADER.findall(ASH_SCRIPT.read_text(encoding="utf-8")))
    reached: set = set()
    pending = [root]
    while pending:
        code = "\n".join(
            line
            for line in _ash_function_source(pending.pop()).splitlines()
            if not line.lstrip().startswith("#")
        )
        for other in sorted(defined - reached - {root}):
            if re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", code):
                reached.add(other)
                pending.append(other)
    return reached


def _bash_fn_status(source: Path, named: Path) -> int:
    """named_in_a_scanned_tree's status with TREES set to the scanned trees the launcher computes for *source*."""
    trees = [str(t) for t in rac._scanned_tree_roots(source)]
    script = (
        'TREES=("${@:2}")\n'
        + _ash_function_text()
        + '\nnamed_in_a_scanned_tree "$1"\necho "status=$?"\n'
    )
    result = subprocess.run(  # nosec B603 B607 - fixed bash, list args, the function text is the tree's own
        [shutil.which("bash"), "-c", script, "_", str(named), *trees],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(source)},
        timeout=60,
        check=False,
    )
    last = [line for line in result.stdout.splitlines() if line.startswith("status=")]
    assert last, (result.stdout, result.stderr)
    return int(last[-1].split("=", 1)[1])


def _bash_run_probe(
    fake_runner, named: Path, source: Path, out: Path
) -> Dict[str, Any]:
    rc, text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(out), "--config", str(named)],
    )
    head = text.replace(str(named), "<name>").replace(str(source), "<source>")
    return {
        "rc": rc,
        "calls": len(calls),
        "says_cannot_be_resolved": "cannot be resolved" in text,
        "says_not_found": "Config file not found:" in text,
        "says_cannot_be_read": "Config file cannot be read" in text,
        "text_head": head.strip()[:170],
    }


# --------------------------------------------------------------------------- layouts


def _checkout(tmp_path: Path) -> Dict[str, Path]:
    root = tmp_path / "repo"
    mark_git_checkout(root)
    source = root / "services" / "api"
    source.mkdir(parents=True)
    (root / "ci").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return {"root": root.resolve(), "source": source.resolve(), "out": out.resolve()}


def _shape(which: str, tmp_path: Path, monkeypatch=None) -> Path:
    """The named config for one failing shape; every link sits outside the scanned checkout."""
    outside = tmp_path / "outside"
    outside.mkdir()
    if which == "loop-as-the-final-component":
        (outside / "a").symlink_to("b")
        (outside / "b").symlink_to("a")
        return outside / "a"
    if which == "loop-as-a-directory-component":
        (outside / "a").symlink_to("b")
        (outside / "b").symlink_to("a")
        return outside / "a" / "ash.yaml"
    if which == "unreadable-link":
        (outside / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
        (outside / "unreadable.yaml").symlink_to("real.yaml")
        real_readlink = os.readlink

        def readlink(path, *args, **kwargs):
            if str(path).endswith("/outside/unreadable.yaml"):
                raise OSError(13, "planted: permission denied")
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(rac.os, "readlink", readlink)
        return outside / "unreadable.yaml"
    if which == "link-in-a-directory-the-process-cannot-search":
        (outside / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
        locked = outside / "locked"
        locked.mkdir()
        (locked / "lnk").symlink_to(outside / "real.yaml")
        return locked / "lnk"
    if which == "link-to-a-directory-the-process-cannot-search":
        # The directory the link lands on is the one that cannot be searched; the
        # link itself and its parent can be looked up. _lock(name) reaches it
        # through the link.
        real = outside / "real"
        real.mkdir()
        (real / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
        (outside / "lnk").symlink_to("real")
        return outside / "lnk" / "ash.yaml"
    raise AssertionError(which)


PY_SHAPES = [
    "loop-as-the-final-component",
    "loop-as-a-directory-component",
    "unreadable-link",
    pytest.param(
        "link-in-a-directory-the-process-cannot-search",
        marks=pytest.mark.skipif(IS_ROOT, reason="root searches any directory"),
    ),
]


def _lock(path: Path) -> None:
    path.parent.chmod(0o000)


def _unlock(path: Path) -> None:
    path.parent.chmod(0o755)


# ------------------------------------------------------------ fail-closed cells: python entrypoint


@pytest.mark.integration
@pytest.mark.parametrize("which", PY_SHAPES)
def test_py_the_failing_shapes_fail_closed(which, tmp_path, monkeypatch):
    checkout = _checkout(tmp_path)
    named = _shape(which, tmp_path, monkeypatch)
    locked = which.startswith("link-in-a-directory")
    if locked:
        _lock(named)
    try:
        result = _py_probe(named, checkout["source"], checkout["out"])
    finally:
        if locked:
            _unlock(named)
    _fact(
        "py-" + which,
        realpath=_fact_realpath(named) if not locked else "<locked>",
        **result,
    )
    assert _py_closed(result) == (True, True, True)


# -------------------------------------------------------------- fail-closed cells: bash entrypoint


@pytest.mark.integration
@pytest.mark.parametrize(
    "which",
    [
        "loop-as-the-final-component",
        "loop-as-a-directory-component",
        pytest.param(
            "link-in-a-directory-the-process-cannot-search",
            marks=pytest.mark.skipif(IS_ROOT, reason="root searches any directory"),
        ),
    ],
)
def test_bash_fn_the_failing_shapes_report_undecided(which, tmp_path):
    checkout = _checkout(tmp_path)
    named = _shape(which, tmp_path)
    locked = which.startswith("link-in-a-directory")
    if locked:
        _lock(named)
    try:
        status = _bash_fn_status(checkout["source"], named)
    finally:
        if locked:
            _unlock(named)
    _fact("bash-fn-" + which, status=status)
    assert status == 2


@pytest.mark.integration
@pytest.mark.parametrize(
    "which",
    [
        "loop-as-the-final-component",
        "loop-as-a-directory-component",
        pytest.param(
            "link-in-a-directory-the-process-cannot-search",
            marks=pytest.mark.skipif(IS_ROOT, reason="root searches any directory"),
        ),
    ],
)
def test_bash_run_the_failing_shapes_are_refused_before_any_runner_call(
    which, fake_runner, tmp_path
):
    checkout = _checkout(tmp_path)
    named = _shape(which, tmp_path)
    locked = which.startswith("link-in-a-directory")
    if locked:
        _lock(named)
    try:
        result = _bash_run_probe(
            fake_runner, named, checkout["source"], checkout["out"]
        )
    finally:
        if locked:
            _unlock(named)
    _fact("bash-run-" + which, **result)
    assert (result["rc"], result["calls"]) == (3, 0)


# ------------------------------------------------ the refusal says what is wrong, per place the walk stops

SEARCH_WORDING = "a directory on the way cannot be searched"
LOOP_WORDING = (
    "a link loop, a link that cannot be read, or the place a link lands on "
    "cannot be examined"
)
UNREADABLE_WORDING = "a link on the way cannot be read"


def _py_refusal_text(named: Path, source: Path) -> str:
    trees = rac._scanned_tree_roots(source)
    with pytest.raises(rac.ContainerInputError) as raised:
        rac._named_in_a_scanned_tree(Path(named), trees)
    return str(raised.value)


@pytest.mark.unit
@pytest.mark.skipif(IS_ROOT, reason="root searches any directory")
def test_py_a_directory_that_cannot_be_searched_is_named_as_that(tmp_path):
    checkout = _checkout(tmp_path)
    named = _shape("link-in-a-directory-the-process-cannot-search", tmp_path)
    _lock(named)
    try:
        text = _py_refusal_text(named, checkout["source"])
    finally:
        _unlock(named)
    assert SEARCH_WORDING in text, text
    assert "link loop" not in text, text


@pytest.mark.unit
@pytest.mark.parametrize(
    "which", ["loop-as-the-final-component", "loop-as-a-directory-component"]
)
def test_py_a_link_loop_is_named_as_a_loop(which, tmp_path):
    checkout = _checkout(tmp_path)
    text = _py_refusal_text(_shape(which, tmp_path), checkout["source"])
    assert LOOP_WORDING in text, text
    assert "cannot be searched" not in text, text


@pytest.mark.unit
def test_py_a_link_whose_collapse_raises_is_named_as_unreadable(tmp_path, monkeypatch):
    named = _shape("loop-as-the-final-component", tmp_path)

    def raising(path, *args, **kwargs):
        raise OSError(5, "planted: input/output error")

    with monkeypatch.context() as patched:
        patched.setattr(rac.os.path, "realpath", raising)
        with pytest.raises(rac.ContainerInputError) as raised:
            rac._named_in_a_scanned_tree(Path(named), [])
    assert UNREADABLE_WORDING in str(raised.value), str(raised.value)


@pytest.mark.unit
@pytest.mark.skipif(IS_ROOT, reason="root searches any directory")
def test_py_a_link_into_a_directory_the_process_cannot_search_is_named_with_its_whole_cause(
    tmp_path,
):
    """The real lstat and readlink, no stand-in: the collapse hands back a link
    it could not follow, still a link, and the refusal names that cause beside
    the loop and the unexaminable landing."""
    checkout = _checkout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
    locked = outside / "locked"
    locked.mkdir()
    (locked / "lnk").symlink_to(outside / "real.yaml")
    named = outside / "entry.yaml"
    named.symlink_to(locked / "lnk")
    locked.chmod(0o000)
    try:
        text = _py_refusal_text(named, checkout["source"])
    finally:
        locked.chmod(0o755)
    assert LOOP_WORDING in text, text
    assert "cannot be searched" not in text, text


def _bash_fn_undecided_at(source: Path, named: Path) -> str:
    """Where named_in_a_scanned_tree says its walk stopped (UNDECIDED_AT)."""
    trees = [str(t) for t in rac._scanned_tree_roots(source)]
    script = (
        'TREES=("${@:2}")\n'
        + _ash_function_text()
        + '\nnamed_in_a_scanned_tree "$1"\necho "status=$? at=${UNDECIDED_AT:-}"\n'
    )
    result = subprocess.run(  # nosec B603 B607 - fixed bash, list args, the function text is the tree's own
        [shutil.which("bash"), "-c", script, "_", str(named), *trees],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(source)},
        timeout=60,
        check=False,
    )
    last = [line for line in result.stdout.splitlines() if line.startswith("status=")]
    assert last, (result.stdout, result.stderr)
    return last[-1]


@pytest.mark.integration
@pytest.mark.skipif(IS_ROOT, reason="root searches any directory")
def test_bash_fn_a_directory_that_cannot_be_searched_says_directory(tmp_path):
    checkout = _checkout(tmp_path)
    named = _shape("link-in-a-directory-the-process-cannot-search", tmp_path)
    _lock(named)
    try:
        said = _bash_fn_undecided_at(checkout["source"], named)
    finally:
        _unlock(named)
    assert said == "status=2 at=directory", said


@pytest.mark.unit
@pytest.mark.skipif(IS_ROOT, reason="root searches any directory")
def test_py_a_link_to_a_directory_that_cannot_be_searched_is_named_as_that(tmp_path):
    """The launcher collapses the link without entering its target, so the next
    lookup is what fails: a directory that cannot be searched, not a link."""
    checkout = _checkout(tmp_path)
    named = _shape("link-to-a-directory-the-process-cannot-search", tmp_path)
    _lock(named)
    try:
        text = _py_refusal_text(named, checkout["source"])
    finally:
        _unlock(named)
    assert SEARCH_WORDING in text, text
    assert "link loop" not in text, text


@pytest.mark.integration
@pytest.mark.skipif(IS_ROOT, reason="root searches any directory")
def test_bash_fn_a_link_to_a_directory_that_cannot_be_searched_says_directory(tmp_path):
    checkout = _checkout(tmp_path)
    named = _shape("link-to-a-directory-the-process-cannot-search", tmp_path)
    _lock(named)
    try:
        said = _bash_fn_undecided_at(checkout["source"], named)
    finally:
        _unlock(named)
    _fact("bash-fn-link-to-unsearchable-directory", said=said)
    assert said == "status=2 at=directory", said


@pytest.mark.integration
def test_bash_fn_a_directory_link_up_to_the_tree_is_collapsed_by_name(tmp_path):
    """A directory link whose last name is ".." lands on the physical parent of
    the directory holding the link, so a name that goes on into the scanned
    tree is judged there."""
    checkout = _checkout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "up").symlink_to("..")
    named = outside / "up" / "repo" / "services" / "api" / "ash.yaml"
    status = _bash_fn_status(checkout["source"], named)
    _fact("bash-fn-link-up-to-the-tree", status=status, name=str(named))
    assert status == 0


@pytest.mark.integration
@pytest.mark.parametrize(
    "which", ["loop-as-the-final-component", "loop-as-a-directory-component"]
)
def test_bash_fn_a_link_loop_says_link(which, tmp_path):
    checkout = _checkout(tmp_path)
    said = _bash_fn_undecided_at(checkout["source"], _shape(which, tmp_path))
    _fact("bash-fn-link-loop-" + which, said=said)
    assert said == "status=2 at=link", said


@pytest.mark.integration
@pytest.mark.parametrize(
    "which", ["loop-as-the-final-component", "loop-as-a-directory-component"]
)
def test_bash_run_a_link_loop_is_refused_as_a_missing_file_before_any_link_is_followed(
    which, fake_runner, tmp_path
):
    """The whole script's own check (the file test) refuses a looped name before
    resolve_file runs, so the link-hop bound there is defense in depth."""
    checkout = _checkout(tmp_path)
    named = _shape(which, tmp_path)
    result = _bash_run_probe(fake_runner, named, checkout["source"], checkout["out"])
    _fact("bash-run-loop-first-refusal-" + which, **result)
    observed = (
        result["rc"],
        result["calls"],
        result["says_not_found"],
        result["says_cannot_be_resolved"],
        result["says_cannot_be_read"],
    )
    assert observed == (3, 0, True, False, False)


@pytest.mark.unit
def test_bash_refuses_each_undecided_place_in_its_own_words():
    """The refusals read from the shipped script: the caller picks by UNDECIDED_AT."""
    text = ASH_SCRIPT.read_text(encoding="utf-8")
    directory = text.index('"${UNDECIDED_AT}" = "directory"')
    searched = text.index("goes through a directory that cannot be searched")
    loop = text.index("goes through a link that cannot be resolved")
    assert directory < searched < loop
    assert "a directory on the way cannot be searched" in text
    assert "a link loop, or a link that cannot be read" in text


@pytest.mark.unit
def test_the_extracted_walk_carries_every_function_it_reaches():
    """The walk runs alone, so a function it starts to call and the harness does not carry fails here by name."""
    carried = set(_FUNCTION_HEADER.findall(_ash_function_text()))
    reached = _functions_reached_from(_WALK_FUNCTION)
    _fact(
        "walk-dependencies",
        carried=sorted(carried),
        reached=sorted(reached),
    )
    # The scanner reads the script's own two resolvers as reached, so an empty
    # reading cannot pass as "nothing is missing".
    observed = (
        sorted(reached - carried),
        {"resolve_dir", "resolve_file"} <= reached,
        {"resolve_dir", "resolve_file"} <= carried,
    )
    assert observed == ([], True, True)


# --------------------------------------------------------------------------- must-not controls


def _control_layout(which: str, tmp_path: Path):
    operator = tmp_path / "operator"
    operator.mkdir()
    real = operator / "ash.yaml"
    real.write_text("project_name: p\n", encoding="utf-8")
    checkout = _checkout(tmp_path)
    if which == "plain-outside-file":
        return checkout, real, False
    (checkout["root"] / "ci" / "link.yaml").symlink_to(real)
    return checkout, checkout["root"] / "ci" / "link.yaml", True


@pytest.mark.integration
@pytest.mark.parametrize("which", ["plain-outside-file", "name-is-a-tree-file-link"])
def test_controls_hold_on_every_entrypoint(which, fake_runner, tmp_path):
    checkout, named, tree_link = _control_layout(which, tmp_path)
    py = _py_probe(named, checkout["source"], checkout["out"])
    fn_status = _bash_fn_status(checkout["source"], named)
    run = _bash_run_probe(fake_runner, named, checkout["source"], checkout["out"])
    _fact(
        "control-" + which,
        bash_fn_status=fn_status,
        **{"py_" + k: v for k, v in py.items()},
        **{"run_" + k: v for k, v in run.items()},
    )
    if tree_link:
        # The name IS a link in the scanned tree: refused on every entrypoint, and not as an "undecided" walk.
        observed = (
            py["refusal_raised"] is not None and py["assemble_raised"] is not None,
            fn_status,
            (run["rc"], run["calls"]),
        )
        assert observed == (True, 0, (3, 0))
    else:
        observed = (
            py["gate_raised"] is None
            and py["refusal_raised"] is None
            and py["assembled"],
            fn_status,
            (run["rc"], run["calls"] >= 1),
        )
        assert observed == (True, 1, (0, True))


# --------------------------------------------------------------------------- parity of the shared layouts


def _steered_layout(layout: str, tmp_path: Path, marker: str = "git-with-head"):
    checkout = tmp_path / "repo"
    if marker == "git-with-head":
        mark_git_checkout(checkout)
    else:
        (checkout / ".git").mkdir(
            parents=True
        )  # a bare .git directory: ./ash counts it, sandbox_grants does not
    source = checkout / "api"
    source.mkdir()
    (checkout / "ci").mkdir()
    config = config_through_links(layout, checkout, tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    return source.resolve(), out.resolve(), config


@pytest.mark.integration
@pytest.mark.parametrize("marker", ["git-with-head", "bare-dot-git-directory"])
@pytest.mark.parametrize("layout", NAMES_STEERED_BY_THE_SCANNED_CHECKOUT)
def test_the_steered_layouts_reach_the_same_verdict_on_both_entrypoints(
    layout, marker, fake_runner, tmp_path
):
    source, out, config = _steered_layout(layout, tmp_path, marker)
    py = _py_probe(config, source, out)
    run = _bash_run_probe(fake_runner, config, source, out)
    fn_status = _bash_fn_status(source, config)
    _fact(
        "steered-%s-%s" % (marker, layout),
        trees=py["trees"],
        name=str(config),
        realpath=_fact_realpath(config),
        py_gate_returns=py["gate_returns"],
        py_refusal=py["refusal_raised"],
        py_assemble_raised=py["assemble_raised"],
        py_assembled=py["assembled"],
        bash_fn_status=fn_status,
        bash_run_rc=run["rc"],
        bash_run_calls=run["calls"],
        bash_run_text=run["text_head"],
    )
    py_refused = py["assemble_raised"] is not None
    bash_refused = (run["rc"], run["calls"]) == (3, 0)
    if marker == "git-with-head":
        assert (py_refused, bash_refused, fn_status) == (True, True, 0)
    else:
        # ./ash treats any .git entry as a checkout and sandbox_grants only a git-shaped one, so
        # the launcher's verdict and the walk's, which takes sandbox_grants' trees, may differ
        # here and are recorded only. What holds either way: the script refuses the steered
        # name, and the extracted walk reaches a verdict (0 or 1) and not an undecided 2.
        assert (bash_refused, fn_status in (0, 1)) == (True, True)


# --------------------------------------------------------------------------- the mark flag for an env config that is not the scan's config


def _env_layout(tmp_path: Path, discoverable: bool) -> Dict[str, Path]:
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
    source = checkout / "services" / "api"
    (source / ".ash").mkdir(parents=True)
    (checkout / "ci").mkdir()
    env_config = checkout / "ci" / "ash.yaml"
    env_config.write_text("project_name: ci\n", encoding="utf-8")
    if discoverable:
        (source / ".ash" / ".ash.yaml").write_text(
            "project_name: discovered\n", encoding="utf-8"
        )
    out = tmp_path / "out"
    out.mkdir()
    return {
        "source": source.resolve(),
        "out": out.resolve(),
        "env": env_config.resolve(),
    }


@pytest.mark.integration
@pytest.mark.parametrize("discoverable", [True, False])
def test_a_marked_env_config_that_is_not_the_scans_config(
    discoverable, tmp_path, monkeypatch
):
    lay = _env_layout(tmp_path, discoverable)
    monkeypatch.setenv("ASH_CONFIG", str(lay["env"]))
    cmd = _assemble(lay["source"], lay["out"], None)
    inner = _inner_args(cmd)
    pairs = [(inner[i], inner[i + 1]) for i in range(len(inner) - 1)]
    _fact(
        "env-config-discoverable-%s" % discoverable,
        inner_args=inner,
        config_arg=[v for k, v in pairs if k == "--config"],
        ash_config_from_host=[
            v for k, v in pairs if k == rac.ASH_CONFIG_FROM_HOST_FLAG
        ],
        config_from_scanned_repository_flag_present=FLAG in inner,
        file_mark_flags=[v for k, v in pairs if k == FILE_FLAG],
        mount_sources=_mount_sources(cmd),
    )
    observed = (
        [v for k, v in pairs if k == "--config"] != [],
        FLAG in inner,
        [v for k, v in pairs if k == FILE_FLAG] != [],
    )
    if discoverable:
        assert observed == (False, False, True)
    else:
        assert observed == (True, True, True)


@pytest.mark.unit
@pytest.mark.skipif(
    os.name != "posix" or IS_ROOT,
    reason="needs a directory the process cannot search",
)
def test_an_unexaminable_component_reads_as_a_link(tmp_path, request):
    """The link test alone, no walk or gate in the path: a path the process
    cannot examine answers True, so every refusal caller fails closed on it."""
    from automated_security_helper.config.config_sources import _is_a_link

    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    request.addfinalizer(lambda: locked.chmod(0o700))

    assert _is_a_link(locked / "x") is True


@pytest.mark.unit
def test_a_provably_absent_component_does_not_read_as_a_link(tmp_path):
    """The must-not twin: a path that provably is not a link, because it does
    not exist under a searchable directory or sits under a plain file,
    answers False."""
    from automated_security_helper.config.config_sources import _is_a_link

    assert _is_a_link(tmp_path / "missing") is False
    plain = tmp_path / "plain.txt"
    plain.write_text("x\n")
    assert _is_a_link(plain / "under-a-file") is False
