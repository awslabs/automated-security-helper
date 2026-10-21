# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode's consumers of the operator's config chain share one record.

Container mode asks about the operator's config from several places before the
runner starts: the refusal that runs ahead of the log and the output, the same
refusal inside the container mode and again inside ``run_ash_container``, the
names of the variables the files read (for the build and for the run), and the
mounts and marks of the run command. Each of those used to walk the chain from
disk on its own. The consumers that go through the shared record
(``run_ash_container.OperatorConfigReads``) now get one resolution of the chain
document per distinct root per phase; the judgment passes that deliberately
keep their own reads still read the disk themselves. A scan that builds an
image gives the run phase a fresh record, because the container reads the
files when it starts.

The walks are counted at ``config_sources.resolve_config_document``, for the
calls made from ``run_ash_container`` only, which is where the record's
consumers live. The exit-code fields (``fail_on_findings`` and
``fail_on_incomplete_scanners``) are read from the document the pre-run gate
resolved, with no load of the config file of their own.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


def _write(path: Path, doc: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _scan_inputs(root: Path):
    """(source, out, config): a scanned checkout and a valid operator config
    kept outside it."""
    (root / "repo" / ".git").mkdir(parents=True)
    (root / "repo" / ".git" / "HEAD").write_text(
        "ref: refs/heads/main\n", encoding="utf-8"
    )
    source = root / "repo" / "app"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = root / "out"
    out.mkdir()
    config = _write(root / "ops" / "ash.yaml", {"project_name": "op"})
    return source, out, config


@pytest.fixture
def recording_runner(monkeypatch):
    """Every runner command is recorded and none is started."""
    commands: list[list[str]] = []

    def record(cmd_list, *args, **kwargs):
        cmd = [str(item) for item in cmd_list if item is not None]
        commands.append(cmd)
        if len(cmd) > 1 and cmd[1] == "run":
            for i, arg in enumerate(cmd[:-1]):
                if arg == "--mount":
                    fields = dict(
                        part.partition("=")[::2] for part in cmd[i + 1].split(",")
                    )
                    if fields.get("destination") == "/out":
                        Path(
                            fields["source"], "ash_aggregated_results.json"
                        ).write_text(
                            '{"sarif": null, "scanners": []}', encoding="utf-8"
                        )
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        run_ash_container, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda _runner: False
    )
    monkeypatch.setattr(run_ash_container, "run_cmd_direct", record)
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    for name in (
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_IMAGE_NAME",
    ):
        monkeypatch.delenv(name, raising=False)
    return commands


@pytest.fixture
def container_walks(monkeypatch):
    """The chain walks ``run_ash_container`` makes, by resolved root file."""
    real = config_sources.resolve_config_document
    walks: list[Path] = []

    def counted(config_path, *args, **kwargs):
        caller = sys._getframe(1).f_code.co_filename
        if Path(caller).name == "run_ash_container.py":
            walks.append(Path(config_path).resolve())
        return real(config_path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "resolve_config_document", counted)
    return walks


@pytest.fixture
def exit_field_loads(monkeypatch):
    """Each load of the config file the exit-code fields are read from."""
    real = ras._load_config_file
    loads: list[bool] = []

    def counted(opts, for_run=False):
        loads.append(for_run)
        return real(opts, for_run=for_run)

    monkeypatch.setattr(ras, "_load_config_file", counted)
    return loads


def _run_scan(source: Path, out: Path, config: Path) -> None:
    ras.run_ash_scan(
        source_dir=str(source),
        output_dir=str(out),
        mode=RunMode.container,
        build=False,
        config=str(config),
        show_summary=False,
        progress=False,
        quiet=True,
    )


def test_one_walk_serves_every_container_mode_consumer_of_the_chain(
    tmp_path, recording_runner, container_walks, exit_field_loads
):
    source, out, config = _scan_inputs(tmp_path)
    _run_scan(source, out, config)

    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        "the scan reached the run command, so every consumer of the chain ran"
    )
    assert container_walks == [config.resolve()], (
        "one walk of the --config chain serves the refusal ahead of the log, the "
        "refusal in container mode, the refusal in run_ash_container, the "
        "variable names for the build and for the run, and the mounts and "
        f"marks of the run command; walks: {container_walks}"
    )
    assert exit_field_loads == [], (
        "fail_on_findings and fail_on_incomplete_scanners are read from the "
        "document the pre-run check parsed, whose model it builds from that "
        f"same read, so the file is not loaded again; loads: {exit_field_loads}"
    )


def test_an_ash_config_file_is_walked_once_beside_the_config(
    tmp_path, recording_runner, container_walks, monkeypatch
):
    source, out, config = _scan_inputs(tmp_path)
    env_config = _write(tmp_path / "ops" / "env.yaml", {"project_name": "env"})
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    _run_scan(source, out, config)

    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        "the scan reached the run command, so every consumer of the chains ran"
    )
    expected = sorted([config.resolve(), env_config.resolve()])
    assert sorted(container_walks) == expected, (
        "one walk of the --config chain and one of the ASH_CONFIG chain serve "
        "every refusal, the variable names and the mounts and marks of the "
        f"run command; walks: {container_walks}"
    )


@pytest.fixture
def stubbed_build(monkeypatch, tmp_path):
    """A build that succeeds without a runner: the revision resolves, a
    Dockerfile exists, and the build step itself is the test's to supply."""
    dockerfile = tmp_path / "build" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(
        run_ash_container, "get_ash_revision", lambda quiet=False: "LOCAL"
    )
    monkeypatch.setattr(
        run_ash_container, "_find_dockerfile", lambda _revision: dockerfile
    )

    def set_build(step):
        monkeypatch.setattr(run_ash_container, "_build_image", lambda **_kwargs: step())

    return set_build


def _run_scan_with_build(source: Path, out: Path, config: Path) -> None:
    ras.run_ash_scan(
        source_dir=str(source),
        output_dir=str(out),
        mode=RunMode.container,
        build=True,
        config=str(config),
        show_summary=False,
        progress=False,
        quiet=True,
    )


def _the_run_command(commands: list[list[str]]) -> list[str]:
    return next(cmd for cmd in commands if len(cmd) > 1 and cmd[1] == "run")


def _mount_sources(run_cmd: list[str]) -> list[str]:
    return [
        dict(part.partition("=")[::2] for part in run_cmd[i + 1].split(",")).get(
            "source", ""
        )
        for i, arg in enumerate(run_cmd[:-1])
        if arg == "--mount"
    ]


def test_a_base_added_to_the_config_during_the_build_is_mounted(
    tmp_path, recording_runner, stubbed_build
):
    """The container reads the operator's files when it starts, so the run
    command must describe them as they are after the build: a base the config
    gained while the image was building is mounted for the run, not silently
    absent from it."""
    source, out, config = _scan_inputs(tmp_path)
    team = _write(tmp_path / "ops" / "team.yaml", {"project_name": "team"})
    stubbed_build(
        lambda: _write(config, {"project_name": "op", "extends": "team.yaml"})
    )

    _run_scan_with_build(source, out, config)

    sources = _mount_sources(_the_run_command(recording_runner))
    assert any(
        candidate in sources for candidate in (str(team), str(team.resolve()))
    ), sources


def test_a_variable_the_config_gains_during_the_build_is_passed_by_name(
    tmp_path, recording_runner, stubbed_build, monkeypatch
):
    """The variable names the chain reads are collected again for the run: a
    reference the config gained while the image was building rides the run
    command by name, so the scan inside resolves it instead of silently using
    the file's absence of a value."""
    source, out, config = _scan_inputs(tmp_path)
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    stubbed_build(
        lambda: config.write_text("project_name: ${ASH_TEAM_NAME}\n", encoding="utf-8")
    )

    _run_scan_with_build(source, out, config)

    run_cmd = _the_run_command(recording_runner)
    pairs = list(zip(run_cmd, run_cmd[1:]))
    assert ("-e", "ASH_TEAM_NAME") in pairs, run_cmd


def test_a_config_left_alone_during_the_build_changes_nothing_for_the_run(
    tmp_path, recording_runner, stubbed_build, monkeypatch
):
    """The must-not twin: with the config untouched during the build, the run
    command mounts the same chain and passes no extra variable name."""
    source, out, config = _scan_inputs(tmp_path)
    monkeypatch.setenv("ASH_TEAM_NAME", "unused")
    stubbed_build(lambda: None)

    _run_scan_with_build(source, out, config)

    run_cmd = _the_run_command(recording_runner)
    sources = _mount_sources(run_cmd)
    assert any(
        candidate in sources for candidate in (str(config), str(config.resolve()))
    ), sources
    assert ("-e", "ASH_TEAM_NAME") not in list(zip(run_cmd, run_cmd[1:])), run_cmd


def _write_text(path: Path, text: str) -> Path:
    """A config file written as YAML text, where ``${VAR}`` is a reference."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _checkout(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return path


@pytest.fixture
def counted_names(monkeypatch):
    """Each computation of the variable names, by the source spelling it was
    given; the computation itself runs."""
    real = run_ash_container._operator_environment_names
    computations: list[str] = []

    def counted(config, env_config, source_dir, reads):
        computations.append(str(source_dir))
        return real(config, env_config, source_dir, reads)

    monkeypatch.setattr(run_ash_container, "_operator_environment_names", counted)
    return computations


def test_one_computation_serves_two_spellings_that_reach_the_same_trees(
    tmp_path, monkeypatch, counted_names
):
    """A link inside the scanned checkout that points inside it names the same
    scan input as its target: both spellings reach one scanned tree, so the
    record answers both from one computation, and the answer is the one the
    computation gives either spelling."""
    repo = _checkout(tmp_path / "repo")
    real = repo / "real-src"
    real.mkdir()
    link = repo / "link-src"
    link.symlink_to(real)
    config = _write_text(
        tmp_path / "ops" / "ash.yaml", "project_name: ${ASH_TEAM_NAME}\n"
    )
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    reads = run_ash_container.OperatorConfigReads()

    first = reads.environment_names(str(config), None, real)
    second = reads.environment_names(str(config), None, link)

    assert first == second == ["ASH_TEAM_NAME"]
    assert counted_names == [str(real)], counted_names
    assert second == run_ash_container.operator_environment_names(
        str(config), None, link
    )


@pytest.mark.parametrize("real_first", [True, False])
def test_a_link_into_another_checkout_is_judged_by_the_trees_it_reaches(
    tmp_path, monkeypatch, real_first
):
    """A link inside one checkout that points into another is scanned as both
    checkouts, while its target alone is scanned as the second. A config file
    kept in the first is the repository's under the link's name and the
    operator's under the target's, so the two spellings read different
    variables, and each is answered as a local scan of that spelling would
    answer it, whichever is asked first."""
    outer = _checkout(tmp_path / "outer")
    mono = _checkout(tmp_path / "mono")
    real = mono / "pkg"
    real.mkdir()
    link = outer / "link-src"
    link.symlink_to(real)
    config = _write_text(outer / "ops" / "ash.yaml", "project_name: ${ASH_TEAM_NAME}\n")
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    reads = run_ash_container.OperatorConfigReads()
    wanted = {
        "link": run_ash_container.operator_environment_names(str(config), None, link),
        "real": run_ash_container.operator_environment_names(str(config), None, real),
    }
    assert wanted == {"link": [], "real": ["ASH_TEAM_NAME"]}, (
        "the two spellings are judged differently by the computation itself"
    )

    order = (
        [("real", real), ("link", link)]
        if real_first
        else [("link", link), ("real", real)]
    )
    got = {
        name: reads.environment_names(str(config), None, spelling)
        for name, spelling in order
    }

    assert got == wanted, got


def test_the_names_and_the_marks_agree_for_a_link_into_another_checkout(
    tmp_path, monkeypatch
):
    """The names and the marks agree: a chain the repository wrote is marked
    and its variable is not passed, for the spelling that reaches the
    repository, even when the record first answered for a spelling that does
    not."""
    outer = _checkout(tmp_path / "outer")
    mono = _checkout(tmp_path / "mono")
    real = mono / "pkg"
    real.mkdir()
    link = outer / "link-src"
    link.symlink_to(real)
    base = _write_text(outer / "ops" / "base.yaml", "project_name: ${ASH_TEAM_NAME}\n")
    config = _write(outer / "ops" / "ash.yaml", {"extends": "base.yaml"})
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    reads = run_ash_container.OperatorConfigReads()

    by_target = reads.environment_names(str(config), None, real)
    by_link = reads.environment_names(str(config), None, link)

    assert by_target == ["ASH_TEAM_NAME"], by_target
    assert by_link == [], by_link
    mounts, _inner, _files, plan = reads.host_file(
        str(config), link, "/ash-config", follow_extends=True
    )
    marked_whole, marked_bases = run_ash_container._config_marks(
        str(config), link, plan
    )
    assert marked_whole is True, (marked_whole, marked_bases, base)


def test_two_source_directories_are_answered_by_two_computations(tmp_path, monkeypatch):
    """The must-not twin: genuinely different source directories are different
    inputs and each gets its own computation."""
    one = tmp_path / "one"
    one.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    computations: list[str] = []

    def counted(config, env_config, source_dir, reads):
        computations.append(str(source_dir))
        return ["ASH_X"]

    monkeypatch.setattr(run_ash_container, "_operator_environment_names", counted)
    reads = run_ash_container.OperatorConfigReads()

    reads.environment_names("c.yaml", None, one)
    reads.environment_names("c.yaml", None, other)

    assert len(computations) == 2, computations


def test_one_pass_serves_two_spellings_of_the_mounted_file_inputs(
    tmp_path, monkeypatch
):
    """A linked spelling of the source directory reaches the one recorded
    mount pass, and a caller's change to a handed-out list reaches no later
    asker."""
    real = tmp_path / "real-src"
    real.mkdir()
    link = tmp_path / "link-src"
    link.symlink_to(real)
    document = object()
    plan = run_ash_container._ChainPlan([(Path("f1"), "/cfg/ash.yaml")], document)
    passes: list[str] = []

    def counted(host_path, source_dir, mount_root, *, follow_extends, reads):
        passes.append(str(source_dir))
        return (["--mount", "m1"], "/cfg/ash.yaml", [Path("f1")], plan)

    monkeypatch.setattr(run_ash_container, "_host_file_in_container", counted)
    reads = run_ash_container.OperatorConfigReads()

    mounts, inner, files, got_plan = reads.host_file(
        "c.yaml", real, "/root", follow_extends=True
    )
    mounts.append("tainted")
    files.append(Path("tainted"))
    got_plan.placements.append((Path("tainted"), "/cfg/tainted"))
    mounts_again, _, files_again, plan_again = reads.host_file(
        "c.yaml", link, "/root", follow_extends=True
    )

    assert len(passes) == 1, passes
    assert plan_again.document is document and inner == "/cfg/ash.yaml"
    assert "tainted" not in mounts_again, mounts_again
    assert Path("tainted") not in files_again, files_again
    assert plan_again.placements == [(Path("f1"), "/cfg/ash.yaml")], (
        plan_again.placements
    )


@pytest.fixture
def container_text_reads(monkeypatch):
    """Each chain-file text read made from ``run_ash_container``."""
    real = config_sources.read_config_text
    reads: list[Path] = []

    def counted(path, *args, **kwargs):
        caller = sys._getframe(1).f_code.co_filename
        if Path(caller).name == "run_ash_container.py":
            reads.append(Path(path).resolve())
        return real(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "read_config_text", counted)
    return reads


def test_each_chain_file_text_is_read_once_for_the_whole_scan(
    tmp_path, recording_runner, container_text_reads
):
    """The record carries the chain's entries across both production entry
    points (the refusals and the run-command assembly), so no file's text is
    read twice from ``run_ash_container`` in one scan."""
    source, out, _ = _scan_inputs(tmp_path)
    base = _write(tmp_path / "ops" / "base.yaml", {"project_name": "base"})
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {"project_name": "op", "extends": ["base.yaml"]},
    )
    _run_scan(source, out, config)

    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        "the scan reached the run command, so every consumer of the chain ran"
    )
    counts = {
        path: container_text_reads.count(path) for path in set(container_text_reads)
    }
    assert set(counts) == {config.resolve(), base.resolve()}, counts
    assert max(counts.values()) == 1, counts


def _linked_source(tmp_path: Path, config_text: str) -> tuple[Path, Path]:
    """(source, config): a source directory that is a link inside one checkout
    pointing into another, and an operator config kept in the first."""
    outer = _checkout(tmp_path / "outer")
    mono = _checkout(tmp_path / "mono")
    real = mono / "pkg"
    real.mkdir()
    (real / "a.py").write_text("x = 1\n", encoding="utf-8")
    link = outer / "link-src"
    link.symlink_to(real)
    config = _write_text(outer / "ops" / "ash.yaml", config_text)
    return link, config


def test_the_run_command_follows_the_judgment_made_before_the_run(
    tmp_path, monkeypatch, recording_runner, counted_names
):
    """A source directory that is a link into another checkout is scanned as
    both checkouts, so a config kept in the first is the repository's. The
    refusal ahead of the run says so, and the run command says the same: the
    config is marked repository-written, its variable is not passed, and the
    variable names are computed once for the scan."""
    link, config = _linked_source(tmp_path, "project_name: ${ASH_TEAM_NAME}\n")
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    judged = run_ash_container.operator_environment_names(str(config), None, link)
    assert judged == [], "the refusal's own computation treats the config as the repo's"
    counted_names.clear()

    result = run_ash_container.run_ash_container(
        source_dir=str(link),
        output_dir=str(out),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode == 0, result.stderr
    run_cmd = _the_run_command(recording_runner)
    pairs = list(zip(run_cmd, run_cmd[1:]))
    assert ("-e", "ASH_TEAM_NAME") not in pairs, run_cmd
    assert run_ash_container.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in run_cmd, run_cmd
    assert counted_names == [str(link)], counted_names


def test_a_workspace_scan_refuses_a_config_from_the_named_roots_checkout(
    tmp_path, monkeypatch, recording_runner
):
    """The same layout in workspace mode: the workspace root is a link inside
    one checkout pointing into another, and the config sits in the first. The
    checkout around the root the operator named holds the config, so container
    mode refuses the run fail closed, before anything is built or made; a run
    that goes ahead means a phase judged the resolved directory instead of the
    one the operator named."""
    link, config = _linked_source(tmp_path, "project_name: op\n")
    definition = link / "ash.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "."}]}), encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    result = run_ash_container.run_ash_container(
        source_dir=str(link),
        output_dir=str(out),
        config=str(config),
        workspace_relative_file="ash.code-workspace",
        build=False,
        run=True,
    )

    assert result.returncode == 3, (result.returncode, result.stderr)
    assert f"The config file '{config}'" in result.stderr, result.stderr
    assert "is the scanned repository's" in result.stderr, result.stderr
    assert not out.exists(), "a refused run makes nothing"


def test_a_scan_is_refused_before_anything_is_made_or_not_at_all(
    tmp_path, monkeypatch, recording_runner
):
    """The same layout with a config that reads a name the container scan does
    not pass. The config is the repository's under the root the operator named,
    so its reads are not collected and nothing refuses a one-directory scan:
    the run completes, and 0 is the only right exit. A refusal here would mean
    a phase judged the resolved directory instead of the named one."""
    link, config = _linked_source(tmp_path, "project_name: ${ASH_MODE}\n")
    out = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    result = run_ash_container.run_ash_container(
        source_dir=str(link),
        output_dir=str(out),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode == 0, (
        result.returncode,
        out.exists(),
        result.stderr,
    )


def test_a_scan_that_builds_judges_the_fresh_record_against_the_named_root(
    tmp_path, monkeypatch, recording_runner, stubbed_build
):
    """The run phase of a scan that built starts a fresh record, and that
    record judges against the source directory as the operator named it too:
    the config stays the repository's, so the run command marks it, holds its
    variable back, and nothing refuses the run."""
    link, config = _linked_source(tmp_path, "project_name: ${ASH_TEAM_NAME}\n")
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    stubbed_build(lambda: None)

    result = run_ash_container.run_ash_container(
        source_dir=str(link),
        output_dir=str(out),
        config=str(config),
        build=True,
        run=True,
    )

    assert result.returncode == 0, (result.returncode, result.stderr)
    run_cmd = _the_run_command(recording_runner)
    pairs = list(zip(run_cmd, run_cmd[1:]))
    assert ("-e", "ASH_TEAM_NAME") not in pairs, run_cmd
    assert run_ash_container.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in run_cmd, run_cmd


@pytest.mark.parametrize("link_first", [True, False])
def test_two_spellings_of_one_config_file_are_judged_apart_by_one_record(
    tmp_path, monkeypatch, link_first
):
    """One config file named twice: through a link inside the scanned checkout
    that points outside both checkouts, and by the file itself. The first
    spelling is the repository's and reads nothing the operator chose; the
    second is the operator's. One record answers each as a local scan of that
    spelling would, whichever it is asked first."""
    outer = _checkout(tmp_path / "outer")
    mono = _checkout(tmp_path / "mono")
    real = mono / "pkg"
    real.mkdir()
    source = outer / "link-src"
    source.symlink_to(real)
    target = _write_text(
        tmp_path / "elsewhere" / "ash.yaml", "project_name: ${ASH_TEAM_NAME}\n"
    )
    through_link = outer / "ops" / "ash.yaml"
    through_link.parent.mkdir(parents=True)
    through_link.symlink_to(target)
    monkeypatch.setenv("ASH_TEAM_NAME", "from-the-operator")
    wanted = {
        "link": run_ash_container.operator_environment_names(
            str(through_link), None, source
        ),
        "file": run_ash_container.operator_environment_names(str(target), None, source),
    }
    assert wanted == {"link": [], "file": ["ASH_TEAM_NAME"]}, (
        "the two spellings are judged differently by the computation itself"
    )
    spellings = {"link": through_link, "file": target}
    order = ["link", "file"] if link_first else ["file", "link"]
    reads = run_ash_container.OperatorConfigReads()

    got = {
        name: reads.environment_names(str(spellings[name]), None, source)
        for name in order
    }

    assert got == wanted, got


def test_the_exit_fields_read_one_shared_load(tmp_path, recording_runner, monkeypatch):
    """The two exit-code fields are resolved from one load made at the scan
    entry, not one load per field."""
    source, out, config = _scan_inputs(tmp_path)
    calls: list[int] = []
    real = ras._load_config_file_or_its_exit_fields

    def counted(opts, **handed_in):
        calls.append(1)
        return real(opts, **handed_in)

    monkeypatch.setattr(ras, "_load_config_file_or_its_exit_fields", counted)
    _run_scan(source, out, config)

    assert len(calls) == 1, calls


@pytest.mark.parametrize("model_loads_the_first_file", [False, True])
def test_the_exit_fields_follow_the_file_the_gate_read_when_it_is_replaced_after(
    tmp_path, recording_runner, monkeypatch, model_loads_the_first_file
):
    """With no build the image's ASH may hold another schema, so the gate reads
    the config and judges only what holds for every revision. The exit-code
    fields are then read from what the gate read, not from the file again: a
    file replaced once the gate has finished must not give the exit code a
    reading the gate never saw."""
    source, out, _ = _scan_inputs(tmp_path)
    first = {"project_name": "op", "fail_on_findings": False}
    if not model_loads_the_first_file:
        first["global_settings"] = {"zz_option_a_later_schema_declares": True}
    config = _write(tmp_path / "ops" / "replaced.yaml", first)
    real_gate = ras._outer_mode_config_load

    def gate_then_replace(opts):
        record = real_gate(opts)
        _write(config, {"project_name": "op", "fail_on_findings": True})
        return record

    forwarded: dict = {}
    real_container_mode = ras._run_container_mode

    def watching(opts, logger, **kwargs):
        forwarded.update(kwargs)
        return real_container_mode(opts, logger, **kwargs)

    monkeypatch.setattr(ras, "_outer_mode_config_load", gate_then_replace)
    monkeypatch.setattr(ras, "_run_container_mode", watching)
    _run_scan(source, out, config)

    assert forwarded["resolved_fail_on_findings"] is False, forwarded


@pytest.mark.parametrize("model_loads_the_first_file", [False, True])
def test_the_gate_reads_the_config_file_once_for_its_judgment_and_its_model(
    tmp_path, recording_runner, monkeypatch, model_loads_the_first_file
):
    """The gate judges the file it parsed and tries the model on that same
    read. A file replaced right after the parse must not give the exit-code
    fields a reading the gate never judged."""
    source, out, _ = _scan_inputs(tmp_path)
    first = {"project_name": "op", "fail_on_findings": False}
    if not model_loads_the_first_file:
        first["global_settings"] = {"zz_option_a_later_schema_declares": True}
    config = _write(tmp_path / "ops" / "replaced.yaml", first)
    real_parse = ras._parse_and_confine_config

    def parse_then_replace(path, opts):
        document = real_parse(path, opts)
        _write(config, {"project_name": "op", "fail_on_findings": True})
        return document

    forwarded: dict = {}
    real_container_mode = ras._run_container_mode

    def watching(opts, logger, **kwargs):
        forwarded.update(kwargs)
        return real_container_mode(opts, logger, **kwargs)

    monkeypatch.setattr(ras, "_parse_and_confine_config", parse_then_replace)
    monkeypatch.setattr(ras, "_run_container_mode", watching)
    _run_scan(source, out, config)

    assert forwarded["resolved_fail_on_findings"] is False, forwarded


def test_a_source_directory_with_an_embedded_nul_is_not_read_when_no_config_names_a_file(
    tmp_path,
):
    """With no config file to read the computation never looks at the source
    directory, so a name that cannot be resolved is no reason to fail: a
    build-only run asks for the variable names with no refusal run before it."""
    reads = run_ash_container.OperatorConfigReads()

    assert reads.environment_names(None, None, "a\0b") == []
    assert reads.environment_names("", "", "a\0b") == []


def test_a_lookup_with_no_config_file_reads_nothing_of_the_source_directory(
    tmp_path, monkeypatch
):
    """With no config file to read there is no answer to key: the lookup
    returns at once, before it walks the source directory's trees."""

    def refuse(_source_dir):
        raise AssertionError("the source directory's trees were walked")

    monkeypatch.setattr(run_ash_container, "_scanned_tree_roots", refuse)
    reads = run_ash_container.OperatorConfigReads()

    assert reads.environment_names(None, None, tmp_path) == []
    assert reads.environment_names("", None, tmp_path) == []


def test_a_source_directory_with_an_embedded_nul_is_a_named_refusal_not_a_crash(
    tmp_path,
):
    """With a config file to read, the unresolvable source directory is
    reported the way the computation reports every unreadable input: a
    ContainerInputError, which the callers turn into exit 3 or into a build
    with nothing to hide, never a ValueError out of the record."""
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    reads = run_ash_container.OperatorConfigReads()

    with pytest.raises(run_ash_container.ContainerInputError):
        reads.environment_names(str(config), None, "a\0b")


def test_a_build_only_run_with_an_embedded_nul_in_the_source_directory_builds(
    tmp_path, recording_runner, stubbed_build
):
    """The Python API can pass a name the command line cannot. A run that only
    builds reads none of the source directory's inputs, so it builds as it did
    before the record existed."""
    built: list[bool] = []
    stubbed_build(lambda: built.append(True))

    result = run_ash_container.run_ash_container(
        source_dir="a\0b",
        output_dir=str(tmp_path / "out"),
        build=True,
        run=False,
        progress=False,
        quiet=True,
    )

    assert built == [True]
    assert result.returncode == 0, result


def _container_scan_with_build(source: Path, out: Path, config: Path):
    return run_ash_container.run_ash_container(
        source_dir=str(source),
        output_dir=str(out),
        config=str(config),
        build=True,
        run=True,
        progress=False,
        quiet=True,
    )


def test_a_chain_that_becomes_refusable_during_the_build_is_refused_without_a_run(
    tmp_path, recording_runner, stubbed_build, monkeypatch
):
    """The chain was acceptable when the build started. The run phase reads it
    again, finds a variable the container scan cannot be given, and refuses
    with exit 3 before any run command is assembled."""
    source, out, config = _scan_inputs(tmp_path)
    monkeypatch.setenv("ASH_MODE", "from-the-operator")
    stubbed_build(lambda: config.write_text("project_name: ${ASH_MODE}\n"))

    result = _container_scan_with_build(source, out, config)

    assert result.returncode == 3, result
    assert not any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        recording_runner
    )


def _checkout_scan_inputs(root: Path):
    """(source, out, config, shared): a config kept outside the scanned
    checkout, in a directory that also holds the checkout, and a file of the
    checkout the config can extend once it names it."""
    ops = root / "ops"
    repo = _checkout(ops / "repo")
    source = repo / "app"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = root / "out"
    out.mkdir()
    config = _write(ops / "ash.yaml", {"project_name": "op"})
    shared = _write(repo / "shared.yaml", {"project_name": "shared"})
    return source, out, config, shared


def test_a_base_inside_the_checkout_added_during_the_build_carries_its_mark(
    tmp_path, recording_runner, stubbed_build
):
    """The container scan cannot tell which mounted file the repository wrote,
    so the host tells it. A base inside the scanned checkout that the config
    gained while the image was building is marked for the run, not mounted as
    if the operator had written it."""
    source, out, config, shared = _checkout_scan_inputs(tmp_path)
    stubbed_build(
        lambda: _write(config, {"project_name": "op", "extends": "repo/shared.yaml"})
    )

    result = _container_scan_with_build(source, out, config)

    run_cmd = _the_run_command(recording_runner)
    pairs = list(zip(run_cmd, run_cmd[1:]))
    assert any(
        flag == "--config-file-from-scanned-repository" and mark.endswith("shared.yaml")
        for flag, mark in pairs
    ), run_cmd
    assert result.returncode == 0, result


def test_a_config_left_alone_during_the_build_marks_no_base(
    tmp_path, recording_runner, stubbed_build
):
    """The must-not twin: nothing was added during the build, so the run
    command marks no file as the repository's."""
    source, out, config, shared = _checkout_scan_inputs(tmp_path)
    stubbed_build(lambda: None)

    _container_scan_with_build(source, out, config)

    run_cmd = _the_run_command(recording_runner)
    assert "--config-file-from-scanned-repository" not in run_cmd, run_cmd
