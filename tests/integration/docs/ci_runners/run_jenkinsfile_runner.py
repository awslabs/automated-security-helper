# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting Jenkinsfile Runner on one of the two pinned Jenkins cores.

Every start goes through ``jenkinsfile_runner_argv``. Immediately before it returns a
command line it hashes ``<jenkins dir>/jenkins.war`` and every plugin archive in
``<jenkins dir>/plugins`` against runners.toml and the core's plugins file, and refuses
on a mismatch, a missing file or a plugin archive the closure does not list. The
command line always passes the WAR with ``-w`` and the plugin directory with ``-p``:
without ``-w`` the release downloads a core over plain http, and without ``-p`` it
reads plugins.txt and resolves plugins from the update center. It never opens a web
port (no ``--httpPort``), and the committed init hook gives the built-in node the label
``linux`` that the docs' Jenkinsfile asks for. JAVA_HOME is the hosted runner's JDK
for the core's Java version.

Jenkins explodes each plugin into a directory beside its archive in the plugin
directory; those directories are its own and are not checked.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .env import CheckedArgv, launch, launch_env, run_in_new_session
from .manifest import RUNNERS_TOML, entry, load_manifest, load_toml, tool_executable

JENKINSFILE_RUNNER_TOOL = "tools.jenkinsfile-runner"
CORES = {"jenkinsfile-runner-lts": "lts", "jenkinsfile-runner-bundled": "bundled"}
MANIFEST_KEYS = {
    leg: (JENKINSFILE_RUNNER_TOOL, f"jenkins.cores.{core}")
    for leg, core in CORES.items()
}
HOOKS_DIR = Path(__file__).resolve().parent / "jenkins" / "init.groovy.d"
COMMANDS = ("lint", "run")
#: Every file Jenkins loads a plugin from: the archives, and the .hpl and .jpl link
#: files it reads first (InitStrategy.listPluginArchives).
PLUGIN_SUFFIXES = (".hpi", ".jpi", ".hpl", ".jpl")


class JenkinsInstallError(RuntimeError):
    """The installed core or plugins are not the ones runners.toml pins."""


def jenkins_core(manifest: Mapping[str, Any], leg: str) -> Mapping[str, Any]:
    if leg not in CORES:
        raise ValueError(f"{leg} is not a Jenkins leg; the legs are {sorted(CORES)}")
    return entry(manifest, f"jenkins.cores.{CORES[leg]}")


def jenkins_plugins(
    core: Mapping[str, Any], *, manifest_path: Path = RUNNERS_TOML
) -> list[Mapping[str, Any]]:
    """The plugin closure of ``core``, from its plugins file beside runners.toml."""
    plugins = load_toml(Path(manifest_path).parent / str(core["plugins"])).get("plugin")
    if not isinstance(plugins, list) or not plugins:
        raise JenkinsInstallError(f"{core['plugins']} lists no plugins")
    return plugins


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jenkins_install_problems(
    jenkins_dir: Path, core: Mapping[str, Any], plugins: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Every way ``jenkins_dir`` differs from the pinned core and plugin closure."""
    jenkins_dir = Path(jenkins_dir)
    problems = []
    war = jenkins_dir / "jenkins.war"
    if not war.is_file():
        problems.append(f"{war} is missing")
    elif _sha256(war) != core["war_sha256"]:
        problems.append(f"{war} is not the pinned core: sha256 {_sha256(war)}")
    plugin_dir = jenkins_dir / "plugins"
    pinned = {str(plugin["name"]): str(plugin["sha256"]) for plugin in plugins}
    for name, sha256 in sorted(pinned.items()):
        archive = plugin_dir / f"{name}.hpi"
        if not archive.is_file():
            problems.append(f"{archive} is missing")
        elif _sha256(archive) != sha256:
            problems.append(
                f"{archive} is not the pinned {name}: sha256 {_sha256(archive)}"
            )
    if plugin_dir.is_dir():
        for path in sorted(plugin_dir.iterdir()):
            if (
                path.suffix in PLUGIN_SUFFIXES
                and not path.is_dir()
                and not (path.suffix == ".hpi" and path.stem in pinned)
            ):
                problems.append(f"{path} is not in the pinned plugin closure")
    else:
        problems.append(f"{plugin_dir} is missing")
    return problems


def _jenkinsfile_runner_program(manifest: Mapping[str, Any], bin_dir: Path) -> Path:
    program = tool_executable(manifest, bin_dir, JENKINSFILE_RUNNER_TOOL)
    if not program.is_file() or not os.access(program, os.X_OK):
        raise JenkinsInstallError(f"{program} is not an installed program")
    return program


def _copy_plugins(
    jenkins_dir: Path, plugins: Sequence[Mapping[str, Any]], plugin_copy: Path
) -> None:
    """Copy the closure's archives into ``plugin_copy``, a new directory, and hash each
    copy again: Jenkins explodes, renames and adds files in the -p directory it is
    given, so every launch gets its own, and the install stays as installed."""
    plugin_copy = Path(plugin_copy)
    if plugin_copy.exists():
        raise JenkinsInstallError(
            f"{plugin_copy} exists already; each launch needs a new copy of the plugins"
        )
    plugin_copy.mkdir(parents=True)
    for plugin in plugins:
        name = str(plugin["name"])
        copy = plugin_copy / f"{name}.hpi"
        shutil.copyfile(Path(jenkins_dir) / "plugins" / f"{name}.hpi", copy)
        if _sha256(copy) != str(plugin["sha256"]):
            raise JenkinsInstallError(f"{copy} is not the pinned {name} once copied")


def jenkinsfile_runner_argv(
    leg: str,
    *,
    command: str,
    bin_dir: Path,
    jenkins_dir: Path,
    jenkinsfile: Path,
    jenkins_home: Path,
    plugin_copy: Path,
    workspace: Path | None = None,
    manifest_path: Path = RUNNERS_TOML,
    hooks_dir: Path = HOOKS_DIR,
) -> CheckedArgv:
    """The command line for ``command`` (lint or run) on ``leg``'s core.

    Hashes the core and its plugins first, every time, and raises JenkinsInstallError
    instead of returning a command line when they are not the pinned ones. The
    plugins are then copied into ``plugin_copy``, a directory that must not exist yet,
    and hashed again there; that copy is the command line's plugin directory.
    """
    if command not in COMMANDS:
        raise ValueError(f"{command!r} is not one of {COMMANDS}")
    manifest = load_manifest(manifest_path)
    core = jenkins_core(manifest, leg)
    plugins = jenkins_plugins(core, manifest_path=manifest_path)
    problems = jenkins_install_problems(jenkins_dir, core, plugins)
    if problems:
        raise JenkinsInstallError(
            f"{leg} will not start on an install that is not the pinned one: "
            + "; ".join(problems)
        )
    if command == "run" and workspace is None:
        raise ValueError("a run needs its workspace")
    program = _jenkinsfile_runner_program(manifest, bin_dir)
    _copy_plugins(jenkins_dir, plugins, plugin_copy)
    argv = [
        str(program),
        command,
        "-w",
        str(Path(jenkins_dir) / "jenkins.war"),
        "-p",
        str(plugin_copy),
        "--jenkinsHome",
        str(jenkins_home),
        "--withInitHooks",
        str(hooks_dir),
        "-f",
        str(jenkinsfile),
    ]
    if command == "run":
        argv += ["--runWorkspace", str(workspace)]
    return CheckedArgv(argv)


def run_jenkinsfile_runner(
    leg: str,
    *,
    command: str,
    bin_dir: Path,
    jenkins_dir: Path,
    jenkinsfile: Path,
    jenkins_home: Path,
    workspace: Path | None,
    plugin_copy: Path,
    cwd: Path,
    home: Path,
    tool_cache: Path,
    outer: Mapping[str, str],
    log: Path,
    manifest_path: Path = RUNNERS_TOML,
    hooks_dir: Path = HOOKS_DIR,
    run: Callable[..., subprocess.CompletedProcess] = run_in_new_session,
    timeout: float | None = None,
) -> int:
    """Start ``command`` on ``leg`` through env -i and return its exit code.

    Jenkins itself starts no container (the closure has no Docker plugin), but a
    pipeline's ``sh`` step may run the docker CLI, so the launch removes every
    container that appeared while it ran.
    """
    argv = jenkinsfile_runner_argv(
        leg,
        command=command,
        bin_dir=bin_dir,
        jenkins_dir=jenkins_dir,
        jenkinsfile=jenkinsfile,
        jenkins_home=jenkins_home,
        plugin_copy=plugin_copy,
        workspace=workspace,
        manifest_path=manifest_path,
        hooks_dir=hooks_dir,
    )
    core = jenkins_core(load_manifest(manifest_path), leg)
    env = launch_env(
        leg,
        home=home,
        runner_bin=Path(argv[0]).parent,
        tool_cache=tool_cache,
        outer=outer,
        java=str(core["java"]),
    )
    return launch(
        env,
        argv,
        cwd=cwd,
        log=log,
        run=run,
        timeout=timeout,
        remove_containers=True,
    )
