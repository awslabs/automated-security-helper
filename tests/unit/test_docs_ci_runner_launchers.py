# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How each CI runner is started: its command line, its environment, and what it runs.

WHY THIS EXISTS
---------------
tests/integration/docs/ci_runners/ has one launcher module per runner. Each builds the
runner's command line from the pinned manifest, runners.toml, and starts it through
``env.launch``, which runs ``env -i`` with an environment built from nothing. The runs
themselves happen only on a GitHub-hosted runner, so these tests check what can be
checked without starting anything: the command lines, the environments, and the files
the runners are given. None of them starts a runner, java or docker; a launch is
tested with a fake ``run=`` callable.

What each launcher must hold to:

* Jenkinsfile Runner: always ``-w <jenkins.war>`` and ``-p <plugins dir>``, so it never
  downloads a core over plain http or resolves plugins from the update center; the WAR
  and every plugin hashed against the manifest immediately before the command line is
  returned, and refused on a mismatch, a missing file or an extra plugin; no web port;
  the committed init hook that labels the built-in node ``linux``; JAVA_HOME from the
  hosted runner's JDK for the leg's core. One function builds that command line, and a
  static check keeps every other path from starting the program.
* CircleCI: each CLI's update check and telemetry turned off by its own switches, never
  by ``CI``, which changes other behavior; ``local execute`` mounts the wheel and a
  report directory and runs the build agent pinned in the manifest.
* The CodeBuild agent: ``codebuild_build.sh`` under ``script`` (it runs ``docker run
  -it``, which needs a terminal), with the pinned images, never ``-c`` (which passes the
  host's AWS credentials) or ``-d`` (privileged mode).
* act: the host as the runner, one job at a time, JSON logs and never verbose ones, the
  actions that write to GitHub replaced with local stubs, and no token.
* gitlab-ci-local: the helper image the run builds from a pinned base, images pulled
  only when missing, the wheel mounted read-only, and merge request variables only on a
  merge request.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import inspect
import itertools
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
RUNNER_TESTS = (
    REPO_ROOT / "tests" / "integration" / "docs" / "test_docs_ci_runners.py",
    REPO_ROOT / "tests" / "integration" / "docs" / "test_docs_ci_runners_can_fail.py",
)
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-docs-ci-runners.yml"
JENKINS_LEGS = ("jenkinsfile-runner-lts", "jenkinsfile-runner-bundled")
JAVA = {"jenkinsfile-runner-lts": "21", "jenkinsfile-runner-bundled": "11"}
OUTER = {
    "PATH": "/work/repo/.venv/bin:/usr/bin:/bin",
    "HOME": "/home/runner",
    "CI": "true",
    "ImageOS": "ubuntu24",
    "ImageVersion": "20261005.1.0",
    "JAVA_HOME_11_X64": "/usr/lib/jvm/temurin-11-jdk-amd64",
    "JAVA_HOME_21_X64": "/usr/lib/jvm/temurin-21-jdk-amd64",
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_TOKEN": "s",
}
BUILD_IMAGE = "public.ecr.aws/codebuild/amazonlinux-x86_64-standard@sha256:" + "1" * 64
AGENT_IMAGE = "public.ecr.aws/codebuild/local-builds@sha256:" + "2" * 64
PICARD = "docker.io/circleci/picard@sha256:" + "3" * 64
MANIFEST = {
    "tools": {
        "codebuild-build-sh": {"executable": "codebuild_build.sh"},
        "circleci-cli-local-execute": {"executable": "circleci"},
        "circleci-cli": {"executable": "circleci"},
    },
    "images": {
        "codebuild-standard-5": {"ref": BUILD_IMAGE},
        "codebuild-local-agent": {"ref": AGENT_IMAGE},
        "circleci-picard": {"ref": PICARD},
    },
}


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


def _value(argv: list[str], flag: str) -> list[str]:
    """Every value given to ``flag`` in an argv."""
    return [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == flag]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeRun:
    """Stands in for subprocess.run: records each call, starts nothing."""

    def __init__(self, returncode: int = 3):
        self.calls: list[tuple[list[str], dict]] = []
        self.returncode = returncode

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(list(argv), self.returncode)


def _launched(fake: FakeRun) -> tuple[dict[str, str], list[str]]:
    """The environment and the command of the one ``env -i`` call a fake recorded."""
    assert len(fake.calls) == 1, fake.calls
    argv, _ = fake.calls[0]
    assert argv[:2] == ["env", "-i"], argv[:4]
    env: dict[str, str] = {}
    index = 2
    while index < len(argv) and "=" in argv[index] and not argv[index].startswith("/"):
        key, value = argv[index].split("=", 1)
        env[key] = value
        index += 1
    return env, argv[index:]


def _home(tmp_path: Path, name: str = "home") -> Path:
    home = tmp_path / name
    home.mkdir()
    return home


# ---------------------------------------------------------------------------
# Jenkinsfile Runner
# ---------------------------------------------------------------------------

PLUGINS = ("junit", "workflow-job")


def _jenkins_install(tmp_path: Path, leg: str) -> dict:
    """A manifest, a plugin closure and an installed core for one leg, all in tmp_path."""
    core = "lts" if leg.endswith("-lts") else "bundled"
    root = tmp_path / leg
    jenkins_dir = root / "jenkins-dir"
    (jenkins_dir / "plugins").mkdir(parents=True)
    war = jenkins_dir / "jenkins.war"
    war.write_bytes(f"a {core} core".encode())
    entries = []
    for name in PLUGINS:
        hpi = jenkins_dir / "plugins" / f"{name}.hpi"
        hpi.write_bytes(f"{name} for {core}".encode())
        entries.append(
            f'[[plugin]]\nname = "{name}"\nversion = "1.0"\n'
            f'url = "https://get.jenkins.io/plugins/{name}/1.0/{name}.hpi"\n'
            f'sha256 = "{_sha256(hpi)}"\ndependencies = []\n'
        )
    manifest_dir = root / "manifest"
    (manifest_dir / "jenkins").mkdir(parents=True)
    bundled = "bundled = []\n\n" if core == "bundled" else ""
    (manifest_dir / "jenkins" / f"plugins-{core}.toml").write_text(
        bundled + "\n".join(entries), encoding="utf-8"
    )
    other = "bundled" if core == "lts" else "lts"
    manifest = manifest_dir / "runners.toml"
    manifest.write_text(
        "[tools.jenkinsfile-runner]\n"
        'version = "1.0-beta-32"\n'
        'url = "https://github.com/jenkinsci/jenkinsfile-runner/releases/download/'
        '1.0-beta-32/jenkinsfile-runner-1.0-beta-32.zip"\n'
        f'sha256 = "{"0" * 64}"\nlicense = "MIT"\nsource = "test"\n'
        'executable = "bin/jenkinsfile-runner"\n\n'
        f"[jenkins.cores.{core}]\n"
        'core_version = "2.0.0"\n'
        'war_url = "https://get.jenkins.io/war-stable/2.0.0/jenkins.war"\n'
        f'war_sha256 = "{_sha256(war)}"\n'
        f'java = "{JAVA[leg]}"\n'
        f'plugins = "jenkins/plugins-{core}.toml"\n\n'
        f"[jenkins.cores.{other}]\n"
        'core_version = "1.0.0"\n'
        'war_url = "https://get.jenkins.io/war-stable/1.0.0/jenkins.war"\n'
        f'war_sha256 = "{"f" * 64}"\n'
        'java = "17"\n'
        f'plugins = "jenkins/plugins-{other}.toml"\n',
        encoding="utf-8",
    )
    bin_dir = root / "bin"
    program = bin_dir / "jenkinsfile-runner" / "bin" / "jenkinsfile-runner"
    program.parent.mkdir(parents=True)
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return {
        "manifest_path": manifest,
        "jenkins_dir": jenkins_dir,
        "bin_dir": bin_dir,
        "program": program,
        "war": war,
        "root": root,
        "copies": itertools.count(1),
    }


def _plugin_copy(install: dict) -> Path:
    """A new directory, not yet made, for one launch's copy of the plugins."""
    return install["root"] / "work" / f"plugins-{next(install['copies'])}"


def _jenkins_argv(
    install: dict, leg: str, command: str = "run", plugin_copy: Path | None = None
) -> list[str]:
    root = install["root"]
    return _api("run_jenkinsfile_runner", "jenkinsfile_runner_argv")(
        leg,
        command=command,
        bin_dir=install["bin_dir"],
        jenkins_dir=install["jenkins_dir"],
        jenkinsfile=root / "project" / "Jenkinsfile",
        jenkins_home=root / "jenkins-home",
        workspace=root / "project",
        plugin_copy=plugin_copy or _plugin_copy(install),
        manifest_path=install["manifest_path"],
    )


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
@pytest.mark.parametrize("command", ["run", "lint"])
def test_jenkinsfile_runner_is_given_the_war_and_the_plugins_dir(
    tmp_path, leg, command
):
    install = _jenkins_install(tmp_path, leg)
    copy = install["root"] / "work" / "plugins-for-this-launch"
    argv = _jenkins_argv(install, leg, command, plugin_copy=copy)
    hooks = _api("run_jenkinsfile_runner", "HOOKS_DIR")
    assert isinstance(argv, _api("env", "CheckedArgv"))
    assert argv[0] == str(install["program"]) and argv[1] == command
    assert _value(argv, "-w") == [str(install["war"])]
    (plugins,) = _value(argv, "-p")
    assert Path(plugins) == copy and copy.is_dir(), (
        "each launch gets its own copy of the verified plugins"
    )
    assert sorted(p.name for p in copy.iterdir()) == sorted(
        f"{name}.hpi" for name in PLUGINS
    )
    for name in PLUGINS:
        assert _sha256(copy / f"{name}.hpi") == _sha256(
            install["jenkins_dir"] / "plugins" / f"{name}.hpi"
        )
    assert _value(argv, "--withInitHooks") == [str(hooks)]
    assert Path(hooks) == CI_RUNNERS / "jenkins" / "init.groovy.d"
    assert _value(argv, "-f") == [str(install["root"] / "project" / "Jenkinsfile")]
    assert _value(argv, "--jenkinsHome") == [str(install["root"] / "jenkins-home")]
    if command == "run":
        assert _value(argv, "--runWorkspace") == [str(install["root"] / "project")]
    for word in argv:
        assert word not in ("--httpPort", "-jv", "--jenkins-version", "--openWebUI")
        assert not word.endswith("plugins.txt"), word
        assert not word.startswith("http:"), word


def _break_war(install: dict) -> None:
    install["war"].write_bytes(b"another core")


def _break_plugin(install: dict) -> None:
    (install["jenkins_dir"] / "plugins" / "junit.hpi").write_bytes(b"another junit")


def _remove_war(install: dict) -> None:
    install["war"].unlink()


def _remove_plugin(install: dict) -> None:
    (install["jenkins_dir"] / "plugins" / "workflow-job.hpi").unlink()


def _extra_hpi(install: dict) -> None:
    (install["jenkins_dir"] / "plugins" / "extra.hpi").write_bytes(
        b"not in the closure"
    )


def _extra_jpi(install: dict) -> None:
    (install["jenkins_dir"] / "plugins" / "extra.jpi").write_bytes(
        b"not in the closure"
    )


def _extra_hpl(install: dict) -> None:
    """Jenkins loads .hpl and .jpl (plugin link) files too, before the archives."""
    (install["jenkins_dir"] / "plugins" / "extra.hpl").write_text(
        "/elsewhere/extra\n", encoding="utf-8"
    )


def _extra_jpl(install: dict) -> None:
    (install["jenkins_dir"] / "plugins" / "junit.jpl").write_text(
        "/elsewhere/junit\n", encoding="utf-8"
    )


BREAKAGES = {
    "another war": (_break_war, "jenkins.war"),
    "another plugin": (_break_plugin, "junit.hpi"),
    "no war": (_remove_war, "jenkins.war"),
    "a missing plugin": (_remove_plugin, "workflow-job.hpi"),
    "an extra hpi": (_extra_hpi, "extra.hpi"),
    "an extra jpi": (_extra_jpi, "extra.jpi"),
    "an extra hpl": (_extra_hpl, "extra.hpl"),
    "a jpl beside a pinned plugin": (_extra_jpl, "junit.jpl"),
}


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
@pytest.mark.parametrize("breakage", sorted(BREAKAGES))
def test_a_core_or_plugin_that_is_not_the_pinned_one_is_refused(
    tmp_path, leg, breakage
):
    install = _jenkins_install(tmp_path, leg)
    error = _api("run_jenkinsfile_runner", "JenkinsInstallError")
    breaker, named = BREAKAGES[breakage]
    breaker(install)
    with pytest.raises(error) as raised:
        _jenkins_argv(install, leg)
    assert named in str(raised.value), str(raised.value)


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_the_install_is_hashed_again_at_every_launch(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    error = _api("run_jenkinsfile_runner", "JenkinsInstallError")
    assert _jenkins_argv(install, leg)
    _break_plugin(install)
    with pytest.raises(error):
        _jenkins_argv(install, leg)


@pytest.mark.unit
def test_exploded_plugin_directories_are_jenkins_own_and_allowed(tmp_path):
    """Jenkins explodes each plugin into a directory beside it in the -p directory."""
    leg = "jenkinsfile-runner-lts"
    install = _jenkins_install(tmp_path, leg)
    (install["jenkins_dir"] / "plugins" / "junit" / "WEB-INF").mkdir(parents=True)
    assert _jenkins_argv(install, leg)


@pytest.mark.unit
def test_a_plugin_copy_that_already_exists_is_refused(tmp_path):
    leg = "jenkinsfile-runner-lts"
    install = _jenkins_install(tmp_path, leg)
    copy = install["root"] / "work" / "used-before"
    copy.mkdir(parents=True)
    with pytest.raises(_api("run_jenkinsfile_runner", "JenkinsInstallError")) as raised:
        _jenkins_argv(install, leg, plugin_copy=copy)
    assert str(copy) in str(raised.value)


@pytest.mark.unit
def test_a_copy_that_is_not_the_pinned_plugin_never_starts(tmp_path, monkeypatch):
    """The copies are hashed again, so a copy that came out different is refused."""
    leg = "jenkinsfile-runner-lts"
    install = _jenkins_install(tmp_path, leg)

    def copies_something_else(source, target):
        Path(target).write_bytes(b"not the pinned plugin")

    monkeypatch.setattr(
        _module("run_jenkinsfile_runner").shutil, "copyfile", copies_something_else
    )
    fake = FakeRun()
    with pytest.raises(_api("run_jenkinsfile_runner", "JenkinsInstallError")) as raised:
        _run_jenkins(install, leg, fake, tmp_path)
    assert "copied" in str(raised.value)
    assert fake.calls == []


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_what_jenkins_does_to_one_launch_s_plugins_never_reaches_the_next(
    tmp_path, leg
):
    """Jenkins explodes, renames and adds files in the -p directory it is given, so
    the lint and the run each get their own copy and the install itself stays as
    installed."""
    install = _jenkins_install(tmp_path, leg)
    first = Path(_value(_jenkins_argv(install, leg, "lint"), "-p")[0])
    (first / "junit" / "WEB-INF").mkdir(parents=True)
    (first / "workflow-job.hpi").rename(first / "workflow-job.jpi")
    (first / "workflow-job.jpi.pinned").write_text("", encoding="utf-8")
    second = Path(_value(_jenkins_argv(install, leg, "run"), "-p")[0])
    assert second != first
    assert sorted(p.name for p in second.iterdir()) == sorted(
        f"{name}.hpi" for name in PLUGINS
    )
    assert sorted(p.name for p in (install["jenkins_dir"] / "plugins").iterdir()) == (
        sorted(f"{name}.hpi" for name in PLUGINS)
    )


def _run_jenkins(
    install: dict, leg: str, fake: FakeRun, tmp_path: Path, **extra
) -> int:
    root = install["root"]
    return _api("run_jenkinsfile_runner", "run_jenkinsfile_runner")(
        leg,
        command="run",
        bin_dir=install["bin_dir"],
        jenkins_dir=install["jenkins_dir"],
        jenkinsfile=root / "project" / "Jenkinsfile",
        jenkins_home=root / "jenkins-home",
        workspace=root / "project",
        plugin_copy=extra.pop("plugin_copy", _plugin_copy(install)),
        cwd=tmp_path,
        home=_home(tmp_path, f"home-{leg}"),
        tool_cache=tmp_path / "tool-cache",
        outer=OUTER,
        log=tmp_path / "logs" / f"{leg}.log",
        manifest_path=install["manifest_path"],
        run=fake,
        **extra,
    )


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_jenkinsfile_runner_runs_with_the_java_of_its_core(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    fake = FakeRun(returncode=1)
    copy = tmp_path / "copy-for-the-run"
    assert _run_jenkins(install, leg, fake, tmp_path, plugin_copy=copy) == 1
    env, command = _launched(fake)
    assert env["JAVA_HOME"] == OUTER[f"JAVA_HOME_{JAVA[leg]}_X64"]
    assert command[:2] == [str(install["program"]), "run"]
    assert _value(command, "-p") == [str(copy)]
    assert _value(command, "-w") == [str(install["war"])]
    assert (tmp_path / "logs" / f"{leg}.log").is_file()


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_the_jenkins_home_exists_when_jenkinsfile_runner_starts(tmp_path, leg):
    """Jenkinsfile Runner refuses a --runHome that is not a directory."""
    install = _jenkins_install(tmp_path, leg)
    home = install["root"] / "jenkins-home"
    assert not home.exists()
    seen = []

    class Checking(FakeRun):
        def __call__(self, *args, **kwargs):
            seen.append(home.is_dir())
            return super().__call__(*args, **kwargs)

    _run_jenkins(install, leg, Checking(returncode=0), tmp_path)
    assert seen == [True]
    assert list(home.iterdir()) == []


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_jenkinsfile_runner_s_launch_has_its_time_limit(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    fake = FakeRun(returncode=0)
    _run_jenkins(install, leg, fake, tmp_path, timeout=11)
    assert fake.calls[0][1].get("timeout") == 11


# Only the checked argv starts Jenkinsfile Runner --------------------------------


def _plain_env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv",
    [
        ["/opt/bin/jenkinsfile-runner/bin/jenkinsfile-runner", "run", "-f", "J"],
        ["jenkinsfile-runner", "lint"],
        ["sh", "-c", "/b/jenkinsfile-runner/bin/jenkinsfile-runner run -f J"],
        ["java", "-cp", "/b/jenkinsfile-runner/lib/setup.jar", "Main"],
    ],
    ids=["its path", "its name", "through a shell", "its jars under java"],
)
def test_an_argv_that_starts_jenkinsfile_runner_unchecked_is_refused(tmp_path, argv):
    """jenkinsfile_runner_argv hashes the core and the plugins before it builds the
    command line; any other command line that would start the program is refused
    where every runner is started, whatever built it."""
    with pytest.raises(ValueError, match="jenkinsfile_runner_argv"):
        _api("env", "launch_argv")(_plain_env(tmp_path), argv)
    fake = FakeRun()
    with pytest.raises(ValueError):
        _api("env", "launch")(
            _plain_env(tmp_path), argv, cwd=tmp_path, log=tmp_path / "x.log", run=fake
        )
    assert fake.calls == []


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_the_checked_argv_is_the_one_that_starts(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    argv = _jenkins_argv(install, leg)
    words = _api("env", "launch_argv")(_plain_env(tmp_path), argv)
    assert words[-len(argv) :] == list(argv)
    plain = list(argv)
    with pytest.raises(ValueError):
        _api("env", "launch_argv")(_plain_env(tmp_path), plain)


@pytest.mark.unit
def test_other_runners_argvs_are_not_refused(tmp_path):
    for argv in (
        ["/b/act/act", "pull_request"],
        ["script", "-q", "-e", "-c", "/b/codebuild-build-sh/codebuild_build.sh", "x"],
        ["/b/x", "--log", "/out/jenkins-lint.log", "/w/Jenkinsfile"],
        ["/b/javac-tools/x", "--java-home", "/usr/lib/jvm/java-21"],
    ):
        assert _api("env", "launch_argv")(_plain_env(tmp_path), argv)[-len(argv) :] == (
            argv
        )


#: Command lines the guard must refuse although no word is the program's exact name:
#: it refuses any word that holds the name, in any case, and any argv whose program
#: is ``java``, since a word boundary around the name lets these through.
UNCHECKED_STARTS = {
    "its jar": ["/b/x", "-jar", "/b/jenkinsfile-runner.jar", "run"],
    "a versioned install": ["/opt/jenkinsfile-runner-1.2/bin/run", "-f", "J"],
    "java -cp with its jar": [
        "java",
        "-cp",
        "/b/lib/jenkinsfile-runner.jar",
        "io.jenkins.jenkinsfile.runner.App",
    ],
    "the name in capitals": ["/b/JENKINSFILE-RUNNER", "run"],
    "the name in mixed case": ["sh", "-c", "exec Jenkinsfile-Runner lint"],
    "a log named after it": ["/b/x", "--log", "/out/jenkinsfile-runner-lint.log"],
    "a leg named after it": ["/b/x", "--leg", "jenkinsfile-runner-lts"],
    "java alone": ["java", "-version"],
    "java by its path": ["/usr/lib/jvm/temurin-21-jdk-amd64/bin/java", "-jar", "x.jar"],
}


#: Command lines that start java through a wrapper or a shell string: the guard looks
#: at every word, and at each shell word of a word, for a program named java.
UNCHECKED_JAVA_STARTS = {
    "env java": ["env", "java", "-jar", "/b/x.jar"],
    "env with options and a variable": [
        "/usr/bin/env",
        "-i",
        "JAVA_OPTS=-Xmx1g",
        "/usr/lib/jvm/temurin-21-jdk-amd64/bin/java",
        "-version",
    ],
    "env -S": ["env", "-S", "java -jar /b/x.jar"],
    "timeout java": ["timeout", "60", "java", "-version"],
    "sh -c": ["sh", "-c", "exec java -jar /b/x.jar"],
    "bash -euc": ["bash", "-euc", "cd /w && java -cp /b/lib/app.jar Main"],
    "a shell string naming java by its path": [
        "/bin/sh",
        "-c",
        '"$HOME"/x; /usr/lib/jvm/temurin-11-jdk-amd64/bin/java -jar /b/x.jar',
    ],
    "script -c": ["script", "-q", "-e", "-c", "java -jar /b/x.jar", "/dev/null"],
}


@pytest.mark.unit
@pytest.mark.parametrize("form", sorted(UNCHECKED_JAVA_STARTS))
def test_the_guard_refuses_java_behind_a_wrapper_or_in_a_shell_string(tmp_path, form):
    argv = UNCHECKED_JAVA_STARTS[form]
    with pytest.raises(ValueError, match="jenkinsfile_runner_argv"):
        _api("env", "launch_argv")(_plain_env(tmp_path), argv)
    fake = FakeRun()
    with pytest.raises(ValueError):
        _api("env", "launch")(
            _plain_env(tmp_path), argv, cwd=tmp_path, log=tmp_path / "x.log", run=fake
        )
    assert fake.calls == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "echo javascript; ls /usr/share/java-common"],
        ["/b/x", "--log", "/out/java-lint.log"],
        ["/b/x", "--setting", "JAVA_HOME=/usr/lib/jvm/java-21"],
        ["script", "-q", "-e", "-c", "/b/codebuild-build-sh/codebuild_build.sh", "x"],
    ],
    ids=["a shell string without java", "a log", "an assignment", "the CodeBuild leg"],
)
def test_the_java_guard_leaves_other_words_alone(tmp_path, argv):
    assert _api("env", "launch_argv")(_plain_env(tmp_path), argv)[-len(argv) :] == argv


@pytest.mark.unit
@pytest.mark.parametrize("form", sorted(UNCHECKED_STARTS))
def test_the_guard_refuses_every_form_of_an_unchecked_start(tmp_path, form):
    argv = UNCHECKED_STARTS[form]
    with pytest.raises(ValueError, match="jenkinsfile_runner_argv"):
        _api("env", "launch_argv")(_plain_env(tmp_path), argv)
    fake = FakeRun()
    with pytest.raises(ValueError):
        _api("env", "launch")(
            _plain_env(tmp_path), argv, cwd=tmp_path, log=tmp_path / "x.log", run=fake
        )
    assert fake.calls == []


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_a_refused_install_never_starts_the_runner(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    _break_war(install)
    fake = FakeRun()
    with pytest.raises(_api("run_jenkinsfile_runner", "JenkinsInstallError")):
        _run_jenkins(install, leg, fake, tmp_path)
    assert fake.calls == []


# The one way to start Jenkinsfile Runner -------------------------------------

SANCTIONED = "run_jenkinsfile_runner.py"
ARGV_FUNCTION = "jenkinsfile_runner_argv"
RUN_FUNCTION = "run_jenkinsfile_runner"
PRIVATE = "_jenkinsfile_runner_program"
TOOL_CONSTANT = "JENKINSFILE_RUNNER_TOOL"
CHECKED_TYPE = "CheckedArgv"
FINDER = "tool_executable"
#: The program as a word (``jenkinsfile-runner``, or a path ending in it) and its
#: manifest key (``tools.jenkinsfile-runner``). Not the leg names
#: (``jenkinsfile-runner-lts``) or log names (``jenkinsfile-runner.log``).
NAMES_THE_PROGRAM = re.compile(
    r"(?:(?<=tools\.)|(?<![\w.-]))jenkinsfile-runner(?![\w.-])"
)
#: Where a name of the program may stand outside the launcher, each with its reason:
#: install_tools.py's RUNNER_PINS names the manifest key of every tool a leg
#: installs, and env.py's CHECKED_PROGRAMS names the programs it refuses to start
#: from any argv but their own launcher's.
NAMED_IN = {"install_tools.py": "RUNNER_PINS", "env.py": "CHECKED_PROGRAMS"}
STARTERS = {
    "launch",
    "launch_argv",
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
    "system",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "create_subprocess_exec",
    "create_subprocess_shell",
}


def _string_value(node: ast.AST) -> str | None:
    """The string ``node`` evaluates to when it is built from string constants only:
    a constant, a ``+`` of such, or ``"<sep>".join([...])`` of such."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string_value(node.left), _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _string_value(node.func.value)
        parts = [_string_value(item) for item in node.args[0].elts]
        if separator is not None and all(part is not None for part in parts):
            return separator.join(parts)  # type: ignore[arg-type]
    return None


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _starts(node: ast.Call) -> bool:
    name = _call_name(node)
    return name in STARTERS or name.startswith(("exec", "spawn"))


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _enclosing_function(node: ast.AST, parents: dict[int, ast.AST]) -> str | None:
    current = parents.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parents.get(id(current))
    return None


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
            ):
                ids.add(id(body[0].value))
    return ids


def _assigned_names(node: ast.AST) -> set[str]:
    targets = getattr(node, "targets", None) or [getattr(node, "target", None)]
    return {t.id for t in targets if isinstance(t, ast.Name)}


def _allowed_namings(tree: ast.AST, module: str) -> set[int]:
    """The string nodes that may name the program in ``module`` (see NAMED_IN)."""
    holder = NAMED_IN.get(module)
    allowed: set[int] = set()
    if holder is None:
        return allowed
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and holder in _assigned_names(node)
            and node.value is not None
        ):
            allowed |= {id(n) for n in ast.walk(node.value)}
    return allowed


def _jenkins_launch_violations(source: str, module: str) -> list[str]:
    """Every way ``source`` could start Jenkinsfile Runner other than through
    ``jenkinsfile_runner_argv``, which hashes the core and the plugins first.

    Outside run_jenkinsfile_runner.py:
    * no string, built from constants or not, names the program or its manifest key
      (docstrings aside, and the two holders in NAMED_IN);
    * nothing uses the private function that finds the program, the module's tool
      key constant, or constructs the checked argv type.
    Everywhere:
    * no starter is looked up with getattr;
    * no list or tuple holds a tool_executable result, except jenkinsfile_runner_argv's.
    Inside run_jenkinsfile_runner.py, tool_executable is called only by the private
    finder, the argv that holds the program is built only in jenkinsfile_runner_argv,
    and the only call that starts anything is in run_jenkinsfile_runner, on that
    function's result.
    """
    tree = ast.parse(source)
    parents = _parents(tree)
    docstrings = _docstrings(tree)
    allowed = _allowed_namings(tree, module)
    problems = []
    sanctioned = module == SANCTIONED
    tainted: dict[str | None, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _call_name(node.value) in (FINDER, PRIVATE):
                tainted.setdefault(_enclosing_function(node, parents), set()).update(
                    _assigned_names(node)
                )
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        function = _enclosing_function(node, parents)
        value = _string_value(node)
        if (
            not sanctioned
            and value is not None
            and NAMES_THE_PROGRAM.search(value)
            and id(node) not in docstrings
            and id(node) not in allowed
            and not (
                isinstance(parents.get(id(node)), ast.BinOp)
                and _string_value(parents[id(node)]) is not None
            )
        ):
            problems.append(f"{module}:{line} names the program: {value!r}")
        names = {
            getattr(node, "id", None),
            getattr(node, "attr", None),
            getattr(node, "name", None),
        }
        if isinstance(node, (ast.Name, ast.Attribute, ast.alias)) and not sanctioned:
            for forbidden in (PRIVATE, TOOL_CONSTANT):
                if forbidden in names:
                    problems.append(f"{module}:{line} uses {forbidden}")
            if CHECKED_TYPE in names and module != "env.py":
                problems.append(f"{module}:{line} uses {CHECKED_TYPE}")
        if (
            isinstance(node, ast.Call)
            and _call_name(node) == CHECKED_TYPE
            and not (sanctioned and function == ARGV_FUNCTION)
        ):
            problems.append(f"{module}:{line} makes a {CHECKED_TYPE} of its own")
        if (
            isinstance(node, ast.Call)
            and _call_name(node) == "getattr"
            and len(node.args) >= 2
            and isinstance(_string_value(node.args[1]), str)
            and (
                _string_value(node.args[1]) in STARTERS
                or str(_string_value(node.args[1])).startswith(("exec", "spawn"))
            )
        ):
            problems.append(f"{module}:{line} looks a process starter up by name")
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            holds = any(
                isinstance(n, ast.Call)
                and _call_name(n) in (FINDER, PRIVATE)
                or isinstance(n, ast.Name)
                and n.id in tainted.get(function, set())
                or sanctioned
                and isinstance(n, ast.Name)
                and n.id == "program"
                for n in ast.walk(node)
            )
            if holds and not (sanctioned and function == ARGV_FUNCTION):
                problems.append(
                    f"{module}:{line} builds an argv with a program from the "
                    f"manifest outside {ARGV_FUNCTION}"
                )
        if not sanctioned:
            continue
        if (
            isinstance(node, ast.Call)
            and _call_name(node) == FINDER
            and function != PRIVATE
        ):
            problems.append(f"{module}:{line} calls {FINDER} outside {PRIVATE}")
        if isinstance(node, ast.Call) and _starts(node):
            if function != RUN_FUNCTION:
                problems.append(
                    f"{module}:{line} starts a process outside {RUN_FUNCTION}"
                )
                continue
            arguments = [*node.args, *(k.value for k in node.keywords)]
            argv_names = {
                target.id
                for statement in ast.walk(tree)
                if isinstance(statement, ast.Assign)
                and _enclosing_function(statement, parents) == RUN_FUNCTION
                and isinstance(statement.value, ast.Call)
                and _call_name(statement.value) == ARGV_FUNCTION
                for target in statement.targets
                if isinstance(target, ast.Name)
            }
            from_the_function = any(
                isinstance(a, ast.Call)
                and _call_name(a) == ARGV_FUNCTION
                or isinstance(a, ast.Name)
                and a.id in argv_names
                for a in arguments
            )
            if not from_the_function:
                problems.append(
                    f"{module}:{line} starts a process whose argv is not "
                    f"{ARGV_FUNCTION}'s"
                )
    return problems


def _harness_sources() -> list[tuple[str, str]]:
    files = sorted(CI_RUNNERS.rglob("*.py"))
    if not (CI_RUNNERS / SANCTIONED).is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{SANCTIONED}")
    missing = [p for p in RUNNER_TESTS if not p.is_file()]
    if missing:
        pytest.fail(f"missing {missing[0].relative_to(REPO_ROOT).as_posix()}")
    return [
        (path.name, path.read_text(encoding="utf-8"))
        for path in [*files, *RUNNER_TESTS]
    ]


@pytest.mark.unit
def test_jenkinsfile_runner_is_started_only_through_the_function_that_checks_it():
    problems = [
        problem
        for module, source in _harness_sources()
        for problem in _jenkins_launch_violations(source, module)
    ]
    assert problems == []


#: Ways to start Jenkinsfile Runner without the hash check, each of which the static
#: check must see: (the module the source would sit in, the source's lines).
EVASIONS = {
    "a direct start": (
        "pipelines.py",
        [
            "import subprocess",
            "def go():",
            "    subprocess.run(['jenkinsfile-runner', 'run', '-f', 'Jenkinsfile'])",
        ],
    ),
    "the private finder": (
        "pipelines.py",
        [
            "from .run_jenkinsfile_runner import _jenkinsfile_runner_program",
            "def go(m, b, env):",
            "    launch(env, [str(_jenkinsfile_runner_program(m, b)), 'run'])",
        ],
    ),
    "another function": (
        SANCTIONED,
        [
            "def other(m, b, env):",
            "    program = _jenkinsfile_runner_program(m, b)",
            "    return launch(env, [str(program), 'run'])",
        ],
    ),
    "a bare argv": (
        SANCTIONED,
        [
            "def run_jenkinsfile_runner(env, program):",
            "    return launch(env, [str(program), 'run'])",
        ],
    ),
    "a path of its own": (
        "pipelines.py",
        [
            "def go(bin_dir, env):",
            "    program = bin_dir / 'jenkinsfile-runner' / 'bin' / 'jenkinsfile-runner'",
            "    return launch(env, [str(program), 'run'])",
        ],
    ),
    "the public manifest helper and launch": (
        "pipelines.py",
        [
            "from .manifest import tool_executable",
            "from .env import launch",
            "def go(m, b, env, cwd, log):",
            "    program = tool_executable(m, b, 'tools.jenkinsfile-runner')",
            "    return launch(env, [str(program), 'run', '-f', 'J'], cwd=cwd, log=log)",
        ],
    ),
    "the launcher module's own constant": (
        "pipelines.py",
        [
            "from .run_jenkinsfile_runner import JENKINSFILE_RUNNER_TOOL",
            "from .manifest import tool_executable",
            "from .env import launch",
            "def go(m, b, env, cwd, log):",
            "    p = tool_executable(m, b, JENKINSFILE_RUNNER_TOOL)",
            "    return launch(env, [str(p), 'run'], cwd=cwd, log=log)",
        ],
    ),
    "string concatenation": (
        "pipelines.py",
        [
            "import subprocess",
            "def go(b):",
            "    name = 'jenkinsfile' + '-runner'",
            "    subprocess.run([str(b / name / 'bin' / name), 'run'])",
        ],
    ),
    "a joined name": (
        "pipelines.py",
        [
            "def go(b, env):",
            "    name = '-'.join(['jenkinsfile', 'runner'])",
            "    return launch(env, [str(b / name), 'run'])",
        ],
    ),
    "a name assigned first, then split": (
        "pipelines.py",
        [
            "import subprocess",
            "def go():",
            "    cmd = 'jenkinsfile-runner run -f Jenkinsfile'",
            "    subprocess.run(cmd.split())",
        ],
    ),
    "a starter looked up with getattr": (
        "pipelines.py",
        [
            "import subprocess",
            "def go(argv):",
            "    getattr(subprocess, 'run')(argv)",
        ],
    ),
    "shutil.which, then a list": (
        "pipelines.py",
        [
            "import shutil, subprocess",
            "def go():",
            "    found = shutil.which('jenkinsfile-runner')",
            "    subprocess.run([found, 'run'])",
        ],
    ),
    "os.system on a literal": (
        "pipelines.py",
        [
            "import os",
            "def go():",
            "    os.system('jenkinsfile-runner run -f Jenkinsfile')",
        ],
    ),
    "an argv list built elsewhere": (
        "pipelines.py",
        ["ARGV = ['jenkinsfile-runner', 'run']", "def go(run):", "    run(ARGV)"],
    ),
    "a second function of the launcher using tool_executable": (
        SANCTIONED,
        [
            "def other(m, b, env, cwd, log):",
            "    p = tool_executable(m, b, JENKINSFILE_RUNNER_TOOL)",
            "    argv = [str(p), 'run']",
            "    return argv",
        ],
    ),
    "a checked argv made elsewhere": (
        "pipelines.py",
        [
            "from .env import CheckedArgv, launch",
            "def go(argv, env):",
            "    return launch(env, CheckedArgv(argv))",
        ],
    ),
    "a checked argv made in env.py": (
        "env.py",
        ["def launch(env, argv):", "    return run(CheckedArgv(argv))"],
    ),
    "the installer naming the key outside RUNNER_PINS": (
        "install_tools.py",
        [
            "RUNNER_PINS = {'jenkinsfile-runner-lts': ('tools.jenkinsfile-runner',)}",
            "PROGRAM = 'tools.jenkinsfile-runner'",
        ],
    ),
    "env.py naming the program outside CHECKED_PROGRAMS": (
        "env.py",
        [
            "CHECKED_PROGRAMS = ('jenkinsfile-runner',)",
            "def go(run):",
            "    run(['jenkinsfile-runner', 'run'])",
        ],
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize("evasion", sorted(EVASIONS))
def test_the_check_flags_a_start_that_skips_the_hash_check(evasion):
    module, lines = EVASIONS[evasion]
    assert _jenkins_launch_violations("\n".join(lines) + "\n", module)


@pytest.mark.unit
def test_the_holders_may_name_the_program_where_they_must():
    """T's RUNNER_PINS and env.py's CHECKED_PROGRAMS are the two places outside the
    launcher where a name of the program has a reason to stand."""
    assert not _jenkins_launch_violations(
        "RUNNER_PINS = {'jenkinsfile-runner-lts': ('tools.jenkinsfile-runner', 'x')}\n",
        "install_tools.py",
    )
    assert not _jenkins_launch_violations(
        "CHECKED_PROGRAMS = ('jenkinsfile-runner',)\n", "env.py"
    )
    assert not _jenkins_launch_violations(
        "LOG = 'jenkinsfile-runner-lint.log'\nLEG = 'jenkinsfile-runner-lts'\n",
        "pipelines.py",
    )


@pytest.mark.unit
def test_the_workflow_starts_jenkinsfile_runner_only_through_pytest():
    if not WORKFLOW.is_file():
        return
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    runs = [
        str(step.get("run", ""))
        for job in (document.get("jobs") or {}).values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict)
    ]
    assert not [run for run in runs if NAMES_THE_PROGRAM.search(run)]


@pytest.mark.unit
def test_the_workflow_check_sees_a_run_that_names_the_program():
    run = 'java -version\n"$BIN/jenkinsfile-runner/bin/jenkinsfile-runner" run -f x\n'
    assert NAMES_THE_PROGRAM.search(run)
    assert not NAMES_THE_PROGRAM.search('if [ "$LEG" = jenkinsfile-runner-lts ]; then')


# The init hook ------------------------------------------------------------------


@pytest.mark.unit
def test_the_init_hook_labels_the_built_in_node_linux():
    hooks = sorted((CI_RUNNERS / "jenkins" / "init.groovy.d").glob("*.groovy"))
    assert hooks, (
        "no init hook in tests/integration/docs/ci_runners/jenkins/init.groovy.d"
    )
    code = [re.sub(r"//.*", "", hook.read_text(encoding="utf-8")) for hook in hooks]
    assert any(
        re.search(r"Jenkins\.get\(\)\s*\.\s*setLabelString\(\s*['\"]linux['\"]\s*\)", c)
        for c in code
    ), "an init hook must call Jenkins.get().setLabelString('linux')"


# ---------------------------------------------------------------------------
# CircleCI
# ---------------------------------------------------------------------------

SWITCHES = {
    "local-execute": {
        "CIRCLECI_CLI_TELEMETRY_OPTOUT": "1",
        "CIRCLECI_CLI_SKIP_UPDATE_CHECK": "true",
    },
    "config": {
        "CIRCLE_NO_TELEMETRY": "1",
        "DO_NOT_TRACK": "1",
        "CIRCLE_NO_UPDATE_CHECK": "1",
    },
}


@pytest.mark.unit
@pytest.mark.parametrize("cli", sorted(SWITCHES))
def test_each_circleci_cli_gets_exactly_its_switches_and_never_ci(tmp_path, cli):
    launch_env = _api("env", "launch_env")
    circleci_env = _api("run_circleci", "circleci_launch_env")
    base = launch_env(
        "circleci",
        home=_home(tmp_path, "base-home"),
        runner_bin=tmp_path / "bin",
        tool_cache=tmp_path / "tool-cache",
        outer=OUTER,
    )
    env = circleci_env(
        cli,
        home=_home(tmp_path),
        runner_bin=tmp_path / "bin",
        tool_cache=tmp_path / "tool-cache",
        outer=OUTER,
    )
    added = {k: v for k, v in env.items() if k not in base}
    assert added == SWITCHES[cli]
    assert {k: v for k, v in env.items() if k in base and k != "HOME"} == {
        k: v for k, v in base.items() if k != "HOME"
    }
    assert "CI" not in env


@pytest.mark.unit
def test_an_unknown_circleci_cli_is_refused(tmp_path):
    with pytest.raises(ValueError):
        _api("run_circleci", "circleci_launch_env")(
            "build",
            home=_home(tmp_path),
            runner_bin=tmp_path / "bin",
            tool_cache=tmp_path / "tool-cache",
            outer=OUTER,
        )


@pytest.mark.unit
@pytest.mark.parametrize("command", ["validate", "process"])
def test_circleci_config_commands_skip_the_update_check(tmp_path, command):
    argv = _api("run_circleci", "circleci_config_argv")(
        program=tmp_path / "circleci",
        command=command,
        config_path=".circleci/config.yml",
    )
    assert argv[:3] == [str(tmp_path / "circleci"), "config", command]
    assert "--skip-update-check" in argv and argv[-1] == ".circleci/config.yml"


@pytest.mark.unit
def test_local_execute_mounts_the_wheel_and_the_reports_and_pins_the_build_agent(
    tmp_path,
):
    argv = _api("run_circleci", "circleci_local_execute_argv")(
        MANIFEST,
        program=tmp_path / "circleci",
        job="ash",
        wheel_dir=tmp_path / "wheel",
        report_dir=tmp_path / "reports",
    )
    assert argv[:4] == [str(tmp_path / "circleci"), "local", "execute", "ash"]
    # The pinned build agent rejects the forwarded flag; the update check is off by
    # CIRCLECI_CLI_SKIP_UPDATE_CHECK.
    assert "--skip-update-check" not in argv
    switches = _api("run_circleci", "SWITCHES")
    assert switches["local-execute"]["CIRCLECI_CLI_SKIP_UPDATE_CHECK"] == "true"
    assert sorted(_value(argv, "-v")) == sorted(
        [f"{tmp_path / 'wheel'}:/ash-wheel", f"{tmp_path / 'reports'}:/ash-reports"]
    )
    assert _value(argv, "--build-agent-version") == ["sha256:" + "3" * 64]
    assert _value(argv, "-c") == [".circleci/config.yml"]


# ---------------------------------------------------------------------------
# The CodeBuild agent
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_codebuild_agent_runs_under_script_with_the_pinned_images(tmp_path):
    out = tmp_path / "out"
    script = tmp_path / "bin" / "codebuild_build.sh"
    argv = _api("run_codebuild_agent", "codebuild_argv")(
        MANIFEST, script=script, source=tmp_path / "project", out_dir=out
    )
    assert argv[:4] == ["script", "-q", "-e", "-c"] and argv[5:] == ["/dev/null"]
    inner = shlex.split(argv[4])
    assert inner[0] == str(script)
    for flag in ("-c", "-d", "-p", "-m", "-e"):
        assert flag not in inner, f"codebuild_build.sh is never given {flag}"
    assert _value(inner, "-i") == [BUILD_IMAGE]
    assert _value(inner, "-l") == [AGENT_IMAGE]
    assert _value(inner, "-s") == [str(tmp_path / "project")]
    for flag in ("-a", "-r"):
        (value,) = _value(inner, flag)
        assert Path(value).is_relative_to(out), (flag, value)
    assert _value(inner, "-a") != _value(inner, "-r")
    assert inner == [
        str(script),
        "-i",
        BUILD_IMAGE,
        "-a",
        str(out / "codebuild-artifacts"),
        "-r",
        str(out / "codebuild-reports"),
        "-s",
        str(tmp_path / "project"),
        "-l",
        AGENT_IMAGE,
    ]


@pytest.mark.unit
@pytest.mark.parametrize("character", [" ", "'", '"', "$", "`", "\\", ";", "\n"])
@pytest.mark.parametrize("where", ["script", "source", "out_dir"])
def test_the_codebuild_agent_is_given_only_paths_its_script_cannot_misread(
    tmp_path, character, where
):
    """codebuild_build.sh builds its docker command line as a string and runs it with
    eval, so a quote, a dollar sign, a backtick or a blank in a path would be read
    again inside the script. Paths are refused unless they hold only letters, digits
    and ``._/-``."""
    paths = {
        "script": tmp_path / "bin" / "codebuild_build.sh",
        "source": tmp_path / "project",
        "out_dir": tmp_path / "out",
    }
    paths[where] = tmp_path / f"a{character}b" / paths[where].name
    with pytest.raises(ValueError, match=where):
        _api("run_codebuild_agent", "codebuild_argv")(MANIFEST, **paths)


@pytest.mark.unit
def test_the_codebuild_agent_is_given_only_digest_references(tmp_path):
    manifest = {
        **MANIFEST,
        "images": {
            **MANIFEST["images"],
            "codebuild-standard-5": {"ref": "x@sha256:" + "1" * 64 + "; touch y"},
        },
    }
    with pytest.raises(ValueError):
        _api("run_codebuild_agent", "codebuild_argv")(
            manifest,
            script=tmp_path / "s.sh",
            source=tmp_path / "p",
            out_dir=tmp_path / "o",
        )


# ---------------------------------------------------------------------------
# act
# ---------------------------------------------------------------------------

WRITERS = {
    "github/codeql-action": ("codeql-action", "upload-sarif"),
    "mshick/add-pr-comment": ("add-pr-comment", ""),
    "mikepenz/action-junit-report": ("action-junit-report", ""),
}
SHA = "0123456789abcdef0123456789abcdef01234567"


def _act_argv(tmp_path: Path, writer_refs=()) -> list[str]:
    return _api("run_act", "act_argv")(
        program=tmp_path / "bin" / "act",
        event_name="pull_request",
        workflow=tmp_path / "project" / ".github" / "workflows" / "ash.yml",
        event_path=tmp_path / "out" / "event.json",
        project=tmp_path / "project",
        artifact_dir=tmp_path / "out" / "artifacts",
        cache_dir=tmp_path / "work" / "cache",
        stub_records=tmp_path / "out" / "stubs",
        writer_refs=list(writer_refs),
        repository="awslabs/automated-security-helper",
    )


@pytest.mark.unit
def test_act_runs_jobs_on_the_host_one_at_a_time_with_json_logs(tmp_path):
    argv = _act_argv(tmp_path)
    assert argv[0] == str(tmp_path / "bin" / "act") and argv[1] == "pull_request"
    assert _value(argv, "-P") == ["ubuntu-latest=-self-hosted"]
    assert _value(argv, "--concurrent-jobs") == ["1"]
    assert "--json" in argv
    assert _value(argv, "--container-daemon-socket") == ["-"]
    assert _value(argv, "-W") == [
        str(tmp_path / "project" / ".github" / "workflows" / "ash.yml")
    ]
    assert _value(argv, "-e") == [str(tmp_path / "out" / "event.json")]
    assert _value(argv, "--artifact-server-path") == [
        str(tmp_path / "out" / "artifacts")
    ]
    for word in argv:
        assert word not in ("-v", "--verbose", "-s", "--secret", "--secret-file")
        assert "TOKEN" not in word.upper(), word
    assert f"DOCTEST_STUB_RECORDS={tmp_path / 'out' / 'stubs'}" in _value(argv, "--env")


@pytest.mark.unit
def test_every_writer_action_is_replaced_with_its_stub(tmp_path):
    texts = [
        "jobs:\n  a:\n    steps:\n"
        f"      - uses: actions/checkout@{SHA} # v7\n"
        f"      - uses: github/codeql-action/upload-sarif@{SHA} # v4\n"
        "      - uses: mshick/add-pr-comment@" + "a" * 40 + "\n",
        "jobs:\n  b:\n    steps:\n"
        "      - uses: 'mikepenz/action-junit-report@" + "b" * 40 + "'\n"
        f"      - uses: github/codeql-action/upload-sarif@{SHA}\n",
    ]
    refs = _api("run_act", "writer_action_refs")(texts)
    assert refs == sorted(
        [
            f"github/codeql-action@{SHA}",
            "mshick/add-pr-comment@" + "a" * 40,
            "mikepenz/action-junit-report@" + "b" * 40,
        ]
    )
    stubs = _api("run_act", "STUBS_DIR")
    assert Path(stubs) == CI_RUNNERS / "stubs"
    mapped = dict(
        value.split("=", 1)
        for value in _value(_act_argv(tmp_path, refs), "--local-repository")
    )
    assert set(mapped) == set(refs)
    for ref, directory in mapped.items():
        stub, subpath = WRITERS[ref.split("@")[0]]
        assert Path(directory) == stubs / stub
        assert (Path(directory) / subpath / "action.yml").is_file(), ref


@pytest.mark.unit
def test_the_stubs_cover_every_writer_action_the_fixture_workflows_use():
    texts = [
        (REPO_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        for name in ("run-ash-security-scan.yml", "upload-ash-sarif.yml")
    ]
    pages = (
        "docs/content/how-to/ci/github-actions.md",
        "docs/content/how-to/scale-large-repos.md",
    )
    texts += [(REPO_ROOT / page).read_text(encoding="utf-8") for page in pages]
    refs = _api("run_act", "writer_action_refs")(texts)
    found = {
        match.group(1)
        for text in texts
        for match in re.finditer(r"uses:\s*['\"]?([\w.-]+/[\w.-]+)[/@]", text)
    }
    assert {ref.split("@")[0] for ref in refs} == found & set(WRITERS)
    assert refs, "the fixture workflows use writer actions"


@pytest.mark.unit
def test_the_act_event_names_the_head_and_the_base_of_the_pull_request():
    event = _api("run_act", "act_event")(
        "pull_request",
        head_sha=SHA,
        base_sha="f" * 40,
        branch="docs-example",
        repository="awslabs/automated-security-helper",
    )
    pull = event["pull_request"]
    assert pull["head"]["sha"] == SHA and pull["head"]["ref"] == "docs-example"
    assert pull["base"]["sha"] == "f" * 40 and pull["base"]["ref"] == "main"
    assert pull["head"]["repo"]["full_name"] == "awslabs/automated-security-helper"
    assert event["repository"]["full_name"] == "awslabs/automated-security-helper"
    assert "act" not in event, "the pages' workflows must run, so no act marker"
    push = _api("run_act", "act_event")(
        "push", head_sha=SHA, base_sha=SHA, branch="main", repository="o/r"
    )
    assert push["ref"] == "refs/heads/main" and push["after"] == SHA
    with pytest.raises(ValueError):
        _api("run_act", "act_event")(
            "merge_group", head_sha=SHA, base_sha=SHA, branch="x", repository="o/r"
        )


@pytest.mark.unit
def test_local_uses_reads_uses_keys_and_not_comments_or_prose():
    local_uses = _api("run_act", "local_uses")
    comment = "      # (`uses: ./.github/workflows/...`) has that repository as\n"
    assert local_uses(comment) == [], "a comment that quotes uses: names no file"
    text = (
        comment
        + "#        uses: ./.github/workflows/commented-out.yml\n"
        + "jobs:\n"
        + "  scan:\n"
        + "    uses: ./.github/workflows/scan.yml # uses: ./.github/workflows/after.yml\n"
        + "  other:\n"
        + "    steps:\n"
        + "      - uses: ./.github/actions/run-scan-test\n"
        + '      - uses: "./.github/actions/quoted"\n'
        + f"      - uses: actions/checkout@{SHA}\n"
        + "      - run: echo uses: ./.github/actions/in-a-command\n"
    )
    assert local_uses(text) == [
        "./.github/workflows/scan.yml",
        "./.github/actions/run-scan-test",
        "./.github/actions/quoted",
    ]


@pytest.mark.unit
@pytest.mark.parametrize("name", ["run-ash-security-scan.yml", "upload-ash-sarif.yml"])
def test_every_local_uses_of_a_fixture_workflow_names_a_file_in_the_repository(name):
    text = (REPO_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    for uses in _api("run_act", "local_uses")(text):
        assert (REPO_ROOT / uses).exists(), f"{name}: uses: {uses} names nothing"


# ---------------------------------------------------------------------------
# gitlab-ci-local
# ---------------------------------------------------------------------------


def _gitlab_argv(tmp_path: Path, event, **extra):
    return _api("run_gitlab_ci_local", "gitlab_ci_local_argv")(
        program=tmp_path / "bin" / "gitlab-ci-local",
        project=tmp_path / "project",
        wheel_dir=tmp_path / "wheel",
        event=event,
        base_sha="f" * 40,
        **extra,
    )


@pytest.mark.unit
def test_gitlab_ci_local_gets_a_relative_cwd(tmp_path):
    """gitlab-ci-local 4.76.1 refuses an absolute --cwd, so the option is the project
    relative to the directory the launch runs it in."""
    here = _gitlab_argv(tmp_path, None, cwd=tmp_path / "project")
    assert _value(here, "--cwd") == ["."]
    assert _value(_gitlab_argv(tmp_path, None), "--cwd") == ["."]
    above = _gitlab_argv(tmp_path, None, cwd=tmp_path)
    assert _value(above, "--cwd") == ["project"]
    for argv in (here, above):
        assert not Path(_value(argv, "--cwd")[0]).is_absolute()


@pytest.mark.unit
@pytest.mark.parametrize("event", [None, "push", "merge_request"])
def test_gitlab_ci_local_uses_the_built_helper_and_the_wheel_mount(tmp_path, event):
    argv = _gitlab_argv(tmp_path, event)
    assert argv[0] == str(tmp_path / "bin" / "gitlab-ci-local")
    assert _value(argv, "--cwd") == ["."]
    assert _value(argv, "--helper-image") == ["doctest-gitlab-helper:local"]
    assert _value(argv, "--pull-policy") == ["if-not-present"]
    assert _value(argv, "--volume") == [f"{tmp_path / 'wheel'}:/ash-wheel:ro"]
    variables = _value(argv, "--variable")
    if event == "merge_request":
        assert sorted(variables) == [
            "CI_MERGE_REQUEST_DIFF_BASE_SHA=" + "f" * 40,
            "CI_PIPELINE_SOURCE=merge_request_event",
        ]
    else:
        assert variables == []


@pytest.mark.unit
def test_gitlab_ci_local_refuses_an_event_gitlab_has_not(tmp_path):
    with pytest.raises(ValueError):
        _gitlab_argv(tmp_path, "pull_request")


@pytest.mark.unit
def test_the_helper_image_is_built_from_the_pinned_debian_digest():
    dockerfile = CI_RUNNERS / "gitlab-helper" / "Dockerfile"
    assert dockerfile.is_file(), "missing gitlab-helper/Dockerfile"
    froms = [
        line.split()[1]
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if line.upper().startswith("FROM ")
    ]
    manifest = _api("manifest", "load_manifest")()
    assert froms == [manifest["images"]["debian-bookworm-slim"]["ref"]]
    argv = _api("run_gitlab_ci_local", "helper_image_build_argv")()
    assert argv[:2] == ["docker", "build"]
    assert _value(argv, "-t") == ["doctest-gitlab-helper:local"]
    assert _value(argv, "-f") == [str(dockerfile)]
    assert argv[-1] == str(dockerfile.parent)


# ---------------------------------------------------------------------------
# Every launcher starts its runner with env -i
# ---------------------------------------------------------------------------


def _launch_cases(tmp_path: Path, **extra):
    common = {
        "cwd": tmp_path,
        "tool_cache": tmp_path / "tool-cache",
        "outer": OUTER,
        "log": tmp_path / "logs" / "runner.log",
        **extra,
    }
    argv = [str(tmp_path / "bin" / "tool"), "go"]
    return {
        "act": lambda fake: _api("run_act", "run_act")(
            argv, runner_bin=tmp_path / "bin", home=_home(tmp_path), run=fake, **common
        ),
        "gitlab-ci-local": lambda fake: _api(
            "run_gitlab_ci_local", "run_gitlab_ci_local"
        )(argv, runner_bin=tmp_path / "bin", home=_home(tmp_path), run=fake, **common),
        "docker build": lambda fake: _api("run_gitlab_ci_local", "build_image")(
            ["docker", "build", "."],
            runner_bin=tmp_path / "bin",
            home=_home(tmp_path),
            run=fake,
            **common,
        ),
        "codebuild-agent": lambda fake: _api(
            "run_codebuild_agent", "run_codebuild_agent"
        )(
            ["script", "-q", "-e", "-c", "x", "/dev/null"],
            runner_bin=tmp_path / "bin",
            home=_home(tmp_path),
            run=fake,
            **common,
        ),
        "circleci config": lambda fake: _api("run_circleci", "run_circleci")(
            "config",
            argv,
            runner_bin=tmp_path / "bin",
            home=_home(tmp_path),
            run=fake,
            **common,
        ),
        "circleci local execute": lambda fake: _api("run_circleci", "run_circleci")(
            "local-execute",
            argv,
            runner_bin=tmp_path / "bin",
            home=_home(tmp_path),
            run=fake,
            **common,
        ),
    }


LAUNCHERS = (
    "act",
    "gitlab-ci-local",
    "docker build",
    "codebuild-agent",
    "circleci config",
    "circleci local execute",
)


@pytest.mark.unit
@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_each_launcher_starts_its_runner_with_env_i(tmp_path, launcher):
    fake = FakeRun(returncode=2)
    assert _launch_cases(tmp_path)[launcher](fake) == 2
    env, command = _launched(fake)
    assert env["PATH"].split(os.pathsep)[0] == str(tmp_path / "bin")
    assert env["HOME"] == str(tmp_path / "home")
    assert "GITHUB_TOKEN" not in env and "CI" not in env
    assert command[-1] in ("go", ".", "/dev/null")
    _, kwargs = fake.calls[0]
    assert kwargs.get("cwd") == tmp_path
    assert kwargs.get("stdin") == subprocess.DEVNULL
    assert kwargs.get("stdout") not in (None, sys.stdout), "output goes to the log"
    assert kwargs.get("env") == {"PATH": _api("env", "SYSTEM_PATH")}, (
        "env itself is found on the system PATH, never on the test process's own"
    )
    assert kwargs.get("timeout") is None
    assert (tmp_path / "logs" / "runner.log").is_file()


@pytest.mark.unit
@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_each_launcher_passes_its_time_limit_on(tmp_path, launcher):
    fake = FakeRun(returncode=0)
    _launch_cases(tmp_path, timeout=37)[launcher](fake)
    assert fake.calls[0][1].get("timeout") == 37


@pytest.mark.unit
@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_each_launcher_runs_its_runner_in_a_new_session_and_sweeps_containers(
    tmp_path, launcher
):
    """Every launch's runner leads a session of its own, so the whole process group
    can be stopped, and its containers are removed when it ends."""
    fake = FakeRun(returncode=0)
    _launch_cases(tmp_path)[launcher](fake)
    env, _ = _launched(fake)
    _, kwargs = fake.calls[0]
    assert kwargs.get("start_new_session") is True
    sweep = kwargs.get("containers")
    assert isinstance(sweep, _api("env", "ContainerSweep")), sweep
    assert dict(sweep.env) == env, "docker is run with the launch's own environment"


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_jenkinsfile_runner_runs_in_a_new_session_and_sweeps_containers(tmp_path, leg):
    install = _jenkins_install(tmp_path, leg)
    fake = FakeRun(returncode=0)
    _run_jenkins(install, leg, fake, tmp_path)
    _, kwargs = fake.calls[0]
    assert kwargs.get("start_new_session") is True
    assert isinstance(kwargs.get("containers"), _api("env", "ContainerSweep"))


LAUNCHER_FUNCTIONS = (
    ("run_act", "run_act"),
    ("run_gitlab_ci_local", "run_gitlab_ci_local"),
    ("run_gitlab_ci_local", "build_image"),
    ("run_codebuild_agent", "run_codebuild_agent"),
    ("run_circleci", "run_circleci"),
    ("run_jenkinsfile_runner", "run_jenkinsfile_runner"),
)


@pytest.mark.unit
@pytest.mark.parametrize("stem,name", LAUNCHER_FUNCTIONS)
def test_each_launcher_defaults_to_the_runner_that_stops_the_group(stem, name):
    """subprocess.run on a timeout stops only the process it started, env, which
    has exec'd into the runner; the runner's children would go on."""
    default = inspect.signature(_api(stem, name)).parameters["run"].default
    assert default is _api("env", "run_in_new_session"), (stem, name, default)


@pytest.mark.unit
def test_a_launch_that_runs_out_of_time_fails_naming_its_log(tmp_path):
    def expires(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    log = tmp_path / "logs" / "slow.log"
    with pytest.raises(_api("env", "LaunchTimedOut")) as raised:
        _api("env", "launch")(
            {"PATH": "/usr/bin:/bin"},
            ["/b/slow", "go"],
            cwd=tmp_path,
            log=log,
            run=expires,
            timeout=5,
        )
    assert issubclass(_api("env", "LaunchTimedOut"), RuntimeError)
    assert str(log) in str(raised.value) and "5" in str(raised.value)
    assert "5" in log.read_text(encoding="utf-8").splitlines()[-1], (
        "the log says the launch ran out of time"
    )


@pytest.mark.unit
def test_the_system_path_has_the_runner_image_s_tool_directories():
    """act runs JavaScript actions with node from /usr/local/bin; git, docker, python3
    and util-linux's script are in /usr/bin."""
    entries = _api("env", "SYSTEM_PATH").split(os.pathsep)
    assert "/usr/local/bin" in entries and "/usr/bin" in entries
    assert entries.index("/usr/local/bin") < entries.index("/usr/bin")


@pytest.mark.integration
def test_the_runner_s_output_goes_to_its_log(tmp_path):
    """A real child, the system ``env``: what it prints lands in the log, nothing else."""
    if not sys.platform.startswith("linux"):
        pytest.skip(
            "the runners run on Linux, and a launch makes the test process a child "
            "subreaper, which only Linux has"
        )
    launch = _api("env", "launch")
    log = tmp_path / "logs" / "printf.log"
    code = launch(
        {"PATH": "/usr/bin:/bin"},
        ["printf", "ran\\n"],
        cwd=tmp_path,
        log=log,
    )
    assert code == 0 and log.read_text(encoding="utf-8") == "ran\n"


# ---------------------------------------------------------------------------
# The launchers name only their leg's pins
# ---------------------------------------------------------------------------

LAUNCHER_LEGS = {
    "run_act": ("act",),
    "run_gitlab_ci_local": ("gitlab-ci-local",),
    "run_codebuild_agent": ("codebuild-agent",),
    "run_circleci": ("circleci",),
}


@pytest.mark.unit
@pytest.mark.parametrize("stem", sorted(LAUNCHER_LEGS))
def test_each_launcher_names_only_pins_its_leg_installs(stem):
    keys = _api(stem, "MANIFEST_KEYS")
    pins = _install_tools().RUNNER_PINS
    manifest = _api("manifest", "load_manifest")()
    for leg in LAUNCHER_LEGS[stem]:
        assert set(keys) <= set(pins[leg]), (stem, sorted(set(keys) - set(pins[leg])))
    for key in keys:
        section, name = key.split(".", 1)
        assert name in manifest[section], key


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_the_jenkins_launcher_names_only_pins_its_leg_installs(leg):
    keys = _api("run_jenkinsfile_runner", "MANIFEST_KEYS")[leg]
    assert set(keys) <= set(_install_tools().RUNNER_PINS[leg])


def _install_tools():
    name = "_ash_ci_runners_install_tools"
    if name not in sys.modules:
        path = CI_RUNNERS / "install_tools.py"
        if not path.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/install_tools.py")
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.mark.unit
def test_the_wheel_is_mounted_where_the_rewrite_installs_it_from():
    mount = _api("rewrite", "WHEEL_MOUNT")
    assert _api("run_gitlab_ci_local", "WHEEL_MOUNT") == mount
    assert _api("run_circleci", "WHEEL_MOUNT") == mount


# ---------------------------------------------------------------------------
# --ci-runner and --ci-runner-page select one leg's blocks of one page
# ---------------------------------------------------------------------------


def _collect(path: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            # The repository's addopts stay on. These override what a nested
            # collection must not do: start workers, write coverage data, or write
            # the junit file the outer run writes. -qq offsets addopts' --verbose,
            # so each node prints as one line.
            "-n",
            "0",
            "--no-cov",
            f"--junit-xml={os.devnull}",
            "-p",
            "no:cacheprovider",
            "--collect-only",
            "-qq",
            str(path),
            "--run-integration",
            "--run-ci-runners",
            *flags,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=_not_a_hosted_runner(),
    )


#: What makes a host a GitHub-hosted runner, or lets the runs go anywhere.
HOST_VARIABLES = (
    "GITHUB_ACTIONS",
    "RUNNER_ENVIRONMENT",
    "ACT",
    "DOCTEST_CI_RUNNERS_ANYWHERE",
)


def _not_a_hosted_runner() -> dict[str, str]:
    """This environment, as a host the runs refuse: collection must still work, so a
    host check at import would fail these tests even on a hosted unit run."""
    return {k: v for k, v in os.environ.items() if k not in HOST_VARIABLES}


@pytest.mark.integration
def test_the_leg_and_page_options_deselect_every_other_block():
    census = _api("census", "census_runs")()
    by_leg: dict[tuple[str, str], int] = {}
    for run in census:
        by_leg[(run.runner, run.page)] = by_leg.get((run.runner, run.page), 0) + 1
    assert by_leg, "the census has no blocks with a runner"
    (runner, page), count = min(by_leg.items())
    selected = _collect(
        RUNNER_TESTS[0], "--ci-runner", runner, "--ci-runner-page", page
    )
    assert selected.returncode == 0, selected.stdout[-2000:] + selected.stderr[-2000:]
    ids = [line for line in selected.stdout.splitlines() if "::" in line]
    assert len(ids) == count, ids
    assert all(runner in line and page in line for line in ids), ids
    others = len(census) - count
    if others:
        assert f"{others} deselected" in selected.stdout, selected.stdout[-2000:]


@pytest.mark.integration
def test_an_unknown_leg_is_a_usage_error():
    result = _collect(RUNNER_TESTS[0], "--ci-runner", "travis")
    assert result.returncode not in (0, 5), result.stdout[-1000:]
