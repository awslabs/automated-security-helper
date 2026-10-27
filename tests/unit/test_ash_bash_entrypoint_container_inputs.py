"""What the bash entrypoint ``./ash`` hands to the OCI runner.

The same three properties tests/unit/interactions/test_container_build_and_mount_inputs.py
holds the Python runner to, for the shell wrapper:

- the source directory is mounted at ``/src`` read-only, wherever the output
  directory is, including the default ``.ash/ash_output`` inside it;
- the image is built from the Dockerfile beside the script, with that directory as
  the build context, never from the scanned project in the working directory;
- the build target is the one requested, ``non-root`` without a request, whatever
  CI variables are set.

The real script runs against a fake OCI runner that records each invocation, so
the assertions are on the command lines the wrapper assembled, and with an ``id``
that reports an unprivileged user unless a test names other IDs
(tests/utils/host_ids.py).
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from tests.utils.config_link_layouts import (
    LINKS_IN_ANOTHER_CHECKOUT,
    LINKS_IN_THE_SCANNED_CHECKOUT,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
    config_through_a_link_in,
    config_through_links,
)
from tests.utils.helpers import mark_git_checkout
from tests.utils.host_ids import UNPRIVILEGED_GID, UNPRIVILEGED_UID, with_fixed_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
    # The same three guards as test_ash_bash_entrypoint_build_failure.py. Each one
    # states its own reason, so a skipped run says why in the report.
    pytest.mark.skipif(
        os.name == "nt",
        reason=(
            "Windows: bash on a Windows runner is the WSL launcher stub, not a POSIX "
            "shell, and Windows users run ASH through utils/ash_helpers.ps1 instead "
            "of ./ash"
        ),
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None,
        reason="no bash on PATH: ./ash is a bash script and cannot run without it",
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason=(
            "./ash is not in this tree: an installed-package layout ships the Python "
            "CLI only, so there is no wrapper to run"
        ),
    ),
]

# Writes each invocation's arguments, NUL-separated, to the next numbered file in
# $FAKE_RUNNER_LOG_DIR, and succeeds. The wrapper calls the runner sequentially.
FAKE_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
exit 0
"""

#: Environment that would change the wrapper's commands if the suite itself runs in
#: a CI job that exported it.
_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
)


@pytest.fixture
def fake_runner(tmp_path):
    runner = tmp_path / "bin" / "fake-oci-runner"
    runner.parent.mkdir()
    runner.write_text(FAKE_RUNNER)
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return runner, log_dir


@pytest.fixture
def project(tmp_path):
    """A scanned project that carries its own Dockerfile and pyproject.toml."""
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch AS non-root\nFROM scratch AS ci\n")
    (root / "pyproject.toml").write_text("[project]\nname = 'scanned'\n")
    return root


def _run_ash_status(
    fake_runner,
    cwd: Path,
    args: List[str],
    extra_env: Optional[Dict[str, str]] = None,
    host_ids: Tuple[str, str] = (UNPRIVILEGED_UID, UNPRIVILEGED_GID),
):
    """Run ./ash against the fake runner: (returncode, stdout and stderr, calls).

    ``id`` reports *host_ids* (UID, GID), an unprivileged user unless a test names
    others, whatever user the suite itself runs as.
    """
    runner, log_dir = fake_runner
    env = with_fixed_ids(
        {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV},
        log_dir.parent / "fixed-id-bin",
        *host_ids,
    )
    env.update(
        {"OCI_RUNNER": str(runner), "FAKE_RUNNER_LOG_DIR": str(log_dir)},
    )
    env.update(extra_env or {})
    result = subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        ["bash", str(ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
        timeout=180,
        check=False,
    )
    calls = []
    for record in sorted(log_dir.iterdir()):
        calls.append(record.read_bytes().decode().split("\0")[:-1])
    return result.returncode, result.stdout + result.stderr, calls


def run_ash(
    fake_runner, cwd: Path, args: List[str], extra_env: Optional[Dict[str, str]] = None
) -> List[List[str]]:
    returncode, output, calls = _run_ash_status(fake_runner, cwd, args, extra_env)
    assert returncode == 0, output
    return calls


def _only(calls: List[List[str]], subcommand: str) -> List[str]:
    matching = [call for call in calls if call and call[0] == subcommand]
    assert len(matching) == 1, f"expected one `{subcommand}` call, got {calls}"
    return matching[0]


def _flag(call: List[str], flag: str) -> str:
    values = [call[i + 1] for i, arg in enumerate(call[:-1]) if arg == flag]
    assert len(values) == 1, f"expected one {flag} in {call}"
    return values[0]


def _mount(call: List[str], destination: str) -> Dict[str, Optional[str]]:
    found = []
    for i, arg in enumerate(call[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, Optional[str]] = {}
        for part in call[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else None
        if options.get("destination") == destination:
            found.append(options)
    assert len(found) == 1, f"expected one mount at {destination} in {call}"
    return found[0]


class TestTheSourceIsMountedReadOnly:
    @pytest.mark.parametrize(
        "layout",
        ["default-output", "output-inside-source", "sibling-sharing-the-prefix"],
    )
    def test_the_source_mount_is_read_only(
        self, layout, fake_runner, project, tmp_path
    ):
        if layout == "default-output":
            # No flags: the source is the working directory and the output is
            # .ash/ash_output inside it.
            args: List[str] = ["--no-build"]
        elif layout == "output-inside-source":
            args = [
                "--no-build",
                "--source-dir",
                str(project),
                "--output-dir",
                str(project / "reports"),
            ]
        else:
            args = [
                "--no-build",
                "--source-dir",
                str(project),
                "--output-dir",
                str(tmp_path / "project-out"),
            ]

        calls = run_ash(fake_runner, project, args)

        src = _mount(_only(calls, "run"), "/src")
        assert Path(str(src["source"])).resolve() == project.resolve()
        assert "readonly" in src, f"/src is writable: {src}"

    def test_the_source_mount_is_read_only_with_output_outside(
        self, fake_runner, project, tmp_path
    ):
        """Control: an output directory outside the source already gets a read-only /src."""
        output = tmp_path / "elsewhere" / "out"
        calls = run_ash(
            fake_runner,
            project,
            ["--no-build", "--source-dir", str(project), "--output-dir", str(output)],
        )

        run = _only(calls, "run")
        assert "readonly" in _mount(run, "/src")
        out = _mount(run, "/out")
        assert Path(str(out["source"])).resolve() == output.resolve()
        assert "readonly" not in out


class TestTheImageIsBuiltFromTheScriptsDockerfile:
    def test_a_project_dockerfile_in_the_cwd_is_not_built(self, fake_runner, project):
        """Control: the wrapper already builds the Dockerfile beside itself."""
        calls = run_ash(fake_runner, project, ["--no-run"])

        build = _only(calls, "build")
        assert Path(_flag(build, "--file")).resolve() == (REPO_ROOT / "Dockerfile")
        assert Path(build[-1]).resolve() == REPO_ROOT


class TestTheBuildTargetIsTheOneRequested:
    @pytest.mark.parametrize(
        ("name", "value"),
        [("CI", "true"), ("CI", "false"), ("CODEBUILD_BUILD_ID", "project:build-1")],
    )
    def test_ci_variables_do_not_change_the_target(
        self, name, value, fake_runner, project
    ):
        """Control: the wrapper already builds non-root unless asked otherwise."""
        calls = run_ash(fake_runner, project, ["--no-run"], {name: value})

        assert _flag(_only(calls, "build"), "--target") == "non-root"

    def test_an_explicit_ci_target_is_built(self, fake_runner, project):
        """Control."""
        calls = run_ash(fake_runner, project, ["--no-run", "--build-target", "ci"])

        assert _flag(_only(calls, "build"), "--target") == "ci"


def _inner_args(call: List[str]) -> List[str]:
    """The arguments the wrapper hands the ``ash`` inside the image."""
    return call[call.index("ash") + 1 :]


#: The three marks a mounted config can carry. The first two say the scanned
#: repository wrote it; the third says it is in a git checkout other than the
#: scanned one (run_ash_container.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG).
SCANNED_CHAIN_FLAG = "--config-from-scanned-repository"
SCANNED_FILE_FLAG = "--config-file-from-scanned-repository"
ELSEWHERE_FLAG = "--config-file-from-another-checkout"


def _flag_values(args: List[str], flag: str) -> List[str]:
    """Every value *flag* is given in *args*, in order."""
    return [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == flag]


class TestTheConfigIsReadableInsideTheContainer:
    """``--config`` (or ``ASH_CONFIG``) names a host file; the container sees it
    only through a mount, so the scan inside is given the path the file has
    there."""

    def test_a_config_inside_the_source_is_read_through_the_source_mount(
        self, fake_runner, project
    ):
        (project / ".ash").mkdir()
        (project / ".ash" / "strict.yaml").write_text("project_name: p\n")

        rc, err, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", ".ash/strict.yaml"]
        )

        assert rc == 0, err
        run = _only(calls, "run")
        assert _flag(_inner_args(run), "--config") == "/src/.ash/strict.yaml"
        assert run.count("--mount") == 2

    @pytest.mark.parametrize(
        "how", ["--config <path>", "--config=<path>", "ASH_CONFIG"]
    )
    def test_a_config_outside_the_source_is_mounted_read_only(
        self, how, fake_runner, project, tmp_path
    ):
        config = tmp_path / "operator" / "ash.yaml"
        config.parent.mkdir()
        config.write_text("project_name: p\n")
        # --config is mounted under /ash-config; the ASH_CONFIG file under its own
        # root, /ash-env-config, and named to the scan as its --config as well when
        # no --config is given, as ash --mode container mounts and names them.
        expected = "/ash-config/ash.yaml"
        if how == "--config <path>":
            args, env = ["--no-build", "--config", str(config)], None
        elif how == "--config=<path>":
            args, env = ["--no-build", f"--config={config}"], None
        else:
            args, env = ["--no-build"], {"ASH_CONFIG": str(config)}
            expected = "/ash-env-config/ash.yaml"

        rc, err, calls = _run_ash_status(fake_runner, project, args, env)

        assert rc == 0, err
        run = _only(calls, "run")
        if how == "--config=<path>":
            # An inline value is rewritten in place, in the same word.
            (word,) = [w for w in _inner_args(run) if w.startswith("--config=")]
            inner = word[len("--config=") :]
        else:
            inner = _flag(_inner_args(run), "--config")
        assert inner == expected
        mount = _mount(run, inner)
        assert Path(str(mount["source"])) == config.resolve()
        assert "readonly" in mount, f"the config mount is writable: {mount}"
        assert str(config) not in _inner_args(run)

    @pytest.mark.parametrize("value", ["missing.yaml", ""], ids=["missing", "empty"])
    def test_an_unreadable_config_is_refused_before_anything_runs(
        self, value, fake_runner, project
    ):
        rc, err, calls = _run_ash_status(fake_runner, project, ["--config", value])

        assert rc == 3
        assert calls == [], f"the runner was called: {calls}"
        assert "Config file not found" in err

    def test_a_build_without_a_run_does_not_need_the_config(self, fake_runner, project):
        """Control: ``--no-run`` scans nothing."""
        rc, err, calls = _run_ash_status(
            fake_runner, project, ["--no-run", "--config", "missing.yaml"]
        )

        assert rc == 0, err
        assert [call[0] for call in calls] == ["build"]


class TestAPathTheMountCannotCarryIsRefused:
    """A comma, a double quote or a line break in a mounted path refuses the run.

    ``--mount`` is read as comma-separated fields, so a comma in a host path starts a
    field of its own (``a,b``), a double quote starts CSV quoting, and a
    line break ends the argument. The wrapper refuses with exit 3 before it builds or
    runs anything.
    """

    @pytest.mark.parametrize(
        "name",
        ["a,b", 'x"y', "x\ny", "x\ry"],
        ids=["comma", "double-quote", "line-feed", "carriage-return"],
    )
    @pytest.mark.parametrize("which", ["source", "output", "config"])
    def test_it_is_refused_before_anything_runs(
        self, name, which, fake_runner, project, tmp_path
    ):
        odd = tmp_path / name
        odd.mkdir()
        args = ["--source-dir", str(project), "--output-dir", str(tmp_path / "out")]
        if which == "source":
            args[1] = str(odd)
        elif which == "output":
            args[3] = str(odd)
        else:
            (odd / "ash.yaml").write_text("project_name: p\n")
            args += ["--config", str(odd / "ash.yaml")]

        rc, output, calls = _run_ash_status(fake_runner, project, args)

        assert rc == 3, output
        assert calls == [], f"the runner was called: {calls}"
        assert "--mount" in output

    def test_ordinary_punctuation_still_runs(self, fake_runner, tmp_path):
        """Control."""
        source = tmp_path / "with space; and (parens)"
        source.mkdir()

        rc, output, calls = _run_ash_status(
            fake_runner, source, ["--no-build", "--output-dir", str(tmp_path / "out")]
        )

        assert rc == 0, output
        assert [call[0] for call in calls] == ["run"]

    @pytest.mark.parametrize("which", ["source", "output"])
    def test_a_build_without_a_run_mounts_nothing_and_is_not_refused(
        self, which, fake_runner, project, tmp_path
    ):
        """Control: ``--no-run`` builds the image and mounts no directory."""
        odd = tmp_path / "a,b"
        odd.mkdir()
        args = ["--no-run", "--source-dir", str(project), "--output-dir", str(odd)]
        if which == "source":
            args = ["--no-run", "--source-dir", str(odd)]

        rc, output, calls = _run_ash_status(fake_runner, project, args)

        assert rc == 0, output
        assert [call[0] for call in calls] == ["build"]


class TestAConfigTheScannedRepositoryWroteKeepsItsLimits:
    """A config inside the scanned checkout but outside the source directory.

    The scan inside the container sees it at /ash-config, outside its own tree, so
    the wrapper tells it the file belongs to the scanned repository, as a local scan
    of that checkout would treat it.
    """

    @pytest.fixture
    def checkout(self, tmp_path):
        root = tmp_path / "repo"
        (root / ".git").mkdir(parents=True)
        (root / "services" / "api").mkdir(parents=True)
        (root / "ci").mkdir()
        return root

    def test_a_config_elsewhere_in_the_checkout_is_marked(self, fake_runner, checkout):
        (checkout / "ci" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(checkout / "ci" / "ash.yaml")],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG in inner
        assert ELSEWHERE_FLAG not in inner

    def test_a_config_in_another_checkout_is_marked(
        self, fake_runner, checkout, tmp_path
    ):
        """As a local scan treats it: a config inside any git checkout cannot grant.

        It is not the scanned repository's, so it is marked as in another checkout
        (``--config-file-from-another-checkout``, which ``ash --mode container``
        sends for the same file), by its path inside the container and nothing
        else: the scan inside reads the mounted file itself."""
        mark_git_checkout(tmp_path / "ops")
        (tmp_path / "ops" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(tmp_path / "ops" / "ash.yaml")],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"
        assert SCANNED_CHAIN_FLAG not in inner
        assert SCANNED_FILE_FLAG not in inner
        assert [word for word in inner if str(tmp_path) in word] == []

    def test_the_outermost_checkout_counts_when_checkouts_nest(
        self, fake_runner, tmp_path
    ):
        """outer/.git and outer/svc/.git: the scanned tree is outer, as a local scan
        defines it, so a config in outer/ci is the repository's."""
        outer = tmp_path / "outer"
        (outer / ".git").mkdir(parents=True)
        (outer / "svc" / ".git").mkdir(parents=True)
        (outer / "ci").mkdir()
        (outer / "ci" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            tmp_path,
            [
                "--no-build",
                "--source-dir",
                str(outer / "svc"),
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(outer / "ci" / "ash.yaml"),
            ],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG in inner
        assert ELSEWHERE_FLAG not in inner

    def test_a_config_outside_the_checkout_is_not_marked(
        self, fake_runner, checkout, tmp_path
    ):
        """Control."""
        (tmp_path / "operator").mkdir()
        (tmp_path / "operator" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(tmp_path / "operator" / "ash.yaml")],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG not in inner
        assert ELSEWHERE_FLAG not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"

    @pytest.mark.parametrize("layout", LINKS_IN_THE_SCANNED_CHECKOUT)
    def test_a_config_reached_through_a_link_in_the_scanned_checkout_is_marked(
        self, layout, fake_runner, checkout, tmp_path
    ):
        """As a local scan treats it (config/sandbox_grants.links_followed): whoever
        wrote a link on the way chose the file the config resolves to, though
        neither the name given nor that file is in the scanned checkout. It is the
        scanned repository's, so it is not also marked as in another checkout; a
        link in some other checkout is marked as that
        (TestAConfigInAnotherCheckoutIsMarkedAsSuch)."""
        config = config_through_links(layout, checkout, tmp_path)

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(config)],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG in inner
        assert ELSEWHERE_FLAG not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"

    def test_a_config_reached_through_a_link_in_the_scanned_directory_is_marked(
        self, fake_runner, tmp_path
    ):
        """Outside every checkout, the scanned directory is the scanned tree."""
        source = tmp_path / "pkg"
        config = config_through_a_link_in(source, tmp_path)

        rc, output, calls = _run_ash_status(
            fake_runner, source, ["--no-build", "--config", str(config)]
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG in inner
        assert ELSEWHERE_FLAG not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"

    def test_a_link_chain_outside_every_checkout_is_not_marked(
        self, fake_runner, checkout, tmp_path
    ):
        """Control."""
        config = config_through_links(LINKS_OUTSIDE_EVERY_CHECKOUT, checkout, tmp_path)

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(config)],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert SCANNED_CHAIN_FLAG not in inner
        assert ELSEWHERE_FLAG not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"


class TestAConfigInAnotherCheckoutIsMarkedAsSuch:
    """A config in a git checkout other than the scanned one is marked as such.

    ``ash --mode container`` sends ``--config-file-from-another-checkout`` for the
    file (``run_ash_container._another_checkout_marks``), so the scan inside reads
    it as a file that cannot grant, as a local scan does
    (``sandbox_grants.checkout_judgment``). ``./ash`` mounts the same file at
    /ash-config or /ash-env-config, where the scan inside sees it in no checkout,
    so it sends the same mark on the same judgment: a ``.git`` that is a file, a
    link or a directory holding HEAD, at the file's directory or above it, found
    from the name the operator gave, from the real path, or from where a link the
    name goes through sits. The mark holds the path inside the container and
    nothing else.
    """

    @pytest.fixture
    def scanned(self, tmp_path):
        root = tmp_path / "repo"
        mark_git_checkout(root)
        (root / "services" / "api").mkdir(parents=True)
        return root

    @pytest.fixture
    def ops(self, tmp_path):
        root = tmp_path / "ops"
        mark_git_checkout(root)
        return root

    @staticmethod
    def _inner(fake_runner, cwd, args, env=None):
        rc, output, calls = _run_ash_status(
            fake_runner, cwd, ["--no-build", *args], env
        )
        assert rc == 0, output
        return _inner_args(_only(calls, "run"))

    def test_a_config_deep_below_the_checkout_root_is_marked(
        self, fake_runner, scanned, ops
    ):
        config = ops / "conf" / "prod" / "ash.yaml"
        config.parent.mkdir(parents=True)
        config.write_text("project_name: p\n")

        inner = self._inner(
            fake_runner, scanned / "services" / "api", ["--config", str(config)]
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]

    def test_a_relative_name_is_judged_from_the_working_directory(
        self, fake_runner, scanned, ops
    ):
        (ops / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", "../../../ops/ash.yaml"],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]
        assert SCANNED_CHAIN_FLAG not in inner

    def test_a_relative_name_that_climbs_out_of_the_checkout_to_a_file_in_none_is_not_marked(
        self, fake_runner, scanned, tmp_path
    ):
        """Run from inside the scanned checkout, ``../../../operator/ash.yaml``
        spells directories that lead to the checkout's .git, but each ``..`` is
        applied as the kernel applies it and the file is in the operator directory
        beside the checkout, in no checkout. Judged as text it would be marked as a
        file in another checkout; it is the operator's own."""
        operator = tmp_path / "operator"
        operator.mkdir()
        (operator / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", "../../../operator/ash.yaml"],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == []
        assert SCANNED_CHAIN_FLAG not in inner
        assert _flag_values(inner, SCANNED_FILE_FLAG) == []

    @pytest.mark.parametrize(
        "shape",
        ["directory-with-head", "gitfile", "link-to-a-directory", "dangling-link"],
    )
    def test_each_shape_of_git_entry_that_counts_marks_the_file(
        self, shape, fake_runner, scanned, tmp_path
    ):
        """Shapes that sandbox_grants._git_shaped counts as a checkout boundary."""
        ops = tmp_path / "ops"
        ops.mkdir()
        entry = ops / ".git"
        if shape == "directory-with-head":
            mark_git_checkout(ops)
        elif shape == "gitfile":
            entry.write_text("gitdir: ../repo/.git/worktrees/ops\n")
        elif shape == "link-to-a-directory":
            mark_git_checkout(tmp_path / "gitdir-home")
            entry.symlink_to(
                tmp_path / "gitdir-home" / ".git", target_is_directory=True
            )
        else:
            entry.symlink_to(tmp_path / "nowhere")
        (ops / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(ops / "ash.yaml")],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]

    @pytest.mark.parametrize(
        "shape", ["empty-directory", "directory-without-head", "fifo"]
    )
    def test_a_git_entry_that_is_not_a_checkout_marks_nothing(
        self, shape, fake_runner, scanned, tmp_path
    ):
        """Control: git would open none of these, and neither does a local scan."""
        ops = tmp_path / "ops"
        ops.mkdir()
        entry = ops / ".git"
        if shape == "empty-directory":
            entry.mkdir()
        elif shape == "directory-without-head":
            (entry / "objects").mkdir(parents=True)
        else:
            os.mkfifo(entry)
        (ops / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(ops / "ash.yaml")],
        )

        assert ELSEWHERE_FLAG not in inner
        assert SCANNED_CHAIN_FLAG not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"

    @pytest.mark.parametrize("layout", LINKS_IN_ANOTHER_CHECKOUT)
    def test_a_config_reached_through_a_link_in_another_checkout_is_marked(
        self, layout, fake_runner, scanned, tmp_path
    ):
        """As a local scan treats it: the checkout holding the link chose where the
        name leads, though neither the name given nor the file it resolves to is
        in a checkout the scan could be started from."""
        config = config_through_links(layout, scanned, tmp_path)

        inner = self._inner(
            fake_runner, scanned / "services" / "api", ["--config", str(config)]
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]
        assert SCANNED_CHAIN_FLAG not in inner

    def test_a_checkout_reached_through_a_link_of_the_operators_own_is_marked(
        self, fake_runner, scanned, ops, tmp_path
    ):
        """The name goes through a link to the checkout: the directories above the
        name as spelled lead to the checkout's .git, and so do those of the real
        path."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        (tmp_path / "alias").symlink_to(ops, target_is_directory=True)

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(tmp_path / "alias" / "ash.yaml")],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]

    def test_a_name_outside_every_checkout_that_resolves_into_one_is_marked(
        self, fake_runner, scanned, ops, tmp_path
    ):
        """The file is the checkout's though the name given is not in it: the real
        path is judged as well as the name."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        (tmp_path / "plain").mkdir()
        (tmp_path / "plain" / "cfg.yaml").symlink_to(ops / "ash.yaml")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(tmp_path / "plain" / "cfg.yaml")],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]

    def test_a_dotdot_after_a_link_in_another_checkout_is_judged_from_the_link(
        self, fake_runner, scanned, ops, tmp_path
    ):
        """``ops/lnk/../x.yaml`` with ``lnk`` a link the checkout holds: the kernel
        follows the link before the ``..``, so the name reaches the file beside the
        link's target, outside the checkout. Neither that name as the kernel reads
        it nor the file is in the checkout; the link that chose the way is."""
        far = tmp_path / "far"
        (far / "d").mkdir(parents=True)
        (far / "x.yaml").write_text("project_name: p\n")
        (ops / "lnk").symlink_to(far / "d", target_is_directory=True)

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", f"{ops}/lnk/../x.yaml"],
        )

        # Mounted by the name of the file it resolves to.
        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/x.yaml"]

    def test_a_checkout_in_a_directory_others_can_write_counts_for_its_owner(
        self, fake_runner, scanned, ops
    ):
        """sandbox_grants._left_by_a_trusted_user: in a directory group members or
        others can write, a .git counts when the scanning user owns it."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        ops.chmod(0o777)

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(ops / "ash.yaml")],
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]

    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root searches a directory whatever its mode says"
    )
    def test_a_git_directory_that_cannot_be_searched_counts_and_says_so(
        self, fake_runner, scanned, ops
    ):
        """The conservative answer stands when the lookup cannot be made, with the
        warning a local scan logs (sandbox_grants._warn_unverifiable_git)."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        (ops / ".git").chmod(0)
        try:
            rc, output, calls = _run_ash_status(
                fake_runner,
                scanned / "services" / "api",
                ["--no-build", "--config", str(ops / "ash.yaml")],
            )
        finally:
            (ops / ".git").chmod(0o700)

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-config/ash.yaml"]
        assert f"Treating {ops / '.git'} as a checkout boundary although its" in output
        assert "contents cannot be read (Permission denied)" in output

    def test_an_ash_config_file_in_another_checkout_is_marked(
        self, fake_runner, scanned, ops
    ):
        (ops / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            [],
            {"ASH_CONFIG": str(ops / "ash.yaml")},
        )

        assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/ash.yaml"
        assert _flag(inner, "--config") == "/ash-env-config/ash.yaml"
        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]
        assert SCANNED_CHAIN_FLAG not in inner
        assert SCANNED_FILE_FLAG not in inner

    def test_an_ash_config_name_that_resolves_into_a_checkout_is_marked(
        self, fake_runner, scanned, ops, tmp_path
    ):
        """The same judgment of the real path for the ASH_CONFIG file: the name
        given is in no checkout, the file it reaches is in one."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        (tmp_path / "plain").mkdir()
        (tmp_path / "plain" / "cfg.yaml").symlink_to(ops / "ash.yaml")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            [],
            {"ASH_CONFIG": str(tmp_path / "plain" / "cfg.yaml")},
        )

        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]

    def test_an_ash_config_file_is_marked_beside_an_operators_own_config(
        self, fake_runner, scanned, ops, tmp_path
    ):
        """Each mounted file is judged for itself: the explicit --config is outside
        every checkout and the ASH_CONFIG file is in one."""
        (ops / "ash.yaml").write_text("project_name: p\n")
        (tmp_path / "operator").mkdir()
        (tmp_path / "operator" / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(tmp_path / "operator" / "ash.yaml")],
            {"ASH_CONFIG": str(ops / "ash.yaml")},
        )

        assert _flag(inner, "--config") == "/ash-config/ash.yaml"
        assert _flag_values(inner, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]

    def test_both_files_in_another_checkout_are_each_marked(
        self, fake_runner, scanned, ops
    ):
        (ops / "ash.yaml").write_text("project_name: p\n")
        (ops / "env.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            ["--config", str(ops / "ash.yaml")],
            {"ASH_CONFIG": str(ops / "env.yaml")},
        )

        assert sorted(_flag_values(inner, ELSEWHERE_FLAG)) == [
            "/ash-config/ash.yaml",
            "/ash-env-config/env.yaml",
        ]

    def test_an_ash_config_file_in_the_scanned_checkout_is_not_marked_as_another(
        self, fake_runner, scanned
    ):
        """Control: the scanned repository's file keeps its own mark alone."""
        (scanned / "ci").mkdir()
        (scanned / "ci" / "ash.yaml").write_text("project_name: p\n")

        inner = self._inner(
            fake_runner,
            scanned / "services" / "api",
            [],
            {"ASH_CONFIG": str(scanned / "ci" / "ash.yaml")},
        )

        assert _flag_values(inner, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
        assert ELSEWHERE_FLAG not in inner

    def test_a_config_inside_the_source_is_not_marked(self, fake_runner, scanned):
        """Control: read through /src, which the scan inside judges itself."""
        source = scanned / "services" / "api"
        (source / ".ash").mkdir()
        (source / ".ash" / "strict.yaml").write_text("project_name: p\n")

        inner = self._inner(fake_runner, source, ["--config", ".ash/strict.yaml"])

        assert ELSEWHERE_FLAG not in inner
        assert SCANNED_CHAIN_FLAG not in inner
        assert _flag(inner, "--config") == "/src/.ash/strict.yaml"

    def test_a_build_without_a_run_judges_nothing(self, fake_runner, scanned, tmp_path):
        """Control: --no-run scans nothing, so no config is carried or judged."""
        rc, output, calls = _run_ash_status(
            fake_runner,
            scanned / "services" / "api",
            ["--no-run", "--config", str(tmp_path / "missing.yaml")],
        )

        assert rc == 0, output
        assert [call[0] for call in calls] == ["build"]


class TestAConfigLinkedOutOfTheTreeIsRefused:
    """A config named inside the scanned checkout whose real path is outside it.

    The wrapper refuses it with exit 3, whether the file or a directory on the way
    to it is the link. A link that stays inside the checkout is followed.
    """

    @pytest.fixture
    def checkout(self, tmp_path):
        root = tmp_path / "repo"
        (root / ".git").mkdir(parents=True)
        (root / ".ash").mkdir()
        outside = tmp_path / "other" / "settings" / "config.json"
        outside.parent.mkdir(parents=True)
        outside.write_text("{}\n")
        return root, outside

    def test_a_file_link_is_refused(self, fake_runner, checkout):
        root, outside = checkout
        (root / ".ash" / ".ash.yaml").symlink_to(outside)

        rc, output, calls = _run_ash_status(
            fake_runner, root, ["--no-build", "--config", ".ash/.ash.yaml"]
        )

        assert rc == 3, output
        assert calls == []

    def test_a_directory_link_is_refused(self, fake_runner, checkout):
        root, outside = checkout
        (root / "conf").symlink_to(outside.parent, target_is_directory=True)

        rc, output, calls = _run_ash_status(
            fake_runner, root, ["--no-build", "--config", "conf/config.json"]
        )

        assert rc == 3, output
        assert calls == []

    def test_a_link_that_stays_inside_still_runs(self, fake_runner, checkout):
        """Control."""
        root, _ = checkout
        (root / ".ash" / "real.yaml").write_text("project_name: p\n")
        (root / ".ash" / ".ash.yaml").symlink_to("real.yaml")

        rc, output, calls = _run_ash_status(
            fake_runner, root, ["--no-build", "--config", ".ash/.ash.yaml"]
        )

        assert rc == 0, output
        assert (
            _flag(_inner_args(_only(calls, "run")), "--config") == "/src/.ash/real.yaml"
        )

    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root reads a file whatever its mode says"
    )
    def test_an_unreadable_config_is_refused(self, fake_runner, project, tmp_path):
        unreadable = tmp_path / "operator.yaml"
        unreadable.write_text("project_name: p\n")
        unreadable.chmod(0)
        try:
            rc, output, calls = _run_ash_status(
                fake_runner, project, ["--no-build", "--config", str(unreadable)]
            )
        finally:
            unreadable.chmod(0o600)

        assert rc == 3, output
        assert calls == []


class TestAPathStartingWithADashIsAPath:
    """``dirname``, ``basename``, ``readlink``, ``cd`` and ``mkdir`` read a word
    starting with ``-`` as options unless ``--`` comes first. The wrapper passes
    ``--``, so a config, source or output path named that way resolves to itself."""

    def test_a_config_named_with_a_leading_dash(self, fake_runner, project):
        (project / "-strict.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", "-strict.yaml"]
        )

        assert rc == 0, output
        run = _only(calls, "run")
        assert _flag(_inner_args(run), "--config") == "/src/-strict.yaml"
        assert run.count("--mount") == 2

    def test_a_link_named_with_a_leading_dash(self, fake_runner, project):
        (project / "real.yaml").write_text("project_name: p\n")
        (project / "-link.yaml").symlink_to("real.yaml")

        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", "-link.yaml"]
        )

        assert rc == 0, output
        run = _only(calls, "run")
        assert _flag(_inner_args(run), "--config") == "/src/real.yaml"

    def test_source_and_output_directories_named_with_a_leading_dash(
        self, fake_runner, project
    ):
        (project / "-src").mkdir()

        rc, output, calls = _run_ash_status(
            fake_runner,
            project,
            ["--no-build", "--source-dir", "-src", "--output-dir", "-out"],
        )

        assert rc == 0, output
        run = _only(calls, "run")
        assert _mount(run, "/src")["source"] == str((project / "-src").resolve())
        assert _mount(run, "/out")["source"] == str((project / "-out").resolve())


class TestADirectoryThatCannotBeEnteredEndsTheRun:
    """A ``--source-dir`` the wrapper cannot enter, or an ``--output-dir`` it cannot
    create, ends the run with exit 5, the usage error ``ash scan`` refuses the same
    input with (utils/directory_refusals.py), in its words. Nothing else is mounted
    in its place."""

    def test_a_source_directory_that_does_not_exist_ends_the_run(
        self, fake_runner, project
    ):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--source-dir", "missing"]
        )

        assert rc == 5, output
        assert calls == []
        assert "missing" in output


class TestANonRootBuildAsUid0IsRefused:
    """The ``non-root`` stage creates its user with ``adduser --uid <UID>``, and UID 0
    is root, which already exists: the build fails at that step after the whole
    ``core`` stage has been built. As in ``ash build-image``, the wrapper refuses it
    before building, with exit 3, the code Invoke-ASH and ``ash --mode container``
    give the same refusal, and names ``--build-target ci``. Any spelling of zero
    counts: the build reads ``UID=00`` as 0 too."""

    @pytest.mark.parametrize("uid", ["0", "00"])
    def test_a_container_uid_of_0(self, uid, fake_runner, project):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-run", "--container-uid", uid]
        )

        assert rc == 3, output
        assert calls == []
        assert "--build-target ci" in output

    def test_running_as_root(self, fake_runner, project):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-run"], host_ids=("0", UNPRIVILEGED_GID)
        )

        assert rc == 3, output
        assert calls == []
        assert "--build-target ci" in output

    def test_the_ci_stage_builds_with_uid_0(self, fake_runner, project):
        """Control: ``ci`` creates no user."""
        calls = run_ash(
            fake_runner,
            project,
            ["--no-run", "--build-target", "ci", "--container-uid", "0"],
        )

        assert [call[0] for call in calls] == ["build"]

    def test_no_build_runs_with_uid_0(self, fake_runner, project):
        """Control: nothing is built, so there is no user to create."""
        calls = run_ash(fake_runner, project, ["--no-build", "--container-uid", "0"])

        assert [call[0] for call in calls] == ["run"]

    @pytest.mark.parametrize("gid", ["0", "00"])
    def test_a_container_gid_of_0(self, gid, fake_runner, project):
        """GID 0 is root's group: the non-root user would get root's group rights."""
        rc, output, calls = _run_ash_status(
            fake_runner,
            project,
            ["--no-run", "--container-uid", "1000", "--container-gid", gid],
        )

        assert rc == 3, output
        assert calls == []
        assert "GID 0" in output
        assert "--build-target ci" in output

    @pytest.mark.parametrize("flag", ["--container-uid", "--container-gid"])
    def test_an_id_that_is_not_a_number(self, flag, fake_runner, project):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-run", flag, "1x"]
        )

        assert rc == 3, output
        assert calls == []
        assert "must be a numeric value" in output

    @pytest.mark.parametrize(
        ("host_ids", "args", "id_flag"),
        [
            pytest.param(("0", "0"), [], "--container-uid", id="uid-0"),
            pytest.param(
                ("1000", "0"), [], "--container-gid", id="gid-0-from-the-host"
            ),
        ],
    )
    def test_the_refusal_names_ci_first_and_other_ids_only_with_a_writable_output(
        self, host_ids, args, id_flag, fake_runner, project
    ):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-run", *args], host_ids=host_ids
        )

        assert rc != 0 and calls == [], output
        # The advice starts with ci; the cause before it may name the flag as given.
        advice = output[output.index("Pass --build-target ci") :]
        assert id_flag in advice
        assert "output directory is writable" in advice[advice.index(id_flag) :]

    @pytest.mark.parametrize("written", ["NON-ROOT", "Non-Root"])
    def test_the_stage_name_in_any_case_is_refused_as_root(
        self, written, fake_runner, project
    ):
        """The build reads stage names in any case, so --target NON-ROOT builds
        ``non-root`` and would fail at ``adduser`` as root."""
        rc, output, calls = _run_ash_status(
            fake_runner,
            project,
            ["--no-run", "--build-target", written],
            host_ids=("0", "0"),
        )

        assert rc != 0, output
        assert calls == []
        assert "--build-target ci" in output

    @pytest.mark.parametrize("written", ["NON-ROOT", "CI"])
    def test_the_stage_is_built_by_its_lower_case_name(
        self, written, fake_runner, project
    ):
        calls = run_ash(fake_runner, project, ["--no-run", "--build-target", written])

        [build] = calls
        assert _flag(build, "--target") == written.lower()
        assert _flag(build, "--tag") == f"automated-security-helper:{written.lower()}"

    def test_an_unprivileged_host_user_builds_non_root_as_itself(
        self, fake_runner, project
    ):
        """Control for test_running_as_root: only the IDs ``id`` reports differ."""
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-run"], host_ids=("1234", "1235")
        )

        assert rc == 0, output
        [build] = calls
        assert _flag(build, "--target") == "non-root"
        assert "UID=1234" in build and "GID=1235" in build


class TestAnOutputDirectoryOverTheSourceIsRefused:
    """``/out`` is read-write and ``/src`` read-only; an output directory that is
    the source directory or above it would hold the source tree writable through
    ``/out``. Refused with exit 3 before anything runs, by real paths. Inside the
    source (the default) or outside it is fine; ``--no-run`` mounts nothing."""

    @pytest.mark.parametrize("where", ["the-source", "its-parent", "a-link-to-it"])
    def test_it_is_refused(self, where, fake_runner, project, tmp_path):
        if where == "the-source":
            output = project
        elif where == "its-parent":
            output = project.parent
        else:
            output = tmp_path / "out-link"
            output.symlink_to(project, target_is_directory=True)

        rc, text, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--output-dir", str(output)]
        )

        assert rc == 3, text
        assert calls == []
        assert "above it" in text

    @pytest.mark.parametrize("where", ["default", "beside-it"])
    def test_inside_or_outside_the_source_runs(
        self, where, fake_runner, project, tmp_path
    ):
        args = ["--no-build"]
        if where == "beside-it":
            args += ["--output-dir", str(tmp_path / "out")]

        calls = run_ash(fake_runner, project, args)

        assert [call[0] for call in calls] == ["run"]

    def test_a_build_without_a_run_is_not_refused(self, fake_runner, project):
        calls = run_ash(fake_runner, project, ["--no-run", "--output-dir", "."])

        assert [call[0] for call in calls] == ["build"]


class TestALinkedOutputDirectoryIsRefused:
    """``/out`` is mounted read-write, so with a linked output directory the scan
    would write wherever the link leads. Refused with exit 3 before the directory is
    created: the output directory when it is a link, wherever it is, and any link
    below the source directory on the way to it, with the source taken under its
    name and its real path. ``--no-run`` builds the image only, so it neither
    checks nor creates the output directory and is not refused. A real directory,
    and a source reached through a link above it, run."""

    @pytest.fixture
    def elsewhere(self, tmp_path):
        path = tmp_path / "elsewhere"
        path.mkdir()
        return path

    @pytest.mark.parametrize(
        "where",
        [
            "the-default-output-directory",
            "a-directory-on-the-way",
            "an-outside-output-directory",
            "a-dangling-link",
        ],
    )
    def test_it_is_refused(self, where, fake_runner, project, elsewhere, tmp_path):
        args = ["--no-build"]
        if where == "the-default-output-directory":
            (project / ".ash").mkdir()
            link = project / ".ash" / "ash_output"
            link.symlink_to(elsewhere, target_is_directory=True)
        elif where == "a-directory-on-the-way":
            link = project / ".ash"
            link.symlink_to(elsewhere, target_is_directory=True)
        elif where == "an-outside-output-directory":
            link = tmp_path / "out-link"
            link.symlink_to(elsewhere, target_is_directory=True)
            args += ["--output-dir", str(link)]
        else:
            (project / ".ash").mkdir()
            link = project / ".ash" / "ash_output"
            link.symlink_to(tmp_path / "not-there", target_is_directory=True)

        rc, text, calls = _run_ash_status(fake_runner, project, args)

        assert rc == 3, text
        assert calls == []
        assert list(elsewhere.iterdir()) == []
        assert str(link) in text

    def test_a_link_on_the_way_is_seen_under_the_real_name_of_the_source(
        self, fake_runner, project, elsewhere, tmp_path
    ):
        named = tmp_path / "project-link"
        named.symlink_to(project, target_is_directory=True)
        (project / ".ash").symlink_to(elsewhere, target_is_directory=True)

        rc, text, calls = _run_ash_status(
            fake_runner,
            project,
            [
                "--no-build",
                "--source-dir",
                str(named),
                "--output-dir",
                str(project / ".ash" / "ash_output"),
            ],
        )

        assert rc == 3, text
        assert calls == []
        assert list(elsewhere.iterdir()) == []

    def test_a_build_without_a_run_creates_nothing_and_is_not_refused(
        self, fake_runner, project, elsewhere
    ):
        """``--no-run`` neither checks nor creates the output directory, so a
        linked ``.ash`` on the way to it is not written through, and not refused."""
        (project / ".ash").symlink_to(elsewhere, target_is_directory=True)

        rc, text, calls = _run_ash_status(fake_runner, project, ["--no-run"])

        assert rc == 0, text
        assert [call[0] for call in calls] == ["build"]
        assert list(elsewhere.iterdir()) == []

    def test_a_real_default_output_directory_runs(self, fake_runner, project):
        calls = run_ash(fake_runner, project, ["--no-build"])

        assert [call[0] for call in calls] == ["run"]
        output = project / ".ash" / "ash_output"
        assert output.is_dir() and not output.is_symlink()

    def test_a_source_reached_through_a_link_above_it_runs(
        self, fake_runner, project, tmp_path
    ):
        named = tmp_path / "via-link"
        named.symlink_to(tmp_path, target_is_directory=True)
        spelled = named / "project"

        calls = run_ash(
            fake_runner,
            project,
            [
                "--no-build",
                "--source-dir",
                str(spelled),
                "--output-dir",
                str(spelled / ".ash" / "ash_output"),
            ],
        )

        assert [call[0] for call in calls] == ["run"]
        assert (project / ".ash" / "ash_output").is_dir()


class TestAnExplicitRunnerPathRunsThatPath:
    """Two runners named ``docker``: one at the path OCI_RUNNER names, one first on
    PATH, each recording its own path. A path runs exactly that file; a bare name
    resolves on PATH. Matches ``ash --mode container`` and Invoke-ASH."""

    @staticmethod
    def _runner(directory: Path, log: Path) -> Path:
        directory.mkdir(parents=True)
        runner = directory / "docker"
        runner.write_text(
            f"#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$1\" >> '{log}'\nexit 0\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        return runner

    @pytest.mark.parametrize("given", ["a-path", "a-name"])
    def test_it_runs_the_given_path(self, given, fake_runner, project, tmp_path):
        log = tmp_path / "runner-calls.txt"
        explicit = self._runner(tmp_path / "given-dir", log)
        on_path = self._runner(tmp_path / "path-bin", log)
        path = os.pathsep.join(
            [
                str(on_path.parent),
                str(tmp_path / "fixed-id-bin"),
                os.environ.get("PATH") or os.defpath,
            ]
        )

        rc, text, _ = _run_ash_status(
            fake_runner,
            project,
            ["--no-build"],
            extra_env={
                "OCI_RUNNER": str(explicit) if given == "a-path" else "docker",
                "PATH": path,
            },
        )

        assert rc == 0, text
        expected = explicit if given == "a-path" else on_path
        assert log.read_text(encoding="utf-8").splitlines() == [f"{expected} run"]


class TestAWorkspaceScanIsRefused:
    """``./ash`` scans one directory: it hands the scan inside ``--source-dir /src``,
    which that scan refuses next to ``--workspace``, after the container has started.
    So it cannot run a workspace scan, and cannot mark a workspace's ``--config``
    either. A ``--workspace`` passed through is refused with exit 3 before anything
    is built or mounted, naming ``ash --mode container --workspace``, whatever the
    config; the case that matters is a config in the checkout but outside the
    workspace, which the scan inside would read as the operator's."""

    @pytest.mark.parametrize(
        "flag",
        [
            ["--workspace", "/src/ash.code-workspace"],
            ["--workspace=/src/ash.code-workspace"],
        ],
        ids=["separate", "joined"],
    )
    def test_it_is_refused(self, flag, fake_runner, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / "ws" / "proj").mkdir(parents=True)
        config = repo / "other" / "ash-config.yaml"
        config.parent.mkdir()
        config.write_text("project_name: tier\n", encoding="utf-8")

        rc, text, calls = _run_ash_status(
            fake_runner, repo / "ws", ["--config", str(config), *flag]
        )

        assert rc == 3, text
        assert calls == []
        assert "ash --mode container --workspace" in text

    def test_a_one_directory_scan_runs(self, fake_runner, project):
        """Control: without --workspace, as before."""
        calls = run_ash(fake_runner, project, ["--no-build"])

        assert [call[0] for call in calls] == ["run"]


class TestAnOutsideConfigThatExtendsIsRefused:
    """``./ash`` mounts a config from outside the source directory on its own, so the
    files it extends are not in the container. A config there with an ``extends``
    entry is refused with exit 3 before anything is built or run, wherever its bases
    are; ``ash --mode container`` mounts such a chain. A config inside the source
    directory is read through ``/src`` with its chain, as before."""

    @pytest.mark.parametrize(
        "text",
        [
            "extends: base.yaml\n",
            "project_name: p\nextends:\n  - base.yaml\n",
            '{"extends": "base.yaml"}\n',
        ],
        ids=["yaml", "yaml-list", "json"],
    )
    def test_it_is_refused(self, text, fake_runner, project, tmp_path):
        (tmp_path / "base.yaml").write_text("project_name: p\n")
        config = tmp_path / "ash.yaml"
        config.write_text(text)

        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", str(config)]
        )

        assert rc == 3, output
        assert calls == []
        assert "extends" in output

    def test_a_config_elsewhere_in_the_checkout_that_extends_is_refused(
        self, fake_runner, tmp_path
    ):
        root = tmp_path / "repo"
        (root / ".git").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "ci").mkdir()
        (root / "ci" / "base.yaml").write_text("project_name: p\n")
        (root / "ci" / "ash.yaml").write_text("extends: base.yaml\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            root,
            ["--no-build", "--source-dir", "src", "--config", "ci/ash.yaml"],
        )

        assert rc == 3, output
        assert calls == []

    @pytest.mark.parametrize(
        "text",
        [
            "project_name: p\nscanners:\n  bandit:\n    enabled: true\n",
            "project_name: extends-demo\n",
        ],
        ids=["no-mention", "a-value-that-mentions-the-word"],
    )
    def test_an_outside_config_without_extends_still_runs(
        self, text, fake_runner, project, tmp_path
    ):
        """Control."""
        config = tmp_path / "ash.yaml"
        config.write_text(text)

        calls = run_ash(fake_runner, project, ["--no-build", "--config", str(config)])

        assert (
            _flag(_inner_args(_only(calls, "run")), "--config")
            == "/ash-config/ash.yaml"
        )

    def test_a_config_inside_the_source_that_extends_still_runs(
        self, fake_runner, project
    ):
        """Control: the chain is read through /src."""
        (project / ".ash").mkdir()
        (project / ".ash" / "base.yaml").write_text("project_name: p\n")
        (project / ".ash" / "ash.yaml").write_text("extends: base.yaml\n")

        calls = run_ash(
            fake_runner, project, ["--no-build", "--config", ".ash/ash.yaml"]
        )

        assert (
            _flag(_inner_args(_only(calls, "run")), "--config") == "/src/.ash/ash.yaml"
        )


class TestAnExplicitConfigIsCheckedOnTheHost:
    """As ``ash --mode container``: a missing ``--config`` exits 3 with
    ``Config file not found: <path>``, and a relative one is the file in the
    working directory, never one the source directory holds by that name."""

    def test_a_missing_config_names_the_path(self, fake_runner, project):
        rc, output, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", "missing.yaml"]
        )

        assert rc == 3, output
        assert calls == []
        assert "Config file not found: missing.yaml" in output

    def test_a_relative_config_is_the_working_directorys_file(
        self, fake_runner, tmp_path
    ):
        (tmp_path / "src").mkdir()
        (tmp_path / "ash.yaml").write_text("project_name: operator\n")
        (tmp_path / "src" / "ash.yaml").write_text("project_name: repository\n")

        calls = run_ash(
            fake_runner,
            tmp_path,
            ["--no-build", "--source-dir", "src", "--config", "ash.yaml"],
        )

        run = _only(calls, "run")
        assert _flag(_inner_args(run), "--config") == "/ash-config/ash.yaml"
        assert _mount(run, "/ash-config/ash.yaml")["source"] == str(
            (tmp_path / "ash.yaml").resolve()
        )
