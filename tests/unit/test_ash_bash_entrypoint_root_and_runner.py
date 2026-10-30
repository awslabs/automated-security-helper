# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How `./ash` finds its own root, its runner and its options' edges.

The repo root is the script file's directory, a symlinked ./ash followed; --help and
--version exit with the host CLI's status; -o after get-genai-guide or config is the
subcommand's, while -o after scan or build-image is still this script's runner;
--offline reaches the scan; a run refused after the output directory is made leaves
it in place, as it always did; a non-numeric container UID is shown, not written raw; a runner found on PATH under a
directory with a space runs; a runner given with arguments is still recognized by its
first word; --debug traces the build with its values shown; a --config inside one
quoted argument is this script's --config; the extends check reads TOML dotted and
escaped keys and a file starting with a byte order mark; and a link whose target ends
in '/' is followed on the mark walk.

A fake OCI runner stands in for docker, as in
test_ash_bash_entrypoint_container_inputs.py, and records each call's argv
NUL-separated. Bash-wrapper tests are integration tier (tests/NAMING_CONVENTIONS.md).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from tests.utils.host_ids import with_fixed_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; ./ash is the POSIX entrypoint",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

# Records each call's arguments, NUL-separated, in the next numbered file under
# $FAKE_RUNNER_LOG_DIR, and fails a build when BUILD_FAILS is set so a test that only
# needs the build's argv never reaches the run step.
RECORDING_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
if [ "$1" = build ] && [ -n "${BUILD_FAILS:-}" ]; then
  echo 'fake runner: refusing to build, argv recorded' >&2
  exit 1
fi
exit 0
"""

_SCRUBBED_ENV = (
    "CI",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
    "CDPATH",
)


def _executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


#: Stands under each runner name the wrapper looks for on PATH and refuses: no test
#: here may reach a real container runtime, whatever the wrapper decides.
GUARD_RUNNER = """#!/bin/bash
echo 'guard runner: ./ash looked a container runtime up on PATH; nothing runs' >&2
exit 99
"""


def _guard_runners(bin_root: Path) -> Path:
    """A directory of guard programs named finch, docker, nerdctl and podman."""
    guards = bin_root / "guard-runners"
    for name in ("finch", "docker", "nerdctl", "podman"):
        _executable(guards / name, GUARD_RUNNER)
    return guards


@pytest.fixture
def runner(tmp_path):
    """The recording runner and the directory its calls land in."""
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return _executable(tmp_path / "bin" / "fake-oci-runner", RECORDING_RUNNER), log_dir


def _calls(log_dir: Path) -> List[List[str]]:
    calls = []
    for record in sorted(log_dir.iterdir()):
        calls.append(record.read_bytes().decode("utf-8").split("\0")[:-1])
    return calls


def _run(
    runner,
    args: List[str],
    *,
    cwd: Path,
    env: Optional[Dict[str, str]] = None,
    script: Optional[Path] = None,
    name_the_runner: bool = True,
    path_prefix: Optional[Path] = None,
):
    """Run ./ash (or *script*) against the recording runner: (result, calls).

    With *name_the_runner* false, OCI_RUNNER is left unset and the script resolves
    its runner from PATH, as it does when no runner is named. *path_prefix* goes
    first on PATH, ahead of the fixed ``id``. Guard programs under the four runner
    names sit on PATH behind *path_prefix* and ahead of the caller's PATH, so a
    wrapper that looks a runtime up (no runner named, or a regression that drops a
    leading -o) meets a guard that refuses, never the developer's finch or docker.
    """
    default_program, log_dir = runner
    environment = with_fixed_ids(
        {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV},
        log_dir.parent / "fixed-id-bin",
    )
    environment["FAKE_RUNNER_LOG_DIR"] = str(log_dir)
    if name_the_runner:
        environment["OCI_RUNNER"] = str(default_program)
    environment["PATH"] = os.pathsep.join(
        [str(_guard_runners(log_dir.parent)), environment["PATH"]]
    )
    if path_prefix is not None:
        environment["PATH"] = os.pathsep.join([str(path_prefix), environment["PATH"]])
    environment.update(env or {})
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", str(script or ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        errors="backslashreplace",
        cwd=str(cwd),
        env=environment,
        stdin=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )
    return result, _calls(log_dir)


def _only(calls: List[List[str]], verb: str, shown: str) -> List[str]:
    found = [call for call in calls if call[:1] == [verb]]
    assert len(found) == 1, f"expected one {verb} call, got {calls}\n{shown}"
    return found[0]


def _mounts(run: List[str]) -> Dict[str, Dict[str, str]]:
    """The run's --mount values, keyed by destination."""
    mounts = {}
    for at, word in enumerate(run):
        if word == "--mount":
            fields = dict(part.partition("=")[::2] for part in run[at + 1].split(","))
            mounts[fields["destination"]] = fields
    return mounts


def _after_image(run: List[str]) -> List[str]:
    """The words the scan inside the container is given: those after `ash`."""
    return run[run.index("ash") + 1 :]


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    return src


@pytest.mark.parametrize("target", ["absolute", "relative", "two-hops"])
def test_a_symlinked_entrypoint_builds_from_the_checkout_it_links_to(
    runner, source, tmp_path, target
):
    """ASH_ROOT_DIR was the directory of the path the script was started by, so a
    symlinked ./ash gave the build the link's directory and a Dockerfile that is not
    there. The script file's own directory, every link followed, is the root: an
    absolute link, a relative one (`ln -s ../checkout/ash ~/bin/ash`, whose target
    resolves against the link's own directory, not the working directory), and a
    link to a link."""
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    link = link_dir / "ash"
    if target == "absolute":
        link.symlink_to(ASH_SCRIPT)
    elif target == "relative":
        link.symlink_to(os.path.relpath(ASH_SCRIPT, link_dir))
    else:
        hop = tmp_path / "hop" / "ash"
        hop.parent.mkdir()
        hop.symlink_to(os.path.relpath(ASH_SCRIPT, hop.parent))
        link.symlink_to(os.path.relpath(hop, link_dir))

    result, calls = _run(
        runner,
        ["--source-dir", str(source)],
        cwd=tmp_path,
        env={"BUILD_FAILS": "1"},
        script=link,
    )

    shown = result.stdout + result.stderr
    build = _only(calls, "build", shown)
    dockerfile = Path(build[build.index("--file") + 1])
    assert dockerfile.resolve() == (REPO_ROOT / "Dockerfile").resolve(), build
    assert Path(build[-1]).resolve() == REPO_ROOT.resolve(), build


@pytest.mark.parametrize("option", ["--help", "--version", "-v"])
def test_help_and_version_exit_with_the_host_clis_status(runner, tmp_path, option):
    """`./ash --help`, `./ash --version` and `./ash -v` exited 0 whatever the host
    CLI did, so a python that cannot run the CLI at all reported success. The short
    form kept its `exit 0` after the long forms were fixed."""
    fake_python = _executable(
        tmp_path / "pybin" / "python",
        "#!/bin/bash\necho 'fake python: cannot run the CLI' >&2\nexit 7\n",
    )

    result, calls = _run(runner, [option], cwd=tmp_path, path_prefix=fake_python.parent)

    assert result.returncode == 7, result.stdout + result.stderr
    assert "fake python: cannot run the CLI" in result.stderr, result.stderr
    assert calls == []


def test_dash_o_after_a_subcommand_is_the_subcommands(runner, source, tmp_path):
    """-o was always this script's --oci-runner, so `./ash get-genai-guide -o guide.md`
    ran a command named guide.md as the container runtime. After a subcommand's name
    the word is the subcommand's and is forwarded."""
    result, calls = _run(
        runner,
        [
            "--no-build",
            "--source-dir",
            str(source),
            "get-genai-guide",
            "-o",
            "guide.md",
        ],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    inner = _after_image(run)
    assert inner[inner.index("get-genai-guide") :][:3] == [
        "get-genai-guide",
        "-o",
        "guide.md",
    ], inner


def test_attached_dash_o_after_a_subcommand_is_the_subcommands(
    runner, source, tmp_path
):
    """The attached spelling is the subcommand's after its name too: `./ash
    get-genai-guide -oguide.md` writes the guide to guide.md, as click reads it.
    The spaced -o arm consulted the subcommand mark; the attached arm did not, so
    the same command with the value attached still ran a runner named guide.md."""
    result, calls = _run(
        runner,
        [
            "--no-build",
            "--source-dir",
            str(source),
            "get-genai-guide",
            "-oguide.md",
        ],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    inner = _after_image(run)
    assert inner[inner.index("get-genai-guide") :][:2] == [
        "get-genai-guide",
        "-oguide.md",
    ], inner


@pytest.mark.parametrize(
    "subcommand, spelling",
    [
        pytest.param("scan", "spaced", id="scan"),
        pytest.param("scan", "attached", id="scan-attached"),
        pytest.param("build-image", "spaced", id="build-image"),
    ],
)
def test_dash_o_after_scan_or_build_image_names_the_runner(
    runner, source, tmp_path, subcommand, spelling
):
    """The CLI's scan defines -o as its own alias of --oci-runner, so `./ash scan -o
    podman` means podman here, as it always did. Forwarding -o after every subcommand
    sent `scan -o podman` into the container while this script picked the first
    runner on PATH, so a host with docker and podman scanned under docker."""
    other = _executable(tmp_path / "bin" / "other-runner", RECORDING_RUNNER)
    dash_o = ["-o", str(other)] if spelling == "spaced" else [f"-o{other}"]

    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), subcommand, *dash_o],
        cwd=tmp_path,
        name_the_runner=False,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    assert f"Resolved OCI_RUNNER to: {other}" in result.stderr, result.stderr
    run = _only(calls, "run", shown)
    inner = _after_image(run)
    assert "-o" not in inner and f"-o{other}" not in inner, inner
    assert str(other) not in inner, inner


def test_dash_o_after_config_is_the_subcommands(runner, source, tmp_path):
    """config's -o is its --output-dir, so after `config` the word is forwarded, as
    after get-genai-guide, and this script keeps the runner it was given."""
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "config", "-o", "out"],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    inner = _after_image(run)
    assert inner[inner.index("config") :][:3] == ["config", "-o", "out"], inner


def test_dash_o_before_a_subcommand_names_the_runner(runner, source, tmp_path):
    """Ahead of a subcommand, -o is still this script's runner option."""
    program, _ = runner
    other = _executable(tmp_path / "bin" / "other-runner", RECORDING_RUNNER)

    result, calls = _run(
        runner,
        ["--no-build", "-o", str(other), "--source-dir", str(source), "scan"],
        cwd=tmp_path,
        name_the_runner=False,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    assert f"Resolved OCI_RUNNER to: {other}" in result.stderr, result.stderr
    run = _only(calls, "run", shown)
    assert "-o" not in _after_image(run), run


def test_offline_reaches_the_scan_inside_the_container(runner, source, tmp_path):
    """--offline cut the container's network and set the image's build argument but
    told the scan nothing, so with --no-build and an image built online the scan ran in
    online mode with no network."""
    result, calls = _run(
        runner,
        ["--no-build", "--offline", "--source-dir", str(source)],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    assert "--network=none" in run, run
    assert "--offline" in _after_image(run), run


def test_a_run_refused_after_the_output_dir_is_made_leaves_it(runner, source, tmp_path):
    """The output directory is made right after its path checks, before the container
    UID check and the runtime lookup, so a run refused later leaves the new
    .ash/ash_output in place: the order every release had, which
    tests/unit/cli/test_directory_refusals_agree.py pins (a missing --output-dir is
    made before the run stops at the runtime refusal). Making it only just before the
    build or the run left no directory behind here, and left the output-dir usage
    refusals behind the runtime one there."""
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--container-uid", "abc"],
        cwd=tmp_path,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert "must be a numeric value" in result.stderr, result.stderr
    assert (source / ".ash" / "ash_output").is_dir(), list(source.iterdir())
    assert calls == []


def test_a_non_numeric_container_uid_is_shown_not_written_raw(runner, source, tmp_path):
    """The refusal interpolated the value raw where every other refusal shows it, so an
    escape in it reached the terminal."""
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--container-uid", "1\x1b[2J2"],
        cwd=tmp_path,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert "\x1b" not in result.stderr, repr(result.stderr)
    # Shown, not dropped or cut: the value in bash's $'...' spelling, ESC as \E.
    assert "$'1\\E[2J2'" in result.stderr, repr(result.stderr)
    assert "must be a numeric value" in result.stderr, result.stderr
    assert calls == []


def test_a_runner_found_on_path_under_a_directory_with_a_space_runs(
    runner, source, tmp_path
):
    """The resolved runner was expanded unquoted, so a path with a space in it was
    split into words and could not be run."""
    _, log_dir = runner
    spaced = _executable(tmp_path / "bin dir" / "finch", RECORDING_RUNNER)

    result, calls = _run(
        runner,
        ["--source-dir", str(source)],
        cwd=tmp_path,
        env={"BUILD_FAILS": "1"},
        name_the_runner=False,
        path_prefix=spaced.parent,
    )

    shown = result.stdout + result.stderr
    assert f"Resolved OCI_RUNNER to: {spaced}" in result.stderr, result.stderr
    build = _only(calls, "build", shown)
    assert build[0] == "build", build


def test_a_runner_given_with_arguments_is_recognized_by_its_first_word(
    runner, source, tmp_path
):
    """OCI_RUNNER_NAME was the basename of the whole runner string, so a runner given
    with arguments never read as nerdctl or finch and the verified layout was not
    used."""
    nerdctl = _executable(tmp_path / "bin" / "nerdctl", RECORDING_RUNNER)
    layout = tmp_path / "layout"
    layout.mkdir()

    result, calls = _run(
        runner,
        ["--source-dir", str(source)],
        cwd=tmp_path,
        env={
            "OCI_RUNNER": f"{nerdctl} --namespace ash",
            "ASH_BASE_OCI_LAYOUT": f"{layout}@sha256:{'0' * 64}",
            "BUILD_FAILS": "1",
        },
    )

    shown = result.stdout + result.stderr
    builds = [call for call in calls if "build" in call[:3]]
    assert len(builds) == 1, f"expected one build call, got {calls}\n{shown}"
    build = builds[0]
    assert build[:3] == ["--namespace", "ash", "build"], build
    assert "--build-context" in build, build
    assert "--pull=false" in build, build


def test_debug_traces_the_build_with_its_values_shown(runner, source, tmp_path):
    """Under --debug, set -x traced the build line with the caller's values raw, so an
    escape in --ash-revision reached the terminal; the build is traced shown."""
    result, calls = _run(
        runner,
        [
            "--debug",
            "--no-run",
            "--source-dir",
            str(source),
            "--ash-revision",
            "rev\x1b[2Jision",
        ],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    _only(calls, "build", shown)
    assert "\x1b" not in result.stderr, repr(result.stderr)
    traced = [line for line in result.stderr.splitlines() if line.startswith("+ ")]
    assert any("INSTALL_ASH_REVISION=" in line for line in traced), result.stderr
    # Shown, not dropped or cut: the value in bash's $'...' spelling, ESC as \E.
    assert any("rev\\E[2Jision" in line for line in traced), result.stderr
    assert any("--target" in line for line in traced), result.stderr


def test_a_config_inside_one_quoted_argument_is_mounted(runner, source, tmp_path):
    """ "--config path" as one argument was split into words and forwarded as the host
    path, with no mount and no mark; found among the words, it is carried as a
    separate --config is."""
    config = tmp_path / "cfg.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), f"--config {config}"],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    mounted = Path(_mounts(run)["/ash-config/cfg.yaml"]["source"])
    assert mounted.resolve() == config.resolve(), run
    inner = _after_image(run)
    assert inner[inner.index("--config") + 1] == "/ash-config/cfg.yaml", inner


@pytest.mark.parametrize(
    ("text", "name"),
    [
        # A dotted key nests extends under a table (ash.extends is not the top-level
        # key the scan reads); the wrapper's check is textual and fails closed, so
        # the spelling is refused all the same rather than mounted alone.
        pytest.param('ash.extends = "base.yaml"\n', "cfg.toml", id="toml-dotted-key"),
        pytest.param(
            '"ext\\u0065nds" = "base.yaml"\n', "cfg.toml", id="toml-escaped-key"
        ),
        pytest.param(
            '{"ext\\u0065nds"\n  : "base.yaml"}\n',
            "cfg.json",
            id="json-escaped-key-next-line",
        ),
        # A byte order mark (U+FEFF) ahead of the key.
        pytest.param(
            chr(0xFEFF) + "extends: base.yaml\n", "cfg.yaml", id="yaml-after-bom"
        ),
    ],
)
def test_an_outside_config_with_an_extends_entry_in_another_spelling_is_refused(
    runner, source, tmp_path, text, name
):
    """The extends check missed a TOML dotted key, an escaped key followed by '=', an
    escaped JSON key whose ':' is on the next line and a file starting with a byte
    order mark, so such a config was mounted alone without its chain. Each file is
    named for its format, so a check that one day chose a grammar by suffix would
    still read these as the operator writes them."""
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--config", str(config)],
        cwd=tmp_path,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert "has an extends entry" in result.stderr, result.stderr
    assert calls == []


def test_a_link_whose_target_ends_in_a_slash_is_followed_on_the_mark_walk(
    runner, tmp_path
):
    """resolve_file stopped following links at a target ending in '/', so a link in
    the scanned tree reached through one was walked past and the repository's link was
    not seen: the file was refused as linked out of the tree instead of mounted with
    the scanned-repository mark."""
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    config = elsewhere / "cfg.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    # The repository commits `inner -> elsewhere`; an outside link names it with a
    # trailing slash.
    (src / "inner").symlink_to(elsewhere, target_is_directory=True)
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "lnk").symlink_to(f"{src / 'inner'}/", target_is_directory=True)

    result, calls = _run(
        runner,
        [
            "--no-build",
            "--source-dir",
            str(src),
            "--config",
            str(outer / "lnk" / "cfg.yaml"),
        ],
        cwd=tmp_path,
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    inner = _after_image(run)
    assert "--config-from-scanned-repository" in inner, inner
    mounted = Path(_mounts(run)["/ash-config/cfg.yaml"]["source"])
    assert mounted.resolve() == config.resolve(), run
