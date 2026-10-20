# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` judges where a config and the output directory are by their real paths.

utils/ash_helpers.ps1 refuses a config that the scanned tree points outside itself, an
output directory that holds the source, and an output directory reached through a link
that a repository committed below the source. Each of those is decided on the path with
every link on the way followed, whatever spelling the operator used for the tree, the
source or the output: a path that reaches the tree through a link of the operator's own
is judged exactly as the direct spelling is.

The cells here run the script, so they need ``pwsh``: they skip on a developer machine
without it and fail in CI, as test_powershell_wrapper_refusals_and_values.py does. They
need symbolic links and a POSIX shell for the recording runner, so they are skipped on
Windows.

Also covered here, with no change in what the script decides: the refusals for a path
that cannot be handed to the runner (a comma in a source or config path, a config the
user cannot read), the output-containment refusal for an output directory that is itself
a link, ``..`` components in the output path, and a path through more than 40 links.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point
from pathlib import Path
from typing import List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="the recording runner is a POSIX shell script and the cells need symlinks",
)


@pytest.fixture
def pwsh():
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


@pytest.fixture
def recording_docker(tmp_path, pwsh) -> Path:
    """A PATH whose docker writes its arguments, one per line, and succeeds."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args.txt"
    runner = bin_dir / "docker"
    runner.write_text(
        f"#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{log}'\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    return bin_dir


def _invoke(
    pwsh,
    tmp_path: Path,
    bin_dir: Path,
    arguments: str,
    before: str = "",
    home: Path | None = None,
):
    """Run Invoke-ASH as a CI step does: under ``Stop``, wrapped so a refusal, which
    throws, ends the step with its code (docs/content/docs/cli-reference.md).

    *before* is PowerShell run after the helpers are loaded and before the call, such
    as a ``Push-Location``; the process working directory stays *tmp_path*. *home*
    is what ``~`` means to PowerShell."""
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; {before} "
        f"try {{ Invoke-ASH -OCIRunner docker -NoBuild {arguments} }} "
        "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
        "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }; "
        "exit [int]$LASTEXITCODE"
    )
    env = {k: v for k, v in os.environ.items() if k not in ("PATH", "ASH_CONFIG")}
    env["PATH"] = os.pathsep.join(
        [bin_dir.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    if home is not None:
        env["HOME"] = home.as_posix()
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


def _recorded(tmp_path: Path) -> List[str]:
    log = tmp_path / "docker-args.txt"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _stderr(result) -> str:
    return " ".join(result.stderr.split())


@pytest.fixture
def checkout(tmp_path) -> Path:
    """repo/.git, repo/svc (the source), repo/ci, and an operator dir outside."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "svc").mkdir()
    (root / "ci").mkdir()
    (tmp_path / "operator").mkdir()
    return root


@pytest.fixture
def elsewhere(tmp_path) -> Path:
    """Where a link points the output directory; nothing may be written to it."""
    path = tmp_path / "elsewhere"
    path.mkdir()
    return path


# ---------------------------------------------------------------------------
# A config the scanned tree links to a file outside it is refused under every
# spelling of the tree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    ["direct", "alias-of-the-checkout", "second-alias-of-the-source"],
)
def test_a_config_linked_out_of_the_tree_is_refused_under_every_spelling(
    spelling, pwsh, recording_docker, checkout, tmp_path
):
    """The repository being scanned chooses which host file is read when a link in
    its tree leads out of it, however the operator spells the way to that link."""
    (tmp_path / "operator" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "svc" / "ash.yaml").symlink_to(tmp_path / "operator" / "ash.yaml")
    source = "repo/svc"
    config = "repo/svc/ash.yaml"
    if spelling == "alias-of-the-checkout":
        (tmp_path / "alias").symlink_to(checkout, target_is_directory=True)
        config = "alias/svc/ash.yaml"
    elif spelling == "second-alias-of-the-source":
        for name in ("svc-a", "svc-b"):
            (tmp_path / name).symlink_to(checkout / "svc", target_is_directory=True)
        source = "svc-a"
        config = "svc-b/ash.yaml"

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir {source} -OutputDir out -Config {config}",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "link" in result.stderr


def test_a_config_linked_inside_the_tree_runs_when_named_through_an_alias(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: the same alias spelling, with a link that stays inside the tree."""
    (checkout / "svc" / "conf").mkdir()
    (checkout / "svc" / "conf" / "real.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "svc" / "ash.yaml").symlink_to("conf/real.yaml")
    (tmp_path / "alias").symlink_to(checkout, target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config alias/svc/ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/src/conf/real.yaml"


# ---------------------------------------------------------------------------
# An output directory that holds the source is refused under mixed spellings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, output",
    [
        pytest.param("work/src", "work-link/src", id="equal-through-an-alias"),
        pytest.param("work/src/inner", "work-link/src", id="above-through-an-alias"),
        pytest.param("work-link/src", "work/src", id="source-through-the-alias"),
    ],
)
def test_an_output_directory_over_the_source_is_refused_under_mixed_spellings(
    source, output, pwsh, recording_docker, tmp_path
):
    """/out is read-write and /src read-only: an output directory that is the source
    or holds it would make the source writable through /out, whichever of its
    spellings each directory is given."""
    (tmp_path / "work" / "src" / "inner").mkdir(parents=True)
    (tmp_path / "work-link").symlink_to(tmp_path / "work", target_is_directory=True)

    result = _invoke(
        pwsh, tmp_path, recording_docker, f"-SourceDir {source} -OutputDir {output}"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "above it" in _stderr(result)


def test_an_output_directory_that_is_a_link_to_a_parent_of_the_source_is_refused(
    pwsh, recording_docker, tmp_path
):
    """A linked output directory is compared by where it leads."""
    (tmp_path / "src").mkdir()
    (tmp_path / "up").symlink_to(tmp_path, target_is_directory=True)

    result = _invoke(pwsh, tmp_path, recording_docker, "-SourceDir src -OutputDir up")

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "above it" in _stderr(result)


# ---------------------------------------------------------------------------
# A link a repository committed below the source is seen under any spelling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, output",
    [
        pytest.param("src", "src-a/.ash/out", id="output-through-an-alias"),
        pytest.param("src-a", "src-b/.ash/out", id="different-aliases"),
    ],
)
def test_a_committed_link_below_the_source_is_refused_under_an_alias(
    source, output, pwsh, recording_docker, elsewhere, tmp_path
):
    """/out is read-write: the scan would write wherever the committed link leads."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / ".ash").symlink_to(elsewhere, target_is_directory=True)
    for name in ("src-a", "src-b"):
        (tmp_path / name).symlink_to(tmp_path / "src", target_is_directory=True)

    result = _invoke(
        pwsh, tmp_path, recording_docker, f"-SourceDir {source} -OutputDir {output}"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert list(elsewhere.iterdir()) == []
    assert "symlink" in result.stderr


def test_an_output_directory_under_an_alias_of_the_source_runs(
    pwsh, recording_docker, tmp_path
):
    """Control: with no link committed below the source, the alias is the operator's
    own spelling."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src-a").symlink_to(tmp_path / "src", target_is_directory=True)

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir src -OutputDir src-a/.ash/out"
    )

    assert result.returncode == 0, result.stdout + result.stderr
    output = tmp_path / "src" / ".ash" / "out"
    assert output.is_dir() and not output.is_symlink()


@pytest.mark.parametrize(
    "output, linked",
    [
        pytest.param("src/x/../.ash/out", True, id="collapsed-onto-a-link"),
        pytest.param("src/.ash/../out2", True, id="through-a-link-to-its-parent"),
        pytest.param("src/.ash/../out2", False, id="collapsed-onto-a-real-directory"),
    ],
)
def test_dot_dot_components_in_the_output_path_are_walked_as_written(
    output, linked, pwsh, recording_docker, elsewhere, tmp_path
):
    """A '..' is applied after the part before it has been looked at: a link the
    repository committed below the source is met before the '..' that leaves it."""
    (tmp_path / "src" / "x").mkdir(parents=True)
    (elsewhere / "sub").mkdir()
    if linked:
        (tmp_path / "src" / ".ash").symlink_to(
            elsewhere / "sub", target_is_directory=True
        )
    else:
        (tmp_path / "src" / ".ash").mkdir()

    result = _invoke(
        pwsh, tmp_path, recording_docker, f"-SourceDir src -OutputDir {output}"
    )

    if linked:
        assert result.returncode == 3, result.stdout + result.stderr
        assert _recorded(tmp_path) == []
        assert [path.name for path in elsewhere.iterdir()] == ["sub"]
        assert list((elsewhere / "sub").iterdir()) == []
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert (tmp_path / "src" / "out2").is_dir()


# ---------------------------------------------------------------------------
# A path the runner cannot be handed
# ---------------------------------------------------------------------------


def test_a_source_directory_with_a_comma_is_refused(pwsh, recording_docker, tmp_path):
    """--mount reads a comma as the end of a field, so the path is refused first."""
    (tmp_path / "a,b").mkdir()

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir 'a,b' -OutputDir out"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    stderr = _stderr(result)
    assert "source directory" in stderr
    assert "cannot be handed to the container runner" in stderr


def test_a_config_file_with_a_comma_is_refused(pwsh, recording_docker, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "operator").mkdir()
    config = tmp_path / "operator" / "a,b.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir src -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    stderr = _stderr(result)
    assert "config file" in stderr
    assert "cannot be handed to the container runner" in stderr


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a file whatever its mode",
)
def test_a_config_the_user_cannot_read_is_refused(pwsh, recording_docker, tmp_path):
    """The runner mounts with its own rights, so ASH does not hand it a file it
    cannot read itself."""
    (tmp_path / "src").mkdir()
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    config.chmod(0)
    try:
        result = _invoke(
            pwsh,
            tmp_path,
            recording_docker,
            f"-SourceDir src -OutputDir out -Config '{config}'",
        )
    finally:
        config.chmod(0o600)

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "cannot be read" in _stderr(result)


# ---------------------------------------------------------------------------
# A path through more than 40 links is not run, whichever check meets it first
# ---------------------------------------------------------------------------


def _chain_of_links(tmp_path: Path, count: int) -> Path:
    """``hop0`` -> ``hop1`` -> ... -> ``hop<count-1>`` -> ``real``, a directory."""
    (tmp_path / "real").mkdir()
    target = tmp_path / "real"
    for index in reversed(range(count)):
        link = tmp_path / f"hop{index}"
        link.symlink_to(target, target_is_directory=True)
        target = link
    return target


def test_a_chain_of_41_links_to_the_source_directory_is_refused(
    pwsh, recording_docker, tmp_path
):
    """The real path is followed at most 40 links deep; past that the directory is
    refused, not taken as it is spelled."""
    _chain_of_links(tmp_path, 41)

    result = _invoke(pwsh, tmp_path, recording_docker, "-SourceDir hop0 -OutputDir out")

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    stderr = _stderr(result)
    assert "more than 40 links" in stderr
    assert "the walk reached 41" in stderr


def test_a_chain_of_40_links_to_the_source_directory_still_resolves(
    pwsh, recording_docker, tmp_path
):
    _chain_of_links(tmp_path, 40)

    result = _invoke(pwsh, tmp_path, recording_docker, "-SourceDir hop0 -OutputDir out")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _recorded(tmp_path) != []


def _config_behind_links(tmp_path: Path, count: int) -> Path:
    """A config file reached through *count* links one after another, each in a
    directory outside every checkout."""
    directories = [tmp_path / f"d{index}" for index in range(count + 1)]
    for directory in directories:
        directory.mkdir()
    for index in range(count):
        (directories[index] / f"c{index + 1}").symlink_to(
            directories[index + 1], target_is_directory=True
        )
    (directories[count] / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    return Path(
        directories[0], *[f"c{index + 1}" for index in range(count)], "ash.yaml"
    )


def test_a_config_behind_45_links_one_after_another_is_refused(
    pwsh, recording_docker, checkout, tmp_path
):
    """The follow walk gives up after 40 links by treating the config as reached
    through a link in a checkout. The kernel stops a path at 40 links on Linux, so
    the config is not found before the walk is reached there; the cell pins that a
    path this long is refused, whichever check meets it first."""
    config = _config_behind_links(tmp_path, 45)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


def test_a_config_behind_20_links_one_after_another_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: every link is outside every checkout, so the config is the
    operator's."""
    config = _config_behind_links(tmp_path, 20)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"
    assert "--config-from-scanned-repository" not in args


# ---------------------------------------------------------------------------
# --workspace is refused however it is quoted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "flag",
    [
        pytest.param("'\"--workspace\"' /src/ash.code-workspace", id="double-quoted"),
        pytest.param("\"'--workspace'\" /src/ash.code-workspace", id="single-quoted"),
        pytest.param("'\"--workspace=/src/ash.code-workspace\"'", id="quoted-joined"),
    ],
)
def test_a_quoted_workspace_flag_is_refused(flag, pwsh, recording_docker, tmp_path):
    """The flag reaches the scan with its quotes removed, so it is refused with them
    removed too."""
    (tmp_path / "src").mkdir()

    result = _invoke(
        pwsh, tmp_path, recording_docker, f"-SourceDir src -OutputDir out {flag}"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "ash --mode container --workspace" in _stderr(result)


# ---------------------------------------------------------------------------
# An outside config with a YAML anchor or alias on a key is refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("k: &a extends\n*a : base.yaml\n", id="alias-as-a-key"),
        pytest.param("{k: &a extends, *a : base.yaml}\n", id="alias-as-a-flow-key"),
        pytest.param("&a extends: base.yaml\n", id="anchor-on-the-key"),
    ],
)
def test_an_outside_config_with_an_anchor_or_alias_on_a_key_is_refused(
    text, pwsh, recording_docker, checkout, tmp_path
):
    """The key can be spelled through an anchor and an alias, so a key that is one is
    not read as anything but a possible ``extends``."""
    config = tmp_path / "operator" / "ash.yaml"
    config.write_text(text, encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


def test_an_outside_config_with_an_anchor_on_a_value_still_runs(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: an anchor on a value and an alias as a value are not keys."""
    config = tmp_path / "operator" / "ash.yaml"
    config.write_text(
        "defaults: &d\n  project_name: p\nother:\n  <<: *d\n", encoding="utf-8"
    )

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"


# ---------------------------------------------------------------------------
# '..' is applied to the real location, after the part before it is resolved
# ---------------------------------------------------------------------------


def _mount_source(args: List[str], destination: str) -> str:
    """The ``source=`` of the one --mount whose destination is *destination*."""
    values = [
        args[i + 1]
        for i, arg in enumerate(args[:-1])
        if arg == "--mount" and f"destination={destination}," in args[i + 1] + ","
    ]
    assert len(values) == 1, f"expected one mount at {destination} in {args}"
    return dict(
        part.partition("=")[::2] for part in values[0].split(",") if "=" in part
    )["source"]


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root searches a directory whatever its mode",
)
def test_a_config_past_an_unsearchable_directory_is_refused(
    pwsh, recording_docker, tmp_path
):
    """``locked/../ash.yaml`` names ``ash.yaml`` only if ``locked`` can be searched,
    as the shell wrapper finds it; a directory that cannot is a part the path
    cannot be placed through, so the config is refused, not read from the lexical
    parent."""
    (tmp_path / "src").mkdir()
    (tmp_path / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        result = _invoke(
            pwsh,
            tmp_path,
            recording_docker,
            "-SourceDir src -OutputDir out -Config locked/../ash.yaml",
        )
    finally:
        locked.chmod(0o700)

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


def test_a_config_past_a_missing_directory_is_refused(pwsh, recording_docker, tmp_path):
    """A part that does not exist cannot be placed, so ``missing/../ash.yaml`` is
    not read as ``ash.yaml``."""
    (tmp_path / "src").mkdir()
    (tmp_path / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir out -Config missing/../ash.yaml",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


def test_dot_dot_after_a_link_names_the_file_beside_the_target(
    pwsh, recording_docker, tmp_path
):
    """``a/../ash.yaml`` with ``a`` a link to ``real/sub`` is ``real/ash.yaml``,
    where the link leads, not the ``ash.yaml`` beside the link."""
    (tmp_path / "src").mkdir()
    (tmp_path / "real" / "sub").mkdir(parents=True)
    (tmp_path / "a").symlink_to(tmp_path / "real" / "sub", target_is_directory=True)
    (tmp_path / "ash.yaml").write_text("project_name: beside\n", encoding="utf-8")
    (tmp_path / "real" / "ash.yaml").write_text(
        "project_name: real\n", encoding="utf-8"
    )

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir out -Config a/../ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    source = _mount_source(_recorded(tmp_path), "/ash-config/ash.yaml")
    assert source == str(tmp_path.resolve() / "real" / "ash.yaml")


def test_dot_dot_after_a_real_directory_names_its_parent(
    pwsh, recording_docker, tmp_path
):
    """Control: with no link, ``x/../ash.yaml`` is ``ash.yaml`` beside ``x``."""
    (tmp_path / "src").mkdir()
    (tmp_path / "x").mkdir()
    (tmp_path / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir out -Config x/../ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    source = _mount_source(_recorded(tmp_path), "/ash-config/ash.yaml")
    assert source == str(tmp_path.resolve() / "ash.yaml")


def test_an_output_directory_that_is_the_source_through_dot_dot_after_a_link_is_refused(
    pwsh, recording_docker, tmp_path
):
    """``L/a/..`` with ``a`` a link to ``s/src/inner`` is ``s/src``, the source,
    though its lexical form ``L`` is unrelated to it."""
    (tmp_path / "s" / "src" / "inner").mkdir(parents=True)
    (tmp_path / "L").mkdir()
    (tmp_path / "L" / "a").symlink_to(
        tmp_path / "s" / "src" / "inner", target_is_directory=True
    )

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir s/src -OutputDir L/a/.."
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "above it" in _stderr(result)


# ---------------------------------------------------------------------------
# A relative path is resolved from PowerShell's location, for the check and the scan
# ---------------------------------------------------------------------------


def test_a_relative_path_is_taken_from_the_powershell_location(
    pwsh, recording_docker, tmp_path
):
    """Push-Location moves PowerShell's location and not the process's working
    directory. The directory that exists for PowerShell is the one that is mounted,
    and the output is created beside it."""
    project = (tmp_path / "proj").resolve()
    (project / "sub").mkdir(parents=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir sub -OutputDir out",
        before=f"Push-Location '{project.as_posix()}';",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _mount_source(args, "/src") == str(project / "sub")
    assert _mount_source(args, "/out") == str(project / "out")
    assert (project / "out").is_dir()
    assert not (tmp_path / "out").exists()


def test_a_tilde_output_directory_is_the_home_directory(
    pwsh, recording_docker, tmp_path
):
    """PowerShell reads ``~`` as the home directory, as it does for every command."""
    home = (tmp_path / "home").resolve()
    home.mkdir()
    (tmp_path / "src").mkdir()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir ~/ash-out",
        home=home,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _mount_source(_recorded(tmp_path), "/out") == str(home / "ash-out")
    assert (home / "ash-out").is_dir()
    assert not (tmp_path / "~").exists()


def test_a_tilde_config_is_the_file_in_the_home_directory(
    pwsh, recording_docker, tmp_path
):
    home = (tmp_path / "home").resolve()
    home.mkdir()
    (home / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    (tmp_path / "src").mkdir()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir out -Config ~/ash.yaml",
        home=home,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"
    assert _mount_source(args, "/ash-config/ash.yaml") == str(home / "ash.yaml")


# ---------------------------------------------------------------------------
# A '..' that leaves a link in the scanned tree is judged at the link
# ---------------------------------------------------------------------------


def test_a_config_named_through_dot_dot_after_a_committed_link_out_is_refused(
    pwsh, recording_docker, checkout, tmp_path
):
    """``svc/lnk/../ash.yaml`` with ``lnk`` a link the repository committed to a
    directory outside it names a file outside the tree, through a name inside it."""
    (tmp_path / "operator" / "sub").mkdir()
    (tmp_path / "operator" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "svc" / "lnk").symlink_to(
        tmp_path / "operator" / "sub", target_is_directory=True
    )

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/svc/lnk/../ash.yaml",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "link" in result.stderr


def test_a_config_named_through_dot_dot_after_a_real_directory_in_the_tree_runs(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: with no link on the way, the '..' names the file beside the directory."""
    (checkout / "svc" / "x").mkdir()
    (checkout / "svc" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/svc/x/../ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/src/ash.yaml"


# ---------------------------------------------------------------------------
# On a host that ignores case, the /src mapping still compares the exact spelling
# ---------------------------------------------------------------------------


def test_a_config_in_a_directory_that_differs_in_case_is_mounted_on_its_own(
    pwsh, recording_docker, tmp_path
):
    """On macOS the case-insensitive comparison is also used to decide that a path
    is in a tree, which can only refuse or mark more. Whether the config is handed to
    the scan as ``/src/<path>`` decides which file is read, so it compares the exact
    spelling: ``Proj`` is not ``proj`` on a case-sensitive volume, and the operator's
    file is mounted, not the source's. The host is made to read as case-insensitive
    by redefining the one function that says so; the file system under the cell is
    case-sensitive."""
    (tmp_path / "proj").mkdir()
    try:
        (tmp_path / "Proj").mkdir()
    except FileExistsError:
        pytest.skip("this file system ignores case, so the two names are one directory")
    (tmp_path / "Proj" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir proj -OutputDir out -Config Proj/ash.yaml",
        before="function Test-AshCaseInsensitiveHost { $true };",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"
    assert _mount_source(args, "/ash-config/ash.yaml") == str(
        tmp_path.resolve() / "Proj" / "ash.yaml"
    )
