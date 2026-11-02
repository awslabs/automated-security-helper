# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bash wrapper shares the operator's config as ``ash --mode container`` does.

``./ash`` runs the scan inside a container that sees the host only through its
mounts, so a host config path names nothing there. ``ash --mode container``
(interactions/run_ash_container.py) already carries both config inputs across
that boundary: a ``--config`` inside the source directory is read through the
read-only ``/src`` mount, one outside it is mounted read-only on its own under
``/ash-config``, and the file the host's ``ASH_CONFIG`` names is mounted under
``/ash-env-config`` and handed to the scan with ``--ash-config-from-host``.
The wrapper used to forward ``--config`` as the host path and drop ``ASH_CONFIG``
with a warning; this file pins it to the launcher's contract instead:

- a ``--config`` outside the source directory is mounted read-only by its real
  path, in every name a mount can take, and the scan inside is given its
  container path;
- a config the scanned repository wrote, by its resolved path or by the name
  that reached it, is marked (``--config-from-scanned-repository``, or
  ``--config-file-from-scanned-repository`` for the ``ASH_CONFIG`` file), as
  ``_config_marks`` and ``_env_config_marks`` mark it;
- a missing or unreadable config, a config linked out of the scanned tree, and
  an outside config with an ``extends`` entry (which the wrapper cannot mount
  as a chain) are refused with exit 3 before any build, in the launcher's words;
- for the same layouts, ``./ash`` and ``_assemble_run_command`` reach the same
  decision, including a relative name taken from a working directory reached
  through a link: the name is read from the physical directory and, when
  ``$PWD`` spells it another way, from ``$PWD`` too, so a link the shell stands
  below that the scanned tree holds makes the name the tree's;
- with no ``--config``, the ``ASH_CONFIG`` file is the scan's ``--config`` even
  when the source directory holds a config of its own, as it is on the command
  line, where the variable is the option's value;
- the handling applies to a scan (no subcommand, or ``scan``), where the inner
  CLI declares the provenance options; another subcommand keeps its words as
  written, and ``ASH_CONFIG`` is then still named in a warning rather than
  dropped silently.

An in-source config travels whole inside ``/src``, so its ``extends`` chain
resolves there and is not second-guessed here; an absolute base in it is the
scan's own refusal inside the container, as the chain is never mounted.

``./ash`` runs against a fake OCI runner that records each invocation, on a
PATH holding only the tools the wrapper needs, so no case here can reach a
real container runner.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess  # nosec B404 - running the repository's own wrapper script is the point
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from automated_security_helper.config.config_sources import read_config_file
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from tests.utils.config_link_layouts import (
    LINKS_IN_ANOTHER_CHECKOUT,
    NAMES_STEERED_BY_THE_SCANNED_CHECKOUT,
    config_through_links,
)
from tests.utils.helpers import mark_git_checkout

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
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

#: The utilities ./ash needs besides bash builtins and the runner: the config
#: handling resolves links (readlink), walks directories (dirname, basename)
#: and reads an outside config's text for the extends check (tr, grep).
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

#: Records each call's arguments NUL-separated, one file per call, and succeeds.
_FAKE_RUNNER = """#!/bin/bash
n=$(cat "$FAKE_RUNNER_COUNT" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$FAKE_RUNNER_COUNT"
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$n")"
exit 0
"""

#: The same names the launcher's mount tests give it: every shape a mount's
#: source can take. A comma, a double quote or a newline cannot (the runtimes
#: read --mount as CSV), and require_mountable refuses those before any call.
UNUSUAL_NAMES = [
    pytest.param("plain", id="plain"),
    pytest.param("with space", id="space"),
    pytest.param("dollar$HOME", id="dollar"),
    pytest.param("glob*?[ab]", id="glob"),
    pytest.param("semi;colon&amp", id="shell-punctuation"),
    pytest.param("quote'single", id="single-quote"),
    pytest.param("uniéü", id="non-ascii"),
    pytest.param("eq=sign", id="equals"),
    pytest.param("-leading-dash", id="leading-dash"),
    pytest.param("back\\slash", id="backslash"),
    pytest.param("tab\there", id="tab"),
]


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
    """Run ./ash against the fake runner: (returncode, stdout and stderr, calls)."""
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


def _only_run(calls: List[List[str]]) -> List[str]:
    runs = [call for call in calls if call and call[0] == "run"]
    assert len(runs) == 1, f"expected one `run` call, got {calls}"
    return runs[0]


def _mounts(call: List[str]) -> Dict[str, Dict[str, object]]:
    found: Dict[str, Dict[str, object]] = {}
    for i, arg in enumerate(call[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, object] = {}
        for part in call[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else True
        destination = str(options.get("destination"))
        assert destination not in found, f"two mounts at {destination}: {call}"
        found[destination] = options
    return found


def _inner_args(call: List[str]) -> List[str]:
    return call[call.index("ash") + 1 :]


def _flag(args: List[str], flag: str) -> Optional[str]:
    values = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == flag]
    assert len(values) <= 1, f"more than one {flag} in {args}"
    return values[0] if values else None


# ---------------------------------------------------------------------------
# ./ash --config: mounted or rewritten so the scan inside can read it
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("name", UNUSUAL_NAMES)
def test_a_config_outside_the_source_is_mounted_read_only_by_its_real_path(
    name, fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / f"operator {name}"
    operator.mkdir()
    config = operator / f"ash {name}.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _flag(_inner_args(run), "--config")
    assert inner == f"/ash-config/ash {name}.yaml"
    mounts = _mounts(run)
    assert set(mounts) == {"/src", "/out", inner}
    assert Path(str(mounts[inner]["source"])) == config.resolve()
    assert mounts[inner].get("readonly") is True


@pytest.mark.integration
def test_a_config_inside_the_source_is_read_through_src(fake_runner, tmp_path):
    source = tmp_path / "project"
    (source / ".ash").mkdir(parents=True)
    config = source / ".ash" / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    assert _flag(_inner_args(run), "--config") == "/src/.ash/strict.yaml"
    assert set(_mounts(run)) == {"/src", "/out"}


@pytest.mark.integration
def test_a_missing_config_is_refused_before_any_build(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--config", str(tmp_path / "absent.yaml")],
    )

    assert rc == 3, output_text
    assert calls == [], f"the runner was called: {calls}"
    assert "Config file not found:" in output_text
    assert "--config (or ASH_CONFIG) has to name an existing file" in output_text


@pytest.mark.integration
def test_a_trailing_config_with_no_value_is_refused(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    rc, output_text, calls = _run_ash(fake_runner, source, ["--no-build", "--config"])

    assert rc == 3, output_text
    assert calls == [], calls
    assert "Config file not found:" in output_text


@pytest.mark.integration
@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: -1)() == 0,
    reason="root reads an unreadable file anyway",
)
def test_an_unreadable_config_is_refused(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    config.chmod(0)
    try:
        rc, output_text, calls = _run_ash(
            fake_runner, source, ["--config", str(config)]
        )
    finally:
        config.chmod(0o600)

    assert rc == 3, output_text
    assert calls == [], calls
    assert "Config file cannot be read:" in output_text
    assert "ASH does not hand the container runner a file it cannot read" in output_text


@pytest.mark.integration
def test_a_config_linked_out_of_the_scanned_tree_is_refused(fake_runner, tmp_path):
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = source / "strict.yaml"
    config.symlink_to(operator / "ash.yaml")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "is inside the scanned tree but is a link" in output_text
    assert "ASH does not mount a file the repository being scanned points it at" in (
        output_text
    )


@pytest.mark.integration
def test_a_config_through_an_outside_link_loop_is_refused(fake_runner, tmp_path):
    """Two links pointing at each other, outside every checkout: the name
    resolves to no file, so it is refused before any runner call, never
    handed to the runner as it stands. The existence check is the one that
    answers, and the text says so: the walk's own refusal is pinned by the
    cells below, which reach it."""
    source = tmp_path / "src"
    source.mkdir()
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(first)],
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "Config file not found:" in output_text, output_text
    assert "cannot be resolved" not in output_text, output_text


#: A readlink as BSD ships it before macOS 12.3: it has no -f. Anything else
#: runs the real one.
_READLINK_WITHOUT_F = """#!/bin/bash
for word in "$@"; do
  if [ "$word" = "-f" ]; then
    echo "readlink: illegal option -- f" >&2
    exit 1
  fi
done
exec "$REAL_READLINK" "$@"
"""

#: A readlink that reads the link named in UNREADABLE_LINK READS_ALLOWED times
#: and refuses it after that, as a link replaced between two reads would.
_READLINK_THAT_STOPS_READING_ONE_LINK = """#!/bin/bash
for word in "$@"; do
  if [ "$word" = "$UNREADABLE_LINK" ]; then
    n=$(cat "$READS_FILE" 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > "$READS_FILE"
    if [ "$n" -gt "$READS_ALLOWED" ]; then
      echo "readlink: $word: Permission denied" >&2
      exit 1
    fi
  fi
done
exec "$REAL_READLINK" "$@"
"""


def _use_readlink(fake_runner, script: str) -> Dict[str, str]:
    """Put *script* in place of the wrapper's readlink; the environment it needs."""
    stub = fake_runner[0] / "readlink"
    stub.unlink()
    stub.write_text(script, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    real = shutil.which("readlink")
    assert real, "readlink is not installed; ./ash needs it"
    return {"REAL_READLINK": real}


@pytest.mark.integration
def test_a_config_through_a_link_the_walk_cannot_read_is_refused(fake_runner, tmp_path):
    """The walk reads the link a second time and cannot: the name cannot be
    decided, so it is refused with the walk's own text before any runner
    call, not carried on with the link unresolved."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
    link = operator / "ash-link.yaml"
    link.symlink_to(operator / "real.yaml")
    env = _use_readlink(fake_runner, _READLINK_THAT_STOPS_READING_ONE_LINK)
    env.update(
        {
            "UNREADABLE_LINK": str(link),
            "READS_FILE": str(tmp_path / "link-reads"),
            "READS_ALLOWED": "1",
        }
    )

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(link)],
        extra_env=env,
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "goes through a link that cannot be resolved" in output_text, output_text
    assert "Config file" not in output_text, output_text


@pytest.mark.integration
@pytest.mark.parametrize("layout", ["directory-link", "file-link"])
def test_a_config_through_an_outside_link_is_carried_where_readlink_has_no_f(
    layout, fake_runner, tmp_path
):
    """The walk collapses a link outside every checkout the way the rest of
    the script reads links, not with ``readlink -f``, which BSD readlink
    lacks before macOS 12.3: there a collapse that failed refused every name
    through the host's own ``/tmp`` or ``/etc``."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    (operator / "real").mkdir(parents=True)
    (operator / "real" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    if layout == "directory-link":
        (operator / "lnk").symlink_to(operator / "real", target_is_directory=True)
        given = operator / "lnk" / "ash.yaml"
    else:
        given = operator / "ash-link.yaml"
        given.symlink_to(operator / "real" / "ash.yaml")
    env = _use_readlink(fake_runner, _READLINK_WITHOUT_F)

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(given)],
        extra_env=env,
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _flag(_inner_args(run), "--config")
    assert inner == "/ash-config/ash.yaml"
    mounts = _mounts(run)
    assert (
        Path(str(mounts[inner]["source"])) == (operator / "real" / "ash.yaml").resolve()
    )
    assert mounts[inner].get("readonly") is True


@pytest.mark.integration
def test_an_outside_parent_dir_link_does_not_hide_an_in_tree_link(
    fake_runner, tmp_path
):
    """A directory link whose target is ``..`` collapses to the parent
    directory itself, never to a spelling ending in ``/..``: the tree tests
    read the walked spelling as a literal prefix, so a name that goes on
    through the collapsed directory into the scanned tree still meets the
    tree's own link there, and the refusal is that link's."""
    base = tmp_path / "base"
    operator = base / "op"
    operator.mkdir(parents=True)
    (operator / "up").symlink_to("..", target_is_directory=True)
    checkout = base / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: p\n", encoding="utf-8")
    (checkout / "cfg-link.yaml").symlink_to(outside)
    given = operator / "up" / "repo" / "cfg-link.yaml"

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(given)],
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "is inside the scanned tree but is a link" in output_text, output_text
    assert "ASH does not mount a file the repository being scanned points it at" in (
        output_text
    )


# ---------------------------------------------------------------------------
# ./ash: an outside config with an extends entry is refused in every spelling
# ---------------------------------------------------------------------------

#: (id, file name, text): spellings ASH reads as an ``extends`` entry.
_EXTENDS_SPELLING_TABLE = [
    ("yaml", "ash.yaml", "extends: base.yaml\n"),
    ("json", "ash.json", '{"extends": "base.json"}\n'),
    ("toml", "ash.toml", 'extends = "base.toml"\n'),
    (
        "json-key-and-colon-on-two-lines",
        "ash.json",
        '{\n  "extends"\n  : "base.json"\n}\n',
    ),
    ("yaml-escaped-key", "ash.yaml", '"ext\\x65nds": base.yaml\n'),
    ("yaml-complex-key", "ash.yaml", "? extends\n: base.yaml\n"),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "text"),
    [pytest.param(name, text, id=id_) for id_, name, text in _EXTENDS_SPELLING_TABLE],
)
def test_the_spelling_is_an_extends_entry_to_ash(name, text, tmp_path):
    """The precondition for the wrapper test below: ASH reads each one as ``extends``."""
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    assert "extends" in read_config_file(config)


@pytest.mark.integration
@pytest.mark.parametrize(
    ("name", "text"),
    [pytest.param(name, text, id=id_) for id_, name, text in _EXTENDS_SPELLING_TABLE],
)
def test_the_bash_wrapper_refuses_an_outside_config_that_extends(
    name, text, fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / name
    config.write_text(text, encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 3, output_text
    assert calls == [], f"the runner was called: {calls}"
    assert "extends" in output_text


# ---------------------------------------------------------------------------
# ./ash and the Python launcher reach the same decision for the same layout
# ---------------------------------------------------------------------------


def _assemble(source_dir: Path, output_dir: Path, config: Optional[str]) -> List[str]:
    return rac._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:non-root",
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


def _decision(run: List[str], inner: List[str]) -> Dict[str, object]:
    mounts = _mounts(run)
    return {
        "refused": False,
        "config": _flag(inner, "--config"),
        "env_config": _flag(inner, rac.ASH_CONFIG_FROM_HOST_FLAG),
        "from_repository": rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in inner,
        "marked_files": sorted(
            inner[i + 1]
            for i, arg in enumerate(inner[:-1])
            if arg == rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG
        ),
        "another_checkout_files": sorted(
            inner[i + 1]
            for i, arg in enumerate(inner[:-1])
            if arg == rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG
        ),
        "src": (
            Path(str(mounts["/src"]["source"])).resolve(),
            mounts["/src"].get("readonly"),
        ),
        "config_sources": sorted(
            str(Path(str(options["source"])).resolve())
            for destination, options in mounts.items()
            if destination not in ("/src", "/out")
        ),
    }


def _python_decision(
    source: Path, output: Path, config: Optional[Path]
) -> Dict[str, object]:
    """``run_ash_container`` resolves the source directory before it builds this."""
    try:
        cmd = _assemble(
            source.resolve(), output.resolve(), None if config is None else str(config)
        )
    except rac.ContainerInputError:
        return {"refused": True}
    inner = cmd[cmd.index("automated-security-helper:non-root") + 2 :]
    return _decision(cmd, inner)


def _bash_decision(
    fake_runner,
    source: Path,
    output: Path,
    config: Optional[Path],
    cwd: Path,
    extra_env: Optional[Dict[str, str]] = None,
):
    args = ["--no-build", "--source-dir", str(source), "--output-dir", str(output)]
    if config is not None:
        args.extend(["--config", str(config)])
    rc, output_text, calls = _run_ash(fake_runner, cwd, args, extra_env)
    if rc == 3 and not calls:
        return {"refused": True}
    assert rc == 0, output_text
    run = _only_run(calls)
    return _decision(run, _inner_args(run))


#: The layouts with a link in another checkout, by the id this file gives them.
LINKS_IN_ANOTHER_CHECKOUT_LAYOUTS = {
    "link-in-another-checkout": LINKS_IN_ANOTHER_CHECKOUT[0],
    "named-as-a-link-in-another-checkout": LINKS_IN_ANOTHER_CHECKOUT[1],
}

#: The layouts a local scan counts as in a git checkout other than the scanned one.
_MARKED_AS_ANOTHER_CHECKOUT = {
    "in-another-checkout",
    "link-in-another-checkout",
    "named-as-a-link-in-another-checkout",
}

_CONFIG_LAYOUTS = [
    "inside-the-source",
    "link-inside-the-source-to-inside",
    "outside-the-checkout",
    "elsewhere-in-the-checkout",
    "link-in-the-source-out-of-the-checkout",
    "directory-link-out-of-the-checkout",
    "link-elsewhere-in-the-checkout-out-of-it",
    "elsewhere-in-the-checkout-source-named-through-a-link",
    "in-another-checkout",
    "link-in-another-checkout",
    "named-as-a-link-in-another-checkout",
    "beside-an-empty-git-directory",
    "name-climbs-from-the-checkout-to-the-operators-file",
]


def _layout(layout: str, tmp_path: Path) -> Tuple[Path, Path, Path]:
    """(source, output, config) for one of the shared layouts."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
    source = checkout / "services" / "api"
    (source / ".ash").mkdir(parents=True)
    (checkout / "ci").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: operator\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    if layout == "inside-the-source":
        config = source / ".ash" / "strict.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
    elif layout == "link-inside-the-source-to-inside":
        (source / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
        config = source / ".ash" / "strict.yaml"
        config.symlink_to(source / "real.yaml")
    elif layout == "outside-the-checkout":
        config = operator / "ash.yaml"
    elif layout == "elsewhere-in-the-checkout":
        config = checkout / "ci" / "ash.yaml"
        config.write_text("project_name: ci\n", encoding="utf-8")
    elif layout == "link-in-the-source-out-of-the-checkout":
        config = source / ".ash" / "strict.yaml"
        config.symlink_to(operator / "ash.yaml")
    elif layout == "directory-link-out-of-the-checkout":
        (source / "conf").symlink_to(operator, target_is_directory=True)
        config = source / "conf" / "ash.yaml"
    elif layout == "discoverable-in-the-source":
        # The file a scan of this directory finds without being told, so the
        # variable's file is not the only candidate.
        config = source / ".ash" / ".ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
    elif layout == "link-elsewhere-in-the-checkout-out-of-it":
        config = checkout / "ci" / "ash.yaml"
        config.symlink_to(operator / "ash.yaml")
    elif layout == "in-another-checkout":
        # An ops repository beside the scanned one: not the scanned tree's, and
        # not the operator's either.
        mark_git_checkout(tmp_path / "ops")
        config = tmp_path / "ops" / "ash.yaml"
        config.write_text("project_name: ops\n", encoding="utf-8")
    elif layout in LINKS_IN_ANOTHER_CHECKOUT_LAYOUTS:
        config = config_through_links(
            LINKS_IN_ANOTHER_CHECKOUT_LAYOUTS[layout], checkout, tmp_path
        )
    elif layout == "beside-an-empty-git-directory":
        # Control: a bare empty .git is not a checkout boundary, so the file is
        # the operator's on every route.
        (tmp_path / "ops" / ".git").mkdir(parents=True)
        config = tmp_path / "ops" / "ash.yaml"
        config.write_text("project_name: ops\n", encoding="utf-8")
    elif layout == "name-climbs-from-the-checkout-to-the-operators-file":
        # The directories above the name as spelled lead to the scanned checkout's
        # .git, but each ".." is applied as the kernel applies it: the file is in
        # the operator directory beside the checkout, in no checkout, so it is the
        # operator's own on every route.
        config = Path(f"{checkout}/ci/../../operator/ash.yaml")
    else:
        # The checkout is found from the source's real path as well as its name.
        config = checkout / "ci" / "ash.yaml"
        config.write_text("project_name: ci\n", encoding="utf-8")
        named = tmp_path / "alias"
        named.symlink_to(source, target_is_directory=True)
        source = named
    return source, output, config


@pytest.mark.integration
@pytest.mark.parametrize("layout", _CONFIG_LAYOUTS)
def test_the_bash_wrapper_and_the_launcher_agree_on_config(
    layout, fake_runner, tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source, output, config = _layout(layout, tmp_path)

    python = _python_decision(source, output, config)
    bash = _bash_decision(fake_runner, source, output, config, tmp_path)

    assert bash == python
    if not python["refused"]:
        assert python["src"] == (source.resolve(), True)
    if layout.startswith("elsewhere-in-the-checkout"):
        assert python["from_repository"] is True
    if "out-of" in layout:
        assert python["refused"] is True
    if layout in _MARKED_AS_ANOTHER_CHECKOUT:
        # The launcher and the wrapper both say it: not the scanned tree's, so
        # no scanned-tree mark, and in another checkout, by its container path.
        assert python["from_repository"] is False
        assert python["marked_files"] == []
        assert python["another_checkout_files"] == ["/ash-config/ash.yaml"]
    elif not python["refused"]:
        assert python["another_checkout_files"] == []
    if layout == "name-climbs-from-the-checkout-to-the-operators-file":
        assert python["refused"] is False
        assert python["from_repository"] is False
        assert python["marked_files"] == []


def _as_the_command_line_passes_it(decision: Dict[str, object]) -> Dict[str, object]:
    """*decision* with the scan's ``--config`` reduced to whether it is named
    and the mounted host files reduced to a set.

    On the command line the variable is ``--config``'s value, so the launcher is
    handed the file as ``config`` and the same file again through the
    environment: it mounts the file under ``/ash-config`` for the option and
    under ``/ash-env-config`` for the variable, where ``./ash`` mounts it once
    and names that one path for both. The container paths differ and the same
    host file is listed twice, so only whether a ``--config`` is named, which
    host files are mounted and which file names a mark for another checkout
    (once, whichever container path) are compared.
    """
    return {
        **decision,
        "config": decision.get("config") is not None,
        "config_sources": sorted(set(decision.get("config_sources", []))),
        "another_checkout_files": sorted(
            {Path(name).name for name in decision.get("another_checkout_files", [])}
        ),
    }


@pytest.mark.integration
@pytest.mark.parametrize(
    "layout",
    [
        "inside-the-source",
        "outside-the-checkout",
        "elsewhere-in-the-checkout",
        "link-in-the-source-out-of-the-checkout",
        "discoverable-in-the-source",
        "in-another-checkout",
        "link-in-another-checkout",
        "beside-an-empty-git-directory",
        "name-climbs-from-the-checkout-to-the-operators-file",
    ],
)
def test_the_bash_wrapper_and_the_launcher_agree_on_ash_config(
    layout, fake_runner, tmp_path, monkeypatch
):
    source, output, env_config = _layout(layout, tmp_path)

    # The launcher's API entry (``config=None``) asks discovery first, which is
    # the right rule for a caller that never passes through the CLI's option.
    # ``./ash`` is the command line: the variable is the option's value, so the
    # launcher it matches is the one a command-line scan reaches, handed the
    # file as its ``config``.
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    python = _as_the_command_line_passes_it(
        _python_decision(source, output, env_config)
    )
    monkeypatch.delenv("ASH_CONFIG")
    bash = _as_the_command_line_passes_it(
        _bash_decision(
            fake_runner, source, output, None, tmp_path, {"ASH_CONFIG": str(env_config)}
        )
    )

    assert bash == python
    if not python["refused"]:
        # With no --config given, the ASH_CONFIG file is also the scan's --config.
        assert python["config"] is True
    if layout == "elsewhere-in-the-checkout":
        assert python["marked_files"], python
        assert python["from_repository"] is True
    if layout in _MARKED_AS_ANOTHER_CHECKOUT:
        # The file is the ops repository's: no scanned-tree mark of either kind,
        # and one mark for another checkout (the launcher names two container
        # paths for the one host file, the wrapper one; the normal form above
        # keeps the file name).
        assert python["from_repository"] is False
        assert python["marked_files"] == []
        assert python["another_checkout_files"] == ["ash.yaml"]
    elif not python["refused"]:
        assert python["another_checkout_files"] == []
    if layout == "name-climbs-from-the-checkout-to-the-operators-file":
        assert python["refused"] is False
        assert python["from_repository"] is False
        assert python["marked_files"] == []
    if "out-of" in layout:
        assert python["refused"] is True


@pytest.mark.unit
def test_the_root_command_and_the_scan_command_read_the_same_config_variable():
    """The command line reaches the scan through the root command or ``scan``,
    and both declare ``--config`` from one function, so the variable is the
    option's value on either."""
    import typer

    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    (root_option,) = [p for p in command.params if "--config" in p.opts]
    (scan_option,) = [
        p for p in command.commands["scan"].params if "--config" in p.opts
    ]

    assert root_option.envvar == scan_option.envvar == "ASH_CONFIG"


def _working_directory_layout(kind: str, tmp_path: Path):
    """(working directory as the operator's shell names it, source, output,
    config as given) for a working directory reached through a link."""
    output = tmp_path / "out"
    output.mkdir()
    if kind.startswith("checkout-alias"):
        # ~/repo is a link to the real checkout; the config sits beside it.
        real = tmp_path / "data" / "repo"
        (real / ".git").mkdir(parents=True)
        (real / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
        shared = tmp_path / "data" / "shared"
        shared.mkdir()
        (shared / "ash.yaml").write_text("project_name: shared\n", encoding="utf-8")
        alias = tmp_path / "home" / "repo"
        alias.parent.mkdir()
        alias.symlink_to(real, target_is_directory=True)
        if kind == "checkout-alias-absolute":
            return alias, alias, output, alias / ".." / "shared" / "ash.yaml"
        return alias, alias, output, Path("../shared/ash.yaml")
    # A link inside the scanned checkout, to a directory outside it, with the
    # operator's shell standing in a directory below the link.
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
    target = tmp_path / "elsewhere" / "dir"
    (target / "sub").mkdir(parents=True)
    (target / "cfg.yaml").write_text("project_name: operator\n", encoding="utf-8")
    (repo / "lnk").symlink_to(target, target_is_directory=True)
    return repo / "lnk" / "sub", repo, output, Path("../cfg.yaml")


@pytest.mark.integration
@pytest.mark.parametrize(
    "kind",
    [
        "checkout-alias-absolute",
        "checkout-alias-relative",
    ],
)
def test_the_wrapper_and_the_launcher_agree_through_a_checkout_alias(
    kind, fake_runner, tmp_path, monkeypatch
):
    """The checkout is reached through a link of the operator's own, with the
    config beside the real checkout. That link sits outside every scanned tree,
    so walking the name from ``$PWD`` as well as from the physical directory
    still lands the config outside the tree: both accept it (the absolute
    spelling isolates the link test, the relative one the working directory)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd, source, output, config = _working_directory_layout(kind, tmp_path)

    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PWD", str(cwd))
    python = _python_decision(source, output, config)
    bash = _bash_decision(fake_runner, source, output, config, cwd, {"PWD": str(cwd)})

    assert python["refused"] is False, python
    assert bash == python


@pytest.mark.integration
def test_the_launcher_judges_a_relative_config_from_the_directory_the_shell_names(
    tmp_path, monkeypatch
):
    """The shell stands below a link the scanned checkout holds, and the config
    is named ``../cfg.yaml``. The kernel reads it from the physical directory,
    but read from where the shell stands it walks the checkout's link, so the
    repository chose which file the name reaches: refused, not handed over as
    the operator's."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd, source, output, config = _working_directory_layout(
        "tree-link-below-the-working-directory", tmp_path
    )

    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PWD", str(cwd))
    python = _python_decision(source, output, config)

    assert python["refused"] is True, python


@pytest.mark.integration
def test_the_launcher_reads_a_relative_config_from_the_physical_directory_without_pwd(
    tmp_path, monkeypatch
):
    """The control for the cell above: with ``$PWD`` unset the name is read from
    the physical directory only, as before, so the same layout is accepted."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd, source, output, config = _working_directory_layout(
        "tree-link-below-the-working-directory", tmp_path
    )

    monkeypatch.chdir(cwd)
    monkeypatch.delenv("PWD", raising=False)
    python = _python_decision(source, output, config)

    assert python["refused"] is False, python


@pytest.mark.integration
def test_the_bash_wrapper_judges_a_relative_config_from_the_directory_the_shell_names(
    fake_runner, tmp_path, monkeypatch
):
    """The wrapper's side of the cell above: the same layout, exit 3 before any
    runner call, in the launcher's words for a link out of the tree."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd, source, output, config = _working_directory_layout(
        "tree-link-below-the-working-directory", tmp_path
    )

    rc, output_text, calls = _run_ash(
        fake_runner,
        cwd,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(output)]
        + ["--config", str(config)],
        {"PWD": str(cwd)},
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "is inside the scanned tree but is a link" in output_text, output_text


@pytest.mark.integration
def test_the_bash_wrapper_reads_a_relative_config_from_the_physical_directory_without_pwd(
    fake_runner, tmp_path, monkeypatch
):
    """The control for the cell above: with ``$PWD`` naming no directory the
    name is read from the physical directory only, and the layout is accepted."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd, source, output, config = _working_directory_layout(
        "tree-link-below-the-working-directory", tmp_path
    )

    bash = _bash_decision(
        fake_runner, source, output, config, cwd, {"PWD": str(tmp_path / "missing")}
    )

    assert bash["refused"] is False, bash


@pytest.mark.integration
@pytest.mark.parametrize("pwd_names_the_directory", [True, False])
def test_a_relative_config_reached_through_an_operators_link_to_a_tree_link_is_marked(
    pwd_names_the_directory, fake_runner, tmp_path, monkeypatch
):
    """The shell stands below a link of the operator's own, which leads to a link
    the checkout holds. Read from the physical directory the name lands outside
    the tree through no link in it; read from where the shell stands, the walk
    passes the checkout's link, so the file is the repository's to steer and is
    marked as such (it is not refused: the operator's link hides the tree link
    from the name's own walk). Without ``$PWD`` naming that directory nothing
    marks it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
    target = tmp_path / "elsewhere" / "dir"
    (target / "sub").mkdir(parents=True)
    (target / "cfg.yaml").write_text("project_name: operator\n", encoding="utf-8")
    (repo / "lnk").symlink_to(target, target_is_directory=True)
    alias = tmp_path / "home" / "alias"
    alias.parent.mkdir()
    alias.symlink_to(repo / "lnk", target_is_directory=True)
    cwd = alias / "sub"
    output = tmp_path / "out"
    output.mkdir()
    config = Path("../cfg.yaml")

    monkeypatch.chdir(cwd)
    if pwd_names_the_directory:
        pwd = str(cwd)
        monkeypatch.setenv("PWD", pwd)
    else:
        pwd = str(tmp_path / "missing")
        monkeypatch.delenv("PWD", raising=False)
    python = _python_decision(repo, output, config)
    bash = _bash_decision(fake_runner, repo, output, config, cwd, {"PWD": pwd})

    assert python["refused"] is False, python
    assert python["from_repository"] is pwd_names_the_directory, python
    assert bash == python


@pytest.mark.integration
@pytest.mark.parametrize("pwd_names_the_directory", [True, False])
def test_a_relative_config_below_a_link_in_another_checkout_is_marked_from_where_the_shell_stands(
    pwd_names_the_directory, fake_runner, tmp_path, monkeypatch
):
    """The shell stands below a link an ops checkout holds, which leads to a
    directory outside every checkout, and the config is named ``../cfg.yaml``.
    Read from the physical directory the name reaches a file in no checkout; read
    from where the shell stands, the walk passes the checkout's link, so a local
    scan counts the file as in that checkout. Both entrypoints read ``$PWD`` the
    same way: with it naming the directory the file is marked as in another
    checkout, without it nothing marks it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    target = tmp_path / "elsewhere" / "dir"
    (target / "sub").mkdir(parents=True)
    (target / "cfg.yaml").write_text("project_name: operator\n", encoding="utf-8")
    (ops / "lnk").symlink_to(target, target_is_directory=True)
    cwd = ops / "lnk" / "sub"
    output = tmp_path / "out"
    output.mkdir()
    config = Path("../cfg.yaml")

    monkeypatch.chdir(cwd)
    if pwd_names_the_directory:
        pwd = str(cwd)
        monkeypatch.setenv("PWD", pwd)
    else:
        pwd = str(tmp_path / "missing")
        monkeypatch.delenv("PWD", raising=False)
    python = _python_decision(repo, output, config)
    bash = _bash_decision(fake_runner, repo, output, config, cwd, {"PWD": pwd})

    assert python["refused"] is False, python
    assert python["from_repository"] is False, python
    expected = ["/ash-config/cfg.yaml"] if pwd_names_the_directory else []
    assert python["another_checkout_files"] == expected, python
    assert bash == python


@pytest.mark.integration
@pytest.mark.parametrize("given_as", ["config", "environment"])
def test_a_config_named_through_a_tree_link_and_back_out_is_refused_by_both(
    given_as, fake_runner, tmp_path, monkeypatch
):
    """``<checkout>/lnk/../cfg.yaml`` with ``lnk`` a link the checkout holds: the
    kernel follows the link before the ``..``, so the name reaches the file
    beside the link's target, which the repository chose. Neither entrypoint
    reads it as the checkout's own ``cfg.yaml``."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/scan\n", encoding="utf-8")
    (repo / "cfg.yaml").write_text("project_name: repo\n", encoding="utf-8")
    target = tmp_path / "elsewhere" / "dir"
    target.mkdir(parents=True)
    (target.parent / "cfg.yaml").write_text("project_name: other\n", encoding="utf-8")
    (repo / "lnk").symlink_to(target, target_is_directory=True)
    output = tmp_path / "out"
    output.mkdir()
    given = Path(f"{repo}/lnk/../cfg.yaml")

    if given_as == "config":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        python = _python_decision(repo, output, given)
        bash = _bash_decision(fake_runner, repo, output, given, tmp_path)
    else:
        monkeypatch.setenv("ASH_CONFIG", str(given))
        python = _python_decision(repo, output, None)
        monkeypatch.delenv("ASH_CONFIG")
        bash = _bash_decision(
            fake_runner, repo, output, None, tmp_path, {"ASH_CONFIG": str(given)}
        )

    assert python["refused"] is True, python
    assert bash["refused"] is True, bash


# ---------------------------------------------------------------------------
# ./ash ASH_CONFIG names the scan's config, as the CLI's --config option does
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_scan_option_reads_ash_config_from_the_environment():
    """The precondition of the next cell: on the command line the variable is
    the ``--config`` option's value, so the file is the scan's config and an
    option wins over discovery. The launcher's discovery-first rule is for a
    caller that never passes through this option."""
    import typer

    from automated_security_helper.cli.main import app

    scan = typer.main.get_command(app).commands["scan"]
    (option,) = [p for p in scan.params if "--config" in p.opts]

    assert option.envvar == "ASH_CONFIG"


@pytest.mark.integration
def test_ash_config_is_the_scans_config_even_when_the_source_holds_one(
    fake_runner, tmp_path
):
    source = tmp_path / "project"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text("project_name: repo\n", encoding="utf-8")
    env_config = tmp_path / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"
    assert _flag(inner, "--config") == "/ash-env-config/base.yaml"


# ---------------------------------------------------------------------------
# ./ash ASH_CONFIG: mounted under its own root and named to the scan inside
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_ash_config_outside_the_source_is_mounted_under_its_own_root(
    fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    env_config = tmp_path / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"
    assert _flag(inner, "--config") == "/ash-env-config/base.yaml"
    mounts = _mounts(run)
    assert set(mounts) == {"/src", "/out", "/ash-env-config/base.yaml"}
    assert Path(str(mounts["/ash-env-config/base.yaml"]["source"])) == (
        env_config.resolve()
    )
    assert mounts["/ash-env-config/base.yaml"].get("readonly") is True
    assert "WARNING: ASH_CONFIG" not in output_text


@pytest.mark.integration
def test_ash_config_inside_the_source_is_read_through_src(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    env_config = source / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--ash-config-from-host") == "/src/base.yaml"
    assert _flag(inner, "--config") == "/src/base.yaml"
    assert set(_mounts(run)) == {"/src", "/out"}


@pytest.mark.integration
def test_ash_config_from_the_scanned_checkout_is_marked(fake_runner, tmp_path):
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    env_config = checkout / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"
    assert _flag(inner, "--config-file-from-scanned-repository") == (
        "/ash-env-config/base.yaml"
    )
    assert _flag(inner, "--config") == "/ash-env-config/base.yaml"
    assert "--config-from-scanned-repository" in inner


@pytest.mark.integration
def test_a_missing_ash_config_is_refused_before_any_build(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [],
        {"ASH_CONFIG": str(tmp_path / "absent.yaml")},
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "Config file not found:" in output_text


@pytest.mark.integration
def test_an_ash_config_that_extends_is_refused_when_mounted_alone(
    fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    env_config = tmp_path / "base.yaml"
    env_config.write_text("extends: other.yaml\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "extends" in output_text


@pytest.mark.integration
def test_both_config_and_ash_config_are_carried_together(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    env_config = operator / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--config") == "/ash-config/strict.yaml"
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"
    assert set(_mounts(run)) == {
        "/src",
        "/out",
        "/ash-config/strict.yaml",
        "/ash-env-config/base.yaml",
    }


# ---------------------------------------------------------------------------
# ./ash: where the words stand, and where the handling does not apply
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_the_last_config_wins_and_is_the_one_rewritten(fake_runner, tmp_path):
    """Two --config words reach the scan as given, except the last one, which the
    inner CLI reads, is rewritten to its container path and mounted."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    first = operator / "first.yaml"
    first.write_text("project_name: a\n", encoding="utf-8")
    last = operator / "last.yaml"
    last.write_text("project_name: b\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(first),
            "--config",
            str(last),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    values = [inner[i + 1] for i, arg in enumerate(inner[:-1]) if arg == "--config"]
    assert values[-1] == "/ash-config/last.yaml"
    assert values[:-1] == [str(first)]
    assert "/ash-config/last.yaml" in _mounts(run)
    assert "/ash-config/first.yaml" not in _mounts(run)


@pytest.mark.integration
def test_a_config_value_in_the_same_word_is_rewritten(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            f"--config={config}",
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    assert "--config=/ash-config/strict.yaml" in _inner_args(run)
    assert "/ash-config/strict.yaml" in _mounts(run)


@pytest.mark.integration
def test_another_options_value_is_not_read_as_a_config(fake_runner, tmp_path):
    """A word after a value-taking option is that option's value: --config-overrides
    takes the next word, so a path there is not resolved or mounted."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "--config-overrides",
            "--config",
            "--config",
            str(config),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--config-overrides") == "--config"
    assert "/ash-config/strict.yaml" in _mounts(run)


@pytest.mark.integration
def test_another_subcommand_keeps_its_config_words_as_written(fake_runner, tmp_path):
    """The provenance options are the scan command's; another subcommand's words
    pass through unchanged, with no mount made for them."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "report",
            "--config",
            str(config),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--config") == str(config)
    assert set(_mounts(run)) == {"/src", "/out"}
    assert "--config-from-scanned-repository" not in inner


@pytest.mark.integration
def test_another_subcommand_still_names_a_dropped_ash_config(fake_runner, tmp_path):
    """For a run the config handling does not cover, ASH_CONFIG is still named in
    a warning rather than dropped silently, as before."""
    source = tmp_path / "project"
    source.mkdir()
    env_config = tmp_path / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "report"],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    assert "WARNING: ASH_CONFIG" in output_text
    run = _only_run(calls)
    assert set(_mounts(run)) == {"/src", "/out"}
    assert _flag(_inner_args(run), "--ash-config-from-host") is None


@pytest.mark.integration
def test_an_explicit_scan_subcommand_gets_the_same_handling(fake_runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "scan",
            "--config",
            str(config),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    assert _flag(_inner_args(run), "--config") == "/ash-config/strict.yaml"
    assert "/ash-config/strict.yaml" in _mounts(run)


# ---------------------------------------------------------------------------
# ./ash: ASH_CONFIG as the scan's --config, ".." after a link, inline values
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_ash_config_with_no_config_is_also_named_as_the_scans_config(
    fake_runner, tmp_path
):
    """The inner CLI reads its config from --config, and ./ash passes no
    ASH_CONFIG into the container, so the file is named to the scan as --config
    as well as with --ash-config-from-host."""
    source = tmp_path / "project"
    source.mkdir()
    env_config = tmp_path / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out")],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert _flag(inner, "--config") == "/ash-env-config/base.yaml"
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"
    assert "--config-from-scanned-repository" not in inner


@pytest.mark.integration
def test_an_explicit_config_is_the_only_config_word_beside_ash_config(
    fake_runner, tmp_path
):
    """The explicit --config wins, so the ASH_CONFIG file adds no --config word."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / "strict.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    env_config = operator / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
        {"ASH_CONFIG": str(env_config)},
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert inner.count("--config") == 1
    assert _flag(inner, "--config") == "/ash-config/strict.yaml"
    assert _flag(inner, "--ash-config-from-host") == "/ash-env-config/base.yaml"


@pytest.mark.integration
def test_a_dotdot_after_a_tree_link_is_the_trees_name_and_is_refused(
    fake_runner, tmp_path
):
    """``api/link/..`` is the directory above the link's target, not ``api``.

    The link sits in the scanned tree, so the tree steers where the ``..``
    lands. The name is the tree's and the file it reaches resolves outside the
    tree, so ./ash refuses it as the launcher does."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    operator = tmp_path / "operator"
    (operator / "deep").mkdir(parents=True)
    config = operator / "cfg.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    (source / "link").symlink_to(operator / "deep", target_is_directory=True)

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            f"{source}/link/../cfg.yaml",
        ],
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "inside the scanned tree but is a link, or is reached through one" in (
        output_text
    )


@pytest.mark.integration
@pytest.mark.parametrize("layout", NAMES_STEERED_BY_THE_SCANNED_CHECKOUT)
def test_a_name_the_scanned_checkout_steers_out_of_it_is_refused(
    layout, fake_runner, tmp_path
):
    """A ``..`` after a link in the checkout, or a directory alias onto a real
    checkout directory followed by a tree file link, puts the name in the
    scanned tree while the file resolves outside it: refused, nothing run."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    (checkout / "ci").mkdir()
    config = config_through_links(layout, checkout, tmp_path)

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "inside the scanned tree but is a link, or is reached through one" in (
        output_text
    )


@pytest.mark.integration
def test_a_file_link_chain_through_a_tree_link_is_mounted_and_marked(
    fake_runner, tmp_path
):
    """``ops/cfg.yaml`` -> ``repo/ci/link.yaml`` -> a file outside the checkout.

    The name the operator gave sits outside the tree, so nothing is refused; the
    chain passes through a link the repository wrote, so the config is marked."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    (checkout / "ci").mkdir()
    config = config_through_links(
        "file-link-in-the-scanned-checkout", checkout, tmp_path
    )

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--config") == "/ash-config/ash.yaml"
    assert Path(str(_mounts(run)["/ash-config/ash.yaml"]["source"])) == (
        (tmp_path / "operator" / "ash.yaml").resolve()
    )
    assert "--config-from-scanned-repository" in inner


@pytest.mark.integration
def test_a_directory_alias_onto_a_tree_directory_link_is_mounted_and_marked(
    fake_runner, tmp_path
):
    """``ops/dir`` -> ``repo/ci/conf`` with ``conf`` a tree link to an outside
    directory, given ``ops/dir/ash.yaml``.

    The alias is the operator's, so the name is not the tree's and nothing is
    refused; the tree's ``conf`` steered the name to the file, so it is marked."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    (checkout / "ci").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    (checkout / "ci" / "conf").symlink_to(operator, target_is_directory=True)
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / "dir").symlink_to(checkout / "ci" / "conf", target_is_directory=True)

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(ops / "dir" / "ash.yaml"),
        ],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert _flag(inner, "--config") == "/ash-config/ash.yaml"
    assert Path(str(_mounts(run)["/ash-config/ash.yaml"]["source"])) == (
        (operator / "ash.yaml").resolve()
    )
    assert "--config-from-scanned-repository" in inner


def _config_by_option_or_environment(via: str, name: str):
    """The config as the operator gives it: the option, or the environment."""
    if via == "option":
        return ["--config", name], {}
    return [], {"ASH_CONFIG": name}


@pytest.mark.integration
@pytest.mark.parametrize("via", ["option", "environment"])
def test_a_dotdot_after_a_tree_link_reached_by_another_spelling_is_refused(
    fake_runner, tmp_path, via
):
    """A link's location is judged by where it sits, not how it was spelled.

    The name goes through ``alias``, a link of the operator's own to the
    directory that holds the checkout's ``link``, and then a ``..``. The alias is
    followed to where it leads, so the checkout's link is met in the checkout
    and the name is the tree's; the file it reaches is outside the tree, so it
    is refused."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = checkout / "api"
    source.mkdir()
    operator = tmp_path / "operator"
    (operator / "deep").mkdir(parents=True)
    (operator / "cfg.yaml").write_text("project_name: p\n", encoding="utf-8")
    (source / "link").symlink_to(operator / "deep", target_is_directory=True)
    spelled = tmp_path / "operator-spelling"
    spelled.mkdir()
    (spelled / "alias").symlink_to(source, target_is_directory=True)
    words, env = _config_by_option_or_environment(
        via, f"{spelled}/alias/link/../cfg.yaml"
    )

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), *words],
        env,
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "is inside the scanned tree but is a link" in output_text


def _run_with_a_checkout_that_is_a_link(fake_runner, tmp_path, via):
    """The operator works in ``home/repo``, their own link to the checkout, with a
    shared config beside the checkout, named ``home/repo/../shared/ash.yaml``.
    Returns (the shared config, rc, output text, the runner's calls)."""
    real = tmp_path / "data-root" / "repo"
    (real / ".git").mkdir(parents=True)
    shared = tmp_path / "data-root" / "shared"
    shared.mkdir()
    config = shared / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    home = tmp_path / "operator-home"
    home.mkdir()
    (home / "repo").symlink_to(real, target_is_directory=True)
    words, env = _config_by_option_or_environment(
        via, f"{home}/repo/../shared/ash.yaml"
    )
    rc, output_text, calls = _run_ash(
        fake_runner,
        tmp_path,
        [
            "--no-build",
            "--source-dir",
            str(home / "repo"),
            "--output-dir",
            str(tmp_path / "out"),
            *words,
        ],
        env,
    )
    return config, rc, output_text, calls


@pytest.mark.integration
@pytest.mark.parametrize("via", ["option", "environment"])
def test_a_checkout_that_is_itself_a_link_is_not_refused_as_a_link_in_the_tree(
    fake_runner, tmp_path, via
):
    """The ``..`` after the checkout's own link leaves the checkout: only a link
    inside the checkout is the repository's, so the shared config beside the
    checkout is mounted and no refusal is printed. (That the file is not marked as
    the repository's is the next cell; the PowerShell twin answers the same.)"""
    config, rc, output_text, calls = _run_with_a_checkout_that_is_a_link(
        fake_runner, tmp_path, via
    )

    assert rc == 0, output_text
    assert "is inside the scanned tree" not in output_text, output_text
    run = _only_run(calls)
    assert any(
        Path(str(mount["source"])) == config.resolve()
        for mount in _mounts(run).values()
        if "source" in mount
    ), _mounts(run)


@pytest.mark.integration
@pytest.mark.parametrize("via", ["option", "environment"])
def test_a_checkout_that_is_itself_a_link_does_not_mark_a_file_beside_it_as_the_repositorys(
    fake_runner, tmp_path, via
):
    """The shared config beside a checkout the operator reaches through their own
    link is the operator's, so no run is given a word marking it as the scanned
    repository's. This cell reads only the marks: a refusal (no run) is the
    previous cell's concern."""
    _, _, _, calls = _run_with_a_checkout_that_is_a_link(fake_runner, tmp_path, via)

    marked = [
        word for call in calls for word in call if "from-scanned-repository" in word
    ]
    assert marked == [], marked


@pytest.mark.integration
@pytest.mark.parametrize("via", ["option", "environment"])
def test_a_name_back_into_the_checkout_through_its_own_link_still_meets_the_links_it_holds(
    fake_runner, tmp_path, via
):
    """The twin of the launcher's check in
    tests/unit/test_sandbox_refused_by_every_container_entrypoint.py: the operator's
    link to the checkout is followed out of the checkout by a ``..``, and the name
    comes back in by the checkout's real name to a link the checkout holds that leads
    outside it. The walk goes on past the operator's link, so the name is the tree's
    and the file is refused as one the repository chose: exit 3, nothing built or
    run. (The previous two checks are the other half: a ``..`` that leaves the
    checkout and stays out is not refused.)"""
    real = tmp_path / "data-root" / "repo"
    (real / ".git").mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    (real / "lnk.yaml").symlink_to(outside)
    home = tmp_path / "operator-home"
    home.mkdir()
    (home / "repo").symlink_to(real, target_is_directory=True)
    words, env = _config_by_option_or_environment(via, f"{home}/repo/../repo/lnk.yaml")

    rc, output_text, calls = _run_ash(
        fake_runner,
        tmp_path,
        [
            "--no-build",
            "--source-dir",
            str(home / "repo"),
            "--output-dir",
            str(tmp_path / "out"),
            *words,
        ],
        env,
    )

    assert rc == 3, output_text
    assert calls == [], calls
    assert "is a link, or is reached through one" in output_text, output_text


@pytest.mark.integration
@pytest.mark.parametrize("via", ["option", "environment"])
def test_a_file_in_the_checkout_is_the_repositorys_when_the_source_is_reached_through_an_alias(
    fake_runner, tmp_path, via
):
    """The source directory is named through ``alias``, the operator's link to the
    checkout, and leads on through a link the checkout holds to a project outside
    it. The scanned tree is the checkout under its typed name and under its
    physical name, so a file the checkout physically holds is still the
    repository's: mounted and marked."""
    checkout = tmp_path / "real" / "repo"
    (checkout / ".git").mkdir(parents=True)
    config = checkout / "cfg.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    project = tmp_path / "elsewhere" / "proj"
    project.mkdir(parents=True)
    (checkout / "lnk").symlink_to(project, target_is_directory=True)
    home = tmp_path / "operator-home"
    home.mkdir()
    (home / "alias").symlink_to(checkout, target_is_directory=True)
    words, env = _config_by_option_or_environment(via, str(config))

    rc, output_text, calls = _run_ash(
        fake_runner,
        tmp_path,
        [
            "--no-build",
            "--source-dir",
            str(home / "alias" / "lnk"),
            "--output-dir",
            str(tmp_path / "out"),
            *words,
        ],
        env,
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    mounts = _mounts(run)
    # The mark and the mount are the route's own: the --config file is mounted at
    # /ash-config and marked with --config-from-scanned-repository; the ASH_CONFIG
    # file at /ash-env-config, named with --ash-config-from-host, marked with the
    # --config-file-from-scanned-repository pair, and, with no --config given, also
    # the scan's --config with that mark. A match on any mount or on one mark word
    # read the two routes alike and could not tell a dropped word from a given one.
    if via == "option":
        destination = "/ash-config/cfg.yaml"
        assert _flag(inner, "--config") == destination, inner
        assert "--config-from-scanned-repository" in inner, inner
        assert "--config-file-from-scanned-repository" not in inner, inner
    else:
        destination = "/ash-env-config/cfg.yaml"
        assert _flag(inner, "--ash-config-from-host") == destination, inner
        assert _flag(inner, "--config-file-from-scanned-repository") == destination, (
            inner
        )
        assert _flag(inner, "--config") == destination, inner
        assert "--config-from-scanned-repository" in inner, inner
    assert destination in mounts, mounts
    assert Path(str(mounts[destination]["source"])) == config.resolve(), mounts
    assert mounts[destination].get("readonly") is True, mounts


@pytest.mark.integration
def test_an_inline_config_value_with_spaces_leaves_no_stray_words(
    fake_runner, tmp_path
):
    """The word list is split on blanks, so an inline ``--config=PATH`` whose
    path holds a space spans several words; all of them are replaced."""
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator with space"
    operator.mkdir()
    config = operator / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        [
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            f"--config={config}",
        ],
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert inner.count("--config=/ash-config/ash.yaml") == 1
    assert [word for word in inner if "space" in word] == []


@pytest.mark.integration
def test_the_wrappers_c_is_its_no_color_option_not_a_config_carry(
    fake_runner, tmp_path
):
    """The config carry covers the long forms only (``--config PATH``
    and ``--config=PATH``): ``-c`` is this wrapper's short form of
    ``--no-color``, so it is consumed there and never becomes a config word or
    a mount."""
    source = tmp_path / "project"
    source.mkdir()
    env_config = tmp_path / "base.yaml"
    env_config.write_text("project_name: base\n", encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "-c"],
    )

    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    assert "--no-color" in inner
    assert "-c" not in inner
    assert _flag(inner, "--config") is None
    assert set(_mounts(run)) == {"/src", "/out"}


# ---------------------------------------------------------------------------
# ./ash: a config in another checkout is marked as such, or the run is refused
# ---------------------------------------------------------------------------

#: The mark ``ash --mode container`` sends for a file in a git checkout other than
#: the scanned one, and the two it sends for the scanned repository's.
ELSEWHERE_FLAG = rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG

#: A stand-in for ``ls`` that prints the listing the test names: $STUB_HOLDER for
#: the directory a link leads to (``-L`` among its options) and $STUB_ENTRY for the
#: entry itself. ./ash asks ``ls -ldn`` for the owner and the mode bits of a .git
#: it cannot settle with the shell's own tests, as sandbox_grants
#: ._left_by_a_trusted_user asks stat and lstat.
_LS_STUB = """#!/bin/bash
follow=NO
for word in "$@"; do
  case "$word" in
    --) break ;;
    -*L*) follow=YES ;;
  esac
done
if [ "$follow" = YES ]; then
  printf '%s\\n' "$STUB_HOLDER"
else
  printf '%s\\n' "$STUB_ENTRY"
fi
"""

#: A listing as ``ls -ldn`` prints it: the mode, the link count, the owner, the group.
_HOLDER_STRANGER_OWNS = "drwxrwxrwx 2 3141592 3141592 4096 Oct 24 05:00 holder"
_ENTRY_OWNED_BY_A_STRANGER = "lrwxrwxrwx 1 2718281 2718281 6 Oct 24 05:00 entry -> x"


def _ops_with_a_linked_git_entry(tmp_path: Path) -> Path:
    """``tmp/ops/ash.yaml`` beside an ``ops/.git`` that is a link: a shape the shell's
    own ownership test cannot settle (it follows a link), so ./ash asks ``ls``."""
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / ".git").symlink_to(tmp_path / "git-directory-nowhere")
    config = ops / "ash.yaml"
    config.write_text("project_name: ops\n", encoding="utf-8")
    return config


def _use_ls(fake_runner, body: str) -> None:
    """Put *body* in place of the wrapper's ``ls``, which this suite does not give it."""
    stub = fake_runner[0] / "ls"
    stub.write_text(
        body if body.startswith("#!") else "#!/bin/bash\n" + body, encoding="utf-8"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)


def _run_with_config(fake_runner, tmp_path: Path, config: Path, env=None):
    source = tmp_path / "project"
    source.mkdir(exist_ok=True)
    return _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
        env,
    )


@pytest.mark.integration
def test_a_git_directory_the_user_owns_needs_no_ls(fake_runner, tmp_path):
    """The shell's own ownership test settles it: this suite's PATH has no ``ls``."""
    mark_git_checkout(tmp_path / "ops")
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: ops\n", encoding="utf-8")
    assert not (fake_runner[0] / "ls").exists()

    rc, output_text, calls = _run_with_config(fake_runner, tmp_path, config)

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert _flag(inner, ELSEWHERE_FLAG) == "/ash-config/ash.yaml"


@pytest.mark.integration
def test_a_checkout_above_an_entry_that_cannot_be_judged_still_counts(
    fake_runner, tmp_path
):
    """A local scan looks at every directory up to the root, so a .git the shell
    cannot judge without ``ls`` (a link, which this suite's PATH cannot ask about)
    does not hide the user's own checkout above it: refusing there would turn away
    a file the shell can place."""
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    (ops / "team").mkdir()
    (ops / "team" / ".git").symlink_to(tmp_path / "git-directory-nowhere")
    config = ops / "team" / "ash.yaml"
    config.write_text("project_name: ops\n", encoding="utf-8")
    assert not (fake_runner[0] / "ls").exists()

    rc, output_text, calls = _run_with_config(fake_runner, tmp_path, config)

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert _flag(inner, ELSEWHERE_FLAG) == "/ash-config/ash.yaml"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("holder", "entry", "marked"),
    [
        pytest.param(
            "drwxr-xr-x 2 3141592 3141592 4096 Oct 24 05:00 holder",
            _ENTRY_OWNED_BY_A_STRANGER,
            True,
            id="a-directory-nobody-else-can-write",
        ),
        pytest.param(
            _HOLDER_STRANGER_OWNS,
            _ENTRY_OWNED_BY_A_STRANGER,
            False,
            id="world-writable",
        ),
        pytest.param(
            "drwxrwxr-x 2 3141592 3141592 4096 Oct 24 05:00 holder",
            _ENTRY_OWNED_BY_A_STRANGER,
            False,
            id="group-writable",
        ),
        pytest.param(
            "drwxr-xrwx 2 3141592 3141592 4096 Oct 24 05:00 holder",
            _ENTRY_OWNED_BY_A_STRANGER,
            False,
            id="other-writable",
        ),
        pytest.param(
            "drwxrwxrwt 2 3141592 3141592 4096 Oct 24 05:00 holder",
            _ENTRY_OWNED_BY_A_STRANGER,
            False,
            id="sticky-and-world-writable",
        ),
        pytest.param(
            "drwxrwxrwx@ 2 3141592 3141592 4096 Oct 24 05:00 holder",
            _ENTRY_OWNED_BY_A_STRANGER,
            False,
            id="a-listing-with-an-attribute-marker",
        ),
        pytest.param(
            _HOLDER_STRANGER_OWNS,
            "lrwxrwxrwx 1 0 0 6 Oct 24 05:00 entry -> x",
            True,
            id="owned-by-root",
        ),
        pytest.param(
            _HOLDER_STRANGER_OWNS,
            "lrwxrwxrwx 1 3141592 3141592 6 Oct 24 05:00 entry -> x",
            True,
            id="owned-by-the-directorys-owner",
        ),
    ],
)
def test_a_git_entry_that_is_a_link_counts_by_who_left_it(
    holder, entry, marked, fake_runner, tmp_path
):
    """sandbox_grants._left_by_a_trusted_user: in a directory that group members or
    others can write, an entry counts only when root, the directory's owner or the
    scanning user left it; elsewhere its shape alone decides."""
    config = _ops_with_a_linked_git_entry(tmp_path)
    _use_ls(fake_runner, _LS_STUB)

    rc, output_text, calls = _run_with_config(
        fake_runner,
        tmp_path,
        config,
        {"STUB_HOLDER": holder, "STUB_ENTRY": entry},
    )

    assert rc == 0, output_text
    inner = _inner_args(_only_run(calls))
    assert (ELSEWHERE_FLAG in inner) is marked
    assert _flag(inner, "--config") == "/ash-config/ash.yaml"


@pytest.mark.integration
def test_a_git_entry_that_is_a_link_the_scanning_user_left_counts(
    fake_runner, tmp_path
):
    config = _ops_with_a_linked_git_entry(tmp_path)
    _use_ls(fake_runner, _LS_STUB)

    rc, output_text, calls = _run_with_config(
        fake_runner,
        tmp_path,
        config,
        {
            "STUB_HOLDER": _HOLDER_STRANGER_OWNS,
            "STUB_ENTRY": f"lrwxrwxrwx 1 {os.geteuid()} 0 6 Oct 24 05:00 entry -> x",
        },
    )

    assert rc == 0, output_text
    assert ELSEWHERE_FLAG in _inner_args(_only_run(calls))


@pytest.mark.integration
@pytest.mark.parametrize(
    "stub",
    [
        pytest.param(None, id="ls-is-not-there"),
        pytest.param("exit 1\n", id="ls-fails"),
        pytest.param("echo 'no listing today'\n", id="ls-prints-no-listing"),
        pytest.param("echo 'drwxr-xr-x 2 nobody nogroup'\n", id="ls-prints-names"),
    ],
)
def test_a_judgment_that_cannot_be_made_refuses_and_starts_nothing(
    stub, fake_runner, tmp_path
):
    """The wrapper cannot tell whether a local scan would count the file as in
    another checkout, and an unmarked file is read inside as the operator's, so it
    refuses, as the launcher does when its judgment raises
    (``_another_checkout_marks``): exit 3, no build, no run."""
    config = _ops_with_a_linked_git_entry(tmp_path)
    if stub is not None:
        _use_ls(fake_runner, stub)
    else:
        assert not (fake_runner[0] / "ls").exists()

    rc, output_text, calls = _run_with_config(fake_runner, tmp_path, config)

    assert rc == 3, output_text
    assert calls == [], f"the runner was called: {calls}"
    # The phrases the launcher's refusal holds, which a reader greps for.
    assert "git checkout other than the scanned one" in output_text, output_text
    assert "could not be judged" in output_text, output_text
    assert "without the mark a local scan's judgment would give it" in output_text


@pytest.mark.integration
def test_the_refusal_for_a_git_entry_it_cannot_judge_names_the_entry(
    fake_runner, tmp_path
):
    """Every directory up to the root is looked at, so the operator cannot tell
    from a fixed sentence which ``.git`` entry blocked the run. The refusal names
    the one ``ls`` could not say anything about, as Invoke-ASH's does."""
    config = _ops_with_a_linked_git_entry(tmp_path)
    assert not (fake_runner[0] / "ls").exists()

    rc, output_text, calls = _run_with_config(fake_runner, tmp_path, config)

    assert rc == 3, output_text
    assert calls == [], f"the runner was called: {calls}"
    assert "ops/.git" in output_text, output_text
    assert "ls could not say who left" in output_text, output_text


# ---------------------------------------------------------------------------
# Invoke-ASH (utils/ash_helpers.ps1): the same carry, read from its text
# ---------------------------------------------------------------------------

#: PowerShell cannot run in this suite, so these cells read the wrapper's text and
#: pin the constructs that carry the config.
_PS1_WRAPPER = REPO_ROOT / "utils" / "ash_helpers.ps1"


def _ps1_text() -> str:
    if not _PS1_WRAPPER.is_file():
        pytest.skip("utils/ash_helpers.ps1 not present (installed-package layout)")
    return _PS1_WRAPPER.read_text(encoding="utf-8")


def _ps1_config_arms(text: str) -> str:
    """The text of the -Config argument arms: from the bound-Config test up to the
    -Scanners arm that follows it."""
    anchor = "if ($PSBoundParameters.ContainsKey('Config')) {"
    assert anchor in text, f"anchor not found in the powershell wrapper: {anchor}"
    start = text.index(anchor)
    anchor = "if ($PSBoundParameters.ContainsKey('Scanners')) {"
    assert anchor in text[start:], (
        f"anchor not found after the -Config test in the powershell wrapper: {anchor}"
    )
    end = text.index(anchor, start)
    return text[start:end]


@pytest.mark.unit
def test_the_powershell_wrapper_passes_an_explicit_config_as_given():
    arms = _ps1_config_arms(_ps1_text())

    assert "$ashCmdArgs.Add(@('--config', $Config))" in arms


#: The guard that makes the ASH_CONFIG file the scan's --config only when no -Config
#: was given, the order of the explicit -Config before the carry, the two --config
#: sites, the pending test and the marks are pinned once, in
#: test_sandbox_refused_by_every_container_entrypoint.py
#: (TestThePowerShellConfigCarryAsText), on whitespace-collapsed text.


@pytest.mark.unit
def test_the_powershell_wrapper_keeps_the_ash_config_carry_only_for_a_scan():
    text = _ps1_text()

    decision = (
        "if ($envConfigPending -and -not $NoRun -and $subcommand -cne '' "
        "-and $subcommand -cne 'scan') {"
    )
    assert decision in text, (
        "the ASH_CONFIG file must be warned about and not carried for a "
        "subcommand that is not a scan"
    )
    assert "elseif ($envConfigPending -and -not $NoRun) {" in text
    assert "passes it only for a scan" in text


@pytest.mark.unit
def test_the_powershell_wrapper_no_longer_tells_the_operator_to_use_source_relative_paths():
    text = _ps1_text()

    assert "relative to the source directory" not in text
    assert "passes a config into the container only with -Config" not in text


@pytest.mark.unit
def test_the_powershell_wrapper_walks_the_links_of_a_name_once():
    """One walk of the name's links serves the scanned tree's mark and the
    other-checkout mark, so a walk that cannot reach the end has one failure shape.
    The settled rule for judging a name: the working directory is the physical one,
    a link counts by the directory it sits in, and a walk that cannot be decided is
    reported to the caller and never ended quietly. Read as text; no pwsh is needed."""
    text = _ps1_text()

    assert "Test-AshFollowsLinkInTree" not in text, "the second walk is gone"
    assert text.count("Get-AshLinkParents $envConfigAbsolute") == 1
    assert (
        "$envConfigWorking = Resolve-AshRealPath (Get-Location).ProviderPath" in text
    ), "a relative name is taken from the physical working directory"
    start = text.index("function Get-AshLinkParents")
    body = text[
        start : text.index("# Whether a local scan would count the config", start)
    ]
    assert "$Parents.Add($walked)" in body, (
        "a link is judged by the directory it sits in"
    )
    returns = [line for line in body.splitlines() if line.strip() == "return"]
    reasons = [line for line in body.splitlines() if "$Undecided.Value = " in line]
    assert len(returns) == len(reasons) == 3, (
        f"every early end of the walk says why: {returns} {reasons}"
    )


@pytest.mark.unit
def test_the_bash_wrapper_walks_the_links_of_a_name_once():
    """The same for ./ash: collect_link_parents is called once for a mounted file, and
    the scanned tree's mark reads its parents, as in_another_checkout does. Read as
    text."""
    bash = ASH_SCRIPT.read_text(encoding="utf-8")

    assert "follows_a_link_in_the_tree" not in bash, "the second walk is gone"
    start = bash.index("carry_config_file() {")
    body = bash[start : bash.index("# Parse arguments", start)]
    assert body.count("collect_link_parents ") == 1
    assert (
        'in_another_checkout "${given}" "${real}" "${walk_reason}" "${spellings[@]}"'
        in body
    )
    # The judgment of the other checkouts reads the list the carry collected and
    # walks nothing itself; a walk that stopped is reported to it as a reason.
    judging = bash.index("in_another_checkout() {")
    judged = bash[judging : bash.index("# Resolve one config input", judging)]
    assert "collect_link_parents" not in judged
    assert "LINK_PARENTS=()" not in judged


@pytest.mark.unit
def test_the_bash_wrapper_marks_the_same_two_flags_for_a_marked_ash_config_file():
    """The flags the PowerShell wrapper appends are the ones ./ash passes."""
    bash = ASH_SCRIPT.read_text(encoding="utf-8")

    assert '--config-file-from-scanned-repository "${CARRIED_INNER}"' in bash, (
        "./ash marks the ASH_CONFIG file by its container path"
    )
    assert "CONFIG_PROVENANCE_ARGS+=(--config-from-scanned-repository)" in bash, (
        "./ash marks the scan's --config when the ASH_CONFIG file is it"
    )


def _flat(text: str) -> str:
    """*text* with every run of whitespace read as one space."""
    return " ".join(text.split())


@pytest.mark.unit
def test_the_bash_wrapper_marks_another_checkout_by_the_container_path_only():
    """One mark for the --config file and one for the ASH_CONFIG file, each the
    option and the path inside the container, as the launcher sends it. No value
    of the file and no host path travels in a mark."""
    bash = ASH_SCRIPT.read_text(encoding="utf-8")

    sites = [
        line.strip()
        for line in bash.splitlines()
        if "CONFIG_PROVENANCE_ARGS+=" in line
        and "--config-file-from-another-checkout" in line
    ]
    assert (
        sites
        == [
            'CONFIG_PROVENANCE_ARGS+=(--config-file-from-another-checkout "${CARRIED_INNER}")'
        ]
        * 2
    )
    assert "--config-file-from-another-checkout=" not in bash


@pytest.mark.unit
def test_the_bash_wrapper_judges_another_checkout_only_for_a_file_it_mounts_unmarked():
    """The judgment sits in the mount arm of carry_config_file, after the scanned
    tree's mark, and runs only when that mark was not given."""
    raw = ASH_SCRIPT.read_text(encoding="utf-8")
    bash = _flat(raw)

    arm = bash.index(
        'CARRIED_MOUNT="type=bind,source=${real},destination=${CARRIED_INNER},readonly"'
    )
    scanned = bash.index('CARRIED_MARK="YES"', arm)
    judged = bash.index(
        'if [[ "${CARRIED_MARK}" = "NO" ]]; then in_another_checkout', arm
    )
    assert arm < scanned < judged
    calls = [
        line
        for line in raw.splitlines()
        if line.strip().startswith("in_another_checkout ")
    ]
    assert len(calls) == 1, calls


@pytest.mark.unit
def test_the_bash_wrapper_refuses_when_it_cannot_judge_another_checkout():
    """The twin of the launcher's check below, read from ./ash's text: an undecided
    judgment inside in_another_checkout is a refusal with the code of any other
    (refuse, exit 3), in the launcher's words, and never an unmarked file.
    test_a_judgment_that_cannot_be_made_refuses_and_starts_nothing runs it."""
    raw = ASH_SCRIPT.read_text(encoding="utf-8")
    bash = _flat(raw)

    judging = bash.index("in_another_checkout() {")
    judged = bash[judging : bash.index("# Resolve one config input", judging)]
    assert 'refuse_unjudged "${given}" "${reason}"' in judged, judged
    assert judged.count("refuse_unjudged ") == 1, "one undecided exit, one refusal"

    # The function's body, to its closing brace at column 0, read in the raw text:
    # _flat folds every newline into a space, so the brace line is found in ``raw``
    # and the body is flattened afterwards for the same whitespace-blind reads.
    helper = raw.index("refuse_unjudged() {")
    body = _flat(raw[helper : raw.index("\n}\n", helper) + 3])
    assert body.index("refuse ") < body.index("could not be judged"), body
    assert "git checkout other than the scanned one" in body, body
    assert "without the mark a local scan's judgment would give it" in body, body
    # refuse exits with the wrapper's refusal code, the same for every refusal.
    assert 'exit "${WRAPPER_REFUSAL_EXIT}"' in bash
    assert "WRAPPER_REFUSAL_EXIT=3" in bash


@pytest.mark.unit
def test_the_powershell_wrapper_marks_another_checkout_by_the_container_path_only():
    text = _flat(_ps1_text())

    group = (
        "if ($envConfigElsewhere) { $envConfigGroups.Add("
        "@('--config-file-from-another-checkout', $envConfigInner)) }"
    )
    assert group in text, "the mark is the option and the container path"
    assert (
        text.count("$envConfigGroups.Add(@('--config-file-from-another-checkout'") == 1
    )
    # After the scanned tree's mark group and before the words for the scan's own --config.
    scanned = text.index(
        "if ($envConfigMarked) { $envConfigGroups.Add("
        "@('--config-file-from-scanned-repository', $envConfigInner)) }"
    )
    own_config = text.index(
        "if (-not $PSBoundParameters.ContainsKey('Config')) {",
        text.index("$envConfigGroups.Add(@('--ash-config-from-host'"),
    )
    assert scanned < text.index(group) < own_config


@pytest.mark.unit
def test_the_powershell_wrapper_judges_another_checkout_after_the_mount_and_unmarked():
    text = _flat(_ps1_text())

    mount = text.index('$runArgs.Add("type=bind,source=$envConfigReal,')
    scanned = text.index("$envConfigMarked = $envConfigRealInTree -or")
    judged = text.index(
        "if (-not $envConfigMarked) { $envConfigElsewhereUndecided = ''", scanned
    )
    carried = text.index("$envConfigGroups.Add(@('--ash-config-from-host'")
    assert mount < scanned < judged < carried
    assert text.count("$envConfigElsewhere = ") == 2, (
        "the mark starts False and is set in the mount arm only"
    )


@pytest.mark.unit
def test_the_powershell_wrapper_refuses_when_it_cannot_judge_another_checkout():
    """An undecided judgment is a refusal with the code of any other, in the
    launcher's words, and not an unmarked file."""
    text = _flat(_ps1_text())

    refusal = text.index("if ($envConfigElsewhereUndecided) {")
    after = text[refusal : refusal + 700]
    assert "$global:LASTEXITCODE = $refusalExitCode" in after, after
    assert "could not be judged" in after, after
    assert "git checkout other than the scanned one" in after, after
    assert "without the mark a local scan's judgment would give it" in after, after


@pytest.mark.unit
def test_the_powershell_wrapper_trusts_a_git_entry_by_user_id():
    """The launcher and ``./ash`` compare the numeric id of the user who left a
    ``.git`` entry with root, the directory's owner and the user running the scan. A
    name does not stand for an id everywhere: a user with no passwd entry, such as a
    CI container run with ``--user 1001``, has none, so a comparison by name leaves
    that user's own entry unmatched and the file unmarked. The ids come from the item
    (``UnixStat``) or from ``ls`` and ``id``, never from a name."""
    text = _ps1_text()

    start = text.index("function Test-AshEntryTrusted(")
    body = text[start : text.index("function Test-AshGitShaped(")]
    assert "UserName" not in body, body
    assert "-ceq 'root'" not in body, body
    assert "Get-AshOwnerId $Entry" in body, body
    assert "Get-AshOwnerId $holder" in body, body
    assert "Get-AshFirstLine 'id' @('-u')" in body, body
    # root, the directory's owner and the scanning user, each by id.
    assert "$entryId -ceq '0'" in body, body
    assert "$entryId -ceq $holderId" in body, body
    assert "$entryId -ceq $currentId" in body, body
    # The scanning user is asked only when the entry is neither root's nor the
    # directory owner's, so a PATH without id still judges those two.
    assert body.index("$entryId -ceq $holderId") < body.index("Get-AshFirstLine 'id'")
