# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every entry point that runs ASH in a container refuses ``--sandbox <mode>``.

Why this file exists
--------------------
Container mode never sandboxes the scanners inside the image: the container is the
boundary. ``ash scan --mode container`` refuses an explicit ``--sandbox`` other than
``off`` with exit 5, a usage error, before it builds or runs anything, and gives the
scan inside ``sandbox.mode=off`` as its last override (tests/unit/interactions/
test_container_mode_reports_sandbox_not_applied.py). The other entry points always
run a container, and each has its own argument handling:

* ``./ash`` forwarded ``--sandbox`` to the scan inside the image, which ships no
  bubblewrap or firejail, so with those modes every scanner was recorded MISSING after
  a full build;
* ``invoke-ash`` in utils/ash_helpers.sh, which calls ``./ash``;
* ``Invoke-ASH`` in utils/ash_helpers.ps1 forwarded it the same way.

All of them refuse it before the image is built, with code 5 and one line
saying the scanners run unsandboxed in a container and how to run sandboxed. Every
``--sandbox`` counts, because the scan inside takes the last one, and so does a
``--sandbox`` with no mode or a value that is not a mode, whose message lists the
modes. ``off`` (in any case) is passed on to the scan.

The wrappers also give the scan inside ``sandbox.mode=off`` as its last override,
as container mode does, so a mode from a config file or ``--config-overrides`` is
turned off there too, except for the commands that take no overrides. And since they
do not pass ``ASH_CONFIG`` into the container for a command other than a scan, they
warn once when it is set, with or without ``-Config``.

``./ash`` and ``invoke-ash`` run against a stand-in runner that records each call.
``Invoke-ASH`` runs under ``pwsh`` the same way; it refuses by throwing with
``$LASTEXITCODE`` set to 5, because ``exit`` would end the session of the caller who
dot-sourced it. As in tests/unit/test_powershell_default_runner_discovery.py, those
tests are skipped on a developer machine without ``pwsh`` and fail in CI without it.

Every run has guards for docker, finch, nerdctl and podman first on PATH that record
the call and fail, so a run that stops using the stand-in reaches no real runtime.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 - runs ./ash, the shell helper and pwsh, fixed argv
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

import pytest

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.unit.test_base_image_override_reaches_every_build_entrypoint import (
    _REQUIRES_BASH,
)
from tests.unit.test_build_date_reaches_every_build_entrypoint import (
    _PYTHON_RECORDER,
    _platform_environment,
    _write_python_command,
    _write_runner_guards,
)
from tests.utils.helpers import mark_git_checkout

REPO_ROOT = Path(__file__).resolve().parents[1].parent
ASH_SCRIPT = REPO_ROOT / "ash"
SH_HELPERS = REPO_ROOT / "utils" / "ash_helpers.sh"
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")

REFUSAL = "cannot be used with ASH in a container"
#: The modes the CLI's --sandbox accepts besides off; a refusal of a value that is
#: not a mode lists them.
MODES = ("auto", "bwrap", "firejail", "landlock", "sandbox-exec")

#: The stand-in runner: _PYTHON_RECORDER's line per call, and first the call's argv
#: as a JSON list in ARGV_JSON, so a test can tell one argument that holds spaces
#: from several.
_RECORDER = (
    """\
import json, os, sys
with open(os.environ["ARGV_JSON"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
"""
    + _PYTHON_RECORDER
)


def _environment(
    tmp_path: Path, build_status: int = 1, env_extra: Optional[Dict[str, str]] = None
) -> Tuple[dict, Path, Path]:
    """A bin dir with the stand-in runner and the guards first on PATH, and the env.

    The runner records each call, one line per call; a build exits with
    *build_status*, so a test can stop at the build or go on to the run. Both are
    Python run by this interpreter: an executable script on POSIX, a ``.cmd`` that
    Get-Command finds through PATHEXT on Windows, which cannot run an extensionless
    script.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_python_command(bin_dir, "fake-oci-runner", _RECORDER)
    runner = bin_dir / "fake-oci-runner"
    guard_log = _write_runner_guards(bin_dir, tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    source = tmp_path / "src"
    if not source.is_symlink():
        source.mkdir(exist_ok=True)
    argv_log = tmp_path / "argv"
    # An allowlist, so the developer's OCI_RUNNER_WRAPPER, BASH_ENV and HOME play
    # no part.
    env = {
        "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
        "HOME": str(home),
        "TMPDIR": str(tmp_path),
        "LANG": "C.UTF-8",
        "OCI_RUNNER": str(runner),
        "ARGV_LOG": str(argv_log),
        "ARGV_JSON": str(tmp_path / "argv.json"),
        "FAKE_BUILD_STATUS": str(build_status),
        **_platform_environment(home),
        **(env_extra or {}),
    }
    return env, argv_log, guard_log


def _calls(argv_log: Path, guard_log: Path) -> List[str]:
    assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
    return (
        argv_log.read_text(encoding="utf-8").splitlines() if argv_log.exists() else []
    )


def _run_ash(
    tmp_path: Path,
    *flags: str,
    build_status: int = 1,
    env_extra: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
):
    env, argv_log, guard_log = _environment(tmp_path, build_status, env_extra)
    proc = subprocess.run(  # nosec B603 B607 - fixed script path, list args
        [
            "bash",
            str(ASH_SCRIPT),
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            *flags,
        ],
        capture_output=True,
        text=True,
        # A byte that is not UTF-8 reads back as a lone surrogate (0x9b as
        # U+DC9B), so a test can tell a raw C1 byte from U+009B and from '?'.
        errors="surrogateescape",
        cwd=str(cwd or REPO_ROOT),
        env=env,
        timeout=180,
        check=False,
    )
    return proc, _calls(argv_log, guard_log)


def _argv_lists(tmp_path: Path) -> List[List[str]]:
    """Each runner call's argv as a list, from the stand-in's ARGV_JSON."""
    path = tmp_path / "argv.json"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _inner_words(run_argv: List[str]) -> List[str]:
    """The words the run gives ash in the image: everything after its ``ash``."""
    return run_argv[run_argv.index("ash") + 1 :]


def _has_pair(words: List[str], first: str, second: str) -> bool:
    return any(words[i : i + 2] == [first, second] for i in range(len(words) - 1))


def _parse_inner(
    inner: List[str], tmp_path: Path
) -> Tuple[int, str, Optional[List[str]]]:
    """Parse the scan's words with the real CLI: exit code, output, overrides.

    ash's own command tree parses the words with run_ash_scan replaced, so nothing
    is scanned even when the parse succeeds; the image's /src and /out become
    directories under *tmp_path*. The overrides are None when no scan was reached.
    A usage error exits ASH_EXIT_USAGE_ERROR (5) here as from the ``ash`` entry
    point: cli/main.py maps click's usage errors to it.
    """
    from unittest import mock

    from typer.testing import CliRunner

    from automated_security_helper.cli import scan as scan_module
    from automated_security_helper.cli.main import app

    paths = {"/src": tmp_path / "parse-src", "/out": tmp_path / "parse-out"}
    for path in paths.values():
        path.mkdir(exist_ok=True)
    words = [str(paths.get(word, word)) for word in inner]
    captured: Dict[str, object] = {}
    with mock.patch.object(
        scan_module, "run_ash_scan", lambda **kwargs: captured.update(kwargs)
    ):
        result = CliRunner().invoke(app, words, catch_exceptions=False)
    overrides = captured.get("config_overrides")
    return (
        result.exit_code,
        result.output,
        None if overrides is None else list(overrides),
    )


def _scan_overrides(inner: List[str], tmp_path: Path) -> List[str]:
    """The config overrides the scan in the image would apply, in order.

    The scan applies them in order, so the last ``sandbox.mode=`` wins.
    """
    code, output, overrides = _parse_inner(inner, tmp_path)
    assert code == 0 and overrides is not None, (inner, output)
    return overrides


#: A --cli-json-input document that asks for a sandbox, and has an override of its
#: own that must still reach the scan.
_SANDBOX_DOCUMENT = {
    "sandbox": "bwrap",
    "config_overrides": ["reporters.markdown.options.compact=true"],
}


def _without(root: Path, text: str) -> str:
    return text.replace(str(root), "<ROOT>")


#: What the wrappers warn when ASH_CONFIG names a config they do not pass on.
ASH_CONFIG_WARNING = "ASH_CONFIG is set"

_REFUSED = [
    ["--sandbox", "bwrap"],
    ["--sandbox=landlock"],
    ["--offline", "--sandbox", "auto"],
    ["--sandbox", "off", "--sandbox", "bwrap"],
    # After the command, where the wrappers' own --sandbox off goes before it:
    # the scan takes the last --sandbox, so the caller's must be refused too.
    ["scan", "--sandbox", "bwrap"],
    ["--sandbox"],
    ["--sandbox=not-a-mode"],
]
_NOT_A_MODE = [["--sandbox"], ["--sandbox=not-a-mode"]]

#: Words given to a wrapper, and whether the command they run is a scan, so is
#: given --sandbox off. The command is the first word that names one, as ash reads
#: it: a root option's value is not a command even when it names one (--phases
#: takes report and inspect; a config file can be called config), and with no
#: command ash scans. Only scan takes --sandbox; another command refuses it.
_COMMAND_POSITION = [
    # inspect first: it takes no override, so the case fails unless its value is
    # skipped. A first value that names scan would pass without any skipping.
    pytest.param(
        [
            "--phases",
            "inspect",
            "--phases",
            "convert",
            "--phases",
            "scan",
            "--phases",
            "report",
        ],
        True,
        id="phase-values-name-commands",
    ),
    pytest.param(["--config", "config"], True, id="a-config-file-named-config"),
    pytest.param(["-f", "merge"], True, id="a-short-option-value"),
    pytest.param(["-Pf", "plugin"], True, id="a-value-after-clustered-short-options"),
    pytest.param(
        ["-Pfplugin", "inspect"], False, id="a-value-attached-to-clustered-options"
    ),
    pytest.param(["--config=config", "inspect"], False, id="an-attached-value"),
    pytest.param(["scan"], True, id="scan"),
    pytest.param(["report"], False, id="report-takes-none"),
    pytest.param(["build-image"], False, id="build-image-takes-none"),
    pytest.param(["--quiet", "merge"], False, id="a-command-after-a-flag"),
    pytest.param(["scan", "--config", "inspect"], True, id="a-later-word-names-one"),
    pytest.param(["get-genai-guide"], False, id="get-genai-guide-takes-none"),
]


def _assert_sandbox_off(run_argv: List[str], is_a_scan: bool) -> None:
    """A scan is given --sandbox off once; any other command, no sandbox at all.

    Were the wrappers to give --config-overrides sandbox.mode=off instead, a
    --cli-json-input document's sandbox would outrank it, and the document's own
    config_overrides would be dropped; neither is given.
    """
    words = _inner_words(run_argv)
    assert "sandbox.mode=off" not in words, words
    if is_a_scan:
        assert _has_pair(words, "--sandbox", "off"), words
        assert words.count("--sandbox") == 1, words
    else:
        assert "--sandbox" not in words, words


@pytest.mark.integration
class TestTheBashEntrypoint:
    pytestmark = _REQUIRES_BASH

    @pytest.mark.parametrize("flags", _REFUSED, ids=" ".join)
    def test_refused_before_the_image_is_built(self, tmp_path, flags):
        proc, calls = _run_ash(tmp_path, *flags)

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert REFUSAL in proc.stderr, proc.stderr
        assert "--mode local" in proc.stderr, proc.stderr
        assert calls == [], calls
        assert not (tmp_path / "out").exists()

    @pytest.mark.parametrize("flags", _NOT_A_MODE, ids=" ".join)
    def test_a_value_that_is_not_a_mode_is_told_the_modes(self, tmp_path, flags):
        proc, _ = _run_ash(tmp_path, *flags)

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert all(mode in proc.stderr for mode in MODES), proc.stderr

    @pytest.mark.parametrize(
        "flags",
        [
            ["--quiet --sandbox bwrap"],
            ["--config-overrides", "reporters.x=1 --sandbox=bwrap"],
            ["--quiet\n--sandbox\nbwrap"],
        ],
        ids=["in-one-argument", "in-an-option-value", "over-lines"],
    )
    def test_a_sandbox_inside_a_quoted_argument_is_refused(self, tmp_path, flags):
        """./ash runs the scan with $ASH_ARGS unquoted, which splits it again.

        So a --sandbox inside one quoted argument reaches the scan as a flag of its
        own, after every --config-overrides, where the appended sandbox.mode=off
        cannot beat it. The refusal checks the words the scan will be given. A
        newline splits them too; ``read`` without ``-d ''`` stops at the first one,
        so the refusal would see only the words before it.
        """
        proc, calls = _run_ash(tmp_path, *flags, build_status=0)

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert REFUSAL in proc.stderr, proc.stderr
        assert calls == [], calls

    @pytest.mark.parametrize(
        "word", ["--sandbox*", "-?sandbox=bwrap"], ids=["star", "question-mark"]
    )
    def test_a_word_is_given_to_the_scan_as_typed(self, tmp_path, word):
        """The scan gets the words the refusal checked, not their glob matches.

        With a file named --sandbox=bwrap in the working directory, the scan still
        gets its words as typed, so ``a*`` stays ``a*`` and no word becomes a
        --sandbox the refusal did not check.
        """
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        (cwd / "--sandbox=bwrap").write_text("", encoding="utf-8")
        (cwd / "a1").write_text("", encoding="utf-8")

        proc, calls = _run_ash(tmp_path / "run", word, "a*", build_status=0, cwd=cwd)

        assert [call.split()[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        run_words = calls[1].split()
        assert word in run_words and "a*" in run_words, calls[1]
        assert "--sandbox=bwrap" not in run_words, calls[1]
        assert "a1" not in run_words, calls[1]

    def test_control_characters_in_the_value_are_not_echoed(self, tmp_path):
        """The value is shown as the other refusals show one, as bash's %q writes it."""
        proc, _ = _run_ash(tmp_path, "--sandbox", "\x1b[2J\x1b[31mRED")

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert "\x1b" not in proc.stderr, repr(proc.stderr)
        assert "$'\\E[2J\\E[31mRED'" in proc.stderr, repr(proc.stderr)

    def test_a_format_character_in_the_value_is_written_out(self, tmp_path):
        """U+202E reverses the text after it; printable cut its bytes into bad UTF-8."""
        proc, _ = _run_ash(tmp_path, "--sandbox", f"r{chr(0x202E)}b")

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert chr(0x202E) not in proc.stderr, repr(proc.stderr)
        assert "$'r\\342\\200\\256b'" in proc.stderr, repr(proc.stderr)

    @pytest.mark.parametrize(
        "csi, shown",
        [
            pytest.param("\u009b", b"$'\\302\\2332J\\302\\23331mRED'", id="utf-8"),
            pytest.param("\udc9b", b"$'\\2332J\\23331mRED'", id="raw-byte"),
        ],
    )
    def test_c1_control_characters_in_the_value_are_not_echoed(
        self, tmp_path, csi, shown
    ):
        """0x9b is CSI on its own, in a terminal that reads 8-bit controls.

        ``tr '[:cntrl:]'`` replaces only C0 and DEL, so the refusal shows CSI as an
        escape itself, whether it arrives as U+009B (bytes c2 9b) or as the raw
        byte. ``"\\udc9b"`` is that raw byte,
        through the surrogateescape that encodes the argv and decodes stderr. The
        checks are on the bytes: a failure report that holds a lone surrogate
        cannot be sent back from an xdist worker.
        """
        proc, _ = _run_ash(tmp_path, "--sandbox", f"{csi}2J{csi}31mRED")
        stderr = proc.stderr.encode("utf-8", "surrogateescape")

        assert proc.returncode == 5, ascii(proc.stdout + proc.stderr)
        assert b"\x9b" not in stderr, stderr
        # Written out in octal, byte by byte, as bash's %q writes them.
        assert shown in stderr, stderr

    def test_a_newline_in_the_value_cannot_forge_a_line(self, tmp_path):
        proc, _ = _run_ash(tmp_path, "--sandbox", "x\nINFO: scan passed, 0 findings")

        assert proc.returncode == 5, proc.stdout + proc.stderr
        lines = (proc.stdout + proc.stderr).splitlines()
        assert not any(line.startswith("INFO:") for line in lines), lines

    @pytest.mark.parametrize("spelling", ["off", "OFF"])
    def test_off_is_passed_to_the_scan(self, tmp_path, spelling):
        proc, calls = _run_ash(tmp_path, "--sandbox", spelling, build_status=0)

        assert REFUSAL not in proc.stderr, proc.stderr
        assert [call.split()[0] for call in calls] == ["build", "run"], calls
        assert "--sandbox off" in calls[1], calls[1]

    @pytest.mark.parametrize("command", [[], ["scan"]], ids=["no-command", "scan"])
    def test_a_configured_sandbox_is_turned_off_in_the_container(
        self, tmp_path, command
    ):
        """A mode from --config-overrides (or a config file) is overridden last.

        As ``ash scan --mode container`` does: the scan inside applies
        ``sandbox.mode=off`` after every other override, so it does not try to
        sandbox its scanners inside the image. The scan's words are parsed by the
        real CLI to see what it would apply.
        """
        proc, _ = _run_ash(
            tmp_path,
            *command,
            "--config-overrides",
            "sandbox.mode=bwrap",
            build_status=0,
        )
        calls = _argv_lists(tmp_path)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        # The caller's override comes after the flag, and the flag still wins.
        assert inner.index("--sandbox") < inner.index("sandbox.mode=bwrap"), inner
        overrides = _scan_overrides(inner, tmp_path)
        assert "sandbox.mode=bwrap" in overrides, overrides
        assert overrides[-1] == "sandbox.mode=off", overrides

    @pytest.mark.parametrize("command", [[], ["scan"]], ids=["no-command", "scan"])
    def test_a_repo_config_mode_resolves_off_through_resolve_config(
        self, tmp_path, command
    ):
        """The scan's own config resolution, over a repository's .ash/.ash.yaml.

        The scanned repository's config sets sandbox.mode; the scan's words from the
        wrapper go through the real CLI, and its overrides through resolve_config
        over that repository, as the scan in the image would resolve them. Without
        the wrapper's flag the same resolution gives the repository's mode, so the
        file is read.
        """
        from automated_security_helper.config.resolve_config import resolve_config

        proc, _ = _run_ash(tmp_path, *command, build_status=0)
        calls = _argv_lists(tmp_path)
        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        overrides = _scan_overrides(_inner_words(calls[1]), tmp_path)
        repository = tmp_path / "src"
        (repository / ".ash").mkdir()
        (repository / ".ash" / ".ash.yaml").write_text(
            'sandbox:\n  mode: "landlock"\n', encoding="utf-8"
        )

        resolved = resolve_config(source_dir=repository, config_overrides=overrides)
        without_the_flag = resolve_config(source_dir=repository, config_overrides=[])

        assert str(resolved.sandbox.mode) == "off", overrides
        assert str(without_the_flag.sandbox.mode) == "landlock"

    def test_a_double_dash_after_the_command_leaves_the_sandbox_off(self, tmp_path):
        """--sandbox off goes right after the command, ahead of the caller's words.

        Appended after them, it came after `scan --`, where it was one of scan's
        extra arguments and no option at all, so the configured mode stayed on.
        ash scan takes no extra arguments, so with a word after the `--` the scan
        refuses it as a usage error and nothing runs; the words still reach it as
        typed.
        """
        bare = tmp_path / "bare"
        proc, _ = _run_ash(
            bare,
            "scan",
            "--config-overrides",
            "sandbox.mode=bwrap",
            "--",
            build_status=0,
        )
        calls = _argv_lists(bare)

        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        inner = _inner_words(calls[1])
        assert inner[:3] == ["scan", "--sandbox", "off"], inner
        assert inner[-1] == "--", inner
        overrides = _scan_overrides(inner, bare)
        assert overrides[-1] == "sandbox.mode=off", overrides

        extra = tmp_path / "extra"
        proc, _ = _run_ash(
            extra,
            "scan",
            "--config-overrides",
            "sandbox.mode=bwrap",
            "--",
            "extra",
            build_status=0,
        )
        calls = _argv_lists(extra)

        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        inner = _inner_words(calls[1])
        assert inner[inner.index("--") :] == ["--", "extra"], inner
        code, output, overrides = _parse_inner(inner, extra)
        assert code == ASH_EXIT_USAGE_ERROR, (code, output, overrides)
        assert "unexpected extra argument(s) (extra)" in " ".join(output.split())
        assert overrides is None, overrides

    def test_a_trailing_option_cannot_take_sandbox_off_as_its_value(self, tmp_path):
        """A value-taking option left last fails in the scan, and swallows nothing.

        Appended at the end, --sandbox became --base-ref's value and off an extra
        argument, and the scan ran with its configured mode. ./ash takes
        --output-dir itself, so the option here is one only the scan takes.
        """
        proc, _ = _run_ash(tmp_path, "scan", "--base-ref", build_status=0)
        calls = _argv_lists(tmp_path)

        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        code, output, overrides = _parse_inner(_inner_words(calls[1]), tmp_path)
        assert code == ASH_EXIT_USAGE_ERROR, (code, output, overrides)
        assert "Option '--base-ref' requires an argument" in " ".join(output.split())
        assert overrides is None, overrides

    def test_a_cli_json_input_document_cannot_turn_the_sandbox_back_on(self, tmp_path):
        """A document's sandbox loses to the wrappers' flag; its overrides stay.

        ``--config-overrides sandbox.mode=off`` lost to the document's
        ``sandbox``, which the scan appends after every override, and set
        config_overrides on the command line, so the document's own were dropped.
        ``--sandbox off`` ranks above the document and keeps them.
        """
        document = tmp_path / "doc.json"
        tmp_path.mkdir(parents=True, exist_ok=True)
        document.write_text(json.dumps(_SANDBOX_DOCUMENT), encoding="utf-8")

        proc, _ = _run_ash(
            tmp_path, "scan", "--cli-json-input", str(document), build_status=0
        )
        calls = _argv_lists(tmp_path)

        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        overrides = _scan_overrides(_inner_words(calls[1]), tmp_path)
        assert overrides[-1] == "sandbox.mode=off", overrides
        assert "reporters.markdown.options.compact=true" in overrides, overrides

    @pytest.mark.parametrize("flags, is_a_scan", _COMMAND_POSITION)
    def test_only_a_scan_is_given_sandbox_off(self, tmp_path, flags, is_a_scan):
        """Only the command ash runs decides; giving it to another command fails it.

        Dropping the override on any word that names a command would leave the
        scan's configured sandbox on for a phase or a config file called inspect
        or config. The config files exist: a scan's config handling resolves and
        mounts them, and a missing one would refuse the run before any call.
        """
        for name in ("config", "inspect"):
            (tmp_path / name).write_text("project_name: p\n", encoding="utf-8")
        proc, _ = _run_ash(tmp_path, *flags, build_status=0, cwd=tmp_path)
        calls = _argv_lists(tmp_path)

        assert [call[0] for call in calls] == ["build", "run"], (
            proc.stdout + proc.stderr
        )
        _assert_sandbox_off(calls[1], is_a_scan)

    def test_the_environment_adds_no_runner_options(self, tmp_path):
        """The run's options are the ones ./ash builds, whatever the caller exports.

        ./ash sets every variable it expands into the run, so a MOUNT_OUTPUT_DIR or
        any other value in the caller's environment adds no runner option.
        """
        with_it, with_calls = _run_ash(
            tmp_path / "set",
            build_status=0,
            env_extra={"MOUNT_OUTPUT_DIR": "--privileged --volume /:/host"},
        )
        _, without_calls = _run_ash(tmp_path / "unset", build_status=0)

        assert [call.split()[0] for call in with_calls] == ["build", "run"], (
            with_it.stdout + with_it.stderr
        )
        assert "--privileged" not in with_calls[1], with_calls[1]
        assert [_without(tmp_path / "set", c) for c in with_calls] == [
            _without(tmp_path / "unset", c) for c in without_calls
        ]

    @pytest.mark.parametrize(
        "flags, env_extra, what, value",
        [
            pytest.param(
                [],
                {"ASH_IMAGE_NAME": "my-ash -e ASH_CONFIG=/src/config"},
                "The image name",
                "my-ash -e ASH_CONFIG=/src/config",
                id="ASH_IMAGE_NAME",
            ),
            pytest.param(
                ["--no-build"],
                {"ASH_IMAGE_NAME": "my-ash ash scan --sandbox bwrap --base-ref"},
                "The image name",
                "my-ash ash scan --sandbox bwrap --base-ref",
                id="ASH_IMAGE_NAME-no-build",
            ),
            pytest.param(
                ["--build-target", "non-root ash scan --sandbox bwrap --base-ref"],
                {},
                "--build-target",
                "non-root ash scan --sandbox bwrap --base-ref",
                id="--build-target",
            ),
            pytest.param(
                [],
                {"ASH_IMAGE_NAME": "my-ash:c*"},
                "The image name",
                "my-ash:c*",
                id="ASH_IMAGE_NAME-glob",
            ),
            pytest.param(
                ["--no-build"],
                {"ASH_IMAGE_NAME": "my-ash:c*"},
                "The image name",
                "my-ash:c*",
                id="ASH_IMAGE_NAME-glob-no-build",
            ),
            pytest.param(
                ["--build-target", "c?"],
                {},
                "--build-target",
                "c?",
                id="--build-target-glob",
            ),
        ],
    )
    def test_an_image_name_or_target_outside_its_characters_is_refused(
        self, tmp_path, flags, env_extra, what, value
    ):
        """An image name or build target with a space or a glob character is refused.

        Such a value would split into more than one word, so it is refused, and no
        word of an image name or target reaches the runner or the scan as an
        option. An image name
        holds only A-Z, a-z, 0-9 and . _ : / @ -, and a build target only A-Z, a-z,
        0-9 and . _ -, as Invoke-ASH requires, so either is refused with 3 before the
        output directory is made or the runner is called.
        """
        workdir = tmp_path / "workdir"
        workdir.mkdir(parents=True)
        # Files the glob values would match, were they expanded.
        for decoy in ("my-ash:ci", "ci", "automated-security-helper:ci"):
            (workdir / decoy).write_text("", encoding="utf-8")
        proc, calls = _run_ash(
            tmp_path, *flags, build_status=0, env_extra=env_extra, cwd=workdir
        )

        assert proc.returncode == 3, proc.stdout + proc.stderr
        assert f"{what} '{value}' starts with '-'" in proc.stderr, proc.stderr
        assert "holds a character other than" in proc.stderr, proc.stderr
        assert calls == [], calls
        assert _argv_lists(tmp_path) == []
        assert not (tmp_path / "out").exists()

    @pytest.mark.parametrize(
        "flags, env_extra",
        [
            pytest.param(
                [],
                {"ASH_IMAGE_NAME": "localhost:5000/team_x/ash.v2:1.0-rc"},
                id="ASH_IMAGE_NAME",
            ),
            pytest.param(
                ["--no-build"],
                {"ASH_IMAGE_NAME": "public.ecr.aws/ash@sha256:" + "0" * 64},
                id="ASH_IMAGE_NAME-digest-no-build",
            ),
            pytest.param(["--build-target", "ci"], {}, id="--build-target"),
        ],
    )
    def test_an_image_name_and_target_it_takes_reach_the_runner_whole(
        self, tmp_path, flags, env_extra
    ):
        """An image name or build target ./ash takes reaches the runner unchanged.

        With only the characters each may hold, a value can neither split nor glob,
        so this checks that it arrives as the one argument it was, in the build's
        --tag and --target and in the run.
        """
        target = flags[1] if "--build-target" in flags else "non-root"
        image = env_extra.get("ASH_IMAGE_NAME", f"automated-security-helper:{target}")
        proc, _ = _run_ash(tmp_path, *flags, build_status=0, env_extra=env_extra)
        calls = _argv_lists(tmp_path)

        assert [call[0] for call in calls] == (
            ["run"] if "--no-build" in flags else ["build", "run"]
        ), proc.stdout + proc.stderr
        for call in calls:
            assert call.count(image) == 1, call
        if calls[0][0] == "build":
            build = calls[0]
            assert build[build.index("--tag") + 1] == image, build
            assert build[build.index("--target") + 1] == target, build

    @pytest.mark.parametrize(
        "flags, env_extra, what, value",
        [
            pytest.param(
                [],
                {"ASH_IMAGE_NAME": "--entrypoint=/bin/sh"},
                "The image name",
                "--entrypoint=/bin/sh",
                id="ASH_IMAGE_NAME",
            ),
            pytest.param(
                ["--no-build"],
                {"ASH_IMAGE_NAME": "--entrypoint=/bin/sh"},
                "The image name",
                "--entrypoint=/bin/sh",
                id="ASH_IMAGE_NAME-no-build",
            ),
            # One dash is an option too: -v/:/host mounts the host's root.
            pytest.param(
                ["--no-build"],
                {"ASH_IMAGE_NAME": "-v/:/host"},
                "The image name",
                "-v/:/host",
                id="ASH_IMAGE_NAME-single-dash",
            ),
            pytest.param(
                ["--build-target", "--entrypoint=/bin/sh"],
                {},
                "--build-target",
                "--entrypoint=/bin/sh",
                id="--build-target",
            ),
            pytest.param(
                ["--build-target", "-v/:/host"],
                {},
                "--build-target",
                "-v/:/host",
                id="--build-target-single-dash",
            ),
        ],
    )
    def test_an_image_name_or_target_that_reads_as_an_option_is_refused(
        self, tmp_path, flags, env_extra, what, value
    ):
        """A value that starts with '-' is refused, quoted or not, before anything.

        One word needs no splitting: ASH_IMAGE_NAME='--entrypoint=/bin/sh' would
        read as a run option on its own. A build
        target that starts with '-' is no Dockerfile stage. Either is a value ./ash
        cannot use, so it is refused with 3 before the output directory is made or
        the runner is called.
        """
        proc, calls = _run_ash(tmp_path, *flags, build_status=0, env_extra=env_extra)

        assert proc.returncode == 3, proc.stdout + proc.stderr
        assert f"{what} '{value}' starts with '-'" in proc.stderr, proc.stderr
        # The runtime reads a dash-led image name as an option. A build target
        # reaches it only as --target's value and the tag, and is refused as what
        # it is: not a Dockerfile stage.
        reason = (
            "is not a Dockerfile stage"
            if what == "--build-target"
            else "which the container runtime would read as an option"
        )
        assert reason in proc.stderr, proc.stderr
        assert calls == [], calls
        assert not (tmp_path / "out").exists()

    def test_ash_config_is_carried_for_a_scan_and_reported_for_the_rest(self, tmp_path):
        """A scan run mounts the ASH_CONFIG file and names its container path to
        the scan inside -- as the host's named file and, with no --config of its
        own, as the scan's --config -- changing nothing else; a run of another
        command still says the variable is dropped, once, rather than dropping
        it silently."""
        operator = tmp_path / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")
        with_it, _ = _run_ash(
            tmp_path / "set",
            build_status=0,
            env_extra={"ASH_CONFIG": str(operator)},
        )
        without_it, _ = _run_ash(tmp_path / "unset", build_status=0)

        assert ASH_CONFIG_WARNING not in with_it.stderr, with_it.stderr
        assert ASH_CONFIG_WARNING not in without_it.stderr, without_it.stderr
        with_argv = _argv_lists(tmp_path / "set")[1]
        without_argv = _argv_lists(tmp_path / "unset")[1]
        mount = (
            f"type=bind,source={operator.resolve()},"
            "destination=/ash-env-config/operator.yaml,readonly"
        )
        mount_at = with_argv.index(mount)
        assert with_argv[mount_at - 1] == "--mount", with_argv
        flag_at = with_argv.index("--ash-config-from-host")
        assert with_argv[flag_at + 1] == "/ash-env-config/operator.yaml", with_argv
        config_at = with_argv.index("--config")
        assert with_argv[config_at + 1] == "/ash-env-config/operator.yaml", with_argv
        pruned = [
            word
            for at, word in enumerate(with_argv)
            if at
            not in (
                mount_at - 1,
                mount_at,
                flag_at,
                flag_at + 1,
                config_at,
                config_at + 1,
            )
        ]
        assert [_without(tmp_path / "set", w) for w in pruned] == [
            _without(tmp_path / "unset", w) for w in without_argv
        ]

        reported, _ = _run_ash(
            tmp_path / "rep",
            "report",
            build_status=0,
            env_extra={"ASH_CONFIG": str(operator)},
        )
        assert reported.stderr.count(ASH_CONFIG_WARNING) == 1, reported.stderr
        assert str(operator) in reported.stderr, reported.stderr
        assert "only for a scan" in reported.stderr.split(ASH_CONFIG_WARNING)[1]
        report_argv = _argv_lists(tmp_path / "rep")[1]
        assert mount not in report_argv, report_argv
        assert "--ash-config-from-host" not in report_argv, report_argv

    def test_the_shell_helper_goes_through_ash(self, tmp_path):
        """`invoke-ash` from utils/ash_helpers.sh, sourced the way its header says."""
        env, argv_log, guard_log = _environment(tmp_path)
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, the helper is sourced
            [
                "bash",
                "-c",
                '. utils/ash_helpers.sh && invoke-ash "$@"',
                "ash-helpers-test",
                "--source-dir",
                str(tmp_path / "src"),
                "--output-dir",
                str(tmp_path / "out"),
                "--sandbox",
                "bwrap",
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
            timeout=180,
            check=False,
        )

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert REFUSAL in proc.stderr, proc.stderr
        assert _calls(argv_log, guard_log) == []


@pytest.fixture
def pwsh(in_ci: bool) -> str:
    """Skip only on a developer machine without pwsh; in CI a missing pwsh fails."""
    if PWSH is None:
        if in_ci:
            pytest.fail("pwsh is not on PATH; CI runners must run these tests")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


class _Invocation(NamedTuple):
    how: str
    message: str
    code: str
    calls: List[str]
    output: str


def _invoke_ash(
    pwsh: str,
    tmp_path: Path,
    *words: str,
    build_status: int = 0,
    parameters: str = "",
    env_extra: Optional[Dict[str, str]] = None,
    timeout: int = 180,
) -> _Invocation:
    """Run ``Invoke-ASH -SourceDir src -OutputDir out <parameters> <words>`` under pwsh.

    The words follow Invoke-ASH's own parameters unquoted, as a user types them, so
    PowerShell binds them to -AshArgs. Returns how the call ended (``returned`` or
    ``threw``), the thrown message, $LASTEXITCODE afterwards, the runner's calls and
    everything pwsh printed. A run that outlasts *timeout* seconds raises
    ``subprocess.TimeoutExpired`` after pwsh is killed.
    """
    env, argv_log, guard_log = _environment(tmp_path, build_status, env_extra)
    env.update(POWERSHELL_TELEMETRY_OPTOUT="1", POWERSHELL_UPDATECHECK="Off")
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{PS1.as_posix()}'",
            "$global:LASTEXITCODE = 0",
            "try {",
            "    Invoke-ASH -SourceDir src -OutputDir out -OCIRunner fake-oci-runner "
            + " ".join([parameters, *words]).strip()
            + " | Out-Null",
            "    'RESULT returned'",
            "} catch {",
            "    'RESULT threw'",
            "    'MESSAGE ' + $_.Exception.Message",
            "}",
            "'CODE ' + $global:LASTEXITCODE",
        ]
    )
    proc = subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
    )
    lines = proc.stdout.splitlines()

    def _field(name: str) -> str:
        found = [line[len(name) + 1 :] for line in lines if line.startswith(name + " ")]
        assert len(found) == 1, proc.stdout + proc.stderr
        return found[0]

    return _Invocation(
        how=_field("RESULT"),
        message=_field("MESSAGE") if _field("RESULT") == "threw" else "",
        code=_field("CODE"),
        calls=_calls(argv_log, guard_log),
        output=proc.stdout + proc.stderr,
    )


#: --config-overrides values that hold a word naming a command (scan, report).
_NIGHTLY = "project_name=Nightly scan report"
_WEEKLY = "project_name=Weekly report summary"


@pytest.mark.integration
class TestThePowerShellEntrypoint:
    @pytest.mark.parametrize("words", _REFUSED, ids=" ".join)
    def test_refused_before_the_image_is_built(self, pwsh, tmp_path, words):
        result = _invoke_ash(pwsh, tmp_path, *words)

        assert result.how == "threw", (result.how, result.code)
        assert result.code == "5", result.code
        assert REFUSAL in result.message, result.message
        assert "--mode local" in result.message, result.message
        assert result.calls == [], result.calls
        assert not (tmp_path / "out").exists()

    @pytest.mark.parametrize("words", _NOT_A_MODE, ids=" ".join)
    def test_a_value_that_is_not_a_mode_is_told_the_modes(self, pwsh, tmp_path, words):
        result = _invoke_ash(pwsh, tmp_path, *words)

        assert result.code == "5", result.code
        assert all(mode in result.message for mode in MODES), result.message

    @pytest.mark.parametrize(
        "words, quoted, scan_parses",
        [
            (["'--quiet --sandbox bwrap'"], "--quiet --sandbox bwrap", False),
            (
                ["--config-overrides", "'reporters.x=1 --sandbox=bwrap'"],
                "reporters.x=1 --sandbox=bwrap",
                True,
            ),
            (['"--quiet`n--sandbox`nbwrap"'], "--quiet\n--sandbox\nbwrap", False),
        ],
        ids=["in-one-argument", "in-an-option-value", "over-lines"],
    )
    def test_a_sandbox_inside_a_quoted_argument_stays_inside_it(
        self, pwsh, tmp_path, words, quoted, scan_parses
    ):
        """A quoted argument reaches the scan as one argument, --sandbox and all.

        Invoke-ASH reads -AshArgs with PowerShell's own tokenizer and passes each
        word as one array element, so the --sandbox inside a quoted argument never
        becomes an option of its own (./ash, which splits such an argument again,
        refuses it instead). The scan in the image gets the argument whole, with
        the wrapper's --sandbox off as the only --sandbox: as one word it is an
        unknown option, refused as a usage error, or a --config-overrides value,
        and the scan applies sandbox.mode=off last.
        """
        result = _invoke_ash(pwsh, tmp_path, *words)
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", (result.how, result.message)
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        assert inner.count(quoted) == 1, inner
        assert inner.count("--sandbox") == 1, inner
        assert _has_pair(inner, "--sandbox", "off"), inner
        assert not any(word.startswith("--sandbox=") for word in inner), inner
        code, output, overrides = _parse_inner(inner, tmp_path)
        if scan_parses:
            assert code == 0, (code, output)
            assert overrides is not None and overrides[-1] == "sandbox.mode=off", (
                overrides
            )
        else:
            assert code == ASH_EXIT_USAGE_ERROR, (code, output)
            assert overrides is None, overrides

    @pytest.mark.parametrize(
        "ash_args, value",
        [
            pytest.param(
                f"--config-overrides '{_NIGHTLY}'", _NIGHTLY, id="value-names-scan"
            ),
            pytest.param(
                f"--config-overrides '{_WEEKLY}'", _WEEKLY, id="value-names-report"
            ),
            pytest.param(
                f"scan --config-overrides '{_NIGHTLY}'",
                _NIGHTLY,
                id="value-names-scan-after-scan",
            ),
            pytest.param(
                f"scan --config-overrides '{_WEEKLY}'",
                _WEEKLY,
                id="value-names-report-after-scan",
            ),
        ],
    )
    def test_a_quoted_value_naming_a_command_leaves_sandbox_off_its_own(
        self, pwsh, tmp_path, ash_args, value
    ):
        """Invoke-ASH gives --sandbox off as arguments of its own, around a quoted value.

        Invoke-ASH gives the scan in the image ``--sandbox off``: right after the
        command word, or ahead of every word when no command is named. Invoke-ASH
        reads ``-AshArgs`` as PowerShell tokenizes it and passes the words on as an
        array: a quoted value holding a word that names a command, such as
        ``--config-overrides 'project_name=Nightly scan report'``, stays one word
        and names no command, so ``--sandbox off`` goes right after the real
        command word. The cases after an explicit ``scan`` are controls.
        """
        result = _invoke_ash(pwsh, tmp_path, parameters=f'-AshArgs "{ash_args}"')
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        # The value reaches the scan as one argument, as the caller quoted it.
        assert inner.count(value) == 1, inner
        # --sandbox and off are arguments of their own, given once.
        assert inner.count("--sandbox") == 1, inner
        assert _has_pair(inner, "--sandbox", "off"), inner
        if ash_args.startswith("scan "):
            at = inner.index("scan")
            assert inner[at + 1 : at + 3] == ["--sandbox", "off"], inner
        else:
            assert inner.index("--sandbox") < inner.index("--config-overrides"), inner
        overrides = _scan_overrides(inner, tmp_path)
        assert overrides[-1] == "sandbox.mode=off", overrides
        assert value in overrides, overrides

    def test_control_characters_in_the_value_are_not_echoed(self, pwsh, tmp_path):
        result = _invoke_ash(
            pwsh, tmp_path, "--sandbox", '"$([char]27)[2J$([char]27)[31mRED"'
        )

        assert result.code == "5", result.code
        assert "\x1b" not in result.message, repr(result.message)
        assert "\\x1B[2J\\x1B[31mRED" in result.message, repr(result.message)

    def test_c1_control_characters_in_the_value_are_not_echoed(self, pwsh, tmp_path):
        """Cc is C0, DEL and C1, so CSI (U+009B) is shown as \\x9B too."""
        result = _invoke_ash(
            pwsh, tmp_path, "--sandbox", '"$([char]0x9b)2J$([char]0x9b)31mRED"'
        )

        assert result.code == "5", result.code
        assert chr(0x9B) not in result.message, repr(result.message)
        assert "\\x9B2J\\x9B31mRED" in result.message, repr(result.message)

    @pytest.mark.parametrize("spelling", ["off", "OFF"])
    def test_off_builds_and_reaches_the_scan(self, pwsh, tmp_path, spelling):
        result = _invoke_ash(pwsh, tmp_path, "--sandbox", spelling)

        assert result.how == "returned", result.message
        calls = result.calls
        assert [call.split()[0] for call in calls] == ["build", "run"], calls
        assert f"--sandbox {spelling}" in calls[1], calls[1]

    @pytest.mark.parametrize("command", [[], ["scan"]], ids=["no-command", "scan"])
    def test_a_configured_sandbox_is_turned_off_in_the_container(
        self, pwsh, tmp_path, command
    ):
        result = _invoke_ash(
            pwsh, tmp_path, *command, "--config-overrides", "sandbox.mode=bwrap"
        )
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        assert inner.index("--sandbox") < inner.index("sandbox.mode=bwrap"), inner
        overrides = _scan_overrides(inner, tmp_path)
        assert "sandbox.mode=bwrap" in overrides, overrides
        assert overrides[-1] == "sandbox.mode=off", overrides

    def test_a_double_dash_after_the_command_leaves_the_sandbox_off(
        self, pwsh, tmp_path
    ):
        # Quoted: a bare -- is PowerShell's own end-of-parameters marker. ash scan
        # takes no extra arguments, so with a word after the `--` it refuses it as a
        # usage error and nothing runs; the words still reach it as typed.
        bare = tmp_path / "bare"
        bare.mkdir()
        result = _invoke_ash(
            pwsh, bare, "scan", "--config-overrides", "sandbox.mode=bwrap", "'--'"
        )
        calls = _argv_lists(bare)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        assert inner[:3] == ["scan", "--sandbox", "off"], inner
        assert inner[-1] == "--", inner
        overrides = _scan_overrides(inner, bare)
        assert overrides[-1] == "sandbox.mode=off", overrides

        extra = tmp_path / "extra"
        extra.mkdir()
        result = _invoke_ash(
            pwsh,
            extra,
            "scan",
            "--config-overrides",
            "sandbox.mode=bwrap",
            "'--'",
            "extra",
        )
        calls = _argv_lists(extra)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        inner = _inner_words(calls[1])
        assert inner[inner.index("--") :] == ["--", "extra"], inner
        code, output, overrides = _parse_inner(inner, extra)
        assert code == ASH_EXIT_USAGE_ERROR, (code, output, overrides)
        assert "unexpected extra argument(s) (extra)" in " ".join(output.split())
        assert overrides is None, overrides

    def test_a_trailing_option_cannot_take_sandbox_off_as_its_value(
        self, pwsh, tmp_path
    ):
        result = _invoke_ash(pwsh, tmp_path, "scan", "--base-ref")
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        code, output, overrides = _parse_inner(_inner_words(calls[1]), tmp_path)
        assert code == ASH_EXIT_USAGE_ERROR, (code, output, overrides)
        assert "Option '--base-ref' requires an argument" in " ".join(output.split())
        assert overrides is None, overrides

    def test_a_cli_json_input_document_cannot_turn_the_sandbox_back_on(
        self, pwsh, tmp_path
    ):
        document = tmp_path / "doc.json"
        tmp_path.mkdir(parents=True, exist_ok=True)
        document.write_text(json.dumps(_SANDBOX_DOCUMENT), encoding="utf-8")

        result = _invoke_ash(
            pwsh, tmp_path, "scan", "--cli-json-input", f"'{document.as_posix()}'"
        )
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        overrides = _scan_overrides(_inner_words(calls[1]), tmp_path)
        assert overrides[-1] == "sandbox.mode=off", overrides
        assert "reporters.markdown.options.compact=true" in overrides, overrides

    @pytest.mark.parametrize("words, is_a_scan", _COMMAND_POSITION)
    def test_only_a_scan_is_given_sandbox_off(self, pwsh, tmp_path, words, is_a_scan):
        # Quoted, so PowerShell binds -f and -Pf to -AshArgs, not as parameters.
        result = _invoke_ash(pwsh, tmp_path, *[f"'{word}'" for word in words])
        calls = _argv_lists(tmp_path)

        assert result.how == "returned", result.message
        assert [call[0] for call in calls] == ["build", "run"], calls
        _assert_sandbox_off(calls[1], is_a_scan)

    @pytest.mark.parametrize(
        "parameters, env_extra, value",
        [
            pytest.param(
                "",
                {"ASH_IMAGE_NAME": "--entrypoint=/bin/sh"},
                "--entrypoint=/bin/sh",
                id="env",
            ),
            pytest.param(
                "-AshImageName '--entrypoint=/bin/sh'",
                {},
                "--entrypoint=/bin/sh",
                id="parameter",
            ),
            pytest.param(
                "-AshImageName '-v/:/host'", {}, "-v/:/host", id="single-dash"
            ),
            # Invoke-Expression reads the joined command again, so a space splits
            # the name: ' --privileged my:tag' gave the run --privileged.
            pytest.param(
                "-AshImageName ' --privileged my:tag' -NoBuild",
                {},
                " --privileged my:tag",
                id="leading-space",
            ),
            pytest.param(
                "-AshImageName 'my:tag --privileged' -NoBuild",
                {},
                "my:tag --privileged",
                id="inner-space",
            ),
        ],
    )
    def test_an_image_name_that_reads_as_an_option_is_refused(
        self, pwsh, tmp_path, parameters, env_extra, value
    ):
        """The same as ./ash: a value it cannot use, refused with 3 and a throw.

        Invoke-ASH passes the image name to the runner as one argument and never
        through Invoke-Expression. An image name may hold only
        A-Z, a-z, 0-9 and . _ : / @ -, so one with a space is refused as well.
        """
        result = _invoke_ash(pwsh, tmp_path, parameters=parameters, env_extra=env_extra)

        assert result.how == "threw", (result.how, result.code)
        assert result.code == "3", result.code
        assert f"'{value}" in result.message, result.message
        assert result.calls == [], result.calls
        assert not (tmp_path / "out").exists()

    def test_ash_config_outside_the_source_is_mounted_and_named_by_container_path(
        self, pwsh, tmp_path
    ):
        """Without -Config, the file ASH_CONFIG names is mounted read-only at
        /ash-env-config and the scan is given that container path, both as its
        --config and as --ash-config-from-host. The host path reaches the run
        only as the mount's source, after the /src and /out mounts."""
        operator = tmp_path / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")
        inner_path = "/ash-env-config/operator.yaml"

        result = _invoke_ash(
            pwsh, tmp_path / "run", env_extra={"ASH_CONFIG": str(operator)}
        )
        runs = [call for call in _argv_lists(tmp_path / "run") if call[0] == "run"]

        assert result.how == "returned", result.message
        assert ASH_CONFIG_WARNING not in result.output, result.output
        assert len(runs) == 1, runs
        run = runs[0]
        mounts = [run[i + 1] for i, word in enumerate(run[:-1]) if word == "--mount"]
        env_mount = f"type=bind,source={operator},destination={inner_path},readonly"
        assert env_mount in mounts, mounts
        destinations = [m.split("destination=")[1].split(",")[0] for m in mounts]
        assert destinations == ["/src", "/out", inner_path], destinations
        inner = _inner_words(run)
        assert _has_pair(inner, "--config", inner_path), inner
        assert _has_pair(inner, "--ash-config-from-host", inner_path), inner
        assert all(str(operator) not in word for word in inner), inner

    def test_ash_config_inside_the_source_is_read_through_src(self, pwsh, tmp_path):
        """A config inside the source directory is not mounted: the scan reads it
        through /src, where it judges the file itself."""
        inside = tmp_path / "run" / "src" / "nested"
        inside.mkdir(parents=True)
        operator = inside / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")

        result = _invoke_ash(
            pwsh, tmp_path / "run", env_extra={"ASH_CONFIG": str(operator)}
        )
        runs = [call for call in _argv_lists(tmp_path / "run") if call[0] == "run"]

        assert result.how == "returned", result.message
        assert len(runs) == 1, runs
        run = runs[0]
        mounts = [run[i + 1] for i, word in enumerate(run[:-1]) if word == "--mount"]
        assert [m.split("destination=")[1].split(",")[0] for m in mounts] == [
            "/src",
            "/out",
        ], mounts
        inner = _inner_words(run)
        assert _has_pair(inner, "--config", "/src/nested/operator.yaml"), inner
        assert _has_pair(
            inner, "--ash-config-from-host", "/src/nested/operator.yaml"
        ), inner

    def test_a_missing_ash_config_is_refused_before_any_runner_call(
        self, pwsh, tmp_path
    ):
        result = _invoke_ash(
            pwsh, tmp_path, env_extra={"ASH_CONFIG": str(tmp_path / "absent.yaml")}
        )

        assert result.how == "threw", (result.how, result.output)
        assert result.code == "3", result.code
        assert "Config file not found" in result.message, result.message
        assert "--config (or ASH_CONFIG) has to name an existing file" in (
            result.message
        )
        assert result.calls == [], result.calls

    def test_an_ash_config_outside_the_source_that_extends_is_refused(
        self, pwsh, tmp_path
    ):
        operator = tmp_path / "operator.yaml"
        operator.write_text("extends: base.yaml\nfail_on_findings: true\n", "utf-8")

        result = _invoke_ash(pwsh, tmp_path, env_extra={"ASH_CONFIG": str(operator)})

        assert result.how == "threw", (result.how, result.output)
        assert result.code == "3", result.code
        message = " ".join(result.message.split())
        assert "is outside the source directory and has an extends entry" in message
        assert "Run ash --mode container, which mounts the chain" in message
        assert result.calls == [], result.calls

    def _refused_before_any_call(self, result, fragment):
        assert result.how == "threw", result.output
        assert fragment in result.message, result.message
        assert result.code == "3", result.code
        assert result.calls == [], result.calls

    def test_a_link_in_the_source_that_leads_outside_is_refused(self, pwsh, tmp_path):
        """A file named inside the scanned tree whose real path is outside it is
        refused: the repository being scanned would choose which host file is
        mounted. Nothing is built or run, and no mount names the outside file."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        outside = tmp_path / "outside.yaml"
        outside.write_text("project_name: outside\n", encoding="utf-8")
        link = root / "src" / "cfg.yaml"
        link.symlink_to(outside)

        result = _invoke_ash(pwsh, root, env_extra={"ASH_CONFIG": str(link)})

        self._refused_before_any_call(result, "is a link, or is reached through one")
        assert str(outside) in result.message, result.message
        assert not any(str(outside) in m for argv in _argv_lists(root) for m in argv)

    def test_a_directory_link_in_the_source_that_leads_outside_is_refused(
        self, pwsh, tmp_path
    ):
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        outdir = tmp_path / "outdir"
        outdir.mkdir()
        (outdir / "cfg.yaml").write_text("project_name: outside\n", encoding="utf-8")
        (root / "src" / "d").symlink_to(outdir, target_is_directory=True)

        result = _invoke_ash(
            pwsh, root, env_extra={"ASH_CONFIG": str(root / "src" / "d" / "cfg.yaml")}
        )

        self._refused_before_any_call(result, "is a link, or is reached through one")
        assert not any(str(outdir) in m for argv in _argv_lists(root) for m in argv)

    def test_a_link_in_the_source_that_stays_inside_is_followed(self, pwsh, tmp_path):
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        (root / "src" / "real.yaml").write_text("project_name: in\n", encoding="utf-8")
        alias = root / "src" / "alias.yaml"
        alias.symlink_to("real.yaml")

        result = _invoke_ash(pwsh, root, env_extra={"ASH_CONFIG": str(alias)})

        assert result.how == "returned", result.message
        runs = [argv for argv in _argv_lists(root) if argv[:1] == ["run"]]
        assert len(runs) == 1, runs
        inner = _inner_words(runs[0])
        assert _has_pair(inner, "--config", "/src/real.yaml"), inner
        assert _has_pair(inner, "--ash-config-from-host", "/src/real.yaml"), inner
        assert not any("ash-env-config" in word for word in runs[0]), runs[0]

    def test_a_link_loop_on_the_ash_config_path_is_refused_not_passed(
        self, pwsh, tmp_path
    ):
        """A link that cannot be followed is a refusal: the loop is the arm's own
        words, not the shared prefix the unreadable-file arm also prints."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        (root / "src" / "a.yaml").symlink_to("b.yaml")
        (root / "src" / "b.yaml").symlink_to("a.yaml")

        result = _invoke_ash(
            pwsh, root, env_extra={"ASH_CONFIG": str(root / "src" / "a.yaml")}
        )

        self._refused_before_any_call(result, "A link on its path cannot be followed")

    def test_a_dotdot_after_a_link_in_the_name_reads_the_file_the_kernel_reads(
        self, pwsh, tmp_path
    ):
        """``names/lnk/../cfg.yaml`` is the file beside the link's target, not the
        file beside the link: the name is resolved as written, one component at a
        time, so the mount is the target's sibling and never the decoy."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        target_dir = tmp_path / "targets" / "sub"
        target_dir.mkdir(parents=True)
        real = target_dir.parent / "cfg.yaml"
        real.write_text("project_name: real\n", encoding="utf-8")
        names = tmp_path / "names"
        names.mkdir()
        decoy = names / "cfg.yaml"
        decoy.write_text("project_name: decoy\n", encoding="utf-8")
        (names / "lnk").symlink_to(target_dir, target_is_directory=True)

        result = _invoke_ash(
            pwsh,
            root,
            env_extra={"ASH_CONFIG": str(names / "lnk" / ".." / "cfg.yaml")},
        )
        runs = [argv for argv in _argv_lists(root) if argv[:1] == ["run"]]

        assert result.how == "returned", result.message
        assert len(runs) == 1, runs
        mounts = [
            runs[0][i + 1] for i, word in enumerate(runs[0][:-1]) if word == "--mount"
        ]
        assert (
            f"type=bind,source={real},destination=/ash-env-config/cfg.yaml,readonly"
            in mounts
        ), mounts
        assert not any(str(decoy) in mount for mount in mounts), mounts

    @pytest.mark.parametrize("collapsed_file", [False, True], ids=["absent", "present"])
    def test_a_dotdot_after_a_link_in_the_checkout_is_the_trees_name_and_is_refused(
        self, pwsh, tmp_path, collapsed_file
    ):
        """``<checkout>/lnk/../cfg.yaml`` with ``lnk`` leading out of the checkout
        is refused as ./ash refuses it, whether or not a file named cfg.yaml sits in
        the checkout: the link is the checkout's, so the rest of the name is its to
        steer."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        mark_git_checkout(root)
        (root / "src").mkdir()
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "dir").mkdir(parents=True)
        (elsewhere / "cfg.yaml").write_text("project_name: outside\n", encoding="utf-8")
        (root / "lnk").symlink_to(elsewhere / "dir", target_is_directory=True)
        if collapsed_file:
            (root / "cfg.yaml").write_text("project_name: inside\n", encoding="utf-8")

        result = _invoke_ash(
            pwsh,
            root,
            env_extra={"ASH_CONFIG": str(root / "lnk" / ".." / "cfg.yaml")},
        )

        self._refused_before_any_call(result, "is a link, or is reached through one")
        assert str(elsewhere / "cfg.yaml") in result.message, result.message

    def test_an_outside_alias_of_the_checkout_does_not_hide_a_link_it_holds(
        self, pwsh, tmp_path
    ):
        """The checkout reached through a link of the operator's own, with a link
        the checkout holds leading out of it: the name is judged by the link the
        checkout holds, whichever way the checkout is spelled."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        mark_git_checkout(root)
        (root / "src").mkdir()
        (root / ".ash").mkdir()
        outside = tmp_path / "outside.yaml"
        outside.write_text("project_name: outside\n", encoding="utf-8")
        (root / ".ash" / "ash.yaml").symlink_to(outside)
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)

        result = _invoke_ash(
            pwsh, root, env_extra={"ASH_CONFIG": str(alias / ".ash" / "ash.yaml")}
        )

        self._refused_before_any_call(result, "is a link, or is reached through one")
        assert not any(str(outside) in m for argv in _argv_lists(root) for m in argv)

    def test_a_checkout_that_is_itself_a_link_is_not_a_link_in_the_tree(
        self, pwsh, tmp_path
    ):
        """The twin of two ./ash tests in
        tests/unit/test_the_container_wrappers_carry_the_operators_config.py,
        test_a_checkout_that_is_itself_a_link_is_not_refused_as_a_link_in_the_tree
        and test_a_checkout_that_is_itself_a_link_does_not_mark_a_file_beside_it_as_the_repositorys:
        the operator works in a link to the checkout, with a shared config beside the
        checkout. The ".." after the checkout's own link leaves the checkout, so the
        file is mounted, neither refused nor marked as the repository's. ./ash tests
        the link's parent against the trees and this wrapper tests the link's own path
        for a place strictly below one; the two answer alike."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        root.mkdir()
        real = tmp_path / "data-root" / "repo"
        mark_git_checkout(real)
        shared = tmp_path / "data-root" / "shared"
        shared.mkdir()
        (shared / "cfg.yaml").write_text("project_name: shared\n", encoding="utf-8")
        (root / "src").symlink_to(real, target_is_directory=True)

        result = _invoke_ash(
            pwsh, root, env_extra={"ASH_CONFIG": f"{root}/src/../shared/cfg.yaml"}
        )
        runs = [argv for argv in _argv_lists(root) if argv[:1] == ["run"]]

        assert result.how == "returned", result.message
        assert len(runs) == 1, runs
        mounts = [
            runs[0][i + 1] for i, word in enumerate(runs[0][:-1]) if word == "--mount"
        ]
        assert (
            f"type=bind,source={(shared / 'cfg.yaml').resolve()},"
            "destination=/ash-env-config/cfg.yaml,readonly"
        ) in mounts, mounts
        assert not any("from-scanned-repository" in word for word in runs[0]), runs[0]

    def test_a_name_back_into_the_checkout_through_its_own_link_still_meets_the_links_it_holds(
        self, pwsh, tmp_path
    ):
        """The operator's link to the checkout is followed out of the checkout by a
        "..", and the name comes back in by the checkout's real name to a link the
        checkout holds that leads outside it. The walk goes on past the operator's
        link, so the name is the tree's and the file is refused as one the
        repository chose."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        root.mkdir()
        real = tmp_path / "data-root" / "repo"
        mark_git_checkout(real)
        outside = tmp_path / "outside.yaml"
        outside.write_text("project_name: outside\n", encoding="utf-8")
        (real / "lnk.yaml").symlink_to(outside)
        (root / "src").symlink_to(real, target_is_directory=True)

        result = _invoke_ash(
            pwsh, root, env_extra={"ASH_CONFIG": f"{root}/src/../repo/lnk.yaml"}
        )

        self._refused_before_any_call(result, "is a link, or is reached through one")

    def test_an_ash_config_under_a_directory_that_cannot_be_searched_is_refused(
        self, pwsh, tmp_path
    ):
        """A name that cannot be looked up is refused, as ./ash refuses it, never
        passed. The file check comes first in both wrappers and refuses a path
        under a directory that cannot be searched with the missing-file text, so
        either text is the refusal here; the walk's own arm is pinned as text."""
        if os.name == "nt" or os.geteuid() == 0:
            pytest.skip("directory modes do not stop this user from searching")
        locked = tmp_path / "locked"
        locked.mkdir()
        (locked / "cfg.yaml").write_text("project_name: x\n", encoding="utf-8")
        locked.chmod(0)
        try:
            result = _invoke_ash(
                pwsh,
                tmp_path / "set",
                env_extra={"ASH_CONFIG": str(locked / "cfg.yaml")},
            )
        finally:
            locked.chmod(0o700)

        assert result.how == "threw", result.output
        assert result.code == "3", result.code
        assert result.calls == [], result.calls
        assert (
            "Config file not found" in result.message
            or "cannot be searched" in result.message
        ), result.message

    def test_a_source_directory_behind_too_many_links_is_a_usage_error(
        self, pwsh, tmp_path
    ):
        """The code is the usage-error code, 5, as ./ash gives a source directory
        it cannot enter, whichever check of the wrapper refuses it first."""
        if os.name == "nt":
            pytest.skip("creating a symbolic link needs a privilege on Windows")
        root = tmp_path / "set"
        root.mkdir()
        (root / "real").mkdir()
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: x\n", encoding="utf-8")
        target = "real"
        for hop in range(41, 0, -1):
            (root / f"hop{hop}").symlink_to(target, target_is_directory=True)
            target = f"hop{hop}"
        (root / "src").symlink_to(target, target_is_directory=True)

        result = _invoke_ash(pwsh, root, env_extra={"ASH_CONFIG": str(operator)})

        assert result.how == "threw", result.output
        assert result.message.startswith("Source directory"), result.message
        assert result.code == "5", result.code
        assert result.calls == [], result.calls

    def _refused_as_not_a_file_and_never_hangs(self, pwsh, root, config):
        """Refused with the missing-file text before anything opens the path. A
        regression would block on the open or read without end, so the run has a
        timeout of its own, and running out of it is a failure."""
        try:
            result = _invoke_ash(
                pwsh, root, env_extra={"ASH_CONFIG": str(config)}, timeout=60
            )
        except subprocess.TimeoutExpired:
            pytest.fail(f"Invoke-ASH did not return for ASH_CONFIG={config}")
        self._refused_before_any_call(result, "Config file not found")

    def test_a_fifo_as_ash_config_is_refused_not_opened(self, pwsh, tmp_path):
        """A FIFO made with permission bits 0644 is the case where the mode text
        starts with a dash: its type has to be read, not guessed from that text."""
        if not hasattr(os, "mkfifo"):
            pytest.skip("named pipes need a POSIX host")
        fifo = tmp_path / "p.yaml"
        os.mkfifo(fifo)
        fifo.chmod(0o644)

        self._refused_as_not_a_file_and_never_hangs(pwsh, tmp_path / "set", fifo)

    def test_a_character_device_as_ash_config_is_refused(self, pwsh, tmp_path):
        device = Path(os.devnull)
        if not device.exists() or os.name == "nt":
            pytest.skip("needs a character device such as /dev/null")

        self._refused_as_not_a_file_and_never_hangs(pwsh, tmp_path / "set", device)

    def test_a_directory_as_ash_config_is_refused(self, pwsh, tmp_path):
        directory = tmp_path / "configs"
        directory.mkdir()

        self._refused_as_not_a_file_and_never_hangs(pwsh, tmp_path / "set", directory)

    def test_a_backslash_in_an_in_source_name_is_carried_whole_off_windows(
        self, pwsh, tmp_path
    ):
        if os.name == "nt":
            pytest.skip("a backslash separates directories on Windows")
        root = tmp_path / "set"
        (root / "src").mkdir(parents=True)
        named = root / "src" / "a\\b.yaml"
        named.write_text("project_name: in\n", encoding="utf-8")

        result = _invoke_ash(pwsh, root, env_extra={"ASH_CONFIG": str(named)})

        assert result.how == "returned", result.message
        runs = [argv for argv in _argv_lists(root) if argv[:1] == ["run"]]
        assert len(runs) == 1, runs
        assert _has_pair(_inner_words(runs[0]), "--config", "/src/a\\b.yaml"), runs

    @pytest.mark.parametrize("shadowed", [False, True])
    def test_a_backslash_name_that_names_no_file_is_refused_as_not_found(
        self, pwsh, tmp_path, shadowed
    ):
        """The other direction of the backslash cell: a file that exists under the
        name with the backslash read as a separator must not stand in for a name
        that is not there."""
        if os.name == "nt":
            pytest.skip("a backslash separates directories on Windows")
        root = tmp_path / "set"
        (root / "src" / "a").mkdir(parents=True)
        if shadowed:
            (root / "src" / "a" / "b.yaml").write_text(
                "project_name: in\n", encoding="utf-8"
            )
        absent = root / "src" / "a\\b.yaml"

        result = _invoke_ash(pwsh, root, env_extra={"ASH_CONFIG": str(absent)})

        self._refused_before_any_call(result, "Config file not found")

    def test_a_fifo_with_a_backslash_in_its_name_is_refused_not_opened(
        self, pwsh, tmp_path
    ):
        if not hasattr(os, "mkfifo") or os.name == "nt":
            pytest.skip("named pipes need a POSIX host")
        fifo = tmp_path / "p\\q.yaml"
        os.mkfifo(fifo)
        fifo.chmod(0o644)

        self._refused_as_not_a_file_and_never_hangs(pwsh, tmp_path / "set", fifo)

    def test_an_unreadable_ash_config_is_refused_before_any_runner_call(
        self, pwsh, tmp_path
    ):
        if os.name == "nt" or os.geteuid() == 0:
            pytest.skip("file modes do not stop this user from reading")
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: x\n", encoding="utf-8")
        operator.chmod(0)
        try:
            result = _invoke_ash(
                pwsh, tmp_path / "set", env_extra={"ASH_CONFIG": str(operator)}
            )
        finally:
            operator.chmod(0o600)

        self._refused_before_any_call(result, "Config file cannot be read")

    def test_ash_config_is_neither_refused_nor_reported_when_nothing_runs(
        self, pwsh, tmp_path
    ):
        """As in ./ash, -NoRun gates the whole ASH_CONFIG handling: a run that
        will not happen refuses nothing and warns about nothing. The image build
        still runs, so the assertion is that no run call was recorded."""
        absent = str(tmp_path / "absent.yaml")

        for words in (["report"], []):
            root = tmp_path / ("-".join(words) or "scan")
            result = _invoke_ash(
                pwsh,
                root,
                *words,
                parameters="-NoRun",
                env_extra={"ASH_CONFIG": absent},
            )

            assert result.how == "returned", (words, result.message)
            assert ASH_CONFIG_WARNING not in result.output, (words, result.output)
            assert "Config file not found" not in result.output, (words, result.output)
            runs = [a for a in _argv_lists(root) if a[:1] == ["run"]]
            assert runs == [], (words, runs)

    def test_an_ash_config_path_a_mount_cannot_take_is_refused(self, pwsh, tmp_path):
        if os.name == "nt":
            pytest.skip("a comma is a legal Windows name but the cell is POSIX-shaped")
        operator = tmp_path / "a,b.yaml"
        operator.write_text("project_name: x\n", encoding="utf-8")

        result = _invoke_ash(
            pwsh, tmp_path / "set", env_extra={"ASH_CONFIG": str(operator)}
        )

        self._refused_before_any_call(result, "which a container runtime's --mount")

    def test_ash_config_beside_config_is_carried_and_the_explicit_config_wins(
        self, pwsh, tmp_path
    ):
        """As ./ash does: the file ASH_CONFIG names is mounted and named to the
        scan as the host's config whether or not -Config is given, and it is the
        scan's own --config only without one. With both set, the scan is given
        -Config's file as its --config, as written, and nothing is printed about
        the variable."""
        operator = tmp_path / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")
        environment_named = tmp_path / "environment.yaml"
        environment_named.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")
        inner_path = "/ash-env-config/environment.yaml"

        result = _invoke_ash(
            pwsh,
            tmp_path / "run",
            parameters=f"-Config '{operator.as_posix()}'",
            env_extra={"ASH_CONFIG": str(environment_named)},
        )
        runs = [call for call in _argv_lists(tmp_path / "run") if call[0] == "run"]

        assert result.how == "returned", result.message
        assert ASH_CONFIG_WARNING not in result.output, result.output
        assert len(runs) == 1, runs
        run = runs[0]
        mounts = [run[i + 1] for i, word in enumerate(run[:-1]) if word == "--mount"]
        env_mount = (
            f"type=bind,source={environment_named},destination={inner_path},readonly"
        )
        assert env_mount in mounts, mounts
        inner = _inner_words(run)
        assert _has_pair(inner, "--ash-config-from-host", inner_path), inner
        assert _has_pair(inner, "--config", operator.as_posix()), inner
        assert inner.count("--config") == 1, inner
        assert "--config-from-scanned-repository" not in inner, inner

    def test_a_config_the_checkout_holds_is_marked_as_the_host_config_beside_config(
        self, pwsh, tmp_path
    ):
        """A mounted ASH_CONFIG file the scanned checkout holds is marked as the
        repository's. With -Config given it is the host's config alone, so only
        its own mark is passed; the scan's --config is -Config's file, whose mark
        the scan inside works out itself."""
        checkout = tmp_path / "set"
        mark_git_checkout(checkout)
        (checkout / "ci").mkdir()
        held = checkout / "ci" / "ash.yaml"
        held.write_text("project_name: held\n", encoding="utf-8")
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        inner_path = "/ash-env-config/ash.yaml"

        result = _invoke_ash(
            pwsh,
            checkout,
            parameters=f"-Config '{operator.as_posix()}'",
            env_extra={"ASH_CONFIG": str(held)},
        )
        runs = [c for c in _argv_lists(checkout) if c[0] == "run"]

        assert result.how == "returned", result.message
        assert len(runs) == 1, runs
        inner = _inner_words(runs[0])
        assert _has_pair(inner, "--ash-config-from-host", inner_path), inner
        assert _has_pair(inner, "--config-file-from-scanned-repository", inner_path), (
            inner
        )
        assert _has_pair(inner, "--config", operator.as_posix()), inner
        assert "--config-from-scanned-repository" not in inner, inner

    def test_a_config_the_checkout_holds_is_the_scans_config_and_marked_without_config(
        self, pwsh, tmp_path
    ):
        checkout = tmp_path / "set"
        mark_git_checkout(checkout)
        (checkout / "ci").mkdir()
        held = checkout / "ci" / "ash.yaml"
        held.write_text("project_name: held\n", encoding="utf-8")
        inner_path = "/ash-env-config/ash.yaml"

        result = _invoke_ash(pwsh, checkout, env_extra={"ASH_CONFIG": str(held)})
        runs = [c for c in _argv_lists(checkout) if c[0] == "run"]

        assert result.how == "returned", result.message
        assert len(runs) == 1, runs
        inner = _inner_words(runs[0])
        assert _has_pair(inner, "--config", inner_path), inner
        assert _has_pair(inner, "--ash-config-from-host", inner_path), inner
        assert _has_pair(inner, "--config-file-from-scanned-repository", inner_path), (
            inner
        )
        assert "--config-from-scanned-repository" in inner, inner

    def test_a_report_with_config_still_reports_ash_config_once(self, pwsh, tmp_path):
        """The variable is not passed to a command other than a scan, and that is
        said once, whether or not -Config is given."""
        operator = tmp_path / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")
        environment_named = tmp_path / "environment.yaml"
        environment_named.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")

        result = _invoke_ash(
            pwsh,
            tmp_path / "report",
            "report",
            parameters=f"-Config '{operator.as_posix()}'",
            env_extra={"ASH_CONFIG": str(environment_named)},
        )

        assert result.how == "returned", result.message
        assert result.output.count(ASH_CONFIG_WARNING) == 1, result.output
        assert "only for a scan" in result.output.split(ASH_CONFIG_WARNING)[1]
        runs = [call for call in result.calls if call.split()[0] == "run"]
        assert runs, result.calls
        assert all("environment.yaml" not in call for call in runs), runs
        assert all("--ash-config-from-host" not in call for call in runs), runs

    def test_ash_config_is_carried_only_for_a_scan(self, pwsh, tmp_path):
        """As ./ash does: a set ASH_CONFIG is the config of a scan, and a
        subcommand that is not a scan is warned about and not given it."""
        operator = tmp_path / "operator.yaml"
        operator.write_text('sandbox:\n  mode: "landlock"\n', encoding="utf-8")

        result = _invoke_ash(
            pwsh, tmp_path / "report", "report", env_extra={"ASH_CONFIG": str(operator)}
        )

        assert result.how == "returned", result.message
        assert result.output.count(ASH_CONFIG_WARNING) == 1, result.output
        assert "only for a scan" in result.output.split(ASH_CONFIG_WARNING)[1]
        runs = [call for call in result.calls if call.split()[0] == "run"]
        assert runs, result.calls
        assert all("--config" not in call.split() for call in runs), runs
        assert all(str(operator) not in call for call in runs), runs


def _wrapper_words_hold_dash_c(text: str) -> bool:
    """Whether the wrapper's own-words list names -c, which ./ash reads as
    --config and the wrapper consumes rather than forwards."""
    found = re.search(r"\$wrapperWords\s*=\s*@\(([^)]*)\)", text)
    if found is None:
        return False
    return "'-c'" in [part.strip() for part in found.group(1).split(",")]


def _config_add_sites(text: str) -> List[str]:
    """Every place the wrapper builds a --config argument pair, as written."""
    return [line.strip() for line in text.splitlines() if "@('--config'," in line]


def _remembers_a_placeholder_group(text: str) -> bool:
    """Whether a --config group with an empty value is remembered ahead of the
    subcommand, to be filled in later by a condition of its own."""
    return "@('--config', '')" in text or "[object]::ReferenceEquals(" in text


def _carry_does_not_wait_for_no_config(text: str) -> bool:
    """Whether the ASH_CONFIG carry is decided by the variable alone."""
    return (
        re.search(
            r"^\s*\$envConfigPending = -not \[string\]::IsNullOrEmpty\(\$env:ASH_CONFIG\)$",
            text,
            re.MULTILINE,
        )
        is not None
    )


def _regular_file_check_reads_the_item_type(text: str) -> bool:
    """Whether the regular-file check reads UnixStat.ItemType, and never the
    UnixMode string, which starts with a dash for any item whose permission bits
    are 0444 or 0644 whatever its type."""
    start = text.index("function Test-AshRegularFile")
    body = text[start : text.index("function Get-AshNamedPath", start)]
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )
    return (
        "$found.PSObject.Properties['UnixStat']" in code
        and "([string]$unixStat.Value.ItemType) -ceq 'File'" in code
        and "UnixMode" not in code
        and "FileAttributes]::Device" in code
    )


def _name_is_resolved_as_written(text: str) -> bool:
    """Whether the ASH_CONFIG string, made absolute, is what is resolved, and
    no item property that PowerShell has already collapsed by text is."""
    carry = text[text.index("$envConfigAbsolute = ") :]
    carry = carry[: carry.index("$envConfigGroups.Add(@('--ash-config-from-host'")]
    return (
        "$envConfigReal = Resolve-AshRealPath $envConfigAbsolute" in carry
        and "$envConfigNamed = Get-AshNamedPath $envConfigAbsolute" in carry
        and "$envConfigItem" not in carry
        and "Get-Item -LiteralPath $envConfigGiven" not in carry
    )


def _flat(text: str) -> str:
    """The wrapper's text with every run of whitespace read as one space, so a
    text pin does not depend on indentation or line breaks."""
    return " ".join(text.split())


def _source_directory_refusals_are_usage_errors(text: str) -> bool:
    """Whether every refusal worded "Source directory cannot be entered" sets the
    usage-error code as the nearest assignment of the exit code before it, as
    ./ash gives it (a condition may sit between them). Read from _flat text."""
    sites = [
        found.start()
        for found in re.finditer(
            re.escape('throw "Source directory cannot be entered'), text
        )
    ]
    assignment = "$global:LASTEXITCODE = "
    return bool(sites) and all(
        text.startswith(
            assignment + "$usageErrorExitCode", text.rfind(assignment, 0, at)
        )
        and text.rfind(assignment, 0, at) != -1
        for at in sites
    )


def _name_walk_refuses_a_directory_it_cannot_search(text: str) -> bool:
    """Whether the walk of the name, like ./ash's, cannot decide on a name whose
    directory cannot be searched, and the carry refuses it."""
    start = text.index("function Get-AshNamedPath")
    end = text.index("if ($envConfigPending -and -not $NoRun -and $subcommand", start)
    walk = text[start:end]
    carry = text[end:]
    return (
        "elseif ($null -eq (Get-Item -LiteralPath $walked -Force -ErrorAction SilentlyContinue))"
        in walk
        and "-not (Test-AshSearchable $walkedParent)" in walk
        and "$UndecidedAt.Value = 'directory'" in walk
        and "$envConfigUndecidedAt -ceq 'directory'" in carry
        and "goes through a directory that cannot be searched" in carry
    )


@pytest.mark.unit
class TestThePowerShellConfigCarryAsText:
    """The ps1 carry of a config is pinned in the text, so no pwsh is needed."""

    def test_a_source_directory_that_cannot_be_entered_is_a_usage_error(self):
        text = _flat(PS1.read_text(encoding="utf-8"))

        assert _source_directory_refusals_are_usage_errors(text)

    def test_the_text_cell_goes_red_for_a_source_directory_refused_with_3(self):
        text = _flat(PS1.read_text(encoding="utf-8"))
        mutant = text.replace(
            "$global:LASTEXITCODE = $usageErrorExitCode "
            'throw "Source directory cannot be entered: '
            "$(Format-AshShownValue $SourceDir). A link",
            "$global:LASTEXITCODE = $refusalExitCode "
            'throw "Source directory cannot be entered: '
            "$(Format-AshShownValue $SourceDir). A link",
            1,
        )

        assert mutant != text
        assert not _source_directory_refusals_are_usage_errors(mutant)

    def test_a_name_in_a_directory_that_cannot_be_searched_is_not_walked_on(self):
        text = PS1.read_text(encoding="utf-8")

        assert _name_walk_refuses_a_directory_it_cannot_search(text)

    def test_the_text_cell_goes_red_when_the_walk_goes_on_past_such_a_directory(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "elseif ($null -eq (Get-Item -LiteralPath $walked -Force -ErrorAction SilentlyContinue)) {",
            "elseif ($false) {",
            1,
        )

        assert mutant != text
        assert not _name_walk_refuses_a_directory_it_cannot_search(mutant)

    def test_dash_c_is_a_wrapper_word_and_never_a_config_carry(self):
        text = PS1.read_text(encoding="utf-8")

        assert _wrapper_words_hold_dash_c(text)
        # One explicit site, which keeps the spelling given, and one environment
        # site: the container-path group a scan is given once the file is resolved.
        # No site builds a --config pair from the host value of ASH_CONFIG, and no
        # placeholder group is remembered before the subcommand is known.
        assert _config_add_sites(text) == [
            "$ashCmdArgs.Add(@('--config', $Config))",
            "$envConfigGroups.Add(@('--config', $envConfigInner))",
        ]

    def test_the_text_cell_goes_red_without_dash_c_in_the_wrapper_words(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace("'--no-color', '-c')", "'--no-color')", 1)

        assert mutant != text
        assert not _wrapper_words_hold_dash_c(mutant)

    def test_the_text_cell_goes_red_for_a_third_config_carry(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "$ashCmdArgs.Add(@('--offline'))",
            "$ashCmdArgs.Add(@('--offline'))\n"
            "            $ashCmdArgs.Add(@('--config', $x))",
            1,
        )

        assert mutant != text
        assert len(_config_add_sites(mutant)) == 3

    def test_no_placeholder_config_group_is_patched_in_place(self):
        """The ASH_CONFIG words are built once the file is resolved and inserted
        where the -Config words sit, so no group with empty values is remembered
        before the subcommand is known, and no second condition has to agree with
        the one that fills it."""
        text = PS1.read_text(encoding="utf-8")

        assert not _remembers_a_placeholder_group(text)
        remembered = text.index("$envConfigAt = $ashCmdArgs.Count")
        inserted = text.index("$ashCmdArgs.Insert($envConfigAt + $i")
        assert remembered < text.index("$ashSubcommands = ") < inserted

    def test_the_text_cell_goes_red_for_a_placeholder_group(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "$envConfigGroups = [System.Collections.Generic.List[object]]::new()",
            "$envConfigGroup = @('--config', '')",
            1,
        )

        assert mutant != text
        assert _remembers_a_placeholder_group(mutant)

    def test_ash_config_is_carried_whether_or_not_config_is_given(self):
        """The decision to carry the file does not depend on -Config: only the
        words that make it the scan's own --config do."""
        raw = PS1.read_text(encoding="utf-8")
        text = _flat(raw)

        assert _carry_does_not_wait_for_no_config(raw)
        # The explicit -Config is added first, and only the place in the argument
        # list is remembered after it, so an explicit -Config comes first.
        explicit = text.index("$ashCmdArgs.Add(@('--config', $Config))")
        pending = text.index("$envConfigPending = -not [string]::IsNullOrEmpty(")
        place = text.index("$envConfigAt = $ashCmdArgs.Count")
        assert explicit < pending < place
        host_words = text.index("$envConfigGroups.Add(@('--ash-config-from-host'")
        gate = text.index(
            "if (-not $PSBoundParameters.ContainsKey('Config')) {", host_words
        )
        config_words = text.index(
            "$envConfigGroups.Add(@('--config', $envConfigInner))", gate
        )
        assert host_words < gate < config_words
        assert "destination=$envConfigInner,readonly" in text

    def test_the_marks_are_added_only_for_a_file_the_repository_wrote(self):
        """The mounted file is marked when its real path is inside the scanned tree
        or its name follows a link that sits in it, after it is mounted; a file
        read through /src is never marked; the host's file carries its mark
        whether or not -Config was given, the scan's own --config and its mark
        only without one."""
        text = _flat(PS1.read_text(encoding="utf-8"))

        mount = text.index('$runArgs.Add("type=bind,source=$envConfigReal,')
        judged = (
            "$envConfigMarked = $envConfigRealInTree -or "
            "(Test-AshAnyInTree $envConfigParents $envConfigTrees "
            "$envConfigComparison)"
        )
        carried = text.index("$envConfigGroups.Add(@('--ash-config-from-host'")
        assert mount < text.index(judged) < carried
        assert text.count("$envConfigMarked = ") == 2, (
            "the mark starts False and is set in the mount arm only"
        )
        host_mark = text.index(
            "$envConfigGroups.Add(@('--config-file-from-scanned-repository', "
            "$envConfigInner))"
        )
        config_mark = text.index(
            "$envConfigGroups.Add(@('--config-from-scanned-repository'))"
        )
        without_config = text.index(
            "if (-not $PSBoundParameters.ContainsKey('Config')) {", carried
        )
        assert carried < host_mark < without_config < config_mark
        # Each add sits directly inside the block of the condition on the mark: the
        # exact flattened sequence, so an add in an else arm, or after the closing
        # brace, does not match.
        host_add = (
            "$envConfigGroups.Add(@('--config-file-from-scanned-repository', "
            "$envConfigInner))"
        )
        config_add = "$envConfigGroups.Add(@('--config-from-scanned-repository'))"
        assert f"if ($envConfigMarked) {{ {host_add} }}" in text
        assert f"if ($envConfigMarked) {{ {config_add} }}" in text
        # And each add appears once in the whole text: the guarded copy. A second,
        # unguarded copy placed before it would keep the order above and the guarded
        # sequence intact while marking every file given without -Config.
        assert text.count(host_add) == 1, "the host mark is added more than once"
        assert text.count(config_add) == 1, "the config mark is added more than once"

    def test_a_name_the_path_functions_throw_on_is_refused_as_a_missing_file(self):
        """Windows PowerShell 5.1 throws from the path functions on a quote or a
        control character, which cmd keeps in set ASH_CONFIG="C:\\x.yaml". That
        cannot be shown on a PowerShell that never throws, so it is pinned here:
        the rooted test and the resolution sit in a try, and its handler refuses
        with the code and the words of any other missing file."""
        text = _flat(PS1.read_text(encoding="utf-8"))

        start = text.index("$envConfigReal = $null try {")
        handler = text.index("} catch {", start)
        assert (
            text.index("[System.IO.Path]::IsPathRooted($envConfigGiven)", start)
            < handler
        )
        assert text.index("Resolve-AshRealPath $envConfigAbsolute", start) < handler
        refusal = text[handler : handler + 260]
        assert "$global:LASTEXITCODE = $refusalExitCode" in refusal, refusal
        assert "Config file not found" in refusal, refusal

    def test_a_name_rooted_without_a_drive_is_put_on_the_current_drive(self):
        """\\repo\\cfg.yaml is rooted, so it was never given a drive and never
        matched the trees, which start with one; only Windows spells a name so."""
        text = _flat(PS1.read_text(encoding="utf-8"))

        assert "$onWindows -and $envConfigGiven -match '^[\\\\/](?![\\\\/])'" in text
        assert (
            "GetPathRoot((Get-Location).ProviderPath).TrimEnd('\\', '/') "
            "+ $envConfigGiven"
        ) in text

    def test_the_text_cell_goes_red_when_the_carry_waits_for_no_config(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "$envConfigPending = -not [string]::IsNullOrEmpty($env:ASH_CONFIG)",
            "$envConfigPending = -not [string]::IsNullOrEmpty($env:ASH_CONFIG) "
            "-and -not $PSBoundParameters.ContainsKey('Config')",
            1,
        )

        assert mutant != text
        assert not _carry_does_not_wait_for_no_config(mutant)

    def test_a_path_is_judged_a_regular_file_by_its_type_before_it_is_opened(self):
        """Pins, as text where pwsh is absent, that the file's type is read from
        UnixStat.ItemType and not from the UnixMode string, and that the check
        comes before anything opens or reads the file."""
        text = PS1.read_text(encoding="utf-8")

        assert _regular_file_check_reads_the_item_type(text)
        check = text.index("Test-AshRegularFile $envConfigReal")
        assert check < text.index("[System.IO.File]::OpenRead($envConfigReal)")
        assert check < text.index("[System.IO.File]::ReadAllText($envConfigReal)")

    def test_the_text_cell_goes_red_for_a_mode_string_type_check(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "([string]$unixStat.Value.ItemType) -ceq 'File'",
            "([string]$unixStat.Value.UnixMode).StartsWith('-')",
            1,
        )

        assert mutant != text
        assert not _regular_file_check_reads_the_item_type(mutant)

    def test_the_name_is_resolved_as_written_not_as_powershell_collapses_it(self):
        text = PS1.read_text(encoding="utf-8")

        assert _name_is_resolved_as_written(text)

    def test_the_text_cell_goes_red_for_a_name_read_from_the_item(self):
        text = PS1.read_text(encoding="utf-8")
        mutant = text.replace(
            "Resolve-AshRealPath $envConfigAbsolute",
            "Resolve-AshRealPath (Get-Item -LiteralPath $envConfigGiven).FullName",
            1,
        )

        assert mutant != text
        assert not _name_is_resolved_as_written(mutant)


@pytest.mark.unit
class TestTheWrappersListsAreTheClis:
    """The wrappers' lists of commands and root options, checked against ash itself.

    Each wrapper finds the command its words run, to decide whether to give it
    --config-overrides. A list that drifted from the CLI would read a new option's
    value as a command, or give the override to a command that refuses it.
    """

    @staticmethod
    def _root():
        import typer.main

        from automated_security_helper.cli.main import app

        return typer.main.get_command(app)

    @staticmethod
    def _bash_list(name: str) -> set:
        script = ASH_SCRIPT.read_text(encoding="utf-8")
        found = re.findall(rf'^\s*{name}="([^"]*)"$', script, re.MULTILINE)
        assert len(found) == 1, (name, found)
        return set(found[0].split())

    @staticmethod
    def _ps1_list(name: str) -> set:
        body = PS1.read_text(encoding="utf-8")
        found = re.findall(rf"^\s*\${name} = @\(([^)]*)\)$", body, re.MULTILINE)
        assert len(found) == 1, (name, found)
        return set(re.findall(r"'([^']*)'", found[0]))

    def test_the_commands_are_the_roots(self):
        commands = set(self._root().commands)

        assert self._bash_list("ASH_SUBCOMMANDS") == commands
        assert self._ps1_list("ashSubcommands") == commands

    def test_the_options_that_take_a_value_are_the_roots(self):
        options = [p for p in self._root().params if p.param_type_name == "option"]
        takes_a_value = {
            spelling
            for option in options
            if not option.is_flag and not option.count
            for spelling in option.opts
        }

        assert self._bash_list("ASH_ROOT_VALUE_OPTIONS") == takes_a_value
        assert self._ps1_list("ashRootValueOptions") == takes_a_value
        # The wrappers skip one word after each of them.
        assert all(option.nargs == 1 for option in options)

    def test_the_commands_given_sandbox_off_are_the_ones_that_take_it(self):
        root = self._root()
        takes_it = {
            name
            for name, command in root.commands.items()
            if "sandbox" in {param.name for param in command.params}
        }

        assert self._bash_list("ASH_TAKES_SANDBOX") == takes_it
        assert self._ps1_list("ashTakesSandbox") == takes_it
        # With no command named, ash scans, and takes --sandbox there too.
        assert "sandbox" in {param.name for param in root.params}

    @staticmethod
    def _options_under(command) -> list:
        """The option params of a click command and of every command under it."""
        found = [p for p in command.params if p.param_type_name == "option"]
        for sub in getattr(command, "commands", {}).values():
            found.extend(TestTheWrappersListsAreTheClis._options_under(sub))
        return found

    def test_the_commands_whose_dash_o_is_their_own_are_the_ones_that_define_one(self):
        """ASH_DASH_O_IS_THE_SUBCOMMANDS names the commands after which ./ash forwards
        -o as the command's own option instead of taking it as its runner: every
        command that defines a -o of its own (on itself or a command under it) that
        is not the CLI's alias of --oci-runner. scan's -o is that alias, so -o after
        scan stays the runner, as it does with no command and after a command that
        defines no -o at all (the containerized CLI would refuse it there). Derived
        from the click commands, as the other lists are, so a command that gains a
        non-runner -o fails here until the list names it, instead of having its -o
        eaten as the runner."""
        root = self._root()
        dash_o_is_the_commands = {
            name
            for name, command in root.commands.items()
            if any(
                "-o" in option.opts and "--oci-runner" not in option.opts
                for option in self._options_under(command)
            )
        }

        assert (
            self._bash_list("ASH_DASH_O_IS_THE_SUBCOMMANDS") == dash_o_is_the_commands
        )
        # The runner's side of the rule: scan's own -o is the runtime alias.
        scan_dash_o = [
            option
            for option in self._options_under(root.commands["scan"])
            if "-o" in option.opts
        ]
        assert [
            set(option.opts) >= {"-o", "--oci-runner"} for option in scan_dash_o
        ] == [True], scan_dash_o


@pytest.mark.unit
class TestThePowerShellRefusalAsText:
    """What the behavior tests above need pwsh to see, checked where pwsh is absent."""

    @pytest.fixture
    def body(self) -> str:
        return PS1.read_text(encoding="utf-8")

    def test_one_constant_holds_the_code(self, body):
        assert len(re.findall(r"\$sandboxRefusalExitCode = 5\b", body)) == 1

    def test_the_help_says_ash_config_becomes_the_scans_config(self, body):
        """A set ASH_CONFIG is carried to the scan as the host's config with or
        without -Config, as an explicit --config argument only when none was
        given, and an explicit -Config wins. The help's description states that
        carry -- the operator-facing contract -- pinned here where pwsh is
        absent."""
        help_text = body[body.index("<#") : body.index("#>")]
        description = help_text[help_text.index(".DESCRIPTION") :]
        description = description[: description.index("\n    .PARAMETER")]
        assert "ASH_CONFIG" in description, description
        assert "--config" in description, description
        assert "explicit option wins" in description, description
        assert "fills in only when none was given" in description, description
        flat = " ".join(description.split())
        assert "whether or not -Config is given" in flat, flat
        assert "that a link leads out of it" in flat, flat
        assert "under -NoRun nothing is resolved" in flat, flat
        config_entry = help_text[help_text.index(".PARAMETER Config") :]
        config_entry = " ".join(
            config_entry[: config_entry.index(".PARAMETER AshArgs")].split()
        )
        assert "that a link leads out of it is refused with 3" in config_entry

    def test_the_refusal_throws_and_never_exits(self, body):
        """Any ``exit`` there ends the dot-sourcing caller's session, whatever code."""
        start = body.index("$sandboxRefusalExitCode = 5")
        # The workspace pass follows the sandbox block.
        end = body.index("# A workspace scan is refused over the same words")
        code = "\n".join(
            line
            for line in body[start:end].splitlines()
            if not line.strip().startswith("#")
        )
        assert not re.search(r"\bexit\b", code, re.IGNORECASE), code
        assert len(re.findall(r"^\s*throw\b", code, re.MULTILINE)) == 2, code

    def test_it_throws_before_anything_is_built(self, body):
        """``exit`` ends the session of a caller who dot-sourced the helpers."""
        refusal = body.index("$global:LASTEXITCODE = $sandboxRefusalExitCode")
        assert refusal < body.index("'build'")
        assert "exit 5" not in body
