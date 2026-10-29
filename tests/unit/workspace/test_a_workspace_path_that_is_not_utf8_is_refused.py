# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace whose root, file or folder has a path that is not UTF-8 is refused.

The workspace plan holds the workspace file's path, its root's and every
project's, and the plan and the results file are UTF-8. A path that is not UTF-8
arrives as a str with surrogate escapes, which neither can hold. Without the
refusal (measured), resolution builds the plan and pydantic refuses the first
project with "Input should be a valid string, unable to parse raw data as a
unicode string [type=string_unicode]": the CLI (--dry-run, a local or container
run, --workspace auto) would exit 1 with a traceback, and both MCP workspace
tools would answer exit_code 1, the code for an ASH bug, with nothing written.

Resolution refuses such a workspace at the start, before it reads any
project's config. The exit code is 4, the code every other workspace definition
refusal has. The way out is to rename the directory, file or folder. Container
mode does not help, since the workspace is planned on the host.

The refusal names each path as it is, in a message of one line, and each sink
shows it once, the whole message through shown_on_one_line: the CLI's refusal,
the workspace run's handler, and the MCP tools' response. So a byte that is not
UTF-8 is written as an escape once, and a newline in a name as \\x0a.

Only some filesystems can hold such a name. Windows cannot decode one, and APFS
refuses it, so there the tests skip, with the reason.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pydantic_core
import pytest

import automated_security_helper
from automated_security_helper.cli.mcp import workspace as mcp_workspace
from automated_security_helper.core.exceptions import (
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.workspace.resolver import resolve_workspace
from tests.utils.helpers import checkout_env

#: For the tests that build a name from bytes that are not UTF-8 themselves.
_NO_NON_UTF8_NAMES = pytest.mark.skipif(
    os.name == "nt",
    reason="NTFS names are UTF-16; a name that is not UTF-8 bytes cannot exist",
)

#: The checkout under test, which a child process is pointed at.
_CHECKOUT = Path(automated_security_helper.__file__).resolve().parents[1]

#: A container runtime stand-in: records that it was called, and fails.
_GUARD_RUNNER = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
exit 97
"""


def _not_utf8(parent: Path, name: bytes = b"caf\xe9") -> Path:
    """A directory below *parent* named *name*, or a skip where that cannot be."""
    try:
        odd = parent / os.fsdecode(name)
        odd.mkdir()
    except (UnicodeDecodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return odd


def _workspace(
    root: Path, folders: List[str], name: str = "dev.code-workspace"
) -> Path:
    """A workspace file in *root* listing *folders*, each made with one file.

    json.dumps writes a name that is not UTF-8 as an escaped lone surrogate, the
    only way UTF-8 JSON can hold one, and json.loads reads it back as the same str.
    """
    root.mkdir(parents=True, exist_ok=True)
    for folder in folders:
        (root / folder).mkdir(exist_ok=True)
        (root / folder / "x.py").write_text('password = "hunter2hunter2hunter2"\n')
    try:
        definition = root / name
        definition.write_text(
            json.dumps({"folders": [{"path": folder} for folder in folders]}),
            encoding="utf-8",
        )
    except (UnicodeEncodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return definition


def _entries(
    top: Path, *, leave_out: Optional[Path] = None
) -> Dict[bytes, Optional[bytes]]:
    """Every entry below *top*, by its path as bytes: a file's content, None for a directory."""
    left_out = os.fsencode(leave_out) if leave_out is not None else None
    found: Dict[bytes, Optional[bytes]] = {}
    for directory, subdirectories, files in os.walk(os.fsencode(top)):
        if left_out is not None:
            subdirectories[:] = [
                name
                for name in subdirectories
                if os.path.join(directory, name) != left_out
            ]
        for name in subdirectories:
            found[os.path.join(directory, name)] = None
        for name in files:
            with open(os.path.join(directory, name), "rb") as handle:
                found[os.path.join(directory, name)] = handle.read()
    return found


def _has_a_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in text)


def _raised(definition: Path, **given) -> WorkspacePathNotUtf8Error:
    with pytest.raises(WorkspacePathNotUtf8Error) as refused:
        resolve_workspace(definition, **given)
    return refused.value


def _refusal(definition: Path, **given) -> str:
    """The refusal as each sink shows it: the whole message, once, on one line."""
    return str(shown_on_one_line(str(_raised(definition, **given))))


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_a_root_that_is_not_utf8_is_refused_before_anything_is_read(
    tmp_path, monkeypatch
):
    root = _not_utf8(tmp_path)
    definition = _workspace(root, ["api"])
    before = _entries(tmp_path)

    def read_a_project_config(*args, **kwargs):
        raise AssertionError("a project's config was read")

    monkeypatch.setattr(
        "automated_security_helper.workspace.resolver._resolve_project_config",
        read_a_project_config,
    )
    message = _refusal(definition)

    assert _entries(tmp_path) == before
    assert f"{tmp_path.as_posix()}/caf\\udce9" in message, ascii(message)
    assert "not UTF-8" in message, ascii(message)
    assert "Rename the directory" in message, ascii(message)
    assert "planned on the host" in message, ascii(message)
    assert not _has_a_surrogate(message), ascii(message)


@pytest.mark.unit
def test_a_folder_that_is_not_utf8_is_refused_and_named(tmp_path):
    root = tmp_path / "cafe"
    odd = os.fsdecode(b"caf\xe9")
    definition = _workspace(root, ["api", odd, os.fsdecode(b"na\xefve")])
    before = _entries(tmp_path)

    message = _refusal(definition)

    assert _entries(tmp_path) == before
    # Every such folder is named, and the folder whose name is UTF-8 is not.
    assert "'caf\\udce9'" in message and "'na\\udcefve'" in message, ascii(message)
    assert "'api'" not in message, ascii(message)
    assert "not UTF-8" in message and "Rename" in message, ascii(message)
    assert not _has_a_surrogate(message), ascii(message)


@_NO_NON_UTF8_NAMES
@pytest.mark.unit
def test_a_workspace_file_whose_name_is_not_utf8_is_refused(tmp_path):
    root = tmp_path / "cafe"
    definition = _workspace(root, ["api"], name=os.fsdecode(b"caf\xe9.code-workspace"))
    before = _entries(tmp_path)

    message = _refusal(definition)

    assert _entries(tmp_path) == before
    assert "caf\\udce9.code-workspace" in message, ascii(message)
    assert "Rename the file" in message, ascii(message)
    assert not _has_a_surrogate(message), ascii(message)


@pytest.mark.unit
def test_the_name_is_shown_not_obeyed(tmp_path):
    root = _not_utf8(tmp_path, b"caf\xe9\x1b[31m[red]x\n::error::injected")
    message = _refusal(_workspace(root, ["api"]))

    assert "caf\\udce9\\x1b[31m[red]x\\x0a::error::injected" in message, ascii(message)
    assert "\x1b" not in message, ascii(message)
    assert not any(line.lstrip().startswith("::") for line in message.splitlines())
    assert not _has_a_surrogate(message), ascii(message)


@pytest.mark.parametrize(
    "where",
    [
        "root",
        "folder",
        pytest.param("file", marks=_NO_NON_UTF8_NAMES),
        "policy",
        "config",
    ],
)
@pytest.mark.unit
def test_the_refusal_holds_each_path_as_it_is_on_one_line(tmp_path, where):
    """Raised with raw text, so each sink shows it once; one line, so showing it
    on one line changes only what a name holds."""
    given = {}
    if where == "root":
        definition = _workspace(_not_utf8(tmp_path), ["api"])
    elif where == "folder":
        # Two of them, so the message joins two entries.
        definition = _workspace(
            tmp_path / "cafe",
            ["api", os.fsdecode(b"caf\xe9"), os.fsdecode(b"na\xefve")],
        )
    elif where == "file":
        definition = _workspace(
            tmp_path / "cafe", ["api"], name=os.fsdecode(b"caf\xe9.code-workspace")
        )
    else:
        _root, definition, policy, config = _with_an_odd_policy_and_config(tmp_path)
        # Both for "config", so that message joins two entries too.
        given = (
            {"workspace_config": policy}
            if where == "policy"
            else {"workspace_config": policy, "default_config": config}
        )

    message = str(_raised(definition, **given))
    # Booleans, so a failure's report holds no lone surrogate: pytest-xdist
    # cannot send one from a worker.
    holds_the_name_as_it_is = "caf\udce9" in message
    holds_an_escape = "\\udce9" in message
    is_one_line = "\n" not in message

    assert holds_the_name_as_it_is, ascii(message)
    assert not holds_an_escape, ascii(message)
    assert is_one_line, ascii(message)


@pytest.mark.unit
def test_a_workspace_whose_paths_are_utf8_resolves(tmp_path):
    """The check reads the paths, and leaves a name with non-ASCII letters alone."""
    plan = resolve_workspace(_workspace(tmp_path / "café", ["api", "naïve"]))

    assert [project.key for project in plan.projects] == ["api", "naïve"]


# --------------------------------------------------------------------------- #
# The CLI
# --------------------------------------------------------------------------- #


_CLI_SURFACES = {
    "dry-run": ["--dry-run"],
    "local": [
        "--mode",
        "local",
        "--scanners",
        "detect-secrets",
        "--python-only",
        "--no-progress",
    ],
    "container": ["--mode", "container", "--no-progress"],
}


def _ash(tmp_path: Path, args: List[str], cwd: Path) -> subprocess.CompletedProcess:
    """`ash` in a child process whose stdout cannot encode a surrogate, with every
    container runtime replaced by a stand-in that records a call and fails."""
    home = tmp_path / "home"
    guards = home / "guards"
    guards.mkdir(parents=True, exist_ok=True)
    for runner in ("docker", "finch", "nerdctl", "podman"):
        path = guards / runner
        path.write_text(_GUARD_RUNNER.format(log=home / "runners.log"))
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "PATH": f"{guards}{os.pathsep}{os.environ.get('PATH', '')}",
        "PYTHONIOENCODING": "utf-8:strict",
        # Wide, so that the path is printed on one line.
        "COLUMNS": "1000",
        "TERMINAL_WIDTH": "1000",
    }
    return subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [sys.executable, "-m", "automated_security_helper.cli.main", "scan", *args],
        cwd=cwd,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )


@pytest.mark.integration
def test_the_child_imports_the_checkout_under_test(tmp_path):
    """Else the CLI tests below would measure whatever ASH the interpreter finds."""
    home = tmp_path / "home"
    home.mkdir()
    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-c",
            "import automated_security_helper as a; print(a.__file__)",
        ],
        cwd=tmp_path,
        env=checkout_env({**os.environ, "HOME": str(home)}),
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )

    assert Path(child.stdout.strip()).resolve().is_relative_to(_CHECKOUT), child.stdout


@pytest.mark.parametrize("surface", list(_CLI_SURFACES))
@pytest.mark.integration
def test_ash_scan_refuses_it_with_exit_4_and_the_message_shown_once(tmp_path, surface):
    root = _not_utf8(tmp_path)
    definition = _workspace(root, ["api"])
    before = _entries(tmp_path)

    child = _ash(
        tmp_path, ["--workspace", str(definition), *_CLI_SURFACES[surface]], tmp_path
    )
    stderr = child.stderr.decode("utf-8")

    assert child.returncode == int(WorkspaceExitCode.WORKSPACE_ERROR), ascii(stderr)
    assert "caf\\udce9" in stderr and "not UTF-8" in stderr, ascii(stderr)
    # Shown once: a second pass would double the escape's backslash.
    assert "caf\\\\udce9" not in stderr, ascii(stderr)
    assert "Traceback" not in stderr and "ValidationError" not in stderr, ascii(stderr)
    assert not (tmp_path / "home" / "runners.log").exists()
    assert _entries(tmp_path, leave_out=tmp_path / "home") == {
        path: content
        for path, content in before.items()
        if not path.startswith(os.fsencode(tmp_path / "home"))
    }


@pytest.mark.integration
def test_ash_scan_workspace_auto_refuses_it_too(tmp_path):
    root = _not_utf8(tmp_path)
    _workspace(root, ["api"])
    before = _entries(root)

    child = _ash(tmp_path, ["--workspace", "auto", "--dry-run"], root)
    stderr = child.stderr.decode("utf-8")

    assert child.returncode == int(WorkspaceExitCode.WORKSPACE_ERROR), ascii(stderr)
    assert "caf\\udce9" in stderr and "Traceback" not in stderr, ascii(stderr)
    assert _entries(root) == before


@pytest.mark.integration
def test_the_cli_shows_a_name_with_controls_once_and_not_obeyed(tmp_path):
    root = _not_utf8(tmp_path, b"caf\xe9\x1b[31m[red]x\n::error::injected")
    definition = _workspace(root, ["api"])

    child = _ash(tmp_path, ["--workspace", str(definition), "--dry-run"], tmp_path)
    stderr = child.stderr.decode("utf-8")

    assert child.returncode == int(WorkspaceExitCode.WORKSPACE_ERROR), ascii(stderr)
    assert "caf\\udce9\\x1b[31m[red]x\\x0a::error::injected" in stderr, ascii(stderr)
    assert "\x1b" not in stderr, ascii(stderr)
    assert not any(line.lstrip().startswith("::") for line in stderr.splitlines())


# --------------------------------------------------------------------------- #
# The MCP tools
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "tool",
    [mcp_workspace.mcp_resolve_workspace, mcp_workspace.mcp_scan_workspace],
    ids=["resolve", "scan"],
)
@pytest.mark.unit
def test_the_mcp_tools_answer_exit_4_in_a_response_that_encodes(tmp_path, tool):
    root = _not_utf8(tmp_path)
    definition = _workspace(root, ["api"])
    before = _entries(tmp_path)

    response = asyncio.run(tool(workspace_file=str(definition)))

    assert response["success"] is False
    assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR), response
    assert "caf\\udce9" in response["error"], ascii(response["error"])
    # The response reaches the client as JSON, which a lone surrogate breaks.
    pydantic_core.to_json(response)
    assert _entries(tmp_path) == before


@pytest.mark.unit
def test_the_mcp_response_shows_a_name_with_controls_once(tmp_path):
    # A lone ESC: the error text has complete CSI sequences removed in every print.
    root = _not_utf8(tmp_path, b"caf\xe9\x1bc[red]x\n::error::injected")
    definition = _workspace(root, ["api"])

    response = asyncio.run(
        mcp_workspace.mcp_resolve_workspace(workspace_file=str(definition))
    )
    error = response["error"]

    assert "caf\\udce9\\x1bc[red]x\\x0a::error::injected" in error, ascii(error)
    assert "caf\\\\udce9" not in error and "\x1b" not in error, ascii(error)
    pydantic_core.to_json(response)


@pytest.mark.parametrize("carried", [True, False], ids=["value-carried", "control"])
@pytest.mark.unit
def test_the_mcp_response_hides_a_value_a_complete_code_splits(tmp_path, carried):
    """The response holds a carried environment value neither whole nor in pieces.

    The refusal's text spells the value with a complete color code in the middle,
    which no contiguous match finds until the code is gone. The control carries
    no value, so the same text prints its pieces: the absence in the first case
    is the redaction's.
    """
    from unittest.mock import patch

    from automated_security_helper.utils.error_text import carry_environment_values

    head, tail = "canary-Zq7Kx9Lm", "Pw4Nv2Rt-canary"
    root = tmp_path / "ws"
    definition = _workspace(root, ["api"])
    raised = WorkspacePathNotUtf8Error(
        f"The workspace root '{root.as_posix()}/{head}\x1b[1m{tail}' has a path "
        "that is not UTF-8."
    )
    if carried:
        carry_environment_values(raised, [head + tail])

    with patch.object(mcp_workspace, "resolve_workspace", side_effect=raised):
        response = asyncio.run(
            mcp_workspace.mcp_resolve_workspace(workspace_file=str(definition))
        )

    assert response["success"] is False, response
    assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR), response
    sent = json.dumps(response)
    assert "has a path that is not UTF-8" in sent, sent
    if carried:
        assert head not in sent and tail not in sent, sent
    else:
        assert head in sent, sent


# --------------------------------------------------------------------------- #
# The workspace run's own handler
# --------------------------------------------------------------------------- #


@_NO_NON_UTF8_NAMES
@pytest.mark.unit
def test_the_workspace_run_shows_the_refusal_once(tmp_path, capsys):
    """run_ash_scan's handler around execute_workspace, given the error as it is
    raised: the whole message shown once, on one line, and exit 4."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from automated_security_helper.interactions import run_ash_scan as ras

    name = os.fsdecode(b"caf\xe9\x1b[31m[red]x\n::error::injected")
    raised = WorkspacePathNotUtf8Error(
        f"The workspace root '{tmp_path.as_posix()}/{name}' has a path that is not "
        "UTF-8."
    )
    opts = SimpleNamespace(workspace_plan=object(), offline=False)
    with (
        patch.object(ras, "build_project_scan_settings", return_value=MagicMock()),
        patch(
            "automated_security_helper.workspace.execution.execute_workspace",
            side_effect=raised,
        ),
        pytest.raises(SystemExit) as stopped,
    ):
        ras._run_workspace_mode(opts, MagicMock())
    stderr = capsys.readouterr().err

    assert stopped.value.code == int(WorkspaceExitCode.WORKSPACE_ERROR)
    assert "caf\\udce9\\x1b[31m[red]x\\x0a::error::injected" in stderr, ascii(stderr)
    assert "caf\\\\udce9" not in stderr and "\x1b" not in stderr, ascii(stderr)
    assert not any(line.lstrip().startswith("::") for line in stderr.splitlines())


# --------------------------------------------------------------------------- #
# A policy file or a default config whose path is not UTF-8
# --------------------------------------------------------------------------- #
#
# A workspace whose own paths are UTF-8, given a --workspace-config or a --config
# below a directory whose name is not. The plan holds the policy file's resolved
# path, and the default config's for every project that declares none. Unchecked
# (measured), both MCP workspace tools would answer success with a plan their
# client cannot be sent ("Error serializing to JSON: ... surrogates not
# allowed"), and the CLI would plan and scan with such a path in its plan.


def _with_an_odd_policy_and_config(tmp_path: Path):
    """A UTF-8 workspace, and a policy file and a config in a folder below its
    root whose name is not UTF-8 (not a project: the workspace does not list it)."""
    root = tmp_path / "ws"
    definition = _workspace(root, ["api"])
    odd = _not_utf8(root)
    policy = odd / "ash-workspace.yaml"
    policy.write_text("workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8")
    config = odd / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    return root, definition, policy, config


@pytest.mark.parametrize("given", ["workspace_config", "default_config"])
@pytest.mark.unit
def test_a_policy_or_default_config_path_that_is_not_utf8_is_refused_first(
    tmp_path, monkeypatch, given
):
    _root, definition, policy, config = _with_an_odd_policy_and_config(tmp_path)
    before = _entries(tmp_path)

    def read_a_project_config(*args, **kwargs):
        raise AssertionError("a project's config was read")

    monkeypatch.setattr(
        "automated_security_helper.workspace.resolver._resolve_project_config",
        read_a_project_config,
    )
    message = _refusal(
        definition, **{given: policy if given == "workspace_config" else config}
    )

    assert _entries(tmp_path) == before
    name = "ash-workspace.yaml" if given == "workspace_config" else "ash.yaml"
    assert f"/ws/caf\\udce9/{name}" in message, ascii(message)
    assert "not UTF-8" in message and "Rename" in message, ascii(message)
    assert not _has_a_surrogate(message), ascii(message)


@pytest.mark.unit
def test_both_are_named_in_one_refusal(tmp_path):
    _root, definition, policy, config = _with_an_odd_policy_and_config(tmp_path)

    message = _refusal(definition, workspace_config=policy, default_config=config)

    assert "caf\\udce9/ash-workspace.yaml" in message, ascii(message)
    assert "caf\\udce9/ash.yaml" in message, ascii(message)


@pytest.mark.unit
def test_a_utf8_link_to_such_a_file_is_refused_too(tmp_path):
    """The plan holds the policy file's resolved path, so a link whose own name is
    UTF-8 does not get around it."""
    root, definition, policy, _config = _with_an_odd_policy_and_config(tmp_path)
    link = root / "policy-link.yaml"
    try:
        link.symlink_to(policy)
    except OSError as error:
        pytest.skip(f"this filesystem cannot hold a symlink: {error}")

    message = _refusal(definition, workspace_config=link)

    assert "caf\\udce9/ash-workspace.yaml" in message, ascii(message)


@pytest.mark.unit
def test_a_utf8_policy_and_default_config_resolve(tmp_path):
    """The check reads the paths, and leaves a name with non-ASCII letters alone."""
    root = tmp_path / "ws"
    definition = _workspace(root, ["api"])
    folder = root / "café"
    folder.mkdir()
    policy = folder / "ash-workspace.yaml"
    policy.write_text("workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8")
    config = folder / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    plan = resolve_workspace(definition, workspace_config=policy, default_config=config)

    assert plan.workspace_config_source == policy.resolve().as_posix()
    assert plan.projects[0].config_source == config.resolve().as_posix()


@pytest.mark.parametrize("flag", ["--workspace-config", "--config"])
@pytest.mark.parametrize("surface", ["dry-run", "local"])
@pytest.mark.integration
def test_ash_scan_refuses_such_a_policy_or_config_with_exit_4(tmp_path, flag, surface):
    _root, definition, policy, config = _with_an_odd_policy_and_config(tmp_path)
    before = _entries(tmp_path)
    value = policy if flag == "--workspace-config" else config

    child = _ash(
        tmp_path,
        ["--workspace", str(definition), flag, str(value), *_CLI_SURFACES[surface]],
        tmp_path,
    )
    stderr = child.stderr.decode("utf-8")

    assert child.returncode == int(WorkspaceExitCode.WORKSPACE_ERROR), ascii(stderr)
    assert "caf\\udce9" in stderr and "not UTF-8" in stderr, ascii(stderr)
    assert "caf\\\\udce9" not in stderr, ascii(stderr)
    assert "Traceback" not in stderr, ascii(stderr)
    assert _entries(tmp_path, leave_out=tmp_path / "home") == {
        path: content
        for path, content in before.items()
        if not path.startswith(os.fsencode(tmp_path / "home"))
    }


@pytest.mark.parametrize(
    "tool",
    [mcp_workspace.mcp_resolve_workspace, mcp_workspace.mcp_scan_workspace],
    ids=["resolve", "scan"],
)
@pytest.mark.unit
def test_the_mcp_tools_refuse_such_a_policy_in_a_response_that_encodes(tmp_path, tool):
    _root, definition, policy, _config = _with_an_odd_policy_and_config(tmp_path)
    before = _entries(tmp_path)

    response = asyncio.run(
        tool(workspace_file=str(definition), workspace_config=str(policy))
    )

    assert response["success"] is False, ascii(str(response)[:2000])
    assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR), response
    assert "caf\\udce9" in response["error"], ascii(response["error"])
    pydantic_core.to_json(response)
    assert _entries(tmp_path) == before
