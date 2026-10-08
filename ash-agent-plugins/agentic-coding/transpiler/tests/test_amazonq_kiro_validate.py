"""The amazonq smoke test validates agent.json with kiro-cli, without a login.

`q agent validate` and `kiro-cli agent validate` both stop at "You are not
logged in", so the smoke test runs kiro-cli-chat, the binary both wrappers
dispatch `agent` to, which validates offline. kiro-cli-chat exits 0 whatever the
outcome and prints a colored `Error: ...` on stderr, so a failure is only visible
in the output. The fakes below reproduce what kiro-cli 2.28.0 prints.

The usage text in fixtures/ is `kiro-cli agent validate --help` from the 2.28.0
release archive that cli_tools.py pins.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from transpiler.backends.amazonq import AmazonqBackend
from transpiler.cli_tools import CLI_KIRO_CLI
from transpiler.core import BuildContext

_HERE = Path(__file__).resolve().parent
_BASE = _HERE.parent / "_base"
_USAGE = _HERE / "fixtures" / "kiro-cli-2.28.0-agent-validate-help.txt"
_AGENT = {"name": "ash", "mcpServers": {"ash": {"command": "uvx", "args": []}}}


def _required_options(usage_line: str) -> list[str]:
    """`--flag` of every `--flag <VALUE>` outside [brackets] in a clap usage line."""
    unbracketed = re.sub(r"\[[^\]]*\]", "", usage_line)
    return re.findall(r"(--[a-z][a-z-]*) <[A-Z_]+>", unbracketed)


def test_usage_fixture_is_from_the_pinned_release():
    pins = json.loads((_BASE / "cli_versions.json").read_text())
    version = re.search(r"kiro-cli-(\d+\.\d+)\.\d+-", _USAGE.name).group(1)
    assert pins["kiro-cli"] == version
    assert f"/{version}." in CLI_KIRO_CLI.install_cmd


def test_kiro_cli_validate_argv_satisfies_the_2_28_usage():
    usage = next(
        line for line in _USAGE.read_text().splitlines() if line.startswith("Usage:")
    )
    required = _required_options(usage)
    assert required == ["--path"], usage
    # The usage line takes no positional arguments, only options.
    assert not re.search(r"\s<[A-Z_]+>", re.sub(r"--[a-z-]+ <[A-Z_]+>", "", usage))

    argv = [
        a.format(agent_json="/x/agent.json")
        for a in CLI_KIRO_CLI.validate_argv_template
    ]
    assert argv[:3] == ["kiro-cli", "agent", "validate"]
    rest = argv[3:]
    for flag in required:
        assert flag in rest, argv
        value = rest[rest.index(flag) + 1]
        assert not value.startswith("-"), argv
    # Nothing left over that the CLI would read as an unexpected positional.
    consumed = {i for f in required for i in (rest.index(f), rest.index(f) + 1)}
    assert consumed == set(range(len(rest))), argv


def _fake(tmp_path: Path, name: str, body: str) -> None:
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)


def _ctx(tmp_path: Path, agent: dict) -> BuildContext:
    out = tmp_path / "out"
    out.mkdir()
    (out / "agent.json").write_text(json.dumps(agent))
    return BuildContext(
        manifest=None,
        out=out,
        plugins_root=tmp_path,
        base_dir=_BASE,
        schemas_dir=tmp_path,
    )


@pytest.fixture
def fake_kiro(tmp_path, monkeypatch):
    """kiro-cli and q as 2.28.0 ships them without a login, and a kiro-cli-chat
    whose `agent validate` output each test sets."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for wrapper in ("kiro-cli", "q"):
        _fake(
            bindir,
            wrapper,
            "echo 'error: You are not logged in, please log in with kiro-cli login' >&2\n"
            "exit 1\n",
        )
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")

    def chat(validate_stderr: str = "", version: str = "2.28.0") -> None:
        _fake(
            bindir,
            "kiro-cli-chat",
            f'if [ "$1" = "--version" ]; then echo "kiro-cli-chat {version}"; exit 0; fi\n'
            f"printf '%b' '{validate_stderr}' >&2\n"
            "exit 0\n",
        )

    return chat


def test_a_clean_file_passes_and_says_the_full_validate_needs_a_login(
    tmp_path, fake_kiro
):
    fake_kiro()
    result = AmazonqBackend().smoke_test(_ctx(tmp_path, _AGENT))
    assert result["ok"] is True, result
    assert not result.get("skipped"), result
    assert "needs a login" in result["detail"]


def test_an_error_on_stderr_with_exit_0_fails(tmp_path, fake_kiro):
    # What 2.28.0 prints for {"tools": "notalist"}, color codes included.
    fake_kiro(
        "\\033[38;5;9mError: \\033[0mJson supplied at agent.json is invalid: "
        'invalid type: string "notalist", expected a sequence\\n'
    )
    result = AmazonqBackend().smoke_test(
        _ctx(tmp_path, {**_AGENT, "tools": "notalist"})
    )
    assert result["ok"] is False, result
    assert "expected a sequence" in result["reason"]


def test_a_version_other_than_the_pin_fails(tmp_path, fake_kiro):
    fake_kiro(version="1.19.7")
    result = AmazonqBackend().smoke_test(_ctx(tmp_path, _AGENT))
    assert result["ok"] is False, result
    assert "1.19" in result["reason"]
