# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``set_source_git`` clones without the server's credentials or configuration.

An MCP client names the URL; the server runs git, without the server account's
ssh agent, askpass helper, credential helpers, proxy settings or token
variables. The required behavior:

* git runs with a scrubbed environment: no ``SSH_AUTH_SOCK``, no askpass, no
  credential helper from any config scope, ``GIT_TERMINAL_PROMPT=0``, no system
  or global git config, no inherited proxy or token variables. Every git
  invocation of a delivery counts, including the fetch and checkout for a ref.
* a non-blank ``ssh_key_id`` the operator has not registered is refused. Nothing
  registers keys yet, so every non-blank id is refused; ``""`` is unset.
* local sources (``file://`` URLs and plain paths) are refused outright.
* a remote host is refused unless it is on an operator-configured allowlist,
  which is empty by default.

Where each rule is checked
--------------------------
The environment tests call ``source_delivery.set_source_git`` directly, below the
MCP tool boundary, because that is where git is spawned and where the
environment it receives can be observed; the host allowlist is the tool
boundary's policy, alongside the local-source check that already lives in
``mcp_tools.mcp_set_source_git``. The allowlist, ``ssh_key_id`` and local-source
tests go through the MCP tool over streamable-HTTP, plus the Python API that
stdio reaches. git itself is replaced by a recorder in every test; the config
test then asks the real git binary what configuration the recorded invocation
would have seen.
"""

from __future__ import annotations

import ntpath
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_streamable_http_app
from automated_security_helper.cli.mcp import source_delivery as sd
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    StreamableHttpClient,
)

#: Captured at import, before any test replaces ``subprocess.run``.
_REAL_RUN = subprocess.run

REMOTE_URLS = [
    "https://git.example.invalid/team/repo.git",
    "ssh://git@git.example.invalid/team/repo.git",
    "git@git.example.invalid:team/repo.git",
    "git://git.example.invalid/team/repo.git",
    "http://git.example.invalid/team/repo.git",
]

#: Values planted in the server's own environment and git configuration. None
#: of them may reach git.
PLANTED_ENV = {
    "SSH_AUTH_SOCK": "/server/ssh-agent.sock",
    "GIT_ASKPASS": "/server/bin/git-askpass",
    "SSH_ASKPASS": "/server/bin/ssh-askpass",
    "SSH_ASKPASS_REQUIRE": "force",
    "HTTPS_PROXY": "http://server-proxy.invalid:3128",
    "https_proxy": "http://server-proxy.invalid:3128",
    "HTTP_PROXY": "http://server-proxy.invalid:3128",
    "http_proxy": "http://server-proxy.invalid:3128",
    "ALL_PROXY": "socks5://server-proxy.invalid:1080",
    "GITHUB_TOKEN": "server-github-token",
    "GH_TOKEN": "server-gh-token",
    "ASH_TEST_DEPLOY_TOKEN": "server-deploy-token",
}


def _is_git(program: str) -> bool:
    """Whether ``program`` is git: ``git``, or the ``git.exe`` file Windows resolves it to.

    ``ntpath`` splits on both kinds of separator, so a Windows path reads the same
    way on every host.
    """
    name = ntpath.basename(str(program))
    return ntpath.splitext(name)[0].lower() == "git"


class GitRecorder:
    """Stands in for ``source_delivery._run_git`` and records each git invocation."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, cmd, **kwargs):
        env = kwargs.get("env")
        self.calls.append(
            {"cmd": list(cmd), "env": dict(env) if env is not None else None}
        )

        class _Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Completed()

    @property
    def git_calls(self) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["cmd"] and _is_git(c["cmd"][0])]


@pytest.fixture
def git(monkeypatch) -> GitRecorder:
    recorder = GitRecorder()
    monkeypatch.setattr(sd, "_run_git", recorder)
    return recorder


class TestTheRecorderKnowsGit:
    """``git_calls`` picks git out of the programs a delivery ran, on every platform.

    ``source_delivery._git_executable`` returns ``find_executable("git")``, which on
    Windows is the ``git.exe`` file, so a filter on the bare name ``git`` finds no
    call there and every test below that asserts on ``git.git_calls`` stops at "the
    delivery never reached git". The programs are spelled as Windows spells them and
    are read the same on every host.
    """

    @pytest.mark.parametrize(
        "program",
        [
            "git",
            "/usr/bin/git",
            r"C:\Program Files\Git\cmd\git.exe",
            "C:/Git/cmd/GIT.EXE",
        ],
        ids=["bare", "posix", "windows-backslash", "windows-slash-upper"],
    )
    @pytest.mark.unit
    def test_git_is_recognized_by_its_file_name(self, program) -> None:
        recorder = GitRecorder()
        recorder(["ssh", "-G"])
        recorder([program, "clone"])

        assert [call["cmd"][0] for call in recorder.git_calls] == [program]

    @pytest.mark.parametrize(
        "program",
        [
            "ssh",
            "/usr/bin/git-lfs",
            r"C:\tools\git-lfs.exe",
            "gitk",
            "/opt/not-git/tool",
        ],
        ids=["ssh", "git-lfs", "git-lfs-exe", "gitk", "directory-named-git"],
    )
    @pytest.mark.unit
    def test_another_program_is_not_git(self, program) -> None:
        recorder = GitRecorder()
        recorder([program, "clone"])

        assert recorder.git_calls == []


@pytest.fixture(autouse=True)
def clean_policy_env(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "mcp-workspaces"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    return workspace


def _effective_env(call: Dict[str, Any]) -> Dict[str, str]:
    """The environment git ran with; ``env=None`` means it inherited ours."""
    import os

    return dict(os.environ) if call["env"] is None else call["env"]


def _deliver(workspace: Path, url: str, ref: Optional[str] = None, **kwargs) -> None:
    try:
        sd.set_source_git(
            url=url,
            ref=ref,
            workspace_root=workspace,
            session_id="probe-session",
            **kwargs,
        )
    finally:
        sd.clear_source("probe-session", workspace_root=workspace)


# ---------------------------------------------------------------------------
# The environment git runs with
# ---------------------------------------------------------------------------


class TestGitEnvironment:
    @pytest.mark.parametrize("url", REMOTE_URLS[:2], ids=["https", "ssh"])
    @pytest.mark.unit
    def test_git_runs_without_the_servers_ssh_agent_askpass_or_prompts(
        self, git, clean_policy_env, monkeypatch, url
    ) -> None:
        for name, value in PLANTED_ENV.items():
            monkeypatch.setenv(name, value)

        _deliver(clean_policy_env, url, ref="main")

        assert git.git_calls, "the delivery never reached git"
        for call in git.git_calls:
            env = _effective_env(call)
            # Names only: an assertion must never render the environment itself.
            reached = sorted(
                name
                for name in (
                    "SSH_AUTH_SOCK",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                    "SSH_ASKPASS_REQUIRE",
                )
                if name in env
            )
            assert not reached, f"{reached} reached `{' '.join(call['cmd'])}`"
            prompt_off = env.get("GIT_TERMINAL_PROMPT") == "0"
            assert prompt_off, (
                f"git may prompt for credentials: `{' '.join(call['cmd'])}`"
            )

    @pytest.mark.parametrize("url", REMOTE_URLS[:2], ids=["https", "ssh"])
    @pytest.mark.unit
    def test_git_runs_without_inherited_proxy_or_token_variables(
        self, git, clean_policy_env, monkeypatch, url
    ) -> None:
        for name, value in PLANTED_ENV.items():
            monkeypatch.setenv(name, value)

        _deliver(clean_policy_env, url, ref="main")

        assert git.git_calls, "the delivery never reached git"
        leaked_values = set(PLANTED_ENV.values())
        for call in git.git_calls:
            env = _effective_env(call)
            leaked = sorted(k for k, v in env.items() if v in leaked_values)
            assert not leaked, f"{leaked} reached `{' '.join(call['cmd'])}`"

    @pytest.mark.integration
    def test_git_reads_no_system_global_or_inherited_configuration(
        self, git, clean_policy_env, tmp_path, monkeypatch
    ) -> None:
        git_binary = shutil.which("git")
        assert git_binary, "git is required to evaluate configuration scopes"
        home = tmp_path / "server-home"
        home.mkdir()
        (home / ".gitconfig").write_text(
            "[credential]\n\thelper = planted-global\n"
            "[http]\n\tproxy = http://planted-global-proxy.invalid:3128\n",
            encoding="utf-8",
        )
        xdg = tmp_path / "server-xdg"
        (xdg / "git").mkdir(parents=True)
        (xdg / "git" / "config").write_text(
            "[credential]\n\thelper = planted-xdg\n", encoding="utf-8"
        )
        system = tmp_path / "server-system-gitconfig"
        system.write_text("[credential]\n\thelper = planted-system\n", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system))
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.helper")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "planted-env")
        monkeypatch.setenv(
            "GIT_CONFIG_PARAMETERS", "'credential.helper'='planted-params'"
        )
        outside_any_repo = tmp_path / "outside-any-repo"
        outside_any_repo.mkdir()

        def helpers(env: Dict[str, str], cflags: List[str]) -> List[str]:
            """credential.helper as git applies it: an empty value resets the list."""
            out = _REAL_RUN(
                [git_binary, *cflags, "config", "--get-all", "credential.helper"],
                env=env,
                cwd=outside_any_repo,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.split("\n")[:-1]
            effective: List[str] = []
            for value in out:
                effective = [] if value == "" else effective + [value]
            return effective

        def proxy(env: Dict[str, str], cflags: List[str]) -> str:
            return _REAL_RUN(
                [git_binary, *cflags, "config", "--get", "http.proxy"],
                env=env,
                cwd=outside_any_repo,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()

        import os

        server_env = dict(os.environ)
        assert {
            "planted-global",
            "planted-xdg",
            "planted-system",
            "planted-env",
        } <= set(helpers(server_env, [])), (
            "the planted configuration is not visible to git, so this test measures nothing"
        )

        _deliver(clean_policy_env, REMOTE_URLS[0], ref="main")

        assert git.git_calls, "the delivery never reached git"
        for call in git.git_calls:
            env = _effective_env(call)
            cflags = _config_flags(call["cmd"])
            planted = [h for h in helpers(env, cflags) if h.startswith("planted-")]
            assert not planted, (
                f"credential helpers {planted} apply to `{' '.join(call['cmd'])}`"
            )
            assert "planted" not in proxy(env, cflags), (
                f"the server's http.proxy applies to `{' '.join(call['cmd'])}`"
            )

    @pytest.mark.unit
    def test_git_is_reached_with_the_url_after_the_end_of_options_marker(
        self, git, clean_policy_env
    ) -> None:
        """Control: the recorder sees the clone, so the tests above observe git."""
        _deliver(clean_policy_env, REMOTE_URLS[0])

        clone = git.git_calls[0]["cmd"]
        assert "clone" in clone
        assert clone[clone.index("--") + 1] == REMOTE_URLS[0]


def _config_flags(cmd: List[str]) -> List[str]:
    """The ``-c key=value`` options given to git before its subcommand."""
    flags: List[str] = []
    index = 1
    while index < len(cmd) and cmd[index].startswith("-"):
        if cmd[index] == "-c" and index + 1 < len(cmd):
            flags += ["-c", cmd[index + 1]]
            index += 2
            continue
        index += 1
    return flags


# ---------------------------------------------------------------------------
# ssh_key_id
# ---------------------------------------------------------------------------


class TestSshKeyId:
    @pytest.mark.unit
    def test_an_unregistered_ssh_key_id_is_refused_before_git_runs(
        self, git, clean_policy_env
    ) -> None:
        with pytest.raises((ValueError, RuntimeError)):
            _deliver(clean_policy_env, REMOTE_URLS[1], ssh_key_id="operator-key-1")

        assert not git.git_calls, "git ran for an ssh_key_id nobody registered"

    @pytest.mark.unit
    def test_an_empty_ssh_key_id_is_unset_and_the_clone_runs(
        self, git, clean_policy_env
    ) -> None:
        """``ssh_key_id=""`` names no key, so it is read as omitted."""
        _deliver(clean_policy_env, REMOTE_URLS[0], ssh_key_id="")

        clone = git.git_calls[0]["cmd"]
        assert "clone" in clone
        assert clone[clone.index("--") + 1] == REMOTE_URLS[0]


# ---------------------------------------------------------------------------
# The MCP tool and the Python API behind it
# ---------------------------------------------------------------------------


@pytest.fixture
def http():
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield StreamableHttpClient(client)


class TestSetSourceGitTool:
    @pytest.mark.parametrize(
        "url", REMOTE_URLS, ids=["https", "ssh", "scp-like", "git", "http-metadata"]
    )
    @pytest.mark.unit
    def test_a_remote_host_not_on_the_operator_allowlist_is_refused(
        self, http, git, url
    ) -> None:
        _session, headers = http.open_session()

        result = http.call_tool("set_source_git", {"url": url}, headers)

        assert result.get("success") is False, (
            f"a clone from an unlisted host was attempted: {result}"
        )
        assert not git.git_calls, f"git ran for {url}"

    @pytest.mark.unit
    def test_an_unregistered_ssh_key_id_is_refused(self, http, git) -> None:
        _session, headers = http.open_session()

        result = http.call_tool(
            "set_source_git",
            {"url": REMOTE_URLS[1], "ssh_key_id": "operator-key-1"},
            headers,
        )

        assert result.get("success") is False, result
        assert not git.git_calls

    @pytest.mark.parametrize("form", ["file-url", "plain-path"])
    @pytest.mark.unit
    def test_a_local_source_is_refused_even_inside_a_grant(
        self, http, git, tmp_path, monkeypatch, form
    ) -> None:
        granted = tmp_path / "granted"
        repo = granted / "repo"
        repo.mkdir(parents=True)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(granted))
        url = f"file://{repo}" if form == "file-url" else str(repo)
        _session, headers = http.open_session()

        result = http.call_tool("set_source_git", {"url": url}, headers)

        assert result.get("success") is False, (
            f"a local clone source was accepted: {result}"
        )
        assert not git.git_calls

    @pytest.mark.unit
    def test_the_python_api_refuses_a_local_source_for_the_stdio_session(
        self, git, tmp_path
    ) -> None:
        from automated_security_helper.cli.mcp_tools import mcp_set_source_git

        repo = tmp_path / "repo"
        repo.mkdir()

        result = mcp_set_source_git(url=f"file://{repo}", session_id="__default__")

        assert result.get("success") is False, (
            f"a local clone source was accepted: {result}"
        )
        assert not git.git_calls

    @pytest.mark.parametrize(
        "url",
        ["--upload-pack=touch /tmp/never", "ext::sh -c true"],
        ids=["option", "ext"],
    )
    @pytest.mark.unit
    def test_a_command_executing_url_is_refused(self, http, git, url) -> None:
        """Control: refused, so the tool path is reached."""
        _session, headers = http.open_session()

        result = http.call_tool("set_source_git", {"url": url}, headers)

        assert result.get("success") is False, result
        assert not git.git_calls
