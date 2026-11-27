# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --source-git`` takes a remote repository on the MCP tool's rules.

The MCP ``set_source_git`` tool's request rules are the contract: the CLI runs
the same function (``source_delivery.validated_remote_clone_request``), and the
rows below hold the two surfaces together. Every request goes to both, with the
operator's host allowlist opened wide for the tool (the allowlist is the one rule
that differs: the MCP server acts for a remote client, so its operator lists the
hosts; on the command line the person typing the URL is the operator). A request
one refuses, the other refuses with the same ``error_type``; one the tool
accepts, the CLI accepts. No git runs and no host is contacted: the clone itself
is replaced by a fake at the one seam each surface has.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp import source_delivery
from automated_security_helper.cli.mcp.source_delivery import (
    ASH_MCP_GIT_ALLOWED_HOSTS_ENV,
    CloneRequestRefused,
    clone_remote_source,
    validated_remote_clone_request,
)
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

URL = "https://example.com/team/repo.git"

#: (id, url, ref, depth, ssh_key_id, the error_type both surfaces answer, or None)
REQUESTS = [
    ("https", URL, None, 1, None, None),
    ("https with a ref", URL, "main", 5, None, None),
    ("ssh url", "ssh://git@example.com/team/repo.git", None, 1, None, None),
    ("scp-like", "git@example.com:team/repo.git", None, 1, None, None),
    (
        "option-like url",
        "--upload-pack=touch /tmp/x",
        None,
        1,
        None,
        "clone_url_not_permitted",
    ),
    ("ext transport", "ext::sh -c id", None, 1, None, "clone_url_not_permitted"),
    (
        "control char",
        "https://example.com/a\x00b",
        None,
        1,
        None,
        "clone_url_not_permitted",
    ),
    (
        "plain http",
        "http://example.com/team/repo.git",
        None,
        1,
        None,
        "clone_url_not_permitted",
    ),
    (
        "git protocol",
        "git://example.com/team/repo.git",
        None,
        1,
        None,
        "clone_url_not_permitted",
    ),
    ("option-like ref", URL, "--output=x", 1, None, "clone_ref_not_permitted"),
    ("depth zero", URL, None, 0, None, "invalid_clone_depth"),
    ("depth too large", URL, None, 100000, None, "invalid_clone_depth"),
    ("local path", "/etc", None, 1, None, "local_clone_source_refused"),
    ("relative path", "../elsewhere", None, 1, None, "local_clone_source_refused"),
    ("file url", "file:///etc", None, 1, None, "local_clone_source_refused"),
    ("ssh key id", URL, None, 1, "key-1", "ssh_key_not_registered"),
]


@pytest.fixture
def all_hosts_allowed(monkeypatch):
    monkeypatch.setenv(ASH_MCP_GIT_ALLOWED_HOSTS_ENV, "example.com")


@pytest.mark.parametrize("case", REQUESTS, ids=[case[0] for case in REQUESTS])
def test_both_surfaces_give_one_answer(case, all_hosts_allowed, tmp_path):
    _name, url, ref, depth, key, expected = case

    with patch.object(
        source_delivery, "set_source_git", return_value=tmp_path
    ) as cloned:
        tool = mcp_set_source_git(
            url, ref, ssh_key_id=key, depth=depth, session_id="parity-session"
        )

    try:
        validated_remote_clone_request(url, ref, depth, key)
        shared = None
    except CloneRequestRefused as refusal:
        shared = refusal.error_type

    assert shared == expected
    if expected is None:
        assert tool["success"] is True and cloned.call_count == 1
    else:
        assert tool["success"] is False
        assert tool["error_type"] == expected
        assert cloned.call_count == 0


def test_the_host_allowlist_is_the_one_rule_only_the_tool_applies(monkeypatch):
    monkeypatch.delenv(ASH_MCP_GIT_ALLOWED_HOSTS_ENV, raising=False)
    answer = mcp_set_source_git(URL, session_id="parity-session")
    assert answer["error_type"] == "clone_host_not_permitted"
    # The command line's request rules do not read the operator's list.
    assert validated_remote_clone_request(URL)[3] == ("https", "example.com", 443)


class TestTheCloneIsGitInTheSameEnvironment:
    def test_the_clone_runs_with_the_deliverys_environment_under_the_destination(
        self, tmp_path
    ):
        seen = {}

        def fake_clone(url, ref, *, depth, target, env, git=None):
            seen.update(url=url, ref=ref, depth=depth, target=target, env=env)

        with (
            patch.object(source_delivery, "_clone", fake_clone),
            patch.object(
                source_delivery, "_git_executable", return_value="/usr/bin/git"
            ),
        ):
            source = clone_remote_source(URL, "v1", depth=3, destination=tmp_path)

        assert source == tmp_path / "source" == seen["target"]
        assert (seen["url"], seen["ref"], seen["depth"]) == (URL, "v1", 3)
        assert seen["env"]["HOME"] == str(tmp_path / "home")
        assert seen["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
        assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"

    def test_a_refused_request_runs_nothing(self, tmp_path):
        with patch.object(source_delivery, "_clone") as clone:
            with pytest.raises(CloneRequestRefused):
                clone_remote_source("file:///etc", destination=tmp_path)
        assert clone.call_count == 0


def _scan(*options: str):
    return CliRunner().invoke(app, ["scan", *options])


def _scan_fs(tmp_path, values: dict, *options: str, clone=None):
    """``ash scan fs`` with a --cli-json-input document of *values*; nothing is cloned.

    Returns the result and the two stand-ins, for the clone and for the scan. A
    document is passed only when *values* holds something; *clone* is what the clone
    stand-in does when it is called.
    """
    arguments = ["scan", "fs", *options]
    if values:
        document = tmp_path / "scan.json"
        document.write_text(json.dumps(values), encoding="utf-8")
        arguments += ["--cli-json-input", str(document)]
    with (
        patch(
            "automated_security_helper.cli.mcp.source_delivery.clone_remote_source",
            side_effect=clone,
        ) as cloned,
        patch("automated_security_helper.cli.scan.run_ash_scan") as run,
    ):
        result = CliRunner().invoke(app, arguments)
    return result, cloned, run


class TestTheCommandLine:
    @pytest.mark.parametrize(
        "case",
        # A NUL cannot be on a command line, and the CLI has no ssh key option.
        [
            c
            for c in REQUESTS
            if c[5] is not None and c[4] is None and c[0] != "control char"
        ],
        ids=lambda c: c[0],
    )
    def test_a_refused_request_is_a_usage_error_before_any_clone(self, case):
        _name, url, ref, depth, _key, _expected = case
        # The "=" form: a value that starts with "-" is the option's value.
        args = [f"--source-git={url}"]
        if ref:
            args += [f"--git-ref={ref}"]
        args += [f"--git-depth={depth}"]
        with patch(
            "automated_security_helper.cli.mcp.source_delivery.clone_remote_source"
        ) as clone:
            result = _scan(*args)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "--source-git" in result.output
        assert clone.call_count == 0

    @pytest.mark.parametrize(
        "other",
        [
            ("--source-dir", "."),
            ("--image", "alpine:3"),
            ("--staged",),
            ("--use-existing",),
            ("--changed-files-only",),
        ],
        ids=lambda o: o[0],
    )
    def test_it_cannot_be_combined_with_another_subject(self, other):
        result = _scan("--source-git", URL, *other)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert other[0] in result.output

    @pytest.mark.parametrize(
        ("values", "options"),
        [
            pytest.param(
                {"source_git": URL, "source_dir": "svc-b"}, [], id="both-keys"
            ),
            pytest.param(
                {"source_git": URL, "--source-dir": "svc-b"}, [], id="the-flag-key"
            ),
            pytest.param(
                {"source_dir": "svc-b"}, ["--source-git", URL], id="a-typed-source-git"
            ),
        ],
    )
    def test_a_json_documents_source_dir_cannot_be_combined_with_it(
        self, values, options, tmp_path
    ):
        # A --cli-json-input document is named on this command line, so the
        # directory its `source_dir` names is given there, as --source-dir is. It is
        # refused before any clone, and the clone never stands in for it.
        result, clone, run = _scan_fs(tmp_path, values, *options)

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert "--source-git cannot be combined with --source-dir" in result.output
        assert clone.call_count == 0
        assert run.call_count == 0

    @pytest.mark.parametrize(
        ("values", "options"),
        [
            pytest.param({}, ["svc-b", "--source-git", URL], id="a-typed-path"),
            pytest.param({"source_git": URL, "path": "svc-b"}, [], id="the-path-key"),
        ],
    )
    def test_a_path_cannot_be_combined_with_it_either(self, values, options, tmp_path):
        # The other place a document can name the directory, which the line for its
        # `source_dir` key sends the reader to: refused as well, so neither key is
        # the way round the refusal.
        result, clone, run = _scan_fs(tmp_path, values, *options)

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert "--source-git cannot be combined with the PATH argument" in result.output
        assert clone.call_count == 0
        assert run.call_count == 0

    @pytest.mark.parametrize(
        "values",
        [
            pytest.param({}, id="no-document"),
            pytest.param({"source_dir": None}, id="a-null-source_dir-key"),
        ],
    )
    def test_the_source_dir_variable_is_not_a_second_directory(
        self, values, tmp_path, monkeypatch
    ):
        # The control for the rows above: ASH_SOURCE_DIR is ambient, as every
        # option's variable is, and a null key names nothing, so the clone is what is
        # scanned.
        monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path / "from-env"))
        made = []

        def fake_clone(url, ref, *, depth, destination):
            source = Path(destination) / "source"
            source.mkdir()
            made.append(source)
            return source

        result, clone, run = _scan_fs(
            tmp_path, values, "--source-git", URL, clone=fake_clone
        )

        assert result.exit_code == 0, result.output
        (source,) = made
        assert clone.call_count == 1
        assert run.call_args.kwargs["source_dir"] == source.as_posix()

    def test_a_ref_or_depth_alone_is_refused(self):
        for option in (("--git-ref", "main"), ("--git-depth", "2")):
            result = _scan(*option)
            assert result.exit_code == ASH_EXIT_USAGE_ERROR
            assert "--source-git" in result.output

    def test_a_clone_becomes_the_source_and_is_removed_afterwards(self, tmp_path):
        made = []

        def fake_clone(url, ref, *, depth, destination):
            source = Path(destination) / "source"
            source.mkdir()
            (source / "app.py").write_text("x = 1\n", encoding="utf-8")
            made.append((url, ref, depth, Path(destination), source))
            return source

        with (
            patch(
                "automated_security_helper.cli.mcp.source_delivery.clone_remote_source",
                side_effect=fake_clone,
            ),
            patch("automated_security_helper.cli.scan.run_ash_scan") as run,
        ):
            result = _scan("--source-git", URL, "--git-ref", "v1", "--git-depth", "4")

        assert result.exit_code == 0, result.output
        ((url, ref, depth, root, source),) = made
        assert (url, ref, depth) == (URL, "v1", 4)
        assert run.call_args.kwargs["source_dir"] == source.as_posix()
        # The output directory is beside the working directory, not in the clone.
        assert not str(run.call_args.kwargs["output_dir"]).startswith(str(root))
        assert not root.exists()

    def test_a_clone_git_refused_exits_one_and_leaves_nothing(self):
        from automated_security_helper.cli.mcp.source_delivery import (
            GitCommandError,
        )

        roots = []

        def failing(url, ref, *, depth, destination):
            roots.append(Path(destination))
            raise GitCommandError("git clone failed (exit 128): no such repo", "x")

        with (
            patch(
                "automated_security_helper.cli.mcp.source_delivery.clone_remote_source",
                side_effect=failing,
            ),
            patch("automated_security_helper.cli.scan.run_ash_scan") as run,
        ):
            result = _scan("--source-git", URL)

        assert result.exit_code == 1
        assert "no such repo" in result.output
        assert run.call_count == 0
        assert roots and not roots[0].exists()
