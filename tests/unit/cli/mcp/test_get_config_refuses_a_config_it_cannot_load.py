# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config refuses a config it cannot load, exit 3, as ``ash config get`` does.

``ash config get`` exits 3 for a named config file that does not exist and for
a named or discovered file that does not parse (cli/config.py). get_config
answered three of those differently:

- a named or discovered file that does not parse answered with the default
  config, as a success, since resolve_config falls back to the defaults on a
  load error unless told not to;
- a named file that does not exist, a link to nothing included, answered with
  the default config too;
- ``raw=True`` on a file that does not parse raised, and the tool's generic
  handler answered exit 1.

Each is ``success`` false with ``exit_code`` 3: ``file_not_found`` for the
missing file, ``permission_denied`` for one the server cannot read (the
OSError from opening it is refused with exit 3, resolved or raw, and not left
to the generic handler's exit 1), and ``invalid_format`` for the others.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest
import yaml

SESSION = "client-one"
BAD_YAML = "project_name: [unclosed\nglobal_settings: {\n"
BAD_JSON = '{"project_name": "x",\n'
GOOD_YAML = "project_name: as-written\n"


class _Context:
    def __init__(self) -> None:
        self.headers = {"mcp-session-id": SESSION}
        self.messages: List[str] = []

    async def info(self, message: str) -> None:
        self.messages.append(message)

    async def error(self, message: str) -> None:
        self.messages.append(message)

    async def warning(self, message: str) -> None:
        self.messages.append(message)

    async def report_progress(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def debug(self, message: str) -> None:
        self.messages.append(message)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "roots" / "project"
    root.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "roots"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    return root.resolve()


def _get_config(config_path: Path, raw: bool = False) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return asyncio.run(
        mcp_server.get_config(_Context(), config_path=str(config_path), raw=raw)
    )


def _refused(response: Dict[str, Any], category: str) -> None:
    assert response.get("success") is False, response
    assert response["exit_code"] == 3, response
    assert response["error_category"] == category, response


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
@pytest.mark.parametrize(
    "name, text",
    [(".ash.yaml", BAD_YAML), (".ash.json", BAD_JSON)],
    ids=["yaml", "json"],
)
def test_a_named_file_that_does_not_parse(root: Path, name: str, text: str, raw: bool):
    config = root / name
    config.write_text(text, encoding="utf-8")

    _refused(_get_config(config, raw=raw), "invalid_format")


@pytest.mark.parametrize(
    "name, text",
    [(".ash.yaml", BAD_YAML), (".ash.json", BAD_JSON)],
    ids=["yaml", "json"],
)
def test_a_discovered_file_that_does_not_parse(root: Path, name: str, text: str):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    (root / name).write_text(text, encoding="utf-8")

    _refused(mcp_get_config(search_dir=str(root), session_id=SESSION), "invalid_format")


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_a_discovery_read_failure_is_refused_not_raised(root: Path, raw: bool):
    """Discovery reads a pyproject.toml to learn whether it configures ASH. One
    that declares [tool.ash] but cannot be parsed fails that read, and the tool
    answers it as a config it cannot load, exit 3, like any other file that does
    not parse: the failure never escapes the tool boundary as a raise."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    (root / "pyproject.toml").write_text(
        "[tool.ash]\nproject_name = [unclosed\n", encoding="utf-8"
    )

    response = mcp_get_config(search_dir=str(root), raw=raw, session_id=SESSION)

    _refused(response, "invalid_format")
    assert "pyproject.toml" in str(response.get("error") or response), response
    # The same response shape as any other discovered file that does not parse:
    # the context names the file, so a client gets one shape for both.
    named = str((response.get("context") or {}).get("config_path", ""))
    assert named.endswith("pyproject.toml"), response


def test_a_named_file_that_does_not_exist(root: Path):
    _refused(_get_config(root / ".ash.yaml"), "file_not_found")


def test_a_named_link_to_nothing(root: Path):
    link = root / ".ash.yaml"
    link.symlink_to(root / "gone.yaml")

    _refused(_get_config(link), "file_not_found")


#: Permission bits are POSIX's, and root reads past them.
_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits, which root reads past",
)


@pytest.fixture
def unreadable(root: Path):
    config = root / ".ash.yaml"
    config.write_text(GOOD_YAML, encoding="utf-8")
    config.chmod(0)
    yield config
    config.chmod(0o600)


@_NEEDS_PERMISSION_BITS
@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_a_named_file_that_cannot_be_read(unreadable: Path, raw: bool):
    _refused(_get_config(unreadable, raw=raw), "permission_denied")


@pytest.fixture
def unreadable_ash_config(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    operator = tmp_path / "operator-unreadable.yaml"
    operator.write_text(GOOD_YAML, encoding="utf-8")
    operator.chmod(0)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    yield operator
    operator.chmod(0o600)


@_NEEDS_PERMISSION_BITS
def test_an_ash_config_that_cannot_be_read_with_no_file_to_answer_with(
    root: Path, unreadable_ash_config: Path
):
    """With no named or discovered file, the tool answers with what a scan
    starts from, the file ASH_CONFIG names. One the server cannot read is a
    config it cannot load, exit 3: the OSError never escapes the tool."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    response = mcp_get_config(search_dir=str(root), session_id=SESSION)

    _refused(response, "permission_denied")


@_NEEDS_PERMISSION_BITS
def test_an_ash_config_that_cannot_be_read_behind_a_named_file(
    root: Path, unreadable_ash_config: Path
):
    """A named file that loads does not hide the ASH_CONFIG file the scan
    would refuse: resolution starts from it, so the tool refuses it first."""
    config = root / ".ash.yaml"
    config.write_text(GOOD_YAML, encoding="utf-8")

    _refused(_get_config(config), "permission_denied")


@_NEEDS_PERMISSION_BITS
@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_a_discovered_file_that_cannot_be_read(root: Path, unreadable: Path, raw: bool):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    response = mcp_get_config(search_dir=str(root), raw=raw, session_id=SESSION)

    _refused(response, "permission_denied")


@_NEEDS_PERMISSION_BITS
@pytest.mark.parametrize(
    "route",
    [
        "named-absolute",
        "named-absolute-raw",
        "named-relative",
        "named-dot",
        "named-symlink",
        "discovered-resolved",
        "discovered-raw",
    ],
)
def test_an_unreadable_file_is_named_once(
    root: Path, unreadable: Path, route: str, monkeypatch: pytest.MonkeyPatch
):
    """The refusal's message names the file exactly once: the frame names it,
    so the operating system's own copy of the name is left out. The structured
    ``config_path`` field is the machine's copy and does not count."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    named = unreadable.name
    if route.startswith("discovered"):
        response = mcp_get_config(
            search_dir=str(root),
            raw=route.endswith("raw"),
            session_id=SESSION,
        )
    else:
        monkeypatch.chdir(root)
        if route == "named-relative":
            target = Path(unreadable.name)
        elif route == "named-dot":
            target = Path(f"./{unreadable.name}")
        elif route == "named-symlink":
            link = root / "link.yaml"
            link.symlink_to(unreadable)
            target, named = link, link.name
        else:
            target = unreadable
        response = _get_config(target, raw=route.endswith("raw"))

    _refused(response, "permission_denied")
    message = str(response.get("error") or response.get("message") or "")
    assert message, response
    assert message.count(named) == 1, message


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_control_a_named_file_that_loads_is_answered(root: Path, raw: bool):
    config = root / ".ash.yaml"
    config.write_text(GOOD_YAML, encoding="utf-8")

    response = _get_config(config, raw=raw)

    assert response.get("success") is not False, response
    assert response["project_name"] == "as-written", response


def test_control_no_config_found_answers_with_the_defaults(root: Path):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    response = mcp_get_config(search_dir=str(root), session_id=SESSION)

    assert response.get("success") is not False, response
    assert "project_name" in response, response


class TestOneUnreadableOperatorConfigAnswersOneCategory:
    """One unreadable ASH_CONFIG reads as one refusal from every tool.

    The operator's config is read by get_config for its answer, by
    scan_directory for the server limits, and by the workspace scan for the
    same limits. Each answers exit 3 with ``config_load_category``'s category,
    so a client that branches on the category reads one value for one broken
    file whichever tool it asked.
    """

    @pytest.fixture
    def unreadable_default(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """ASH_CONFIG naming a directory: opening it for reading is an OSError."""
        config_dir = root / "config-dir"
        config_dir.mkdir()
        monkeypatch.setenv("ASH_CONFIG", str(config_dir))
        return config_dir

    def test_get_config(self, root: Path, unreadable_default: Path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        # search_dir keeps discovery inside the granted root, where it finds
        # nothing, so the answer falls to the default config ASH_CONFIG names.
        response = mcp_get_config(search_dir=str(root), session_id=SESSION)

        _refused(response, "invalid_format")

    def test_scan_directory(self, root: Path, unreadable_default: Path):
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        target = root / "project"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n", encoding="utf-8")

        response = asyncio.run(mcp_scan_directory(directory_path=str(target)))

        _refused(response, "invalid_format")

    def test_workspace_scan(self, root: Path, unreadable_default: Path):
        from automated_security_helper.cli import mcp_server

        (root / "api").mkdir()
        workspace_file = root / "dev.code-workspace"
        workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")

        response = asyncio.run(
            mcp_server.run_ash_workspace_scan(
                _Context(), workspace_file=str(workspace_file)
            )
        )

        _refused(response, "invalid_format")

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                lambda: _validation_error("the operator config is refused"),
                id="refused",
            ),
            pytest.param(lambda: IsADirectoryError(21, "Is a directory"), id="os"),
            pytest.param(
                lambda: FileNotFoundError(2, "No such file or directory"),
                id="missing",
            ),
        ],
    )
    def test_the_workspace_limits_read_answers_the_same_category(
        self, root: Path, error
    ):
        """The workspace scan reads the server limits from the operator's config
        after resolving the plan. Resolution usually refuses a broken operator
        config first, so this read failing is reached only when the reads are
        reordered or the file changes in between: made to fail here directly, it
        answers exit 3 with config_load_category's value, as get_config and
        scan_directory do, and not the generic response's category."""
        from automated_security_helper.cli import mcp_server
        from automated_security_helper.cli.mcp_tools import config_load_category

        failure = error()
        (root / "api").mkdir()
        workspace_file = root / "dev.code-workspace"
        workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")

        with patch(
            "automated_security_helper.cli.mcp_tools._resource_limits",
            side_effect=failure,
        ) as limits:
            response = asyncio.run(
                mcp_server.run_ash_workspace_scan(
                    _Context(), workspace_file=str(workspace_file)
                )
            )

        assert limits.called, (
            "the limits read was not reached; the cell measured nothing"
        )
        _refused(response, config_load_category(failure).value)


def _validation_error(message: str):
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    return ASHConfigValidationError(message)


class TestADiscoveryFailureOutsideTheSourceErrorIsAnswered:
    """Discovery can raise more than ASHConfigSourceError, and the discovery
    site answers every kind the resolve step below it catches as a config it
    cannot load, exit 3: never a raise the generic handler turns into exit 1.

    The input that reaches it: a ``.ash`` directory the server may not search.
    Discovery asks ``Path.is_file`` about each name in it, and on Python 3.10 to
    3.13 that re-raises the PermissionError from stat; 3.14's answers False, so
    there the names are skipped as absent (measured on each interpreter).
    """

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(lambda: _validation_error("x"), id="validation"),
            pytest.param(lambda: yaml.YAMLError("x"), id="yaml"),
            pytest.param(lambda: PermissionError(13, "Permission denied"), id="os"),
            pytest.param(lambda: ValueError("x"), id="value"),
        ],
    )
    def test_each_kind_is_answered_as_a_config_it_cannot_load(self, root: Path, error):
        from automated_security_helper.cli.mcp_tools import (
            config_load_category,
            mcp_get_config,
        )

        failure = error()
        with patch(
            "automated_security_helper.config.resolve_config.find_config_file",
            side_effect=failure,
        ) as discovery:
            response = mcp_get_config(search_dir=str(root), session_id=SESSION)

        assert discovery.called, "discovery was not reached; the cell measured nothing"
        _refused(response, config_load_category(failure).value)

    @_NEEDS_PERMISSION_BITS
    def test_a_config_directory_the_server_cannot_search(self, root: Path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        ash_dir = root / ".ash"
        ash_dir.mkdir()
        ash_dir.chmod(0)
        try:
            response = mcp_get_config(search_dir=str(root), session_id=SESSION)
        finally:
            ash_dir.chmod(0o755)

        assert response.get("exit_code") != 1, response
        if sys.version_info < (3, 14):
            # Below 3.14 the walk raises PermissionError on the unsearchable
            # directory, and the category mapping answers it as the operating
            # system's refusal, never as a format problem.
            _refused(response, "permission_denied")
        else:
            assert response.get("success") is not False, response
            assert "project_name" in response, response


@_NEEDS_PERMISSION_BITS
def test_discovery_over_an_unreadable_pyproject_answers_and_never_raises(root: Path):
    """Discovery reads a pyproject.toml to learn whether it configures ASH. One
    it cannot read at all is skipped as if absent, and the tool answers the
    defaults -- measured, and pinned so a change of that contract is visible.
    What may never happen is the raise reaching the generic handler as exit 1;
    the discovery site catches the same tuple the resolve step below it does."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    pyproject = root / "pyproject.toml"
    pyproject.write_text('[tool.ash]\nproject_name = "x"\n', encoding="utf-8")
    pyproject.chmod(0)
    try:
        response = mcp_get_config(search_dir=str(root), session_id=SESSION)
    finally:
        pyproject.chmod(0o644)

    assert response.get("success") is not False, response
    assert response.get("exit_code") != 1, response
    assert "project_name" in response, response


def _ends_within(call: Callable[[], Any], seconds: float = 5.0) -> Any:
    """``call``'s answer, run on a daemon thread and given ``seconds`` to end.

    A cause walk that cycles never returns, and the venv has no pytest-timeout,
    so the walk is bounded here: a cycle it does not stop at reads as this
    cell's failure rather than a hung run.
    """
    answers: List[Any] = []
    worker = threading.Thread(target=lambda: answers.append(call()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"the walk did not end within {seconds} s"
    return answers[0]


def _two_exception_cycle():
    first, second = ValueError("a"), OSError("b")
    first.__cause__ = second
    second.__cause__ = first
    return first, second


class TestACyclicCauseChainEnds:
    """``raise e from e`` makes ``__cause__`` a cycle; the walks end anyway.

    The self-cycles below need only a walk that stops at its own error. The
    two-exception cycles need the seen set: a walk that only compares each
    cause with the error before it passes from one to the other forever, so
    those cells run the walk on a thread with a bound.
    """

    def test_caused_by_ends_on_a_two_exception_cycle(self):
        from automated_security_helper.utils.error_text import caused_by

        first, _ = _two_exception_cycle()

        assert _ends_within(lambda: caused_by(first, KeyError)) is False
        assert _ends_within(lambda: caused_by(first, OSError)) is True

    def test_config_load_category_ends_on_a_two_exception_cycle(self):
        from automated_security_helper.cli.mcp_tools import config_load_category

        first, _ = _two_exception_cycle()

        # The walk ends, and it saw the cycle's OSError: a read failure's
        # category, not a format's.
        assert _ends_within(lambda: config_load_category(first)).value == (
            "invalid_path"
        )

    def test_the_workspace_tools_walk_ends_on_a_two_exception_cycle(self):
        from automated_security_helper.cli.mcp.workspace import _caused_by

        first, _ = _two_exception_cycle()

        assert _ends_within(lambda: _caused_by(first, KeyError)) is False

    def test_config_load_category_answers_on_a_cycle(self):
        from automated_security_helper.cli.mcp_tools import config_load_category

        error = ValueError("x")
        error.__cause__ = error

        assert config_load_category(error).value == "invalid_format"

    def test_a_file_not_found_cycle_keeps_its_category(self):
        from automated_security_helper.cli.mcp_tools import config_load_category

        error = FileNotFoundError("x")
        error.__cause__ = error

        assert config_load_category(error).value == "file_not_found"

    def test_caused_by_answers_false_on_an_unrelated_cycle(self):
        from automated_security_helper.utils.error_text import caused_by

        error = ValueError("x")
        error.__cause__ = error

        assert caused_by(error, KeyError) is False
        assert caused_by(error, ValueError) is True
