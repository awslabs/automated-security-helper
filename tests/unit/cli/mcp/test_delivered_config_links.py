# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file reached through a symlink is judged by every name it has.

``set_source_git`` clones a tree as it is, symlinks included, so a delivered
tree's ``.ash/.ash.yaml`` can be a link to a file outside the MCP workspace
root. Each file of a config's chain is judged by the name it was found or named
by, by each symlink followed on the way to it, and by the file it resolves to. A
file is a client's when any of those names is, and the repository's when any of
them is inside the scanned tree.

An MCP scan reads the config file it discovers only when the file it resolves to
is one the caller may read config from, as ``get_config`` already checks a file
it finds (``validate_config_input``). So for a remote caller the linked file is
reached only when the operator set its directory aside
(``ASH_MCP_ALLOWED_CONFIG_ROOTS``); the tests of the checks above set it aside
(``host_set_aside``), and the last section covers the refusal.

The trees here are delivered by a real git clone of a local repository that
holds the link, through the clone step ``set_source_git`` runs after its url
checks (``tests/utils/delivered_trees.deliver_local_repository``; the tool
itself takes only a remote url). The scans go through the real
``_run_scan_async``, ``run_ash_scan`` and orchestrator, stopped after the config
is resolved.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from automated_security_helper.config.ash_config import AshConfig

SESSION = "client-1"

#: On Windows an MCP scan refuses a linked config source whose chain leads to a
#: network share before it opens it (``config_sources._permitted``: resolving a
#: link there can open a connection to the host a UNC target names), and judges
#: a link that leads to a local file as the file it names, as on POSIX. These
#: tests have not been measured on a Windows host with links, so they stay skipped
#: there; the Windows rule itself is pinned by
#: ``tests/unit/config/test_config_sources_windows_link_chain.py``.
follows_a_link = pytest.mark.skipif(
    sys.platform == "win32",
    reason="not yet measured on a Windows host with links (see config_sources._permitted)",
)

DENIED = "project_name: linked\nfail_on_findings: false\n"
SUPPRESSIONS = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
    "  ignore_paths:\n"
    "    - path: 'vendor/**'\n"
    "      reason: vendored code\n"
)
EXCLUSION = (
    "project_name: linked\n"
    "scanners:\n"
    "  bandit:\n"
    "    options:\n"
    "      excluded_paths:\n"
    "        - path: client-dir\n"
    "          reason: not ours\n"
)
#: Not a config at all: a host file whose text must not reach an error message.
NOT_A_CONFIG = "canary-text-5c1e9d2b on the first line\nsecond line\n"
CANARY = "canary-text-5c1e9d2b"
#: Not YAML: the parser's own message would quote this line.
YAML_CANARY = "canary-yaml-77aa31"
NOT_YAML = f"key: [unclosed {YAML_CANARY}\n"


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def host_set_aside(_server, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The operator sets the host directory aside, so a scan may reach it."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    return _server["host"]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.symlinks=true",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _clone(tmp: Path, files: Dict[str, str], links: Dict[str, Path]) -> Path:
    """Deliver a tree holding ``files`` and ``links`` through a real git clone."""
    from tests.utils.delivered_trees import deliver_local_repository

    origin = tmp / "origin"
    origin.mkdir()
    for name, text in files.items():
        _write(origin / name, text)
    for name, target in links.items():
        _symlink(origin / name, target)
    _git(origin, "init", "-q")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "tree")
    source = deliver_local_repository(origin, SESSION)
    for name in links:
        if os.name == "nt" and not (source / name).is_symlink():
            pytest.skip(
                f"the clone dropped the link {name}: this git cannot write symlinks here"
            )
        assert (source / name).is_symlink(), f"the clone dropped the link {name}"
    return source


def _linked_tree(server: Dict[str, Path], text: str) -> Path:
    """A delivered tree whose ``.ash/.ash.yaml`` links to a host file holding ``text``."""
    host_file = _write(server["host"] / "ash.yaml", text)
    return _clone(server["tmp"], {"app.py": "x = 1\n"}, {".ash/.ash.yaml": host_file})


def _scan_resolution(target: Path, session_id: Optional[str] = SESSION) -> Any:
    """Start an MCP scan; return the config it resolved, or the error resolution raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    outcomes: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> Any:
        try:
            outcomes.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            outcomes.append(exc)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                session_id=session_id,
            )
        )
    assert outcomes, "the scan never reached config resolution"
    return outcomes[-1]


def _start_scan(target: Path, session_id: Optional[str] = SESSION) -> Dict[str, Any]:
    """Call the scan tool; the background scan itself is not started."""
    from automated_security_helper.cli import mcp_tools

    with patch.object(mcp_tools, "_run_scan_async", AsyncMock()) as started:
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(str(target), session_id=session_id)
        )
    if result.get("success") is False:
        started.assert_not_called()
    return result


# ---------------------------------------------------------------------------
# The runtime-override policy
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_config_setting_a_denied_field_is_refused(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _linked_tree(_server, DENIED)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert "fail_on_findings" in str(outcome)


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_the_scan_tool_refuses_a_linked_config_up_front(_server) -> None:
    source = _linked_tree(_server, DENIED)

    result = _start_scan(source)

    assert result.get("success") is False, result
    assert result.get("error_type") == "config_field_denied", result
    assert "fail_on_findings" in result.get("error", ""), result


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_config_widening_the_sandbox_is_refused(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _linked_tree(
        _server,
        yaml.safe_dump(
            {
                "project_name": "linked",
                "sandbox": {"extra_read_paths": [str(_server["host"])]},
            }
        ),
    )

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert "sandbox.extra_read_paths" in str(outcome)


@pytest.mark.unit
def test_positive_control_the_same_file_named_by_the_operator_is_not_refused(
    _server,
) -> None:
    """The refusals above come from how the file was reached, not from its text."""
    from automated_security_helper.config.resolve_config import resolve_config

    host_file = _write(_server["host"] / "ash.yaml", DENIED)
    elsewhere = _server["tmp"] / "elsewhere"
    elsewhere.mkdir()

    config = resolve_config(config_path=host_file, source_dir=elsewhere)

    assert config.fail_on_findings is False


# ---------------------------------------------------------------------------
# What the linked file hides is marked or moved
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_configs_suppressions_and_ignore_paths_are_marked(_server) -> None:
    source = _linked_tree(_server, SUPPRESSIONS)

    config = _scan_resolution(source)

    assert isinstance(config, AshConfig), config
    suppressions = config.global_settings.suppressions
    ignore_paths = config.global_settings.ignore_paths
    assert [entry.rule_id for entry in suppressions] == ["B101"]
    assert [entry.client_supplied for entry in suppressions] == [True]
    assert [entry.path for entry in ignore_paths] == ["vendor/**"]
    assert [entry.client_supplied for entry in ignore_paths] == [True]


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_configs_scanner_exclusion_is_moved_out_of_the_options(
    _server,
) -> None:
    source = _linked_tree(_server, EXCLUSION)

    config = _scan_resolution(source)

    assert isinstance(config, AshConfig), config
    options = config.get_plugin_config("scanner", "bandit")["options"]
    kept = [
        entry["path"] if isinstance(entry, dict) else entry
        for entry in options.get("excluded_paths") or []
    ]
    assert "client-dir" not in kept
    assert [
        (item.scanner, item.option, item.pattern)
        for item in config._client_scanner_exclusions
    ] == [("bandit", "excluded_paths", "client-dir")]


@pytest.mark.integration
def test_a_linked_config_directory_is_judged_by_the_link(_server) -> None:
    """A symlinked ``.ash`` directory: the file sits in the host directory.

    The MCP scan refuses such a tree before it reads a config, because its
    output directory is under ``.ash``; any other resolve of the tree's config
    judges the file by the link.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    host_dir = _server["host"] / "configs"
    _write(host_dir / ".ash.yaml", DENIED)
    source = _clone(_server["tmp"], {"app.py": "x = 1\n"}, {".ash": host_dir})

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(source_dir=source)

    assert "fail_on_findings" in str(refused.value)
    # Named by the path in the delivered tree, not by the host file.
    assert str(host_dir) not in str(refused.value)


# ---------------------------------------------------------------------------
# A link crossed on the way to the file
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_file_reached_through_a_delivered_link_is_the_clients(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The name a link sits at counts, not only the first name and the last."""
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    operator_dir = _server["tmp"] / "operator"
    operator_dir.mkdir()
    real = _write(operator_dir / "real.yaml", "project_name: real\n")
    source = _clone(_server["tmp"], {"app.py": "x = 1\n"}, {"hop.yaml": real})
    named = operator_dir / "ash.yaml"
    _symlink(named, source / "hop.yaml")

    assert config_is_client_supplied(named) is True
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator_dir))
    assert client_named_config_is_untrusted(named) is True
    # Positive control: the target named directly, and a link that stays in the
    # operator's directory, are the operator's.
    assert config_is_client_supplied(real) is False
    direct = operator_dir / "direct.yaml"
    _symlink(direct, real)
    assert config_is_client_supplied(direct) is False


# ---------------------------------------------------------------------------
# The error for a file that is not a config
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_file_that_is_not_a_config_is_not_quoted(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    source = _linked_tree(_server, NOT_A_CONFIG)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigValidationError), outcome
    assert ".ash.yaml" in str(outcome)
    assert CANARY not in str(outcome)
    assert CANARY not in repr(outcome.args)


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_linked_file_that_does_not_parse_is_not_quoted(_server) -> None:
    """The parser's message quotes the line it stopped at; the refusal does not."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    source = _linked_tree(_server, NOT_YAML)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigSourceError), outcome
    assert "could not be parsed" in str(outcome), outcome
    assert ".ash.yaml" in str(outcome)
    assert YAML_CANARY not in str(outcome)
    assert YAML_CANARY not in repr(outcome.args)
    assert outcome.__cause__ is None


@pytest.mark.usefixtures("host_set_aside")
@pytest.mark.integration
def test_the_log_line_for_it_does_not_quote_it_either(_server, caplog) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError
    from automated_security_helper.utils.log import ASH_LOGGER

    source = _linked_tree(_server, NOT_YAML)

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        with pytest.raises(ASHConfigSourceError) as raised:
            resolve_config(source_dir=source)

    # A discovered file that does not parse is reported once, by the raised
    # refusal, which each caller prints in its own words; no "Failed to load
    # configuration file" record is written beside it (config/resolve_config.py,
    # the unparsed-config branch). Whatever is logged, nothing quotes the line.
    assert "could not be parsed" in str(raised.value), raised.value
    assert YAML_CANARY not in str(raised.value)
    quoting = [r.getMessage() for r in caplog.records if YAML_CANARY in r.getMessage()]
    assert quoting == [], quoting


@pytest.mark.usefixtures("host_set_aside")
@pytest.mark.integration
def test_the_scan_tool_does_not_quote_it_either(_server) -> None:
    source = _linked_tree(_server, NOT_A_CONFIG)

    result = _start_scan(source)

    assert CANARY not in repr(result)


#: A suppression expiration the model's own validator rejects. Its message names
#: the rule, not the value.
EXPIRY_CANARY = "canary-zz-41f7"
BAD_EXPIRY = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
    f"      expiration: '{EXPIRY_CANARY}'\n"
)


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_validators_own_message_is_reported_by_its_type(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    source = _linked_tree(_server, BAD_EXPIRY)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigValidationError), outcome
    assert "expiration: invalid value (value_error)" in str(outcome), outcome
    assert EXPIRY_CANARY not in str(outcome)


#: A key the schema does not have; pydantic's location for it repeats it.
KEY_CANARY = "canary-key-9d1e"


@pytest.mark.usefixtures("host_set_aside")
@follows_a_link
@pytest.mark.integration
def test_a_key_the_schema_does_not_have_is_not_named(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    source = _linked_tree(
        _server,
        f"project_name: linked\nglobal_settings:\n  {KEY_CANARY}: 1\n"
        "  severity_threshold: NOT-A-SEVERITY\n",
    )

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigValidationError), outcome
    message = str(outcome)
    assert "global_settings.<key>: Extra inputs are not permitted" in message
    # A key the schema has is still named, so the location is still useful.
    assert "global_settings.severity_threshold:" in message
    assert KEY_CANARY not in message
    assert "NOT-A-SEVERITY" not in message


@pytest.mark.unit
def test_the_validators_message_names_the_rule_not_the_value(_server) -> None:
    """The operator's own file gets the validator's message, which names the rule
    and not the value: a value can be one read from the environment."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    host_file = _write(_server["host"] / "ash.yaml", BAD_EXPIRY)
    elsewhere = _server["tmp"] / "elsewhere"
    elsewhere.mkdir()

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(config_path=host_file, source_dir=elsewhere)

    message = str(raised.value)
    assert "Invalid expiration date format. Use YYYY-MM-DD" in message, message
    assert EXPIRY_CANARY not in message, message


@pytest.mark.unit
def test_positive_control_an_operator_file_keeps_the_detailed_error(
    _server,
) -> None:
    """The operator's own file is reported with the validator's full detail: the
    model and the kind of problem. Not the value: no model's error quotes its
    input, since a config value can be a secret read from the environment."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    host_file = _write(_server["host"] / "ash.yaml", NOT_A_CONFIG)
    elsewhere = _server["tmp"] / "elsewhere"
    elsewhere.mkdir()

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(config_path=host_file, source_dir=elsewhere)

    message = str(raised.value)
    # The refusal wording is the renderer's own, a ruled and documented
    # contract (the restack merge d9644331: refusal messages name the
    # container by its own kind and the location by the config's path), not
    # pydantic's raw text, which quoted the superseded shape.
    assert "Invalid value at '(top level)'" in message, message
    assert "Input should be a valid dictionary or instance of AshConfig" in message, (
        message
    )
    assert CANARY not in message, message


# ---------------------------------------------------------------------------
# A discovered config that links out of what the caller may read
# ---------------------------------------------------------------------------

#: A host config whose text must not reach the client.
LINK_OUT = f"# {CANARY}\nproject_name: linked\n"


def _reads(during: Callable[[], Any]) -> List[Path]:
    """The config files read while ``during`` runs, resolved.

    Recorded at ``read_config_bytes``, the one read every config file goes
    through; the stock chain read never calls the ``read_config_file``
    callable, so a wrapper on that name records nothing.
    """
    from automated_security_helper.config import config_sources

    read: List[Path] = []
    real = config_sources.read_config_bytes

    def recording(path: Path, *args: Any, **kwargs: Any) -> Any:
        read.append(Path(path).resolve())
        return real(path, *args, **kwargs)

    with patch.object(config_sources, "read_config_bytes", recording):
        during()
    return read


@pytest.mark.integration
def test_a_remote_scan_refuses_a_discovered_config_linking_out(_server) -> None:
    source = _linked_tree(_server, LINK_OUT)
    host_file = _server["host"] / "ash.yaml"

    reads: List[Any] = []
    read = _reads(lambda: reads.append(_start_scan(source)))
    (result,) = reads

    assert result.get("success") is False, result
    assert result.get("error_type") == "config_input_not_permitted", result
    assert (source / ".ash" / ".ash.yaml").as_posix() in result["error"], result
    assert str(_server["host"]) not in repr(result)
    assert CANARY not in repr(result)
    assert host_file.resolve() not in read


@pytest.mark.integration
def test_the_scan_itself_refuses_it_without_reading_it(_server) -> None:
    """The scan's own resolution refuses it too, should the file change after the check."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    source = _linked_tree(_server, LINK_OUT)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    def run() -> None:
        with (
            patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
            patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(source),
                    output_dir=str(output),
                    severity_threshold="MEDIUM",
                    session_id=SESSION,
                )
            )

    read = _reads(run)
    entry = registry.get_scan(scan_id)

    # The code, then the text the CLI showed for the refusal
    # (mcp_tools._exit_message); it names the link by its in-tree path.
    assert entry.error_message.startswith("ASH exited with code 3"), entry.to_dict()
    assert (source / ".ash" / ".ash.yaml").as_posix() in entry.error_message
    assert str(_server["host"]) not in repr(entry.to_dict())
    assert (_server["host"] / "ash.yaml").resolve() not in read
    assert CANARY not in repr(entry.to_dict())


def _remote_options(source: Path, output: Path) -> Any:
    from automated_security_helper.cli.mcp.profile_registry import (
        session_client_rules,
    )
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(
        source_dir=source,
        output_dir=output,
        remote_client=True,
        client_config_policy=session_client_rules(SESSION),
        config_base_gate=config_base_gate(SESSION),
    )


@pytest.mark.integration
def test_the_output_dir_check_does_not_read_it(_server) -> None:
    """The host file turns the sandbox off; read, it would let the linked output through."""
    from automated_security_helper.interactions.run_ash_scan import (
        _refuse_symlinked_output_dir,
    )

    source = _linked_tree(_server, f"# {CANARY}\nsandbox:\n  mode: 'off'\n")
    real_output = _server["tmp"] / "real-output"
    real_output.mkdir()
    output = source / "out"
    _symlink(output, real_output)
    exited: List[Any] = []

    def run() -> None:
        try:
            _refuse_symlinked_output_dir(_remote_options(source, output))
        except SystemExit as exc:
            exited.append(exc.code)

    read = _reads(run)

    # The delivered config that links out of the tree is refused, as any config
    # input outside the session's grant is (exit 3), and never read.
    assert exited == [3]
    assert (_server["host"] / "ash.yaml").resolve() not in read


@pytest.mark.integration
def test_the_workspace_knobs_reader_does_not_read_it(_server) -> None:
    from automated_security_helper.interactions.run_ash_scan import (
        _resolve_workspace_execution_config,
    )

    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )

    source = _linked_tree(
        _server, f"# {CANARY}\nworkspace:\n  max_parallel_projects: 9\n"
    )
    refused: List[Any] = []

    def run() -> None:
        try:
            _resolve_workspace_execution_config(
                _remote_options(source, _server["tmp"] / "out")
            )
        except ASHConfigInputNotPermittedError as exc:
            refused.append(exc)

    read = _reads(run)

    # Refused, as the run refuses it, rather than read or passed over.
    (refusal,) = refused
    assert CANARY not in str(refusal)
    assert (_server["host"] / "ash.yaml").resolve() not in read


@pytest.mark.integration
def test_get_config_refuses_the_same_layout_as_before(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    source = _linked_tree(_server, LINK_OUT)

    result = mcp_get_config(search_dir=str(source), session_id=SESSION)

    assert result.get("error_type") == "config_input_not_permitted", result
    assert CANARY not in repr(result)


@follows_a_link
@pytest.mark.unit
def test_stdio_keeps_a_local_repositorys_linked_config(_server) -> None:
    """Over stdio only the system-directory net applies, as before."""
    host_file = _write(_server["host"] / "ash.yaml", LINK_OUT)
    repo = _server["tmp"] / "home" / "repo"
    _write(repo / "app.py", "x = 1\n")
    _symlink(repo / ".ash" / ".ash.yaml", host_file)

    started = _start_scan(repo, session_id=None)
    config = _scan_resolution(repo, session_id=None)

    assert started.get("success") is True, started
    assert isinstance(config, AshConfig), config
    assert config.project_name == "linked"


@pytest.mark.parametrize("where", ["in the delivered tree", "in a config root"])
@follows_a_link
@pytest.mark.integration
def test_a_link_that_stays_inside_the_allowed_roots_is_followed(
    _server, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    if where == "in a config root":
        monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
        target = _write(_server["host"] / "ash.yaml", "project_name: linked\n")
        source = _clone(
            _server["tmp"], {"app.py": "x = 1\n"}, {".ash/.ash.yaml": target}
        )
    else:
        source = _clone(
            _server["tmp"],
            {"app.py": "x = 1\n", "conf/real.yaml": "project_name: linked\n"},
            {".ash/.ash.yaml": Path("../conf/real.yaml")},
        )

    started = _start_scan(source)
    config = _scan_resolution(source)

    assert started.get("success") is True, started
    assert isinstance(config, AshConfig), config
    assert config.project_name == "linked"
