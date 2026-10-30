# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An extends base the load cannot read is answered by its path, named once.

Three parts of one contract. A base the operating system refuses is named by
the refusal exactly once: the message already names the file, so the OSError's
own copy of the name said it twice. A base that is missing, a directory, or a
symbolic link loop is a path problem, so the refusal chains an OSError cause
and the MCP category mapping answers file_not_found or invalid_path, never
invalid_format with format advice. And a top-level config that is a symbolic
link loop is named as the loop it is, not as a file that does not exist.
"""

from __future__ import annotations

import os
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp_tools import config_load_category
from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

_PRE_313 = sys.version_info < (3, 13)
#: A base name read from the environment: it must appear on no refusal surface.
HIDDEN_BASE = "envbase-hidden-7731"

_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="root (and Windows, with no mode bits) reads through permission bits",
)


@pytest.fixture
def chain(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "cfg"
    folder.mkdir()
    top = folder / "top.yaml"
    top.write_text("extends: cfl-base.yaml\nproject_name: top\n", encoding="utf-8")
    return folder, top


@_NEEDS_PERMISSION_BITS
def test_an_unreadable_base_is_named_once(chain):
    folder, top = chain
    base = folder / "cfl-base.yaml"
    base.write_text("project_name: base\n", encoding="utf-8")
    base.chmod(0)
    try:
        with pytest.raises(ASHConfigSourceError) as refused:
            load_config_file_for_run(top)
    finally:
        base.chmod(0o644)
    text = str(refused.value)
    assert text.count("cfl-base.yaml") == 1, text


def _category_for(top):
    with pytest.raises(ASHConfigSourceError) as refused:
        load_config_file_for_run(top)
    return refused.value, config_load_category(refused.value).value


def test_a_missing_base_is_answered_file_not_found(chain):
    _, top = chain
    error, category = _category_for(top)
    assert category == "file_not_found", (category, str(error))


def test_a_directory_base_is_answered_as_a_path_problem(chain):
    folder, top = chain
    (folder / "cfl-base.yaml").mkdir()
    error, category = _category_for(top)
    assert category in ("invalid_path", "file_not_found"), (category, str(error))
    assert category != "file_not_found", (category, str(error))


def test_a_looped_base_is_answered_as_a_path_problem(chain):
    folder, top = chain
    (folder / "cfl-base.yaml").symlink_to(folder / "cfl-base.yaml")
    error, category = _category_for(top)
    assert category == "invalid_path", (category, str(error))


def test_a_looped_path_loaded_directly_is_a_path_problem(tmp_path, monkeypatch):
    # A direct load resolves the named path first for its confinement root
    # (default_confinement_root), so that site answers this cell; the chain
    # walker's own resolve has its own cell below, reached by passing the
    # confinement root in. Before Python 3.13 either raise was a RuntimeError
    # the catch-all read as a format problem.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    # The refusal may be the open's own OSError (ELOOP) or a wrapped source
    # error; either way the category mapping reads it as a path problem and
    # no RuntimeError (whose text names the path) survives anywhere.
    with pytest.raises((OSError, ASHConfigSourceError)) as refused:
        load_config_file_for_run(loop)
    category = config_load_category(refused.value).value
    assert category == "invalid_path", (category, str(refused.value))
    assert "RuntimeError" not in str(refused.value), str(refused.value)


def test_a_looped_path_reaches_the_chain_walker_when_the_root_is_given(
    tmp_path, monkeypatch
):
    """With the confinement root passed in, default_confinement_root never
    resolves the path, so the chain walker's own resolve is the site that
    answers a loop: still a path problem, with no RuntimeError anywhere."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    with pytest.raises((OSError, ASHConfigSourceError)) as refused:
        resolve_config_document(loop, confine_to=tmp_path)
    category = config_load_category(refused.value).value
    assert category == "invalid_path", (category, str(refused.value))
    if _PRE_313:
        assert "the path is a symbolic link loop" in str(refused.value), str(
            refused.value
        )
    members = _chain_members(refused.value)
    assert [m for m in members if isinstance(m, RuntimeError)] == [], [
        type(m).__name__ for m in members
    ]


def test_the_scan_load_refuses_a_looped_named_config(tmp_path, monkeypatch):
    # The scan's loader treats a path that fails exists() as missing and falls
    # back to the default config. A symbolic link loop is not a missing file:
    # defaulting would run the scan with settings the operator did not choose.
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    with pytest.raises(Exception) as refused:
        resolve_config(config_path=loop, source_dir=tmp_path)
    text = str(refused.value)
    assert "link loop" in text or "symbolic" in text, text
    assert "RuntimeError" not in text, text


def test_a_looped_top_level_config_is_named_as_a_loop(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "get", "--config", str(loop)])
    assert result.exit_code == 3, result.output
    flat = " ".join(result.output.split())
    assert "not found" not in flat, flat
    assert "link loop" in flat or "symbolic link" in flat, flat


@_NEEDS_PERMISSION_BITS
def test_a_named_config_under_an_unsearchable_directory_never_runs_the_default(
    tmp_path, monkeypatch
):
    """A named config whose directory denies the stat is not a missing file:
    running the default config instead would scan with settings the operator
    did not choose, silently. Only a missing path (ENOENT, ENOTDIR) keeps the
    documented fallback."""
    from automated_security_helper.config.resolve_config import resolve_config

    canary = "canary-default-ran-8812"
    operator = tmp_path / "operator" / "op.yaml"
    operator.parent.mkdir()
    operator.write_text(f"project_name: {canary}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    src = tmp_path / "src"
    src.mkdir()
    folder = tmp_path / "locked"
    folder.mkdir()
    path = folder / "named.yaml"
    path.write_text("project_name: locked-one\n", encoding="utf-8")
    folder.chmod(0)
    try:
        with pytest.raises(Exception) as refused:
            resolve_config(config_path=path, source_dir=src, fallback_to_default=True)
    finally:
        folder.chmod(0o755)
    assert canary not in str(refused.value), str(refused.value)


@_NEEDS_PERMISSION_BITS
def test_resolve_config_names_an_unsearchable_named_config_by_its_errno(
    tmp_path, monkeypatch
):
    """The loader's errno classification answers on every interpreter. Before
    3.14, exists() raised the stat's PermissionError itself, so the named
    refusal below never ran there and the raw error reached the caller."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    folder = tmp_path / "locked"
    folder.mkdir()
    named = folder / "named.yaml"
    named.write_text("project_name: locked-one\n", encoding="utf-8")
    folder.chmod(0)
    try:
        with pytest.raises(
            ASHConfigValidationError, match=r"cannot be read \(EACCES\)"
        ):
            resolve_config(config_path=named, source_dir=src, fallback_to_default=True)
    finally:
        folder.chmod(0o755)


def test_a_denied_stat_is_refused_even_if_a_later_stat_would_pass(
    tmp_path, monkeypatch
):
    """The classification reads the error of the one stat the presence check
    made. Stat again, and a path whose first stat was denied but whose second
    passed (a permission or mount change in between) fell through to "not
    found" and the default config: the outcome the refusal exists to rule out."""
    import os as os_module

    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    named = tmp_path / "named.yaml"
    named.write_text("project_name: operator-choice\n", encoding="utf-8")
    real_stat = os_module.stat
    denied: list = []

    def denied_once(path, *args, **kwargs):
        if os_module.fspath(path) == str(named) and not denied:
            denied.append(True)
            raise PermissionError(13, "Permission denied", str(named))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os_module, "stat", denied_once)
    with pytest.raises(ASHConfigValidationError, match=r"cannot be read \(EACCES\)"):
        resolve_config(config_path=named, source_dir=src, fallback_to_default=True)
    assert denied == [True], denied


def test_a_stat_failure_with_no_errno_is_still_a_named_refusal(tmp_path, monkeypatch):
    """An OSError whose errno is None (a filesystem or wrapper raising
    OSError(text) alone) classifies like any other unreadable path. Building
    the refusal's cause used to call os.strerror(None), a TypeError that
    reached the caller as an unexpected error instead of the path problem."""
    import os as os_module

    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    named = tmp_path / "named.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")
    real_stat = os_module.stat

    def stat_without_errno(path, *args, **kwargs):
        if os_module.fspath(path) == str(named):
            raise OSError("stat failed without an errno")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os_module, "stat", stat_without_errno)
    with pytest.raises(
        ASHConfigValidationError, match=r"cannot be read \(no error code\)"
    ):
        resolve_config(config_path=named, source_dir=src, fallback_to_default=True)


def test_the_cli_scan_names_a_looped_config_as_a_loop(tmp_path, monkeypatch):
    """The scan CLI's own pre-check refuses a named path that is not a file
    before the resolution runs, so it needs the same classification: a loop
    is named as one, never as a missing file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    src = tmp_path / "src"
    src.mkdir()
    reached = []

    def stop(self, *args, **kwargs):
        reached.append(True)
        raise SystemExit(0)

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        stop,
    )
    monkeypatch.chdir(src)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(src),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(loop),
        ],
    )
    flat = " ".join(result.output.split())
    assert result.exit_code == 3, (result.exit_code, flat[-1500:])
    assert reached == [], reached
    assert "not found" not in flat, flat[-1500:]
    assert "link loop" in flat or "symbolic link" in flat, flat[-1500:]


@_NEEDS_PERMISSION_BITS
def test_the_cli_scan_refuses_a_config_it_cannot_stat(tmp_path, monkeypatch):
    """A named config under an unsearchable directory is refused like the
    loop above: a clean named refusal, never a traceback. Before Python 3.14
    the pre-check's is_file() raised the stat's PermissionError itself, which
    reached the operator as a traceback and exit 1."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "locked"
    folder.mkdir()
    named = folder / "named.yaml"
    named.write_text("project_name: locked-one\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    reached = []

    def stop(self, *args, **kwargs):
        reached.append(True)
        raise SystemExit(0)

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        stop,
    )
    monkeypatch.chdir(src)
    folder.chmod(0)
    try:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                "local",
                "--no-progress",
                "--source-dir",
                str(src),
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(named),
            ],
        )
    finally:
        folder.chmod(0o755)
    flat = " ".join(result.output.split())
    assert result.exit_code == 3, (result.exit_code, flat[-1500:])
    assert reached == [], reached
    assert "Traceback" not in result.output, flat[-1500:]
    assert "not found" not in flat, flat[-1500:]
    assert "cannot be read (EACCES)" in flat, flat[-1500:]


def _chain_members(error):
    """Every member on the refusal's cause AND context chains: what a chain
    walker (logger.exception, a debugger, format_exception with chaining)
    can print, beyond the one rendered message."""
    from automated_security_helper.utils.error_text import _chain

    return list(_chain(error))


def test_a_direct_load_loop_keeps_no_runtime_error_in_its_chain(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    with pytest.raises((OSError, ASHConfigSourceError)) as refused:
        load_config_file_for_run(loop)
    members = _chain_members(refused.value)
    assert [m for m in members if isinstance(m, RuntimeError)] == [], [
        type(m).__name__ for m in members
    ]


def test_an_env_read_looped_base_names_no_value_on_any_chain_member(
    tmp_path, monkeypatch
):
    """Pre-3.13 the RuntimeError's text (and resolve()'s own context) names the
    looped path, whose base name here is an environment-read value; every
    member a chain walker can print has to be free of it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "cfg"
    folder.mkdir()
    name = HIDDEN_BASE + ".yaml"
    monkeypatch.setenv("ASH_LOOP_BASE_VAR", name)
    top = folder / "top.yaml"
    top.write_text("extends: ${ASH_LOOP_BASE_VAR}\nproject_name: t\n", encoding="utf-8")
    os.symlink(folder / "other.yaml", folder / name)
    os.symlink(folder / name, folder / "other.yaml")
    with pytest.raises(ASHConfigSourceError) as refused:
        load_config_file_for_run(top)
    members = _chain_members(refused.value)
    assert [m for m in members if isinstance(m, RuntimeError)] == [], [
        type(m).__name__ for m in members
    ]
    text = "\n".join(f"{member!s}\n{member!r}" for member in members)
    assert HIDDEN_BASE not in text, text[:2000]


def test_a_blind_refusal_keeps_the_original_error_off_its_chains(tmp_path, monkeypatch):
    """The environment-blind refusal replaces an error that can quote a value
    read from the environment. Raised inside the handler, that error stayed on
    __context__ even under `from None`, so a chain walker printing every
    member still reached it; it has to be on neither chain."""
    from automated_security_helper.config.config_sources import (
        ASHConfigUnsetVariableError,
        resolve_config_document,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_BLIND_READ_VAR", "blind-read-value-7731")
    monkeypatch.delenv("ASH_BLIND_UNSET_VAR", raising=False)
    config = tmp_path / "top.yaml"
    config.write_text(
        "project_name: ${ASH_BLIND_READ_VAR}\nextends: ${ASH_BLIND_UNSET_VAR}\n",
        encoding="utf-8",
    )
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(config)
    members = _chain_members(refused.value)
    assert [m for m in members if isinstance(m, ASHConfigUnsetVariableError)] == [], [
        type(m).__name__ for m in members
    ]
    text = "\n".join(f"{member!s}\n{member!r}" for member in members)
    assert "blind-read-value-7731" not in text, text[:2000]


@_NEEDS_PERMISSION_BITS
def test_a_blind_refusal_built_from_the_literal_reading_carries_one_error(
    tmp_path, monkeypatch
):
    """A literal base under an unsearchable directory, beside a value the top
    file reads from the environment. The base is checked with
    ``is_regular_file``, which answers a denied stat as "not a file" on every
    Python version, so the base is refused by its own path refusal and no blind
    refusal is built (before that check, a Python older than 3.14 raised the
    denied stat into the chain's catch-all, and the blind refusal was the literal
    resolution's own error). Either way the chain carries at most one
    document-quoting error and never the value the top file read."""
    from automated_security_helper.config import config_sources
    from automated_security_helper.config.config_sources import (
        _QUOTES_THE_DOCUMENT_MARK,
    )

    blind_calls: list = []
    real_blind = config_sources._environment_blind_error

    def counting_blind(*args, **kwargs):
        blind_calls.append(getattr(args[3], _QUOTES_THE_DOCUMENT_MARK, False))
        return real_blind(*args, **kwargs)

    monkeypatch.setattr(config_sources, "_environment_blind_error", counting_blind)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_BLIND_LITERAL_VAR", "blind-literal-value-7731")
    folder = tmp_path / "cfg"
    folder.mkdir()
    locked = folder / "locked"
    locked.mkdir()
    (locked / "base.yaml").write_text("fail_on_findings: false\n", encoding="utf-8")
    top = folder / "top.yaml"
    top.write_text(
        "project_name: ${ASH_BLIND_LITERAL_VAR}\nextends: locked/base.yaml\n",
        encoding="utf-8",
    )
    locked.chmod(0)
    try:
        with pytest.raises(Exception) as refused:
            load_config_file_for_run(top)
    finally:
        locked.chmod(0o755)
    members = _chain_members(refused.value)
    text = "\n".join(f"{member!s}\n{member!r}" for member in members)
    assert "blind-literal-value-7731" not in text, text[:2000]
    quoting = [
        m for m in members if getattr(m, _QUOTES_THE_DOCUMENT_MARK, False) is True
    ]
    assert len(quoting) <= 1, [type(m).__name__ for m in members]
    # The base is refused by its own path refusal on every Python version:
    # the denied stat never reaches the chain's catch-all, so no blind error is
    # built.
    assert blind_calls == [], blind_calls


@_NEEDS_PERMISSION_BITS
def test_an_env_named_base_under_an_unsearchable_directory_names_no_value(
    tmp_path, monkeypatch
):
    """A base named through the environment, under a directory the stat is
    denied for, with the stock reader. Before 3.14 the denied stat reaches the
    chain's catch-all, whose text quotes the OSError and so the env-chosen
    path; only the environment-blind replacement takes it out. No member of
    either chain and no printer may name it."""
    import traceback

    from automated_security_helper.utils.error_text import error_text, traceback_text

    hidden = "env-locked-base-7731"
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "cfg"
    folder.mkdir()
    locked = folder / "locked"
    locked.mkdir()
    (locked / f"{hidden}.yaml").write_text(
        "fail_on_findings: false\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_LOCKED_BASE_VAR", f"locked/{hidden}.yaml")
    top = folder / "top.yaml"
    top.write_text("extends: ${ASH_LOCKED_BASE_VAR}\n", encoding="utf-8")
    locked.chmod(0)
    try:
        with pytest.raises(ASHConfigSourceError) as refused:
            load_config_file_for_run(top)
    finally:
        locked.chmod(0o755)
    error = refused.value
    from automated_security_helper.config.config_sources import (
        _QUOTES_THE_DOCUMENT_MARK,
    )

    members = _chain_members(error)
    parts = [f"{m!s}\n{m!r}\n{getattr(m, 'args', '')!r}" for m in members]
    parts.append(error_text(error))
    parts.append(traceback_text(error))
    parts.append(
        "".join(traceback.format_exception(type(error), error, error.__traceback__))
    )
    text = "\n".join(parts)
    assert hidden not in text, text[:3000]
    # The document-quoting error the env-read resolution raised is the one
    # that quotes the env-chosen path; it is replaced, not carried: it is on
    # neither chain, whatever its text happens to hold.
    assert not any(
        getattr(m, _QUOTES_THE_DOCUMENT_MARK, False) is True for m in members
    ), [type(m).__name__ for m in members]


def test_ash_config_naming_a_loop_names_the_loop(tmp_path, monkeypatch):
    """ASH_CONFIG naming a path exists() cannot answer is not a missing file;
    the refusal names the actual reason, the way the --config path does."""
    from automated_security_helper.config.default_config import get_default_config

    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    monkeypatch.setenv("ASH_CONFIG", str(loop))
    with pytest.raises(Exception) as refused:
        get_default_config()
    message = str(refused.value)
    assert "does not exist" not in message, message
    assert "symbolic link loop" in message, message


@_NEEDS_PERMISSION_BITS
def test_ash_config_naming_an_unreadable_path_names_the_errno(tmp_path, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config

    locked = tmp_path / "locked"
    locked.mkdir()
    named = locked / "named.yaml"
    named.write_text("project_name: locked-one\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    locked.chmod(0)
    try:
        with pytest.raises(Exception) as refused:
            get_default_config()
    finally:
        locked.chmod(0o755)
    message = str(refused.value)
    assert "does not exist" not in message, message
    assert "cannot be read (EACCES)" in message, message
