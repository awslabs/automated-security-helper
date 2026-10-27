# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two loaders the scan reaches give a remote caller the ``!ENV`` rule.

Why this exists
---------------
``run_ash_scan._load_with_confinement`` and ``_load_for_run_with_confinement``
load a project's config file on behalf of a scan. A config file that reads a
value from the environment (an ``!ENV`` tag or a ``${VAR}`` reference) gets the
server's value. For a remote MCP client that value is the server's, and the
client reads back what ASH makes of the file, so a file the operator did not set
aside resolves none: the load raises ``ASHConfigEnvNotResolvedError``. For a
local caller, who launched the server and holds its environment, the file
resolves it. Both loaders take ``remote_client`` and choose the rule from it
(``config_sources.env_refused_for``); the run loader used to take none, so a
remote client's config the run protocol loaded resolved ``!ENV``.

The cells run each loader for a local and a remote caller. The values below are
fake markers set for the test; no cell reads a real variable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, List

import pytest

from automated_security_helper.core.exceptions import ASHConfigEnvNotResolvedError
from automated_security_helper.interactions import run_ash_scan

PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-1342"
ENV_FORMS = {
    "plain": ("ash.yaml", f"project_name: ${{{PROBE_VAR}:unset}}\n"),
    "tagged": ("ash.yaml", f"project_name: !ENV ${{{PROBE_VAR}:unset}}\n"),
    "toml": ("ash.toml", f'project_name = "${{{PROBE_VAR}:unset}}"\n'),
}
ENV_FORM = pytest.mark.parametrize("form", sorted(ENV_FORMS))


def _through_the_confined_loader(path: Path, remote_client: bool) -> Any:
    return run_ash_scan._load_with_confinement(
        str(path), path.parent, remote_client=remote_client
    )


def _through_the_run_loader(path: Path, remote_client: bool) -> Any:
    return run_ash_scan._load_for_run_with_confinement(
        str(path), path.parent, remote_client=remote_client
    )


EACH_LOADER = pytest.mark.parametrize(
    "load",
    [_through_the_confined_loader, _through_the_run_loader],
    ids=["confined_loader", "run_loader"],
)


@pytest.fixture
def an_operator_config_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The server's grants: a workspace root and one operator config root, neither
    of which holds the project below, and the probe variable in its environment."""
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    return operator


def _write(directory: Path, name: str, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def _everything_the_refusal_carries(error: BaseException) -> List[str]:
    found: List[str] = []
    seen: List[BaseException] = []
    stack: List[BaseException] = [error]
    while stack:
        current = stack.pop()
        if any(current is earlier for earlier in seen):
            continue
        seen.append(current)
        found += [str(current), repr(current.args)]
        stack += [e for e in (current.__cause__, current.__context__) if e]
    return found


@EACH_LOADER
@ENV_FORM
def test_a_remote_callers_config_that_reads_the_environment_is_refused(
    tmp_path: Path,
    an_operator_config_root: Path,
    load: Callable[[Path, bool], Any],
    form: str,
) -> None:
    name, text = ENV_FORMS[form]
    config = _write(tmp_path / "project", name, text)

    with pytest.raises(ASHConfigEnvNotResolvedError) as refused:
        load(config, True)

    for carried in _everything_the_refusal_carries(refused.value):
        assert PROBE not in carried


@EACH_LOADER
@ENV_FORM
def test_a_local_callers_config_that_reads_the_environment_resolves_it(
    tmp_path: Path,
    an_operator_config_root: Path,
    load: Callable[[Path, bool], Any],
    form: str,
) -> None:
    """The control: the caller launched the server and holds its environment."""
    name, text = ENV_FORMS[form]
    config = _write(tmp_path / "project", name, text)

    loaded = load(config, False)

    assert loaded.project_name == PROBE


@EACH_LOADER
def test_a_remote_callers_base_that_reads_the_environment_is_refused(
    tmp_path: Path,
    an_operator_config_root: Path,
    load: Callable[[Path, bool], Any],
) -> None:
    """Every file of the chain is judged, not only the one the client named."""
    project = tmp_path / "project"
    _write(project, "base.yaml", ENV_FORMS["plain"][1])
    config = _write(project, "ash.yaml", "extends: base.yaml\n")

    with pytest.raises(ASHConfigEnvNotResolvedError) as refused:
        load(config, True)

    for carried in _everything_the_refusal_carries(refused.value):
        assert PROBE not in carried


@EACH_LOADER
@ENV_FORM
def test_a_remote_callers_config_the_operator_set_aside_resolves_the_environment(
    an_operator_config_root: Path,
    load: Callable[[Path, bool], Any],
    form: str,
) -> None:
    """A directory ASH_MCP_ALLOWED_CONFIG_ROOTS names holds the operator's files."""
    name, text = ENV_FORMS[form]
    config = _write(an_operator_config_root, name, text)

    loaded = load(config, True)

    assert loaded.project_name == PROBE


@EACH_LOADER
def test_a_refused_remote_load_leaves_no_rule_behind(
    tmp_path: Path,
    an_operator_config_root: Path,
    load: Callable[[Path, bool], Any],
) -> None:
    """The rule belongs to one load: the next load, for a local caller, is not held to it."""
    name, text = ENV_FORMS["plain"]
    config = _write(tmp_path / "project", name, text)

    with pytest.raises(ASHConfigEnvNotResolvedError):
        load(config, True)

    assert load(config, False).project_name == PROBE
