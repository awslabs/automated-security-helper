# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator file in another checkout loses its grants and keeps its restrictions.

An ``ASH_CONFIG`` or ``trusted_config_path`` file that sits in a git checkout
other than the scanned one cannot grant (``sandbox_grants``), so it is not the
trusted base the scanned repository's config is held to. What it sets that can
only restrict still holds: a lowered archive extraction limit, a scanner option
that sends no usage data, a ``network_scanners`` list (which can only remove
network from a file that may not grant). ``honor_ignore_files: false`` is not
among them: it widens the scan to the files the ignore files leave out. A
file an MCP client delivered keeps nothing: its base is the defaults. A file
outside every checkout is the operator's own and is the base as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config import client_config_policy
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

#: The operator's file: a grant, a lowered limit, a restriction on usage data and
#: a network list. The grant is the one setting that must not survive.
OPERATOR = """\
project_name: operator
sandbox:
  extra_read_paths: [/data]
  network_scanners: [semgrep]
converters:
  archive:
    options:
      max_members: 10
scanners:
  semgrep:
    options:
      metrics: "off"
"""

#: A repository config between the operator's lowered limit and the default
#: (100000), so only the operator's value caps it.
REPOSITORY = """\
project_name: repository
converters:
  archive:
    options:
      max_members: 5000
"""

ROUTES = ["ASH_CONFIG", "trusted_config_path"]


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path: Path) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


def _resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
    route: str,
    operator_text: str = OPERATOR,
    repository_text: str = REPOSITORY,
    applied: Optional[List[Any]] = None,
) -> AshConfig:
    """Resolve the repository's config with the operator's file at *where*.

    *where* is ``checkout`` (a git checkout other than the scanned one),
    ``delivered`` (under the MCP workspace root) or ``outside`` (in no checkout
    and not delivered). For ``delivered`` the client-policy step is replaced by one
    that returns the config as it is, and each config it was given is appended to
    *applied*, so a caller can show the step was reached.
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    if where == "checkout":
        ops = tmp_path / "ops"
        mark_git_checkout(ops)
        path = ops / "ash.yaml"
    elif where == "delivered":
        root = tmp_path / "mcp-workspaces"
        path = root / "session-1" / "source" / "ash.yaml"
        path.parent.mkdir(parents=True)
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))

        # The client-policy step refuses some of these files before the
        # confinement runs; what is measured here is the confinement alone.
        def unchanged(config, *args, **kwargs):
            if applied is not None:
                applied.append(config)
            return config

        monkeypatch.setattr(
            client_config_policy, "apply_client_config_rules", unchanged
        )
    else:
        path = tmp_path / "operator" / "ash.yaml"
        path.parent.mkdir()
    path.write_text(operator_text, encoding="utf-8")
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    (repository / ".ash").mkdir()
    (repository / ".ash" / ".ash.yaml").write_text(repository_text, encoding="utf-8")
    if route == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(path))
        return resolve_config(source_dir=repository)
    return resolve_config(source_dir=repository, trusted_config_path=path)


def _metrics(config: AshConfig) -> Any:
    return config.get_plugin_config("scanner", "semgrep")["options"]["metrics"]


@pytest.mark.parametrize("route", ROUTES)
def test_a_lowered_limit_in_a_file_in_another_checkout_still_caps_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    config = _resolve(tmp_path, monkeypatch, "checkout", route)

    assert config.converters.archive.options.max_members == 10
    # The grant in the same file is the part that does not survive.
    assert config.sandbox.extra_read_paths == []


@pytest.mark.parametrize("route", ROUTES)
def test_a_no_usage_data_option_in_a_file_in_another_checkout_still_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    config = _resolve(tmp_path, monkeypatch, "checkout", route)

    assert _metrics(config) == "off"


@pytest.mark.parametrize("route", ROUTES)
def test_a_network_list_in_a_file_in_another_checkout_still_narrows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    config = _resolve(tmp_path, monkeypatch, "checkout", route)

    assert config.sandbox.network_limit == ["semgrep"]
    # Only the limit is kept: the list does not replace the scanners' defaults.
    assert config.sandbox.network_scanners is None


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_delivered_file_falls_to_the_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    applied: List[Any] = []

    config = _resolve(tmp_path, monkeypatch, "delivered", route, applied=applied)

    # The stub was reached, so the defaults below come from the confinement.
    assert len(applied) >= 1, applied
    assert config.converters.archive.options.max_members == 5000
    assert _metrics(config) == "auto"
    assert config.sandbox.network_limit is None
    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []


@pytest.mark.parametrize("route", ROUTES)
def test_control_the_operators_own_file_outside_every_checkout_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    config = _resolve(tmp_path, monkeypatch, "outside", route)

    assert config.converters.archive.options.max_members == 10
    assert _metrics(config) == "off"
    assert config.sandbox.extra_read_paths == ["/data"]
    assert config.sandbox.network_scanners == ["semgrep"]


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_looser_value_in_a_file_in_another_checkout_is_not_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    looser = OPERATOR.replace("max_members: 10", "max_members: 1000000").replace(
        'metrics: "off"', 'metrics: "on"'
    )
    above_the_default = REPOSITORY.replace("5000", "200000")

    config = _resolve(
        tmp_path, monkeypatch, "checkout", route, looser, above_the_default
    )

    # The default (100000) caps the repository; the operator file's higher
    # value is not the cap.
    assert config.converters.archive.options.max_members == 100_000
    assert _metrics(config) == "auto"


def _loaded(document: Dict[str, Any]) -> AshConfig:
    return AshConfig.model_validate(document)


def test_the_kept_archive_limit_is_the_lower_of_the_two() -> None:
    from automated_security_helper.config.restrictions_kept import keep_restrictions

    base = _loaded({})
    source = _loaded(
        {
            "converters": {
                "archive": {
                    "options": {
                        "max_members": 10,
                        "max_member_bytes": 10_000_000_000,
                    }
                }
            }
        }
    )

    keep_restrictions(base, source)

    options = base.converters.archive.options
    defaults = AshConfig().converters.archive.options
    assert options.max_members == 10
    # A limit above the default is not kept: the base stays at the default.
    assert options.max_member_bytes == defaults.max_member_bytes
    assert options.max_total_bytes == defaults.max_total_bytes
    assert source.converters.archive.options.max_members == 10


def test_a_tightening_scanner_value_is_kept_and_a_looser_one_is_not() -> None:
    from automated_security_helper.config.restrictions_kept import keep_restrictions

    base = _loaded({"scanners": {"trivy": {"options": {"disable_telemetry": False}}}})
    tight = _loaded(
        {
            "scanners": {
                "semgrep": {"options": {"metrics": "off"}},
                "trivy": {"options": {"disable_telemetry": True}},
            }
        }
    )

    keep_restrictions(base, tight)

    assert _metrics(base) == "off"
    trivy = base.get_plugin_config("scanner", "trivy")["options"]
    assert trivy["disable_telemetry"] is True

    loose_base = _loaded({})
    loose = _loaded({"scanners": {"semgrep": {"options": {"metrics": "on"}}}})

    keep_restrictions(loose_base, loose)

    assert _metrics(loose_base) == "auto"


def test_a_network_list_becomes_a_limit_and_never_a_list() -> None:
    from automated_security_helper.config.restrictions_kept import keep_restrictions

    base = _loaded({})
    two = _loaded({"sandbox": {"network_scanners": ["semgrep", "grype"]}})

    keep_restrictions(base, two)

    assert base.sandbox.network_limit == ["semgrep", "grype"]
    assert base.sandbox.network_scanners is None

    one = _loaded({"sandbox": {"network_scanners": ["semgrep"]}})

    keep_restrictions(base, one)

    assert base.sandbox.network_limit == ["semgrep"]

    untouched = _loaded({})

    keep_restrictions(untouched, _loaded({}))

    assert untouched.sandbox.network_limit is None


def test_nothing_else_is_carried_from_the_source() -> None:
    from automated_security_helper.config.restrictions_kept import keep_restrictions

    base = _loaded({})
    source = _loaded(
        {
            "honor_ignore_files": False,
            "content_db_staleness": "warn",
            "sandbox": {
                "extra_read_paths": ["/data"],
                "read_path_scanners": ["semgrep"],
                "env_scanners": ["semgrep"],
                "mode": "bwrap",
            },
        }
    )

    keep_restrictions(base, source)

    defaults = AshConfig()
    # A false honor_ignore_files widens the scan, so it is not kept; the tests
    # for it are in
    # test_the_other_checkout_rule_is_kept_one_way_and_worded_one_way.py.
    assert base.honor_ignore_files is True
    assert base.content_db_staleness == defaults.content_db_staleness
    assert base.sandbox.extra_read_paths == []
    assert base.sandbox.read_path_scanners == []
    assert base.sandbox.env_scanners == []
    # The mode is the floor trusted_base_config carries on its own.
    assert base.sandbox.mode == defaults.sandbox.mode
