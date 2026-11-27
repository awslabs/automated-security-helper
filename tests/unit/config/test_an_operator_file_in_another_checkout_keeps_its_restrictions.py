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

``keep_operator_floors``, beside ``keep_restrictions``, holds every config that is
not the operator's to the operator's floors; those tests follow the restriction
tests.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config import client_config_policy
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

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
    (repository / ".ash.yaml").write_text(repository_text, encoding="utf-8")
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


# ---------------------------------------------------------------------------
# keep_operator_floors: a config that is not the operator's may narrow the
# operator's floors, never loosen them
# ---------------------------------------------------------------------------


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records: List[logging.LogRecord]) -> List[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


def _floors(config: AshConfig, trusted: AshConfig) -> None:
    from automated_security_helper.config.restrictions_kept import keep_operator_floors

    keep_operator_floors(config, trusted, [], [Path(".ash.yaml")])


def _mcp(config: AshConfig) -> Any:
    """mcp-config's options as the scanner reads them from *config*."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner import (
        McpConfigScannerConfigOptions,
    )

    section = config.get_plugin_config("scanner", "mcp-config") or {}
    return McpConfigScannerConfigOptions.model_validate(section.get("options") or {})


def _mcp_document(options: Optional[Dict[str, Any]]) -> AshConfig:
    """A config whose mcp-config options are *options*; None names no such section.

    The section is a typed one, so a config that names none still reads as the
    scanner's defaults.
    """
    if options is None:
        return _loaded({})
    return _loaded({"scanners": {"mcp-config": {"options": options}}})


#: An https URL prefix that ends at a path boundary on one host, the same prefix
#: without its trailing slash, and an absolute command directory.
P = "https://mcp.example.test/tools/"
P_BARE = "https://mcp.example.test/tools"
R = "/opt/mcp/bin"

#: The five checks of mcp-config.
BOOLEANS = [
    "forbid_privilege_escalation",
    "forbid_unpinned_runners",
    "forbid_auto_approval",
    "flag_env_secrets",
    "require_local",
]
#: Its two prefix lists, each with a value the operator may set and an entry that
#: is not under it.
LISTS = {
    "remote_url_prefixes": ([P], "https://other.example.test/tools/v1"),
    "allowed_command_prefixes": ([R], "/usr/local/bin/server"),
}


@pytest.mark.parametrize("check", BOOLEANS)
def test_a_check_the_operator_turns_on_stays_on(check: str) -> None:
    trusted = _mcp_document({check: True})
    config = _mcp_document({check: False})

    _floors(config, trusted)

    assert getattr(_mcp(config), check) is True


def test_a_check_written_as_text_is_read_as_the_scanner_reads_it() -> None:
    trusted = _mcp_document({"forbid_auto_approval": True})
    config = _mcp_document({"forbid_auto_approval": "off"})

    _floors(config, trusted)

    assert _mcp(config).forbid_auto_approval is True


def test_a_check_the_config_leaves_out_takes_the_operator_s() -> None:
    trusted = _mcp_document({"require_local": True})
    config = _mcp_document({"forbid_auto_approval": True})

    _floors(config, trusted)

    assert _mcp(config).require_local is True


def test_an_operator_who_sets_nothing_still_has_the_default_checks() -> None:
    trusted = _mcp_document(None)
    config = _mcp_document({"forbid_auto_approval": False})

    _floors(config, trusted)

    assert _mcp(config).forbid_auto_approval is True


def test_with_no_section_the_operator_s_floors_are_written() -> None:
    trusted = _mcp_document(
        {
            "require_local": True,
            "remote_url_prefixes": [P],
            "allowed_command_prefixes": [R],
        }
    )
    config = _mcp_document(None)

    _floors(config, trusted)

    options = _mcp(config)
    assert options.require_local is True
    assert options.remote_url_prefixes == [P]
    assert options.allowed_command_prefixes == [R]


@pytest.mark.parametrize("option", LISTS)
def test_an_empty_list_keeps_the_operator_s(option: str) -> None:
    operator, _outside = LISTS[option]
    trusted = _mcp_document({option: operator})
    config = _mcp_document({option: []})

    _floors(config, trusted)

    assert getattr(_mcp(config), option) == operator


@pytest.mark.parametrize(
    "operator, entry",
    [
        pytest.param([P], P, id="the-prefix-itself"),
        pytest.param([P], P + "v1", id="one-segment-below-it"),
        pytest.param(
            [P_BARE], P_BARE + "/v1", id="no-trailing-slash-then-a-slash-and-a-segment"
        ),
        pytest.param(
            [P], "HTTPS://MCP.EXAMPLE.TEST/tools/", id="scheme-and-host-in-other-case"
        ),
    ],
)
def test_a_url_prefix_under_the_operator_s_is_kept(
    operator: List[str], entry: str
) -> None:
    trusted = _mcp_document({"remote_url_prefixes": operator})
    config = _mcp_document({"remote_url_prefixes": [entry]})

    _floors(config, trusted)

    assert _mcp(config).remote_url_prefixes == [entry]


@pytest.mark.parametrize(
    "operator, kept, entry",
    [
        pytest.param(
            [P_BARE],
            P_BARE + "/v1",
            P_BARE + "evil",
            id="its-text-continued-with-no-boundary-character",
        ),
        pytest.param(
            [P],
            P + "v1",
            "https://other.example.test/tools/v1",
            id="the-same-path-on-another-host",
        ),
        pytest.param(
            [P], P + "v1", "https://mcp.example.test/", id="a-proper-prefix-of-it"
        ),
    ],
)
def test_a_url_prefix_not_under_the_operator_s_is_dropped(
    operator: List[str], kept: str, entry: str
) -> None:
    trusted = _mcp_document({"remote_url_prefixes": operator})
    config = _mcp_document({"remote_url_prefixes": [kept, entry]})

    _floors(config, trusted)

    assert _mcp(config).remote_url_prefixes == [kept]


@pytest.mark.parametrize("option", LISTS)
def test_a_list_with_nothing_under_the_operator_s_keeps_the_operator_s(
    option: str,
) -> None:
    operator, outside = LISTS[option]
    trusted = _mcp_document({option: operator})
    config = _mcp_document({option: [outside]})

    _floors(config, trusted)

    assert getattr(_mcp(config), option) == operator


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(R, id="the-directory-itself"),
        pytest.param(R + "/server", id="one-segment-below-it"),
        pytest.param(R + "\\server", id="one-segment-below-it-with-a-backslash"),
        pytest.param(R + "/./server", id="a-dot-segment-before-the-segment"),
        pytest.param(".", id="a-dot"),
    ],
)
def test_a_command_prefix_under_the_operator_s_is_kept(entry: str) -> None:
    trusted = _mcp_document({"allowed_command_prefixes": [R]})
    config = _mcp_document({"allowed_command_prefixes": [entry]})

    _floors(config, trusted)

    assert _mcp(config).allowed_command_prefixes == [entry]


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(R + "evil", id="the-directory-with-letters-appended"),
        pytest.param(R.lstrip("/"), id="the-directory-without-its-leading-slash"),
    ],
)
def test_a_command_prefix_not_under_the_operator_s_is_dropped(entry: str) -> None:
    kept = R + "/server"
    trusted = _mcp_document({"allowed_command_prefixes": [R]})
    config = _mcp_document({"allowed_command_prefixes": [kept, entry]})

    _floors(config, trusted)

    assert _mcp(config).allowed_command_prefixes == [kept]


@pytest.mark.parametrize("check", BOOLEANS)
def test_control_a_check_the_operator_leaves_off_may_be_turned_on(check: str) -> None:
    trusted = _mcp_document({check: False})
    config = _mcp_document({check: True})

    _floors(config, trusted)

    assert getattr(_mcp(config), check) is True


@pytest.mark.parametrize("option", LISTS)
def test_control_an_operator_s_empty_list_accepts_any_list(option: str) -> None:
    _operator, outside = LISTS[option]
    trusted = _mcp_document({option: []})
    config = _mcp_document({option: [outside]})

    _floors(config, trusted)

    assert getattr(_mcp(config), option) == [outside]


def test_control_nothing_on_either_side_writes_nothing() -> None:
    trusted = _mcp_document(None)
    config = _mcp_document(None)

    _floors(config, trusted)

    assert config.scanners.mcp_config.options.model_fields_set == set()
    assert _mcp(config) == _mcp(_mcp_document(None))


@pytest.mark.parametrize("option", LISTS)
def test_control_a_value_the_scanner_would_refuse_is_left_for_it(option: str) -> None:
    operator, _outside = LISTS[option]
    trusted = _mcp_document({option: operator})
    config = _mcp_document(None)
    # An options model keeps what is assigned to it, a value its field refuses
    # included; the scanner refuses it when it is built.
    setattr(config.scanners.mcp_config.options, option, 5)

    _floors(config, trusted)

    assert getattr(config.scanners.mcp_config.options, option) == 5


#: The floors whose default is the plugin's own: (scanner, option, the module that
#: holds the options class, the class).
_MCP_CONFIG_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner"
)
FLOOR_MODELS = [
    ("mcp-config", option, _MCP_CONFIG_MODULE, "McpConfigScannerConfigOptions")
    for option in (*BOOLEANS, *LISTS)
]


@pytest.mark.parametrize("scanner, option, module, name", FLOOR_MODELS)
def test_each_floor_default_is_the_plugin_s_own(
    scanner: str, option: str, module: str, name: str
) -> None:
    import importlib

    from automated_security_helper.config import restrictions_kept

    floors = getattr(restrictions_kept, "OPERATOR_FLOORS", {})
    model = getattr(importlib.import_module(module), name)

    assert (scanner, option) in floors
    assert floors[(scanner, option)].default == model.model_fields[option].get_default()


# The operator's file sits outside every checkout and the repository's config in
# one, so the repository's config is the one held to the floors.
MCP_OPERATOR = f"""\
project_name: operator
scanners:
  mcp-config:
    options:
      forbid_auto_approval: true
      require_local: true
      remote_url_prefixes: ["{P}"]
      allowed_command_prefixes: ["{R}"]
"""

MCP_LOOSER = """\
project_name: repository
scanners:
  mcp-config:
    options:
      forbid_auto_approval: false
      require_local: false
      remote_url_prefixes: []
      allowed_command_prefixes: ["/usr/local/bin"]
"""


def test_an_in_tree_config_cannot_lower_the_operator_s_mcp_config_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log: List[logging.LogRecord]
) -> None:
    config = _resolve(
        tmp_path,
        monkeypatch,
        "outside",
        "trusted_config_path",
        operator_text=MCP_OPERATOR,
        repository_text=MCP_LOOSER,
    )

    options = _mcp(config)
    assert options.forbid_auto_approval is True
    assert options.require_local is True
    assert options.remote_url_prefixes == [P]
    assert options.allowed_command_prefixes == [R]
    named = [w for w in _warnings(ash_log) if "scanners.mcp-config.options" in w]
    assert len(named) == 1, _warnings(ash_log)
    for option in (
        "forbid_auto_approval",
        "require_local",
        "remote_url_prefixes",
        "allowed_command_prefixes",
    ):
        assert f"scanners.mcp-config.options.{option}" in named[0], named[0]


def test_an_in_tree_config_that_leaves_mcp_config_out_keeps_the_operator_s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log: List[logging.LogRecord]
) -> None:
    config = _resolve(
        tmp_path,
        monkeypatch,
        "outside",
        "trusted_config_path",
        operator_text=MCP_OPERATOR,
        repository_text="project_name: repository\n",
    )

    options = _mcp(config)
    assert options.require_local is True
    assert options.remote_url_prefixes == [P]
    assert options.allowed_command_prefixes == [R]
    # An omission is not the config's choice, so no warning names it.
    assert not [w for w in _warnings(ash_log) if "scanners.mcp-config.options" in w]
