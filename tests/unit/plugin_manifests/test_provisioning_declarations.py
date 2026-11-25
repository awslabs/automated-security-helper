# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The provisioning tables are iterated from what each plugin declares.

``TOOL_VERSIONS``, ``CONTENT_DATABASES`` and ``OFFLINE_TOOL_ENVIRONMENT`` used to be
three module-level tables the engine owned. They are now derived from the
``Provisioning`` block of each scanner's manifest (plus the one tool the engine pins
itself), so these rows hold the derivation to what the manifests say, hold the registry
to its refusals, and hold the standard-library-only property the CI and container
consumers depend on.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from automated_security_helper.base import plugin_provisioning as provisioning
from automated_security_helper.base.plugin_provisioning import (
    ENGINE_TOOL_PINS,
    PROVISIONING,
    ContentDatabase,
    OfflineEnvRow,
    Provisioning,
    ProvisioningRegistryError,
    ToolPin,
    check_registry,
)
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.utils import (
    content_databases,
    offline_tool_env,
    tool_downloads,
)
from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

_PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _manifest_blocks() -> dict[str, Provisioning]:
    return {m.name: m.provisioning for m in scanner_manifests()}


# ---------------------------------------------------------------------------
# The manifests carry the blocks, and the tables are what the blocks add up to
# ---------------------------------------------------------------------------


def test_every_declared_block_belongs_to_a_manifest() -> None:
    """A block for a scanner that has no manifest would provision for nothing."""
    names = {m.name for m in scanner_manifests()}
    assert set(PROVISIONING) <= names, sorted(set(PROVISIONING) - names)


def test_each_manifest_carries_its_declared_block() -> None:
    blocks = _manifest_blocks()
    for name, block in PROVISIONING.items():
        assert blocks[name] is block, name
    for name in set(blocks) - set(PROVISIONING):
        assert blocks[name] == provisioning.NO_PROVISIONING, name


def test_tool_versions_is_the_pins_the_manifests_and_the_engine_declare() -> None:
    declared = {pin.tool: pin.version for pin in ENGINE_TOOL_PINS}
    for block in _manifest_blocks().values():
        for pin in block.tool_pins:
            assert pin.tool not in declared, pin.tool
            declared[pin.tool] = pin.version
    assert tool_downloads.TOOL_VERSIONS == declared
    assert list(tool_downloads.TOOL_VERSIONS) == sorted(declared)


def test_content_databases_is_what_the_manifests_declare() -> None:
    declared = [
        database
        for block in _manifest_blocks().values()
        for database in block.content_databases
    ]
    assert sorted(d.name for d in content_databases.CONTENT_DATABASES) == sorted(
        d.name for d in declared
    )
    for database in content_databases.CONTENT_DATABASES:
        assert any(database is d for d in declared), database.name


def test_offline_environment_is_what_the_manifests_declare() -> None:
    declared: dict[str, str] = {}
    for block in _manifest_blocks().values():
        for row in block.offline_env:
            declared[row.variable] = row.value
    assert dict(offline_tool_env.OFFLINE_TOOL_ENVIRONMENT) == declared


def test_the_derived_tables_are_not_writable_through_the_engine_name() -> None:
    with pytest.raises(TypeError):
        offline_tool_env.OFFLINE_TOOL_ENVIRONMENT["X"] = "1"  # type: ignore[index]


def test_every_offline_row_says_why() -> None:
    for scanner, block in PROVISIONING.items():
        for row in block.offline_env:
            assert row.reason.strip(), (scanner, row.variable)


# The tables as they were when they were literals in the engine: moving them into
# manifests changes who declares each row and nothing a run does.
_OFFLINE_ROWS_BEFORE_THE_MOVE = {
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
    "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
    "npm_config_update_notifier": "false",
    "TRIVY_SKIP_VERSION_CHECK": "true",
    "TRIVY_DISABLE_TELEMETRY": "true",
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_JAVA_USE_NETWORK": "false",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE": "false",
    "SYFT_GOLANG_USE_PACKAGES_LIB": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
    "GOPROXY": "off",
    "GOTOOLCHAIN": "local",
    "GIT_ALLOW_PROTOCOL": "file",
}


def test_the_offline_environment_is_unchanged_by_the_move() -> None:
    assert dict(offline_tool_env.OFFLINE_TOOL_ENVIRONMENT) == (
        _OFFLINE_ROWS_BEFORE_THE_MOVE
    )


def test_the_content_databases_are_unchanged_by_the_move() -> None:
    rows = [
        (d.name, d.scanner, d.also_read_by, d.max_age, d.cacheable_in_ci)
        for d in content_databases.CONTENT_DATABASES
    ]
    assert rows == [
        ("grype-db", "grype", (), timedelta(hours=120), True),
        ("trivy-db", "trivy-repo", ("trivy",), timedelta(hours=24), False),
        ("semgrep-offline-rules", "semgrep", (), timedelta(days=30), False),
        ("opengrep-offline-rules", "opengrep", (), timedelta(days=30), False),
    ]


def test_the_tool_pinned_by_every_binary_runtime_is_declared() -> None:
    """A scanner whose runtime names a pinned tool must find that pin declared."""
    names = {pin.tool for pin in ENGINE_TOOL_PINS}
    for block in PROVISIONING.values():
        names.update(pin.tool for pin in block.tool_pins)
    assert {
        "actionlint",
        "betterleaks",
        "cfn-guard",
        "gitleaks",
        "grype",
        "hadolint",
        "opengrep",
        "syft",
        "trivy",
        "uv",
    } == names


# ---------------------------------------------------------------------------
# The registry refuses a contradiction
# ---------------------------------------------------------------------------


def _database(name: str = "db", scanner: str = "a") -> ContentDatabase:
    return ContentDatabase(
        name=name,
        scanner=scanner,
        cache_path="/x",
        max_age=timedelta(hours=1),
        bound_source="s",
        bound_is_tool_default=False,
        age_source="a",
        refresh="r",
    )


@pytest.mark.parametrize(
    ("blocks", "message"),
    [
        (
            {
                "a": Provisioning(tool_pins=(ToolPin("t", "1"),)),
                "b": Provisioning(tool_pins=(ToolPin("t", "1"),)),
            },
            "pinned by both",
        ),
        (
            {"a": Provisioning(tool_pins=(ToolPin("uv", "9"),))},
            "pinned by both",
        ),
        (
            {
                "a": Provisioning(content_databases=(_database("db", "a"),)),
                "b": Provisioning(content_databases=(_database("db", "b"),)),
            },
            "declared by both",
        ),
        (
            {"a": Provisioning(content_databases=(_database("db", "b"),))},
            "names 'b' as its scanner",
        ),
        (
            {
                "a": Provisioning(offline_env=(OfflineEnvRow("V", "1", "why"),)),
                "b": Provisioning(offline_env=(OfflineEnvRow("V", "2", "why"),)),
            },
            "V is '1' for 'a' and '2' for 'b'",
        ),
    ],
    ids=[
        "tool pinned by two scanners",
        "tool pinned by a scanner and the engine",
        "database declared twice",
        "database names another scanner",
        "variable with two values",
    ],
)
def test_the_registry_refuses_a_contradiction(blocks, message) -> None:
    with pytest.raises(ProvisioningRegistryError, match=message):
        check_registry(blocks)


def test_two_scanners_may_declare_one_variable_with_one_value() -> None:
    row = OfflineEnvRow("V", "1", "why")
    check_registry(
        {
            "a": Provisioning(offline_env=(row,)),
            "b": Provisioning(offline_env=(row,)),
        }
    )


def test_a_manifest_refuses_a_database_declared_for_another_scanner() -> None:
    from automated_security_helper.base.plugin_manifest import ScannerManifest

    manifest = scanner_manifests()[0]
    data = manifest.model_dump()
    data["provisioning"] = Provisioning(
        content_databases=(_database("db", "someone-else"),)
    )
    with pytest.raises(ValueError, match="names 'someone-else' as its scanner"):
        ScannerManifest.model_validate(data)


# ---------------------------------------------------------------------------
# What reads these before ASH's dependencies exist can still read them
# ---------------------------------------------------------------------------

_PROBE = """
import json, sys
{imports}
heavy = sorted(
    name for name in ("pydantic", "yaml", "toml", "tomli", "rich")
    if name in sys.modules
)
print(json.dumps({{"heavy": heavy, "tables": {tables}}}))
"""


def _fresh(imports: str, tables: str = "None") -> dict:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            importing_this_checkout(_PROBE.format(imports=imports, tables=tables)),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_the_probe_sees_a_heavy_import() -> None:
    """Planted control: importing pydantic is visible to the probe."""
    assert _fresh("import pydantic")["heavy"] == ["pydantic"]


@pytest.mark.parametrize(
    "imports",
    [
        "import automated_security_helper.base.plugin_provisioning",
        "import automated_security_helper.utils.content_databases",
    ],
)
def test_the_declarations_and_their_ci_consumer_import_only_the_standard_library(
    imports: str,
) -> None:
    """``content_databases`` runs in CI before ASH's dependencies are installed, and
    the container build loads the pins before the wheel exists."""
    assert _fresh(imports)["heavy"] == []


def test_the_staged_copy_carries_every_table_the_installer_reads() -> None:
    """``assets/install-pinned-tool.py`` loads these files by path, so the module
    the pins derive from must be one of them."""
    text = (_PACKAGE / "assets" / "install-pinned-tool.py").read_text(encoding="utf-8")
    assert '_PROVISIONING_MODULE = ("base", "plugin_provisioning.py")' in text
    assert "automated_security_helper.base.plugin_provisioning" in text
