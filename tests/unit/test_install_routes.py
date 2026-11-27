"""The install-route reader says how each scanner is installed and where each runs.

``scripts/_install_routes.py`` reads what the package already declares: the
manifests, the operational facets, the release pins, the PyPI pins and the install
commands a plugin declares. For each manifest it gives the install route, the pin
(found in a fixed order), the platforms ASH provisions a release for, and, for an
environment, which scanners that environment runs.

Every control is planted: a manifest with no route, two scanners that differ only in
whether they declare install commands, a pin table with all four sources in it, an
environment that lacks one builtin tool. A check over the real registers alone could
not tell a reader that answers from the runtime kind from one that reads what the
plugin declares, because on main the two agree.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_manifest import (
    BUNDLED_VERSION,
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    PluginTier,
    ScannerManifest,
)
from automated_security_helper.base.plugin_provisioning import (
    NO_PROVISIONING,
    Provisioning,
    PypiPin,
)
from automated_security_helper.core import constants
from automated_security_helper.core.enums import RunMode
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.utils import tool_downloads

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "_install_routes.py"
DOCS_CHECKS = REPO_ROOT / "scripts" / "docs_checks.py"

BUILTIN = (
    "actionlint",
    "bandit",
    "cdk-nag",
    "cfn-guard",
    "cfn-lint",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "gitleaks",
    "grype",
    "mcp-config",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
    "trivy",
    "zizmor",
)
ALPHA = (
    "betterleaks",
    "ferret-scan",
    "guarddog",
    "hadolint",
    "snyk-code",
    "trivy-repo",
)


@pytest.fixture(scope="module")
def ir():
    """scripts/_install_routes.py, loaded by path and registered first."""
    name = "_ash_install_routes_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    yield module
    sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def regs(ir):
    """The registers as the package declares them."""
    return ir.Registers.read()


# ---------------------------------------------------------------------------
# Planted scanners
# ---------------------------------------------------------------------------


def _manifest(
    name: str,
    *,
    tier: PluginTier = PluginTier.ALPHA,
    default_enabled: bool = False,
    provisioning: Provisioning = NO_PROVISIONING,
) -> ScannerManifest:
    module = f"planted_plugins.{name.replace('-', '_')}"
    return ScannerManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        name=name,
        version=BUNDLED_VERSION,
        aliases=(),
        tier=tier,
        default_enabled=default_enabled,
        plugin_module=module,
        entry_points=EntryPoints(scanner=f"{module}.scanner:PlantedScanner"),
        options_model=f"{module}.scanner:PlantedOptions",
        file_ownership=(f"planted_plugins/{name}",),
        provisioning=provisioning,
    )


def _facets(
    name: str,
    kind: opsf.RuntimeKind,
    *,
    key: str | None = None,
    programs: tuple[str, ...] = (),
    image: opsf.ImageFacet | None = None,
    provisionable: tuple[str, ...] = (),
) -> opsf.ScannerOperationalFacets:
    """A register row for a planted scanner: a real row with a new runtime."""
    from automated_security_helper.plugin_modules.ash_hadolint_plugins.hadolint_scanner import (
        HadolintScanner,
    )

    runtime = opsf.RuntimeFacet(
        kind=kind,
        external_programs=programs,
        invocations=opsf.Invocations.ONE,
        tool_versions_key=key,
        python_only=False,
        use_uv_tool=kind is opsf.RuntimeKind.UV_PYTHON,
    )
    left_out = opsf.ImageFacet(route=opsf.ImageRoute.NOT_IN_IMAGE, reason="planted")
    return HadolintScanner.operational_facets.model_copy(
        update={
            "scanner_name": name,
            "runtime": runtime,
            "platforms": opsf.PlatformsFacet(
                provisionable=provisionable, note="a planted row"
            ),
            "image": image if image is not None else left_out,
        }
    )


def _plant(regs, manifest, facets, declared=(), **replace):
    """*regs* with one more scanner; *declared* are the pairs it declares installs for."""
    old = regs.declared_on

    def declared_on(candidate):
        return tuple(declared) if candidate.name == manifest.name else old(candidate)

    return dataclasses.replace(
        regs,
        manifests=tuple(sorted((*regs.manifests, manifest), key=lambda m: m.name)),
        facets={**regs.facets, manifest.name: facets},
        declared_on=declared_on,
        **replace,
    )


def _module(monkeypatch, name: str, **values) -> None:
    """A planted module holding constants, importable for the test."""
    planted = types.ModuleType(name)
    for key, value in values.items():
        setattr(planted, key, value)
    monkeypatch.setitem(sys.modules, name, planted)


# ---------------------------------------------------------------------------
# Totality over the real registers
# ---------------------------------------------------------------------------


def test_every_manifest_has_one_route_row_sorted_by_name(ir, regs):
    rows = ir.routes(regs)

    names = [row.scanner for row in rows]
    assert names == sorted(names)
    assert names == [m.name for m in scanner_manifests()]
    assert sorted(names) == sorted(BUILTIN + ALPHA)
    assert len(rows) == 23


def test_the_routes_are_the_ones_the_register_and_the_declarations_give(ir, regs):
    got = {row.scanner: row.route.value for row in ir.routes(regs)}

    assert got == {
        "actionlint": "release_asset",
        "bandit": "uv_tool",
        "betterleaks": "release_asset",
        "cdk-nag": "in_process",
        "cfn-guard": "release_asset",
        "cfn-lint": "uv_tool",
        "cfn-nag": "declared_commands",
        "checkov": "uv_tool",
        "detect-secrets": "in_process",
        "ferret-scan": "ash_environment",
        "gitleaks": "release_asset",
        "grype": "release_asset",
        "guarddog": "uv_tool",
        "hadolint": "release_asset",
        "mcp-config": "in_process",
        "npm-audit": "none",
        "opengrep": "release_asset",
        "semgrep": "uv_tool",
        "snyk-code": "none",
        "syft": "release_asset",
        "trivy": "release_asset",
        "trivy-repo": "release_asset",
        "zizmor": "uv_tool",
    }


def test_a_row_carries_the_manifest_and_the_runtime_it_was_read_from(ir, regs):
    row = ir.route_for("guarddog", regs)

    assert row.module == "automated_security_helper.plugin_modules.ash_guarddog_plugins"
    assert row.tier is PluginTier.ALPHA
    assert row.builtin is False
    assert row.runtime_kind is opsf.RuntimeKind.UV_PYTHON
    assert ir.route_for("trivy", regs).builtin is True
    assert ir.route_for("semgrep", regs).tier is PluginTier.DEPRECATED


def test_asking_for_a_scanner_that_has_no_manifest_names_it(ir, regs):
    with pytest.raises(ir.RouteError, match="no-such-scanner"):
        ir.route_for("no-such-scanner", regs)


# ---------------------------------------------------------------------------
# The release pin of a downloaded binary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,key",
    [
        ("betterleaks", "betterleaks"),
        ("hadolint", "hadolint"),
        ("trivy-repo", "trivy"),
        ("trivy", "trivy"),
        ("opengrep", "opengrep"),
    ],
)
def test_a_pinned_binary_reads_the_release_pin_of_its_tool(ir, regs, name, key):
    row = ir.route_for(name, regs)

    assert row.route is ir.Route.RELEASE_ASSET
    assert row.programs == (key,)
    assert [(p.version, p.source) for p in row.pins] == [
        (regs.release_pins[key], ir.PinSource.RELEASE_PIN)
    ]
    assert row.installable is True


def test_trivy_repo_resolves_to_the_pin_of_the_trivy_it_runs(ir, regs):
    assert ir.route_for("trivy-repo", regs).pin == ir.route_for("trivy", regs).pin


def test_a_pinned_binary_no_register_pins_has_no_pin_and_is_not_installable(ir, regs):
    planted = _plant(
        regs,
        _manifest("planted-binary"),
        _facets(
            "planted-binary",
            opsf.RuntimeKind.PINNED_BINARY,
            key="planted-binary",
            provisionable=opsf.PLATFORMS_ALL,
        ),
    )

    row = ir.route_for("planted-binary", planted)

    assert row.route is ir.Route.RELEASE_ASSET
    assert row.pins == ()
    assert row.pin is None
    assert row.installable is False


def test_the_platforms_are_the_pairs_the_register_says_ash_provisions(ir, regs):
    assert ir.route_for("betterleaks", regs).platforms == opsf.PLATFORMS_ALL
    assert ir.route_for("hadolint", regs).platforms == opsf.PLATFORMS_NO_WINDOWS_ARM64
    assert "windows/arm64" not in ir.route_for("trivy-repo", regs).platforms
    guarddog = ir.route_for("guarddog", regs)
    assert guarddog.platforms == ()
    assert guarddog.platforms_note == regs.facets["guarddog"].platforms.note


# ---------------------------------------------------------------------------
# The pin of a Python tool: four sources in a fixed order
# ---------------------------------------------------------------------------


def _uv_scanner(regs, name="planted-uv", specifier="==1.0.0", **replace):
    pin = PypiPin(distribution=name, specifier=specifier, runtime="uv-tool")
    return _plant(
        regs,
        _manifest(name, provisioning=Provisioning(pypi_pins=(pin,))),
        _facets(name, opsf.RuntimeKind.UV_PYTHON),
        **replace,
    )


def test_the_pin_comes_from_the_four_sources_in_their_fixed_order(
    ir, regs, monkeypatch
):
    _module(monkeypatch, "planted_pins", INTERIM="1.0.2", LOCAL="v1.0.3")
    planted = _uv_scanner(
        regs,
        distribution_pins={"planted-uv": "v1.0.1"},
        module_pins={"planted-uv": "planted_pins:LOCAL"},
    )

    row = ir.route_for(
        "planted-uv", planted, interim={"planted-uv": "planted_pins:INTERIM"}
    )

    assert [(p.version, p.source.value) for p in row.pins] == [
        ("1.0.0", "pypi_pin"),
        ("1.0.1", "distribution_entry"),
        ("1.0.2", "interim"),
        ("1.0.3", "module_constant"),
    ]
    assert row.pin.version == "1.0.0"
    assert row.route is ir.Route.UV_TOOL


@pytest.mark.parametrize(
    "present,first",
    [
        (("distribution_entry", "interim", "module_constant"), "1.0.1"),
        (("interim", "module_constant"), "1.0.2"),
        (("module_constant",), "1.0.3"),
    ],
)
def test_the_next_source_answers_when_every_higher_one_is_missing(
    ir, regs, monkeypatch, present, first
):
    _module(monkeypatch, "planted_pins", INTERIM="1.0.2", LOCAL="1.0.3")
    planted = _uv_scanner(
        regs,
        specifier=">=1.0",
        distribution_pins=(
            {"planted-uv": "1.0.1"} if "distribution_entry" in present else {}
        ),
        module_pins={"planted-uv": "planted_pins:LOCAL"},
    )
    interim = {"planted-uv": "planted_pins:INTERIM"} if "interim" in present else {}

    row = ir.route_for("planted-uv", planted, interim=interim)

    assert row.pin.version == first


@pytest.mark.parametrize(
    "specifier",
    [
        ">=1.0.0,<2.0",
        ">=1.0.0",
        "~=1.0",
        "==1.*",
        "!=1.0.0",
        "==1.0.0,<2",
        "===1.0.0",
        "<=1.0.0",
        "",
    ],
)
def test_a_specifier_that_is_not_one_exact_version_is_no_pin(ir, regs, specifier):
    planted = _uv_scanner(regs, specifier=specifier)

    row = ir.route_for("planted-uv", planted)

    assert row.pins == ()
    assert row.installable is False


def test_ferret_scan_has_no_pin_until_something_gives_it_one(ir, regs):
    ferret = ir.route_for("ferret-scan", regs)
    manifest = next(m for m in regs.manifests if m.name == "ferret-scan")

    assert ferret.route is ir.Route.ASH_ENVIRONMENT
    assert manifest.provisioning.pypi_pins[0].specifier.startswith(">=")
    assert ferret.pins == ()
    assert ferret.installable is False


def test_guarddog_is_pinned_by_its_pypi_pin_and_its_distribution_entry_agrees(ir, regs):
    row = ir.route_for("guarddog", regs)

    assert [(p.version, p.source.value) for p in row.pins] == [
        ("3.2.0", "pypi_pin"),
        ("3.2.0", "distribution_entry"),
    ]


@pytest.mark.parametrize("name", ["bandit", "cfn-lint", "checkov", "semgrep", "zizmor"])
def test_a_builtin_python_tool_is_pinned_by_its_distribution_entry(ir, regs, name):
    entry = tool_downloads.THIRD_PARTY_LICENSES[name]

    row = ir.route_for(name, regs)

    assert entry.distribution
    assert [(p.version, p.source.value) for p in row.pins] == [
        (entry.version.lstrip("v"), "distribution_entry")
    ]
    assert row.route is ir.Route.UV_TOOL


def test_an_entry_that_names_no_distribution_is_no_pin(ir, regs):
    assert tool_downloads.THIRD_PARTY_LICENSES["hadolint"].distribution is None
    assert "hadolint" not in regs.distribution_pins
    assert set(regs.distribution_pins) == {
        "bandit",
        "cfn-lint",
        "checkov",
        "guarddog",
        "semgrep",
        "zizmor",
    }


def test_the_license_table_is_read_and_never_written(ir):
    before = dict(tool_downloads.THIRD_PARTY_LICENSES)
    pins_before = dict(tool_downloads.TOOL_VERSIONS)

    fresh = ir.Registers.read()
    ir.routes(fresh)
    ir.scanners_for(
        ir.Env(
            "linux",
            "amd64",
            RunMode.container,
            ir.Provision("image", image_stage="ci", tools=ir.ALL_TOOLS),
        ),
        fresh,
    )

    assert dict(tool_downloads.THIRD_PARTY_LICENSES) == before
    assert all(
        tool_downloads.THIRD_PARTY_LICENSES[key] is entry
        for key, entry in before.items()
    )
    assert dict(tool_downloads.TOOL_VERSIONS) == pins_before


_TABLES = {
    "THIRD_PARTY_LICENSES",
    "TOOL_VERSIONS",
    "PROVISIONING",
    "INSTALL_PACKAGE_FACETS",
}
_WRITERS = {"update", "pop", "popitem", "clear", "setdefault"}


def _table_writes(source: str) -> list[int]:
    """Line numbers where *source* stores into, deletes from or mutates a table."""

    def leaf(node):
        return node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)

    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and leaf(node.value) in _TABLES
        ):
            found.append(node.lineno)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _WRITERS
            and leaf(node.func.value) in _TABLES
        ):
            found.append(node.lineno)
    return found


def test_the_reader_never_writes_into_a_table_it_reads():
    assert _table_writes(SCRIPT.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "line",
    [
        "tool_downloads.THIRD_PARTY_LICENSES['x'] = 1",
        "THIRD_PARTY_LICENSES['x'] += 1",
        "del tool_downloads.TOOL_VERSIONS['x']",
        "tool_downloads.THIRD_PARTY_LICENSES.update({})",
        "PROVISIONING.pop('x')",
    ],
)
def test_the_write_scan_flags_a_write_to_each_table_shape(line):
    assert _table_writes(line + "\n") == [1]


def test_a_module_constant_and_an_interim_reference_are_read_when_they_are_asked(
    ir, regs, monkeypatch
):
    _module(monkeypatch, "planted_pins", INTERIM="2.0.0")
    planted = _uv_scanner(regs, specifier=">=1")
    refs = {"planted-uv": "planted_pins:INTERIM"}

    assert ir.route_for("planted-uv", planted, interim=refs).pin.version == "2.0.0"

    sys.modules["planted_pins"].INTERIM = "2.0.1"
    assert ir.route_for("planted-uv", planted, interim=refs).pin.version == "2.0.1"


@pytest.mark.parametrize(
    "ref,values",
    [
        ("planted_pins:MISSING", {"INTERIM": "1.0.0"}),
        ("not_a_module_anywhere:INTERIM", {}),
        ("planted_pins:INTERIM", {"INTERIM": 100}),
        ("planted_pins:INTERIM", {"INTERIM": ">=1.0"}),
        ("planted_pins:INTERIM", {"INTERIM": ""}),
        ("planted_pins", {"INTERIM": "1.0.0"}),
    ],
)
def test_a_reference_that_cannot_be_read_as_one_version_is_an_error(
    ir, regs, monkeypatch, ref, values
):
    _module(monkeypatch, "planted_pins", **values)
    planted = _uv_scanner(regs, specifier=">=1")

    with pytest.raises(ir.RouteError, match="planted-uv"):
        ir.route_for("planted-uv", planted, interim={"planted-uv": ref})


def test_cfn_nag_is_pinned_by_the_constant_its_installer_uses(ir, regs):
    row = ir.route_for("cfn-nag", regs)

    assert row.route is ir.Route.DECLARED_COMMANDS
    assert [(p.version, p.source.value) for p in row.pins] == [
        (tool_downloads.CFN_NAG_GEM_VERSION, "module_constant")
    ]
    assert row.installable is True
    assert "linux/amd64" in row.declared_on


def test_every_module_constant_the_reader_names_is_a_scanner_it_reads_and_resolves(
    ir, regs
):
    names = {m.name for m in regs.manifests}

    assert set(ir.MODULE_LOCAL_PINS) <= names
    for name in ir.MODULE_LOCAL_PINS:
        assert ir.route_for(name, regs).pins, name


def test_a_python_runtime_that_disagrees_with_its_pin_is_refused(ir, regs):
    pin = PypiPin(
        distribution="planted-uv", specifier="==1.0.0", runtime="ash-environment"
    )
    planted = _plant(
        regs,
        _manifest("planted-uv", provisioning=Provisioning(pypi_pins=(pin,))),
        _facets("planted-uv", opsf.RuntimeKind.UV_PYTHON),
    )

    with pytest.raises(ir.RouteError, match="planted-uv"):
        ir.route_for("planted-uv", planted)


# ---------------------------------------------------------------------------
# A route is what the plugin declares, not what its runtime kind suggests
# ---------------------------------------------------------------------------


def _cli_scanner(regs, name, declared):
    return _plant(
        regs,
        _manifest(name),
        _facets(name, opsf.RuntimeKind.USER_INSTALLED_CLI, programs=(name,)),
        declared=declared,
    )


def test_a_user_installed_cli_that_declares_install_commands_has_a_route(ir, regs):
    planted = _cli_scanner(regs, "planted-cli", ("linux/amd64", "linux/arm64"))

    row = ir.route_for("planted-cli", planted)

    assert row.runtime_kind is opsf.RuntimeKind.USER_INSTALLED_CLI
    assert row.route is ir.Route.DECLARED_COMMANDS
    assert row.declared_on == ("linux/amd64", "linux/arm64")
    assert row.pins == ()
    assert row.installable is False


def test_a_user_installed_cli_that_declares_none_has_no_route(ir, regs):
    planted = _cli_scanner(regs, "planted-cli", ())

    row = ir.route_for("planted-cli", planted)

    assert row.route is ir.Route.NONE
    assert row.declared_on == ()
    assert "planted-cli" in row.reason
    assert row.installable is False


def test_two_scanners_that_differ_only_in_their_declaration_route_differently(
    ir, regs
):
    declaring = _cli_scanner(regs, "planted-cli", ("linux/amd64",))
    silent = _cli_scanner(regs, "planted-cli", ())
    kind = opsf.RuntimeKind.USER_INSTALLED_CLI

    for planted in (declaring, silent):
        assert planted.facets["planted-cli"].runtime.kind is kind
    assert ir.route_for("planted-cli", declaring).route is not (
        ir.route_for("planted-cli", silent).route
    )


def test_a_module_local_installer_with_its_own_pin_constant_is_a_pin_source(
    ir, regs, monkeypatch
):
    _module(monkeypatch, "planted_installer", VERSION="v0.23.0")
    planted = dataclasses.replace(
        _cli_scanner(regs, "planted-cli", ("linux/amd64",)),
        module_pins={"planted-cli": "planted_installer:VERSION"},
    )

    row = ir.route_for("planted-cli", planted)

    assert row.route is ir.Route.DECLARED_COMMANDS
    assert [(p.version, p.source.value) for p in row.pins] == [
        ("0.23.0", "module_constant")
    ]
    assert row.installable is True


def test_a_ruby_gem_and_a_node_subcommand_follow_the_same_rule(ir, regs):
    assert ir.route_for("cfn-nag", regs).runtime_kind is opsf.RuntimeKind.RUBY_GEM
    assert ir.route_for("cfn-nag", regs).route is ir.Route.DECLARED_COMMANDS
    npm = ir.route_for("npm-audit", regs)
    assert npm.runtime_kind is opsf.RuntimeKind.NODE_SUBCOMMAND
    assert npm.route is ir.Route.NONE
    assert npm.declared_on == ()


def test_snyk_code_declares_nothing_and_has_no_route(ir, regs):
    row = ir.route_for("snyk-code", regs)

    assert row.runtime_kind is opsf.RuntimeKind.USER_INSTALLED_CLI
    assert row.route is ir.Route.NONE
    assert row.declared_on == ()


def test_an_in_process_scanner_has_nothing_to_install(ir, regs):
    for name in ("detect-secrets", "mcp-config", "cdk-nag"):
        row = ir.route_for(name, regs)
        assert row.route is ir.Route.IN_PROCESS, name
        assert row.pins == ()
        assert row.installable is False


def test_a_scanner_with_no_operational_facets_is_refused_by_name(ir, regs):
    planted = dataclasses.replace(
        regs, manifests=(*regs.manifests, _manifest("planted-bare"))
    )

    with pytest.raises(ir.RouteError, match="planted-bare"):
        ir.route_for("planted-bare", planted)


def test_an_install_declaration_that_raises_is_an_error_naming_the_scanner(ir, regs):
    def raising(_candidate):
        raise RuntimeError("could not be built")

    planted = dataclasses.replace(
        _cli_scanner(regs, "planted-cli", ()), declared_on=raising
    )

    with pytest.raises(ir.RouteError, match="planted-cli"):
        ir.route_for("planted-cli", planted)


def test_the_declaration_reader_asks_each_platform_the_register_names(ir):
    asked = []

    class Plugin:
        def get_installation_commands(self, target_platform, arch):
            asked.append(f"{target_platform}/{arch}")
            return [["echo"]] if arch == "arm64" else []

    pairs = ir.declared_pairs(Plugin())

    assert asked == list(opsf.PLATFORMS_ALL)
    assert pairs == ("darwin/arm64", "linux/arm64", "windows/arm64")


def test_a_declaration_of_empty_lists_declares_nothing(ir):
    class Silent:
        def get_installation_commands(self, target_platform, arch):
            return []

    assert ir.declared_pairs(Silent()) == ()


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------


def _modules(regs):
    return {m.name: m.plugin_module for m in regs.manifests}


def _statuses(availability):
    return {row.scanner: row.status.value for row in availability.rows}


def _reasons(availability):
    return {row.scanner: row.reason for row in availability.rows if row.reason}


def _image(ir, **replace):
    provision = ir.Provision("image", image_stage="ci", tools=ir.ALL_TOOLS)
    return ir.Env(
        "linux", "amd64", RunMode.container, dataclasses.replace(provision, **replace)
    )


def test_a_provision_and_an_environment_refuse_a_malformed_value(ir):
    with pytest.raises(ValueError):
        ir.Provision("cloud")
    with pytest.raises(ValueError):
        ir.Provision("image")
    with pytest.raises(ValueError):
        ir.Provision("image", image_stage="core")
    with pytest.raises(ValueError):
        ir.Provision("host", image_stage="ci")
    with pytest.raises(ValueError):
        ir.Env("linux", "x86_64", RunMode.local, ir.Provision("host"))
    with pytest.raises(ValueError):
        ir.Env("linux", "amd64", "local", ir.Provision("host"))
    for stage in ("ci", "non-root"):
        assert ir.Provision("image", image_stage=stage).image_stage == stage


def test_all_tools_is_one_value_and_not_a_set(ir):
    assert ir.AllTools() == ir.ALL_TOOLS
    assert not isinstance(ir.ALL_TOOLS, frozenset)


def test_the_image_runs_every_builtin_and_every_alpha_scanner_it_installs(ir, regs):
    got = ir.scanners_for(_image(ir), regs)

    assert _statuses(got) == {
        **{name: "available" for name in BUILTIN},
        "betterleaks": "opt_in",
        "guarddog": "opt_in",
        "hadolint": "opt_in",
        "trivy-repo": "opt_in",
        "ferret-scan": "missing",
        "snyk-code": "missing",
    }
    assert _reasons(got) == {
        "ferret-scan": f"not in image: {regs.facets['ferret-scan'].image.reason}",
        "snyk-code": f"not in image: {regs.facets['snyk-code'].image.reason}",
    }
    assert got.env.provision.kind == "image"


def test_a_builtin_the_image_leaves_out_is_missing_with_its_reason(ir, regs):
    left_out = opsf.ImageFacet(
        route=opsf.ImageRoute.NOT_IN_IMAGE, reason="it is kept out on purpose"
    )
    planted = dataclasses.replace(
        regs,
        facets={
            **regs.facets,
            "grype": regs.facets["grype"].model_copy(update={"image": left_out}),
        },
    )

    got = ir.scanners_for(_image(ir), planted)

    assert _statuses(got)["grype"] == "missing"
    assert _reasons(got)["grype"] == "not in image: it is kept out on purpose"
    assert sum(r.status is ir.Status.AVAILABLE for r in got.rows) == 16


def test_an_image_with_a_short_tool_list_misses_what_the_list_lacks(ir, regs):
    env = _image(ir, tools=frozenset({"bandit", "trivy"}))

    got = ir.scanners_for(env, regs)

    assert _statuses(got)["bandit"] == "available"
    assert _statuses(got)["trivy"] == "available"
    assert _statuses(got)["trivy-repo"] == "opt_in"
    assert _reasons(got)["gitleaks"] == "needs gitleaks"
    assert _reasons(got)["betterleaks"] == "needs betterleaks"


def _precommit(ir):
    return ir.Env("linux", "amd64", RunMode.precommit, ir.Provision("precommit"))


def test_precommit_runs_exactly_the_precommit_set(ir, regs):
    got = ir.scanners_for(_precommit(ir), regs)

    available = {n for n, s in _statuses(got).items() if s == "available"}
    assert available == set(constants.PRECOMMIT_MODE_SCANNERS)
    assert available == {"bandit", "cdk-nag", "checkov", "detect-secrets", "npm-audit"}
    assert _reasons(got)["gitleaks"] == "outside the precommit set"
    assert _statuses(got)["hadolint"] == "missing"


def test_the_precommit_set_is_read_when_the_question_is_asked(ir, regs, monkeypatch):
    monkeypatch.setattr(constants, "PRECOMMIT_MODE_SCANNERS", ("gitleaks", "syft"))

    got = ir.scanners_for(_precommit(ir), regs)

    assert {n for n, s in _statuses(got).items() if s == "available"} == {
        "gitleaks",
        "syft",
    }


def test_precommit_mode_limits_any_environment_to_the_precommit_set(ir, regs):
    env = ir.Env(
        "linux",
        "amd64",
        RunMode.precommit,
        ir.Provision("host", tools=ir.ALL_TOOLS, extras=frozenset({"cdk"})),
    )

    got = ir.scanners_for(env, regs)

    assert _reasons(got)["gitleaks"] == "outside the precommit set"
    assert _statuses(got)["bandit"] == "available"


def _nix(ir, **replace):
    provision = ir.Provision("nix", runtimes=frozenset({"node", "npm"}))
    return ir.Env(
        "linux", "amd64", RunMode.nix, dataclasses.replace(provision, **replace)
    )


def test_nix_runs_what_the_flake_carries_and_cdk_nag_needs_the_host_extra(ir, regs):
    got = ir.scanners_for(_nix(ir), regs)

    assert _statuses(got) == {
        **{name: "available" for name in BUILTIN},
        "cdk-nag": "missing",
        "betterleaks": "opt_in",
        "hadolint": "opt_in",
        "trivy-repo": "opt_in",
        "ferret-scan": "missing",
        "guarddog": "missing",
        "snyk-code": "missing",
    }
    assert _reasons(got) == {
        "cdk-nag": "needs the cdk extra",
        "ferret-scan": "needs ferret-scan",
        "guarddog": "needs guarddog",
        "snyk-code": "needs snyk-code",
    }


def test_nix_with_the_extra_runs_cdk_nag(ir, regs):
    got = ir.scanners_for(_nix(ir, extras=frozenset({"cdk"})), regs)

    assert _statuses(got)["cdk-nag"] == "available"


def test_a_nix_environment_without_node_misses_npm_audit_and_not_the_nix_tools(ir, regs):
    got = ir.scanners_for(_nix(ir, runtimes=frozenset()), regs)

    assert _reasons(got)["npm-audit"] == "needs node, npm"
    assert _statuses(got)["cfn-nag"] == "available"
    assert _statuses(got)["bandit"] == "available"


def test_a_tool_with_a_nix_row_the_flake_does_not_list_is_found_by_the_cross_check(ir):
    flake = (REPO_ROOT / "flake.nix").read_text(encoding="utf-8")

    assert ir.nix_rows_missing_from_flake(flake) == []
    stripped = flake.replace("pkgs.gitleaks", "pkgs.not-gitleaks")
    assert ir.nix_rows_missing_from_flake(stripped) == ["gitleaks"]


_HOST_TOOLS = frozenset(
    {
        "bandit",
        "actionlint",
        "cfn-lint",
        "cfn-guard",
        "gitleaks",
        "checkov",
        "semgrep",
        "zizmor",
    }
)


def _host(ir, *, os_="linux", arch="amd64", **replace):
    provision = ir.Provision(
        "host",
        tools=_HOST_TOOLS,
        extras=frozenset({"cdk"}),
        runtimes=frozenset({"node", "npm"}),
    )
    return ir.Env(
        os_, arch, RunMode.local, dataclasses.replace(provision, **replace)
    )


def test_a_host_runs_the_tools_its_recipe_installs(ir, regs):
    modules = _modules(regs)
    env = _host(ir, alpha_with_tools=frozenset({modules["betterleaks"]}))

    got = ir.scanners_for(env, regs)

    assert {n for n, s in _statuses(got).items() if s == "available"} == {
        "actionlint",
        "bandit",
        "cdk-nag",
        "cfn-guard",
        "cfn-lint",
        "checkov",
        "detect-secrets",
        "gitleaks",
        "mcp-config",
        "npm-audit",
        "semgrep",
        "zizmor",
    }
    assert _reasons(got) == {
        "cfn-nag": "needs cfn-nag, ruby",
        "grype": "needs grype",
        "opengrep": "needs opengrep",
        "syft": "needs syft",
        "trivy": "needs trivy",
        "hadolint": "needs hadolint",
        "trivy-repo": "needs trivy",
        "ferret-scan": "needs ferret-scan",
        "guarddog": "needs guarddog",
        "snyk-code": "needs snyk-code",
    }
    assert _statuses(got)["betterleaks"] == "opt_in"


def test_removing_a_tool_from_a_recipe_removes_that_scanner_and_no_other(ir, regs):
    full = ir.scanners_for(_host(ir), regs)
    short = ir.scanners_for(_host(ir, tools=_HOST_TOOLS - {"gitleaks"}), regs)

    changed = {n for n in _statuses(full) if _statuses(full)[n] != _statuses(short)[n]}
    assert changed == {"gitleaks"}
    assert _reasons(short)["gitleaks"] == "needs gitleaks"


def test_a_host_without_the_extra_or_node_misses_the_scanners_that_need_them(ir, regs):
    got = ir.scanners_for(_host(ir, extras=frozenset(), runtimes=frozenset()), regs)

    assert _reasons(got)["cdk-nag"] == "needs the cdk extra, node"
    assert _reasons(got)["npm-audit"] == "needs node, npm"


def test_a_host_with_every_tool_and_every_runtime_misses_nothing_builtin(ir, regs):
    got = ir.scanners_for(
        _host(ir, tools=ir.ALL_TOOLS, runtimes=frozenset({"node", "npm", "ruby"})),
        regs,
    )

    assert all(r.status is ir.Status.AVAILABLE for r in got.rows if r.builtin)


def test_an_architecture_the_release_table_lacks_misses_that_tool(ir, regs):
    modules = _modules(regs)
    env = _host(
        ir,
        os_="windows",
        arch="arm64",
        tools=ir.ALL_TOOLS,
        runtimes=frozenset({"node", "npm", "ruby"}),
        alpha_with_tools=frozenset({modules["hadolint"], modules["betterleaks"]}),
    )

    got = ir.scanners_for(env, regs)

    gaps = {n for n, r in _reasons(got).items() if r.startswith("no windows/arm64")}
    assert gaps == {"grype", "opengrep", "trivy", "hadolint", "trivy-repo"}
    assert _reasons(got)["grype"] == "no windows/arm64 release asset"
    assert _statuses(got)["gitleaks"] == "available"
    assert _statuses(got)["betterleaks"] == "opt_in"


def test_an_alpha_scanner_never_changes_a_count_cell(ir, regs):
    planted_manifest = _manifest("planted-alpha")
    planted = _plant(
        regs,
        planted_manifest,
        _facets(
            "planted-alpha",
            opsf.RuntimeKind.PINNED_BINARY,
            key="planted-alpha",
            image=opsf.ImageFacet(
                route=opsf.ImageRoute.RELEASE_ASSET,
                tool="planted-alpha",
                version_check=("planted-alpha", "--version"),
            ),
        ),
    )
    modules = _modules(regs)
    listed = frozenset({modules["betterleaks"], planted_manifest.plugin_module})
    for env in (_image(ir), _host(ir, tools=ir.ALL_TOOLS, alpha_with_tools=listed)):
        before = ir.scanners_for(env, regs)
        after = ir.scanners_for(env, planted)

        assert _statuses(after)["planted-alpha"] == "opt_in"
        assert ir.builtin_count(after) == ir.builtin_count(before)
        assert ir.scanner_set_cell(after) == ir.scanner_set_cell(before)


# ---------------------------------------------------------------------------
# The scanner-set cell, on planted availabilities
# ---------------------------------------------------------------------------


def _row(ir, name, status, *, builtin=True, reason="", tier=PluginTier.SUPPORTED):
    return ir.ScannerAvailability(
        scanner=name,
        module=f"planted.{name}",
        tier=tier,
        builtin=builtin,
        status=ir.Status(status),
        reason=reason,
    )


def _planted_availability(ir, *, missing=(), alpha=("alpha-a",)):
    names = [f"builtin-{i:02d}" for i in range(1, 18)]
    rows = [
        _row(
            ir,
            name,
            "missing" if name in missing else "available",
            reason="needs a thing" if name in missing else "",
        )
        for name in names
    ]
    rows += [
        _row(ir, name, "opt_in", builtin=False, tier=PluginTier.ALPHA) for name in alpha
    ]
    env = ir.Env(
        "linux",
        "amd64",
        RunMode.container,
        ir.Provision("image", image_stage="ci", tools=ir.ALL_TOOLS),
    )
    return ir.Availability(env, tuple(rows))


def test_the_header_is_exported_once(ir):
    assert ir.SCANNER_SET_HEADER == "Scanner set"


def test_every_builtin_available_reads_all_built_in(ir):
    got = _planted_availability(ir)

    assert ir.builtin_count(got) == (17, 17)
    assert ir.scanner_set_cell(got).startswith("all built-in")


def test_one_missing_builtin_reads_n_minus_one_of_n(ir):
    got = _planted_availability(ir, missing=("builtin-03",))

    assert ir.builtin_count(got) == (16, 17)
    assert ir.scanner_set_cell(got).startswith("16 of 17 built-in")
    assert "all built-in" not in ir.scanner_set_cell(got)


def test_several_missing_builtins_read_the_count_that_remains(ir):
    got = _planted_availability(ir, missing=("builtin-03", "builtin-09", "builtin-10"))

    assert ir.scanner_set_cell(got).startswith("14 of 17 built-in")


def test_the_missing_builtin_and_its_reason_are_in_the_names_view(ir):
    got = _planted_availability(ir, missing=("builtin-03",))

    names = ir.scanner_names(got)

    assert "`builtin-03` (missing: needs a thing)" in names.builtin
    assert "`builtin-04`" in names.builtin
    assert len(names.builtin) == 17
    assert names.alpha == ("`alpha-a`",)


def test_alpha_reads_opt_in_with_no_count(ir):
    one = _planted_availability(ir, alpha=("alpha-a",))
    three = _planted_availability(ir, alpha=("alpha-a", "alpha-b", "alpha-c"))
    none = _planted_availability(ir, alpha=())

    assert ir.scanner_set_cell(one) == "all built-in, alpha opt-in"
    assert ir.scanner_set_cell(three) == ir.scanner_set_cell(one)
    assert ir.scanner_set_cell(none) == "all built-in"
    assert not re.search(r"\d", ir.scanner_set_cell(three))


def test_a_missing_alpha_scanner_adds_nothing_to_the_cell(ir):
    got = _planted_availability(ir, alpha=("alpha-a",))
    rows = (*got.rows, _row(ir, "alpha-z", "missing", builtin=False, reason="no tool"))
    more = dataclasses.replace(got, rows=rows)

    assert ir.scanner_set_cell(more) == ir.scanner_set_cell(got)
    assert "`alpha-z`" not in " ".join(ir.scanner_names(more).alpha)


def test_the_precommit_kind_reads_the_size_of_the_precommit_set(ir, regs, monkeypatch):
    env = _precommit(ir)

    assert ir.scanner_set_cell(ir.scanners_for(env, regs)) == "5 (the precommit set)"

    monkeypatch.setattr(constants, "PRECOMMIT_MODE_SCANNERS", ("bandit", "checkov"))
    assert ir.scanner_set_cell(ir.scanners_for(env, regs)) == "2 (the precommit set)"


def test_semgrep_is_marked_deprecated_in_the_names_view(ir, regs):
    got = ir.scanners_for(_image(ir), regs)

    names = ir.scanner_names(got)

    assert "`semgrep` (deprecated)" in names.builtin
    assert "`opengrep`" in names.builtin
    assert sum("(deprecated" in item for item in names.builtin) == 1


def test_a_deprecated_scanner_that_is_also_missing_carries_both_notes(ir, regs):
    short = ir.scanners_for(_host(ir, tools=_HOST_TOOLS - {"semgrep"}), regs)

    names = ir.scanner_names(short)

    assert "`semgrep` (deprecated; missing: needs semgrep)" in names.builtin


def test_the_image_cell_and_names_on_the_real_registers(ir, regs):
    got = ir.scanners_for(_image(ir), regs)

    assert ir.scanner_set_cell(got) == "all built-in, alpha opt-in"
    assert len(ir.scanner_names(got).builtin) == 17
    assert ir.scanner_names(got).alpha == (
        "`betterleaks`",
        "`guarddog`",
        "`hadolint`",
        "`trivy-repo`",
    )


def test_a_reason_with_parentheses_or_a_pipe_cannot_break_the_cell(ir):
    rows = (
        _row(ir, "bandit", "missing", reason="needs (a thing) | or two"),
        _row(ir, "gitleaks", "available"),
    )
    got = ir.Availability(
        ir.Env("linux", "amd64", RunMode.local, ir.Provision("host")), rows
    )

    item = ir.scanner_names(got).builtin[0]

    assert item.startswith("`bandit` (missing: ")
    assert item.count("(") == 1 and item.count(")") == 1
    assert "|" not in item


def _docs_checks():
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, DOCS_CHECKS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _page(tmp_path: Path, builtin: str, alpha: str) -> Path:
    page = tmp_path / "docs" / "scanners.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        "| Environment | Built-in scanners | Alpha scanners |\n"
        "|---|---|---|\n"
        f"| host | {builtin} | {alpha} |\n",
        encoding="utf-8",
    )
    return page


def test_the_names_pass_check_scanner_names_and_a_planted_name_does_not(
    ir, regs, tmp_path
):
    checks = _docs_checks()
    modules = _modules(regs)
    got = ir.scanners_for(
        _host(
            ir,
            tools=_HOST_TOOLS - {"gitleaks"},
            runtimes=frozenset(),
            alpha_with_tools=frozenset({modules["betterleaks"]}),
        ),
        regs,
    )
    names = ir.scanner_names(got)
    good = _page(tmp_path, ", ".join(names.builtin), ", ".join(names.alpha))
    assert any("(missing:" in item for item in names.builtin)
    assert names.alpha == ("`betterleaks`",)

    assert checks.check_scanner_names([good], tmp_path) == []

    bad = _page(
        tmp_path, ", ".join((*names.builtin, "`gitleakz`")), ", ".join(names.alpha)
    )
    findings = checks.check_scanner_names([bad], tmp_path)
    assert any("gitleakz" in str(f) for f in findings), findings


# ---------------------------------------------------------------------------
# Hand facts the reader holds are checked against what they describe
# ---------------------------------------------------------------------------


def test_the_extra_a_scanner_needs_is_an_extra_the_project_declares(ir):
    import tomllib

    declared = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text("utf-8"))[
        "project"
    ]["optional-dependencies"]

    assert dict(ir.SCANNER_EXTRAS) == {"cdk-nag": "cdk"}
    assert set(ir.SCANNER_EXTRAS.values()) <= set(declared)


def test_the_runtimes_the_reader_judges_are_node_npm_and_ruby(ir):
    assert ir.HOST_RUNTIMES == frozenset({"node", "npm", "ruby"})
