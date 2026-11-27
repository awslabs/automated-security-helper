"""Bindings between the registers.

Several registers describe one fact from different sides: a scanner's operational
facets say how it reaches the image, the provisioning register pins the PyPI package an
alpha scanner installs, the image register records what the Dockerfile builds, the
download table records what each pinned asset links against, and the install-package
facets name hosts. Each register is checked on its own elsewhere. These rows check that
they agree with one another, and each comparison that could not fail has a planted
input beside it that makes it fail.

What is not checked: whether an image holds a scanner is not compared with the
provenance register, and the programs a scanner needs are not yet compared with the
system packages, which this unit declares and does not fill.

Every name the unit adds is read inside a test body, so the rows that need it fail one
by one where it does not exist.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import platform
import re
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base import install_package_facets as ipf
from automated_security_helper.base import plugin_provisioning as prov
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import enums
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.utils import tool_downloads as td
from automated_security_helper.utils.install_providers import INSTALL_PROVIDERS
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

# Rebuild models to resolve forward references, as the other construction tests do.
AshConfig.model_rebuild()

SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()

_ROOT = Path(__file__).resolve().parents[3]
_DOCKERFILE = (_ROOT / "Dockerfile").read_text(encoding="utf-8")


def _ir():
    return importlib.import_module("automated_security_helper.base.image_register")


def _facets_by_name() -> dict[str, opsf.ScannerOperationalFacets]:
    declared = (opsf.declared_operational_facets(cls) for cls in SCANNER_CLASSES)
    return {facets.scanner_name: facets for facets in declared if facets is not None}


def _class_named(name: str) -> type:
    return next(
        cls
        for cls in SCANNER_CLASSES
        if getattr(opsf.declared_operational_facets(cls), "scanner_name", None) == name
    )


@pytest.fixture(scope="module")
def _context(tmp_path_factory):
    root = tmp_path_factory.mktemp("registerbindings")
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = root / "src"
    ctx.output_dir = root / "out"
    ctx.source_dir.mkdir()
    ctx.output_dir.mkdir()
    ctx.global_ignore_paths = []
    return ctx


# ---------------------------------------------------------------------------
# The build engine enum
# ---------------------------------------------------------------------------


def test_the_build_engine_enum_names_only_the_runner_beside_the_build_target() -> None:
    assert [member.name for member in enums.BuildEngine] == ["RUNNER"]
    assert enums.BuildEngine.RUNNER.value == "runner"
    assert issubclass(enums.BuildEngine, str)
    source = inspect.getsource(enums)
    assert (
        source.index("class BuildTarget")
        < source.index("class BuildEngine")
        < source.index("class RunMode")
    )


# ---------------------------------------------------------------------------
# PyPI pins and the alpha scanners that need one
# ---------------------------------------------------------------------------

#: The pin's ``runtime`` word for each scanner runtime that installs a PyPI package.
_PIN_RUNTIME = {
    opsf.RuntimeKind.UV_PYTHON: "uv-tool",
    opsf.RuntimeKind.PYPI_PACKAGE: "ash-environment",
}


def _alpha_python_scanners() -> list[str]:
    alpha = {m.name for m in scanner_manifests() if m.tier is PluginTier.ALPHA}
    return sorted(
        name
        for name, facets in _facets_by_name().items()
        if name in alpha and facets.runtime.kind in _PIN_RUNTIME
    )


_ALPHA_PYTHON = _alpha_python_scanners()


def test_the_pin_sweep_covers_the_two_alpha_python_scanners() -> None:
    """A sweep over an empty list would pass whatever the register held."""
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert _ALPHA_PYTHON == ["ferret-scan", "guarddog"]


@pytest.mark.parametrize("name", _ALPHA_PYTHON)
def test_an_alpha_python_scanner_has_exactly_one_pin_in_the_extra_or_excluded(
    name: str,
) -> None:
    pins = prov.provisioning_for(name).pypi_pins

    assert len(pins) == 1, name
    (pin,) = pins
    assert bool(pin.extra) != (pin.excluded is not None), (
        f"{name}: a pin is in the extra or excluded from it, not both and not neither"
    )
    assert pin.runtime == _PIN_RUNTIME[_facets_by_name()[name].runtime.kind]


def test_a_pin_belongs_to_an_alpha_python_scanner() -> None:
    pinned = sorted(
        scanner for scanner, block in prov.PROVISIONING.items() if block.pypi_pins
    )

    assert pinned == _ALPHA_PYTHON


@pytest.mark.parametrize("name", _ALPHA_PYTHON)
def test_a_pins_specifier_is_the_scanners_default_constraint(
    name: str, _context
) -> None:
    (pin,) = prov.provisioning_for(name).pypi_pins
    instance = _class_named(name)(context=_context)

    assert pin.specifier == instance._get_tool_version_constraint(), name


@pytest.mark.parametrize("name", _ALPHA_PYTHON)
def test_a_pins_with_requirements_are_the_scanners_with_dependencies(
    name: str, _context
) -> None:
    (pin,) = prov.provisioning_for(name).pypi_pins
    instance = _class_named(name)(context=_context)

    assert pin.with_requirements == tuple(instance._get_tool_with_dependencies() or ())


def python_upper_bound(text: str) -> Optional[str]:
    """The ``X.Y`` in a ``<X.Y`` bound, whether it is written in a request such as
    ``>=3.10,<3.14`` or in a marker such as ``python_version < '3.14'``; None when
    the text has no strict upper bound."""
    match = re.search(r"(?<![<>=!~])<\s*'?(\d+\.\d+)", text)
    return match.group(1) if match else None


@pytest.mark.parametrize(
    ("text", "bound"),
    [
        ("python_version < '3.14'", "3.14"),
        (">=3.10,<3.14", "3.14"),
        (">=3.10,<3.15", "3.15"),
        (">=3.10", None),
        ("<=3.13", None),
        ("python_version >= '3.10'", None),
        ("", None),
    ],
)
def test_the_python_bound_reader_has_controls_in_both_directions(
    text: str, bound: Optional[str]
) -> None:
    assert python_upper_bound(text) == bound


@pytest.mark.parametrize("name", _ALPHA_PYTHON)
def test_a_pins_python_bound_is_the_bound_of_the_scanners_compat_row(
    name: str,
) -> None:
    (pin,) = prov.provisioning_for(name).pypi_pins
    rows = [
        row
        for row in _facets_by_name()[name].runtime_compat.rows
        if row.runtime is opsf.RuntimeName.PYTHON
        and row.resolution is opsf.CompatResolution.PIN
    ]

    if rows:
        bounds = {python_upper_bound(row.runtime_request) for row in rows}
        assert bounds == {python_upper_bound(pin.python_marker)}, name
    else:
        assert pin.python_marker == "", name


@pytest.mark.parametrize("name", _ALPHA_PYTHON)
def test_a_pins_platform_marker_is_where_the_scanner_says_it_cannot_install(
    name: str, _context, monkeypatch: pytest.MonkeyPatch
) -> None:
    (pin,) = prov.provisioning_for(name).pypi_pins
    instance = _class_named(name)(context=_context)

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert instance.unsupported_platform_reason() is None
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    unsupported_on_windows = instance.unsupported_platform_reason() is not None

    assert bool(pin.platform_marker) == unsupported_on_windows, name
    if pin.platform_marker:
        assert pin.platform_marker == "sys_platform != 'win32'"


def pin_matches_the_license_entry(specifier: str, version: str) -> bool:
    """A uv-tool pin is ``==`` the version the license entry records, which is the
    upstream release tag, so it may carry the leading ``v`` the install does not."""
    return specifier == "==" + version.removeprefix("v")


@pytest.mark.parametrize(
    ("specifier", "version", "matches"),
    [
        ("==3.2.0", "v3.2.0", True),
        ("==3.2.0", "3.2.0", True),
        ("==3.2.1", "v3.2.0", False),
        (">=3.2.0", "v3.2.0", False),
        ("==3.2.0", "v3.2.00", False),
    ],
)
def test_the_license_version_comparison_has_controls_in_both_directions(
    specifier: str, version: str, matches: bool
) -> None:
    assert pin_matches_the_license_entry(specifier, version) is matches


def test_guarddogs_pin_is_the_version_its_license_entry_records() -> None:
    """Read only: the entry is the one the image installs license files for, and
    nothing here writes to it."""
    (pin,) = prov.provisioning_for("guarddog").pypi_pins
    entry = td.THIRD_PARTY_LICENSES["guarddog"]

    assert entry.distribution == pin.distribution
    assert pin_matches_the_license_entry(pin.specifier, entry.version), (
        pin.specifier,
        entry.version,
    )


# ---------------------------------------------------------------------------
# Every pinned tool has one way into the image
# ---------------------------------------------------------------------------


def image_path_problems(
    pinned: set[str], engine: set[str], released: set[str], provisioned: set[str]
) -> list[str]:
    """What is wrong with the way *pinned* tools reach the image: a tool with no path,
    a path for a tool that is not pinned, or two paths for one tool."""
    problems = []
    paths = {
        "an engine step": engine,
        "a release-asset scanner": released,
        "dependencies install": provisioned,
    }
    names = sorted(paths)
    for index, first in enumerate(names):
        for second in names[index + 1 :]:
            for tool in sorted(paths[first] & paths[second]):
                problems.append(f"{tool} is installed by {first} and by {second}")
    every = engine | released | provisioned
    for tool in sorted(pinned - every):
        problems.append(f"{tool} has no way into the image")
    for tool in sorted(every - pinned):
        problems.append(f"{tool} is not a pinned tool")
    return problems


def test_the_path_reader_has_controls_in_both_directions() -> None:
    assert image_path_problems({"a", "b", "c"}, {"a"}, {"b"}, {"c"}) == []
    assert image_path_problems({"a", "b"}, {"a"}, set(), set()) == [
        "b has no way into the image"
    ]
    assert image_path_problems({"a"}, {"a"}, {"a"}, set()) == [
        "a is installed by a release-asset scanner and by an engine step"
    ]
    assert image_path_problems({"a"}, {"a"}, {"z"}, set()) == ["z is not a pinned tool"]


def _released_tools() -> set[str]:
    return {
        facets.image.tool
        for facets in _facets_by_name().values()
        if facets.image.route is opsf.ImageRoute.RELEASE_ASSET
    }


def test_every_pinned_tool_reaches_the_image_one_way() -> None:
    ir = _ir()

    problems = image_path_problems(
        set(td.TOOL_VERSIONS),
        {step.tool for step in ir.ENGINE_IMAGE_STEPS},
        _released_tools(),
        set(ir.PROVISIONED_BY_DEPENDENCIES_INSTALL),
    )

    assert problems == []


def test_the_engine_steps_are_the_pins_no_scanner_owns() -> None:
    ir = _ir()

    assert {step.tool for step in ir.ENGINE_IMAGE_STEPS} == {
        pin.tool for pin in prov.ENGINE_TOOL_PINS
    }


def test_dependencies_install_provisions_the_pinned_binaries_of_its_scanners() -> None:
    expected = {
        facets.runtime.tool_versions_key
        for facets in _facets_by_name().values()
        if facets.image.route is opsf.ImageRoute.DEPENDENCIES_INSTALL
        and facets.runtime.kind is opsf.RuntimeKind.PINNED_BINARY
    }

    assert set(_ir().PROVISIONED_BY_DEPENDENCIES_INSTALL) == expected == {"opengrep"}


def test_a_hand_written_program_is_a_program_some_scanner_needs() -> None:
    needed = {
        program
        for facets in _facets_by_name().values()
        for program in facets.runtime.external_programs
    }

    assert set(_ir().HAND_WRITTEN_PROVIDES) <= needed


def test_a_family_builds_with_an_implemented_install_provider() -> None:
    for family in _ir().OS_FAMILIES:
        provider = INSTALL_PROVIDERS.get(family.package_manager)

        assert provider is not None and provider.implemented, family.name


# ---------------------------------------------------------------------------
# The alpha scanners the image loads
# ---------------------------------------------------------------------------


def _alpha_modules_in_the_dockerfile() -> list[set[str]]:
    copies = re.findall(
        r'^ARG ASH_ALPHA_PLUGIN_MODULES="([^"]*)"', _DOCKERFILE, flags=re.MULTILINE
    )
    return [{module for module in value.split(",") if module} for value in copies]


def test_the_alpha_module_list_reader_has_a_positive_and_a_negative_control() -> None:
    assert re.findall(
        r'^ARG ASH_ALPHA_PLUGIN_MODULES="([^"]*)"',
        'ARG ASH_ALPHA_PLUGIN_MODULES="a,b"\n# ARG ASH_ALPHA_PLUGIN_MODULES="c"\n',
        flags=re.MULTILINE,
    ) == ["a,b"]


def test_the_image_loads_the_alpha_modules_of_the_scanners_that_bring_a_tool() -> None:
    """The Dockerfile's own words: the modules listed are the alpha ones that bring
    tools of their own. A scanner whose tool is another scanner's, or is not in the
    image, is not listed."""
    routes = {name: facets.image.route for name, facets in _facets_by_name().items()}
    bring_a_tool = {opsf.ImageRoute.RELEASE_ASSET, opsf.ImageRoute.DEPENDENCIES_INSTALL}
    expected = {
        m.plugin_module
        for m in scanner_manifests()
        if m.tier is PluginTier.ALPHA and routes[m.name] in bring_a_tool
    }
    copies = _alpha_modules_in_the_dockerfile()

    assert len(expected) == 3, sorted(expected)
    assert copies, "the Dockerfile names no alpha plugin modules"
    for copy in copies:
        assert copy == expected


# ---------------------------------------------------------------------------
# One host match, two modules
# ---------------------------------------------------------------------------


def _shape(cls: type) -> list[tuple[str, object]]:
    return [(field.name, field.default) for field in dataclasses.fields(cls)]


def test_the_shape_reader_sees_a_planted_difference() -> None:
    @dataclasses.dataclass(frozen=True)
    class Fewer:
        ids: tuple = ()
        versions: tuple = ()

    assert _shape(Fewer) != _shape(ipf.HostMatch)
    assert _shape(ipf.HostMatch) == _shape(ipf.HostMatch)


def test_the_image_registers_host_match_has_the_shape_of_the_facets() -> None:
    ir = _ir()

    assert _shape(ir.HostMatch) == _shape(ipf.HostMatch)


@pytest.mark.parametrize(
    ("ids", "versions"),
    [
        (("debian",), ("12",)),
        (("alpine",), ("3.24",)),
        (("debian", "ubuntu"), ("12", "24.04")),
        (("opensuse-tumbleweed",), ()),
    ],
)
def test_the_image_registers_host_match_matches_the_hosts_the_facets_match(
    ids: tuple[str, ...], versions: tuple[str, ...]
) -> None:
    """The register cannot import the facets module, so the two matchers are held to
    one table of hosts instead."""
    ir = _ir()
    hosts = [
        ("debian", "12"),
        ("debian", "12.12"),
        ("debian", "1"),
        ("debian", "123"),
        ("debian", "13"),
        ("debian", ""),
        ("ubuntu", "24.04"),
        ("ubuntu", "24.04.1"),
        ("ubuntu", "24.045"),
        ("alpine", "3.24.4"),
        ("alpine", "3.240"),
        ("Alpine", "3.24"),
        ("opensuse-tumbleweed", "20261101"),
        ("opensuse-leap", "16.0"),
        ("", ""),
    ]
    local = ir.HostMatch(ids=ids, versions=versions)
    shared = ipf.HostMatch(ids=ids, versions=versions)

    for os_id, version_id in hosts:
        assert local.matches(os_id, version_id) is shared.matches(
            ipf.OsRelease(id=os_id, version_id=version_id)
        ), (ids, versions, os_id, version_id)
