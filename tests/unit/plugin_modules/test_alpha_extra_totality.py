"""The admission and promotion gate for the ``alpha`` extra.

Every scanner declared in ``plugin_manifests/alpha.py`` reaches its user's machine one
way, and the register says which. This gate reads that declaration for each scanner and
holds it to the rule for its kind:

* a scanner whose tool is a PyPI distribution (``uv_python``, ``pypi_package``) declares
  exactly one ``PypiPin`` in ``base/plugin_provisioning.py``, and that pin is either a
  member of the ``alpha`` extra or excluded from it with a recorded reason, never both and
  never neither; its with-requirements are the scanner's own, and its markers say what the
  scanner says about the Python versions and platforms it cannot run on;
* a pinned binary names a pin in the download table;
* a user-installed CLI names the program the user installs and states what it needs;
* any other kind is refused by name, so a new kind is a decision somebody makes here.

A pin that is a member of the extra must also belong to a scanner whose tier is
``alpha``. Promoting a scanner is a one-line tier edit in ``alpha.py``, so a promoted
scanner turns this gate red until its pin leaves the extra.

The gate is one function, :func:`problems`, run over the real manifests (all green) and
over planted facts (each defect flagged, each clean sibling, differing only in the flagged
property, accepted). A gate that has only ever read green data could be flagging nothing.

Reading of "install hint". The register has no structured install-hint field yet. A
user-installed CLI is read here the way the promotion bar's provisioning row reads one
(``core/plugin_conformance.py``): the scanner names the program in its runtime row and
states its prerequisites in a non-blank note. The facet model already refuses a blank
note, so on real data the program name is what the rule checks, and the planted cases
build their facts directly to show the note check can fire. When the install-package
facets carry a hint for these tools, this rule should read that instead.

The last test holds the sync script's rendering equal to what pyproject.toml carries, so
the register, the script and the extra cannot say three things.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import platform
import re
import sys
import tomllib
from pathlib import Path
from typing import Optional
from unittest import mock

import pytest

from automated_security_helper.base import plugin_provisioning as prov
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_manifests import alpha, scanner_manifests
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

# Rebuild models to resolve forward references, as the other construction tests do.
AshConfig.model_rebuild()

SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()

REPO_ROOT = Path(__file__).resolve().parents[3]
REAL_PYPROJECT = REPO_ROOT / "pyproject.toml"
SCRIPT_PATH = REPO_ROOT / "scripts" / "sync_alpha_extra.py"

#: The extra this gate guards, and the marker for where its scanners cannot install.
EXTRA = "alpha"
WINDOWS_MARKER = "sys_platform != 'win32'"

#: The pin's ``runtime`` word for each scanner runtime that installs a PyPI package.
PIN_RUNTIME = {
    opsf.RuntimeKind.UV_PYTHON: "uv-tool",
    opsf.RuntimeKind.PYPI_PACKAGE: "ash-environment",
}

#: The alpha scanners main declares. A floor, not an equality: admitting a scanner adds
#: a manifest, and the sweep must keep reading these.
MAIN_ALPHA = {
    "betterleaks",
    "ferret-scan",
    "guarddog",
    "hadolint",
    "snyk-code",
    "trivy-repo",
}


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Facts:
    """What the gate reads about one alpha scanner."""

    name: str
    tier: PluginTier
    runtime: opsf.RuntimeKind
    pins: tuple[prov.PypiPin, ...]
    #: The TOOL_VERSIONS key of a pinned binary.
    tool_versions_key: Optional[str] = None
    #: A user-installed CLI: the programs its runtime row names and its prerequisites.
    external_programs: tuple[str, ...] = ()
    prerequisites_note: str = ""
    #: What the scanner itself installs with its tool (``uv tool install --with``).
    with_dependencies: tuple[str, ...] = ()
    #: The ``X.Y`` upper bound of each of the scanner's Python PIN rows.
    python_bounds: frozenset[Optional[str]] = frozenset()
    #: Whether the scanner reports itself unsupported on Windows.
    unsupported_on_windows: bool = False


def python_upper_bound(text: str) -> Optional[str]:
    """The ``X.Y`` in a ``<X.Y`` bound, whether it is written in a request such as
    ``>=3.10,<3.14`` or in a marker such as ``python_version < '3.14'``; None when
    the text has no strict upper bound."""
    match = re.search(r"(?<![<>=!~])<\s*'?(\d+\.\d+)", text)
    return match.group(1) if match else None


def membership_problems(
    name: str, tier: PluginTier, pins: tuple[prov.PypiPin, ...]
) -> list[str]:
    """A member of the extra on a scanner that is not alpha, or in an extra the
    generator does not render."""
    found: list[str] = []
    for pin in pins:
        if pin.extra == EXTRA and tier is not PluginTier.ALPHA:
            found.append(
                f"{name}: {pin.distribution} is a member of the {EXTRA} extra but the "
                f"scanner is tier {tier.value}; move the pin out of the extra when a "
                "scanner is promoted"
            )
        elif pin.extra and pin.extra != EXTRA:
            found.append(
                f"{name}: {pin.distribution} names the extra {pin.extra!r}, and the "
                f"generator renders only {EXTRA!r}"
            )
    return found


def _python_scanner_problems(facts: Facts) -> list[str]:
    name = facts.name
    if len(facts.pins) != 1:
        return [
            f"{name}: a {facts.runtime.value} scanner declares exactly one PyPI pin, "
            f"and this one declares {len(facts.pins)}"
        ]
    (pin,) = facts.pins
    found: list[str] = []
    if bool(pin.extra) == (pin.excluded is not None):
        found.append(
            f"{name}: {pin.distribution} must be a member of the {EXTRA} extra or be "
            f"excluded from it with a reason; it is {'both' if pin.extra else 'neither'}"
        )
    if pin.runtime != PIN_RUNTIME[facts.runtime]:
        found.append(
            f"{name}: the pin's runtime is {pin.runtime!r}, and a "
            f"{facts.runtime.value} scanner installs as {PIN_RUNTIME[facts.runtime]!r}"
        )
    if tuple(pin.with_requirements) != facts.with_dependencies:
        found.append(
            f"{name}: the pin's with-requirements {tuple(pin.with_requirements)} are "
            f"not the scanner's {facts.with_dependencies}"
        )
    marker_bound = python_upper_bound(pin.python_marker)
    if facts.python_bounds:
        if {marker_bound} != set(facts.python_bounds):
            found.append(
                f"{name}: the python marker {pin.python_marker!r} bounds Python at "
                f"{marker_bound}, and the scanner's compat rows at "
                f"{sorted(map(str, facts.python_bounds))}"
            )
    elif pin.python_marker:
        found.append(
            f"{name}: the python marker {pin.python_marker!r} has no compat row of the "
            "scanner's behind it"
        )
    if bool(pin.platform_marker) != facts.unsupported_on_windows:
        found.append(
            f"{name}: the platform marker is {pin.platform_marker!r} and the scanner "
            f"{'cannot' if facts.unsupported_on_windows else 'can'} install on Windows"
        )
    elif pin.platform_marker and pin.platform_marker != WINDOWS_MARKER:
        found.append(
            f"{name}: the platform marker {pin.platform_marker!r} is not "
            f"{WINDOWS_MARKER!r}, the one place this scanner reports it cannot install"
        )
    return found


def problems(facts: Facts, pinned_tools: frozenset[str]) -> list[str]:
    """Everything wrong with how one alpha scanner is classified; empty when sound."""
    name = facts.name
    kind = facts.runtime
    found: list[str] = []
    if kind in PIN_RUNTIME:
        found += _python_scanner_problems(facts)
    elif kind is opsf.RuntimeKind.PINNED_BINARY:
        if not facts.tool_versions_key:
            found.append(f"{name}: a pinned binary names its TOOL_VERSIONS key")
        elif facts.tool_versions_key not in pinned_tools:
            found.append(
                f"{name}: TOOL_VERSIONS has no {facts.tool_versions_key!r} pin"
            )
    elif kind is opsf.RuntimeKind.USER_INSTALLED_CLI:
        if not facts.external_programs:
            found.append(
                f"{name}: a user-installed CLI names the program the user installs"
            )
        if not facts.prerequisites_note.strip():
            found.append(
                f"{name}: a user-installed CLI carries an install hint, and this "
                "one states no prerequisites"
            )
    else:
        found.append(
            f"{name}: runtime kind {kind.value!r} has no admission rule in this gate; "
            "add one before admitting it"
        )
    return found + membership_problems(name, facts.tier, facts.pins)


# ---------------------------------------------------------------------------
# Reading the real scanners
# ---------------------------------------------------------------------------


def _classes_by_name() -> dict[str, type]:
    named: dict[str, type] = {}
    for cls in SCANNER_CLASSES:
        declared = opsf.declared_operational_facets(cls)
        if declared is not None:
            named[declared.scanner_name] = cls
    return named


_CLASSES = _classes_by_name()


@pytest.fixture(scope="module")
def _context(tmp_path_factory):
    root = tmp_path_factory.mktemp("alphaextra")
    ctx = mock.MagicMock(spec=PluginContext)
    ctx.source_dir = root / "src"
    ctx.output_dir = root / "out"
    ctx.source_dir.mkdir()
    ctx.output_dir.mkdir()
    ctx.global_ignore_paths = []
    return ctx


def real_facts(manifest, context) -> Facts:
    """The facts of one alpha manifest, read from the scanner it names."""
    cls = _CLASSES[manifest.name]
    facets = opsf.declared_operational_facets(cls)
    runtime = facets.runtime
    with_dependencies: tuple[str, ...] = ()
    unsupported_on_windows = False
    if runtime.kind in PIN_RUNTIME:
        instance = cls(context=context)
        with_dependencies = tuple(instance._get_tool_with_dependencies() or ())
        with mock.patch.object(platform, "system", return_value="Windows"):
            unsupported_on_windows = instance.unsupported_platform_reason() is not None
    python_bounds = frozenset(
        python_upper_bound(row.runtime_request)
        for row in facets.runtime_compat.rows
        if row.runtime is opsf.RuntimeName.PYTHON
        and row.resolution is opsf.CompatResolution.PIN
    )
    return Facts(
        name=manifest.name,
        tier=manifest.tier,
        runtime=runtime.kind,
        pins=tuple(manifest.provisioning.pypi_pins),
        tool_versions_key=runtime.tool_versions_key,
        external_programs=tuple(runtime.external_programs),
        prerequisites_note=facets.prerequisites.note,
        with_dependencies=with_dependencies,
        python_bounds=python_bounds,
        unsupported_on_windows=unsupported_on_windows,
    )


# ---------------------------------------------------------------------------
# The real manifests
# ---------------------------------------------------------------------------


def test_the_sweep_reads_the_alpha_manifests_main_declares() -> None:
    """A sweep over a shrunken list would pass whatever the register held."""
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    names = {manifest.name for manifest in alpha.MANIFESTS}

    assert MAIN_ALPHA <= names, sorted(MAIN_ALPHA - names)
    assert names <= set(_CLASSES), (
        "an alpha manifest names no registered scanner class: "
        f"{sorted(names - set(_CLASSES))}"
    )


@pytest.mark.parametrize(
    "manifest", alpha.MANIFESTS, ids=lambda manifest: manifest.name
)
def test_every_alpha_manifest_is_classified(manifest, _context) -> None:
    facts = real_facts(manifest, _context)

    assert problems(facts, frozenset(prov.tool_versions())) == []


def test_a_member_pin_belongs_to_a_scanner_that_is_still_alpha() -> None:
    """Over every manifest, not just the alpha module's: a pin is a member of the
    alpha extra only while its scanner is an alpha scanner."""
    found: list[str] = []
    for manifest in scanner_manifests():
        found += membership_problems(
            manifest.name, manifest.tier, manifest.provisioning.pypi_pins
        )

    assert found == []


# ---------------------------------------------------------------------------
# Planted defects, each beside the sibling that differs only in the flagged property
# ---------------------------------------------------------------------------

_TOOLS = frozenset({"hadolint", "trivy"})


def _pin(**changes) -> prov.PypiPin:
    fields = {
        "distribution": "alpha-tool",
        "specifier": "==1.0.0",
        "runtime": "uv-tool",
        "extra": EXTRA,
    }
    fields.update(changes)
    return prov.PypiPin(**fields)


def _excluded() -> prov.Exclusion:
    return prov.Exclusion(
        reason=prov.ExclusionReason.OWNER_HOLD,
        detail="a detail",
        measured="a measurement",
    )


def _facts(**changes) -> Facts:
    fields = {
        "name": "alpha-tool",
        "tier": PluginTier.ALPHA,
        "runtime": opsf.RuntimeKind.UV_PYTHON,
        "pins": (_pin(),),
    }
    fields.update(changes)
    return Facts(**fields)


def _binary(**changes) -> Facts:
    fields = {
        "runtime": opsf.RuntimeKind.PINNED_BINARY,
        "pins": (),
        "tool_versions_key": "hadolint",
    }
    fields.update(changes)
    return _facts(**fields)


def _cli(**changes) -> Facts:
    fields = {
        "runtime": opsf.RuntimeKind.USER_INSTALLED_CLI,
        "pins": (),
        "external_programs": ("snyk",),
        "prerequisites_note": "an authenticated CLI on PATH",
    }
    fields.update(changes)
    return _facts(**fields)


def _held(**changes) -> prov.PypiPin:
    """A pin that is excluded from the extra instead of a member of it."""
    return _pin(extra="", excluded=_excluded(), **changes)


_PYTHON_ROW = frozenset({"3.14"})
_PYTHON_MARKER = "python_version < '3.14'"

#: case -> (builder of the planted facts, a fragment of the problem it must raise)
_FLAGGED = {
    "a uv-python scanner with no pin": (
        lambda: _facts(pins=()),
        "exactly one PyPI pin",
    ),
    "a uv-python scanner with two pins": (
        lambda: _facts(pins=(_pin(), _pin(distribution="other-tool"))),
        "exactly one PyPI pin",
    ),
    "a pin that is neither a member nor excluded": (
        lambda: _facts(pins=(_pin(extra=""),)),
        "it is neither",
    ),
    "a pin that is both a member and excluded": (
        lambda: _facts(pins=(_pin(excluded=_excluded()),)),
        "it is both",
    ),
    "a pin whose runtime word is the other runtime's": (
        lambda: _facts(pins=(_pin(runtime="ash-environment"),)),
        "the pin's runtime is 'ash-environment'",
    ),
    "an alpha pin on a supported manifest": (
        lambda: _facts(tier=PluginTier.SUPPORTED),
        "is tier supported",
    ),
    "an alpha pin on a deprecated manifest": (
        lambda: _facts(tier=PluginTier.DEPRECATED),
        "is tier deprecated",
    ),
    "a pin in an extra the generator does not render": (
        lambda: _facts(pins=(_pin(extra="cdk"),)),
        "names the extra 'cdk'",
    ),
    "with-requirements the scanner does not install": (
        lambda: _facts(pins=(_pin(with_requirements=("pluggy<1.7",)),)),
        "are not the scanner's",
    ),
    "with-requirements the pin does not carry": (
        lambda: _facts(with_dependencies=("pluggy<1.7",)),
        "are not the scanner's",
    ),
    "with-requirements that differ in one bound": (
        lambda: _facts(
            pins=(_pin(with_requirements=("pluggy<1.7",)),),
            with_dependencies=("pluggy<1.8",),
        ),
        "are not the scanner's",
    ),
    "a python marker that bounds another version": (
        lambda: _facts(
            pins=(_pin(python_marker="python_version < '3.13'"),),
            python_bounds=_PYTHON_ROW,
        ),
        "bounds Python at 3.13",
    ),
    "a python marker the scanner has no row for": (
        lambda: _facts(pins=(_pin(python_marker=_PYTHON_MARKER),)),
        "has no compat row",
    ),
    "a python compat row the pin has no marker for": (
        lambda: _facts(python_bounds=_PYTHON_ROW),
        "bounds Python at None",
    ),
    "a platform marker on a scanner that installs on Windows": (
        lambda: _facts(pins=(_pin(platform_marker=WINDOWS_MARKER),)),
        "the platform marker is",
    ),
    "no platform marker on a scanner that cannot install on Windows": (
        lambda: _facts(unsupported_on_windows=True),
        "cannot install on Windows",
    ),
    "a platform marker spelled for another platform": (
        lambda: _facts(
            pins=(_pin(platform_marker="sys_platform == 'linux'"),),
            unsupported_on_windows=True,
        ),
        "is not \"sys_platform != 'win32'\"",
    ),
    "a pinned binary that names no key": (
        lambda: _binary(tool_versions_key=None),
        "names its TOOL_VERSIONS key",
    ),
    "a pinned binary whose key is not pinned": (
        lambda: _binary(tool_versions_key="not-pinned"),
        "has no 'not-pinned' pin",
    ),
    "a user-installed CLI that names no program": (
        lambda: _cli(external_programs=()),
        "names the program the user installs",
    ),
    "a user-installed CLI that states no prerequisites": (
        lambda: _cli(prerequisites_note="  "),
        "states no prerequisites",
    ),
    "a runtime kind with no rule": (
        lambda: _facts(runtime=opsf.RuntimeKind.IN_PROCESS, pins=()),
        "has no admission rule",
    ),
}

#: case -> builder of facts that differ from a flagged case only in the flagged property
_CLEAN = {
    "a uv-python scanner with one member pin": lambda: _facts(),
    "a uv-python scanner with one excluded pin": lambda: _facts(pins=(_held(),)),
    "a pypi-package scanner with its own runtime word": lambda: _facts(
        runtime=opsf.RuntimeKind.PYPI_PACKAGE,
        pins=(_pin(runtime="ash-environment"),),
    ),
    "a promoted scanner whose pin left the extra": lambda: _facts(
        tier=PluginTier.SUPPORTED, pins=(_held(),)
    ),
    "with-requirements the scanner installs": lambda: _facts(
        pins=(_pin(with_requirements=("pluggy<1.7",)),),
        with_dependencies=("pluggy<1.7",),
    ),
    "a python marker that matches the compat row": lambda: _facts(
        pins=(_pin(python_marker=_PYTHON_MARKER),), python_bounds=_PYTHON_ROW
    ),
    "a platform marker where the scanner cannot install on Windows": lambda: _facts(
        pins=(_pin(platform_marker=WINDOWS_MARKER),), unsupported_on_windows=True
    ),
    "a pinned binary whose key is pinned": lambda: _binary(),
    "a user-installed CLI that names its program and prerequisites": lambda: _cli(),
}


@pytest.mark.parametrize("case", sorted(_FLAGGED))
def test_the_gate_flags_a_planted_defect(case: str) -> None:
    build, fragment = _FLAGGED[case]

    found = problems(build(), _TOOLS)

    assert any(fragment in problem for problem in found), (case, found)


@pytest.mark.parametrize("case", sorted(_CLEAN))
def test_the_gate_accepts_the_sibling_of_each_planted_defect(case: str) -> None:
    assert problems(_CLEAN[case](), _TOOLS) == [], case


def test_a_planted_defect_is_flagged_for_only_the_reason_it_plants() -> None:
    """The siblings above pass and the planted cases fail, so each case is one
    property apart: here, a pin with no member and no exclusion raises one problem."""
    found = problems(_facts(pins=(_pin(extra=""),)), _TOOLS)

    assert len(found) == 1, found


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


# ---------------------------------------------------------------------------
# The generator renders what pyproject.toml carries
# ---------------------------------------------------------------------------


def _load_script():
    """Import the generator by path; ``scripts/`` is not a package."""
    spec = importlib.util.spec_from_file_location(
        "ash_sync_alpha_extra_totality", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _committed_alpha_extra() -> Optional[list[str]]:
    with REAL_PYPROJECT.open("rb") as handle:
        extras = tomllib.load(handle)["project"]["optional-dependencies"]
    return extras.get(EXTRA)


def test_the_generators_rendering_equals_pyprojects_alpha_array() -> None:
    script = _load_script()

    pins = script.member_pins(prov.PROVISIONING)

    assert (script.requirement_lines(pins) or None) == _committed_alpha_extra()


def test_a_member_in_the_register_would_change_what_the_extra_must_hold() -> None:
    """The comparison above can fail: one planted member is a line pyproject.toml
    does not carry."""
    script = _load_script()
    planted = prov.PypiPin("planted-tool", "==1.0.0", "uv-tool", extra=EXTRA)

    rendered = script.requirement_lines(script.member_pins(prov.PROVISIONING) + [planted])

    assert "planted-tool==1.0.0" in rendered
    assert "planted-tool==1.0.0" not in (_committed_alpha_extra() or [])
