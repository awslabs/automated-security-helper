"""The alpha install plan lists, installs and checks every alpha scanner it can.

``.github/scripts/alpha-doctest-installs.py`` reads ``scripts/_install_routes.py`` and
answers three questions for the docs job: which alpha scanner is installed at which
version (``plan``), which arguments make ``ash dependencies install`` do it (``args``),
and whether each installed tool is where the docs sessions look (``verify``). Nothing
here installs anything: ``verify`` runs against planted directories and planted
probes.

A table of exemptions that nothing checks goes stale without a sound, so each table
the script holds (what it does not install and why, what it holds for a decision, the
interim pins) is refused when its rows no longer describe the registers. Every refusal
has a planted control, and the plan on main is pinned row by row, because a gate that
only checks the shape of the plan cannot tell a plan that installs five scanners from
one that installs none.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import re
import shlex
import shutil
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
    tool_versions,
)
from automated_security_helper.plugin_manifests import opt_in_scanner_modules

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "alpha-doctest-installs.py"
MODULE_LOAD_TEST = (
    REPO_ROOT / "tests" / "unit" / "test_ci_alpha_tool_installs_load_their_module.py"
)
PLUGINS = "automated_security_helper.plugin_modules"

MAIN_SCANNERS = (
    "betterleaks",
    "ferret-scan",
    "guarddog",
    "hadolint",
    "snyk-code",
    "trivy-repo",
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@pytest.fixture(scope="module")
def script():
    module = _load("_ash_alpha_doctest_installs_under_test", SCRIPT)
    yield module
    sys.modules.pop("_ash_alpha_doctest_installs_under_test", None)
    sys.modules.pop(module.install_routes.__name__, None)


@pytest.fixture(scope="module")
def ir(script):
    """The reader module the script loaded, so planted values are its own types."""
    return script.install_routes


@pytest.fixture(scope="module")
def regs(ir):
    return ir.Registers.read()


# ---------------------------------------------------------------------------
# Planted scanners, built from the script's own reader
# ---------------------------------------------------------------------------


def _manifest(name: str, provisioning: Provisioning = NO_PROVISIONING):
    module = f"planted_plugins.{name.replace('-', '_')}"
    return ScannerManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        name=name,
        version=BUNDLED_VERSION,
        aliases=(),
        tier=PluginTier.ALPHA,
        default_enabled=False,
        plugin_module=module,
        entry_points=EntryPoints(scanner=f"{module}.scanner:PlantedScanner"),
        options_model=f"{module}.scanner:PlantedOptions",
        file_ownership=(f"planted_plugins/{name}",),
        provisioning=provisioning,
    )


def _facets(name, kind, *, key=None, programs=(), provisionable=()):
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
    return HadolintScanner.operational_facets.model_copy(
        update={
            "scanner_name": name,
            "runtime": runtime,
            "platforms": opsf.PlatformsFacet(
                provisionable=provisionable, note="a planted row"
            ),
        }
    )


def _plant(regs, manifest, facets, declared=(), **replace):
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
    planted = types.ModuleType(name)
    for key, value in values.items():
        setattr(planted, key, value)
    monkeypatch.setitem(sys.modules, name, planted)


def _row(rows, name):
    return next(row for row in rows if row.scanner == name)


# ---------------------------------------------------------------------------
# The plan on main
# ---------------------------------------------------------------------------


def test_the_plan_on_main_gives_one_row_per_alpha_manifest(script):
    rows = script.plan()

    assert [row.scanner for row in rows] == list(MAIN_SCANNERS)
    assert {row.status for row in rows} == {"install", "exempt"}


def test_the_plan_on_main_installs_five_scanners_and_exempts_snyk_code(script):
    rows = script.plan()
    pins = tool_versions()

    got = {
        r.scanner: (r.runtime, r.route, r.version, r.pin_source, r.status) for r in rows
    }
    assert got == {
        "betterleaks": (
            "pinned_binary",
            "release_asset",
            pins["betterleaks"],
            "release_pin",
            "install",
        ),
        "ferret-scan": (
            "pypi_package",
            "ash_environment",
            "2.5.3",
            "interim",
            "install",
        ),
        "guarddog": ("uv_python", "uv_tool", "3.2.0", "pypi_pin", "install"),
        "hadolint": (
            "pinned_binary",
            "release_asset",
            pins["hadolint"],
            "release_pin",
            "install",
        ),
        "snyk-code": ("user_installed_cli", "none", "", "", "exempt"),
        "trivy-repo": (
            "pinned_binary",
            "release_asset",
            pins["trivy"],
            "release_pin",
            "install",
        ),
    }
    assert _row(rows, "snyk-code").reason == script.EXEMPT["snyk-code"]


def test_hadolint_resolves_to_its_register_pin(script):
    """The control a pin lookup that returned nothing could not pass."""
    assert _row(script.plan(), "hadolint").version == "v2.15.1"


def test_the_tables_on_main_hold_what_the_plan_needs_and_nothing_else(script):
    assert set(script.EXEMPT) == {"snyk-code"}
    assert script.HELD == {}
    assert set(script.INTERIM_PINS) == {"ferret-scan"}
    assert all(reason.strip() for reason in script.EXEMPT.values())


def test_every_alpha_manifest_is_in_exactly_one_row(script, regs):
    rows = script.plan()
    alpha = sorted(m.name for m in regs.manifests if m.tier is PluginTier.ALPHA)

    assert [row.scanner for row in rows] == alpha
    assert len({row.scanner for row in rows}) == len(rows)


def test_every_install_row_has_one_exact_version(script):
    exact = re.compile(r"v?\d+(\.\d+)*")

    for row in script.plan():
        if row.status == "install":
            assert exact.fullmatch(row.version), row
            assert row.pin_source, row
        else:
            assert row.version == "" and row.pin_source == "", row


# ---------------------------------------------------------------------------
# The arguments
# ---------------------------------------------------------------------------


def _expected_args():
    def module(package):
        return f"{PLUGINS}.ash_{package}_plugins"

    return [
        *[
            part
            for package in ("betterleaks", "ferret", "guarddog", "hadolint", "trivy")
            for part in (
                "--config-overrides",
                f"ash_plugin_modules+=[{module(package)}]",
            )
        ],
        "--tool",
        "betterleaks",
        "--tool",
        "ferret-scan",
        "--tool",
        "guarddog",
        "--tool",
        "hadolint",
        "--tool",
        "trivy-repo",
        "--config-overrides",
        "scanners.ferret-scan.options.tool_version===2.5.3",
        "--config-overrides",
        "scanners.guarddog.options.tool_version===3.2.0",
    ]


def test_the_arguments_on_main_load_each_module_once_name_each_tool_and_pin_the_python_ones(
    script,
):
    assert script.install_args(script.plan()) == _expected_args()


def test_every_tool_the_arguments_name_is_an_opt_in_scanner(script):
    args = script.install_args(script.plan())
    tools = [b for a, b in zip(args, args[1:]) if a == "--tool"]

    assert tools
    assert set(tools) <= set(opt_in_scanner_modules())
    assert "snyk-code" not in tools


def _problems_in():
    return _load("_ash_module_load_test", MODULE_LOAD_TEST).problems_in


def _command(args):
    return "ash dependencies install " + " ".join(shlex.quote(a) for a in args)


def test_the_arguments_pass_the_module_load_gate(script):
    problems_in = _problems_in()

    assert problems_in(_command(script.install_args(script.plan()))) == []


def test_the_module_load_gate_turns_red_when_one_module_is_dropped(script):
    problems_in = _problems_in()
    args = script.install_args(script.plan())
    index = next(i for i, a in enumerate(args) if "ash_hadolint_plugins" in a)
    without = args[: index - 1] + args[index + 1 :]

    found = problems_in(_command(without))

    assert len(found) == 1
    assert "--tool hadolint without" in found[0]


def test_a_python_tool_is_pinned_by_a_version_override_and_a_binary_is_not(script):
    args = script.install_args(script.plan())
    overrides = [a for a in args if ".options.tool_version===" in a]

    assert overrides == [
        "scanners.ferret-scan.options.tool_version===2.5.3",
        "scanners.guarddog.options.tool_version===3.2.0",
    ]


# ---------------------------------------------------------------------------
# Planted controls: each must be refused, and the control beside it accepted
# ---------------------------------------------------------------------------


def _cli(regs, name, declared=(), programs=None):
    return _plant(
        regs,
        _manifest(name),
        _facets(
            name, opsf.RuntimeKind.USER_INSTALLED_CLI, programs=programs or (name,)
        ),
        declared=declared,
    )


def test_an_alpha_cli_that_declares_no_install_command_needs_an_exemption(script, regs):
    planted = _cli(regs, "planted-cli")

    with pytest.raises(script.PlanError, match=r"planted-cli: no ASH install path"):
        script.plan(planted)

    rows = script.plan(
        planted, exempt={**script.EXEMPT, "planted-cli": "the user installs it"}
    )
    assert _row(rows, "planted-cli").status == "exempt"
    assert _row(rows, "planted-cli").reason == "the user installs it"


def test_an_alpha_cli_that_declares_install_commands_and_a_pin_constant_installs(
    script, regs, monkeypatch
):
    _module(monkeypatch, "planted_installer", VERSION="v0.23.0")
    planted = dataclasses.replace(
        _cli(regs, "planted-cli", declared=("linux/amd64", "linux/arm64")),
        module_pins={"planted-cli": "planted_installer:VERSION"},
    )

    row = _row(script.plan(planted), "planted-cli")

    assert (row.runtime, row.route, row.version, row.status) == (
        "user_installed_cli",
        "declared_commands",
        "0.23.0",
        "install",
    )
    assert row.pin_source == "module_constant"
    assert script.install_args([row]) == [
        "--config-overrides",
        "ash_plugin_modules+=[planted_plugins.planted_cli]",
        "--tool",
        "planted-cli",
    ]


def test_an_alpha_cli_that_declares_install_commands_but_no_pin_is_unpinned(
    script, regs
):
    planted = _cli(regs, "planted-cli", declared=("linux/amd64",))

    with pytest.raises(script.PlanError, match=r"planted-cli: unpinned"):
        script.plan(planted)


def test_an_alpha_cli_that_declares_nothing_for_linux_amd64_is_refused_by_platform(
    script, regs, monkeypatch
):
    _module(monkeypatch, "planted_installer", VERSION="1.0.0")
    planted = dataclasses.replace(
        _cli(regs, "planted-cli", declared=("darwin/arm64",)),
        module_pins={"planted-cli": "planted_installer:VERSION"},
    )

    with pytest.raises(script.PlanError, match=r"planted-cli.*linux/amd64"):
        script.plan(planted)


def _binary(regs, name="planted-binary", provisionable=opsf.PLATFORMS_ALL, pinned=True):
    planted = _plant(
        regs,
        _manifest(name),
        _facets(
            name,
            opsf.RuntimeKind.PINNED_BINARY,
            key=name,
            provisionable=provisionable,
        ),
    )
    if pinned:
        planted = dataclasses.replace(
            planted, release_pins={**planted.release_pins, name: "v9.9.9"}
        )
    return planted


def test_a_pinned_binary_with_no_pin_is_refused_and_one_with_a_pin_installs(
    script, regs
):
    with pytest.raises(script.PlanError, match=r"planted-binary: no release pin"):
        script.plan(_binary(regs, pinned=False))

    row = _row(script.plan(_binary(regs)), "planted-binary")
    assert (row.route, row.version, row.status) == (
        "release_asset",
        "v9.9.9",
        "install",
    )


def test_a_pinned_binary_with_no_linux_amd64_asset_is_refused_naming_the_platform(
    script, regs
):
    planted = _binary(regs, provisionable=("darwin/arm64", "windows/amd64"))

    with pytest.raises(script.PlanError, match=r"planted-binary.*linux/amd64"):
        script.plan(planted)


def _python(regs, specifier, **replace):
    pin = PypiPin(distribution="planted-py", specifier=specifier, runtime="uv-tool")
    return _plant(
        regs,
        _manifest("planted-py", Provisioning(pypi_pins=(pin,))),
        _facets("planted-py", opsf.RuntimeKind.UV_PYTHON),
        **replace,
    )


def test_a_python_tool_with_only_a_range_is_unpinned_and_with_an_exact_pin_installs(
    script, regs
):
    with pytest.raises(script.PlanError, match=r"planted-py: unpinned"):
        script.plan(_python(regs, ">=1.0,<2.0"))

    row = _row(script.plan(_python(regs, "==1.4.2")), "planted-py")
    assert (row.route, row.version, row.pin_source) == ("uv_tool", "1.4.2", "pypi_pin")


def test_two_pins_that_disagree_are_refused_naming_the_scanner(script, regs):
    planted = _python(regs, "==1.4.2", distribution_pins={"planted-py": "v1.4.3"})

    with pytest.raises(script.PlanError, match=r"planted-py: its pins disagree"):
        script.plan(planted)

    agreeing = _python(regs, "==1.4.2", distribution_pins={"planted-py": "v1.4.2"})
    assert _row(script.plan(agreeing), "planted-py").version == "1.4.2"


def test_an_in_process_alpha_scanner_has_nothing_to_install(script, regs):
    planted = _plant(
        regs,
        _manifest("planted-inline"),
        _facets("planted-inline", opsf.RuntimeKind.IN_PROCESS),
    )

    row = _row(script.plan(planted), "planted-inline")

    assert row.status == "nothing"
    assert row.version == ""
    assert "planted-inline" not in script.install_args(script.plan(planted))


# ---------------------------------------------------------------------------
# The tables: each row has to keep describing the registers
# ---------------------------------------------------------------------------


def test_an_exemption_that_names_no_manifest_is_refused(script):
    with pytest.raises(script.PlanError, match=r"EXEMPT names ghost-scanner"):
        script.plan(exempt={**script.EXEMPT, "ghost-scanner": "no such scanner"})


def test_an_exemption_for_a_builtin_scanner_is_refused(script):
    with pytest.raises(script.PlanError, match=r"EXEMPT names gitleaks"):
        script.plan(exempt={**script.EXEMPT, "gitleaks": "not an alpha scanner"})


def test_an_exemption_for_a_scanner_the_plan_could_install_is_refused(script):
    with pytest.raises(script.PlanError, match=r"EXEMPT names hadolint.*could install"):
        script.plan(exempt={**script.EXEMPT, "hadolint": "left out by hand"})


@pytest.mark.parametrize("reason", ["", "   ", "\n"])
def test_an_exemption_without_a_reason_is_refused(script, reason):
    with pytest.raises(
        script.PlanError, match=r"EXEMPT row for snyk-code gives no reason"
    ):
        script.plan(exempt={"snyk-code": reason})


def test_an_interim_pin_for_a_scanner_with_a_pypi_pin_is_refused(script):
    interim = {**script.INTERIM_PINS, "guarddog": script.INTERIM_PINS["ferret-scan"]}

    with pytest.raises(script.PlanError, match=r"INTERIM_PINS names guarddog"):
        script.plan(interim=interim)


def test_an_interim_pin_for_a_scanner_with_a_distribution_entry_is_refused(
    script, regs, monkeypatch
):
    _module(monkeypatch, "planted_pins", INTERIM="1.0.0")
    planted = _python(regs, ">=1.0", distribution_pins={"planted-py": "v1.0.0"})
    interim = {**script.INTERIM_PINS, "planted-py": "planted_pins:INTERIM"}

    with pytest.raises(script.PlanError, match=r"INTERIM_PINS names planted-py"):
        script.plan(planted, interim=interim)


def test_an_interim_pin_for_a_scanner_with_no_manifest_is_refused(script):
    with pytest.raises(script.PlanError, match=r"INTERIM_PINS names ghost-scanner"):
        script.plan(interim={**script.INTERIM_PINS, "ghost-scanner": "x:Y"})


def test_an_interim_pin_for_a_binary_is_refused(script):
    interim = {**script.INTERIM_PINS, "hadolint": script.INTERIM_PINS["ferret-scan"]}

    with pytest.raises(script.PlanError, match=r"INTERIM_PINS names hadolint"):
        script.plan(interim=interim)


def test_an_interim_pin_is_read_when_the_plan_is_made(script, regs, monkeypatch):
    _module(monkeypatch, "planted_pins", INTERIM="3.1.4")
    planted = _python(regs, ">=1.0")
    interim = {**script.INTERIM_PINS, "planted-py": "planted_pins:INTERIM"}

    assert _row(script.plan(planted, interim=interim), "planted-py").version == "3.1.4"

    sys.modules["planted_pins"].INTERIM = "3.1.5"
    assert _row(script.plan(planted, interim=interim), "planted-py").version == "3.1.5"


def test_an_interim_reference_that_cannot_be_read_is_a_plan_error(script):
    broken = {"ferret-scan": "automated_security_helper.no_such_module:NOTHING"}

    with pytest.raises(script.PlanError, match=r"ferret-scan"):
        script.plan(interim=broken)


def test_the_ferret_scan_interim_reads_the_plugins_recommended_version(script):
    from automated_security_helper.plugin_modules.ash_ferret_plugins import (
        ferret_scanner,
    )

    assert _row(script.plan(), "ferret-scan").version == (
        ferret_scanner.RECOMMENDED_VERSION
    )
    assert ferret_scanner.RECOMMENDED_VERSION == "2.5.3"


# The class held for a decision: distinct from an exemption, empty on main.


def test_a_scanner_held_for_a_decision_is_listed_and_not_installed(script):
    rows = script.plan(held={"hadolint": "held until the maintainer decides"})

    row = _row(rows, "hadolint")
    assert row.status == "held"
    assert row.reason == "held until the maintainer decides"
    args = script.install_args(rows)
    assert "hadolint" not in args
    assert not any("ash_hadolint_plugins" in a for a in args)


@pytest.mark.parametrize(
    "held,message",
    [
        ({"ghost-scanner": "why"}, r"HELD names ghost-scanner"),
        ({"hadolint": ""}, r"HELD row for hadolint gives no reason"),
        ({"hadolint": "  "}, r"HELD row for hadolint gives no reason"),
        ({"gitleaks": "why"}, r"HELD names gitleaks"),
        ({"snyk-code": "why"}, r"snyk-code is in both EXEMPT and HELD"),
    ],
)
def test_a_held_row_that_no_longer_describes_the_registers_is_refused(
    script, held, message
):
    with pytest.raises(script.PlanError, match=message):
        script.plan(held=held)


def test_a_held_scanner_the_plan_could_not_install_anyway_belongs_in_the_exemptions(
    script, regs
):
    planted = _cli(regs, "planted-cli")

    with pytest.raises(script.PlanError, match=r"HELD names planted-cli.*EXEMPT"):
        script.plan(planted, held={"planted-cli": "waiting on a decision"})


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_an_error_exits_2_names_the_script_and_prints_nothing_on_stdout(
    script, capsys, monkeypatch
):
    monkeypatch.setattr(script, "EXEMPT", {})

    code = script.main(["plan"])

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err.startswith("alpha-doctest-installs: ")
    assert "snyk-code" in captured.err


def test_plan_prints_one_tab_separated_row_per_scanner_under_a_header(script, capsys):
    assert script.main(["plan"]) == 0

    lines = capsys.readouterr().out.rstrip("\n").split("\n")
    assert lines[0].split("\t") == [
        "scanner",
        "module",
        "runtime",
        "route",
        "version",
        "pin_source",
        "status",
        "reason",
    ]
    assert [line.split("\t")[0] for line in lines[1:]] == list(MAIN_SCANNERS)
    assert all(len(line.split("\t")) == 8 for line in lines)
    guarddog = next(line for line in lines if line.startswith("guarddog\t"))
    assert guarddog.split("\t")[1:7] == [
        f"{PLUGINS}.ash_guarddog_plugins",
        "uv_python",
        "uv_tool",
        "3.2.0",
        "pypi_pin",
        "install",
    ]


def test_plan_json_is_a_list_of_the_same_rows(script, capsys):
    assert script.main(["plan", "--json"]) == 0

    rows = json.loads(capsys.readouterr().out)
    assert [row["scanner"] for row in rows] == list(MAIN_SCANNERS)
    assert set(rows[0]) == {
        "scanner",
        "module",
        "runtime",
        "route",
        "version",
        "pin_source",
        "status",
        "reason",
    }
    assert {row["scanner"]: row["status"] for row in rows}["snyk-code"] == "exempt"


def test_args_prints_one_token_per_line(script, capsys):
    assert script.main(["args"]) == 0

    assert capsys.readouterr().out.rstrip("\n").split("\n") == _expected_args()


def test_a_plan_that_installs_nothing_is_an_error_for_args(script, capsys, monkeypatch):
    held_all = {name: "held" for name in MAIN_SCANNERS if name != "snyk-code"}
    monkeypatch.setattr(script, "HELD", held_all)

    code = script.main(["args"])

    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert "installs no scanner" in captured.err


def test_json_belongs_to_plan_only(script, capsys):
    with pytest.raises(SystemExit) as raised:
        script.main(["args", "--json"])

    assert raised.value.code == 2
    assert capsys.readouterr().out == ""


def test_a_pin_module_that_raises_when_imported_exits_2_with_the_scripts_message(
    script, monkeypatch, capsys, tmp_path
):
    (tmp_path / "ash_planted_raising_pin.py").write_text(
        'raise RuntimeError("raised while importing")\n', encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        script, "INTERIM_PINS", {"ferret-scan": "ash_planted_raising_pin:VERSION"}
    )

    code = script.main(["plan"])

    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert captured.err.startswith("alpha-doctest-installs: ")
    assert "ferret-scan" in captured.err and "raised while importing" in captured.err


# ---------------------------------------------------------------------------
# verify, against planted directories and planted probes
# ---------------------------------------------------------------------------


_WINDOWS_EXTENSIONS = (".com", ".exe", ".bat", ".cmd")


def _windows_which(program, path=None):
    """``shutil.which`` as Windows answers it, run on any machine.

    A name matches only with one of the PATHEXT extensions on it, or when one is added:
    a file with no extension is never a program there (CPython 3.11 to 3.14 under the
    default X_OK mode).
    """
    names = (
        [program]
        if program.lower().endswith(_WINDOWS_EXTENSIONS)
        else [program + extension for extension in _WINDOWS_EXTENSIONS]
    )
    for directory in (path or "").split(os.pathsep):
        for name in names:
            candidate = Path(directory) / name
            if candidate.is_file():
                return str(candidate)
    return None


@pytest.fixture(params=[False, True], ids=["this-machines-lookup", "windows-lookup"])
def windows(request):
    """Whether a program is found the way Windows finds it, by a PATHEXT extension."""
    return request.param


def test_the_windows_lookup_finds_a_name_with_an_extension_and_not_a_bare_one(tmp_path):
    directory = tmp_path / "bin"
    directory.mkdir()
    (directory / "bare").write_text("", encoding="utf-8")
    (directory / "extended.exe").write_text("", encoding="utf-8")
    extended = str(directory / "extended.exe")

    assert _windows_which("bare", path=str(directory)) is None
    assert _windows_which("extended", path=str(directory)) == extended
    assert _windows_which("extended.exe", path=str(directory)) == extended
    assert _windows_which("missing", path=str(directory)) is None


def _bin(tmp_path, *names, windows=False):
    """A directory holding one executable per name.

    Windows finds a program only by a PATHEXT extension, so for its lookup, and on
    Windows itself, each file carries ``.exe``; on other systems the name is bare.
    """
    suffix = ".exe" if windows or os.name == "nt" else ""
    directory = tmp_path / "bin"
    directory.mkdir(exist_ok=True)
    for name in names:
        path = directory / f"{name}{suffix}"
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
    return directory


def _probes(
    script,
    *,
    versions=None,
    uv="guarddog v3.2.0\n- guarddog\n",
    distributions=None,
    windows=False,
):
    versions = {
        "betterleaks": "betterleaks version 1.10.1",
        "hadolint": "Haskell Dockerfile Linter 2.15.1",
        "trivy": "Version: 0.76.2",
        **(versions or {}),
    }
    distributions = {"ferret-scan": "2.5.3", **(distributions or {})}
    return script.Probes(
        which=_windows_which if windows else shutil.which,
        version_text=lambda executable: versions.get(Path(executable).stem, ""),
        uv_tool_list=lambda: uv,
        distribution_version=distributions.get,
    )


_ALL_TOOLS = ("betterleaks", "ferret-scan", "guarddog", "hadolint", "trivy")


def test_verify_accepts_what_the_plan_says_is_installed(script, tmp_path, windows):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)

    problems = script.verify(
        script.plan(), path=str(directory), probes=_probes(script, windows=windows)
    )

    assert problems == []


def test_verify_names_a_tool_that_is_not_on_the_path(script, tmp_path, windows):
    directory = _bin(
        tmp_path, *(t for t in _ALL_TOOLS if t != "hadolint"), windows=windows
    )

    problems = script.verify(
        script.plan(), path=str(directory), probes=_probes(script, windows=windows)
    )

    assert len(problems) == 1
    assert "hadolint" in problems[0] and "not on the session PATH" in problems[0]


def test_verify_names_a_binary_that_reports_another_version(script, tmp_path, windows):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)

    problems = script.verify(
        script.plan(),
        path=str(directory),
        probes=_probes(
            script, versions={"betterleaks": "betterleaks 1.10.0"}, windows=windows
        ),
    )

    assert len(problems) == 1
    assert "betterleaks" in problems[0] and "1.10.1" in problems[0]


@pytest.mark.parametrize(
    "reported",
    ["trivy 0.76.20", "trivy 10.76.2", "trivy 0.76.2.1", "trivy 0.76.2-rc1"],
)
def test_a_version_found_inside_another_is_not_the_pin(
    script, tmp_path, windows, reported
):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)

    problems = script.verify(
        script.plan(),
        path=str(directory),
        probes=_probes(script, versions={"trivy": reported}, windows=windows),
    )

    assert [p for p in problems if "trivy" in p and reported in p], reported


def test_verify_names_a_uv_tool_the_tool_list_does_not_show_at_the_pin(
    script, tmp_path, windows
):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)

    for listing in ("", "guarddog v3.1.0\n- guarddog\n", "other-tool v3.2.0\n"):
        problems = script.verify(
            script.plan(),
            path=str(directory),
            probes=_probes(script, uv=listing, windows=windows),
        )

        assert [p for p in problems if "guarddog" in p and "uv tool list" in p], listing


def test_verify_names_a_python_package_at_another_version_or_not_installed(
    script, tmp_path, windows
):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)

    for distributions in ({"ferret-scan": "2.5.2"}, {"ferret-scan": None}):
        problems = script.verify(
            script.plan(),
            path=str(directory),
            probes=_probes(script, distributions=distributions, windows=windows),
        )

        assert [p for p in problems if "ferret-scan" in p and "the installed" in p], (
            distributions
        )


def test_verify_checks_only_what_the_plan_installs(script, tmp_path, windows):
    directory = _bin(
        tmp_path, *(t for t in _ALL_TOOLS if t != "hadolint"), windows=windows
    )
    rows = script.plan(held={"hadolint": "held"})

    problems = script.verify(
        rows, path=str(directory), probes=_probes(script, windows=windows)
    )

    assert problems == []


def test_verify_searches_only_the_path_it_is_given(script, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    problems = script.verify(script.plan(), path=str(empty), probes=_probes(script))

    assert {p.split(":")[0] for p in problems} >= {
        "betterleaks",
        "hadolint",
        "trivy-repo",
        "guarddog",
        "ferret-scan",
    }


def test_the_session_path_comes_from_the_docs_runner(script):
    module = script.docs_runner_module()

    assert callable(module.session_path)
    assert Path(module.__file__).name == "docs_runner.py"


def test_verify_exits_1_on_a_problem_and_prints_it_on_stderr_only(
    script, monkeypatch, capsys
):
    monkeypatch.setattr(script, "session_path", lambda: "/nonexistent-bin")
    monkeypatch.setattr(script, "default_probes", lambda: _probes(script))

    code = script.main(["verify"])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("alpha-doctest-installs: ")


def test_verify_prints_what_it_found_and_exits_0_when_everything_resolves(
    script, tmp_path, monkeypatch, capsys, windows
):
    directory = _bin(tmp_path, *_ALL_TOOLS, windows=windows)
    monkeypatch.setattr(script, "session_path", lambda: str(directory))
    monkeypatch.setattr(
        script, "default_probes", lambda: _probes(script, windows=windows)
    )

    code = script.main(["verify"])

    out = capsys.readouterr().out
    assert code == 0
    assert out.count("verified ") == 5
    assert "snyk-code" not in out


# ---------------------------------------------------------------------------
# The script's own text
# ---------------------------------------------------------------------------


def test_the_script_names_no_license_and_no_review_in_its_text():
    text = SCRIPT.read_text(encoding="utf-8").lower()

    assert not re.search(r"licen[sc]", text)
    assert not re.search(r"review", text)


def test_the_script_never_writes_where_it_reads_pins():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "THIRD_PARTY_LICENSES" not in text
    assert "open(" not in text and ".write_text(" not in text
