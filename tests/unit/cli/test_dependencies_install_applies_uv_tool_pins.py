"""The image's Python scanners are installed at exactly their license entries' versions.

The Dockerfile pins bandit and checkov by passing the output of
``install-pinned-tool --uv-tool-pins`` (``--config-overrides
scanners.<tool>.options.tool_version===<version>``) to ``ashx dependencies install``.
The overrides reached the resolved ``AshConfig``, but ``ashx dependencies install``
built every plugin from its context alone, without its section of that config, so
each scanner fell back to its own default range. The image then installed whatever
PyPI had that day: semgrep 1.180.0 against a license entry for v1.179.0, which the
in-image license gate (``install-pinned-tool --licenses-only``) refused, failing
every container build.

``TestTheOverridesReachTheInstallCommand`` drives the real command with the real
plugins and the installer's real output, and records the ``uv tool install`` it
would run. ``TestTheDockerfileInstallsOnlyThroughThePins`` reads the Dockerfile and
fails if any step there installs one of these tools without the pins.
"""

import importlib.util
import platform
import re
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GUARDDOG_DEFAULT_VERSION_CONSTRAINT,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"
# The command the Dockerfile runs, spelled with the CLI's canonical name so the
# match follows a rename instead of silently finding no install step.
DEPS_INSTALL = f"{CANONICAL_CLI_NAME} dependencies install"
GUARDDOG_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_guarddog_plugins"

# Every third-party entry installed from PyPI, which is to say by `uv tool install`.
PYTHON_TOOLS = sorted(
    tool for tool, entry in THIRD_PARTY_LICENSES.items() if entry.distribution
)

# Distributions `ash dependencies install` does not install on this host because
# their scanner cannot run here: GuardDog on Windows (see
# GuardDogScanner.unsupported_platform_reason, checked against this set below).
NOT_INSTALLABLE_HERE = {"guarddog"} if platform.system().lower() == "windows" else set()
INSTALLED_HERE = [
    tool
    for tool in PYTHON_TOOLS
    if THIRD_PARTY_LICENSES[tool].distribution not in NOT_INSTALLABLE_HERE
]


# The one scanner whose install argv carries an exact pin WITHOUT the Dockerfile's
# overrides, and why (root cause, read at the bytes):
#   1. guarddog_scanner.py:173-177 declares GUARDDOG_DEFAULT_VERSION_CONSTRAINT =
#      "==3.2.0", exact on purpose: the JSON the parser reads is not a versioned
#      format and 3.x reshaped it between minor releases.
#   2. guarddog_scanner.py:879-882 `_get_tool_version_constraint` returns that
#      constant whenever `options.tool_version` is unset, which is the unpinned run
#      these tests drive.
#   3. The install command takes that constraint from the scanner, so the recorded
#      `uv tool install` argv ends in `guarddog==3.2.0`.
#   4. tool_downloads.py:1187-1199 records the same version (v3.2.0) in the license
#      entry, so the pin and the license gate agree.
# The expected pin is derived from that license entry, not from the constant under
# test, and the constant must equal it. The exempt set is this literal, so a second
# exemption needs an edit here, and the negative control below pins that.
EXACT_PIN_EXEMPT_TOOLS = frozenset({"guarddog"})
EXPECTED_EXACT_PINS = {
    tool: "==" + THIRD_PARTY_LICENSES[tool].version.lstrip("v")
    for tool in EXACT_PIN_EXEMPT_TOOLS
}
SHIPPED_EXACT_DEFAULTS = {"guarddog": GUARDDOG_DEFAULT_VERSION_CONSTRAINT}


def _exact_pins_without_a_shipped_default(argvs):
    """The `uv tool install` argvs that carry an exact pin the license entries do not allow.

    An exact `==` is allowed only for the exempt tools, and only at the value their
    license entry records.
    """
    assert set(SHIPPED_EXACT_DEFAULTS) == EXACT_PIN_EXEMPT_TOOLS, (
        f"exact-pin exemptions {sorted(SHIPPED_EXACT_DEFAULTS)} differ from "
        f"{sorted(EXACT_PIN_EXEMPT_TOOLS)}"
    )
    allowed = {}
    for tool in EXACT_PIN_EXEMPT_TOOLS:
        default = SHIPPED_EXACT_DEFAULTS[tool]
        expected = EXPECTED_EXACT_PINS[tool]
        assert default == expected, (
            f"{tool} ships {default!r} but its license entry records "
            f"{THIRD_PARTY_LICENSES[tool].version} ({expected!r})"
        )
        allowed[THIRD_PARTY_LICENSES[tool].distribution] = expected
    offenders = []
    for argv in argvs:
        for arg in argv:
            bare = re.sub(r"\[[^\]]*\]", "", arg)
            if "==" not in bare:
                continue
            distribution = bare.split("==", 1)[0]
            if allowed.get(distribution) is None or bare != (
                distribution + allowed[distribution]
            ):
                offenders.append(argv)
                break
    return offenders


def _load_installer():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_installer()


def _dockerfile_run_instructions() -> "list[str]":
    """Each RUN instruction with its continuation lines joined, comments dropped."""
    lines = [
        line
        for line in DOCKERFILE.read_text().splitlines()
        if not line.lstrip().startswith("#")
    ]
    instructions: "list[str]" = []
    current: "list[str]" = []
    for line in lines:
        current.append(line.rstrip().rstrip("\\"))
        if not line.rstrip().endswith("\\"):
            joined = " ".join(part.strip() for part in current).strip()
            if joined.startswith("RUN "):
                instructions.append(joined)
            current = []
    return instructions


def _uv_tool_install_specs(ran: "list[list[str]]") -> "dict[str, str]":
    """Package name to the requirement each recorded `uv tool install` names."""
    specs: "dict[str, str]" = {}
    for cmd in ran:
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if argv[:3] != ["uv", "tool", "install"] and argv[1:4] != [
            "tool",
            "install",
        ]:
            continue
        start = 3 if argv[0] == "uv" else 4
        # `--python <request>` (GuardDog pins its interpreter) takes a value; the
        # requirement is the first argument that is neither an option nor its value.
        requirement = None
        skip_value = False
        for arg in argv[start:]:
            if skip_value:
                skip_value = False
            elif arg in ("--python", "--with"):
                skip_value = True
            elif not arg.startswith("-"):
                requirement = arg
                break
        assert requirement, f"no requirement in {argv}"
        name = re.match(r"[A-Za-z0-9_.-]+", requirement).group(0).lower()
        specs[name] = requirement
    return specs


@pytest.fixture
def recorded_install(tmp_path, monkeypatch):
    """Run `ashx dependencies install` for the Python tools; return what it would run."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    # The version probe runs `uv` per scanner and says nothing about what gets
    # installed; the install command is what is under test.
    monkeypatch.setattr(UVToolMixin, "_get_uv_tool_version", lambda *_a, **_k: None)
    ran: "list" = []
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.run_command",
        lambda cmd, shell=False: ran.append(cmd) or 0,
    )
    # The install looks a tool up as a scan of the source tree does, scoped to
    # the tree's root; the fake takes that root and says every tool is on PATH.
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.find_executable_for_scan",
        lambda cmd, root: f"/usr/bin/{cmd}",
    )

    def invoke(extra_args: "list[str]"):
        tool_args = [arg for tool in PYTHON_TOOLS for arg in ("--tool", tool)]
        result = CliRunner().invoke(
            dependencies_app,
            [
                "--plugin-type",
                "scanner",
                "--bin-path",
                str(tmp_path / "bin"),
                *tool_args,
                # guarddog is an alpha scanner: `ash dependencies install` knows
                # it only once its module is loaded. Without this the run depended
                # on an earlier test in the same worker having imported that module
                # (plugin registration happens at import, once per process), and
                # failed with "Unknown tool(s): guarddog" wherever none had.
                "--config-overrides",
                f"ash_plugin_modules+=[{GUARDDOG_PLUGIN_MODULE}]",
                *extra_args,
            ],
        )
        assert result.exit_code == 0, result.output
        return _uv_tool_install_specs(ran)

    return invoke


class TestTheOverridesReachTheInstallCommand:
    def test_the_python_tools_are_bandit_and_checkov(self):
        # A guard on the fixture: if the table stops naming them, the tests below
        # would check nothing about the tools the image actually ships.
        assert {"bandit", "checkov"} <= set(PYTHON_TOOLS)

    def test_each_tool_is_installed_at_exactly_its_license_entry(
        self, recorded_install
    ):
        specs = recorded_install(
            installer.uv_tool_pins(installer.default_package_root())
        )
        for distribution in NOT_INSTALLABLE_HERE:
            assert distribution not in specs, (
                f"{distribution} cannot be installed on this platform, so the "
                f"installer must not try: {specs}"
            )
        for tool in INSTALLED_HERE:
            entry = THIRD_PARTY_LICENSES[tool]
            assert entry.distribution in specs, (
                f"no `uv tool install` was recorded for {entry.distribution}: {specs}"
            )
            requirement = specs[entry.distribution]
            pinned = "==" + entry.version.lstrip("v")
            assert requirement.endswith(pinned), (
                f"{tool} is installed as {requirement!r}; its license entry records "
                f"{entry.version}, so the install must end in {pinned!r}"
            )
            # Exactly one specifier, `==X`, and nothing that widens it. Extras
            # (`bandit[sarif,toml]`) carry a comma of their own, so they go first.
            specifier = re.sub(r"\[[^\]]*\]", "", requirement)[
                len(entry.distribution) :
            ]
            assert specifier == pinned, requirement

    def test_without_the_pins_each_tool_gets_its_own_range(self, recorded_install):
        """The control: the same run without the overrides is NOT pinned.

        If this ever starts producing exact pins, the test above no longer shows the
        overrides doing anything, and the Dockerfile's reliance on them is untested.
        """
        specs = recorded_install([])
        ranged = 0
        for tool in INSTALLED_HERE:
            entry = THIRD_PARTY_LICENSES[tool]
            pinned = "==" + entry.version.lstrip("v")
            requirement = specs[entry.distribution]
            if "==" in re.sub(r"\[[^\]]*\]", "", requirement):
                # A scanner whose own default is already an exact pin (GuardDog's
                # GUARDDOG_DEFAULT_VERSION_CONSTRAINT) needs no override, and that
                # default must then be the license entry's version.
                assert requirement.endswith(pinned), requirement
                continue
            ranged += 1
            assert not requirement.endswith(pinned), requirement
        # The control has to cover at least the tools the image pins only by override.
        assert ranged >= 3, specs

    def test_without_the_pins_no_install_argv_carries_an_exact_pin(
        self, recorded_install, monkeypatch
    ):
        """Stronger than the test above: no `==` anywhere in the unpinned argv.

        The test above only says each install does not end in its license entry's
        version, which a pin to some OTHER version would also satisfy. Without
        overrides the scanners' own ranges must be installed, so no `uv tool
        install` argument may name an exact version at all.
        """
        argvs: "list[list[str]]" = []
        real = _uv_tool_install_specs

        def capture(ran):
            argvs.extend(
                shlex.split(cmd) if isinstance(cmd, str) else list(cmd) for cmd in ran
            )
            return real(ran)

        monkeypatch.setattr(f"{__name__}._uv_tool_install_specs", capture, raising=True)
        specs = recorded_install([])
        installs = [
            argv
            for argv in argvs
            if argv[:3] == ["uv", "tool", "install"] or argv[1:4] == ["tool", "install"]
        ]
        for tool in INSTALLED_HERE:
            assert THIRD_PARTY_LICENSES[tool].distribution in specs, specs
        assert installs, "no `uv tool install` was recorded"
        # The universe is the tools WITHOUT a shipped exact default constraint. A
        # tool that ships one (GuardDog's GUARDDOG_DEFAULT_VERSION_CONSTRAINT) is
        # exempt only while that default equals its license entry's version, so the
        # exemption cannot drift from the entry.
        offenders = _exact_pins_without_a_shipped_default(installs)
        assert not offenders, offenders

    def test_the_exact_pin_check_still_trips_on_a_spurious_pin(self):
        """Negative control: the exemption above must not swallow a real defect."""
        entry = THIRD_PARTY_LICENSES["guarddog"]
        matching = [
            "uv",
            "tool",
            "install",
            f"{entry.distribution}=={entry.version.lstrip('v')}",
        ]
        assert _exact_pins_without_a_shipped_default([matching]) == []
        # A tool with no shipped default that gains an exact pin.
        spurious = [
            "uv",
            "tool",
            "install",
            "--python",
            ">=3.10,<3.14",
            "somescanner==9.9.9",
        ]
        assert _exact_pins_without_a_shipped_default([spurious]) == [spurious]
        # A ranged tool pinned exactly, even at its own license version.
        bandit = THIRD_PARTY_LICENSES["bandit"]
        ranged_pin = [
            "uv",
            "tool",
            "install",
            f"{bandit.distribution}=={bandit.version.lstrip('v')}",
        ]
        assert _exact_pins_without_a_shipped_default([ranged_pin]) == [ranged_pin]
        # A tool with a shipped default pinned to some OTHER version.
        drifted = ["uv", "tool", "install", f"{entry.distribution}==0.0.1"]
        assert _exact_pins_without_a_shipped_default([drifted]) == [drifted]
        # The exemption is exactly one tool, at exactly the license entry's value.
        assert EXACT_PIN_EXEMPT_TOOLS == {"guarddog"}
        assert EXPECTED_EXACT_PINS == {"guarddog": "==" + entry.version.lstrip("v")}
        # A longer version that merely ends in the exempt one is not the exempt pin.
        bare_version = entry.version.lstrip("v")
        suffix = ["uv", "tool", "install", f"{entry.distribution}==1{bare_version}"]
        assert _exact_pins_without_a_shipped_default([suffix]) == [suffix]

    def test_a_single_override_pins_only_its_tool(self, recorded_install):
        specs = recorded_install(
            ["--config-overrides", "scanners.bandit.options.tool_version===1.2.3"]
        )
        # bandit installs with its declared extras; the override pins the version.
        assert specs["bandit"] == "bandit[sarif,toml]==1.2.3"
        assert not specs["checkov"].endswith(
            "==" + THIRD_PARTY_LICENSES["checkov"].version.lstrip("v")
        )


class TestTheDockerfileInstallsOnlyThroughThePins:
    def test_every_ash_dependencies_install_passes_the_pins(self):
        installs = [
            run for run in _dockerfile_run_instructions() if DEPS_INSTALL in run
        ]
        assert installs, f"the Dockerfile no longer runs `{DEPS_INSTALL}`"
        for run in installs:
            assert 'pins="$(install-pinned-tool --uv-tool-pins)" &&' in run, run
            assert re.search(re.escape(DEPS_INSTALL) + r" [^;&|]*\$\{pins\}", run), run

    def test_every_ash_dependencies_install_runs_online(self):
        """The build downloads on purpose, so the install must not inherit ASH_OFFLINE.

        ``ENV ASH_OFFLINE="${OFFLINE}"`` is YES in an ``OFFLINE=YES`` image, and under it
        ``install_pinned_tool`` refuses every download. opengrep is a bare executable
        that only ``ash dependencies install`` fetches, so the offline image failed to
        build with ``opengrep ... is not installed and ASH is offline``. The ENV stays
        (it is what the finished image runs with); each install clears it for its own
        process only.
        """
        installs = [
            run for run in _dockerfile_run_instructions() if DEPS_INSTALL in run
        ]
        assert installs, f"the Dockerfile no longer runs `{DEPS_INSTALL}`"
        for run in installs:
            assert re.search(
                r"\bASH_OFFLINE=NO\s+(?:\w+=\S+\s+)*" + re.escape(DEPS_INSTALL) + " ",
                run,
            ), run

    def test_no_other_step_installs_a_python_tool(self):
        """A bare `uv tool install bandit` or `pip install checkov` would float."""
        names = "|".join(
            re.escape(THIRD_PARTY_LICENSES[tool].distribution) for tool in PYTHON_TOOLS
        )
        floating = re.compile(
            rf"(uv\s+tool\s+install|pip3?\s+install|uv\s+pip\s+install)[^;&|]*\b({names})\b"
        )
        offenders = [
            run for run in _dockerfile_run_instructions() if floating.search(run)
        ]
        assert offenders == []

    def test_the_license_step_follows_the_pinned_install_and_covers_every_tool(self):
        runs = _dockerfile_run_instructions()
        license_steps = [i for i, run in enumerate(runs) if "--licenses-only" in run]
        install_steps = [i for i, run in enumerate(runs) if DEPS_INSTALL in run]
        python_license_step = next(
            i for i in license_steps if all(t in runs[i] for t in PYTHON_TOOLS)
        )
        assert install_steps[0] < python_license_step


@pytest.mark.parametrize("system", ["Windows", "Linux", "Darwin"])
def test_the_not_installable_set_is_the_scanners_own_rule(monkeypatch, system):
    """NOT_INSTALLABLE_HERE restates GuardDog's platform rule; hold the two equal."""
    from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
        guarddog_scanner,
    )

    monkeypatch.setattr(guarddog_scanner.platform, "system", lambda: system)
    reason = guarddog_scanner.GuardDogScanner.unsupported_platform_reason(None)
    assert (reason is not None) is (system == "Windows")
