"""The image's Python scanners are installed at exactly their license entries' versions.

The Dockerfile pins bandit, checkov and semgrep by passing the output of
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
import re
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"
# The command the Dockerfile runs, spelled with the CLI's canonical name so the
# match follows a rename instead of silently finding no install step.
DEPS_INSTALL = f"{CANONICAL_CLI_NAME} dependencies install"

# Every third-party entry installed from PyPI, which is to say by `uv tool install`.
PYTHON_TOOLS = sorted(
    tool for tool, entry in THIRD_PARTY_LICENSES.items() if entry.distribution
)


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
        requirement = next(a for a in argv[start:] if not a.startswith("-"))
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
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.find_executable",
        lambda cmd: f"/usr/bin/{cmd}",
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
                *extra_args,
            ],
        )
        assert result.exit_code == 0, result.output
        return _uv_tool_install_specs(ran)

    return invoke


class TestTheOverridesReachTheInstallCommand:
    def test_the_python_tools_are_bandit_checkov_and_semgrep(self):
        # A guard on the fixture: if the table stops naming them, the tests below
        # would check nothing about the tools the image actually ships.
        assert {"bandit", "checkov", "semgrep"} <= set(PYTHON_TOOLS)

    def test_each_tool_is_installed_at_exactly_its_license_entry(
        self, recorded_install
    ):
        specs = recorded_install(
            installer.uv_tool_pins(installer.default_package_root())
        )
        for tool in PYTHON_TOOLS:
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
        for tool in PYTHON_TOOLS:
            entry = THIRD_PARTY_LICENSES[tool]
            assert not specs[entry.distribution].endswith(
                "==" + entry.version.lstrip("v")
            ), specs[entry.distribution]

    def test_a_single_override_pins_only_its_tool(self, recorded_install):
        specs = recorded_install(
            ["--config-overrides", "scanners.semgrep.options.tool_version===1.2.3"]
        )
        assert specs["semgrep"] == "semgrep==1.2.3"
        assert not specs["bandit"].endswith(
            "==" + THIRD_PARTY_LICENSES["bandit"].version.lstrip("v")
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

    def test_no_other_step_installs_a_python_tool(self):
        """A bare `uv tool install semgrep` or `pip install checkov` would float."""
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
