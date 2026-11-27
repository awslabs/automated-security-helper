"""``scripts/check_platform_wheels.py`` and the workflow that runs it.

Why this file exists
--------------------
ASH installs from wheels: nothing in its install path builds a package from source on
the platforms the install page names. Whether that stays true depends on what PyPI
publishes, which changes without a commit here, and on what a new requirement drags
in. The script resolves ASH's requirements with ``uv pip compile --no-build`` for each
platform and Python version, keeps the outcome of every cell in
``scripts/platform_wheels.json`` and fails when

* a measured cell no longer matches its record,
* an alpha member has no recorded row,
* adding the alpha requirements moves a version in the base install's closure.

A second mode plants the two requirements that must break it (a package with no musl
wheels, a pin below the base closure's version) and fails when they do not.

How it is tested
----------------
Nothing here reaches a network. ``uv`` is replaced by ``FakeUv``, which answers from
planted facts, so each outcome the script reports has a test that sets the fact the
script reads: a cell that changes without a re-record, a member with no recorded row,
a clean record, a backtracked pin, a resolution that fails, and an index that cannot
be reached, which must never be recorded as a failed cell.

The unit tests start no real tool, so nothing here runs ``uv``. That the ``uv`` the
workflow installs accepts every flag and platform name the script passes is measured
by the workflow's own runs.

What is not asserted
--------------------
What PyPI publishes today, and what that ``uv`` accepts. The workflow's runs, the weekly
one included, measure both.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import tomllib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_platform_wheels.py"
RECORD_PATH = REPO_ROOT / "scripts" / "platform_wheels.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-platform-wheels.yml"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
REGISTRY_PATH = (
    REPO_ROOT / "automated_security_helper" / "base" / "plugin_provisioning.py"
)

NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
CUTOFF = "2026-11-20T12:00:00Z"
ENVIRONMENT = {"PATH": "/usr/bin", "HOME": "/home/ci"}
CORE = ("requests>=2.0,<3", "rich>=15.0,<16")

#: The platforms the script measures, with the name uv gives each. The table is the
#: specification: a platform is added or renamed here and in the script together.
PLATFORM_TABLE = {
    "linux-x86_64-glibc": "x86_64-unknown-linux-gnu",
    "linux-aarch64-glibc": "aarch64-unknown-linux-gnu",
    "linux-x86_64-musl": "x86_64-unknown-linux-musl",
    "linux-aarch64-musl": "aarch64-unknown-linux-musl",
    "macos-aarch64": "aarch64-apple-darwin",
    "macos-x86_64": "x86_64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "windows-aarch64": "aarch64-pc-windows-msvc",
}
MUSL_TRIPLES = frozenset(
    triple for key, triple in PLATFORM_TABLE.items() if key.endswith("-musl")
)

PYPROJECT_TEXT = """\
[project]
name = "demo"
requires-python = ">=3.11,<3.14"
dependencies = [
    "requests>=2.0,<3",
    "rich>=15.0,<16",
    "tomli>=2.0,<2.4; python_full_version < '3.11'",
]

[project.optional-dependencies]
cdk = ["constructs>=10.8,<11"]
symbols = ["tree-sitter>=0.26,<0.27"]
"""

LOCK_TEXT = """\
version = 1
revision = 5
requires-python = ">=3.11, <3.14"

[options]
exclude-newer = "0001-01-01T00:00:00Z" # no effect with a relative value
exclude-newer-span = "P7D"
"""

#: Wording of the failures uv reports, as the script has to read them. The texts are
#: representative, not captured output: the script classifies on the first sentence
#: and treats the rest as detail it may fail to read.
NO_SOLUTION = (
    "  x No solution found when resolving dependencies:\n"
    "  `-> Because {name}==1.0.0 has no usable wheels and you require "
    "{name}==1.0.0, we can conclude that your requirements are unsatisfiable.\n"
)
NETWORK_DOWN = (
    "error: Failed to fetch: `https://pypi.org/simple/{name}/`\n"
    "  Caused by: error sending request for url (https://pypi.org/simple/{name}/)\n"
)
BASE_PINS = {"anyio": "4.16.0", "idna": "3.11"}


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class FakeUv:
    """``uv`` as the script sees it: argv, stdin and an environment in, a result out.

    ``broken`` maps a distribution to the platform triples it cannot be resolved on
    (``"*"`` for every platform). ``versions`` overrides the version one platform
    resolves for one package. ``unreachable`` names distributions whose lookup dies
    with a network error rather than a failed resolution. ``moves_anyio`` names
    distributions that drag anyio below the base closure's version, and
    ``ignore_anyio_plant`` makes the planted ``anyio<4.16`` requirement change
    nothing. ``base_pins`` is the closure every resolution carries.
    """

    def __init__(
        self,
        script,
        *,
        broken=None,
        versions=None,
        unreachable=(),
        moves_anyio=(),
        ignore_anyio_plant=False,
        base_pins=None,
        banner="uv 0.13.4 (0123456789abcdef 2026-11-20)",
    ):
        self.script = script
        self.broken = broken or {}
        self.versions = versions or {}
        self.unreachable = frozenset(unreachable)
        self.moves_anyio = frozenset(moves_anyio)
        self.ignore_anyio_plant = ignore_anyio_plant
        self.base_pins = dict(BASE_PINS if base_pins is None else base_pins)
        self.banner = banner
        self.calls = []

    def compiles(self):
        return [call for call in self.calls if call[0][1:3] == ["pip", "compile"]]

    def __call__(self, argv, stdin, env):
        self.calls.append((list(argv), stdin, dict(env)))
        if list(argv[1:]) == ["--version"]:
            return self.script.Result(0, self.banner + "\n", "")
        triple = None
        if "--python-platform" in argv:
            triple = argv[argv.index("--python-platform") + 1]
        lines = [line for line in stdin.splitlines() if line.strip()]
        names = [
            _normalized(re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line).group(0))
            for line in lines
        ]
        for name in names:
            if name in self.unreachable:
                return self.script.Result(1, "", NETWORK_DOWN.format(name=name))
            where = self.broken.get(name, ())
            if "*" in where or triple in where:
                return self.script.Result(1, "", NO_SOLUTION.format(name=name))
        pins = dict.fromkeys(names, "1.0.0")
        pins.update(self.base_pins)
        planted = any(line.startswith("anyio<4.16") for line in lines)
        dragged = bool(self.moves_anyio & set(names))
        if "anyio" in pins and ((planted and not self.ignore_anyio_plant) or dragged):
            pins["anyio"] = "4.15.0"
        for (where_triple, name), version in self.versions.items():
            if where_triple == triple and name in pins:
                pins[name] = version
        body = "".join(f"{name}=={version}\n" for name, version in sorted(pins.items()))
        return self.script.Result(0, "# generated by uv\n" + body, "Resolved\n")


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location(
        "ash_check_platform_wheels", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def register(script):
    return script.load_register(REGISTRY_PATH)


def _pin(register, name, *, spec="==1.0.0", extra="", reason=None, until="", **more):
    excluded = None
    if reason is not None:
        excluded = register.Exclusion(
            reason=register.ExclusionReason(reason),
            detail="planted",
            measured="planted",
            until=until,
        )
    return register.PypiPin(
        distribution=name,
        specifier=spec,
        runtime="uv-tool",
        extra=extra,
        excluded=excluded,
        **more,
    )


def _blocks(register, *pins):
    return {"planted": register.Provisioning(pypi_pins=tuple(pins))}


def _platforms(script, *keys):
    return [platform for platform in script.PLATFORMS if platform.key in keys]


def _real_pyproject():
    return tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))


class TestCells:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("ok", ("ok", "")),
            ("fail", ("fail", "")),
            ("fail: nono-py", ("fail", "nono-py")),
            ("fail: cryptography, nono-py", ("fail", "cryptography, nono-py")),
            (
                "backtracked: extractcode-7z 16.5.210531 -> 16.5.210525",
                ("backtracked", "extractcode-7z 16.5.210531 -> 16.5.210525"),
            ),
        ],
    )
    def test_a_cell_is_a_status_and_an_optional_detail(self, script, text, expected):
        assert script.parse_cell(text) == expected
        assert script.render_cell(*expected) == text

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "OK",
            "okay",
            "ok: why",
            "fail:",
            "fail:x",
            "unmeasured",
            " ok",
            "ok ",
            "pass",
            "fail: a\nb",
        ],
    )
    def test_a_malformed_cell_is_refused(self, script, text):
        with pytest.raises(script.RecordError):
            script.parse_cell(text)

    def test_a_cell_is_rendered_only_from_a_known_status(self, script):
        with pytest.raises(ValueError):
            script.render_cell("unmeasured")
        with pytest.raises(ValueError):
            script.render_cell("ok", "a detail")


class TestTheCooldownWindow:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("P7D", timedelta(days=7)),
            ("P1W", timedelta(weeks=1)),
            ("P2W3D", timedelta(days=17)),
            ("PT36H", timedelta(hours=36)),
            ("P1DT12H", timedelta(days=1, hours=12)),
            ("PT90M", timedelta(minutes=90)),
            ("PT30S", timedelta(seconds=30)),
        ],
    )
    def test_an_iso_duration_is_read(self, script, text, expected):
        assert script.parse_duration(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["", "P", "PT", "7 days", "P1M", "P1Y", "p7d", "P-7D", "P7", "PT7", "P1D2H"],
    )
    def test_a_duration_with_no_fixed_length_or_no_form_is_refused(self, script, text):
        with pytest.raises(ValueError):
            script.parse_duration(text)

    def test_the_cutoff_is_the_lock_span_before_now(self, script):
        cutoff = script.read_cutoff(LOCK_TEXT, NOW)
        assert script.format_timestamp(cutoff) == CUTOFF

    def test_the_placeholder_timestamp_is_not_a_cutoff(self, script):
        lock = LOCK_TEXT.replace("exclude-newer-span", "# exclude-newer-span")
        with pytest.raises(ValueError, match="exclude-newer"):
            script.read_cutoff(lock, NOW)

    def test_an_absolute_timestamp_is_used_when_the_lock_has_no_span(self, script):
        lock = LOCK_TEXT.replace(
            'exclude-newer = "0001-01-01T00:00:00Z"',
            'exclude-newer = "2026-11-19T19:11:25Z"',
        ).replace('exclude-newer-span = "P7D"\n', "")
        cutoff = script.read_cutoff(lock, NOW)
        assert script.format_timestamp(cutoff) == "2026-11-19T19:11:25Z"

    def test_the_span_wins_over_a_stored_timestamp(self, script):
        lock = LOCK_TEXT.replace(
            'exclude-newer = "0001-01-01T00:00:00Z"',
            'exclude-newer = "2026-01-01T00:00:00Z"',
        )
        assert script.format_timestamp(script.read_cutoff(lock, NOW)) == CUTOFF

    @pytest.mark.parametrize(
        "lock",
        ["", "version = 1\n", "[options]\n", "[options\nbroken"],
    )
    def test_a_lock_with_no_readable_cooldown_is_refused(self, script, lock):
        with pytest.raises(ValueError):
            script.read_cutoff(lock, NOW)

    def test_a_timestamp_drops_fractions_and_never_rounds_up(self, script):
        moment = datetime(2026, 11, 27, 12, 0, 0, 999999, tzinfo=timezone.utc)
        assert script.format_timestamp(moment) == "2026-11-27T12:00:00Z"

    def test_a_timestamp_without_a_zone_is_refused(self, script):
        with pytest.raises(ValueError):
            script.format_timestamp(datetime(2026, 11, 27, 12, 0, 0))

    def test_a_timestamp_reads_back_the_way_it_is_written(self, script):
        assert script.parse_timestamp(CUTOFF) == datetime(
            2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc
        )
        with pytest.raises(ValueError):
            script.parse_timestamp("2026-11-20")


class TestPythonVersions:
    @pytest.mark.parametrize(
        "requires,expected",
        [
            (">=3.11,<3.15", ("3.11", "3.12", "3.13", "3.14")),
            (">=3.12,<3.14", ("3.12", "3.13")),
            (">= 3.11, < 3.15", ("3.11", "3.12", "3.13", "3.14")),
            ("<3.15,>=3.11", ("3.11", "3.12", "3.13", "3.14")),
        ],
    )
    def test_the_minors_between_the_bounds_are_measured(
        self, script, requires, expected
    ):
        assert script.python_versions(requires) == expected

    @pytest.mark.parametrize(
        "requires", [">=3.11", "~=3.11", ">=3.12,<3.12", ">=3.11,<4.0", "", "3.11"]
    )
    def test_a_range_that_cannot_be_enumerated_is_refused(self, script, requires):
        with pytest.raises(ValueError):
            script.python_versions(requires)


class TestRequirementSets:
    def test_the_sets_follow_the_real_pyproject(self, script, register):
        pyproject = _real_pyproject()
        sets = script.requirement_sets(pyproject, register.PROVISIONING)
        core = tuple(pyproject["project"]["dependencies"])
        assert sets["core"] == core
        extras = pyproject["project"].get("optional-dependencies", {})
        for extra, requirements in extras.items():
            if extra == "alpha":
                continue
            assert sets[f"core+{extra}"] == (*core, *requirements)

    def test_every_alpha_candidate_of_the_real_register_has_a_row(
        self, script, register
    ):
        pyproject = _real_pyproject()
        sets = script.requirement_sets(pyproject, register.PROVISIONING)
        candidates = {
            f"core+alpha:{_normalized(pin.distribution)}"
            for block in register.PROVISIONING.values()
            for pin in block.pypi_pins
            if pin.extra == "alpha"
            or (pin.excluded is not None and pin.excluded.reason.value == "owner_hold")
        }
        assert {row for row in sets if row.startswith("core+alpha:")} == candidates
        assert ("core+alpha" in sets) == bool(candidates)

    def test_a_pin_renders_with_its_markers_and_its_with_requirements(
        self, script, register
    ):
        pin = _pin(
            register,
            "scancode-toolkit",
            spec="==32.5.0",
            extra="alpha",
            with_requirements=("pluggy<1.7",),
            python_marker="python_version < '3.14'",
            platform_marker="sys_platform != 'win32'",
        )
        marker = "python_version < '3.14' and sys_platform != 'win32'"
        assert script.render_pin(pin) == (
            f"scancode-toolkit==32.5.0; {marker}",
            f"pluggy<1.7; {marker}",
        )

    def test_one_marker_stands_alone_and_none_leaves_the_bare_requirement(
        self, script, register
    ):
        one = _pin(
            register, "a", extra="alpha", platform_marker="sys_platform != 'win32'"
        )
        none = _pin(register, "b", spec=">=2,<3", extra="alpha")
        assert script.render_pin(one) == ("a==1.0.0; sys_platform != 'win32'",)
        assert script.render_pin(none) == ("b>=2,<3",)

    def test_a_marker_with_or_is_parenthesised_before_it_is_joined(
        self, script, register
    ):
        pin = _pin(
            register,
            "a",
            extra="alpha",
            python_marker="python_version < '3.12' or python_version >= '3.14'",
            platform_marker="sys_platform != 'win32'",
        )
        expected = (
            "a==1.0.0; (python_version < '3.12' or python_version >= '3.14') "
            "and sys_platform != 'win32'"
        )
        assert script.render_pin(pin) == (expected,)

    def test_members_and_held_pins_are_measured_and_the_rest_are_not(
        self, script, register
    ):
        blocks = _blocks(
            register,
            _pin(register, "Member_A", extra="alpha"),
            _pin(register, "held-b", reason="owner_hold"),
            _pin(register, "conflict-c", reason="core_pin_conflict"),
            _pin(register, "cooling-d", reason="cooldown", until="2026-12-01"),
        )
        pyproject = {"project": {"dependencies": list(CORE)}}
        sets = script.requirement_sets(pyproject, blocks)
        assert set(sets) == {
            "core",
            "core+alpha",
            "core+alpha:member-a",
            "core+alpha:held-b",
        }
        assert sets["core+alpha:member-a"] == (*CORE, "Member_A==1.0.0")
        assert sets["core+alpha"] == (*CORE, "held-b==1.0.0", "Member_A==1.0.0")

    def test_no_candidate_means_no_alpha_row_at_all(self, script, register):
        blocks = _blocks(register, _pin(register, "x", reason="no_wheels"))
        sets = script.requirement_sets(
            {"project": {"dependencies": list(CORE)}}, blocks
        )
        assert set(sets) == {"core"}

    def test_the_register_is_the_alpha_source_not_pyproject(self, script, register):
        pyproject = {
            "project": {
                "dependencies": list(CORE),
                "optional-dependencies": {"alpha": ["ghost>=1"], "cdk": ["c>=1"]},
            }
        }
        sets = script.requirement_sets(pyproject, _blocks(register))
        assert set(sets) == {"core", "core+cdk"}

    def test_only_members_must_have_a_recorded_row(self, script, register):
        blocks = _blocks(
            register,
            _pin(register, "member-a", extra="alpha"),
            _pin(register, "held-b", reason="owner_hold"),
        )
        assert script.member_rows(blocks) == {"core+alpha", "core+alpha:member-a"}
        assert script.member_rows(_blocks(register)) == set()


class TestTheCommands:
    def test_the_platform_table_is_the_specification(self, script):
        assert {p.key: p.triple for p in script.PLATFORMS} == PLATFORM_TABLE
        assert len({p.triple for p in script.PLATFORMS}) == len(script.PLATFORMS)

    def test_only_macos_sets_a_deployment_target(self, script):
        for platform in script.PLATFORMS:
            expected = (
                {"MACOSX_DEPLOYMENT_TARGET": "14.0"}
                if platform.key.startswith("macos-")
                else {}
            )
            assert dict(platform.env) == expected, platform.key

    def test_a_cell_is_one_no_build_compile_for_one_platform(self, script):
        platform = _platforms(script, "linux-x86_64-musl")[0]
        assert script.cell_command("uv", platform, "3.12", CUTOFF) == [
            "uv",
            "pip",
            "compile",
            "--no-build",
            "--no-config",
            "--python-platform",
            "x86_64-unknown-linux-musl",
            "--python-version",
            "3.12",
            "--exclude-newer",
            CUTOFF,
            "-",
        ]

    def test_the_closure_is_one_universal_no_build_compile(self, script):
        assert script.closure_command("uv", "3.11", CUTOFF) == [
            "uv",
            "pip",
            "compile",
            "--universal",
            "--no-build",
            "--no-config",
            "--python-version",
            "3.11",
            "--exclude-newer",
            CUTOFF,
            "-",
        ]

    def test_the_child_environment_keeps_the_runner_and_drops_the_index_settings(
        self, script
    ):
        base = {
            "PATH": "/usr/bin",
            "HOME": "/home/ci",
            "UV_CACHE_DIR": "/cache",
            "UV_INDEX_URL": "https://evil.invalid/simple",
            "UV_EXTRA_INDEX_URL": "https://evil.invalid/extra",
            "UV_DEFAULT_INDEX": "https://evil.invalid/simple",
            "UV_EXCLUDE_NEWER": "2000-01-01T00:00:00Z",
            "PIP_INDEX_URL": "https://evil.invalid/simple",
            "GITHUB_TOKEN": "not-for-a-resolver",
        }
        env = script.child_environment(base)
        assert env == {"PATH": "/usr/bin", "HOME": "/home/ci", "UV_CACHE_DIR": "/cache"}

    def test_a_macos_cell_carries_its_deployment_target(self, script):
        macos = _platforms(script, "macos-aarch64")[0]
        env = script.child_environment({"PATH": "/usr/bin"}, macos)
        assert env["MACOSX_DEPLOYMENT_TARGET"] == "14.0"
        linux = _platforms(script, "linux-x86_64-glibc")[0]
        assert "MACOSX_DEPLOYMENT_TARGET" not in script.child_environment(
            {"PATH": "/usr/bin"}, linux
        )


class TestReadingUvsAnswers:
    def test_pins_are_read_past_comments_markers_and_extras(self, script):
        output = (
            "# This file was autogenerated by uv via the following command:\n"
            "#    uv pip compile --no-build\n"
            "annotated-types==0.7.0\n"
            "    # via pydantic\n"
            "anyio==4.16.0 ; python_full_version >= '3.11'\n"
            "Typing_Extensions==4.15.0\n"
            "requests[socks]==2.34.0\n"
            "\n"
        )
        assert script.parse_pins(output) == {
            "annotated-types": ("0.7.0",),
            "anyio": ("4.16.0",),
            "typing-extensions": ("4.15.0",),
            "requests": ("2.34.0",),
        }

    def test_a_universal_fork_keeps_every_version_it_resolved(self, script):
        output = (
            "numpy==1.26.4 ; python_full_version < '3.12'\n"
            "numpy==2.0.1 ; python_full_version >= '3.12'\n"
        )
        assert script.parse_pins(output) == {"numpy": ("1.26.4", "2.0.1")}

    def test_only_a_failed_resolution_counts_as_a_failed_cell(self, script):
        assert script.resolution_failed(NO_SOLUTION.format(name="x"))
        assert script.resolution_failed(
            "x No solution found when resolving dependencies for split "
            "(python_full_version == '3.12.*'):"
        )
        for stderr in ("", NETWORK_DOWN.format(name="x"), "error: unexpected argument"):
            assert not script.resolution_failed(stderr), stderr

    @pytest.mark.parametrize(
        "stderr,expected",
        [
            (
                (
                    "Because nono-py==0.16.0 has no usable wheels and you require "
                    "nono-py==0.16.0, we can conclude that your requirements are "
                    "unsatisfiable."
                ),
                ("nono-py",),
            ),
            (
                (
                    "Because only pygit2<=1.18.2 is available and pygit2==1.18.2 has "
                    "no usable wheels, we can conclude that all versions of pygit2 "
                    "cannot be used."
                ),
                ("pygit2",),
            ),
            (
                (
                    "Because cryptography==50.0.2 has no wheels with a matching "
                    "platform tag (e.g., `macosx_14_0_x86_64`) and you require "
                    "cryptography>=50.0.2"
                ),
                ("cryptography",),
            ),
            (
                (
                    "Because b==1 has no usable wheels. And because a==2 has no "
                    "usable wheels and b==1 has no usable wheels, a conclusion."
                ),
                ("a", "b"),
            ),
            ("Because nothing in this message names a wheel problem.", ()),
        ],
    )
    def test_the_blockers_are_the_distributions_with_no_usable_wheel(
        self, script, stderr, expected
    ):
        assert script.blockers(stderr) == expected

    def test_a_workflow_command_in_tool_output_is_defused(self, script):
        text = "ok\n::error::boom\r::warning::x\n  ::notice::y\nvalue ##[error]z"
        cleaned = script.defuse(text)
        assert all(not line.lstrip().startswith("::") for line in cleaned.splitlines())
        assert "##[" not in cleaned
        assert "boom" in cleaned and "value" in cleaned

    def test_plain_text_is_left_alone(self, script):
        assert script.defuse("Resolved 3 packages in 12ms\n") == (
            "Resolved 3 packages in 12ms\n"
        )

    def test_uvs_version_is_read_from_its_banner(self, script):
        fake = FakeUv(script)
        assert script.read_uv_version(fake, "uv", ENVIRONMENT) == "0.13.4"

    def test_a_banner_that_is_not_uvs_is_refused(self, script):
        fake = FakeUv(script, banner="not a version banner")
        with pytest.raises(script.ResolverError):
            script.read_uv_version(fake, "uv", ENVIRONMENT)


class TestMeasuring:
    def test_every_cell_of_every_set_is_measured_once(self, script):
        fake = FakeUv(script)
        sets = {"core": ("requests>=2",), "core+x": ("requests>=2", "x>=1")}
        measured = script.measure_sets(
            fake, "uv", sets, ("3.11", "3.12"), CUTOFF, ENVIRONMENT
        )
        assert set(measured) == set(sets)
        for rows in measured.values():
            assert set(rows) == set(PLATFORM_TABLE)
            for cells in rows.values():
                assert cells == {"3.11": "ok", "3.12": "ok"}
        assert len(fake.compiles()) == len(sets) * len(PLATFORM_TABLE) * 2
        assert fake.compiles()[0][1] == "requests>=2\n"

    def test_each_call_names_its_own_platform_and_python(self, script):
        fake = FakeUv(script)
        script.measure_sets(
            fake, "uv", {"core": ("a",)}, ("3.11", "3.13"), CUTOFF, ENVIRONMENT
        )
        seen = set()
        for argv, _, _ in fake.compiles():
            seen.add(
                (
                    argv[argv.index("--python-platform") + 1],
                    argv[argv.index("--python-version") + 1],
                )
            )
        assert seen == {
            (triple, python)
            for triple in PLATFORM_TABLE.values()
            for python in ("3.11", "3.13")
        }

    def test_a_failed_resolution_is_a_failed_cell_with_its_blocker(self, script):
        fake = FakeUv(script, broken={"tree-sitter": {"aarch64-unknown-linux-musl"}})
        sets = {"core": ("a",), "core+symbols": ("a", "tree-sitter>=0.26")}
        measured = script.measure_sets(fake, "uv", sets, ("3.12",), CUTOFF, ENVIRONMENT)
        assert measured["core+symbols"]["linux-aarch64-musl"] == {
            "3.12": "fail: tree-sitter"
        }
        assert measured["core+symbols"]["linux-x86_64-musl"] == {"3.12": "ok"}
        assert {
            cell for cells in measured["core"].values() for cell in cells.values()
        } == {"ok"}

    def test_an_unreachable_index_is_never_a_cell(self, script):
        fake = FakeUv(script, unreachable={"tree-sitter"})
        sets = {"core+symbols": ("a", "tree-sitter>=0.26")}
        with pytest.raises(script.ResolverError, match="Failed to fetch"):
            script.measure_sets(fake, "uv", sets, ("3.12",), CUTOFF, ENVIRONMENT)

    def test_a_flag_uv_does_not_know_is_not_a_cell_either(self, script):
        def runner(argv, stdin, env):
            return script.Result(2, "", "error: unexpected argument '--frobnicate'\n")

        with pytest.raises(script.ResolverError, match="unexpected argument"):
            script.measure_sets(
                runner, "uv", {"core": ("a",)}, ("3.12",), CUTOFF, ENVIRONMENT
            )

    def test_a_runner_that_gives_up_stops_the_measurement(self, script):
        def runner(argv, stdin, env):
            raise script.ResolverError("uv timed out after 300 s")

        with pytest.raises(script.ResolverError, match="timed out"):
            script.measure_sets(
                runner, "uv", {"core": ("a",)}, ("3.12",), CUTOFF, ENVIRONMENT
            )

    def test_a_pin_that_differs_from_the_first_resolved_platform_is_backtracked(
        self, script
    ):
        fake = FakeUv(
            script,
            versions={("aarch64-unknown-linux-musl", "requests"): "0.9.0"},
        )
        measured = script.measure_sets(
            fake, "uv", {"core": ("requests>=0.1",)}, ("3.12",), CUTOFF, ENVIRONMENT
        )
        cells = {key: row["3.12"] for key, row in measured["core"].items()}
        assert cells["linux-aarch64-musl"] == "backtracked: requests 1.0.0 -> 0.9.0"
        assert {v for key, v in cells.items() if key != "linux-aarch64-musl"} == {"ok"}

    def test_the_reference_is_the_first_platform_that_resolved(self, script):
        fake = FakeUv(
            script,
            broken={"requests": {"x86_64-unknown-linux-gnu"}},
            versions={("aarch64-unknown-linux-musl", "requests"): "0.9.0"},
        )
        measured = script.measure_sets(
            fake, "uv", {"core": ("requests>=0.1",)}, ("3.12",), CUTOFF, ENVIRONMENT
        )
        cells = {key: row["3.12"] for key, row in measured["core"].items()}
        assert cells["linux-x86_64-glibc"] == "fail: requests"
        assert cells["linux-aarch64-glibc"] == "ok"
        assert cells["linux-aarch64-musl"] == "backtracked: requests 1.0.0 -> 0.9.0"

    def test_the_macos_target_reaches_the_resolver_and_the_index_settings_do_not(
        self, script
    ):
        fake = FakeUv(script)
        base = {**ENVIRONMENT, "UV_INDEX_URL": "https://evil.invalid/simple"}
        script.measure_sets(fake, "uv", {"core": ("a",)}, ("3.12",), CUTOFF, base)
        for argv, _, env in fake.compiles():
            triple = argv[argv.index("--python-platform") + 1]
            assert "UV_INDEX_URL" not in env
            assert ("MACOSX_DEPLOYMENT_TARGET" in env) == triple.endswith("-darwin")


class TestComparing:
    RECORDED = {
        "core": {
            "linux-x86_64-glibc": {"3.11": "ok", "3.12": "ok"},
            "linux-x86_64-musl": {"3.11": "ok", "3.12": "fail: nono-py"},
        }
    }

    def _measured(self):
        return json.loads(json.dumps(self.RECORDED))

    def test_a_clean_record_passes(self, script):
        assert script.compare(self.RECORDED, self._measured()) == []

    def test_a_cell_that_changes_without_a_rerecord_fails(self, script):
        measured = self._measured()
        measured["core"]["linux-x86_64-glibc"]["3.12"] = "fail: pygit2"
        findings = script.compare(self.RECORDED, measured)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.kind == "changed"
        assert finding.blocking
        assert finding.where == "core / linux-x86_64-glibc / 3.12"
        assert finding.message == "recorded ok, measured fail: pygit2"

    @pytest.mark.parametrize(
        "recorded,measured",
        [
            ("ok", "fail"),
            ("fail", "ok"),
            ("ok", "backtracked: a 1 -> 0"),
            ("backtracked: a 1 -> 0", "ok"),
            ("fail: a", "backtracked: a 1 -> 0"),
        ],
    )
    def test_any_change_of_status_is_a_change(self, script, recorded, measured):
        before = {"core": {"p": {"3.12": recorded}}}
        after = {"core": {"p": {"3.12": measured}}}
        assert [f.kind for f in script.compare(before, after)] == ["changed"]

    @pytest.mark.parametrize(
        "recorded,measured",
        [
            ("fail: nono-py", "fail: pygit2"),
            ("fail", "fail: nono-py"),
            ("backtracked: a 1 -> 0", "backtracked: b 2 -> 1"),
        ],
    )
    def test_a_change_of_detail_alone_is_not_a_change(self, script, recorded, measured):
        before = {"core": {"p": {"3.12": recorded}}}
        after = {"core": {"p": {"3.12": measured}}}
        assert script.compare(before, after) == []

    def test_a_member_with_no_recorded_row_fails(self, script):
        measured = {
            **self._measured(),
            "core+alpha:member-a": {"linux-x86_64-glibc": {"3.11": "ok", "3.12": "ok"}},
        }
        findings = script.compare(
            self.RECORDED, measured, members={"core+alpha:member-a"}
        )
        assert [(f.kind, f.where, f.blocking) for f in findings] == [
            ("member-row", "core+alpha:member-a", True)
        ]

    def test_a_row_that_is_not_a_member_is_a_note_until_completeness_is_required(
        self, script
    ):
        measured = {
            **self._measured(),
            "core+symbols": {"linux-x86_64-glibc": {"3.11": "ok", "3.12": "ok"}},
        }
        notes = script.compare(self.RECORDED, measured)
        assert [(f.kind, f.where, f.blocking) for f in notes] == [
            ("unrecorded-row", "core+symbols", False)
        ]
        strict = script.compare(self.RECORDED, measured, require_complete=True)
        assert [(f.kind, f.blocking) for f in strict] == [("unrecorded-row", True)]

    def test_a_recorded_row_that_is_no_longer_measured_fails(self, script):
        recorded = {**self.RECORDED, "core+gone": self.RECORDED["core"]}
        findings = script.compare(recorded, self._measured())
        assert [(f.kind, f.where, f.blocking) for f in findings] == [
            ("stale-row", "core+gone", True)
        ]

    def test_a_python_or_platform_the_record_lacks_is_a_shape_change(self, script):
        measured = self._measured()
        measured["core"]["linux-x86_64-glibc"]["3.13"] = "ok"
        measured["core"]["linux-aarch64-musl"] = {"3.11": "ok", "3.12": "ok"}
        findings = script.compare(self.RECORDED, measured)
        assert [(f.kind, f.where, f.blocking) for f in findings] == [
            ("shape", "core", True)
        ]
        assert "3.13" in findings[0].message
        assert "linux-aarch64-musl" in findings[0].message

    def test_a_cell_the_script_no_longer_measures_is_a_shape_change(self, script):
        measured = self._measured()
        del measured["core"]["linux-x86_64-musl"]
        findings = script.compare(self.RECORDED, measured)
        assert [f.kind for f in findings] == ["shape"]
        assert "linux-x86_64-musl" in findings[0].message

    def test_findings_come_back_in_a_fixed_order(self, script):
        measured = self._measured()
        measured["core"]["linux-x86_64-musl"]["3.11"] = "fail"
        measured["core"]["linux-x86_64-glibc"]["3.12"] = "fail"
        findings = script.compare(self.RECORDED, measured)
        assert [f.where for f in findings] == [
            "core / linux-x86_64-glibc / 3.12",
            "core / linux-x86_64-musl / 3.11",
        ]


class TestTheBaseClosure:
    CORE_CLOSURE = {"anyio": ("4.16.0",), "idna": ("3.11",), "rich": ("15.0.0",)}

    def test_a_moved_version_is_reported_with_both_versions(self, script):
        moved = {**self.CORE_CLOSURE, "anyio": ("4.15.0",)}
        lines = script.closure_differences(self.CORE_CLOSURE, moved)
        assert len(lines) == 1
        assert "anyio" in lines[0] and "4.16.0" in lines[0] and "4.15.0" in lines[0]

    def test_a_package_that_drops_out_is_reported(self, script):
        without = {k: v for k, v in self.CORE_CLOSURE.items() if k != "idna"}
        lines = script.closure_differences(self.CORE_CLOSURE, without)
        assert len(lines) == 1 and "idna" in lines[0]

    def test_a_new_package_and_a_second_fork_are_not_differences(self, script):
        grown = {**self.CORE_CLOSURE, "pygit2": ("1.18.2",)}
        assert script.closure_differences(self.CORE_CLOSURE, grown) == []

    def test_a_second_version_of_a_base_package_is_a_difference(self, script):
        forked = {**self.CORE_CLOSURE, "idna": ("3.11", "3.12")}
        assert len(script.closure_differences(self.CORE_CLOSURE, forked)) == 1

    def test_equal_closures_have_no_differences(self, script):
        assert script.closure_differences(self.CORE_CLOSURE, self.CORE_CLOSURE) == []

    def test_a_requirement_that_does_not_move_the_base_passes(self, script):
        fake = FakeUv(script)
        assert (
            script.closure_findings(
                fake, "uv", CORE, ("x>=1",), "3.11", CUTOFF, ENVIRONMENT
            )
            == []
        )
        assert all("--universal" in argv for argv, _, _ in fake.compiles())

    def test_a_requirement_that_moves_the_base_fails(self, script):
        fake = FakeUv(script, moves_anyio={"x"})
        lines = script.closure_findings(
            fake, "uv", CORE, ("x>=1",), "3.11", CUTOFF, ENVIRONMENT
        )
        assert len(lines) == 1 and "anyio" in lines[0]

    def test_an_alpha_set_that_does_not_resolve_is_a_finding_not_an_error(self, script):
        fake = FakeUv(script, broken={"x": {None}})
        lines = script.closure_findings(
            fake, "uv", CORE, ("x>=1",), "3.11", CUTOFF, ENVIRONMENT
        )
        assert len(lines) == 1 and "does not resolve" in lines[0]

    def test_an_unreachable_index_stops_the_closure_check(self, script):
        fake = FakeUv(script, unreachable={"x"})
        with pytest.raises(script.ResolverError):
            script.closure_findings(
                fake, "uv", CORE, ("x>=1",), "3.11", CUTOFF, ENVIRONMENT
            )


class TestTheControls:
    def _run(self, script, fake):
        return script.run_controls(
            fake, "uv", CORE, ("3.11", "3.12"), CUTOFF, ENVIRONMENT
        )

    def test_the_controls_pass_when_the_planted_requirements_break_what_they_must(
        self, script
    ):
        fake = FakeUv(script, broken={"scancode-toolkit": MUSL_TRIPLES})
        results = self._run(script, fake)
        assert [r.name for r in results] == ["scancode-musl", "anyio-closure"]
        assert all(r.passed for r in results), results

    def test_the_scancode_control_plants_the_member_and_its_with_requirement(
        self, script
    ):
        fake = FakeUv(script, broken={"scancode-toolkit": MUSL_TRIPLES})
        self._run(script, fake)
        planted = [
            call[1] for call in fake.compiles() if "scancode-toolkit==32.5.0" in call[1]
        ]
        assert planted and all("pluggy<1.7" in stdin for stdin in planted)

    def test_a_planted_scancode_that_stays_green_on_musl_fails_the_control(
        self, script
    ):
        results = self._run(script, FakeUv(script))
        scancode = results[0]
        assert not scancode.passed
        assert "musl" in scancode.message

    def test_one_musl_cell_staying_green_fails_the_control(self, script):
        one = {"x86_64-unknown-linux-musl"}
        results = self._run(script, FakeUv(script, broken={"scancode-toolkit": one}))
        assert not results[0].passed
        assert "linux-aarch64-musl" in results[0].message

    def test_a_planted_requirement_that_fails_everywhere_proves_nothing(self, script):
        fake = FakeUv(script, broken={"scancode-toolkit": {"*"}})
        scancode = self._run(script, fake)[0]
        assert not scancode.passed
        assert "linux-x86_64-glibc" in scancode.message

    def test_a_pin_that_moves_nothing_fails_the_closure_control(self, script):
        fake = FakeUv(
            script,
            broken={"scancode-toolkit": MUSL_TRIPLES},
            ignore_anyio_plant=True,
        )
        closure = self._run(script, fake)[1]
        assert not closure.passed
        assert "anyio" in closure.message

    def test_a_base_closure_without_anyio_cannot_run_the_control(self, script):
        fake = FakeUv(
            script,
            broken={"scancode-toolkit": MUSL_TRIPLES},
            base_pins={"idna": "3.11"},
        )
        closure = self._run(script, fake)[1]
        assert not closure.passed
        assert "not in the base closure" in closure.message

    def test_an_unreachable_index_stops_the_controls(self, script):
        fake = FakeUv(script, unreachable={"scancode-toolkit"})
        with pytest.raises(script.ResolverError):
            self._run(script, fake)


class TestTheCooldownReport:
    def test_a_cooldown_that_has_ended_is_reported_from_the_day_it_ends(
        self, script, register
    ):
        blocks = _blocks(
            register, _pin(register, "newpkg", reason="cooldown", until="2026-12-01")
        )
        assert script.cooldown_report(blocks, date(2026, 11, 30)) == []
        lines = script.cooldown_report(blocks, date(2026, 12, 1))
        assert len(lines) == 1
        assert "newpkg" in lines[0] and "2026-12-01" in lines[0]
        assert len(script.cooldown_report(blocks, date(2026, 12, 9))) == 1

    def test_other_exclusions_and_members_are_not_cooldowns(self, script, register):
        blocks = _blocks(
            register,
            _pin(register, "a", reason="owner_hold"),
            _pin(register, "b", reason="no_wheels"),
            _pin(register, "c", extra="alpha"),
        )
        assert script.cooldown_report(blocks, date(2030, 1, 1)) == []

    def test_a_timestamp_until_is_read_by_its_date(self, script, register):
        blocks = _blocks(
            register,
            _pin(register, "t", reason="cooldown", until="2026-12-01T00:00:00Z"),
        )
        assert len(script.cooldown_report(blocks, date(2026, 12, 1))) == 1

    def test_an_until_that_is_not_a_date_names_the_pin(self, script, register):
        blocks = _blocks(
            register, _pin(register, "oops", reason="cooldown", until="next week")
        )
        with pytest.raises(ValueError, match="oops"):
            script.cooldown_report(blocks, date(2026, 12, 1))

    def test_the_real_register_has_no_ended_cooldown_to_report(self, script, register):
        assert script.cooldown_report(register.PROVISIONING, date(2026, 11, 27)) == []


class TestTheRecordFile:
    def _record(self):
        return {
            "format": 1,
            "metadata": {"uv_version": "0.13.4"},
            "sets": {"core": {"p": {"3.12": "ok"}}},
        }

    def test_the_record_is_written_the_way_the_json_hook_writes_it(self, script):
        record = self._record()
        assert script.render_record(record) == (
            json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        )

    def test_a_record_reads_back_what_was_written(self, script, tmp_path):
        path = tmp_path / "record.json"
        path.write_text(script.render_record(self._record()), encoding="utf-8")
        assert script.load_record(path) == self._record()

    @pytest.mark.parametrize(
        "text",
        [
            "not json",
            "[]",
            '{"format": 2, "metadata": {}, "sets": {}}',
            '{"format": 1, "sets": {}}',
            '{"format": 1, "metadata": {}}',
            '{"format": 1, "metadata": {}, "sets": []}',
            '{"format": 1, "metadata": {}, "sets": {"core": {"p": {"3.12": "pass"}}}}',
            '{"format": 1, "metadata": {}, "sets": {"core": {"p": []}}}',
        ],
    )
    def test_a_record_it_cannot_read_is_refused_naming_the_file(
        self, script, tmp_path, text
    ):
        path = tmp_path / "record.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(script.RecordError, match="record.json"):
            script.load_record(path)

    def test_a_missing_record_is_refused(self, script, tmp_path):
        with pytest.raises(script.RecordError, match="nothing.json"):
            script.load_record(tmp_path / "nothing.json")


@pytest.fixture
def project(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT_TEXT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(LOCK_TEXT, encoding="utf-8")
    return tmp_path


def _argv(project, *modes, registry=REGISTRY_PATH):
    return [
        *modes,
        "--pyproject",
        str(project / "pyproject.toml"),
        "--lock",
        str(project / "uv.lock"),
        "--registry",
        str(registry),
        "--file",
        str(project / "platform_wheels.json"),
        "--uv",
        "uv",
    ]


class TestTheCommandLine:
    def test_recording_writes_every_cell_and_says_how_it_was_measured(
        self, script, project, capsys
    ):
        fake = FakeUv(script)
        assert script.main(_argv(project, "--record"), runner=fake, now=NOW) == 0
        text = (project / "platform_wheels.json").read_text(encoding="utf-8")
        record = json.loads(text)
        assert text == script.render_record(record)
        assert record["format"] == 1
        metadata = record["metadata"]
        assert metadata["uv_version"] == "0.13.4"
        assert metadata["exclude_newer"] == CUTOFF
        assert metadata["measured_at"] == "2026-11-27T12:00:00Z"
        assert metadata["cooldown"] == "P7D"
        assert metadata["platforms"] == PLATFORM_TABLE
        assert metadata["pythons"] == ["3.11", "3.12", "3.13"]
        assert "--no-build" in metadata["command"]
        assert {"core", "core+cdk", "core+symbols"} <= set(record["sets"])
        for rows in record["sets"].values():
            assert set(rows) == set(PLATFORM_TABLE)
            for cells in rows.values():
                assert set(cells) == {"3.11", "3.12", "3.13"}
        assert "recorded" in capsys.readouterr().out

    def test_a_record_checks_clean_against_the_same_resolution(
        self, script, project, capsys
    ):
        assert (
            script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW) == 0
        )
        capsys.readouterr()
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 0
        )
        assert capsys.readouterr().out.startswith("## Platform wheels: ok")

    def test_a_cell_that_changed_fails_the_check_and_names_the_cell(
        self, script, project, capsys
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        capsys.readouterr()
        drifted = FakeUv(script, broken={"requests": MUSL_TRIPLES})
        assert script.main(_argv(project, "--check"), runner=drifted, now=NOW) == 1
        out = capsys.readouterr().out
        assert out.startswith("## Platform wheels: FAILED")
        assert "core / linux-x86_64-musl / 3.12" in out
        assert "recorded ok, measured fail: requests" in out
        assert "--record" in out

    def test_a_failed_check_leaves_the_record_alone_and_can_keep_what_it_saw(
        self, script, project
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        record_path = project / "platform_wheels.json"
        before = record_path.read_bytes()
        measured_path = project / "measured.json"
        drifted = FakeUv(script, broken={"requests": MUSL_TRIPLES})
        argv = [*_argv(project, "--check"), "--measured-out", str(measured_path)]
        assert script.main(argv, runner=drifted, now=NOW) == 1
        assert record_path.read_bytes() == before
        measured = json.loads(measured_path.read_text(encoding="utf-8"))
        assert measured["sets"]["core"]["linux-x86_64-musl"]["3.12"] == "fail: requests"

    def test_a_member_with_no_recorded_row_fails_the_check(
        self, script, register, project, monkeypatch, capsys
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        capsys.readouterr()
        blocks = _blocks(register, _pin(register, "zz-new", extra="alpha"))
        monkeypatch.setattr(script, "load_blocks", lambda path: blocks)
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 1
        )
        out = capsys.readouterr().out
        assert "core+alpha:zz-new" in out and "member-row" in out

    def test_a_row_that_is_not_recorded_is_a_note_and_a_failure_when_required(
        self, script, project, capsys
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        record_path = project / "platform_wheels.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        del record["sets"]["core+symbols"]
        record_path.write_text(script.render_record(record), encoding="utf-8")
        capsys.readouterr()
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 0
        )
        out = capsys.readouterr().out
        assert "core+symbols" in out and "no recorded row" in out
        strict = [*_argv(project, "--check"), "--require-complete"]
        assert script.main(strict, runner=FakeUv(script), now=NOW) == 1

    def test_a_record_with_a_row_the_script_no_longer_has_fails(
        self, script, project, capsys
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        record_path = project / "platform_wheels.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["sets"]["core+gone"] = record["sets"]["core"]
        record_path.write_text(script.render_record(record), encoding="utf-8")
        capsys.readouterr()
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 1
        )
        assert "stale-row" in capsys.readouterr().out

    def test_a_candidate_that_moves_the_base_closure_fails_the_check(
        self, script, register, project, monkeypatch, capsys
    ):
        blocks = _blocks(register, _pin(register, "mover", reason="owner_hold"))
        monkeypatch.setattr(script, "load_blocks", lambda path: blocks)
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        capsys.readouterr()
        mover = FakeUv(script, moves_anyio={"mover"})
        assert script.main(_argv(project, "--check"), runner=mover, now=NOW) == 1
        out = capsys.readouterr().out
        assert "anyio" in out and "4.16.0" in out and "4.15.0" in out

    def test_a_check_with_no_candidates_skips_the_closure_and_says_so(
        self, script, register, project, monkeypatch, capsys
    ):
        monkeypatch.setattr(script, "load_blocks", lambda path: _blocks(register))
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        capsys.readouterr()
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 0
        )
        assert "no alpha candidate" in capsys.readouterr().out

    def test_an_unreachable_index_records_nothing(self, script, project, capsys):
        fake = FakeUv(script, unreachable={"requests"})
        assert script.main(_argv(project, "--record"), runner=fake, now=NOW) == 2
        assert not (project / "platform_wheels.json").exists()
        assert "cannot measure" in capsys.readouterr().err

    def test_an_unreachable_index_leaves_an_existing_record_byte_for_byte(
        self, script, project
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        record_path = project / "platform_wheels.json"
        before = record_path.read_bytes()
        fake = FakeUv(script, unreachable={"requests"})
        assert script.main(_argv(project, "--record"), runner=fake, now=NOW) == 2
        assert record_path.read_bytes() == before

    def test_an_unreachable_index_is_neither_drift_nor_a_pass(
        self, script, project, capsys
    ):
        script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW)
        capsys.readouterr()
        fake = FakeUv(script, unreachable={"requests"})
        assert script.main(_argv(project, "--check"), runner=fake, now=NOW) == 2
        captured = capsys.readouterr()
        assert "cannot measure" in captured.err
        assert "Platform wheels: ok" not in captured.out

    def test_a_record_that_is_missing_cannot_be_checked(self, script, project, capsys):
        assert (
            script.main(_argv(project, "--check"), runner=FakeUv(script), now=NOW) == 2
        )
        assert "platform_wheels.json" in capsys.readouterr().err

    def test_a_lock_with_no_cooldown_cannot_be_measured(self, script, project, capsys):
        (project / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        assert (
            script.main(_argv(project, "--record"), runner=FakeUv(script), now=NOW) == 2
        )
        assert "exclude-newer" in capsys.readouterr().err

    def test_the_controls_pass_and_fail_through_the_command_line(
        self, script, project, capsys
    ):
        good = FakeUv(script, broken={"scancode-toolkit": MUSL_TRIPLES})
        assert script.main(_argv(project, "--controls"), runner=good, now=NOW) == 0
        assert "scancode-musl" in capsys.readouterr().out
        assert (
            script.main(_argv(project, "--controls"), runner=FakeUv(script), now=NOW)
            == 1
        )
        assert "FAILED" in capsys.readouterr().out

    def test_the_cooldown_report_fails_only_when_a_window_has_ended(
        self, script, register, project, monkeypatch, capsys
    ):
        blocks = _blocks(
            register, _pin(register, "newpkg", reason="cooldown", until="2026-12-01")
        )
        monkeypatch.setattr(script, "load_blocks", lambda path: blocks)
        argv = _argv(project, "--cooldown-report")
        early = datetime(2026, 11, 30, tzinfo=timezone.utc)
        assert script.main(argv, now=early) == 0
        assert "no cooldown" in capsys.readouterr().out
        late = datetime(2026, 12, 2, tzinfo=timezone.utc)
        assert script.main(argv, now=late) == 1
        assert "newpkg" in capsys.readouterr().out

    def test_the_cooldown_report_needs_no_uv(self, script, project):
        def refuse(argv, stdin, env):
            raise AssertionError("the cooldown report must not run uv")

        argv = _argv(project, "--cooldown-report")
        assert script.main(argv, runner=refuse, now=NOW) == 0

    def test_exactly_one_mode_is_required(self, script, project):
        for argv in ([], ["--check", "--record"]):
            with pytest.raises(SystemExit) as raised:
                script.main(argv, runner=FakeUv(script), now=NOW)
            assert raised.value.code == 2

    def test_recording_while_a_requirement_is_planted_is_not_offered(self, script):
        assert "--plant" not in script.build_parser().format_help()


class TestTheCommittedFiles:
    def test_the_script_uses_only_the_standard_library(self):
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        assert roots, "the script imports nothing; this test would read nothing"
        assert roots <= set(sys.stdlib_module_names), sorted(
            roots - set(sys.stdlib_module_names)
        )

    def test_the_script_never_asks_a_shell_to_run_uv(self):
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        shell_calls = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.keyword)
            and node.arg == "shell"
            and isinstance(node.value, ast.Constant)
            and node.value.value
        ]
        assert shell_calls == []

    def test_the_committed_record_is_readable_and_in_the_json_hooks_format(
        self, script
    ):
        record = script.load_record(RECORD_PATH)
        text = RECORD_PATH.read_bytes().decode("utf-8")
        assert text == script.render_record(record)
        assert (
            text
            == json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=True)
            + "\n"
        )

    def test_the_committed_record_covers_the_platforms_the_script_measures(
        self, script
    ):
        record = script.load_record(RECORD_PATH)
        metadata = record["metadata"]
        assert metadata["platforms"] == {p.key: p.triple for p in script.PLATFORMS}
        assert "core" in record["sets"]
        for name, rows in record["sets"].items():
            assert set(rows) == set(metadata["platforms"]), name
            for cells in rows.values():
                assert set(cells) == set(metadata["pythons"]), name

    def test_the_committed_record_says_how_and_when_it_was_measured(self, script):
        metadata = script.load_record(RECORD_PATH)["metadata"]
        measured_at = script.parse_timestamp(metadata["measured_at"])
        cutoff = script.parse_timestamp(metadata["exclude_newer"])
        assert measured_at - cutoff == script.parse_duration(metadata["cooldown"])
        assert re.fullmatch(r"\d+\.\d+\.\d+", metadata["uv_version"])
        assert "--no-build" in metadata["command"]
        assert metadata["index"] == "https://pypi.org/simple"
        assert metadata["origin"].strip()


def _workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _steps(job):
    return job.get("steps") or []


def _runs(workflow):
    return [
        (name, step["run"])
        for name, job in workflow["jobs"].items()
        for step in _steps(job)
        if "run" in step
    ]


class TestTheWorkflow:
    def test_it_runs_on_the_files_it_depends_on_and_on_a_weekly_schedule(self):
        workflow = _workflow()
        triggers = workflow.get("on", workflow.get(True))
        assert set(triggers) == {"pull_request", "schedule", "workflow_dispatch"}
        paths = triggers["pull_request"]["paths"]
        assert set(paths) == {
            "pyproject.toml",
            "uv.lock",
            "automated_security_helper/base/plugin_provisioning.py",
            "scripts/check_platform_wheels.py",
            "scripts/platform_wheels.json",
            ".github/workflows/ash-platform-wheels.yml",
        }
        for path in paths:
            assert (REPO_ROOT / path).exists(), path
        (entry,) = triggers["schedule"]
        fields = entry["cron"].split()
        assert len(fields) == 5
        assert fields[2:4] == ["*", "*"] and fields[4] != "*", entry["cron"]

    def test_it_reads_the_repository_and_nothing_else(self):
        workflow = _workflow()
        assert workflow["permissions"] == {"contents": "read"}
        for name, job in workflow["jobs"].items():
            assert job["permissions"] == {"contents": "read"}, name
            assert isinstance(job["timeout-minutes"], int), name
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        assert not re.search(r"\$\{\{\s*secrets\.", text)
        for name, run in _runs(workflow):
            assert "${{" not in run, f"{name}: an expression inside a script"

    def test_every_action_is_pinned_to_a_commit_with_its_release_beside_it(self):
        lines = [
            line
            for line in WORKFLOW_PATH.read_text(encoding="utf-8").splitlines()
            if re.match(r"\s*(-\s+)?uses:", line)
        ]
        assert lines
        for line in lines:
            assert re.search(r"@[0-9a-f]{40} # v\d", line), line

    def test_checkout_keeps_no_credentials(self):
        for name, job in _workflow()["jobs"].items():
            for step in _steps(job):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False, name

    def test_uv_is_pinned_to_a_version(self):
        versions = [
            step["with"]["version"]
            for job in _workflow()["jobs"].values()
            for step in _steps(job)
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
        ]
        assert versions
        for version in versions:
            assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

    def test_pull_requests_check_and_plant_but_never_report_cooldowns(self):
        workflow = _workflow()
        measuring = [
            name
            for name, run in _runs(workflow)
            if "--check" in run or "--controls" in run
        ]
        assert measuring, "no job runs the check"
        for name in set(measuring):
            assert "if" not in workflow["jobs"][name], f"{name} skips pull requests"
        reporting = {
            name for name, run in _runs(workflow) if "--cooldown-report" in run
        }
        assert len(reporting) == 1
        (name,) = reporting
        condition = workflow["jobs"][name]["if"]
        assert "schedule" in condition and "pull_request" not in condition
        assert name not in set(measuring)

    def test_the_check_and_the_controls_both_run(self):
        runs = " ".join(run for _, run in _runs(_workflow()))
        assert "--check" in runs and "--controls" in runs

    def test_what_the_workflow_runs_exists_in_the_script(self, script):
        help_text = script.build_parser().format_help()
        for _, run in _runs(_workflow()):
            for flag in re.findall(r"--[a-z][a-z-]*", run):
                assert flag in help_text, flag
            for path in re.findall(r"scripts/[\w.]+\.py", run):
                assert (REPO_ROOT / path).is_file(), path

    def test_the_measured_record_is_kept_whatever_the_outcome(self):
        uploads = [
            step
            for job in _workflow()["jobs"].values()
            for step in _steps(job)
            if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        ]
        assert len(uploads) == 1
        (upload,) = uploads
        assert re.search(r"\b(always|cancelled|failure)\(", upload["if"])
        assert upload["with"]["if-no-files-found"] == "ignore"
        assert "platform_wheels" in upload["with"]["path"]
