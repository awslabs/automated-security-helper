"""The image register: the image-level facts no scanner owns.

``base/image_register.py`` holds what the Dockerfile says about the image as a whole:
its stages, the operating-system family it is built on, the engine tools it installs
before any scanner (uv and crane), the pinned tool that arrives through
``ash dependencies install`` and the programs a hand-written step provides. A scanner's
own route into the image is the ``image`` row on its operational facets.

The module is standard library only and loads by file path, because a weekly checker
reads it before ASH is installed. The rows here hold that property with a probe that
loads the file by path under ``python -I`` and a planted copy that imports the package,
so a clean result is the detector working and not the detector dead.

The seeds are read from the Dockerfile and the tests read the Dockerfile back, so a
stage renamed there, or an engine tool installed under another directory, turns a row
red here and not a build later. The system-package and build-step rows are declared
empty: the package rows arrive with the generator that needs them.

Every name the unit adds is read inside a test body, so each row fails where the module
does not exist, and the file still loads.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE = _ROOT / "automated_security_helper"
_MODULE = _PACKAGE / "base" / "image_register.py"
_DOCKERFILE = (_ROOT / "Dockerfile").read_text(encoding="utf-8")


def _ir():
    return importlib.import_module("automated_security_helper.base.image_register")


# ---------------------------------------------------------------------------
# Reading the Dockerfile
# ---------------------------------------------------------------------------


def dockerfile_stages(text: str) -> dict[str, str]:
    """``{stage name: the stage's lines}`` in file order. A commented-out FROM is not
    a stage, and lines before the first FROM (the global ARGs) belong to none."""
    stages: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        match = re.match(r"^FROM\s+\S+\s+AS\s+(\S+)\s*$", line, flags=re.IGNORECASE)
        if match:
            current = match.group(1)
            stages[current] = []
        elif current is not None:
            stages[current].append(line)
    return {name: "\n".join(lines) for name, lines in stages.items()}


def test_the_stage_reader_has_a_positive_and_a_negative_control() -> None:
    planted = (
        "ARG BASE_IMAGE=x\n"
        "FROM ${BASE_IMAGE} AS one\n"
        "RUN true\n"
        "# FROM ${BASE_IMAGE} AS commented\n"
        "FROM one AS two\n"
        "from two as three\n"
    )

    stages = dockerfile_stages(planted)

    assert list(stages) == ["one", "two", "three"]
    assert "RUN true" in stages["one"]
    assert "ARG BASE_IMAGE" not in "".join(stages.values())
    assert dockerfile_stages("RUN true\n") == {}


def test_the_stage_reader_names_a_stage_as_docker_does() -> None:
    """A FROM line may carry flags, spell AS in any case, indent itself or name no
    stage at all. A stage with no name is filed under its position, which is how
    ``COPY --from=<n>`` refers to it, and a name is folded to lower case."""
    planted = (
        "ARG BASE_IMAGE=x\n"
        "FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS builder\n"
        "RUN one\n"
        "From builder As Mixed\n"
        "RUN two\n"
        "FROM scratch\n"
        "COPY --from=mixed /a /a\n"
        "  FROM --platform=linux/amd64 builder\n"
        "RUN four\n"
    )

    stages = dockerfile_stages(planted)

    assert list(stages) == ["builder", "mixed", "2", "3"]
    assert stages["builder"] == "RUN one"
    assert stages["mixed"] == "RUN two"
    assert stages["2"] == "COPY --from=mixed /a /a"
    assert stages["3"] == "RUN four"


@pytest.mark.parametrize(
    "line",
    [
        "FROM",
        "FROM image extra",
        "FROM image AS",
        "FROM image BEFORE name",
        "FROM image AS 9lives",
        "FROM --platform=linux/amd64 \\",
    ],
)
def test_the_stage_reader_refuses_a_from_line_it_cannot_name(line: str) -> None:
    """A FROM line the reader cannot name would hand its lines to the stage before it,
    and the rows that read a stage by name would read the wrong lines."""
    planted = f"FROM base AS first\nRUN true\n{line}\nRUN false\n"

    with pytest.raises(ValueError, match="cannot name the stage"):
        dockerfile_stages(planted)


def test_the_stage_reader_refuses_a_stage_named_twice() -> None:
    with pytest.raises(ValueError, match="named twice"):
        dockerfile_stages("FROM a AS one\nRUN true\nFROM b AS ONE\n")


def _comment_run(lines: list[str], note: tuple[str, ...]) -> bool:
    """Whether *note* is a run of consecutive lines of *lines*."""
    width = len(note)
    return width > 0 and any(
        tuple(lines[start : start + width]) == note
        for start in range(len(lines) - width + 1)
    )


def test_the_run_reader_has_a_positive_and_a_negative_control() -> None:
    lines = ["# one", "# two", "RUN true", "# three"]

    assert _comment_run(lines, ("# one", "# two"))
    assert _comment_run(lines, ("# two", "RUN true"))
    assert not _comment_run(lines, ("# one", "RUN true"))
    assert not _comment_run(lines, ("# two", "# one"))
    assert not _comment_run(lines, ("# one", "# tw0"))
    assert not _comment_run(lines, ())


# ---------------------------------------------------------------------------
# What the register holds
# ---------------------------------------------------------------------------


def test_the_stages_are_the_four_the_dockerfile_builds() -> None:
    ir = _ir()

    assert [stage.name for stage in ir.IMAGE_STAGES] == [
        "uv-reqs",
        "core",
        "ci",
        "non-root",
    ]
    assert [stage.name for stage in ir.IMAGE_STAGES if stage.pins_dir_inline] == [
        "uv-reqs"
    ]


def test_the_family_is_debian_twelve_under_apt() -> None:
    ir = _ir()

    (family,) = ir.OS_FAMILIES

    assert (family.name, family.package_manager, family.suite) == (
        "debian-bookworm",
        "apt",
        "bookworm",
    )
    assert family.host == ir.HostMatch(ids=("debian",), versions=("12",))
    assert family.host.matches("debian", "12.12")
    assert not family.host.matches("debian", "13")
    assert not family.host.matches("ubuntu", "12.04")


def test_the_engine_steps_are_uv_and_crane() -> None:
    ir = _ir()

    steps = {step.tool: step for step in ir.ENGINE_IMAGE_STEPS}

    assert list(steps) == ["uv", "crane"]
    assert steps["uv"].bin_dir == "/root/.local/bin"
    assert steps["uv"].stages == ("uv-reqs", "core")
    assert steps["uv"].version_check == ("uv", "--version")
    assert steps["crane"].bin_dir == "/usr/local/bin"
    assert steps["crane"].stages == ("core",)
    assert steps["crane"].version_check == ("crane", "version")


def test_opengrep_is_the_one_pinned_tool_dependencies_install_provisions() -> None:
    ir = _ir()

    assert list(ir.PROVISIONED_BY_DEPENDENCIES_INSTALL) == ["opengrep"]
    assert ir.PROVISIONED_BY_DEPENDENCIES_INSTALL["opengrep"].strip()


def test_yarn_and_pnpm_are_the_programs_a_hand_written_step_provides() -> None:
    ir = _ir()

    assert sorted(ir.HAND_WRITTEN_PROVIDES) == ["pnpm", "yarn"]
    assert all(reason.strip() for reason in ir.HAND_WRITTEN_PROVIDES.values())


def test_the_system_package_and_build_step_rows_are_declared_empty() -> None:
    """The package rows arrive with the generator that renders them."""
    ir = _ir()

    assert ir.SYSTEM_PACKAGES == ()
    assert ir.BUILD_STEPS == ()


def test_the_shipped_register_passes_its_own_rules() -> None:
    _ir().check_register()


# ---------------------------------------------------------------------------
# The Dockerfile says the same
# ---------------------------------------------------------------------------


def test_the_stage_names_are_the_dockerfiles_stage_names() -> None:
    ir = _ir()

    assert [stage.name for stage in ir.IMAGE_STAGES] == list(
        dockerfile_stages(_DOCKERFILE)
    )


def test_only_the_stage_that_names_the_pins_directory_inline_is_marked() -> None:
    """``uv-reqs`` prefixes its install with ``ASH_PINS_DIR=/ash-pins``; ``core`` sets
    the variable once for itself and for the two stages built on it."""
    ir = _ir()
    stages = dockerfile_stages(_DOCKERFILE)
    inline = {
        name
        for name, body in stages.items()
        if re.search(r"^RUN ASH_PINS_DIR=/ash-pins ", body, flags=re.MULTILINE)
    }
    in_env = {
        name
        for name, body in stages.items()
        if re.search(r"^ENV ASH_PINS_DIR=", body, flags=re.MULTILINE)
    }

    assert {stage.name for stage in ir.IMAGE_STAGES if stage.pins_dir_inline} == inline
    assert inline == {"uv-reqs"}
    assert in_env == {"core"}


def test_the_family_suite_is_the_suite_of_the_base_image() -> None:
    ir = _ir()
    base = re.search(
        r"^ARG BASE_IMAGE=\S+-slim-(\w+)$", _DOCKERFILE, flags=re.MULTILINE
    )
    debian_release = {"bookworm": "12", "trixie": "13"}

    (family,) = ir.OS_FAMILIES

    assert base is not None
    assert family.suite == base.group(1)
    assert family.host.versions == (debian_release[family.suite],)


def test_each_engine_step_is_installed_and_checked_in_exactly_its_stages() -> None:
    ir = _ir()
    stages = dockerfile_stages(_DOCKERFILE)

    for step in ir.ENGINE_IMAGE_STEPS:
        install = f"install-pinned-tool {step.tool} -b {step.bin_dir}"
        check = "RUN " + " ".join(step.version_check)
        for name, body in stages.items():
            if name in step.stages:
                assert install in body, (step.tool, name)
                pattern = rf"^{re.escape(check)}\s*$"
                assert re.search(pattern, body, flags=re.MULTILINE), (step.tool, name)
            else:
                assert f"install-pinned-tool {step.tool} " not in body, (
                    step.tool,
                    name,
                )
        assert set(step.stages) <= set(stages)


def test_an_engine_step_note_is_a_run_of_dockerfile_comments() -> None:
    ir = _ir()
    lines = _DOCKERFILE.splitlines()

    for step in ir.ENGINE_IMAGE_STEPS:
        if step.dockerfile_note:
            assert all(line.startswith("#") for line in step.dockerfile_note)
            assert _comment_run(lines, step.dockerfile_note), step.tool


# ---------------------------------------------------------------------------
# The rules, each with a planted register that must be refused
# ---------------------------------------------------------------------------


def _nodesource():
    return _ir().PackageSource(
        "nodesource",
        major="20",
        key_url="https://example.invalid/nodesource.gpg",
        list_line="deb https://example.invalid/node_20.x nodistro main",
    )


def _base() -> dict:
    """The parts of a small register that passes every rule. A planted case changes
    one part and leaves the rest as it is."""
    ir = _ir()
    host = ir.HostMatch(ids=("debian",), versions=("12",))
    return {
        "stages": (
            ir.ImageStage("uv-reqs", True),
            ir.ImageStage("core"),
            ir.ImageStage("ci"),
        ),
        "families": (ir.OsFamily("debian-bookworm", "apt", host, "bookworm"),),
        "build_steps": (ir.BuildStep("gems", "core", ("build-essential",)),),
        "packages": (
            ir.SystemPackage(
                key="nodejs",
                rows={"debian-bookworm": ir.OsPackage("nodejs", "20.*", _nodesource())},
                stages=("core",),
                phase="runtime",
                provides=("node", "npm"),
                reason="the JavaScript scanners run on it",
            ),
            ir.SystemPackage(
                key="build-essential",
                rows={"debian-bookworm": ir.OsPackage("build-essential", "12.9")},
                stages=("core",),
                phase="build:gems",
                reason="the gem build needs a compiler",
            ),
        ),
        "engine_steps": (
            ir.EngineImageStep(
                "uv", "/root/.local/bin", ("uv-reqs", "core"), ("uv", "--version")
            ),
        ),
        "provisioned": {"opengrep": "installed by ash dependencies install"},
        "hand_written": {"yarn": "the corepack step"},
    }


def _also(part: str, *extra) -> dict:
    parts = _base()
    parts[part] = parts[part] + tuple(extra)
    return parts


def _replacing(**changes) -> dict:
    parts = _base()
    parts.update(changes)
    return parts


def _package(**changes):
    ir = _ir()
    fields = {
        "key": "extra",
        "rows": {"debian-bookworm": ir.OsPackage("extra")},
        "stages": ("core",),
        "phase": "runtime",
        "provides": ("extra-tool",),
        "reason": "a planted package",
    }
    fields.update(changes)
    return ir.SystemPackage(**fields)


def _engine(**changes):
    ir = _ir()
    fields = {
        "tool": "crane",
        "bin_dir": "/usr/local/bin",
        "stages": ("core",),
        "version_check": ("crane", "version"),
    }
    fields.update(changes)
    return ir.EngineImageStep(**fields)


_REFUSED = {
    "a stage declared twice": (
        lambda ir: _also("stages", ir.ImageStage("core")),
        "stage 'core' is declared twice",
    ),
    "a stage with no name": (
        lambda ir: _also("stages", ir.ImageStage(" ")),
        "a stage has no name",
    ),
    "a family declared twice": (
        lambda ir: _also("families", _base()["families"][0]),
        "family 'debian-bookworm' is declared twice",
    ),
    "a family with no package manager": (
        lambda ir: _also(
            "families",
            ir.OsFamily("alpine-3", " ", ir.HostMatch(ids=("alpine",))),
        ),
        "family 'alpine-3' names no package manager",
    ),
    "an engine step declared twice": (
        lambda ir: _also("engine_steps", _base()["engine_steps"][0]),
        "engine step 'uv' is declared twice",
    ),
    "an engine step in an unknown stage": (
        lambda ir: _also("engine_steps", _engine(stages=("nope",))),
        "engine step 'crane' names the unknown stage 'nope'",
    ),
    "an engine step in no stage": (
        lambda ir: _also("engine_steps", _engine(stages=())),
        "engine step 'crane' names no stage",
    ),
    "an engine step with a relative directory": (
        lambda ir: _also("engine_steps", _engine(bin_dir="usr/local/bin")),
        "engine step 'crane' has the relative bin_dir 'usr/local/bin'",
    ),
    "an engine step with no version check": (
        lambda ir: _also("engine_steps", _engine(version_check=())),
        "engine step 'crane' has no version check",
    ),
    "an engine step with a blank word in its check": (
        lambda ir: _also("engine_steps", _engine(version_check=("crane", " "))),
        "engine step 'crane' has a blank word in its version check",
    ),
    "an engine step note that is not a comment": (
        lambda ir: _also("engine_steps", _engine(dockerfile_note=("RUN true",))),
        "engine step 'crane' has the note line 'RUN true', which is not a comment",
    ),
    "a package declared twice": (
        lambda ir: _also("packages", _base()["packages"][0]),
        "system package 'nodejs' is declared twice",
    ),
    "a package row for an unknown family": (
        lambda ir: _also(
            "packages", _package(rows={"alpine-3": ir.OsPackage("extra")})
        ),
        "system package 'extra' has a row for the unknown family 'alpine-3'",
    ),
    "a package in an unknown stage": (
        lambda ir: _also("packages", _package(stages=("nope",))),
        "system package 'extra' names the unknown stage 'nope'",
    ),
    "a package with a phase that is neither kind": (
        lambda ir: _also("packages", _package(phase="later")),
        (
            "system package 'extra' has the phase 'later'; a phase is 'runtime' or "
            "'build:<step>'"
        ),
    ),
    "a package built by an unknown step": (
        lambda ir: _also("packages", _package(phase="build:missing")),
        "system package 'extra' names the unknown build step 'missing'",
    ),
    "a package with no reason": (
        lambda ir: _also("packages", _package(reason=" ")),
        "system package 'extra' gives no reason",
    ),
    "two packages providing one program": (
        lambda ir: _also("packages", _package(provides=("node",))),
        "the program 'node' is provided by both 'nodejs' and 'extra'",
    ),
    "a package providing what a hand-written step provides": (
        lambda ir: _also("packages", _package(provides=("yarn",))),
        "the program 'yarn' is provided by both 'extra' and a hand-written step",
    ),
    "a build step declared twice": (
        lambda ir: _also("build_steps", _base()["build_steps"][0]),
        "build step 'gems' is declared twice",
    ),
    "a build step in an unknown stage": (
        lambda ir: _also("build_steps", ir.BuildStep("more", "nope", ("a",))),
        "build step 'more' names the unknown stage 'nope'",
    ),
    "a build step with no build package": (
        lambda ir: _also("build_steps", ir.BuildStep("more", "core", ())),
        "build step 'more' lists no build package",
    ),
    "a dependencies-install tool with no reason": (
        lambda ir: _replacing(provisioned={"opengrep": " "}),
        "'opengrep' is provisioned by dependencies install without a reason",
    ),
    "a hand-written program with no reason": (
        lambda ir: _replacing(hand_written={"yarn": ""}),
        "'yarn' is provided by a hand-written step without a reason",
    ),
}


@pytest.mark.parametrize("case", sorted(_REFUSED))
def test_the_register_refuses_a_contradiction(case: str) -> None:
    ir = _ir()
    build, fragment = _REFUSED[case]

    with pytest.raises(ir.ImageRegisterError, match=re.escape(fragment)):
        ir.check_register(**build(ir))


_ACCEPTED = {
    "the small register the planted cases start from": lambda ir: _base(),
    "a second family on another package manager": lambda ir: _also(
        "families",
        ir.OsFamily(
            "alpine-3", "apk", ir.HostMatch(ids=("alpine",), versions=("3.24",))
        ),
    ),
    "a package that provides nothing": lambda ir: _also(
        "packages", _package(provides=())
    ),
    "a package built by a declared step": lambda ir: _also(
        "packages", _package(phase="build:gems", provides=())
    ),
    "an engine step with a note": lambda ir: _also(
        "engine_steps", _engine(dockerfile_note=("# a comment", "#"))
    ),
    "no hand-written program and no provisioned tool": lambda ir: _replacing(
        provisioned={}, hand_written={}
    ),
}


@pytest.mark.parametrize("case", sorted(_ACCEPTED))
def test_the_register_accepts_a_register_that_contradicts_nothing(case: str) -> None:
    ir = _ir()

    ir.check_register(**_ACCEPTED[case](ir))


def test_a_refusal_is_a_value_error() -> None:
    ir = _ir()

    assert issubclass(ir.ImageRegisterError, ValueError)


# ---------------------------------------------------------------------------
# The value types refuse a malformed row when it is built
# ---------------------------------------------------------------------------


def test_a_distro_source_is_the_default_and_carries_no_nodesource_field() -> None:
    ir = _ir()

    assert ir.PackageSource() == ir.PackageSource("distro")
    assert ir.OsPackage("jq").source == ir.PackageSource("distro")
    assert ir.OsPackage("jq").version == ""
    with pytest.raises(ValueError, match="a distro source carries no nodesource field"):
        ir.PackageSource("distro", major="20")


def test_a_nodesource_source_names_its_major_its_key_and_its_list_line() -> None:
    ir = _ir()

    assert _nodesource().major == "20"
    for missing in ("major", "key_url", "list_line"):
        fields = {
            "major": "20",
            "key_url": "https://example.invalid/nodesource.gpg",
            "list_line": "deb https://example.invalid/node_20.x nodistro main",
        }
        fields[missing] = " "
        with pytest.raises(
            ValueError,
            match="a nodesource source names its major, key_url and list_line",
        ):
            ir.PackageSource("nodesource", **fields)


def test_a_source_kind_the_register_does_not_know_is_refused() -> None:
    ir = _ir()

    with pytest.raises(ValueError, match="unknown source kind 'ppa'"):
        ir.PackageSource("ppa")


@pytest.mark.parametrize("names", [(), (" ",), ("debian", "")])
def test_a_host_match_names_at_least_one_id_and_no_blank_one(names) -> None:
    ir = _ir()

    with pytest.raises(ValueError, match="a host match names at least one id"):
        ir.HostMatch(ids=names)


@pytest.mark.parametrize(
    ("os_id", "version_id", "expected"),
    [
        ("alpine", "3.24", True),
        ("alpine", "3.24.4", True),
        ("alpine", "3.240", False),
        ("alpine", "3.2", False),
        ("alpine", "", False),
        ("Alpine", "3.24", False),
        ("wolfi", "3.24", False),
    ],
)
def test_a_version_prefix_matches_on_a_dot_boundary(
    os_id: str, version_id: str, expected: bool
) -> None:
    match = _ir().HostMatch(ids=("alpine",), versions=("3.24",))

    assert match.matches(os_id, version_id) is expected


def test_a_host_match_with_no_versions_takes_every_version_of_its_ids() -> None:
    match = _ir().HostMatch(ids=("opensuse-tumbleweed", "arch"))

    assert match.matches("arch", "")
    assert match.matches("opensuse-tumbleweed", "20261101")
    assert not match.matches("opensuse-leap", "16.0")


# ---------------------------------------------------------------------------
# Standard library only, and loadable by path
# ---------------------------------------------------------------------------

_LOAD_BY_PATH = """
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("_image_register_probe", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
print(json.dumps({
    "package_modules": sorted(
        name for name in sys.modules
        if name.split(".")[0] == "automated_security_helper"
    ),
    "stages": [stage.name for stage in module.IMAGE_STAGES],
}))
"""


def _load_by_path(path: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _LOAD_BY_PATH, str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_the_register_loads_by_file_path_and_imports_nothing_from_the_package() -> None:
    probe = _load_by_path(_MODULE)

    assert probe["package_modules"] == []
    assert probe["stages"] == ["uv-reqs", "core", "ci", "non-root"]


def test_the_probe_sees_a_planted_package_import(tmp_path: Path) -> None:
    """Planted control: the same module with one package import appended."""
    planted = tmp_path / "image_register_planted.py"
    planted.write_text(
        _MODULE.read_text(encoding="utf-8")
        + "\n\nimport sys as _sys\n"
        + f"_sys.path.insert(0, {str(_ROOT)!r})\n"
        + "import automated_security_helper.core.enums  # planted\n",
        encoding="utf-8",
    )

    probe = _load_by_path(planted)

    assert "automated_security_helper.core.enums" in probe["package_modules"]


def _imports_beyond_the_standard_library(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = ["." * node.level + (node.module or "")]
        else:
            continue
        found.extend(
            name for name in names if name.split(".")[0] not in sys.stdlib_module_names
        )
    return sorted(found)


def _calls_at_import(source: str, function: str) -> bool:
    return any(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == function
        for node in ast.parse(source).body
    )


def test_the_static_checks_have_a_positive_and_a_negative_control() -> None:
    assert _imports_beyond_the_standard_library("import yaml\n") == ["yaml"]
    assert _imports_beyond_the_standard_library("def f():\n    import yaml\n") == [
        "yaml"
    ]
    assert _imports_beyond_the_standard_library("import re\nimport enum\n") == []
    assert _calls_at_import("check()\n", "check")
    assert not _calls_at_import("def check():\n    check()\n", "check")
    assert not _calls_at_import("x = check()\n", "check")


def test_the_register_source_imports_only_the_standard_library() -> None:
    assert _imports_beyond_the_standard_library(_MODULE.read_text("utf-8")) == []


def test_the_register_checks_itself_when_it_is_imported() -> None:
    assert _calls_at_import(_MODULE.read_text("utf-8"), "check_register")
