"""PyPI pins in the provisioning register, and the rules that keep them honest.

``base/plugin_provisioning.py`` declares what the engine provisions for each scanner.
It now also records the PyPI distribution an alpha scanner installs (``PypiPin``), the
reason a distribution is held out of the alpha extra (``Exclusion``), and, for a content
database, the environment variable that moves its cache (``ContentDatabase.cache_env``).

The registry refuses six contradictions in pins, and each refusal here has a planted
input that must be refused and a sibling input, differing only in the flagged property,
that must be accepted. Without the sibling a pass could mean the check refuses
everything.

Every name the unit adds is read inside a test body, so the rows that exist today stay
importable and the new rows fail one by one where the names do not exist.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
import re
from datetime import timedelta
from pathlib import Path

import pytest

from automated_security_helper.base import plugin_provisioning as prov
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.utils.sandbox.policy import (
    SandboxPolicy,
    SandboxRequirements,
)

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE = _ROOT / "automated_security_helper"


# ---------------------------------------------------------------------------
# Builders. Each reads the new names when it is called, not when this file loads.
# ---------------------------------------------------------------------------


def _pin(**changes):
    """A pin that is a member of the alpha extra. A case that excludes the pin says
    ``extra=""`` as well, because a pin is a member or excluded and never both."""
    fields = {
        "distribution": "alpha-tool",
        "specifier": "==1.0.0",
        "runtime": "uv-tool",
        "extra": "alpha",
    }
    fields.update(changes)
    return prov.PypiPin(**fields)


def _exclusion(reason="OWNER_HOLD", **changes):
    fields = {
        "reason": prov.ExclusionReason[reason],
        "detail": "a detail",
        "measured": "a measurement",
    }
    fields.update(changes)
    return prov.Exclusion(**fields)


def _block(*pins):
    return prov.Provisioning(pypi_pins=tuple(pins))


# ---------------------------------------------------------------------------
# The vocabulary and the shapes
# ---------------------------------------------------------------------------


def test_the_exclusion_reasons_are_the_six_the_register_names() -> None:
    assert [reason.value for reason in prov.ExclusionReason] == [
        "core_pin_conflict",
        "extra_conflict",
        "needs_build",
        "no_wheels",
        "cooldown",
        "owner_hold",
    ]
    assert issubclass(prov.ExclusionReason, str)


def test_a_pin_needs_only_a_distribution_a_specifier_and_a_runtime() -> None:
    pin = prov.PypiPin("tool", "==1", "uv-tool")

    assert pin.with_requirements == ()
    assert pin.python_marker == ""
    assert pin.platform_marker == ""
    assert pin.extra == ""
    assert pin.excluded is None
    assert pin.note == ""
    assert prov.Exclusion(prov.ExclusionReason.OWNER_HOLD, "d", "m").until == ""


def test_a_provisioning_block_with_no_pin_has_an_empty_tuple() -> None:
    """Every block that exists today keeps meaning what it meant."""
    assert prov.Provisioning().pypi_pins == ()
    assert prov.NO_PROVISIONING.pypi_pins == ()


def test_a_pin_and_its_exclusion_are_values() -> None:
    pin = _pin(excluded=_exclusion())

    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.specifier = "==2"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.excluded.detail = "another"  # type: ignore[misc]
    assert _pin() == _pin()
    assert _pin() != _pin(specifier="==2.0.0")


@pytest.mark.parametrize(
    ("name", "normalized"),
    [
        ("Foo_Bar", "foo-bar"),
        ("foo.bar", "foo-bar"),
        ("FOO--bar", "foo-bar"),
        ("a_._b", "a-b"),
        ("ferret-scan", "ferret-scan"),
        ("foobar", "foobar"),
    ],
)
def test_a_distribution_name_is_compared_the_way_pep_503_normalizes_it(
    name, normalized
) -> None:
    assert prov.normalize_distribution(name) == normalized


# ---------------------------------------------------------------------------
# The six refusals, each with a planted input and an accepted sibling
# ---------------------------------------------------------------------------


def _same_distribution_in_two_scanners():
    return {"a": _block(_pin()), "b": _block(_pin())}


def _same_distribution_twice_in_one_block():
    return {"a": _block(_pin(), _pin(specifier="==2.0.0"))}


def _same_distribution_under_two_spellings():
    return {
        "a": _block(_pin(distribution="Foo_Bar")),
        "b": _block(_pin(distribution="foo.bar")),
    }


def _a_member_that_is_also_excluded():
    return {"a": _block(_pin(extra="alpha", excluded=_exclusion()))}


def _a_specifier_with_a_marker_in_it():
    return {"a": _block(_pin(specifier=">=1.0; python_version < '3.14'"))}


def _an_empty_specifier():
    return {"a": _block(_pin(specifier=""))}


def _a_blank_specifier():
    return {"a": _block(_pin(specifier="   "))}


def _a_cooldown_with_no_date():
    return {"a": _block(_pin(extra="", excluded=_exclusion("COOLDOWN")))}


def _a_pin_that_is_neither_a_member_nor_excluded():
    return {"a": _block(_pin(extra=""))}


def _a_member_of_an_extra_nothing_names():
    return {"a": _block(_pin(extra="alhpa"))}


_DUPLICATE = "is pinned twice"
_BOTH = "as a member of the 'alpha' extra and also excludes it"
_NEITHER = "as neither a member of an extra nor excluded from one"
_UNKNOWN_EXTRA = "as a member of the unknown extra 'alhpa'"
_SPECIFIER = "must be non-empty and hold no ';'"
_COOLDOWN = "cooldown exclusion of 'alpha-tool' carries no 'until' date"

_REFUSED = {
    "a distribution pinned by two scanners": (
        _same_distribution_in_two_scanners,
        _DUPLICATE,
    ),
    "a distribution pinned twice in one block": (
        _same_distribution_twice_in_one_block,
        _DUPLICATE,
    ),
    "a distribution under two spellings": (
        _same_distribution_under_two_spellings,
        _DUPLICATE,
    ),
    "a member that is also excluded": (_a_member_that_is_also_excluded, _BOTH),
    "a pin that is neither a member nor excluded": (
        _a_pin_that_is_neither_a_member_nor_excluded,
        _NEITHER,
    ),
    "a member of an extra nothing names": (
        _a_member_of_an_extra_nothing_names,
        _UNKNOWN_EXTRA,
    ),
    "a specifier holding a marker": (_a_specifier_with_a_marker_in_it, _SPECIFIER),
    "an empty specifier": (_an_empty_specifier, _SPECIFIER),
    "a blank specifier": (_a_blank_specifier, _SPECIFIER),
    "a cooldown with no date": (_a_cooldown_with_no_date, _COOLDOWN),
}


def _two_different_distributions():
    return {"a": _block(_pin()), "b": _block(_pin(distribution="other-tool"))}


def _two_distributions_that_only_look_alike():
    return {
        "a": _block(_pin(distribution="foo-bar")),
        "b": _block(_pin(distribution="foobar")),
    }


def _a_member_that_is_not_excluded():
    return {"a": _block(_pin(extra="alpha"))}


def _an_exclusion_that_is_not_a_member():
    return {"a": _block(_pin(extra="", excluded=_exclusion()))}


def _a_range_and_the_markers_in_their_own_fields():
    return {
        "a": _block(
            _pin(
                specifier=">=2.4.5,<2.7.0",
                with_requirements=("pluggy<1.7",),
                python_marker="python_version < '3.14'",
                platform_marker="sys_platform != 'win32'",
            )
        )
    }


def _a_cooldown_with_a_date():
    return {
        "a": _block(_pin(extra="", excluded=_exclusion("COOLDOWN", until="2026-12-01")))
    }


def _an_exclusion_that_needs_no_date():
    return {
        "a": _block(
            _pin(extra="", excluded=_exclusion("NEEDS_BUILD")),
            _pin(distribution="b", extra="", excluded=_exclusion("NO_WHEELS")),
        )
    }


_ACCEPTED = {
    "two different distributions": _two_different_distributions,
    "two distributions that only look alike": _two_distributions_that_only_look_alike,
    "a member that is not excluded": _a_member_that_is_not_excluded,
    "an exclusion that is not a member": _an_exclusion_that_is_not_a_member,
    "a range with its markers in their own fields": (
        _a_range_and_the_markers_in_their_own_fields
    ),
    "a cooldown with a date": _a_cooldown_with_a_date,
    "an exclusion that needs no date": _an_exclusion_that_needs_no_date,
}


@pytest.mark.parametrize("case", sorted(_REFUSED))
def test_the_registry_refuses_a_contradiction_in_pins(case: str) -> None:
    build, fragment = _REFUSED[case]

    with pytest.raises(prov.ProvisioningRegistryError, match=re.escape(fragment)):
        prov.check_registry(build())


@pytest.mark.parametrize("case", sorted(_ACCEPTED))
def test_the_registry_accepts_a_pin_that_contradicts_nothing(case: str) -> None:
    prov.check_registry(_ACCEPTED[case]())


def test_a_refusal_names_the_scanners_and_the_distribution() -> None:
    """A reader fixing the table is told which blocks to look at."""
    with pytest.raises(prov.ProvisioningRegistryError) as excinfo:
        prov.check_registry(_same_distribution_in_two_scanners())

    message = str(excinfo.value)
    assert "'alpha-tool'" in message
    assert "'a'" in message and "'b'" in message


def test_the_shipped_pins_pass_the_rules() -> None:
    prov.check_registry()


# ---------------------------------------------------------------------------
# What the register holds today
# ---------------------------------------------------------------------------

#: scanner -> (distribution, runtime). ferret-scan installs into the environment ASH
#: runs in; GuardDog is a uv tool with an environment of its own.
_SEEDS = {
    "ferret-scan": ("ferret-scan", "ash-environment"),
    "guarddog": ("guarddog", "uv-tool"),
}


@pytest.mark.parametrize("scanner", sorted(_SEEDS))
def test_an_alpha_python_package_is_pinned_and_held_for_a_maintainer_decision(
    scanner: str,
) -> None:
    distribution, runtime = _SEEDS[scanner]

    (pin,) = prov.provisioning_for(scanner).pypi_pins

    assert (pin.distribution, pin.runtime) == (distribution, runtime)
    assert pin.extra == ""
    assert pin.excluded is not None
    assert pin.excluded.reason is prov.ExclusionReason.OWNER_HOLD
    assert "maintainer" in pin.excluded.detail
    assert pin.excluded.measured.strip()
    assert pin.excluded.until == ""


def test_guarddog_is_held_for_its_python_and_platform_limits() -> None:
    """The markers record what the pin would need if the hold were lifted; the rows
    that say why are the runtime-compat row and ``unsupported_platform_reason``."""
    (pin,) = prov.provisioning_for("guarddog").pypi_pins

    assert pin.python_marker == "python_version < '3.14'"
    assert pin.platform_marker == "sys_platform != 'win32'"


def test_only_the_two_alpha_python_packages_declare_a_pin() -> None:
    declared = sorted(
        name for name, block in prov.PROVISIONING.items() if block.pypi_pins
    )

    assert declared == ["ferret-scan", "guarddog"]


def test_the_alpha_manifests_carry_the_new_blocks() -> None:
    manifests = {m.name: m for m in scanner_manifests()}

    for name in sorted(_SEEDS):
        assert manifests[name].provisioning is prov.PROVISIONING[name], name
        assert manifests[name].provisioning.pypi_pins, name


def test_a_pin_adds_no_release_pin_to_the_tool_table() -> None:
    """A PyPI pin is not a release asset: ``tool_versions`` is unchanged by it."""
    assert "ferret-scan" not in prov.tool_versions()
    assert "guarddog" not in prov.tool_versions()


# ---------------------------------------------------------------------------
# The content database's cache variable
# ---------------------------------------------------------------------------


def test_each_database_names_the_cache_variable_ash_relies_on() -> None:
    """grype's, semgrep's and opengrep's rows named none while ASH reads or sets all
    three variables, so a later unit that read the field would have stated that the
    tool has no variable to move its cache."""
    rows = [(db.name, db.cache_env) for db in prov.content_databases()]

    assert rows == [
        ("grype-db", "GRYPE_DB_CACHE_DIR"),
        ("trivy-db", "TRIVY_CACHE_DIR"),
        ("semgrep-offline-rules", "SEMGREP_RULES_CACHE_DIR"),
        ("opengrep-offline-rules", "OPENGREP_RULES_CACHE_DIR"),
    ]


def _string_constants(path: Path) -> set[str]:
    """Every string literal a module holds, read from its syntax tree: a name in a
    comment, or inside a longer message, is not one."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _scanner_class(scanner: str) -> type:
    """The class a scanner's manifest names."""
    manifests = {m.name: m for m in scanner_manifests()}
    assert scanner in manifests, scanner
    module, _, name = manifests[scanner].entry_points.scanner.partition(":")
    return getattr(importlib.import_module(module), name)


def _scanner_modules(scanner: str) -> list[Path]:
    """The files of the plugin modules that hold a scanner's class or a class it
    inherits from, the scanner's own first. A base that lives outside the plugin
    modules is not one of them: the engine's base names no scanner's variable."""
    paths: list[Path] = []
    for cls in _scanner_class(scanner).__mro__:
        if cls.__module__.startswith("automated_security_helper.plugin_modules."):
            path = Path(inspect.getfile(cls))
            if path not in paths:
                paths.append(path)
    return paths


def test_the_module_reader_takes_in_the_shared_base_and_not_the_generic_one() -> None:
    """Both trivy scanners read their cache variable in ``_trivy_scanner_base.py``,
    which neither scanner module holds, and the base every scanner shares reads no
    scanner's variable."""
    names = {path.name for path in _scanner_modules("trivy-repo")}

    assert {"trivy_repo_scanner.py", "_trivy_scanner_base.py"} <= names
    assert "scanner_plugin.py" not in names


def _image_sets(dockerfile: str, variable: str) -> bool:
    """Whether the image sets the variable with an ``ENV`` line of its own."""
    return bool(re.search(rf"^ENV {variable}=", dockerfile, flags=re.MULTILINE))


def _image_env_value(dockerfile: str, variable: str) -> str | None:
    """The value the image's own ``ENV`` line gives *variable*, without its quotes."""
    match = re.search(
        rf'^ENV {re.escape(variable)}="?([^"\s]+)"?\s*$',
        dockerfile,
        flags=re.MULTILINE,
    )
    return match.group(1) if match else None


def test_the_value_reader_sees_a_quoted_and_a_bare_value_and_not_a_mention() -> None:
    dockerfile = (
        'ENV A_VARIABLE="/quoted/path"\n'
        "ENV B_VARIABLE=/bare/path\n"
        "ENV C_VARIABLE=\n"
        '# ENV D_VARIABLE="/commented"\n'
        "RUN echo ENV E_VARIABLE=/in/a/run\n"
        'ENV A_VARIABLE_LONGER="/other"\n'
    )

    assert _image_env_value(dockerfile, "A_VARIABLE") == "/quoted/path"
    assert _image_env_value(dockerfile, "B_VARIABLE") == "/bare/path"
    assert _image_env_value(dockerfile, "C_VARIABLE") is None
    assert _image_env_value(dockerfile, "D_VARIABLE") is None
    assert _image_env_value(dockerfile, "E_VARIABLE") is None
    assert _image_env_value(dockerfile, "A_VARIABLE_LONGER") == "/other"
    assert _image_env_value(dockerfile, "MISSING") is None


def test_the_readers_see_a_planted_variable_and_not_a_mention(tmp_path: Path) -> None:
    module = tmp_path / "scanner.py"
    module.write_text(
        "# A_VARIABLE is only named in this comment.\n"
        'value = environ.get("B_VARIABLE")\n'
        'message = "set C_VARIABLE to move it"\n',
        encoding="utf-8",
    )
    dockerfile = "ENV A_VARIABLE=1\n# ENV B_VARIABLE=2\nRUN echo ENV C_VARIABLE=3\n"

    constants = _string_constants(module)

    assert "B_VARIABLE" in constants
    assert "A_VARIABLE" not in constants and "C_VARIABLE" not in constants
    assert _image_sets(dockerfile, "A_VARIABLE")
    assert not _image_sets(dockerfile, "B_VARIABLE")
    assert not _image_sets(dockerfile, "C_VARIABLE")


_DATABASES = (
    "grype-db",
    "trivy-db",
    "semgrep-offline-rules",
    "opengrep-offline-rules",
)


def _row(database: str) -> prov.ContentDatabase:
    return next(db for db in prov.content_databases() if db.name == database)


@pytest.mark.parametrize("database", _DATABASES)
def test_a_cache_variable_is_one_the_scanner_names_and_the_image_sets(
    database: str,
) -> None:
    """The scanner reads the variable (grype sets it for its child as well) and the
    Dockerfile sets it, so the register records a fact the code holds."""
    row = _row(database)
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    constants = set().union(
        *(_string_constants(path) for path in _scanner_modules(row.scanner))
    )

    assert row.cache_env is not None, database
    assert row.cache_env in constants, database
    assert _image_sets(dockerfile, row.cache_env), database


def _database(**changes) -> prov.ContentDatabase:
    fields = {
        "name": "db",
        "scanner": "a",
        "cache_path": "/deps/.x",
        "max_age": timedelta(hours=1),
        "bound_source": "s",
        "bound_is_tool_default": False,
        "age_source": "a",
        "refresh": "r",
        "cache_env": "X_CACHE_DIR",
    }
    fields.update(changes)
    return prov.ContentDatabase(**fields)


def cache_value_problems(row: prov.ContentDatabase, dockerfile: str) -> list[str]:
    """What the image's value for a row's cache variable says against the row.

    The value is an absolute directory, because a relative one is read against the
    working directory of whoever reads it. A row with an absolute ``cache_path`` names
    the directory the image keeps the cache in, so the image sets the variable to that
    directory. A row whose ``cache_path`` is under ``~`` names the tool's own default,
    which the image moves with the variable, so there is nothing to equate it to."""
    variable = row.cache_env or ""
    value = _image_env_value(dockerfile, variable)
    if value is None:
        return [f"the image sets no {variable}"]
    problems = []
    if not value.startswith("/"):
        problems.append(
            f"the image sets {variable} to {value!r}, which is not absolute"
        )
    if row.cache_path.startswith("/") and value != row.cache_path:
        problems.append(
            f"the row keeps the cache in {row.cache_path!r} and the image sets "
            f"{variable} to {value!r}"
        )
    return problems


def test_the_value_rule_refuses_a_value_the_row_does_not_name() -> None:
    keeps = _database()
    tool_default = _database(cache_path="~/.cache/x")

    assert cache_value_problems(keeps, 'ENV X_CACHE_DIR="/deps/.x"\n') == []
    moved = cache_value_problems(keeps, 'ENV X_CACHE_DIR="/deps/.y"\n')
    assert len(moved) == 1 and "keeps the cache in '/deps/.x'" in moved[0]
    missing = cache_value_problems(keeps, "RUN true\n")
    assert missing == ["the image sets no X_CACHE_DIR"]
    # A row that is the tool's default is not equated to the directory the image moves
    # it to, but the value is an absolute directory whatever the row says.
    assert cache_value_problems(tool_default, 'ENV X_CACHE_DIR="/deps/.x"\n') == []
    relative = cache_value_problems(tool_default, 'ENV X_CACHE_DIR="deps/.x"\n')
    assert len(relative) == 1 and "which is not absolute" in relative[0]


@pytest.mark.parametrize("database", _DATABASES)
def test_the_image_sets_a_cache_variable_to_the_directory_its_row_names(
    database: str,
) -> None:
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert cache_value_problems(_row(database), dockerfile) == [], database


def passes_the_allowlist(requirements: SandboxRequirements, variable: str) -> bool:
    """Whether the sandbox hands *variable* to a scanner that declares *requirements*:
    the policy's own filter, given the scanner's prefixes and names."""
    policy = SandboxPolicy(
        scanner_name="probe",
        read_only=(),
        writable=(Path("/results"),),
        cache=(),
        network=True,
        home=Path("/home/probe"),
        cwd=None,
        env_prefixes=requirements.env_prefixes,
        env_names=requirements.env_names,
    )
    return variable in policy.filter_env({variable: "/deps/.x"})


def test_the_allowlist_reader_tells_a_passed_variable_from_a_dropped_one() -> None:
    trivy = SandboxRequirements(env_prefixes=("TRIVY_",))
    other = SandboxRequirements(env_prefixes=("OTHER_",))

    assert passes_the_allowlist(trivy, "TRIVY_CACHE_DIR")
    assert not passes_the_allowlist(SandboxRequirements(), "TRIVY_CACHE_DIR")
    assert not passes_the_allowlist(other, "TRIVY_CACHE_DIR")
    # A name that looks like a credential is dropped under an allowed prefix, and
    # passes only when the scanner names it.
    assert not passes_the_allowlist(trivy, "TRIVY_PASSWORD")
    named = SandboxRequirements(env_names=("TRIVY_PASSWORD",))
    assert passes_the_allowlist(named, "TRIVY_PASSWORD")


@pytest.mark.parametrize("database", _DATABASES)
def test_a_cache_variable_passes_the_allowlist_of_each_scanner_that_reads_it(
    database: str,
) -> None:
    row = _row(database)

    for scanner in row.readers:
        requirements = _scanner_class(scanner).sandbox_requirements
        assert passes_the_allowlist(requirements, row.cache_env or ""), (
            database,
            scanner,
        )


def test_a_database_may_leave_its_cache_variable_out() -> None:
    database = prov.ContentDatabase(
        name="db",
        scanner="a",
        cache_path="/x",
        max_age=timedelta(hours=1),
        bound_source="s",
        bound_is_tool_default=False,
        age_source="a",
        refresh="r",
    )

    assert database.cache_env is None


def test_the_trivy_plugin_readme_documents_the_cache_variable() -> None:
    """The variable the scanner reads and the image sets is also the one the plugin's
    readme tells an operator to use; the binding tests above read the code."""
    readme_path = _PACKAGE / "plugin_modules" / "ash_trivy_plugins" / "README.md"

    assert "`TRIVY_CACHE_DIR`" in readme_path.read_text(encoding="utf-8")
