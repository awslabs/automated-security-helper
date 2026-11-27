"""The support register: what ASH supports, polyfills, degrades or refuses.

The register is declared data plus one evaluator. These tests hold the data to
the rules it states about itself, in the order the rules are stated:

- construction refuses a row, polyfill, path or profile that breaks a rule
  (each refusal is built from a valid control with one field changed, so a
  passing refusal is the rule firing and not a malformed fixture);
- every token of every dimension is supported, covered by a row, or declared
  "not declared" with its reason (the totality rule);
- every upgrade path a degraded or unsupported row offers leads somewhere the
  row's problem is gone (the validity rule), with must-fail controls and the
  shipped register as the must-not-flag control;
- the evaluator, the matrix cell mapping and the refusal accessor read the
  declared rows and nothing else;
- the scanner skip rows carry, byte for byte, the text today's scan records.

Nothing here reads the host the tests run on: facts are planted.
"""

from __future__ import annotations

import ast
import functools
import itertools
import json
import re
import subprocess  # nosec B404 - fixed argv, sys.executable, no shell
import sys
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base import support_register as sr
from tests.utils.helpers import importing_this_checkout
from tests.utils.scanner_enumeration import load_scanner_universe
from tests.utils.support_gaps import all_platforms_but, pinned_binaries

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PAGE = REPO_ROOT / "docs" / "content" / "how-to" / "supported-configurations.md"


@functools.cache
def _universe() -> tuple[type, ...]:
    """The scanner classes ASH ships, loaded once for every test that reads them."""
    classes, _errors = load_scanner_universe()
    return tuple(classes)


def _facets(cls: type) -> opsf.ScannerOperationalFacets:
    return vars(cls)[opsf.OPERATIONAL_FACETS_ATTR]


def _pinned_binaries() -> list[sr.PinnedBinary]:
    """One record per scanner whose tool ASH downloads, from the register and the
    download table the consistency test already binds together."""
    return pinned_binaries(_universe())


def _facts(**overlay: str) -> sr.HostFacts:
    """The reference facts with ``overlay`` on them, settled as a run's are."""
    return sr.settle(replace(sr.REFERENCE_FACTS, **overlay))


# ---------------------------------------------------------------------------
# Valid controls. Every refusal below changes one field of one of these.
# ---------------------------------------------------------------------------


def _polyfill(**changes: Any) -> sr.Polyfill:
    base: dict[str, Any] = {
        "id": "demo-stand-in",
        "name": "Demo stand-in",
        "kind": sr.PolyfillKind.SUBSTITUTE,
        "cell": "demo stand-in",
        "stands_in_for": "a capability this demo platform lacks",
        "difference": "it is slower than the original",
        "code_sites": (),
    }
    return sr.Polyfill(**{**base, **changes})


def _path(**changes: Any) -> sr.UpgradePath:
    base: dict[str, Any] = {
        "id": "demo-path",
        "kind": sr.PathKind.OTHER_HOST,
        "summary": "Run ASH on another machine.",
        "target": "LINUX_AMD64",
        "available_when": sr.Match(),
        "docs": "how-to/supported-configurations.md#demo-path",
    }
    return sr.UpgradePath(**{**base, **changes})


def _row(**changes: Any) -> sr.SupportRow:
    base: dict[str, Any] = {
        "id": "demo.row",
        "scope": "ash",
        "dimension": "os",
        "match": sr.Match(host_os=("other",)),
        "level": sr.SupportLevel.UNSUPPORTED,
        "behavior": sr.Behavior.CONTINUES,
        "notify": sr.Notify.START,
        "reason": "This demo configuration is unsupported.",
        "cell": "demo configuration",
        "paths": ("ci-runner",),
    }
    return sr.SupportRow(**{**base, **changes})


def _degraded(**changes: Any) -> sr.SupportRow:
    base: dict[str, Any] = {
        "level": sr.SupportLevel.DEGRADED,
        "lost": "a demo function is lost",
    }
    return _row(**{**base, **changes})


def _with(**parts: Any) -> sr.Register:
    """The shipped register plus the given rows, paths and polyfills."""
    return sr.REGISTER.extended(**parts)


def test_the_controls_construct() -> None:
    assert _polyfill().kind is sr.PolyfillKind.SUBSTITUTE
    assert _path().kind is sr.PathKind.OTHER_HOST
    assert _row().level is sr.SupportLevel.UNSUPPORTED
    assert _degraded().lost
    register = _with(rows=(_row(),), paths=(_path(),), polyfills=(_polyfill(),))
    assert register.row("demo.row").id == "demo.row"
    assert register.path("demo-path").id == "demo-path"


# ---------------------------------------------------------------------------
# Construction refuses: a row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["reason", "cell"])
def test_a_blank_reason_or_cell_is_refused(field: str) -> None:
    with pytest.raises(sr.SupportRegisterError, match=field):
        _row(**{field: "   "})


@pytest.mark.parametrize("field", ["reason", "cell"])
def test_a_non_ascii_reason_or_cell_is_refused(field: str) -> None:
    with pytest.raises(sr.SupportRegisterError, match="ASCII"):
        _row(**{field: "caf" + chr(233)})


def test_a_cell_phrase_is_at_most_forty_eight_characters() -> None:
    assert sr.CELL_LIMIT == 48
    assert _row(cell="x" * 48).cell == "x" * 48
    with pytest.raises(sr.SupportRegisterError, match="48"):
        _row(cell="x" * 49)


def test_a_dimension_outside_the_declared_set_is_refused() -> None:
    with pytest.raises(sr.SupportRegisterError, match="dimension"):
        _row(dimension="weather")


def test_a_polyfilled_row_needs_a_polyfill() -> None:
    with pytest.raises(sr.SupportRegisterError, match="polyfill"):
        _row(level=sr.SupportLevel.POLYFILLED, polyfill=None, paths=())


def test_a_degraded_row_needs_its_loss_and_its_paths() -> None:
    with pytest.raises(sr.SupportRegisterError, match="lost"):
        _degraded(lost=None)
    with pytest.raises(sr.SupportRegisterError, match="paths"):
        _degraded(paths=())


def test_an_unsupported_row_is_always_shown_and_always_names_paths() -> None:
    with pytest.raises(sr.SupportRegisterError, match="cli"):
        _row(cli=False)
    with pytest.raises(sr.SupportRegisterError, match="matrix"):
        _row(notify=sr.Notify.MATRIX)
    with pytest.raises(sr.SupportRegisterError, match="paths"):
        _row(paths=())


def test_a_matrix_only_row_never_asks_for_the_console() -> None:
    assert _degraded(notify=sr.Notify.MATRIX).notify is sr.Notify.MATRIX
    with pytest.raises(sr.SupportRegisterError, match="cli"):
        _degraded(notify=sr.Notify.MATRIX, cli=True)


def test_a_token_outside_its_field_vocabulary_is_refused() -> None:
    with pytest.raises(sr.SupportRegisterError, match="plan9"):
        sr.Match(host_os=("plan9",))
    with pytest.raises(sr.SupportRegisterError, match="tuple"):
        sr.Match(host_os="linux")  # type: ignore[arg-type]


def test_unknown_never_names_a_row_that_is_not_supported() -> None:
    """``unknown`` is what a failed read answers, and it must raise nothing."""
    assert sr.Match(arch=("unknown",)).arch == ("unknown",)
    with pytest.raises(sr.SupportRegisterError, match="unknown"):
        _row(match=sr.Match(arch=("unknown",)))


# ---------------------------------------------------------------------------
# Construction refuses: the register around the rows
# ---------------------------------------------------------------------------


def test_a_row_naming_an_unknown_path_or_polyfill_is_refused() -> None:
    with pytest.raises(sr.SupportRegisterError, match="no-such-path"):
        _with(rows=(_row(paths=("no-such-path", "ci-runner")),))
    with pytest.raises(sr.SupportRegisterError, match="no-such-stand-in"):
        _with(
            rows=(
                _row(
                    level=sr.SupportLevel.POLYFILLED,
                    polyfill="no-such-stand-in",
                    paths=(),
                ),
            )
        )


def test_a_path_naming_an_unknown_profile_is_refused() -> None:
    with pytest.raises(sr.SupportRegisterError, match="NO_SUCH_PROFILE"):
        _with(paths=(_path(target="NO_SUCH_PROFILE"),))
    with pytest.raises(sr.SupportRegisterError, match="NO_SUCH_PROFILE"):
        _with(paths=(_path(target=("LINUX_AMD64", "NO_SUCH_PROFILE")),))


def test_an_unsupported_row_with_only_same_os_paths_is_refused() -> None:
    """An unsupported row offers at least one way out on another system: a container,
    WSL, another OS, another host or a CI runner."""
    assert sr.REGISTER.path("polars-compat-runtime").kind is sr.PathKind.SAME_OS
    with pytest.raises(sr.SupportRegisterError, match="same-os"):
        _with(rows=(_row(paths=("polars-compat-runtime",)),))
    assert _with(rows=(_row(paths=("polars-compat-runtime", "ci-runner")),))


def test_a_supported_row_names_an_adaptation_and_nothing_else() -> None:
    supported = {
        "level": sr.SupportLevel.SUPPORTED,
        "behavior": sr.Behavior.CONTINUES,
        "notify": sr.Notify.MATRIX,
        "paths": (),
    }
    adaptation = _polyfill(
        id="demo-adaptation",
        kind=sr.PolyfillKind.ADAPTATION,
        difference=None,
    )
    ok = _row(**supported, polyfill="demo-adaptation")
    assert _with(rows=(ok,), polyfills=(adaptation,))
    with pytest.raises(sr.SupportRegisterError, match="adaptation"):
        _with(rows=(_row(**supported, polyfill="powershell-5-compat"),))
    with pytest.raises(sr.SupportRegisterError, match="adaptation"):
        _with(rows=(_row(**supported, polyfill=None),))


@pytest.mark.parametrize(
    "parts",
    [
        {"rows": (_row(id="host.os.other"),)},
        {"paths": (_path(id="ci-runner"),)},
        {"polyfills": (_polyfill(id="polars-compat-runtime"),)},
    ],
    ids=["row", "path", "polyfill"],
)
def test_a_second_declaration_of_an_id_is_refused(parts: dict[str, Any]) -> None:
    with pytest.raises(sr.SupportRegisterError, match="twice|duplicate"):
        _with(**parts)


def test_a_not_declared_token_that_is_supported_or_named_by_a_row_is_refused() -> None:
    """Not declared means that no row and no supported set names the token. A key for
    a token the register declares anywhere else contradicts itself, and a matrix
    would add "not declared" to every cell that holds the token, so the register
    refuses the key when it is built."""
    declared = dict(sr.REGISTER.not_declared)
    assert replace(sr.REGISTER, not_declared=declared).not_declared == declared
    reason = "ASH declares nothing about it."
    with pytest.raises(sr.SupportRegisterError, match="shell=pwsh"):
        replace(sr.REGISTER, not_declared={**declared, ("shell", "pwsh"): reason})
    with pytest.raises(sr.SupportRegisterError, match="host.arch.other"):
        replace(sr.REGISTER, not_declared={**declared, ("arch", "other"): reason})
    with pytest.raises(sr.SupportRegisterError, match="host.os.other"):
        replace(sr.REGISTER, not_declared={**declared, ("os", "other"): reason})


# ---------------------------------------------------------------------------
# Construction refuses: a path, a polyfill, a profile, the facts
# ---------------------------------------------------------------------------


def test_a_path_on_this_machine_never_names_the_processor_level() -> None:
    """A container or a reinstall changes no processor: the image runs on the
    host's, so a path that claims to change ``cpu_level`` would show a way out
    that is not one."""
    with pytest.raises(sr.SupportRegisterError, match="cpu_level"):
        _path(
            id="demo-here",
            kind=sr.PathKind.SAME_OS,
            target=sr.Match(cpu_level=("full",)),
        )


def test_a_path_on_this_machine_names_arch_only_for_a_translated_run() -> None:
    translated = sr.Match(translation=("rosetta", "x64-on-arm64"))
    assert _path(
        id="demo-here",
        kind=sr.PathKind.SAME_OS,
        target=sr.Match(arch=("arm64",), translation=("native",)),
        available_when=translated,
    )
    with pytest.raises(sr.SupportRegisterError, match="arch"):
        _path(
            id="demo-here",
            kind=sr.PathKind.SAME_OS,
            target=sr.Match(arch=("arm64",)),
        )
    with pytest.raises(sr.SupportRegisterError, match="arch"):
        _path(
            id="demo-here",
            kind=sr.PathKind.SAME_OS,
            target=sr.Match(arch=("arm64",)),
            available_when=sr.Match(translation=("native", "rosetta")),
        )


def test_a_path_target_matches_the_kind_of_path() -> None:
    """On this machine a path overlays tokens; to another machine it names the
    profile it moves to."""
    with pytest.raises(sr.SupportRegisterError, match="profile"):
        _path(kind=sr.PathKind.CI_RUNNER, target=sr.Match(run_mode=("local",)))
    with pytest.raises(sr.SupportRegisterError, match="tokens"):
        _path(kind=sr.PathKind.SAME_OS, target="LINUX_AMD64")


@pytest.mark.parametrize(
    "summary",
    [
        "Run `ash scan` on another machine.",
        "Run ash scan on another machine.",
        "Use ash --version to check.",
        "",
        "Run ASH on another machine, which is caf" + chr(233) + ".",
    ],
)
def test_a_path_sentence_holds_no_command_text(summary: str) -> None:
    """The command is built where the path is offered, and a generated cell refuses
    command text, so the sentence carries none."""
    with pytest.raises(sr.SupportRegisterError):
        _path(summary=summary)


def test_a_path_sentence_may_name_the_product_and_words_that_end_in_ash() -> None:
    assert _path(summary="Run ASH in the bash shell of another machine.")


def test_a_docs_anchor_has_the_one_shape() -> None:
    with pytest.raises(sr.SupportRegisterError, match="docs"):
        _path(docs="how-to/install.md#demo-path")
    with pytest.raises(sr.SupportRegisterError, match="docs"):
        _path(docs="how-to/supported-configurations.md#Demo Path")


def test_a_polyfill_states_what_a_user_can_see_unless_it_is_an_adaptation() -> None:
    assert _polyfill(kind=sr.PolyfillKind.ADAPTATION, difference=None)
    with pytest.raises(sr.SupportRegisterError, match="difference"):
        _polyfill(kind=sr.PolyfillKind.ADAPTATION)
    with pytest.raises(sr.SupportRegisterError, match="difference"):
        _polyfill(difference=None)


@pytest.mark.parametrize(
    "changes",
    [
        {"name": " "},
        {"stands_in_for": ""},
        {"cell": "y" * 49},
        {"code_sites": ("not-a-site",)},
        {"code_sites": ("automated_security_helper/utils/x.py",)},
    ],
    ids=["name", "stands-in-for", "cell", "site-shape", "site-name"],
)
def test_a_polyfill_with_a_blank_or_malformed_field_is_refused(
    changes: dict[str, Any],
) -> None:
    with pytest.raises(sr.SupportRegisterError):
        _polyfill(**changes)


def test_host_facts_refuse_a_token_outside_the_vocabulary() -> None:
    assert sr.HostFacts(arch="arm64").arch == "arm64"
    with pytest.raises(sr.SupportRegisterError, match="m68k"):
        sr.HostFacts(arch="m68k")
    with pytest.raises(sr.SupportRegisterError, match="run_mode"):
        sr.HostFacts(run_mode="remote")


def test_a_profile_states_every_fact_and_its_own_facts_are_possible() -> None:
    profile = sr.REGISTER.profile("LINUX_AMD64")
    missing = {k: v for k, v in profile.possible.items() if k != "wsl"}
    with pytest.raises(sr.SupportRegisterError, match="wsl"):
        replace(profile, possible=missing)
    odd = {**profile.possible, "arch": ("arm64",)}
    with pytest.raises(sr.SupportRegisterError, match="arch"):
        replace(profile, possible=odd)


# ---------------------------------------------------------------------------
# The vocabularies and the totality rule
# ---------------------------------------------------------------------------


def _group_of(field: str) -> tuple[str, ...]:
    for group in sr.FIELD_GROUPS:
        if field in group:
            return group
    return (field,)


def _covered(register: sr.Register, field: str) -> set[str]:
    tokens: set[str] = set()
    for row in register.rows:
        for member in _group_of(field):
            tokens.update(getattr(row.match, member))
    return tokens


def _totality_failures(
    register: sr.Register, vocabulary: dict[str, tuple[str, ...]] | None = None
) -> list[str]:
    """Every token of every dimension that is none of: in the dimension's
    supported set, in the match of some row, or declared not declared."""
    vocabulary = sr.VOCABULARY if vocabulary is None else vocabulary
    failures = []
    for field, tokens in vocabulary.items():
        covered = _covered(register, field)
        for token in tokens:
            if token == sr.UNKNOWN:
                continue
            if token in sr.SUPPORTED_TOKENS[field] or token in covered:
                continue
            if (field, token) in register.not_declared:
                continue
            failures.append(f"{field}={token}")
    return failures


def test_the_facts_and_the_match_name_the_same_dimensions() -> None:
    import dataclasses

    assert [f.name for f in dataclasses.fields(sr.HostFacts)] == list(sr.FIELDS)
    assert [f.name for f in dataclasses.fields(sr.Match)] == list(sr.MATCH_FIELDS)
    assert set(sr.FIELDS) - set(sr.MATCH_FIELDS) == {"os_release"}
    assert set(sr.VOCABULARY) == set(sr.MATCH_FIELDS)
    assert set(sr.SUPPORTED_TOKENS) == set(sr.MATCH_FIELDS)


def test_a_supported_set_is_part_of_its_vocabulary_and_never_unknown() -> None:
    for field, tokens in sr.SUPPORTED_TOKENS.items():
        assert set(tokens) <= set(sr.VOCABULARY[field]), field
        assert sr.UNKNOWN not in tokens, field


def test_every_token_is_supported_covered_by_a_row_or_not_declared() -> None:
    assert _totality_failures(sr.REGISTER) == []
    checked = sum(len(tokens) for tokens in sr.VOCABULARY.values())
    assert checked > 60, checked


def test_a_token_no_row_and_no_supported_set_names_fails_the_totality_rule() -> None:
    planted = {**sr.VOCABULARY, "host_os": (*sr.VOCABULARY["host_os"], "plan9")}
    assert _totality_failures(sr.REGISTER, planted) == ["host_os=plan9"]


def test_dropping_a_not_declared_entry_fails_the_totality_rule() -> None:
    declared = dict(sr.REGISTER.not_declared)
    assert ("libc", "musl") in declared
    del declared[("libc", "musl")]
    register = replace(sr.REGISTER, not_declared=declared)
    assert _totality_failures(register) == ["libc=musl"]


def test_not_declared_names_the_four_tokens_and_says_why() -> None:
    declared = sr.REGISTER.not_declared
    for key in [
        ("libc", "musl"),
        ("wsl", "wsl1"),
        ("python_build", "free-threaded"),
        ("python_build", "other-implementation"),
    ]:
        assert key in declared, key
    for (field, token), reason in declared.items():
        assert token in sr.VOCABULARY[field], (field, token)
        assert reason.isascii() and reason.strip(), (field, token)


def test_not_declared_is_never_shown_as_unsupported() -> None:
    """A token the register is silent on matches no row and is not a level."""
    for field, token in sr.REGISTER.not_declared:
        facts = _facts(**{field: token})
        assert sr.evaluate(facts, "ash") == (), (field, token)


# ---------------------------------------------------------------------------
# Witnesses, offered paths, and the validity rule
# ---------------------------------------------------------------------------


def _admits(profile: sr.Profile, row: sr.SupportRow) -> bool:
    return all(
        any(token in profile.possible[field] for token in tokens)
        for field, tokens in row.match.constraints()
    )


#: The facts a run chooses that a row may leave unnamed. The validity rule tries each
#: one a profile can have on every witness, so a way out that only leads to another
#: row in one mode, or with one sandbox request, is still found.
_CHOSEN = ("run_mode", "sandbox_mode")


def _witnesses(
    register: sr.Register, row: sr.SupportRow
) -> list[tuple[sr.Profile, sr.HostFacts]]:
    """The profile's facts overlaid with each combination of the row's match tokens
    the profile can have and with each run mode and sandbox request the profile can
    have that the row does not name, settled, and still matching the row."""
    found: list[tuple[sr.Profile, sr.HostFacts]] = []
    constraints = row.match.constraints()
    names = [field for field, _ in constraints]
    chosen = [field for field in _CHOSEN if field not in names]
    for profile in register.profiles:
        if not _admits(profile, row):
            continue
        choices = [
            [t for t in tokens if t in profile.possible[field]]
            for field, tokens in constraints
        ]
        picks = [profile.possible[field] for field in chosen]
        seen: set[sr.HostFacts] = set()
        for combo in itertools.product(*choices):
            for pick in itertools.product(*picks):
                overlay = {**dict(zip(names, combo)), **dict(zip(chosen, pick))}
                facts = sr.settle(replace(profile.facts, **overlay))
                if row.match.matches(facts) and facts not in seen:
                    seen.add(facts)
                    found.append((profile, facts))
    return found


def _describe(row: sr.SupportRow, facts: sr.HostFacts) -> str:
    return ", ".join(f"{f}={getattr(facts, f)}" for f, _ in row.match.constraints())


def _validity_failures(
    register: sr.Register, rows: tuple[sr.SupportRow, ...] | None = None
) -> list[str]:
    """The validity rule over the degraded and unsupported rows (and the
    polyfilled rows that advise a path): each row has a witness, every witness is
    offered a path, an unsupported row is offered one that is not same-os, and
    every offered path leaves the row unmatched and trades it for no other
    degraded or unsupported row of the same dimension."""
    failures: list[str] = []
    for row in register.rows if rows is None else rows:
        if row.level is sr.SupportLevel.SUPPORTED:
            continue
        if row.level is sr.SupportLevel.POLYFILLED and not row.paths:
            continue
        witnesses = _witnesses(register, row)
        if not witnesses:
            failures.append(f"{row.id}: no witness, no profile admits its match")
            continue
        for profile, facts in witnesses:
            where = (
                f"{row.id} on {profile.name} ({_describe(row, facts)}, "
                f"run_mode={facts.run_mode}, sandbox_mode={facts.sandbox_mode})"
            )
            offered = register.offered_paths(row, facts)
            if not offered:
                failures.append(f"{where}: no path is offered")
                continue
            if row.level is sr.SupportLevel.UNSUPPORTED and all(
                path.kind is sr.PathKind.SAME_OS for path in offered
            ):
                failures.append(f"{where}: every offered path is same-os")
            for path in offered:
                for after in register.apply_path(path, facts):
                    for found in register.evaluate(after, row.scope):
                        if found.row.id == row.id:
                            failures.append(
                                f"{where}: path {path.id} leaves the row matching"
                            )
                        elif (
                            found.row.level.rank >= sr.SupportLevel.DEGRADED.rank
                            and found.row.dimension == row.dimension
                        ):
                            failures.append(
                                f"{where}: path {path.id} trades it for {found.row.id}"
                            )
    return failures


def _not_supported_rows() -> list[sr.SupportRow]:
    return [r for r in sr.REGISTER.rows if r.level.rank >= 2]


def test_the_shipped_register_passes_the_validity_rule() -> None:
    """The must-not-flag control: every path of every row leads somewhere the
    row's problem is gone, and the rule checked rows, not nothing."""
    assert len(_not_supported_rows()) >= 26
    assert _validity_failures(sr.REGISTER) == []


def test_every_row_that_is_not_supported_has_a_witness_on_some_profile() -> None:
    for row in _not_supported_rows():
        assert _witnesses(sr.REGISTER, row), row.id


def test_the_container_image_is_no_way_out_of_a_missing_instruction_set() -> None:
    """The image runs on the same processor and carries the same default runtime,
    so offering it for the processor row would show a way out that is not one."""
    for row_id in ["host.cpu.below-polars-runtime", "host.cpu.below-polars-compat"]:
        assert "container-image" not in sr.REGISTER.row(row_id).paths, row_id
    row = sr.REGISTER.row("host.cpu.below-polars-runtime")
    plant = replace(
        row, id="plant.cpu", paths=("polars-compat-runtime", "container-image")
    )
    failures = _validity_failures(_with(rows=(plant,)), rows=(plant,))
    assert failures, "a planted CPU row offering the image must fail the rule"
    assert all(f.startswith("plant.cpu on ") for f in failures), failures
    assert any("path container-image leaves the row matching" in f for f in failures), (
        failures
    )


def test_a_path_that_trades_the_problem_for_one_of_the_same_dimension_fails() -> None:
    """Nix on Windows moved into the container image meets the container leftover
    limit; the two are different dimensions, which is why the shipped row is
    valid. Declared as one dimension, the same path is a trade and fails."""
    row = sr.REGISTER.row("host.mode.nix-on-windows")
    assert "container-image" in row.paths
    plant = replace(row, id="plant.trade", dimension="container leftovers")
    failures = _validity_failures(_with(rows=(plant,)), rows=(plant,))
    assert any("trades it for host.windows.container-leftovers" in f for f in failures)


def test_a_row_no_profile_can_have_fails_the_rule() -> None:
    row = sr.REGISTER.row("host.os.other")
    plant = replace(
        row,
        id="plant.nowhere",
        match=sr.Match(host_os=("windows",), wsl=("wsl2",)),
    )
    assert _validity_failures(_with(rows=(plant,)), rows=(plant,)) == [
        "plant.nowhere: no witness, no profile admits its match"
    ]


def test_a_backend_row_needs_the_sandbox_it_belongs_to() -> None:
    """``settle`` makes the backend n/a while the sandbox is off, and in container
    mode, so a row that names a backend without a sandbox mode matches only the runs
    that ask for a sandbox outside a container."""
    row = sr.REGISTER.row("host.sandbox.landlock-below-6")
    assert row.match.sandbox_mode
    plant = replace(
        row,
        id="plant.landlock",
        match=sr.Match(
            sandbox_backend=("landlock",), sandbox_loss=("landlock-below-6",)
        ),
    )
    witnesses = _witnesses(_with(rows=(plant,)), plant)
    assert witnesses
    assert {facts.sandbox_mode for _, facts in witnesses} <= {"auto", "named"}
    assert "container" not in {facts.run_mode for _, facts in witnesses}


def test_a_trade_that_exists_only_in_container_mode_fails_the_rule() -> None:
    """The witnesses try every run mode and sandbox request the row does not name. A
    row about a sandbox that names neither offers a way out that leads, in container
    mode, to the row that says the sandbox is not applied there."""
    row = sr.REGISTER.row("host.sandbox.unavailable-auto")
    plant = replace(
        row,
        id="plant.container-trade",
        match=sr.Match(sandbox_mode=("auto",)),
        paths=("sandbox-capable-host", "install-bubblewrap"),
    )
    failures = _validity_failures(_with(rows=(plant,)), rows=(plant,))
    trades = [f for f in failures if "trades it for" in f]
    assert trades, failures
    assert all(
        "trades it for host.sandbox.not-applied-in-container" in f
        and "run_mode=container" in f
        for f in trades
    ), trades


def test_a_row_whose_paths_are_never_offered_fails_the_rule() -> None:
    plant = _degraded(
        id="plant.nopath",
        match=sr.Match(host_os=("windows",), translation=("native",)),
        paths=("native-arm64",),
    )
    failures = _validity_failures(_with(rows=(plant,)), rows=(plant,))
    assert failures
    assert all("no path is offered" in f for f in failures), failures


def test_an_offered_set_with_only_same_os_paths_fails_for_an_unsupported_row() -> None:
    """The construction rule counts a row's declared paths; the validity rule
    counts the ones offered where it matters. Both must hold."""
    row = sr.REGISTER.row("host.cpu.below-polars-runtime")
    plant = replace(
        row, id="plant.same-os", paths=("polars-compat-runtime", "ci-runner")
    )
    narrowed = sr.REGISTER.path("ci-runner")
    never = replace(
        narrowed, id="plant-never", available_when=sr.Match(host_os=("other",))
    )
    plant = replace(plant, paths=("polars-compat-runtime", "plant-never"))
    failures = _validity_failures(_with(rows=(plant,), paths=(never,)), rows=(plant,))
    assert any("every offered path is same-os" in f for f in failures), failures


def test_a_path_to_another_machine_keeps_only_the_runs_own_choices() -> None:
    facts = _facts(
        os="windows",
        host_os="windows",
        arch="arm64",
        translation="native",
        run_mode="precommit",
        sandbox_mode="auto",
        express_requested="yes",
        shell="pwsh",
        ignore_paths="set",
    )
    (after,) = sr.REGISTER.apply_path(sr.REGISTER.path("ci-runner"), facts)
    assert (after.os, after.host_os, after.arch) == ("linux", "linux", "amd64")
    assert after.libc == "glibc" and after.translation == "native"
    assert after.express_available == "yes"
    assert after.sandbox_backend == "bwrap" and after.sandbox_loss == "none"
    assert (after.run_mode, after.sandbox_mode) == ("precommit", "auto")
    assert (after.express_requested, after.shell, after.ignore_paths) == (
        "yes",
        "pwsh",
        "set",
    )


def test_a_path_to_another_machine_in_container_mode_leaves_no_sandbox_backend() -> (
    None
):
    facts = _facts(run_mode="container", sandbox_mode="auto")
    (after,) = sr.REGISTER.apply_path(sr.REGISTER.path("ci-runner"), facts)
    assert (after.run_mode, after.sandbox_mode) == ("container", "auto")
    assert (after.sandbox_backend, after.sandbox_loss) == ("n/a", "none")


def test_a_path_to_two_profiles_is_checked_against_each() -> None:
    facts = _facts(arch="amd64", cpu_level="compat-only")
    results = sr.REGISTER.apply_path(sr.REGISTER.path("arm64-host"), facts)
    assert [(r.host_os, r.arch) for r in results] == [
        ("linux", "arm64"),
        ("darwin", "arm64"),
    ]


def test_a_path_on_this_machine_keeps_every_other_fact_the_processor_included() -> None:
    facts = _facts(arch="amd64", cpu_level="compat-only", host_os="windows")
    (after,) = sr.REGISTER.apply_path(sr.REGISTER.path("container-image"), facts)
    assert (after.arch, after.cpu_level) == ("amd64", "compat-only")
    assert (after.run_mode, after.os, after.host_os) == (
        "container",
        "linux",
        "windows",
    )
    assert after.install_channel == "image" and after.polars_runtime == "runtime-32"


def test_several_tokens_for_one_fact_make_the_check_run_each() -> None:
    facts = _facts(sandbox_mode="auto", sandbox_backend="none")
    results = sr.REGISTER.apply_path(sr.REGISTER.path("mode-local-sandboxed"), facts)
    assert sorted(r.sandbox_backend for r in results) == ["bwrap", "sandbox-exec"]
    assert {r.run_mode for r in results} == {"local"}


# ---------------------------------------------------------------------------
# settle: a combination no run has cannot make a row match
# ---------------------------------------------------------------------------


def test_settle_resets_the_facts_a_run_did_not_ask_for() -> None:
    odd = replace(
        sr.REFERENCE_FACTS,
        os="windows",
        arch="arm64",
        cpu_level="compat-only",
        sandbox_mode="off",
        sandbox_backend="bwrap",
        sandbox_loss="caches-read-only",
        run_mode="local",
        image_arch_matches="no",
        libc="glibc",
        wsl="wsl2",
    )
    settled = sr.settle(odd)
    assert settled.cpu_level == "n/a"
    assert (settled.sandbox_backend, settled.sandbox_loss) == ("n/a", "none")
    assert settled.image_arch_matches == "n/a"
    assert (settled.libc, settled.wsl) == ("n/a", "n/a")


def test_settle_keeps_the_facts_a_run_did_ask_for() -> None:
    asked = replace(
        sr.REFERENCE_FACTS,
        arch="amd64",
        cpu_level="compat-only",
        sandbox_mode="auto",
        sandbox_backend="bwrap",
        sandbox_loss="caches-read-only",
        run_mode="precommit",
        os="linux",
        libc="musl",
        wsl="wsl2",
    )
    assert sr.settle(asked) == asked


def test_settle_leaves_no_sandbox_backend_in_container_mode() -> None:
    """Container mode applies no per-scanner sandbox, so the backend the host has and
    the loss it comes with say nothing about the run. The request is still the
    run's own choice, and so is the image's architecture."""
    asked = replace(
        sr.REFERENCE_FACTS,
        run_mode="container",
        sandbox_mode="named",
        sandbox_backend="none",
        sandbox_loss="caches-read-only",
        image_arch_matches="no",
    )
    settled = sr.settle(asked)
    assert (settled.sandbox_backend, settled.sandbox_loss) == ("n/a", "none")
    assert (settled.sandbox_mode, settled.image_arch_matches) == ("named", "no")
    assert sr.settle(replace(asked, run_mode="local")).sandbox_backend == "none"


def test_settle_changes_nothing_for_the_reference_and_is_idempotent() -> None:
    assert sr.settle(sr.REFERENCE_FACTS) == sr.REFERENCE_FACTS
    odd = replace(sr.REFERENCE_FACTS, arch="arm64", cpu_level="full", os="darwin")
    assert sr.settle(sr.settle(odd)) == sr.settle(odd)


# ---------------------------------------------------------------------------
# The evaluator
# ---------------------------------------------------------------------------


def _ids(found: tuple[sr.Evaluation, ...]) -> list[str]:
    return [e.row.id for e in found]


def _scopes() -> list[str]:
    return sorted({row.scope for row in sr.REGISTER.rows})


@pytest.mark.parametrize("scope", _scopes())
def test_the_reference_environment_raises_nothing_in_any_scope(scope: str) -> None:
    assert sr.evaluate(sr.REFERENCE_FACTS, scope) == ()


@pytest.mark.parametrize("scope", _scopes())
def test_a_host_nothing_could_be_read_from_raises_nothing(scope: str) -> None:
    """Every reader failure answers ``unknown``, and ``unknown`` matches no row."""
    assert sr.evaluate(sr.HostFacts(), scope) == ()


def test_the_same_unread_host_raises_the_row_once_the_fact_is_read() -> None:
    """The must-flag twin of the test above: the same facts with one fact read as
    a processor without the instructions polars is built for."""
    unread = replace(
        sr.HostFacts(),
        arch="amd64",
        polars_runtime="runtime-32",
        cpu_level="compat-only",
    )
    assert _ids(sr.evaluate(unread, "ash")) == ["host.cpu.below-polars-runtime"]


def test_a_scope_reads_only_its_own_rows() -> None:
    windows = _facts(os="windows", host_os="windows")
    assert _ids(sr.evaluate(windows, "semgrep")) == ["scanner.semgrep.windows"]
    assert _ids(sr.evaluate(windows, "bandit")) == []
    assert "scanner.semgrep.windows" not in _ids(sr.evaluate(windows, "ash"))


def test_the_worst_row_comes_first_and_ties_keep_declaration_order() -> None:
    both = _facts(
        os="darwin",
        host_os="darwin",
        translation="rosetta",
        cpu_level="compat-only",
        libc="n/a",
    )
    found = sr.evaluate(both, "ash")
    assert _ids(found) == ["host.cpu.below-polars-runtime", "host.translation.rosetta"]
    assert [e.row.level.rank for e in found] == sorted(
        (e.row.level.rank for e in found), reverse=True
    )
    windows = sr.evaluate(_facts(os="windows", host_os="windows"), "ash")
    declared = [row.id for row in sr.REGISTER.rows]
    positions = [declared.index(e.row.id) for e in windows]
    assert positions == sorted(positions)


def test_the_raised_rows_are_a_start_or_a_decision_never_a_matrix_row() -> None:
    windows = _facts(os="windows", host_os="windows")
    assert sr.evaluate(windows, "ash", notify=sr.Notify.START) == ()
    assert (
        sr.evaluate(windows, "ash", notify=(sr.Notify.START, sr.Notify.DECISION)) == ()
    )
    matrix = _ids(sr.evaluate(windows, "ash", notify=sr.Notify.MATRIX))
    assert matrix == [
        "host.windows.no-graceful-stop",
        "host.windows.no-tool-database-lock",
    ]
    decision = sr.evaluate(windows, "semgrep", notify=sr.Notify.DECISION)
    assert _ids(decision) == ["scanner.semgrep.windows"]


def test_supported_rows_are_adaptations_and_are_listed_only_on_request() -> None:
    windows = _facts(os="windows", host_os="windows")
    plain = _ids(sr.evaluate(windows, "ash"))
    with_supported = _ids(sr.evaluate(windows, "ash", include_supported=True))
    assert set(plain) < set(with_supported)
    extra = set(with_supported) - set(plain)
    assert extra and all(i.startswith("host.adaptation.windows-") for i in extra), extra


def test_an_evaluation_carries_the_facts_the_row_matched_and_its_paths() -> None:
    facts = _facts(arch="amd64", cpu_level="compat-only")
    (found,) = sr.evaluate(facts, "ash")
    assert found.matched == {
        "arch": "amd64",
        "cpu_level": "compat-only",
        "polars_runtime": "runtime-32",
    }
    assert found.facts == facts
    assert found.polyfill is None
    assert [p.id for p in found.paths] == [
        "polars-compat-runtime",
        "x86-host-with-features",
        "arm64-host",
        "ci-runner",
    ]
    compat = _facts(arch="amd64", cpu_level="full", polars_runtime="compat")
    (polyfilled,) = sr.evaluate(compat, "ash")
    assert polyfilled.row.id == "host.cpu.polars-compat-runtime"
    assert polyfilled.polyfill is not None
    assert polyfilled.polyfill.id == "polars-compat-runtime"


def _offered(row_id: str, facts: sr.HostFacts) -> list[str]:
    row = sr.REGISTER.row(row_id)
    return [p.id for p in sr.REGISTER.offered_paths(row, facts)]


@pytest.mark.parametrize("channel", ["brew", "nix", "image"])
def test_the_compatibility_runtime_is_not_offered_into_an_environment_ash_must_not_change(
    channel: str,
) -> None:
    facts = _facts(arch="amd64", cpu_level="compat-only", install_channel=channel)
    offered = _offered("host.cpu.below-polars-runtime", facts)
    assert "polars-compat-runtime" not in offered
    assert offered[0] == "x86-host-with-features"


@pytest.mark.parametrize("channel", ["uv-tool", "uvx", "pipx", "pip", "source"])
def test_the_compatibility_runtime_is_offered_where_the_environment_is_the_users(
    channel: str,
) -> None:
    facts = _facts(arch="amd64", cpu_level="compat-only", install_channel=channel)
    assert (
        _offered("host.cpu.below-polars-runtime", facts)[0] == "polars-compat-runtime"
    )


def test_the_compatibility_runtime_needs_a_processor_it_can_run_on() -> None:
    """Below the compatibility runtime's own set it cannot help."""
    facts = _facts(arch="amd64", cpu_level="below-compat")
    assert _offered("host.cpu.below-polars-runtime", facts) == [
        "x86-host-with-features",
        "arm64-host",
        "ci-runner",
    ]


def test_a_translated_run_is_offered_the_native_build() -> None:
    facts = _facts(
        os="darwin",
        host_os="darwin",
        translation="rosetta",
        arch="amd64",
        cpu_level="compat-only",
        libc="n/a",
    )
    assert _offered("host.cpu.below-polars-runtime", facts) == [
        "polars-compat-runtime",
        "native-arm64",
        "x86-host-with-features",
        "arm64-host",
        "ci-runner",
    ]
    assert "native-arm64" not in _offered(
        "host.cpu.below-polars-runtime", _facts(arch="amd64", cpu_level="compat-only")
    )


def test_wsl_is_offered_from_windows_and_never_from_linux_or_macos() -> None:
    row = "host.sandbox.unavailable-auto"
    unavailable = {"sandbox_mode": "auto", "sandbox_backend": "none"}
    windows = _facts(os="windows", host_os="windows", **unavailable)
    linux = _facts(**unavailable)
    mac = _facts(os="darwin", host_os="darwin", libc="n/a", **unavailable)
    assert "wsl2-sandboxed" in _offered(row, windows)
    assert "wsl2-sandboxed" not in _offered(row, linux)
    assert "wsl2-sandboxed" not in _offered(row, mac)
    assert "install-bubblewrap" in _offered(row, linux)
    assert "install-bubblewrap" not in _offered(row, windows)


def test_bubblewrap_is_offered_by_the_host_and_not_by_the_image_it_runs() -> None:
    """In container mode ``os`` is the image's Linux, so a Windows or macOS host that
    runs the image is not a machine where bubblewrap can be installed."""
    row = sr.REGISTER.row("host.sandbox.unavailable-auto")
    unavailable = {"sandbox_mode": "auto", "sandbox_backend": "none"}
    assert "install-bubblewrap" in _offered(row.id, _facts(**unavailable))
    for host in ("windows", "darwin"):
        image = _facts(os="linux", host_os=host, **unavailable)
        assert "install-bubblewrap" not in _offered(row.id, image), host


def test_the_container_is_no_way_out_of_a_missing_sandbox() -> None:
    """Container mode applies no per-scanner sandbox, so it trades the problem
    for the row that says so."""
    for row_id in ["host.sandbox.unavailable-auto", "host.sandbox.unavailable-named"]:
        assert "container-image" not in sr.REGISTER.row(row_id).paths, row_id


def test_a_path_kind_is_on_this_machine_or_elsewhere() -> None:
    here = {k for k in sr.PathKind if k.here}
    assert here == {sr.PathKind.SAME_OS, sr.PathKind.CONTAINER, sr.PathKind.WSL}
    assert {k for k in sr.PathKind if not k.here} == {
        sr.PathKind.OTHER_OS,
        sr.PathKind.OTHER_HOST,
        sr.PathKind.CI_RUNNER,
    }


def test_levels_order_from_supported_to_unsupported() -> None:
    ranks = [level.rank for level in sr.SupportLevel]
    assert ranks == sorted(ranks) == [0, 1, 2, 3]
    assert [level.value for level in sr.SupportLevel] == [
        "supported",
        "polyfilled",
        "degraded",
        "unsupported",
    ]


# ---------------------------------------------------------------------------
# One cell of a matrix, and the refusal accessor
# ---------------------------------------------------------------------------


def test_a_matrix_cell_for_the_reference_environment_is_yes() -> None:
    assert sr.cells("ash", {}) == "yes"
    assert sr.cells("semgrep", {}) == "yes"


def test_a_matrix_cell_says_the_level_and_the_rows_cell_phrase() -> None:
    row = sr.REGISTER.row("host.cpu.below-polars-runtime")
    assert sr.cells("ash", {"cpu_level": "compat-only"}) == f"unsupported: {row.cell}"
    degraded = sr.REGISTER.row("host.translation.rosetta")
    rosetta = {"os": "darwin", "host_os": "darwin", "translation": "rosetta"}
    assert sr.cells("ash", rosetta) == f"degraded: {degraded.cell}"
    stand_in = sr.REGISTER.polyfill("polars-compat-runtime")
    assert sr.cells("ash", {"polars_runtime": "compat"}) == f"polyfill: {stand_in.cell}"


def test_a_matrix_cell_lists_every_row_worst_first_joined_by_a_semicolon() -> None:
    overlay = {
        "os": "darwin",
        "host_os": "darwin",
        "translation": "rosetta",
        "cpu_level": "compat-only",
        "libc": "n/a",
    }
    first = sr.REGISTER.row("host.cpu.below-polars-runtime")
    second = sr.REGISTER.row("host.translation.rosetta")
    assert sr.cells("ash", overlay) == (
        f"unsupported: {first.cell}; degraded: {second.cell}"
    )


def test_matrix_only_rows_show_in_a_cell_though_they_raise_nothing() -> None:
    row14 = sr.REGISTER.row("host.windows.no-graceful-stop")
    row15 = sr.REGISTER.row("host.windows.no-tool-database-lock")
    assert sr.cells("ash", {"os": "windows", "host_os": "windows"}) == (
        f"degraded: {row14.cell}; degraded: {row15.cell}"
    )


def test_a_skipped_scanner_cell_is_the_rows_cell_phrase() -> None:
    """A skipped scanner's cell carries the row's cell phrase, which is the refusal
    text for semgrep and a shorter phrase for GuardDog, so only GuardDog tells the
    two apart."""
    windows = {"os": "windows", "host_os": "windows"}
    assert sr.cells("semgrep", windows) == "refused: semgrep publishes no Windows build"
    assert sr.cells("guarddog", windows) == (
        "refused: GuardDog cannot be installed on Windows"
    )
    for scanner in ("semgrep", "guarddog"):
        row = sr.REGISTER.row(f"scanner.{scanner}.windows")
        assert sr.cells(scanner, windows) == f"refused: {row.cell}", scanner
    guarddog = sr.REGISTER.row("scanner.guarddog.windows")
    assert guarddog.cell != guarddog.reason
    assert sr.cells("semgrep", {"os": "linux"}) == "yes"


def test_a_token_the_register_leaves_undeclared_is_not_declared_not_unsupported() -> (
    None
):
    assert sr.cells("ash", {"libc": "musl"}) == "not declared"
    assert sr.cells("ash", {"wsl": "wsl1"}) == "not declared"
    assert sr.cells("ash", {"python_build": "free-threaded"}) == "not declared"


def test_a_cell_overlay_with_a_bad_token_is_refused() -> None:
    with pytest.raises(sr.SupportRegisterError, match="plan9"):
        sr.cells("ash", {"host_os": "plan9"})
    with pytest.raises(sr.SupportRegisterError, match="no_such_fact"):
        sr.cells("ash", {"no_such_fact": "yes"})


def test_a_cell_never_reads_the_machine_that_renders_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A matrix calls ``cells`` on declared facts, so the same call answers the
    same everywhere: it takes no host reading, and every reader of the machine
    raises here, so a cell that read one would fail."""
    import inspect
    import os
    import platform

    assert list(inspect.signature(sr.cells).parameters) == [
        "scope",
        "overlay",
        "register",
    ]

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a cell read the machine that renders it")

    for reader in ("system", "machine", "release", "mac_ver", "uname", "processor"):
        monkeypatch.setattr(platform, reader, refuse)
    monkeypatch.setattr(os, "cpu_count", refuse)
    with pytest.raises(AssertionError, match="read the machine"):
        platform.machine()
    with pytest.raises(AssertionError, match="read the machine"):
        os.cpu_count()
    row = sr.REGISTER.row("host.cpu.below-polars-runtime")
    assert sr.cells("ash", {"cpu_level": "compat-only"}) == f"unsupported: {row.cell}"
    refused = sr.REGISTER.row("scanner.guarddog.windows")
    windows = {"os": "windows", "host_os": "windows"}
    assert sr.cells("guarddog", windows) == f"refused: {refused.cell}"


def test_the_refusal_accessor_reads_the_declared_skip_rows() -> None:
    assert sr.refusal("semgrep", "windows") == "semgrep publishes no Windows build"
    assert sr.refusal("guarddog", "windows") == (
        "GuardDog 3.2.0 cannot be installed on Windows: its dependency nono-py "
        "publishes no Windows build and does not compile there"
    )
    for os_name in ["linux", "darwin"]:
        assert sr.refusal("semgrep", os_name) is None
        assert sr.refusal("guarddog", os_name) is None
    assert sr.refusal("bandit", "windows") is None
    assert sr.refusal("trivy", "windows") is None


def test_the_refusal_accessor_takes_an_os_token_and_says_so() -> None:
    with pytest.raises(sr.SupportRegisterError, match="Windows"):
        sr.refusal("semgrep", "Windows")


# ---------------------------------------------------------------------------
# The rows derived from a pinned binary's platforms
# ---------------------------------------------------------------------------


def _pinned(provisionable: tuple[str, ...] = ("linux/amd64",)) -> sr.PinnedBinary:
    return sr.PinnedBinary(
        scanner="demo", tool="demotool", version="1.2.3", provisionable=provisionable
    )


def test_a_pinned_binary_gets_one_row_per_platform_it_has_no_build_for() -> None:
    rows = sr.no_build_rows((_pinned(),))
    assert [r.id for r in rows] == [
        "scanner.demo.no-build.darwin-amd64",
        "scanner.demo.no-build.darwin-arm64",
        "scanner.demo.no-build.linux-arm64",
        "scanner.demo.no-build.windows-amd64",
        "scanner.demo.no-build.windows-arm64",
    ]
    row = rows[-1]
    assert row.reason == "ASH has no demotool 1.2.3 build for windows/arm64."
    assert row.scope == "demo"
    assert row.level is sr.SupportLevel.UNSUPPORTED
    assert row.behavior is sr.Behavior.SCANNER_MISSING
    assert row.notify is sr.Notify.DECISION
    assert row.match == sr.Match(os=("windows",), arch=("arm64",))
    assert row.anchor == sr.NO_BUILD_ANCHOR


def test_a_tool_ash_does_not_download_has_no_missing_build_rows() -> None:
    assert sr.no_build_rows((_pinned(provisionable=()),)) == ()


def test_a_tool_with_every_build_has_no_missing_build_rows() -> None:
    assert sr.no_build_rows((_pinned(provisionable=sr.ALL_PLATFORMS),)) == ()


#: Every platform but windows/arm64: the one gap the shipped scanners have today.
_ONLY_WINDOWS_ARM64_MISSING = tuple(
    pair for pair in sr.ALL_PLATFORMS if pair != "windows/arm64"
)


def test_a_derived_row_whose_way_out_lands_on_another_missing_build_fails_the_rule() -> (
    None
):
    """With no linux/arm64 build either, WSL 2 and the image on an arm64 machine
    run the same missing build, so those paths trade one gap for another."""
    register = _with(rows=sr.no_build_rows((_pinned(),)))
    row = register.row("scanner.demo.no-build.windows-arm64")
    failures = _validity_failures(register, rows=(row,))
    assert any(
        "trades it for scanner.demo.no-build.linux-arm64" in f for f in failures
    ), failures


def test_a_derived_row_is_read_by_the_evaluator_and_valid() -> None:
    register = _with(
        rows=sr.no_build_rows((_pinned(provisionable=_ONLY_WINDOWS_ARM64_MISSING),))
    )
    windows_arm = _facts(os="windows", host_os="windows", arch="arm64")
    found = register.evaluate(windows_arm, "demo")
    assert [e.row.id for e in found] == ["scanner.demo.no-build.windows-arm64"]
    assert [p.id for p in found[0].paths] == [
        "wsl2",
        "container-image",
        "linux-or-macos-host",
    ]
    assert (
        register.cells("demo", {"os": "windows", "host_os": "windows", "arch": "arm64"})
        == "no asset"
    )
    assert register.refusal("demo", "windows") is None
    derived = tuple(r for r in register.rows if r.scope == "demo")
    assert _validity_failures(register, rows=derived) == []


@pytest.mark.parametrize("gap", sr.ALL_PLATFORMS)
def test_a_derived_row_leads_out_of_each_single_platform_gap(gap: str) -> None:
    """Whichever one platform a tool lacks, every way out its row offers leaves the
    gap. WSL 2, the container image and another operating system keep the
    processor or land on Linux with it, so for a Linux gap the way out is another
    machine."""
    provisionable = tuple(pair for pair in sr.ALL_PLATFORMS if pair != gap)
    register = _with(rows=sr.no_build_rows((_pinned(provisionable=provisionable),)))
    (row,) = [r for r in register.rows if r.scope == "demo"]
    assert row.id == f"scanner.demo.no-build.{gap.replace('/', '-')}"
    assert _validity_failures(register, rows=(row,)) == []


# ---------------------------------------------------------------------------
# Nothing declared is dead, and every name resolves
# ---------------------------------------------------------------------------


def test_every_path_is_offered_by_some_row_and_every_polyfill_is_named() -> None:
    offered = {pid for row in sr.REGISTER.rows for pid in row.paths}
    assert {p.id for p in sr.REGISTER.paths} == offered
    named = {row.polyfill for row in sr.REGISTER.rows if row.polyfill}
    assert {p.id for p in sr.REGISTER.polyfills} == named


def _never_offered(register: sr.Register, rows: Iterable[sr.SupportRow]) -> list[str]:
    """The ``row: path`` pairs of ``rows`` that no witness of the row is offered, so
    the register and the page would list a way out for a row that nobody sees."""
    dead = []
    for row in rows:
        witnesses = _witnesses(register, row)
        for path_id in row.paths:
            offered_somewhere = any(
                path_id in [path.id for path in register.offered_paths(row, facts)]
                for _, facts in witnesses
            )
            if not offered_somewhere:
                dead.append(f"{row.id}: {path_id}")
    return dead


def test_every_path_a_row_lists_is_offered_at_some_witness_of_the_row() -> None:
    """The check above names each path once. This one holds each pair: a path a row
    lists is offered where the row matches, or the row lists a way out that is never
    shown."""
    assert _never_offered(sr.REGISTER, sr.REGISTER.rows) == []


def test_a_listed_path_no_witness_is_offered_fails_the_check() -> None:
    """The must-fail control: the compatibility runtime needs a processor that has its
    instruction set, so it is never offered for the row of a processor below it."""
    row = sr.REGISTER.row("host.cpu.below-polars-compat")
    plant = replace(
        row,
        id="plant.dead-pair",
        paths=("x86-host-with-features", "polars-compat-runtime"),
    )
    assert _never_offered(_with(rows=(plant,)), (plant,)) == [
        "plant.dead-pair: polars-compat-runtime"
    ]


def _unshipped_scopes(register: sr.Register, shipped: set[str]) -> list[str]:
    """The scanner scopes ``register`` has rows for that ASH does not ship."""
    return sorted({row.scope for row in register.rows} - {"ash"} - shipped)


def test_every_scope_but_ash_is_a_scanner_ash_ships() -> None:
    shipped = {_facets(cls).scanner_name for cls in _universe()}
    scopes = {row.scope for row in sr.REGISTER.rows} - {"ash"}
    assert shipped and scopes, "nothing to compare"
    assert _unshipped_scopes(sr.REGISTER, shipped) == []


def test_a_row_for_a_scanner_that_is_not_shipped_is_named() -> None:
    """The must-fail control for the rule above, and the check that the rule follows
    the roster: the same row passes once its scanner is shipped."""
    register = _with(rows=(_row(id="scanner.ghost.other", scope="ghost"),))
    shipped = {_facets(cls).scanner_name for cls in _universe()}
    assert _unshipped_scopes(register, shipped) == ["ghost"]
    assert _unshipped_scopes(register, shipped | {"ghost"}) == []


def _derivation_failures(
    binaries: Sequence[sr.PinnedBinary], rows: Iterable[sr.SupportRow]
) -> list[str]:
    """How ``rows`` differ from what the scanners' own platform declarations call for:
    one row for each platform a tool ASH downloads has no build for, and no other."""
    wanted = {
        f"scanner.{binary.scanner}.no-build.{pair.replace('/', '-')}"
        for binary in binaries
        if binary.provisionable
        for pair in sr.ALL_PLATFORMS
        if pair not in binary.provisionable
    }
    found = {row.id for row in rows}
    return [f"missing {row_id}" for row_id in sorted(wanted - found)] + [
        f"extra {row_id}" for row_id in sorted(found - wanted)
    ]


def test_the_rows_derived_from_the_shipped_scanners_are_valid() -> None:
    """Every pinned binary gets a row for each platform it has no build for and for
    no other, and each row's paths lead out."""
    binaries = _pinned_binaries()
    assert binaries, "the scanner universe holds no pinned binary"
    derived = sr.no_build_rows(binaries)
    assert _derivation_failures(binaries, derived) == []
    register = _with(rows=derived)
    assert _validity_failures(register, rows=derived) == []


def test_a_missing_or_an_extra_derived_row_is_caught() -> None:
    """The must-fail control for the check above, and the check that it follows the
    roster: a scanner added with a gap gets its row and the check stays green."""
    gap = _pinned(provisionable=_ONLY_WINDOWS_ARM64_MISSING)
    assert _derivation_failures((gap,), sr.no_build_rows((gap,))) == []
    assert _derivation_failures((gap,), ()) == [
        "missing scanner.demo.no-build.windows-arm64"
    ]
    every_gap = sr.no_build_rows((_pinned(),))
    assert _derivation_failures((gap,), every_gap) == [
        "extra scanner.demo.no-build.darwin-amd64",
        "extra scanner.demo.no-build.darwin-arm64",
        "extra scanner.demo.no-build.linux-arm64",
        "extra scanner.demo.no-build.windows-amd64",
    ]
    not_downloaded = _pinned(provisionable=())
    assert len(_derivation_failures((not_downloaded,), every_gap)) == 5
    grown = (*_pinned_binaries(), gap)
    assert _derivation_failures(grown, sr.no_build_rows(grown)) == []


def test_a_scanner_that_loses_windows_amd64_fails_the_derived_rows_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The must-fail control for the test above, run on the test itself. A scanner that
    loses its windows/amd64 build to a typo gets a missing-build row for the Windows
    most machines run. The rows still match the declaration they come from and every
    way out still leads out, so only the allowed platforms report it. The same scanner
    lacking only windows/arm64, the gap the shipped scanners have, passes."""
    loses_amd64 = _pinned(provisionable=all_platforms_but("windows/amd64"))
    monkeypatch.setitem(globals(), "_pinned_binaries", lambda: [loses_amd64])
    with pytest.raises(AssertionError, match="outside ALLOWED_GAP_PLATFORMS"):
        test_the_rows_derived_from_the_shipped_scanners_are_valid()
    loses_arm64 = _pinned(provisionable=all_platforms_but("windows/arm64"))
    monkeypatch.setitem(globals(), "_pinned_binaries", lambda: [loses_arm64])
    test_the_rows_derived_from_the_shipped_scanners_are_valid()


def test_a_row_and_a_path_each_link_to_one_section_of_the_page() -> None:
    for row in sr.REGISTER.rows:
        assert row.docs == f"how-to/supported-configurations.md#{row.anchor}", row.id
        assert re.fullmatch(r"[a-z0-9-]+", row.anchor), row.id
    for path in sr.REGISTER.paths:
        assert path.docs == f"how-to/supported-configurations.md#{path.id}", path.id


def test_rows_share_a_section_only_where_they_say_the_same_thing() -> None:
    from collections import Counter

    anchors = Counter(
        row.anchor
        for row in sr.REGISTER.rows
        if row.level is not sr.SupportLevel.SUPPORTED
    )
    shared = {a: n for a, n in anchors.items() if n > 1}
    assert shared == {"scanner-windows-ignore-paths": 4}, shared
    assert not set(anchors) & {p.id for p in sr.REGISTER.paths}


# ---------------------------------------------------------------------------
# Code sites are bound to the code
# ---------------------------------------------------------------------------


def _definitions(path: Path) -> set[str]:
    """Every dotted name of a class or function defined in ``path``."""
    names: set[str] = set()

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                dotted = f"{prefix}{child.name}"
                names.add(dotted)
                walk(child, dotted + ".")
            else:
                walk(child, prefix)

    walk(ast.parse(path.read_text(encoding="utf-8")), "")
    return names


def _unbound(sites: list[tuple[str, str]]) -> list[str]:
    failures = []
    for owner, site in sites:
        file_name, _, qualname = site.partition(":")
        path = REPO_ROOT / file_name
        if not path.is_file():
            failures.append(f"{owner}: {file_name} is not a file")
        elif qualname not in _definitions(path):
            failures.append(f"{owner}: {file_name} defines no {qualname}")
    return failures


def _code_sites() -> list[tuple[str, str]]:
    sites = [
        (f"polyfill {p.id}", s) for p in sr.REGISTER.polyfills for s in p.code_sites
    ]
    sites += [(f"row {r.id}", s) for r in sr.REGISTER.rows for s in r.code_sites]
    return sites


def test_the_site_reader_sees_a_definition_and_refuses_one_that_is_not_there() -> None:
    atomic = REPO_ROOT / "automated_security_helper" / "utils" / "atomic_write.py"
    assert "_replace" in _definitions(atomic)
    scanner = (
        REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_builtin"
        / "scanners"
        / "detect_secrets_scanner.py"
    )
    assert "DetectSecretsScanner._ensure_fork_multiprocessing" in _definitions(scanner)
    assert _unbound(
        [("planted", "automated_security_helper/utils/atomic_write.py:nope")]
    )
    assert _unbound([("planted", "automated_security_helper/utils/no_such_file.py:x")])


def test_every_declared_code_site_is_a_definition_in_a_file_of_the_tree() -> None:
    sites = _code_sites()
    assert len(sites) >= 12, sites
    assert _unbound(sites) == []


def test_every_adaptation_is_bound_to_the_code_that_implements_it() -> None:
    adaptations = [
        p for p in sr.REGISTER.polyfills if p.kind is sr.PolyfillKind.ADAPTATION
    ]
    assert len(adaptations) == 9
    assert [p.id for p in adaptations if not p.code_sites] == []


# ---------------------------------------------------------------------------
# The skip rows are today's refusals, byte for byte
# ---------------------------------------------------------------------------

SKIPPING = [r for r in sr.REGISTER.rows if r.behavior is sr.Behavior.SKIPS_SCANNER]
_PLATFORM_SYSTEM = {"linux": "Linux", "darwin": "Darwin", "windows": "Windows"}


def _scanner_class(name: str) -> type:
    found = [c for c in _universe() if _facets(c).scanner_name == name]
    assert len(found) == 1, (name, found)
    return found[0]


def _recorded_skip(tmp_path: Path, name: str, hook: Any) -> str | None:
    """The ``skipped_reason`` ScanPhase records for a scanner whose platform hook
    is ``hook``, read from the results the phase builds."""
    from unittest.mock import MagicMock, patch

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.phases.scan_phase import ScanPhase
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    plugin_cls = MagicMock(name=name)
    plugin_cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = plugin_cls
    instance.__class__.__name__ = name
    config = MagicMock()
    config.enabled = True
    config.name = name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.side_effect = hook
    instance.validate_plugin_dependencies.return_value = False
    instance.dependencies_satisfied = False
    plugin_cls.return_value = instance
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[plugin_cls],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        result = phase._execute_phase(aggregated_results=aggregated)
    return result.scanner_results[name].skipped_reason


def test_the_register_declares_a_skip_row_for_each_scanner_that_refuses_a_platform() -> (
    None
):
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    base = ScannerPluginBase.unsupported_platform_reason
    overriding = {
        _facets(cls).scanner_name
        for cls in _universe()
        if cls.unsupported_platform_reason is not base  # type: ignore[attr-defined]
    }
    assert SKIPPING, "the register declares no skip row"
    assert overriding == {row.scope for row in SKIPPING}


@pytest.mark.parametrize("row", SKIPPING, ids=lambda row: row.id)
@pytest.mark.parametrize("os_token", sorted(_PLATFORM_SYSTEM))
def test_a_skip_rows_reason_is_the_text_the_scanner_hook_returns_on_that_os(
    row: sr.SupportRow, os_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("platform.system", lambda: _PLATFORM_SYSTEM[os_token])
    expected = row.reason if os_token in row.match.os else None
    scanner = _scanner_class(row.scope)
    assert scanner.unsupported_platform_reason(object()) == expected  # type: ignore[attr-defined]


@pytest.mark.parametrize("row", SKIPPING, ids=lambda row: row.id)
def test_a_skip_rows_reason_is_the_skipped_reason_the_scan_records(
    row: sr.SupportRow, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real scan phase, so the text a user and a report read is the
    row's, with the one prefix the phase adds."""
    monkeypatch.setattr("platform.system", lambda: "Windows")
    scanner = _scanner_class(row.scope)
    recorded = _recorded_skip(
        tmp_path,
        row.scope,
        lambda: scanner.unsupported_platform_reason(object()),  # type: ignore[attr-defined]
    )
    assert recorded == f"not supported on this platform: {row.reason}"


# ---------------------------------------------------------------------------
# The module costs a command nothing it does not run
# ---------------------------------------------------------------------------

_IMPORT_DRIVER = """
import json
import sys

before = set(sys.modules)
import automated_security_helper.base.support_register  # noqa: F401

new = sorted(set(sys.modules) - before)
tops = {name.split(".")[0] for name in new}
outside = sorted(tops - set(sys.stdlib_module_names) - {"automated_security_helper"})
ash = sorted(n for n in new if n.split(".")[0] == "automated_security_helper")
print(json.dumps({"outside": outside, "ash": ash}))
"""


def test_the_register_imports_the_standard_library_and_nothing_of_ash() -> None:
    completed = subprocess.run(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", importing_this_checkout(_IMPORT_DRIVER)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout.splitlines()[-1])
    assert report["outside"] == [], report
    assert report["ash"] == [
        "automated_security_helper.base",
        "automated_security_helper.base.support_register",
    ], report


# ---------------------------------------------------------------------------
# The page carries what the register declares
# ---------------------------------------------------------------------------

_ANCHOR = re.compile(r"\{#([a-z0-9-]+)\}")
#: The sections of the page that are not a row or a path.
SECTION_ANCHORS = frozenset(
    {
        "levels",
        "supported",
        "not-declared",
        "adaptations",
        "described",
        "configurations",
        "ways-out",
    }
)


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _row_and_path_anchors() -> set[str]:
    rows = {
        row.anchor
        for row in sr.REGISTER.rows
        if row.level is not sr.SupportLevel.SUPPORTED
    }
    return rows | {sr.NO_BUILD_ANCHOR} | {path.id for path in sr.REGISTER.paths}


def test_the_page_has_a_section_for_every_row_and_every_path() -> None:
    anchors = set(_ANCHOR.findall(_page()))
    assert _row_and_path_anchors() - anchors == set()


def test_every_section_of_the_page_is_a_row_a_path_or_a_named_part() -> None:
    anchors = set(_ANCHOR.findall(_page()))
    assert anchors - _row_and_path_anchors() - SECTION_ANCHORS == set()
    assert SECTION_ANCHORS <= anchors, sorted(SECTION_ANCHORS - anchors)


def test_the_page_carries_the_sentence_of_every_row_and_way_out() -> None:
    page = _flat(_page())
    missing = []
    for row in sr.REGISTER.rows:
        if row.level is not sr.SupportLevel.SUPPORTED and row.message not in page:
            missing.append(row.id)
    for path in sr.REGISTER.paths:
        if path.summary not in page:
            missing.append(path.id)
    assert missing == []


def test_the_page_names_each_adaptation_and_each_stand_in() -> None:
    page = _flat(_page())
    missing = [p.id for p in sr.REGISTER.polyfills if p.name not in page]
    assert missing == []


def test_the_page_is_prose_with_no_fenced_block_and_no_command() -> None:
    """Commands live in the pages it links to, which the docs runner executes."""
    text = _page()
    assert "```" not in text and "~~~" not in text
    assert not re.search(r"`ash[ `]", text)
    assert text.isascii()
    lowered = text.lower()
    for term in ("whitelist", "blacklist", "master", "slave"):
        assert term not in lowered, term


def test_the_page_is_in_the_navigation_once() -> None:
    nav = (REPO_ROOT / "docs" / "content" / ".nav.yml").read_text(encoding="utf-8")
    assert nav.count("how-to/supported-configurations.md") == 1
