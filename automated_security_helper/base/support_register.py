"""What ASH supports, and what it does where it does not.

This module declares, as frozen and validated data, the configurations ASH runs in
and the level of support each one has. It also holds the one evaluator that turns a
description of a host into the rows that match it. It reads nothing from the machine
it runs on: a host reader fills a ``HostFacts`` value and hands it in, and a generated
support matrix hands in facts it declares itself, so a matrix cell never describes the
machine that rendered it.

Four levels, ordered from best to worst:

- supported: ASH works here and has nothing to say about it;
- polyfilled: ASH works here through a named stand-in for something the platform or
  the runtime lacks, and the stand-in can change what a user sees;
- degraded: ASH runs here and loses a named function;
- unsupported: ASH refuses, skips the part that cannot work, or runs with results it
  cannot stand behind.

An adaptation is the platform's own implementation of a function with no loss a user
can see. It is declared, so the matrices list it and a test binds it to its code, but
its level stays supported and it raises no notice.

Every fact is a token from a closed vocabulary, so a row matches exactly and an
unexpected value reads as ``other`` or ``unknown`` instead of crashing or guessing.
A row never matches ``unknown``, so a failed read raises nothing. A token that no row
and no supported set names is "not declared": the register says nothing about it and
raises no notice for it.

Every sentence here is public text. It is ASCII, names no internal host, path or
account, and is the one source the CLI, the scan results, the docs page and the
generated matrices all read, so they say the same words.

Importing this module costs the standard library and nothing else of ASH. It is used
when a scan starts and by the support matrices, never to print a version.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from enum import Enum
from typing import TypeVar

__all__ = [
    "ALL_PLATFORMS",
    "CELL_LIMIT",
    "DIMENSIONS",
    "FIELDS",
    "FIELD_GROUPS",
    "MATCH_FIELDS",
    "NO_BUILD_ANCHOR",
    "NOT_DECLARED",
    "REFERENCE_FACTS",
    "REGISTER",
    "SUPPORTED_TOKENS",
    "UNKNOWN",
    "VOCABULARY",
    "Behavior",
    "Evaluation",
    "HostFacts",
    "Match",
    "Notify",
    "PathKind",
    "PinnedBinary",
    "Polyfill",
    "PolyfillKind",
    "Profile",
    "Register",
    "SupportLevel",
    "SupportRegisterError",
    "SupportRow",
    "UpgradePath",
    "cells",
    "evaluate",
    "no_build_rows",
    "refusal",
    "settle",
]


class SupportRegisterError(ValueError):
    """A declaration, an overlay or a token breaks a rule the register states."""


# ---------------------------------------------------------------------------
# The facts, and the closed vocabulary of each
# ---------------------------------------------------------------------------

UNKNOWN = "unknown"

#: The facts a host reader fills, in declaration order. ``os_release`` is free text
#: that no row matches; it is recorded in a notice so a user can see what ASH read.
FIELDS: tuple[str, ...] = (
    "os",
    "host_os",
    "os_release",
    "arch",
    "translation",
    "cpu_level",
    "polars_runtime",
    "libc",
    "python_in_range",
    "python_build",
    "install_channel",
    "run_mode",
    "wsl",
    "shell",
    "image_arch_matches",
    "sandbox_mode",
    "sandbox_backend",
    "sandbox_loss",
    "express_requested",
    "express_available",
    "tool_sandbox",
    "ignore_paths",
)

#: The facts a row can match on: every fact but the free-text one.
MATCH_FIELDS: tuple[str, ...] = tuple(name for name in FIELDS if name != "os_release")

_OS_TOKENS = ("linux", "darwin", "windows", "other", UNKNOWN)

#: Every token each fact can have. ``os`` is where the scanners run (the image's
#: Linux in container mode) and ``host_os`` is where ASH was started. ``unknown`` is
#: what a failed read answers.
VOCABULARY: dict[str, tuple[str, ...]] = {
    "os": _OS_TOKENS,
    "host_os": _OS_TOKENS,
    "arch": ("amd64", "arm64", "other", UNKNOWN),
    "translation": ("native", "rosetta", "x64-on-arm64", UNKNOWN),
    "cpu_level": ("full", "compat-only", "below-compat", UNKNOWN, "n/a"),
    "polars_runtime": ("runtime-32", "runtime-64", "compat", "absent", UNKNOWN),
    "libc": ("glibc", "musl", "n/a", UNKNOWN),
    "python_in_range": ("yes", "no", UNKNOWN),
    "python_build": ("standard", "free-threaded", "other-implementation", UNKNOWN),
    "install_channel": (
        "uv-tool",
        "uvx",
        "pipx",
        "pip",
        "brew",
        "nix",
        "image",
        "source",
        UNKNOWN,
    ),
    "run_mode": ("local", "container", "precommit", "nix"),
    "wsl": ("wsl2", "wsl1", "no", "n/a", UNKNOWN),
    "shell": ("none", "bash-wrapper", "msys-wrapper", "pwsh", "powershell-5"),
    "image_arch_matches": ("yes", "no", UNKNOWN, "n/a"),
    "sandbox_mode": ("off", "auto", "named"),
    "sandbox_backend": ("bwrap", "firejail", "landlock", "sandbox-exec", "none", "n/a"),
    "sandbox_loss": ("none", "landlock-below-6", "caches-read-only"),
    "express_requested": ("yes", "no"),
    "express_available": ("yes", "no", UNKNOWN),
    "tool_sandbox": ("own", "replaced", "unavailable", "n/a"),
    "ignore_paths": ("set", "none"),
}

#: The tokens ASH declares as working fully, with nothing to say about them. A token
#: outside this set is covered by a row or is "not declared" (the totality rule).
SUPPORTED_TOKENS: dict[str, tuple[str, ...]] = {
    "os": ("linux", "darwin", "windows"),
    "host_os": ("linux", "darwin", "windows"),
    "arch": ("amd64", "arm64"),
    "translation": ("native",),
    "cpu_level": ("full", "n/a"),
    "polars_runtime": ("runtime-32", "runtime-64"),
    "libc": ("glibc", "n/a"),
    "python_in_range": ("yes",),
    "python_build": ("standard",),
    "install_channel": (
        "uv-tool",
        "uvx",
        "pipx",
        "pip",
        "brew",
        "nix",
        "image",
        "source",
    ),
    "run_mode": ("local", "container", "precommit", "nix"),
    "wsl": ("wsl2", "no", "n/a"),
    "shell": ("none", "bash-wrapper", "pwsh"),
    "image_arch_matches": ("yes", "n/a"),
    "sandbox_mode": ("off",),
    "sandbox_backend": ("bwrap", "firejail", "landlock", "sandbox-exec", "n/a"),
    "sandbox_loss": ("none",),
    "express_requested": ("no",),
    "express_available": ("yes",),
    "tool_sandbox": ("own", "n/a"),
    "ignore_paths": ("set", "none"),
}

#: Facts that share one coverage: a token of ``os`` is covered when a row names it as
#: ``os`` or as ``host_os``, because the two are the same vocabulary seen from two
#: places.
FIELD_GROUPS: tuple[tuple[str, ...], ...] = (("os", "host_os"),)

#: The dimensions a row can be about. A path that trades a row's problem for another
#: row's of the same dimension is no way out (the validity rule).
DIMENSIONS: tuple[str, ...] = (
    "cpu",
    "translation",
    "os",
    "arch",
    "python",
    "run mode",
    "sandbox",
    "express",
    "shell",
    "container image",
    "container leftovers",
    "tool sandbox",
    "ignore paths",
    "platform",
)

#: The longest phrase a matrix cell holds, so a README cell stays inside its budget.
CELL_LIMIT = 48

#: The page every docs link points at, relative to the docs content root.
DOCS_PAGE = "how-to/supported-configurations.md"

#: The one page section the rows derived from a pinned binary's platforms share.
NO_BUILD_ANCHOR = "scanner-no-build"

#: The page section that lists the adaptations, which have no section of their own.
ADAPTATIONS_ANCHOR = "adaptations"

_ID = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_PROFILE_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_DOCS_LINK = re.compile(re.escape(DOCS_PAGE) + r"#[a-z0-9]+(?:-[a-z0-9]+)*")
_SITE = re.compile(
    r"automated_security_helper/[A-Za-z0-9_/]+\.py:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)
#: Command text in a sentence: the lowercase word ``ash`` on its own. The product's
#: name is written ASH, and ``bash`` and ``hash`` hold the letters inside a word.
_COMMAND_WORD = re.compile(r"\bash\b")


def _public(owner: str, name: str, text: object, limit: int | None = None) -> str:
    """``text`` as one public sentence or phrase: non-blank, ASCII, within ``limit``."""
    if not isinstance(text, str) or not text.strip():
        raise SupportRegisterError(f"{owner}: {name} is blank")
    if not text.isascii():
        raise SupportRegisterError(f"{owner}: {name} must be ASCII")
    if limit is not None and len(text) > limit:
        raise SupportRegisterError(
            f"{owner}: {name} is {len(text)} characters, more than the {limit} "
            "a matrix cell holds"
        )
    return text


def _sites(owner: str, sites: object) -> None:
    """Every code site is ``<file under the package>.py:<qualified name>``."""
    if not isinstance(sites, tuple):
        raise SupportRegisterError(f"{owner}: code_sites is a tuple of strings")
    for site in sites:
        if not isinstance(site, str) or not _SITE.fullmatch(site):
            raise SupportRegisterError(
                f"{owner}: code site {site!r} is not "
                "automated_security_helper/<file>.py:<qualified name>"
            )


@dataclass(frozen=True)
class HostFacts:
    """What is known about the host and the run, one token per fact.

    A host reader fills the facts it can read and leaves ``unknown`` in the rest. The
    facts the caller chooses (the mode, the wrapper shell, the sandbox request, the
    express request and whether ignore paths are set) default to the neutral token
    and are filled by whoever parsed the options.
    """

    os: str = UNKNOWN
    host_os: str = UNKNOWN
    os_release: str = UNKNOWN
    arch: str = UNKNOWN
    translation: str = UNKNOWN
    cpu_level: str = UNKNOWN
    polars_runtime: str = UNKNOWN
    libc: str = UNKNOWN
    python_in_range: str = UNKNOWN
    python_build: str = UNKNOWN
    install_channel: str = UNKNOWN
    run_mode: str = "local"
    wsl: str = UNKNOWN
    shell: str = "none"
    image_arch_matches: str = "n/a"
    sandbox_mode: str = "off"
    sandbox_backend: str = "n/a"
    sandbox_loss: str = "none"
    express_requested: str = "no"
    express_available: str = UNKNOWN
    tool_sandbox: str = "n/a"
    ignore_paths: str = "none"

    def __post_init__(self) -> None:
        if not isinstance(self.os_release, str):
            raise SupportRegisterError("os_release is free text, a string")
        for name in MATCH_FIELDS:
            token = getattr(self, name)
            if token not in VOCABULARY[name]:
                raise SupportRegisterError(
                    f"{name}: {token!r} is not one of {', '.join(VOCABULARY[name])}"
                )


#: The environment ASH's CI treats as its baseline. A matrix cell and a validity check
#: overlay their own facts on it.
REFERENCE_FACTS = HostFacts(
    os="linux",
    host_os="linux",
    os_release="linux",
    arch="amd64",
    translation="native",
    cpu_level="full",
    polars_runtime="runtime-32",
    libc="glibc",
    python_in_range="yes",
    python_build="standard",
    install_channel="uv-tool",
    run_mode="local",
    wsl="no",
    shell="none",
    image_arch_matches="n/a",
    sandbox_mode="off",
    sandbox_backend="n/a",
    sandbox_loss="none",
    express_requested="no",
    express_available="yes",
    tool_sandbox="n/a",
    ignore_paths="none",
)


def settle(facts: HostFacts) -> HostFacts:
    """Reset the facts a run did not ask for, so an overlay cannot make a row match
    on a combination no run has.

    The processor level is n/a unless the architecture is amd64; the sandbox backend
    and its loss are n/a and none while the sandbox is off; the image architecture is
    n/a outside container mode; libc and WSL are n/a unless the scanners run on Linux.
    """
    changes: dict[str, str] = {}
    if facts.arch != "amd64" and facts.cpu_level != "n/a":
        changes["cpu_level"] = "n/a"
    if facts.sandbox_mode == "off":
        if facts.sandbox_backend != "n/a":
            changes["sandbox_backend"] = "n/a"
        if facts.sandbox_loss != "none":
            changes["sandbox_loss"] = "none"
    if facts.run_mode != "container" and facts.image_arch_matches != "n/a":
        changes["image_arch_matches"] = "n/a"
    if facts.os != "linux":
        if facts.libc != "n/a":
            changes["libc"] = "n/a"
        if facts.wsl != "n/a":
            changes["wsl"] = "n/a"
    return replace(facts, **changes) if changes else facts


@dataclass(frozen=True)
class Match:
    """A conjunction over the facts: each field is a tuple of the tokens it accepts,
    and an empty tuple accepts anything."""

    os: tuple[str, ...] = ()
    host_os: tuple[str, ...] = ()
    arch: tuple[str, ...] = ()
    translation: tuple[str, ...] = ()
    cpu_level: tuple[str, ...] = ()
    polars_runtime: tuple[str, ...] = ()
    libc: tuple[str, ...] = ()
    python_in_range: tuple[str, ...] = ()
    python_build: tuple[str, ...] = ()
    install_channel: tuple[str, ...] = ()
    run_mode: tuple[str, ...] = ()
    wsl: tuple[str, ...] = ()
    shell: tuple[str, ...] = ()
    image_arch_matches: tuple[str, ...] = ()
    sandbox_mode: tuple[str, ...] = ()
    sandbox_backend: tuple[str, ...] = ()
    sandbox_loss: tuple[str, ...] = ()
    express_requested: tuple[str, ...] = ()
    express_available: tuple[str, ...] = ()
    tool_sandbox: tuple[str, ...] = ()
    ignore_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in MATCH_FIELDS:
            tokens = getattr(self, name)
            if not isinstance(tokens, tuple):
                raise SupportRegisterError(
                    f"{name}: a match names its tokens in a tuple, not {tokens!r}"
                )
            for token in tokens:
                if token not in VOCABULARY[name]:
                    raise SupportRegisterError(
                        f"{name}: {token!r} is not one of {', '.join(VOCABULARY[name])}"
                    )
            if len(set(tokens)) != len(tokens):
                raise SupportRegisterError(f"{name}: a token is named twice")

    def constraints(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """The fields this match constrains, with their tokens, in field order."""
        return tuple(
            (name, getattr(self, name))
            for name in MATCH_FIELDS
            if getattr(self, name)
        )

    def is_empty(self) -> bool:
        """True for a match that accepts every host."""
        return not self.constraints()

    def matches(self, facts: HostFacts) -> bool:
        """True when every constrained fact holds one of the tokens."""
        return all(getattr(facts, name) in tokens for name, tokens in self.constraints())


# ---------------------------------------------------------------------------
# Levels, kinds and behaviors
# ---------------------------------------------------------------------------

_LEVEL_ORDER = ("supported", "polyfilled", "degraded", "unsupported")


class SupportLevel(str, Enum):
    """How well ASH works in a configuration, ordered from best to worst."""

    SUPPORTED = "supported"
    POLYFILLED = "polyfilled"
    DEGRADED = "degraded"
    UNSUPPORTED = "unsupported"

    @property
    def rank(self) -> int:
        """0 for supported up to 3 for unsupported."""
        return _LEVEL_ORDER.index(self.value)


class PolyfillKind(str, Enum):
    """What stands in, and where."""

    SHIM = "shim"  # code injected into a tool
    SUBSTITUTE = "substitute"  # another mechanism or package stands in
    PINNED_RUNTIME = "pinned-runtime"  # the tool runs on another interpreter
    ADAPTATION = "adaptation"  # the platform's own implementation, no visible loss


class Behavior(str, Enum):
    """What ASH does when a row matches."""

    CONTINUES = "continues"
    SKIPS_SCANNER = "skips-scanner"
    SCANNER_MISSING = "scanner-missing"
    SCANNER_ERROR = "scanner-error"
    REFUSES = "refuses"


class PathKind(str, Enum):
    """What an upgrade path changes. The first three are on this machine, and the
    other three are elsewhere."""

    SAME_OS = "same-os"
    CONTAINER = "container"
    WSL = "wsl"
    OTHER_OS = "other-os"
    OTHER_HOST = "other-host"
    CI_RUNNER = "ci-runner"

    @property
    def here(self) -> bool:
        """True for a path that changes this machine, false for another one."""
        return self in (PathKind.SAME_OS, PathKind.CONTAINER, PathKind.WSL)


class Notify(str, Enum):
    """When a matching row becomes a notice."""

    START = "start"  # on the host facts, once per run, before polars loads
    DECISION = "decision"  # where ASH makes the decision, with the facts known there
    MATRIX = "matrix"  # a documented limit: matrices and the docs page, never a notice


@dataclass(frozen=True)
class Polyfill:
    """A named stand-in for something a platform lacks, or an adaptation.

    ``cell`` is the phrase a matrix shows, at most ``CELL_LIMIT`` characters.
    ``difference`` is what a user can see because the stand-in is there; an
    adaptation loses nothing a user can see, so it has none. Each code site is
    ``<file under the package>.py:<qualified name>``, and a test holds it to the code.
    """

    id: str
    name: str
    kind: PolyfillKind
    cell: str
    stands_in_for: str
    difference: str | None
    code_sites: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _SLUG.fullmatch(self.id):
            raise SupportRegisterError(f"polyfill id {self.id!r} is not a lowercase slug")
        _public(self.id, "name", self.name)
        _public(self.id, "cell", self.cell, CELL_LIMIT)
        _public(self.id, "stands_in_for", self.stands_in_for)
        if self.kind is PolyfillKind.ADAPTATION:
            if self.difference is not None:
                raise SupportRegisterError(
                    f"{self.id}: an adaptation loses nothing a user can see, "
                    "so it states no difference"
                )
        else:
            if self.difference is None:
                raise SupportRegisterError(
                    f"{self.id}: a stand-in states the difference a user can see"
                )
            _public(self.id, "difference", self.difference)
        _sites(self.id, self.code_sites)


def _translated_only(available_when: Match) -> bool:
    """True when a path is offered only to a run that is translated to another
    architecture, which is the one case a path on this machine can name ``arch``."""
    return bool(available_when.translation) and set(available_when.translation) <= {
        "rosetta",
        "x64-on-arm64",
    }


@dataclass(frozen=True)
class UpgradePath:
    """One way to a supported configuration.

    ``summary`` is one public imperative sentence with no command text: the CLI spells
    the command at run time from its own declarations, through ``command_builder``.
    ``target`` is what the path changes. On this machine (same-os, container, wsl) it
    is a ``Match`` of the tokens to overlay, several tokens for one fact meaning the
    validity check runs each. Elsewhere it names the host profile, or profiles, the
    path moves to. ``available_when`` says where the path can be offered, so WSL is
    offered from Windows only.
    """

    id: str
    kind: PathKind
    summary: str
    target: Match | str | tuple[str, ...]
    available_when: Match = field(default_factory=Match)
    docs: str = ""
    command_builder: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _SLUG.fullmatch(self.id):
            raise SupportRegisterError(f"path id {self.id!r} is not a lowercase slug")
        _public(self.id, "summary", self.summary)
        if "`" in self.summary or _COMMAND_WORD.search(self.summary):
            raise SupportRegisterError(
                f"{self.id}: a path sentence holds no command text, because the CLI "
                "builds the command from its own declarations"
            )
        if not self.docs:
            object.__setattr__(self, "docs", f"{DOCS_PAGE}#{self.id}")
        if not _DOCS_LINK.fullmatch(self.docs):
            raise SupportRegisterError(
                f"{self.id}: docs {self.docs!r} is not {DOCS_PAGE}#<anchor>"
            )
        if self.command_builder is not None and not _SLUG.fullmatch(
            self.command_builder
        ):
            raise SupportRegisterError(
                f"{self.id}: command_builder {self.command_builder!r} is not a slug"
            )
        if self.kind.here:
            self._check_target_on_this_machine()
        else:
            names = (self.target,) if isinstance(self.target, str) else self.target
            if (
                isinstance(self.target, Match)
                or not isinstance(names, tuple)
                or not names
                or not all(isinstance(name, str) for name in names)
            ):
                raise SupportRegisterError(
                    f"{self.id}: a path to another machine names the profile it "
                    "moves to, not tokens"
                )

    def _check_target_on_this_machine(self) -> None:
        target = self.target
        if not isinstance(target, Match):
            raise SupportRegisterError(
                f"{self.id}: a path on this machine names the tokens it overlays, "
                "not a profile"
            )
        if target.is_empty():
            raise SupportRegisterError(f"{self.id}: its tokens overlay nothing")
        if target.cpu_level:
            raise SupportRegisterError(
                f"{self.id}: a path on this machine never names cpu_level, because "
                "a container or a reinstall changes no processor"
            )
        if target.arch and not _translated_only(self.available_when):
            raise SupportRegisterError(
                f"{self.id}: a path on this machine names arch only when it is "
                "offered to a translated run"
            )

    @property
    def targets(self) -> tuple[str, ...]:
        """The profile names a path to another machine moves to, or ``()``."""
        if isinstance(self.target, Match):
            return ()
        if isinstance(self.target, str):
            return (self.target,)
        return self.target


@dataclass(frozen=True)
class SupportRow:
    """One configuration, the level of support it has and what ASH does there.

    ``scope`` is ``ash`` or the config name of a scanner. ``reason`` is the one public
    sentence the CLI prints and the docs page carries; for a scanner refusal it is the
    text ``skipped_reason`` carries. ``cell`` is the phrase a matrix shows. ``cli`` says
    whether the CLI writes the notice straight to stderr, past ``--quiet``: ``None``
    means the level's default (always for unsupported, a log line otherwise). A row
    with ``results=False`` is kept out of the scan results because it changes speed and
    no finding.
    """

    id: str
    scope: str
    dimension: str
    match: Match
    level: SupportLevel
    behavior: Behavior
    notify: Notify
    reason: str
    cell: str
    polyfill: str | None = None
    lost: str | None = None
    paths: tuple[str, ...] = ()
    cli: bool | None = None
    results: bool = True
    code_sites: tuple[str, ...] = ()
    docs_anchor: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _ID.fullmatch(self.id):
            raise SupportRegisterError(f"row id {self.id!r} is not a lowercase dotted id")
        if not isinstance(self.scope, str) or not _SLUG.fullmatch(self.scope):
            raise SupportRegisterError(f"{self.id}: scope {self.scope!r} is not a slug")
        _public(self.id, "reason", self.reason)
        _public(self.id, "cell", self.cell, CELL_LIMIT)
        if self.dimension not in DIMENSIONS:
            raise SupportRegisterError(
                f"{self.id}: dimension {self.dimension!r} is not one of "
                f"{', '.join(DIMENSIONS)}"
            )
        if not isinstance(self.paths, tuple) or not all(
            isinstance(path_id, str) for path_id in self.paths
        ):
            raise SupportRegisterError(f"{self.id}: paths is a tuple of path ids")
        if self.docs_anchor is not None and not _SLUG.fullmatch(self.docs_anchor):
            raise SupportRegisterError(
                f"{self.id}: docs anchor {self.docs_anchor!r} is not a slug"
            )
        _sites(self.id, self.code_sites)
        if self.level is not SupportLevel.SUPPORTED:
            for name, tokens in self.match.constraints():
                if UNKNOWN in tokens:
                    raise SupportRegisterError(
                        f"{self.id}: a {self.level.value} row never matches unknown "
                        f"({name}), so a failed read raises nothing"
                    )
        self._check_level()

    def _check_level(self) -> None:
        level = self.level
        if level is SupportLevel.SUPPORTED:
            if self.polyfill is None:
                raise SupportRegisterError(
                    f"{self.id}: a supported row names the adaptation it declares"
                )
            if self.paths or self.lost is not None:
                raise SupportRegisterError(
                    f"{self.id}: a supported row loses nothing and offers no paths"
                )
            if self.notify is not Notify.MATRIX or self.behavior is not Behavior.CONTINUES:
                raise SupportRegisterError(
                    f"{self.id}: a supported row only continues and is listed in the "
                    "matrices (notify matrix)"
                )
        elif level is SupportLevel.POLYFILLED:
            if self.polyfill is None:
                raise SupportRegisterError(
                    f"{self.id}: a polyfilled row names its polyfill"
                )
            if self.behavior is not Behavior.CONTINUES:
                raise SupportRegisterError(f"{self.id}: a polyfilled row continues")
        elif level is SupportLevel.DEGRADED:
            if self.lost is None:
                raise SupportRegisterError(
                    f"{self.id}: a degraded row says what is lost"
                )
            _public(self.id, "lost", self.lost)
            if not self.paths:
                raise SupportRegisterError(
                    f"{self.id}: a degraded row names upgrade paths"
                )
            if self.behavior is not Behavior.CONTINUES:
                raise SupportRegisterError(f"{self.id}: a degraded row continues")
        else:
            if self.notify is Notify.MATRIX:
                raise SupportRegisterError(
                    f"{self.id}: an unsupported row is never matrix-only, because an "
                    "unsupported configuration is always shown"
                )
            if self.cli is False:
                raise SupportRegisterError(
                    f"{self.id}: an unsupported row is always shown, so cli cannot "
                    "be False"
                )
            if not self.paths:
                raise SupportRegisterError(
                    f"{self.id}: an unsupported row names upgrade paths"
                )
        if self.notify is Notify.MATRIX and self.cli:
            raise SupportRegisterError(
                f"{self.id}: a matrix-only row never asks for the console (cli)"
            )

    @property
    def anchor(self) -> str:
        """The section of the docs page that explains this row."""
        return self.docs_anchor or self.id.replace(".", "-")

    @property
    def docs(self) -> str:
        """The docs link of this row, relative to the docs content root."""
        return f"{DOCS_PAGE}#{self.anchor}"

    @property
    def message(self) -> str:
        """The one sentence a notice, the docs page and a report all carry."""
        return self.reason

    @property
    def cli_on_stderr(self) -> bool:
        """True when the CLI writes this row straight to stderr, past ``--quiet``."""
        if self.notify is Notify.MATRIX:
            return False
        if self.cli is not None:
            return self.cli
        return self.level is SupportLevel.UNSUPPORTED


@dataclass(frozen=True)
class Profile:
    """A kind of host, with the facts it has and the tokens each fact can have.

    The facts are what a path to this kind of machine moves a run to. ``possible``
    states, for every fact a row can match on, every token a host of this kind can
    have, which is what the validity rule builds its witnesses from: a Windows host
    has no sandbox backend, and GuardDog's own sandbox is unavailable only on Linux.
    """

    name: str
    facts: HostFacts
    possible: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _PROFILE_NAME.fullmatch(self.name):
            raise SupportRegisterError(f"profile name {self.name!r} is not UPPER_CASE")
        if not isinstance(self.facts, HostFacts):
            raise SupportRegisterError(f"{self.name}: facts is a HostFacts value")
        missing = [name for name in MATCH_FIELDS if name not in self.possible]
        extra = [name for name in self.possible if name not in MATCH_FIELDS]
        if missing or extra:
            raise SupportRegisterError(
                f"{self.name}: possible must state every fact a row can match on "
                f"(missing: {', '.join(missing) or 'none'}; "
                f"extra: {', '.join(extra) or 'none'})"
            )
        for name in MATCH_FIELDS:
            tokens = self.possible[name]
            if not isinstance(tokens, tuple) or not tokens:
                raise SupportRegisterError(
                    f"{self.name}: {name} lists the tokens it can have, in a tuple"
                )
            for token in tokens:
                if token not in VOCABULARY[name]:
                    raise SupportRegisterError(
                        f"{self.name}: {name} {token!r} is not in its vocabulary"
                    )
            own = getattr(self.facts, name)
            if own not in tokens:
                raise SupportRegisterError(
                    f"{self.name}: its own {name} {own!r} is not among the tokens "
                    f"it can have ({', '.join(tokens)})"
                )


@dataclass(frozen=True)
class Evaluation:
    """One row that matches a host: the facts it matched, the paths a user is
    offered there, and the polyfill the row names."""

    row: SupportRow
    facts: HostFacts
    paths: tuple[UpgradePath, ...]
    polyfill: Polyfill | None
    matched: Mapping[str, str]


_T = TypeVar("_T")


def _index(kind: str, items: Iterable[_T], key: Callable[[_T], str]) -> dict[str, _T]:
    """``items`` by their id, refusing an id declared twice."""
    found: dict[str, _T] = {}
    for item in items:
        name = key(item)
        if name in found:
            raise SupportRegisterError(f"{kind} {name} is declared twice")
        found[name] = item
    return found


def _overlaid(overlay: Mapping[str, str]) -> HostFacts:
    """The reference facts with ``overlay`` on them, settled as a run's are."""
    unknown = [name for name in overlay if name not in FIELDS]
    if unknown:
        raise SupportRegisterError(
            f"no such fact: {', '.join(unknown)} (the facts are {', '.join(FIELDS)})"
        )
    return settle(replace(REFERENCE_FACTS, **overlay))


_NO_BUILD = "no-build"


def _is_no_build(row: SupportRow) -> bool:
    """True for a row derived from a pinned binary's missing platform."""
    return f".{_NO_BUILD}." in row.id


@dataclass(frozen=True)
class Register:
    """The declared polyfills, upgrade paths, host profiles and rows, with the
    evaluator that reads them.

    Construction refuses what can be refused from the declarations alone: an id
    declared twice, a row that names a path or a polyfill nobody declared, a path that
    names a profile nobody declared, an unsupported row whose paths are all on this
    operating system, a supported row that names a stand-in. What the register says
    about itself beyond that (every token covered, every path valid) is held by tests.
    """

    polyfills: tuple[Polyfill, ...]
    paths: tuple[UpgradePath, ...]
    profiles: tuple[Profile, ...]
    rows: tuple[SupportRow, ...]
    #: ``(fact, token)`` to the reason the register says nothing about it.
    not_declared: Mapping[tuple[str, str], str]
    _polyfills: dict[str, Polyfill] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )
    _paths: dict[str, UpgradePath] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )
    _profiles: dict[str, Profile] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )
    _rows: dict[str, SupportRow] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        polyfills = _index("polyfill", self.polyfills, lambda item: item.id)
        paths = _index("path", self.paths, lambda item: item.id)
        profiles = _index("profile", self.profiles, lambda item: item.name)
        rows = _index("row", self.rows, lambda item: item.id)
        for path in self.paths:
            for name in path.targets:
                if name not in profiles:
                    raise SupportRegisterError(
                        f"path {path.id}: no such profile {name}"
                    )
        for row in self.rows:
            for path_id in row.paths:
                if path_id not in paths:
                    raise SupportRegisterError(f"row {row.id}: no such path {path_id}")
            if row.polyfill is not None:
                polyfill = polyfills.get(row.polyfill)
                if polyfill is None:
                    raise SupportRegisterError(
                        f"row {row.id}: no such polyfill {row.polyfill}"
                    )
                adaptation = polyfill.kind is PolyfillKind.ADAPTATION
                if row.level is SupportLevel.SUPPORTED and not adaptation:
                    raise SupportRegisterError(
                        f"row {row.id}: a supported row names an adaptation, and "
                        f"{polyfill.id} is not one"
                    )
                if row.level is not SupportLevel.SUPPORTED and adaptation:
                    raise SupportRegisterError(
                        f"row {row.id}: only a supported row names an adaptation "
                        f"({polyfill.id})"
                    )
            if row.level is SupportLevel.UNSUPPORTED and all(
                paths[path_id].kind is PathKind.SAME_OS for path_id in row.paths
            ):
                raise SupportRegisterError(
                    f"row {row.id}: every path is same-os, and an unsupported row "
                    "offers at least one container, WSL, other-os, other-host or "
                    "CI-runner path"
                )
        for key, reason in self.not_declared.items():
            if not (isinstance(key, tuple) and len(key) == 2):
                raise SupportRegisterError(f"not declared: {key!r} is (fact, token)")
            name, token = key
            if name not in VOCABULARY or token not in VOCABULARY[name]:
                raise SupportRegisterError(
                    f"not declared: {name}={token} is not in the vocabulary"
                )
            _public(f"{name}={token}", "reason", reason)
        object.__setattr__(self, "_polyfills", polyfills)
        object.__setattr__(self, "_paths", paths)
        object.__setattr__(self, "_profiles", profiles)
        object.__setattr__(self, "_rows", rows)

    # -- lookups ----------------------------------------------------------

    def polyfill(self, polyfill_id: str) -> Polyfill:
        """The polyfill declared as ``polyfill_id``."""
        try:
            return self._polyfills[polyfill_id]
        except KeyError:
            raise SupportRegisterError(f"no such polyfill {polyfill_id}") from None

    def path(self, path_id: str) -> UpgradePath:
        """The upgrade path declared as ``path_id``."""
        try:
            return self._paths[path_id]
        except KeyError:
            raise SupportRegisterError(f"no such path {path_id}") from None

    def profile(self, name: str) -> Profile:
        """The host profile declared as ``name``."""
        try:
            return self._profiles[name]
        except KeyError:
            raise SupportRegisterError(f"no such profile {name}") from None

    def row(self, row_id: str) -> SupportRow:
        """The row declared as ``row_id``."""
        try:
            return self._rows[row_id]
        except KeyError:
            raise SupportRegisterError(f"no such row {row_id}") from None

    def extended(
        self,
        *,
        rows: Iterable[SupportRow] = (),
        paths: Iterable[UpgradePath] = (),
        polyfills: Iterable[Polyfill] = (),
        profiles: Iterable[Profile] = (),
    ) -> Register:
        """This register with more declarations added, validated as a whole. The rows
        derived from a pinned binary's platforms join the shipped register this way."""
        return Register(
            polyfills=self.polyfills + tuple(polyfills),
            paths=self.paths + tuple(paths),
            profiles=self.profiles + tuple(profiles),
            rows=self.rows + tuple(rows),
            not_declared=self.not_declared,
        )

    # -- the evaluator ----------------------------------------------------

    def offered_paths(
        self, row: SupportRow, facts: HostFacts
    ) -> tuple[UpgradePath, ...]:
        """The row's paths, in the row's order, that can be offered on ``facts``."""
        return tuple(
            path
            for path in (self._paths[path_id] for path_id in row.paths)
            if path.available_when.matches(facts)
        )

    def apply_path(self, path: UpgradePath, facts: HostFacts) -> tuple[HostFacts, ...]:
        """The facts a run has after taking ``path``, one result for each token a
        fact can take or each profile the path can lead to.

        A path on this machine overlays its tokens and keeps every other fact, the
        processor included. A path to another machine replaces the host's facts with
        its profile's and keeps only the run's own choices: the mode, the sandbox
        request, the express request, the wrapper shell and the ignore paths.
        """
        if path.kind.here:
            target = path.target
            if not isinstance(target, Match):
                raise SupportRegisterError(f"path {path.id}: its target is not tokens")
            constraints = target.constraints()
            names = [name for name, _ in constraints]
            return tuple(
                settle(replace(facts, **dict(zip(names, combo, strict=True))))
                for combo in itertools.product(*(tokens for _, tokens in constraints))
            )
        results = []
        for name in path.targets:
            results.append(
                settle(
                    replace(
                        self.profile(name).facts,
                        run_mode=facts.run_mode,
                        sandbox_mode=facts.sandbox_mode,
                        express_requested=facts.express_requested,
                        shell=facts.shell,
                        ignore_paths=facts.ignore_paths,
                    )
                )
            )
        return tuple(results)

    def evaluate(
        self,
        facts: HostFacts,
        scope: str = "ash",
        *,
        notify: Notify | Iterable[Notify] | None = None,
        include_supported: bool = False,
    ) -> tuple[Evaluation, ...]:
        """The rows of ``scope`` that match ``facts``, worst first, ties in
        declaration order.

        ``notify`` keeps only the rows raised at that moment (one value or several);
        the default keeps every row, matrix-only ones included. Supported rows, which
        are adaptations, are left out unless ``include_supported`` is set.
        """
        settled = settle(facts)
        wanted: frozenset[Notify] | None
        if notify is None:
            wanted = None
        elif isinstance(notify, str):
            wanted = frozenset((Notify(notify),))
        else:
            wanted = frozenset(Notify(item) for item in notify)
        found: list[Evaluation] = []
        for row in self.rows:
            if row.scope != scope:
                continue
            if row.level is SupportLevel.SUPPORTED and not include_supported:
                continue
            if wanted is not None and row.notify not in wanted:
                continue
            if not row.match.matches(settled):
                continue
            found.append(
                Evaluation(
                    row=row,
                    facts=settled,
                    paths=self.offered_paths(row, settled),
                    polyfill=self._polyfills[row.polyfill] if row.polyfill else None,
                    matched={
                        name: getattr(settled, name)
                        for name, _ in row.match.constraints()
                    },
                )
            )
        found.sort(key=lambda item: -item.row.level.rank)
        return tuple(found)

    # -- one cell of a matrix, and the refusal accessor -------------------

    def _token(self, evaluation: Evaluation) -> str:
        row = evaluation.row
        if row.level is SupportLevel.POLYFILLED and evaluation.polyfill is not None:
            return f"polyfill: {evaluation.polyfill.cell}"
        if row.behavior in (Behavior.SKIPS_SCANNER, Behavior.REFUSES):
            return f"refused: {row.cell}"
        if _is_no_build(row):
            return "no asset"
        if row.level is SupportLevel.DEGRADED:
            return f"degraded: {row.cell}"
        return f"unsupported: {row.cell}"

    def cells(self, scope: str, overlay: Mapping[str, str]) -> str:
        """What one cell of a support matrix says for ``scope`` on the reference
        host with ``overlay`` on it.

        ``yes`` for a supported cell and for an adaptation; otherwise each matching
        row as ``polyfill: <cell>``, ``degraded: <cell>``, ``unsupported: <cell>``,
        ``refused: <cell>`` or ``no asset``, worst first and joined by ``; ``. A
        token the register leaves undeclared adds ``not declared``. It reads declared
        data only, so it answers the same on every machine.
        """
        facts = _overlaid(overlay)
        tokens = [self._token(item) for item in self.evaluate(facts, scope)]
        if any(getattr(facts, name) == token for name, token in self.not_declared):
            tokens.append("not declared")
        return "; ".join(tokens) if tokens else "yes"

    def refusal(self, scanner: str, os: str) -> str | None:
        """The reason ``scanner`` is skipped on operating system ``os``, or None.

        It reads the declared rows whose behavior is to skip the scanner, so a matrix
        needs no patch of ``platform.system`` to learn today's refusals.
        """
        facts = _overlaid({"os": os, "host_os": os})
        for item in self.evaluate(facts, scanner):
            if item.row.behavior is Behavior.SKIPS_SCANNER:
                return item.row.reason
        return None


# ---------------------------------------------------------------------------
# The polyfills and the adaptations
# ---------------------------------------------------------------------------

if tuple(f.name for f in fields(HostFacts)) != FIELDS or tuple(
    f.name for f in fields(Match)
) != MATCH_FIELDS:
    raise SupportRegisterError("the facts and the match must name the same dimensions")

_STAND_INS: tuple[Polyfill, ...] = (
    Polyfill(
        id="polars-compat-runtime",
        name="Polars compatibility runtime",
        kind=PolyfillKind.SUBSTITUTE,
        cell="polars compatibility runtime",
        stands_in_for=(
            "The default polars runtime, which is built for AVX2-class x86-64 "
            "processors."
        ),
        difference=(
            "It runs on older x86-64 processors and is slower than the default runtime."
        ),
    ),
    Polyfill(
        id="powershell-5-compat",
        name="PowerShell 5 compatibility",
        kind=PolyfillKind.SUBSTITUTE,
        cell="PowerShell 5 compatibility",
        stands_in_for=(
            "The PowerShell 7 behavior the wrapper relies on: the IsWindows variable, "
            "link and file-mode reads, and argument quoting."
        ),
        difference=(
            "Values that PowerShell before 7.3 would pass to a program wrongly are "
            "refused one by one, with exit 3."
        ),
    ),
    Polyfill(
        id="msys-path-rules",
        name="MSYS path rules",
        kind=PolyfillKind.SUBSTITUTE,
        cell="MSYS path rules",
        stands_in_for=(
            "Windows path handling in a POSIX shell (Git Bash, MSYS2, Cygwin)."
        ),
        difference="MSYS path conversion cannot be turned off for ASH's arguments.",
    ),
    Polyfill(
        id="guarddog-ash-sandbox",
        name="ASH sandbox for GuardDog",
        kind=PolyfillKind.SUBSTITUTE,
        cell="ASH sandbox replaces GuardDog's own",
        stands_in_for=(
            "ASH's own sandbox-exec confinement stands in for GuardDog's kernel sandbox."
        ),
        difference=(
            "GuardDog's own nono policy is not applied; ASH's sandbox confines the "
            "scan instead."
        ),
    ),
    Polyfill(
        id="betterleaks-private-home",
        name="Betterleaks private home directory",
        kind=PolyfillKind.SUBSTITUTE,
        cell="private home for Betterleaks",
        stands_in_for=(
            "A private home directory stands in for the cache directory that "
            "sandbox-exec denies."
        ),
        difference="Its compile cache is not kept between runs.",
    ),
)

_PACKAGE = "automated_security_helper"

_ADAPTATIONS: tuple[Polyfill, ...] = (
    Polyfill(
        id="windows-executable-lookup",
        name="Windows executable lookup",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows executable lookup",
        stands_in_for=(
            "On Windows the file that carries a tool's name is often not one Windows "
            "can run, so ASH looks for the .exe, .bat and .cmd wrappers that package "
            "managers write beside it."
        ),
        difference=None,
        code_sites=(f"{_PACKAGE}/utils/subprocess_utils.py:_executable_candidate_names",),
    ),
    Polyfill(
        id="windows-command-line-bounds",
        name="Windows command-line bounds",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows command-line bounds",
        stands_in_for=(
            "Windows can re-read a command line through cmd.exe, which splits it at "
            "characters other platforms pass through, so ASH writes the paths it "
            "gives Checkov in a form that survives that."
        ),
        difference=None,
        code_sites=(
            (
                f"{_PACKAGE}/plugin_modules/ash_builtin/scanners/checkov_scanner.py:"
                "_known_ignore_skip_pattern"
            ),
        ),
    ),
    Polyfill(
        id="windows-console-rendering",
        name="Windows console rendering",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows console rendering",
        stands_in_for=(
            "Some Windows consoles cannot encode every character ASH prints, so ASH "
            "writes ASCII in place of emoji in log messages and sets its console "
            "streams to UTF-8."
        ),
        difference=None,
        code_sites=(
            f"{_PACKAGE}/utils/log.py:_make_message_windows_safe",
            f"{_PACKAGE}/utils/log.py:configure_windows_safe_logging",
        ),
    ),
    Polyfill(
        id="windows-atomic-replace-retry",
        name="Windows atomic replace retry",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows atomic replace retry",
        stands_in_for=(
            "On Windows a reader that holds a file open makes the rename that "
            "replaces it fail, so ASH retries the rename for a short time and reads "
            "the file again."
        ),
        difference=None,
        code_sites=(
            f"{_PACKAGE}/utils/atomic_write.py:_replace",
            f"{_PACKAGE}/utils/atomic_write.py:read_text_of_replaced_file",
        ),
    ),
    Polyfill(
        id="windows-output-decoding",
        name="Windows output decoding",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows output decoding",
        stands_in_for=(
            "Windows tools write text in the console's code page, so ASH decodes the "
            "partial output of a timed-out tool with the locale's encoding and not "
            "with UTF-8."
        ),
        difference=None,
        code_sites=(f"{_PACKAGE}/utils/subprocess_utils.py:_late_decoded",),
    ),
    Polyfill(
        id="windows-link-open-check",
        name="Windows link open check",
        kind=PolyfillKind.ADAPTATION,
        cell="Windows link open check",
        stands_in_for=(
            "Windows cannot open a file relative to a directory handle, so ASH checks "
            "by path that a file it reads is not a link."
        ),
        difference=None,
        code_sites=(f"{_PACKAGE}/utils/sandbox/fs_guard.py:_guarded_read_fd",),
    ),
    Polyfill(
        id="macos-process-wait",
        name="macOS process wait",
        kind=PolyfillKind.ADAPTATION,
        cell="macOS process wait",
        stands_in_for=(
            "CPython has no waitid call on macOS, so ASH polls for the end of a tool "
            "process and forgets its process id once the process has ended."
        ),
        difference=None,
        code_sites=(
            f"{_PACKAGE}/utils/subprocess_utils.py:discard_tool_pid_once_exited",
            f"{_PACKAGE}/utils/subprocess_utils.py:discard_tool_pid_before_reap",
        ),
    ),
    Polyfill(
        id="macos-quarantine-removal",
        name="macOS quarantine removal",
        kind=PolyfillKind.ADAPTATION,
        cell="macOS quarantine removal",
        stands_in_for=(
            "macOS marks a downloaded binary as quarantined, so ASH removes the mark "
            "from the tools it downloads before it runs them."
        ),
        difference=None,
        code_sites=(f"{_PACKAGE}/utils/download_utils.py:unquarantine_macos_binary",),
    ),
    Polyfill(
        id="linux-fork-start",
        name="Linux fork start",
        kind=PolyfillKind.ADAPTATION,
        cell="Linux fork start",
        stands_in_for=(
            "Linux starts worker processes with fork, so a worker begins with ASH's "
            "modules loaded; macOS and Windows start a fresh interpreter instead."
        ),
        difference=None,
        code_sites=(
            (
                f"{_PACKAGE}/plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py:"
                "DetectSecretsScanner._ensure_fork_multiprocessing"
            ),
            f"{_PACKAGE}/config/client_scanner_exclusions.py:_process_context",
        ),
    ),
)

#: The operating system whose platform each adaptation belongs to.
_ADAPTATION_OS: dict[str, str] = {
    "windows-executable-lookup": "windows",
    "windows-command-line-bounds": "windows",
    "windows-console-rendering": "windows",
    "windows-atomic-replace-retry": "windows",
    "windows-output-decoding": "windows",
    "windows-link-open-check": "windows",
    "macos-process-wait": "darwin",
    "macos-quarantine-removal": "darwin",
    "linux-fork-start": "linux",
}

# ---------------------------------------------------------------------------
# The upgrade paths
# ---------------------------------------------------------------------------

#: What a run moved into WSL 2 has: Linux under the Windows host, a glibc distribution,
#: a native processor and the bwrap sandbox a sandboxed run there gets.
_WSL_TARGET = Match(
    os=("linux",),
    host_os=("linux",),
    wsl=("wsl2",),
    libc=("glibc",),
    translation=("native",),
    install_channel=("uv-tool",),
    shell=("none",),
    express_available=("yes",),
    sandbox_backend=("bwrap",),
    sandbox_loss=("none",),
)

#: Where the compatibility runtime can be installed: an environment the user owns.
_USER_ENVIRONMENTS = ("uv-tool", "uvx", "pipx", "pip", "source")

_PATHS: tuple[UpgradePath, ...] = (
    UpgradePath(
        id="polars-compat-runtime",
        kind=PathKind.SAME_OS,
        summary=(
            "Add polars' compatibility runtime (its rtcompat extra) to ASH's "
            "environment, at the polars version ASH uses."
        ),
        target=Match(polars_runtime=("compat",)),
        available_when=Match(
            arch=("amd64",),
            cpu_level=("compat-only",),
            install_channel=_USER_ENVIRONMENTS,
        ),
        command_builder="polars-compat-runtime",
    ),
    UpgradePath(
        id="native-arm64",
        kind=PathKind.SAME_OS,
        summary=(
            "Install an arm64 build of Python and reinstall ASH with it, so nothing "
            "runs translated."
        ),
        target=Match(arch=("arm64",), translation=("native",)),
        available_when=Match(translation=("rosetta", "x64-on-arm64")),
    ),
    UpgradePath(
        id="x86-host-with-features",
        kind=PathKind.OTHER_HOST,
        summary=(
            "Run ASH on an x86-64 processor with the instruction set polars is built "
            "for (AVX2 and its companions)."
        ),
        target="LINUX_AMD64",
    ),
    UpgradePath(
        id="arm64-host",
        kind=PathKind.OTHER_HOST,
        summary=(
            "Run ASH on an arm64 machine: Linux on arm64 or a Mac with Apple silicon."
        ),
        target=("LINUX_ARM64", "MACOS_ARM64"),
    ),
    UpgradePath(
        id="ci-runner",
        kind=PathKind.CI_RUNNER,
        summary=(
            "Run the scan in CI on a hosted runner; ASH's reusable GitHub workflow "
            "runs on ubuntu-latest by default."
        ),
        target="LINUX_AMD64",
    ),
    UpgradePath(
        id="supported-python",
        kind=PathKind.SAME_OS,
        summary=(
            "Reinstall ASH on a Python inside the range it declares, for example 3.12."
        ),
        target=Match(python_in_range=("yes",), python_build=("standard",)),
    ),
    UpgradePath(
        id="container-image",
        kind=PathKind.CONTAINER,
        summary=(
            "Scan in ASH's Linux container image (container mode); it needs Docker, "
            "Finch, Podman or nerdctl."
        ),
        target=Match(
            run_mode=("container",),
            os=("linux",),
            libc=("glibc",),
            python_in_range=("yes",),
            python_build=("standard",),
            install_channel=("image",),
            polars_runtime=("runtime-32",),
        ),
        available_when=Match(host_os=("linux", "darwin", "windows")),
        command_builder="container-image",
    ),
    UpgradePath(
        id="wsl2",
        kind=PathKind.WSL,
        summary="Install ASH inside WSL 2 on this Windows machine and scan from there.",
        target=_WSL_TARGET,
        available_when=Match(host_os=("windows",)),
    ),
    UpgradePath(
        id="wsl2-sandboxed",
        kind=PathKind.WSL,
        summary=(
            "Install ASH inside WSL 2 and scan there in local mode with the bwrap "
            "sandbox."
        ),
        target=replace(_WSL_TARGET, run_mode=("local",)),
        available_when=Match(host_os=("windows",)),
    ),
    UpgradePath(
        id="linux-or-macos-host",
        kind=PathKind.OTHER_OS,
        summary="Run ASH on Linux or macOS.",
        target="LINUX_AMD64",
        available_when=Match(host_os=("windows", "other")),
    ),
    UpgradePath(
        id="sandbox-capable-host",
        kind=PathKind.OTHER_HOST,
        summary=(
            "Run ASH on a machine where a sandbox backend works: Linux that allows "
            "unprivileged user namespaces, or macOS."
        ),
        target="LINUX_AMD64",
    ),
    UpgradePath(
        id="mode-local-sandboxed",
        kind=PathKind.SAME_OS,
        summary=(
            "Scan in local mode with a working sandbox backend, so each scanner is "
            "sandboxed."
        ),
        target=Match(
            run_mode=("local",),
            sandbox_backend=("bwrap", "sandbox-exec"),
            sandbox_loss=("none",),
        ),
        available_when=Match(host_os=("linux", "darwin")),
        command_builder="mode-local-sandboxed",
    ),
    UpgradePath(
        id="install-bubblewrap",
        kind=PathKind.SAME_OS,
        summary=(
            "Install bubblewrap and allow unprivileged user namespaces, or use the "
            "firejail or landlock backend."
        ),
        target=Match(sandbox_backend=("bwrap",), sandbox_loss=("none",)),
        available_when=Match(os=("linux",)),
    ),
    UpgradePath(
        id="newer-kernel-landlock",
        kind=PathKind.SAME_OS,
        summary=(
            "Use a Linux kernel whose Landlock ABI is 6 or later, or the bwrap backend."
        ),
        target=Match(sandbox_loss=("none",)),
        available_when=Match(os=("linux",)),
    ),
    UpgradePath(
        id="newer-bubblewrap",
        kind=PathKind.SAME_OS,
        summary="Use bubblewrap 0.8 or later on Linux 5.11 or later.",
        target=Match(sandbox_loss=("none",)),
        available_when=Match(os=("linux",)),
    ),
    UpgradePath(
        id="enable-landlock",
        kind=PathKind.SAME_OS,
        summary=(
            "Use a Linux kernel with Landlock enabled (add landlock to the lsm= "
            "kernel parameter), which GuardDog's own sandbox needs."
        ),
        target=Match(tool_sandbox=("own",)),
        available_when=Match(os=("linux",)),
    ),
    UpgradePath(
        id="pwsh7",
        kind=PathKind.SAME_OS,
        summary="Run the wrapper from PowerShell 7.3 or later (pwsh).",
        target=Match(shell=("pwsh",)),
        available_when=Match(shell=("powershell-5", "msys-wrapper")),
    ),
    UpgradePath(
        id="mode-local",
        kind=PathKind.SAME_OS,
        summary="Scan in local mode on this machine.",
        target=Match(run_mode=("local",)),
        available_when=Match(run_mode=("nix",)),
        command_builder="mode-local",
    ),
    UpgradePath(
        id="native-image",
        kind=PathKind.SAME_OS,
        summary=(
            "Build the image for this machine's architecture, which ASH's image "
            "build does by default, and scan with it."
        ),
        target=Match(image_arch_matches=("yes",)),
        available_when=Match(run_mode=("container",)),
        command_builder="native-image",
    ),
)

# ---------------------------------------------------------------------------
# The host profiles
# ---------------------------------------------------------------------------

#: The facts a user chooses, which any host can have a user choose either way.
_RUN_CHOICES: dict[str, tuple[str, ...]] = {
    "python_in_range": ("yes", "no"),
    "python_build": ("standard", "free-threaded", "other-implementation"),
    "run_mode": ("local", "container", "precommit", "nix"),
    "image_arch_matches": ("n/a", "yes", "no"),
    "sandbox_mode": ("off", "auto", "named"),
    "express_requested": ("no", "yes"),
    "ignore_paths": ("none", "set"),
}

_ALL_CHANNELS = ("uv-tool", "uvx", "pipx", "pip", "brew", "nix", "image", "source")

_LINUX_POSSIBLE: dict[str, tuple[str, ...]] = {
    **_RUN_CHOICES,
    "os": ("linux",),
    "host_os": ("linux",),
    "arch": ("amd64", "other"),
    "translation": ("native",),
    "cpu_level": ("full", "compat-only", "below-compat"),
    "polars_runtime": ("runtime-32", "runtime-64", "compat"),
    "libc": ("glibc", "musl"),
    "install_channel": _ALL_CHANNELS,
    "wsl": ("no", "wsl2", "wsl1"),
    "shell": ("none", "bash-wrapper", "pwsh"),
    "sandbox_backend": ("bwrap", "firejail", "landlock", "none"),
    "sandbox_loss": ("none", "landlock-below-6", "caches-read-only"),
    "express_available": ("yes",),
    # GuardDog's own kernel sandbox is unavailable only where Landlock is.
    "tool_sandbox": ("own", "unavailable", "n/a"),
}

#: A Mac can run the container image, so ``os`` can be Linux there; it has the
#: sandbox-exec backend or none, and no libc of its own.
_MACOS_POSSIBLE: dict[str, tuple[str, ...]] = {
    **_RUN_CHOICES,
    "os": ("darwin", "linux"),
    "host_os": ("darwin",),
    "arch": ("arm64",),
    "translation": ("native",),
    "cpu_level": ("n/a",),
    "polars_runtime": ("runtime-32", "runtime-64"),
    "libc": ("n/a", "glibc"),
    "install_channel": ("uv-tool", "uvx", "pipx", "pip", "brew", "nix", "source"),
    "wsl": ("n/a", "no"),
    "shell": ("none", "bash-wrapper", "pwsh"),
    "sandbox_backend": ("sandbox-exec", "none"),
    "sandbox_loss": ("none",),
    "express_available": ("yes",),
    "tool_sandbox": ("own", "replaced", "n/a"),
}

#: A Windows host has no sandbox backend and no express mode, and none of the
#: scanners that need a tool sandbox run there.
_WINDOWS_POSSIBLE: dict[str, tuple[str, ...]] = {
    **_RUN_CHOICES,
    "os": ("windows", "linux"),
    "host_os": ("windows",),
    "arch": ("amd64", "other"),
    "translation": ("native",),
    "cpu_level": ("full", "compat-only", "below-compat"),
    "polars_runtime": ("runtime-32", "runtime-64", "compat"),
    "libc": ("n/a", "glibc"),
    "install_channel": ("uv-tool", "uvx", "pipx", "pip", "source"),
    "wsl": ("n/a", "no"),
    "shell": ("none", "pwsh", "powershell-5", "msys-wrapper"),
    "sandbox_backend": ("none",),
    "sandbox_loss": ("none",),
    "express_available": ("no",),
    "tool_sandbox": ("n/a",),
}

#: An operating system and processor ASH is not built for. It can run in the local
#: and pre-commit modes only, and has no sandbox.
_OTHER_POSSIBLE: dict[str, tuple[str, ...]] = {
    "os": ("other",),
    "host_os": ("other",),
    "arch": ("other",),
    "translation": ("native",),
    "cpu_level": ("n/a",),
    "polars_runtime": ("absent",),
    "libc": ("n/a",),
    "python_in_range": ("yes", "no"),
    "python_build": ("standard", "free-threaded", "other-implementation"),
    "install_channel": ("pip", "source"),
    "run_mode": ("local", "precommit"),
    "wsl": ("n/a",),
    "shell": ("none",),
    "image_arch_matches": ("n/a",),
    "sandbox_mode": ("off",),
    "sandbox_backend": ("none",),
    "sandbox_loss": ("none",),
    "express_requested": ("no",),
    "express_available": ("yes",),
    "tool_sandbox": ("n/a",),
    "ignore_paths": ("none", "set"),
}

#: The host part of the reference facts, with bwrap as the backend a sandboxed run
#: gets and GuardDog's own sandbox available.
_LINUX_AMD64 = replace(REFERENCE_FACTS, sandbox_backend="bwrap", tool_sandbox="own")
_MACOS_ARM64 = replace(
    REFERENCE_FACTS,
    os="darwin",
    host_os="darwin",
    os_release="macos",
    arch="arm64",
    cpu_level="n/a",
    libc="n/a",
    wsl="n/a",
    sandbox_backend="sandbox-exec",
    tool_sandbox="own",
)
_MACOS_AMD64 = replace(_MACOS_ARM64, arch="amd64", cpu_level="full")
_WINDOWS_AMD64 = replace(
    REFERENCE_FACTS,
    os="windows",
    host_os="windows",
    os_release="windows",
    libc="n/a",
    wsl="n/a",
    sandbox_backend="none",
    express_available="no",
)
_X86_RUNTIMES = ("runtime-32", "runtime-64", "compat")

_PROFILES: tuple[Profile, ...] = (
    Profile("LINUX_AMD64", _LINUX_AMD64, _LINUX_POSSIBLE),
    Profile(
        "LINUX_ARM64",
        replace(_LINUX_AMD64, arch="arm64", cpu_level="n/a"),
        {
            **_LINUX_POSSIBLE,
            "arch": ("arm64", "other"),
            "cpu_level": ("n/a",),
            "polars_runtime": ("runtime-32", "runtime-64"),
        },
    ),
    Profile("MACOS_ARM64", _MACOS_ARM64, _MACOS_POSSIBLE),
    Profile(
        "MACOS_AMD64",
        _MACOS_AMD64,
        {
            **_MACOS_POSSIBLE,
            "arch": ("amd64",),
            "cpu_level": ("full", "compat-only", "below-compat"),
            "polars_runtime": _X86_RUNTIMES,
        },
    ),
    Profile(
        "MACOS_ROSETTA",
        replace(_MACOS_AMD64, translation="rosetta"),
        {
            **_MACOS_POSSIBLE,
            "arch": ("amd64",),
            "translation": ("rosetta",),
            "cpu_level": ("full", "compat-only", "below-compat"),
            "polars_runtime": _X86_RUNTIMES,
        },
    ),
    Profile("WINDOWS_AMD64", _WINDOWS_AMD64, _WINDOWS_POSSIBLE),
    Profile(
        "WINDOWS_ARM64",
        replace(_WINDOWS_AMD64, arch="arm64", cpu_level="n/a"),
        {
            **_WINDOWS_POSSIBLE,
            "arch": ("arm64", "other"),
            "cpu_level": ("n/a",),
            "polars_runtime": ("runtime-32", "runtime-64"),
        },
    ),
    Profile(
        "WINDOWS_X64_ON_ARM64",
        replace(_WINDOWS_AMD64, translation="x64-on-arm64"),
        {
            **_WINDOWS_POSSIBLE,
            "arch": ("amd64",),
            "translation": ("x64-on-arm64",),
        },
    ),
    Profile(
        "OTHER",
        HostFacts(
            os="other",
            host_os="other",
            os_release="other",
            arch="other",
            translation="native",
            cpu_level="n/a",
            polars_runtime="absent",
            libc="n/a",
            python_in_range="yes",
            python_build="standard",
            install_channel="pip",
            run_mode="local",
            wsl="n/a",
            shell="none",
            image_arch_matches="n/a",
            sandbox_mode="off",
            sandbox_backend="none",
            sandbox_loss="none",
            express_requested="no",
            express_available="yes",
            tool_sandbox="n/a",
            ignore_paths="none",
        ),
        _OTHER_POSSIBLE,
    ),
)

# ---------------------------------------------------------------------------
# The tokens the register says nothing about
# ---------------------------------------------------------------------------

#: A token no row covers and no supported set names. The matrices render it "not
#: declared", the runtime raises no notice for it, and each entry says why.
NOT_DECLARED: dict[tuple[str, str], str] = {
    ("libc", "musl"): (
        "ASH does not declare support for Linux with musl libc, such as Alpine, and "
        "raises no notice there."
    ),
    ("wsl", "wsl1"): "ASH documents WSL 2 only and declares nothing about WSL 1.",
    ("python_build", "free-threaded"): (
        "The free-threaded CPython build cannot use the stable ABI wheels polars' "
        "runtime ships, so installing ASH there means building polars from source, "
        "and ASH declares nothing about it."
    ),
    ("python_build", "other-implementation"): (
        "ASH declares nothing about Python implementations other than CPython."
    ),
    ("polars_runtime", "absent"): (
        "ASH needs a polars runtime to start, so no run reaches the register without "
        "one."
    ),
}

# ---------------------------------------------------------------------------
# The rows
# ---------------------------------------------------------------------------


def _unsupported(
    row_id: str,
    *,
    dimension: str,
    match: Match,
    behavior: Behavior,
    notify: Notify,
    reason: str,
    cell: str,
    paths: tuple[str, ...],
    scope: str = "ash",
) -> SupportRow:
    return SupportRow(
        id=row_id,
        scope=scope,
        dimension=dimension,
        match=match,
        level=SupportLevel.UNSUPPORTED,
        behavior=behavior,
        notify=notify,
        reason=reason,
        cell=cell,
        paths=paths,
    )


def _degraded(
    row_id: str,
    *,
    dimension: str,
    match: Match,
    notify: Notify,
    text: str,
    cell: str,
    paths: tuple[str, ...],
    scope: str = "ash",
    cli: bool | None = None,
    results: bool = True,
    docs_anchor: str | None = None,
) -> SupportRow:
    """A degraded row. The sentence that names what is lost is also its reason."""
    return SupportRow(
        id=row_id,
        scope=scope,
        dimension=dimension,
        match=match,
        level=SupportLevel.DEGRADED,
        behavior=Behavior.CONTINUES,
        notify=notify,
        reason=text,
        cell=cell,
        lost=text,
        paths=paths,
        cli=cli,
        results=results,
        docs_anchor=docs_anchor,
    )


def _polyfilled(
    row_id: str,
    *,
    dimension: str,
    match: Match,
    notify: Notify,
    reason: str,
    cell: str,
    polyfill: str,
    paths: tuple[str, ...] = (),
    scope: str = "ash",
) -> SupportRow:
    return SupportRow(
        id=row_id,
        scope=scope,
        dimension=dimension,
        match=match,
        level=SupportLevel.POLYFILLED,
        behavior=Behavior.CONTINUES,
        notify=notify,
        reason=reason,
        cell=cell,
        polyfill=polyfill,
        paths=paths,
    )


_CPU_PATHS = (
    "polars-compat-runtime",
    "native-arm64",
    "x86-host-with-features",
    "arm64-host",
    "ci-runner",
)
_HERE_PATHS = ("wsl2", "container-image", "linux-or-macos-host")
_SANDBOX_PATHS = ("install-bubblewrap", "wsl2-sandboxed", "sandbox-capable-host")
_WINDOWS_LOCAL = Match(os=("windows",), run_mode=("local", "precommit"))

_ASH_ROWS: tuple[SupportRow, ...] = (
    _unsupported(
        "host.cpu.below-polars-runtime",
        dimension="cpu",
        match=Match(
            arch=("amd64",),
            polars_runtime=("runtime-32", "runtime-64"),
            cpu_level=("compat-only", "below-compat"),
        ),
        behavior=Behavior.CONTINUES,
        notify=Notify.START,
        reason=(
            "This x86-64 processor lacks instructions the installed polars runtime "
            "is built for, and polars warns that running on it will likely crash."
        ),
        cell="processor below polars' default runtime",
        paths=_CPU_PATHS,
    ),
    _unsupported(
        "host.cpu.below-polars-compat",
        dimension="cpu",
        match=Match(
            arch=("amd64",),
            polars_runtime=("compat",),
            cpu_level=("below-compat",),
        ),
        behavior=Behavior.CONTINUES,
        notify=Notify.START,
        reason=(
            "This x86-64 processor lacks instructions even polars' compatibility "
            "runtime is built for, and polars warns that running on it will likely "
            "crash."
        ),
        cell="processor below polars' compat runtime",
        paths=_CPU_PATHS,
    ),
    _polyfilled(
        "host.cpu.polars-compat-runtime",
        dimension="cpu",
        match=Match(polars_runtime=("compat",), cpu_level=("full", "compat-only")),
        notify=Notify.START,
        reason=(
            "ASH runs with polars' compatibility runtime, which runs on older x86-64 "
            "processors and is slower than the default runtime."
        ),
        cell="polars compat runtime in use",
        polyfill="polars-compat-runtime",
    ),
    _degraded(
        "host.translation.rosetta",
        dimension="translation",
        match=Match(host_os=("darwin",), translation=("rosetta",)),
        notify=Notify.START,
        text=(
            "ASH runs as x86-64 code translated by Rosetta 2, and in local mode so do "
            "the tools it downloads for x86-64, which is slower than arm64 builds."
        ),
        cell="x86-64 under Rosetta 2",
        paths=("native-arm64",),
        cli=True,
    ),
    _degraded(
        "host.translation.x64-on-arm64",
        dimension="translation",
        match=Match(host_os=("windows",), translation=("x64-on-arm64",)),
        notify=Notify.START,
        text=(
            "ASH runs as x86-64 code under Windows emulation on an arm64 processor, "
            "and in local mode so do the tools it downloads for x86-64, which is "
            "slower."
        ),
        cell="x64 Python under Windows emulation",
        paths=("native-arm64", "wsl2"),
        cli=True,
    ),
    _unsupported(
        "host.os.other",
        dimension="os",
        match=Match(host_os=("other",)),
        behavior=Behavior.CONTINUES,
        notify=Notify.START,
        reason=(
            "ASH is built and tested for Linux, macOS and Windows, and this operating "
            "system is none of them."
        ),
        cell="not Linux, macOS or Windows",
        paths=("linux-or-macos-host", "ci-runner"),
    ),
    _unsupported(
        "host.arch.other",
        dimension="arch",
        match=Match(arch=("other",)),
        behavior=Behavior.CONTINUES,
        notify=Notify.START,
        reason=(
            "ASH runs on 64-bit x86 and arm64 processors, and polars, which ASH "
            "needs, publishes no build for this one."
        ),
        cell="not an x86-64 or arm64 processor",
        paths=("x86-host-with-features", "arm64-host", "ci-runner"),
    ),
    _unsupported(
        "host.python.outside-requires",
        dimension="python",
        match=Match(python_in_range=("no",)),
        behavior=Behavior.CONTINUES,
        notify=Notify.START,
        reason="This Python version is outside the range ASH declares.",
        cell="Python outside ASH's declared range",
        paths=("supported-python", "container-image", "ci-runner"),
    ),
    _unsupported(
        "host.mode.nix-on-windows",
        dimension="run mode",
        match=Match(host_os=("windows",), run_mode=("nix",)),
        behavior=Behavior.REFUSES,
        notify=Notify.START,
        reason=(
            "Nix mode runs on Linux and macOS, because native Nix on Windows cannot "
            "fetch the pinned scanners."
        ),
        cell="Nix mode on Windows",
        paths=("wsl2", "container-image", "mode-local"),
    ),
    _degraded(
        "host.sandbox.not-applied-in-container",
        dimension="sandbox",
        match=Match(run_mode=("container",), sandbox_mode=("auto", "named")),
        notify=Notify.START,
        text=(
            "The per-scanner sandbox is not applied in container mode, so the "
            "container is the only boundary around the scanners."
        ),
        cell="no per-scanner sandbox in container mode",
        paths=("mode-local-sandboxed", "wsl2-sandboxed"),
        cli=True,
    ),
    _unsupported(
        "host.sandbox.unavailable-auto",
        dimension="sandbox",
        match=Match(sandbox_mode=("auto",), sandbox_backend=("none",)),
        behavior=Behavior.SCANNER_MISSING,
        notify=Notify.DECISION,
        reason=(
            "No scanner sandbox backend works on this host, so scanners that must run "
            "sandboxed are not run."
        ),
        cell="no working scanner sandbox backend",
        paths=_SANDBOX_PATHS,
    ),
    _unsupported(
        "host.sandbox.unavailable-named",
        dimension="sandbox",
        match=Match(sandbox_mode=("named",), sandbox_backend=("none",)),
        behavior=Behavior.SCANNER_ERROR,
        notify=Notify.DECISION,
        reason=(
            "The scanner sandbox backend you named does not work on this host, so "
            "scanners that must run sandboxed report an error."
        ),
        cell="named sandbox backend not available",
        paths=_SANDBOX_PATHS,
    ),
    _degraded(
        "host.sandbox.landlock-below-6",
        dimension="sandbox",
        match=Match(
            sandbox_mode=("auto", "named"),
            sandbox_backend=("landlock",),
            sandbox_loss=("landlock-below-6",),
        ),
        notify=Notify.DECISION,
        text=(
            "Abstract Unix sockets and signals to processes outside the sandbox are "
            "not restricted, because the kernel's Landlock ABI is below 6."
        ),
        cell="Landlock ABI below 6",
        paths=("newer-kernel-landlock", "install-bubblewrap"),
    ),
    _degraded(
        "host.sandbox.bwrap-caches-read-only",
        dimension="sandbox",
        match=Match(
            sandbox_mode=("auto", "named"),
            sandbox_backend=("bwrap",),
            sandbox_loss=("caches-read-only",),
        ),
        notify=Notify.DECISION,
        text=(
            "Scanner caches are mounted read-only, and a tool that must write its "
            "cache gets an empty private one."
        ),
        cell="bubblewrap mounts caches read-only",
        paths=("newer-bubblewrap",),
    ),
    _degraded(
        "host.express.unavailable",
        dimension="express",
        match=Match(express_requested=("yes",), express_available=("no",)),
        notify=Notify.START,
        text=(
            "Express mode needs Unix sockets, descriptor passing and fork, so each "
            "scan starts cold."
        ),
        cell="express mode unavailable",
        paths=("wsl2", "linux-or-macos-host"),
        cli=True,
        results=False,
    ),
    _degraded(
        "host.windows.no-graceful-stop",
        dimension="os",
        match=_WINDOWS_LOCAL,
        notify=Notify.MATRIX,
        text=(
            "A timed-out or cancelled scanner is ended at once with its process tree, "
            "with no graceful stop, and Ctrl-C does not stop a scan cooperatively."
        ),
        cell="no graceful stop of scanner processes",
        paths=_HERE_PATHS,
    ),
    _degraded(
        "host.windows.no-tool-database-lock",
        dimension="os",
        match=_WINDOWS_LOCAL,
        notify=Notify.MATRIX,
        text=(
            "Scanner databases have no cross-process lock on Windows, so two scans at "
            "once can race on one."
        ),
        cell="no cross-process scanner database lock",
        paths=("wsl2", "container-image"),
    ),
    _degraded(
        "host.windows.container-leftovers",
        dimension="container leftovers",
        match=Match(host_os=("windows",), run_mode=("container",)),
        notify=Notify.MATRIX,
        text="Containers a cancelled scan leaves behind are not recorded or swept.",
        cell="cancelled scan containers not swept",
        paths=("wsl2",),
    ),
    _polyfilled(
        "host.shell.powershell-5",
        dimension="shell",
        match=Match(shell=("powershell-5",)),
        notify=Notify.START,
        reason=(
            "The wrapper runs under PowerShell 5.1, which lacks behavior it relies "
            "on, so a compatibility layer stands in for it."
        ),
        cell="PowerShell 5.1 compatibility layer",
        polyfill="powershell-5-compat",
        paths=("pwsh7",),
    ),
    _polyfilled(
        "host.shell.msys",
        dimension="shell",
        match=Match(shell=("msys-wrapper",)),
        notify=Notify.START,
        reason=(
            "The wrapper runs in a POSIX shell on Windows, such as Git Bash, MSYS2 or "
            "Cygwin, so ASH's own path rules stand in for Windows path handling."
        ),
        cell="POSIX shell on Windows path rules",
        polyfill="msys-path-rules",
        paths=("pwsh7", "wsl2"),
    ),
    _degraded(
        "host.container.image-arch-mismatch",
        dimension="container image",
        match=Match(run_mode=("container",), image_arch_matches=("no",)),
        notify=Notify.DECISION,
        text=(
            "The image's architecture differs from this machine's, so the engine runs "
            "it under emulation, which is slow."
        ),
        cell="image architecture differs from host",
        paths=("native-image",),
        cli=True,
    ),
)

#: The tools whose ignore-path options ASH does not pass on Windows.
_IGNORE_PATHS_TOOLS = ("trivy", "trivy-repo", "checkov", "ferret-scan")

_SCANNER_ROWS: tuple[SupportRow, ...] = (
    _unsupported(
        "scanner.semgrep.windows",
        scope="semgrep",
        dimension="os",
        match=Match(os=("windows",)),
        behavior=Behavior.SKIPS_SCANNER,
        notify=Notify.DECISION,
        reason="semgrep publishes no Windows build",
        cell="semgrep publishes no Windows build",
        paths=_HERE_PATHS,
    ),
    _unsupported(
        "scanner.guarddog.windows",
        scope="guarddog",
        dimension="os",
        match=Match(os=("windows",)),
        behavior=Behavior.SKIPS_SCANNER,
        notify=Notify.DECISION,
        reason=(
            "GuardDog 3.2.0 cannot be installed on Windows: its dependency nono-py "
            "publishes no Windows build and does not compile there"
        ),
        cell="GuardDog cannot be installed on Windows",
        paths=_HERE_PATHS,
    ),
    _polyfilled(
        "scanner.guarddog.sandbox-replaced",
        scope="guarddog",
        dimension="tool sandbox",
        match=Match(tool_sandbox=("replaced",)),
        notify=Notify.DECISION,
        reason=(
            "GuardDog runs inside ASH's sandbox-exec confinement instead of its own "
            "kernel sandbox."
        ),
        cell="GuardDog confined by ASH's sandbox",
        polyfill="guarddog-ash-sandbox",
    ),
    _degraded(
        "scanner.guarddog.sandbox-unavailable",
        scope="guarddog",
        dimension="tool sandbox",
        match=Match(tool_sandbox=("unavailable",)),
        notify=Notify.DECISION,
        text=(
            "GuardDog runs without its own kernel sandbox, because the kernel offers "
            "none here."
        ),
        cell="GuardDog has no kernel sandbox",
        paths=("enable-landlock",),
        cli=True,
    ),
    _polyfilled(
        "scanner.betterleaks.private-home",
        scope="betterleaks",
        dimension="sandbox",
        match=Match(
            os=("darwin",),
            sandbox_mode=("auto", "named"),
            sandbox_backend=("sandbox-exec",),
        ),
        notify=Notify.DECISION,
        reason=(
            "Betterleaks runs with a private home directory, which stands in for the "
            "cache directory that sandbox-exec denies."
        ),
        cell="Betterleaks private home directory",
        polyfill="betterleaks-private-home",
    ),
    *(
        _degraded(
            f"scanner.{tool}.windows-ignore-paths",
            scope=tool,
            dimension="ignore paths",
            match=Match(
                os=("windows",),
                run_mode=("local", "precommit"),
                ignore_paths=("set",),
            ),
            notify=Notify.DECISION,
            text=(
                f"ASH's ignore paths are not passed to {tool} on Windows, so it reads "
                "files you ignored; ASH still suppresses their findings."
            ),
            cell=f"{tool} reads ASH-ignored files on Windows",
            paths=("wsl2", "container-image"),
            docs_anchor="scanner-windows-ignore-paths",
        )
        for tool in _IGNORE_PATHS_TOOLS
    ),
    _degraded(
        "scanner.snyk-code.windows-leftovers",
        scope="snyk-code",
        dimension="os",
        match=_WINDOWS_LOCAL,
        notify=Notify.MATRIX,
        text=(
            "Copies of the scan input that a run leaves behind are not swept on "
            "Windows."
        ),
        cell="scan input copies not swept on Windows",
        paths=("wsl2", "container-image"),
    ),
)

_ADAPTATION_ROWS: tuple[SupportRow, ...] = tuple(
    SupportRow(
        id=f"host.adaptation.{adaptation.id}",
        scope="ash",
        dimension="os",
        match=Match(os=(_ADAPTATION_OS[adaptation.id],)),
        level=SupportLevel.SUPPORTED,
        behavior=Behavior.CONTINUES,
        notify=Notify.MATRIX,
        reason=adaptation.stands_in_for,
        cell=adaptation.cell,
        polyfill=adaptation.id,
        docs_anchor=ADAPTATIONS_ANCHOR,
    )
    for adaptation in _ADAPTATIONS
)

#: The register ASH ships: the ASH-scope rows, the scanner-scope rows that need no
#: scanner to be read, the adaptations, and what they share.
REGISTER = Register(
    polyfills=_STAND_INS + _ADAPTATIONS,
    paths=_PATHS,
    profiles=_PROFILES,
    rows=_ASH_ROWS + _SCANNER_ROWS + _ADAPTATION_ROWS,
    not_declared=NOT_DECLARED,
)

# ---------------------------------------------------------------------------
# Rows derived from a scanner's own declaration
# ---------------------------------------------------------------------------

#: Every operating system and architecture pair ASH downloads pinned tools for, in the
#: order ``PlatformsFacet.provisionable`` states them.
ALL_PLATFORMS: tuple[str, ...] = (
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm64",
    "windows/amd64",
    "windows/arm64",
)


@dataclass(frozen=True)
class PinnedBinary:
    """A scanner whose tool ASH downloads, and the platforms it has a build for."""

    scanner: str
    tool: str
    version: str
    provisionable: tuple[str, ...]


def no_build_rows(binaries: Iterable[PinnedBinary]) -> tuple[SupportRow, ...]:
    """One row for each platform a pinned tool has no build for.

    A tool ASH does not download, and a tool with every build, give no rows. The rows
    are unsupported and raised at the decision, where a missing tool is graded, so a
    copy the user put on the path raises nothing. They are derived from the scanner's
    declaration so the same fact is never typed twice.
    """
    rows: list[SupportRow] = []
    for binary in binaries:
        if not binary.provisionable:
            continue
        for pair in ALL_PLATFORMS:
            if pair in binary.provisionable:
                continue
            os_token, _, arch = pair.partition("/")
            cell = f"no {binary.tool} build for {pair}"
            rows.append(
                SupportRow(
                    id=f"scanner.{binary.scanner}.{_NO_BUILD}.{os_token}-{arch}",
                    scope=binary.scanner,
                    dimension="platform",
                    match=Match(os=(os_token,), arch=(arch,)),
                    level=SupportLevel.UNSUPPORTED,
                    behavior=Behavior.SCANNER_MISSING,
                    notify=Notify.DECISION,
                    reason=f"ASH has no {binary.tool} {binary.version} build for {pair}.",
                    cell=cell if len(cell) <= CELL_LIMIT else f"no build for {pair}",
                    paths=_HERE_PATHS,
                    docs_anchor=NO_BUILD_ANCHOR,
                )
            )
    return tuple(rows)


# ---------------------------------------------------------------------------
# The module-level entry points, which read the register ASH ships
# ---------------------------------------------------------------------------


def evaluate(
    facts: HostFacts,
    scope: str = "ash",
    *,
    notify: Notify | Iterable[Notify] | None = None,
    include_supported: bool = False,
) -> tuple[Evaluation, ...]:
    """The rows of ``scope`` that match ``facts``, worst first (``Register.evaluate``)."""
    return REGISTER.evaluate(
        facts, scope, notify=notify, include_supported=include_supported
    )


def cells(
    scope: str, overlay: Mapping[str, str], register: Register | None = None
) -> str:
    """One cell of a support matrix for ``scope`` (``Register.cells``)."""
    return (REGISTER if register is None else register).cells(scope, overlay)


def refusal(scanner: str, os: str) -> str | None:
    """The reason ``scanner`` is skipped on ``os``, or None (``Register.refusal``)."""
    return REGISTER.refusal(scanner, os)
