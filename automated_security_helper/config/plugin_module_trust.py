# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``ash_plugin_modules`` entries a config file in the scanned tree or any
git checkout may add.

ASH imports every module ``ash_plugin_modules`` names into its own process. When the
config was built from a file inside the scanned tree or any git checkout
(``config/sandbox_grants.py`` decides that), the entries it adds beyond the trusted
list (the defaults, an operator config outside the tree, and ``--config-overrides``)
are kept only if they name an installed module: one that ``importlib.util.find_spec``
locates outside the scanned tree and outside every git checkout (a virtualenv inside
a checkout counts as inside it). An entry that is not importable, or whose spec
points into the tree or a checkout, is dropped with one warning naming
``ash_plugin_modules``. An entry
outside the plugin namespace is kept, unimported, so the scan refuses it with exit
code 3 (``plugins.loader.refuse_plugin_modules_outside_namespace``) as it would from
any other config source.

Packages named this way keep working, which is what ASH's own
``.ash/.ash_community_plugins.yaml`` relies on: its entries live in the installed
``automated_security_helper`` package. A module inside the directory the running
``automated_security_helper`` package was imported from is ASH's own code and is
kept even when that directory is in the tree, as it is for an editable install of
the repository being scanned; that code is already running.

The exception is ASH's own packages in ``OFF_HOST_PLUGIN_PACKAGES``, which send
data to a remote service with the operator's credentials: ``ash_aws_plugins``'
reporters send findings, from the ASH process and outside the scanner sandbox, and
``ash_snyk_plugins``' scanner sends the scanned source to Snyk with the operator's
Snyk token. Their plugins are enabled by default, so naming the package is enough
to send the data. An in-tree file's entry naming one of them, or a module inside
one, is kept only when the trusted list names it or its package.

Each level of a dotted name is located without importing its parent packages
(``_spec_without_importing``), so checking a name runs no code.
``--ash-plugin-modules`` and ``ASH_PLUGIN_MODULES`` are the operator's and are not
filtered here.

``ash merge`` holds the config a shard recorded in its results to these rules with
``UntrustedSource.named_modules_only`` (``config/untrusted_source.py``): the
merge loads the trusted list, the modules its ``--config`` and
``--config-overrides`` name, whether or not a shard recorded them, and an entry
only the shard names is dropped whether or not it is installed, because nothing
the merge imports is a shard's choice. Every class the merge then loads comes
from a module the operator named, so it does not call
``drop_untrusted_off_host_plugins``.

The name check alone does not cover another installed package that imports one
of those classes and lists it in its own ``ASH_SCANNERS``, ``ASH_REPORTERS`` or
``ASH_CONVERTERS``: the entry names that package, and importing it registers the
class. So ``resolve_config`` also records the trusted list on the config
(``AshConfig._trusted_plugin_modules``), and ``drop_untrusted_off_host_plugins``,
which ``ScanExecutionEngine`` and ``ash report`` call once the plugin modules are
loaded, drops each selected class whose defining module (``cls.__module__``) is
inside an off-host package, unless a trusted entry or ``--ash-plugin-modules``
names that module or a package around it, or names a module that lists the
class. A class another package defines as a subclass of one of those classes
sends what its base sends, so the check walks ``cls.__mro__``: such a class is
also kept when a trusted entry names the base's module or a package around it.
One warning names each dropped class and its package. A config with no
trusted list recorded is built only from the operator's files, so its own
``ash_plugin_modules`` are the trusted entries. The check runs for every config,
because a scan is offered every class registered in the process so far: under
the MCP server, those an earlier scan's config loaded as well. The off-host
packages declare no ``ASH_EVENT_HANDLERS``
(tests/unit/config/test_off_host_plugin_modules_from_repo_config.py derives what
they send from their reporters, handlers and scanners), so only classes are
checked.

That process-wide registry holds every other package an earlier scan's
untrusted config loaded as well. ``plugin_modules_by_trust`` splits the modules
a scan loads into the operator's and the rest; the engine imports the rest
inside ``ash_plugin_manager.untrusted_import``, and
``AshPluginManager.plugins_loaded_by`` leaves the classes those imports
registered out of a later scan that loads neither the module nor any module the
operator named.
"""

from __future__ import annotations

import importlib.util
import pkgutil
import sys
from dataclasses import replace
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.config.path_trust import (
    scanned_tree_judgment,
    scanned_tree_reason,
)
from automated_security_helper.config.sandbox_grants import (
    checkout_judgment,
    confinement_membership,
    described,
    is_within,
    joined_membership,
    membership_clause,
)
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.terminal_text import shown_on_one_line

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.sandbox_grants import WalkJudgment
    from automated_security_helper.plugins.loader import PluginModuleError


class PluginModuleReferenceError(RuntimeError):
    """The ``ash_plugin_modules`` reference bookkeeping does not describe the list.

    Raised by the index-remap mover when a reference names an entry past the
    ones its caller described. That is a caller bug, not an invalid
    configuration, so it is not a ``ValueError``: every config-validation
    error is one, and a handler reporting an invalid configuration must not
    catch a programming error. ``drop_plugin_module_references_past_the_list``
    is how the load keeps the production callers from meeting it.
    """


#: ASH's plugin packages that send findings or source off the host, with what each
#: sends, as the warning names it. Derived from the packages' reporters, event
#: handlers and scanners by
#: tests/unit/config/test_off_host_plugin_modules_from_repo_config.py.
OFF_HOST_PLUGIN_SENDS: Dict[str, str] = {
    "automated_security_helper.plugin_modules.ash_aws_plugins": (
        "its reporters send findings off the host"
    ),
    "automated_security_helper.plugin_modules.ash_snyk_plugins": (
        "its scanner sends the scanned source off the host"
    ),
}
OFF_HOST_PLUGIN_PACKAGES: Tuple[str, ...] = tuple(OFF_HOST_PLUGIN_SENDS)


def off_host_package(name: str) -> Optional[str]:
    """The package of ``OFF_HOST_PLUGIN_PACKAGES`` that ``name`` is or is inside, or None.

    Compared without regard to case: an import on a case-insensitive file system
    with ``PYTHONCASEOK`` set loads the package's files under a differently
    cased module name, and that name is still the off-host package.
    """
    folded = name.casefold()
    for package in OFF_HOST_PLUGIN_PACKAGES:
        lowered = package.casefold()
        if folded == lowered or folded.startswith(lowered + "."):
            return package
    return None


def split_plugin_modules(entries: object) -> List[str]:
    """Entries split on commas and stripped, the way ScanExecutionEngine reads them.

    A value that is not a list, which a raw document a client delivered can hold
    (``ash_plugin_modules: 5``, or a bare string), is read as one entry, so a
    check on the document reports the module it names instead of raising.
    """
    items: Iterable[object]
    if entries is None:
        items = ()
    elif isinstance(entries, (list, tuple, set, frozenset)):
        items = entries
    else:
        items = (entries,)
    names: List[str] = []
    for entry in items:
        if entry is None:
            continue
        for part in str(entry).split(","):
            part = part.strip()
            if part and part not in names:
                names.append(part)
    return names


def environment_plugin_modules() -> List[str]:
    """``ASH_PLUGIN_MODULES``'s entries, read as the scan's own option reads it.

    The variable is the scan option's envvar, so it is a scan input: a check
    surface that ignores it judges a different configuration than the one a
    scan of the same directory runs with. Split on whitespace, as the option's
    environment handling splits a list-valued variable, with commas inside
    each piece left to :func:`split_plugin_modules`, where the scan splits
    them. For the CLI config commands: a run that is not started through the
    CLI's scan option does not read the variable, so neither do its checks.
    """
    import os

    value = os.environ.get("ASH_PLUGIN_MODULES")
    return value.split() if value else []


def environment_only_plugin_modules(
    additional: object, config_modules: object
) -> FrozenSet[str]:
    """The entries only ``ASH_PLUGIN_MODULES`` contributed to a scan.

    ``additional`` is the scan's own option list (``--ash-plugin-modules``,
    which the variable feeds as its envvar); ``config_modules`` is every entry
    the configs name. An entry counts only when the variable names it, the
    option list carries it, and no config names it: unsetting the variable
    fixes nothing for any other entry. Naming the option list as well keeps a
    ``--ash-plugin-modules`` that overrode the variable from being blamed on
    it. Named limit: an entry given on the command line AND present in the
    variable is still counted.
    """
    return (
        frozenset(split_plugin_modules(environment_plugin_modules()))
        & frozenset(split_plugin_modules(additional))
    ) - frozenset(split_plugin_modules(config_modules))


def shown_module_names(entries: object, shown: object) -> Dict[str, str]:
    """How a message names each module ``split_plugin_modules(entries)`` gives.

    ``shown`` is ``entries`` as ``environment_record.with_environment_values_shown``
    returns it. Every module of an entry read from the environment is shown as
    that placeholder, whichever piece of the entry it is: the split can cut one
    value into several names, and none of them is in the file. A module the file
    wrote is shown as it is.
    """
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    def as_list(value: object) -> List[object]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set, frozenset)):
            return list(value)
        return [value]

    read = as_list(entries)
    written = as_list(shown)
    if len(written) != len(read):
        # Not the copy of these entries: show none of them.
        written = [ENVIRONMENT_VALUE_SHOWN] * len(read)
    names: Dict[str, str] = {}
    for entry, shown_entry in zip(read, written):
        from_environment = shown_entry != entry
        for name in split_plugin_modules([entry]):
            if from_environment:
                names[name] = ENVIRONMENT_VALUE_SHOWN
            else:
                names.setdefault(name, name)
    return names


def merged_module_names(*maps: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """One naming of a run's plugin modules from several ``shown_module_names``.

    For a run whose modules come from more than one config, a workspace's
    projects above all. The masked form wins per name, whatever the order of the
    maps: one config having read a name from the environment is enough to make
    printing it a leak, and a later map's literal spelling of the same name must
    not overwrite the mask.
    """
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    merged: Dict[str, str] = {}
    for names in maps:
        for name, label in (names or {}).items():
            if merged.get(name) != ENVIRONMENT_VALUE_SHOWN:
                merged[name] = label
    return merged


def config_module_names(config: "AshConfig") -> Dict[str, str]:
    """``shown_module_names`` for ``config.ash_plugin_modules``, by what the
    config's files read from the environment (``AshConfig._environment_references``,
    which ``resolve_config`` sets). A config built without them names every
    module as it is."""
    from automated_security_helper.config.environment_record import (
        with_environment_values_shown,
    )

    entries = list(getattr(config, "ash_plugin_modules", None) or [])
    references = getattr(config, "_environment_references", None) or ()
    shown = with_environment_values_shown({"ash_plugin_modules": entries}, references)
    return shown_module_names(entries, shown.get("ash_plugin_modules"))


def _own_package_dir() -> Optional[Path]:
    import automated_security_helper

    origin = getattr(automated_security_helper, "__file__", None)
    return Path(origin).resolve().parent if origin else None


def _location_is_own(location: Path, own: Path, *, as_named: bool) -> bool:
    """Whether a module *location* sits inside ASH's own package directory *own*.

    The one place the own-module test is written, so the two callers cannot
    drift in what they call a location of the package. It always asks where
    the location resolves (``is_within``). With ``as_named`` it also asks
    whether the location sits there under the name its entry gave, which a link
    the scanned repository placed does not: such a link resolves into the
    package but is named in the repository. That holds for a link to a
    subdirectory and for a link to the package directory itself.

    ``refusal_reason`` passes ``as_named=True``: its exemption is for code the
    entry reaches as the installed package, never for a repository's link to
    it. ``_is_ash_own_module`` passes ``as_named=False``: it runs only where no
    tree is known (the fail-closed client refusal), keeps the resolved-only
    test it has always used, and so behaves as before.
    """
    if not is_within(location, own):
        return False
    if not as_named:
        return True
    from automated_security_helper.config.sandbox_grants import _as_named

    # The closest unresolved parent that is the package directory decides, and
    # it must be the directory itself. ``_named_within`` answers "is the package
    # one of the location's parents", which a link to the whole package
    # directory also satisfies (the check follows links), so an alias placed in
    # a repository would read as the package. An exemption has to fail the other
    # way: a link standing for the package is not the package.
    named = _as_named(location)
    for candidate in (named, *named.parents):
        try:
            if candidate.samefile(own):
                return not candidate.is_symlink()
        except OSError:
            continue
    return False


def _spec_locations(spec: ModuleSpec) -> List[Path]:
    locations: List[Path] = []
    for entry in spec.submodule_search_locations or []:
        location = Path(entry)
        # A relative entry that names nothing on disk is a path hook's marker
        # string (an editable install's finder uses one), not a place a module
        # file lives; judged as a path it would be read against the working
        # directory.
        if not location.is_absolute() and not location.exists():
            continue
        locations.append(location)
    if spec.has_location and spec.origin:
        locations.append(Path(spec.origin))
    return locations


def _spec_without_importing(
    name: str, parent: Optional[ModuleSpec]
) -> Optional[ModuleSpec]:
    """The spec for ``name``, found without running any package's ``__init__``.

    A top-level name, or one whose parent is already imported, goes through
    ``importlib.util.find_spec``, which then imports nothing; a child of an
    imported parent that is a plain module, not a package, has no spec. Otherwise the
    parent's spec gives the directories to search, and :func:`_find_spec_in` looks there
    directly. A package that adds to its ``__path__`` when imported, or a submodule
    only a custom finder can see, is then reported as not importable, which
    refuses it.
    """
    parent_name = name.rpartition(".")[0]
    if (
        parent_name in sys.modules
        and name not in sys.modules
        and not hasattr(sys.modules[parent_name], "__path__")
    ):
        # An imported parent that is a plain module has no ``__path__``, so
        # ``find_spec`` would raise for the child. Answer as the not-yet-imported
        # plain parent below does, so a name is judged the same whether or not
        # the process has imported its parent.
        return None
    if not parent_name or parent_name in sys.modules:
        return importlib.util.find_spec(name)
    if parent is None or not parent.submodule_search_locations:
        return None
    return _find_spec_in(name, list(parent.submodule_search_locations))


def _find_spec_in(name: str, locations: Sequence[str]) -> Optional[ModuleSpec]:
    """The spec for ``name`` in ``locations``, the way ``PathFinder`` finds it.

    The first location holding a module or a regular package wins. A directory with
    no ``__init__`` in any of them makes ``name`` a namespace package, returned as a
    spec with no origin and those directories as its search locations.
    ``PathFinder.find_spec`` builds such a spec's search path from the parent
    package's ``__path__``, so it fails when the parent is not imported, which is
    the case here.
    """
    portions: List[str] = []
    for location in locations:
        finder = pkgutil.get_importer(location)
        find_spec = getattr(finder, "find_spec", None)
        if find_spec is None:
            continue
        spec = find_spec(name)
        if spec is None:
            continue
        if spec.loader is not None:
            return spec
        portions.extend(spec.submodule_search_locations or ())
    if not portions:
        return None
    spec = ModuleSpec(name, None, is_package=True)
    spec.submodule_search_locations = portions
    return spec


def _is_ash_own_module(name: str) -> bool:
    """Whether every location of *name*'s spec chain sits inside the running
    ``automated_security_helper`` package.

    Such a module is ASH's own code, which is already running, so even the
    fail-closed client refusal keeps it -- the exemption the module docstring
    states, located the way ``refusal_reason`` locates specs (importing
    nothing). An unimportable name, one with any location outside the
    package, and one whose spec has no location at some level (a built-in or
    frozen module, or one a finder serves without a file) is not ASH's own.
    """
    own = _own_package_dir()
    if own is None:
        return False
    parts = name.split(".")
    spec: Optional[ModuleSpec] = None
    for depth in range(1, len(parts) + 1):
        prefix = ".".join(parts[:depth])
        try:
            spec = _spec_without_importing(prefix, spec)
        except Exception:  # noqa: BLE001 -- a finder that fails has not located it
            spec = None
        if spec is None:
            return False
        locations = _spec_locations(spec)
        if not locations or not all(
            _location_is_own(location, own, as_named=False) for location in locations
        ):
            return False
    return True


def _judged_against_trees(
    location: Path, scanned_root: Optional[Path], also_scanned: Sequence[Path]
) -> "WalkJudgment":
    """``scanned_tree_judgment`` of ``location`` against the scan root and every
    ``also_scanned`` root, the first True verdict winning (an undecided True is
    kept only when no root decides it)."""
    judgment = scanned_tree_judgment(location, scanned_root)
    if judgment.verdict and judgment.decided:
        return judgment
    for extra in also_scanned:
        other = scanned_tree_judgment(location, extra)
        if other.verdict and other.decided:
            return other
        if other.verdict and not judgment.verdict:
            judgment = other
    return judgment


def refusal_reason(
    name: str,
    scanned_root: Optional[Path],
    any_checkout: bool = False,
    root_judged: bool = False,
    also_scanned: Sequence[Path] = (),
) -> Optional[str]:
    """Why ``name`` may not be imported for a config in the scanned tree, or None.

    Imports nothing that is not already imported, so a refused name runs no code.
    A None ``scanned_root`` (no scanned tree) leaves the membership test its
    client-supplied arm only, as ``in_scanned_tree`` reads it, unless
    ``any_checkout`` adds the fail-closed arm: a location inside ANY checkout is
    then the scanned party's, the membership resolve_config's chain reads use
    when the working directory is gone and no tree says whose checkout is whose.
    ``root_judged`` changes only the wording, never the judgment: the caller
    passes it for every no-scanned-tree load with a root given, where the
    modules are judged against that root wherever the config files sit, so
    the reason says the given root's trees instead of "the scanned tree",
    which such a load declared it does not have. For a scan of a tree (a root,
    neither ``root_judged`` nor ``any_checkout``), a location inside any other
    checkout is refused too, with the reason ``scanned_tree_reason`` gives.
    ``also_scanned`` are the other roots whose trees the load counts as
    scanned (``resolve_config``'s ``also_scanned``, the results' repository
    for ``ash report``); a location inside one of their trees is refused as a
    location inside the scan root's is.

    ASH's own package is exempt: code inside the running package is already
    running. The exemption holds for a location that sits inside the package
    AS NAMED (``_named_within``), not merely one that resolves there: an entry
    whose spec sits in the scanned tree and reaches the installed package
    through a link the repository placed is judged by where it sits, under the
    module name the tree gave it.
    """
    # The scan's loader drops the import system's caches before it imports
    # (plugins.loader), so a long-lived process (the MCP server) finds a module
    # installed since the process started. This lookup does the same, or it
    # would refuse a module the scan then imports.
    importlib.invalidate_caches()
    own = _own_package_dir()
    parts = name.split(".")
    spec: Optional[ModuleSpec] = None
    for depth in range(1, len(parts) + 1):
        prefix = ".".join(parts[:depth])
        try:
            spec = _spec_without_importing(prefix, spec)
        except Exception:  # noqa: BLE001 -- a finder that fails has not located it
            spec = None
        if spec is None:
            return "it is not importable from the installed environment"
        locations = _spec_locations(spec)
        if not locations:
            # Nothing to judge: a module with no file location (built in,
            # frozen, or served by a finder) cannot be shown to sit outside
            # the scanned tree, so it is refused rather than kept unjudged.
            return (
                "it has no file location to check, and a module that cannot "
                "be placed is refused"
            )
        for location in locations:
            if own is not None and _location_is_own(location, own, as_named=True):
                continue
            tree_judgment = _judged_against_trees(location, scanned_root, also_scanned)
            if tree_judgment.verdict:
                if not tree_judgment.decided:
                    # The fail-closed answer of a walk that never finished:
                    # the reason says so instead of claiming a location. A
                    # rootless load passes no trees to the walk, so it
                    # speaks the checkout, never a tree it does not have.
                    if any_checkout:
                        return (
                            "whether it resolves inside a checkout could not be "
                            "decided (the walk of its location stopped before "
                            "the end), and an undecided location is refused"
                        )
                    where = (
                        "the given root's trees" if root_judged else "the scanned tree"
                    )
                    return (
                        f"whether it resolves inside {where} could not be "
                        "decided (the walk of its location stopped before "
                        "the end), and an undecided location is refused"
                    )
                if tree_judgment.client_delivered:
                    # True here came from the client-supplied arm: the location
                    # sits in no tree the walk found, so no tree is named.
                    return "it is a file an MCP client delivered"
                if root_judged:
                    return "it resolves inside the given root's trees"
                if any_checkout:
                    # No root at all: the decision came from a mark the host set
                    # or from a file a client delivered, and the load declared
                    # it has no scanned tree to name.
                    return "it resolves inside a tree the scanned party controls"
                return "it resolves inside the scanned tree"
            if any_checkout:
                judgment = checkout_judgment(location)
                if judgment.verdict and not judgment.decided:
                    return (
                        "whether it resolves inside a checkout could not be "
                        "decided (the walk of its location stopped before "
                        "the end), and an undecided location is refused"
                    )
                if judgment.verdict:
                    if root_judged:
                        return (
                            "it resolves inside a checkout, and with no scanned "
                            "tree every checkout is read as the repository's"
                        )
                    return (
                        "it resolves inside a checkout, and with no working "
                        "directory every checkout is read as the scanned tree"
                    )
            elif scanned_root is not None and not root_judged:
                # A scan of a tree: a module installed in ANY checkout is the
                # scanned party's too, the rule a config file and a tool config
                # path are held to (sandbox_grants.untrusted_reason). A load
                # judged against a given root keeps the plain tree judgment
                # above, and a load with no root keeps its own arm.
                why = scanned_tree_reason(location, scanned_root)
                if why is not None:
                    return f"it is at {location.as_posix()}, and {why}"
    return None


def _refuse_wording_flags_that_contradict_the_judgment(
    *,
    rootless: bool,
    checkout_membership: bool,
    mixed_membership: bool,
    given_root_membership: bool,
    undecided_membership: bool,
) -> None:
    """Raise TypeError for wording flags the no-tree judgment contradicts.

    A TypeError, like the keyword-only guard on ``confine_plugin_modules``'s
    signature: the flags are a bad argument combination, which only a caller
    bug produces. Not a ValueError, because every config-validation error is
    one and a handler reporting an invalid configuration must not catch a
    programming error (``PluginModuleReferenceError``'s rationale).

    - A rootless load (no root at all) judges by the any-checkout rule, so a
      caller that states no membership for it (neither the checkout one, the
      mixed one, nor known trees) would get the scanned-tree head beside the
      every-checkout tail.
    - A load that gives a root judges against that root, so the sentence has
      to speak the given root: the given-root flag, or the undecided one,
      whose head claims no location. Without them the head claims a
      location that is not the given root (the scanned tree; for the
      checkout flag alone, a checkout "with no working directory"; for the
      mixed flag alone, the rootless mixed reading) beside the given-root
      tail.

    resolve_config states a consistent set for every load it builds, so only
    a direct caller meets this.
    """
    if rootless:
        if not (
            checkout_membership
            or mixed_membership
            or given_root_membership
            or undecided_membership
        ):
            raise TypeError(
                "confine_plugin_modules was given wording flags that state no "
                "membership for a rootless load: the load has no root, so it "
                "judges by the any-checkout rule, and the scanned-tree "
                "sentence its flags would give claims a tree the load "
                "declared it does not have"
            )
    elif not (given_root_membership or undecided_membership):
        # The undecided head claims no location at all, so it cannot
        # contradict the given-root judgment either.
        raise TypeError(
            "confine_plugin_modules was given wording flags that do not "
            "speak the given root for a load with a given root: the load "
            "judges against that root, so the sentence its flags would give "
            "contradicts the judgment it explains"
        )


def confine_plugin_modules(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    scanned_root: Optional[Path],
    in_tree: Sequence[Path],
    environment_paths: Collection[Path] = frozenset(),
    # Keyword-only below: these are judgment and wording flags, and
    # checkout_membership was inserted before untrusted, so a positional
    # call written against the older signature must fail with a TypeError
    # instead of silently setting the wrong flag
    # (confinement_membership's guard).
    *,
    no_scanned_tree: bool = False,
    # The four wording flags carry no defaults: a default is a guess about
    # the caller's membership, and the rootless guess was wrong (a scanned
    # tree claimed on a load that declared none). Every caller states them,
    # so the sandbox, settle and module warnings are fed the same values.
    checkout_membership: bool,
    untrusted: bool = False,
    mixed_membership: bool,
    given_root_membership: bool,
    undecided_membership: bool,
    outside_membership: bool = False,
    source: Optional[UntrustedSource] = None,
    also_scanned: Sequence[Path] = (),
) -> None:
    """Drop the entries of ``config.ash_plugin_modules`` an in-tree file may not add.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under
            ``ash_plugin_modules`` are replayed onto ``trusted_config`` to get the
            trusted list, the same way the sandbox overrides are.
        scanned_root: The scan root; the trees it is checked against are
            ``path_trust.in_scanned_tree``'s.
        also_scanned: Other roots whose trees the load counts as scanned
            (``resolve_config``'s ``also_scanned``: the results' repository for
            ``ash report``). A module location inside one of their trees is
            refused as one inside the scan root's trees is.
        in_tree: The config files inside the tree, named in the warning.
        environment_paths: Those of them the environment chose, named
            ``<value>`` (``sandbox_grants.described``).
        no_scanned_tree: The caller knows no tree is scanned. With no
            ``scanned_root`` either, the membership test adds the any-checkout
            arm (``refusal_reason``), the fail-closed rule the rest of the
            no-tree load already uses. A caller that still GIVES a root (the
            MCP get_config construction passes the delivered file's own
            confinement root with ``no_scanned_tree``) keeps the plain tree
            judgment: a scan of that delivered source judges modules against
            that tree, and nothing else.
        checkout_membership: Whether the warned files are in a checkout by
            the ANY-CHECKOUT rule (the caller computed it where ``in_tree``
            was built): the rule added them, or the load has no tree at all
            and every file it confines is there by the host's mark, which
            is the host's checkout verdict (``in_a_checkout``). The
            membership sentence and the per-entry reason follow it, so a
            file ``files_inside`` added -- a plain non-checkout root is its
            own tree -- is never said to be in a checkout. The JUDGMENT
            never follows it. Used as stated, like the sandbox and settle
            warnings use it.
        given_root_membership: The no-tree load's trees are known (a root
            given, or ``also_scanned``'s), so the wording never claims a
            scanned tree the load declared it does not have. Used as
            stated: a load that gives a root must state it (or the mixed
            flag), and a rootless load must state some membership, or the
            call is refused (TypeError), because the sentence the flags
            would give contradicts the judgment. Wording only, like
            ``checkout_membership``: the judgment stays on ``scanned_root``
            and ``no_scanned_tree``.
        undecided_membership: Some of *in_tree* are there only because
            resolving their name stopped before the walk finished
            (``confined_files``'s or ``checkout_judgment``'s undecided
            answer), so the membership half says the walk stopped
            (``membership_clause``) instead of stating a location it never
            established. Wording only; the judgment is unchanged.
        outside_membership: Some of *in_tree* sit in a git checkout other
            than the scanned tree, on a load that has a scanned tree, or an
            MCP client delivered them (``resolve_config``'s outside files),
            so the membership half names every membership
            (``membership_clause``). Wording only; the judgment is unchanged.
        untrusted: The config is client-supplied content. With no root at all
            there is nothing to judge an entry's location against -- an
            installed module's checkout could be the very one the missing
            working directory would have named -- so every entry outside the
            trusted list refuses the load, naming the missing working
            directory, instead of a judged drop. With a root given, the
            entries are judged against it like a scan's.
        source: Why those files are not the operator's, and the fix, for the
            warning's closing sentence (``untrusted_source.UntrustedSource``,
            ``modules_remedy``). With ``named_modules_only`` (``ash merge``),
            the list becomes the trusted list: an entry it does not name is
            dropped as well, and one it names is added whether or not the
            config named it. None keeps the in-tree remedy.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )
    from automated_security_helper.plugins.loader import _is_allowed_module_path

    module_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        == "ash_plugin_modules"
    ]
    if module_overrides:
        trusted_config = apply_config_overrides(trusted_config, module_overrides)
    trusted_list = split_plugin_modules(trusted_config.ash_plugin_modules)
    trusted_names = set(trusted_list)
    config._trusted_plugin_modules = tuple(sorted(trusted_names))
    named_modules_only = source is not None and source.named_modules_only
    # The warning names each module by its place: one an entry read from the
    # environment is `<value>`, every piece of a split entry alike.
    shown = config_module_names(config)
    # The fail-closed arms apply only with no root AT ALL: a caller that gives
    # a root while declaring no scanned tree (MCP get_config's construction)
    # wants modules judged against that root, as a scan of it would.
    rootless = no_scanned_tree and scanned_root is None
    # Both wording flags are used as stated, never derived here: the rootless
    # checkout rule and the given-root rule are applied by the caller, where
    # the flags are computed (resolve_config), so the sandbox, settle and
    # module warnings all speak the same values. Deriving one in this voice
    # alone overrode a caller's stated flag here while the other voices
    # honored it. What this voice can see, and the others cannot, is the
    # judgment: a pair of flags the judgment contradicts would give a
    # sentence that claims a tree the load declared it does not have, so
    # those are refused instead of patched. The check is eager: it runs on
    # every call, so an inconsistent set fails on the first call that states
    # it, in a test, and not on the first call that refuses a real module.
    if no_scanned_tree and not untrusted:
        _refuse_wording_flags_that_contradict_the_judgment(
            rootless=rootless,
            checkout_membership=checkout_membership,
            mixed_membership=mixed_membership,
            given_root_membership=given_root_membership,
            undecided_membership=undecided_membership,
        )
    # The per-entry reason's wording follows the load's known trees, not where
    # the config file sits: with no scanned tree and known trees (a root
    # given, or also_scanned's), the reason never claims a scanned tree the
    # load declared it does not have. Loop-invariant -- no entry changes it,
    # so it is computed once, not per name.
    root_judged = no_scanned_tree and (not rootless or given_root_membership)
    if untrusted and rootless:
        # ASH's own modules keep the module docstring's exemption even here:
        # code inside the running package is already running, so refusing it
        # protects nothing, and the defaults name such modules routinely.
        # The off-host packages are ASH's own modules too, but the own-module
        # exemption never covers them: a client's config may not add a package
        # that sends findings off the host unless the trusted list names it,
        # the same exception the judged path applies below. A name outside the
        # plugin namespace is refused without being located: locating it asks
        # every meta-path finder about a name the scan never imports.
        outside = [
            f"'{shown.get(name, name)}'"
            for name in split_plugin_modules(getattr(config, "ash_plugin_modules", []))
            if name not in trusted_names
            and (
                not _is_allowed_module_path(name)
                or not _is_ash_own_module(name)
                or off_host_package(name) is not None
            )
        ]
        if outside:
            from automated_security_helper.core.exceptions import (
                ASHConfigSourceError,
            )

            # Raw text, not shown_on_one_line: a raise site carries the raw
            # message and the one surface that prints an ASHConfigSourceError
            # escapes it exactly once. Wrapping here would escape twice,
            # which shows only when a name carries a literal backslash run
            # (that run would print doubled); for other names the double
            # escape is invisible, so the one-pass rule is about keeping
            # every raise site uniform, not about every message changing.
            raise ASHConfigSourceError(
                f"ash_plugin_modules entries {', '.join(outside)} are "
                "refused: the working directory is gone, so a "
                "client-supplied config may name only the trusted list's "
                "modules. Restore a working directory, or name them with "
                "--ash-plugin-modules, --config-overrides or a config "
                "file of the operator's."
            )
        return
    original_entries = list(getattr(config, "ash_plugin_modules", []) or [])
    kept: List[str] = []
    refused: List[str] = []
    for name in split_plugin_modules(getattr(config, "ash_plugin_modules", [])):
        # Kept for the scan's namespace refusal, which imports nothing and
        # refuses the scan with exit 3.
        if not _is_allowed_module_path(name):
            kept.append(name)
            continue
        if name in trusted_names:
            kept.append(name)
            continue
        if named_modules_only:
            refused.append(
                f"'{shown.get(name, name)}' (the operator's configuration "
                "does not name it)"
            )
            continue
        package = off_host_package(name)
        if package is not None and package not in trusted_names:
            refused.append(
                f"'{shown.get(name, name)}' ({OFF_HOST_PLUGIN_SENDS[package]})"
            )
            continue
        reason = refusal_reason(
            name,
            scanned_root,
            any_checkout=rootless,
            root_judged=root_judged,
            also_scanned=also_scanned,
        )
        if reason is None:
            kept.append(name)
        else:
            refused.append(f"'{shown.get(name, name)}' ({reason})")
    # The operator's off-host plugin packages stay loaded whatever the config's
    # own list says: a config the operator did not write may not turn off the
    # operator's off-host reporters (config/reporter_trust.py), and a list that
    # leaves their package out would, since a reporter whose module is not
    # imported never runs. Their references come with them, so an entry the
    # operator's file read from the environment stays named as it wrote it.
    carried: List[str] = []
    if not named_modules_only:
        carried = [
            name
            for name in trusted_list
            if off_host_package(name) is not None and name not in kept
        ]
        if carried:
            kept.extend(carried)
            trusted_shown = config_module_names(trusted_config)
            ASH_LOGGER.warning(
                shown_on_one_line(
                    "Keeping the operator's off-host plugin modules "
                    f"{', '.join(repr(trusted_shown.get(name, name)) for name in carried)}, "
                    "which the configuration's own ash_plugin_modules leaves out: a "
                    "configuration the operator did not write may not turn off the "
                    "reporters that send findings off the host, and a list without "
                    "their package would."
                ),
                extra=NO_MARKUP,
            )
    if named_modules_only:
        # The merge loads the operator's modules, not the shards': the trusted
        # list, after any entry outside the namespace kept above for the refusal.
        # The list's references move with the kept entries before the list is
        # swapped, as in the drop path below.
        outside_names = [name for name in kept if not _is_allowed_module_path(name)]
        loaded = list(dict.fromkeys(outside_names + trusted_list))
        if loaded != split_plugin_modules(getattr(config, "ash_plugin_modules", [])):
            reindex_plugin_module_references(config, original_entries, loaded)
            config.ash_plugin_modules = loaded
        # The entries are now the operator's, so the record and the import
        # log name each as the operator's file wrote it: its references
        # come with them (_carry_trusted_module_references).
        _carry_trusted_module_references(config, trusted_config, loaded)
    if not refused and not carried:
        return
    if not named_modules_only:
        # The list's environment references move WITH the kept entries: a drop
        # shifts every later entry down, and a reference left at its old index is
        # matched there by the display's exact-index marking, so the entry after a
        # dropped one would be shown with the marker meant for its neighbor -- and
        # the environment-read entry itself shown in clear. The move runs BEFORE
        # the list is swapped: it checks every reference first and changes nothing
        # when it refuses, so a refusal leaves the list and the references as they
        # were instead of the new list beside the old indices.
        reindex_plugin_module_references(config, original_entries, kept)
        config.ash_plugin_modules = kept
        if carried:
            _carry_trusted_module_references(config, trusted_config, kept, only=carried)
    if not refused:
        return
    # The names and paths are the repository's: the whole message is shown, once
    # and on one line, and not read as markup. A repr of a name would write its
    # controls as escapes the sinks then showed again.
    # With no root at all, every checkout's file is read as the repository's
    # and modules inside ANY checkout are refused, so the scanned-tree wording
    # would contradict the drop it explains. Keyed on the same flag as the
    # judgment above (rootless): a caller that declares no scanned tree but
    # GIVES a root judges against that root. That caller's FILE can still be
    # a foreign checkout's, put under the confinement by the any-checkout
    # membership, so the middle arm says both halves -- claiming the file sits
    # inside the scanned tree would be false for it, and claiming an
    # any-checkout module judgment would be false too.
    # The judged half, built ONCE for every arm that speaks the given-root
    # judgment, so the copies cannot drift; each arm's membership half is its
    # own.
    judged_against_root = (
        "modules are judged against the given root, so only installed "
        "modules outside its trees are imported from it"
    )
    if untrusted:
        # One client-supplied file gets ONE voice: the sandbox and settle
        # warnings explain their drops by the client-supplied membership
        # (confinement_membership), and either location wording could be
        # false for an uploaded file, so the module line says the same
        # sentence; only the judgment tail is the module rule's own.
        judged = (
            judged_against_root
            if no_scanned_tree
            else (
                "only installed modules outside the scanned tree and every git "
                "checkout are imported from it"
            )
        )
        # checkout_membership stays False here: the client arm's sentence
        # names the client's content whatever the file's location, and
        # passing the checkout flag through would re-tie the wording flag to
        # a location the sentence deliberately does not claim.
        membership = (
            f"{confinement_membership(checkout_membership=False, client_supplied=True)}"
            f", and {judged}"
        )
    else:
        if source is not None and not source.located:
            # A config that is no file in a tree (ash merge's shard record):
            # the location clause would claim a place it has none of, so the
            # source's own reason is the head, as the sandbox step says it.
            head = source.reason
        else:
            # The location half is the shared clause, so this voice cannot
            # drift from the sandbox and settle warnings' location claims;
            # only the judgment tail is the module rule's own.
            head = membership_clause(
                checkout_membership=checkout_membership,
                mixed=mixed_membership,
                given_root=given_root_membership,
                undecided=undecided_membership,
                outside=outside_membership,
            )
        if named_modules_only:
            membership = joined_membership(
                head,
                "so only modules the operator's configuration names are "
                "imported from it",
            )
        elif rootless:
            # The judgment is the any-checkout rule's whether the load's
            # trees came from a root or from also_scanned; the head speaks
            # the trees when the load has them.
            membership = joined_membership(
                head,
                "so only installed modules outside every checkout are imported from it",
            )
        elif no_scanned_tree:
            membership = joined_membership(head, f"and {judged_against_root}")
        else:
            # A scan of a tree refuses a module installed in the tree or in any
            # other checkout (refusal_reason), so the clause says both.
            membership = joined_membership(
                head,
                "so only installed modules outside the scanned tree and every "
                "git checkout are imported from it",
            )
    remedy = (
        source.modules_remedy
        if source is not None
        # A file in another checkout is already outside the tree, so "a config
        # file outside the tree" is no way to name a module from it.
        else IN_TREE_OR_DELIVERED.modules_remedy
        if outside_membership
        else "Name other modules with --ash-plugin-modules, --config-overrides "
        "or a config file outside the tree."
    )
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"Ignoring ash_plugin_modules entries {', '.join(refused)} from "
            f"{described(in_tree, environment_paths)}: {membership}. {remedy}"
        ),
        extra=NO_MARKUP,
    )


def _carry_trusted_module_references(
    config: "AshConfig",
    trusted_config: "AshConfig",
    loaded: Sequence[str],
    *,
    only: Optional[Collection[str]] = None,
) -> None:
    """Carry the trusted base's ``ash_plugin_modules`` references onto ``config``.

    With ``named_modules_only`` the list becomes the trusted base's, and the
    merge imports and records those entries: one the operator's file read from
    the environment is named ``<value>`` in the import log
    (``config_module_names``) and written as the file wrote it in the merged
    results (``config_validator.record_of_config``), as a shard records its
    own. The references sit on the trusted config at the indices of ITS list,
    so each is moved to the index its name holds in ``loaded``, under the one
    rule ``reindex_plugin_module_references`` applies to its own list
    (``_remapped_module_reference_lists``): an entry of several comma-joined
    names gets one per kept piece, re-resolved to the piece; a name two trusted
    entries both hold is carried ONCE, from the first of them that a reference
    names (else the first of them), so the record never holds two rewrites at
    one index and a literal spelling before the read one does not swallow the
    read one's reference; and a trusted reference
    recorded at or past the end of the trusted list refuses the carry
    (PluginModuleReferenceError, ``config`` unchanged), as the reindex refuses
    it, because such a reference describes no entry and dropping or keeping it
    are the two harms that docstring names. The three lists move together.
    References into other config places are not the list's and stay where they
    are: ``cli/merge.py`` carries those at the write.

    ``only`` restricts the carry to the named pieces: the confinement carries
    the operator's off-host packages into a list the config itself wrote, and
    the config's own entries keep the references the load recorded for them.
    """
    entries = list(getattr(trusted_config, "ash_plugin_modules", None) or [])
    new_index = {
        name: i for i, name in enumerate(loaded) if only is None or name in only
    }
    sources = {
        attribute: tuple(
            reference
            for reference in (getattr(trusted_config, attribute, None) or ())
            if _names_a_plugin_module_entry(reference)
        )
        for attribute in _MODULE_REFERENCE_LISTS
    }
    referenced = {
        tuple(reference.path)[1]
        for references in sources.values()
        for reference in references
    }
    # The entry a duplicated name is carried from: the first entry a reference
    # names, else the first entry. The reindex keeps the first entry outright
    # because its references were recorded against that very list; here the
    # references are the trusted base's and a literal spelling may come first.
    owner: Dict[str, int] = {}
    pieces_of: Dict[int, List[str]] = {}
    respelled: Dict[int, bool] = {}
    for old, entry in enumerate(entries):
        pieces = split_plugin_modules([entry])
        pieces_of[old] = pieces
        respelled[old] = pieces != [entry]
        for piece in pieces:
            holder = owner.get(piece)
            if holder is None or (old in referenced and holder not in referenced):
                owner[piece] = old
    new_indices: Dict[int, List[int]] = {}
    for old, pieces in pieces_of.items():
        mine: List[int] = []
        for piece in dict.fromkeys(pieces):
            if owner[piece] == old and piece in new_index:
                mine.append(new_index[piece])
        new_indices[old] = mine
    carried = _remapped_module_reference_lists(
        sources,
        new_indices,
        lambda old, index: loaded[index] if respelled[old] else None,
        described_entries=len(entries),
    )
    for attribute, moved in carried.items():
        if not moved:
            continue
        held = getattr(config, attribute, None) or ()
        if attribute == "_written_references":
            setattr(config, attribute, [*held, *moved])
        else:
            setattr(config, attribute, (*tuple(held), *moved))


_MODULE_REFERENCE_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


def _names_a_plugin_module_entry(reference: Any) -> bool:
    """Whether ``reference`` points into the ``ash_plugin_modules`` list."""
    path = tuple(reference.path)
    return (
        len(path) >= 2 and path[0] == "ash_plugin_modules" and isinstance(path[1], int)
    )


def _referenced_module_entries(owner: Any) -> FrozenSet[int]:
    """The ``ash_plugin_modules`` indices that ``owner``'s reference lists name."""
    return frozenset(
        tuple(reference.path)[1]
        for attribute in _MODULE_REFERENCE_LISTS
        for reference in (getattr(owner, attribute, None) or ())
        if _names_a_plugin_module_entry(reference)
    )


def reindex_plugin_module_references(
    config: "AshConfig", entries: Sequence[str], kept: Sequence[str]
) -> None:
    """Re-point ``ash_plugin_modules`` environment references at the kept list.

    ``entries`` is the list as it stood when the references were recorded (an
    entry may hold several comma-joined names); ``kept`` is the judged list of
    NAMES the caller kept, in split order -- the confinement's drop, or any
    other caller that split, shortened or reordered the list itself.
    A reference recorded at an entry's old index is
    dropped with its entry, or moved to its kept name's new index; one
    recorded AT OR PAST ``len(entries)`` refuses the whole move
    (PluginModuleReferenceError, nothing changed), because neither mending
    is safe -- dropping its record
    rewrite leaves the environment-read value in the record in clear, while
    keeping it persists a stale rewrite that can later mark another entry's
    equal text (the asymmetry _remap_module_reference_lists' docstring
    states), and a past-end reference only exists when a caller passed a
    list the references were not recorded against (the load itself drops the
    references a shortening override leaves past the list:
    ``drop_plugin_module_references_past_the_list``). The one
    per-piece rule: an entry whose reference resolved to SEVERAL names gets a
    whole-piece reference on each kept name, so each is shown as the marker --
    over-marking a possibly literal fragment errs toward not disclosing an
    environment value, and such split references are rare (the loaders record
    none for a reference after a comma).

    All three reference lists move together. The two display lists mark what
    get_config shows; ``_written_references`` is what the records write
    (config_validator.record_of_config): the results file's ash_config and
    to_simple_dict, which reporters send off the host. A rewrite left at the
    entry's old index names another entry after a drop -- record_of_config
    writes a rewrite only where the record's string equals its resolved value,
    so the moved entry's value then stays in the record in clear. A moved
    rewrite of a multi-piece entry takes the kept piece as its ``resolved``
    and ``environment_part``, so the record writes the file's own reference
    text in the piece's place.
    """
    new_index = {name: i for i, name in enumerate(kept)}
    referenced = _referenced_module_entries(config)
    seen: set[str] = set()
    new_indices: Dict[int, List[int]] = {}
    respelled: Dict[int, bool] = {}
    for old, entry in enumerate(entries):
        pieces = split_plugin_modules([entry])
        # Not a piece COUNT: a one-piece entry whose stored text differs from
        # its stripped piece (a trailing comma, a leading space) also needs
        # its moved rewrite re-resolved to the kept piece, or ``resolved``
        # stays the unstripped text, record_of_config's value check matches
        # nothing, and the environment-read value lands in the record.
        respelled[old] = pieces != [entry]
        mine: List[int] = []
        for piece in pieces:
            if piece in seen:
                continue
            # Only an entry that carries a reference claims its piece: a plain
            # entry that repeats the name earlier must not take the place of
            # the environment-read entry that follows it, or that entry's
            # reference is dropped and the name is shown in clear.
            if old in referenced:
                seen.add(piece)
            if piece in new_index:
                mine.append(new_index[piece])
        new_indices[old] = mine
    _remap_module_reference_lists(
        config,
        new_indices,
        lambda old, index: kept[index] if respelled[old] else None,
        described_entries=len(entries),
    )


def _remap_module_reference_lists(
    config: "AshConfig",
    new_indices: Mapping[int, Sequence[int]],
    piece_at: Callable[[int, int], Optional[str]],
    *,
    described_entries: "Union[int, Literal['all']]",
) -> None:
    """Rebuild the three ``ash_plugin_modules`` reference lists under one rule.

    ``new_indices`` maps each old entry index to the kept indices its
    references move to. ``described_entries`` states the map's kind, so an
    omitted old index is never guessed at:

    - ``"all"`` is a WHOLE-ENTRY map (move_plugin_module_references): the
      caller speaks for every entry, so an omitted old index means that entry
      was dropped, and its references and record rewrite leave with it. Every
      drop path reassigns the entry list before the move, so the record
      (config_validator.record_of_config over the model's current list) no
      longer carries the dropped entry, and the run-wide redaction set keeps
      its value either way.
    - an int is an INDEX-REMAP map (reindex_plugin_module_references): the
      caller described exactly that many old entries, one map key each. An
      old index AT OR PAST the count was never described, and neither
      mending is safe: dropping its record REWRITE leaves the
      environment-read value in the record in clear (record_of_config writes
      a rewrite only where the record's string equals the reference's
      resolved value), while keeping it persists bookkeeping that no longer
      describes the list -- a stale rewrite can later replace an unrelated
      entry's equal text with a reference it never was, and
      render_config_file_as_written writes it into the file a scan reloads.
      Both production callers pass the list the references were recorded
      against (the load drops the references a shortening override leaves
      past the list, ``drop_plugin_module_references_past_the_list``), so
      such a reference is a caller bug, and the move REFUSES it
      (PluginModuleReferenceError, not a ValueError, before any list is
      rebuilt) rather than guessing which harm to take. A described old
      index absent from such a map is treated as a dropped entry, like the
      whole-entry kind.

    An old index mapped to an empty sequence drops everything either way: the
    caller knows the entry and dropped it. ``piece_at(old, new)`` is the kept
    piece text a moved reference of a multi-piece entry re-resolves to, or
    None to keep the reference's own text. References into other config
    places are not the remap's and stay as they are.

    The rebuild itself is ``_remapped_module_reference_lists``, which the
    trusted-base carry (``_carry_trusted_module_references``) also applies to
    the trusted config's lists, so the two movers share one rule.
    """
    sources = {
        attribute: tuple(getattr(config, attribute, None) or ())
        for attribute in _MODULE_REFERENCE_LISTS
    }
    moved_lists = _remapped_module_reference_lists(
        sources, new_indices, piece_at, described_entries=described_entries
    )
    for attribute, rebuilt_list in moved_lists.items():
        setattr(config, attribute, rebuilt_list)


def _remapped_module_reference_lists(
    sources: Mapping[str, Sequence[Any]],
    new_indices: Mapping[int, Sequence[int]],
    piece_at: Callable[[int, int], Optional[str]],
    *,
    described_entries: "Union[int, Literal['all']]",
) -> Dict[str, Any]:
    """Rebuild the reference lists in ``sources`` under the remap rule.

    ``sources`` maps each of the three list names to the references it holds
    now (``_remap_module_reference_lists`` passes a config's own lists; the
    carry passes the trusted base's ``ash_plugin_modules`` references). The
    result maps each NON-EMPTY source list to its rebuilt form: a tuple for
    the two display lists, a list for the rewrites. Nothing is assigned here,
    so a refusal leaves every caller's config exactly as it was. The rule is
    ``_remap_module_reference_lists``'s docstring.
    """
    if described_entries != "all":
        # The whole check runs before any list is rebuilt, so a refusal
        # leaves the config exactly as it was: a half-moved config (displays
        # rebuilt, rewrites untouched) would be a state nothing documents.
        for attribute in _MODULE_REFERENCE_LISTS:
            for reference in sources.get(attribute, None) or ():
                path = tuple(reference.path)
                if _names_a_plugin_module_entry(reference) and (
                    path[1] >= described_entries
                ):
                    raise PluginModuleReferenceError(
                        f"ash_plugin_modules reference at index {path[1]} is "
                        f"past the {described_entries} "
                        f"entr{'y' if described_entries == 1 else 'ies'} the "
                        "caller described: the reference bookkeeping no "
                        "longer matches the list, so the move is refused "
                        "rather than guessed at"
                    )
    # Every list is rebuilt before any is assigned, so the three change
    # together or not at all.
    moved_lists: Dict[str, Any] = {}
    for attribute in ("_environment_references", "_displayed_environment_references"):
        references = tuple(sources.get(attribute, None) or ())
        if not references:
            continue
        rebuilt = []
        for reference in references:
            if not _names_a_plugin_module_entry(reference):
                rebuilt.append(reference)
                continue
            path = tuple(reference.path)
            old = path[1]
            for index in new_indices.get(old, ()):
                moved = reference.moved_to_unknown_list(
                    ("ash_plugin_modules", index) + path[2:]
                )
                piece = piece_at(old, index)
                if piece is not None:
                    moved = replace(moved, resolved=piece, value=piece)
                rebuilt.append(moved)
        moved_lists[attribute] = tuple(rebuilt)
    rewrites = list(sources.get("_written_references", None) or [])
    if rewrites:
        rebuilt_rewrites = []
        for rewrite in rewrites:
            if not _names_a_plugin_module_entry(rewrite):
                rebuilt_rewrites.append(rewrite)
                continue
            path = tuple(rewrite.path)
            old = path[1]
            if old not in new_indices:
                # A dropped entry: its rewrite leaves with it (see the
                # docstring; a past-end index was refused above, so an
                # unmapped index here is always a described, dropped entry).
                continue
            for index in new_indices.get(old, ()):
                moved = rewrite._replace(path=("ash_plugin_modules", index) + path[2:])
                piece = piece_at(old, index)
                if piece is not None:
                    moved = moved._replace(resolved=piece, environment_part=piece)
                rebuilt_rewrites.append(moved)
        moved_lists["_written_references"] = rebuilt_rewrites
    return moved_lists


def drop_plugin_module_references_past_the_list(
    config: "AshConfig", *, replaced: bool = False
) -> None:
    """Drop the ``ash_plugin_modules`` references that name an entry the list lacks.

    A load records its references and record rewrites from the config file's
    own document, but ``--config-overrides`` are applied to the model before
    they are attached (and again when a loaded model is overridden a second
    time), so an override that replaces the list with a shorter one leaves a
    reference at an index past its end. The entry that reference described
    was replaced by the override, so it names nothing, and the record is
    built from the model's current list: dropping it discloses nothing, and
    the run-wide redaction set keeps the value either way.

    ``replaced`` says a replacing override landed on the list. Then NO
    reference of the list describes the entry now at its index, whatever the
    new length: one kept at an index the new list still has would show the
    operator's literal as ``<value>``, mark it environment-read in
    ``ash config get`` and the MCP ``get_config``, and keep a record rewrite
    that can later replace an equal text with a reference it never was. Every
    ``ash_plugin_modules`` reference is dropped; the run-wide redaction set
    keeps the value either way.

    The movers (``reindex_plugin_module_references``) refuse a reference past
    the entries they are told about, because for a caller that passed the
    wrong list neither mending is safe. This is where the invariant they rely
    on is made true for the callers that pass the right one: after a load, no
    reference is past the list. Without ``replaced`` (a load with no
    replacing override, or an appending one) a reference at an index inside
    the list is the file's own and stays.
    """
    entries = 0 if replaced else len(getattr(config, "ash_plugin_modules", None) or [])
    for attribute in (
        "_environment_references",
        "_displayed_environment_references",
        "_written_references",
    ):
        held = getattr(config, attribute, None)
        if not held:
            continue
        kept = []
        for reference in held:
            path = tuple(reference.path)
            if (
                len(path) >= 2
                and path[0] == "ash_plugin_modules"
                and isinstance(path[1], int)
                and path[1] >= entries
            ):
                continue
            kept.append(reference)
        if len(kept) != len(held):
            setattr(config, attribute, tuple(kept) if isinstance(held, tuple) else kept)


def move_plugin_module_references(
    config: "AshConfig", index_map: Mapping[int, int]
) -> None:
    """Move each ``ash_plugin_modules`` reference and record rewrite from its
    old entry index to ``index_map[old index]``, dropping those of entries no
    longer present. The remap rule is _remap_module_reference_lists'; this
    caller's map is the WHOLE-ENTRY kind (``described_entries="all"``): it
    carries each kept entry whole, so no reference re-resolves, and an old
    index it omits is a dropped entry whose references and rewrite leave
    with it.

    For a caller that keeps or drops WHOLE entries without splitting -- the
    config wizard's keep prompt (cli/config.py) is the production caller --
    the kept entry's text is unchanged, so the reference moves as it is. The
    wizard's generated file is dumped from the model's user data
    (config_writer.render_config_file), not written through record_of_config,
    and the config it edits carries no references today: the move keeps the
    object's bookkeeping right for anything that records it
    (config_validator.record_of_config), where a rewrite left at a dropped
    entry's index would write the reference text over another entry, or
    leave the moved entry's value in such a record in clear.

    The unchanged-text contract is enforced before anything moves: a mapped
    position must exist in the config's current list, no two old indices may
    map to one position, and for every reference being moved the config's
    entry at the mapped position must equal the reference's recorded value,
    else ValueError is raised, so a rewrite is never recorded against an
    entry it no longer matches. The message names the position and the old
    index, never the entry text. This is the lower-level function;
    ``replace_plugin_module_list`` reads the old list from the config itself,
    assigns the new one and builds the map, so a caller that swaps a list
    uses that instead.
    """
    current = list(getattr(config, "ash_plugin_modules", None) or [])
    taken: Dict[int, int] = {}
    for old, new in index_map.items():
        if not 0 <= new < len(current):
            raise ValueError(
                f"index_map sends old index {old} to position {new}, outside "
                f"the config's list of {len(current)} entries"
            )
        if new in taken:
            raise ValueError(
                f"index_map sends old index {old} to position {new}, which "
                f"old index {taken[new]} already names"
            )
        taken[new] = old
    for attribute in (
        "_environment_references",
        "_displayed_environment_references",
        "_written_references",
    ):
        for reference in getattr(config, attribute, None) or ():
            path = tuple(reference.path)
            if not (
                len(path) >= 2
                and path[0] == "ash_plugin_modules"
                and isinstance(path[1], int)
            ):
                continue
            old = path[1]
            if old not in index_map:
                continue
            recorded = getattr(reference, "resolved", None)
            if recorded is not None and current[index_map[old]] != recorded:
                raise ValueError(
                    f"the config's module list at position {index_map[old]} "
                    f"does not hold the entry recorded at old index {old}; "
                    "the list was edited after the map was derived"
                )
    _remap_module_reference_lists(
        config,
        {old: (new,) for old, new in index_map.items()},
        lambda old, index: None,
        described_entries="all",
    )


def replace_plugin_module_list(
    config: "AshConfig", kept_old_indices: Sequence[int], added: Sequence[str]
) -> None:
    """Replace ``config``'s ``ash_plugin_modules`` with the entries at
    ``kept_old_indices`` of its current list, in that order, followed by
    ``added``, and move the references and record rewrites with the entries.

    The old list is read from the config itself, so the index map cannot be
    derived from an edited list. An index outside the current list or named
    twice raises ValueError before the list is assigned. A ValueError from the
    move (its check that each moved reference still describes the entry at its
    new position) puts the previous list back before it propagates, so the
    list and the references are left as they were.
    ``move_plugin_module_references`` stays public as the lower-level function
    this one calls with the map it builds.
    """
    old = list(config.ash_plugin_modules or [])
    stated: set[int] = set()
    for index in kept_old_indices:
        if not 0 <= index < len(old):
            raise ValueError(
                f"kept_old_indices names index {index}, outside the recorded "
                f"list of {len(old)} entries"
            )
        if index in stated:
            raise ValueError(
                f"kept_old_indices names index {index} twice; a repeated old "
                "index would collapse to one map row with no error"
            )
        stated.add(index)
    previous = config.ash_plugin_modules
    config.ash_plugin_modules = [old[i] for i in kept_old_indices] + list(added)
    try:
        move_plugin_module_references(
            config, {old_index: new for new, old_index in enumerate(kept_old_indices)}
        )
    except ValueError:
        config.ash_plugin_modules = previous
        raise


def refuse_plugin_modules_a_scan_refuses(
    resolved: "AshConfig", additional_plugin_modules: Sequence[str]
) -> None:
    """Raise the refusal a scan's plugin loader gives ``ash_plugin_modules``.

    ``resolved`` came from ``resolve_config``, so the trust confinement already
    ran and the list judged is the one a scan would import, plus
    ``additional_plugin_modules`` -- the scan inputs that reach a scan beside
    its config (``ASH_PLUGIN_MODULES``), first, in the order the scan engine
    combines them; the caller's handler maps the error (an
    ASHConfigValidationError) to exit 3 like any other invalid configuration.
    An entry read from the environment of a config FILE is named by its
    placeholder, never the variable's value; an additional entry is the
    operator's own text.

    The argument is required on purpose: whether the server's environment
    joins the judgment is each surface's own decision, made where its scans'
    inputs are known. A CLI check command passes
    ``environment_plugin_modules()``, because a scan of the same inputs reads
    the variable; a surface whose scans never read it, and which must not
    show the server's environment (the MCP tools), passes ``()``. A default
    that read the environment here made the safe spelling the implicit one.
    """
    from automated_security_helper.plugins.loader import (
        PluginModuleError,
        refuse_plugin_modules_outside_namespace,
        refuse_unfindable_plugin_imports,
    )

    config_modules = getattr(resolved, "ash_plugin_modules", None) or []
    modules = split_plugin_modules([*additional_plugin_modules, *config_modules])
    names = config_module_names(resolved)
    try:
        refuse_plugin_modules_outside_namespace(modules, shown=names)
        # The import refusal's locatable half: a kept name no installed package
        # provides scan-refuses with exit 3, so these commands say so too,
        # importing nothing (a module that is installed but fails while
        # importing can only be caught by importing it, which stays the
        # scan's).
        refuse_unfindable_plugin_imports(modules, shown=names)
    except PluginModuleError as e:
        # The printers offer "unset it in ASH_PLUGIN_MODULES" only for an
        # entry nothing else contributed, the same subtraction the validator's
        # check makes (with_environment_remedy): for an entry the config also
        # names, unsetting the variable fixes nothing. Computed here, where
        # both lists are at hand; the error carries it to the printer.
        e.environment_only_entries = frozenset(
            split_plugin_modules(list(additional_plugin_modules))
        ) - frozenset(split_plugin_modules(list(config_modules)))
        raise


def plugin_module_refusal_message(
    error: "PluginModuleError",
    namespace_closing: Optional[str] = None,
    import_closing: Optional[str] = None,
) -> str:
    """The verdict a check surface gives for ``ash_plugin_modules`` entries a
    scan refuses: the raised naming, closed in that surface's own words.

    ``str(error)`` carries the scan's closing, which names a run a config
    command does not make and option spellings it does not take, and
    re-checking the file would re-derive the same refusal with the validator's
    closing, whose namespace form offers only the config file - wrong for an
    entry ``--config-overrides`` added, which the config commands take. Every
    surface builds its refusal here, so they cannot drift apart on the shared
    half; each passes a closing naming only the remedies its caller has (the
    defaults are the config commands', which take ``--config-overrides``; the
    MCP surface's closings are ``cli/mcp_tools._MCP_PLUGIN_MODULE_CLOSINGS``).

    An entry only ``ASH_PLUGIN_MODULES`` contributed has a remedy the file and
    the overrides do not offer, so the closing names it the way the
    validator's check does (``with_environment_remedy``): for an entry the
    config also names, unsetting the variable fixes nothing, and the advice
    would read as if either remedy sufficed.
    """
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.plugins.loader import PluginModuleNamespaceError

    # An if/else rather than a conditional expression: the former shape,
    # `A or "..." if isinstance(...) else B or "..."`, was correct only
    # because `or` binds tighter than the conditional.
    if isinstance(error, PluginModuleNamespaceError):
        closing = namespace_closing or (
            "Nothing was imported. Rename the package or name the "
            "packages inside it, or remove the entry from the config "
            "file or --config-overrides"
        )
    else:
        closing = import_closing or (
            "Nothing was imported. Install what the module needs, "
            "or remove the entry from the config file or "
            "--config-overrides"
        )
    environment_only = getattr(error, "environment_only_entries", None)
    if environment_only is None:
        # Raised somewhere other than refuse_plugin_modules_a_scan_refuses,
        # which always records the subtraction: no environment remedy, rather
        # than reading the server's environment here. Every surface that can
        # offer the remedy routes through the judge, where both lists are at
        # hand; a builder-side environment read put the variable's content
        # one forgotten attribute away from a reply.
        environment_only = frozenset()
    return error.shown_with(
        ConfigValidator.with_environment_remedy(closing, error, set(environment_only))
    )


def plugin_modules_by_trust(
    config: Optional["AshConfig"],
    operator_modules: Optional[Iterable[object]],
) -> Tuple[List[str], List[str]]:
    """The plugin modules a scan loads: the operator's, and those only its untrusted config names.

    The operator's are ``operator_modules`` (``--ash-plugin-modules`` and
    ``ASH_PLUGIN_MODULES``) and the config's ``ash_plugin_modules`` entries that
    its recorded trusted list names: the defaults, an operator config outside
    the tree, and ``--config-overrides``. A config with no trusted list recorded
    was built only from the operator's files, so all of its entries are the
    operator's. The rest came from a config file inside the scanned tree or one
    an MCP client delivered, and passed ``confine_plugin_modules``. A module both
    name is the operator's.

    ``ScanExecutionEngine`` imports the second list inside
    ``ash_plugin_manager.untrusted_import``, so a later scan in the process that
    does not load one of those modules is not offered the classes its import
    registered (``AshPluginManager.plugins_loaded_by``).

    Returns:
        The operator's modules, then the others, each in order and without
        repeats, with entries split on commas.
    """
    from automated_security_helper.config.ash_config import AshConfig

    configured = split_plugin_modules(
        getattr(config, "ash_plugin_modules", None) if config is not None else None
    )
    recorded = config._trusted_plugin_modules if isinstance(config, AshConfig) else None
    trusted = set(configured if recorded is None else recorded)
    operator = split_plugin_modules(
        [*(operator_modules or []), *(name for name in configured if name in trusted)]
    )
    return operator, [name for name in configured if name not in operator]


#: The module attributes that list a plugin package's classes.
_PLUGIN_LISTS: Tuple[str, ...] = ("ASH_SCANNERS", "ASH_REPORTERS", "ASH_CONVERTERS")


def _within(module: str, name: str) -> bool:
    return module == name or module.startswith(name + ".")


def _off_host_bases(cls: type) -> Dict[str, type]:
    """By off-host package, the first class of ``cls.__mro__`` defined in it.

    That is ``cls`` itself for a class an off-host package defines, and the base
    it derives from for a subclass another package defines. Empty for a class
    that derives from no class an off-host package defines.
    """
    bases: Dict[str, type] = {}
    for base in getattr(cls, "__mro__", (cls,)):
        package = off_host_package(getattr(base, "__module__", "") or "")
        if package is not None:
            bases.setdefault(package, base)
    return bases


def _off_host_classes_trusted(cls: type, trusted: Sequence[str]) -> bool:
    """Whether every off-host class of ``cls.__mro__`` is covered by ``trusted``.

    An off-host class is covered when a trusted name is its defining module or a
    package around it, or when it is a base of a covered class (a trusted
    module's class carries what it derives from). Every such class has to be
    covered, not only the first one per package: a class that mixes in a second
    class from another module of the same package sends what that class sends.
    """
    mro = getattr(cls, "__mro__", (cls,))
    off_host = [
        base
        for base in mro
        if off_host_package(getattr(base, "__module__", "") or "") is not None
    ]
    covered = {
        id(inherited)
        for base in off_host
        if any(_within(getattr(base, "__module__", "") or "", name) for name in trusted)
        for inherited in getattr(base, "__mro__", (base,))
    }
    return all(id(base) in covered for base in off_host)


def drop_untrusted_off_host_plugins(
    config: Optional["AshConfig"],
    plugins: Mapping[str, Sequence[type]],
    operator_modules: Optional[Iterable[object]],
) -> Dict[str, List[type]]:
    """``plugins`` without the off-host classes the trusted modules do not load.

    A class whose defining module is inside a package of
    ``OFF_HOST_PLUGIN_PACKAGES`` is kept only when a trusted module name (the
    config's ``_trusted_plugin_modules`` and ``operator_modules``) is that module
    or a package around it, or is an imported module that lists the class in its
    ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_CONVERTERS``. A class defined
    elsewhere that derives from such a class is kept under the same terms, or
    when a trusted name is the defining module, or a package around it, of
    every off-host class it derives from (``_off_host_classes_trusted``; a base
    of a trusted module's class is covered with it).
    Every other class is kept. For a config ``resolve_config`` recorded no trusted
    list on, every file it was built from is the operator's, so its own
    ``ash_plugin_modules`` are the trusted names. The classes a scan is offered
    are every class registered in the process so far, and the MCP server runs
    every scan in the server's process, so a class an earlier scan loaded is held
    to the same rule.

    Args:
        config: The config ``resolve_config`` returned, or None for the defaults.
        plugins: The selected plugin classes, by plugin type.
        operator_modules: ``--ash-plugin-modules`` and ``ASH_PLUGIN_MODULES``.

    Returns:
        The classes to select, by plugin type, in their original order.
    """
    from automated_security_helper.config.ash_config import AshConfig

    selected = {kind: list(classes) for kind, classes in plugins.items()}
    if config is None:
        config = AshConfig()
    if not isinstance(config, AshConfig):
        return selected
    recorded = config._trusted_plugin_modules
    trusted = split_plugin_modules(
        [
            *(config.ash_plugin_modules if recorded is None else recorded),
            *(operator_modules or []),
        ]
    )
    listed: List[type] = []
    for name in trusted:
        imported = sys.modules.get(name)
        for attribute in _PLUGIN_LISTS:
            listed.extend(getattr(imported, attribute, None) or [])
    dropped: List[str] = []
    for kind, classes in selected.items():
        kept: List[type] = []
        for cls in classes:
            module = getattr(cls, "__module__", "") or ""
            bases = _off_host_bases(cls)
            if (
                not bases
                or any(_within(module, name) for name in trusted)
                or any(cls is entry for entry in listed)
                or _off_host_classes_trusted(cls, trusted)
            ):
                kept.append(cls)
                continue
            label = repr(getattr(cls, "__name__", cls))
            derived = [
                f"{base.__name__!r} from {package}"
                for package, base in bases.items()
                if base is not cls
            ]
            entry = (
                f"{label} from {module} (a subclass of {' and '.join(derived)})"
                if derived
                else f"{label} from {next(iter(bases))}"
            )
            if entry not in dropped:
                dropped.append(entry)
        selected[kind] = kept
    if dropped:
        ASH_LOGGER.warning(
            f"Plugin classes {', '.join(dropped)} are not selected: they send "
            "findings or source off the host, and no module that "
            "--ash-plugin-modules or the operator's configuration names lists "
            "them, defines them, or defines the off-host class they subclass. A "
            "module that a config inside the scanned tree, or one an MCP client "
            "delivered, loads can import them, as can an earlier scan in the same "
            "process. Load their package with --ash-plugin-modules, "
            "--config-overrides or a config file outside the tree."
        )
    return selected
