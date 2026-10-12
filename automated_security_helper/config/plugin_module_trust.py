# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``ash_plugin_modules`` entries a config file in the scanned tree may add.

ASH imports every module ``ash_plugin_modules`` names into its own process. When the
config was built from a file inside the scanned tree (``config/sandbox_grants.py``
decides that), the entries it adds beyond the trusted list (the defaults, an
operator config outside the tree, and ``--config-overrides``) are kept only if
they name an installed module: one that ``importlib.util.find_spec`` locates
outside the scanned tree. An entry that is not importable, or whose spec points
into the tree, is dropped with one warning naming ``ash_plugin_modules``.

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
``UntrustedSource.named_modules_only`` (``config/untrusted_source.py``): an entry
the trusted list does not name is dropped whether or not it is installed, because
nothing the merge imports is a shard's choice. Every class the merge then loads
comes from a module the operator named, so it does not call
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
class. One warning names each dropped class and its package. A config with no
trusted list recorded is built only from the operator's files, so its own
``ash_plugin_modules`` are the trusted entries. That check covers every config
because the classes a scan is offered are every class registered in the process
so far: under the MCP server, those an earlier scan's config loaded. The off-host
packages declare no ``ASH_EVENT_HANDLERS``
(tests/unit/config/test_off_host_plugin_modules_from_repo_config.py derives what
they send from their reporters, handlers and scanners), so only classes are
checked.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import ModuleSpec, PathFinder
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.config.sandbox_grants import is_within
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


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
    """The package of ``OFF_HOST_PLUGIN_PACKAGES`` that ``name`` is or is inside, or None."""
    for package in OFF_HOST_PLUGIN_PACKAGES:
        if name == package or name.startswith(package + "."):
            return package
    return None


def split_plugin_modules(entries: Optional[Iterable[object]]) -> List[str]:
    """Entries split on commas and stripped, the way ScanExecutionEngine reads them."""
    names: List[str] = []
    for entry in entries or []:
        if entry is None:
            continue
        for part in str(entry).split(","):
            part = part.strip()
            if part and part not in names:
                names.append(part)
    return names


def _own_package_dir() -> Optional[Path]:
    import automated_security_helper

    origin = getattr(automated_security_helper, "__file__", None)
    return Path(origin).resolve().parent if origin else None


def _spec_locations(spec: ModuleSpec) -> List[Path]:
    locations = [Path(p) for p in (spec.submodule_search_locations or [])]
    if spec.has_location and spec.origin:
        locations.append(Path(spec.origin))
    return locations


def _spec_without_importing(
    name: str, parent: Optional[ModuleSpec]
) -> Optional[ModuleSpec]:
    """The spec for ``name``, found without running any package's ``__init__``.

    A top-level name, or one whose parent is already imported, goes through
    ``importlib.util.find_spec``, which then imports nothing. Otherwise the
    parent's spec gives the directories to search, and ``PathFinder`` looks there
    directly. A package that adds to its ``__path__`` when imported, or a submodule
    only a custom finder can see, is then reported as not importable, which
    refuses it.
    """
    parent_name = name.rpartition(".")[0]
    if not parent_name or parent_name in sys.modules:
        return importlib.util.find_spec(name)
    if parent is None or not parent.submodule_search_locations:
        return None
    return PathFinder.find_spec(name, list(parent.submodule_search_locations))


def refusal_reason(name: str, scanned_root: Path) -> Optional[str]:
    """Why ``name`` may not be imported for a config in the scanned tree, or None.

    Imports nothing that is not already imported, so a refused name runs no code.
    """
    own = _own_package_dir()
    parts = name.split(".")
    spec: Optional[ModuleSpec] = None
    for depth in range(1, len(parts) + 1):
        prefix = ".".join(parts[:depth])
        try:
            spec = _spec_without_importing(prefix, spec)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            return "it is not importable from the installed environment"
        for location in _spec_locations(spec):
            if own is not None and is_within(location, own):
                continue
            if in_scanned_tree(location, scanned_root):
                return "it resolves inside the scanned tree"
    return None


def confine_plugin_modules(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    scanned_root: Path,
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
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
        in_tree: The config files inside the tree, named in the warning.
        source: Why those files are not the operator's, and the fix, for the
            warning. With ``named_modules_only`` (``ash merge``), an entry the
            trusted list does not name is dropped as well.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    module_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        == "ash_plugin_modules"
    ]
    if module_overrides:
        trusted_config = apply_config_overrides(trusted_config, module_overrides)
    trusted_names = set(split_plugin_modules(trusted_config.ash_plugin_modules))
    config._trusted_plugin_modules = tuple(sorted(trusted_names))
    kept: List[str] = []
    refused: List[str] = []
    for name in split_plugin_modules(getattr(config, "ash_plugin_modules", [])):
        if name in trusted_names:
            kept.append(name)
            continue
        if source.named_modules_only:
            refused.append(f"{name!r} (the operator's configuration does not name it)")
            continue
        package = off_host_package(name)
        if package is not None and package not in trusted_names:
            refused.append(f"{name!r} ({OFF_HOST_PLUGIN_SENDS[package]})")
            continue
        reason = refusal_reason(name, scanned_root)
        if reason is None:
            kept.append(name)
        else:
            refused.append(f"{name!r} ({reason})")
    if not refused:
        return
    config.ash_plugin_modules = kept
    files = ", ".join(describe_config_path(path) for path in in_tree)
    imported = (
        "only modules the operator's configuration names are imported from it"
        if source.named_modules_only
        else "only installed modules outside the tree are imported from it, and not "
        "ASH's plugin packages that send findings or source off the host"
    )
    ASH_LOGGER.warning(
        f"Ignoring ash_plugin_modules entries {', '.join(refused)} from {files}: "
        f"{source.reason}, so {imported}. Name other modules with "
        f"{source.modules_remedy}."
    )


#: The module attributes that list a plugin package's classes.
_PLUGIN_LISTS: Tuple[str, ...] = ("ASH_SCANNERS", "ASH_REPORTERS", "ASH_CONVERTERS")


def _within(module: str, name: str) -> bool:
    return module == name or module.startswith(name + ".")


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
    ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_CONVERTERS``. Every other class is
    kept. For a config ``resolve_config`` recorded no trusted list on, every file
    it was built from is the operator's, so its own ``ash_plugin_modules`` are the
    trusted names. The classes a scan is offered are every class registered in the
    process so far, and the MCP server runs every scan in the server's process, so
    a class an earlier scan loaded is held to the same rule.

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
            package = off_host_package(module)
            if (
                package is None
                or any(_within(module, name) for name in trusted)
                or any(cls is entry for entry in listed)
            ):
                kept.append(cls)
                continue
            entry = f"{getattr(cls, '__name__', cls)!r} from {package}"
            if entry not in dropped:
                dropped.append(entry)
        selected[kind] = kept
    if dropped:
        ASH_LOGGER.warning(
            f"Plugin classes {', '.join(dropped)} are not selected: they send "
            "findings or source off the host, and no module that "
            "--ash-plugin-modules or the operator's configuration names defines or "
            "lists them. A module that a config inside the scanned tree, or one an "
            "MCP client delivered, loads can import them, as can an earlier scan in "
            "the same process. Load their package with --ash-plugin-modules, "
            "--config-overrides or a config file outside the tree."
        )
    return selected
