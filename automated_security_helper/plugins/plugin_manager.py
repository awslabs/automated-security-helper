# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import re
import sys
from contextlib import contextmanager
from threading import Lock, local
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Annotated,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    Sequence,
    Set,
)
from pydantic import BaseModel, Field, ConfigDict, PrivateAttr

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext


class AshPluginRegistration(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )

    name: Annotated[str, Field(description="The name of the plugin")]
    plugin_module_path: Annotated[
        str,
        Field(
            description="The module path containing the plugin. This module will be imported at the start of ASH to identify plugins to use. Example: `automated_security_helper.plugin_modules.ash_builtin.scanners`"
        ),
    ]
    description: Annotated[
        str | None, Field(description="A description of the plugin")
    ] = None
    version: Annotated[str | None, Field(description="The version of the plugin")] = (
        None
    )
    author: Annotated[str | None, Field(description="The author of the plugin")] = None
    enabled: Annotated[bool, Field(description="Whether the plugin is enabled")] = True


class AshPluginLibrary(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    converters: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of converters to register with the plugin manager"
        ),
    ] = {}
    scanners: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of scanners to register with the plugin manager"
        ),
    ] = {}
    reporters: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of scanners to register with the plugin manager"
        ),
    ] = {}
    event_handlers: Annotated[
        Dict[AshEventType, List[Callable]],
        Field(
            description="A dictionary of event handlers to register with the plugin manager"
        ),
    ] = {}


class AshPluginManager(BaseModel):
    model_config = ConfigDict(extra="allow")

    plugin_library: Annotated[AshPluginLibrary, Field()] = AshPluginLibrary()
    context: Any = None
    _resolved_plugins: dict = PrivateAttr(default_factory=dict)
    #: Guards the shared event-handler lists. This manager is a module-level
    #: singleton (``plugins/__init__.py``) and workspace mode runs several
    #: differently-configured scans against it concurrently, so subscribe and
    #: notify cannot both touch the same list unsynchronised.
    _event_lock: Lock = PrivateAttr(default_factory=Lock)
    #: Which registrations an untrusted import made, so a scan is offered only
    #: the classes its own modules load (``plugins_loaded_by``). By plugin type
    #: and name: the module imported for an untrusted source, and the
    #: registration, so a later registration under the same name is not taken
    #: for it.
    _untrusted_registrations: dict = PrivateAttr(default_factory=dict)
    #: Every module the operator named in this process (``trust_plugin_modules``).
    _operator_modules: set = PrivateAttr(default_factory=set)
    _provenance_lock: Lock = PrivateAttr(default_factory=Lock)
    #: The module ``untrusted_import`` is importing on this thread, if any.
    _importing: local = PrivateAttr(default_factory=local)

    def set_context(self, context: "PluginContext"):
        """Set the plugin context for this plugin manager.

        Args:
            context: The PluginContext to use for plugin discovery and operations
        """
        self.context = context
        ASH_LOGGER.debug(f"Plugin manager context set: {context}")

    def subscribe(self, event_type, callback):
        """Subscribe a callback to a specific event type, at most once.

        Idempotent, and locked, because both properties are load-bearing once
        more than one differently-configured scan runs in a process:

        * ``load_internal_plugins()`` runs per ``ScanExecutionEngine``, so a
          workspace of five projects previously ended up with five copies of
          every handler and fired each one five times. Harmless while the
          handlers only log, and a verdict bug as soon as one touches results --
          which is exactly what the reporter and workspace-policy phases add.
        * The old ``not in``-then-assign was unsynchronised, so two threads could
          each build a fresh list for the same event and one would clobber the
          other, silently dropping the subscription it had just made.

        Identity is decided by ``==``, which for a plain function is identity and
        for a bound method compares both the instance and the function -- the
        right granularity, since two instances of a handler class are genuinely
        two subscribers.

        Still returns the callback so decorator usage is unchanged.
        """
        with self._event_lock:
            handlers = self.plugin_library.event_handlers.setdefault(event_type, [])
            if callback in handlers:
                ASH_LOGGER.debug(
                    f"Callback already subscribed to event {event_type}; skipping "
                    f"the duplicate. Total subscribers: {len(handlers)}"
                )
                return callback
            handlers.append(callback)
            total = len(handlers)
        ASH_LOGGER.debug(
            f"Subscribed callback to event {event_type}. Total subscribers for this event: {total}"
        )
        return callback  # Return for decorator usage

    def notify(self, event_type, *args, **kwargs):
        """Notify all subscribers of an event"""
        if not hasattr(self.plugin_library, "event_handlers"):
            ASH_LOGGER.debug(
                f"No event handlers dictionary exists for event {event_type}"
            )
            return []

        if event_type not in self.plugin_library.event_handlers:
            ASH_LOGGER.debug(f"No subscribers for event {event_type}")
            return []

        # Snapshot under the lock. A callback subscribed from another project's
        # thread while this loop ran would otherwise raise "list changed size
        # during iteration", and the same handler list is shared by every project
        # in a workspace.
        with self._event_lock:
            handlers = list(self.plugin_library.event_handlers[event_type])

        ASH_LOGGER.debug(f"Notifying {len(handlers)} subscribers of event {event_type}")
        results = []
        for callback in handlers:
            ASH_LOGGER.debug(
                f"Calling subscriber callback {callback.__name__ if hasattr(callback, '__name__') else 'anonymous'}"
            )
            results.append(callback(*args, **kwargs))

        return results

    def register_plugin_module(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_module_class,
        plugin_module_path: str,
        plugin_module_version: str | None = None,
        plugin_module_enabled: bool = True,
    ):
        """Register a plugin module with the plugin manager.

        Args:
            plugin_type: Type of plugin (converter, scanner, reporter)
            plugin_module_class: The plugin class to register
            plugin_module_path: Path to the module containing the plugin
            plugin_module_version: Optional version of the plugin
            plugin_module_enabled: Whether the plugin is enabled
        """
        # If plugin_module_class is a string, use it directly as the name
        if isinstance(plugin_module_class, str):
            plugin_module_name = plugin_module_class
        else:
            plugin_module_name = getattr(plugin_module_class, "__name__", "Unknown")

        if plugin_module_name == "ash-default" and not re.match(
            pattern=r"^automated_security_helper\.(converters|scanners|reporters)\.ash_default$",
            string=plugin_module_path,
        ):
            ASH_LOGGER.error(
                f"ash-default is a protected plugin_module_name. Plugin module at path '{plugin_module_path}' should register with a different name."
            )
            return
        elif (
            (
                plugin_type == "converter"
                and plugin_module_name in self.plugin_library.converters
            )
            or (
                plugin_type == "scanner"
                and plugin_module_name in self.plugin_library.scanners
            )
            or (
                plugin_type == "reporter"
                and plugin_module_name in self.plugin_library.reporters
            )
        ):
            ASH_LOGGER.warning(
                f"Plugin module '{plugin_module_name}' already registered. Skipping."
            )
            return

        plug_reg = AshPluginRegistration(
            name=plugin_module_name,
            plugin_module_path=plugin_module_path,
            version=plugin_module_version,
            enabled=plugin_module_enabled,
        )
        if plugin_type == "converter":
            self.plugin_library.converters[plugin_module_name] = plug_reg
        elif plugin_type == "scanner":
            self.plugin_library.scanners[plugin_module_name] = plug_reg
        elif plugin_type == "reporter":
            self.plugin_library.reporters[plugin_module_name] = plug_reg

        untrusted = getattr(self._importing, "module", None)
        if untrusted is not None:
            with self._provenance_lock:
                self._untrusted_registrations[(plugin_type, plugin_module_name)] = (
                    untrusted,
                    plug_reg,
                )

        ASH_LOGGER.verbose(f"Registered plugin module '{plugin_module_name}'")

    @contextmanager
    def untrusted_import(self, module_name: str) -> Iterator[None]:
        """Attribute what this thread registers inside the block to ``module_name``.

        For importing a module the operator did not name: one that a config
        file inside the scanned tree, or a config an MCP client delivered, lists
        in ``ash_plugin_modules``, or one an MCP client's request loads.
        Registration lasts for the rest of the process, and the MCP server and a
        workspace run build several scans in one process, so
        ``plugins_loaded_by`` leaves these registrations' classes out of a scan
        that does not itself load the module.

        Per thread, because the decorators register a class on the thread that
        runs its module's code, which is the thread importing it; a scan
        importing on another thread at the same time is not attributed here. A
        module already imported registers nothing again, so what an earlier
        import of it registered keeps its earlier attribution.
        """
        previous = getattr(self._importing, "module", None)
        self._importing.module = module_name
        try:
            yield
        finally:
            self._importing.module = previous

    def trust_plugin_modules(self, module_names: Iterable[str]) -> None:
        """Record ``module_names`` as modules the operator loaded.

        ``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``, or the operator's
        configuration. What their imports registered is the operator's choice
        and stays selectable by every later scan in the process, even when an
        untrusted import registered it first: the operator loading a module
        first would have left it untracked, and the order two scans load a
        module in does not decide what a later scan is offered.
        """
        with self._provenance_lock:
            self._operator_modules.update(name for name in module_names if name)

    def plugins_loaded_by(
        self,
        plugins: Mapping[str, Sequence[type]],
        module_names: Iterable[str],
    ) -> Dict[str, List[type]]:
        """``plugins`` without the classes only another scan's untrusted imports brought in.

        A class is left out when every registration that brings it into
        ``plugin_modules`` was made inside ``untrusted_import`` of a module that
        neither ``module_names`` (the modules this scan loads) nor a module the
        operator named (``trust_plugin_modules``) is, and none of those modules
        defines the class, is a package around its module, has it as an
        attribute, or lists it in ``ASH_SCANNERS``, ``ASH_REPORTERS`` or
        ``ASH_CONVERTERS``. Those last checks cover a module this scan names that
        an untrusted import already imported along the way: importing it again
        registers nothing. Every other class is kept, including one embedding
        code registered through ``register_plugin_module`` itself.

        The resolved list ``plugin_modules`` caches stays as it is; this filters
        what one scan takes from it.

        Args:
            plugins: The classes ``plugin_modules`` resolved, by plugin type.
            module_names: The plugin modules this scan loads: the operator's and
                those its own config names.

        Returns:
            The classes to select, by plugin type, in their original order.
        """
        selected = {kind: list(classes) for kind, classes in plugins.items()}
        with self._provenance_lock:
            tracked = dict(self._untrusted_registrations)
            names = set(module_names) | self._operator_modules
        if not tracked:
            return selected
        dropped: Dict[type, Set[str]] = {}
        for kind, classes in selected.items():
            registry = self._registry(kind)
            if registry is None:
                continue
            untracked_classes: Set[type] = set()
            origins: Dict[type, Set[str]] = {}
            # A copy: a registration on another thread must not resize the dict
            # this loop walks.
            for name, registration in dict(registry).items():
                if not registration.enabled:
                    continue
                found = self._registered_classes(kind, registration, quiet=True)
                entry = tracked.get((kind, name))
                if entry is None or entry[1] is not registration:
                    untracked_classes.update(found)
                    continue
                for cls in found:
                    origins.setdefault(cls, set()).add(entry[0])
            kept: List[type] = []
            for cls in classes:
                if (
                    cls in untracked_classes
                    or cls not in origins
                    or origins[cls] & names
                    or _named_module_provides(names, cls)
                ):
                    kept.append(cls)
                else:
                    dropped[cls] = origins[cls]
            selected[kind] = kept
        if dropped:
            described = ", ".join(
                f"{getattr(cls, '__name__', cls)!r} (imported with "
                f"{', '.join(sorted(modules))})"
                for cls, modules in dropped.items()
            )
            ASH_LOGGER.verbose(
                f"Plugin classes {described} are not selected: this process "
                "registered them while importing a module for another scan's "
                "config file inside its scanned tree, a config an MCP client "
                "delivered, or an MCP client's request, and neither this scan nor "
                "the operator loads that module."
            )
        return selected

    def _registry(self, plugin_type: str) -> Dict[str, AshPluginRegistration] | None:
        return {
            "converter": self.plugin_library.converters,
            "scanner": self.plugin_library.scanners,
            "reporter": self.plugin_library.reporters,
        }.get(plugin_type)

    @staticmethod
    def _registered_classes(
        plugin_type: str, registration: AshPluginRegistration, quiet: bool = False
    ) -> List[type]:
        """The ``plugin_type`` classes in the module ``registration`` names.

        Every class there with that ``ash_plugin_type``, not only the registered
        one, which is how ``plugin_modules`` has always resolved a registration.
        """
        try:
            # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
            module = importlib.import_module(registration.plugin_module_path)
        except ImportError as e:
            if not quiet:
                ASH_LOGGER.warning(
                    f"Failed to import plugin module {registration.plugin_module_path}: {e}"
                )
            return []
        found: List[type] = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and hasattr(attr, "ash_plugin_type")
                and attr.ash_plugin_type == plugin_type
                and attr not in found
            ):
                found.append(attr)
        return found

    def filter_plugin_modules(self, items: List, callback: Callable, *args, **kwargs):
        filtered = []
        for item in items:
            if callback(item, *args, **kwargs):
                filtered.append(item)
        return filtered

    def plugin_modules(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        filter_callback: Callable = lambda x: True,
        *args,
        **kwargs,
    ):
        """Get plugin modules of a specific type.

        Args:
            plugin_type: The type of plugin to get (IConverter, IScanner, IReporter)
            filter_callback: Optional callback to filter plugins

        Returns:
            List of plugin class implementations (not registration objects)
        """
        # Normalize plugin_type to a string key
        cache_key = plugin_type if isinstance(plugin_type, str) else None
        if cache_key is None:
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []

        if cache_key in self._resolved_plugins:
            cached = self._resolved_plugins[cache_key]
            return self.filter_plugin_modules(cached, filter_callback, *args, **kwargs)

        registry = self._registry(plugin_type)
        if registry is None:
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []

        # Get all registered plugins (internal and external). The live dict, not
        # a copy: tests/unit/workspace/test_concurrent_plugin_resolution.py pins
        # what a registration during this loop does, and the workspace pre-warm
        # is what keeps one from happening.
        plugins: List[type] = []
        for registration in registry.values():
            if registration.enabled:
                for attr in self._registered_classes(plugin_type, registration):
                    if attr not in plugins:  # Avoid duplicates
                        plugins.append(attr)

        # Cache the unfiltered result so repeat calls skip the import work
        if cache_key:
            self._resolved_plugins[cache_key] = plugins

        # Apply filter callback
        return self.filter_plugin_modules(plugins, filter_callback, *args, **kwargs)


#: The module attributes that list a plugin package's classes.
_PLUGIN_LISTS = ("ASH_SCANNERS", "ASH_REPORTERS", "ASH_CONVERTERS")


def _named_module_provides(module_names: Set[str], cls: type) -> bool:
    """Whether one of ``module_names`` defines ``cls``, or has it or lists it.

    Defines it: the name is ``cls.__module__`` or a package around it. Has it: an
    imported module of that name has it as the attribute of its name. Lists it:
    that module's ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_CONVERTERS``
    includes it.
    """
    defined_in = getattr(cls, "__module__", "") or ""
    for name in module_names:
        if defined_in == name or defined_in.startswith(name + "."):
            return True
        imported = sys.modules.get(name)
        if imported is None:
            continue
        if getattr(imported, getattr(cls, "__name__", ""), None) is cls:
            return True
        for attribute in _PLUGIN_LISTS:
            if any(entry is cls for entry in getattr(imported, attribute, None) or []):
                return True
    return False
