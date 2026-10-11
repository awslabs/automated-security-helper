# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Dict, Annotated, List, Literal
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
    #: Resolved plugin classes per plugin type, each stored with the registrations
    #: it was resolved from. A stored list is reused while the registrations are
    #: unchanged and resolved again after a new registration, so a module imported
    #: after the first resolve (a later scan's ``ash_plugin_modules``, or
    #: ``list_scanners`` loading the community packages) is in the next resolve, and
    #: each scanner a scan selects gets a row in its results.
    _resolved_plugins: dict = PrivateAttr(default_factory=dict)
    #: Guards the registration dicts while they are changed or copied. Imports run
    #: outside it: an import registers plugins, which takes this lock.
    _registry_lock: Lock = PrivateAttr(default_factory=Lock)
    #: Guards the shared event-handler lists. This manager is a module-level
    #: singleton (``plugins/__init__.py``) and workspace mode runs several
    #: differently-configured scans against it concurrently, so subscribe and
    #: notify cannot both touch the same list unsynchronised.
    _event_lock: Lock = PrivateAttr(default_factory=Lock)

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

    def notify(
        self,
        event_type,
        *args,
        handler_filter: Callable[[Callable], bool] | None = None,
        **kwargs,
    ):
        """Notify the subscribers of an event.

        Args:
            event_type: The event to notify.
            handler_filter: Which subscribers this notification reaches. A scan
                passes its own (``plugins.loader.scan_handler_filter``), so a
                handler registered by a plugin module only another scan named is
                not called for it. None notifies every subscriber.
        """
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
        if handler_filter is not None:
            handlers = [callback for callback in handlers if handler_filter(callback)]

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

        A registration is identified by its module path and name. Registering the
        same pair again adds nothing. A class whose name is already registered
        from another module path is registered as well, under a key that adds its
        module path (``<module path>:<name>``), so a plugin package with a class
        named like another package's, or like one of ASH's built-in plugins, does
        not keep either class from resolving, whichever registers first. No
        registration is ever replaced.

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

        registrations = self._registrations(plugin_type)
        with self._registry_lock:
            key = plugin_module_name
            existing = registrations.get(key) if registrations is not None else None
            if (
                existing is not None
                and existing.plugin_module_path != plugin_module_path
            ):
                key = f"{plugin_module_path}:{plugin_module_name}"
                existing = registrations.get(key)
            already_registered = existing is not None
            if registrations is not None and not already_registered:
                registrations[key] = AshPluginRegistration(
                    name=plugin_module_name,
                    plugin_module_path=plugin_module_path,
                    version=plugin_module_version,
                    enabled=plugin_module_enabled,
                )
        if already_registered:
            ASH_LOGGER.warning(
                f"Plugin module '{plugin_module_name}' from '{plugin_module_path}' "
                "already registered. Skipping."
            )
            return

        ASH_LOGGER.verbose(f"Registered plugin module '{plugin_module_name}'")

    def _registrations(self, plugin_type) -> Dict[str, AshPluginRegistration] | None:
        """The registration dict for *plugin_type*, or None for an unknown type."""
        if plugin_type == "converter":
            return self.plugin_library.converters
        if plugin_type == "scanner":
            return self.plugin_library.scanners
        if plugin_type == "reporter":
            return self.plugin_library.reporters
        return None

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
        import importlib

        # Normalize plugin_type to a string key
        cache_key = plugin_type if isinstance(plugin_type, str) else None
        registrations = self._registrations(plugin_type) if cache_key else None
        if registrations is None:
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []

        # Copied under the lock: another thread importing a plugin module registers
        # into this dict, and iterating it while that happens raises
        # "dictionary changed size during iteration".
        with self._registry_lock:
            snapshot = tuple(
                (registration.plugin_module_path, registration.enabled)
                for registration in registrations.values()
            )
        cached = self._resolved_plugins.get(cache_key)
        if cached is not None and cached[0] == snapshot:
            return self.filter_plugin_modules(
                cached[1], filter_callback, *args, **kwargs
            )

        plugins = []
        for plugin_module_path, enabled in snapshot:
            if not enabled:
                continue
            try:
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                module = importlib.import_module(plugin_module_path)
                # Find the plugin class in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and hasattr(attr, "ash_plugin_type")
                        and attr.ash_plugin_type == plugin_type
                    ):
                        if attr not in plugins:  # Avoid duplicates
                            plugins.append(attr)
            except ImportError as e:
                ASH_LOGGER.warning(
                    f"Failed to import plugin module {plugin_module_path}: {e}"
                )

        # Cache the unfiltered result, keyed by the registrations it came from, so
        # repeat calls skip the import work until something new registers
        self._resolved_plugins[cache_key] = (snapshot, plugins)

        # Apply filter callback
        return self.filter_plugin_modules(plugins, filter_callback, *args, **kwargs)
