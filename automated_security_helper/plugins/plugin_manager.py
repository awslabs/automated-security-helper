# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
from typing import TYPE_CHECKING, Any, Callable, Dict, Annotated, List, Literal
from pydantic import BaseModel, Field, ConfigDict

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
    plugin_library: Annotated[AshPluginLibrary, Field()] = AshPluginLibrary()
    context: Any = None

    def set_context(self, context: "PluginContext"):
        """Set the plugin context for this plugin manager.

        Args:
            context: The PluginContext to use for plugin discovery and operations
        """
        self.context = context
        ASH_LOGGER.debug(f"Plugin manager context set: {context}")

    def subscribe(self, event_type, callback):
        """Subscribe a callback to a specific event type"""
        if event_type not in self.plugin_library.event_handlers:
            self.plugin_library.event_handlers[event_type] = []

        self.plugin_library.event_handlers[event_type].append(callback)
        ASH_LOGGER.debug(
            f"Subscribed callback to event {event_type}. Total subscribers for this event: {len(self.plugin_library.event_handlers[event_type])}"
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

        ASH_LOGGER.debug(
            f"Notifying {len(self.plugin_library.event_handlers[event_type])} subscribers of event {event_type}"
        )
        results = []
        for callback in self.plugin_library.event_handlers[event_type]:
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

        ASH_LOGGER.verbose(f"Registered plugin module '{plugin_module_name}'")

    def filter_plugin_modules(self, items: List, callback: callable, *args, **kwargs):
        filtered = []
        for item in items:
            if callback(item, *args, **kwargs):
                filtered.append(item)
        return filtered

    def plugin_modules(
        self,
        plugin_type: type,
        filter_callback: callable = lambda x: True,
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
        from automated_security_helper.plugins.interfaces import (
            IConverter,
            IReporter,
            IScanner,
        )

        plugins = []

        # Get all registered plugins (internal and external)
        if plugin_type == IConverter or plugin_type == "converter":
            # Add registered converters
            for name, registration in self.plugin_library.converters.items():
                if registration.enabled:
                    try:
                        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                        module = importlib.import_module(
                            registration.plugin_module_path
                        )
                        # Find the plugin class in the module
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (
                                isinstance(attr, type)
                                and hasattr(attr, "ash_plugin_type")
                                and attr.ash_plugin_type == "converter"
                            ):
                                if attr not in plugins:  # Avoid duplicates
                                    plugins.append(attr)
                    except ImportError as e:
                        ASH_LOGGER.warning(
                            f"Failed to import plugin module {registration.plugin_module_path}: {e}"
                        )

        elif plugin_type == IScanner or plugin_type == "scanner":
            # Add registered scanners
            for name, registration in self.plugin_library.scanners.items():
                if registration.enabled:
                    try:
                        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                        module = importlib.import_module(
                            registration.plugin_module_path
                        )
                        # Find the plugin class in the module
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (
                                isinstance(attr, type)
                                and hasattr(attr, "ash_plugin_type")
                                and attr.ash_plugin_type == "scanner"
                            ):
                                if attr not in plugins:  # Avoid duplicates
                                    plugins.append(attr)
                    except ImportError as e:
                        ASH_LOGGER.warning(
                            f"Failed to import plugin module {registration.plugin_module_path}: {e}"
                        )

        elif plugin_type == IReporter or plugin_type == "reporter":
            # Add registered reporters
            for name, registration in self.plugin_library.reporters.items():
                if registration.enabled:
                    try:
                        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                        module = importlib.import_module(
                            registration.plugin_module_path
                        )
                        # Find the plugin class in the module
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (
                                isinstance(attr, type)
                                and hasattr(attr, "ash_plugin_type")
                                and attr.ash_plugin_type == "reporter"
                            ):
                                if attr not in plugins:  # Avoid duplicates
                                    plugins.append(attr)
                    except ImportError as e:
                        ASH_LOGGER.warning(
                            f"Failed to import plugin module {registration.plugin_module_path}: {e}"
                        )
        else:
            # If we get here, we don't know what to do with this plugin type
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []

        # Apply filter callback
        return self.filter_plugin_modules(plugins, filter_callback, *args, **kwargs)
