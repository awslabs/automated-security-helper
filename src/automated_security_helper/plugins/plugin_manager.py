# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
from typing import Dict, Annotated, List, Literal
from pydantic import BaseModel, Field, ConfigDict

from automated_security_helper import __version__
from automated_security_helper.utils.log import ASH_LOGGER


class AshPluginRegistration(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )

    name: Annotated[str, Field(description="The name of the plugin")]
    plugin_module_path: Annotated[
        str,
        Field(
            description="The module path containing the plugin. This module will be imported at the start of ASH to identify plugins to use. Example: `automated_security_helper.scanners.ash_default`"
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


class AshPluginManager(BaseModel):
    plugin_library: Annotated[AshPluginLibrary, Field()] = AshPluginLibrary(
        converters={
            "ash-default": AshPluginRegistration(
                name="ash-default",
                plugin_module_path="automated_security_helper.converters.ash_default",
                description="The default set of converters for ASH",
                version=__version__,
                author="Nate Ferrell<nateferl@amazon.com>",
                enabled=True,
            )
        },
        scanners={
            "ash-default": AshPluginRegistration(
                name="ash-default",
                plugin_module_path="automated_security_helper.scanners.ash_default",
                description="The default set of scanners for ASH",
                version=__version__,
                author="Nate Ferrell<nateferl@amazon.com>",
                enabled=True,
            )
        },
        reporters={
            "ash-default": AshPluginRegistration(
                name="ash-default",
                plugin_module_path="automated_security_helper.reporters.ash_default",
                description="The default set of reporters for ASH",
                version=__version__,
                author="Nate Ferrell<nateferl@amazon.com>",
                enabled=True,
            )
        },
    )

    def subscribe(self, event_type, callback):
        """Subscribe a callback to a specific event type"""
        if not hasattr(self, "_subscribers"):
            self._subscribers = {}

        if event_type not in self._subscribers:
            self._subscribers[event_type] = []

        self._subscribers[event_type].append(callback)
        ASH_LOGGER.debug(
            f"Subscribed callback to event {event_type}. Total subscribers for this event: {len(self._subscribers[event_type])}"
        )
        return callback  # Return for decorator usage

    def notify(self, event_type, *args, **kwargs):
        """Notify all subscribers of an event"""
        if not hasattr(self, "_subscribers"):
            ASH_LOGGER.debug(f"No subscribers dictionary exists for event {event_type}")
            return []

        if event_type not in self._subscribers:
            ASH_LOGGER.debug(f"No subscribers for event {event_type}")
            return []

        ASH_LOGGER.debug(
            f"Notifying {len(self._subscribers[event_type])} subscribers of event {event_type}"
        )
        results = []
        for callback in self._subscribers[event_type]:
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
        from automated_security_helper.plugins.interfaces import (
            IConverter,
            IReporter,
            IScanner,
        )

        # For internal plugins, we can directly access the module lists
        if plugin_type == IConverter or plugin_type == "converter":
            from automated_security_helper.converters import ASH_CONVERTERS

            return ASH_CONVERTERS
        elif plugin_type == IScanner or plugin_type == "scanner":
            from automated_security_helper.scanners import ASH_SCANNERS

            return ASH_SCANNERS
        elif plugin_type == IReporter or plugin_type == "reporter":
            from automated_security_helper.reporters import ASH_REPORTERS

            return ASH_REPORTERS
        else:
            # If we get here, we don't know what to do with this plugin type
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []
