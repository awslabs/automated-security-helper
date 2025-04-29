# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import ASH_LOGGER
from importlib.metadata import version, PackageNotFoundError


def ash_plugin(
    cls=None,
    *,
    plugin_type: Literal["converter", "scanner", "reporter"],
    auto_register=True,
):
    """Decorator to register a plugin of specified type with ASH

    Args:
        cls: The class to decorate
        auto_register: Whether to automatically register the plugin with the plugin manager

    Returns:
        The decorated class
    """

    def wrap(cls):
        cls.ash_plugin_type = plugin_type
        if auto_register:
            # Get the module path of the class
            module_path = cls.__module__
            ASH_LOGGER.info(
                f"Auto-registering {plugin_type} plugin {cls.__name__} from {module_path}"
            )
            plug_mod_ver = None
            try:
                if "." in module_path:
                    root_module_path = module_path.split(".")[0]
                    plug_mod_ver = version(root_module_path)
                else:
                    plug_mod_ver = version(module_path)
            except PackageNotFoundError:
                try:
                    plug_mod_ver = version(module_path)
                except PackageNotFoundError:
                    plug_mod_ver = getattr(cls, "__version__", None)

            ash_plugin_manager.register_plugin_module(
                plugin_type=plugin_type,
                plugin_module_class=cls,
                plugin_module_path=module_path,
                plugin_module_version=plug_mod_ver,
                plugin_module_enabled=True,
            )
        return cls

    # Handle both @ash_converter_plugin and @ash_converter_plugin(auto_register=True)
    if cls is None:
        return wrap
    return wrap(cls)


def ash_converter_plugin(cls=None, *, auto_register=True):
    """Decorator to register a converter plugin with ASH

    Args:
        cls: The class to decorate
        auto_register: Whether to automatically register the plugin with the plugin manager

    Returns:
        The decorated class
    """

    def wrap(cls):
        cls.ash_plugin_type = "converter"
        if auto_register:
            # Get the module path of the class
            module_path = cls.__module__
            ASH_LOGGER.info(
                f"Auto-registering converter plugin {cls.__name__} from {module_path}"
            )

            ash_plugin_manager.register_plugin_module(
                plugin_type="converter",
                plugin_module_class=cls,
                plugin_module_path=module_path,
                plugin_module_version=getattr(cls, "__version__", None),
                plugin_module_enabled=True,
            )
        return cls

    # Handle both @ash_converter_plugin and @ash_converter_plugin(auto_register=True)
    if cls is None:
        return wrap
    return wrap(cls)


def ash_scanner_plugin(cls=None, *, auto_register=True):
    """Decorator to register a scanner plugin with ASH

    Args:
        cls: The class to decorate
        auto_register: Whether to automatically register the plugin with the plugin manager

    Returns:
        The decorated class
    """

    def wrap(cls):
        cls.ash_plugin_type = "scanner"
        if auto_register:
            # Get the module path of the class
            module_path = cls.__module__
            ASH_LOGGER.info(
                f"Auto-registering scanner plugin {cls.__name__} from {module_path}"
            )

            ash_plugin_manager.register_plugin_module(
                plugin_type="scanner",
                plugin_module_class=cls,
                plugin_module_path=module_path,
                plugin_module_version=getattr(cls, "__version__", None),
                plugin_module_enabled=True,
            )
        return cls

    # Handle both @ash_scanner_plugin and @ash_scanner_plugin(auto_register=True)
    if cls is None:
        return wrap
    return wrap(cls)


def ash_reporter_plugin(cls=None, *, auto_register=True):
    """Decorator to register a reporter plugin with ASH

    Args:
        cls: The class to decorate
        auto_register: Whether to automatically register the plugin with the plugin manager

    Returns:
        The decorated class
    """

    def wrap(cls):
        cls.ash_plugin_type = "reporter"
        if auto_register:
            # Get the module path of the class
            module_path = cls.__module__
            ASH_LOGGER.debug(
                f"Auto-registering reporter plugin {cls.__name__} from {module_path}"
            )

            ash_plugin_manager.register_plugin_module(
                plugin_type="reporter",
                plugin_module_class=cls,
                plugin_module_path=module_path,
                plugin_module_version=getattr(cls, "__version__", None),
                plugin_module_enabled=True,
            )
        return cls

    # Handle both @ash_reporter_plugin and @ash_reporter_plugin(auto_register=True)
    if cls is None:
        return wrap
    return wrap(cls)


def event_subscriber(event_type):
    """Decorator to subscribe a function to an event"""

    def decorator(func):
        ash_plugin_manager.subscribe(event_type, func)
        return func

    return decorator
