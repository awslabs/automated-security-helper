from enum import Enum
import importlib
import inspect
import json
import pkgutil
from typing import Annotated, Dict, Literal

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import ASHConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.utils.log import ASH_LOGGER


class PluginType(str, Enum):
    converter = "converter"
    scanner = "scanner"
    reporter = "reporter"


class RegisteredPlugin(BaseModel):
    """Represents a plugin that has been registered."""

    model_config = ConfigDict(
        extra="allow",
        arbitrary_types_allowed=True,
        use_enum_values=True,
    )

    name: str = Field(description="The name of the plugin.")
    enabled: Annotated[bool, Field(description="Whether the plugin is enabled.")] = True
    plugin_type: PluginType = Field(description="The type of plugin.")
    plugin_class: type = Field(description="The Python class representing the plugin.")
    plugin_config: Annotated[
        PluginConfigBase | None, Field(description="The plugin configuration.")
    ] = None
    plugin_module: Annotated[
        str | None, Field(description="The Python module containing the plugin.")
    ] = None
    plugin_fqn: Annotated[
        str | None,
        Field(description="The fully qualified name of the plugin module + class."),
    ] = None


class PluginRegistry(BaseModel):
    """Registry for plugins."""

    config: ASHConfig | None = None
    plugin_context: PluginContext | None = None
    registered_plugins: Dict[str, Dict[str, RegisteredPlugin]] = {}

    def model_post_init(self, context):
        ASH_LOGGER.info("Discovering ASH plugins...")
        for plugin_type in [e.name for e in PluginType]:
            self.registered_plugins[plugin_type] = self.discover_plugins(
                plug_type=plugin_type
            )
            reg_log = "\n\n- ".join(
                [
                    f"{plug_name}: {json.dumps(plug, default=str)}"
                    for plug_name, plug in self.registered_plugins[plugin_type].items()
                ]
            )
            ASH_LOGGER.debug(
                f"Registered {len(self.registered_plugins[plugin_type])} {plugin_type} plugins:\n\n- {reg_log}"
            )
        return super().model_post_init(context)

    def discover_plugins(
        self, plug_type: str, package: str = None, config: ASHConfig | None = None
    ) -> dict:
        """Discover plugins and register them."""
        state_dict: dict = {}
        # We need to make sure that the discovered classes are actually plugins by
        # confirming if they extend the base class along with existing in the correct
        # plugin namespace.
        if config is not None:
            self.config = config
        if self.config is None:
            self.config = get_default_config()
        if package is None:
            package = f"automated_security_helper.{plug_type}s"
            ASH_LOGGER.debug(
                f"Walking {plug_type} plugin namespace for plugin modules: {package}"
            )
        else:
            ASH_LOGGER.debug(f"Walking {plug_type} plugin submodule: {package}")
        for _importer, module_name, is_package in pkgutil.iter_modules(
            importlib.import_module(package).__path__
        ):
            plugin_module_full_name = f"{package}.{module_name}"
            # Recurse through any sub-packages
            if is_package:
                classes_in_subpackage: dict = self.discover_plugins(
                    plug_type=plug_type,
                    package=plugin_module_full_name,
                )
                for k, v in classes_in_subpackage.items():
                    if k in state_dict:
                        ASH_LOGGER.debug(f"Skipping duplicate plugin: {k}")
                        continue
                    state_dict[k] = v

            # Load the module for inspection
            module = importlib.import_module(plugin_module_full_name)

            # Iterate through all the objects in the module and
            # using the lambda, filter for class objects and only objects that exist within the module
            for _name, obj in inspect.getmembers(
                module,
                lambda member, module_name=plugin_module_full_name: inspect.isclass(
                    member
                )
                and member.__module__ == module_name,
            ):
                if _name == "CustomScanner":
                    ASH_LOGGER.debug(
                        f"Skipping CustomScanner class -- this class needs to be customized before use: {plugin_module_full_name}.{_name}"
                    )
                    continue
                plugin_name = _name
                obj_mro = inspect.getmro(obj)
                if plugin_name in state_dict:
                    ASH_LOGGER.debug(f"Skipping duplicate plugin: {plugin_name}")
                    continue
                elif "scanner" in plug_type and ScannerPluginBase not in obj_mro:
                    ASH_LOGGER.debug(
                        f"Skipping non-plugin class: {plugin_name} in module: {plugin_module_full_name}. Scanner does not extend any of the known base classes for configuration, scan or build specs. MRO: {obj_mro}"
                    )
                    continue
                elif "converter" in plug_type and ConverterPluginBase not in obj_mro:
                    ASH_LOGGER.debug(
                        f"Skipping non-plugin class: {plugin_name} in module: {plugin_module_full_name}. Converter does not extend any of the known base classes for configuration, scan or build specs. MRO: {obj_mro}"
                    )
                    continue
                elif "reporter" in plug_type and ReporterPluginBase not in obj_mro:
                    ASH_LOGGER.debug(
                        f"Skipping non-plugin class: {plugin_name} in module: {plugin_module_full_name}. Reporter does not extend any of the known base classes for configuration, scan or build specs. MRO: {obj_mro}"
                    )
                    continue

                ASH_LOGGER.debug(
                    f"Found {plug_type} plugin: {plugin_name} ({plugin_module_full_name}.{_name})"
                )

                plugin_config = self.config.get_plugin_config(
                    plugin_type=plug_type,
                    plugin_name=plugin_name,
                )
                if isinstance(plugin_config, dict):
                    if plug_type == "converter":
                        plugin_config = ConverterPluginConfigBase(**plugin_config)
                    elif plug_type == "scanner":
                        plugin_config = ScannerPluginConfigBase(**plugin_config)
                    elif plug_type == "reporter":
                        plugin_config = ReporterPluginConfigBase(**plugin_config)
                    else:
                        plugin_config = PluginConfigBase(**plugin_config)

                if (
                    plugin_config is not None
                    and plugin_config.name is not None
                    and plugin_config.name != plugin_name
                ):
                    plugin_name = plugin_config.name
                state_dict[plugin_name] = RegisteredPlugin(
                    name=plugin_name,
                    enabled=(
                        plugin_config.enabled if plugin_config is not None else True
                    ),
                    plugin_type=PluginType[plug_type],
                    plugin_class=obj,
                    plugin_config=plugin_config,
                    plugin_module=plugin_module_full_name,
                    plugin_fqn=f"{plugin_module_full_name}.{_name}",
                )

        return state_dict

    def get_plugin(
        self,
        plugin_type: Literal["scanner", "converter", "reporter"],
        plugin_name: str = None,
    ) -> RegisteredPlugin | Dict[str, RegisteredPlugin] | None:
        """Get a plugin by name or get all plugins for a specific type."""
        ptype = plugin_type if isinstance(plugin_type, str) else plugin_type.value
        if ptype not in self.registered_plugins:
            ASH_LOGGER.warning(f"Plugin type {plugin_type} not found in registry.")
            return None

        if plugin_name is None:
            return self.registered_plugins[ptype]

        found = self.registered_plugins[ptype].get(plugin_name, None)
        if found is not None:
            ASH_LOGGER.debug(f"Found plugin {plugin_name}: {found.plugin_fqn}")
        return found
