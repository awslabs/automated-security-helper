# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils.log import ASH_LOGGER


def register_converter_adapters(converter_plugins):
    """Register adapters for existing converter plugins."""

    ASH_LOGGER.debug(
        f"Registering converter adapters for {len(converter_plugins)} plugins"
    )
    for plugin in converter_plugins:
        ASH_LOGGER.debug(f"Converter plugin: {plugin.__class__.__name__}")

    # Create event handler for CONVERT_TARGET
    def handle_convert_target(target, plugin_context, **kwargs):
        ASH_LOGGER.debug(
            f"CONVERT_TARGET event handler called with {len(converter_plugins)} plugins"
        )
        results = []
        for plugin in converter_plugins:
            ASH_LOGGER.debug(
                f"Processing converter plugin: {plugin.__class__.__name__}"
            )
            if plugin.validate():
                plugin.context = plugin_context
                try:
                    ASH_LOGGER.debug(
                        f"Calling convert() on {plugin.__class__.__name__}"
                    )
                    converted = plugin.convert(target)
                    if converted:
                        ASH_LOGGER.debug(
                            f"Converter {plugin.__class__.__name__} returned {len(converted)} converted files"
                        )
                        results.extend(converted)
                    else:
                        ASH_LOGGER.debug(
                            f"Converter {plugin.__class__.__name__} returned no converted files"
                        )
                except Exception as e:
                    ASH_LOGGER.error(
                        f"Error in converter {plugin.__class__.__name__}: {e}"
                    )
                    import traceback

                    ASH_LOGGER.debug(
                        f"Converter exception traceback: {traceback.format_exc()}"
                    )
        return results

    # Register the handler
    ASH_LOGGER.debug("Subscribing to CONVERT_TARGET event")
    ash_plugin_manager.subscribe(AshEventType.CONVERT_TARGET, handle_convert_target)
    ASH_LOGGER.debug("Converter adapter registration complete")


def register_scanner_adapters(scanner_plugins):
    """Register adapters for existing scanner plugins."""

    # Create event handler for SCAN_TARGET
    def handle_scan_target(
        target, target_type, plugin_context, global_ignore_paths=None, **kwargs
    ):
        results = []
        for plugin in scanner_plugins:
            if plugin.validate():
                plugin.context = plugin_context
                try:
                    scan_result = plugin.scan(target, target_type, global_ignore_paths)
                    if scan_result:
                        results.append(scan_result)
                except Exception as e:
                    ASH_LOGGER.error(
                        f"Error in scanner {plugin.__class__.__name__}: {e}"
                    )
        return results

    # Register the handler
    ash_plugin_manager.subscribe(AshEventType.SCAN_TARGET, handle_scan_target)


def register_reporter_adapters(reporter_plugins):
    """Register adapters for existing reporter plugins."""

    ASH_LOGGER.debug(
        f"Registering reporter adapters for {len(reporter_plugins)} plugins"
    )
    for plugin in reporter_plugins:
        ASH_LOGGER.debug(f"Reporter plugin: {plugin.__class__.__name__}")

    # Create event handler for REPORT_GENERATE
    def handle_report_generate(model, plugin_context, **kwargs):
        ASH_LOGGER.debug(
            f"REPORT_GENERATE event handler called with {len(reporter_plugins)} plugins"
        )
        results = []
        for plugin in reporter_plugins:
            ASH_LOGGER.debug(f"Processing reporter plugin: {plugin.__class__.__name__}")
            plugin.context = plugin_context
            try:
                ASH_LOGGER.debug(f"Calling report() on {plugin.__class__.__name__}")
                report = plugin.report(model)
                if report:
                    ASH_LOGGER.debug(
                        f"Reporter {plugin.__class__.__name__} returned a report"
                    )
                    results.append(report)
                else:
                    ASH_LOGGER.debug(
                        f"Reporter {plugin.__class__.__name__} returned None or empty report"
                    )
            except Exception as e:
                ASH_LOGGER.error(f"Error in reporter {plugin.__class__.__name__}: {e}")
                import traceback

                ASH_LOGGER.debug(
                    f"Reporter exception traceback: {traceback.format_exc()}"
                )
        return results

    # Register the handler
    ASH_LOGGER.debug("Subscribing to REPORT_GENERATE event")
    ash_plugin_manager.subscribe(AshEventType.REPORT_GENERATE, handle_report_generate)
    ASH_LOGGER.debug("Reporter adapter registration complete")
