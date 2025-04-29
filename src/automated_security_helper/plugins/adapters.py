# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils.log import ASH_LOGGER


def register_converter_adapters(converter_plugins):
    """Register adapters for existing converter plugins."""

    # Create event handler for CONVERT_TARGET
    def handle_convert_target(target, plugin_context, **kwargs):
        results = []
        for plugin in converter_plugins:
            if plugin.validate():
                plugin.context = plugin_context
                try:
                    converted = plugin.convert(target)
                    if converted:
                        results.extend(converted)
                except Exception as e:
                    ASH_LOGGER.error(
                        f"Error in converter {plugin.__class__.__name__}: {e}"
                    )
        return results

    # Register the handler
    ash_plugin_manager.subscribe(AshEventType.CONVERT_TARGET, handle_convert_target)


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

    # Create event handler for REPORT_GENERATE
    def handle_report_generate(model, plugin_context, **kwargs):
        results = []
        for plugin in reporter_plugins:
            plugin.context = plugin_context
            try:
                report = plugin.report(model)
                if report:
                    results.append(report)
            except Exception as e:
                ASH_LOGGER.error(f"Error in reporter {plugin.__class__.__name__}: {e}")
        return results

    # Register the handler
    ash_plugin_manager.subscribe(AshEventType.REPORT_GENERATE, handle_report_generate)
