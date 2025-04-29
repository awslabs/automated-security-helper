# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugins import ash_plugin_manager


def ash_converter_plugin(cls):
    """Decorator to register a converter plugin with ASH"""
    cls.ash_plugin_type = "converter"
    return cls


def ash_scanner_plugin(cls):
    """Decorator to register a scanner plugin with ASH"""
    cls.ash_plugin_type = "scanner"
    return cls


def ash_reporter_plugin(cls):
    """Decorator to register a reporter plugin with ASH"""
    cls.ash_plugin_type = "reporter"
    return cls


def event_subscriber(event_type):
    """Decorator to subscribe a function to an event"""

    def decorator(func):
        ash_plugin_manager.subscribe(event_type, func)
        return func

    return decorator
