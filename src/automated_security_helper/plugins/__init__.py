# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from types import FunctionType
from automated_security_helper.plugins.plugin_manager import AshPluginManager

ash_plugin_manager = AshPluginManager()


def method_name(method_name):
    def _auto_caller_template(cls, *args, **kwargs):
        for impl in cls.implementors():
            method = getattr(impl, method_name)
            method(*args, **kwargs)

    return _auto_caller_template


class AshPluginInterface(type):
    """
    Marker for public interfaces
    """

    def __new__(metaclass, classname, bases, attrs):
        new_class = super(AshPluginInterface, metaclass).__new__(
            metaclass, classname, bases, attrs
        )
        for k in new_class.__dict__:
            v = new_class.__dict__[k]
            if type(v) in (FunctionType, staticmethod):
                setattr(new_class, k, classmethod(method_name(k)))

        return new_class

    def __hash__(self):
        return hash(f"{self.__module__}.{self.__name__}")

    def __eq__(self, other):
        if hasattr(other, "__module__") and hasattr(other, "__name__"):
            return (
                f"{self.__module__}.{self.__name__}"
                == f"{other.__module__}.{other.__name__}"
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class AshPlugin(type):
    def __new__(metaclass, classname, bases, attrs):
        new_class = super(AshPlugin, metaclass).__new__(
            metaclass, classname, bases, attrs
        )

        if "ash_plugin_type" in attrs:
            new_class_instance = new_class()
            for interface in attrs["implements"]:
                ash_plugin_manager.register_plugin_module(interface, new_class_instance)

        return new_class


@classmethod
def implementors(cls, filter_callback=None, *args, **kwargs):
    return ash_plugin_manager.plugin_modules(
        cls, filter_callback=filter_callback, *args, **kwargs
    )
