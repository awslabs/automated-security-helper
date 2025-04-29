# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugins import AshPluginInterface


class IConverter(metaclass=AshPluginInterface):
    """Interface for converter plugins"""

    def convert(self, target):
        """Convert a target file/directory"""
        pass

    def validate(self):
        """Validate converter configuration"""
        pass


class IScanner(metaclass=AshPluginInterface):
    """Interface for scanner plugins"""

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        """Scan a target file/directory"""
        pass

    def validate(self):
        """Validate scanner configuration"""
        pass


class IReporter(metaclass=AshPluginInterface):
    """Interface for reporter plugins"""

    def report(self, model):
        """Generate a report from scan results"""
        pass
