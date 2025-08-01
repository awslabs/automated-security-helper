# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


class IConverter:
    """Interface for converter plugins"""

    def convert(self, target):
        """Convert a target file/directory"""
        pass

    def validate_plugin_dependencies(self):
        """Validate converter configuration"""
        pass


class IScanner:
    """Interface for scanner plugins"""

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        """Scan a target file/directory"""
        pass

    def validate_plugin_dependencies(self):
        """Validate scanner configuration"""
        pass


class IReporter:
    """Interface for reporter plugins"""

    def report(self, model):
        """Generate a report from scan results"""
        pass
